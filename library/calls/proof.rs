//! A host's proof that it is current (card 49): what it says first on a
//! session or an inbox fetch, before the caller tells it anything.
//!
//! A caller dials from its view, and the first thing it would send a host is
//! its ID token and the call's arguments. A host the admin has since removed
//! (dropped from the service's hosts, or node-banned) is still in an old
//! view. So the host speaks first: a [`HostProof`], its root-signed head and
//! the current [`Fresh`]es it holds for that head (no entries: a stranger
//! learns a version and who vouched, nothing about services). The caller
//! sends nothing until [`HostProof::check`] passes:
//!
//! - the head verifies under the network root and hasn't expired;
//! - it is no older than the caller's view (and, at the same version, it is
//!   the same head);
//! - some `Fresh` in it [`vouches`](Fresh::vouches) for it to a caller
//!   dialing this host: current, and signed by a directory other than the
//!   host, unless the head lists the host as its one directory.
//!
//! An honest directory signs a `Fresh` only for its newest head, so within
//! `fresh_secs` of an edit reaching the directories a host the edit removed
//! has nothing to show. [`Standing::Same`]: the caller's view decides whether
//! this host serves what it wants. [`Standing::Newer`]: the caller refreshes
//! its view first. Any error is a dial failure: the caller tries the next
//! host, and has sent this one nothing.
//!
//! ```
//! use library::{Fresh, HostProof, NodeIdentity, Policy, Standing, StateVersion};
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let (dir, host) = (NodeIdentity::from_seed([2u8; 32]), NodeIdentity::from_seed([3u8; 32]));
//! let mut policy = Policy::new(root.node_id());
//! policy.version = StateVersion(4);
//! policy.not_after = i64::MAX;
//! policy.directories = vec![dir.node_id()];
//! let head = policy.sign(&root).unwrap().head;
//! let proof = HostProof {
//!     head: head.clone(),
//!     fresh: vec![Fresh::sign(&dir, &head, 1_000, 1_900).unwrap()],
//! };
//! let checked = proof.check(root.node_id(), &head, host.node_id(), 1_500).unwrap();
//! assert_eq!(checked, Standing::Same);
//! // Fifteen minutes on, nothing vouches: the caller sends nothing.
//! assert!(proof.check(root.node_id(), &head, host.node_id(), 1_901).is_err());
//! ```

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::fresh::{Fresh, MAX_FRESH_SET};
use crate::head::{SignedPolicyHead, StateVersion};
use crate::identity::NodeId;

/// What a host shows a caller before it is told anything: its head and the
/// current `Fresh`es it holds for it (at most [`MAX_FRESH_SET`]). Unsigned
/// envelope: the head verifies under the root, each `Fresh` under the
/// directory key the head lists.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostProof {
    /// The root-signed head the host decides under.
    pub head: SignedPolicyHead,
    /// The current `Fresh`es it holds for that head, one per directory (none
    /// when no directory has vouched for it lately).
    pub fresh: Vec<Fresh>,
}

/// Where a host stands against a caller's view, once its proof checks out.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Standing {
    /// The host holds the view's head: the view says whether it serves.
    Same,
    /// The host holds a newer head, vouched for: the caller refreshes its view
    /// before it decides.
    Newer(StateVersion),
}

impl HostProof {
    /// Check the proof of the host the caller dialed (`host`, the key iroh
    /// authenticated), against the head of the caller's view (`held`,
    /// verified under `root`), at `now`. See the module docs. Errors:
    /// the head's own ([`SignedPolicyHead::verify`], [`Error::Expired`]);
    /// [`Error::OlderHead`]; [`Error::FreshMismatch`] for another head at the
    /// view's version; [`Error::BadFrame`] for more than [`MAX_FRESH_SET`]
    /// `Fresh`es; else the reason the best candidate fails
    /// ([`Error::SelfVouched`], [`Error::FreshLapsed`]), or
    /// [`Error::Unvouched`] when there is none.
    pub fn check(
        &self,
        root: NodeId,
        held: &SignedPolicyHead,
        host: NodeId,
        now: i64,
    ) -> Result<Standing> {
        if self.fresh.len() > MAX_FRESH_SET {
            return Err(Error::BadFrame);
        }
        self.head.verify(root)?;
        self.head.check_fresh(now)?;
        let (theirs, ours) = (self.head.head.version, held.head.version);
        if theirs < ours {
            return Err(Error::OlderHead {
                theirs: theirs.0,
                ours: ours.0,
            });
        }
        if theirs == ours && self.head.hash()? != held.hash()? {
            return Err(Error::FreshMismatch);
        }
        self.vouching(host, now)?;
        Ok(if theirs > ours {
            Standing::Newer(theirs)
        } else {
            Standing::Same
        })
    }

    /// The `Fresh` that vouches for this proof's head to a caller dialing
    /// `host` at `now`; else why none does: the first candidate's reason
    /// ([`Fresh::vouches`]), [`Error::Unvouched`] with none at all.
    pub fn vouching(&self, host: NodeId, now: i64) -> Result<&Fresh> {
        let mut why = Error::Unvouched;
        for f in &self.fresh {
            match f.vouches(&self.head, host, now) {
                Ok(()) => return Ok(f),
                Err(e) => {
                    if matches!(why, Error::Unvouched) {
                        why = e;
                    }
                }
            }
        }
        Err(why)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use crate::signed_policy::Policy;
    use proptest::prelude::*;

    fn root() -> NodeIdentity {
        NodeIdentity::from_seed([1; 32])
    }
    fn dir() -> NodeIdentity {
        NodeIdentity::from_seed([2; 32])
    }
    /// The host being dialed; a directory too, in [`head`] with `both`.
    fn host() -> NodeIdentity {
        NodeIdentity::from_seed([3; 32])
    }

    /// A head at `version` listing `directories`.
    fn head_listing(version: u64, directories: Vec<NodeId>) -> SignedPolicyHead {
        let mut p = Policy::new(root().node_id());
        p.version = StateVersion(version);
        p.not_after = i64::MAX;
        p.directories = directories;
        p.sign(&root()).unwrap().head
    }

    /// A head at `version` listing [`dir`], and also [`host`] when `both`.
    fn head(version: u64, both: bool) -> SignedPolicyHead {
        let mut dirs = vec![dir().node_id()];
        if both {
            dirs.push(host().node_id());
        }
        head_listing(version, dirs)
    }

    fn proof(head: &SignedPolicyHead, signers: &[&NodeIdentity]) -> HostProof {
        HostProof {
            head: head.clone(),
            fresh: signers
                .iter()
                .map(|s| Fresh::sign(s, head, 1_000, 1_900).unwrap())
                .collect(),
        }
    }

    fn check(p: &HostProof, held: &SignedPolicyHead, now: i64) -> Result<Standing> {
        p.check(root().node_id(), held, host().node_id(), now)
    }

    #[test]
    fn a_current_proof_from_another_directory_passes() {
        let h = head(4, true);
        assert_eq!(
            check(&proof(&h, &[&dir()]), &h, 1_500).unwrap(),
            Standing::Same
        );
        // With the host's own beside it: the other directory's counts.
        let both = proof(&h, &[&host(), &dir()]);
        assert_eq!(check(&both, &h, 1_500).unwrap(), Standing::Same);
        assert_eq!(
            both.vouching(host().node_id(), 1_500).unwrap().directory,
            dir().node_id()
        );
    }

    /// The attack card 49 closes: a removed host that is also a directory
    /// signs a `Fresh` for its own old head; the caller sends nothing.
    #[test]
    fn a_host_vouching_for_its_own_old_head_fails() {
        let old = head(4, true);
        assert!(matches!(
            check(&proof(&old, &[&host()]), &old, 1_500),
            Err(Error::SelfVouched)
        ));
        // And with nothing at all, or only a lapsed word, likewise.
        assert!(matches!(
            check(&proof(&old, &[]), &old, 1_500),
            Err(Error::Unvouched)
        ));
        assert!(matches!(
            check(&proof(&old, &[&dir()]), &old, 1_901),
            Err(Error::FreshLapsed)
        ));
    }

    #[test]
    fn a_one_machine_network_takes_the_hosts_own_word() {
        let alone = head_listing(4, vec![host().node_id()]);
        assert_eq!(
            check(&proof(&alone, &[&host()]), &alone, 1_500).unwrap(),
            Standing::Same
        );
    }

    #[test]
    fn an_older_head_or_another_head_at_the_same_version_fails() {
        let (v4, v5) = (head(4, false), head(5, false));
        assert!(matches!(
            check(&proof(&v4, &[&dir()]), &v5, 1_500),
            Err(Error::OlderHead { theirs: 4, ours: 5 })
        ));
        let twin = head_listing(
            4,
            vec![dir().node_id(), NodeIdentity::from_seed([9; 32]).node_id()],
        );
        assert!(matches!(
            check(&proof(&twin, &[&dir()]), &v4, 1_500),
            Err(Error::FreshMismatch)
        ));
        assert_eq!(
            check(&proof(&v5, &[&dir()]), &v4, 1_500).unwrap(),
            Standing::Newer(StateVersion(5))
        );
    }

    #[test]
    fn a_forged_or_foreign_head_or_too_many_fresh_fails() {
        let h = head(4, false);
        let rogue = NodeIdentity::from_seed([8; 32]);
        let mut p = Policy::new(rogue.node_id());
        p.version = StateVersion(9);
        p.not_after = i64::MAX;
        p.directories = vec![dir().node_id()];
        let foreign = p.sign(&rogue).unwrap().head;
        assert!(check(&proof(&foreign, &[&dir()]), &h, 1_500).is_err());
        let mut expired = Policy::new(root().node_id());
        expired.version = StateVersion(5);
        expired.not_after = 1_200;
        expired.directories = vec![dir().node_id()];
        let expired = expired.sign(&root()).unwrap().head;
        assert!(matches!(
            check(&proof(&expired, &[&dir()]), &h, 1_500),
            Err(Error::Expired { .. })
        ));
        let mut many = proof(&h, &[&dir()]);
        many.fresh = vec![many.fresh[0].clone(); MAX_FRESH_SET + 1];
        assert!(matches!(check(&many, &h, 1_500), Err(Error::BadFrame)));
    }

    proptest! {
        /// Whatever a host shows, a proof passes only when some `Fresh` in it
        /// is current, for its head, and not the host's own (unless it is
        /// the one directory), and the head is no older than the view.
        #[test]
        fn a_proof_passes_only_when_someone_else_vouches(
            theirs in 3u64..7,
            ours in 3u64..7,
            signers in proptest::collection::vec(any::<bool>(), 0..4),
            both in any::<bool>(),
            now in 900i64..2_000,
        ) {
            let h = head(theirs, both);
            let held = head(ours, both);
            let who: Vec<NodeIdentity> = signers
                .iter()
                .map(|&by_dir| if by_dir { dir() } else { host() })
                .filter(|s| h.head.is_directory(s.node_id()))
                .collect();
            let refs: Vec<&NodeIdentity> = who.iter().collect();
            let p = proof(&h, &refs);
            let other = who.iter().any(|s| s.node_id() == dir().node_id());
            let current = (1_000 - crate::CLOCK_SKEW_SECS..=1_900).contains(&now);
            let should = theirs >= ours && other && current;
            prop_assert_eq!(check(&p, &held, now).is_ok(), should);
        }
    }
}

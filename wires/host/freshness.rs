//! The host's freshness (cards 36c and 49): the newest [`Fresh`] each
//! directory signed for the head this host decides under, which it shows a
//! caller before the caller tells it anything.
//!
//! A directory signs `Fresh {version, head, at, until}` for its newest head
//! every `settings.beat_secs`; it is valid because the root-signed head
//! lists the signer in `directories`. The host keeps the newest one from each
//! directory that vouches for its own head ([`FreshSet`]), in memory and in
//! `fresh.json` (so a restarted host can still prove itself before any
//! directory answers). Every frame of the host's `policy` subscription
//! ([`follow`](super::follow)) carries one, and a host that is itself a
//! directory takes its own as well.
//!
//! Keeping one per directory matters for a host that is also a directory: a
//! caller takes its own word only when the head lists it as the one
//! directory, so it must still hold the `Fresh` of the directory it follows.
//!
//! **What a lapse costs** (card 49): every session and inbox fetch opens with
//! [`Freshness::proof`]. With no current `Fresh` from a directory other than
//! this host (every directory down, or this host cut off from them), callers
//! send it nothing, so it serves nobody until a directory vouches again. The
//! host says so in its trace (throttled, [`Freshness::proof`]).

use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use library::{Fresh, FreshSet, HostProof, SignedPolicyHead};

use crate::admin::keystore::{Keystore, write_private};

/// The file under `$WIRES_HOME` holding the newest `Fresh` per directory for
/// the held head.
pub(crate) const FRESH_FILE: &str = "fresh.json";

/// The host's freshness: the newest verified `Fresh` per directory, in
/// memory and in [`FRESH_FILE`]. See the module docs.
pub(crate) struct Freshness {
    /// Where [`FRESH_FILE`] lives.
    ks: Arc<Keystore>,
    /// The newest `Fresh` per directory offered that verified against the
    /// head it was offered for.
    held: RwLock<FreshSet>,
}

impl std::fmt::Debug for Freshness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Freshness")
            .field("held", &self.held)
            .finish_non_exhaustive()
    }
}

/// Lapses a host traces at most this often (one line per window).
static LAPSES: crate::host::transport::Throttle = crate::host::transport::Throttle::new();

impl Freshness {
    /// The host's freshness from `ks`: its [`FRESH_FILE`], keeping only those
    /// that vouch for `head` (the head on disk; `None`: no policy yet, so
    /// nothing is kept). A missing or unreadable file is none, never an
    /// error: freshness only ever arrives from a directory again.
    pub(crate) fn load(ks: Arc<Keystore>, head: Option<&SignedPolicyHead>) -> Freshness {
        let held: FreshSet = std::fs::read_to_string(ks.path(FRESH_FILE))
            .ok()
            .and_then(|text| serde_json::from_str::<Vec<Fresh>>(text.trim()).ok())
            .unwrap_or_default()
            .into_iter()
            .filter(|f| head.is_some_and(|h| f.verify(h).is_ok()))
            .collect();
        Freshness {
            ks,
            held: RwLock::new(held),
        }
    }

    /// Keep `fresh` if it vouches for `head` (the head this host holds now,
    /// already verified under the root: see [`Fresh::verify`]) and ranks
    /// above the one held from its directory at `now` ([`FreshSet::insert`]).
    /// Writes [`FRESH_FILE`] when it keeps it. `Ok(false)`: not better.
    /// `Err`: it doesn't vouch for `head` (another head, a signer the head
    /// doesn't list, a bad signature), and nothing changes.
    pub(crate) fn offer(&self, fresh: &Fresh, head: &SignedPolicyHead, now: i64) -> Result<bool> {
        fresh
            .verify(head)
            .context("the freshness doesn't vouch for the held head")?;
        let text = {
            let mut held = self.held.write().unwrap_or_else(|e| e.into_inner());
            if !held.insert(fresh.clone(), now) {
                return Ok(false);
            }
            let kept: Vec<&Fresh> = held.iter().collect();
            serde_json::to_string(&kept).context("encoding the freshness")?
        };
        write_private(&self.ks.path(FRESH_FILE), format!("{text}\n"))?;
        Ok(true)
    }

    /// What this host shows a caller first, for `head` at `now`: the head and
    /// every current `Fresh` it holds for it. When none of them is from a
    /// directory other than `me` (or `me` as the head's one directory), no
    /// caller will go on, and the host traces that (throttled).
    pub(crate) fn proof(
        &self,
        head: &SignedPolicyHead,
        me: library::NodeId,
        now: i64,
    ) -> HostProof {
        let fresh = self
            .held
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .current_for(head, now);
        let proof = HostProof {
            head: head.clone(),
            fresh,
        };
        if let Err(why) = proof.vouching(me, now)
            && let Some(n) = LAPSES.tick(crate::clock::now_ms())
        {
            tracing::warn!(
                version = head.head.version.0,
                sessions = n,
                "callers will send this host nothing: {why} (is a directory running, and can \
                 this host reach it?)"
            );
        }
        proof
    }

    /// Whether some current `Fresh` from a directory other than `me` (or `me`
    /// as the one directory) vouches for `head` at `now`: whether a caller
    /// will talk to this host.
    #[cfg(test)]
    pub(crate) fn vouched(&self, head: &SignedPolicyHead, me: library::NodeId, now: i64) -> bool {
        self.held
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .vouching(head, me, now)
            .is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{NodeId, NodeIdentity, Policy, StateVersion};

    /// Root 1, directories 30 and 32: the head at `version`, listing both.
    fn head(version: u64) -> SignedPolicyHead {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut p = Policy::new(root.node_id());
        p.version = StateVersion(version);
        p.not_after = i64::MAX;
        p.directories = vec![dir().node_id(), me_dir().node_id()];
        crate::testutil::signed_policy(&root, p).head
    }

    fn dir() -> NodeIdentity {
        NodeIdentity::from_seed([30u8; 32])
    }

    /// This host, itself a directory of [`head`].
    fn me_dir() -> NodeIdentity {
        NodeIdentity::from_seed([32u8; 32])
    }

    fn me() -> NodeId {
        me_dir().node_id()
    }

    fn fresh(head: &SignedPolicyHead, at: i64, until: i64) -> Fresh {
        Fresh::sign(&dir(), head, at, until).unwrap()
    }

    fn freshness() -> Freshness {
        Freshness::load(Arc::new(Keystore::at(crate::testutil::temp_dir())), None)
    }

    #[test]
    fn a_current_fresh_for_the_held_head_vouches_until_it_lapses() {
        let f = freshness();
        let h = head(2);
        assert!(!f.vouched(&h, me(), 100));
        assert!(f.offer(&fresh(&h, 100, 200), &h, 100).unwrap());
        assert!(f.vouched(&h, me(), 150));
        assert!(f.vouched(&h, me(), 200));
        assert!(!f.vouched(&h, me(), 201));
        assert!(
            f.proof(&h, me(), 201).fresh.is_empty(),
            "a lapsed one isn't shown"
        );
        // It vouches for that head only.
        assert!(!f.vouched(&head(3), me(), 150));
    }

    /// A host that is also a directory keeps its own `Fresh` and the one of
    /// the directory it follows, and shows both: a caller takes the other.
    #[test]
    fn a_host_that_is_a_directory_keeps_the_other_directorys_word() {
        let f = freshness();
        let h = head(2);
        let own = Fresh::sign(&me_dir(), &h, 100, 500).unwrap();
        assert!(f.offer(&own, &h, 100).unwrap());
        assert!(!f.vouched(&h, me(), 150), "its own word isn't enough");
        assert!(f.offer(&fresh(&h, 100, 200), &h, 100).unwrap());
        assert!(f.vouched(&h, me(), 150));
        let proof = f.proof(&h, me(), 150);
        assert_eq!(proof.fresh.len(), 2);
        assert!(proof.vouching(me(), 150).is_ok());
        // A later beat of its own doesn't displace the other's.
        let later = Fresh::sign(&me_dir(), &h, 140, 900).unwrap();
        assert!(f.offer(&later, &h, 140).unwrap());
        assert!(f.vouched(&h, me(), 150));
    }

    #[test]
    fn only_newer_freshness_is_kept() {
        let f = freshness();
        let h = head(2);
        assert!(f.offer(&fresh(&h, 100, 200), &h, 100).unwrap());
        assert!(!f.offer(&fresh(&h, 50, 150), &h, 100).unwrap());
        assert!(!f.offer(&fresh(&h, 100, 200), &h, 100).unwrap());
        assert!(f.offer(&fresh(&h, 150, 300), &h, 100).unwrap());
        // A newer head's, however short.
        let h3 = head(3);
        assert!(f.offer(&fresh(&h3, 10, 20), &h3, 100).unwrap());
        assert!(f.vouched(&h3, me(), 15));
    }

    #[test]
    fn a_fresh_for_another_head_or_from_an_unlisted_node_is_refused() {
        let f = freshness();
        let (h2, h3) = (head(2), head(3));
        assert!(f.offer(&fresh(&h3, 100, 200), &h2, 100).is_err());
        // Signed by a node the head doesn't list: its signature is fine, but
        // it vouches for nothing.
        let stranger = Fresh::sign(
            &NodeIdentity::from_seed([31u8; 32]),
            &{
                let root = NodeIdentity::from_seed([1u8; 32]);
                let mut p = Policy::new(root.node_id());
                p.version = StateVersion(2);
                p.not_after = i64::MAX;
                p.directories = vec![NodeIdentity::from_seed([31u8; 32]).node_id()];
                crate::testutil::signed_policy(&root, p).head
            },
            100,
            200,
        )
        .unwrap();
        assert!(f.offer(&stranger, &h2, 100).is_err());
        assert!(!f.vouched(&h2, me(), 150));
    }

    #[test]
    fn a_restarted_host_reads_its_freshness_back_for_the_same_head_only() {
        let home = crate::testutil::temp_dir();
        let ks = Arc::new(Keystore::at(&home));
        let h = head(2);
        let first = Freshness::load(Arc::clone(&ks), Some(&h));
        first.offer(&fresh(&h, 100, 200), &h, 100).unwrap();
        first
            .offer(&Fresh::sign(&me_dir(), &h, 100, 200).unwrap(), &h, 100)
            .unwrap();
        let back = Freshness::load(Arc::clone(&ks), Some(&h));
        assert!(back.vouched(&h, me(), 150));
        assert_eq!(back.proof(&h, me(), 150).fresh.len(), 2);
        // Under another head (or none) the file vouches for nothing.
        let other = Freshness::load(Arc::clone(&ks), Some(&head(3)));
        assert!(other.proof(&head(3), me(), 150).fresh.is_empty());
        let none = Freshness::load(ks, None);
        assert!(!none.vouched(&h, me(), 150));
    }

    #[test]
    fn a_garbled_file_is_no_freshness() {
        let home = crate::testutil::temp_dir();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join(FRESH_FILE), "{not json").unwrap();
        let f = Freshness::load(Arc::new(Keystore::at(&home)), Some(&head(2)));
        assert!(!f.vouched(&head(2), me(), 150));
    }
}

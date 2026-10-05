//! Freshness: a directory's signed "this head is the newest" (card 36; TUF's
//! timestamp role).
//!
//! Every [`Settings::beat_secs`](crate::Settings::beat_secs) each directory
//! signs a [`Fresh`] for the head it holds, good until `at +`
//! [`Settings::fresh_secs`](crate::Settings::fresh_secs). A node holding a
//! current `Fresh` for its head knows its policy is the newest.
//!
//! **What it decides** (card 49): a caller tells a host nothing (no ID
//! token, no arguments) until a current `Fresh` vouches for the head the host
//! holds, signed by a directory **other than that host** ([`Fresh::vouches`]).
//! An honest directory signs only for its newest head, so within
//! `fresh_secs` of an edit reaching the directories a host the edit removed
//! has nothing to show. The one exception is a head that lists exactly one
//! directory, the host itself: a one-machine network, where the host's own
//! word is all there is. A [`FreshSet`] keeps the newest `Fresh` per
//! directory, on a host (what it shows) and on a caller (what it has seen).
//!
//! A `Fresh` is signed by the directory's own node key, never the root, and is
//! valid only because the root-signed head lists that key in `directories`
//! ([`Fresh::verify`]). It names the head by version and [`HeadHash`], so it
//! can't vouch for another head of the same version.
//!
//! - **Signed bytes:** [`FRESH_CONTEXT`] followed by the canonical JSON of
//!   every field but `sig`.
//! - **Format:** [`FRESH_V1`], signed; unknown fields are refused at decode.
//!
//! ```
//! use library::{Fresh, NodeIdentity, Policy, StateVersion};
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let dir = NodeIdentity::from_seed([2u8; 32]);
//! let mut policy = Policy::new(root.node_id());
//! policy.version = StateVersion(1);
//! policy.not_after = i64::MAX;
//! policy.directories.push(dir.node_id());
//! let head = policy.sign(&root).unwrap().head;
//! let fresh = Fresh::sign(&dir, &head, 1_000, 1_900).unwrap();
//! fresh.verify(&head).unwrap();
//! assert!(fresh.is_current(1_900));
//! assert!(!fresh.is_current(1_901));
//! ```

use serde::{Deserialize, Serialize};

use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::head::StateVersion;
use crate::head::{HeadHash, SignedPolicyHead};
use crate::identity::{AlgorithmId, NodeId, NodeIdentity, Signature};
use crate::idp::CLOCK_SKEW_SECS;

/// The current (and only) `Fresh` format.
pub const FRESH_V1: u8 = 1;

/// Domain-separation prefix of a `Fresh`'s signed bytes.
pub const FRESH_CONTEXT: &[u8] = b"wires/fresh/v1\0";

/// A directory's signed statement that `head` (version `version`) is the
/// newest policy it holds, from `at` until `until`. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fresh {
    /// Format discriminant; [`FRESH_V1`]. Signed.
    pub format: u8,
    /// The network's root key, which the head belongs to.
    pub fabric: NodeId,
    /// The directory that signed it: must be in the head's `directories`.
    pub directory: NodeId,
    /// The head's version.
    pub version: StateVersion,
    /// The head's hash.
    pub head: HeadHash,
    /// When the directory signed it, unix seconds.
    pub at: i64,
    /// Good until, unix seconds, inclusive.
    pub until: i64,
    /// Which scheme `sig` was produced with.
    pub alg: AlgorithmId,
    /// The directory's signature over [`FRESH_CONTEXT`] ‖ the canonical body.
    pub sig: Signature,
}

impl Fresh {
    /// Sign a `Fresh` for `head` with the directory's node key.
    /// [`Error::NotADirectory`] if the head does not list `directory`;
    /// [`Error::InvalidPolicy`] if `until < at`.
    pub fn sign(
        directory: &NodeIdentity,
        head: &SignedPolicyHead,
        at: i64,
        until: i64,
    ) -> Result<Fresh> {
        if !head.head.is_directory(directory.node_id()) {
            return Err(Error::NotADirectory);
        }
        if until < at {
            return Err(Error::InvalidPolicy(
                "freshness ends before it starts".into(),
            ));
        }
        let body = SignedBody {
            format: FRESH_V1,
            fabric: head.head.fabric,
            directory: directory.node_id(),
            version: head.head.version,
            head: head.hash()?,
            at,
            until,
            alg: AlgorithmId::Ed25519,
        };
        let sig = directory.sign(&body.signed_bytes()?);
        Ok(Fresh {
            format: body.format,
            fabric: body.fabric,
            directory: body.directory,
            version: body.version,
            head: body.head,
            at,
            until,
            alg: body.alg,
            sig,
        })
    }

    /// Check it vouches for exactly `head` (a head the caller has already
    /// verified under its root): format and algorithm, the same fabric,
    /// version and [`HeadHash`] ([`Error::FreshMismatch`]), a signer the head
    /// lists in `directories` ([`Error::NotADirectory`]), `at <= until`, and
    /// the signature. Does not check the time
    /// ([`is_current`](Self::is_current)).
    pub fn verify(&self, head: &SignedPolicyHead) -> Result<()> {
        if self.format != FRESH_V1 {
            return Err(Error::UnsupportedVersion);
        }
        if self.alg != AlgorithmId::Ed25519 {
            return Err(Error::UnsupportedAlgorithm);
        }
        if self.fabric != head.head.fabric
            || self.version != head.head.version
            || self.head != head.hash()?
        {
            return Err(Error::FreshMismatch);
        }
        if !head.head.is_directory(self.directory) {
            return Err(Error::NotADirectory);
        }
        if self.until < self.at {
            return Err(Error::InvalidPolicy(
                "freshness ends before it starts".into(),
            ));
        }
        self.directory.verify(&self.signed_bytes()?, &self.sig)
    }

    /// Whether it is current at `now`: `now <= until`, and `at` is no further
    /// in the future than [`CLOCK_SKEW_SECS`].
    pub fn is_current(&self, now: i64) -> bool {
        now >= self.at.saturating_sub(CLOCK_SKEW_SECS) && now <= self.until
    }

    /// Whether it lets a caller dialing `host` take `head` (verified under
    /// the root already) as current at `now` (card 49): it
    /// [`verify`](Self::verify)s for `head`, [`is_current`](Self::is_current)
    /// ([`Error::FreshLapsed`]), and was signed by a directory other than
    /// `host`, unless `head` lists exactly one directory and it is `host`
    /// ([`Error::SelfVouched`]).
    ///
    /// ```
    /// use library::{Fresh, NodeIdentity, Policy, StateVersion};
    /// let root = NodeIdentity::from_seed([1u8; 32]);
    /// let (a, b) = (NodeIdentity::from_seed([2u8; 32]), NodeIdentity::from_seed([3u8; 32]));
    /// let mut policy = Policy::new(root.node_id());
    /// policy.version = StateVersion(1);
    /// policy.not_after = i64::MAX;
    /// policy.directories = vec![a.node_id(), b.node_id()];
    /// let head = policy.sign(&root).unwrap().head;
    /// let by_a = Fresh::sign(&a, &head, 1_000, 1_900).unwrap();
    /// // Directory `a` vouches for host `b`, but not for itself.
    /// assert!(by_a.vouches(&head, b.node_id(), 1_500).is_ok());
    /// assert!(by_a.vouches(&head, a.node_id(), 1_500).is_err());
    /// ```
    pub fn vouches(&self, head: &SignedPolicyHead, host: NodeId, now: i64) -> Result<()> {
        self.verify(head)?;
        if !self.is_current(now) {
            return Err(Error::FreshLapsed);
        }
        let only_the_host = head.head.directories.as_slice() == [host];
        if self.directory == host && !only_the_host {
            return Err(Error::SelfVouched);
        }
        Ok(())
    }
}

/// The most directories a [`FreshSet`] keeps a [`Fresh`] from; past it, the
/// worst-ranked is dropped. A host shows at most this many to a caller.
pub const MAX_FRESH_SET: usize = 16;

/// The newest [`Fresh`] from each directory: what a host shows a caller
/// before it is told anything, and what a caller keeps of what it has seen
/// (card 49). Holding one `Fresh` per signer, not one in all, is what lets a
/// host that is also a directory still show another directory's word, and a
/// caller still find one to dial that directory with.
///
/// It verifies nothing on the way in: every use checks each `Fresh` again
/// against the head it is asked about ([`vouching`](Self::vouching),
/// [`current_for`](Self::current_for)), so a set read back from disk can't
/// vouch for anything a signer didn't sign.
///
/// ```
/// use library::{Fresh, FreshSet, NodeIdentity, Policy, StateVersion};
/// let root = NodeIdentity::from_seed([1u8; 32]);
/// let (dir, host) = (NodeIdentity::from_seed([2u8; 32]), NodeIdentity::from_seed([3u8; 32]));
/// let mut policy = Policy::new(root.node_id());
/// policy.version = StateVersion(1);
/// policy.not_after = i64::MAX;
/// policy.directories = vec![dir.node_id(), host.node_id()];
/// let head = policy.sign(&root).unwrap().head;
/// let mut set = FreshSet::default();
/// assert!(set.insert(Fresh::sign(&host, &head, 1_000, 1_900).unwrap(), 1_000));
/// assert!(set.vouching(&head, host.node_id(), 1_500).is_none(), "its own word");
/// assert!(set.insert(Fresh::sign(&dir, &head, 1_000, 1_900).unwrap(), 1_000));
/// assert_eq!(set.vouching(&head, host.node_id(), 1_500).unwrap().directory, dir.node_id());
/// assert_eq!(set.current_for(&head, 1_500).len(), 2);
/// assert!(set.current_for(&head, 1_901).is_empty());
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FreshSet(Vec<Fresh>);

impl FreshSet {
    /// Keep `fresh` if it ranks above the one held from its signer at `now`
    /// (none held, a newer head's, or for the same head: current where the
    /// held one isn't, then a later `until`; so one from a directory whose
    /// clock runs ahead never displaces a current one). With
    /// [`MAX_FRESH_SET`] signers held already, a new signer displaces the
    /// worst-ranked, if it ranks above it. Whether it was kept.
    pub fn insert(&mut self, fresh: Fresh, now: i64) -> bool {
        let rank = |f: &Fresh| (f.version, f.is_current(now), f.until);
        if let Some(held) = self.0.iter_mut().find(|f| f.directory == fresh.directory) {
            if rank(&fresh) <= rank(held) {
                return false;
            }
            *held = fresh;
            return true;
        }
        if self.0.len() >= MAX_FRESH_SET {
            let Some((worst, _)) = self.0.iter().enumerate().min_by_key(|(_, f)| rank(f)) else {
                return false;
            };
            if rank(&fresh) <= rank(&self.0[worst]) {
                return false;
            }
            self.0.remove(worst);
        }
        self.0.push(fresh);
        true
    }

    /// The first one that [`vouches`](Fresh::vouches) for `head` to a caller
    /// dialing `host` at `now`.
    pub fn vouching(&self, head: &SignedPolicyHead, host: NodeId, now: i64) -> Option<&Fresh> {
        self.0.iter().find(|f| f.vouches(head, host, now).is_ok())
    }

    /// Every one that verifies for `head` and is current at `now`, at most
    /// [`MAX_FRESH_SET`]: what a host shows a caller.
    pub fn current_for(&self, head: &SignedPolicyHead, now: i64) -> Vec<Fresh> {
        self.0
            .iter()
            .filter(|f| f.verify(head).is_ok() && f.is_current(now))
            .take(MAX_FRESH_SET)
            .cloned()
            .collect()
    }

    /// Every `Fresh` held, one per signer.
    pub fn iter(&self) -> impl Iterator<Item = &Fresh> {
        self.0.iter()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromIterator<Fresh> for FreshSet {
    /// Insert each in turn, ranking at their own `at` (what a set read back
    /// whole needs: the one per signer with the newest head and `until`).
    fn from_iter<I: IntoIterator<Item = Fresh>>(iter: I) -> Self {
        let mut set = FreshSet::default();
        for f in iter {
            let at = f.at;
            set.insert(f, at);
        }
        set
    }
}

/// The signed portion of a [`Fresh`]: every field but `sig`.
#[derive(Serialize)]
struct SignedBody {
    format: u8,
    fabric: NodeId,
    directory: NodeId,
    version: StateVersion,
    head: HeadHash,
    at: i64,
    until: i64,
    alg: AlgorithmId,
}

impl SignedBody {
    /// [`FRESH_CONTEXT`] ‖ the canonical body: what the directory signs.
    fn signed_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = FRESH_CONTEXT.to_vec();
        bytes.extend(canonical_bytes(self)?);
        Ok(bytes)
    }
}

impl Fresh {
    /// The bytes [`sig`](Self::sig) covers.
    fn signed_bytes(&self) -> Result<Vec<u8>> {
        SignedBody {
            format: self.format,
            fabric: self.fabric,
            directory: self.directory,
            version: self.version,
            head: self.head,
            at: self.at,
            until: self.until,
            alg: self.alg,
        }
        .signed_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::head::ItemsHash;
    use crate::head::{POLICY_V5, PolicyHead};
    use proptest::prelude::*;

    fn root() -> NodeIdentity {
        NodeIdentity::from_seed([1u8; 32])
    }

    fn dir() -> NodeIdentity {
        NodeIdentity::from_seed([2u8; 32])
    }

    fn head_with(version: u64, items: u8, directories: Vec<NodeId>) -> SignedPolicyHead {
        PolicyHead {
            format: POLICY_V5,
            fabric: root().node_id(),
            version: StateVersion(version),
            issued: 0,
            not_after: i64::MAX,
            directories,
            items_hash: ItemsHash::from_hex(&format!("{items:02x}").repeat(32)).unwrap(),
        }
        .sign(&root())
        .unwrap()
    }

    fn head() -> SignedPolicyHead {
        head_with(5, 3, vec![dir().node_id()])
    }

    #[test]
    fn sign_verify_round_trip() {
        let fresh = Fresh::sign(&dir(), &head(), 1_000, 1_900).unwrap();
        fresh.verify(&head()).unwrap();
        assert_eq!(fresh.format, FRESH_V1);
        assert_eq!(fresh.directory, dir().node_id());
        assert_eq!(fresh.version, StateVersion(5));
        assert_eq!(fresh.head, head().hash().unwrap());
        let back: Fresh = serde_json::from_slice(&canonical_bytes(&fresh).unwrap()).unwrap();
        assert_eq!(back, fresh);
        assert!(
            fresh
                .signed_bytes()
                .unwrap()
                .starts_with(b"wires/fresh/v1\0")
        );
    }

    #[test]
    fn only_a_listed_directory_can_vouch() {
        let stranger = NodeIdentity::from_seed([7u8; 32]);
        assert!(matches!(
            Fresh::sign(&stranger, &head(), 0, 1),
            Err(Error::NotADirectory)
        ));
        // Signed while listed, checked against a head that no longer lists it.
        let fresh = Fresh::sign(&dir(), &head(), 0, 1).unwrap();
        let dropped = head_with(5, 3, vec![]);
        assert!(fresh.verify(&dropped).is_err());
        // A stranger signing for the right head as itself is not a directory.
        let mut own = fresh.clone();
        own.directory = stranger.node_id();
        own.sig = stranger.sign(&own.signed_bytes().unwrap());
        assert!(matches!(own.verify(&head()), Err(Error::NotADirectory)));
        // A stranger's forgery naming a listed directory fails the signature.
        let mut forged = fresh.clone();
        forged.sig = stranger.sign(&forged.signed_bytes().unwrap());
        assert!(matches!(
            forged.verify(&head()),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn it_vouches_for_one_exact_head() {
        let fresh = Fresh::sign(&dir(), &head(), 0, 1).unwrap();
        let newer = head_with(6, 3, vec![dir().node_id()]);
        assert!(matches!(fresh.verify(&newer), Err(Error::FreshMismatch)));
        // Same version, other content.
        let twin = head_with(5, 4, vec![dir().node_id()]);
        assert!(matches!(fresh.verify(&twin), Err(Error::FreshMismatch)));
        // Another network.
        let other = NodeIdentity::from_seed([9u8; 32]);
        let mut h = head().head;
        h.fabric = other.node_id();
        assert!(fresh.verify(&h.sign(&other).unwrap()).is_err());
    }

    #[test]
    fn tampering_and_bad_fields_are_refused() {
        let fresh = Fresh::sign(&dir(), &head(), 1_000, 1_900).unwrap();
        let mut t = fresh.clone();
        t.until += 1;
        assert!(matches!(t.verify(&head()), Err(Error::InvalidSignature)));
        let mut t = fresh.clone();
        t.format = FRESH_V1 + 1;
        assert!(matches!(t.verify(&head()), Err(Error::UnsupportedVersion)));
        assert!(Fresh::sign(&dir(), &head(), 1_000, 999).is_err());
        let mut v = serde_json::to_value(&fresh).unwrap();
        v["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<Fresh>(v).is_err());
    }

    #[test]
    fn currency_is_inclusive_with_skew() {
        let fresh = Fresh::sign(&dir(), &head(), 1_000, 1_900).unwrap();
        assert!(fresh.is_current(1_000));
        assert!(fresh.is_current(1_900));
        assert!(!fresh.is_current(1_901));
        assert!(fresh.is_current(1_000 - CLOCK_SKEW_SECS));
        assert!(!fresh.is_current(1_000 - CLOCK_SKEW_SECS - 1));
        let extreme = Fresh::sign(&dir(), &head(), i64::MIN, i64::MAX).unwrap();
        assert!(extreme.is_current(0));
    }

    /// Node 3: a host that is also a directory, in [`two`].
    fn host() -> NodeIdentity {
        NodeIdentity::from_seed([3u8; 32])
    }

    /// A head at `version` listing [`dir`] and [`host`].
    fn two(version: u64) -> SignedPolicyHead {
        head_with(version, 3, vec![dir().node_id(), host().node_id()])
    }

    /// Card 49: a caller dialing a host takes another directory's word for
    /// the host's head, never the host's own, unless the host is the head's
    /// one directory.
    #[test]
    fn a_host_vouches_for_itself_only_as_the_one_directory() {
        let h = two(5);
        let other = Fresh::sign(&dir(), &h, 1_000, 1_900).unwrap();
        let own = Fresh::sign(&host(), &h, 1_000, 1_900).unwrap();
        assert!(other.vouches(&h, host().node_id(), 1_500).is_ok());
        assert!(matches!(
            own.vouches(&h, host().node_id(), 1_500),
            Err(Error::SelfVouched)
        ));
        // To a caller dialing the other directory as a host, the host's word
        // counts.
        assert!(own.vouches(&h, dir().node_id(), 1_500).is_ok());
        // The one-machine network: the host is the only directory.
        let alone = head_with(5, 3, vec![host().node_id()]);
        let own = Fresh::sign(&host(), &alone, 1_000, 1_900).unwrap();
        assert!(own.vouches(&alone, host().node_id(), 1_500).is_ok());
    }

    #[test]
    fn a_lapsed_or_mismatched_fresh_vouches_for_nothing() {
        let h = two(5);
        let f = Fresh::sign(&dir(), &h, 1_000, 1_900).unwrap();
        assert!(matches!(
            f.vouches(&h, host().node_id(), 1_901),
            Err(Error::FreshLapsed)
        ));
        assert!(matches!(
            f.vouches(&h, host().node_id(), 1_000 - CLOCK_SKEW_SECS - 1),
            Err(Error::FreshLapsed)
        ));
        assert!(matches!(
            f.vouches(&two(6), host().node_id(), 1_500),
            Err(Error::FreshMismatch)
        ));
    }

    #[test]
    fn a_set_keeps_the_best_per_signer() {
        let (h5, h6) = (two(5), two(6));
        let mut set = FreshSet::default();
        assert!(set.insert(Fresh::sign(&dir(), &h5, 100, 200).unwrap(), 100));
        assert!(!set.insert(Fresh::sign(&dir(), &h5, 50, 150).unwrap(), 100));
        assert!(set.insert(Fresh::sign(&dir(), &h5, 150, 300).unwrap(), 150));
        assert!(set.insert(Fresh::sign(&host(), &h5, 150, 300).unwrap(), 150));
        assert_eq!(set.iter().count(), 2, "one per signer");
        // A newer head's replaces the older one's, however short.
        assert!(set.insert(Fresh::sign(&dir(), &h6, 10, 20).unwrap(), 150));
        assert!(set.vouching(&h5, host().node_id(), 160).is_none());
        assert_eq!(set.current_for(&h5, 160).len(), 1, "the host's own");
        // One from the future never displaces a current one.
        let skew = CLOCK_SKEW_SECS;
        let mut set = FreshSet::default();
        assert!(set.insert(Fresh::sign(&dir(), &h5, 990, 1_100).unwrap(), 1_000));
        let ahead = Fresh::sign(&dir(), &h5, 1_000 + skew + 60, 2_000).unwrap();
        assert!(!set.insert(ahead, 1_000));
    }

    #[test]
    fn a_full_set_drops_its_worst() {
        let signers: Vec<NodeIdentity> = (0..=MAX_FRESH_SET as u8)
            .map(|i| NodeIdentity::from_seed([100 + i; 32]))
            .collect();
        let h = head_with(5, 3, signers.iter().map(|s| s.node_id()).collect());
        let mut set = FreshSet::default();
        for (i, s) in signers.iter().enumerate().take(MAX_FRESH_SET) {
            assert!(set.insert(Fresh::sign(s, &h, 0, 100 + i as i64).unwrap(), 0));
        }
        let last = signers.last().unwrap();
        // Ranked below every one held: not kept.
        assert!(!set.insert(Fresh::sign(last, &h, 0, 50).unwrap(), 0));
        // Above the worst: it goes in, the worst goes out.
        assert!(set.insert(Fresh::sign(last, &h, 0, 1_000).unwrap(), 0));
        assert_eq!(set.iter().count(), MAX_FRESH_SET);
        assert!(set.iter().all(|f| f.until != 100), "the worst was dropped");
    }

    #[test]
    fn a_set_round_trips_as_a_plain_list_and_verifies_on_use() {
        let h = two(5);
        let mut set = FreshSet::default();
        set.insert(Fresh::sign(&dir(), &h, 100, 200).unwrap(), 100);
        let text = serde_json::to_string(&set).unwrap();
        assert!(text.starts_with('['), "{text}");
        let back: FreshSet = serde_json::from_str(&text).unwrap();
        assert_eq!(back, set);
        // A tampered entry read back vouches for nothing.
        let mut forged: FreshSet = serde_json::from_str(&text).unwrap();
        forged.0[0].until = 10_000;
        assert!(forged.vouching(&h, host().node_id(), 5_000).is_none());
        assert!(forged.current_for(&h, 5_000).is_empty());
    }

    proptest! {
        /// Whatever is inserted, in any order, a set holds at most one per
        /// signer and at most [`MAX_FRESH_SET`], and every `Fresh` it hands a
        /// caller vouches.
        #[test]
        fn a_set_stays_bounded_and_vouches_only_truly(
            picks in proptest::collection::vec((0u8..20, 0i64..1_000, 0i64..500, 4u64..7), 0..60),
            now in 0i64..1_500,
        ) {
            let signers: Vec<NodeIdentity> =
                (0..20u8).map(|i| NodeIdentity::from_seed([60 + i; 32])).collect();
            let heads: Vec<SignedPolicyHead> = (4..7)
                .map(|v| head_with(v, 3, signers.iter().map(|s| s.node_id()).collect()))
                .collect();
            let mut set = FreshSet::default();
            for (who, at, len, v) in picks {
                let h = &heads[(v - 4) as usize];
                set.insert(Fresh::sign(&signers[who as usize], h, at, at + len).unwrap(), now);
            }
            let mut signed: Vec<NodeId> = set.iter().map(|f| f.directory).collect();
            let n = signed.len();
            signed.sort();
            signed.dedup();
            prop_assert_eq!(signed.len(), n);
            prop_assert!(n <= MAX_FRESH_SET);
            for h in &heads {
                for host in [signers[0].node_id(), signers[1].node_id()] {
                    if let Some(f) = set.vouching(h, host, now) {
                        prop_assert!(f.vouches(h, host, now).is_ok());
                        prop_assert!(f.directory != host);
                    }
                }
                for f in set.current_for(h, now) {
                    prop_assert!(f.verify(h).is_ok() && f.is_current(now));
                }
            }
        }

        #[test]
        fn any_window_verifies_and_is_current_inside_it(
            at in -1_000_000i64..1_000_000,
            len in 0i64..100_000,
            now in -2_000_000i64..2_000_000,
        ) {
            let fresh = Fresh::sign(&dir(), &head(), at, at + len).unwrap();
            prop_assert!(fresh.verify(&head()).is_ok());
            prop_assert_eq!(
                fresh.is_current(now),
                now >= at - CLOCK_SKEW_SECS && now <= at + len
            );
        }
    }
}

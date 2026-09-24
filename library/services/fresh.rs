//! Freshness: a directory's signed "this head is the newest" (card 36; TUF's
//! timestamp role).
//!
//! Every [`Settings::beat_secs`](crate::Settings::beat_secs) each directory
//! signs a [`Fresh`] for the head it holds, good until `at +`
//! [`Settings::fresh_secs`](crate::Settings::fresh_secs). A node holding a
//! current `Fresh` for its head knows its policy is the newest; when it
//! lapses, the settings' [`FreshnessMode`](crate::FreshnessMode) decides.
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
use crate::head::{HeadHash, SignedPolicyHead};
use crate::identity::{AlgorithmId, NodeId, NodeIdentity, Signature};
use crate::idp::CLOCK_SKEW_SECS;
use crate::state::StateVersion;

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
    /// The fabric (root key) the head belongs to.
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
    use crate::head::{POLICY_V3, PolicyHead};
    use crate::merkle::ItemsRoot;
    use proptest::prelude::*;

    fn root() -> NodeIdentity {
        NodeIdentity::from_seed([1u8; 32])
    }

    fn dir() -> NodeIdentity {
        NodeIdentity::from_seed([2u8; 32])
    }

    fn head_with(version: u64, count: u64, directories: Vec<NodeId>) -> SignedPolicyHead {
        PolicyHead {
            format: POLICY_V3,
            fabric: root().node_id(),
            version: StateVersion(version),
            issued: 0,
            not_after: i64::MAX,
            directories,
            items_root: ItemsRoot::from_hex(&"ab".repeat(32)).unwrap(),
            item_count: count,
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
        // Another fabric.
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

    proptest! {
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

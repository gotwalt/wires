//! Fabric membership: a root-signed, offline-verifiable, non-transferable proof
//! that a node belongs to a fabric.
//!
//! A [`Membership`] binds a *member* node key to a *fabric* (named by the fabric
//! root's public key) until `not_after`, signed by that root. Unlike a
//! [`Grant`](crate::Grant) it is **scope-independent** — it answers "is this node
//! a member of fabric R, and who is it?", the question an identity-aware tool
//! asks the instant a session opens. Like a grant it is non-transferable: a
//! responder accepts it only when the iroh-authenticated caller equals `member`
//! (see [`crate::policy::check_inclusion`]).
//!
//! Two choices distinguish this from [`Grant`], both load-bearing for soundness:
//!
//! - **`fabric` is a *signed* field.** A grant's trusted root is supplied out of
//!   band; a membership instead carries `fabric` inside the signed body, and
//!   [`verify`](Membership::verify) asserts `fabric == fabric_root`. The
//!   credential *names its own authority*, so a responder cannot be steered into
//!   checking it against the wrong root, and the leaf authority is pinned for a
//!   future delegation chain (which must terminate at this `fabric`).
//! - **`version` is a *signed* discriminant.** Each version serializes a fixed,
//!   total set of fields; a future v2 defines a *separate* body with its new
//!   fields **required**, never an `Option` added to the v1 body. Optional-but-
//!   signed is forbidden — an absent vs. present-default field produce different
//!   signed bytes, the classic JSON-signing downgrade hole. v1 bytes stay frozen
//!   forever and a v1-only verifier rejects a v2 credential with
//!   [`Error::UnsupportedVersion`] rather than ignoring fields it cannot read.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::grant::AlgorithmId;
use crate::identity::{NodeId, NodeIdentity, Signature};

/// The base64 alphabet for membership tokens: URL-safe, no padding (matches
/// [`CapabilityTicket`](crate::CapabilityTicket)).
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The current (and only) membership format version.
pub const MEMBERSHIP_V1: u8 = 1;

/// The signed portion of a v1 membership: every field except `sig`. Serialized
/// to canonical JSON to produce the exact bytes the root signs and a verifier
/// recomputes. Field order here is irrelevant — `canonical_bytes` sorts keys.
#[derive(Serialize)]
struct MembershipBody<'a> {
    version: u8,
    fabric: &'a NodeId,
    member: &'a NodeId,
    issued: i64,
    not_after: i64,
    alg: &'a AlgorithmId,
}

/// A fabric-root-signed proof that `member` belongs to `fabric`.
///
/// Non-transferable: a responder accepts it only when the iroh-authenticated
/// caller equals `member` (see [`crate::policy::check_inclusion`]).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Membership {
    /// Format version; `= MEMBERSHIP_V1`. A *signed* discriminant.
    pub version: u8,
    /// The fabric root's public key — the authority. A *signed* field, pinned by
    /// [`verify`](Self::verify) against the responder's trusted root.
    pub fabric: NodeId,
    /// The included node (non-transferable).
    pub member: NodeId,
    /// Mint time, unix seconds.
    pub issued: i64,
    /// Expiry, unix seconds (inclusive).
    pub not_after: i64,
    /// Which scheme `sig` was produced with.
    pub alg: AlgorithmId,
    /// Fabric-root signature over the canonical-JSON membership body.
    pub sig: Signature,
}

impl Membership {
    /// Mint a membership: the fabric `root` signs the canonical body binding
    /// `member` to its own fabric id (`root.node_id()`) until `not_after`.
    ///
    /// ```
    /// use library::{Membership, NodeIdentity};
    /// let root = NodeIdentity::from_seed([1u8; 32]);
    /// let member = NodeIdentity::from_seed([2u8; 32]);
    /// let m = Membership::mint(&root, member.node_id(), 0, i64::MAX).unwrap();
    /// assert!(m.verify(root.node_id()).is_ok());
    /// // A different root does not verify it.
    /// assert!(m.verify(member.node_id()).is_err());
    /// ```
    pub fn mint(
        root: &NodeIdentity,
        member: NodeId,
        issued: i64,
        not_after: i64,
    ) -> Result<Membership> {
        let alg = AlgorithmId::Ed25519;
        let fabric = root.node_id();
        let body = MembershipBody {
            version: MEMBERSHIP_V1,
            fabric: &fabric,
            member: &member,
            issued,
            not_after,
            alg: &alg,
        };
        let sig = root.sign(&canonical_bytes(&body)?);
        Ok(Membership {
            version: MEMBERSHIP_V1,
            fabric,
            member,
            issued,
            not_after,
            alg,
            sig,
        })
    }

    /// Verify this membership was signed by `fabric_root` and is for that fabric.
    ///
    /// Checks the algorithm is supported, the version is understood, the
    /// `fabric == fabric_root` pin holds, and the signature covers the canonical
    /// body. Does **not** check `member == caller`, TTL, or revocation — that is
    /// [`crate::policy::check_inclusion`].
    pub fn verify(&self, fabric_root: NodeId) -> Result<()> {
        if self.alg != AlgorithmId::Ed25519 {
            return Err(Error::UnsupportedAlgorithm);
        }
        if self.version != MEMBERSHIP_V1 {
            return Err(Error::UnsupportedVersion);
        }
        // The credential names its own authority; refuse to check it against any
        // root but the one it claims (and the one the responder trusts).
        if self.fabric != fabric_root {
            return Err(Error::InvalidSignature);
        }
        let body = MembershipBody {
            version: self.version,
            fabric: &self.fabric,
            member: &self.member,
            issued: self.issued,
            not_after: self.not_after,
            alg: &self.alg,
        };
        fabric_root.verify(&canonical_bytes(&body)?, &self.sig)
    }

    /// Encode to the base64url (no-pad) text form — a single copy-pasteable
    /// token. The fabric id is recoverable from the decoded credential.
    ///
    /// ```
    /// use library::{Membership, NodeIdentity};
    /// let root = NodeIdentity::from_seed([1u8; 32]);
    /// let member = NodeIdentity::from_seed([2u8; 32]).node_id();
    /// let m = Membership::mint(&root, member, 0, i64::MAX).unwrap();
    /// assert_eq!(Membership::decode(&m.encode().unwrap()).unwrap(), m);
    /// ```
    pub fn encode(&self) -> Result<String> {
        Ok(B64.encode(canonical_bytes(self)?))
    }

    /// Decode from the base64url (no-pad) text form.
    pub fn decode(text: &str) -> Result<Membership> {
        let bytes = B64.decode(text)?;
        serde_json::from_slice(&bytes).map_err(Error::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn seed() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    proptest! {
        /// A freshly minted membership verifies under the minting root and names
        /// that root as its fabric.
        #[test]
        fn mint_then_verify_ok(rs in seed(), ms in seed(), issued in any::<i64>(), not_after in any::<i64>()) {
            let root = NodeIdentity::from_seed(rs);
            let member = NodeIdentity::from_seed(ms).node_id();
            let m = Membership::mint(&root, member, issued, not_after).unwrap();
            prop_assert_eq!(m.fabric, root.node_id());
            prop_assert_eq!(m.member, member);
            prop_assert!(m.verify(root.node_id()).is_ok());
        }

        /// Tampering with any signed field breaks verification. `member`,
        /// `fabric`, `issued`, and `not_after` surface as `InvalidSignature`
        /// (the `fabric` rewrite trips the pin first, also `InvalidSignature`).
        #[test]
        fn tampered_field_fails(rs in seed(), ms in seed(), os in seed(), issued in any::<i64>(), not_after in any::<i64>()) {
            prop_assume!(rs != os && ms != os);
            let root = NodeIdentity::from_seed(rs);
            let member = NodeIdentity::from_seed(ms).node_id();
            let other = NodeIdentity::from_seed(os).node_id();

            let base = Membership::mint(&root, member, issued, not_after).unwrap();

            let mut tampered_member = base.clone();
            tampered_member.member = other;
            prop_assert!(matches!(tampered_member.verify(root.node_id()), Err(Error::InvalidSignature)));

            let mut tampered_issued = base.clone();
            tampered_issued.issued = issued.wrapping_add(1);
            prop_assert!(matches!(tampered_issued.verify(root.node_id()), Err(Error::InvalidSignature)));

            let mut tampered_expiry = base.clone();
            tampered_expiry.not_after = not_after.wrapping_add(1);
            prop_assert!(matches!(tampered_expiry.verify(root.node_id()), Err(Error::InvalidSignature)));
        }

        /// A membership does not verify under a different root key, and rewriting
        /// `fabric` (unsigned) to another key fails the pin — locking the
        /// `fabric == fabric_root` invariant.
        #[test]
        fn fabric_pin_holds(rs in seed(), ms in seed(), os in seed(), not_after in any::<i64>()) {
            prop_assume!(rs != os);
            let root = NodeIdentity::from_seed(rs);
            let other = NodeIdentity::from_seed(os).node_id();
            let member = NodeIdentity::from_seed(ms).node_id();
            let m = Membership::mint(&root, member, 0, not_after).unwrap();

            // Verifying against a root the credential does not name fails.
            prop_assert!(matches!(m.verify(other), Err(Error::InvalidSignature)));

            // Rewriting `fabric` to `other` and verifying against `other` still
            // fails — the signature was over the original fabric.
            let mut rewritten = m.clone();
            rewritten.fabric = other;
            prop_assert!(rewritten.verify(other).is_err());
        }

        /// An encode/decode round-trip is the identity.
        #[test]
        fn encode_decode_roundtrips(rs in seed(), ms in seed(), issued in any::<i64>(), not_after in any::<i64>()) {
            let root = NodeIdentity::from_seed(rs);
            let member = NodeIdentity::from_seed(ms).node_id();
            let m = Membership::mint(&root, member, issued, not_after).unwrap();
            prop_assert_eq!(Membership::decode(&m.encode().unwrap()).unwrap(), m);
        }

        /// Arbitrary text decodes to an `Err`, never a panic.
        #[test]
        fn garbage_decode_never_panics(s in ".*") {
            let _ = Membership::decode(&s);
        }
    }

    /// A future version is rejected outright — locks discriminant dispatch
    /// before any v2 body exists.
    #[test]
    fn future_version_is_unsupported() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let member = NodeIdentity::from_seed([2u8; 32]).node_id();
        let mut m = Membership::mint(&root, member, 0, i64::MAX).unwrap();
        m.version = 2;
        assert!(matches!(
            m.verify(root.node_id()),
            Err(Error::UnsupportedVersion)
        ));
    }

    /// Known-answer: the signed body canonicalizes to exactly these bytes
    /// (sorted keys, compact, `version` as a bare number). Guards the
    /// canonicalization invariant signatures depend on.
    #[test]
    fn body_canonical_bytes_known_answer() {
        let fabric = NodeId::from_bytes([0u8; 32]);
        let member = NodeId::from_bytes([0x11u8; 32]);
        let alg = AlgorithmId::Ed25519;
        let body = MembershipBody {
            version: MEMBERSHIP_V1,
            fabric: &fabric,
            member: &member,
            issued: 1000,
            not_after: 2000,
            alg: &alg,
        };
        let expected = format!(
            r#"{{"alg":"ed25519","fabric":"{}","issued":1000,"member":"{}","not_after":2000,"version":1}}"#,
            "00".repeat(32),
            "11".repeat(32),
        );
        assert_eq!(canonical_bytes(&body).unwrap(), expected.into_bytes());
    }
}

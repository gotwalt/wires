//! The policy head: the root-signed summary every node holds (card 36).
//!
//! A [`PolicyHead`] names the fabric, a monotonic version, its lifetime, the
//! directory nodes, and the Merkle root and count of the policy's items
//! ([`crate::merkle`]). The root signs it ([`SignedPolicyHead`]); every item
//! a node holds is proved against it, so a directory can hand out any subset
//! of the policy without being able to forge or mix one.
//!
//! - **Signed bytes:** [`POLICY_HEAD_CONTEXT`] followed by the canonical JSON
//!   of `{alg, head}`. The context separates it from the state, memberships,
//!   call-log entries and [`Fresh`](crate::Fresh).
//! - **Format:** [`POLICY_V3`], a signed discriminant (the state was 1, and 2
//!   after card 35). Unknown fields are refused at decode.
//! - **Versioning:** as the state's: [`StateVersion`] only goes up, and a node
//!   adopts a head only if it verifies, is fresh and
//!   [is newer](SignedPolicyHead::is_newer_than).
//! - **`directories`** sits in the head, not in an item: every node needs it,
//!   and needs it before it can check any proof.
//!
//! ```
//! use library::{NodeIdentity, Policy, StateVersion};
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let mut policy = Policy::new(root.node_id());
//! policy.version = StateVersion(1);
//! policy.not_after = i64::MAX;
//! let signed = policy.sign(&root).unwrap();
//! signed.head.verify(root.node_id()).unwrap();
//! assert_eq!(signed.head.head.item_count, 1, "just the settings item");
//! ```

use serde::{Deserialize, Serialize};

use crate::codec::{canonical_bytes, hex_id};
use crate::error::{Error, Result};
use crate::identity::{AlgorithmId, NodeId, NodeIdentity, Signature};
use crate::merkle::ItemsRoot;
use crate::state::StateVersion;

/// The policy head format: the third signed-state format.
pub const POLICY_V3: u8 = 3;

/// Domain-separation prefix of a head's signed bytes.
pub const POLICY_HEAD_CONTEXT: &[u8] = b"wires/policy-head/v1\0";

hex_id! {
    /// The blake3 hash of a [`SignedPolicyHead`]'s canonical JSON (signature
    /// included): names one exact head, for [`Fresh`](crate::Fresh) to vouch
    /// for.
    pub struct HeadHash([u8; 32]);
}

/// The content of a policy head. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyHead {
    /// Format discriminant; [`POLICY_V3`]. Signed.
    pub format: u8,
    /// The root's node id: the authority, pinned by
    /// [`SignedPolicyHead::verify`].
    pub fabric: NodeId,
    /// Monotonic version: every admin edit bumps it by one.
    pub version: StateVersion,
    /// When the admin signed it, unix seconds.
    pub issued: i64,
    /// Expiry, unix seconds, inclusive (default 90 days out: the directories'
    /// [`Fresh`](crate::Fresh), not this, keeps copies current).
    pub not_after: i64,
    /// The directory nodes, in the admin's preference order, each once. Their
    /// keys sign [`Fresh`](crate::Fresh).
    pub directories: Vec<NodeId>,
    /// The Merkle root over every item.
    pub items_root: ItemsRoot,
    /// How many items the tree holds (fixes its shape).
    pub item_count: u64,
}

/// A [`PolicyHead`] with the root's signature over it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyHead {
    /// The signed content.
    pub head: PolicyHead,
    /// Which scheme `sig` was produced with.
    pub alg: AlgorithmId,
    /// The root's signature over [`POLICY_HEAD_CONTEXT`] ‖ canonical
    /// `{alg, head}`.
    pub sig: Signature,
}

impl PolicyHead {
    /// Sign as-is with the root key. [`Error::FabricMismatch`] if `root` is
    /// not this head's `fabric`; [`Error::InvalidPolicy`] if a directory is
    /// listed twice. (Heads are normally signed by
    /// [`Policy::sign`](crate::Policy::sign), which also computes the root.)
    pub fn sign(&self, root: &NodeIdentity) -> Result<SignedPolicyHead> {
        if root.node_id() != self.fabric {
            return Err(Error::FabricMismatch);
        }
        self.check_directories()?;
        let alg = AlgorithmId::Ed25519;
        let sig = root.sign(&signed_bytes(self, &alg)?);
        Ok(SignedPolicyHead {
            head: self.clone(),
            alg,
            sig,
        })
    }

    /// [`Error::InvalidPolicy`] if a directory is listed twice.
    fn check_directories(&self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        match self.directories.iter().find(|d| !seen.insert(**d)) {
            Some(d) => Err(Error::InvalidPolicy(format!(
                "directory {} is listed twice",
                d.hex()
            ))),
            None => Ok(()),
        }
    }

    /// Whether `node` is one of the head's directories.
    pub fn is_directory(&self, node: NodeId) -> bool {
        self.directories.contains(&node)
    }
}

impl SignedPolicyHead {
    /// Verify it was signed by `root` for that fabric: algorithm, format, the
    /// `fabric == root` pin, the signature, then that no directory is listed
    /// twice. Does not check freshness ([`check_fresh`](Self::check_fresh)).
    pub fn verify(&self, root: NodeId) -> Result<()> {
        if self.alg != AlgorithmId::Ed25519 {
            return Err(Error::UnsupportedAlgorithm);
        }
        if self.head.format != POLICY_V3 {
            return Err(Error::UnsupportedVersion);
        }
        if self.head.fabric != root {
            return Err(Error::InvalidSignature);
        }
        root.verify(&signed_bytes(&self.head, &self.alg)?, &self.sig)?;
        self.head.check_directories()
    }

    /// [`Error::Expired`] when `now > not_after`.
    pub fn check_fresh(&self, now: i64) -> Result<()> {
        if now > self.head.not_after {
            return Err(Error::Expired {
                not_after: self.head.not_after,
            });
        }
        Ok(())
    }

    /// Whether this head should replace `other`: same fabric and a strictly
    /// higher version. Says nothing about signatures; verify first.
    ///
    /// ```
    /// use library::{NodeIdentity, Policy, StateVersion};
    /// let root = NodeIdentity::from_seed([1u8; 32]);
    /// let mut p = Policy::new(root.node_id());
    /// p.version = StateVersion(1);
    /// let v1 = p.sign(&root).unwrap().head;
    /// p.version = StateVersion(2);
    /// let v2 = p.sign(&root).unwrap().head;
    /// assert!(v2.is_newer_than(&v1));
    /// assert!(!v1.is_newer_than(&v2));
    /// ```
    pub fn is_newer_than(&self, other: &SignedPolicyHead) -> bool {
        self.head.fabric == other.head.fabric && self.head.version > other.head.version
    }

    /// The [`HeadHash`] naming this exact signed head.
    pub fn hash(&self) -> Result<HeadHash> {
        Ok(HeadHash(*blake3::hash(&canonical_bytes(self)?).as_bytes()))
    }
}

/// The signed portion of a [`SignedPolicyHead`].
#[derive(Serialize)]
struct SignedBody<'a> {
    alg: &'a AlgorithmId,
    head: &'a PolicyHead,
}

fn signed_bytes(head: &PolicyHead, alg: &AlgorithmId) -> Result<Vec<u8>> {
    let mut bytes = POLICY_HEAD_CONTEXT.to_vec();
    bytes.extend(canonical_bytes(&SignedBody { alg, head })?);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn root() -> NodeIdentity {
        NodeIdentity::from_seed([1u8; 32])
    }

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    fn sample() -> PolicyHead {
        PolicyHead {
            format: POLICY_V3,
            fabric: root().node_id(),
            version: StateVersion(3),
            issued: 10,
            not_after: 1_000,
            directories: vec![node(2), node(3)],
            items_root: ItemsRoot::from_hex(&"ab".repeat(32)).unwrap(),
            item_count: 7,
        }
    }

    #[test]
    fn sign_verify_round_trip() {
        let signed = sample().sign(&root()).unwrap();
        signed.verify(root().node_id()).unwrap();
        let back: SignedPolicyHead =
            serde_json::from_slice(&canonical_bytes(&signed).unwrap()).unwrap();
        assert_eq!(back, signed);
        back.verify(root().node_id()).unwrap();
        assert!(signed.head.is_directory(node(3)));
        assert!(!signed.head.is_directory(node(4)));
    }

    #[test]
    fn signed_bytes_are_domain_separated() {
        let signed = sample().sign(&root()).unwrap();
        let bytes = signed_bytes(&signed.head, &signed.alg).unwrap();
        assert!(bytes.starts_with(b"wires/policy-head/v1\0{\"alg\":\"ed25519\",\"head\":{"));
        // The same body under the state's context doesn't verify.
        let mut other = crate::state::STATE_CONTEXT.to_vec();
        other.extend_from_slice(&bytes[POLICY_HEAD_CONTEXT.len()..]);
        assert!(root().node_id().verify(&other, &signed.sig).is_err());
    }

    #[test]
    fn wrong_root_and_tampering_are_refused() {
        let signed = sample().sign(&root()).unwrap();
        assert!(signed.verify(node(9)).is_err());
        assert!(matches!(
            sample().sign(&NodeIdentity::from_seed([9u8; 32])),
            Err(Error::FabricMismatch)
        ));
        let tampers: [fn(&mut PolicyHead); 4] = [
            |h| h.item_count += 1,
            |h| {
                h.directories.pop();
            },
            |h| h.not_after += 1,
            |h| h.items_root = ItemsRoot::from_hex(&"cd".repeat(32)).unwrap(),
        ];
        for tamper in tampers {
            let mut t = signed.clone();
            tamper(&mut t.head);
            assert!(
                matches!(t.verify(root().node_id()), Err(Error::InvalidSignature)),
                "{t:?}"
            );
        }
    }

    #[test]
    fn format_and_duplicate_directories_are_refused() {
        let mut h = sample();
        h.format = POLICY_V3 + 1;
        let signed = SignedPolicyHead {
            sig: root().sign(&signed_bytes(&h, &AlgorithmId::Ed25519).unwrap()),
            head: h,
            alg: AlgorithmId::Ed25519,
        };
        assert!(matches!(
            signed.verify(root().node_id()),
            Err(Error::UnsupportedVersion)
        ));

        let mut h = sample();
        h.directories.push(node(2));
        assert!(matches!(h.sign(&root()), Err(Error::InvalidPolicy(_))));
        let signed = SignedPolicyHead {
            sig: root().sign(&signed_bytes(&h, &AlgorithmId::Ed25519).unwrap()),
            head: h,
            alg: AlgorithmId::Ed25519,
        };
        assert!(matches!(
            signed.verify(root().node_id()),
            Err(Error::InvalidPolicy(_))
        ));
    }

    #[test]
    fn freshness_and_ordering() {
        let a = sample().sign(&root()).unwrap();
        let mut h = sample();
        h.version = StateVersion(4);
        let b = h.sign(&root()).unwrap();
        assert!(b.is_newer_than(&a));
        assert!(!a.is_newer_than(&b));
        assert!(!a.is_newer_than(&a));
        assert!(a.check_fresh(1_000).is_ok());
        assert!(matches!(
            a.check_fresh(1_001),
            Err(Error::Expired { not_after: 1_000 })
        ));
        // Another fabric's head is never newer.
        let other = NodeIdentity::from_seed([9u8; 32]);
        let mut h = sample();
        h.fabric = other.node_id();
        h.version = StateVersion(99);
        assert!(!h.sign(&other).unwrap().is_newer_than(&a));
    }

    #[test]
    fn the_hash_names_one_exact_head() {
        let a = sample().sign(&root()).unwrap();
        assert_eq!(a.hash().unwrap(), a.clone().hash().unwrap());
        let mut h = sample();
        h.item_count += 1;
        let b = h.sign(&root()).unwrap();
        assert_ne!(a.hash().unwrap(), b.hash().unwrap());
        assert_eq!(
            a.hash().unwrap().hex(),
            blake3::hash(&canonical_bytes(&a).unwrap())
                .to_hex()
                .as_str()
        );
    }

    #[test]
    fn unknown_fields_are_refused() {
        let signed = sample().sign(&root()).unwrap();
        let mut v = serde_json::to_value(&signed).unwrap();
        v["head"]["members"] = serde_json::json!([]);
        assert!(serde_json::from_value::<SignedPolicyHead>(v).is_err());
    }

    proptest! {
        #[test]
        fn a_changed_version_never_verifies(version in any::<u64>(), other in any::<u64>()) {
            prop_assume!(version != other);
            let mut h = sample();
            h.version = StateVersion(version);
            let mut signed = h.sign(&root()).unwrap();
            signed.head.version = StateVersion(other);
            prop_assert!(signed.verify(root().node_id()).is_err());
        }

        #[test]
        fn any_directory_list_round_trips(seeds in proptest::collection::btree_set(2u8.., 0..8)) {
            let mut h = sample();
            h.directories = seeds.iter().map(|b| node(*b)).collect();
            let signed = h.sign(&root()).unwrap();
            let back: SignedPolicyHead =
                serde_json::from_slice(&canonical_bytes(&signed).unwrap()).unwrap();
            prop_assert!(back.verify(root().node_id()).is_ok());
            prop_assert_eq!(back, signed);
        }
    }
}

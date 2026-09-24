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

use blake3::Hasher;
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
        todo!("PolicyHead::sign {}", root.node_id().hex())
    }

    /// Whether `node` is one of the head's directories.
    pub fn is_directory(&self, node: NodeId) -> bool {
        todo!("PolicyHead::is_directory {}", node.hex())
    }
}

impl SignedPolicyHead {
    /// Verify it was signed by `root` for that fabric: algorithm, format, the
    /// `fabric == root` pin, the signature, then that no directory is listed
    /// twice. Does not check freshness ([`check_fresh`](Self::check_fresh)).
    pub fn verify(&self, root: NodeId) -> Result<()> {
        todo!("SignedPolicyHead::verify {}", root.hex())
    }

    /// [`Error::Expired`] when `now > not_after`.
    pub fn check_fresh(&self, now: i64) -> Result<()> {
        todo!("SignedPolicyHead::check_fresh {now}")
    }

    /// Whether this head should replace `other`: same fabric and a strictly
    /// higher version. Says nothing about signatures; verify first.
    pub fn is_newer_than(&self, other: &SignedPolicyHead) -> bool {
        todo!("SignedPolicyHead::is_newer_than {other:?}")
    }

    /// The [`HeadHash`] naming this exact signed head.
    pub fn hash(&self) -> Result<HeadHash> {
        todo!("SignedPolicyHead::hash")
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
mod tests {}

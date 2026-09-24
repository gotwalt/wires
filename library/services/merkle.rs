//! The Merkle tree over a policy's items: what lets a directory hand out any
//! subset of the policy and each receiver check it against the root-signed
//! head alone.
//!
//! - **Leaves** are the items in [`ItemKey`](crate::ItemKey) order, each
//!   hashed as `blake3(0x00 ‖ canonical JSON of the item)` ([`ItemHash`]).
//! - **Inner nodes** are `blake3(0x01 ‖ left ‖ right)`. The prefixes keep a
//!   leaf from ever passing as an inner node (RFC 6962).
//! - **An odd node at the end of a level is carried up unchanged**, so a tree
//!   of `n` leaves has exactly one shape, fixed by `n`.
//! - **The root** ([`ItemsRoot`]) and the leaf count are what the head signs.
//!   A tree with no leaves has the root `blake3("")` (a signed policy never
//!   has one: it always holds its settings item).
//!
//! An [`InclusionProof`] is the item's leaf index and the sibling hashes from
//! it up to the root. The sides are derived from the index and the head's
//! `item_count`, never sent, so a proof is bound to one position in one tree:
//! an item proved under another head, or at another index, fails.
//!
//! ```
//! use library::{Item, ItemHash, ItemTree, Settings};
//! let items = [Item::Settings { body: Settings::default() }];
//! let leaves: Vec<ItemHash> = items.iter().map(|i| ItemHash::of(i).unwrap()).collect();
//! let tree = ItemTree::new(leaves);
//! let proof = tree.prove(0).unwrap();
//! proof.verify(&items[0], tree.root(), tree.len()).unwrap();
//! ```

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::codec::{B64, canonical_bytes, hex_id};
use crate::error::{Error, Result};
use crate::item::Item;

/// The deepest proof accepted: a tree of up to 2^64 leaves.
pub const MAX_PROOF_DEPTH: usize = 64;

/// Leaf domain-separation byte.
const LEAF_PREFIX: u8 = 0x00;
/// Inner-node domain-separation byte.
const NODE_PREFIX: u8 = 0x01;

hex_id! {
    /// The leaf hash of one [`Item`]: `blake3(0x00 ‖ canonical JSON)`. Names
    /// an item's exact bytes (a directory's store keys items by it).
    pub struct ItemHash([u8; 32]);
}

hex_id! {
    /// The root of a Merkle tree over items (the head's `items_root`), or of
    /// one of its subtrees (a sibling on an [`InclusionProof`]'s path).
    pub struct ItemsRoot([u8; 32]);
}

impl ItemHash {
    /// The leaf hash of `item`.
    pub fn of(item: &Item) -> Result<ItemHash> {
        todo!("ItemHash::of {item:?}")
    }
}

/// The sibling hashes on the path from a leaf to the root, leaf end first.
/// Travels as one base64url string of the concatenated 32-byte hashes (about
/// two thirds the size of a list of hex strings), since proofs are most of a
/// slice's bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProofPath(Vec<ItemsRoot>);

impl ProofPath {
    /// The sibling hashes, leaf end first.
    pub fn hashes(&self) -> &[ItemsRoot] {
        &self.0
    }
}

impl TryFrom<String> for ProofPath {
    type Error = Error;
    /// Decode the base64url string; [`Error::BadLength`] unless it is whole
    /// hashes, at most [`MAX_PROOF_DEPTH`] of them.
    fn try_from(s: String) -> Result<Self> {
        todo!("ProofPath::try_from {s}")
    }
}

impl From<ProofPath> for String {
    fn from(p: ProofPath) -> String {
        todo!("ProofPath into String {p:?}")
    }
}

/// Proof that an item is leaf `index` of the tree a head commits to. Check
/// it with [`verify`](Self::verify) against that head's `items_root` and
/// `item_count`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InclusionProof {
    /// The item's position among the sorted leaves.
    pub index: u64,
    /// The sibling hashes from the leaf up.
    pub path: ProofPath,
}

impl InclusionProof {
    /// Check that `item` is leaf [`index`](Self::index) of the tree with
    /// `root` and `count` leaves; [`Error::BadProof`] if not (a changed item,
    /// a changed or truncated path, an index out of range, or another tree).
    pub fn verify(&self, item: &Item, root: ItemsRoot, count: u64) -> Result<()> {
        todo!("InclusionProof::verify {item:?} {root} {count}")
    }
}

/// A built tree: every level, so proofs are cheap after one `O(n)` build.
#[derive(Clone, Debug)]
pub struct ItemTree {
    /// `levels[0]` is the leaves; the last level is the root alone (empty
    /// when there are no leaves).
    levels: Vec<Vec<ItemsRoot>>,
}

impl ItemTree {
    /// Build the tree over `leaves`, which must already be in
    /// [`ItemKey`](crate::ItemKey) order.
    pub fn new(leaves: Vec<ItemHash>) -> ItemTree {
        todo!("ItemTree::new {}", leaves.len())
    }

    /// The number of leaves.
    pub fn len(&self) -> u64 {
        todo!("ItemTree::len {}", self.levels.len())
    }

    /// Whether the tree has no leaves.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The root hash (`blake3("")` for no leaves).
    pub fn root(&self) -> ItemsRoot {
        todo!("ItemTree::root")
    }

    /// The proof for leaf `index`, or `None` past the last leaf.
    pub fn prove(&self, index: u64) -> Option<InclusionProof> {
        todo!("ItemTree::prove {index}")
    }
}

#[cfg(test)]
mod tests {}

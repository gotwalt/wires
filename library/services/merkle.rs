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
        let mut h = blake3::Hasher::new();
        h.update(&[LEAF_PREFIX]);
        h.update(&canonical_bytes(item)?);
        Ok(ItemHash(*h.finalize().as_bytes()))
    }
}

/// `blake3(0x01 ‖ left ‖ right)`.
fn node_hash(left: &ItemsRoot, right: &ItemsRoot) -> ItemsRoot {
    let mut h = blake3::Hasher::new();
    h.update(&[NODE_PREFIX]);
    h.update(&left.0);
    h.update(&right.0);
    ItemsRoot(*h.finalize().as_bytes())
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
        // Refuse an over-long path before decoding it.
        if s.len() > (32 * MAX_PROOF_DEPTH).div_ceil(3) * 4 {
            return Err(Error::BadLength);
        }
        let bytes = B64.decode(s)?;
        let (chunks, rest) = bytes.as_chunks::<32>();
        if !rest.is_empty() || chunks.len() > MAX_PROOF_DEPTH {
            return Err(Error::BadLength);
        }
        Ok(ProofPath(chunks.iter().copied().map(ItemsRoot).collect()))
    }
}

impl From<ProofPath> for String {
    fn from(p: ProofPath) -> String {
        B64.encode(p.0.iter().flat_map(|h| h.0).collect::<Vec<u8>>())
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
        if self.index >= count {
            return Err(Error::BadProof);
        }
        let mut acc = ItemsRoot(ItemHash::of(item)?.0);
        let mut siblings = self.path.0.iter();
        let (mut i, mut n) = (self.index, count);
        // Walk up the one shape `count` fixes: an odd last node has no
        // sibling and carries up unchanged.
        while n > 1 {
            if i % 2 == 1 {
                acc = node_hash(siblings.next().ok_or(Error::BadProof)?, &acc);
            } else if i + 1 < n {
                acc = node_hash(&acc, siblings.next().ok_or(Error::BadProof)?);
            }
            i /= 2;
            n = n.div_ceil(2);
        }
        if siblings.next().is_some() || acc != root {
            return Err(Error::BadProof);
        }
        Ok(())
    }
}

/// A built tree: every level, so proofs are cheap after one `O(n)` build.
#[derive(Clone, Debug)]
pub struct ItemTree {
    /// `levels[0]` is the leaves; the last level is the root alone (or no
    /// node at all, for no leaves).
    levels: Vec<Vec<ItemsRoot>>,
}

impl ItemTree {
    /// Build the tree over `leaves`, which must already be in
    /// [`ItemKey`](crate::ItemKey) order.
    pub fn new(leaves: Vec<ItemHash>) -> ItemTree {
        let mut levels = vec![
            leaves
                .into_iter()
                .map(|l| ItemsRoot(l.0))
                .collect::<Vec<_>>(),
        ];
        while let Some(level) = levels.last().filter(|l| l.len() > 1) {
            let next = level
                .chunks(2)
                .map(|pair| match pair {
                    [left, right] => node_hash(left, right),
                    [odd] => *odd,
                    _ => unreachable!("chunks(2) yields one or two"),
                })
                .collect();
            levels.push(next);
        }
        ItemTree { levels }
    }

    /// The number of leaves.
    pub fn len(&self) -> u64 {
        self.levels[0].len() as u64
    }

    /// Whether the tree has no leaves.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The root hash (`blake3("")` for no leaves).
    pub fn root(&self) -> ItemsRoot {
        match self.levels.last().and_then(|top| top.first()) {
            Some(root) => *root,
            None => ItemsRoot(*blake3::hash(b"").as_bytes()),
        }
    }

    /// The proof for leaf `index`, or `None` past the last leaf.
    pub fn prove(&self, index: u64) -> Option<InclusionProof> {
        let mut i = usize::try_from(index).ok()?;
        self.levels[0].get(i)?;
        let mut path = Vec::new();
        for level in &self.levels[..self.levels.len() - 1] {
            if let Some(sibling) = level.get(i ^ 1) {
                path.push(*sibling);
            }
            i /= 2;
        }
        Some(InclusionProof {
            index,
            path: ProofPath(path),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use crate::item::Ban;
    use proptest::prelude::*;

    fn ban(b: u8, until: i64) -> Item {
        Item::Ban {
            key: NodeIdentity::from_seed([b; 32]).node_id(),
            body: Ban { until },
        }
    }

    /// `count` distinct items, their leaves, and the tree over them.
    fn tree_of(count: u8) -> (Vec<Item>, ItemTree) {
        let items: Vec<Item> = (0..count).map(|b| ban(b, i64::from(b))).collect();
        let leaves = items.iter().map(|i| ItemHash::of(i).unwrap()).collect();
        (items, ItemTree::new(leaves))
    }

    fn h(bytes: &[&[u8]]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        for b in bytes {
            hasher.update(b);
        }
        *hasher.finalize().as_bytes()
    }

    #[test]
    fn leaf_hash_is_domain_separated_canonical_json() {
        let item = ban(1, 5);
        let want = h(&[&[0], &canonical_bytes(&item).unwrap()]);
        assert_eq!(ItemHash::of(&item).unwrap().0, want);
    }

    #[test]
    fn known_shapes() {
        assert_eq!(
            ItemTree::new(vec![]).root().0,
            *blake3::hash(b"").as_bytes()
        );
        assert!(ItemTree::new(vec![]).is_empty());
        assert_eq!(ItemTree::new(vec![]).prove(0), None);

        let (items, one) = tree_of(1);
        assert_eq!(one.root().0, ItemHash::of(&items[0]).unwrap().0);
        assert_eq!(one.prove(0).unwrap().path.hashes(), &[]);

        // Three leaves: ((0, 1), 2); the odd leaf carries up unchanged.
        let (items, three) = tree_of(3);
        let l: Vec<[u8; 32]> = items.iter().map(|i| ItemHash::of(i).unwrap().0).collect();
        let left = h(&[&[1], &l[0], &l[1]]);
        assert_eq!(three.root().0, h(&[&[1], &left, &l[2]]));
        assert_eq!(three.len(), 3);
        assert_eq!(three.prove(2).unwrap().path.hashes(), &[ItemsRoot(left)]);
        assert_eq!(
            three.prove(0).unwrap().path.hashes(),
            &[ItemsRoot(l[1]), ItemsRoot(l[2])]
        );
        assert_eq!(three.prove(3), None);
    }

    #[test]
    fn a_leaf_does_not_pass_for_an_inner_node() {
        // A two-leaf tree's root is not the leaf hash of the concatenated
        // leaves: the prefixes differ.
        let (items, two) = tree_of(2);
        let l0 = ItemHash::of(&items[0]).unwrap().0;
        let l1 = ItemHash::of(&items[1]).unwrap().0;
        assert_ne!(two.root().0, h(&[&[0], &l0, &l1]));
    }

    #[test]
    fn proof_paths_travel_as_one_base64_string() {
        let (_, tree) = tree_of(5);
        let proof = tree.prove(4).unwrap();
        let text = serde_json::to_string(&proof).unwrap();
        assert!(!text.contains('['), "{text}");
        let back: InclusionProof = serde_json::from_str(&text).unwrap();
        assert_eq!(back, proof);
        assert!(
            ProofPath::try_from("AAAA".to_string()).is_err(),
            "not whole hashes"
        );
        assert!(ProofPath::try_from("!".to_string()).is_err(), "not base64");
        let too_deep = B64.encode(vec![0u8; 32 * (MAX_PROOF_DEPTH + 1)]);
        assert!(ProofPath::try_from(too_deep).is_err());
        assert_eq!(
            ProofPath::try_from(String::new()).unwrap(),
            ProofPath::default()
        );
    }

    #[test]
    fn a_proof_is_bound_to_its_position_and_tree() {
        let (items, tree) = tree_of(6);
        let proof = tree.prove(2).unwrap();
        proof.verify(&items[2], tree.root(), 6).unwrap();
        assert!(matches!(
            proof.verify(&items[3], tree.root(), 6),
            Err(Error::BadProof)
        ));
        let moved = InclusionProof {
            index: 3,
            ..proof.clone()
        };
        assert!(moved.verify(&items[2], tree.root(), 6).is_err());
        // The count fixes the shape (the head signs it with the root): where
        // the shapes differ, so do the paths.
        let fifth = tree.prove(4).unwrap();
        fifth.verify(&items[4], tree.root(), 6).unwrap();
        assert!(fifth.verify(&items[4], tree.root(), 7).is_err());
        assert!(proof.verify(&items[2], tree.root(), 2).is_err());
        let out_of_range = InclusionProof {
            index: 6,
            ..proof.clone()
        };
        assert!(out_of_range.verify(&items[2], tree.root(), 6).is_err());
        let mut longer = proof.clone();
        longer.path.0.push(tree.root());
        assert!(longer.verify(&items[2], tree.root(), 6).is_err());
        let mut shorter = proof;
        shorter.path.0.pop();
        assert!(shorter.verify(&items[2], tree.root(), 6).is_err());
    }

    proptest! {
        #[test]
        fn every_item_proves_and_nothing_else_does(
            count in 1u8..40,
            pick in any::<proptest::sample::Index>(),
            byte in 0usize..32,
            step in any::<proptest::sample::Index>(),
        ) {
            let (items, tree) = tree_of(count);
            let n = tree.len();
            prop_assert_eq!(n, u64::from(count));
            for (i, item) in items.iter().enumerate() {
                let proof = tree.prove(i as u64).unwrap();
                prop_assert!(proof.verify(item, tree.root(), n).is_ok());
            }
            let i = pick.index(items.len());
            let proof = tree.prove(i as u64).unwrap();

            // A tampered item fails.
            let Item::Ban { key, body } = &items[i] else { unreachable!() };
            let tampered = Item::Ban { key: *key, body: Ban { until: body.until + 1 } };
            prop_assert!(proof.verify(&tampered, tree.root(), n).is_err());

            // A tampered path fails.
            if !proof.path.0.is_empty() {
                let mut bad = proof.clone();
                let s = step.index(bad.path.0.len());
                bad.path.0[s].0[byte] ^= 1;
                prop_assert!(bad.verify(&items[i], tree.root(), n).is_err());
            }

            // The same item under another tree (one more leaf) fails.
            let (_, bigger) = tree_of(count + 1);
            prop_assert!(proof.verify(&items[i], bigger.root(), n + 1).is_err());
            prop_assert!(proof.verify(&items[i], bigger.root(), n).is_err());
        }

        #[test]
        fn proof_paths_round_trip(hashes in proptest::collection::vec(any::<[u8; 32]>(), 0..20)) {
            let path = ProofPath(hashes.into_iter().map(ItemsRoot).collect());
            let back = ProofPath::try_from(String::from(path.clone())).unwrap();
            prop_assert_eq!(back, path);
        }

        #[test]
        fn decoding_any_string_never_panics(s in ".{0,200}") {
            let _ = ProofPath::try_from(s);
        }
    }
}

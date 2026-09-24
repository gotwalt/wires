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
        let hashes = decode_hashes(s)?;
        if hashes.len() > MAX_PROOF_DEPTH {
            return Err(Error::BadLength);
        }
        Ok(ProofPath(hashes))
    }
}

impl From<ProofPath> for String {
    fn from(p: ProofPath) -> String {
        encode_hashes(&p.0)
    }
}

/// base64url of the concatenated hashes.
fn encode_hashes(hashes: &[ItemsRoot]) -> String {
    B64.encode(hashes.iter().flat_map(|h| h.0).collect::<Vec<u8>>())
}

/// The inverse of [`encode_hashes`]; [`Error::BadLength`] unless whole
/// hashes.
fn decode_hashes(s: String) -> Result<Vec<ItemsRoot>> {
    let bytes = B64.decode(s)?;
    let (chunks, rest) = bytes.as_chunks::<32>();
    if !rest.is_empty() {
        return Err(Error::BadLength);
    }
    Ok(chunks.iter().copied().map(ItemsRoot).collect())
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
    ///
    /// ```
    /// use library::{Ban, Item, ItemHash, ItemTree, NodeIdentity};
    /// let ban = |b: u8, until| Item::Ban {
    ///     key: NodeIdentity::from_seed([b; 32]).node_id(),
    ///     body: Ban { until },
    /// };
    /// let items = [ban(1, 10), ban(2, 20), ban(3, 30)];
    /// let tree = ItemTree::new(items.iter().map(|i| ItemHash::of(i).unwrap()).collect());
    /// let proof = tree.prove(1).unwrap();
    /// assert!(proof.verify(&items[1], tree.root(), 3).is_ok());
    /// // The same key with another body doesn't prove.
    /// assert!(proof.verify(&ban(2, 99), tree.root(), 3).is_err());
    /// ```
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

/// Sibling hashes of a [`MultiProof`], in the order its check consumes them
/// (level by level from the leaves, left to right). Travels as one base64url
/// string like [`ProofPath`], without its depth cap: the frame limit bounds
/// it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProofHashes(Vec<ItemsRoot>);

impl ProofHashes {
    /// The hashes, in the order they are consumed.
    pub fn hashes(&self) -> &[ItemsRoot] {
        &self.0
    }
}

impl TryFrom<String> for ProofHashes {
    type Error = Error;
    /// Decode the base64url string; [`Error::BadLength`] unless it is whole
    /// hashes.
    fn try_from(s: String) -> Result<Self> {
        Ok(ProofHashes(decode_hashes(s)?))
    }
}

impl From<ProofHashes> for String {
    fn from(p: ProofHashes) -> String {
        encode_hashes(&p.0)
    }
}

/// A run of consecutive leaves: `start`, `start + 1`, … `start + len - 1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafRange {
    /// The first leaf's index.
    pub start: u64,
    /// How many leaves (at least one).
    pub len: u64,
}

/// One proof for a set of leaves under one root: which leaves (as ascending,
/// non-touching [`LeafRange`]s, so a contiguous run like a fabric's bans
/// costs one entry) and the sibling hashes the set doesn't determine itself,
/// each sent once. A contiguous run of `k` leaves costs about `2·log n`
/// hashes; `k` scattered leaves about `k·(log n − log k)`.
///
/// Like an [`InclusionProof`], it is bound to positions in one tree: the
/// sides come from the indices and the head's `item_count`.
///
/// ```
/// use library::{Ban, Item, ItemHash, ItemTree, LeafRange, NodeIdentity};
/// let items: Vec<Item> = (0..100u8)
///     .map(|b| Item::Ban {
///         key: NodeIdentity::from_seed([b; 32]).node_id(),
///         body: Ban { until: 0 },
///     })
///     .collect();
/// let tree = ItemTree::new(items.iter().map(|i| ItemHash::of(i).unwrap()).collect());
/// // Forty consecutive leaves: one range, a handful of hashes.
/// let proof = tree.prove_many(&(40..80).collect::<Vec<_>>()).unwrap();
/// assert_eq!(proof.leaves, vec![LeafRange { start: 40, len: 40 }]);
/// assert!(proof.hashes.hashes().len() <= 2 * 7);
/// proof.verify_items(&items[40..80], tree.root(), 100).unwrap();
/// // Another set of items doesn't prove.
/// assert!(proof.verify_items(&items[41..81], tree.root(), 100).is_err());
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiProof {
    /// The proved leaves' indices.
    pub leaves: Vec<LeafRange>,
    /// The sibling hashes.
    pub hashes: ProofHashes,
}

impl MultiProof {
    /// The proved indices, ascending. [`Error::BadProof`] if the ranges are
    /// empty, out of order, touching or overlapping, or name more than
    /// `count` leaves (checked before anything is expanded).
    pub fn indices(&self, count: u64) -> Result<Vec<u64>> {
        let mut next = 0u64; // the lowest start the next range may have
        let mut total = 0u64;
        for (k, r) in self.leaves.iter().enumerate() {
            let end = r.start.checked_add(r.len).ok_or(Error::BadProof)?;
            if r.len == 0 || end > count || (k > 0 && r.start < next) {
                return Err(Error::BadProof);
            }
            // A gap of at least one leaf, so each set has one encoding.
            next = end + 1;
            total += r.len;
        }
        // `total <= count`, which the signed head bounds.
        let mut out = Vec::with_capacity(usize::try_from(total).map_err(|_| Error::BadProof)?);
        for r in &self.leaves {
            out.extend(r.start..r.start + r.len);
        }
        Ok(out)
    }

    /// Check that `leaves` (one hash per proved index, in index order) are
    /// exactly those leaves of the tree with `root` and `count` leaves.
    /// [`Error::BadProof`] otherwise: a changed leaf, a changed, missing or
    /// extra hash, another root or count, or a leaf count that doesn't match
    /// the ranges. No leaves and no hashes proves nothing and passes.
    pub fn verify(&self, leaves: &[ItemHash], root: ItemsRoot, count: u64) -> Result<()> {
        let total: u64 = self
            .leaves
            .iter()
            .map(|r| r.len)
            .fold(0, u64::saturating_add);
        if total != leaves.len() as u64 {
            return Err(Error::BadProof);
        }
        let indices = self.indices(count)?;
        if indices.is_empty() {
            return match self.hashes.0.is_empty() {
                true => Ok(()),
                false => Err(Error::BadProof),
            };
        }
        let known = indices
            .into_iter()
            .zip(leaves.iter().map(|l| ItemsRoot(l.0)))
            .collect();
        let mut hashes = self.hashes.0.iter().copied();
        let got = walk(known, count, |_, _| hashes.next()).ok_or(Error::BadProof)?;
        if hashes.next().is_some() || got != root {
            return Err(Error::BadProof);
        }
        Ok(())
    }

    /// [`verify`](Self::verify) over the items' leaf hashes.
    pub fn verify_items<'a>(
        &self,
        items: impl IntoIterator<Item = &'a Item>,
        root: ItemsRoot,
        count: u64,
    ) -> Result<()> {
        let leaves = items
            .into_iter()
            .map(ItemHash::of)
            .collect::<Result<Vec<_>>>()?;
        self.verify(&leaves, root, count)
    }
}

/// Compute the root from `known` nodes (ascending leaf indices with their
/// hashes; not empty) of a tree of `count` leaves, asking `sibling(level,
/// index)` for each node the known ones don't determine, level by level from
/// the leaves, left to right: the order a [`MultiProof`] carries them in.
/// `None` when `sibling` has none to give.
fn walk(
    mut known: Vec<(u64, ItemsRoot)>,
    count: u64,
    mut sibling: impl FnMut(usize, u64) -> Option<ItemsRoot>,
) -> Option<ItemsRoot> {
    let (mut level, mut n) = (0, count);
    while n > 1 {
        let mut next = Vec::with_capacity(known.len().div_ceil(2));
        let mut k = 0;
        while k < known.len() {
            let (i, h) = known[k];
            let parent = if i % 2 == 1 {
                node_hash(&sibling(level, i - 1)?, &h)
            } else if i + 1 == n {
                h // the odd last node carries up
            } else if known.get(k + 1).is_some_and(|(j, _)| *j == i + 1) {
                k += 1;
                node_hash(&h, &known[k].1)
            } else {
                node_hash(&h, &sibling(level, i + 1)?)
            };
            next.push((i / 2, parent));
            k += 1;
        }
        known = next;
        n = n.div_ceil(2);
        level += 1;
    }
    known.first().map(|(_, h)| *h)
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

    /// One [`MultiProof`] for the leaves at `indices`, which must be strictly
    /// ascending and in range (else `None`). Each sibling hash is sent once,
    /// and none that the proved leaves themselves determine.
    pub fn prove_many(&self, indices: &[u64]) -> Option<MultiProof> {
        if indices.windows(2).any(|w| w[0] >= w[1]) {
            return None;
        }
        let known = indices
            .iter()
            .map(|i| Some((*i, *self.levels[0].get(usize::try_from(*i).ok()?)?)))
            .collect::<Option<Vec<_>>>()?;
        let mut leaves: Vec<LeafRange> = Vec::new();
        for &i in indices {
            match leaves.last_mut() {
                Some(r) if r.start + r.len == i => r.len += 1,
                _ => leaves.push(LeafRange { start: i, len: 1 }),
            }
        }
        let mut hashes = Vec::new();
        if !known.is_empty() {
            walk(known, self.len(), |level, index| {
                let h = self.levels[level][usize::try_from(index).ok()?];
                hashes.push(h);
                Some(h)
            })?;
        }
        Some(MultiProof {
            leaves,
            hashes: ProofHashes(hashes),
        })
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
        // Built once: key derivation and hashing dominate the proptests.
        static ALL: std::sync::OnceLock<Vec<(Item, ItemHash)>> = std::sync::OnceLock::new();
        let all = ALL.get_or_init(|| {
            (0..=u8::MAX)
                .map(|b| {
                    let item = ban(b, i64::from(b));
                    let hash = ItemHash::of(&item).unwrap();
                    (item, hash)
                })
                .collect()
        });
        let some = &all[..usize::from(count)];
        let items = some.iter().map(|(i, _)| i.clone()).collect();
        let leaves = some.iter().map(|(_, h)| *h).collect();
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
            let _ = ProofPath::try_from(s.clone());
            let _ = ProofHashes::try_from(s);
        }

        /// Every subset proves; its verdict on a mix of genuine and
        /// tampered items equals the individual proofs' verdicts.
        #[test]
        fn every_subset_proves_and_agrees_with_single_proofs(
            count in 1u8..120,
            chosen in proptest::collection::vec(any::<bool>(), 120),
            tamper in proptest::collection::vec(any::<bool>(), 120),
        ) {
            let (items, tree) = tree_of(count);
            let n = tree.len();
            let indices: Vec<u64> = (0..n).filter(|i| chosen[*i as usize]).collect();
            let proof = tree.prove_many(&indices).unwrap();
            prop_assert_eq!(proof.indices(n).unwrap(), indices.clone());
            let genuine: Vec<&Item> = indices.iter().map(|i| &items[*i as usize]).collect();
            prop_assert!(proof.verify_items(genuine, tree.root(), n).is_ok());

            let candidates: Vec<Item> = indices
                .iter()
                .map(|i| {
                    let item = items[*i as usize].clone();
                    if tamper[*i as usize] { bumped(&item) } else { item }
                })
                .collect();
            let singles = indices.iter().zip(&candidates).all(|(i, item)| {
                tree.prove(*i).unwrap().verify(item, tree.root(), n).is_ok()
            });
            prop_assert_eq!(proof.verify_items(&candidates, tree.root(), n).is_ok(), singles);
        }

        #[test]
        fn a_tampered_multiproof_or_another_tree_fails(
            count in 2u8..100,
            chosen in proptest::collection::vec(any::<bool>(), 100),
            at in any::<proptest::sample::Index>(),
            byte in 0usize..32,
        ) {
            let (items, tree) = tree_of(count);
            let n = tree.len();
            let mut indices: Vec<u64> = (0..n).filter(|i| chosen[*i as usize]).collect();
            if indices.is_empty() {
                indices.push(0);
            }
            let leaves: Vec<ItemHash> =
                indices.iter().map(|i| ItemHash::of(&items[*i as usize]).unwrap()).collect();
            let proof = tree.prove_many(&indices).unwrap();

            if !proof.hashes.0.is_empty() {
                let mut bad = proof.clone();
                let k = at.index(bad.hashes.0.len());
                bad.hashes.0[k].0[byte] ^= 1;
                prop_assert!(bad.verify(&leaves, tree.root(), n).is_err());
                let mut short = proof.clone();
                short.hashes.0.pop();
                prop_assert!(short.verify(&leaves, tree.root(), n).is_err());
            }
            let mut long = proof.clone();
            long.hashes.0.push(tree.root());
            prop_assert!(long.verify(&leaves, tree.root(), n).is_err());

            // Another tree's root (one more leaf) fails.
            let (_, bigger) = tree_of(count + 1);
            prop_assert!(proof.verify(&leaves, bigger.root(), n).is_err());
            prop_assert!(proof.verify(&leaves, bigger.root(), n + 1).is_err());

            // One leaf too few or too many for the ranges fails.
            prop_assert!(proof.verify(&leaves[1..], tree.root(), n).is_err());
            let mut more = leaves.clone();
            more.push(leaves[0]);
            prop_assert!(proof.verify(&more, tree.root(), n).is_err());
        }

        /// A contiguous run costs at most about two paths.
        #[test]
        fn a_run_costs_about_two_paths(count in 1u8..=255, a in any::<u8>(), b in any::<u8>()) {
            let (_, tree) = tree_of(count);
            let n = tree.len();
            let (lo, hi) = (u64::from(a.min(b)) % n, u64::from(a.max(b)) % n);
            let (lo, hi) = (lo.min(hi), lo.max(hi));
            let proof = tree.prove_many(&(lo..=hi).collect::<Vec<_>>()).unwrap();
            prop_assert_eq!(proof.leaves.len(), 1);
            let depth = 64 - (n - 1).leading_zeros() as usize;
            prop_assert!(proof.hashes.0.len() <= 2 * depth, "{} > 2·{depth}", proof.hashes.0.len());
        }

        #[test]
        fn multiproofs_round_trip(count in 1u8..60, chosen in proptest::collection::vec(any::<bool>(), 60)) {
            let (_, tree) = tree_of(count);
            let indices: Vec<u64> = (0..tree.len()).filter(|i| chosen[*i as usize]).collect();
            let proof = tree.prove_many(&indices).unwrap();
            let back: MultiProof = serde_json::from_str(&serde_json::to_string(&proof).unwrap()).unwrap();
            prop_assert_eq!(back, proof);
        }
    }

    /// The same ban, one second longer.
    fn bumped(item: &Item) -> Item {
        let Item::Ban { key, body } = item else {
            unreachable!()
        };
        Item::Ban {
            key: *key,
            body: Ban {
                until: body.until + 1,
            },
        }
    }

    #[test]
    fn multiproof_known_shapes() {
        let (items, tree) = tree_of(3);
        let l: Vec<ItemsRoot> = items
            .iter()
            .map(|i| ItemsRoot(ItemHash::of(i).unwrap().0))
            .collect();
        // Leaves 0 and 1 determine their parent; only leaf 2 is sent.
        let proof = tree.prove_many(&[0, 1]).unwrap();
        assert_eq!(proof.leaves, vec![LeafRange { start: 0, len: 2 }]);
        assert_eq!(proof.hashes.hashes(), &[l[2]]);
        // Leaves 0 and 2: leaf 1, then nothing (0-1's parent and 2 are known).
        let proof = tree.prove_many(&[0, 2]).unwrap();
        assert_eq!(
            proof.leaves,
            vec![
                LeafRange { start: 0, len: 1 },
                LeafRange { start: 2, len: 1 }
            ]
        );
        assert_eq!(proof.hashes.hashes(), &[l[1]]);
        // All leaves: no hashes at all.
        let all = tree.prove_many(&[0, 1, 2]).unwrap();
        assert!(all.hashes.hashes().is_empty());
        all.verify_items(&items, tree.root(), 3).unwrap();
        // A single leaf is its inclusion proof's path.
        assert_eq!(
            tree.prove_many(&[1]).unwrap().hashes.hashes(),
            tree.prove(1).unwrap().path.hashes()
        );
        // Nothing proves nothing, and passes only with no hashes.
        let none = tree.prove_many(&[]).unwrap();
        assert_eq!(none, MultiProof::default());
        none.verify(&[], tree.root(), 3).unwrap();
        let mut stray = none;
        stray.hashes.0.push(l[0]);
        assert!(stray.verify(&[], tree.root(), 3).is_err());
    }

    #[test]
    fn prove_many_refuses_bad_index_lists() {
        let (_, tree) = tree_of(5);
        assert!(tree.prove_many(&[1, 1]).is_none());
        assert!(tree.prove_many(&[2, 1]).is_none());
        assert!(tree.prove_many(&[5]).is_none());
    }

    #[test]
    fn leaf_ranges_must_be_canonical_and_in_range() {
        let range = |start, len| LeafRange { start, len };
        let proof = |leaves| MultiProof {
            leaves,
            hashes: ProofHashes::default(),
        };
        assert_eq!(
            proof(vec![range(0, 2), range(3, 1)]).indices(4).unwrap(),
            vec![0, 1, 3]
        );
        for bad in [
            vec![range(0, 0)],
            vec![range(0, 2), range(2, 1)], // touching: should be one range
            vec![range(0, 2), range(1, 1)], // overlapping
            vec![range(3, 1), range(0, 1)], // out of order
            vec![range(3, 2)],              // past the last leaf
            vec![range(0, u64::MAX)],       // huge: refused before expanding
            vec![range(u64::MAX, 1)],
        ] {
            assert!(
                matches!(proof(bad.clone()).indices(4), Err(Error::BadProof)),
                "{bad:?}"
            );
        }
        assert!(ProofHashes::try_from("AAAA".to_string()).is_err());
        let (items, tree) = tree_of(4);
        let leaves: Vec<ItemHash> = items.iter().map(|i| ItemHash::of(i).unwrap()).collect();
        let text =
            String::from_utf8(canonical_bytes(&tree.prove_many(&[0, 1, 3]).unwrap()).unwrap())
                .unwrap();
        assert!(text.starts_with(r#"{"hashes":""#), "{text}");
        let back: MultiProof = serde_json::from_str(&text).unwrap();
        back.verify(&[leaves[0], leaves[1], leaves[3]], tree.root(), 4)
            .unwrap();
    }
}

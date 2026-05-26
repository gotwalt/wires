//! The committed roster: a root-signed, versioned commitment to a fabric's
//! member set, so a verifier can decide *"is this node a current member"*
//! offline against a 32-byte head — and revoke fabric-wide by re-signing the
//! head without the departed member.
//!
//! The shape mirrors [`membership`](crate::membership): a private borrowed-field
//! body, sign over [`canonical_bytes`](crate::codec), reuse [`AlgorithmId`].
//! Confidentiality comes from the Merkle root: the [`RosterHead`] is 32 bytes of
//! root plus a signature and timestamps — it reveals neither the size nor the
//! members of the set; an [`InclusionProof`] reveals only its holder's `NodeId`
//! and `O(log n)` sibling hashes.
//!
//! The full member set ([`Roster`]) lives only on the root's machine; this slice
//! distributes the head and each member's proof by file copy (the sealed
//! full-set blob and gossip distribution are deferred — see
//! `docs/committed-roster.md`).

use std::collections::BTreeSet;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::grant::AlgorithmId;
use crate::identity::{NodeId, NodeIdentity, Signature};

/// The base64 alphabet for roster tokens: URL-safe, no padding (matches
/// [`Membership`](crate::Membership)).
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The current (and only) roster-head format version.
pub const ROSTER_HEAD_V1: u8 = 1;

/// Merkle leaf domain-separation prefix (RFC 6962 style): `blake3(0x00 || …)`.
const LEAF_PREFIX: u8 = 0x00;
/// Merkle internal-node domain-separation prefix: `blake3(0x01 || …)`.
const NODE_PREFIX: u8 = 0x01;

/// A 32-byte blake3 digest: the Merkle root over a member set, and (within an
/// [`InclusionProof`]) each sibling subtree's root. Serializes as lowercase hex,
/// like [`NodeId`], so `canonical_bytes` stays deterministic.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MerkleRoot([u8; 32]);

impl MerkleRoot {
    /// Wrap raw digest bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw 32 digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase-hex rendering of the digest.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl Serialize for MerkleRoot {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for MerkleRoot {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("MerkleRoot expects 32 bytes"))?;
        Ok(MerkleRoot(arr))
    }
}

/// A monotonic roster version. A verifier that has seen `V` rejects `V-1`
/// (enforcement lands once heads arrive over gossip — slice (c)); here it binds a
/// proof to the head it was issued against.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct RosterVersion(pub u64);

/// Which side of a Merkle parent a sibling sits on.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    /// The sibling is the left child; the proven node is the right child.
    Left,
    /// The sibling is the right child; the proven node is the left child.
    Right,
}

/// One step on a Merkle path: a sibling subtree's root hash and its side.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct MerkleStep {
    /// The sibling subtree's root hash.
    pub hash: MerkleRoot,
    /// Which side of the parent the sibling sits on.
    pub side: Side,
}

/// A member's proof that its `NodeId` is a leaf under a given head. Bound to
/// `version` so a verifier rejects a path issued against a different head.
/// Reveals only the member's own `NodeId` and `O(log n)` sibling hashes — never
/// another member's identity.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct InclusionProof {
    /// The member this path proves inclusion for (non-transferable).
    pub member: NodeId,
    /// The roster version this path was issued against.
    pub version: RosterVersion,
    /// The sibling hashes from the member's leaf up to the root.
    pub path: Vec<MerkleStep>,
}

/// The signed portion of a v1 roster head: every field but `sig`. Field order
/// here is irrelevant — `canonical_bytes` sorts keys.
#[derive(Serialize)]
struct RosterHeadBody<'a> {
    format: u8,
    fabric: &'a NodeId,
    version: u64,
    root: &'a MerkleRoot,
    issued: i64,
    not_after: i64,
    alg: &'a AlgorithmId,
}

/// A fabric-root-signed commitment to the member set at a point in time.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RosterHead {
    /// Format discriminant; `= ROSTER_HEAD_V1`. A *signed* field.
    pub format: u8,
    /// The fabric root's public key — the authority. A *signed* field, pinned by
    /// [`verify`](Self::verify).
    pub fabric: NodeId,
    /// Monotonic content counter; verifiers adopt the highest they see.
    pub version: RosterVersion,
    /// Merkle root over the sorted member set.
    pub root: MerkleRoot,
    /// Commit time, unix seconds.
    pub issued: i64,
    /// Expiry, unix seconds (inclusive) — stale heads self-expire.
    pub not_after: i64,
    /// Which scheme `sig` was produced with.
    pub alg: AlgorithmId,
    /// Fabric-root signature over the canonical-JSON [`RosterHeadBody`].
    pub sig: Signature,
}

/// The root's authoritative member set — the source of truth behind every head.
/// Lives only on the root's machine (keystore `roster.json`, mode `0600`); it is
/// never published in the clear.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Roster {
    /// The fabric this roster commits to (the root's node id).
    pub fabric: NodeId,
    /// The last committed version (the next `commit` follows it).
    pub version: RosterVersion,
    /// The member set, ordered by `NodeId` bytes.
    pub members: BTreeSet<NodeId>,
}

/// `blake3(0x00 || member bytes)` — the domain-separated leaf hash.
fn leaf_hash(member: &NodeId) -> MerkleRoot {
    let mut h = blake3::Hasher::new();
    h.update(&[LEAF_PREFIX]);
    h.update(member.as_bytes());
    MerkleRoot(*h.finalize().as_bytes())
}

/// `blake3(0x01 || left || right)` — the domain-separated internal-node hash.
fn node_hash(left: &MerkleRoot, right: &MerkleRoot) -> MerkleRoot {
    let mut h = blake3::Hasher::new();
    h.update(&[NODE_PREFIX]);
    h.update(&left.0);
    h.update(&right.0);
    MerkleRoot(*h.finalize().as_bytes())
}

/// The Merkle root of the empty set: a fixed sentinel, `blake3` of empty input.
fn empty_root() -> MerkleRoot {
    MerkleRoot(*blake3::hash(&[]).as_bytes())
}

/// Build the tree levels bottom-up from `leaves` (level 0 = the leaves). An odd
/// node at any level carries up unchanged (the CT rule). `leaves` must be the
/// leaf hashes of the *sorted* member set. Returns `None` for an empty set.
fn build_levels(leaves: Vec<MerkleRoot>) -> Option<Vec<Vec<MerkleRoot>>> {
    if leaves.is_empty() {
        return None;
    }
    let mut levels = vec![leaves];
    while levels.last().expect("non-empty").len() > 1 {
        let cur = levels.last().expect("non-empty");
        let mut next = Vec::with_capacity(cur.len().div_ceil(2));
        let mut i = 0;
        while i < cur.len() {
            if i + 1 < cur.len() {
                next.push(node_hash(&cur[i], &cur[i + 1]));
                i += 2;
            } else {
                next.push(cur[i]); // odd node carries up unchanged
                i += 1;
            }
        }
        levels.push(next);
    }
    Some(levels)
}

impl RosterHead {
    /// Verify the head was signed by `fabric_root` for that fabric: algorithm,
    /// the `format` discriminant, the `fabric == fabric_root` pin, and the sig.
    /// Does NOT check freshness or any member — that is
    /// [`crate::policy::check_roster_inclusion`].
    pub fn verify(&self, fabric_root: NodeId) -> Result<()> {
        if self.alg != AlgorithmId::Ed25519 {
            return Err(Error::UnsupportedAlgorithm);
        }
        if self.format != ROSTER_HEAD_V1 {
            return Err(Error::UnsupportedVersion);
        }
        if self.fabric != fabric_root {
            return Err(Error::InvalidSignature);
        }
        let body = RosterHeadBody {
            format: self.format,
            fabric: &self.fabric,
            version: self.version.0,
            root: &self.root,
            issued: self.issued,
            not_after: self.not_after,
            alg: &self.alg,
        };
        fabric_root.verify(&canonical_bytes(&body)?, &self.sig)
    }

    /// base64url-no-pad of `canonical_bytes(self)` — one copy-pasteable head
    /// token. The fabric id is recoverable from the decoded head.
    ///
    /// ```
    /// use library::{NodeIdentity, Roster, RosterHead};
    /// let root = NodeIdentity::from_seed([1u8; 32]);
    /// let mut roster = Roster::new(root.node_id());
    /// roster.insert(NodeIdentity::from_seed([2u8; 32]).node_id());
    /// let (head, _) = roster.commit(&root, 0, i64::MAX).unwrap();
    /// assert_eq!(RosterHead::decode(&head.encode().unwrap()).unwrap(), head);
    /// ```
    pub fn encode(&self) -> Result<String> {
        Ok(B64.encode(canonical_bytes(self)?))
    }

    /// Decode a head from its base64url-no-pad token.
    pub fn decode(text: &str) -> Result<RosterHead> {
        let bytes = B64.decode(text)?;
        serde_json::from_slice(&bytes).map_err(Error::Decode)
    }
}

impl InclusionProof {
    /// Recompute the Merkle root this path implies for `member`. A verifier
    /// compares the result to the `root` in a head it trusts.
    pub fn recompute_root(&self) -> MerkleRoot {
        let mut acc = leaf_hash(&self.member);
        for step in &self.path {
            acc = match step.side {
                Side::Left => node_hash(&step.hash, &acc),
                Side::Right => node_hash(&acc, &step.hash),
            };
        }
        acc
    }

    /// base64url-no-pad of `canonical_bytes(self)`.
    pub fn encode(&self) -> Result<String> {
        Ok(B64.encode(canonical_bytes(self)?))
    }

    /// Decode a proof from its base64url-no-pad token.
    pub fn decode(text: &str) -> Result<InclusionProof> {
        let bytes = B64.decode(text)?;
        serde_json::from_slice(&bytes).map_err(Error::Decode)
    }
}

impl Roster {
    /// A fresh, empty roster for `fabric` at version 0.
    pub fn new(fabric: NodeId) -> Roster {
        Roster {
            fabric,
            version: RosterVersion(0),
            members: BTreeSet::new(),
        }
    }

    /// Add `member`; returns whether the set changed.
    pub fn insert(&mut self, member: NodeId) -> bool {
        self.members.insert(member)
    }

    /// Remove `member`; returns whether the set changed.
    pub fn remove(&mut self, member: &NodeId) -> bool {
        self.members.remove(member)
    }

    /// Whether `member` is in the set.
    pub fn contains(&self, member: &NodeId) -> bool {
        self.members.contains(member)
    }

    /// The current Merkle root over the sorted member set (no signing).
    pub fn root_hash(&self) -> MerkleRoot {
        let leaves: Vec<MerkleRoot> = self.members.iter().map(leaf_hash).collect();
        match build_levels(leaves) {
            None => empty_root(),
            Some(levels) => levels.last().expect("non-empty")[0],
        }
    }

    /// The inclusion path for `member`, or `None` if not a member.
    pub fn proof_for(&self, member: &NodeId) -> Option<InclusionProof> {
        // Position of `member` among the sorted leaves.
        let mut idx = self.members.iter().position(|m| m == member)?;
        let leaves: Vec<MerkleRoot> = self.members.iter().map(leaf_hash).collect();
        let mut path = Vec::new();
        if let Some(levels) = build_levels(leaves) {
            // Walk every level except the root, recording the sibling (if any).
            for level in &levels[..levels.len() - 1] {
                if idx % 2 == 1 {
                    // We are the right child; sibling is on the left.
                    path.push(MerkleStep {
                        hash: level[idx - 1],
                        side: Side::Left,
                    });
                } else if idx + 1 < level.len() {
                    // We are the left child; sibling is on the right.
                    path.push(MerkleStep {
                        hash: level[idx + 1],
                        side: Side::Right,
                    });
                }
                // else: odd node carried up — no sibling at this level.
                idx /= 2;
            }
        }
        Some(InclusionProof {
            member: *member,
            version: self.version,
            path,
        })
    }

    /// Bump `version`, build the tree, sign a head, and emit every member's
    /// fresh proof. The signing key must be the fabric root
    /// (`root.node_id() == self.fabric`), else [`Error::FabricMismatch`].
    ///
    /// ```
    /// use library::{NodeIdentity, Roster};
    /// let root = NodeIdentity::from_seed([1u8; 32]);
    /// let member = NodeIdentity::from_seed([2u8; 32]).node_id();
    /// let mut roster = Roster::new(root.node_id());
    /// roster.insert(member);
    /// let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
    /// assert!(head.verify(root.node_id()).is_ok());
    /// assert_eq!(proofs[0].1.recompute_root(), head.root);
    /// ```
    pub fn commit(
        &mut self,
        root: &NodeIdentity,
        issued: i64,
        not_after: i64,
    ) -> Result<(RosterHead, Vec<(NodeId, InclusionProof)>)> {
        if root.node_id() != self.fabric {
            return Err(Error::FabricMismatch);
        }
        self.version = RosterVersion(self.version.0 + 1);
        let merkle_root = self.root_hash();
        let alg = AlgorithmId::Ed25519;
        let body = RosterHeadBody {
            format: ROSTER_HEAD_V1,
            fabric: &self.fabric,
            version: self.version.0,
            root: &merkle_root,
            issued,
            not_after,
            alg: &alg,
        };
        let sig = root.sign(&canonical_bytes(&body)?);
        let head = RosterHead {
            format: ROSTER_HEAD_V1,
            fabric: self.fabric,
            version: self.version,
            root: merkle_root,
            issued,
            not_after,
            alg,
            sig,
        };
        let proofs = self
            .members
            .iter()
            .map(|m| (*m, self.proof_for(m).expect("member has a proof")))
            .collect();
        Ok((head, proofs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    fn id(b: u8) -> NodeId {
        NodeId::from_bytes([b; 32])
    }

    fn seed() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    proptest! {
        /// Every member's `proof_for` recomputes to the roster root.
        #[test]
        fn member_proof_recomputes_to_root(seeds in proptest::collection::vec(seed(), 1..12)) {
            let mut r = Roster::new(id(0));
            for s in &seeds {
                r.insert(NodeId::from_bytes(*s));
            }
            let root = r.root_hash();
            for m in r.members.clone() {
                let proof = r.proof_for(&m).expect("member has a proof");
                prop_assert_eq!(proof.member, m);
                prop_assert_eq!(proof.recompute_root(), root);
            }
        }

        /// A non-member has no proof, and a hand-built path for it does not
        /// recompute to the root.
        #[test]
        fn non_member_has_no_proof(seeds in proptest::collection::vec(seed(), 1..8), os in seed()) {
            let mut r = Roster::new(id(0));
            for s in &seeds {
                r.insert(NodeId::from_bytes(*s));
            }
            let outsider = NodeId::from_bytes(os);
            prop_assume!(!r.contains(&outsider));
            prop_assert!(r.proof_for(&outsider).is_none());

            // Borrow some member's path but swap in the outsider as the leaf:
            // it must not recompute to the real root.
            let some = *r.members.iter().next().unwrap();
            if let Some(borrowed) = r.proof_for(&some) {
                let forged = InclusionProof {
                    member: outsider,
                    version: borrowed.version,
                    path: borrowed.path,
                };
                prop_assert_ne!(forged.recompute_root(), r.root_hash());
            }
        }
    }

    /// A single member's proof is the empty path (it *is* the root).
    #[test]
    fn single_member_proof_is_empty_path() {
        let mut r = Roster::new(id(0));
        r.insert(id(0x11));
        let proof = r.proof_for(&id(0x11)).unwrap();
        assert!(proof.path.is_empty());
        assert_eq!(proof.recompute_root(), r.root_hash());
    }

    /// The leaf hash is `blake3(0x00 || member)` — pinned against raw blake3.
    #[test]
    fn leaf_hash_is_domain_separated() {
        let m = id(0x11);
        let mut h = blake3::Hasher::new();
        h.update(&[LEAF_PREFIX]);
        h.update(m.as_bytes());
        assert_eq!(leaf_hash(&m).as_bytes(), h.finalize().as_bytes());
    }

    /// The node hash is `blake3(0x01 || left || right)` — pinned against raw blake3.
    #[test]
    fn node_hash_is_domain_separated() {
        let l = MerkleRoot::from_bytes([1u8; 32]);
        let r = MerkleRoot::from_bytes([2u8; 32]);
        let mut h = blake3::Hasher::new();
        h.update(&[NODE_PREFIX]);
        h.update(&[1u8; 32]);
        h.update(&[2u8; 32]);
        assert_eq!(node_hash(&l, &r).as_bytes(), h.finalize().as_bytes());
    }

    /// The leaf and node prefixes differ, so an internal node can never be
    /// passed off as a leaf (second-preimage resistance).
    #[test]
    fn leaf_and_node_prefixes_differ() {
        assert_ne!(LEAF_PREFIX, NODE_PREFIX);
    }

    /// Empty set → the fixed sentinel `blake3(&[])`.
    #[test]
    fn empty_set_root_is_sentinel() {
        let r = Roster::new(id(0));
        assert_eq!(r.root_hash().as_bytes(), blake3::hash(&[]).as_bytes());
    }

    /// One member → its leaf hash (RFC 6962 single-leaf rule).
    #[test]
    fn single_member_root_is_its_leaf() {
        let mut r = Roster::new(id(0));
        r.insert(id(0x11));
        assert_eq!(r.root_hash(), leaf_hash(&id(0x11)));
    }

    /// Two members → `node(leaf(min), leaf(max))`, sorted by bytes regardless of
    /// insertion order.
    #[test]
    fn two_member_root_is_node_of_sorted_leaves() {
        let a = id(0x11);
        let b = id(0x22);
        let expect = node_hash(&leaf_hash(&a), &leaf_hash(&b));

        let mut r1 = Roster::new(id(0));
        r1.insert(a);
        r1.insert(b);
        let mut r2 = Roster::new(id(0));
        r2.insert(b); // reverse insertion order
        r2.insert(a);

        assert_eq!(r1.root_hash(), expect);
        assert_eq!(r2.root_hash(), expect, "root must be order-independent");
    }

    /// Three members → `node(node(leaf(a),leaf(b)), leaf(c))` — the odd node `c`
    /// carries up unchanged (CT rule), with a<b<c by bytes.
    #[test]
    fn three_member_root_carries_odd_node() {
        let a = id(0x01);
        let b = id(0x02);
        let c = id(0x03);
        let expect = node_hash(&node_hash(&leaf_hash(&a), &leaf_hash(&b)), &leaf_hash(&c));

        let mut r = Roster::new(id(0));
        r.insert(c);
        r.insert(a);
        r.insert(b);
        assert_eq!(r.root_hash(), expect);
    }

    proptest! {
        /// `commit` bumps the version, signs a head that verifies under the
        /// root, and emits a proof per member that recomputes to the head root.
        #[test]
        fn commit_then_verify_roundtrips(
            rs in seed(),
            seeds in proptest::collection::vec(seed(), 0..8),
            issued in any::<i64>(),
            not_after in any::<i64>(),
        ) {
            let root = NodeIdentity::from_seed(rs);
            let mut r = Roster::new(root.node_id());
            for s in &seeds {
                r.insert(NodeId::from_bytes(*s));
            }
            let before = r.version;
            let (head, proofs) = r.commit(&root, issued, not_after).unwrap();

            prop_assert_eq!(head.version.0, before.0 + 1);
            prop_assert_eq!(r.version.0, before.0 + 1, "commit persists the bump");
            prop_assert_eq!(head.fabric, root.node_id());
            prop_assert_eq!(head.root, r.root_hash());
            prop_assert!(head.verify(root.node_id()).is_ok());
            prop_assert_eq!(proofs.len(), r.members.len());
            for (m, proof) in proofs {
                prop_assert_eq!(proof.version, head.version);
                prop_assert_eq!(proof.recompute_root(), head.root);
                prop_assert!(r.contains(&m));
            }
        }

        /// A head/proof token survives an encode/decode round-trip.
        #[test]
        fn head_and_proof_encode_decode_roundtrip(
            rs in seed(),
            seeds in proptest::collection::vec(seed(), 1..6),
        ) {
            let root = NodeIdentity::from_seed(rs);
            let mut r = Roster::new(root.node_id());
            for s in &seeds {
                r.insert(NodeId::from_bytes(*s));
            }
            let (head, proofs) = r.commit(&root, 0, i64::MAX).unwrap();
            prop_assert_eq!(RosterHead::decode(&head.encode().unwrap()).unwrap(), head);
            let (_, proof) = &proofs[0];
            prop_assert_eq!(InclusionProof::decode(&proof.encode().unwrap()).unwrap(), proof.clone());
        }

        /// Tampering with any signed head field breaks verification.
        #[test]
        fn tampered_head_fails(rs in seed(), os in seed(), v in any::<u64>()) {
            prop_assume!(rs != os);
            let root = NodeIdentity::from_seed(rs);
            let other = NodeIdentity::from_seed(os).node_id();
            let mut r = Roster::new(root.node_id());
            r.insert(NodeId::from_bytes([7u8; 32]));
            let (head, _) = r.commit(&root, 100, 200).unwrap();

            let mut t = head.clone();
            t.version = RosterVersion(v ^ head.version.0 ^ 0x9e3779b9);
            prop_assert!(t.verify(root.node_id()).is_err());

            let mut t = head.clone();
            t.root = MerkleRoot::from_bytes([0xab; 32]);
            prop_assert!(matches!(t.verify(root.node_id()), Err(Error::InvalidSignature)));

            let mut t = head.clone();
            t.issued = head.issued.wrapping_add(1);
            prop_assert!(matches!(t.verify(root.node_id()), Err(Error::InvalidSignature)));

            let mut t = head.clone();
            t.not_after = head.not_after.wrapping_add(1);
            prop_assert!(matches!(t.verify(root.node_id()), Err(Error::InvalidSignature)));

            // Wrong root → fabric pin trips first (InvalidSignature).
            prop_assert!(matches!(head.verify(other), Err(Error::InvalidSignature)));

            // Rewriting the (unsigned-position) fabric to `other` and verifying
            // against `other` still fails — the sig was over the original fabric.
            let mut t = head.clone();
            t.fabric = other;
            prop_assert!(t.verify(other).is_err());
        }

        /// Arbitrary text decodes to `Err`, never a panic.
        #[test]
        fn garbage_decode_never_panics(s in ".*") {
            let _ = RosterHead::decode(&s);
            let _ = InclusionProof::decode(&s);
        }
    }

    /// `commit` with a signing key that is not the fabric root is a usage error.
    #[test]
    fn commit_requires_the_fabric_root() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let imposter = NodeIdentity::from_seed([2u8; 32]);
        let mut r = Roster::new(root.node_id());
        r.insert(NodeId::from_bytes([9u8; 32]));
        assert!(matches!(r.commit(&imposter, 0, 1), Err(Error::FabricMismatch)));
    }

    /// A future format is rejected outright (locks discriminant dispatch).
    #[test]
    fn future_format_is_unsupported() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut r = Roster::new(root.node_id());
        r.insert(NodeId::from_bytes([3u8; 32]));
        let (mut head, _) = r.commit(&root, 0, i64::MAX).unwrap();
        head.format = 2;
        assert!(matches!(
            head.verify(root.node_id()),
            Err(Error::UnsupportedVersion)
        ));
    }

    /// Known-answer: the signed head body canonicalizes to exactly these bytes
    /// (sorted keys, compact, hex roots). Guards the canonicalization invariant.
    #[test]
    fn head_body_canonical_bytes_known_answer() {
        let fabric = NodeId::from_bytes([0u8; 32]);
        let root = MerkleRoot::from_bytes([0x22u8; 32]);
        let alg = AlgorithmId::Ed25519;
        let body = RosterHeadBody {
            format: ROSTER_HEAD_V1,
            fabric: &fabric,
            version: 7,
            root: &root,
            issued: 1000,
            not_after: 2000,
            alg: &alg,
        };
        let expected = format!(
            r#"{{"alg":"ed25519","fabric":"{}","format":1,"issued":1000,"not_after":2000,"root":"{}","version":7}}"#,
            "00".repeat(32),
            "22".repeat(32),
        );
        assert_eq!(canonical_bytes(&body).unwrap(), expected.into_bytes());
    }
}

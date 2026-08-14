# Committed Roster (slice 2b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a root-signed, versioned Merkle commitment to a fabric's member set (the "committed roster"), so a verifier can decide *"is this node a current member"* offline against a 32-byte head, with mutual-inclusion in ticket-less sessions.

**Architecture:** A new pure `//library` module `roster.rs` (Merkle tree over sorted member NodeIds, blake3, RFC-6962 domain separation) provides `Roster`, `RosterHead`, `InclusionProof`, `MerkleRoot`, `RosterVersion`. `policy.rs` gains `check_roster_inclusion` beside `check_inclusion`. The session handshake gains an optional proof and a new `HandshakeAck` response frame (ALPN bump `/1`→`/2`). The `wires` transport gains a `ServeConfig` bundling the responder's policy + own identity; the dialer verifies the responder's membership in ticket-less mode. A `roster` CLI subcommand authors the set and signs heads; keystore gains three files.

**Tech Stack:** Rust 2024, Bazel-only build/test, `blake3`, `ed25519-dalek`, `serde_json` (canonical JSON), `iroh` 0.98, `tokio`, `proptest`.

**Spec:** `docs/committed-roster.md`. **Vision:** `docs/fabric-vision.md`.

---

## Conventions for every task

- **Build/test are Bazel-only.** Never `cargo build`/`cargo test`. Commands:
  - Library: `bazel test //library/...`
  - Wires: `bazel test //wires/...`
  - Everything: `bazel test //...`
  - A single test: `bazel test //library:library_test --test_arg=roster::tests::NAME` is *not* how rules_rust filters; instead use `bazel test --config=debug //library:library_test` and read the full output, or rely on the whole-target run. Prefer running the whole target.
- **Type-driven order** (per `CLAUDE.md`): types + signatures + docstrings with `todo!("…")` bodies → `proptest` + unit tests (red) → implement (green) → doctests → readability.
- **No bare `[u8; N]`/`Vec<u8>` in public API** — use newtypes. (This plan introduces `MerkleRoot` as the single 32-byte blake3 digest newtype and uses it for sibling hashes too; this is a deliberate, convention-honoring deviation from the spec's literal `[u8; 32]` in `MerkleStep`, and gives the hex-in-JSON the spec's comment asks for.)
- **Signed bodies never use `skip_serializing_if`.** Unsigned wire envelopes may.
- Run `format` and `make lint` before the final commit (Task 16).
- Commit after each task with the message shown.

---

## File structure

| File | Responsibility | This plan |
|---|---|---|
| `library/roster.rs` *(new)* | `Roster`, `RosterHead`, `InclusionProof`, `MerkleRoot`, `RosterVersion`, `Side`, `MerkleStep`, Merkle build/verify, `commit` | Tasks 3–6 |
| `library/policy.rs` | `check_roster_inclusion` beside `check_inclusion` | Task 7 |
| `library/error.rs` | `NotInRoster`, `StaleProof`, `InclusionProofRequired`, `FabricMismatch` | Task 2 |
| `library/identity.rs` | derive `PartialOrd, Ord` on `NodeId` (for `BTreeSet`) | Task 3 |
| `library/lib.rs` | re-export the roster surface | Task 3 |
| `library/session.rs` | `proof` on `Frame::Handshake`; new `Frame::HandshakeAck`; envelope codecs; proptest | Task 8 |
| `wires/transport.rs` | `ServeConfig`; ALPN `/2`; `HandshakeAck` send + dialer-side verify; roster head gate; `WIRES_ROSTER_VERSION` | Tasks 9–10, 14 |
| `wires/keystore.rs` | `roster.json` / `roster-head.json` / `inclusion-proof.json` read/save + resolvers | Task 11 |
| `wires/main.rs` | `roster` subcommand; `serve --roster-head` + own membership/proof; `connect --inclusion-proof` | Tasks 12–13 |
| `library/Cargo.toml`, `Cargo.toml`, `Cargo.lock`, `library/BUILD` | add `blake3` | Task 1 |

---

## Phase 0 — dependency + error scaffolding

### Task 1: Wire the `blake3` dependency

**Why:** `blake3` 1.8.5 is already in `Cargo.lock` (transitive via iroh) but **not** exposed as `@crates//:blake3` (verified: `bazel query @crates//:blake3` fails). It becomes addressable only once declared as a *direct* dependency of a workspace member.

**Files:**
- Modify: `Cargo.toml` (root `[workspace.dependencies]`)
- Modify: `library/Cargo.toml`
- Modify: `library/BUILD`
- Regenerate: `Cargo.lock`

- [ ] **Step 1: Add to root workspace deps.** In `Cargo.toml`, add under `[workspace.dependencies]` (after `rand = "0.8"`):

```toml
blake3 = "1"
```

- [ ] **Step 2: Add to the library crate.** In `library/Cargo.toml`, add under `[dependencies]` (after `rand = { workspace = true }`):

```toml
blake3 = { workspace = true }
```

- [ ] **Step 3: Regenerate the lockfile with the Bazel-vendored cargo** (the only cargo invocation):

Run: `bazel run @rules_rust//tools/upstream_wrapper:cargo -- generate-lockfile`
Expected: `Cargo.lock` updated; `blake3` stays at a `1.x` (currently 1.8.5).

- [ ] **Step 4: Add the dep to `library/BUILD`.** In `_DEPS`, insert (keep alphabetical):

```python
    "@crates//:blake3",
```

so `_DEPS` reads:

```python
_DEPS = [
    "@crates//:base64",
    "@crates//:blake3",
    "@crates//:ed25519-dalek",
    "@crates//:hex",
    "@crates//:rand",
    "@crates//:serde",
    "@crates//:serde_json",
    "@crates//:thiserror",
]
```

- [ ] **Step 5: Verify it resolves and the crate still builds.**

Run: `bazel query @crates//:blake3 && bazel build //library`
Expected: the query prints the target (no "not declared" error); build succeeds.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock library/Cargo.toml library/BUILD
git commit -m "build(library): add blake3 dependency for the roster Merkle tree"
```

---

### Task 2: Add the roster error variants

**Files:**
- Modify: `library/error.rs`

- [ ] **Step 1: Add four variants.** In `library/error.rs`, inside `enum Error`, add before the closing `}` (after the `BadFrame` variant):

```rust
    /// A roster inclusion proof did not recompute to the head's Merkle root —
    /// the presented node is not a member under that head.
    #[error("not a member of the roster")]
    NotInRoster,

    /// An inclusion proof targets a different roster version than the head it
    /// was checked against (the member must refresh its proof against the
    /// current head).
    #[error("stale inclusion proof: proof targets version {proof}, head is version {head}")]
    StaleProof {
        /// The roster version the proof was issued against.
        proof: u64,
        /// The roster version of the head it was checked against.
        head: u64,
    },

    /// A responder configured with a roster head required an inclusion proof in
    /// the handshake, but none was presented.
    #[error("inclusion proof required")]
    InclusionProofRequired,

    /// `Roster::commit` was handed a signing key whose node id is not the
    /// roster's `fabric` — a usage error (the fabric root must sign its own
    /// roster).
    #[error("signing key is not the fabric root")]
    FabricMismatch,
```

- [ ] **Step 2: Verify it still compiles.**

Run: `bazel build //library`
Expected: success (variants are unused yet — that's fine; `enum` arms don't warn).

- [ ] **Step 3: Commit**

```bash
git add library/error.rs
git commit -m "feat(library): add roster error variants"
```

---

## Phase 1 — pure library (`bazel test //library/...`)

### Task 3: `roster.rs` type skeleton + re-exports

Define every type, constant, and function signature with `///` docstrings and `todo!("…")` bodies so the crate compiles. No behavior yet.

**Files:**
- Modify: `library/identity.rs` (derive `Ord` on `NodeId`)
- Create: `library/roster.rs`
- Modify: `library/lib.rs` (module + re-exports)

- [ ] **Step 1: Make `NodeId` orderable** (required for `BTreeSet<NodeId>` and byte-sorted leaves). In `library/identity.rs`, change the `NodeId` derive line from:

```rust
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NodeId([u8; 32]);
```

to:

```rust
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct NodeId([u8; 32]);
```

(Deriving `Ord` on a `[u8; 32]` newtype gives lexicographic byte ordering — exactly "sorted by their bytes".)

- [ ] **Step 2: Create `library/roster.rs` with the full skeleton:**

```rust
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
    todo!("leaf hash")
}

/// `blake3(0x01 || left || right)` — the domain-separated internal-node hash.
fn node_hash(left: &MerkleRoot, right: &MerkleRoot) -> MerkleRoot {
    todo!("node hash")
}

/// The Merkle root of the empty set: a fixed sentinel, `blake3` of empty input.
fn empty_root() -> MerkleRoot {
    todo!("empty sentinel")
}

impl MerkleRoot {
    /// Serialize as a lowercase-hex string (custom, like `NodeId`).
    // (impl in Task 4)
}

impl RosterHead {
    /// Verify the head was signed by `fabric_root` for that fabric: algorithm,
    /// the `format` discriminant, the `fabric == fabric_root` pin, and the sig.
    /// Does NOT check freshness or any member — that is
    /// [`crate::policy::check_roster_inclusion`].
    pub fn verify(&self, fabric_root: NodeId) -> Result<()> {
        todo!("verify head")
    }

    /// base64url-no-pad of `canonical_bytes(self)` — one copy-pasteable head
    /// token. The fabric id is recoverable from the decoded head.
    pub fn encode(&self) -> Result<String> {
        todo!("encode head")
    }

    /// Decode a head from its base64url-no-pad token.
    pub fn decode(text: &str) -> Result<RosterHead> {
        todo!("decode head")
    }
}

impl InclusionProof {
    /// Recompute the Merkle root this path implies for `member`. A verifier
    /// compares the result to the `root` in a head it trusts.
    pub fn recompute_root(&self) -> MerkleRoot {
        todo!("recompute root")
    }

    /// base64url-no-pad of `canonical_bytes(self)`.
    pub fn encode(&self) -> Result<String> {
        todo!("encode proof")
    }

    /// Decode a proof from its base64url-no-pad token.
    pub fn decode(text: &str) -> Result<InclusionProof> {
        todo!("decode proof")
    }
}

impl Roster {
    /// A fresh, empty roster for `fabric` at version 0.
    pub fn new(fabric: NodeId) -> Roster {
        todo!("new roster")
    }

    /// Add `member`; returns whether the set changed.
    pub fn insert(&mut self, member: NodeId) -> bool {
        todo!("insert")
    }

    /// Remove `member`; returns whether the set changed.
    pub fn remove(&mut self, member: &NodeId) -> bool {
        todo!("remove")
    }

    /// Whether `member` is in the set.
    pub fn contains(&self, member: &NodeId) -> bool {
        todo!("contains")
    }

    /// The current Merkle root over the sorted member set (no signing).
    pub fn root_hash(&self) -> MerkleRoot {
        todo!("root hash")
    }

    /// The inclusion path for `member`, or `None` if not a member.
    pub fn proof_for(&self, member: &NodeId) -> Option<InclusionProof> {
        todo!("proof for")
    }

    /// Bump `version`, build the tree, sign a head, and emit every member's
    /// fresh proof. The signing key must be the fabric root
    /// (`root.node_id() == self.fabric`), else [`Error::FabricMismatch`].
    pub fn commit(
        &mut self,
        root: &NodeIdentity,
        issued: i64,
        not_after: i64,
    ) -> Result<(RosterHead, Vec<(NodeId, InclusionProof)>)> {
        todo!("commit")
    }
}
```

- [ ] **Step 3: Add the custom hex serde for `MerkleRoot`** (mirrors `NodeId` in `identity.rs`). Append to `library/roster.rs`:

```rust
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
```

(Remove the empty placeholder `impl MerkleRoot { /// Serialize … }` block from Step 2 — it was only a doc marker.)

- [ ] **Step 4: Wire the module + re-exports** in `library/lib.rs`. Add `pub mod roster;` after `pub mod policy;`:

```rust
pub mod policy;
pub mod roster;
pub mod session;
```

and add the re-export after the `policy` re-export:

```rust
pub use roster::{
    InclusionProof, MerkleRoot, MerkleStep, ROSTER_HEAD_V1, Roster, RosterHead, RosterVersion, Side,
};
```

Also extend the module-layout doc comment list near the top of `lib.rs` (after the `membership` bullet) with:

```rust
//! - [`roster`] — the root-signed, versioned [`Roster`] commitment: the
//!   [`RosterHead`], the Merkle [`InclusionProof`], and offline verification.
```

- [ ] **Step 5: Verify the skeleton compiles** (bodies are `todo!()`, so no tests run yet).

Run: `bazel build //library`
Expected: success. (`todo!()` returns `!`, satisfying every signature.)

- [ ] **Step 6: Commit**

```bash
git add library/identity.rs library/roster.rs library/lib.rs
git commit -m "feat(library): roster.rs type skeleton + NodeId Ord + re-exports"
```

---

### Task 4: Merkle hashing (leaf/node/root) — tests then impl

**Files:**
- Modify: `library/roster.rs` (impl `leaf_hash`, `node_hash`, `empty_root`, `Roster::root_hash`; tests)

- [ ] **Step 1: Write the failing tests.** Append a test module to `library/roster.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> NodeId {
        NodeId::from_bytes([b; 32])
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
}
```

- [ ] **Step 2: Run the tests to verify they fail** (`todo!()` panics).

Run: `bazel test //library:library_test`
Expected: FAIL (panics in `leaf_hash`/`root_hash`).

- [ ] **Step 3: Implement the hashing + tree build.** In `library/roster.rs`, replace the three `todo!()` hashing fns and add a private tree builder; implement `Roster::root_hash`:

```rust
fn leaf_hash(member: &NodeId) -> MerkleRoot {
    let mut h = blake3::Hasher::new();
    h.update(&[LEAF_PREFIX]);
    h.update(member.as_bytes());
    MerkleRoot(*h.finalize().as_bytes())
}

fn node_hash(left: &MerkleRoot, right: &MerkleRoot) -> MerkleRoot {
    let mut h = blake3::Hasher::new();
    h.update(&[NODE_PREFIX]);
    h.update(&left.0);
    h.update(&right.0);
    MerkleRoot(*h.finalize().as_bytes())
}

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
```

Then implement `Roster::root_hash` (replace its `todo!()`):

```rust
    pub fn root_hash(&self) -> MerkleRoot {
        let leaves: Vec<MerkleRoot> = self.members.iter().map(leaf_hash).collect();
        match build_levels(leaves) {
            None => empty_root(),
            Some(levels) => levels.last().expect("non-empty")[0],
        }
    }
```

Also implement the trivial `Roster` constructors/mutators now (needed by the tests above), replacing their `todo!()`s:

```rust
    pub fn new(fabric: NodeId) -> Roster {
        Roster {
            fabric,
            version: RosterVersion(0),
            members: BTreeSet::new(),
        }
    }

    pub fn insert(&mut self, member: NodeId) -> bool {
        self.members.insert(member)
    }

    pub fn remove(&mut self, member: &NodeId) -> bool {
        self.members.remove(member)
    }

    pub fn contains(&self, member: &NodeId) -> bool {
        self.members.contains(member)
    }
```

- [ ] **Step 4: Run the tests to verify they pass.**

Run: `bazel test //library:library_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add library/roster.rs
git commit -m "feat(library): blake3 Merkle hashing + root over sorted member set"
```

---

### Task 5: `proof_for` + `recompute_root` — tests then impl

**Files:**
- Modify: `library/roster.rs`

- [ ] **Step 1: Write the failing tests.** Add to the `tests` module in `library/roster.rs`:

```rust
    use proptest::prelude::*;

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
```

- [ ] **Step 2: Run to verify failure.**

Run: `bazel test //library:library_test`
Expected: FAIL (`proof_for`/`recompute_root` are `todo!()`).

- [ ] **Step 3: Implement `proof_for` and `recompute_root`.** Replace their `todo!()` bodies:

```rust
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
```

```rust
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
```

- [ ] **Step 4: Run to verify pass.**

Run: `bazel test //library:library_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add library/roster.rs
git commit -m "feat(library): Merkle inclusion proof_for + recompute_root"
```

---

### Task 6: `RosterHead` sign/verify, `commit`, encode/decode, canonical-bytes — tests then impl

**Files:**
- Modify: `library/roster.rs`

- [ ] **Step 1: Write the failing tests.** Add to the `tests` module:

```rust
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
        assert!(matches!(
            r.commit(&imposter, 0, 1),
            Err(Error::FabricMismatch)
        ));
    }

    /// A future format is rejected outright (locks discriminant dispatch).
    #[test]
    fn future_format_is_unsupported() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut r = Roster::new(root.node_id());
        r.insert(NodeId::from_bytes([3u8; 32]));
        let (mut head, _) = r.commit(&root, 0, i64::MAX).unwrap();
        head.format = 2;
        assert!(matches!(head.verify(root.node_id()), Err(Error::UnsupportedVersion)));
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
```

- [ ] **Step 2: Run to verify failure.**

Run: `bazel test //library:library_test`
Expected: FAIL (`verify`/`commit`/`encode`/`decode` are `todo!()`).

- [ ] **Step 3: Implement `verify`, `encode`/`decode` (head + proof), and `commit`.** Replace the `todo!()` bodies:

```rust
    // --- RosterHead ---
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

    pub fn encode(&self) -> Result<String> {
        Ok(B64.encode(canonical_bytes(self)?))
    }

    pub fn decode(text: &str) -> Result<RosterHead> {
        let bytes = B64.decode(text)?;
        serde_json::from_slice(&bytes).map_err(Error::Decode)
    }
```

```rust
    // --- InclusionProof ---
    pub fn encode(&self) -> Result<String> {
        Ok(B64.encode(canonical_bytes(self)?))
    }

    pub fn decode(text: &str) -> Result<InclusionProof> {
        let bytes = B64.decode(text)?;
        serde_json::from_slice(&bytes).map_err(Error::Decode)
    }
```

```rust
    // --- Roster::commit ---
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
```

- [ ] **Step 4: Run to verify pass.**

Run: `bazel test //library:library_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add library/roster.rs
git commit -m "feat(library): sign/verify roster head, commit, token codecs"
```

---

### Task 7: `check_roster_inclusion` in `policy.rs` — tests then impl

**Files:**
- Modify: `library/policy.rs`

- [ ] **Step 1: Add the function (with `todo!()`) and its imports.** In `library/policy.rs`, extend the imports at the top:

```rust
use crate::roster::{InclusionProof, RosterHead};
```

and add, after `check_inclusion`:

```rust
/// Decide whether `proof` shows `caller` is a current member under `head`.
///
/// Accepts iff `head` verifies under `fabric_root`, the head is fresh
/// (`now_unix <= not_after`), the proof is for `caller`, it targets this head's
/// version, and the recomputed root matches `head.root`.
///
/// Like [`check_inclusion`], this is **only safe when `caller` is a
/// cryptographically authenticated peer** — the path proves a `NodeId` is in the
/// set; iroh's mutual auth proves the entity on the wire *is* that `NodeId`.
///
/// ```
/// use library::{check_roster_inclusion, NodeIdentity, Roster};
/// let root = NodeIdentity::from_seed([1u8; 32]);
/// let member = NodeIdentity::from_seed([2u8; 32]);
/// let mut roster = Roster::new(root.node_id());
/// roster.insert(member.node_id());
/// let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
/// let (_, proof) = &proofs[0];
/// assert!(check_roster_inclusion(&head, proof, root.node_id(), member.node_id(), 0).is_ok());
/// ```
pub fn check_roster_inclusion(
    head: &RosterHead,
    proof: &InclusionProof,
    fabric_root: NodeId,
    caller: NodeId,
    now_unix: i64,
) -> Result<()> {
    todo!("check roster inclusion")
}
```

- [ ] **Step 2: Write the failing tests.** Add to the `tests` module in `policy.rs`:

```rust
    use crate::roster::Roster;

    fn roster_fixture(not_after: i64) -> (NodeIdentity, NodeId, RosterHead, InclusionProof) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let member = NodeIdentity::from_seed([2u8; 32]);
        let mut roster = Roster::new(root.node_id());
        roster.insert(member.node_id());
        roster.insert(NodeIdentity::from_seed([3u8; 32]).node_id());
        let (head, proofs) = roster.commit(&root, 0, not_after).unwrap();
        let proof = proofs
            .into_iter()
            .find(|(m, _)| *m == member.node_id())
            .unwrap()
            .1;
        (root, member.node_id(), head, proof)
    }

    #[test]
    fn roster_inclusion_accepts_a_current_member() {
        let (root, member, head, proof) = roster_fixture(i64::MAX);
        assert!(check_roster_inclusion(&head, &proof, root.node_id(), member, 0).is_ok());
    }

    #[test]
    fn roster_inclusion_rejects_wrong_caller() {
        let (root, _member, head, proof) = roster_fixture(i64::MAX);
        let other = NodeIdentity::from_seed([9u8; 32]).node_id();
        assert!(matches!(
            check_roster_inclusion(&head, &proof, root.node_id(), other, 0),
            Err(Error::SubjectMismatch)
        ));
    }

    #[test]
    fn roster_inclusion_rejects_expired_head() {
        let (root, member, head, proof) = roster_fixture(100);
        assert!(matches!(
            check_roster_inclusion(&head, &proof, root.node_id(), member, 101),
            Err(Error::Expired { not_after: 100 })
        ));
    }

    #[test]
    fn roster_inclusion_rejects_stale_proof() {
        // Commit again so the head advances to v2; the v1 proof is stale.
        let root = NodeIdentity::from_seed([1u8; 32]);
        let member = NodeIdentity::from_seed([2u8; 32]);
        let mut roster = Roster::new(root.node_id());
        roster.insert(member.node_id());
        let (_v1_head, v1_proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let v1_proof = v1_proofs.into_iter().next().unwrap().1;
        let (v2_head, _) = roster.commit(&root, 0, i64::MAX).unwrap();
        assert!(matches!(
            check_roster_inclusion(&v2_head, &v1_proof, root.node_id(), member.node_id(), 0),
            Err(Error::StaleProof { proof: 1, head: 2 })
        ));
    }

    #[test]
    fn roster_inclusion_rejects_non_member_path() {
        // A removed member's proof, version-matched to the head, recomputes to
        // the wrong root → NotInRoster. (Construct a head whose version matches
        // the proof but whose root differs.)
        let root = NodeIdentity::from_seed([1u8; 32]);
        let member = NodeIdentity::from_seed([2u8; 32]);
        let mut roster = Roster::new(root.node_id());
        roster.insert(member.node_id());
        roster.insert(NodeIdentity::from_seed([5u8; 32]).node_id());
        let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let proof = proofs
            .into_iter()
            .find(|(m, _)| *m == member.node_id())
            .unwrap()
            .1;
        // Forge a head at the same version but a different root.
        let mut bad_head = head.clone();
        // Re-sign so verify() passes but the root no longer matches the proof.
        let mut roster2 = Roster::new(root.node_id());
        roster2.insert(NodeIdentity::from_seed([6u8; 32]).node_id());
        roster2.insert(NodeIdentity::from_seed([7u8; 32]).node_id());
        roster2.version = RosterVersion(0); // so commit bumps to v1 == proof.version
        let (other_head, _) = roster2.commit(&root, 0, i64::MAX).unwrap();
        bad_head = other_head;
        assert_eq!(bad_head.version, proof.version);
        assert!(matches!(
            check_roster_inclusion(&bad_head, &proof, root.node_id(), member.node_id(), 0),
            Err(Error::NotInRoster)
        ));
    }
```

Add `use crate::roster::RosterVersion;` to the test module imports if not already present (it is referenced above), alongside the other `use` lines in `mod tests`.

- [ ] **Step 3: Run to verify failure.**

Run: `bazel test //library:library_test`
Expected: FAIL (`check_roster_inclusion` is `todo!()`).

- [ ] **Step 4: Implement** (replace the `todo!()`):

```rust
pub fn check_roster_inclusion(
    head: &RosterHead,
    proof: &InclusionProof,
    fabric_root: NodeId,
    caller: NodeId,
    now_unix: i64,
) -> Result<()> {
    head.verify(fabric_root)?;
    if now_unix > head.not_after {
        return Err(Error::Expired {
            not_after: head.not_after,
        });
    }
    if proof.member != caller {
        return Err(Error::SubjectMismatch);
    }
    if proof.version != head.version {
        return Err(Error::StaleProof {
            proof: proof.version.0,
            head: head.version.0,
        });
    }
    if proof.recompute_root() != head.root {
        return Err(Error::NotInRoster);
    }
    Ok(())
}
```

- [ ] **Step 5: Re-export** in `library/lib.rs` — change the policy re-export line:

```rust
pub use policy::{Crl, check_accept, check_inclusion, check_roster_inclusion};
```

- [ ] **Step 6: Run to verify pass.**

Run: `bazel test //library:library_test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add library/policy.rs library/lib.rs
git commit -m "feat(library): check_roster_inclusion policy gate"
```

---

### Task 8: Session frames — `proof` on `Handshake`, new `HandshakeAck`

**Files:**
- Modify: `library/session.rs`

- [ ] **Step 1: Update the module + types.** In `library/session.rs`:

Add the import:

```rust
use crate::roster::InclusionProof;
```

Add the new tag constant after `const TAG_EXIT: u8 = 4;`:

```rust
const TAG_HANDSHAKE_ACK: u8 = 5;
```

Replace the `HandshakeBody` struct with one carrying the optional proof, and add `HandshakeAckBody`:

```rust
/// The unsigned wire envelope for a [`Frame::Handshake`]: a mandatory membership,
/// an optional scope grant, and an optional roster inclusion proof, serialized as
/// one canonical-JSON blob. `skip_serializing_if` is safe here precisely because
/// this struct is *not* signed — the membership, grant, and the head a proof is
/// checked against are each signed independently over their own fixed bodies.
#[derive(Serialize, Deserialize)]
struct HandshakeBody {
    membership: Membership,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grant: Option<Grant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof: Option<InclusionProof>,
}

/// The unsigned wire envelope for a [`Frame::HandshakeAck`]: the responder's own
/// membership and an optional inclusion proof.
#[derive(Serialize, Deserialize)]
struct HandshakeAckBody {
    membership: Membership,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof: Option<InclusionProof>,
}
```

Update the `Frame::Handshake` variant and add `Frame::HandshakeAck`:

```rust
    /// Opening frame: the dialer presents its fabric membership (always), the
    /// matching grant for a scoped session, and a roster inclusion proof when a
    /// head-enforcing responder requires one.
    Handshake {
        /// The membership proving the dialer belongs to the fabric.
        membership: Membership,
        /// The grant authorizing a specific scope, when one is being requested.
        grant: Option<Grant>,
        /// The dialer's roster inclusion proof, when presenting one.
        proof: Option<InclusionProof>,
    },
    /// First frame back from the responder: its own membership (so a ticket-less
    /// dialer can verify the service's fabric membership before streaming stdin)
    /// and, optionally, its own inclusion proof.
    HandshakeAck {
        /// The responder's membership.
        membership: Membership,
        /// The responder's inclusion proof, if it presents one.
        proof: Option<InclusionProof>,
    },
```

Update `Frame::encode` — replace the `Frame::Handshake` arm and add the ack arm:

```rust
            Frame::Handshake {
                membership,
                grant,
                proof,
            } => {
                payload.push(TAG_HANDSHAKE);
                let body = HandshakeBody {
                    membership: membership.clone(),
                    grant: grant.clone(),
                    proof: proof.clone(),
                };
                payload.extend_from_slice(&canonical_bytes(&body)?);
            }
            Frame::HandshakeAck { membership, proof } => {
                payload.push(TAG_HANDSHAKE_ACK);
                let body = HandshakeAckBody {
                    membership: membership.clone(),
                    proof: proof.clone(),
                };
                payload.extend_from_slice(&canonical_bytes(&body)?);
            }
```

Update `Frame::decode` — replace the `TAG_HANDSHAKE` arm and add the ack arm:

```rust
            TAG_HANDSHAKE => {
                let hs: HandshakeBody = serde_json::from_slice(body).map_err(Error::Decode)?;
                Frame::Handshake {
                    membership: hs.membership,
                    grant: hs.grant,
                    proof: hs.proof,
                }
            }
            TAG_HANDSHAKE_ACK => {
                let ack: HandshakeAckBody = serde_json::from_slice(body).map_err(Error::Decode)?;
                Frame::HandshakeAck {
                    membership: ack.membership,
                    proof: ack.proof,
                }
            }
```

Update the module-doc wire-format table comment (the `| 0 | Handshake | … |` block): add a row:

```rust
//! | `5`  | `HandshakeAck` | canonical-JSON of the ack envelope          |
```

- [ ] **Step 2: Update the proptest strategy and add coverage.** In the `tests` module of `session.rs`, replace the `frame()` strategy's handshake arm and add the ack arm. Replace the whole `fn frame()`:

```rust
    /// An arbitrary frame of any variant, covering Handshake (grant/proof
    /// present or absent) and HandshakeAck (proof present or absent).
    fn frame() -> impl Strategy<Value = Frame> {
        prop_oneof![
            (seed(), seed(), "[a-z.]{1,16}", any::<i64>(), any::<bool>(), any::<bool>()).prop_map(
                |(rs, ss, sc, na, with_grant, with_proof)| {
                    let root = NodeIdentity::from_seed(rs);
                    let member = NodeIdentity::from_seed(ss).node_id();
                    let membership = Membership::mint(&root, member, 0, na).unwrap();
                    let grant =
                        with_grant.then(|| Grant::mint(&root, member, Scope::new(sc), na).unwrap());
                    let proof = with_proof.then(|| {
                        let mut roster = crate::roster::Roster::new(root.node_id());
                        roster.insert(member);
                        let (_head, proofs) = roster.commit(&root, 0, na).unwrap();
                        proofs.into_iter().next().unwrap().1
                    });
                    Frame::Handshake {
                        membership,
                        grant,
                        proof,
                    }
                }
            ),
            (seed(), seed(), any::<i64>(), any::<bool>()).prop_map(|(rs, ss, na, with_proof)| {
                let root = NodeIdentity::from_seed(rs);
                let member = NodeIdentity::from_seed(ss).node_id();
                let membership = Membership::mint(&root, member, 0, na).unwrap();
                let proof = with_proof.then(|| {
                    let mut roster = crate::roster::Roster::new(root.node_id());
                    roster.insert(member);
                    let (_head, proofs) = roster.commit(&root, 0, na).unwrap();
                    proofs.into_iter().next().unwrap().1
                });
                Frame::HandshakeAck { membership, proof }
            }),
            bytes().prop_map(|b| Frame::Stdin(Chunk::from_bytes(b))),
            bytes().prop_map(|b| Frame::Stdout(Chunk::from_bytes(b))),
            bytes().prop_map(|b| Frame::Stderr(Chunk::from_bytes(b))),
            any::<i32>().prop_map(Frame::Exit),
        ]
    }
```

- [ ] **Step 3: Run to verify** (these are existing-shape tests; they should pass once the impl compiles). First confirm it compiles and the round-trip tests pass:

Run: `bazel test //library:library_test`
Expected: PASS (round-trips, stream splits, truncation, garbage — all cover the new variants).

- [ ] **Step 4: Commit**

```bash
git add library/session.rs
git commit -m "feat(library): handshake proof field + HandshakeAck frame"
```

---

### Task 8b: Library doctests + full library green

- [ ] **Step 1: Run the library doctests** (the `check_roster_inclusion` doctest added in Task 7 runs here):

Run: `bazel test //library:library_doc_test`
Expected: PASS.

- [ ] **Step 2: Run the whole library target set.**

Run: `bazel test //library/...`
Expected: PASS.

- [ ] **Step 3: Commit** (only if any doctest fix was needed; otherwise skip).

---

## Phase 2 — `//wires` transport + CLI (`bazel test //wires/...`)

### Task 9: `ServeConfig` + ALPN bump + mutual-inclusion ack (no head gate yet)

This refactors the responder to carry a config struct and present a `HandshakeAck`; the dialer reads the ack and (in ticket-less mode) verifies the responder's membership. The roster *head gate* is added in Task 10.

**Files:**
- Modify: `wires/transport.rs`

- [ ] **Step 1: Bump the ALPN and imports.** In `wires/transport.rs`:

Change the ALPN constant + doc:

```rust
/// The custom ALPN identifying a wires capability session.
///
/// Bumped to `/2` for the mutual-inclusion handshake (a proof in the dialer's
/// handshake and a `HandshakeAck` carrying the responder's own membership): a
/// peer speaking `/1` fails cleanly at connect time rather than mid-handshake.
pub const ALPN: &[u8] = b"wires/session/2";
```

Extend the `library` import to add the roster types and the new policy fn:

```rust
use library::{
    Chunk, Crl, Frame, Grant, InclusionProof, Membership, NodeId, NodeIdentity, RosterHead, Scope,
    check_accept, check_inclusion, check_roster_inclusion,
};
```

- [ ] **Step 2: Define `ServeConfig`.** Add after the imports (before the key-bridge section):

```rust
/// The responder's static configuration: what it trusts, what it serves, the
/// optional roster head it enforces, the identity it presents in the ack, and
/// the child to exec. Built once per `serve` and shared across connections.
pub struct ServeConfig {
    /// The trusted fabric root whose memberships, grants, and head are honored.
    pub trust_root: NodeId,
    /// The scope this responder serves; `None` is inclusion-only.
    pub scope: Option<Scope>,
    /// The revocation list applied to the slice-1 credential checks.
    pub crl: Crl,
    /// When `Some`, the head a caller's inclusion proof is checked against.
    pub roster_head: Option<RosterHead>,
    /// The responder's own membership, presented in the `HandshakeAck`.
    pub membership: Membership,
    /// The responder's own inclusion proof, presented if set (unused by the
    /// dialer in this slice; reverse roster-freshness is deferred).
    pub proof: Option<InclusionProof>,
    /// The command (program + args) to exec per session.
    pub command: Vec<String>,
}
```

- [ ] **Step 3: Rewrite `serve` / `serve_on` / `handle_connection` to thread `ServeConfig`.** Replace the existing `serve`, `serve_on`, and `handle_connection` functions with:

```rust
/// Bind for `node` and serve the session ALPN (see [`serve_on`]).
pub async fn serve(node: NodeIdentity, config: ServeConfig, relay_url: Option<&str>) -> Result<()> {
    let endpoint = bind(&node, relay_url).await?;
    serve_on(endpoint, config).await
}

/// Accept connections on `endpoint`, verifying each caller against `config`, then
/// exec `config.command` and bridge its stdio. One task per connection; a
/// rejected or failed connection is logged at `warn` and does not stop the
/// listener.
pub async fn serve_on(endpoint: Endpoint, config: ServeConfig) -> Result<()> {
    tracing::info!(
        node = %to_node_id(&endpoint.id()).hex(),
        scope = ?config.scope.as_ref().map(Scope::as_str),
        enforcing_head = config.roster_head.is_some(),
        sockets = ?endpoint.bound_sockets(),
        "serving session ALPN (egress-only)"
    );
    if config.scope.is_none() {
        tracing::warn!("inclusion-only: any fabric member may connect");
    }
    let config = Arc::new(config);
    while let Some(incoming) = endpoint.accept().await {
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, &config).await {
                tracing::warn!("connection rejected or failed: {e:#}");
            }
        });
    }
    Ok(())
}

/// Accept one inbound iroh connection, then run the session over its bi-stream.
async fn handle_connection(incoming: iroh::endpoint::Incoming, config: &ServeConfig) -> Result<()> {
    let conn = incoming.await.context("accepting connection")?;
    let caller = to_node_id(&conn.remote_id());
    tracing::info!(caller = %caller.hex(), "connection accepted (iroh-authenticated)");
    let (send, recv) = conn.accept_bi().await.context("accepting bi-stream")?;

    serve_session(send, recv, caller, config).await?;

    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), conn.closed()).await;
    Ok(())
}
```

- [ ] **Step 4: Rewrite `serve_session`** to take `&ServeConfig`, capture the dialer's proof, send the ack, and (head gate added in Task 10) inject `WIRES_ROSTER_VERSION`. Replace the whole `serve_session` function:

```rust
/// The responder half of a session over an established, already-authenticated
/// bi-stream: read and verify the handshake against `caller` and `config`, send a
/// `HandshakeAck`, then exec `config.command` and bridge its stdio. `caller` must
/// already be authenticated by whoever supplies the streams.
async fn serve_session<S, R>(
    mut send: S,
    mut recv: R,
    caller: NodeId,
    config: &ServeConfig,
) -> Result<()>
where
    S: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    let first = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_frame(&mut recv))
        .await
        .context("timed out waiting for handshake")??;
    let (membership, grant, proof) = match first {
        Some(Frame::Handshake {
            membership,
            grant,
            proof,
        }) => (membership, grant, proof),
        Some(_) => bail!("first frame was not a handshake"),
        None => bail!("connection closed before handshake"),
    };
    let now = crate::now_unix();

    // Inclusion is always required (root-vouched identity, bound to the
    // iroh-authenticated key).
    check_inclusion(&membership, config.trust_root, caller, now, &config.crl)
        .map_err(|e| anyhow!("membership rejected: {e}"))?;

    // A scoped responder additionally requires a matching, accepted grant.
    if let Some(scope) = config.scope.as_ref() {
        let grant = grant
            .as_ref()
            .ok_or_else(|| anyhow!("scoped session requires a grant; none presented"))?;
        check_accept(grant, config.trust_root, caller, now, &config.crl)
            .map_err(|e| anyhow!("grant rejected: {e}"))?;
        if grant.scope.as_str() != scope.as_str() {
            bail!(
                "grant scope {:?} does not match served scope {:?}",
                grant.scope.as_str(),
                scope.as_str()
            );
        }
    }

    if let Some(grant) = grant.as_ref()
        && grant.subject != membership.member
    {
        bail!("grant subject does not match membership member");
    }

    // Roster head gate (added in Task 10): when a head is configured, require a
    // proof and check current membership; remember the admitting version.
    let roster_version = roster_gate(config, proof.as_ref(), caller, now)?;

    tracing::info!(
        caller = %caller.hex(),
        scope = ?config.scope.as_ref().map(Scope::as_str),
        roster_version = ?roster_version,
        "session accepted"
    );

    // Mutual inclusion: present our own membership (+ optional proof) so a
    // ticket-less dialer can verify us before streaming stdin. Written directly
    // on `send` so it is the first frame back, before any child output.
    write_frame(
        &mut send,
        &Frame::HandshakeAck {
            membership: config.membership.clone(),
            proof: config.proof.clone(),
        },
    )
    .await?;

    // Spawn the configured child with piped stdio, injecting the verified caller
    // identity (and the admitting roster version, if any). Scrub inherited
    // WIRES_* first.
    let (program, args) = config
        .command
        .split_first()
        .ok_or_else(|| anyhow!("empty serve command"))?;
    tracing::info!(program = %program, "spawning child and bridging stdio");
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_remove("WIRES_CALLER_NODE")
        .env_remove("WIRES_FABRIC_ROOT")
        .env_remove("WIRES_MEMBERSHIP_NOT_AFTER")
        .env_remove("WIRES_ROSTER_VERSION")
        .env("WIRES_CALLER_NODE", caller.hex())
        .env("WIRES_FABRIC_ROOT", config.trust_root.hex())
        .env("WIRES_MEMBERSHIP_NOT_AFTER", membership.not_after.to_string());
    if let Some(v) = roster_version {
        cmd.env("WIRES_ROSTER_VERSION", v.to_string());
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {program}"))?;
    let mut child_stdin = child.stdin.take().context("child stdin")?;
    let child_stdout = child.stdout.take().context("child stdout")?;
    let child_stderr = child.stderr.take().context("child stderr")?;

    let (tx, mut rx) = mpsc::channel::<Frame>(64);
    let writer = tokio::spawn(async move {
        let mut send = send;
        while let Some(frame) = rx.recv().await {
            write_frame(&mut send, &frame).await?;
        }
        send.shutdown().await.ok();
        Ok::<(), anyhow::Error>(())
    });

    let stdin_task = tokio::spawn(async move {
        loop {
            match read_frame(&mut recv).await? {
                Some(Frame::Stdin(chunk)) => {
                    child_stdin.write_all(chunk.as_bytes()).await?;
                }
                Some(_) => {}
                None => break,
            }
        }
        child_stdin.shutdown().await.ok();
        Ok::<(), anyhow::Error>(())
    });

    let out_task = tokio::spawn(pump_reader(child_stdout, Frame::Stdout, tx.clone()));
    let err_task = tokio::spawn(pump_reader(child_stderr, Frame::Stderr, tx.clone()));

    let status = child.wait().await.context("waiting for child")?;
    out_task.await.context("stdout pump")??;
    err_task.await.context("stderr pump")??;
    let _ = stdin_task.await;

    let code = status.code().unwrap_or(-1);
    tracing::info!(code, "child exited; closing session");
    tx.send(Frame::Exit(code)).await.ok();
    drop(tx);
    writer.await.context("writer task")??;
    Ok(())
}

/// The roster head gate. When `config.roster_head` is `None`, returns
/// `Ok(None)` (slice-1 behavior). When `Some`, requires `proof` and checks the
/// caller's *current* membership against the head, returning the admitting
/// version for `WIRES_ROSTER_VERSION`.
fn roster_gate(
    config: &ServeConfig,
    proof: Option<&InclusionProof>,
    caller: NodeId,
    now: i64,
) -> Result<Option<u64>> {
    let Some(head) = config.roster_head.as_ref() else {
        return Ok(None);
    };
    let proof = proof.ok_or(library::Error::InclusionProofRequired)?;
    check_roster_inclusion(head, proof, config.trust_root, caller, now)
        .map_err(|e| anyhow!("roster inclusion rejected: {e}"))?;
    Ok(Some(head.version.0))
}
```

- [ ] **Step 5: Update the dialer half.** Replace `connect_io`, `connect_on`, and `dial_session`:

```rust
/// Bind for `node` and dial `target` (see [`connect_on`]).
#[allow(clippy::too_many_arguments)]
pub async fn connect_io<R, W, E>(
    node: NodeIdentity,
    target: EndpointAddr,
    membership: Membership,
    grant: Option<Grant>,
    proof: Option<InclusionProof>,
    ticketless: bool,
    relay_url: Option<&str>,
    stdin: R,
    stdout: W,
    stderr: E,
) -> Result<i32>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let endpoint = bind(&node, relay_url).await?;
    connect_on(
        endpoint, target, membership, grant, proof, ticketless, stdin, stdout, stderr,
    )
    .await
}

/// Dial `target` on `endpoint`, present `membership` (+ `grant`/`proof` if any),
/// then bridge local stdio and return the child's exit code. When `ticketless`,
/// verify the responder's `HandshakeAck` membership before forwarding any stdin.
#[allow(clippy::too_many_arguments)]
pub async fn connect_on<R, W, E>(
    endpoint: Endpoint,
    target: EndpointAddr,
    membership: Membership,
    grant: Option<Grant>,
    proof: Option<InclusionProof>,
    ticketless: bool,
    stdin: R,
    stdout: W,
    stderr: E,
) -> Result<i32>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    tracing::info!("dialing the capability over wires");
    let conn = endpoint
        .connect(target, ALPN)
        .await
        .map_err(|e| anyhow!("dialing target: {e}"))?;
    let target_id = to_node_id(&conn.remote_id());
    let (send, recv) = conn.open_bi().await.context("opening bi-stream")?;
    tracing::info!("session open; presenting membership and bridging stdio");

    let verify_target = ticketless.then_some(target_id);
    let result = dial_session(
        send,
        recv,
        membership,
        grant,
        proof,
        verify_target,
        stdin,
        stdout,
        stderr,
    )
    .await;

    endpoint.close().await;
    result
}

/// The dialer half of a session over an established bi-stream. Presents the
/// handshake, then reads the responder's `HandshakeAck`; when `verify_target` is
/// `Some` (ticket-less mode), verifies the responder's membership against the
/// dialer's own fabric root and the authenticated target id **before** any stdin
/// is forwarded. On failure, aborts with no stdin sent.
#[allow(clippy::too_many_arguments)]
async fn dial_session<S, R, I, W, E>(
    mut send: S,
    mut recv: R,
    membership: Membership,
    grant: Option<Grant>,
    proof: Option<InclusionProof>,
    verify_target: Option<NodeId>,
    stdin: I,
    mut stdout: W,
    mut stderr: E,
) -> Result<i32>
where
    S: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin,
    I: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    // The dialer's own fabric root is the authority for verifying the responder.
    let fabric_root = membership.fabric;
    write_frame(
        &mut send,
        &Frame::Handshake {
            membership,
            grant,
            proof,
        },
    )
    .await?;

    // Read the responder's ack first (it is always the responder's first frame).
    let ack_membership = match read_frame(&mut recv).await? {
        Some(Frame::HandshakeAck { membership, .. }) => membership,
        Some(_) => bail!("responder's first frame was not a handshake ack"),
        None => bail!("responder closed before sending a handshake ack"),
    };
    // Ticket-less: verify the service is a fabric member before streaming stdin.
    // Credential-only (root-vouched + TTL); reverse roster-freshness is deferred.
    if let Some(target_id) = verify_target {
        check_inclusion(&ack_membership, fabric_root, target_id, crate::now_unix(), &Crl::new())
            .map_err(|e| anyhow!("responder membership rejected (no stdin sent): {e}"))?;
    }

    let stdin_task = tokio::spawn(async move {
        let mut stdin = stdin;
        let mut buf = vec![0u8; PUMP_BUF];
        loop {
            let n = stdin.read(&mut buf).await.context("reading local stdin")?;
            if n == 0 {
                break;
            }
            write_frame(&mut send, &Frame::Stdin(Chunk::from_bytes(buf[..n].to_vec()))).await?;
        }
        send.shutdown().await.ok();
        Ok::<(), anyhow::Error>(())
    });

    let mut code = 0;
    let mut saw_exit = false;
    loop {
        match read_frame(&mut recv).await? {
            Some(Frame::Stdout(chunk)) => stdout.write_all(chunk.as_bytes()).await?,
            Some(Frame::Stderr(chunk)) => stderr.write_all(chunk.as_bytes()).await?,
            Some(Frame::Exit(c)) => {
                code = c;
                saw_exit = true;
                tracing::info!(code, "remote child exited");
                break;
            }
            Some(_) => {}
            None => break,
        }
    }
    stdout.flush().await.ok();
    stderr.flush().await.ok();
    stdin_task.abort();
    if !saw_exit {
        bail!("session ended without an exit code (responder closed early?)");
    }
    Ok(code)
}
```

- [ ] **Step 6: Update the transport test helpers + tests** to the new signatures. In the `tests` module of `transport.rs`, make these replacements:

(a) Add a helper to build a `ServeConfig` and replace `run_session` and `serve_rejects`:

```rust
    /// A responder config for tests: server is a fabric member under `root`.
    fn test_config(
        root: &NodeIdentity,
        server: NodeId,
        scope: Option<&str>,
        crl: Crl,
        command: Vec<String>,
    ) -> ServeConfig {
        ServeConfig {
            trust_root: root.node_id(),
            scope: scope.map(Scope::new),
            crl,
            roster_head: None,
            membership: Membership::mint(root, server, 0, i64::MAX).unwrap(),
            proof: None,
            command,
        }
    }

    /// Run a full session over two in-memory duplex pipes (no iroh): returns the
    /// dialer's exit result plus captured stdout/stderr. Ticketed (grant present,
    /// ack ignored).
    async fn run_session(
        command: Vec<String>,
        input: &[u8],
        served_scope: &str,
    ) -> (Result<i32>, Vec<u8>, Vec<u8>) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let server = NodeIdentity::from_seed([4u8; 32]).node_id();
        let membership = Membership::mint(&root, caller, 0, i64::MAX).unwrap();
        let grant = Grant::mint(&root, caller, Scope::new(served_scope), i64::MAX).unwrap();

        let (c2s_w, c2s_r) = tokio::io::duplex(64 * 1024);
        let (s2c_w, s2c_r) = tokio::io::duplex(64 * 1024);

        let config = test_config(&root, server, Some(served_scope), Crl::new(), command);
        let srv = tokio::spawn(async move {
            serve_session(s2c_w, c2s_r, caller, &config).await
        });

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = dial_session(
            c2s_w,
            s2c_r,
            membership,
            Some(grant),
            None,             // dialer proof
            None,             // verify_target: ticketed → ignore ack
            std::io::Cursor::new(input.to_vec()),
            &mut out,
            &mut err,
        )
        .await;
        let _ = srv.await;
        (code, out, err)
    }

    /// Whether the responder rejects a handshake bearing `membership`/`grant`
    /// for a session serving `served_scope` (`None` = inclusion-only).
    async fn serve_rejects(
        membership: Membership,
        grant: Option<Grant>,
        trust_root: NodeId,
        served_scope: Option<&str>,
        crl: Crl,
        caller: NodeId,
    ) -> bool {
        let recv = std::io::Cursor::new(
            Frame::Handshake {
                membership,
                grant,
                proof: None,
            }
            .encode()
            .unwrap(),
        );
        let send: Vec<u8> = Vec::new();
        // The server's own membership is signed by `trust_root` so the (unreached)
        // ack would be valid; rejection happens during dialer verification.
        let server = NodeIdentity::from_seed([44u8; 32]);
        let server_membership = Membership::mint(
            &NodeIdentity::from_seed([1u8; 32]),
            server.node_id(),
            0,
            i64::MAX,
        )
        .unwrap();
        let config = ServeConfig {
            trust_root,
            scope: served_scope.map(Scope::new),
            crl,
            roster_head: None,
            membership: server_membership,
            proof: None,
            command: vec!["cat".to_string()],
        };
        serve_session(send, recv, caller, &config).await.is_err()
    }
```

> Note: in `serve_rejects`, `trust_root` is whatever the test passes; the server's
> own membership is minted under seed `[1u8;32]`. Because rejection happens during
> the dialer credential check (before the ack), the server membership's signer is
> irrelevant to these negative tests. Leave it as written.

(b) Update `inclusion_only_session_echoes` (it calls `serve_session`/`dial_session` directly). Replace its body:

```rust
    #[tokio::test]
    async fn inclusion_only_session_echoes() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let server = NodeIdentity::from_seed([4u8; 32]).node_id();
        let membership = valid_membership(&root, caller);

        let (c2s_w, c2s_r) = tokio::io::duplex(64 * 1024);
        let (s2c_w, s2c_r) = tokio::io::duplex(64 * 1024);
        let config = test_config(&root, server, None, Crl::new(), vec!["cat".to_string()]);
        let srv = tokio::spawn(async move { serve_session(s2c_w, c2s_r, caller, &config).await });

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = dial_session(
            c2s_w,
            s2c_r,
            membership,
            None,
            None,
            None, // ticketed-style call: do not verify ack
            std::io::Cursor::new(b"hi inclusion".to_vec()),
            &mut out,
            &mut err,
        )
        .await;
        let _ = srv.await;
        assert_eq!(code.unwrap(), 0);
        assert_eq!(out, b"hi inclusion");
    }
```

(c) Update `frames_round_trip_over_a_pipe` — add `proof: None` to the `Handshake` and add a `HandshakeAck` frame:

```rust
        let frames = vec![
            Frame::Handshake {
                membership: membership.clone(),
                grant: Some(grant),
                proof: None,
            },
            Frame::HandshakeAck {
                membership,
                proof: None,
            },
            Frame::Stdin(Chunk::from_bytes(b"hi".to_vec())),
            Frame::Stdout(Chunk::from_bytes(Vec::new())),
            Frame::Exit(7),
        ];
```

(Add `.clone()` to the first `membership` use as shown, since it is reused.)

(d) Update the four loopback tests (`loopback_echo_round_trip`, `loopback_inclusion_only_injects_identity`, `loopback_rejects_untrusted_grant`, `loopback_rejects_untrusted_membership`). For each: replace the `serve_on(server_ep, root.node_id(), scope, Crl::new(), command)` call with a `ServeConfig` built via `test_config`, and update each `connect_on(...)` call to add the `proof` and `ticketless` arguments. Concretely:

`loopback_echo_round_trip` (ticketed):

```rust
        let srv = tokio::spawn(serve_on(
            server_ep,
            test_config(&root, server.node_id(), Some("tools.cat"), Crl::new(), vec!["cat".to_string()]),
        ));
        // ...
        let code = connect_on(
            client_ep,
            addr,
            membership,
            Some(grant),
            None,  // proof
            false, // ticketed
            std::io::Cursor::new(b"hello world".to_vec()),
            &mut out,
            &mut err,
        )
        .await
        .unwrap();
```

(Note `test_config` mints the server's membership under `root`, and `server` here is the `NodeIdentity::from_seed([11u8; 32])` already in that test.)

`loopback_inclusion_only_injects_identity` (ticket-less — dialer verifies the ack):

```rust
        let srv = tokio::spawn(serve_on(
            server_ep,
            test_config(
                &root,
                server.node_id(),
                None,
                Crl::new(),
                vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    r#"printf "%s,%s,%s" "$WIRES_CALLER_NODE" "$WIRES_FABRIC_ROOT" "$WIRES_MEMBERSHIP_NOT_AFTER""#
                        .to_string(),
                ],
            ),
        ));
        // ...
        let code = connect_on(
            client_ep,
            addr,
            membership,
            None,
            None, // proof
            true, // ticket-less → verify the responder's ack
            std::io::Cursor::new(Vec::new()),
            &mut out,
            &mut err,
        )
        .await
        .unwrap();
```

`loopback_rejects_untrusted_grant` (ticketed): build config with `test_config(&trusted_root, server.node_id(), Some("tools.cat"), Crl::new(), vec!["cat".into()])`; `connect_on(..., Some(grant), None, false, ...)`.

`loopback_rejects_untrusted_membership` (ticket-less): build config with `test_config(&trusted_root, server.node_id(), None, Crl::new(), vec!["sh".into(),"-c".into(),"echo SHOULD_NOT_RUN".into()])`; `connect_on(..., None, None, true, ...)`.

- [ ] **Step 7: Run the transport tests.**

Run: `bazel test //wires:wires_test`
Expected: PASS (all existing behaviors preserved; ack round-trips; ticket-less loopback verifies the server).

- [ ] **Step 8: Commit**

```bash
git add wires/transport.rs
git commit -m "feat(wires): ServeConfig + ALPN /2 + mutual-inclusion HandshakeAck"
```

---

### Task 10: Roster head-gate transport tests (over pipes)

`roster_gate` was already wired in Task 9. This task adds the focused tests proving the head gate accepts/rejects correctly. (The end-to-end iroh tests are Task 15.)

**Files:**
- Modify: `wires/transport.rs` (tests only)

- [ ] **Step 1: Write the tests.** Add to the `tests` module of `transport.rs`:

```rust
    use library::Roster;

    /// Build a head-enforcing config for `member` plus the member's proof.
    fn head_enforcing(
        root: &NodeIdentity,
        server: NodeId,
        member: NodeId,
        command: Vec<String>,
    ) -> (ServeConfig, InclusionProof) {
        let mut roster = Roster::new(root.node_id());
        roster.insert(member);
        roster.insert(server);
        let (head, proofs) = roster.commit(root, 0, i64::MAX).unwrap();
        let proof = proofs.into_iter().find(|(m, _)| *m == member).unwrap().1;
        let config = ServeConfig {
            trust_root: root.node_id(),
            scope: None,
            crl: Crl::new(),
            roster_head: Some(head),
            membership: Membership::mint(root, server, 0, i64::MAX).unwrap(),
            proof: None,
            command,
        };
        (config, proof)
    }

    /// Drive `serve_session` against a one-shot handshake; returns the result.
    async fn serve_once(config: ServeConfig, caller: NodeId, handshake: Frame) -> Result<()> {
        let recv = std::io::Cursor::new(handshake.encode().unwrap());
        let send: Vec<u8> = Vec::new();
        serve_session(send, recv, caller, &config).await
    }

    #[tokio::test]
    async fn head_enforcing_accepts_member_with_matching_proof() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let server = NodeIdentity::from_seed([3u8; 32]).node_id();
        let (config, proof) = head_enforcing(&root, server, caller, vec!["cat".to_string()]);
        let membership = Membership::mint(&root, caller, 0, i64::MAX).unwrap();
        let ok = serve_once(
            config,
            caller,
            Frame::Handshake {
                membership,
                grant: None,
                proof: Some(proof),
            },
        )
        .await;
        assert!(ok.is_ok());
    }

    #[tokio::test]
    async fn head_enforcing_rejects_missing_proof() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let server = NodeIdentity::from_seed([3u8; 32]).node_id();
        let (config, _proof) = head_enforcing(&root, server, caller, vec!["cat".to_string()]);
        let membership = Membership::mint(&root, caller, 0, i64::MAX).unwrap();
        let res = serve_once(
            config,
            caller,
            Frame::Handshake {
                membership,
                grant: None,
                proof: None,
            },
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn head_enforcing_rejects_proof_for_other_member() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let other = NodeIdentity::from_seed([8u8; 32]).node_id();
        let server = NodeIdentity::from_seed([3u8; 32]).node_id();
        // Head/proof are built for `other`; `caller` presents other's proof.
        let (config, other_proof) = head_enforcing(&root, server, other, vec!["cat".to_string()]);
        let membership = Membership::mint(&root, caller, 0, i64::MAX).unwrap();
        let res = serve_once(
            config,
            caller,
            Frame::Handshake {
                membership,
                grant: None,
                proof: Some(other_proof),
            },
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn head_enforcing_rejects_stale_proof_after_recommit() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let server = NodeIdentity::from_seed([3u8; 32]).node_id();
        // Build a v1 proof, then advance the enforced head to v2.
        let (mut config, v1_proof) =
            head_enforcing(&root, server, caller, vec!["cat".to_string()]);
        let mut roster = Roster::new(root.node_id());
        roster.insert(caller);
        roster.insert(server);
        let _ = roster.commit(&root, 0, i64::MAX).unwrap(); // v1
        let (v2_head, _) = roster.commit(&root, 0, i64::MAX).unwrap(); // v2
        config.roster_head = Some(v2_head);
        let membership = Membership::mint(&root, caller, 0, i64::MAX).unwrap();
        let res = serve_once(
            config,
            caller,
            Frame::Handshake {
                membership,
                grant: None,
                proof: Some(v1_proof),
            },
        )
        .await;
        assert!(res.is_err());
    }
```

- [ ] **Step 2: Run.**

Run: `bazel test //wires:wires_test`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add wires/transport.rs
git commit -m "test(wires): roster head-gate accept/reject over pipes"
```

---

### Task 11: Keystore files + resolvers

**Files:**
- Modify: `wires/keystore.rs`

- [ ] **Step 1: Extend imports + add Keystore methods.** In `wires/keystore.rs`:

Change the `library` import:

```rust
use library::{Crl, InclusionProof, Membership, NodeIdentity, Roster, RosterHead};
```

Extend the module doc bullet list (after the `membership.json` bullet) with:

```rust
//! - `roster.json`: the root's full member set + version (mode `0600` — reveals
//!   membership, so private).
//! - `roster-head.json`: the signed roster head token (mode `0644` — public).
//! - `inclusion-proof.json`: a member's own inclusion-proof token (mode `0644`).
```

Add these methods inside `impl Keystore` (after `save_membership`):

```rust
    /// Read `roster.json` as a [`Roster`]; `None` if the file is absent.
    pub fn read_roster(&self) -> Result<Option<Roster>> {
        let path = self.path("roster.json");
        match read_to_string_opt(&path)? {
            Some(text) => Ok(Some(
                serde_json::from_str(&text)
                    .with_context(|| format!("parsing {}", path.display()))?,
            )),
            None => Ok(None),
        }
    }

    /// Persist the root's member set to `roster.json` (mode `0600` — it reveals
    /// membership). Returns the written path.
    pub fn save_roster(&self, roster: &Roster) -> Result<PathBuf> {
        ensure_dir(&self.dir)?;
        let path = self.path("roster.json");
        let json = serde_json::to_string(roster).context("encoding roster")?;
        write_secret_overwrite(&path, &json)?;
        Ok(path)
    }

    /// Read `roster-head.json` as a [`RosterHead`]; `None` if absent.
    pub fn read_roster_head(&self) -> Result<Option<RosterHead>> {
        let path = self.path("roster-head.json");
        match read_to_string_opt(&path)? {
            Some(text) => Ok(Some(
                RosterHead::decode(text.trim())
                    .with_context(|| format!("parsing {}", path.display()))?,
            )),
            None => Ok(None),
        }
    }

    /// Persist `head` to `roster-head.json` as its token (mode `0644` — public).
    pub fn save_roster_head(&self, head: &RosterHead) -> Result<PathBuf> {
        ensure_dir(&self.dir)?;
        let path = self.path("roster-head.json");
        write_text(&path, &head.encode()?)?;
        set_mode(&path, 0o644);
        Ok(path)
    }

    /// Read `inclusion-proof.json` as an [`InclusionProof`]; `None` if absent.
    pub fn read_inclusion_proof(&self) -> Result<Option<InclusionProof>> {
        let path = self.path("inclusion-proof.json");
        match read_to_string_opt(&path)? {
            Some(text) => Ok(Some(
                InclusionProof::decode(text.trim())
                    .with_context(|| format!("parsing {}", path.display()))?,
            )),
            None => Ok(None),
        }
    }

    /// Persist `proof` to `inclusion-proof.json` as its token (mode `0644`).
    pub fn save_inclusion_proof(&self, proof: &InclusionProof) -> Result<PathBuf> {
        ensure_dir(&self.dir)?;
        let path = self.path("inclusion-proof.json");
        write_text(&path, &proof.encode()?)?;
        set_mode(&path, 0o644);
        Ok(path)
    }
```

Add two small file helpers near `write_text` (bottom of the low-level helpers section):

```rust
/// Set a file's unix mode (best-effort; no-op on non-unix).
fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).ok();
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}

/// Write a secret file at mode `0600`, overwriting any existing file (used for
/// `roster.json`, which is rewritten in place by `roster add`/`remove`/`commit`).
fn write_secret_overwrite(path: &Path, contents: &str) -> Result<()> {
    write_text(path, contents)?;
    set_mode(path, 0o600);
    Ok(())
}
```

- [ ] **Step 2: Add the resolvers** (flag → env → file → keystore), after the `membership` resolver fn:

```rust
/// Resolve a roster head for `serve`: inline `--roster-head` token, then
/// `$WIRES_ROSTER_HEAD`, then `--roster-head-file`, then the keystore
/// (`roster-head.json`). `None` when none is configured (slice-1 behavior).
pub fn roster_head(inline: Option<&str>, file: Option<&Path>) -> Result<Option<RosterHead>> {
    if let Some(token) = inline {
        return Ok(Some(RosterHead::decode(token).context("--roster-head")?));
    }
    if let Some(token) = std::env::var("WIRES_ROSTER_HEAD")
        .ok()
        .filter(|s| !s.is_empty())
    {
        return Ok(Some(
            RosterHead::decode(&token).context("$WIRES_ROSTER_HEAD")?,
        ));
    }
    if let Some(path) = file {
        let text = read_to_string_opt(path)?
            .ok_or_else(|| anyhow!("roster head file not found: {}", path.display()))?;
        return Ok(Some(
            RosterHead::decode(text.trim())
                .with_context(|| format!("parsing {}", path.display()))?,
        ));
    }
    Keystore::resolve()?.read_roster_head()
}

/// Resolve an inclusion proof: inline `--inclusion-proof` token, then
/// `$WIRES_INCLUSION_PROOF`, then `--inclusion-proof-file`, then the keystore
/// (`inclusion-proof.json`). `None` when none is configured.
pub fn inclusion_proof(inline: Option<&str>, file: Option<&Path>) -> Result<Option<InclusionProof>> {
    if let Some(token) = inline {
        return Ok(Some(
            InclusionProof::decode(token).context("--inclusion-proof")?,
        ));
    }
    if let Some(token) = std::env::var("WIRES_INCLUSION_PROOF")
        .ok()
        .filter(|s| !s.is_empty())
    {
        return Ok(Some(
            InclusionProof::decode(&token).context("$WIRES_INCLUSION_PROOF")?,
        ));
    }
    if let Some(path) = file {
        let text = read_to_string_opt(path)?
            .ok_or_else(|| anyhow!("inclusion proof file not found: {}", path.display()))?;
        return Ok(Some(
            InclusionProof::decode(text.trim())
                .with_context(|| format!("parsing {}", path.display()))?,
        ));
    }
    Keystore::resolve()?.read_inclusion_proof()
}
```

- [ ] **Step 3: Write the tests.** Add to the `tests` module of `keystore.rs`:

```rust
    fn fixture_roster() -> (NodeIdentity, Roster) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut roster = Roster::new(root.node_id());
        roster.insert(NodeIdentity::from_seed([2u8; 32]).node_id());
        roster.insert(NodeIdentity::from_seed([3u8; 32]).node_id());
        (root, roster)
    }

    #[test]
    fn roster_round_trips_and_is_none_when_absent() {
        let ks = Keystore::at(temp_dir());
        assert!(ks.read_roster().unwrap().is_none());
        let (_root, roster) = fixture_roster();
        ks.save_roster(&roster).unwrap();
        assert_eq!(ks.read_roster().unwrap().unwrap(), roster);
    }

    #[test]
    fn roster_head_and_proof_round_trip() {
        let ks = Keystore::at(temp_dir());
        let (root, mut roster) = fixture_roster();
        let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        ks.save_roster_head(&head).unwrap();
        assert_eq!(ks.read_roster_head().unwrap().unwrap(), head);

        let proof = proofs.into_iter().next().unwrap().1;
        ks.save_inclusion_proof(&proof).unwrap();
        assert_eq!(ks.read_inclusion_proof().unwrap().unwrap(), proof);
    }

    #[cfg(unix)]
    #[test]
    fn roster_file_modes() {
        use std::os::unix::fs::PermissionsExt;
        let ks = Keystore::at(temp_dir());
        let (root, mut roster) = fixture_roster();
        let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let rp = ks.save_roster(&roster).unwrap();
        let hp = ks.save_roster_head(&head).unwrap();
        let pp = ks.save_inclusion_proof(&proofs[0].1).unwrap();
        assert_eq!(std::fs::metadata(&rp).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&hp).unwrap().permissions().mode() & 0o777, 0o644);
        assert_eq!(std::fs::metadata(&pp).unwrap().permissions().mode() & 0o777, 0o644);
    }

    #[test]
    fn roster_head_resolver_prefers_inline_then_file() {
        let (root, mut roster) = fixture_roster();
        let (head, _) = roster.commit(&root, 0, i64::MAX).unwrap();
        assert_eq!(
            roster_head(Some(&head.encode().unwrap()), None).unwrap().unwrap(),
            head
        );
        let path = temp_dir().join("roster-head.json");
        write_text(&path, &head.encode().unwrap()).unwrap();
        assert_eq!(roster_head(None, Some(&path)).unwrap().unwrap(), head);
    }

    #[test]
    fn inclusion_proof_resolver_prefers_inline_then_file() {
        let (root, mut roster) = fixture_roster();
        let (_head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let proof = proofs.into_iter().next().unwrap().1;
        assert_eq!(
            inclusion_proof(Some(&proof.encode().unwrap()), None).unwrap().unwrap(),
            proof
        );
        let path = temp_dir().join("inclusion-proof.json");
        write_text(&path, &proof.encode().unwrap()).unwrap();
        assert_eq!(inclusion_proof(None, Some(&path)).unwrap().unwrap(), proof);
    }
```

- [ ] **Step 4: Run.**

Run: `bazel test //wires:wires_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add wires/keystore.rs
git commit -m "feat(wires): keystore roster.json / roster-head.json / inclusion-proof.json"
```

---

### Task 12: `roster` CLI subcommand (add / remove / commit / head)

**Files:**
- Modify: `wires/main.rs`

- [ ] **Step 1: Add the subcommand types.** In `wires/main.rs`:

In `enum Command`, add after `Member(MemberArgs)`:

```rust
    /// Author the fabric roster (add/remove members, sign a committed head).
    Roster(RosterArgs),
```

Add the arg structs after `MemberArgs`:

```rust
/// `roster` has four offline operations on the local `roster.json`.
#[derive(Args)]
struct RosterArgs {
    #[command(subcommand)]
    cmd: RosterCmd,
}

#[derive(Subcommand)]
enum RosterCmd {
    /// Add a member to the local roster (no signing).
    Add(RosterMemberArgs),
    /// Remove a member from the local roster (no signing).
    Remove(RosterMemberArgs),
    /// Bump the version, build the tree, sign a head, and emit per-member proofs.
    Commit(RosterCommitArgs),
    /// Print the current head token (from the keystore `roster-head.json`).
    Head,
}

/// `roster add` / `roster remove`: the member to (de)list and an optional
/// fabric override (defaults to the keystore root identity's node id).
#[derive(Args)]
struct RosterMemberArgs {
    /// Hex node id of the member to add/remove.
    #[arg(long)]
    member: String,
    /// Hex node id of the fabric (defaults to the keystore root key's node id),
    /// used only when creating a fresh `roster.json`.
    #[arg(long)]
    fabric: Option<String>,
}

/// `roster commit`: the root signing key, the head's expiry, and where to write
/// the emitted per-member proofs.
#[derive(Args)]
struct RosterCommitArgs {
    /// Hex 32-byte seed of the root (signing) key. Falls back to env / file /
    /// keystore (`root.seed`).
    #[arg(long)]
    root_seed: Option<String>,
    /// Read the root key seed (hex) from this file instead of the keystore.
    #[arg(long)]
    root_seed_file: Option<PathBuf>,
    /// Seconds from now until the head expires (mutually exclusive with `--not-after`).
    #[arg(long, conflicts_with = "not_after")]
    ttl: Option<i64>,
    /// Absolute head expiry, unix seconds (mutually exclusive with `--ttl`).
    #[arg(long)]
    not_after: Option<i64>,
    /// Directory to write each member's `<node-id>.proof` token into. When
    /// omitted, the proofs are printed to stdout.
    #[arg(long)]
    out: Option<PathBuf>,
}
```

- [ ] **Step 2: Route it in `main`.** `roster` is offline admin like `member`. In `main()`, extend the offline-admin match arm to include `Roster`:

```rust
        Command::Keygen(_)
        | Command::Grant(_)
        | Command::Member(_)
        | Command::Revoke(_)
        | Command::Roster(_) => match cli_admin(cli.command) {
```

- [ ] **Step 3: Implement the command in `cli_admin`.** In `cli_admin`, add a match arm before the `unreachable!` arm:

```rust
        Command::Roster(a) => run_roster_cmd(a),
```

and update the final arm to keep the network commands unreachable:

```rust
        Command::Pair(_) | Command::Serve(_) | Command::Connect(_) => {
            unreachable!("handled in main")
        }
```

Add the implementation functions (near `run_member_cmd`):

```rust
/// `roster`: dispatch the four offline roster operations.
fn run_roster_cmd(a: RosterArgs) -> Result<String, String> {
    match a.cmd {
        RosterCmd::Add(m) => roster_edit(&m, true).map_err(stringify),
        RosterCmd::Remove(m) => roster_edit(&m, false).map_err(stringify),
        RosterCmd::Commit(c) => roster_commit(c).map_err(stringify),
        RosterCmd::Head => roster_head_token().map_err(stringify),
    }
}

/// Add or remove `member` in the keystore `roster.json`, persisting the result.
/// Creates the roster (fabric = `--fabric` or the root key's node id) on first use.
fn roster_edit(a: &RosterMemberArgs, add: bool) -> anyhow::Result<String> {
    let ks = keystore::Keystore::resolve()?;
    let member = NodeId::from_hex(&a.member)?;
    let mut roster = match ks.read_roster()? {
        Some(r) => r,
        None => {
            let fabric = match a.fabric.as_deref() {
                Some(hex) => NodeId::from_hex(hex)?,
                None => keystore::root_identity(None, None)
                    .context("resolving fabric id from the root key (or pass --fabric)")?
                    .node_id(),
            };
            library::Roster::new(fabric)
        }
    };
    let changed = if add {
        roster.insert(member)
    } else {
        roster.remove(&member)
    };
    ks.save_roster(&roster)?;
    Ok(format!(
        "{} {} ({} members, version {})",
        if !changed {
            "no change for"
        } else if add {
            "added"
        } else {
            "removed"
        },
        member.hex(),
        roster.members.len(),
        roster.version.0,
    ))
}

/// Sign a head over the current `roster.json`, persist the bumped roster and the
/// head, and emit each member's proof (to `--out` or stdout). Returns the head token.
fn roster_commit(a: RosterCommitArgs) -> anyhow::Result<String> {
    let ks = keystore::Keystore::resolve()?;
    let root = keystore::root_identity(a.root_seed.as_deref(), a.root_seed_file.as_deref())?;
    let not_after = resolve_not_after(a.ttl, a.not_after, now_unix()).map_err(anyhow::Error::msg)?;
    let mut roster = ks
        .read_roster()?
        .ok_or_else(|| anyhow::anyhow!("no roster.json; run `wires roster add --member <id>` first"))?;

    let (head, proofs) = roster.commit(&root, now_unix(), not_after)?;
    ks.save_roster(&roster)?; // persist the version bump
    ks.save_roster_head(&head)?;

    let mut lines = Vec::new();
    for (member, proof) in &proofs {
        let token = proof.encode()?;
        match a.out.as_deref() {
            Some(dir) => {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
                let path = dir.join(format!("{}.proof", member.hex()));
                std::fs::write(&path, &token)
                    .with_context(|| format!("writing {}", path.display()))?;
                lines.push(format!("proof {} -> {}", member.hex(), path.display()));
            }
            None => lines.push(format!("proof {} {}", member.hex(), token)),
        }
    }
    let head_token = head.encode()?;
    Ok(format!(
        "committed roster version {} ({} members)\nhead {}\n{}",
        head.version.0,
        proofs.len(),
        head_token,
        lines.join("\n")
    ))
}

/// Print the current head token from the keystore `roster-head.json`.
fn roster_head_token() -> anyhow::Result<String> {
    let ks = keystore::Keystore::resolve()?;
    let head = ks
        .read_roster_head()?
        .ok_or_else(|| anyhow::anyhow!("no roster-head.json; run `wires roster commit` first"))?;
    head.encode().map_err(Into::into)
}
```

- [ ] **Step 4: Write tests.** Add to the `tests` module of `main.rs`:

```rust
    use library::Roster;

    #[test]
    fn roster_commit_emits_includable_proofs() {
        // Build a roster directly (the CLI editing path is exercised via keystore
        // tests); assert commit's proofs pass check_roster_inclusion.
        let root = NodeIdentity::from_seed([1u8; 32]);
        let member = NodeIdentity::from_seed([2u8; 32]).node_id();
        let mut roster = Roster::new(root.node_id());
        roster.insert(member);
        let before = roster.version.0;
        let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        assert_eq!(head.version.0, before + 1);
        let proof = proofs.into_iter().find(|(m, _)| *m == member).unwrap().1;
        assert!(
            library::check_roster_inclusion(&head, &proof, root.node_id(), member, 0).is_ok()
        );
    }

    #[test]
    fn roster_add_remove_changes_membership() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let m = NodeIdentity::from_seed([2u8; 32]).node_id();
        let mut roster = Roster::new(root.node_id());
        assert!(roster.insert(m));
        assert!(!roster.insert(m)); // idempotent
        assert!(roster.contains(&m));
        assert!(roster.remove(&m));
        assert!(!roster.contains(&m));
    }
```

- [ ] **Step 5: Run.**

Run: `bazel test //wires:wires_test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add wires/main.rs
git commit -m "feat(wires): roster subcommand (add/remove/commit/head)"
```

---

### Task 13: Wire `serve` + `connect` CLI to the new config

**Files:**
- Modify: `wires/main.rs`

- [ ] **Step 1: Extend `ServeArgs`.** Add these fields to `struct ServeArgs` (after `relay_url`):

```rust
    /// The responder's own membership token, presented in the handshake ack so a
    /// ticket-less dialer can verify it. Falls back to `$WIRES_MEMBERSHIP`, then
    /// `--membership-file`, then the keystore (`membership.json`).
    #[arg(long)]
    membership: Option<String>,
    /// Read the responder's membership token from this file.
    #[arg(long)]
    membership_file: Option<PathBuf>,
    /// The signed roster head this responder enforces (inclusion proof required
    /// from callers). Falls back to `$WIRES_ROSTER_HEAD`, then
    /// `--roster-head-file`, then the keystore (`roster-head.json`). Absent ⇒
    /// slice-1 behavior (membership + CRL + TTL only).
    #[arg(long)]
    roster_head: Option<String>,
    /// Read the roster head token from this file.
    #[arg(long)]
    roster_head_file: Option<PathBuf>,
    /// The responder's own inclusion proof token (optional; presented in the ack).
    #[arg(long)]
    inclusion_proof: Option<String>,
    /// Read the responder's inclusion proof from this file.
    #[arg(long)]
    inclusion_proof_file: Option<PathBuf>,
```

- [ ] **Step 2: Extend `ConnectArgs`.** Add after `membership_file`:

```rust
    /// The inclusion proof token to present (required by a head-enforcing
    /// responder). Falls back to `$WIRES_INCLUSION_PROOF`, then
    /// `--inclusion-proof-file`, then the keystore (`inclusion-proof.json`).
    #[arg(long)]
    inclusion_proof: Option<String>,
    /// Read the inclusion proof token from this file.
    #[arg(long)]
    inclusion_proof_file: Option<PathBuf>,
```

- [ ] **Step 3: Rewrite `serve_cmd`** to resolve the responder's own membership/proof and the head, and build a `ServeConfig`:

```rust
async fn serve_cmd(a: ServeArgs) -> anyhow::Result<()> {
    init_logging();
    let node = keystore::node_identity(a.node_seed.as_deref(), a.node_seed_file.as_deref())?;
    let trust_root = NodeId::from_hex(&a.trust_root)?;
    let scope = a.scope.map(Scope::new);
    if scope.is_none() && !a.allow_any_member {
        anyhow::bail!(
            "refusing to serve: pass --scope <name>, or --allow-any-member for an \
             inclusion-only responder (any fabric member may connect)"
        );
    }
    let crl = keystore::load_crl(a.crl_json.as_deref(), a.crl_file.as_deref())?;
    let membership =
        keystore::membership(a.membership.as_deref(), a.membership_file.as_deref())?;
    let roster_head =
        keystore::roster_head(a.roster_head.as_deref(), a.roster_head_file.as_deref())?;
    let proof = keystore::inclusion_proof(
        a.inclusion_proof.as_deref(),
        a.inclusion_proof_file.as_deref(),
    )?;
    let config = transport::ServeConfig {
        trust_root,
        scope,
        crl,
        roster_head,
        membership,
        proof,
        command: a.command,
    };
    transport::serve(node, config, a.relay_url.as_deref()).await
}
```

- [ ] **Step 4: Rewrite `connect_cmd`** to resolve a proof and pass the ticket-less flag:

```rust
async fn connect_cmd(a: ConnectArgs) -> anyhow::Result<i32> {
    init_logging();
    let node = keystore::node_identity(a.node_seed.as_deref(), a.node_seed_file.as_deref())?;
    let membership = keystore::membership(a.membership.as_deref(), a.membership_file.as_deref())?;
    let proof = keystore::inclusion_proof(
        a.inclusion_proof.as_deref(),
        a.inclusion_proof_file.as_deref(),
    )?;

    let ticketless = a.ticket.is_none();
    let (target_id, addrs, grant, ticket_relay) = match a.ticket.as_deref() {
        Some(text) => {
            let t = CapabilityTicket::decode(text)?;
            (t.target, t.addrs, Some(t.grant), t.relay_url)
        }
        None => {
            let id = NodeId::from_hex(
                a.target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("--ticket or --target is required"))?,
            )?;
            (id, a.addr.clone(), None, None)
        }
    };
    let relay = a.relay_url.or(ticket_relay);
    let target = transport::endpoint_addr(&target_id, &addrs, relay.as_deref())?;
    transport::connect_io(
        node,
        target,
        membership,
        grant,
        proof,
        ticketless,
        relay.as_deref(),
        tokio::io::stdin(),
        tokio::io::stdout(),
        tokio::io::stderr(),
    )
    .await
}
```

- [ ] **Step 5: Run the whole wires target.**

Run: `bazel test //wires/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add wires/main.rs
git commit -m "feat(wires): serve --roster-head + own membership; connect --inclusion-proof"
```

---

## Phase 3 — end-to-end (iroh loopback)

### Task 14: End-to-end roster + mutual-inclusion over a real connection

**Files:**
- Modify: `wires/transport.rs` (tests)

- [ ] **Step 1: Write the e2e tests.** Add to the `tests` module of `transport.rs`:

```rust
    /// A root commits a roster of {client, server}; an inclusion-only,
    /// head-enforcing responder admits the client over a real loopback
    /// connection; the child prints WIRES_CALLER_NODE / WIRES_ROSTER_VERSION.
    #[tokio::test]
    async fn loopback_head_enforcing_admits_member() {
        let root = NodeIdentity::from_seed([50u8; 32]);
        let server = NodeIdentity::from_seed([51u8; 32]);
        let client = NodeIdentity::from_seed([52u8; 32]);

        let mut roster = Roster::new(root.node_id());
        roster.insert(client.node_id());
        roster.insert(server.node_id());
        let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let head_version = head.version.0;
        let client_proof = proofs
            .into_iter()
            .find(|(m, _)| *m == client.node_id())
            .unwrap()
            .1;

        let server_ep = test_endpoint(&server).await;
        let addr = endpoint_addr(&server.node_id(), &localhost_socks(&server_ep), None).unwrap();
        let config = ServeConfig {
            trust_root: root.node_id(),
            scope: None,
            crl: Crl::new(),
            roster_head: Some(head),
            membership: Membership::mint(&root, server.node_id(), 0, i64::MAX).unwrap(),
            proof: None,
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                r#"printf "%s,%s" "$WIRES_CALLER_NODE" "$WIRES_ROSTER_VERSION""#.to_string(),
            ],
        };
        let srv = tokio::spawn(serve_on(server_ep, config));

        let client_ep = test_endpoint(&client).await;
        let membership = Membership::mint(&root, client.node_id(), 0, i64::MAX).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = connect_on(
            client_ep,
            addr,
            membership,
            None,
            Some(client_proof),
            true, // ticket-less
            std::io::Cursor::new(Vec::new()),
            &mut out,
            &mut err,
        )
        .await
        .unwrap();

        assert_eq!(code, 0);
        let expected = format!("{},{}", client.node_id().hex(), head_version);
        assert_eq!(String::from_utf8(out).unwrap(), expected);
        srv.abort();
    }

    /// After the client is removed and the roster re-committed, the client's old
    /// proof is rejected and the child never runs.
    #[tokio::test]
    async fn loopback_head_enforcing_rejects_removed_member() {
        let root = NodeIdentity::from_seed([60u8; 32]);
        let server = NodeIdentity::from_seed([61u8; 32]);
        let client = NodeIdentity::from_seed([62u8; 32]);

        let mut roster = Roster::new(root.node_id());
        roster.insert(client.node_id());
        roster.insert(server.node_id());
        let (_v1, v1_proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let client_proof = v1_proofs
            .into_iter()
            .find(|(m, _)| *m == client.node_id())
            .unwrap()
            .1;
        // Remove the client and re-commit; the enforced head is now v2.
        roster.remove(&client.node_id());
        let (v2, _) = roster.commit(&root, 0, i64::MAX).unwrap();

        let server_ep = test_endpoint(&server).await;
        let addr = endpoint_addr(&server.node_id(), &localhost_socks(&server_ep), None).unwrap();
        let config = ServeConfig {
            trust_root: root.node_id(),
            scope: None,
            crl: Crl::new(),
            roster_head: Some(v2),
            membership: Membership::mint(&root, server.node_id(), 0, i64::MAX).unwrap(),
            proof: None,
            command: vec!["sh".to_string(), "-c".to_string(), "echo SHOULD_NOT_RUN".to_string()],
        };
        let srv = tokio::spawn(serve_on(server_ep, config));

        let client_ep = test_endpoint(&client).await;
        let membership = Membership::mint(&root, client.node_id(), 0, i64::MAX).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = connect_on(
            client_ep,
            addr,
            membership,
            None,
            Some(client_proof),
            true,
            std::io::Cursor::new(Vec::new()),
            &mut out,
            &mut err,
        )
        .await;
        assert!(result.is_err());
        assert!(out.is_empty());
        srv.abort();
    }

    /// Mutual inclusion: a ticket-less dialer aborts (no stdin echoed) when the
    /// responder's ack membership is signed by a different root; succeeds when it
    /// is signed by the trusted root.
    #[tokio::test]
    async fn loopback_mutual_inclusion_checks_the_responder() {
        let root = NodeIdentity::from_seed([70u8; 32]);
        let evil = NodeIdentity::from_seed([71u8; 32]);
        let client = NodeIdentity::from_seed([73u8; 32]);
        let membership = Membership::mint(&root, client.node_id(), 0, i64::MAX).unwrap();

        // Helper: serve with the server's own membership signed by `signer`.
        async fn run(
            signer: &NodeIdentity,
            client_membership: Membership,
            client: &NodeIdentity,
        ) -> Result<i32> {
            let server = NodeIdentity::from_seed([72u8; 32]);
            let trust_root = NodeIdentity::from_seed([70u8; 32]).node_id();
            let server_ep = test_endpoint(&server).await;
            let addr =
                endpoint_addr(&server.node_id(), &localhost_socks(&server_ep), None).unwrap();
            let config = ServeConfig {
                trust_root,
                scope: None,
                crl: Crl::new(),
                roster_head: None,
                membership: Membership::mint(signer, server.node_id(), 0, i64::MAX).unwrap(),
                proof: None,
                command: vec!["cat".to_string()],
            };
            let srv = tokio::spawn(serve_on(server_ep, config));
            let client_ep = test_endpoint(client).await;
            let mut out = Vec::new();
            let mut err = Vec::new();
            let code = connect_on(
                client_ep,
                addr,
                client_membership,
                None,
                None,
                true, // ticket-less → verify the responder
                std::io::Cursor::new(b"ping".to_vec()),
                &mut out,
                &mut err,
            )
            .await;
            srv.abort();
            code
        }

        // Server membership signed by the trusted root → success.
        assert!(run(&root, membership.clone(), &client).await.is_ok());
        // Server membership signed by a different root → dialer aborts.
        assert!(run(&evil, membership, &client).await.is_err());
    }
```

- [ ] **Step 2: Run.**

Run: `bazel test //wires:wires_test`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add wires/transport.rs
git commit -m "test(wires): e2e roster head enforcement + mutual inclusion over loopback"
```

---

## Phase 4 — doctests, full green, readability, docs

### Task 15: Roster doctests + whole-repo green

**Files:**
- Modify: `library/roster.rs` (add doctests)

- [ ] **Step 1: Add runnable doctests** to the public roster API. In `library/roster.rs`, add a `///` example to `Roster::commit` and `RosterHead::encode`/`decode`:

On `Roster::commit` (above the `pub fn commit`):

```rust
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
```

On `RosterHead::encode` (above `pub fn encode`):

```rust
    /// ```
    /// use library::{NodeIdentity, Roster, RosterHead};
    /// let root = NodeIdentity::from_seed([1u8; 32]);
    /// let mut roster = Roster::new(root.node_id());
    /// roster.insert(NodeIdentity::from_seed([2u8; 32]).node_id());
    /// let (head, _) = roster.commit(&root, 0, i64::MAX).unwrap();
    /// assert_eq!(RosterHead::decode(&head.encode().unwrap()).unwrap(), head);
    /// ```
```

- [ ] **Step 2: Run the doctests + the whole repo.**

Run: `bazel test //...`
Expected: PASS (library, wires, relay, doctests).

- [ ] **Step 3: Commit**

```bash
git add library/roster.rs
git commit -m "docs(library): runnable doctests on the roster public API"
```

---

### Task 16: Readability pass, lint, format, README/demo

**Files:**
- Modify: `library/roster.rs`, `README.md` (demo block), as needed.

- [ ] **Step 1: Readability pass.** Re-read `library/roster.rs`: confirm one concept per section, that `lib.rs` re-exports are complete (`MerkleRoot`, `RosterVersion`, `Side`, `MerkleStep`, `InclusionProof`, `RosterHead`, `Roster`, `ROSTER_HEAD_V1` — all public), and that internals (`leaf_hash`, `node_hash`, `empty_root`, `build_levels`, `RosterHeadBody`) stay private. Fix any awkward names.

- [ ] **Step 2: Lint.**

Run: `make lint`
Expected: clippy + shellcheck clean. Fix any clippy findings (e.g. needless clones, `div_ceil` already used).

- [ ] **Step 3: Format.**

Run: `format`
Expected: rustfmt/buildifier rewrite in place; re-run `bazel test //...` if anything changed materially.

- [ ] **Step 4: Add a manual demo to `README.md`** (or `docs/`) mirroring the spec's "Manual demonstration" block, so the feature is documented. Use the block from `docs/committed-roster.md` lines under "Manual demonstration", adjusting the `serve`/`connect` flags to the implemented ones (`--membership` for the server's own, `--roster-head-file`, `--inclusion-proof-file`).

- [ ] **Step 5: Final whole-repo verification.**

Run: `bazel test //...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: roster readability pass, lint/format, README demo"
```

---

## Self-review notes (author checklist applied)

- **Spec coverage:** roster data model (Task 3), Merkle construction incl. empty/1/2/3 + odd-node (Tasks 4–5), head sign/verify + commit + version bump (Task 6), `check_roster_inclusion` truth table + targeted errors (Task 7), handshake `proof` + `HandshakeAck` + ALPN bump (Tasks 8–9), serve head gate + `WIRES_ROSTER_VERSION` (Tasks 9–10), mutual inclusion ticket-less verify (Tasks 9, 14), CLI `roster`/`serve`/`connect` (Tasks 12–13), keystore three files + resolvers (Task 11), e2e (Task 14), forward-compat known-answer canonical bytes (Task 6). CRL is deliberately untouched by the roster path (verified: `roster_gate` reads/writes no CRL).
- **Deferred (not built), per spec:** sealed full-set blob, member-facing enumeration, gossip/iroh-blobs/blind node, monotonic-version *enforcement* across heads, pairing-mints-memberships, sparse trees, federated leaf claims. The wire format (`format` discriminant, fixed signed body, no `skip_serializing_if` in signed bodies) keeps these forward-compatible.
- **Type consistency:** `RosterVersion(pub u64)`, `MerkleRoot([u8;32])` hex serde, `head.version.0` used uniformly; `commit` returns `(RosterHead, Vec<(NodeId, InclusionProof)>)` consumed identically in policy/transport/CLI tests; `ServeConfig` field names match across `serve_cmd`, `test_config`, and the e2e tests.
- **Deviations from the literal spec (deliberate):** (1) `MerkleStep.hash` and the private hash fns use the `MerkleRoot` newtype, not bare `[u8;32]`, honoring CLAUDE.md's no-bare-array rule and the "hex in JSON" intent. (2) Added `Error::FabricMismatch` (a 4th variant) for `commit`'s root precondition, since the spec listed only the three policy/handshake variants but `commit` returns `Result`. (3) `--roster-head`/`--roster-head-file` and `--inclusion-proof`/`--inclusion-proof-file` are split into two flags each (consistent with the existing `--membership`/`--membership-file` pattern) rather than one `<token | file>` arg. (4) `serve` now *always* sends a `HandshakeAck` and therefore *requires its own membership* — a real behavioral addition mandated by the mutual-inclusion section.

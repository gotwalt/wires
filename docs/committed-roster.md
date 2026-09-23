# Design: the committed roster (slice 2)

The second concrete step toward the fabric vision (deleted; see git history): a
**root-signed, versioned commitment to the member set**, so a verifier can
decide not just "did the root vouch for this node *once*" (the slice-1
membership credential) but "is this node a
member *right now*" — offline, against a 32-byte head it already holds, with no
extra network traffic. Revocation becomes "re-sign the head without that node."

> **Status.** Design only — not yet implemented. The vision's slice-2 row
> ("personal fabric") decomposes into three independently buildable pieces:
> **(a)** pairing mints memberships, **(b)** this committed roster — the data
> structure, offline verification, and local wiring, and **(c)** distribution —
> gossip for the head, blobs for the sealed full set, and the blind persistence
> node. **This document is (b).** It deliberately stops at the data structure and
> a *file-based* manual distribution seam, exactly where (c) later slots in. The
> sealed full-set blob, confidential enumeration, gossip, blobs, and the blind
> node are **reserved but not built**, behind the same versioning discipline
> slice 1 established.

## Motivation

Slice 1 gave a node a standalone proof of inclusion: a `Membership` the root
signed, verified offline by [`check_inclusion`](../library/policy.rs) — signature,
`fabric` pin, `member == caller`, TTL, CRL. That answers *"did the root vouch for
this node, and is the credential unexpired and un-revoked."* It is bearer-ish but
sound, because iroh independently authenticates the connection to `member`'s key.

What it does not give is a **current, scope-independent commitment to the set**:

1. **No positive freshness.** A credential says the root vouched *at issue time*,
   bounded only by its TTL. Within that window the only revocation signal is the
   CRL — a list that must itself be distributed, and that revokes a node for
   *everything* at once.
2. **No enumeration.** There is no object the root (or a member) can point at and
   ask "who is in this fabric?" The fabric is implicit in the set of credentials
   the root has ever minted.

The committed roster closes (1) directly and lays the groundwork for (2). The
root keeps a versioned member set and re-signs a tiny **head** whenever it
changes; a verifier holding the latest head checks a caller's **inclusion path**
against it and learns *current* membership offline. Removing a member and
re-signing is a fabric-wide revocation that needs no CRL distribution and no
per-node TTL shortening — the freshness the slice-1 doc explicitly deferred to
"the roster's job."

This buys three things the vision names — confidentiality (a Merkle head leaks
nothing; a flat list or CRL leaks the whole set), enumeration, and re-signed-head
revocation — at the cost of one new dependency (`blake3`) and a per-commit proof
re-issue. Both are addressed below.

## What this slice changes (and what it defers)

**In scope (b):**

- A pure `//library` module, `roster.rs`: the `Roster` (the root's member set),
  the signed `RosterHead`, the Merkle `InclusionProof`, and their verification.
- `check_roster_inclusion` beside `check_inclusion` in `policy.rs`.
- A handshake that carries the caller's proof, plus a response leg so a
  ticket-less dialer can verify the *service's* membership before it streams any
  stdin (**mutual inclusion**, below).
- A `roster` CLI for the root; `serve --roster-head`; `connect --inclusion-proof`;
  keystore files for the head, the member's proof, and the root's set.

**Deferred, by design** (named so the wire format stays forward-compatible):

- The **sealed full-set blob** and **confidential/member-facing enumeration** —
  the root enumerates its own local set trivially; the *encrypted, member-readable*
  set is a (c) concern.
- **Gossip head distribution, iroh-blobs, and the blind persistence node** —
  slice (c). Here the head and each member's proof move by **manual file copy**,
  exactly as slice 1 moved tickets and memberships. In (c) members stop receiving
  *pushed* proofs altogether and instead recompute their own from the gossiped head
  plus the sealed set — which is what makes the per-commit refresh (see *Proof
  churn*) automatic and operator-free.
- **Monotonic-version *enforcement*.** The `version` field is signed now, but
  rejecting an *older* head needs persistent "highest-seen" state that only bites
  once heads arrive over an untrusted channel — so enforcement lands in (c). See
  the soundness section.
- **Pairing minting memberships** — sibling slice (a), untouched here.
- **Sparse Merkle trees / non-membership proofs, federated identity claims in
  leaves, root rotation** — later slices.

## Roles: who holds the head

The roster introduces no new node type. A **verifier** is just a member running
`serve`: an endpoint on the *data plane* that, before spawning its child, checks
the caller against a head it holds. It verifies **offline** — the head reached it
out of band, never via a hot-path callback.

This is distinct from the always-on, keyless **blind node** of slice (c), which is
*control-plane* infrastructure: it persists and gossips the root-signed head and
the sealed blob so verifiers can sync, but runs no session and makes no decision.
In this slice there is no blind node — the verifier obtains its head by file copy.
The verifier *consumes* what (c)'s node will later *distribute*; the two are
orthogonal.

## The roster data model

A new pure module, `//library`'s `roster.rs`, following the
[`membership.rs`](../library/membership.rs) shape (private borrowed-field body,
derive `Serialize`, sign over `canonical_bytes`, reuse `AlgorithmId`).

Two newtypes keep the public API honest (no bare `[u8; 32]` / `u64`):

```rust
/// A blake3 Merkle root over a fabric's member set. Serializes as hex, with the
/// same serde as `NodeId`/`Signature`, so `canonical_bytes` stays deterministic.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct MerkleRoot([u8; 32]);

/// A monotonic roster version. A verifier that has seen `V` rejects `V-1`
/// (enforced once heads arrive over gossip — slice (c)); here it binds a proof
/// to the head it was issued against.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct RosterVersion(u64);
```

### The signed head

```rust
/// The signed portion of a v1 roster head: every field but `sig`. Field order
/// here is irrelevant — `canonical_bytes` sorts keys.
#[derive(Serialize)]
struct RosterHeadBody<'a> {
    format: u8,             // = ROSTER_HEAD_V1 — the schema discriminant
    fabric: &'a NodeId,
    version: u64,           // the monotonic content counter
    root: &'a MerkleRoot,
    issued: i64,
    not_after: i64,
    alg: &'a AlgorithmId,
}

/// A fabric-root-signed commitment to the member set at a point in time. The
/// whole credential is 32 bytes of root plus signature and timestamps — it
/// reveals nothing about who is in the set.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RosterHead {
    pub format: u8,             // = ROSTER_HEAD_V1
    pub fabric: NodeId,         // fabric root pubkey — the authority (a SIGNED field)
    pub version: RosterVersion, // monotonic; verifiers adopt the highest they see
    pub root: MerkleRoot,       // Merkle root over the sorted member set
    pub issued: i64,            // unix seconds, commit time
    pub not_after: i64,         // unix seconds, inclusive — stale heads self-expire
    pub alg: AlgorithmId,
    pub sig: Signature,         // fabric-root signature over RosterHeadBody
}

pub const ROSTER_HEAD_V1: u8 = 1;

impl RosterHead {
    /// Verify the head was signed by `fabric_root` for that fabric: algorithm,
    /// the `format` discriminant, the `fabric == fabric_root` pin, and the sig.
    /// Does NOT check freshness or any member — that is
    /// [`crate::policy::check_roster_inclusion`].
    pub fn verify(&self, fabric_root: NodeId) -> Result<()>;

    /// base64url-no-pad of `canonical_bytes(self)` — one copy-pasteable head
    /// token. The fabric id is recoverable from the decoded head.
    pub fn encode(&self) -> Result<String>;
    pub fn decode(text: &str) -> Result<RosterHead>;
}
```

> **Naming.** The *schema discriminant* is `format` here, and `version` is the
> *monotonic content counter*, because the vision speaks of "the highest version
> you see." `Membership` calls its schema discriminant `version` (it has no
> counter). The split is deliberate: each struct uses its domain's word.

### The member's proof

```rust
/// Which side of a Merkle parent a sibling sits on.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Side { Left, Right }

/// One step on a Merkle path: a sibling node hash and its side.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct MerkleStep {
    pub hash: [u8; 32],   // hex in JSON
    pub side: Side,
}

/// A member's proof that its NodeId is a leaf under a given head. Bound to
/// `version` so a verifier rejects a path issued against a different head.
/// Reveals only the member's own NodeId and O(log n) sibling hashes — never
/// another member's identity.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct InclusionProof {
    pub member: NodeId,
    pub version: RosterVersion,
    pub path: Vec<MerkleStep>,
}

impl InclusionProof {
    /// Recompute the Merkle root this path implies for `member`. A verifier
    /// compares the result to the `root` in a head it trusts.
    pub fn recompute_root(&self) -> MerkleRoot;

    pub fn encode(&self) -> Result<String>;
    pub fn decode(text: &str) -> Result<InclusionProof>;
}
```

### The root's source of truth

```rust
/// The root's authoritative member set — the source of truth behind every head.
/// Lives only on the root's machine (keystore `roster.json`, mode 0600); it is
/// never published in the clear. The confidential, member-readable sealed blob
/// is a deferred slice.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Roster {
    pub fabric: NodeId,
    pub version: RosterVersion,
    pub members: BTreeSet<NodeId>,
}

impl Roster {
    pub fn new(fabric: NodeId) -> Roster;
    pub fn insert(&mut self, member: NodeId) -> bool;
    pub fn remove(&mut self, member: &NodeId) -> bool;
    pub fn contains(&self, member: &NodeId) -> bool;

    /// The current Merkle root over the sorted member set (no signing).
    pub fn root_hash(&self) -> MerkleRoot;

    /// The inclusion path for `member`, or `None` if not a member.
    pub fn proof_for(&self, member: &NodeId) -> Option<InclusionProof>;

    /// Bump `version`, build the tree, sign a head, and emit every member's
    /// fresh proof. The signing key must be the fabric root
    /// (`root.node_id() == self.fabric`); a mismatch is a usage error.
    pub fn commit(&mut self, root: &NodeIdentity, issued: i64, not_after: i64)
        -> Result<(RosterHead, Vec<(NodeId, InclusionProof)>)>;
}
```

`commit` is the one place version increments — every published head is `+1`, so
the on-disk `roster.json` records the last committed version and the next commit
follows it.

## The Merkle construction

Standard binary tree, [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)-style
domain separation, `blake3`:

```rust
fn leaf_hash(member: &NodeId) -> [u8; 32];          // blake3(0x00 || member bytes)
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32]; // blake3(0x01 || left || right)
```

- **Leaves are the member NodeIds, sorted by their bytes** — so the tree (and the
  root) is a deterministic function of the set, independent of insertion order.
- The leaf prefix `0x00` and node prefix `0x01` prevent second-preimage attacks
  that pass an internal node off as a leaf.
- **Odd levels carry the last node up unchanged** (the CT rule), rather than
  duplicating it. Pinned by a known-answer test.
- **Edge cases**, each with a known-answer test: an **empty** set hashes to a
  fixed sentinel constant (no leaves to hash); a **single** member's root is its
  `leaf_hash`; two and three members assert exact bytes.
- **Any change reshuffles.** Because the tree is built over the *sorted list*,
  adding or removing a member shifts later leaves' positions, so a single change
  can alter many members' paths — not just one. (A sparse, position-keyed tree
  would bound it to one sibling per change; we do not need that, because members
  recompute their own paths once distribution lands — see *Proof churn* in the
  soundness analysis.)

The leaf is the **NodeId only**, not a hash of the credential. This keeps the
roster orthogonal to credential TTL — re-issuing a member's `Membership` with a
new expiry does not perturb the head — and matches the "credential + path"
verification model below: the path proves *set membership*, the separately
presented credential proves *root-vouched identity with a TTL*. Richer leaves
(federation claims) are a later slice, behind a new `format`.

## Forward-compat: the same discipline as slice 1

The head is signed bytes from `canonical_bytes`, so the
slice-1 rule applies verbatim: **optional-but-signed
is forbidden.** The `format` field is signed and **each format serializes a fixed,
total set of fields**; a future v2 head defines a separate `RosterHeadBodyV2`
(say, adding a `prev` hash to chain heads) and `verify` dispatches on
`self.format`. A v1-only verifier rejects a v2 head with `Error::UnsupportedVersion`
rather than silently ignoring fields. v1 bytes stay frozen forever.

`MerkleRoot` serializes as a hex string (not a JSON array of bytes) for the same
reason `NodeId` does — compact, and stable under `canonical_bytes`' `BTreeMap`
key ordering. As in slice 1, a known-answer test asserts `canonical_bytes` of a
fixed `RosterHeadBody` equals a hardcoded byte string, guarding the
canonicalization invariant against an accidental `serde_json` `preserve_order` /
`arbitrary_precision` feature creeping in.

## Inclusion-against-the-head policy

Alongside `check_inclusion` in [`library/policy.rs`](../library/policy.rs):

```rust
/// Decide whether `proof` shows `caller` is a current member under `head`.
///
/// Accepts iff `head` verifies under `fabric_root`, the head is fresh
/// (`now_unix <= not_after`), the proof is for `caller`, it targets this head's
/// version, and the recomputed root matches `head.root`.
pub fn check_roster_inclusion(
    head: &RosterHead, proof: &InclusionProof,
    fabric_root: NodeId, caller: NodeId, now_unix: i64,
) -> Result<()> {
    head.verify(fabric_root)?;                                          // sig + format + alg + fabric pin
    if now_unix > head.not_after { return Err(Error::Expired { not_after: head.not_after }); }
    if proof.member != caller { return Err(Error::SubjectMismatch); }   // non-transferable
    if proof.version != head.version {
        return Err(Error::StaleProof { proof: proof.version.0, head: head.version.0 });
    }
    if proof.recompute_root() != head.root { return Err(Error::NotInRoster); }
    Ok(())
}
```

The expiry boundary is `now_unix > not_after` (`not_after` inclusive), matching
`check_accept` and `check_inclusion`. As with those, the same invariant holds:
**`check_roster_inclusion` is only safe when `caller` is a cryptographically
authenticated peer.** The path proves a NodeId is in the set; iroh's mutual auth
proves the entity on the wire *is* that NodeId. Neither alone is enough.

New error variants in [`library/error.rs`](../library/error.rs), in the existing
`thiserror` style: `NotInRoster`, `StaleProof { proof: u64, head: u64 }`, and
`InclusionProofRequired` (raised by the responder, below). `Expired`,
`SubjectMismatch`, `UnsupportedVersion`, `InvalidSignature`, and
`UnsupportedAlgorithm` are reused verbatim.

## How it composes with the credential and the CRL

The roster does **not** replace the slice-1 credential — it layers freshness on
top. A responder configured with a head runs **both** checks on a caller:

1. `check_inclusion(&membership, fabric_root, caller, now, crl)` — *always*
   (root-vouched identity, TTL, the bare CRL).
2. `check_roster_inclusion(&head, &proof, fabric_root, caller, now)` — *only when
   a head is configured*.

So:

- **A verifier holding a head** gets instant, fabric-wide revocation: drop the
  member, re-sign, and step (2) fails on the next session — no CRL distribution,
  no TTL shortening.
- **A head-less verifier** is exactly slice-1 behavior: the credential plus the
  CRL plus the TTL. This is the documented offline fallback; the credential's TTL
  bounds how long a removed member can still transact against a verifier that has
  no head. Short TTLs are the knob.

Consequently **revocation is head-only**: `roster remove` re-signs the head
without the member, full stop. The **CRL is left entirely untouched** as the
legacy head-less mechanism — no code in this slice writes to it, and the roster
verify path neither reads nor extends it. ("Belt-and-suspenders" — also adding a
removed member to the CRL — was considered and rejected: it keeps two revocation
mechanisms alive and the CRL must itself be distributed to matter.)

## The session handshake

[`Frame::Handshake`](../library/session.rs) gains an optional proof, and a new
response frame carries the responder's own identity back:

```rust
// dialer -> responder, first frame (membership mandatory, the rest optional):
Frame::Handshake { membership: Membership, grant: Option<Grant>, proof: Option<InclusionProof> }

// responder -> dialer, first frame back (new):
Frame::HandshakeAck { membership: Membership, proof: Option<InclusionProof> }
```

Each is encoded as one JSON blob via a private **unsigned** envelope — here
`skip_serializing_if` is fine, because the *signed* objects are the `Membership`,
`Grant`, and the head a proof is checked against, each with its own fixed signed
body:

```rust
#[derive(Serialize, Deserialize)]
struct HandshakeBody {
    membership: Membership,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grant: Option<Grant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof: Option<InclusionProof>,
}

#[derive(Serialize, Deserialize)]
struct HandshakeAckBody {
    membership: Membership,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof: Option<InclusionProof>,
}
```

This is an **incompatible wire change** — acceptable on a fresh branch with no
deployed peers. **Bump the session ALPN** from `wires/session/1` to
`wires/session/2` so a mismatch fails cleanly at connect time.

## Mutual inclusion in ticket-less mode

iroh authenticates *identity* (the dialer knows it reached exactly NodeId `X`),
but identity is not membership. When a dialer connects with a `--ticket`, the
ticket's root-signed grant *names the target*, so verifying the grant already
proves the root vouched for reaching that service. When a dialer connects with a
bare `--target` (no ticket), nothing yet proves the service is a fabric member —
the dialer would stream its stdin to a NodeId it was merely told to trust.

So the responder **always** answers the handshake with `Frame::HandshakeAck`
carrying its own membership (and optionally its own proof), and a **ticket-less
dialer verifies it before forwarding any stdin**:

1. Dialer → responder: `Handshake { membership, grant?, proof? }`.
2. Responder verifies the dialer (the two checks above), then sends
   `HandshakeAck { membership: <its own>, proof? }`.
3. Dialer, *in `--target` mode only*, verifies the ack with the **head-less
   credential check**: same-fabric check, then
   `check_inclusion(responder_membership, fabric_root, <authenticated target id>, now, crl)`
   — the **same function**, with `caller` now the iroh-authenticated remote (the
   service). On failure → abort, **no stdin sent**. In ticketed mode the ack is
   ignored (the grant already vouches for the target).
4. Both sides bridge stdio.

*Reverse* roster-freshness — checking the service against a head — is deferred to
slice (c): a dialer only reliably holds the *current* head once it syncs over
gossip, so forcing a head-version match here would spuriously abort sessions
against a service whose proof is newer than the dialer's stale head. In this
slice the reverse direction is therefore **credential-only** (root-vouched + TTL),
which is robust, needs no head, and requires no new dialer config. The forward
direction keeps full roster freshness, because the responder is the authority on
the head it enforces.

This is nearly free:

- **The dialer needs no new config and no head.** Its own `membership.fabric` *is*
  the fabric root, so it runs the head-less credential check on the responder with
  what it already holds.
- **The responder loads its own `membership.json`** (+ optional proof) to present
  — reusing the keystore resolver, now on the `serve` side too. For this slice it
  may present membership alone, so the freshness layer adds no proof churn here.
- **One extra in-band frame, no external round-trip** — the "no callback to an
  identity server" property is intact.

One deliberate exposure: the dialer sends *its own* membership (step 1) before it
verifies the responder (step 3). That is fine — a membership is a public
credential (NodeId + fabric + TTL, no secret); only the stdin payload is withheld
until verification.

## Responder logic and serve modes

In `serve_session` ([`wires/transport.rs`](../wires/transport.rs)), the serve
configuration gains an optional `roster_head: Option<RosterHead>`. After the
slice-1 inclusion check (and any scope/grant check), when a head is configured:

1. Require `proof` present, else `Error::InclusionProofRequired`.
2. `check_roster_inclusion(&head, &proof, trust_root, caller, now_unix())?`.

`trust_root` *is* the fabric root, as in slice 1. With no head configured, `serve`
is unchanged from slice 1 (membership + CRL + TTL, plus `--allow-any-member` /
`--scope` modes). The head is purely additive.

### Caller identity to the served child

When a head admits the caller, extend the slice-1 env injection with the version
that vouched for them, scrubbing inherited `WIRES_*` first exactly as slice 1
does:

```rust
.env_remove("WIRES_ROSTER_VERSION")
.env("WIRES_ROSTER_VERSION", head.version.0.to_string())  // the roster that admitted this caller
```

alongside `WIRES_CALLER_NODE` / `WIRES_FABRIC_ROOT` / `WIRES_MEMBERSHIP_NOT_AFTER`.
The child now learns not just *who* its caller is but *which roster version*
admitted them — a server can log or gate on it. As in slice 1, every value is
server-derived post-verification, never a handshake claim.

## CLI and keystore

All roster authoring is offline admin (no network), routed through `cli_admin`
like `grant` / `member`:

- **`wires roster add --member <hex NodeId>`** / **`remove --member <hex NodeId>`**
  — edit the local `roster.json`; no key needed.
- **`wires roster commit [--root-seed[-file]] [--ttl | --not-after] [--out <dir>]`**
  — the only signing op: bump the version, build the tree, sign the head, write
  `roster-head.json`, print the head token, and emit each member's `InclusionProof`
  (to `--out`, or stdout). Mirrors `member` for root resolution and
  `resolve_not_after`.
- **`wires roster head`** — print the current head token, to copy to a verifier.
- **`wires serve --roster-head <token | file>`** — resolve a head (inline → env →
  file → keystore `roster-head.json`); when present, enforce it. Absent ⇒ slice-1
  behavior.
- **`wires connect --inclusion-proof <token | file>`** — resolve the member's
  proof (inline → env → file → keystore `inclusion-proof.json`), mirroring
  `--membership`, and present it in the handshake.

Keystore files ([`wires/keystore.rs`](../wires/keystore.rs)), each with a
read/save pair and a resolver mirroring the slice-1 `membership` plumbing:

| File | Mode | Holder | Purpose |
|---|---|---|---|
| `roster.json` | `0600` | root | the full member set + version (reveals membership → private) |
| `roster-head.json` | `0644` | verifier | the signed head (public; leaks nothing) |
| `inclusion-proof.json` | `0644` | member | the member's own path (public; reveals only its own membership) |

`serve` now also resolves its **own** `membership.json` (+ optional
`inclusion-proof.json`) to present in the ack — the same files slice 1 added,
read on the responder side for the first time.

## Out of scope (deferred by design)

- **The sealed full-set blob and member-facing enumeration** — the confidential
  encrypted set readable by members and the root. The root enumerates its own
  local `roster.json` trivially; the sealed blob is slice (c).
- **Gossip head distribution, iroh-blobs, the blind persistence node** — slice (c).
  Here the head and proofs move by file copy.
- **Monotonic-version enforcement** across heads — slice (c); the field is signed
  now.
- **Pairing minting memberships** — sibling slice (a).
- **Sparse Merkle trees / non-membership proofs** — an enterprise/transparency
  upgrade; the binary tree suffices at personal scale.
- **Federated identity claims in leaves, root rotation** — later slices, as on
  `main`.

## Soundness analysis

- **Non-transferability, both directions.** Forward: `proof.member != caller`
  rejects a path presented over a connection iroh did not authenticate as
  `member`. Reverse (the ack): `responder_membership.member != <authenticated
  target id>` rejects a service replaying someone else's credential. The single
  load-bearing property in both is `caller = to_node_id(conn.remote_id())` — the
  authenticated peer, never a wire field. Treat it as inviolable.
- **Revocation is forgery-proof, freshness-bounded.** A removed member cannot
  forge a path to a new head (it would need the root key) — so verifiers holding
  the head reject instantly. A head-less verifier accepts until the credential's
  TTL expires; that window is the explicit, bounded price of offline operation,
  and short TTLs shrink it. This is the vision's "the residual risk is freshness,
  not forgery."
- **Anti-rollback is deferred but format-ready.** A signed head is monotonic in
  `version`, but this slice does not *enforce* rejecting an older head: with
  file-copied heads there is no untrusted channel to roll one back over, and
  enforcement needs persistent "highest-seen" state. Slice (c), where heads arrive
  over gossip, adds that state and the `not_after` self-expiry already in the head
  bounds a withheld-update attack in the meantime. Nothing about the format
  changes when enforcement arrives.
- **Proof churn is a distribution cost, not a crypto cost.** A whole-set head
  fuses every member into one root, so *any* commit moves the root and every
  outstanding path must be refreshed against the new head — **including members
  unrelated to the change.** Concretely: with roster `{A, B}` at head v1, add `C`
  and commit head v2; once a verifier adopts v2 (the whole point of committing it),
  `A`'s and `B`'s v1 proofs fail — `recompute → R1 ≠ R2`; the version pin merely
  turns the resulting `NotInRoster` into a clearer `StaleProof`. A verifier
  recognizes `C` *iff* it enforces v2 *iff* it rejects the v1 proofs it had been
  accepting. This is the price of a single authoritative current-set head, taken
  knowingly. The mitigations:
  - The *root moving* is inherent to a current-set commitment; the *per-node push*
    is **not** — a proof is derivable from `(set + head)`. In slice (c) a member
    recomputes its own `O(log N)` path from the gossiped head and the
    content-addressed sealed set, so the root pushes only the 32-byte head, at a
    cost independent of `N`. This is the decisive mitigation, and the reason the
    sealed-set blob exists.
  - Proofs are needed only **at dial time**, so a member refreshes lazily (per
    active dialer, when it next connects after a head change), never fabric-wide on
    every commit; and commits can be **batched**.
  - **In this slice there is no distribution layer, so the refresh is manual (file
    copy)** — an accepted, temporary tax that (c) removes. It is tolerable here only
    because personal-scale sets are tiny and change rarely.
  - At large/churny scale the flat roster is the wrong tool outright; **slice 3**
    (federation, short-TTL credentials, revoke-by-not-renewing) replaces it — no
    commitment to re-sign, no proofs to reissue, so the tax dissolves rather than
    being mitigated.
- **Confidentiality of the head.** The head is a 32-byte root plus a signature and
  timestamps; it reveals neither the size nor the members of the set. A proof
  reveals only its holder's NodeId and `O(log n)` sibling hashes — never another
  member's identity. The full set is confidential because it simply is not
  published in this slice (and will be sealed in (c)). This is the
  public-signed-head / encrypted-full-set split the vision calls for.
- **Canonical-JSON invariant.** As in slice 1, `canonical_bytes` depends on
  `serde_json`'s default `BTreeMap` key ordering; a known-answer test on a fixed
  `RosterHeadBody` guards it, and `preserve_order` / `arbitrary_precision` must
  never be enabled.
- **Versioning is downgrade-resistant.** A v2 head re-encoded as v1 changes the
  signed bytes and fails; a v1-only verifier rejects v2 outright. The one rule, as
  ever: never `skip_serializing_if` inside a signed body.

## Implementation roadmap

Build is **Bazel-only** (`bazel test //...`; never `cargo build`/`cargo test` —
see [CLAUDE.md](../CLAUDE.md)). New `.rs` files are picked up by each package's
`glob(["*.rs"])` srcs. **Unlike slice 1, this slice adds a new external crate**
(`blake3`): add it to the root `[workspace.dependencies]` and `library/Cargo.toml`,
refresh the lockfile with the Bazel-vendored cargo
(`bazel run @rules_rust//tools/upstream_wrapper:cargo -- generate-lockfile`), and
hand-edit `library/BUILD` to add `@crates//:blake3` to `deps`. Follow the repo's
type-driven order: signatures + docstrings → `proptest` + unit tests (red) →
implement (green) → doctests → readability.

**Phase 1 — pure `//library` (`bazel test //library/...`)**
1. Add `Error::{NotInRoster, StaleProof, InclusionProofRequired}`.
2. `leaf_hash` / `node_hash` known-answer vectors; roots of the empty, 1-, 2-, and
   3-member sets assert exact bytes (locks the odd-node rule and edge cases).
3. proptest: for a random `Roster` of `N` members, every member's `proof_for`
   recomputes to `root_hash`; a non-member has no proof, and a hand-built path for
   a non-member recomputes to something `!= root` (`NotInRoster`).
4. `Roster::commit` then `RosterHead::verify` round-trips (proptest over random
   seeds/times); `commit` bumps the version.
5. Tampering any signed head field (`fabric`/`version`/`root`/`issued`/`not_after`/
   `format`) ⇒ `InvalidSignature` (or `UnsupportedVersion` for `format`);
   `verify(other_root)` and an unsigned `fabric` rewrite both fail — locks the pin.
6. `encode`/`decode` round-trips for head and proof; garbage decode never panics.
7. `check_roster_inclusion` truth table (proptest) + targeted `Expired` /
   `SubjectMismatch` / `StaleProof` / `NotInRoster`.
8. Known-answer `canonical_bytes(RosterHeadBody)` byte-string test (fixed NodeIds).
9. `Frame::Handshake` and `Frame::HandshakeAck` round-trip with `proof: Some/None`;
   update the `session.rs` `frame()` proptest; truncated/garbage still safe.

**Phase 2 — `//wires` transport + CLI (`bazel test //wires/...`)**
10. Head-enforcing `serve_session` accepts a valid member with a matching proof;
    `cat` child echoes; exit 0.
11. Rejects a missing proof (`InclusionProofRequired`), a proof for another member
    (`SubjectMismatch`), a stale-version proof (`StaleProof`), and a
    removed-then-re-committed member's old proof (`NotInRoster`).
12. Head-less `serve_session` is unchanged slice-1 behavior.
13. `roster commit` emits a head and proofs that pass `check_roster_inclusion`;
    `add`/`remove` mutate the set and the next `commit` bumps the version.
14. Keystore round-trips for `roster.json` (0600), `roster-head.json` (0644),
    `inclusion-proof.json` (0644); resolvers prefer inline → env → file → keystore.

**Phase 3 — end-to-end (iroh loopback, mirrors `loopback_echo_round_trip`)**
15. The root commits a roster of `{member}`; an inclusion-only `serve_on` enforces
    the head; a dialer presents its membership **and** proof over a real loopback
    connection; the child prints `WIRES_CALLER_NODE` / `WIRES_ROSTER_VERSION` and
    they match. Negatives: a proof from a re-committed (member-removed) head ⇒
    `connect_on` errors, child never runs.
16. **Mutual inclusion:** a `--target` (ticket-less) dialer aborts before sending
    stdin when the responder's ack carries a membership signed by a different root
    or an expired membership; succeeds when the responder presents a valid
    membership. (Reverse roster-freshness is slice (c).)

## Manual demonstration (once built)

```bash
bazel run -q //wires -- keygen --save-root                       # fabric root → ROOT_ID
bazel run -q //wires -- keygen --save-node                       # service node → SVC_ID
bazel run -q //wires -- keygen --save-node                       # a member node → MEMBER_ID
bazel run -q //wires -- member --subject "$MEMBER_ID" --ttl 3600 --save
bazel run -q //wires -- member --subject "$SVC_ID"    --ttl 3600 --save   # the service is a member too

bazel run -q //wires -- roster add --member "$MEMBER_ID"
bazel run -q //wires -- roster add --member "$SVC_ID"
bazel run -q //wires -- roster commit --ttl 3600 --out ./proofs  # → roster-head.json + per-member proofs

# Verifier (the service node) enforces the head:
bazel run -q //wires -- serve --trust-root "$ROOT_ID" --allow-any-member \
  --roster-head ./roster-head.json \
  -- printenv WIRES_CALLER_NODE WIRES_ROSTER_VERSION

# Member dials, presenting membership + its inclusion proof:
bazel run -q //wires -- connect --target "$SVC_ID" \
  --inclusion-proof ./proofs/$MEMBER_ID.proof
# → the child prints the member's node id and the roster version that admitted it.
# Now: roster remove --member "$MEMBER_ID" && roster commit, and the same dial is rejected.
```

## Critical files

| File | Change |
|---|---|
| `library/roster.rs` *(new)* | `Roster`, `RosterHead`, `InclusionProof`, `MerkleRoot`, `RosterVersion`, Merkle build/verify, `commit`; re-export from `library/lib.rs` |
| `library/policy.rs` | `check_roster_inclusion` beside `check_inclusion` |
| `library/error.rs` | `NotInRoster`, `StaleProof`, `InclusionProofRequired` |
| `library/session.rs` | `proof` on `Frame::Handshake`; new `Frame::HandshakeAck`; envelope codecs; updated proptest |
| `wires/transport.rs` | `roster_head` on serve config; head gate; `HandshakeAck` send + dialer-side verify; `WIRES_ROSTER_VERSION`; ALPN bump to `/2` |
| `wires/main.rs` | `roster` subcommand (`add`/`remove`/`commit`/`head`); `serve --roster-head`; `connect --inclusion-proof`; `serve` resolves its own membership |
| `wires/keystore.rs` | `roster.json` / `roster-head.json` / `inclusion-proof.json` read/save + resolvers |
| `library/Cargo.toml`, `Cargo.toml`, `Cargo.lock`, `library/BUILD` | add `blake3` (lockfile via Bazel-vendored cargo; `@crates//:blake3` in deps) |

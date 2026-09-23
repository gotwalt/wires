# Design: provable fabric inclusion (slice 1)

> **Archived 2026-09-22.** Slice-1 design: implemented, then extended by [committed-roster.md](../committed-roster.md). Kept for its reasoning, not as a current spec; code paths cited below may have moved.

The first concrete step toward the [fabric vision](./fabric-vision.md): a
**root-signed membership credential** that lets a node prove, offline and
non-interactively, that it belongs to a fabric — and the plumbing to hand that
verified identity to a served tool with no extra network traffic.

> **Status.** Design only — not yet implemented. Scope is deliberately the
> *credential primitive*; the committed roster and delegation/federation layers
> (see the vision doc) are **reserved but not built**, behind an explicit
> credential version.

## Motivation

`serve` today authenticates the dialer to its key (iroh QUIC) and checks a
`Grant` with [`check_accept`](../../library/policy.rs) — verify root signature,
`subject == authenticated caller`, TTL, CRL. That gives authorization (*may you
reach this scope*) but not two things a fabric needs:

1. A **scope-independent identity** — "this node is a member of fabric R" —
   distinct from holding one tool grant.
2. **Delivery of that identity to the served binary.** An MCP server behind
   `serve` cannot currently see who called it.

This slice adds a `Membership` credential for (1) and environment-variable
injection for (2). It changes the layer in one small, well-bounded way and leaves
the harder revocation/identity questions to later slices by design.

## The `Membership` credential

A new pure module, `//library`'s `membership.rs`, mirroring the established
[`grant.rs`](../../library/grant.rs) shape (private borrowed-field body, derive
`Serialize`, sign over `canonical_bytes`, reuse `AlgorithmId`).

```rust
/// The signed portion of a v1 membership: every field but `sig`. Field order
/// here is irrelevant — `canonical_bytes` sorts keys.
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
/// caller equals `member` (see [`check_inclusion`]).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Membership {
    pub version: u8,        // = MEMBERSHIP_V1
    pub fabric: NodeId,     // fabric root pubkey — the authority (a SIGNED field)
    pub member: NodeId,     // the included node (non-transferable)
    pub issued: i64,        // unix seconds, mint time
    pub not_after: i64,     // unix seconds, inclusive expiry
    pub alg: AlgorithmId,
    pub sig: Signature,     // fabric-root signature over MembershipBody
}

pub const MEMBERSHIP_V1: u8 = 1;
```

```rust
impl Membership {
    /// Mint a membership: the fabric `root` signs the canonical body binding
    /// `member` to its own fabric id until `not_after`.
    pub fn mint(root: &NodeIdentity, member: NodeId, issued: i64, not_after: i64) -> Result<Membership>;

    /// Verify this membership was signed by `fabric_root` and is for that fabric.
    /// Checks algorithm, version, the `fabric == fabric_root` pin, and the
    /// signature. Does NOT check member==caller / TTL / revocation — that is
    /// [`crate::policy::check_inclusion`].
    pub fn verify(&self, fabric_root: NodeId) -> Result<()>;

    /// base64url-no-pad of `canonical_bytes(self)` — a single copy-pasteable
    /// token. The fabric id is recoverable from the decoded credential.
    pub fn encode(&self) -> Result<String>;
    pub fn decode(text: &str) -> Result<Membership>;
}
```

Two choices distinguish this from `Grant`, both load-bearing for soundness.

### `fabric` is a signed field

`Grant::verify(root)` takes the trusted root entirely out of band. `Membership`
instead carries `fabric` *inside the signed body* and `verify` additionally
asserts `self.fabric == fabric_root`. The credential **names its own authority**,
so a responder cannot be steered into checking against the wrong root, and the
leaf authority is pinned for when a v2 `authority_chain` arrives (the chain must
terminate at this `fabric`).

### Forward-compat via a signed `version` discriminant — never a signed optional

The thing signed is **bytes** from `canonical_bytes` (`serde_json` →
`serde_json::to_value`, which sorts keys via `BTreeMap`, → `to_vec`). The
signature commits to exactly the set of keys present.

The tempting way to "reserve" fields — `#[serde(skip_serializing_if =
"Option::is_none")]` optionals in the signed body — is a **canonicalization
footgun**: an absent field and a present-but-default field produce different
byte strings, and an attacker can strip an optional, re-encode, and obtain a
different-but-plausibly-valid blob. That is the classic JSON-signing downgrade
hole. It is survivable for [`CapabilityTicket`](../../library/ticket.rs) only because
tickets are *not signed* (the `Grant` inside them is, and a grant body has a
fixed key set).

So instead: the `version` field is **signed**, and **each version serializes a
fixed, total set of fields**. v2 does not add `Option<AuthorityChain>` to the v1
body; it defines a separate `MembershipBodyV2` with `authority_chain` as a
*required* field, and `verify` dispatches on `self.version`. v1 bytes stay frozen
forever; a v1-only verifier rejects a v2 credential with a clean
`Error::UnsupportedVersion` rather than silently ignoring fields it does not
understand. This makes future fields a *non-breaking addition to the type* while
never creating a "same body, two valid encodings" hazard.

> **Rule.** Optional-but-signed is forbidden. Optionals live only in *unsigned*
> envelopes (the handshake body below) and *unsigned* containers
> (`CapabilityTicket`).

`Error::UnsupportedVersion` is a one-line addition to
[`library/error.rs`](../../library/error.rs), mirroring `UnsupportedAlgorithm`.

## Inclusion policy

Alongside `check_accept` in [`library/policy.rs`](../../library/policy.rs), reusing
the existing `Crl` and the existing `SubjectMismatch` / `Expired` / `Revoked`
errors verbatim:

```rust
/// Decide whether a responder should accept `membership` from `caller` now.
///
/// Accepts iff the membership verifies under `fabric_root`, its member equals
/// `caller`, `now_unix <= not_after`, and the member is not in `crl`.
pub fn check_inclusion(
    m: &Membership, fabric_root: NodeId, caller: NodeId, now_unix: i64, crl: &Crl,
) -> Result<()> {
    m.verify(fabric_root)?;                                       // sig + version + alg + fabric pin
    if m.member != caller { return Err(Error::SubjectMismatch); } // non-transferable
    if now_unix > m.not_after { return Err(Error::Expired { not_after: m.not_after }); }
    if crl.contains(&m.member) { return Err(Error::Revoked); }
    Ok(())
}
```

The expiry boundary is `now_unix > not_after` (`not_after` inclusive), matching
`check_accept` exactly. Document the same invariant `check_accept` carries:
**`check_inclusion` is only safe when `caller` is a cryptographically
authenticated peer.** Non-transferability rests entirely on iroh having
authenticated the connection to `member`'s key; the credential alone is bearer-ish
and proves nothing about who is presenting it.

## The session handshake

[`Frame::Handshake`](../../library/session.rs) carries the credential. Today it is
`Handshake { grant: Grant }`; it becomes:

```rust
Frame::Handshake { membership: Membership, grant: Option<Grant> }
```

Membership is mandatory; the scope grant is optional. The two values are encoded
as one JSON blob via a private **unsigned** envelope struct — here
`skip_serializing_if` is fine, because the *signed* objects are the `Membership`
and `Grant` nested inside, each with its own fixed signed body:

```rust
#[derive(Serialize, Deserialize)]
struct HandshakeBody {
    membership: Membership,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grant: Option<Grant>,
}
```

`Frame::encode`/`decode` for tag `0` serialize/parse `canonical_bytes(&HandshakeBody)`
instead of a bare grant. This is an **incompatible wire change** — acceptable on a
fresh branch with no deployed peers. **Bump the session ALPN** from
`wires/session/0` to `wires/session/1` so a version mismatch fails cleanly at
connect time rather than as a confusing decode error mid-handshake.

## Responder logic and serve modes

In `serve_session` ([`wires/transport.rs`](../../wires/transport.rs)), the served
`scope` becomes `Option<&Scope>`. After reading the handshake frame:

1. `check_inclusion(&membership, trust_root, caller, now_unix(), crl)?` — **always**.
   `trust_root` *is* the fabric root in this slice (one authority signs both
   grants and memberships); the existing `--trust-root` flag covers it.
2. If `scope.is_some()`: require `grant` present, `check_accept(&grant, trust_root,
   caller, now, crl)?`, and `grant.scope == scope`.
3. If both `membership` and `grant` are present: assert `grant.subject ==
   membership.member`. Redundant (both are pinned to `caller`) but cheap, and it
   defends against a future refactor that loosens one path.

This yields two modes, surfaced in [`wires/main.rs`](../../wires/main.rs) by making
`--scope` optional on `ServeArgs`:

- **With `--scope`** — membership **and** a matching grant are required (today's
  behavior, plus an inclusion check).
- **Without `--scope`** — an *inclusion-only* responder: any fabric member may
  open a session, and the served binary does its own authorization from the
  injected identity (below). This is the enterprise-MCP shape. Because it execs
  its command for **any** member, it is an intentional authorization downgrade and
  must be **explicit**: gate it behind `--allow-any-member` and log loudly at
  startup (`"inclusion-only: any fabric member may connect"`). Without that flag
  and without `--scope`, `serve` refuses to start.

## Caller identity to the served child

At the child-spawn site in `serve_session` (the `Command::new(program)` builder),
after the gate and before `.spawn()`, inject **only post-verification,
server-derived values**, having first removed any inherited `WIRES_*` so a
malicious parent environment cannot smuggle a stale identity to a child that
trusts it:

```rust
let mut child = Command::new(program)
    .args(args)
    .env_remove("WIRES_CALLER_NODE")
    .env_remove("WIRES_FABRIC_ROOT")
    .env_remove("WIRES_MEMBERSHIP_NOT_AFTER")
    .env("WIRES_CALLER_NODE", caller.hex())          // iroh-authenticated peer, NOT a wire claim
    .env("WIRES_FABRIC_ROOT", trust_root.hex())      // the responder's own configured root
    .env("WIRES_MEMBERSHIP_NOT_AFTER", membership.not_after.to_string())
    .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
    .spawn()?;
```

`caller` comes from `to_node_id(conn.remote_id())`, never from a handshake field —
the env exposes what the responder *verified*, not what the dialer *claimed*. This
is what finally makes the README's "the tool knows which endpoint is driving it"
literally true for the served process. Identity claims (org, role, email) will
ride alongside these vars once federation lands.

## CLI and keystore

Mirroring `grant`/`revoke`, all offline admin (no network):

- **`wires member`** — new subcommand routed through `cli_admin`. Args mirror
  `grant`: `--root-seed[-file]` (resolved via `keystore::root_identity`),
  `--subject <hex NodeId>` (the member), `--ttl | --not-after` (the existing
  `resolve_not_after`), optional `--save`. Prints `Membership::encode()`. The
  fabric id is recoverable from the token, so nothing else need cross machines.
- **Keystore `membership.json`** — `read_membership()` / `save_membership()` via
  `write_text` (mode `0644` — a membership is a *public* signed credential, not a
  secret; do **not** use the `0600` `write_secret` path). Resolver
  `membership(inline, file, keystore)` mirrors `node_identity`'s
  inline → env → file → keystore precedence.
- **`wires connect --membership <token>`** — optional; falls back to
  `membership.json`. `connect` decodes it and presents it in the handshake
  alongside the (now optional) ticket grant.

`CapabilityTicket` is **unchanged** — membership is *not* folded in. A ticket is a
per-target address an operator mints; a membership is the dialer's own per-node
identity proof, reused across every connection regardless of target or scope.
Keeping them orthogonal avoids coupling a per-target artifact to a per-node one,
avoids tempting anyone to share a ticket that embeds someone's membership, and
keeps tickets small.

## Out of scope (deferred by design)

- **Pairing is unchanged.** `pair` uses its own `wires/pair/0` ALPN and JSON
  messages, not `Frame::Handshake`, so the handshake change does not touch it.
  Having `pair accept` also mint a membership for the authenticated requester is
  the natural **slice-2** follow-up.
- **Committed roster** (signed Merkle snapshot, enumeration) — slice 2.
- **Delegation / `authority_chain` and federated identity claims** — slice 3.
- **Root rotation** — out of scope for all near-term slices, as on `main`.

## Soundness analysis

- **Replay.** A `Membership` is bearer-ish but bound to `member`. Replaying a
  stolen credential buys nothing: iroh independently authenticates the connection
  to `member`'s key, so presenting it over a connection you cannot authenticate as
  `member` fails at `member != caller`. Freshness comes from (a) the live iroh
  mutual auth and (b) the TTL. No per-credential nonce is needed — the same
  reasoning that makes James's grants safe without one.
- **Non-transferability.** Enforced by `m.member != caller`, where `caller =
  to_node_id(conn.remote_id())`. This is the single load-bearing property; treat
  it as inviolable.
- **Inclusion-only downgrade.** A no-`--scope` responder execs for any member.
  Mitigations: the explicit `--allow-any-member` flag, loud startup logging, and
  the env vars that let the child authorize. Pointing an inclusion-only `serve` at
  a shell is the foreseeable foot-gun; the flag makes it a deliberate act.
- **Versioning is downgrade-resistant.** Stripping a v2 `authority_chain` and
  re-presenting as v1 fails: the signature is over the v2 body, re-encoding as v1
  changes the bytes, and a v1-only verifier rejects v2 outright. The one rule:
  *never* `skip_serializing_if` inside a signed body.
- **Canonical-JSON invariant.** `canonical_bytes` depends on `serde_json`'s
  default `BTreeMap` key ordering. Enabling the `preserve_order` or
  `arbitrary_precision` feature transitively would silently change canonicalization
  and **break every existing signature.** Pin this as a do-not-touch invariant and
  add a known-answer test asserting `canonical_bytes` of a fixed `MembershipBody`
  equals a hardcoded byte string (extends the existing `codec` test
  `sorts_keys_and_is_compact`).
- **CRL is node-granular.** One `Crl` (a `Vec<NodeId>`) revokes a node for both
  grants and membership — you cannot revoke a member's grant while keeping their
  membership with a single list. Acceptable here ("revoke the node entirely");
  fine-grained revocation is the deferred roster's job.
- **Env-var visibility.** The injected vars are unforgeable *from the network*
  (only the verified responder sets them) but are readable by same-uid processes
  via `/proc/<pid>/environ`. Acceptable for slice 1; a typed side-channel is the
  richer alternative if a future need arises. (Note: these are *public ids*, not
  secrets — the README's warning about secrets leaking to a child's environment
  does not apply.)

## Implementation roadmap

Build is **Bazel-only** (`bazel test //...`; never `cargo build`/`cargo test` —
see [CLAUDE.md](../../CLAUDE.md)). New `.rs` files are picked up by each package's
`glob(["*.rs"])` srcs; no `BUILD` edits are needed because this slice adds **no
new external crate** (it reuses `serde`, `serde_json`, `base64`, `hex`, and the
existing identity/Ed25519 plumbing). Follow the repo's type-driven order:
signatures + docstrings → `proptest` + unit tests (red) → implement (green) →
doctests → readability.

**Phase 1 — pure `//library` (`bazel test //library/...`)**
1. Add `Error::UnsupportedVersion`.
2. `Membership::mint` then `verify` round-trips (proptest over random seeds/times).
3. Tampering any signed field (`member`/`fabric`/`issued`/`not_after`/`version`)
   ⇒ `InvalidSignature` (or `UnsupportedVersion` for version) — mirrors
   `grant.rs::tampered_scope_fails`.
4. `verify(other_root)` fails; a credential whose `fabric` is rewritten (unsigned)
   to a different key fails — locks the `fabric == fabric_root` pin.
5. `version = 2` ⇒ `UnsupportedVersion` — locks discriminant dispatch before any
   v2 exists.
6. `encode`/`decode` round-trips; garbage decode never panics.
7. `check_inclusion` truth table (proptest, mirrors `policy.rs::accept_iff_all_conditions`)
   + targeted `SubjectMismatch` / `Expired` / `Revoked`.
8. `Frame::Handshake` round-trips with `grant: Some` and `grant: None`; update the
   `session.rs` `frame()` proptest strategy; `truncated_is_none` /
   `garbage_never_panics` still hold.
9. Known-answer `canonical_bytes(MembershipBody)` byte-string test.

**Phase 2 — `//wires` transport + CLI (`bazel test //wires/...`)**
10. `serve_session` inclusion-only (scope `None`) accepts a valid member; `cat`
    child echoes; exit 0.
11. `serve_session` rejects wrong fabric, expired, revoked, `member != caller`
    (extend the existing `serve_rejects` helper).
12. `serve_session` with scope: membership-only ⇒ reject; membership + matching
    grant ⇒ accept; `grant.subject != membership.member` ⇒ reject.
13. `dial_session` presents the new handshake (first frame decodes to
    `Handshake { membership, grant }`).
14. `run_member` mints a token that decodes, has the right `member`/`fabric`, and
    passes `check_inclusion`.
15. Keystore membership round-trip (save→read equal; absent ⇒ `None`; mode `0644`);
    `--membership` token beats the keystore file.

**Phase 3 — end-to-end (iroh loopback, mirrors `loopback_echo_round_trip`)**
16. Inclusion-only `serve_on` (scope `None`), child =
    `sh -c 'printf "%s,%s,%s" "$WIRES_CALLER_NODE" "$WIRES_FABRIC_ROOT" "$WIRES_MEMBERSHIP_NOT_AFTER"'`.
    A dialer presents its membership over a real loopback iroh connection. Assert
    the child's stdout equals `caller.hex(),root.hex(),<not_after>` — proving
    inclusion verified end-to-end **and** the verified identity reached the child
    with no extra round-trip. Negative: a membership signed by a different root ⇒
    `connect_on` errors, child never runs.

## Manual demonstration (once built)

```bash
bazel run -q //wires -- keygen --save-root            # fabric root
bazel run -q //wires -- keygen --save-node            # a member node → MEMBER_ID
bazel run -q //wires -- member --subject "$MEMBER_ID" --ttl 3600 --save   # mint + store
bazel run -q //wires -- serve --trust-root "$ROOT_ID" --allow-any-member \
  -- printenv WIRES_CALLER_NODE WIRES_FABRIC_ROOT      # inclusion-only responder
bazel run -q //wires -- connect --target "$SERVE_NODE_ID"   # from the member node
# → prints the member's own node id and the fabric root: identity conveyed, zero extra round-trips.
```

## Critical files

| File | Change |
|---|---|
| `library/membership.rs` *(new)* | `Membership`, `mint`/`verify`, `encode`/`decode`; re-export from `library/lib.rs` |
| `library/policy.rs` | `check_inclusion` beside `check_accept`; reuse `Crl` |
| `library/error.rs` | `UnsupportedVersion` |
| `library/session.rs` | `Frame::Handshake { membership, grant: Option<Grant> }`, `HandshakeBody` codec, updated proptest |
| `wires/transport.rs` | `serve_session` inclusion gate + env injection; `serve`/`serve_on` + `dial_session`/`connect_*` signatures; ALPN bump |
| `wires/main.rs` | `member` subcommand; optional `--scope` + `--allow-any-member`; `connect` loads/presents membership |
| `wires/keystore.rs` | `membership.json` read/save + resolver |

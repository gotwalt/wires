# wires — responder-driven pairing (OAuth-style)

**Status:** design, 2026-05-15. Replaces the `InviteToken`-based onboarding sketch in the substrate spec §2.6 and the hosted-service spec §8.

## 1. Motivation

Today's onboarding is *inviter-driven*: Alice pre-mints a `Capability` and ships it to Bob as an `InviteToken` (base64 paste). Bob is initialized with `wires init --root <ROOT_HEX>` and then runs `wires join <token>` to install the cap.

This is the wrong shape for the agents we actually want to enroll. "Bob" is rarely a person — it's something like an email account, a home-automation system, a calendar bridge. Such an agent has no business knowing Alice's root pubkey in advance, no business choosing its own scopes from Alice's namespace, and no reason to be parameterized at init time with household-specific identity. It should just be itself.

The natural model is OAuth: the agent (Bob) declares "I am this kind of thing, and I'd like permissions on these channels"; the operator (Alice) approves or denies, optionally narrowing scopes, and the agent installs whatever was granted.

This spec defines that protocol.

## 2. Scope of change

**Replaced:**

- `wires init --root <ROOT_HEX>` — removed. Bob no longer pins a root at init.
- `wires invite --agent-pubkey ... --topics ... --rights ...` as the *onboarding* entry point — removed. Supplemental cap-mints post-pairing continue to be possible via the existing substrate `__cap.grant` mechanism (out of scope here).
- `wires join <token>` — removed.
- `wires-net::invite::InviteToken` — deleted.

**Added:**

- `wires-net::pair::PairRequest` — Bob's signed authorization-request, encoded as base64 JSON. QR-or-paste.
- `wires-net::pair::PairGrant` (+ `PairGrantEnvelope`) — Alice's sealed authorization-grant, delivered over a new `/wires/pair/0` ALPN.
- `wires pair-listen` — Bob's command to enter a short pair window.
- `wires pair-approve <token>` — Alice's command to consent and grant.
- `wires init --new-root` — explicit flag for the operator path that today is the implicit default. Plain `wires init` now generates identity only.

**Trust model.** TOFU + fresh nonce. The QR/paste handoff is the trust-establishment act. Bob has no prior knowledge of any root; he accepts the first valid signed `PairGrant` arriving over `/wires/pair/0` whose nonce matches his outstanding `PairRequest`. After install, `root_pubkey_hex` is pinned in `config.toml`; subsequent `__caps` envelopes must be signed by it. Re-pairing requires a wipe (out of scope; root rotation lives in the substrate spec's `__cap.root_rotation`).

**Crate layout impact:**

- `wires-net/src/pair.rs` — new module, peer of `tenant.rs`.
- `wires-net/src/invite.rs` — deleted.
- `wires-net/src/peer_hint.rs` — kept; reused for `PairGrant.host.peer_hints`.
- `wires-cli/src/cmd/pair_listen.rs`, `wires-cli/src/cmd/pair_approve.rs` — new.
- `wires-cli/src/cmd/invite.rs`, `wires-cli/src/cmd/join.rs` — deleted.
- `wires-node` grows a `pair::listen` runtime entry point alongside the existing `replay` and `tenant` handlers in `NodeRuntime`.

Layering is unchanged: `wires-net::pair` depends on `wires-core` (for `Capability`, ed25519 verify) and `wires-crypto` (for sealed-box).

## 3. `PairRequest` (Bob → Alice)

```rust
// wires-net/src/pair.rs

pub struct PairRequest {
    pub version: u8,                       // currently 1
    pub agent_pubkey: [u8; 32],            // Bob's ed25519 agent identity
    pub agent_x25519: [u8; 32],            // Bob's persistent x25519 — Alice records it so future
                                           // supplemental `__cap.grant` events can be SealedTo it;
                                           // not used during pairing itself
    pub ephemeral_x25519: [u8; 32],        // Bob's one-shot key for sealing the PairGrant
    pub dial: PairDial,                    // iroh node addr Alice will dial
    pub manifest: PairManifest,            // self-asserted role + requested scopes
    pub nonce: [u8; 32],                   // random, single-use
    pub issued_at: i64,                    // unix ms
    pub expires: i64,                      // unix ms — TTL from issued_at, default 5 min
    pub signature: [u8; 64],               // ed25519 over canonical JSON with `signature` zeroed
}

pub struct PairDial {
    pub node_id: String,                   // hex iroh EndpointId
    pub addrs: Vec<String>,                // observed socket addrs (best-effort)
    pub relay: Option<String>,             // relay url if known
}

pub struct PairManifest {
    pub role: String,                      // short ASCII slug, e.g. "home-automation", "email"
    pub description: String,               // free-form human label shown at consent
    pub requested_scopes: Vec<RequestedScope>,
}

pub struct RequestedScope {
    pub topic_name: String,                // human topic name (e.g. "home.notes")
    pub rights: Vec<Right>,                // ["read"], ["read", "write"], etc.
}
```

**Encoding.** URL-safe base64 of canonical JSON (same envelope shape as the deleted `InviteToken`, so the QR pipeline is unchanged).

**Signing.** Bob's agent ed25519 signs the canonical JSON with `signature: [0u8; 64]`. The signature scope covers every other field — same pattern as `WireMessage::SigningView` in `wires-core`. Detached signature, no AAD construction needed.

**Why ephemeral X25519.** Bob's persistent x25519 is for long-term `SealedTo` events on `__caps`. The pairing grant is short-lived and high-value; using a one-shot key gives forward secrecy. A future compromise of Bob's persistent x25519 does not decrypt the stored `PairGrant` ciphertext.

**Why dial info inline.** Alice has no other way to discover Bob; the QR is the only handoff. `addrs` and `relay` are best-effort hints; iroh's N0 discovery does the rest.

**Why topic *names*, not IDs.** Bob is household-naïve. He knows he wants `home.notes` or `mail.**`, but he doesn't have a topic-id map yet — Alice owns the name→id table. Alice's `pair-approve` resolves names against her `topic_names.json`, refuses unknown names with a clear error, and embeds the resolved IDs into the `PairGrant`.

**Nonce semantics.** Random 32 bytes. Bob persists it (in `pair_pending.json`) for the duration of his pair-listen window. He rejects any `PairGrant` whose `nonce` doesn't match. After successful pairing or TTL expiry, the file is deleted. Single-use per attempt.

**Size bounds** (enforced at decode; reject with `DecodeToken` if exceeded):

- `role`: 1..=32 ASCII bytes, `[a-z0-9_-]+`.
- `description`: 1..=256 UTF-8 bytes.
- `requested_scopes`: 1..=16 entries.
- `RequestedScope.topic_name`: 1..=128 bytes, matching the substrate spec's topic-name grammar.
- TTL (`expires - issued_at`): 1 min..=1 hour. Default 5 min. Keeps the attack window short.
- Whole encoded token: ≤ 4 KiB. Keeps the QR scannable on real-world phones.

## 4. `PairGrant` (Alice → Bob)

```rust
// wires-net/src/pair.rs

pub struct PairGrant {
    pub version: u8,                       // currently 1
    pub root_pubkey: [u8; 32],             // the household root ed25519
    pub cap: Capability,                   // root-signed wires-Capability
    pub topic_keys: Vec<TopicEpochKey>,    // per granted topic, current epoch key
    pub topic_names: Vec<TopicNameEntry>,  // human name → topic_id, seeds Bob's local name map
    pub host: Option<HostInfo>,            // Some(_) iff Alice is paired with a host
    pub nonce: [u8; 32],                   // MUST equal PairRequest.nonce — echoed for freshness
    pub issued_at: i64,                    // unix ms
}

pub struct TopicEpochKey {
    pub topic_id: [u8; 32],
    pub epoch: u32,
    pub key: [u8; 32],                     // ChaCha20-Poly1305 epoch key
}

pub struct TopicNameEntry {
    pub topic_id: [u8; 32],
    pub name: String,
}

pub struct HostInfo {
    pub peer_hints: Vec<PeerHint>,
    pub service_discovery_url: Option<String>,
}
```

**Wire envelope** (the bytes that hit `/wires/pair/0`):

```rust
pub struct PairGrantEnvelope {
    pub root_pubkey:    [u8; 32], // claimed signer; matches inner.root_pubkey
    pub sealed_payload: Vec<u8>,  // 32-byte Alice ephemeral X25519 pubkey || ChaCha20-Poly1305 ciphertext
    pub signature:      [u8; 64], // ed25519 by root over (root_pubkey || sealed_payload)
}
```

**Crypto choices.**

- **Sealed to Bob's ephemeral X25519** via `wires-crypto::sealed::seal_to`. That helper internally generates Alice's one-shot ephemeral X25519 keypair, prepends the public key to the ciphertext, and discards the secret on return. The first 32 bytes of `sealed_payload` are therefore Alice's ephemeral pubkey; the remaining bytes are the AEAD ciphertext. Forward-secret — the ephemeral secret never persists.
- **Sealed-box AAD = `b"wires.pair.v1"`** (a fixed domain separator). The AEAD nonce is derived from `(grant.nonce, grant.root_pubkey, seq=0)` per the existing sealed-box convention in `wires_crypto::sealed::sealed_nonce`. A tampered or stale nonce causes AEAD failure on decrypt.
- **Outer signature by the root key.** The signature covers `root_pubkey || sealed_payload` — and because Alice's ephemeral pubkey is the first 32 bytes of `sealed_payload`, the signature also authenticates the ephemeral key. Bob has no agent pubkey to trust yet; he learns the root pubkey from this envelope. The verification chain: outer signature checks against `envelope.root_pubkey`; that pubkey matches `inner.root_pubkey`; `cap.verify(&inner.root_pubkey)` succeeds (i.e. the cap was actually signed by that root); `cap.agent` matches Bob's ed25519 identity. TOFU on the root pubkey is the trust act; the QR handoff and nonce binding give freshness.
- **Nonce binding.** A `PairGrant` whose nonce doesn't match Bob's pending request fails AEAD decryption (because the nonce is baked into the AEAD nonce). Bob also re-checks the inner `grant.nonce` against pending after decrypt as belt-and-suspenders, but in practice the AEAD layer catches the mismatch first and surfaces it as `SealUndecryptable`. Closes replay (an old grant cannot bootstrap a new Bob-instance) and substitution (a grant for a different agent cannot be redirected because `cap.agent` is signed inside).

**Validation order on Bob's receive side:**

1. Decode envelope; verify outer ed25519 signature against `envelope.root_pubkey` over `(root_pubkey || sealed_payload)`.
2. Sealed-box-decrypt `sealed_payload` with Bob's ephemeral X25519 secret. The first 32 bytes of `sealed_payload` are Alice's ephemeral pubkey (per `wires_crypto::sealed`); the rest is AEAD ciphertext keyed by ECDH-derived material with AAD `b"wires.pair.v1"` and AEAD nonce derived from the pending request nonce + `envelope.root_pubkey`. A wrong recipient or stale nonce fails here.
3. Parse inner `PairGrant`. Check `inner.root_pubkey == envelope.root_pubkey` (defensive; the AEAD layer already binds them in practice).
4. Check `inner.nonce == pending_nonce` (from `pair_pending.json`) — also defensive given the AEAD nonce binding.
5. Check `inner.issued_at` is within the still-valid request window (≤ `request.expires`).
6. Verify the `Capability`: `cap.verify(&inner.root_pubkey)` returns `Ok` (signature valid under that root) and `cap.agent == self.agent_pubkey` (the ed25519 identity on disk).
7. Install everything (see §6 for order and idempotence). Delete `pair_pending.json`.
8. Send `PairFrame::Ack` so Alice's CLI knows pairing succeeded.

Any check failure aborts without writing state and returns a typed `PairFrame::Reject` with a `PairRejectCode` (§7).

## 5. `/wires/pair/0` ALPN

A new ALPN registered on the iroh `Router` Bob already runs after `wires init`. Same shape as `wires-net::tenant`: length-prefixed JSON frames over a single bidirectional QUIC stream.

```
client → server : PairFrame::Grant(PairGrantEnvelope)
server → client : PairFrame::Ack(PairAck)
                    | PairFrame::Reject(PairReject)
```

```rust
pub enum PairFrame {
    Grant(PairGrantEnvelope),
    Ack(PairAck),
    Reject(PairReject),
}

pub struct PairAck {
    pub installed_cap_id: [u8; 16],
    pub installed_at: i64,                 // unix ms
}

pub struct PairReject {
    pub code: PairRejectCode,
    pub message: String,                   // human-readable, safe to print
}

pub enum PairRejectCode {
    NonceMismatch,
    NonceExpired,
    SignatureInvalid,
    SealUndecryptable,
    RootMismatch,
    CapInvalid,
    UnknownTopic,
    AlreadyPaired,
    InternalError,
}
```

**Framing.** Reuse `wires-net::framing::{read_frame, write_frame}` (length-prefixed JSON, 64 KiB cap). A typical `PairGrant` with 2–3 topics is ~1–2 KiB.

**Server side (Bob).**

```rust
pub trait PairHandler: Send + Sync + 'static {
    async fn handle_grant(&self, envelope: PairGrantEnvelope) -> PairFrame;
}

pub struct PairProtocol<H: PairHandler> { /* iroh ProtocolHandler */ }
```

`PairProtocol::accept` reads one `PairFrame::Grant`, calls `handler.handle_grant`, writes the resulting `Ack` or `Reject`, then closes the stream. After a successful `Ack`, the handler signals the outer `pair-listen` loop (via `oneshot` or `watch`) → the runtime drops the listener and exits the pair-mode window.

**Client side (Alice).**

```rust
pub struct PairClient { endpoint: iroh::Endpoint }

impl PairClient {
    pub async fn deliver_grant(
        &self,
        dial: &PairDial,
        envelope: PairGrantEnvelope,
    ) -> Result<PairAck, PairError>;
}
```

Resolves `dial.node_id` into an iroh `NodeAddr`, adds `dial.addrs` and `dial.relay` as discovery hints, opens a stream on `/wires/pair/0`, writes the `Grant`, reads one frame back. Maps `Reject` into `PairError::Rejected`.

**Listen lifecycle (Bob).** `wires pair-listen`:

1. Opens `Node` and `NodeRuntime`.
2. Registers `PairProtocol` on the `Router` alongside gossip and replay.
3. Writes `pair_pending.json` (nonce, ephemeral_x25519_secret, expires, request token).
4. Prints the `PairRequest` as base64 (and, with `--qr`, as a terminal QR).
5. Waits on a `oneshot::Receiver<PairOutcome>` with deadline at `expires`.
6. On `Ok(Paired)` — installation already happened in step 7 of §4 — prints summary, exits 0.
7. On timeout — prints "pairing window expired", deletes `pair_pending.json`, exits non-zero.

**Concurrency / repeat dials.** Multiple Alice attempts within the window are allowed (operator fat-fingers, retries). Bob's handler is serialized by a `tokio::sync::Mutex`. Idempotent installs (§6) make duplicate grants safe; outside the window the ALPN is not registered.

**Why not piggyback on `/wires/tenant/0`?** Two reasons: (1) `wires-host` serves the tenant ALPN but not pairing; pairing is purely peer-to-peer and the host has no role. (2) The trust models differ — tenant authenticates by root key on the host side; pair authenticates by ephemeral nonce on Bob's side. Folding them invites confusion.

## 6. Persistence + security invariants

**New on-disk state.** One new file in Bob's data dir, present only during an open pair-listen:

```
~/.wires/
  pair_pending.json          # mode 0600
```

Shape:

```json
{
  "version": 1,
  "nonce_hex": "<64 hex chars>",
  "ephemeral_x25519_secret_hex": "<64 hex chars>",
  "expires_unix_ms": 1747343821000,
  "request_token": "<base64 of the PairRequest Bob printed>"
}
```

Mode 0600 to match the other secret material (`identity.ed25519`, `identity.x25519`, `iroh.secret`, `root.ed25519`).

**Crash recovery / idempotence.** Every step of grant installation is idempotent on its natural key:

- `Capability` insert keyed by `cap_id`.
- Epoch-key insert keyed by `(topic_id, epoch)`.
- `topic_names.json` rebuild-and-write of a `name → topic_id` map; re-merging the same entries is identity.
- `config.toml` updates (`root_pubkey_hex`, `host`) overwrite the same keys.

Install order on Bob's side: write config (root pubkey + host) → topic names → epoch keys → cap → delete `pair_pending.json` → send `Ack`. If Bob crashes anywhere before deleting `pair_pending.json`, on next `wires pair-listen` invocation we detect the pending file, refuse to overwrite with a fresh nonce, and resume listening with the same nonce + same ephemeral key + same TTL. The pending file holds the original `request_token`, so role/description/requested-scopes flags from the resuming invocation are ignored — the user gets exactly the request Bob already printed. Alice can retry `pair-approve` with the original token; duplicate `Grant` frames hit idempotent writes and return a fresh `Ack`. To force a fresh attempt, the user deletes `pair_pending.json` manually (or waits for TTL). `PairRejectCode::AlreadyPaired` is reserved for grants arriving *outside* the resolved pair-listen window (i.e. `pair_pending.json` is gone because pairing already completed).

**Single-use nonce, defined precisely.**

- Bob persists the nonce in `pair_pending.json` for the entire pair-listen window.
- Any `PairGrant` whose inner `nonce` ≠ pending nonce is rejected with `NonceMismatch`.
- The same nonce may be used by multiple grant frames in the same window iff they're crash-recovery retries from the same Alice — idempotence makes this safe.
- After the window closes (paired or TTL), `pair_pending.json` is deleted and the nonce is gone forever. Next `pair-listen` generates a fresh nonce.

**Trust pinning, defined precisely.** `config.toml` gains `root_pubkey_hex` only at successful pair-install. After that, every `__caps` envelope Bob ingests must be signed by that pubkey. There is no rotate-to-different-root path in v1 — re-pairing requires a wipe of `caps.redb`, `keys_*.redb`, `config.toml`, and `topic_names.json`, then a fresh `wires init` + `pair-listen`. Future `__cap.root_rotation` support handles the legitimate rotation case.

**Invariants.**

1. `pair_pending.json` exists ⟺ Bob is in an unresolved pair-listen window.
2. `config.toml.root_pubkey_hex` is set ⟺ Bob has been successfully paired at least once.
3. `caps.redb` contains a cap for a topic ⟺ Bob received a valid `Capability` for that topic signed by `root_pubkey_hex`.
4. `keys_<topic>.redb` contains keys ⟹ `caps.redb` contains a cap referencing that topic. (Bob doesn't hoard epoch keys he can't authorize.)
5. Every installed cap's `agent` field equals the local `identity.ed25519` pubkey. Sanity-check at install; refuses caps targeted at someone else.

## 7. Error handling

**Rust error type** in `wires-net::pair::PairError` follows the project's snafu convention (every variant has `#[snafu(implicit)] location: Location`, display strings end with `, at {location}`, external errors are leaves linked via `source`).

Variants:

- `DecodeToken { source }` — base64 or JSON decode of `PairRequest` failed.
- `BadRequestSignature` — Bob's signature on `PairRequest` did not verify.
- `Expired { issued_at, now }` — request TTL elapsed before Alice tried to approve.
- `UnknownTopic { name }` — Alice's `topic_names.json` has no entry for a requested name.
- `EpochKeyMissing { topic_id }` — Alice has no current epoch key for a topic she's about to grant.
- `Dial { source }` — iroh dial to Bob failed.
- `Stream { source }` — bidirectional QUIC stream error.
- `Frame { source }` — length-prefixed framing error (oversize, truncated, malformed).
- `Rejected { code, message }` — Bob sent `PairFrame::Reject`; surfaces `PairRejectCode` + Bob's human message.
- `InstallFailed { source }` — Bob-side failure persisting the grant.

**Wire reject codes** are the frozen public surface. Mapping inside Bob's `PairProtocol::handle_grant`:

| Internal cause | `PairRejectCode` |
|---|---|
| inner `nonce` ≠ pending | `NonceMismatch` |
| `pair_pending.json` was deleted between dial and grant | `NonceExpired` |
| outer ed25519 verify failed | `SignatureInvalid` |
| sealed-box decrypt failed | `SealUndecryptable` |
| `inner.root_pubkey != envelope.root_pubkey` | `RootMismatch` |
| `cap.verify(&inner.root_pubkey)` fails / cap.agent ≠ self / any inner data check | `CapInvalid` |
| `topic_keys` references a `topic_id` not in `topic_names` | `CapInvalid` |
| handler invoked after successful install in the same window | `AlreadyPaired` |
| redb or file write error during install | `InternalError` |

**Operator-facing rendering.** Alice's `pair-approve` translates `PairError::Rejected` into a short sentence; e.g.

```
Pairing rejected by Bob: NonceMismatch
  Bob's nonce doesn't match — the token may be from a previous pair-listen.
  Ask Bob to run `wires pair-listen` again and rescan.
```

**Timeouts.**

- Bob's `pair-listen` enforces the request TTL (default 5 min); on expiry the listener drops, `pair_pending.json` is deleted, exit nonzero.
- Alice's `pair-approve` dial has a 30s timeout against `dial.node_id`.
- The stream has a 30s overall deadline once connected; the grant-handler is expected to complete in well under a second.

**Concurrency on Bob's side.** A `tokio::sync::Mutex` inside the `PairHandler` serializes grant processing. Two concurrent Alice dials in the same window: the first installs and `Ack`s; the second sees `pair_pending.json` gone and gets `AlreadyPaired`.

**Logging.** `info!` for each grant accepted/rejected with `cap_id` and reject code; `debug!` for stream lifecycle. Never log ephemeral X25519 secrets, epoch keys, or full nonces (prefix only).

## 8. CLI surface

**`wires init`** — identity only. Generates `identity.ed25519`, `identity.x25519`, `iroh.secret`, an empty `config.toml`. No root, no caps, no household awareness. Bob's only init step.

**`wires init --new-root`** — identity plus a fresh local root key (`root.ed25519`). Alice's init step. Replaces today's default "no-flag generates root" behavior — now it's explicit.

**`wires init --root <ROOT_HEX>`** — *removed*. There's no use case for "I know the root but skip pairing" — Bob still needs caps, epoch keys, and host info.

**`wires topic create <name>`** — same as today, plus: if `root.ed25519` is present and the local agent has no `read+write` cap on the new topic yet, auto-mint one and install it. Eliminates the self-invite dance.

**`wires pair-listen`** — Bob's side. Flags:

- `--role <slug>` (required) — short ASCII slug, e.g. `home-automation`, `email`.
- `--description <text>` (required) — human-readable label shown to Alice's operator.
- `--request <name:rights>` (repeatable, required) — `home.notes:read+write`, `mail.**:read`.
- `--ttl <duration>` (optional, default `5m`) — pair-listen window length.
- `--qr` (optional) — emits a terminal QR alongside the base64 token.

Behavior: prints the `PairRequest` token, blocks until paired or TTL. Exits 0 on pair, nonzero on timeout. Daemons (`wires-ha`, future `wires-mail`) invoke `wires-node::pair::listen` directly with role/description compiled in.

**`wires pair-approve <token>`** — Alice's side. Flags:

- `--scope <name:rights>` (repeatable, optional) — narrow per-topic rights. Default: grant each topic's requested rights.
- `--topics <names>` (optional) — narrow to a subset of requested topics. Default: grant all.
- `--no-host` (optional) — omit host info from the grant (peer-to-peer-only Bob). Default: include host info if Alice is paired with a host.
- `--yes` (optional) — skip the interactive confirmation prompt.

Behavior: decodes the token, verifies Bob's signature, prints the manifest:

```
Pair request from agent <BOB_AGENT_HEX>
  role        : email
  description : Gmail account, household@example.com
  requested   :
    mail.inbox   : read, write
    mail.sent    : read, write
  issued_at   : 2026-05-15 14:22:01 UTC
  expires_at  : 2026-05-15 14:27:01 UTC (in 4m 38s)
  nonce       : <NONCE_HEX_PREFIX>...
Approve and grant? [y/N]
```

On approve: resolves topic names against `topic_names.json` (refuses unknown names with `UnknownTopic`), reads epoch keys, mints a root-signed `Capability` using `root.ed25519`, builds the `PairGrant`, seals + signs it, dials Bob, awaits `Ack`. On success prints `Paired: cap <CAP_ID> issued to <BOB_AGENT_HEX>`.

**`wires invite` and `wires join`** — *deleted*. Subsumed by the pair flow. No migration shim — this is a prototype.

**`wires host pair / topic-register / topic-unregister / status`** — unchanged. Tenant control plane is orthogonal.

**`wires publish / cat / revoke`** — unchanged.

**Updated README walkthrough:**

- Tab 1: `wires-host --data-dir ./host`.
- Tab 2 (Alice, operator): `wires init --new-root` → `host pair --discovery-url ...` → `topic create home.notes` → `host topic-register home.notes`.
- Tab 3 (Bob): `wires init` → `wires pair-listen --role chat-agent --description "Bob" --request home.notes:read+write`. Prints token, blocks.
- Tab 2: `wires pair-approve <BOB_TOKEN>`.
- Bob's pair-listen exits; he can `wires cat home.notes --tail`.
- Tab 2 publishes; Bob's tail prints.

## 9. Testing

**Unit tests in `wires-net::pair`** (fast, no I/O):

- `PairRequest` encode/decode round-trip and `version != 1` rejection.
- `PairRequest` signature verify — tampering any field invalidates.
- `PairRequest` signature verify — substituting `agent_pubkey` rejected.
- `PairGrant` inner-payload canonical-JSON round-trip.
- `PairGrantEnvelope` outer signature verify — tampering `ephemeral_alice_x25519` or `sealed_payload` invalidates.
- Sealed-box round-trip end-to-end; decryption with the wrong ephemeral secret fails.
- Nonce-mismatch → `NonceMismatch`.
- `inner.root_pubkey != envelope.root_pubkey` → `RootMismatch`.
- Cap validation rejects when `cap.agent_pubkey != self`, wrong signature, signer ≠ inner root.
- Expiry: `inner.issued_at > request.expires` → `NonceExpired`.

**Integration tests in `wires-node`** (real iroh endpoints, `MemoryLookup` cross-registration to avoid pkarr warm-up):

- *Happy path.* Bob's `pair::listen` in a task; Alice's `pair::deliver_grant` runs and succeeds. Assert `caps.redb`, `keys_<topic>.redb`, `topic_names.json`, `config.toml` (root + host), and that `pair_pending.json` is gone. `Ack` received.
- *Narrowed scopes.* Two topics requested, one approved. Bob has one cap and one set of epoch keys; the un-granted topic name is absent.
- *Wrong cap target.* Alice's cap is for a different `agent_pubkey`. `CapInvalid`; no install.
- *Crash recovery.* Abort Bob after writing the cap but before deleting `pair_pending.json`. Restart `pair::listen` — resumes with same nonce + ephemeral key. Alice's retry completes; Bob ends up fully installed.
- *Stale token across windows.* Bob pair-listen → TTL expiry. Second `pair-listen` (new nonce). Alice tries to approve the first token. `NonceMismatch`.
- *Concurrent dials.* Two parallel Alice dials in one window. One `Ack`, one `AlreadyPaired`. Exactly one cap.

**Acceptance scenarios** (`#[ignore]`, run with `--ignored`):

- *End-to-end multi-process.* Spawn `wires-host`, spawn Bob with `wires init` + `wires pair-listen`, capture token from stdout, spawn Alice with `wires init --new-root` + `host pair` + `topic create` + `host topic-register` + `pair-approve <token>`. After pair, Alice `publish` → Bob `cat` sees the message.
- *Operator narrows scopes.* Same flow with `pair-approve --scope home.notes:read`. Bob's `publish` fails with a clear "missing write right" error; `cat` still works.

**Test deletions / rewrites.**

- All `wires-net/src/invite.rs` unit tests deleted with the file.
- `wires-cli` integration tests that exercise `invite` / `join` / `init --root` are rewritten against the new commands.
- Existing acceptance test that walks invite-and-join in the hosted-service plan: rewrite.
- Substrate spec §11 wording "agent C bootstrapped from an invite token" → "agent C bootstrapped via pair-listen / pair-approve" (doc change only).

## 10. Out of scope

Explicitly deferred:

- **Re-pairing / root rotation.** v1 is "wipe and re-pair." Real root rotation lives in the substrate spec's `__cap.root_rotation` mechanism.
- **`__cap.grant` propagation via `__caps`.** Already specified in the substrate spec; not implemented end-to-end. Pairing as designed injects the initial cap inline; supplemental caps post-pair will use the substrate mechanism once it lands. This design does not depend on it.
- **Migration from `InviteToken`.** Prototype repo — no compatibility shim. Old tokens stop working when this lands. The on-disk data layout for an already-paired Bob is unchanged (`config.toml.root_pubkey_hex` already exists today and means the same thing); only the *moment* of setting it shifts from `wires init --root` to pair-install. No upgrade step is needed for previously-paired data dirs.
- **iOS-specific QR delivery.** The protocol is QR-shaped, but the iOS scanner/UX is a separate effort. The stale iOS companion spec gets a referenced revision after this lands.
- **Multiple simultaneous pair-listens per data dir.** One Bob, one pair window. Concurrent invocations fail with "another pair-listen is active."
- **Pairing one Bob to multiple roots/households.** Bob is single-tenant. A future household-multiplex design could extend this.
- **Operator-side approval UI.** v1 is a terminal prompt; the iOS app eventually replaces it with a native consent screen; the protocol is unchanged.
- **Discovery beyond the QR.** No HTTPS service-discovery fallback for the pair channel (unlike the host tenant flow). The QR carries `dial.node_id` + `addrs` + `relay`; iroh N0 discovery covers the rest. If Bob is unreachable, pair fails — operator brings them within reach and retries.

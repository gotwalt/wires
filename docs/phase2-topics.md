# Phase 2 design: multiway topics on the committed roster

*2026-08-14. The implementation spec for restart.md Phase 2. Decisions herein were
made against the exploration of both this tree and the archived PoC
(`archive/poc-2026-05`); PoC file references are read-only ancestry, never merge
sources. The spec is the contract: code follows this document, and deviations are
edits to this document first.*

Scope: topics over iroh-gossip gated by roster inclusion; per-publisher
hash-chained logs with peer-symmetric replay; E2EE from day one (fabric data key
minted per `roster commit`, sealed per member); `wires publish` / `wires tail`.
Out of scope (restart.md): epochs, retention/eviction, cap tables, blind-relay
store-and-forward, iOS/OAuth/deploy.

## 1. Topic model — `library/topic.rs`

- `TopicId([u8; 32])` — newtype, hex serde (same discipline as `NodeId`).
  Derivation: `blake3::derive_key("wires topic-id v1", fabric_bytes ‖ name_utf8)`
  — unambiguous because fabric is fixed 32 bytes. Doubles as the iroh-gossip
  `TopicId` (via `from_bytes`).
  API: `derive(fabric: NodeId, name: &str)`, `as_bytes`, `from_bytes`, `hex`,
  `from_hex`.
- Topics are implicit: no `topic create`. Any member computes the id from its
  membership's fabric + `--topic <name>`.
- `TopicPeer { node: NodeId, addrs: Vec<SocketAddr>, relay_url: Option<String> }`
  (addrs/relay skip-serializing when empty/none).
- `TopicTicket { fabric: NodeId, name: String, peers: Vec<TopicPeer> }` —
  base64url-no-pad canonical JSON `encode`/`decode`, like `CapabilityTicket`.
  Entirely unsigned routing hints: iroh authenticates the peer key, admission
  proves membership; a tampered ticket can fail to connect, never admit.

## 2. Admission — `library/admission.rs` + `wires/admission.rs`

iroh-gossip has no auth hook → mutual handshake on ALPN `wires/topic-admit/1`,
feeding a per-process allowlist consulted by a wrapper `ProtocolHandler` before
delegating to `Gossip`. One `iroh::protocol::Router` registers gossip + admit +
replay ALPNs (two Routers clobber each other's ALPN sets — PoC trap).

### 2.1 Frames (pure)

Same 4-byte-BE-length + 1-byte-tag codec family as `session.rs`, own enum and tag
space:

```rust
pub enum AdmitFrame {
    /// tag 0 — dialer → responder.
    Request { topic: TopicId, head: RosterHead, proof: InclusionProof },
    /// tag 1 — responder → dialer on success (mutual admission in one RTT).
    Ack { topic: TopicId, head: RosterHead, proof: InclusionProof },
    /// tag 2 — refusal with human-readable reason (mirrors Frame::Denied).
    Denied { reason: String },
}
// encode() -> Result<Vec<u8>>; decode(buf) -> Result<Option<(AdmitFrame, usize)>>
// (None until a whole frame arrives; garbage never panics)
pub const MAX_ADMIT_FRAME: usize = 64 * 1024;
```

The ceiling is part of the codec, not of the reader. `wires/topic-admit/1` is
the one surface that runs **before any authorization** — the responder must read
a whole `Request` before `check_topic_admission` can say anything — so a
four-byte `FF FF FF FF` followed by a dribble would otherwise buffer 4 GiB per
connection with no credential presented. `decode` returns `BadFrame` the instant
an over-long length prefix lands (never `Ok(None)`), and `encode` refuses to
emit one, so all three readers in the tree inherit one bound instead of each
picking their own. (`wires/transport.rs`'s private `MAX_FRAME` is the Phase 1
equivalent and stays as-is.)

The envelope is unsigned; the signed objects inside (head; proof via root
recomputation) carry the authority. Caller identity is NEVER a wire field — it is
`to_node_id(&conn.remote_id())`, the iroh-authenticated key.

### 2.2 Pure decision

```rust
pub struct Admission {
    pub version: RosterVersion,
    /// Some(head) when the presented head was strictly newer and verified:
    /// the caller persists it (passive head distribution).
    pub adopt: Option<RosterHead>,
}
pub fn check_topic_admission(
    local_head: &RosterHead,
    presented_head: &RosterHead,
    proof: &InclusionProof,
    fabric_root: NodeId,
    caller: NodeId,
    now_unix: i64,
) -> Result<Admission>;
```

Head selection: adopt the presented head iff `presented.version > local.version`
AND `presented.verify(fabric_root)` passes AND it is fresh (not_after). Otherwise
check against the local head. Then `policy::check_roster_inclusion(check_head,
proof, fabric_root, caller, now)`. A proof against an older head fails
`StaleProof`; the remedy is `wires import`.

Anti-rollback is **not** free, because `local_head` is a snapshot the caller
passed in and §2.3 has each admission independently re-loading `HeadSource`.
Two admissions landing together — an honest peer with v5 (attacker removed) and
the attacker with a genuine v4 — both read v3, both compute "advances", and a
plain read-modify-write persists whichever lands last. The attacker picks its own
dial timing, so it can lose that race on purpose and pin the victim on v4, which
also defeats the §2.4 watchdog (it re-checks against the rolled-back head).

The write is therefore a library-owned compare-and-swap:

```rust
pub fn adopt_if_newer(stored: &RosterHead, candidate: &RosterHead,
                      fabric_root: NodeId, now_unix: i64) -> Option<RosterHead>;
```

Same predicate, re-run against the head as re-read at write time; the candidate
is fully re-verified. Caller obligation, stated in the docs: **re-read, call,
write, all under one exclusive lock.** `Admission.adopt` is never persisted
directly. With that, `roster-head.json` really is highest-seen state and a
rollback attempt really is a no-op.

Known and accepted: a genuine newer head with a *nearer* `not_after` displaces a
longer-lived older one. The root is the authority on the validity window as well
as the member set, and keeping a superseded roster (with a removed member still
admitted) is the worse failure; the cost is that a nearly-expired advance can
leave a node admitting nobody until the next `wires import`.

CRL is NOT consulted for topics: topic revocation is head-advance only.

### 2.3 Runtime (`wires/admission.rs`)

- `Admitted` — `Arc<Mutex<HashMap<NodeId, AdmittedPeer>>>`;
  `AdmittedPeer { proof, version, expires, conns: Vec<Connection> }`. Expiry =
  `min(now + ADMIT_TTL, head.not_after)`. API: `is_admitted`, `insert`, `evict`
  (closes tracked conns), `attach_conn`.
- `AdmitHandler` — ProtocolHandler for `wires/topic-admit/1`; re-loads
  `HeadSource` per admission (fails closed, like `serve`); on success inserts,
  persists adopted heads via keystore, sends `Ack`.
- `admit_peer(...)` — client side; verifies the `Ack` with the same
  `check_topic_admission` (mutual).
- Duplex-testable split: `serve_admission(send, recv, caller, ...)` /
  `request_admission(send, recv, responder, ...)` (the `serve_session` pattern).
- `GatedGossip { inner: Gossip, admitted: Admitted }` — `accept()` rejects
  non-admitted `remote_id` (close + warn) before delegating; tracks accepted
  conns for eviction.
- Watchdog task every `ADMIT_RECHECK` (default 30s, injectable): reload
  `HeadSource`; re-run `check_roster_inclusion` on each stored proof; evict
  failures (closing their gossip conns).

### 2.4 Revocation latency story (demo-asserted)

1. **Confidentiality: immediate.** The commit that removed the member minted a
   new fabric key sealed only to survivors.
2. **Ingest integrity: immediate.** Envelopes are verify-at-ingest; a removed
   member can't mint ciphertext that opens under keys it doesn't hold.
3. **Mesh eviction: ≤ watchdog interval** after a node holds the new head.
4. **Residual (documented deferral):** outbound dials to PEX-learned revoked
   peers are not gated (inbound-only gate); harm bounded by (1)+(2).

## 3. E2EE keys — `library/fabric_key.rs`

- `FabricKey([u8; 32])` — deliberately NOT Serialize/Deserialize; `generate()`
  (OsRng), `from_bytes/as_bytes`, `hex/from_hex` (keystore only).
- `SealedFabricKey` — root-signed, member-sealed key for one roster version.
  Signed body (fixed total field set; no optional-but-signed fields — the
  membership.rs rule): `{ format: SEALED_KEY_V1(=1), fabric, version: u64,
  member, sealed: hex, alg }` + `sig`. Fields: `format, fabric: NodeId,
  version: RosterVersion, member: NodeId, sealed: SealedBox (newtype Vec<u8>,
  hex serde), alg: AlgorithmId, sig: Signature`.
  - `seal(root: &NodeIdentity, member, version, key) -> Result<SealedFabricKey>`
  - `open(&self, recipient: &NodeIdentity, fabric_root) -> Result<FabricKey>` —
    verify sig/format/alg, `fabric == fabric_root` pin, `member == recipient`,
    then unseal. Errors: `UnsupportedVersion`, `InvalidSignature`,
    `SubjectMismatch`, `SealedKeyOpen`.
  - `encode/decode` — base64url canonical JSON.
- Sealing mechanics: recipient X25519 pub =
  `VerifyingKey::to_montgomery().to_bytes()` (dalek 2) fed to x25519-dalek 3's
  `PublicKey::from` (the 2/3 split crosses only byte arrays, never types);
  recipient secret = `SigningKey::to_scalar_bytes()` → `StaticSecret::from`.
  Fresh `EphemeralSecret` per seal; AEAD key =
  `blake3::derive_key("wires sealed-fabric-key v1",
  dh_shared ‖ ephemeral_pub ‖ member_pub)`;
  ChaCha20-Poly1305 with zero nonce (unique key per seal); AAD = canonical bytes
  of the sealing context `{format, fabric, version, member, alg}`.
  `sealed` = `ephemeral_pub(32) ‖ ct+tag`.
- **Weak-key rejection (load-bearing).** Ed25519 decompression accepts
  small-order points, and nothing upstream validates the bytes an operator types
  into `roster add` — `0100…00` is a well-formed 64-hex "node id" that passes
  every existing check. Sealing to one derives the AEAD key from an all-zero
  Diffie–Hellman, i.e. a key anyone can compute from the public blob, which for a
  token designed to be pasted through untrusted channels is a plaintext-
  equivalent leak of the fabric-wide data key. So: `VerifyingKey::is_weak()`
  refuses such recipients (`SealedKeyOpen`), `SharedSecret::was_contributory()`
  is asserted on both the seal and open paths, and the derivation names both
  public keys, which closes unknown-key-share variants generically rather than
  one known family of bad inputs.
- Forward secrecy honesty (module doc): rotation-at-commit only; long-term-seed
  compromise reads all history sealed to it; ratcheting deferred.

Distribution: `roster_commit` mints one `FabricKey` per commit and writes
`<node-id>.key` beside `<node-id>.proof`; the root does NOT retain the plaintext
key (blind-root posture). Keystore: `$WIRES_HOME/keyring/<version>.key` (hex,
0600, dir 0700); old keys kept forever (replayed history stays readable; late
joiners can't read pre-join history). `wires import --fabric-key[-file]` opens
(verifying root sig + member binding) and installs.

## 4. Envelope + chain — `library/envelope.rs`, `library/chain.rs`

### 4.1 Envelope

```rust
pub const ENVELOPE_V1: u8 = 1;
pub struct Seq(pub u64);                 // 0-based, dense, per publisher
                                         // Seq::checked_next() -> Option<Seq>
pub struct MessageHash([u8; 32]);        // hex serde; MessageHash::ZERO
pub struct MessageNonce([u8; 12]);       // hex serde; MessageNonce::ZERO
pub struct Ciphertext(Vec<u8>);          // hex serde

pub struct TopicEnvelope {
    pub format: u8,               // ENVELOPE_V1
    pub topic: TopicId,
    pub sender: NodeId,
    pub seq: Seq,
    pub prev_hash: MessageHash,   // ZERO iff seq == 0
    pub key_version: RosterVersion,
    pub timestamp: i64,           // unix secs; informational, unverifiable
    pub nonce: MessageNonce,      // synthetic IV (below)
    pub ciphertext: Ciphertext,
    pub alg: AlgorithmId,
    pub sig: Signature,           // sender-signed over canonical body
}
```

- `seal(sender: &NodeIdentity, topic, seq, prev_hash, key_version, key,
  timestamp, plaintext) -> Result<TopicEnvelope>` — encrypt-then-sign. AAD =
  canonical body with empty ciphertext (the nonce is inside it); nonce =
  **synthetic IV**, `blake3::derive_key("wires topic-envelope nonce v1",
  key ‖ slot ‖ plaintext)[..12]`, where `slot` is the canonical body with an
  empty ciphertext and a zero nonce.
- **Why an SIV and not `blake3(topic ‖ sender ‖ seq)`.** The slot-keyed form
  makes any seq rollback a keystream reuse under a still-current key: keys rotate
  only on a root `roster commit`, while the seq allocator is the per-topic redb
  file, so restoring `$WIRES_HOME` from an older backup, losing the topic db, or
  pointing a second home at the same `--node-seed` republishes seq `0..N` with
  different plaintexts under the same `key_version` — `C1 ⊕ C2 = P1 ⊕ P2`, and
  the Poly1305 one-time key with it. The chain classifier calls the second
  envelope a `Fork`, but only after it has been broadcast, which hands exactly
  the adversary of `late_joiner_cannot_read_pre_join_history` the plaintext it is
  not supposed to have. The SIV keeps every property the deterministic nonce was
  chosen for — re-sealing an identical message in an identical slot is still
  byte-identical, so an idempotent republish is a `Duplicate` — while making
  reuse require the same plaintext too. `open` re-derives the nonce from the
  recovered plaintext and rejects a mismatch, so a rolled-back or hostile sender
  cannot serve two messages under one (key, nonce) pair either. Keying on the
  fabric key means the nonce leaks nothing to a non-holder. The single-allocator
  rule (§7) remains the primary guarantee; this is the defence behind it.
- `Seq::checked_next() -> Option<Seq>`, never an unchecked `+ 1`: the value it
  gets applied to arrives off the wire (`ReplayFrame::Request.hwm` carries a
  peer-chosen `Seq` per publisher), where `u64::MAX` would panic under
  `fastbuild`/`dbg` overflow checks and wrap to genesis — re-streaming a whole
  log — under `--config=release`.
- `verify()` — structure + sig only (no decrypt, no chain): envelopes are
  storable before their key arrives; a late-imported key heals display.
- `open(&self, key: &FabricKey) -> Result<Vec<u8>>`.
- `signing_bytes()`, `message_hash()` (= blake3(signing_bytes)),
  `to_wire`/`from_wire` (canonical JSON bytes — binary channel, no base64).
- Guard test (ported from PoC): `signing_bytes_covers_every_non_signature_field`.
- Dropped from the PoC envelope: `cap_id` (authorization = roster inclusion +
  key possession), `kind` (Standard-only; control messages would be a new
  format), `payload_len` (retention out of scope), `epoch` (→ `key_version`).
- Ingest acceptance rule: `verify()` ∧ chain classifies Ok/Duplicate ∧ (if key
  held) `open()` succeeds; without the key, store provisionally.
- Payload convention: CLI sends UTF-8 text; binary representable, no surface.

### 4.2 Chain

```rust
pub struct ChainState { pub seq: Seq, pub hash: MessageHash }
pub enum LinkStatus { Ok, Duplicate, Gap { have: Option<Seq> }, Fork }
pub fn classify_link(env, state: Option<ChainState>,
                     held_hash_at_seq: Option<MessageHash>) -> Result<LinkStatus>;
pub fn next_prev_hash(state: Option<ChainState>) -> MessageHash; // ZERO genesis
```

Truth table: genesis requires `prev_hash == ZERO`; seq strictly `prev + 1`
(gaps → `Gap`, never silent drop-forever — replay heals, §6); same
(sender, seq) same hash → `Duplicate`; different hash / bad genesis / prev_hash
mismatch → `Fork`. Fork = detect, refuse, log; no fork choice (deferred).

## 5. Store — `wires/store.rs` (redb)

One db per topic: `$WIRES_HOME/topics/<topic-hex>.db` (0600; dir 0700). Tables:
`topic_log` (`sender[32] ‖ seq_be[8]` → canonical JSON envelope), `topic_hwm`
(`sender[32]` → `seq_be[8] ‖ hash[32]`). API: `open`, `append -> Appended
{Inserted, Duplicate}` (idempotent; fork = error; one write txn covers both
tables), `chain_state`, `hash_at`, `read_after`, `senders`, `hwm_all`,
`read_backfill(limit)` (merged (timestamp, sender, seq) display order). Rule:
every read path maps `redb TableDoesNotExist` → empty via one private helper
(fresh dbs have no tables until the first write txn).

## 6. Replay — `library/replay.rs` (frames) + `wires/replay.rs` (glue)

ALPN `wires/topic-replay/1`. One bidi stream per request.

```rust
pub enum ReplayFrame {
    Request { topic: TopicId, hwm: BTreeMap<NodeId, ChainState>, limit: u32 },
    Item(TopicEnvelope),
    End,
    Denied { reason: String },
}
pub const MAX_REPLAY_FRAME: usize = 1024 * 1024;
```

- Same codec-owned ceiling as §2.1, and for the same reason: `hwm` and an
  envelope's ciphertext are both unbounded collections chosen by the peer, and
  "admitted" is a large set. `decode` refuses an over-long length prefix rather
  than waiting for the body.
- Server verifies presented hwm hashes against `hash_at`; on mismatch streams
  that sender FROM GENESIS so the requester's `classify_link` surfaces the fork
  (PoC never verified — silent divergence).
- `ReplayHandler` requires admission (same `Admitted` registry as gossip).
- `catch_up(endpoint, peers, store, topic, ...)`: per admitted peer, Request
  with local `hwm_all()`, ingest Items via verify → classify → append; loop
  until a full pass adds nothing.
- Live `Gap` at ingest: don't store the gapped message; schedule debounced
  (~2s) `catch_up`; the gap heals and the message re-arrives via replay.
- Peer-symmetric: every tail runs the handler; there is no host.

## 7. CLI — `wires publish` / `wires tail` + `wires/ipc.rs` + `wires/topics.rs`

Ownership: redb is single-process and one endpoint identity must not run twice →
**`wires tail` is the resident node** (store + endpoint + gossip + admission +
replay server + unix control socket `$WIRES_HOME/run/<topic-hex>.sock`, 0600,
unlinked on exit, stale-socket probe). `wires publish`:
1. Socket accepts → `{"publish":{"text":…}}` NDJSON; tail allocates seq, seals,
   appends, broadcasts; reply `{"ok":{"seq":N}}` / `{"err":…}`.
2. Else one-shot: open store, bind endpoint, admit vs known peers, subscribe,
   wait first NeighborUp (≤15s — no blind sleeps), seal+append+broadcast,
   linger ~1s, exit. No reachable peer → append locally + stderr warning
   (replay makes it eventually consistent).

Single seq allocator per (node, topic) = the deterministic-nonce soundness
guarantee (PoC's publish-lock hazard resolved structurally).

- `TailArgs { topic, peer: Vec<ticket> (repeatable), backfill (default 200),
  json, node-seed/relay-url resolution flags }`; `PublishArgs { topic,
  message | stdin lines, peer, ... }`. Preflight before network I/O: node.seed,
  membership, proof, head, ≥1 keyring key; fabric root = membership.fabric.
- Tail prints a stderr banner incl. its own `TopicTicket`
  (`share to bootstrap: <token>`); stdout is byte-pure message lines
  (`HH:MM:SS <sender8> <text>` or `--json` NDJSON). Printing gated on
  `append == Inserted` → structural dedupe across live/replay/restart.
- Missing key version: one stderr warning per version; skip on stdout until the
  key arrives.
- Liveness: persist peers to `topics/<hex>.peers.json` (tickets ∪ NeighborUp);
  neighbor count 0 → backoff redial 5s→60s → re-admit (fresh head check — a
  revoked peer learns via Denied) → catch_up → resume. `Lagged` → schedule
  catch_up, never die silently (PoC trap). Admission refusal at startup =
  exit 77 (`EXIT_DENIED`), same reporting shape as `connect`.
- `wires/topics.rs`: `TopicNode::{spawn(identity, cfg), join(topic, bootstrap)
  -> (TopicSender, mpsc::Receiver<TopicEvent>), ticket(name)}`;
  `TopicEvent::{Message(TopicEnvelope), NeighborUp(NodeId),
  NeighborDown(NodeId), Lagged}`. Gossip built via `Gossip::builder()` and
  registered on the single Router. Channel cap 256; bridge logs drops.

## 8. Errors (library/error.rs additions)

`SealedKeyOpen`, `KeyVersionUnknown { version }`, `ChainFork`, `TopicMismatch`
(envelope topic ≠ subscribed topic) — thiserror, message conventions as-is.

## 9. Test plan

- Library: proptest + known-answer + doctests per module, mirroring
  session.rs/roster.rs suites — encode/decode roundtrip, stream-split,
  truncated → None, garbage never panics, tamper-any-signed-field fails,
  known-answer canonical bytes; seal/open roundtrips; wrong recipient/root/key;
  chain truth table; `check_topic_admission` matrix {older/equal/newer} ×
  {valid/forged/expired} × {fresh/stale/non-member} incl. "newer forged head is
  NOT adopted"; DH agreement both directions. Plus the adversarial-review
  regressions: weak/undecompressable member keys refused by `seal`, a
  non-contributory exchange yields no cipher, a zero ephemeral public refused by
  `open`; two different plaintexts in one slot never share a nonce (no two-time
  pad) and a substituted nonce is refused by `open`; `Seq::MAX.checked_next()` is
  `None` and the classifier is exercised at the ceiling; `adopt_if_newer` is
  monotone under any interleaving (the late-older-writer race); an over-long
  length prefix is `BadFrame` on both codecs, on decode and encode.
- wires: store (idempotent/fork/fresh-empty/reopen/backfill); duplex admission
  tests; hermetic loopback QUIC (`presets::Minimal`, 2–3 endpoints, injected
  timeouts) — money shots: `revocation_evicts_neighbor_between_rechecks`,
  `removed_member_cannot_read_after_head_advance`,
  `late_joiner_cannot_read_pre_join_history`, `tail_catches_up_after_offline`,
  `live_gap_triggers_replay_and_heals`, plus join/refusal, replay-denied,
  ipc socket tests.
- Demos: self-asserting `.scripts/demo-topic.sh`, `demo-topic-revoke.sh`,
  `soak-topic.sh` (SIGSTOP/SIGCONT + kill/restart, transcript audit).

## 10. Honest deferrals

Inbound-only gossip gating; forward secrecy = commit rotation only; fork =
detect-and-refuse; single fabric per keystore; no discovery service (tickets +
persisted peers); timestamps informational; per-commit `wires import` stays a
manual member tax (head adoption at admission is the only distribution sliver
pulled forward).

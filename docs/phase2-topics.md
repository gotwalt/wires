# Phase 2 design: multiway topics on the committed roster

*2026-08-14. The implementation spec for restart.md Phase 2. Decisions herein were
made against the exploration of both this tree and the archived PoC
(`archive/poc-2026-05`); PoC file references are read-only ancestry, never merge
sources. The spec is the contract: code follows this document, and deviations are
edits to this document first.*

*Status: implemented and merged 2026-08-14 (`2d87c78`…`7ddaad9`);
`bazel test //...` green. This document has since been reconciled line-by-line
against the tree, so it describes what shipped, not what was planned.*

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
  (closes tracked conns), `attach_conn`, `peers_since`, `expiring_before`.
  - **`attach_conn` is the gate, not bookkeeping.** It re-checks admission and
    records the connection *under one lock*, returning `false` when the peer is
    not (or no longer) admitted, and a caller that gets `false` must close the
    connection. Checking with `is_admitted` and then attaching is a TOCTOU with a
    permanent consequence: an eviction landing between the two removes the map
    entry, the attach silently no-ops, and the connection stays live and
    *untracked* — out of the registry, so no later watchdog pass lists it, and
    never closed.
  - **An admission is a lease, and leases are refreshed.** `ADMIT_TTL` with
    nothing renewing it means every peer lapses, the watchdog closes its
    connections, and a stable mesh tears itself down every five minutes — in
    lockstep, since the expiries all derive from one wall clock. The resident
    tail re-admits peers within `ADMIT_REFRESH` (TTL/3) of their expiry.
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
  failures (closing their gossip conns) and sweep lapsed leases.
- **Every await on this surface is bounded** (`TOPIC_DIAL_TIMEOUT`,
  `TOPIC_HANDSHAKE_TIMEOUT`, both 10s, applied through one `within` helper that
  takes the budget as an argument so the timeout path is asserted in
  milliseconds). `transport.rs` has had this since Phase 1 and the topic layer
  inherited none of it: a peer that accepted a connection and then said nothing
  hung `wires tail` at startup, before the control socket was bound.
- **The pre-authorization surface is bounded too.** `MAX_ADMIT_FRAME` bounds one
  frame, not the surface: iroh spawns a task per accepted connection with no cap.
  `MAX_INFLIGHT_ADMISSIONS` (64) permits are taken *before* the first read and
  a caller that cannot get one is refused immediately, and the frame body is
  grown as bytes arrive rather than pre-allocated from the peer's length prefix.

### 2.4 Revocation latency story (demo-asserted)

1. **Confidentiality: immediate.** The commit that removed the member minted a
   new fabric key sealed only to survivors.
2. **Ingest integrity: immediate against any node that holds the new head —
   enforced by an epoch floor, not by the signature.** The original wording here
   ("a removed member can't mint ciphertext that opens under keys it doesn't
   hold") was true and did not imply what it was used to claim. `verify()` is a
   signature check: it says who wrote an envelope, never that the writer is still
   in the roster. A removed member keeps every key ever sealed to it, and §3
   keeps those keys on *every* survivor forever, so a member removed at v2 can go
   on sealing v1 envelopes that verify, chain onto its own log, store, decrypt
   and print as authentic. Nothing in an envelope distinguishes one of those from
   genuine pre-commit history, so the rule is positional:

   - **Live path (gossip):** `ingest` refuses any envelope whose `key_version` is
     below the roster version this node currently enforces (its `roster-head.json`,
     re-read per message like every other reader of the head). The refusal names
     the epoch.
   - **Publish path:** symmetrically, `wires publish` refuses to seal under a key
     older than the stored head — such a message would be refused by every
     up-to-date peer, and failing at the source names the `wires import` that
     fixes it instead of losing the line silently.
   - **Replay path:** epoch-**permissive**, deliberately. A publisher's chain is
     dense, so refusing its pre-commit run would leave every later message from
     it permanently unlinkable — no late joiner and no member offline across a
     commit could ever catch up again. What bounds the removed member here is the
     *dial set*: `catch_up` asks only peers whose admission was decided under the
     head this node currently enforces (`Admitted::peers_since`), so a peer
     admitted under the superseded head is not a source of history even in the
     window before the watchdog evicts it.
3. **Mesh eviction: ≤ watchdog interval** after a node holds the new head.
4. **Residuals (documented deferrals):**
   - Outbound dials to PEX-learned revoked peers are not gated (inbound-only
     gate); harm bounded by (1)+(2).
   - A member that has not yet imported the new head still enforces the old
     epoch, so it accepts and stores the removed member's later messages. It
     cannot inject them into an upgraded node's live path, but it can serve them
     as history once it has upgraded and been re-admitted. Closing this needs
     proof-carrying envelopes plus heads that chain (so an old proof is
     verifiable against a new head) — Phase 3, out of scope here. The honest
     claim is: **complete against every node that holds the head, eventually
     complete for the rest.**

### 2.5 Re-key distribution (card 14, 2026-09-23)

"Holds the new head" no longer waits on a manual `wires advanced import`.
`wires invite` / `wires remove` publish each commit on the channel as
`ChannelRecord::Rekey { head, entries: [{ proof, key: SealedFabricKey }] }`
(`library/membership/rekey.rs`), and the resident loop (`wires watch`,
`serve --audit-topic`) adopts it (`wires/channel/rekey.rs`):

- **Self-verifying.** The head is root-signed, each proof must recompute its
  root, each sealed key is root-signed and sealed to its proof's member.
  Whoever publishes or replays a Rekey can only advance a reader to a *newer
  root-signed* head (the same `adopt_if_newer` CAS as admission) and hand it a
  key the root sealed to it.
- **Published under the outgoing key**, from the admin's node *before* it
  installs the commit, so the members it is for can open it and their ingest
  floor accepts it. The removed member can read it too: it learns the head, the
  survivors' ids and Merkle paths — never the new key (§2.4.1 holds). Adoption
  runs on every received envelope whatever its ingest verdict (a node whose head
  moved via admission first refuses to *store* the record, but still adopts it)
  and on everything a catch-up inserts.
- **Install order:** own key → own proof → the proof directory → head (CAS).
- **Proof directory** (`roster-directory.json`): the current head's proof for
  every member, from the Rekey. The session gate, topic admission and the
  watchdog accept a caller's stale proof when the directory for *exactly* the
  enforced head lists that caller (`check_roster_inclusion_via`) — as strong as
  the caller presenting it, since the caller is still the key iroh
  authenticated. This is what keeps a node that missed a re-key (a one-shot
  `wires call`, a restarted tail) admitted, and keeps the watchdog from
  evicting every survivor after each commit. A one-shot publish whose newest
  key is behind its head runs one catch-up pass and adopts the Rekey before
  sealing.
- Latencies are unchanged in shape: every guarantee in §2.4 is measured from
  "holds the new head", which is now "received the Rekey" (live gossip, ~one
  RTT) or "was admitted by a peer that did" (passive head distribution). A
  member offline across a commit and never re-admitted by a peer holding the
  directory still needs a fresh invite (`wires invite <id>` re-issues one).
- Gossip messages may be 64 KiB (`GOSSIP_MAX_MESSAGE`); a Rekey carries 32
  members per record (`REKEY_ENTRIES_PER_RECORD`).

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

Ingest reads this rule in the other direction (§2.4.2): keys are kept so that
*stored* history stays readable, not so that a superseded epoch stays
publishable. New live traffic under an old key is refused; replayed history under
one is not.

Distribution: `roster_commit` mints one `FabricKey` per commit and writes
`<node-id>.key` beside `<node-id>.proof`; the root does NOT retain the plaintext
key (blind-root posture). Keystore: `$WIRES_HOME/keyring/<version>.key` (hex,
0600, dir 0700); old keys kept forever (replayed history stays readable; late
joiners can't read pre-join history). `wires import --fabric-key[-file]` opens
(verifying root sig + member binding) and installs. `wires import --roster-head`
applies the same monotonicity rule the admission CAS does — a strictly older head
is refused without `--force` — because the stored head is what a running tail
enforces on every handshake and every watchdog pass, and a head token is public
and held by every past member.

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
- Ingest acceptance rule: (epoch floor, §2.4.2, live path only) ∧ `verify()` ∧
  chain classifies Ok/Duplicate ∧ (if key held) `open()` succeeds; without the
  key, store provisionally.
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
- `catch_up(endpoint, admit: &AdmitHandler, store, topic, limit)`: the dial set
  is `admit.admitted.replay_targets(admit.current_version()?)` — peers admitted
  under the head this node currently enforces (§2.4.2), minus any whose tracked
  connections have all closed (a one-shot publisher that exited; skipped, not
  evicted — a fresh admission makes it a target again), re-read every round so a
  mid-loop eviction stops the asking. The handler is passed rather than a peer
  list precisely so that set is recomputed from live state instead of
  snapshotted by the caller. Per peer: Request with local `hwm_all()`, ingest
  Items via verify → classify → append; loop until a full pass adds nothing,
  **or** until `MAX_CATCH_UP_ROUNDS` (32) or `CATCH_UP_BUDGET` (30s) is spent.
  The "adds nothing" condition alone is attacker-controlled: a peer with one
  genuinely new, correctly chained envelope per round keeps it productive
  forever.
- **The tail never awaits a catch-up inline.** It runs one `catch_up_collect`
  at a time as a task beside its loop and prints the envelopes that call
  inserted when it finishes; deadlines that come due meanwhile wait for it. The
  loop is the single seq allocator (§7), and `serve --audit-topic` feeds call
  records through it, so a pass stuck on a quiet peer must not hold a publish
  (board card 11: a departed `wires login --topic` node held audit records 20s).
- Bounds on the client side of a pass, none of which the server is trusted to
  respect: `REPLAY_PASS_TIMEOUT` (20s) over dial + stream + every frame read,
  of which the dial and stream open get `REPLAY_CONNECT_TIMEOUT` (5s);
  the requester stops at the item limit it asked for (a hostile peer can stream
  past it, and every item costs a signature verification and a `stopped`-set
  entry); and the request's `hwm` carries at most `MAX_HWM_ENTRIES` (1024) marks
  in a window that rotates by round. That last one is not tidiness: `hwm_all`
  grows with every distinct sender ever stored and `sender` is a wire field, so
  an admitted member minting genesis envelopes under fresh keypairs could push
  the request past `MAX_REPLAY_FRAME` — after which every replay from that node
  fails at encode, forever, with the pollution on disk so a restart does not
  clear it. Omitting a mark only costs duplicates.
- Live `Gap` at ingest: don't store the gapped message; schedule debounced
  (~2s) `catch_up`; the gap heals and the message re-arrives via replay.
- Peer-symmetric: every tail runs the handler; there is no host.

## 7. CLI — `wires publish` / `wires tail` + `wires/ipc.rs` + `wires/topics.rs`

Ownership: redb is single-process and one endpoint identity must not run twice →
**`wires tail` is the resident node** (store + endpoint + gossip + admission +
replay server + unix control socket `$WIRES_HOME/run/<topic-hex[..16]>.sock`
(the full 64 does not fit in `sockaddr_un::sun_path` — 104 bytes on macOS —
once the home is any deeper than `~/.config/wires`), 0600,
unlinked on exit, stale-socket probe). `wires publish`:
1. Socket accepts → `{"publish":{"text":…}}` NDJSON; tail allocates seq, seals,
   appends, broadcasts; reply `{"ok":{"seq":N}}` / `{"err":…}`. A refusal or a
   dropped connection costs the *line* up to `PUBLISH_ATTEMPTS` (3) reconnecting
   retries, never the rest of the feed: `tail -f app.log | wires publish ops`
   must survive the window between a `roster commit` and the operator's `wires
   import`, and must survive the tail restarting. The client's wait for a reply
   is bounded (`PUBLISH_REPLY_TIMEOUT`).
2. Else one-shot: open store, bind endpoint, admit vs known peers, subscribe,
   wait first NeighborUp (≤15s — no blind sleeps), seal+append+broadcast,
   linger ~1s, exit. No reachable peer → append locally + stderr warning
   (replay makes it eventually consistent). A broadcast failure is a warning for
   the same reason it is in the tail path: the sequence is already allocated and
   the message is already in the log, so aborting would drop the remaining lines
   and invite a retry that republishes this one under a fresh sequence.

The tail binds its **control socket before it joins the network**, and both
commands wait out the topic log's exclusive redb lock for `STORE_LOCK_WAIT`
(20s). Otherwise a publish issued while a tail is starting finds no socket, falls
through to the one-shot path, and collides on the lock — killing whichever loses,
including the resident node.

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
- Liveness. The loop keeps one invariant, reconciled after every pass rather
  than at each of the places that can break it: **an empty mesh always has a
  redial pending.** Persist peers to `topics/<hex>.peers.json` (tickets ∪
  NeighborUp); backoff redial 5s→60s → re-admit (fresh head check — a revoked
  peer learns via Denied) → catch_up → resume. Specifically:
  - `neighbors` is cleared on every re-join: a peer that vanished while the
    bridge was down never produces a `NeighborDown` on the new subscription, and
    one stale entry means the mesh looks populated forever and the redial timer
    is never armed again.
  - A successful redial does **not** disarm the timer. `admit_peer` proves the
    handshake, never that the gossip mesh formed; the invariant above re-arms it
    until a `NeighborUp` actually arrives.
  - `Lagged` and a dead event bridge disable the event arm and schedule a
    re-join on its own backoff (a closed channel is permanently ready, so an arm
    that logs and continues is a hot spin). Same for a dead control socket.
  - Catch-up is also **periodic** (`CATCHUP_INTERVAL`, 60s), not only
    edge-triggered: a hole whose only holder is asleep is never healed by an
    event that does not come. Deadlines are folded with a "keep the sooner"
    helper, so an urgent debounce moves a pending periodic pass in.
  - Exit 77 (`EXIT_DENIED`) on admission refusal at startup, and in the live loop
    only after `DENIAL_STRIKES` (3) consecutive rounds in which every reachable
    peer refused. One refusal is not evidence: a peer that imported a commit
    first answers `stale inclusion proof` to a node that is still a member, and a
    peer whose own head is briefly unreadable answers `responder configuration
    error`.
- `wires/topics.rs`: `TopicNode::{spawn(identity, cfg: TopicNodeConfig),
  spawn_on(endpoint, lookup, cfg), join(topic, bootstrap)
  -> (TopicSender, mpsc::Receiver<TopicEvent>), ticket(name), shutdown()}`.
  `spawn` is `spawn_on` plus the bind, split for the same reason
  `transport::serve_on` is: the hermetic loopback tests bind with
  `presets::Minimal` and hand the endpoint (and the `MemoryLookup` registered
  on it) in. `spawn` deliberately does **not** join or dial — a caller admits
  its bootstrap peers first, so it can learn it has been revoked (exit 77)
  before it ever subscribes. Events are
  `TopicEvent::{Message(TopicEnvelope), NeighborUp(NodeId),
  NeighborDown(NodeId), Lagged}`. Gossip built via `Gossip::builder()` and
  registered on the single Router. Channel cap 256; a full channel makes the
  bridge **wait**, never drop — the tail task is the only ingester, so a dropped
  `Message` was never stored here and the bridge cannot schedule the catch-up
  that would re-fetch it; backpressure surfaces upstream as `Lagged`, which is
  wired to a re-join and a catch-up. `join` is bounded by `BOOTSTRAP_BUDGET`
  (30s) over the whole peer book; the rest is the redial timer's job.

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
- Plus the integration-review regressions: a removed member's later messages are
  refused at ingest and its history is not pulled by replay (§2.4.2, e2e);
  `attach_conn` is the admission check, and an evicted peer's tracked connection
  is closed; the pre-authorization surface refuses past `MAX_INFLIGHT_ADMISSIONS`
  and every handshake await times out (asserted in milliseconds, via the
  budget-taking `within`); the requester stops at its own item limit and the
  `hwm` window caps and rotates; a full event channel waits instead of dropping;
  `wires import --roster-head` refuses a rollback; publishing under a superseded
  key is refused; a torn `roster-head.json` is impossible under a concurrent
  reader; `arm` keeps the sooner deadline; a refusal becomes exit 77 only after
  `DENIAL_STRIKES`; the topic log's lock is waited out; a streaming publish
  survives a refusal and a reconnect, and gives up on a mute tail.
- Demos: self-asserting `.scripts/demo-topic.sh`, `demo-topic-revoke.sh`,
  `soak-topic.sh` (SIGSTOP/SIGCONT + kill/restart, transcript audit).
  `demo-topic-revoke.sh` asserts all four §2.4 claims, and asserts claim 2 in the
  window **before** eviction — otherwise it is claim 3 wearing claim 2's label.

## 10. Honest deferrals

Proof-carrying envelopes and chained heads (§2.4.4: what would make ingest
integrity complete against a member that has not imported the new head);
inbound-only gossip gating; forward secrecy = commit rotation only; fork =
detect-and-refuse; single fabric per keystore; no discovery service (tickets +
persisted peers); timestamps informational; per-commit `wires import` stays a
manual member tax (head adoption at admission is the only distribution sliver
pulled forward).

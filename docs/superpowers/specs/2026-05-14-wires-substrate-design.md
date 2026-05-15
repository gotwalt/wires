# Wires — Substrate Design

**Date:** 2026-05-14
**Status:** Draft (awaiting user review)
**Scope:** v1 of the gossip substrate only. iOS companion app, REST gateway, MCP server, ingestion daemons, and schema-conventions library are explicitly out of scope and will get their own specs.

---

## 1. Mental model

Wires is a Rust crate (plus a thin daemon binary) that gives any agent on a household network a single primitive: *publish a signed, encrypted message to a topic, and tail or replay topics you have access to*.

It is local-first: two agents on the same LAN can coordinate without any external service. A hosted node may participate as an always-on convenience peer, but is structurally indistinguishable from any other peer — it is blind to content by construction.

It is built on iroh. iroh NodeIds are the addressing layer, `iroh-gossip` is the live transport, and custom RPCs (replay sync, capability publication) ride over iroh's QUIC. `iroh-blobs` is reserved for large attachments referenced by hash from messages; it is not used for the log itself.

**Non-goals for v1:**
- Total ordering across publishers (causal per-publisher only).
- MLS-grade post-compromise security (epoch rotation is the floor).
- Bounded retention or log compaction (full history retained; revisit when volume demands).
- Multi-household federation (one trust root per node for v1).

---

## 2. Identity and capabilities

**Root identity.** A single Ed25519 keypair held in the iOS companion's Secure Enclave, gated by biometrics. The key never leaves the device. Its only job is to sign capabilities and revocations.

**Agent identity.** Every agent process — a Claude Code session, a fridge daemon, the hosted relay, a Siri bridge — generates its own iroh NodeId / Ed25519 keypair locally on first run. Cheap, disposable, never communicated to the root device except as a target pubkey when minting a capability.

**Capability format.** A signed bearer-style token (compact JSON, signed by the root):

```json
{
  "agent": "<agent_pubkey_hex>",
  "topics": ["home.*", "mail.inbox", "agents.chat"],
  "rights": ["read", "write"],
  "issued": 1747200000,
  "expires": null,
  "cap_id": "<uuid>",
  "sig": "<root_signature>"
}
```

Topic patterns are dotted-namespace globs: `*` matches one segment, `**` matches zero or more segments, anything else is a literal segment. Examples: `home.*` matches `home.fridge` but not `home.fridge.temp`; `home.**` matches both. The reserved `__caps` topic and any `__`-prefixed topic only match if specified by literal name. Rights are any subset of `read` and `write`. Expiry may be `null` for non-expiring caps.

**Capability distribution.** Capabilities are published to a reserved topic, `__caps`, in two modes (see Section 3 and Section 4 for the encryption modes):

- `__cap.grant` events use `SealedTo(recipient)` — only the agent the cap was minted for can read the cap content (which includes the topic patterns, rights, and names for any topics granted).
- `__cap.revoke` and `__cap.root_rotation` events use `Public` — cleartext payload, signed by the root. They have to be readable by every participant for revocation enforcement and successor-key adoption to work.

Every node maintains a local cap-table by tailing `__caps`. The cap-table is the authoritative source for "is this `cap_id` valid?"

**Two-layer ACL enforcement:**
- **Host layer (coarse).** The host can only see opaque `SealedTo(recipient)` `__cap.grant` events. It cannot read the granted topic patterns or rights. The host therefore enforces only: "this message's `cap_id` matches a `__cap.grant` issued to this `sender` pubkey, and no `__cap.revoke` for it exists." That's enough to prevent any non-authorized identity from spamming the network, but the host cannot enforce per-topic or per-right scope.
- **Receiver layer (fine).** When an agent decrypts a `SealedTo(self)` `__cap.grant`, it learns the cap's topic patterns and rights. It maintains a local fine-grained ACL keyed by `cap_id`. On message receipt, the agent re-checks: the sender's `cap_id` must allow write on the message's `topic_id`. Receivers reject messages whose cap doesn't grant the appropriate right, even if the host accepted them.

This split is the practical consequence of host blindness: the host enforces anti-spam, agents enforce semantics.

**Revocation.** A `__cap.revoke` event published as `Public` on `__caps`, signed by the root, referencing a `cap_id`. Honored from its log offset forward. An agent that was using the cap and is now offline learns about its revocation on next reconnect; before that, peers refuse messages signed under the revoked cap by looking up the `cap_id` carried in every message envelope.

**Bootstrapping.** When a new agent comes online, it needs (a) an iroh `EndpointAddr` of at least one peer and (b) a capability. Both are conveyed via the responder-driven pairing flow defined in [`docs/superpowers/specs/2026-05-15-wires-responder-driven-pairing-design.md`](2026-05-15-wires-responder-driven-pairing-design.md): the agent declares its role and requested scopes through a signed `PairRequest` token (QR or paste); the operator consents and dials the agent over `/wires/pair/0` with a sealed, signed `PairGrant` carrying the root pubkey, root-signed cap, per-topic epoch keys, and host info. The token's single-use nonce binds the grant to a live pairing window; the QR/paste handoff is the trust-establishment act (TOFU on the root pubkey).

**Trust root rotation.** Out of scope for v1, but accommodated: a `root_rotation` event signed by the current root nominating a successor pubkey, persisted in `__caps`. Implemented when the iOS app supports backup/recovery.

---

## 3. Topics and encryption

**Topic identity.** A topic is identified by an opaque 32-byte random `topic_id` plus a human-readable `name` (e.g. `home.fridge`). The id is what appears on the wire; the name is metadata only, carried in the topic's creation event. Two topics with the same name on different networks are unrelated.

**Topic creation.** A topic comes into being when (a) the root mints `__cap.grant` events for its initial members (the grant content includes the topic name and id, sealed to each recipient), and (b) the root publishes the first `__topic.epoch_advance` events on the new topic, sealed to each initial member, carrying `{old_epoch: null, new_epoch: 0, key: <epoch_0_key>}`. There is no separate `__topic.create` event — a topic exists once at least one capability references its id and at least one epoch key has been published for it.

**The firehose.** A built-in topic with a deterministic `topic_id = BLAKE3("wires.firehose.v1" || root_pubkey)`. Every agent's default cap grants `read+write` on the firehose. Membership equals "everyone the root has authorized at all." This is where casual agent chatter lives.

**The `__caps` topic.** Reserved `topic_id = BLAKE3("wires.caps.v1" || root_pubkey)`. Carries control-plane events (`__cap.grant`, `__cap.revoke`, `__cap.root_rotation`). Has no epoch key. Grants are `SealedTo` the recipient; revokes and root-rotations are `Public`. Anyone may gossip-forward any `__caps` event.

**Three encryption modes.** Every message declares its mode in the envelope (see Section 4):

1. **`Standard`** — content encrypted under the topic's current epoch symmetric key (ChaCha20-Poly1305, 256-bit). All topic members can decrypt. This is the mode for normal traffic.
2. **`SealedTo(recipient_pubkey)`** — content sealed to a single recipient via x25519 sealed-box (ephemeral keypair → ECDH → ChaCha20-Poly1305). Only the holder of `recipient_pubkey`'s private key can decrypt. This is the mode for events that must be readable by recipients who do not yet hold any epoch key: `__cap.grant`, `__topic.epoch_advance` (per-recipient wraps), and `__topic.history_grant`.
3. **`Public`** — content is cleartext, signed by the sender but not encrypted. Used only for `__cap.revoke` and `__cap.root_rotation`, where the meaning is intentionally public and global readability is required for enforcement.

For `Standard` and `SealedTo`, AEAD associated-data is the full cleartext envelope, so altering envelope fields invalidates the tag. For `Public`, the envelope signature covers the content (no separate AEAD tag).

**Epoch rotation.** Triggered by any membership change (add or remove). For v1, only the root has admin rights on topics. The root generates a new symmetric key and publishes a series of `__topic.epoch_advance` events to the topic — one per current member, each with kind `SealedTo(member_pubkey)` and content `{old_epoch, new_epoch, key: <new_epoch_key>}`. Each member receives the wrap addressed to them, decrypts, and switches. Members not addressed in the new round (i.e. removed members) simply never receive the new key.

**History on join.** When minting a cap for a new agent, the root publishes one `__topic.history_grant` event per topic the agent joins, kind `SealedTo(agent_pubkey)`, content `{topic_id, epochs: [{epoch, key}, ...]}` — all prior epoch keys for that topic. The new agent decrypts and can read the full history. This is the load-bearing design choice that makes "new agent has full context immediately" possible. (If a forward-only member is ever needed, the root omits the `history_grant`. History grant is the default.)

**What the blind host sees per message:** `topic_id`, `epoch`, `kind` (and the recipient pubkey if `SealedTo`), sender pubkey, `cap_id`, sequence number, signed timestamp, ciphertext length. For `Public` events on `__caps`, the host also sees the cleartext content — but the only Public events are revocations and root-rotations, both of which are intentionally global. The host cannot read `Standard` or `SealedTo` content, cannot determine `type` for those, and cannot tell `home.fridge` from `mail.inbox` — topic names live inside `SealedTo` `__cap.grant` payloads.

**Host knowledge floor (intentional leakage):** message rate per topic, message size, sender pubkeys, recipient pubkeys for `SealedTo` events, time of day, the social graph of "which pubkeys send each other sealed events on which topics," and the full content of `__cap.revoke` / `__cap.root_rotation` events. These are unavoidable for a participating relay. Documented explicitly so users know what self-hosting buys.

---

## 4. Wire format

### Envelope (cleartext)

```rust
pub enum MessageKind {
    Standard,                       // content encrypted under topic epoch key
    SealedTo([u8; 32]),             // content sealed to recipient x25519 pubkey
    Public,                         // content cleartext, signed only (used on __caps)
}

pub struct WireMessage {
    // Cleartext envelope — host-readable
    pub topic_id:    [u8; 32],
    pub epoch:       u32,           // 0 if kind = SealedTo or topic has no epoch (__caps)
    pub kind:        MessageKind,
    pub sender:      [u8; 32],      // ed25519 pubkey
    pub cap_id:      [u8; 16],      // capability used to authorize
    pub seq:         u64,           // per-(sender, topic) monotonic
    pub prev_hash:   [u8; 32],      // hash of prior message from this sender on this topic
    pub timestamp:   i64,           // sender's clock, millis since unix epoch
    pub payload_len: u32,
    pub signature:   [u8; 64],      // ed25519 over all preceding bytes

    // Encrypted payload — host-opaque
    pub ciphertext:  Vec<u8>,
}
```

**AEAD parameters for `Standard` mode:**
- Key: current epoch key for `(topic_id, epoch)`.
- Nonce: 12-byte truncation of `BLAKE3(topic_id || sender || seq.to_le_bytes())`. Unique by construction.
- AAD: byte serialization of the cleartext envelope fields (everything above `ciphertext`).

**Encryption for `SealedTo` mode:**
- Sealed-box construction: sender generates an ephemeral x25519 keypair; derives a shared secret via ECDH with `recipient_pubkey`; uses ChaCha20-Poly1305 with that shared secret as the key.
- Ephemeral pubkey is prepended to `ciphertext`.
- Nonce: 12-byte truncation of `BLAKE3(topic_id || sender || seq.to_le_bytes() || recipient_pubkey)`.
- AAD: same as `Standard`.

**`Public` mode:**
- `ciphertext` field holds the cleartext canonical JSON content directly (no AEAD).
- Integrity is provided by the envelope `signature`, which already covers `ciphertext` bytes.
- Only valid for events on the `__caps` topic with reserved types `__cap.revoke` and `__cap.root_rotation`. Any other `Public` message is rejected at validation.

### Content (plaintext, after decryption)

Canonical JSON (sorted keys, no insignificant whitespace), so re-serialization is stable:

```json
{
  "type": "home.fridge.temp",
  "text": "fridge holding at 38°F",
  "data": { "value": 38, "unit": "F", "sensor": "main" }
}
```

- `type` (string, required): dotted namespace, no central registry. Doubles as a filter handle and a hint for the shape of `data`.
- `text` (string, required): natural-language summary. Lets humans tail the log readably, lets LLMs ingest without parsing.
- `data` (object, optional): structured payload for agents that want it.

### Replay offset

What an agent persists as its high-water mark per topic:

```rust
type HighWaterMark = HashMap<SenderPubkey, (Seq, MessageHash)>;
```

To resume, an agent says "send me everything for `topic_id=T` past these per-sender `(seq, hash)` pairs." Peers compare and stream the delta. New senders not in the map stream from `seq=0`.

### Control-plane events

Capability events, topic-create events, epoch-advance events, history-grants, and revocations all use the same `WireMessage` shape. They are messages with reserved `type` values on `__caps` or per-topic streams. Same auth, same chain, same replay.

Reserved types and their modes:
- `__cap.grant` — on `__caps`, mode `SealedTo(recipient)`.
- `__cap.revoke` — on `__caps`, mode `Public`.
- `__cap.root_rotation` — on `__caps`, mode `Public`.
- `__topic.epoch_advance` — on the affected topic, mode `SealedTo(member)`. One event per current member at each rotation.
- `__topic.history_grant` — on the affected topic, mode `SealedTo(new_member)`. Carries all prior epoch keys.

A receiver rejects any message whose `type` is reserved but whose mode does not match the table above.

---

## 5. Ordering, replay, and gaps

**Ordering model.**
- *Causal per publisher* by construction: `seq` + `prev_hash` chain enforce that any consumer sees a given publisher's messages in publisher-emit order.
- *Across publishers within a topic*: not totally ordered. Consumers see a merged stream sorted by signed `timestamp`, with ties broken by `(sender, seq)` for determinism.
- *Across topics*: no ordering claim at all. Each topic is independent.

**Replay protocol.** A small custom RPC over iroh's QUIC, opened between any two NodeIds:

```rust
pub struct ReplayRequest {
    pub topic_id: [u8; 32],
    pub hwm:      HashMap<SenderPubkey, (Seq, MessageHash)>, // empty = from genesis
    pub limit:    u32,
}

// Response: stream of WireMessage frames, in chain order per sender,
// interleaved by topic-level timestamp.
```

The responder validates the requester's cap allows read on the topic (signature check + cap-table lookup), then streams everything past the high-water mark. The blind host serves this exactly the same way as any peer — it just happens to have the most history.

**Gap detection and repair.** A live gossip subscriber receiving `seq=N` when its hwm for that sender is at `seq=N-3` knows it missed two messages. It opens a targeted replay to any reachable peer for that sender's gap. Peers that have those messages serve them; if none do, the consumer tolerates the gap and notes it. The hash chain means tampering at the gap boundary is detectable.

**Initial sync (cold start).** A freshly bootstrapped agent:
1. Connects to a peer hint from its `PairGrant.host` (typically the host).
2. Subscribes to `__caps` first; issues `ReplayRequest{topic_id: __caps, hwm: {}}`. From the resulting stream: decrypts every `SealedTo(self)` `__cap.grant` to learn its own capability set (including the topic ids and names granted to it); reads every `Public` `__cap.revoke` and `__cap.root_rotation` directly; materializes a local cap-table indexed by `cap_id` for verifying every other sender.
3. Derives the set of topics it has read rights on from its own caps. For each, subscribes via iroh-gossip and issues `ReplayRequest{hwm: {}}`. Processes `SealedTo(self)` `__topic.epoch_advance` and `__topic.history_grant` events to populate `keys.db`, then decrypts the topic's `Standard`-mode messages.
4. Verifies hash chains and signatures as it goes; rejects anything invalid.
5. Switches to live-tail mode.

**Forking / divergence.** If two messages claim the same `(sender, topic, seq)` with different `prev_hash`, the sender is misbehaving (likely a private key compromised and operating from two places). On detection, the receiving agent logs a `__caps`-channel alarm event, refuses both messages, and waits for a revocation from the root. v1 detects and alarms; it does not auto-heal.

**Idempotency.** A message's identity is the hash of its envelope (which covers the ciphertext via AAD). Receiving the same hash twice is a no-op. Replay is safely re-issuable.

---

## 6. Persistence and host role

### Local store per agent

Each participant — agent or host — maintains a local append-only log per topic on disk. Storage backend: `redb` (pure-Rust, embedded, single-file, ACID, transactional). Layout:

```
~/.wires/
  identity.key                       # this agent's ed25519 keypair
  node.toml                          # iroh secret, peer hints, config
  caps.db                            # redb: __caps log + materialized cap-table
  topics/
    <topic_id_hex>/
      log.db                         # redb: append-only WireMessages, indexed by (sender, seq)
      keys.db                        # redb: epoch keys keyed by epoch number
      meta.toml                      # human-readable name, joined-at, etc.
```

**Write path.** Receive `WireMessage` via gossip or replay → verify signature → verify cap → verify hash chain links → write to `log.db` inside a single redb transaction → if live, emit to in-process subscribers. Failures at any step are logged and the message is dropped (idempotent, so re-receipt is safe).

**Read path.** Subscribers register with the local node:

```rust
node.subscribe(topic_id, SubscribeMode::LiveAndReplay { hwm });
```

The node tails its `log.db` and the live gossip channel, decrypts using `keys.db`, and yields a stream of decrypted content. Folding to "current state" is the subscriber's job.

### Retention

Unbounded for v1. Each topic accumulates forever. A `wires compact <topic>` admin command is stubbed but not implemented in v1; when needed, it will publish a `__topic.snapshot` event signed by the root, and agents may drop pre-snapshot history. v2 also needs a scalable disk-backed approach for hosts under real load.

### The hosted node

A binary `wires-host` that:
- Runs an iroh node 24/7 with a stable public NodeId.
- Holds *no* root key, *no* epoch keys, and *no* capability of its own. It doesn't originate messages, so it doesn't need a cap. It is purely a relay and replay-server peer.
- Subscribes via iroh-gossip to every topic it learns about (i.e. every `topic_id` it has seen on the wire).
- Builds a local cap-table by reading `Public` events on `__caps` (revokes and root-rotations) and recording the existence and target of `SealedTo` `__cap.grant` events (cap_id and recipient pubkey, not content).
- For each incoming message, performs host-layer enforcement: signature valid, sender pubkey matches a known un-revoked `cap_id`. Drops messages that fail.
- Stores ciphertext envelopes in redb, indexed by `(topic_id, sender, seq)`.
- Serves `ReplayRequest`s: validates that the requester's `cap_id` is un-revoked and was issued to the requester's pubkey, then streams matching messages from storage.

The host is "blind" by structural omission: it never receives `SealedTo(host)` events because no such events are ever sent. It cannot decrypt `Standard` or `SealedTo` content. It can read `Public` content, which is by design intentionally global (revokes, root-rotations).

The host cannot validate message *content*, only envelope properties. A misbehaving agent with a valid cap could write garbage that the host happily stores. Consumers detect bad content on decrypt and discard. This is accepted: host blindness is the higher-order property.

---

## 7. Crate layout and v1 deliverables

```
wires/
  Cargo.toml                          # workspace
  crates/
    wires-core/                       # protocol types: WireMessage, Cap, Topic;
                                      # serialization, signature verification, hash chains.
                                      # Zero iroh dependency — pure types + logic.
    wires-crypto/                     # ed25519 / x25519 / chacha20-poly1305 wrappers;
                                      # epoch-key wrap/unwrap; AEAD nonce derivation.
    wires-store/                      # redb-backed local store: log, caps, epoch keys;
                                      # read/write/replay-iteration APIs.
    wires-net/                        # iroh integration: gossip subscribe/publish;
                                      # custom QUIC replay RPC; peer-hint handling.
    wires-node/                       # agent-facing runtime: composes the above;
                                      # exposes subscribe(topic, mode) -> Stream<Decrypted>
                                      # and publish(topic, type, text, data?).
    wires-cli/                        # `wires` binary: invite, topic create, cat,
                                      # publish, status. Wraps wires-node.
    wires-host/                       # the always-on blind relay binary.
                                      # Same wires-node, configured to participate
                                      # without epoch keys.
```

### v1 acceptance criteria

1. Two `wires` CLI instances on the same LAN can `wires topic create home.test`, then publish/subscribe and see each other's messages in real time.
2. Stopping one agent for an hour and restarting → it replays missed messages on reconnect, hash chains verify, and no gaps go undetected.
3. A third agent bootstrapped via `wires pair-listen` / `wires pair-approve` → receives full history (including all prior epoch keys), tails live.
4. Revoking the third agent's cap → it can no longer post; a fourth agent created after revoke does not see the revoked agent's prior messages decrypted into garbage (chain intact, messages still stored, receiver refuses them on cap-check).
5. `wires-host` running on a VPS (no cap of its own) → mediates replay between two agents that have never been directly peered, while content is not decryptable from its disk dumps. Verified by dumping the host's storage and confirming the only readable content is `Public` `__cap.revoke` / `__cap.root_rotation` events.
6. `wires cat home.test --tail` produces human-readable lines: timestamp, sender alias, type, text.

### Out of scope (each gets its own spec)

- iOS companion app (root key custody, cap-minting UI, invite QR generation).
- REST gateway (HTTP wrapper around `wires-node` for skill-based agents).
- MCP server (same surface as REST, exposed as MCP tools).
- Ingestion daemons (Gmail, calendar, Home Assistant, etc.).
- Schema-conventions library (recommended `type` namespaces and `data` shapes per domain).
- Compaction and snapshots.
- Multi-household federation.

### Dependencies (pinned at workspace level)

- `iroh`, `iroh-gossip`
- `ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `blake3`
- `redb`
- `serde`, `serde_json`
- `tokio`, `tracing`, `clap`
- `snafu`

---

## 8. Error handling conventions

All crates use `snafu` for errors. No `anyhow`, no `thiserror`.

- Errors form a hierarchy. Errors from other crates (`serde_json`, `iroh`, `redb`, etc.) are leaves, linked into higher-level errors via `#[snafu(source)] source: <ExternalError>`.
- Every error variant includes a `location` field: `#[snafu(implicit)] location: Location` (from `snafu::Location`).
- Variant messages end with `, at {location}` so traces are easy to scan.
- No `message: String` field on variants. All human-readable formatting lives inside `#[snafu(display("..."))]`.
- Convert errors at boundaries with `.context(SomethingSnafu)` (the macro-generated context builder).

Template:

```rust
use snafu::{Snafu, ResultExt, Location};

#[derive(Debug, Snafu)]
pub enum MessageError {
    #[snafu(display("Failed to deserialize message, at {location}"))]
    Deserialization {
        #[snafu(source)]
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Failed to validate message, at {location}"))]
    Validate {
        #[snafu(implicit)]
        location: Location,
    },
}

pub fn read_message(json: &str) -> Result<Message, MessageError> {
    let message = serde_json::from_str(json).context(DeserializationSnafu)?;
    let validated_message = message.validate().context(ValidateSnafu)?;
    Ok(validated_message)
}
```

---

## 9. Testing strategy

**Pure unit tests per crate.**
- `wires-core`: serialization round-trips, signature verify, hash chain validation, capability glob matching — over `proptest`-generated inputs. Fast, deterministic, no I/O.
- `wires-crypto`: known-answer tests for AEAD nonce derivation, epoch-key wrap/unwrap, ed25519 sign/verify; fuzz on decrypt with corrupted ciphertext.
- `wires-store`: redb open/append/iterate/replay over tempdirs; verifies idempotency of double-write and gap detection on iterate.

**Integration tests.** A `tests/` directory in `wires-node` that spins up multiple in-process `wires-node` instances connected via iroh's in-memory transport. Scenarios:

- Two nodes, one topic, alternating publishes — both converge.
- Three nodes, one offline during five publishes, comes back — replays exactly the missed messages, hash chain valid.
- Revoke node B's cap → B's posts after revoke are refused by A and C.
- Epoch advance → old key still decrypts old messages, new key decrypts new ones, member without new wrap reads only up to old epoch.
- Hash chain fork (same sender, same seq, different prev_hash) → both refused, alarm emitted.

**Acceptance test.** A `tests/acceptance.rs` that drives the six v1 acceptance criteria end-to-end using the public `wires-node` API (no internal access).

**Network / soak test.** A `wires-host` plus three agents on real iroh networking, running for 24h with synthetic traffic, asserting no message loss and bounded memory. Not part of CI; run before each release.

**No mocks at integration level.** Spawn real nodes, use real iroh transports (in-process variant for speed), real redb stores in tempdirs. Mocks at this layer hide the bugs that actually bite.

**TDD discipline.** Per the test-driven-development skill, each new behavior gets a failing test first, then the smallest implementation that passes, then refactor. The implementation plan will call this out explicitly so we do not drift.

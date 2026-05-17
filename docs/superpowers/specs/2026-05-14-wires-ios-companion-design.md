# Wires — iOS Companion App Design

**Date:** 2026-05-14 (revised 2026-05-17)
**Status:** Draft. Revised again on 2026-05-17 to track the host-ticket-discovery slice that landed since the last revision: the HTTPS `/v1/bootstrap` discovery flow is gone, replaced by a base64 `HostTicket` distributed by QR / paste / AirDrop. The iOS bootstrap wizard now scans a QR from a running `wires-host` instead of typing a URL. This revision aligns the iOS surface against [the hosted-service design](2026-05-14-wires-hosted-service-design.md), [the responder-driven pairing design](2026-05-15-wires-responder-driven-pairing-design.md), and [the host-ticket-discovery design](2026-05-15-wires-iroh-host-ticket-discovery-design.md).
**Scope:** v1 of the iOS companion app. The app is the household's root of trust and operator console: it custodies the Ed25519 root key, registers with a hosted `wires-host` for relay, registers topics, and approves new agents into the household via the responder-driven pair flow.

---

## 1. Mental model

The iOS app is the **root of trust** and the **operator console** for a household's wires network. It is *not* itself a wires gossip peer — it does not publish `__cap.grant` envelopes, does not maintain a per-publisher hash chain, and does not subscribe to `__caps`. It does only what the root key alone is competent to do:

1. Pair with a hosted `wires-host` by scanning the host's `HostTicket` QR (or pasting the base64), then sending a signed `TenantRegisterRequest` over the `/wires/tenant/0` ALPN; register any topics the household creates over the same ALPN.
2. Approve agent enrollment by scanning the agent's `PairRequest` QR (or pasting it), reviewing the manifest, narrowing scopes if desired, minting a root-signed `Capability` plus the matching epoch keys, and delivering a sealed `PairGrant` over the `/wires/pair/0` ALPN.

There are exactly two QR codes in the iOS surface: a **host ticket** at first launch, an **agent pair request** every time the operator approves an agent. Both are decoded by the same `ScanFeature` reducer with a different parser closure.

Architecturally it is a SwiftUI + The Composable Architecture (TCA) app over a Rust core. The Rust core (`crates/wires-uniffi`) is a narrow facade reusing `wires-core`, `wires-crypto`, and `wires-net`. It does not depend on `wires-store` or `wires-node`: nothing on the iOS side needs an append-only log, an envelope replay responder, or a gossip subscription.

Persistence is split by sensitivity: SwiftData for low-sensitivity records (host info, topic registry, cap registry); Keychain for secrets (root signing key, topic epoch keys).

**v1 user-visible scope:**
- Generate household root key on first launch.
- Pair with the household's hosted `wires-host` by scanning its `HostTicket` QR (`wires-host` emits the QR to stderr at startup; the same ticket is reproducible at any time via `wires-host ticket`). Operators on an iOS-without-a-camera path can paste the base64 ticket instead.
- Register topics on demand with the host via a signed `TopicRegisterRequest`.
- Approve agent enrollment by scanning a `PairRequest` QR (produced by `wires pair-listen --qr`), narrowing scopes if desired, and delivering a sealed `PairGrant`.

**Explicitly out of scope for v1:**
- Revoking capabilities (no Revoke UI). Revocation can only be performed by the root key, so this is an iOS feature when added.
- Tail / view feeds (read-only household activity view).
- Supplemental cap-mints after initial pair (would require gossiping `__cap.grant` on `__caps`; deferred until the substrate spec's `__cap.grant` propagation lands).
- Multi-device root key custody (e.g. iPhone + iPad).
- Backup / recovery of the root key. Lose the phone, lose the household.
- iCloud sync of any iOS-app state.
- Operator-side topic creation UI as a discrete screen. Topics are created inline during pair-approve when a `PairRequest`'s `requested_scopes` references a literal topic name not yet in the registry.

---

## 2. Trust model and key custody

### Root key

A single Ed25519 keypair, generated in CryptoKit at first launch and stored in iOS Keychain.

- Keychain accessibility: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
- Access control: `SecAccessControlCreateWithFlags(.privateKeyUsage, [.biometryCurrentSet])`. Every signing operation triggers Face ID / Touch ID via LocalAuthentication.
- `kSecAttrSynchronizable = false`. Key does not replicate to iCloud Keychain.
- `.afterFirstUnlockThisDeviceOnly` excludes the key from iCloud backups by definition.

**Why not Secure Enclave?** iOS Secure Enclave hardware only supports P-256 ECDSA. The wires protocol uses Ed25519 consistently across all signatures (envelope signing, agent identity, cap signing). Adding a second signature algorithm to the protocol surface to accommodate a single platform constraint was the alternative; we chose to keep Ed25519 uniform and accept the Keychain-with-biometric storage compromise.

**Security delta:** Both SE and Keychain-with-biometric gate signing on biometric assertion and prevent extraction via the normal Keychain API without that assertion. SE additionally guarantees the private key bytes never enter normal CPU memory; Keychain does not — the seed is briefly in process memory during signing. For a household-scale trust root the realistic threats (lost or stolen phone) are mitigated identically by both. Kernel compromise during an authorized sign window is the differential threat and is judged out-of-scope.

### What the iOS app uses the root key for

Three signing sites, all biometric-gated:

1. **`TenantRegisterRequest` / `TopicRegisterRequest`** — root-signed messages over `/wires/tenant/0` (signing-bytes layout per the hosted-service spec §4).
2. **`Capability.sign`** — the inner root-signed cap embedded in every `PairGrant`.
3. **`PairGrantEnvelope.signature`** — the outer ed25519 signature over `(root_pubkey || sealed_payload)` (responder-driven-pairing spec §4).

The iOS app does *not* sign `WireMessage` envelopes. It does not publish `__cap.grant` envelopes via gossip. Future work that introduces supplemental cap-mints will need a separate signing path; not in v1.

### No iOS agent identity

The previous draft of this spec gave iOS its own ed25519+x25519 "agent identity" so the app could publish `__cap.grant` envelopes on `__caps`. In the responder-driven pair flow, the cap reaches the new agent out-of-band inside the `PairGrant` ciphertext — there is no gossip publish. The iOS app therefore has no agent identity, no self-cap, and no per-publisher hash chain. The previous Keychain entries `wires.agent.ed25519` and `wires.agent.x25519` are removed from this design.

### iroh node identity

`PairClient` requires an iroh `Endpoint` to dial Bob's address. The endpoint needs a secret key, but it is purely a transport identity unrelated to the wires trust model. We persist 32 random bytes as `wires.iroh.secret` in Keychain (`.afterFirstUnlockThisDeviceOnly`, no biometric ACL) and pass them to `wires-net::endpoint::bind_lan` on each launch. There is no security requirement that this key be biometric-gated — it does not authorize anything in the wires protocol.

### Topic epoch keys

The iOS app holds, for each topic the household has created, every epoch symmetric key (32 bytes, ChaCha20-Poly1305) ever issued. Required because pair-approve embeds the full epoch-key set for each granted topic into the `PairGrant` so a newly enrolled agent can decrypt historical traffic on that topic up to its retention horizon.

Storage: Keychain, one entry per (topic_id, epoch).
- Key: `wires.topic.<topic_id_hex>.epoch.<n>`
- Value: 32 raw bytes
- Accessibility: `.afterFirstUnlockThisDeviceOnly`, no biometric ACL. (Reading epoch keys to assemble a `PairGrant` is gated by the biometric prompt on the *root* sign of the cap and envelope, not on each key read.)

Topic epoch keys are placed in Keychain rather than SwiftData because SwiftData's store, while encrypted at rest while the device is locked, is plaintext while the device is unlocked. An attacker with a one-time unlocked-device backup can therefore extract a SwiftData store but not Keychain entries with `.afterFirstUnlockThisDeviceOnly`.

---

## 3. Flows

Three flows: first-launch wizard, agent approval, and per-launch refresh.

### 3.1 First-launch wizard

Triggered when `AppFeature` observes no `Household` record in SwiftData.

**Step 1: Scan host ticket.** A single screen shows a camera viewfinder ("Scan the QR from your `wires-host` terminal"). A "Paste ticket" button below opens a text-entry sheet for the base64 form. On a successful scan or paste:

1. `WiresClient.parseHostTicket(payload)` calls into Rust → `wires_net::ticket::HostTicket::decode(payload)` → returns a typed `HostTicket`. The Rust side validates the version byte, address-count bound, base64 framing, and that `endpoint_id` is 32 valid bytes of an iroh `EndpointId`. iOS receives a `HostInfo { endpointIdHex, addrs, relay, hintExpiresAtMs }`.
2. Surface a confirmation screen showing the host's `endpoint_id` (first 12 hex chars + ellipsis), the count of direct addrs, the optional relay URL, and the `hint_expires_at` timestamp. Operator taps "Continue". (Manual identity verification beyond reading the prefix is left to the operator — the ticket itself is unsigned; trust is established by the scan-from-a-machine-I-physically-have-in-front-of-me handshake.)
3. Persist a `Household` draft with the host fields populated; cache `HostInfo` in feature state for step 2.

**Step 2: Generate root and register tenant.** Single button "Create Household". On tap:

1. Generate Ed25519 root keypair in CryptoKit. Persist to Keychain at `wires.root.signingkey` with the biometric ACL described in §2. Cache root pubkey hex separately at `wires.root.pubkey` (no ACL, read freely). Generate iroh node secret at `wires.iroh.secret`.
2. Call `WiresClient.registerWithHostedService(hostInfo)`. Rust:
   a. Binds an iroh `Endpoint` using the iroh node secret.
   b. Adds the host's `endpoint_id`, direct addrs, and optional relay to the endpoint's address book (the ticket's `addrs`/`relay` are short-TTL hints; iroh's discovery resolves the `endpoint_id` to fresh addrs over time).
   c. Builds a `TenantRegisterRequest`: `{ version: 1, root_pubkey, timestamp = now_ms, nonce = random[16], signature = root_sign(signing_bytes) }`. The `signing_bytes` layout comes from `wires_net::tenant::signing_bytes(TenantOp::Register, host_endpoint_id, ...)` (hosted-service spec §4.2). Root-sign call triggers the Face ID prompt on the Swift side.
   d. Opens a bidirectional stream over `/wires/tenant/0`, sends `TenantRequest::Register(...)`, awaits `TenantResponse::Register(ok = true, ...)`. Returns the `caps_topic_id` and `host_endpoint_id` to Swift.
   e. On error: stream/dial failures map to `WiresError::TenantStream { message }`; signature-rejection responses map to `WiresError::TenantRejected { code, message }`.
3. Persist a complete `Household` record: `rootPubkeyHex`, `hostEndpointIdHex`, `hostDirectAddrs`, `hostRelayURL`, `hostHintExpiresAtMs`, `capsTopicIdHex`, `tenantRegisteredAt`, empty `topics` and `caps` relationships. Single SwiftData transaction.
4. Advance to step 3.

**Step 3: Done.** Confirmation screen showing the household root pubkey hex (a long string the operator may want to save for verification). "Continue" enters Home.

The biometric prompt fires exactly once in this wizard, at step 2's root sign.

### 3.2 Agent approval (responder-driven pair)

Triggered from Home by "Approve agent" button.

**Step 1: Agent prepares.** On a separate machine, the new agent runs `wires pair-listen --role <slug> --description <text> --request <topic:rights> --qr [...]` (responder-driven-pairing spec §8). The CLI prints the `PairRequest` as base64 plus a terminal QR. The operator points the iOS camera at the QR.

**Step 2: iOS scans and previews.** `ScanFeature` decodes the QR string. iOS feeds the payload to `WiresClient.parsePairRequest(payload)`:

1. Rust calls `wires_net::pair::request::PairRequest::decode_and_verify(payload)` which base64-decodes, parses canonical JSON, and verifies the agent's ed25519 signature on the request body. On failure → `WiresError::InvalidPairRequest { reason }`.
2. Returns a `PairRequestPreview { agentPubkeyHex, role, description, issuedAt, expiresAt, dial, requestedScopes }` to Swift. The raw token and ephemeral X25519 pubkey are kept inside the Rust core so Swift never touches them directly.

`AgentEnrollmentFeature` presents an approval sheet pre-filled from the preview.

**Step 3: Operator reviews and approves.** The sheet shows the agent's role + description + requested scopes. For each `RequestedScope`:

- If the topic name resolves against `TopicRecord` in SwiftData → show "✓ existing topic", precheck the requested rights (operator may downgrade `read+write` to `read`).
- If the topic name has no matching `TopicRecord` and is a syntactically valid literal name → show "+ new topic", offer to create it. Precheck the requested rights.
- If the operator denies a scope, it is dropped from the grant.

The sheet has a top-level Approve button that becomes enabled once at least one scope is checked. Approve triggers the pair effect chain:

1. **Resolve / create topics.** For each kept scope:
   - Existing topic: load its `topic_id` and all epoch keys from Keychain.
   - New literal-name topic: call `WiresClient.generateTopicIdAndEpoch0()` → returns `(topic_id_hex, epoch_0_key)`. Persist a `TopicRecord` (currentEpoch = 0). Persist the key to Keychain at `wires.topic.<id>.epoch.0`. Call `WiresClient.registerTopic(topicIdBytes)` — Rust sends a signed `TopicRegisterRequest` over `/wires/tenant/0`. Biometric prompt fires here for the root signature. On host failure → `WiresError::TopicRegisterFailed { code, message }`; the topic record is left in place (idempotent re-register on retry).
2. **Mint the grant.** Single FFI call `WiresClient.approvePairRequest(pendingHandle, grantedScopes)`. Rust:
   - Loads the cached `PairRequest` (kept by handle from step 2 above).
   - Constructs a `Capability { agent_pubkey = request.agent_pubkey, topics = [name for each granted scope], rights = combined rights, issued_at = now, expires_at = None, cap_id = random[16] }`.
   - Signs the cap via the `RootSigner` callback (biometric prompt fires here; this is the second prompt in the agent-approve flow if a new topic was registered, or the first if all topics were pre-existing).
   - Assembles `PairGrant { version: 1, root_pubkey, cap, topic_keys = [...], topic_names = [...], host = Some(HostInfo { peer_hints: vec![PeerHint { node_id: Household.hostEndpointIdHex, addrs: Household.hostDirectAddrs, relay: Household.hostRelayURL }] }), nonce = request.nonce, issued_at = now }`. (The substrate `PairGrant::HostInfo` is `{ peer_hints }` only.)
   - Serializes the grant to canonical JSON, seals it to `request.ephemeral_x25519` with AAD `b"wires.pair.v1"` and AEAD nonce derived per `wires_crypto::sealed::sealed_nonce(grant.nonce, grant.root_pubkey, seq=0)` (responder-driven-pairing spec §4 "Crypto choices").
   - Signs the envelope: `signature = root_sign(root_pubkey || sealed_payload)`. **Re-uses the cap-sign biometric assertion** if iOS can do so within a single LocalAuthentication transaction; otherwise this is a second prompt. (See §6 "Biometric prompts" for the resolution.)
   - Returns `PairGrantEnvelope` to be sent.
3. **Deliver the grant.** Rust uses `wires_net::pair::PairClient::deliver_grant(dial, envelope)`:
   - Resolves `request.dial` into an iroh `NodeAddr`, adds direct-addr and relay hints.
   - Opens a stream on `/wires/pair/0`, writes `PairFrame::Grant`, reads one frame back.
   - Returns `Ok(PairAck)` or `Err(PairError::Rejected { code, message })`.
4. **Persist.** On `Ok(ack)`, in a single SwiftData transaction:
   - Insert a `CapRecord` with `capIdHex = ack.installed_cap_id`, `agentPubkeyHex`, `agentAlias = request.role + ": " + request.description`, `topicNames = ...`, `rights = ...`, `issuedAt = ack.installed_at`.
   - No chain advance — there is no chain on iOS.
   Dismiss the sheet, return to Home with a brief confirmation.

**Failure modes (operator-facing):**

- Scan decode / signature verify fails → "Couldn't read pair request. Ask the agent to print a fresh QR."
- Pair-request TTL has elapsed (`request.expires < now`) → "Pair request has expired. Ask the agent to re-run `wires pair-listen`."
- Host topic-register fails → "Couldn't register topic with host: {code}. {message}." Keep sheet open for retry.
- Pair dial fails (agent unreachable) → "Couldn't reach agent at {addrs}. Make sure `wires pair-listen` is still running on that machine."
- `PairAck` not received within 30s → same as above.
- `PairFrame::Reject` received → render the specific `PairRejectCode` (NonceMismatch, NonceExpired, RootMismatch, CapInvalid, etc.) with a sentence of guidance.

Concurrent approval of two different `PairRequest` tokens is not supported; the sheet is modal. Two-phase commit is unnecessary because the cap install on the agent's side is idempotent (responder-driven-pairing spec §6 "Crash recovery / idempotence").

### 3.3 Per-launch refresh

On every launch after first:

1. `AppFeature` reads the `Household` from SwiftData. Completion is judged by `tenantRegisteredAt != nil`. If absent → bootstrap path; if present → home path.
2. The iroh `Endpoint` is bound lazily — on the first action that needs it (Approve agent, Register topic) rather than at launch. Idle iOS apps stay quiet.
3. No background refresh of host info is required. The host's `endpoint_id` is permanent, and iroh discovery resolves it to fresh addresses on demand whether or not the cached `addrs`/`relay` hints have expired. `hostHintExpiresAtMs` is recorded for future re-scan UX (a settings-screen "Re-scan host ticket" action), but v1 does not enforce it.
4. No reconnection or subscription state needs to be re-established: the iOS app has no long-lived stream beyond the per-action ones it opens for tenant-register / topic-register / pair-deliver.

---

## 4. Data model

Three SwiftData `@Model` types, in `Wires/Wires/Models/`. There is no `PendingPublish` queue — iOS never has unsent gossip envelopes.

```swift
@Model final class Household {
    @Attribute(.unique) var rootPubkeyHex: String
    var createdAt: Date

    // Host info, populated from the scanned/pasted HostTicket at bootstrap step 1.
    // hostEndpointIdHex is permanent; addrs / relay are short-TTL hints that
    // iroh re-resolves over time. hostHintExpiresAtMs is recorded for future
    // re-scan UX but not enforced in v1.
    var hostEndpointIdHex: String?           // nil until ticket parsed
    var hostDirectAddrs: [String]
    var hostRelayURL: String?
    var hostHintExpiresAtMs: Int64?
    var capsTopicIdHex: String?              // echoed by tenant register
    var tenantRegisteredAt: Date?            // nil until tenant register succeeds

    @Relationship(deleteRule: .cascade) var topics: [TopicRecord]
    @Relationship(deleteRule: .cascade) var caps: [CapRecord]
}

@Model final class TopicRecord {
    @Attribute(.unique) var topicIdHex: String
    var name: String
    var createdAt: Date
    var currentEpoch: UInt32
    var registeredWithHost: Bool             // true once register_topic succeeded
    // Epoch key bytes live in Keychain at wires.topic.<topicIdHex>.epoch.<n>.
}

@Model final class CapRecord {
    @Attribute(.unique) var capIdHex: String
    var agentPubkeyHex: String
    var agentAlias: String?                  // "role: description" from PairRequest
    var topicNames: [String]                 // resolved literal names in this cap
    var rights: [String]
    var issuedAt: Date
    var expiresAt: Date?
    var revokedAt: Date?                     // unused in v1; reserved
}
```

**Keychain layout** (all `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, `kSecAttrSynchronizable = false`):

| Key | Value | ACL |
|---|---|---|
| `wires.root.signingkey` | Raw 32-byte Ed25519 seed | `.biometryCurrentSet` |
| `wires.root.pubkey` | Raw 32-byte Ed25519 pubkey | None (read freely) |
| `wires.iroh.secret` | Raw 32-byte iroh node secret | None |
| `wires.topic.<id_hex>.epoch.<n>` | Raw 32-byte symmetric key | None |

Removed compared to the previous draft: `wires.agent.ed25519`, `wires.agent.x25519`. iOS has no agent identity.

---

## 5. Wire-side surface (already landed)

This section was previously titled "Wire-side additions" and proposed three substrate changes. The substrate has since absorbed all three. For this revision the section is a pointer to what already exists; no new substrate work is required to ship the iOS app.

- **`wires-net::pair`** — `PairRequest`, `PairGrant`, `PairGrantEnvelope`, `PairClient::deliver_grant`, plus all framing and crypto. Used directly by `wires-uniffi`.
- **`wires-net::tenant`** — `TenantClient`, `TenantRequest::{Register, TopicRegister, TopicUnregister, Status}`, signing-bytes helpers. Used directly by `wires-uniffi`.
- **`wires-net::ticket::HostTicket`** — base64-encoded JSON ticket: `{ version, endpoint_id, addrs, relay, hint_expires_at }`. Bounds-checked on decode (`MAX_TICKET_BYTES = 1024`, `MAX_HINT_ADDRS = 8`). `HostTicket::decode(&str)` and `HostTicket::to_peer_hint()` are the entry points `wires-uniffi` will use.
- **`wires-net::endpoint::bind_lan`** — used by `wires-uniffi` to bind the iroh Endpoint. (The iOS app is on-LAN-as-far-as-its-router-is-concerned; mDNS is harmless and useful when the operator's host is on the same network.)
- **`RootSigner` trait** — *not yet landed* in `wires-core`. Today `Capability::sign(&self, root_sk: &SigningKey)`. The plan introduces a `RootSigner` trait so the iOS side can supply a callback-backed signer (Swift Keychain + biometric prompt) without `wires-core` learning anything about Swift. See the implementation plan, Phase 1, Task 1.

Deleted compared to the previous draft:

- `wires-host show-pair-qr` subcommand — never landed; hosted-service spec §9 explicitly forbids it. Replaced first by HTTPS discovery, then by the `HostTicket` flow.
- `wires enroll` subcommand + `EnrollmentToken` — replaced by `wires pair-listen` + `PairRequest`, which already ship.
- The iOS-only `HostPairToken` — never landed; superseded by `HostTicket` + tenant-register.
- `wires-net::discovery` module and HTTPS `/v1/bootstrap` — deleted; the `HostTicket` flow replaces them.
- `PairGrant::HostInfo.service_discovery_url` — the field never existed on the wire; the previous spec described it but the substrate `HostInfo` is `{ peer_hints }` only.

---

## 6. Rust-on-iOS shape: `wires-uniffi`

A new crate, `crates/wires-uniffi`, depending on `wires-core`, `wires-crypto`, `wires-net`. It does **not** depend on `wires-store` or `wires-node`.

### Public FFI surface

```rust
#[derive(uniffi::Object)]
pub struct WiresApp {
    rt: tokio::runtime::Runtime,
    iroh_secret: [u8; 32],
    root_signer: Arc<dyn SwiftRootSigner>,
    // Resolved on first use; cached for the process lifetime.
    endpoint: tokio::sync::OnceCell<iroh::Endpoint>,
    // Pending pair-request preview, keyed by opaque handle.
    pending: parking_lot::Mutex<HashMap<PendingPairHandle, PendingPair>>,
}

#[uniffi::export]
impl WiresApp {
    #[uniffi::constructor]
    pub fn bootstrap(
        iroh_secret: Vec<u8>,          // 32 raw bytes
        root_signer: Arc<dyn SwiftRootSigner>,
    ) -> Arc<Self>;

    pub fn parse_host_ticket(&self, payload: String) -> Result<HostInfo, WiresError>;

    pub async fn register_with_hosted_service(
        &self,
        host: HostInfo,
    ) -> Result<TenantRegistration, WiresError>;

    pub async fn register_topic(
        &self,
        host: HostInfo,
        topic_id: Vec<u8>,             // 32 bytes
    ) -> Result<(), WiresError>;

    pub fn parse_pair_request(
        &self,
        payload: String,
    ) -> Result<PairRequestPreview, WiresError>;

    pub fn generate_topic_id_and_epoch0(&self) -> NewTopic;

    pub async fn approve_pair_request(
        &self,
        handle: PendingPairHandle,
        granted_scopes: Vec<GrantedScope>,
        // Inline host info to embed in the PairGrant (must match the
        // household's current host).
        host: HostInfo,
    ) -> Result<PairAckRecord, WiresError>;

    pub fn discard_pair_request(&self, handle: PendingPairHandle);
}
```

UniFFI records and enums:

```rust
#[derive(uniffi::Record)] pub struct HostInfo {
    pub endpoint_id_hex: String,
    pub addrs: Vec<String>,
    pub relay: Option<String>,
    pub hint_expires_at_ms: i64,
}

#[derive(uniffi::Record)] pub struct TenantRegistration {
    pub caps_topic_id_hex: String,
    pub host_endpoint_id_hex: String,
    pub server_time_ms: i64,
}

#[derive(uniffi::Record)] pub struct PairRequestPreview {
    pub handle: PendingPairHandle,
    pub agent_pubkey_hex: String,
    pub role: String,
    pub description: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub requested_scopes: Vec<RequestedScopePreview>,
    pub dial_summary: String,          // human-readable "endpoint_id + addrs" for display
}

#[derive(uniffi::Record)] pub struct RequestedScopePreview {
    pub topic_name: String,
    pub rights: Vec<Right>,
}

#[derive(uniffi::Record)] pub struct GrantedScope {
    pub topic_id_hex: String,          // resolved by Swift
    pub topic_name: String,
    pub rights: Vec<Right>,
    pub epochs: Vec<EpochKey>,         // all epoch keys for this topic
}

#[derive(uniffi::Record)] pub struct EpochKey {
    pub epoch: u32,
    pub key: Vec<u8>,                  // 32 bytes
}

#[derive(uniffi::Record)] pub struct NewTopic {
    pub topic_id_hex: String,
    pub epoch_0_key: Vec<u8>,          // 32 bytes
}

#[derive(uniffi::Record)] pub struct PairAckRecord {
    pub installed_cap_id_hex: String,
    pub installed_at_ms: i64,
}

#[derive(uniffi::Record)] pub struct PendingPairHandle { pub id: String } // UUID

#[derive(uniffi::Enum)] pub enum Right { Read, Write }

pub trait SwiftRootSigner: Send + Sync {
    fn pubkey(&self) -> Vec<u8>;       // 32 bytes
    fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, WiresError>;  // 64 bytes
}
```

### Internal state

A single `tokio` runtime owned by `WiresApp`. One iroh `Endpoint` is bound lazily on first network call via `wires_net::endpoint::bind_lan` and cached. The `pending` map holds verified-but-not-yet-approved `PairRequest` payloads keyed by a Swift-opaque handle so the raw token and ephemeral pubkey never need to cross the FFI again. Entries are reaped on `discard_pair_request` or after a TTL (15 min) whichever comes first.

### `RootSigner` adapter

Internally `WiresApp` constructs a thin Rust adapter that implements the new `wires_core::RootSigner` trait (see §5) by calling the Swift-side `SwiftRootSigner` trait object. The adapter normalizes byte-length errors (32-byte pubkey, 64-byte signature) at the FFI boundary so `wires_core` sees a typed `SignError` and not a Swift-shaped one.

### Biometric prompts

LocalAuthentication on iOS will reuse a recently-passed evaluation for ~10 seconds by default when subsequent `SecItemCopyMatching` calls hit the same access-control flag. In practice for `approve_pair_request` this means:

- If a new topic was registered just before approval: two prompts (one for `TopicRegisterRequest` signature, one for the cap-sign that happens shortly after). Acceptable; the cap-sign prompt is the visible "you are about to grant access to this agent" act.
- If all topics already existed: one prompt at cap-sign time.
- The envelope's outer signature reuses the same Keychain access window as the cap-sign; in practice no extra prompt.

If LocalAuthentication does not coalesce in a future iOS release, we can wrap the two sign calls in an explicit `LAContext` with a single `evaluatePolicy` up-front, then perform both sign operations within its validity window. Not implementing that fallback until we see a measured regression.

### Public surface invariants

- `WiresApp` is `Send + Sync`. UniFFI generates `Arc<WiresApp>` on the Swift side.
- All `async` methods are driven from the embedded tokio runtime; Swift sees Swift `async` thanks to the `uniffi` `tokio` feature.
- No method panics on bad input. Every validation failure returns a typed `WiresError` variant.
- The Rust core is stateless across crashes. Restart-safety lives entirely in SwiftData + Keychain.

---

## 7. Swift architecture under TCA

The iOS app uses [swift-composable-architecture](https://github.com/pointfreeco/swift-composable-architecture) (TCA, current 1.16+ release line).

### Features

One folder per feature under `Wires/Wires/Features/`, each containing a `Feature.swift` (reducer) and a `FeatureView.swift` (SwiftUI).

- **`AppFeature`** — root. `State` is an enum: `case bootstrap(BootstrapFeature.State)` or `case home(HomeFeature.State)`. Transitions on `bootstrapCompleted`. At launch, reads `Household` from SwiftData via `HouseholdClient`; `tenantRegisteredAt == nil` → bootstrap, else → home.
- **`BootstrapFeature`** — three-screen wizard using `StackState<Path.State>` with cases `scanTicket`, `confirmHost`, `done`. The `scanTicket` step composes `ScanFeature` parameterised with the host-ticket parser closure (`WiresClient.parseHostTicket`) and offers a "Paste ticket" alternate path that opens a sheet for the base64 form.
- **`HomeFeature`** — lists `CapRecord`s grouped by agent, "Approve agent" button. Presents `AgentEnrollmentFeature` via `@Presents`.
- **`AgentEnrollmentFeature`** — composes `ScanFeature` and `ApprovalFeature` via a small two-state stack.
- **`ScanFeature`** — reusable QR scanner reducer. State: camera permission, last decoded payload, error. Generic in payload shape via an init-time parser closure. Used in two places: bootstrap (parser = `parseHostTicket`) and agent enrollment (parser = `parsePairRequest`).
- **`ApprovalFeature`** — approval sheet driven by the `PairRequestPreview`. State: per-scope grant/deny + rights toggles; per-new-topic create/skip; "Approve" enabled when ≥1 scope kept. Approve action triggers the topic-register-then-mint-then-deliver effect chain.

### Dependencies

Under `Wires/Wires/Dependencies/`. Each is a `struct` of closures with `DependencyKey` conformance, plus `liveValue`, `testValue` (unimplemented), and `previewValue` (canned data).

```swift
@DependencyClient struct WiresClient {
    var bootstrap: @Sendable (Data, any RootSignerCallback) -> Void
    var parseHostTicket: @Sendable (String) throws -> HostInfo
    var registerWithHostedService: @Sendable (HostInfo) async throws -> TenantRegistration
    var registerTopic: @Sendable (HostInfo, Data) async throws -> Void
    var parsePairRequest: @Sendable (String) throws -> PairRequestPreview
    var generateTopicIdAndEpoch0: @Sendable () -> NewTopic
    var approvePairRequest: @Sendable (PendingPairHandle, [GrantedScope], HostInfo) async throws -> PairAckRecord
    var discardPairRequest: @Sendable (PendingPairHandle) -> Void
}

@DependencyClient struct HouseholdClient {
    var loadHousehold: @Sendable () async throws -> Household?
    var saveHousehold: @Sendable (Household) async throws -> Void
    var refreshHostInfo: @Sendable (HostInfo) async throws -> Void
    var listTopics: @Sendable () async throws -> [TopicRecord]
    var saveTopic: @Sendable (TopicRecord) async throws -> Void
    var markTopicRegistered: @Sendable (String) async throws -> Void
    var listCaps: @Sendable () async throws -> [CapRecord]
    var saveCap: @Sendable (CapRecord) async throws -> Void
}

@DependencyClient struct KeychainClient {
    var getData: @Sendable (String) throws -> Data?
    var setData: @Sendable (String, Data, KeychainAccessibility) throws -> Void
    var deleteData: @Sendable (String) throws -> Void
    var signWithBiometric: @Sendable (String, Data) async throws -> Data
}
```

Reducers never touch `ModelContext` or `SecItem` APIs directly — all I/O goes through these clients.

### Folder layout

```
Wires/
  Wires/
    App/
      WiresApp.swift              # @main, instantiates root Store
      AppFeature.swift
    Features/
      Bootstrap/
        BootstrapFeature.swift
        BootstrapView.swift
        ScanTicketView.swift
        ConfirmHostView.swift
      Home/
        HomeFeature.swift
        HomeView.swift
      AgentEnrollment/
        AgentEnrollmentFeature.swift
        ApprovalFeature.swift
        AgentEnrollmentView.swift
      Scan/
        ScanFeature.swift
        ScanView.swift
    Dependencies/
      WiresClient.swift
      HouseholdClient.swift
      KeychainClient.swift
    Models/
      Household.swift
      TopicRecord.swift
      CapRecord.swift
  WiresKit/                       # SwiftPM local package
    Package.swift
    Sources/WiresKit/             # UniFFI-generated Swift
    Frameworks/wires.xcframework  # built by scripts/build-ioskit.sh
  WiresTests/                     # TestStore-based reducer tests
  WiresUITests/                   # snapshot + UI tests
```

Removed compared to the previous draft: `Models/PendingPublish.swift`. iOS has nothing to retry.

### Xcode project dependencies

- `swift-composable-architecture` pinned `from: "1.16.0"`.
- Local SwiftPM package at `path: "../WiresKit"`.
- `swift-snapshot-testing` (dev-only, test target).

---

## 8. Build and packaging

### `wires-uniffi` build

The crate is `crate-type = ["staticlib", "cdylib"]`. UniFFI 0.28+ via `uniffi-bindgen`. The build script `scripts/build-ioskit.sh`:

1. `cargo build --release --target aarch64-apple-ios -p wires-uniffi`
2. `cargo build --release --target aarch64-apple-ios-sim -p wires-uniffi`
3. `cargo build --release --target x86_64-apple-ios-sim -p wires-uniffi`
4. `lipo -create` the two simulator slices into a fat library.
5. `xcodebuild -create-xcframework` combining the device library and the fat simulator library into `Wires/WiresKit/Frameworks/wires.xcframework`.
6. `cargo run --bin uniffi-bindgen` to emit `wires_uniffi.swift` and module headers into `Wires/WiresKit/Sources/WiresKit/`.

The script is idempotent; CI runs it on a macOS runner before Xcode build.

### Xcode project

`Wires.xcodeproj` is updated to:

- Add `Package.swift` references for swift-composable-architecture and the local `WiresKit` package.
- Update the `Wires` target's "Frameworks, Libraries, and Embedded Content" to include `ComposableArchitecture` and `WiresKit`.
- Bump deployment target to iOS 17 (TCA + SwiftData + `@Observable` macro require it).
- Replace the SwiftData/Item template scaffolding (`Item.swift`, default `ContentView`) with the new structure from §7.

---

## 9. Error handling

### Rust side: `WiresError`

A single UniFFI-modeled enum, in `wires-uniffi/src/error.rs` per the existing snafu pattern (every variant has `#[snafu(implicit)] location: Location`, display ends with `, at {location}`, no `message: String` field unless required as data; external errors are leaves linked via `source`).

```rust
#[derive(Debug, Snafu, uniffi::Error)]
pub enum WiresError {
    #[snafu(display("Failed to decode host ticket: {message}, at {location}"))]
    TicketDecode { message: String, #[snafu(implicit)] location: Location },

    #[snafu(display("Tenant register stream failed, at {location}"))]
    TenantStream { source: wires_net::error::NetError, #[snafu(implicit)] location: Location },

    #[snafu(display("Host rejected tenant register: {code:?}: {message}, at {location}"))]
    TenantRejected { code: TenantErrorCode, message: String, #[snafu(implicit)] location: Location },

    #[snafu(display("Topic register stream failed, at {location}"))]
    TopicRegisterStream { source: wires_net::error::NetError, #[snafu(implicit)] location: Location },

    #[snafu(display("Host rejected topic register: {code:?}: {message}, at {location}"))]
    TopicRegisterRejected { code: TenantErrorCode, message: String, #[snafu(implicit)] location: Location },

    #[snafu(display("Pair request token is invalid, at {location}"))]
    InvalidPairRequest { reason: PairDecodeReason, #[snafu(implicit)] location: Location },

    #[snafu(display("Pair request has expired, at {location}"))]
    PairRequestExpired { #[snafu(implicit)] location: Location },

    #[snafu(display("Unknown pending pair handle, at {location}"))]
    UnknownPairHandle { #[snafu(implicit)] location: Location },

    #[snafu(display("Pair grant delivery failed, at {location}"))]
    PairDeliveryFailed { source: wires_net::pair::PairError, #[snafu(implicit)] location: Location },

    #[snafu(display("Agent rejected pair grant: {code:?}: {message}, at {location}"))]
    PairRejected { code: PairRejectCode, message: String, #[snafu(implicit)] location: Location },

    #[snafu(display("Root signer failed, at {location}"))]
    RootSignerFailed { message: String, #[snafu(implicit)] location: Location },

    #[snafu(display("Internal error: {message}, at {location}"))]
    Internal { message: String, #[snafu(implicit)] location: Location },
}
```

`TenantErrorCode`, `PairRejectCode`, and `PairDecodeReason` are re-exported from `wires-net` so Swift sees the same vocabulary the protocols define. `TenantErrorCode` is re-exported as a `uniffi::Enum` rather than passed across the boundary as a string.

### Swift side

`WiresClient` and `HouseholdClient` calls in effects produce `WiresError` and `HouseholdError` respectively. Reducers translate via a `userMessage(for: any Error) -> String` helper. Each presenting feature has a `@Presents var destination: Destination.State?` with an `alert` case.

`KeychainClient` exposes its own small Swift enum:

```swift
enum KeychainError: Error {
    case notFound
    case biometricCancelled       // user dismissed Face ID — handled non-modal
    case biometricFailed
    case unexpectedStatus(OSStatus)
}
```

User-cancelled Face ID is silent: the reducer returns to the previous state without alerting. Other Keychain failures surface as alerts.

---

## 10. Testing strategy

### Rust tests in `wires-uniffi`

- **Pure parser tests.** `parse_pair_request` round-trip and signature-verify rejection. Synthetic `PairRequest`s constructed via `wires_net::pair::request::PairRequest::new + sign`. `parse_host_ticket` round-trip on a synthetic `HostTicket` (encoded with `HostTicket::encode`) plus rejection of arbitrary garbage strings.
- **`generate_topic_id_and_epoch0`** returns 32+32 bytes, distinct across calls, nonzero.
- **`RootSigner` adapter** roundtrip: a fake `SwiftRootSigner` (in-process ed25519 keypair) signs a `Capability`; `cap.verify(&pubkey)` passes.
- **Integration with real iroh + wires-host.** Spins up `wires-host` in a test process, reads the host's `HostTicket` (via the host lib's ticket accessor), feeds it to `WiresApp.parse_host_ticket` → `register_with_hosted_service` → `register_topic`, then verifies `tenants.redb` and `topic_index.redb` reflect the registration.
- **Pair end-to-end.** Two `WiresApp`s would be wrong — iOS only plays Alice. Spin up `wires-node` in a test process running `pair::listen`, point `WiresApp.approve_pair_request` at its endpoint, assert the listener's cap install completes and the SwiftData-side `PairAckRecord` matches.

### Swift reducer tests (`WiresTests/`, TCA `TestStore`)

- **`BootstrapFeatureTests`** — drives the wizard with mocked dependencies. Cases:
  - Happy path (scan): decoded payload → confirm host → register → done. Assert `parseHostTicket` and `registerWithHostedService` each called once.
  - Happy path (paste): same as above, via the paste sheet.
  - Bad ticket payload (`parseHostTicket` throws `TicketDecode`) → alert, stays on scanTicket step.
  - Tenant register fails on first attempt, succeeds on retry → final state matches happy path.
  - Tenant register receives `TenantErrorCode::BadSignature` from host → alert with code-specific copy.
- **`AgentEnrollmentFeatureTests`** — scan → approval → mint → deliver. Cases:
  - Happy path: existing topic, requested rights granted as-is.
  - Operator narrows `read+write` to `read` → assert `approvePairRequest` receives the narrowed rights.
  - Happy path: new topic name → assert `generateTopicIdAndEpoch0` was called, new `TopicRecord` saved, `registerTopic` called, then mint proceeds.
  - Operator denies one of two requested scopes → assert only the kept one appears in `GrantedScope[]`.
  - Pair-request expired (preview's `expiresAt < now`) → block Approve, show inline error.
  - Topic register fails → keep sheet open, retry button enabled.
  - Pair deliver fails with `PairRejectCode::NonceMismatch` → render guidance, don't persist a `CapRecord`.
  - Pair deliver succeeds → `CapRecord` saved exactly once with `installed_cap_id_hex` from the ack.
- **`ScanFeatureTests`** — permission denied path, malformed payload path, successful decode propagation.
- **`AppFeatureTests`** — restoration: nil household → bootstrap; populated → home; reads from `HouseholdClient.loadHousehold` exactly once at launch.

`TestStore` enforces that every emitted action is consumed by a `receive(...)` assertion, so unintended state changes fail the test.

### UI snapshot tests (`WiresUITests/`)

Using `swift-snapshot-testing`. One snapshot per major screen state:

- Bootstrap: scan-ticket (camera viewfinder), scan-ticket (paste sheet visible), confirm host, registering (in flight), done.
- Home: empty (no caps), populated.
- Approval sheet: pristine preview, partially-narrowed, all-denied (Approve disabled), in-flight, success.

### End-to-end manual acceptance

Not part of CI. Run before each release.

1. Fresh install on a real device → wizard runs → operator scans the `wires-host` terminal QR (or pastes the base64 from `wires-host ticket --no-qr`) → root key generated, Face ID enrolled, tenant registered against a known `wires-host` (self-hosted or hosted).
2. New agent (`wires pair-listen --role chat-agent --description "Bob" --request home.notes:read+write --qr` on a third machine) produces QR → operator scans → approves with `home.notes` + read+write → Bob's pair-listen exits with success → Bob can `wires publish home.notes hello`.
3. Kill app, relaunch → state restored, immediately ready to approve another agent.
4. Approve a second agent for the same `home.notes` topic → epoch-key history is included in the new agent's grant; second agent can `wires cat home.notes` and see Bob's earlier message.

---

## 11. Out of scope (each gets its own spec)

- **Revoke UI.** Listing existing caps, tapping to revoke. Requires the substrate `__cap.revoke` flow plus a tap-to-confirm-with-biometric path. The iOS surface is small but depends on `__cap.revoke` propagation existing.
- **Tail / view feeds.** Read-only "household activity" view. Requires the iOS app to subscribe to topics beyond what tenant-register sets up, decrypt with epoch keys, render. Substantial new work that pulls `wires-store` (or a SwiftData equivalent) onto iOS.
- **Supplemental cap-mints post-pair.** Granting Alice's existing agent access to a new topic without re-pairing. Requires the substrate's `__cap.grant`-over-`__caps` propagation to land. Iff that lands, iOS gains an agent identity, a self-cap, and a per-publisher hash chain — i.e. the architecture the *previous* draft of this spec proposed for v1. The shape of that work is captured in the previous draft.
- **Root key backup and recovery.** Secret sharing, recovery phrase, or successor key designation. Depends on protocol-level `__cap.root_rotation` flow being designed and implemented.
- **Multi-device root custody.** Pairing iPhone + iPad as co-custodians of the same root key.
- **Multi-endpoint discovery selection.** v1 always picks `endpoints[0]`. Sharding awareness, latency-based selection, and signed discovery responses come with sub-project B of the hosted-service work.
- **Epoch rotation triggers.** Wired when revoke lands.
- **macOS / iPadOS variants.** Same SwiftUI + TCA + WiresKit code targets these, but layout, navigation, and Keychain accessibility nuances need their own pass.
- **Operator-side topic management UI.** Standalone "create topic" screen, "unregister topic" action, viewing per-topic stats. Topic creation is currently inline-only during pair-approve. A future operator-tools pass adds the full surface.

# Wires — Hosted Multi-Tenant Service Design

**Date:** 2026-05-14
**Status:** Draft (awaiting user review)
**Scope:** Make `wires-host` multi-tenant so that one or more host processes can serve many users' worlds. Includes the tenant-control protocol an iOS app uses to onboard a fresh root of trust, the per-tenant storage layout, the bumped invite token format, the iOS-app hosted-service pairing mode, and a minimal HTTPS service-discovery surface. Builds on but does not replace [the substrate design](2026-05-14-wires-substrate-design.md) or [the iOS companion design](2026-05-14-wires-ios-companion-design.md). Sharding across multiple host processes, root-key recovery, and operational tooling are explicitly out of scope and get their own specs.

---

## 1. Mental model

The substrate spec describes a self-hosted single-tenant `wires-host`. This spec replaces that operational model with a uniform, multi-tenant one: every `wires-host` process is structurally capable of serving many tenants, and every iOS app onboards through the same flow — HTTPS service discovery to find a host `EndpointId`, then a signed tenant-registration RPC over a new iroh ALPN. Self-hosting is preserved by virtue of being trivial (run `wires-host`, run a discovery URL pointing at it, point your iOS app at that URL); it is not a separate code path.

Nothing in the wire format changes. The host's blindness contract is unchanged: it sees `topic_id`, `epoch`, `kind`, `recipient` (for `SealedTo`), `sender`, `cap_id`, `seq`, `timestamp`, and ciphertext length, and the cleartext content of `Public` messages on `__caps`. It learns one additional metadata fact per tenant: the tenant's root pubkey, plus the topic_ids that root has registered for service. The root pubkey is already cleartext in every `__cap.grant` envelope's `sender` field, so this is not new leakage — only an explicit binding the host already could have inferred from traffic.

The per-tenant log is **bounded**: each tenant has a fixed retention budget, and the oldest messages are evicted to make room for new writes. This replaces v1's "unbounded retention" non-goal from the substrate spec.

**Non-goals for this spec:**
- Topic→host sharding (a single host process serves all registered tenants and topics; fleet sharding comes later).
- Multi-host high availability (a tenant binds to one host process; restart preserves identity because `iroh.secret` is persistent).
- Cross-region replication, backup tooling, billing UI.
- iOS root-key custody, backup, social recovery, multi-device root.
- Sub-protocols for migrating a tenant from one host to another.

---

## 2. Tenant lifecycle

A **tenant** is a (root_pubkey, hosted-host) pair. The host knows:
- The root pubkey.
- Which topics the root has asked it to serve.
- Per-tenant rate-limit counters.
- A pointer to per-tenant on-disk storage.

The host does **not** know:
- Any agent pubkey other than what it sees as `sender` on inbound envelopes.
- Any cap content (sealed).
- Any topic content (sealed or encrypted under epoch key).
- Any topic name (it knows topic_ids only).

A tenant is created via the registration protocol (§4), persisted across host restarts via `tenants.redb`, and can be suspended or removed administratively. There is no v1 self-service "delete my tenant" flow.

---

## 3. Components and crate layout

New code lives in the existing workspace; no new crate boundaries.

| Crate | Additions |
|---|---|
| `wires-core` | No changes. Reserved message types are unchanged. |
| `wires-crypto` | No changes. |
| `wires-store` | Adds `TopicLog::evict_oldest_until(target_bytes)` and `TopicLog::bytes_stored()` for the per-tenant rolling-log retention behavior (§5). `TopicLogs` is otherwise reused per-tenant. |
| `wires-net` | New `tenant` module: `TenantProtocol` (server-side ALPN handler), `TenantClient` (client-side dialer), request/response types. `InviteToken` replaced outright with the new shape (§6) — only one version is valid, no compat shim. |
| `wires-node` | Join flow gains an iterating peer-hint loop that consumes `InviteToken::peer_hints` in order and optionally falls back to `service_discovery_url` (§6). Existing publish/subscribe surface is unchanged. |
| `wires-host` | New `tenant_registry` module: tenant table, topic→tenant index, per-tenant storage. New `http_discovery` module: tiny axum service. Main rewritten to wire all this together and to remove `--topic` flags (topics are registered dynamically now). |
| `wires-cli` | Picks up the new `InviteToken` via `wires-net`; no other changes. |
| iOS `wires-uniffi` | New FFI: `register_with_hosted_service`, `register_topic`. New `HostedServiceClient` type. |

No new external dependencies except `axum` (or `hyper`+`tower`) in `wires-host` for the HTTPS surface. We pick the latest stable `axum` (currently 0.8.x at the time of writing).

---

## 4. Tenant control protocol

A new ALPN: `/wires/tenant/0`.

The protocol is **synchronous request/response** over a single QUIC bidirectional stream per request. Frame format mirrors `wires-net::replay`: 4-byte big-endian length prefix followed by `serde_json`-encoded body. One request, one response, then both sides close. This keeps the implementation small and lets us add new request types by extending the enum.

### 4.1 Request and response types

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TenantRequest {
    Register(TenantRegisterRequest),
    TopicRegister(TopicRegisterRequest),
    TopicUnregister(TopicUnregisterRequest),
    Status(TenantStatusRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TenantResponse {
    Register(TenantRegisterResponse),
    TopicRegister(TopicRegisterResponse),
    TopicUnregister(TopicUnregisterResponse),
    Status(TenantStatusResponse),
    Error(TenantErrorResponse),
}
```

### 4.2 `TenantRegisterRequest`

```rust
pub struct TenantRegisterRequest {
    pub version: u8,                 // 1
    pub root_pubkey: [u8; 32],
    pub timestamp: i64,              // unix millis, client clock
    pub nonce: [u8; 16],             // random per request
    pub signature: [u8; 64],         // ed25519 over signing_bytes (below)
}
```

`signing_bytes` = `b"wires-tenant-register-v1\0"` || `root_pubkey` || `timestamp.to_le_bytes()` || `nonce` || `host_endpoint_id_bytes`. The host's `EndpointId` is included so a captured registration cannot be replayed against a different host.

Server behavior:
1. Verify signature with `root_pubkey`.
2. Verify `|server_time - timestamp| <= 60_000` ms.
3. Verify `(root_pubkey, nonce)` not in the recent nonce table (TTL ≥ 120s). Insert.
4. If tenant already exists: re-derive `__caps_topic_id`, ensure host is subscribed, return `ok: true` (idempotent re-register).
5. Otherwise: insert `Tenant { root_pubkey, registered_at: server_time, status: Active, retention_budget_bytes: default_retention_budget }` into `tenants.redb`. Derive `__caps_topic_id = BLAKE3("wires.caps.v1" || root_pubkey)`. Insert `(__caps_topic_id → root_pubkey)` into `topic_index.redb`. Spawn the gossip subscription for `__caps_topic_id`. Return `ok: true`.

```rust
pub struct TenantRegisterResponse {
    pub ok: bool,
    pub host_endpoint_id: String,    // hex
    pub server_time: i64,
    pub caps_topic_id: [u8; 32],     // echoed for client convenience
}
```

### 4.3 `TopicRegisterRequest`

```rust
pub struct TopicRegisterRequest {
    pub version: u8,                 // 1
    pub root_pubkey: [u8; 32],
    pub topic_id: [u8; 32],
    pub timestamp: i64,
    pub nonce: [u8; 16],
    pub signature: [u8; 64],         // by root_pubkey
}
```

`signing_bytes` = `b"wires-topic-register-v1\0"` || `root_pubkey` || `topic_id` || `timestamp.to_le_bytes()` || `nonce` || `host_endpoint_id_bytes`.

Server behavior:
1. Verify signature.
2. Verify tenant exists and is `Active`. If not → `Error(TenantNotFound | TenantSuspended)`.
3. Verify replay protection (same as register).
4. If `(topic_id → other_root_pubkey)` exists in `topic_index.redb` and `other_root_pubkey != root_pubkey`: `Error(TopicAlreadyRegistered)`. (Cosmically unlikely with 256-bit topic_ids, but we check.)
5. If `(topic_id → root_pubkey)` already exists: idempotent success.
6. Otherwise: insert, spawn gossip subscription for `topic_id`, return `ok: true`.

```rust
pub struct TopicRegisterResponse {
    pub ok: bool,
    pub topic_id: [u8; 32],
}
```

### 4.4 `TopicUnregisterRequest`

Same shape, opposite effect. Removes `topic_id` from `topic_index.redb`, drops the gossip subscription, but **does not delete** the per-tenant topic log file — that's a separate explicit operation (out of scope for this spec).

### 4.5 `TenantStatusRequest`

```rust
pub struct TenantStatusRequest {
    pub version: u8,
    pub root_pubkey: [u8; 32],
    pub timestamp: i64,
    pub nonce: [u8; 16],
    pub signature: [u8; 64],
}

pub struct TenantStatusResponse {
    pub registered_at: i64,
    pub topic_count: u32,
    pub bytes_stored: u64,           // current total ciphertext bytes across all topics
    pub retention_budget_bytes: u64, // configured ceiling; ingestion evicts oldest past this
    pub oldest_retained_at: i64,     // unix millis of the oldest retained message (informational)
    pub write_rate_limit_per_sec: u32,
    pub status: TenantStatusKind,    // Active | Suspended
}
```

### 4.6 Error response

```rust
pub struct TenantErrorResponse {
    pub code: TenantErrorCode,
    pub message: String,
}

pub enum TenantErrorCode {
    BadSignature,
    StaleTimestamp,
    ReplayedNonce,
    TenantNotFound,
    TenantSuspended,
    TopicAlreadyRegistered,
    RegistrationRateLimited,
    Internal,
}
```

### 4.7 Anti-abuse on the registration path

- Per-remote-address rate limit on `Register` requests: 5/minute, 50/hour. Address is the iroh `EndpointId` of the dialing client (always available from the QUIC handshake, even when the connection traverses a relay). Enforced before signature verification, because ed25519 verification is expensive enough that we don't want unauthenticated clients to burn CPU.
- Nonce table TTL: 120s. Stored in `nonces.redb`, periodic sweep.
- Per-(root_pubkey) rate limit on `Register` after the first success: 10/hour. Re-registration is allowed (idempotent) but bounded.

---

## 5. Host-side storage layout

Per host process:

```
data_dir/
  iroh.secret                        # 32-byte iroh node secret (this host's EndpointId)
  tenants.redb                       # tenant table: root_pubkey -> Tenant
  topic_index.redb                   # topic_id -> root_pubkey (forward index)
  nonces.redb                        # recent registration nonces with TTL
  tenants/
    <root_pubkey_hex>/
      log_<topic_hex>.redb           # per-topic ciphertext log (existing format)
      meta.json                      # joined_at, last_active_at, counters
```

The per-topic log file format is unchanged from the substrate spec — `TopicLogs::get_or_open` is reused, scoped to a per-tenant subdirectory.

### Routing inbound envelopes

The existing `wires-host/src/main.rs` accepts envelopes from gossip and appends them to a single `TopicLogs`. The new behavior:

1. Receive envelope, parse `WireMessage`.
2. Look up `root_pubkey = topic_index[envelope.topic_id]`. Absent → drop (with rate-limited tracing).
3. Look up `tenant = tenants[root_pubkey]`. `Suspended` → drop.
4. Check write-rate ceiling for this tenant. Over → drop (with a per-tenant warning counter so operators can see who's being throttled).
5. Run `verify_envelope(&msg)` — unchanged signature check.
6. Append to the per-tenant per-topic log.
7. If `tenant.bytes_stored > retention_budget`, evict oldest messages globally within the tenant until back under budget.

This is a thin layer over the existing flow — about 50 lines of additional routing logic plus the tenant_registry module.

### Replay protocol

The existing `/wires/replay/0` ALPN gains tenant-awareness:

1. Decode `ReplayRequest`, extract `topic_id`.
2. Look up `topic_index[topic_id]`. Absent → reply with empty stream or `NotFound`.
3. Open per-tenant `TopicLogs` for the resolved root_pubkey.
4. Stream as before.

No ACL checks on replay beyond the existing "host serves anyone who asks" model — the receiver still verifies caps and decrypts on its end. Adding cap-level enforcement at the host would require breaking blindness; we don't.

### Retention (rolling log per tenant)

Each tenant has a fixed **retention budget** measured in bytes. v1 default: 1 GiB per tenant, hardcoded. When a write would push a tenant's total stored ciphertext past the budget, the host evicts the **oldest entries (lowest `seq` per publisher chain, across all topics in the tenant)** until the total is back under the budget. Writes themselves always succeed (modulo signature verification, tenant status, and the write-rate ceiling below) — the log is a ring, not a gate.

The eviction unit is the message. Eviction order is global within a tenant, by ingestion timestamp on the host (which is monotonic per host process). This is simpler than per-topic round-robin and matches "you get N bytes of history, period."

**Consequence for receivers.** An agent doing a cold-start replay receives only what the host still retains. If its high-water mark is older than the host's oldest retained `seq` for some `(topic, sender)` pair, the replay returns the surviving suffix and the agent records a gap. The substrate spec's hash chain detects tampering within the surviving suffix; it does not let receivers reconstruct the lost prefix. This is acceptable for a SaaS retention bound and is the same property a future `__topic.snapshot` compaction would have.

**Write-rate ceiling (anti-CPU-DoS, not anti-storage).** A tenant signing valid envelopes faster than the host can persist them would burn CPU even if storage is bounded. A coarse rate limiter caps write rate at 1 000 envelopes/sec per tenant; excess envelopes are dropped at the routing step (§ below). This is a CPU/network protection, not a storage policy. v1 hardcodes the limit; later specs make it tier-configurable.

---

## 6. Invite token

The existing `InviteToken` in `wires-net/src/invite.rs` is replaced outright with the structure below. There is no shipped consumer of the old format, so no compatibility shim is needed. `InviteToken::decode` accepts only `version: 1` (this format); anything else is an error.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteToken {
    pub version: u8,                       // 1 (only valid value)
    pub cap: Capability,
    pub peer_hints: Vec<PeerHint>,         // try in order
    pub service_discovery_url: Option<String>,
    pub expires: i64,
    pub token_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerHint {
    pub node_id: String,                   // hex iroh EndpointId
    pub addrs: Vec<String>,                // direct addr hints
    pub relay: Option<String>,
}
```

The CLI agent's join flow (in `wires-node`):
1. Iterate `peer_hints`. For each, try `endpoint.connect(node_id).await`. On success, run the existing bootstrap logic (subscribe to `__caps`, replay, etc.).
2. If all peers fail and `service_discovery_url` is set: fetch `service_discovery_url`, get fresh endpoints, retry.
3. If still nothing: return a clear error.

---

## 7. Service discovery

A small HTTPS endpoint, run as a separate axum task in the same `wires-host` process for v1. Listens on a configurable port (default 8443, expects to be behind a TLS terminator or has a configured cert+key).

```
GET /v1/bootstrap
→ 200 OK
  Content-Type: application/json

  {
    "version": 1,
    "endpoints": [
      {
        "endpoint_id": "abc123...",
        "relay": "https://use1-1.relay.iroh.network/",
        "addrs": ["198.51.100.10:11204"]
      }
    ],
    "ttl_seconds": 300
  }
```

In this slice, the response always contains one entry: this host's own `EndpointId`. Sub-project B (sharding) will return multiple entries with sharding hints. The iOS app picks the first entry and uses it.

A self-hosting operator runs their own discovery URL (a static HTTPS endpoint returning their `wires-host`'s `EndpointId`) and points their iOS-app build at it. There is no separate "self-hosted pairing mode" — the same code path is used either way.

---

## 8. iOS app changes

The iOS companion is on hold (see memory note), and its spec will be revisited when this work lands. This section describes the iOS-side surface that must exist when iOS is revived — the QR-scan `HostPairToken` flow from the original iOS spec is dropped in favor of the single discovery-and-register path below.

### 8.1 First-launch wizard

Pairing has a single path. The QR-scan `HostPairToken` flow from the iOS companion spec is removed; the iOS app finds its host via service discovery.

1. iOS app fetches `https://discovery.wires.example/v1/bootstrap` (URL is build-time configurable; for a self-hosted operator, they configure a build pointing at their own discovery URL).
2. Picks `endpoints[0]`. Constructs a `HostInfo { hostNodeIdHex, hostRelayURL, hostDirectAddrs }` from it.
3. Calls into Rust: `WiresApp.bootstrap(agentIdentity, rootSigner)` then `WiresApp.registerWithHostedService(hostInfo, discoveryUrl)`. This dials the host on `/wires/tenant/0`, sends `TenantRegisterRequest` signed by the root key (biometric prompt to access the Secure Enclave). On success, populates `Household.hostNodeIdHex` and `Household.discoveryUrl`.
4. Continues with the existing "mint iOS agent self-cap" flow.

### 8.2 FFI additions

In `wires-uniffi`:

```rust
impl WiresApp {
    pub async fn register_with_hosted_service(
        &self,
        host: HostInfo,
        discovery_url: String,
    ) -> Result<(), WiresError> { ... }

    pub async fn register_topic(
        &self,
        topic_id: Vec<u8>,
    ) -> Result<(), WiresError> { ... }
}
```

`register_topic` is called by the iOS app after minting any cap that references a topic not yet known to the host. The mint flow becomes: derive topic_ids from the cap's resolved topic list → call `register_topic` for each new one → publish the `__cap.grant` to `__caps` as before. The mint is not considered complete until the host has acked all topic registrations.

### 8.3 `Household` model changes

```swift
@Model
final class Household {
    // ...existing fields...
    var discoveryUrl: String                 // always set; selected at first launch
}
```

There is no on-disk migration concern: the iOS companion is on hold pending this work (see memory note), so no production `Household` records exist.

---

## 9. Self-hosting

Self-hosting is supported but does not get a separate pairing flow. A self-hosting operator:

1. Runs `wires-host` on their own infrastructure.
2. Runs an HTTPS service-discovery endpoint that returns their host's `EndpointId`. This can be as simple as a static file served by any HTTPS server, or a `--serve-discovery` flag on `wires-host` itself (out of scope for this spec; the host process exposes one in §7 by default, which already covers single-operator setups).
3. Builds the iOS app with that discovery URL baked in (or enters it in a settings screen — design choice deferred to the iOS-revival spec).

There is no `--topic <hex>` flag on `wires-host` and no `show-pair-qr` subcommand. All topics arrive via the tenant control protocol. All onboarding is HTTPS discovery + tenant register. The hosted-vs-self-hosted distinction is purely "whose discovery URL the iOS app points at."

---

## 10. Error handling

Snafu pattern per `CLAUDE.md`. New error variants live in:

- `wires-net::error::NetError`: `TenantRegisterFailed { source, location }`, `TopicRegisterFailed { source, location }`, `TenantStreamClosed { location }`, `TenantBadResponse { source, location }`. Each with `Location`, message ending in `, at {location}`.
- `wires-host::error::HostError`: `TenantTableOpen { source, location }`, `TopicIndexOpen { source, location }`, `NonceTableOpen { source, location }`, `TenantSignatureInvalid { location }`, `TenantSuspended { root_hex, location }`, `RetentionEvictionFailed { source, location }`.
- iOS `wires-uniffi::error::WiresError`: `RegisterHostedService { source, location }`, `RegisterTopic { source, location }`, `DiscoveryFetchFailed { source, location }`.

---

## 11. Testing

Following the substrate spec's testing strategy: real iroh transports (in-memory variant where possible), real redb, no mocks at integration level.

### Unit
- `wires-net::tenant`: signature round-trip for each request type, replay-nonce rejection, response decode, malformed-frame handling.
- `wires-host::tenant_registry`: tenant create/load roundtrip, idempotent re-register, topic register idempotent, topic→tenant lookup, write-rate ceiling, retention eviction (writes beyond budget cause oldest to disappear), persistence across restart.
- `wires-store`: `TopicLog::evict_oldest_until(target_bytes)` correctness — oldest seq disappears first, ordering across multiple senders, no corruption of hash chain on surviving suffix.

### Integration (`crates/wires-host/tests/` or `crates/wires-node/tests/`)
- **Single tenant happy path**: spin up a host, dial via `TenantClient`, register tenant, register topic, publish on that topic from a separate agent, confirm host appends to the right per-tenant log.
- **Two tenants isolated**: same host, two iOS-stand-ins each register, each registers their own topic, each publishes. Dump `data_dir/tenants/<a>/` and `<b>/` and verify no cross-contamination.
- **Retention eviction**: set retention budget to a small value (e.g. 1 MiB), publish enough messages to overflow, verify total stored stays within budget and oldest messages are dropped first. Replay from `hwm: {}` returns only the surviving suffix.
- **Write-rate ceiling**: publish above the per-tenant ceiling, verify the excess is dropped without corrupting log state.
- **Bad signature rejection**: `TenantRegisterRequest` with wrong signature → `Error(BadSignature)`.
- **Replay rejection**: same nonce within TTL → `Error(ReplayedNonce)`.
- **Unknown topic dropped**: publish on a topic the tenant never registered, confirm host drops and does not panic.

### Acceptance (`crates/wires-host/tests/acceptance.rs`, marked `#[ignore]`)
1. Two fresh `wires` CLI clients (representing two iOS apps' agent identities) on the same host process register two distinct tenants. Each registers `home.test`. Each publishes. Each can only read their own messages (host enforces topic→tenant routing; cross-tenant traffic is dropped at the host).
2. A `wires-host` process is restarted with its data dir intact. Both tenants reconnect, no re-registration required (idempotent), retained messages still served via replay; previously-evicted messages do not reappear.
3. Invite token with multiple peer hints: agent tries the first hint (unreachable), falls back to the second (reachable), bootstraps successfully.
4. Service discovery: agent fetches `https://localhost:8443/v1/bootstrap` from the same `wires-host` process, parses the endpoint list, dials, registers.

---

## 12. Acceptance criteria

For this spec to be considered done:

1. `wires-host` runs without `--topic` flags and without a `show-pair-qr` subcommand. Topics arrive only via `/wires/tenant/0`.
2. A fresh iOS app can complete the full onboarding flow: discovery fetch → tenant register → topic register → mint self-cap → publish a message → replay it.
3. Two iOS apps with distinct root pubkeys can coexist on the same host process with no cross-tenant content leakage (verified by inspecting `data_dir/tenants/`).
4. A tenant whose ingest exceeds its retention budget has its oldest messages dropped automatically; `tenant_status` shows `bytes_stored ≤ retention_budget_bytes` after settling, and `oldest_retained_at` advances forward.
5. Invite token round-trips through `wires-cli` cleanly; decoding any token whose `version` field is not `1` returns an explicit error.
6. All new error variants follow the snafu/location convention from `CLAUDE.md`.
7. Acceptance test suite (§11) passes.

---

## 13. Out of scope (each gets its own spec)

- **Topic→host sharding and multi-host HA.** Multiple host processes serving different tenant subsets, with a routing layer (consistent hash on root_pubkey, redirect protocol, or shared control plane).
- **Cross-host replication.** Hot-standby hosts so a tenant survives a single host process death.
- **iOS root-key custody and recovery.** iCloud Keychain sync, passphrase-wrapped backup, social recovery via Shamir, multi-device root.
- **Operator backup/restore.** Snapshot pipeline for per-tenant redb files, point-in-time recovery, cross-region async replication.
- **Billing and per-tenant retention tiers.** v1 hardcodes a single retention budget for all tenants. Tiering, payment integration, and admin dashboard come later.
- **Tenant deletion and data export.** GDPR-shaped flows.
- **Service-discovery hardening.** Multi-region discovery, signed discovery responses (today the response is bare HTTPS; signing it with a long-term service key is sub-project B territory).
- **Migration tooling.** Moving a tenant from one host to another, key rotation, host EndpointId rotation.

---

## 14. Open questions deferred to the implementation plan

These are real questions but they're small enough that I'd rather resolve them while writing the impl plan than block the spec:

- Exact wire format of the length-prefixed JSON frame on `/wires/tenant/0`: reuse the helper functions in `wires-net::replay`, or factor them into a shared `wires-net::framing` module.
- Whether to factor a `wires-net::tenant::TenantSigner` trait so the iOS Secure Enclave and the local ed25519 signing key are uniform from the protocol's perspective.
- Default discovery URL baked into the iOS app at build time vs. runtime-configurable. Probably build-time with a setting screen override.
- Exact axum/hyper version pin and the TLS strategy for the discovery HTTPS endpoint (terminator in front, vs. rustls in-process). Picked at implementation time based on what stable on `axum 0.8.x` offers cleanly.

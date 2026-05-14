# Wires — Hosted Multi-Tenant Service Design

**Date:** 2026-05-14
**Status:** Draft (awaiting user review)
**Scope:** Make `wires-host` multi-tenant so that one or more host processes can serve many users' worlds. Includes the tenant-control protocol an iOS app uses to onboard a fresh root of trust, the per-tenant storage layout, the bumped invite token format, the iOS-app hosted-service pairing mode, and a minimal HTTPS service-discovery surface. Builds on but does not replace [the substrate design](2026-05-14-wires-substrate-design.md) or [the iOS companion design](2026-05-14-wires-ios-companion-design.md). Sharding across multiple host processes, root-key recovery, and operational tooling are explicitly out of scope and get their own specs.

---

## 1. Mental model

In the substrate spec, `wires-host` is a self-hosted appliance: an operator runs it on their NAS or VPS, hands its `EndpointId` to their iOS app via a QR code, and that one host serves that one user's world. That model is preserved.

This spec adds a second deployment mode: **hosted service**. The same `wires-host` binary, with the same blind-host contract, runs as a single process that may serve **many** users' worlds. A fresh iOS app discovers the service's `EndpointId` via an HTTPS endpoint, proves possession of a freshly minted root key by signing a registration challenge, and the host commits to serving that root pubkey's `__caps` topic plus any topics the root later registers.

Nothing in the wire format changes. The host's blindness contract is unchanged: it sees `topic_id`, `epoch`, `kind`, `recipient` (for `SealedTo`), `sender`, `cap_id`, `seq`, `timestamp`, and ciphertext length, and the cleartext content of `Public` messages on `__caps`. It learns one additional metadata fact per tenant: the tenant's root pubkey, plus the topic_ids that root has registered for service. The root pubkey is already cleartext in every `__cap.grant` envelope's `sender` field, so this is not new leakage — only an explicit binding the host already could have inferred from traffic.

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
| `wires-store` | No changes. (The `TopicLogs` struct is reused per-tenant.) |
| `wires-net` | New `tenant` module: `TenantProtocol` (server-side ALPN handler), `TenantClient` (client-side dialer), request/response types. New invite-token format `v2`, with v1-compat decode. |
| `wires-node` | Join flow gains an iterating peer-hint loop that consumes `InviteToken::peer_hints` in order and optionally falls back to `service_discovery_url` (§6). Existing publish/subscribe surface is unchanged. |
| `wires-host` | New `tenant_registry` module: tenant table, topic→tenant index, per-tenant storage. New `http_discovery` module: tiny axum service. Main rewritten to wire all this together and to remove `--topic` flags (topics are registered dynamically now). |
| `wires-cli` | Updated to decode invite token v2; otherwise unchanged. |
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
5. Otherwise: insert `Tenant { root_pubkey, registered_at: server_time, status: Active, quota: default_quota }` into `tenants.redb`. Derive `__caps_topic_id = BLAKE3("wires.caps.v1" || root_pubkey)`. Insert `(__caps_topic_id → root_pubkey)` into `topic_index.redb`. Spawn the gossip subscription for `__caps_topic_id`. Return `ok: true`.

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
    pub message_count_24h: u64,
    pub bytes_24h: u64,
    pub quota_messages_per_hour: u32,
    pub quota_bytes_per_hour: u64,
    pub status: TenantStatusKind,    // Active | Suspended | RateLimited
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
    QuotaExceeded,
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
3. Look up `tenant = tenants[root_pubkey]`. `Suspended` → drop. Already `RateLimited` for this hour → drop.
4. Run `verify_envelope(&msg)` — unchanged signature check.
5. Increment per-tenant and per-(tenant, sender) counters, check quotas. Over quota → drop and mark tenant `RateLimited` for the remainder of the rolling hour.
6. Append to the per-tenant per-topic log.

This is a thin layer over the existing flow — about 50 lines of additional routing logic plus the tenant_registry module.

### Replay protocol

The existing `/wires/replay/0` ALPN gains tenant-awareness:

1. Decode `ReplayRequest`, extract `topic_id`.
2. Look up `topic_index[topic_id]`. Absent → reply with empty stream or `NotFound`.
3. Open per-tenant `TopicLogs` for the resolved root_pubkey.
4. Stream as before.

No ACL checks on replay beyond the existing "host serves anyone who asks" model — the receiver still verifies caps and decrypts on its end. Adding cap-level enforcement at the host would require breaking blindness; we don't.

### Quotas (v1, single tier)

Hardcoded defaults:
- 50 000 messages/hour per tenant.
- 100 MiB/hour per tenant.
- 5 000 messages/hour per (tenant, sender) pair.

Stored in-memory with a 1-hour rolling window (simple bucket + epoch). Persisted snapshots every 5 minutes so quotas survive a process restart. Counters reset to zero after `Suspended` → `Active` transitions (manual admin action, no v1 UI).

---

## 6. Invite token v2

The current `InviteToken` (in `wires-net/src/invite.rs`) carries a single peer hint. v2 carries multiple.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteToken {
    pub version: u8,                       // 2
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

`InviteToken::decode` first parses the JSON, inspects `version`:
- `1`: lift the single `peer_node_id`/`peer_addrs`/`peer_relay` into a one-element `peer_hints` vec; set `service_discovery_url: None`.
- `2`: parse directly.
- other: error.

`InviteToken::encode` always writes v2.

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

For self-hosted operators, this URL is optional — the iOS app's existing `HostPairToken` QR flow stays valid and bypasses HTTPS discovery entirely. The two modes are selected at first-launch ("hosted service" vs "self-hosted") and recorded on the iOS-side `Household` record.

---

## 8. iOS app changes

The iOS spec already implements `Household` and the QR-scan `HostPairToken` flow. This spec adds a hosted-service pairing mode alongside it.

### 8.1 First-launch wizard changes

A new step inserted before "Pair with host":

> **Where is your wires backend?**
> ◦ Use the hosted Wires service (recommended)
> ◦ I'm running my own wires-host

"Hosted service" path:
1. iOS app fetches `https://discovery.wires.example/v1/bootstrap` (URL is build-time configurable; default points at the public hosted service).
2. Picks `endpoints[0]`. Constructs a `HostInfo { hostNodeIdHex, hostRelayURL, hostDirectAddrs }` from it.
3. Calls into Rust: `WiresApp.bootstrap(agentIdentity, rootSigner)` then `WiresApp.registerWithHostedService(hostInfo, discoveryUrl)`.
   - This dials the host on `/wires/tenant/0`, sends `TenantRegisterRequest` signed by the root key (biometric prompt to access the Secure Enclave).
   - On success, populates `Household.hostNodeIdHex`, `Household.discoveryUrl`, `Household.mode = .hostedService`.
4. Continues with the existing "mint iOS agent self-cap" flow.

"Self-hosted" path: existing flow (QR scan from `wires-host show-pair-qr`).

### 8.2 FFI additions

In `wires-uniffi`:

```rust
impl WiresApp {
    pub async fn register_with_hosted_service(
        &self,
        host: HostInfo,
        discovery_url: Option<String>,
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
    var mode: HouseholdMode               // .selfHosted | .hostedService
    var discoveryUrl: String?             // nil for self-hosted
}
```

Migration for existing data: any pre-existing `Household` records (none in production yet) get `mode = .selfHosted`, `discoveryUrl = nil`.

---

## 9. Backward compatibility

The self-hosted single-tenant deployment continues to work, with one operational change: `wires-host` no longer takes `--topic <hex>` flags. Topics must now be registered via the tenant control protocol. To preserve the self-hosted UX:

- `wires-host show-pair-qr` is unchanged in payload: the QR carries `host_node_id`, `host_addrs`, `host_relay` exactly as the existing iOS spec defines.
- The iOS app, after scanning, runs the same `register_with_hosted_service` flow against the scanned `EndpointId`. The host has no special-case code for self-hosted vs. hosted; both paths funnel through `TenantProtocol`. The only difference between the two pairing modes on the iOS side is where the host endpoint hints came from (HTTPS discovery vs. QR scan).

This means `wires-host` is now always multi-tenant — even in the self-hosted single-user case, the user's root pubkey is one tenant on a host that *could* hold many. The operational footprint difference between self-hosted and hosted is purely deployment (where the binary runs, who pays for the box, what discovery URL the iOS app uses).

---

## 10. Error handling

Snafu pattern per `CLAUDE.md`. New error variants live in:

- `wires-net::error::NetError`: `TenantRegisterFailed { source, location }`, `TopicRegisterFailed { source, location }`, `TenantStreamClosed { location }`, `TenantBadResponse { source, location }`. Each with `Location`, message ending in `, at {location}`.
- `wires-host::error::HostError`: `TenantTableOpen { source, location }`, `TopicIndexOpen { source, location }`, `NonceTableOpen { source, location }`, `TenantSignatureInvalid { location }`, `TenantSuspended { root_hex, location }`, `QuotaExceeded { root_hex, location }`.
- iOS `wires-uniffi::error::WiresError`: `RegisterHostedService { source, location }`, `RegisterTopic { source, location }`, `DiscoveryFetchFailed { source, location }`.

---

## 11. Testing

Following the substrate spec's testing strategy: real iroh transports (in-memory variant where possible), real redb, no mocks at integration level.

### Unit
- `wires-net::tenant`: signature round-trip for each request type, replay-nonce rejection, response decode, malformed-frame handling.
- `wires-host::tenant_registry`: tenant create/load roundtrip, idempotent re-register, topic register idempotent, topic→tenant lookup, quota bucket logic, persistence across restart.

### Integration (`crates/wires-host/tests/` or `crates/wires-node/tests/`)
- **Single tenant happy path**: spin up a host, dial via `TenantClient`, register tenant, register topic, publish on that topic from a separate agent, confirm host appends to the right per-tenant log.
- **Two tenants isolated**: same host, two iOS-stand-ins each register, each registers their own topic, each publishes. Dump `data_dir/tenants/<a>/` and `<b>/` and verify no cross-contamination.
- **Quota exceeded**: agent publishes 50 001 messages in an hour, 50 001st is dropped, `tenant_status` reflects `RateLimited`.
- **Bad signature rejection**: `TenantRegisterRequest` with wrong signature → `Error(BadSignature)`.
- **Replay rejection**: same nonce within TTL → `Error(ReplayedNonce)`.
- **Unknown topic dropped**: publish on a topic the tenant never registered, confirm host drops and does not panic.
- **Self-hosted compat**: `wires-host show-pair-qr` → iOS scans → register flow succeeds → invite token v2 round-trip end-to-end.

### Acceptance (`crates/wires-host/tests/acceptance.rs`, marked `#[ignore]`)
1. Two fresh `wires` CLI clients (representing two iOS apps' agent identities) on the same host process register two distinct tenants. Each registers `home.test`. Each publishes. Each can only read their own messages (host enforces topic→tenant routing; cross-tenant traffic is dropped at the host).
2. A `wires-host` process is restarted with its data dir intact. Both tenants reconnect, no re-registration required (idempotent), historical messages still served via replay.
3. Invite token v2 with multiple peer hints: agent tries the first hint (unreachable), falls back to the second (reachable), bootstraps successfully.
4. Service discovery: agent fetches `https://localhost:8443/v1/bootstrap` from the same `wires-host` process, parses the endpoint list, dials, registers.

---

## 12. Acceptance criteria

For this spec to be considered done:

1. `wires-host` runs without `--topic` flags. Topics are registered dynamically through `/wires/tenant/0`.
2. A fresh iOS app can complete the full onboarding flow against a hosted `wires-host`: discovery fetch → tenant register → topic register → mint self-cap → publish a message → replay it.
3. Two iOS apps with distinct root pubkeys can coexist on the same host process with no cross-tenant content leakage (verified by inspecting `data_dir/tenants/`).
4. Existing self-hosted users (using `wires-host show-pair-qr`) experience the same UX they would have under the substrate+iOS specs — just routed through the new tenant protocol under the hood.
5. Invite token v2 is correctly decoded by `wires-cli`, with v1 round-trip preserved.
6. Quotas fire as documented, surfaced via `tenant_status`.
7. All new error variants follow the snafu/location convention from `CLAUDE.md`.
8. Acceptance test suite (§11) passes.

---

## 13. Out of scope (each gets its own spec)

- **Topic→host sharding and multi-host HA.** Multiple host processes serving different tenant subsets, with a routing layer (consistent hash on root_pubkey, redirect protocol, or shared control plane).
- **Cross-host replication.** Hot-standby hosts so a tenant survives a single host process death.
- **iOS root-key custody and recovery.** iCloud Keychain sync, passphrase-wrapped backup, social recovery via Shamir, multi-device root.
- **Operator backup/restore.** Snapshot pipeline for per-tenant redb files, point-in-time recovery, cross-region async replication.
- **Billing and quota UI.** Per-tenant tier configuration, payment integration, admin dashboard.
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

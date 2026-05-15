# wires — iroh-native host-ticket discovery

**Status:** design, 2026-05-15. Replaces the HTTPS `/v1/bootstrap` surface defined in the hosted-service spec §7 with an iroh-native QR/paste artifact. Drops `PairGrant.HostInfo.service_discovery_url` from the responder-driven-pairing spec §4 — the field's job (recover from stale `peer_hints`) is already covered by iroh's pkarr/DNS + mDNS resolution layer, so nothing replaces it.

## 1. Motivation

Today's cold-start path for a hosted client is HTTPS:

1. Operator (or future iOS app) is told an HTTPS URL — `https://<host>/v1/bootstrap`.
2. They `GET` it via reqwest.
3. The response is a JSON `DiscoveryResponse` carrying one `DiscoveryEndpoint { endpoint_id, addrs, relay }`.
4. The client extracts `endpoint_id` and dials over iroh.

This works, but it has costs that scale poorly with the project's mission ("E2E gossip substrate for a household's AI agents"):

- **Operational complexity for self-hosting.** A household running a single `wires-host` binary needs a second internet-reachable HTTPS endpoint with a valid TLS certificate just so the iOS app and CLI can learn the host's `EndpointId`. Pure ceremony — the actual relay traffic rides iroh.
- **Mixed transport story.** Everything else in the system is iroh. The bootstrap path is the only HTTPS surface; it pulls in `axum`, `reqwest`, and TLS plumbing for a one-shot key lookup.
- **Doesn't match the actual UX target.** The iOS companion spec §3.1 has the operator paste a discovery URL into a text field on first launch. A QR code scan is what users expect from "join my home server" flows; nothing about HTTPS makes that simpler.
- **Wrong abstraction for what we actually need.** The HTTPS response carries one load-bearing field (`endpoint_id`) plus best-effort hints (`addrs`, `relay`). iroh's pkarr/DNS and the freshly-landed mDNS feature already resolve socket addresses given an `EndpointId`. The discovery service is an awkward layer over a primitive iroh resolution can do natively.

This spec introduces a **`HostTicket`**: a small, self-contained, base64-encoded JSON artifact (QR-shaped) that carries an `EndpointId` plus optional reachability hints. The operator distributes it however they like — QR scan, paste, email, AirDrop. The HTTPS bootstrap surface and the `reqwest` dependency are deleted.

## 2. Scope of change

**Added:**

- `wires-net::ticket` — new module, peer of `pair.rs`. Defines `HostTicket`, encode/decode, terminal-QR rendering.
- `qrcode = "0.14"` dependency in `wires-net`, used by `HostTicket::render_qr_ansi` and (as a bonus) the existing `wires pair-listen --qr` flag.
- `wires-host ticket` CLI subcommand to print the host's ticket on demand.
- Startup-time ticket emission in the `wires-host` binary: base64 to logs, QR to stderr when stderr is a TTY.
- `--no-qr` and `--qr` flags on `wires-host` and `wires-host ticket` to override TTY autodetection.

**Changed:**

- `wires-cli`: `wires host pair --discovery-url <URL>` → `wires host pair --ticket <STRING>` (also accepts `@path` to read from a file). Same swap on `host topic-register`, `host topic-unregister`, `host status`.
- `wires pair-listen --qr` becomes a real renderer (currently it prints a hint telling the user to pipe to `qrencode`). Same `qrcode 0.14` dep handles both.

**Deleted:**

- `wires-net::discovery` module (`fetch_endpoints`, `DiscoveryEndpoint`, `DiscoveryResponse` types).
- `wires-host::http_discovery` module.
- `axum` boot in `wires-host/src/main.rs` (the discovery axum task and its config plumbing).
- `reqwest` dependency from `wires-net`.
- `axum` dependency from `wires-host` (was only used for the discovery surface).
- `pair::HostInfo.service_discovery_url` field (see §6 for the rationale).
- `peer_hint::first_reachable_with_discovery` (and its test fixture). The remaining `peer_hint::first_reachable` is sufficient — see §7.
- `wires-node::config::HostConfig.discovery_url` field. No replacement.
- Integration tests that stand up an axum harness for discovery — see §10 for rewrites.

**Unchanged:**

- Wire formats: `WireMessage`, AEAD modes, capability surface, replay protocol, tenant control protocol, pairing protocol. The ticket is an out-of-band coordination artifact; nothing on the wire knows it exists.
- iroh n0/pkarr/DNS and mDNS resolution paths (from the mDNS-discovery spec). Resolution stays inside iroh; the ticket only supplies the input.
- Crate layering. `wires-net::ticket` lives in the same layer as `wires-net::pair` and depends on nothing above it.
- Trust model. Host trust remains "availability-only" — a hostile host can refuse to relay but cannot decrypt, mint caps, or impersonate the root. Cap-based authorization is the security boundary, just as today.

## 3. `HostTicket` — wire format

```rust
// crates/wires-net/src/ticket.rs

pub const TICKET_VERSION: u8 = 1;
pub const MAX_TICKET_BYTES: usize = 1024;
pub const MAX_HINT_ADDRS: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostTicket {
    pub version: u8,
    /// Hex iroh EndpointId (matches PairDial / PeerHint convention).
    pub endpoint_id: String,
    pub addrs: Vec<String>,
    pub relay: Option<String>,
    /// Unix ms after which addrs/relay are treated as zero-weight hints by the
    /// consumer (iroh pkarr/DNS still resolves). `endpoint_id` never expires.
    pub hint_expires_at: i64,
}
```

**Encoding.** URL-safe base64 (no pad) of canonical JSON, same envelope shape as `PairRequest`. Decode rejects:

- `version != 1` (`TicketUnsupportedVersion`)
- encoded length > `MAX_TICKET_BYTES * 2` after URL-safe base64 expansion (`TicketBounds`)
- `endpoint_id` not 64 hex chars or not decoding to a valid `EndpointId` (`TicketInvalidEndpointId`)
- `addrs.len() > MAX_HINT_ADDRS` (`TicketBounds`)
- `serde_json` parse failure (`TicketParse`)
- base64 decode failure (`TicketDecode`)

**Trust.** Unsigned. The host has no `root` key (by design — that's the operator's), and host identity is not trust-bearing in the wires threat model. A malicious actor substituting a `HostTicket` mid-flight can point a victim's client at a hostile host; that host learns the same `root_pubkey` and `topic_id`s any honest host would learn (both already cleartext in `__cap.grant` envelopes), cannot decrypt sealed or AEAD'd payloads, cannot mint caps, and cannot serve forged replay because the receiver verifies signatures. The worst outcome is denial-of-service, which a network-level adversary can already do. Future versions may add a host-operator signature — that's a `version: 2` change with a bumped enum.

**`hint_expires_at` semantics.** Informational, not enforced. A ticket whose hint-expiry is past `now` decodes successfully and exposes its full `endpoint_id`; only the `addrs` and `relay` fields are downgraded to zero-weight by the consumer. iroh's pkarr/DNS plus mDNS resolve the rest. v1 default `--hint-ttl` for `wires-host ticket` is `7d`; this is purely a soft signal that a freshly-printed ticket is more useful than a year-old one.

**Helpers.**

```rust
impl HostTicket {
    pub fn from_endpoint(
        endpoint: &iroh::Endpoint,
        hint_ttl: std::time::Duration,
    ) -> Result<Self, NetError>;

    pub fn encode(&self) -> Result<String, NetError>;
    pub fn decode(s: &str) -> Result<Self, NetError>;

    /// `HostTicket` → `PeerHint`. Adapter used by the CLI when dispatching
    /// `wires host …` subcommands: the `--ticket` value is decoded into a
    /// `HostTicket`, converted to a `PeerHint`, and handed to
    /// `peer_hint::first_reachable`.
    pub fn to_peer_hint(&self) -> crate::peer_hint::PeerHint;

    /// Render the encoded ticket as an ANSI-art QR code. Returns a string the
    /// caller writes wherever it likes (typically stderr).
    pub fn render_qr_ansi(&self) -> Result<String, NetError>;
}
```

`from_endpoint` pulls the live `EndpointAddr` off the iroh endpoint (`endpoint.id()`, `endpoint.bound_sockets()`, `endpoint.home_relay()` — exact API per iroh 0.98 surface) and constructs a ticket with `hint_expires_at = now_ms + hint_ttl.as_millis()`.

`render_qr_ansi` calls `self.encode()` internally, then `qrcode::QrCode::new(s)?.render::<unicode::Dense1x2>()…`. v1 uses default error correction (`Medium`); the base64 ticket fits within Version-40-M capacity (~2,331 bytes) with our `MAX_TICKET_BYTES = 1024` ceiling.

## 4. Host surface — `wires-host` binary

### 4.1 Default `wires-host` (run the host)

**Startup behavior (new):** after binding the endpoint and registering ALPNs, before entering the gossip event loop:

1. Build a `HostTicket` via `HostTicket::from_endpoint(&endpoint, hint_ttl)`. `hint_ttl` comes from a new `--ticket-hint-ttl <duration>` flag (default `7d`).
2. `tracing::info!("host ticket: {}", ticket.encode()?)`. Always.
3. If `std::io::stderr().is_terminal()` and `--no-qr` is not set, additionally render `ticket.render_qr_ansi()?` and write it to stderr followed by a blank line. If `--qr` is explicitly set, render regardless of TTY status.

Existing `wires-host` flags are preserved. New flags:

- `--ticket-hint-ttl <duration>` (default `7d`)
- `--qr` (force QR even on non-TTY stderr)
- `--no-qr` (suppress QR even on TTY stderr)

`--qr` and `--no-qr` are mutually exclusive; clap-level validation rejects both.

### 4.2 `wires-host ticket` subcommand

```
wires-host ticket [--qr | --no-qr] [--hint-ttl <duration>]
```

Identical ticket construction as §4.1. Always prints the base64 encoding to **stdout** (pipe-friendly: `wires-host ticket | qrencode -t ansi` keeps working in operator scripts even though it's now redundant). Prints the QR to stderr per the same TTY rule.

This subcommand intentionally re-derives the ticket each invocation rather than reading a cached file. Hints reflect the host's *current* `EndpointAddr`. The persistent identity (`endpoint_id`) is invariant across invocations because `iroh.secret` is persisted.

### 4.3 Cargo plumbing

`crates/wires-host/Cargo.toml`:

- Remove `axum = "0.8"` (was only used by `http_discovery`).
- Remove `tower` (if it was pulled solely for `http_discovery`; check at impl time and remove if so).
- Add `is-terminal = "0.4"` if `std::io::IsTerminal` isn't usable on the project's MSRV. Workspace is on stable 1.95 per CLAUDE.md, so `std::io::IsTerminal` (stabilized in 1.70) is available — no new dep needed.

`crates/wires-net/Cargo.toml`:

- Remove `reqwest`.
- Add `qrcode = "0.14"` with `default-features = false` to drop the `image` feature; we only need the terminal renderer.

## 5. CLI surface — `wires-cli`

**Replaced flags.** Every `wires host …` subcommand that took `--discovery-url <URL>` now takes `--ticket <STRING>`:

```
wires host pair             --ticket <STRING>
wires host topic-register   <name>  --ticket <STRING>
wires host topic-unregister <name>  --ticket <STRING>
wires host status                   --ticket <STRING>
```

`<STRING>` is the raw URL-safe base64 ticket, or `@<path>` to read it from a file. The `@<path>` convention is implemented in a custom clap value parser (not native clap behavior); the parser strips a leading `@`, reads the named file via `std::fs::read_to_string`, trims whitespace, and decodes the result. The same parser validates raw tokens via `HostTicket::decode`. Failures surface as a clear CLI error before any iroh call.

The ticket is consumed in-process only — there is no on-disk cache and `wires pair-approve` gains no new flag. The operator's `wires host pair` flow already persists the host's `EndpointId` into the operator-side config (it's how `pair-approve` already populates `PairGrant.HostInfo.peer_hints`); the ticket itself doesn't need to survive past the command that used it.

**Removed flags.** `--discovery-url` on all four `host` subcommands. No shim; no deprecation period. Prototype rules per CLAUDE.md.

**`wires pair-listen --qr` rewrite.** Today the flag prints `"(--qr requested; pipe the token to qrencode -t ANSI256UTF8 -o-)"`. After this change it calls `request.render_qr_ansi()` (a sibling method on `PairRequest`, sharing the `qrcode` dep) and prints inline.

## 6. `PairGrant.HostInfo` change

```rust
// crates/wires-net/src/pair/grant.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub peer_hints: Vec<PeerHint>,
}
```

The `service_discovery_url: Option<String>` field is deleted with no replacement. The field's job in the v1 design was "give Bob a fallback when his cached `peer_hints` go stale" — a real concern in the HTTPS world, because the discovery URL was a *live indirection* (URL → current addrs). A ticket would not be a live indirection; it would be another static snapshot, identical in structure to the `peer_hints` snapshot already in `HostInfo`. Two snapshots of the same data add complexity without adding recovery capability.

Liveness is already provided by iroh: given an `EndpointId` (always present in `peer_hints[0]`), iroh's pkarr/DNS resolves the host's *current* socket addresses. The mDNS lookup (default-on per the mDNS-discovery spec) does the same on-LAN. If every entry in `peer_hints` becomes unreachable, iroh's resolution layer transparently re-resolves the same `EndpointId` to a fresh `EndpointAddr`. No application-layer fallback is needed.

No `version`-bump on `PairGrant` itself. The responder-driven-pairing spec was newly landed and has no shipped consumers outside the wires repo; mid-flight `PairGrant`s do not survive process restart (`pair_pending.json` is a Bob-side artifact); the substrate spec's `version` discipline is reserved for envelope structure, not for HostInfo content shifts.

## 7. `peer_hint` — bootstrap iteration

The `peer_hint::first_reachable_with_discovery` helper is deleted along with the HTTPS surface. `peer_hint::first_reachable` (already present, unchanged) is the only iteration helper; it iterates `peer_hints` in order, dials each, returns the first that succeeds, and returns `None` on exhaustion. Re-resolution of stale addresses happens inside iroh, transparently to this layer.

Consumers:

- `wires-node::pair::install_grant` — drop the `service_discovery_url` argument; call `first_reachable` instead of `first_reachable_with_discovery`.
- `wires-node::config::HostConfig` — `discovery_url: Option<String>` field is deleted with no replacement.

## 8. Error handling

All new variants live in `wires-net::error::NetError`. Snafu pattern per CLAUDE.md (`#[snafu(implicit)] location: Location`, no `message` field, display ends with `, at {location}`, external errors as `source` on leaf variants).

**Added:**

```rust
#[snafu(display("ticket base64 decode failed: {source}, at {location}"))]
TicketDecode {
    source: base64::DecodeError,
    #[snafu(implicit)] location: Location,
},

#[snafu(display("ticket JSON parse failed: {source}, at {location}"))]
TicketParse {
    source: serde_json::Error,
    #[snafu(implicit)] location: Location,
},

#[snafu(display("ticket field {what} exceeded limit {limit}, at {location}"))]
TicketBounds {
    what: &'static str,
    limit: usize,
    #[snafu(implicit)] location: Location,
},

#[snafu(display("ticket version {version} unsupported, at {location}"))]
TicketUnsupportedVersion {
    version: u8,
    #[snafu(implicit)] location: Location,
},

#[snafu(display("ticket endpoint_id was not valid 32-byte hex, at {location}"))]
TicketInvalidEndpointId {
    #[snafu(implicit)] location: Location,
},

#[snafu(display("QR rendering failed: {source}, at {location}"))]
TicketQrRender {
    source: qrcode::types::QrError,
    #[snafu(implicit)] location: Location,
},
```

**Removed:** `DiscoveryFetch { source: reqwest::Error, location }` (and its snafu context selector).

**iOS-side (`wires-uniffi`, not implemented yet but specified for the iOS revival):** `WiresError::InvalidHostTicket { reason }` replaces `WiresError::DiscoveryFetchFailed`. The first-launch wizard's "Step 1" screen swaps from a text-field for an HTTPS URL to a QR scanner that decodes a base64 ticket; everything downstream is the same.

## 9. Trust and threat model

mDNS-discovery spec §6 already documents that the wires threat model treats `EndpointId`s as public. The ticket carries one `EndpointId` plus reachability hints already broadcast on every iroh handshake. Specifically:

- **Host blindness:** unchanged. The host still sees only `topic_id`, `kind`, ciphertext length, and `sender`; the ticket changes none of that.
- **Per-publisher hash chain:** unchanged; storage-layer property.
- **AEAD / sealed-box:** unchanged; ticket does not touch payloads.
- **Capability mint/revoke:** unchanged; caps travel inside `PairGrant` sealed payloads, never inside a ticket.
- **Pair-grant flow:** unchanged. The ticket is on the *operator-to-host* axis; pairing is on the *operator-to-agent* axis. They never share state.

**Threat: hostile ticket substitution.** A man-in-the-middle who substitutes a ticket convinces a client to register with a host they control. That host:

- Learns the victim's `root_pubkey` (already cleartext in every `__cap.grant` envelope).
- Learns the victim's registered `topic_id`s (already cleartext in tenant control plane, and inferrable from gossip traffic anyway).
- Cannot decrypt sealed-to or AEAD payloads (no caps, no epoch keys).
- Cannot mint caps (no root key).
- Cannot forge replay (signatures verified by receivers).
- Can refuse to relay traffic (denial-of-service equivalent to any other network-level adversary).

The mitigation is the same as the rest of the system: cap-based authorization on the receiver. Future signed-ticket support (v2) is straightforward but unnecessary at v1's threat budget.

**Threat: ticket replay across networks.** A ticket whose `addrs` have gone stale still resolves correctly via iroh pkarr/DNS as long as the host's `EndpointId` remains valid. `hint_expires_at` is informational; the consumer never *rejects* a ticket based on it.

## 10. Testing

Following the substrate spec's testing strategy: real iroh transports, real redb, no mocks at integration level.

### Unit (`crates/wires-net/src/ticket.rs`)

- Encode/decode round-trip.
- `version != 1` rejected.
- Oversize JSON (> `MAX_TICKET_BYTES`) rejected with `TicketBounds`.
- `addrs.len() > MAX_HINT_ADDRS` rejected with `TicketBounds`.
- `endpoint_id` not 64 hex chars: rejected with `TicketInvalidEndpointId`.
- `endpoint_id` 64 hex but doesn't decode to a valid `EndpointId`: rejected with `TicketInvalidEndpointId`.
- `from_endpoint` round-trip: build, encode, decode, assert `endpoint_id == hex(endpoint.id().as_bytes())`.
- `hint_expires_at` past `now`: ticket still decodes; `to_peer_hint()` returns full hint (consumer policy not encoded here).
- `render_qr_ansi` returns a non-empty string for a valid ticket.
- `render_qr_ansi` failure mode: if `MAX_TICKET_BYTES` were ever raised past QR-Version-40-M capacity, the underlying call returns `QrError::DataTooLong` and we surface `TicketQrRender`. Asserted via a property test that constructs a ticket near the bound.

### Unit (`crates/wires-net/src/peer_hint.rs`)

The existing `first_reachable_falls_back_to_discovery_url` test is **deleted** along with the helper it covered. `first_reachable` already has coverage via existing peer-hint tests; no new cases are needed here.

### Integration (`crates/wires-host/tests/`)

- `wires-host ticket` subcommand: spawn the binary with `--no-qr`, capture stdout, decode the printed ticket, assert `endpoint_id` matches the host's bound endpoint and that `addrs` is non-empty for a host bound to a real interface.
- Acceptance test `end_to_end_register_via_http_discovery` is renamed to `end_to_end_register_via_host_ticket` and rewritten: spawn `wires-host` with `--no-qr`, parse the ticket out of its INFO log line, hand it to `wires host pair --ticket <captured>`, assert tenant register succeeds.

### Integration (`crates/wires-cli/tests/`)

- `cli_host_pair.rs` and `cli_host_topic_register.rs` lose `wires_host::http_discovery::DiscoveryState` and the axum harness. Both gain `spawn_test_host_and_capture_ticket()`, a small helper that builds a `Host` library-side, binds an endpoint, constructs a ticket via `HostTicket::from_endpoint`, and returns it for the test body. Net deletion of test scaffolding is substantial.

### Acceptance (`#[ignore]`)

1. End-to-end Tab 1/Tab 2/Tab 3 walkthrough from the responder-driven-pairing spec §8 README, with the operator-side bootstrap going through `wires-host ticket` instead of the deleted `--discovery-url`. The pair flow proceeds as before; assert that the new agent receives a `PairGrant` containing the host's `EndpointId` in `HostInfo.peer_hints` and can dial it.

## 11. Acceptance criteria

For this spec to be considered done:

1. `wires-host` runs without `axum` or HTTPS surface; `/v1/bootstrap` is gone. Startup logs include a `host ticket: <base64>` line; TTY runs additionally print a QR to stderr.
2. `wires-host ticket [--qr | --no-qr] [--hint-ttl <duration>]` prints a valid base64 ticket to stdout and (per TTY rule) a QR to stderr.
3. `wires host pair --ticket <STRING>` registers a tenant successfully against a real host; `--discovery-url` is removed from every CLI subcommand.
4. `wires pair-listen --qr` renders a real terminal QR inline.
5. `PairGrant.HostInfo` is `{ peer_hints }` only; `service_discovery_url` is gone from the type, `pair_pending.json`, and every consumer; `peer_hint::first_reachable_with_discovery` is deleted; `HostConfig.discovery_url` is deleted.
6. `reqwest` and `axum` are no longer declared by `wires-net` or `wires-host`. `qrcode = "0.14"` is the only new dep.
7. All new error variants follow CLAUDE.md's snafu convention.
8. Existing acceptance suite (with `end_to_end_register_via_host_ticket` substituted) passes.

## 12. Out of scope

- **Signed tickets (host-operator attestation).** A `version: 2` ticket carrying an ed25519 signature by a long-term host-operator key, with verification on the consumer side. Useful when host trust grows beyond "availability-only" (e.g. host-side privacy properties become load-bearing). Not needed at the prototype's threat budget.
- **Multi-endpoint tickets (sharding).** A future ticket version could carry an ordered list of `endpoint_id`s for tenant-sharded hosted-service deployments. Out of scope here; lives with sub-project B of the hosted-service spec.
- **Universal-link / `wires://` URL scheme.** The iOS spec will eventually want a tappable link in addition to a QR. v1 sticks with QR + paste; the URL-scheme handler is a thin layer over `HostTicket::decode` that an iOS implementation can add later.
- **Discovery for the pair channel.** The responder-driven-pairing spec §10 already opts out of HTTPS discovery for `PairRequest` (the QR carries `dial.node_id` + iroh N0). Nothing to change there.
- **Ticket revocation.** A `HostTicket` is a hint, not a grant. If the operator wants to disinvite a previously-given ticket-holder, they suspend the tenant on the host side — same mechanism as today (`tenants.redb` `Status::Suspended`).
- **iOS QR rendering.** iOS will render its own QR via `CoreImage.CIFilter.qrCodeGenerator`. The Rust `qrcode` crate is for terminal-side use only.
- **De-anyhow'ing existing `NetError` variants.** Five variants in `wires-net::error` (`Endpoint`, `GossipSubscribe`, `GossipPublish`, `ReplayRpc`, `TenantRegister`) still wrap `Box<anyhow::Error>`. Pre-existing — flagged in the mDNS spec §10 and unchanged here.

## 13. CLAUDE.md updates required

Two short edits, made as part of the implementation plan:

1. Under "Crate layout" — `wires-net` row updated to mention `ticket.rs` and to drop `discovery.rs`. `wires-host` row updated to drop `http_discovery`.
2. Under "Authoritative docs" — add a line for this spec.

The "HTTPS service discovery at `/v1/bootstrap`" mention under "Hosted service v1" status is rewritten to "host-ticket discovery (base64 + QR)".

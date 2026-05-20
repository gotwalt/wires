# wires — Notes for future Claude sessions

End-to-end encrypted gossip substrate for a household's AI agents. Rust workspace, iroh-powered, blind hosting, capability-gated.

## Status

Prototype. Three slices have landed on `main`:

- **Substrate v1** (merge `fefbbfc`) — identity, topic creation, capability mint/revoke, publish with AEAD, gossip + replay between peers, decrypt on receive, persisted hash-chained logs. Drives the CLI end-to-end.
- **Hosted service v1** (merge `3da4ec8`) — `wires-host` is multi-tenant: tenant registration over a `/wires/tenant/0` ALPN, per-tenant rolling retention with FIFO eviction, topic→tenant routing, write-rate ceiling, host-ticket discovery (base64 + terminal QR; `wires-host ticket` and startup-time emission). The host became a `lib + bin` crate.
- **Responder-driven pairing v1** — agents declare a role + requested scopes via `wires pair-listen`; the operator consents and dials in via `wires pair-approve` over the new `/wires/pair/0` ALPN with a sealed, signed `PairGrant` carrying root pubkey, root-signed cap, per-topic epoch keys, and host info. Replaces the deleted `InviteToken` / `wires invite` / `wires join` surface. Spec: `docs/superpowers/specs/2026-05-15-wires-responder-driven-pairing-design.md`.
- **MCP gateway v1** — `wires-mcp` is a multi-tenant authenticated MCP gateway. It joins each household as a normal wires agent via the responder pair flow, exposes OAuth 2.1 (PRM + AS + DCR) with the household root pubkey as `sub` and iOS as the universal authenticator. MCP tools: `wires_list_topics`, `wires_publish`, `wires_tail` (renamed from dotted names; Claude's MCP client validates `^[a-zA-Z0-9_-]{1,64}$`). Spec: `docs/superpowers/specs/2026-05-18-wires-mcp-gateway-design.md`.
- **Per-user retention v1** (landed 2026-05-19) — `wires-mcp` enforces a TTL + byte-budget eviction policy on each user's `TopicLogs`. `wires-store`'s `IngestIndex` rows now carry `ingested_at_ms`, with new `evict_older_than` / `evict_oldest_until` / backfill helpers. `wires-node` opens an `IngestIndex` when `NodeConfig.retention` is `Some(_)`, hooks record+sweep into publish and inbound, runs `reconcile_ingest_index` at open (backfill + crash-window safety net), and `NodeRuntime` spawns a 60 s `spawn_blocking` sweep loop. `GatewayConfig::retention_policy()` resolves operator TOML (`[retention] ttl_secs / max_bytes_per_user`) or defaults (1 h / 50 MiB); `TenantSupervisor::new(.., retention)` injects per-user. Spec: `docs/superpowers/specs/2026-05-18-wires-mcp-retention-design.md`.
- **MCP single-QR consent dispatch** (landed 2026-05-19) — `/oauth/authorize` now renders ONE `SessionTicket` QR; iOS POSTs `/oauth/session/probe { session_id, root_pubkey_hex }` and the gateway dispatches into the pair flow (unknown root) or sign-in flow (known root). `pair_bridge.start` is now idempotent per session so probe retries reuse the cached iroh endpoint. iOS gained `OAuthSignInFeature` for the returning-user biometric-sign path (full `ApprovalFeature` composition for the pair branch is a v1 deferral). Eliminates the dual-QR camera-framing hazard and the "do first-time twice → `AlreadyPaired`" cliff. Spec §5 updated.
- **iOS UI snapshot tooling v1** (landed 2026-05-19) — `scripts/snapshot-ios.sh` drives `WiresUITests/SnapshotSweep` to capture every notable iOS UI state as PNGs under `Wires/screenshots/<run-id>/`. 17 fixtures × light/dark on iPhone 17 Pro (iOS 26.4). Fixture mode swaps every external client via `prepareDependencies`, seeds `AppFeature.State` directly into the target screen, and renders a static `FixtureCameraPlaceholder` instead of the live `CameraCaptureView`. Spec: `docs/superpowers/specs/2026-05-19-wires-ios-snapshot-tooling-design.md`. Plan: `docs/superpowers/plans/2026-05-19-wires-ios-snapshot-tooling.md`.

A Home Assistant ingestion daemon (`wires-ha`) also exists as a working example of an agent that participates in gossip + replay.

What does **not** exist yet: iOS companion (still a stock SwiftUI scaffold — the spec/plan need revision against the post-hosted-service architecture), `__cap.*` gossip propagation, `__topic.epoch_advance` distribution. See "Out of scope" in each design spec.

## Authoritative docs

- **Substrate spec** — `docs/superpowers/specs/2026-05-14-wires-substrate-design.md`. Wire format, encryption modes, capability model, reserved message types, host blindness contract. Load-bearing.
- **Substrate plan** — `docs/superpowers/plans/2026-05-14-wires-substrate.md`. The 32-task plan that built v1; map of who-implements-what.
- **Hosted-service spec** — `docs/superpowers/specs/2026-05-14-wires-hosted-service-design.md`. Multi-tenant `wires-host`, tenant control protocol, per-tenant storage layout, HTTPS discovery surface. NOTE: the spec's §6 "InviteToken" section is **stale** — that token has been deleted in favor of the responder-driven pairing flow (see below). Treat §6 as historical.
- **Hosted-service plan** — `docs/superpowers/plans/2026-05-14-wires-hosted-service.md`. 29 tasks, fully landed.
- **Responder-driven pairing spec** — `docs/superpowers/specs/2026-05-15-wires-responder-driven-pairing-design.md`. OAuth-style flow: `PairRequest` token (signed by Bob's agent key), `/wires/pair/0` ALPN, `PairGrant` sealed to Bob's ephemeral x25519 and signed by the root, single-use nonce, crash-safe idempotent install.
- **Responder-driven pairing plan** — `docs/superpowers/plans/2026-05-15-wires-responder-driven-pairing.md`. 18 tasks, fully landed.
- **Host-ticket discovery spec** — `docs/superpowers/specs/2026-05-15-wires-iroh-host-ticket-discovery-design.md`. Replaces HTTPS `/v1/bootstrap` with a base64 `HostTicket` + terminal QR. Drops `service_discovery_url` and `HostConfig.discovery_url`.
- **Host-ticket discovery plan** — `docs/superpowers/plans/2026-05-15-wires-iroh-host-ticket-discovery.md`.
- **iOS companion spec** — `docs/superpowers/specs/2026-05-14-wires-ios-companion-design.md`. **Stale**: written before hosted-service landed; still describes the dropped `HostPairToken` QR-pair flow. Revise against the hosted-service spec's §8 (discovery + `register_with_hosted_service`) before implementing.
- **iOS companion plan** — `docs/superpowers/plans/2026-05-14-wires-ios-companion.md`. Also **stale** for the same reason. Revise after the spec.
- **MCP gateway spec** — `docs/superpowers/specs/2026-05-18-wires-mcp-gateway-design.md`. PRM, AS, DCR, the two consent paths, the MCP tool surface.
- **MCP gateway plan** — `docs/superpowers/plans/2026-05-18-wires-mcp-gateway.md`. 34 tasks, fully landed.
- **wires-mcp retention spec** — `docs/superpowers/specs/2026-05-18-wires-mcp-retention-design.md`. Approach A: extend `wires-host`'s `IngestIndex` with `ingested_at_ms` and add `evict_older_than`; gateway-only — CLI/HA opt out by leaving `NodeConfig.retention = None`.
- **wires-mcp retention plan** — `docs/superpowers/plans/2026-05-18-wires-mcp-retention.md`. 14 tasks, fully landed 2026-05-19.

## Crate layout

Strict bottom-up layering — a crate may only depend on crates above it in this list:

| Crate | Role |
|---|---|
| `wires-core` | Pure types: `WireMessage`, `MessageKind` (Standard/SealedTo/Public), `Capability`, content schema, envelope sign/verify, hash-chain link math. No I/O, no async. |
| `wires-crypto` | AEAD primitives: `standard.rs` (ChaCha20-Poly1305 with BLAKE3-derived nonces), `sealed.rs` (x25519 sealed-box), `public.rs` (plaintext-with-AAD), `keywrap.rs`. |
| `wires-store` | redb-backed persistence: per-publisher hash-chained `topic_log` (with `bytes_stored` and `delete` for eviction), `cap_table`, `epoch_keys`, and `ingest_index` for FIFO eviction across a tenant's topics. `IngestIndex` rows carry `ingested_at_ms`; methods `evict_older_than` (TTL), `evict_oldest_until` (byte budget), `iter_all_entries` and `is_backfilled` / `set_backfilled` (one-shot backfill flag). Row decode is length-tolerant — legacy 76-byte rows fall through with `ingested_at_ms = 0` so `wires-host`'s pre-retention data keeps working. |
| `wires-net` | iroh transport: `gossip.rs` wraps `iroh-gossip`; `replay.rs` is a custom QUIC protocol on `/wires/replay/0`; `tenant.rs` is the `/wires/tenant/0` control-plane (request/response types, `TenantClient`, `TenantProtocol`); `pair.rs` is the `/wires/pair/0` responder-driven pairing protocol (`PairRequest`, `PairGrantEnvelope`, `PairFrame`, `PairProtocol`, `PairClient`, `PairHandler`); `ticket.rs` is the HostTicket module for host-ticket discovery (base64 + QR serialization); `framing.rs` is the shared length-prefixed JSON helper; `peer_hint.rs` exposes join-time endpoint discovery helpers; `endpoint.rs` exposes `bind_lan` / `bind_cloud` helpers that consolidate every `Endpoint::builder(presets::N0)…bind()` call site and wire in iroh's mDNS local discovery for on-LAN binaries. |
| `wires-node` | Agent runtime. `Node::open` opens identity + storage (synchronous, no I/O on the network). `NodeRuntime` is the async wrapper: owns an iroh `Endpoint`, gossip + replay glue, per-topic gossip handles, exposes `join_topic` / `publish_and_broadcast` / `replay_from_host`. `pair.rs` houses `install_grant` (transactional pair-install), `NodePairHandler` (concrete `PairHandler`), and the `pair_listen` runtime entry. `pair_pending.rs` persists in-flight pair state. |
| `wires-cli` | `wires` binary — clap-based human/agent CLI. Speaks the tenant control protocol (`wires host pair / topic-register / topic-unregister / status`), drives responder-driven pairing (`wires pair-listen` on the agent, `wires pair-approve <token>` on the operator), and auto-dials gossip on `publish` / `cat`. `wires init` is identity-only by default; `wires init --new-root` is the operator path. `wires topic create` auto-mints a self-cap when run with a root key present. |
| `wires-host` | `lib + bin`. The binary is a multi-tenant blind relay; the library houses `tenant_registry` (tenants/topic_index/nonces), `per_tenant_logs`, `retention`, `routing`, `replay_source`, and `error`. Still has no root key, no epoch keys, no caps; only persists ciphertext after a signature check, routed by topic→tenant lookup. |
| `wires-ha` | `wires-ha` binary — Home Assistant ingestion daemon. Subscribes to a HA WebSocket, publishes `state_changed` events onto a configured topic, participates in gossip + replay like any other agent. Example of a non-CLI agent. |
| `wires-mcp` | `lib + bin`. Authenticated MCP gateway. Holds one wires-agent data dir per OAuth user (`users/<root>/`) plus a small `gateway.redb` for OAuth state. Per-user `NodeRuntime`s are managed by `TenantSupervisor`, which injects the resolved `RetentionPolicy` into every per-user `NodeConfig.retention` so each user's `Node` opens an `IngestIndex` and the `NodeRuntime` spawns a 60 s sweep loop. First-time `/authorize` runs the existing pair flow via a per-session iroh endpoint; returning `/authorize` accepts a root-signed challenge over HTTPS. Tokens are EdDSA JWTs, verified offline. |

Do not reach across layers (e.g. `wires-net` must not depend on `wires-store`).

## Conventions to follow

**Errors — snafu only.** Every variant has `#[snafu(implicit)] location: Location`, no `message: String` field, display strings end with `, at {location}`. External errors are leaves linked via `source`. Convert at boundaries with `.context(SomethingSnafu)`. The pattern is established in `crates/*/src/error.rs` — match it. (See also `~/.claude/projects/-Users-aaron-src-wires/memory/feedback_rust_errors_snafu.md`.)

**Rust edition 2024**, toolchain stable (`rust-toolchain.toml`). Tested on 1.95.0. Workspace `resolver = "3"`.

**Latest stable deps policy.** When adding a dependency, pick the latest non-pre-release version. Do **not** chase iroh 0.99 / 1.0.0-rc — they're pre-release and pull breaking changes. The stable pair is `iroh = "0.98"` + `iroh-gossip = "0.98"`. Likewise `redb = "4"` (not 5-pre), `chacha20poly1305 = "0.10"`, `ed25519-dalek = "2"`, `x25519-dalek = "2"`.

**RNG compatibility gotcha.** `ed25519-dalek` 2.x uses `rand_core` 0.6 traits. `rand` 0.10's `OsRng` does not implement them. Use `rand_core::OsRng` directly (see how `wires-cli`/`wires-node` do it).

**redb 4 API.** Reading from a `Database` requires `use redb::ReadableDatabase`. A fresh database has no tables yet, so reads that touch a non-existent table must pattern-match `TableError::TableDoesNotExist` and treat it as empty. Example: `publish::next_seq_and_prev_hash` in `wires-node`.

## Load-bearing invariants

These are easy to break by accident and break the security model when broken:

1. **AAD = canonical envelope with `signature`, `ciphertext`, `payload_len` zeroed.** This is computed by `WireMessage::signing_bytes` via the `SigningView` mirror. If you add a field to `WireMessage`, also add it to `SigningView` — the `signing_bytes_covers_every_non_signature_field` test in `wire.rs` is the safety net. AAD is used as both AEAD associated data and the signature input.

2. **Encrypt-then-sign, with AAD computed from a placeholder envelope.** The publish flow: build envelope with `ciphertext: vec![]` and `payload_len: 0`, compute `signing_bytes` → use as AAD, encrypt, set the real `ciphertext` and `payload_len`, sign over `signing_bytes` again. See `wires-node/src/publish.rs`.

3. **Host blindness.** The host enforces `verify_envelope` (signature) only. ACL checks (cap_id has rights to topic, sender owns cap, not revoked) happen on the **receiver** at decrypt time. Never add cap lookups to `wires-host`. The host has no caps and no epoch keys. Multi-tenancy did **not** soften this: the only per-tenant metadata the host learns is `(root_pubkey, registered topic_ids)`, both of which were already inferrable from on-wire traffic.

4. **Per-publisher hash chain.** Each `(topic_id, sender)` has its own chain. `TopicLog::append` is idempotent on duplicate hash but errors on fork attempts (same `seq`, different content). The log key is `32-byte sender || 8-byte BE seq`.

5. **Three `MessageKind`s, three nonce schemes.** `Standard` uses a deterministic nonce derived from `(topic_id, sender, seq)` — never reuse epoch keys across (sender, seq). `SealedTo(pubkey)` is x25519 sealed-box; the ephemeral pubkey is prepended to ciphertext. `Public` is JSON-with-AAD, no encryption. Reserved message types (prefix `__`) require specific kinds — see `wires-core/src/reserved.rs`.

6. **Topic→tenant routing is the host's only ACL.** Inbound envelopes whose `topic_id` is not in `topic_index.redb` are dropped (no panic, no log spam). Envelopes whose tenant is `Suspended` are dropped. Envelopes that would push a tenant past its retention budget are accepted, then the oldest entries (across all of that tenant's topics, ordered by host-side ingest timestamp) are evicted via `IngestIndex::evict_oldest_until`. Eviction is global within a tenant, not per-topic.

## Build and test

```bash
cargo build                         # all crates
cargo test --workspace              # ~154 unit/integration tests
cargo test --workspace -- --ignored # 8 acceptance scenarios (slower)
cargo clippy --workspace -- -D warnings
cargo fmt --all
```

**Note on cold-start flakiness:** The integration tests bring real iroh endpoints online via the N0 preset. The first run after a cold machine can take 5–30s as pkarr/DNS lookups warm up — tests defend with 10s `endpoint.online()` timeouts and `MemoryLookup` cross-registration where possible. Transient failures on the first run that pass on retry are usually iroh warm-up, not your code.

mDNS is enabled by default in all on-LAN binaries via `wires-net`'s `mdns` feature; two test peers running on the same LAN may now resolve each other through mDNS faster than the documented n0 warm-up window. The defensive timeouts and `MemoryLookup` cross-registration in tests are still correct for non-LAN CI environments and for runs that disable the feature (`--no-default-features`).

Binaries land at `target/debug/wires`, `target/debug/wires-host`, and `target/debug/wires-ha`.

## iOS UI snapshot harness

The iOS app has a fixture-driven XCUITest harness that renders every
notable UI state as a deterministic PNG without needing a live
wires-host, wires-mcp gateway, or pair partner. Drive it with
`scripts/snapshot-ios.sh`. It's the workflow we use for UI/UX review
and for catching regressions before merging iOS changes.

### Running a sweep

```bash
# Full sweep — 17 fixtures × light/dark = 34 PNGs, ~5 minutes:
./scripts/snapshot-ios.sh

# Single fixture — useful while iterating on one screen:
./scripts/snapshot-ios.sh --fixture home_one_cap

# Output:
#   Wires/screenshots/<YYYY-MM-DD-HHMM>/<flow>/<short>-<appearance>.png
#   Wires/screenshots/latest  →  symlink to most recent run
# The whole Wires/screenshots/ tree is gitignored.
```

The script boots an iPhone 17 Pro / iOS 26.4 simulator (UDID
`161DAE86-C4C7-47FE-B25E-1FAF251F93F6` on the primary dev machine,
falls back to any iPhone 17 Pro / iOS 26.x by name+runtime). It pre-grants
the camera permission so the system pre-flight dialog doesn't appear
on top of fixture screens.

**First-time setup on a fresh worktree** (one-time per developer):

```bash
# 1. Build the UniFFI Rust→Swift xcframework. Worktrees don't share it.
scripts/build-ioskit.sh

# 2. If no iPhone 17 Pro / iOS 26.4 simulator exists, create one:
xcrun simctl create "iPhone 17 Pro - 26.4" \
  "com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro" \
  "com.apple.CoreSimulator.SimRuntime.iOS-26-4"

# 3. The first xcodebuild after these steps takes 5–10 minutes (SPM
#    resolution + simulator warm-up). Subsequent runs are fast.
```

### Reading the output

`Wires/screenshots/latest/` is the entry point for UI/UX review:

- `bootstrap/` — first-run scan/confirm/done states
- `home/` — household view in empty/loading/populated states
- `enroll/` — node enrollment sheet (scan/approve/done)
- `oauth/` — wires-mcp OAuth sheet (scan/signin/pair/done/error)
- `.meta.json` — run id, commit SHA, simulator runtime, macOS version

Use Claude's `Read` tool directly on a `.png` to view the image. Each
fixture renders twice — `<short>-light.png` and `<short>-dark.png` —
so appearance regressions stand out.

To track a baseline historically, copy a curated run into
`docs/ui-baselines/<date>/` and commit those PNGs explicitly.

### Adding a new fixture

A "fixture" is one screenshot-worthy moment of the app's state. To add
one (e.g. `home_load_error`):

1. **`Wires/Wires/Fixtures/LaunchFixture.swift`** — add an enum case
   with a stable raw value (snake_case, flow-prefixed):
   ```swift
   case homeLoadError = "home_load_error"
   ```

2. Same file — add an arm to `applyDependencies(to:)` that installs the
   right per-dependency fixture clients. The flow-default arms (e.g.
   the four bootstrap arms) are good templates; adjust the
   `HouseholdClient.fixture(...)` parameters to seed the state your
   screenshot needs.

3. Same file — add an arm to `initialAppState` that returns the
   seeded `AppFeature.State` for this fixture. Construct
   `BootstrapFeature.State` / `HomeFeature.State` / etc. directly and
   wrap in the appropriate `AppFeature.State` case.

4. **`Wires/WiresUITests/SnapshotSweep.swift`** — add a `test_*`
   method that calls `try snap(rawValue, flow: "...", short: "...")`.

5. **`Wires/WiresTests/LaunchFixtureTests.swift`** — bump the
   `allCases.count` assertion to the new fixture count.

6. Run the new fixture in isolation to verify:
   ```bash
   ./scripts/snapshot-ios.sh --fixture home_load_error
   open Wires/screenshots/latest/home/load-error-light.png
   ```

### Adding a new screen or flow

If a new top-level screen lands (e.g. a Settings page reachable from
Home), expanding the harness is two layers of work:

- **Flow folder.** Pick a new prefix (e.g. `settings`) and use it in
  every new fixture's raw value (`settings_root`, `settings_about`).
  The `flowAndShortName` helper auto-derives the output directory
  from the prefix — no other plumbing.

- **Camera-touching screens.** If the screen uses `ScanView` for any
  reason, fixture-mode rendering works out of the box (the
  `cameraPreviewKind = .placeholder` default in
  `LaunchFixture.applyDependencies` covers every fixture). For
  fixtures that should display the "denied" or "not determined"
  permission states explicitly, set `values.cameraPermissionClient =
  .fixture(.denied)` in that fixture's arm.

If the screen depends on a new TCA dependency that doesn't have a
`.fixture(...)` constructor yet:

- Add a `Fixtures+<Client>.swift` file under `Wires/Wires/Fixtures/`
  that mirrors the pattern in `Fixtures+Household.swift` —
  `static func fixture(...) -> <Client>` returning a no-op or
  parameterized stub. Keep the constructor minimal (canned data, no
  I/O, no throwing).

### Common gotchas

- **`TEST_RUNNER_` env-var prefix.** `xcodebuild` only forwards
  environment variables prefixed with `TEST_RUNNER_` to the UITest
  runner process (and strips the prefix). The driver script already
  exports `TEST_RUNNER_WIRES_SCREENSHOT_DIR` for this reason; if you
  add new env vars the UITest needs to read, follow the same
  pattern.
- **SourceKit "no such module"** diagnostics on files freshly created
  outside Xcode are stale-index noise — Xcode rebuilds the index on
  next IDE launch. The actual `xcodebuild build` is the source of
  truth.
- **Synchronized folder groups.** The Xcode project uses
  `PBXFileSystemSynchronizedRootGroup`. Files placed under
  `Wires/Wires/`, `Wires/WiresTests/`, or `Wires/WiresUITests/` are
  automatically members of the matching target. No `project.pbxproj`
  edits needed.
- **`prepareDependencies` is global.** `LaunchFixture.install(named:)`
  installs fixture clients process-wide via TCA's
  `prepareDependencies`. This is intentional — every reducer scoped
  under the store sees the same dependency overrides — but it means
  fixture installation is one-shot per launch. The app's `Store` is
  built after `prepareDependencies`, so the install must happen in
  `WiresIOSApp`'s `static let store` closure, before the store reads
  any dependency.
- **`home_loading` is the only "blocking" fixture.** It seeds
  `loading=true` and the fixture `HouseholdClient.listCaps` sleeps
  60s so the spinner stays on screen past the 600 ms settle. If a
  new fixture needs a similar "captures a transient state" behavior,
  use the `listCapsBehavior: .block` pattern (or extend
  `ListBehavior` with new modes).

### Where the design lives

- **Spec:** `docs/superpowers/specs/2026-05-19-wires-ios-snapshot-tooling-design.md`
- **Plan:** `docs/superpowers/plans/2026-05-19-wires-ios-snapshot-tooling.md`

## Data-dir layouts

### CLI agent (default `~/.wires/`)

```
config.toml             NodeConfig (root_pubkey_hex empty until paired, data_dir, optional host)
identity.ed25519        agent signing key (32 bytes raw)
identity.x25519         agent x25519 secret (32 bytes raw)
iroh.secret             iroh node secret (created on first endpoint open)
root.ed25519            local root key (only when `wires init --new-root` generated it)
topic_names.json        name → 32-byte topic_id map (CLI-side convenience)
caps.db                 CapTable (redb)
log_<topic-hex>.redb    per-topic hash-chained ciphertext log
keys_<topic-hex>.redb   per-topic epoch keys
pair_pending.json       in-flight pair-listen state (mode 0600, present only while pairing)
```

### Host (passed via `--data-dir`)

```
iroh.secret                    32-byte iroh node secret (this host's EndpointId)
tenants.redb                   tenant table: root_pubkey -> TenantRecord
topic_index.redb               topic_id -> root_pubkey (forward index)
nonces.redb                    recent registration nonces with TTL (replay protection)
tenants/
  <root_pubkey_hex>/
    log_<topic_hex>.redb       per-topic ciphertext log (unchanged format)
    ingest_<root_hex>.redb     per-tenant FIFO eviction index (ingest_ts + size)
```

## Deployment

**This is a temporary deploy story.** Docker Compose + Tailscale Funnel is
a placeholder we picked so we could dogfood the gateway against a real
public HTTPS URL. The eventual alpha hosting target hasn't been chosen
yet — don't invest in deep automation around this stack. If a future
conversation looks like it's heading toward "let's harden this for
production," push back and clarify the target first.

The reference deploy host is `workbench` (a Tailscale node). The full
runbook lives in `docker/README.md` — load that file before touching deploy
plumbing. Quick orientation:

- **Two services, one Compose stack.** `docker/compose.yaml` builds
  `wires-host` and `wires-mcp` from a single multi-stage `docker/Dockerfile`
  and runs both with `network_mode: host`. State is in named volumes
  (`wires-host-data`, `wires-mcp-data`) — destroying them rotates the
  iroh `EndpointId` and the gateway's JWT signing key, so don't.
- **127.0.0.1 binds only.** Tailscale Funnel listens on the node's Tailnet
  IP for the public port, so the matching container must bind localhost or
  it will `AddrInUse`. `wires-host` is overridden to `--http-bind
  127.0.0.1:10000`; `wires-mcp` reads `bind = "127.0.0.1:10001"` from
  `docker/wires-mcp.toml` (operator-edited, mounted read-only).
- **Funnel slots.** Tailscale Funnel exposes only `443`, `8443`, `10000`
  publicly. Current assignments:

  | Local | Service | Funnel public |
  |---|---|---|
  | `127.0.0.1:10000` | wires-host ticket | Funnel `:10000` |
  | `127.0.0.1:10001` | wires-mcp OAuth + MCP | Funnel `:443` |
  | `127.0.0.1:10002+` | future wires-* services | tbd |

  The `SERVICES` array at the top of `docker/funnel.sh` is the single
  source of truth. Adding a third wires-* service means stealing a Funnel
  slot from another tenant on the node or sharing one via sub-paths.
- **Deploy command.** `./docker/deploy.sh` does `git pull --ff-only`,
  `docker compose build`, `docker compose up -d`, then polls `:10000/` and
  `:10001/_health`. `--no-pull` skips the pull; `--no-verify` skips the
  polls. Subsequent rollouts from the dev machine:
  `git push origin main && ssh workbench 'bash -lc "cd ~/src/wires && ./docker/deploy.sh"'`.
- **`docker/wires-mcp.toml`** is gitignored. First deploy on a new host
  must `cp docker/wires-mcp.toml.example docker/wires-mcp.toml` and edit
  `public_url` to the Funnel hostname before `deploy.sh` will succeed.
  Changing `public_url` later invalidates every outstanding JWT (the
  string is the OAuth issuer baked into tokens).
- **Hostname detection when invoking deploys.** If `hostname == workbench`,
  skip the `ssh workbench` wrapper and run `./docker/deploy.sh` directly —
  ssh-from-workbench-to-workbench works but is wasteful.

## When working in this repo

- Don't invent a CLAUDE/AGENTS-side convention layer over snafu. The error pattern in `crates/*/src/error.rs` is canonical.
- Reserved message types and required kinds (`__cap.grant` must be `SealedTo`, `__cap.revoke` must be `Public`, etc.) are checked in `wires-core::reserved`. Adding a new reserved type means updating that registry **and** the matching check in `inbound.rs`.
- The spec is the contract. If you find yourself disagreeing with the spec, update the spec first.

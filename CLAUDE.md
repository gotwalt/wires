# wires — Notes for future Claude sessions

End-to-end encrypted gossip substrate for a household's AI agents. Rust workspace, iroh-powered, blind hosting, capability-gated.

## Status

Prototype. Two slices have landed on `main`:

- **Substrate v1** (merge `fefbbfc`) — identity, topic creation, capability mint/revoke, publish with AEAD, gossip + replay between peers, decrypt on receive, persisted hash-chained logs. Drives the CLI end-to-end.
- **Hosted service v1** (merge `3da4ec8`) — `wires-host` is now multi-tenant: tenant registration over a `/wires/tenant/0` ALPN, per-tenant rolling retention with FIFO eviction, topic→tenant routing, write-rate ceiling, HTTPS service discovery at `/v1/bootstrap`, new `InviteToken` shape with `peer_hints` + `service_discovery_url`. The host became a `lib + bin` crate. The `--topic` CLI flag is gone; topics arrive only via the tenant protocol.

A Home Assistant ingestion daemon (`wires-ha`) also exists as a working example of an agent that participates in gossip + replay.

What does **not** exist yet: iOS companion (still a stock SwiftUI scaffold — the spec/plan need revision against the post-hosted-service architecture), REST/MCP surface, `__cap.*` gossip propagation, `__topic.epoch_advance` distribution, any CLI client for the tenant protocol. See "Out of scope" in each design spec.

## Authoritative docs

- **Substrate spec** — `docs/superpowers/specs/2026-05-14-wires-substrate-design.md`. Wire format, encryption modes, capability model, reserved message types, host blindness contract. Load-bearing.
- **Substrate plan** — `docs/superpowers/plans/2026-05-14-wires-substrate.md`. The 32-task plan that built v1; map of who-implements-what.
- **Hosted-service spec** — `docs/superpowers/specs/2026-05-14-wires-hosted-service-design.md`. Multi-tenant `wires-host`, tenant control protocol, per-tenant storage layout, new invite-token shape, HTTPS discovery surface.
- **Hosted-service plan** — `docs/superpowers/plans/2026-05-14-wires-hosted-service.md`. 29 tasks, fully landed.
- **iOS companion spec** — `docs/superpowers/specs/2026-05-14-wires-ios-companion-design.md`. **Stale**: written before hosted-service landed; still describes the dropped `HostPairToken` QR-pair flow. Revise against the hosted-service spec's §8 (discovery + `register_with_hosted_service`) before implementing.
- **iOS companion plan** — `docs/superpowers/plans/2026-05-14-wires-ios-companion.md`. Also **stale** for the same reason. Revise after the spec.

## Crate layout

Strict bottom-up layering — a crate may only depend on crates above it in this list:

| Crate | Role |
|---|---|
| `wires-core` | Pure types: `WireMessage`, `MessageKind` (Standard/SealedTo/Public), `Capability`, content schema, envelope sign/verify, hash-chain link math. No I/O, no async. |
| `wires-crypto` | AEAD primitives: `standard.rs` (ChaCha20-Poly1305 with BLAKE3-derived nonces), `sealed.rs` (x25519 sealed-box), `public.rs` (plaintext-with-AAD), `keywrap.rs`. |
| `wires-store` | redb-backed persistence: per-publisher hash-chained `topic_log` (now with `bytes_stored` and `delete` for eviction), `cap_table`, `epoch_keys`, and `ingest_index` for FIFO eviction across a tenant's topics. |
| `wires-net` | iroh transport: `gossip.rs` wraps `iroh-gossip`, `replay.rs` is a custom QUIC protocol on ALPN `/wires/replay/0`, `tenant.rs` is the new `/wires/tenant/0` control-plane (request/response types, `TenantClient`, `TenantProtocol` server-side handler, `TenantHandler` trait), `framing.rs` is the shared length-prefixed JSON helper, `invite.rs` is the new `InviteToken` with `peer_hints` + `service_discovery_url`, `peer_hint::first_reachable` is the join-time fallback iterator. |
| `wires-node` | Agent runtime. `Node::open` opens identity + storage; `publish_standard` / `handle_inbound` are the main entry points. `NetGlue` wires gossip + replay into a `Node`. |
| `wires-cli` | `wires` binary — clap-based human/agent CLI. Does **not** yet speak the tenant control protocol. |
| `wires-host` | `lib + bin`. The binary is a multi-tenant blind relay; the library houses `tenant_registry` (tenants/topic_index/nonces), `per_tenant_logs`, `retention`, `routing`, `replay_source`, `http_discovery` (axum `/v1/bootstrap`), and `error`. Still has no root key, no epoch keys, no caps; only persists ciphertext after a signature check, routed by topic→tenant lookup. |
| `wires-ha` | `wires-ha` binary — Home Assistant ingestion daemon. Subscribes to a HA WebSocket, publishes `state_changed` events onto a configured topic, participates in gossip + replay like any other agent. Example of a non-CLI agent. |

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
cargo test --workspace              # ~139 unit/integration tests
cargo test --workspace -- --ignored # 7 acceptance scenarios (slower)
cargo clippy --workspace -- -D warnings
cargo fmt --all
```

Binaries land at `target/debug/wires`, `target/debug/wires-host`, and `target/debug/wires-ha`.

## Data-dir layouts

### CLI agent (default `~/.wires/`)

```
config.toml             NodeConfig (root_pubkey_hex, data_dir, bootstrap_peers)
identity.ed25519        agent signing key (32 bytes raw)
identity.x25519         agent x25519 secret (32 bytes raw)
root.ed25519            local root key (only when `wires init` generated it)
topic_names.json        name → 32-byte topic_id map (CLI-side convenience)
caps.redb               CapTable
log_<topic-hex>.redb    per-topic hash-chained ciphertext log
keys_<topic-hex>.redb   per-topic epoch keys
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

## When working in this repo

- Don't invent a CLAUDE/AGENTS-side convention layer over snafu. The error pattern in `crates/*/src/error.rs` is canonical.
- Reserved message types and required kinds (`__cap.grant` must be `SealedTo`, `__cap.revoke` must be `Public`, etc.) are checked in `wires-core::reserved`. Adding a new reserved type means updating that registry **and** the matching check in `inbound.rs`.
- The spec is the contract. If you find yourself disagreeing with the spec, update the spec first.

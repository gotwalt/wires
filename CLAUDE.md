# wires — Notes for future Claude sessions

End-to-end encrypted gossip substrate for a household's AI agents. Rust workspace, iroh-powered, blind hosting, capability-gated.

## Status

Prototype. The **v1 substrate** is built and merged on `main` (commit `fefbbfc`). What works end-to-end via the CLI: identity, topic creation, capability mint/revoke, publish with AEAD, gossip + replay between peers, decrypt on receive, persisted hash-chained logs. What does **not** exist yet: iOS companion (root key custody), REST/MCP surface, ingestion daemons, `__cap.*` gossip propagation, `__topic.epoch_advance` distribution. See "Out of scope for v1" in the design spec.

## Authoritative docs

- **Design spec** — `docs/superpowers/specs/2026-05-14-wires-substrate-design.md`. Read this before making non-trivial changes. It defines the wire format, encryption modes, capability model, reserved message types, and host blindness contract. Treat it as load-bearing.
- **Implementation plan** — `docs/superpowers/plans/2026-05-14-wires-substrate.md`. The 32-task plan that built v1; useful as a map of who-implements-what.

## Crate layout

Strict bottom-up layering — a crate may only depend on crates above it in this list:

| Crate | Role |
|---|---|
| `wires-core` | Pure types: `WireMessage`, `MessageKind` (Standard/SealedTo/Public), `Capability`, content schema, envelope sign/verify, hash-chain link math. No I/O, no async. |
| `wires-crypto` | AEAD primitives: `standard.rs` (ChaCha20-Poly1305 with BLAKE3-derived nonces), `sealed.rs` (x25519 sealed-box), `public.rs` (plaintext-with-AAD), `keywrap.rs`. |
| `wires-store` | redb-backed persistence: per-publisher hash-chained `topic_log`, `cap_table`, `epoch_keys`. |
| `wires-net` | iroh transport: `gossip.rs` wraps `iroh-gossip`, `replay.rs` is a custom QUIC protocol on ALPN `/wires/replay/0`, `invite.rs` is the base64 invite token format. |
| `wires-node` | Agent runtime. `Node::open` opens identity + storage; `publish_standard` / `handle_inbound` are the main entry points. `NetGlue` wires gossip + replay into a `Node`. |
| `wires-cli` | `wires` binary — clap-based human/agent CLI. |
| `wires-host` | `wires-host` binary — blind relay/replay-server. Holds no root key, no epoch keys, no caps; only persists ciphertext after a coarse signature check. |

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

3. **Host blindness.** The host enforces `verify_envelope` (signature) only. ACL checks (cap_id has rights to topic, sender owns cap, not revoked) happen on the **receiver** at decrypt time. Never add cap lookups to `wires-host`. The host has no caps and no epoch keys.

4. **Per-publisher hash chain.** Each `(topic_id, sender)` has its own chain. `TopicLog::append` is idempotent on duplicate hash but errors on fork attempts (same `seq`, different content). The log key is `32-byte sender || 8-byte BE seq`.

5. **Three `MessageKind`s, three nonce schemes.** `Standard` uses a deterministic nonce derived from `(topic_id, sender, seq)` — never reuse epoch keys across (sender, seq). `SealedTo(pubkey)` is x25519 sealed-box; the ephemeral pubkey is prepended to ciphertext. `Public` is JSON-with-AAD, no encryption. Reserved message types (prefix `__`) require specific kinds — see `wires-core/src/reserved.rs`.

## Build and test

```bash
cargo build                         # all crates
cargo test --workspace              # 95 unit/integration tests
cargo test --workspace -- --ignored # 6 acceptance scenarios (slower)
cargo clippy --workspace -- -D warnings
cargo fmt --all
```

Binaries land at `target/debug/wires` and `target/debug/wires-host`.

## Data-dir layout (for the CLI)

Default `~/.wires/`:

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

## When working in this repo

- Don't invent a CLAUDE/AGENTS-side convention layer over snafu. The error pattern in `crates/*/src/error.rs` is canonical.
- Reserved message types and required kinds (`__cap.grant` must be `SealedTo`, `__cap.revoke` must be `Public`, etc.) are checked in `wires-core::reserved`. Adding a new reserved type means updating that registry **and** the matching check in `inbound.rs`.
- The spec is the contract. If you find yourself disagreeing with the spec, update the spec first.

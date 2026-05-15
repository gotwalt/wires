# wires

End-to-end encrypted gossip substrate for a household's AI agents. Think "a private group chat that machines can read and write to, hosted by a server that cannot."

**Status: prototype.** Two slices have landed on `main`:

- **Substrate v1** — identity, topics, capabilities, encrypted publish/subscribe, replay between peers, persisted hash-chained logs. Drives the CLI end-to-end. Spec: [`docs/superpowers/specs/2026-05-14-wires-substrate-design.md`](docs/superpowers/specs/2026-05-14-wires-substrate-design.md).
- **Hosted service v1** — `wires-host` is now a multi-tenant blind relay with a `/wires/tenant/0` control-plane ALPN, per-tenant rolling retention, an HTTPS service-discovery endpoint, and a new invite-token shape. Spec: [`docs/superpowers/specs/2026-05-14-wires-hosted-service-design.md`](docs/superpowers/specs/2026-05-14-wires-hosted-service-design.md).

A working Home Assistant ingestion daemon (`wires-ha`) ships as a separate binary.

Not built yet: iOS companion app (still a stock SwiftUI scaffold pending revised plan), REST/MCP surface, `__cap.*` gossip propagation, `__topic.epoch_advance` distribution, a CLI client for the tenant control protocol.

## Build

Requires stable Rust (tested on 1.95).

```bash
cargo build --release
```

Three binaries land in `target/release/`:

- **`wires`** — the agent/human CLI. One data directory per agent.
- **`wires-host`** — a multi-tenant blind relay/replay server. Holds no keys; persists ciphertext only for tenants and topics that have registered via the tenant control protocol.
- **`wires-ha`** — Home Assistant ingestion daemon. Subscribes to a HA WebSocket and publishes `state_changed` events onto a configured wires topic.

## Quick start: two agents on one machine

This walks through one agent ("alice") minting a capability for another ("bob"), then both publishing and reading.

```bash
# 1. Initialize alice. Generates a local root + agent identity, writes config.
wires --data-dir ./alice init
# → "Generated local root pubkey: <ROOT_HEX>"
# → "Root pubkey: <ROOT_HEX>"

# 2. Initialize bob, pointing at the same root pubkey alice generated.
wires --data-dir ./bob init --root <ROOT_HEX>

# 3. Create a topic on alice's side. Prints a 64-char topic id and a 64-char
#    epoch key. In v1 you copy the epoch key to bob manually (gossip
#    distribution of epoch keys is not implemented yet).
wires --data-dir ./alice topic create home.notes
# → "Created topic 'home.notes' with id <TOPIC_HEX>"
# → "Note: ... share epoch key <EPOCH_HEX> with peers manually."

# 4. Look up alice's and bob's agent pubkeys.
wires --data-dir ./alice status   # "agent pubkey : <ALICE_AGENT_HEX>"
wires --data-dir ./bob   status   # "agent pubkey : <BOB_AGENT_HEX>"

# 5. Alice (as root holder) mints a capability for bob giving read+write on
#    the topic name. Prints a 16-byte cap_id.
wires --data-dir ./alice invite \
  --agent-pubkey <BOB_AGENT_HEX> \
  --topics home.notes \
  --rights read,write
# → "cap_id : <CAP_HEX>"

# Alice also needs her own cap to publish.
wires --data-dir ./alice invite \
  --agent-pubkey <ALICE_AGENT_HEX> \
  --topics home.notes \
  --rights read,write
# → "cap_id : <ALICE_CAP_HEX>"

# 6. Publish from alice. The topic can be passed by name (resolved from
#    ./alice/topic_names.json) or by hex id.
wires --data-dir ./alice publish \
  --topic home.notes \
  --cap <ALICE_CAP_HEX> \
  --type agent.note \
  "hello from alice"

# 7. Tail the log on alice.
wires --data-dir ./alice cat home.notes
```

Bob can publish and tail the same way once you've copied the topic id + epoch key over and the cap minted for bob is installed in his cap table. (Today this requires sharing both manually; cap-grant gossip is a future task.)

## Running a host

`wires-host` is a multi-tenant blind relay. It accepts tenant registrations over the `/wires/tenant/0` ALPN, persists ciphertext per tenant under a rolling retention budget, and serves replay to anyone who asks (the receiver still verifies caps and decrypts on its end).

```bash
wires-host --data-dir ./host
# → prints "EndpointId = <ID>" and the discovery address (default 0.0.0.0:8443).
```

Optional flags:

- `--discovery-addr <ADDR>` — where the HTTPS `/v1/bootstrap` service listens (default `0.0.0.0:8443`).
- `--public-url <URL>` — what the discovery response advertises; defaults to `http://<discovery_addr>` (testing only — production wants a real HTTPS terminator in front).

The host no longer accepts `--topic` flags. Topics arrive dynamically when a registered tenant calls `TopicRegister` over `/wires/tenant/0`. The shipped client for that protocol is the iOS companion (not yet built); the integration tests under `crates/wires-host/tests/` exercise it via `wires-net::tenant::TenantClient`.

Pass `RUST_LOG=info` (or `debug`) for tracing output.

## Networking notes

- Transport is [iroh](https://www.iroh.computer) (`0.98`). Discovery uses iroh's N0 preset by default.
- Gossip runs over iroh-gossip on the topic id directly.
- Replay (catching up after downtime) uses a custom QUIC stream on ALPN `/wires/replay/0`.
- Tenant control (registration + topic register/unregister + status) uses ALPN `/wires/tenant/0` with length-prefixed JSON frames.
- Service discovery is plain HTTPS at `GET /v1/bootstrap`, returning a list of host endpoints. Self-hosting operators can serve a static JSON file; the host serves its own by default.

## Layout

```
crates/
  wires-core    pure types (WireMessage, Capability, content, sign/verify)
  wires-crypto  AEAD (chacha20-poly1305), sealed-box (x25519), public envelopes
  wires-store   redb-backed hash-chained logs, cap table, epoch keys, ingest index
  wires-net     iroh gossip + replay protocol + tenant control protocol + invite tokens
  wires-node    Node runtime (publish, inbound, sync, NetGlue)
  wires-cli     `wires` binary
  wires-host    `wires-host` multi-tenant relay (lib + bin: tenant registry, retention, routing, http discovery)
  wires-ha      `wires-ha` Home Assistant ingestion daemon
docs/superpowers/
  specs/        design docs (substrate, hosted-service, iOS companion)
  plans/        implementation plans
```

## License

MIT OR Apache-2.0

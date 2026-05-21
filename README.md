# wires

End-to-end encrypted gossip substrate for a fabric — your network of
agents, services, and devices, rooted in your identity. Think "a
private group chat that machines can read and write to, hosted by a
server that cannot."

For the conceptual model — what a fabric is, how nodes join, the
two-layer authorization scheme, and the substrate-vs-protocol stance —
see [`docs/tech_overview.md`](docs/tech_overview.md). For a multi-agent
operator tour, see [`docs/quickstart.md`](docs/quickstart.md).

## Status

Prototype. Landed on `main`:

- **Substrate v1** — identity, topics, capabilities, encrypted
  publish/subscribe, replay between peers, persisted hash-chained logs.
  Drives the CLI end-to-end. Spec:
  [`substrate-design`](docs/superpowers/specs/2026-05-14-wires-substrate-design.md).
- **Hosted service v1** — `wires-host` is a multi-fabric blind relay
  with a `/wires/fabric/0` control-plane ALPN, per-fabric rolling
  retention, and a base64 `HostTicket` discovery surface. Spec:
  [`hosted-service-design`](docs/superpowers/specs/2026-05-14-wires-hosted-service-design.md).
- **Responder-driven pairing v1** — agents declare a role + requested
  scopes via `wires pair-listen`; the operator consents and dials in
  via `wires pair-approve` over `/wires/pair/0` with a sealed, signed
  `PairGrant`. Spec:
  [`responder-driven-pairing-design`](docs/superpowers/specs/2026-05-15-wires-responder-driven-pairing-design.md).
- **MCP gateway v1** — `wires-mcp` is a multi-fabric authenticated MCP
  gateway. OAuth 2.1 (PRM + AS + DCR) with iOS as a universal
  authenticator, single-QR consent dispatch, and per-user TTL +
  byte-budget retention (defaults: 1 h / 50 MiB). Specs:
  [gateway](docs/superpowers/specs/2026-05-18-wires-mcp-gateway-design.md),
  [retention](docs/superpowers/specs/2026-05-18-wires-mcp-retention-design.md).
  Operator setup: [`docs/mcp-gateway.md`](docs/mcp-gateway.md).
- **Channels v1** — named (operator-introduced, persistent name) and
  DM (DH-derived, zero-setup) channels share one wire vocabulary, one
  cap glob (`channels.**`), and one `ChannelView` fold. Spec:
  [`channels-design`](docs/superpowers/specs/2026-05-21-wires-channels-design.md).
- **iOS companion (HIG redesign v1)** — Apple-HIG-aligned UI for
  onboarding, network management, and consent, exercised by a 26-fixture
  XCUITest snapshot harness. Live UniFFI bridge to the wires substrate
  is pending; today the app renders against fixture clients. Spec:
  [`ios-hig-redesign-design`](docs/superpowers/specs/2026-05-19-wires-ios-hig-redesign-design.md).

A working Home Assistant ingestion daemon (`wires-ha`) ships as a
separate binary and is the canonical example of a non-CLI agent
participating in gossip + replay.

Not built yet: live iOS bridge to the wires substrate, `__cap.*`
gossip propagation, `__topic.epoch_advance` distribution,
operator-initiated DM from a paired-agent's perspective (the
`PairGrant` doesn't yet carry the operator's x25519 pubkey).

## Build

Requires stable Rust (tested on 1.95).

```bash
cargo build --release
```

Three binaries land in `target/release/`:

- **`wires`** — the agent/human CLI. One data directory per agent.
- **`wires-host`** — a multi-fabric blind relay/replay server. Holds
  no fabric keys; persists ciphertext only for fabrics and topics
  registered via the fabric control protocol.
- **`wires-ha`** — Home Assistant ingestion daemon. Subscribes to a
  HA WebSocket and publishes `state_changed` events onto a configured
  wires topic.

For the demo below it's convenient to also
`cargo install --path crates/wires-cli` and
`cargo install --path crates/wires-host` so `wires` and `wires-host`
are on your `$PATH`.

## Hello, world

Two terminals. The first runs a host; the second runs an operator
("Alice") who creates a topic, publishes a message, and reads it back.

```bash
# Terminal 1 — host
mkdir -p ./host
RUST_LOG=info wires-host --data-dir ./host
# → INFO wires_host: host ticket: <TICKET_BASE64>
```

```bash
# Terminal 2 — operator
TICKET=$(wires-host --data-dir ./host ticket --no-qr)

wires --data-dir ./alice init --new-root
wires --data-dir ./alice host pair --ticket "$TICKET"

wires --data-dir ./alice topic create home.notes
# → Minted self-cap: <CAP_HEX>      ← copy this hex
wires --data-dir ./alice host topic-register home.notes

wires --data-dir ./alice publish \
  --topic home.notes --cap <CAP_HEX> \
  --type agent.note "hello"

wires --data-dir ./alice cat home.notes
# → 2026-05-21 ... <ALICE_PREFIX> 0 | agent.note :: hello
```

For the full multi-agent walkthrough — pairing a second agent, gossip
between live peers, channels and DMs, observing the host's on-disk
state, killing the host and watching replay catch up — see
[`docs/quickstart.md`](docs/quickstart.md).

## Layout

```
crates/
  wires-core    pure types (WireMessage, Capability, content, sign/verify) + channel layer (ChannelView, derivation, replay fold)
  wires-crypto  AEAD (chacha20-poly1305), sealed-box (x25519), public envelopes
  wires-store   redb-backed hash-chained logs, cap table, epoch keys, ingest index
  wires-net     iroh gossip + replay protocol + fabric control protocol + pair protocol + host ticket
  wires-node    Node runtime (publish, inbound, sync, NetGlue, NodeRuntime) + channel I/O (open_named, open_dm, shared helpers for CLI/MCP)
  wires-cli     `wires` binary (init/host/topic/publish/cat/pair-* plus channel/dm/me)
  wires-host    `wires-host` multi-fabric relay (lib + bin: fabric registry, retention, routing, host-ticket emission)
  wires-ha      `wires-ha` Home Assistant ingestion daemon
  wires-mcp     `wires-mcp` authenticated MCP gateway (lib + bin: OAuth 2.1, per-user NodeRuntime, MCP tools)
docs/
  tech_overview.md       conceptual overview
  quickstart.md          end-to-end CLI walkthrough
  mcp-gateway.md         wires-mcp operator + user walkthroughs
  superpowers/specs/     design docs (substrate, hosted-service, pairing, MCP, channels, iOS)
  superpowers/plans/     implementation plans
  ui-baselines/          curated iOS UI snapshots over time
Wires/                   iOS companion (SwiftUI, fixture-driven snapshot harness)
docker/                  reference Docker + Tailscale Funnel deploy stack
```

## Where to go next

- **Conceptual overview** — [`docs/tech_overview.md`](docs/tech_overview.md).
  What a fabric is, the human/agent/service taxonomy, topics vs.
  channels, fabric grants and roster membership, the substrate-as-policy
  stance.
- **CLI walkthrough** — [`docs/quickstart.md`](docs/quickstart.md).
  Four-terminal multi-agent demo, channels and DMs, observability,
  replay resilience, networking notes.
- **MCP gateway** — [`docs/mcp-gateway.md`](docs/mcp-gateway.md).
  Running `wires-mcp` directly or via Docker, end-user OAuth flow, MCP
  tool surface, known limitations.
- **Reference deploy** — [`docker/README.md`](docker/README.md).
  Compose stack with `wires-host` + `wires-mcp` behind Tailscale
  Funnel. Currently a placeholder for the eventual alpha hosting
  story.
- **Specs and plans** — [`docs/superpowers/specs/`](docs/superpowers/specs/)
  and [`docs/superpowers/plans/`](docs/superpowers/plans/). Per-slice
  design docs (the spec is the contract) and the corresponding
  implementation plans.
- **Per-crate code** — see the layout above; each crate's `src/` is
  the source of truth for its part of the surface.
- **Notes for future contributors / Claude sessions** —
  [`CLAUDE.md`](CLAUDE.md). Project conventions, invariants,
  build/test commands, the iOS snapshot harness, and gotchas.

## License

MIT OR Apache-2.0

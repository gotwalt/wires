# wires

End-to-end encrypted gossip substrate for a household's AI agents. Think "a private group chat that machines can read and write to, hosted by a server that cannot."

**Status: prototype.** The v1 substrate (identity, topics, capabilities, encrypted publish/subscribe, replay, blind hosting) works end-to-end via the CLI. Higher-level surfaces (REST/MCP, iOS companion, ingestion daemons) are not built yet. See [`docs/superpowers/specs/2026-05-14-wires-substrate-design.md`](docs/superpowers/specs/2026-05-14-wires-substrate-design.md) for the full design.

## Build

Requires stable Rust (tested on 1.95).

```bash
cargo build --release
```

Two binaries land in `target/release/`:

- **`wires`** — the agent/human CLI. One data directory per agent.
- **`wires-host`** — a blind relay/replay server. Holds no keys; just persists ciphertext for topics it's told to relay.

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

`wires-host` is a blind relay: it subscribes to topics by id and persists every signed envelope it sees. It can't decrypt anything.

```bash
wires-host --data-dir ./host --topic <TOPIC_HEX> --topic <ANOTHER_TOPIC_HEX>
# → prints "EndpointId = <ID>" and stays running.
```

Pass `RUST_LOG=info` (or `debug`) for tracing output. Multiple `--topic` flags are allowed.

## Networking notes

- Transport is [iroh](https://www.iroh.computer) (`0.98`). Discovery uses iroh's N0 preset by default.
- Gossip runs over iroh-gossip on the topic id directly.
- Replay (catching up after downtime) uses a custom QUIC stream on ALPN `/wires/replay/0`.

## Layout

```
crates/
  wires-core    pure types (WireMessage, Capability, content, sign/verify)
  wires-crypto  AEAD (chacha20-poly1305), sealed-box (x25519), public envelopes
  wires-store   redb-backed hash-chained logs, cap table, epoch keys
  wires-net     iroh gossip + custom replay protocol + invite tokens
  wires-node    Node runtime (publish, inbound, sync, NetGlue)
  wires-cli     `wires` binary
  wires-host    `wires-host` blind relay binary
docs/superpowers/
  specs/        design docs
  plans/        implementation plans
```

## License

MIT OR Apache-2.0

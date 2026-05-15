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

For the walkthrough below it's convenient to also `cargo install --path crates/wires-cli` and `cargo install --path crates/wires-host` so `wires` and `wires-host` are on your `$PATH`.

## Concepts in one paragraph each

- **Identity.** Every agent has an Ed25519 signing key and an X25519 secret. The root key for a household is a separate Ed25519 keypair held by the operator; capabilities are signed by it. `wires init` generates the agent identity; with no `--root` it also generates a local root key.
- **Capability.** A signed grant of `read` and/or `write` on a topic to a specific agent pubkey. Capabilities are the only way to publish, and they live in each agent's `caps.redb`.
- **Topic.** A 32-byte id with a per-epoch symmetric key. Messages on a topic are encrypted under the current epoch key. Topic names (e.g. `home.notes`) are a CLI-side convenience that maps to a random id at creation time.
- **Host.** A `wires-host` process is a blind multi-tenant relay: it persists ciphertext per tenant, serves replay, and routes by `topic_id → tenant`. It cannot decrypt anything.
- **Tenant.** A household paired with a host. Created via the `/wires/tenant/0` ALPN, signed by the root key. One tenant per root pubkey per host.

## Quick start: a local proof-of-concept in four terminals

This walks through running the full system on one machine. Open four terminal tabs. We use four data directories: `./host`, `./alice`, `./bob`, and (for observation) the host's data dir again.

### Tab 1 — `wires-host`

```bash
mkdir -p ./host
wires-host --data-dir ./host
# → wires-host: EndpointId = <HOST_ID>
# → wires-host: discovery listening at 0.0.0.0:8443 (public=http://0.0.0.0:8443)
# → wires-host: running. Press Ctrl-C to exit.
```

Leave it running for the rest of the walkthrough. Set `RUST_LOG=info` (or `debug`) before the command if you want to see routing decisions in real time.

### Tab 2 — Alice, the operator

Alice is the root-key holder for this household.

```bash
# 1. Initialize Alice's data dir. Generates a local root + agent identity.
wires --data-dir ./alice init
# → Generated local root pubkey: <ROOT_HEX>
# → Initialized at ./alice
# → Root pubkey: <ROOT_HEX>

# 2. Pair Alice's root with the host. Signs a TenantRegisterRequest with
#    ./alice/root.ed25519, dials the host at the EndpointId returned by
#    discovery, persists host info into ./alice/config.toml.
wires --data-dir ./alice host pair \
  --discovery-url http://127.0.0.1:8443/v1/bootstrap
# → Paired with host <HOST_ID> (server_time=<MILLIS>)
# → Host info persisted to ./alice/config.toml

# 3. Create a topic on Alice's side. Prints a 64-char topic id and the
#    epoch key (you'll share this manually with Bob — auto-distribution is
#    a future spec item).
wires --data-dir ./alice topic create home.notes
# → Created topic 'home.notes' with id <TOPIC_HEX>
# → Note: share epoch key <EPOCH_HEX> with peers manually.

# 4. Register the topic with the host so the host persists envelopes for it.
wires --data-dir ./alice host topic-register home.notes
# → Registered topic <TOPIC_HEX>

# 5. Check what the host reports for this tenant.
wires --data-dir ./alice host status
# → Tenant status (as reported by host):
# →   registered_at         : <MILLIS>
# →   topic_count           : 1
# →   bytes_stored          : 0
# →   retention_budget      : 1073741824
# →   write_rate_limit_per_sec : 1000
# →   status                : Active
```

### Tab 3 — Bob, an invited agent

Bob is a second agent under the same household. He shares Alice's root pubkey but has his own agent identity.

```bash
# 1. Initialize Bob, pinning him to Alice's root pubkey. No root.ed25519
#    is created; Bob cannot mint caps or pair with a host, only operate
#    under caps Alice grants him.
wires --data-dir ./bob init --root <ROOT_HEX>
# → Initialized at ./bob
# → Root pubkey: <ROOT_HEX>

# 2. Look up Bob's agent pubkey — Alice needs it to mint his invite.
wires --data-dir ./bob status
# → agent pubkey : <BOB_AGENT_HEX>
# → ...
```

### Tab 2 again — Alice mints invites

```bash
# 6. Mint an invite for Bob: cap + the host info Alice is paired with,
#    bundled into an InviteToken (base64).
wires --data-dir ./alice invite \
  --agent-pubkey <BOB_AGENT_HEX> \
  --topics home.notes \
  --rights read,write
# → Invite token (share with the invitee):
# → <BOB_TOKEN>

# 7. Also mint a self-cap so Alice can publish (the root pubkey is not an
#    automatic publisher; she still needs a cap pointing at her agent pk).
wires --data-dir ./alice status     # → "agent pubkey : <ALICE_AGENT_HEX>"
wires --data-dir ./alice invite \
  --agent-pubkey <ALICE_AGENT_HEX> \
  --topics home.notes \
  --rights read,write
# → Minted capability:
# →   cap_id : <ALICE_CAP_HEX>
# →   agent  : <ALICE_AGENT_HEX>
# →   topics : ["home.notes"]
# →   rights : ["read", "write"]
# →
# → Invite token (share with the invitee):
# → <ALICE_TOKEN>
#
# Note: `wires invite` always mints AND installs the cap into the inviter's
# caps.redb, so Alice doesn't need to `wires join` her own self-cap — she
# just uses <ALICE_CAP_HEX> directly in `wires publish` below.
```

### Tab 3 again — Bob joins and reads

```bash
# 3. Bob joins his invite token. Installs the cap into ./bob/caps.redb and
#    copies Alice's host info into ./bob/config.toml.
wires --data-dir ./bob join <BOB_TOKEN>
# → Joined: cap <BOB_CAP_HEX> installed; host info persisted.
# → Note: epoch keys for 1 topic(s) are not in the invite token; obtain
# →       them out-of-band before publishing.

# 4. Manual step (v1 only): copy the topic id + epoch key from Tab 2 step 3
#    into Bob's data dir. The simplest local hack is to copy the topic name
#    map and the epoch-key db file from Alice — they're keyed by topic_id:
cp ./alice/topic_names.json ./bob/topic_names.json
cp ./alice/keys_<TOPIC_HEX>.redb ./bob/keys_<TOPIC_HEX>.redb

# 5. Bob tails the topic. cat first replays any history the host has, then
#    streams live events from gossip.
wires --data-dir ./bob cat home.notes --tail
# → (replay catch-up: N envelopes from host)
# → [waits for live events]
```

### Tab 2 again — Alice publishes

```bash
# 8. Alice publishes. publish auto-dials the host (because config.toml has
#    `host`), broadcasts over gossip, and writes locally.
wires --data-dir ./alice publish \
  --topic home.notes \
  --cap <ALICE_CAP_HEX> \
  --type agent.note \
  "hello from alice"
# → published seq=0 sender=<ALICE_AGENT_HEX> timestamp=<MILLIS>
```

Within a second or two Bob's `cat --tail` in Tab 3 should print the message:

```
2026-05-14 23:42:01.234 <ALICE_AGENT_HEX_PREFIX> 0 | agent.note :: hello from alice
```

## Observing the system

### Where files live

```bash
ls ./host
# iroh.secret  tenants.redb  topic_index.redb  nonces.redb  tenants/

ls ./host/tenants
# <root_pubkey_hex>/        ← one directory per registered tenant

ls ./host/tenants/<ROOT_HEX>
# log_<TOPIC_HEX>.redb      ← per-topic ciphertext log
# ingest_<ROOT_HEX>.redb    ← per-tenant FIFO eviction index
```

The host has zero per-tenant secrets — no caps, no epoch keys. Verify with `ls`: you'll see only the four host-level redb files plus a per-tenant subdir of opaque ciphertext logs. The host literally cannot decrypt the content.

### Tenant status from the operator's side

```bash
wires --data-dir ./alice host status
```

Re-run after publishing a few messages — `bytes_stored` will grow, `topic_count` reflects registered topics, and `oldest_retained_at` advances forward as the retention budget evicts.

### Inspect on-disk per-tenant size

```bash
du -h ./host/tenants/<ROOT_HEX>
```

This is what a hosted-service operator would graph per tenant.

## Resilience: kill the host and watch replay catch up

1. In Tab 2, publish several more messages over a few seconds.
2. In Tab 1, `Ctrl-C` the host.
3. In Tab 2, publish a few more — these go peer-to-peer (Alice + Bob still see each other via gossip) but are NOT persisted by the host because it's down.
4. Restart Tab 1: `wires-host --data-dir ./host`. The host reloads its tenants.redb and topic_index.redb, re-subscribes to every previously-registered topic.
5. In a fresh Tab 4, run a "cold" Bob — copy `./bob` to `./bob2`, then `wires --data-dir ./bob2 cat home.notes`. The replay client pulls every message the host retains, and Bob2 sees everything published while the host was alive. Messages published while the host was down are visible to live Bob (via gossip) but not to cold Bob2 (because they were never persisted) — exactly the substrate's hash-chained "gap detection" property.

## Other useful commands

```bash
wires --data-dir ./alice host topic-unregister home.notes  # host stops persisting new envelopes
wires --data-dir ./alice revoke <CAP_HEX>                  # tomb a cap (substrate v1 — no gossip propagation yet)
wires --data-dir ./alice cat home.notes                    # no --tail: print local log and exit
```

## Networking notes

- Transport is [iroh](https://www.iroh.computer) (`0.98`). Discovery uses iroh's N0 preset by default.
- Gossip runs over iroh-gossip on the topic id directly.
- Replay (catching up after downtime) uses a custom QUIC stream on ALPN `/wires/replay/0`.
- Tenant control (registration + topic register/unregister + status) uses ALPN `/wires/tenant/0` with length-prefixed JSON frames.
- Service discovery is plain HTTPS at `GET /v1/bootstrap`, returning a list of host endpoints. Self-hosting operators can serve a static JSON file; the host serves its own by default (HTTP only — production wants a TLS terminator in front).

## Layout

```
crates/
  wires-core    pure types (WireMessage, Capability, content, sign/verify)
  wires-crypto  AEAD (chacha20-poly1305), sealed-box (x25519), public envelopes
  wires-store   redb-backed hash-chained logs, cap table, epoch keys, ingest index
  wires-net     iroh gossip + replay protocol + tenant control protocol + invite tokens + discovery
  wires-node    Node runtime (publish, inbound, sync, NetGlue, NodeRuntime)
  wires-cli     `wires` binary
  wires-host    `wires-host` multi-tenant relay (lib + bin: tenant registry, retention, routing, http discovery)
  wires-ha      `wires-ha` Home Assistant ingestion daemon
docs/superpowers/
  specs/        design docs (substrate, hosted-service, iOS companion)
  plans/        implementation plans
```

## License

MIT OR Apache-2.0

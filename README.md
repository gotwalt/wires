# wires

End-to-end encrypted gossip substrate for a household's AI agents. Think "a private group chat that machines can read and write to, hosted by a server that cannot."

**Status: prototype.** Five slices have landed on `main`:

- **Substrate v1** — identity, topics, capabilities, encrypted publish/subscribe, replay between peers, persisted hash-chained logs. Drives the CLI end-to-end. Spec: [`docs/superpowers/specs/2026-05-14-wires-substrate-design.md`](docs/superpowers/specs/2026-05-14-wires-substrate-design.md).
- **Hosted service v1** — `wires-host` is a multi-tenant blind relay with a `/wires/tenant/0` control-plane ALPN, per-tenant rolling retention, and an HTTPS service-discovery endpoint. Spec: [`docs/superpowers/specs/2026-05-14-wires-hosted-service-design.md`](docs/superpowers/specs/2026-05-14-wires-hosted-service-design.md).
- **Responder-driven pairing v1** — agents declare a role + requested scopes via `wires pair-listen`; the operator consents and dials in via `wires pair-approve` over `/wires/pair/0` with a sealed, signed `PairGrant`. Spec: [`docs/superpowers/specs/2026-05-15-wires-responder-driven-pairing-design.md`](docs/superpowers/specs/2026-05-15-wires-responder-driven-pairing-design.md).
- **MCP gateway v1** — `wires-mcp` is a multi-tenant authenticated MCP gateway. OAuth 2.1 (PRM + AS + DCR), iOS as universal authenticator. Per-user TTL + byte-budget retention (defaults: 1 h / 50 MiB; operator-tunable via `[retention]`). Specs: [gateway](docs/superpowers/specs/2026-05-18-wires-mcp-gateway-design.md), [retention](docs/superpowers/specs/2026-05-18-wires-mcp-retention-design.md).
- **Channels v1** — named (operator-introduced, persistent name) and DM (DH-derived, zero-setup) channels share one wire vocabulary, one cap glob (`channels.**`), and one `ChannelView` fold. Three new reserved types (`__channel.create/invite/member_meta`). Spec: [`docs/superpowers/specs/2026-05-21-wires-channels-design.md`](docs/superpowers/specs/2026-05-21-wires-channels-design.md).

A working Home Assistant ingestion daemon (`wires-ha`) ships as a separate binary.

Not built yet: iOS companion app (still a stock SwiftUI scaffold pending revised plan), `__cap.*` gossip propagation, `__topic.epoch_advance` distribution. In channels v1, DMs are operator-initiated only — the `PairGrant` doesn't yet carry the operator's x25519, so paired agents can't `wires dm open <operator>` back at the household root holder.

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
- **Capability.** A signed grant of `read` and/or `write` on a topic to a specific agent pubkey. Capabilities are the only way to publish. Operators (root-key holders) mint them in response to a pair request from an agent via `wires pair-approve`; caps live in each agent's `caps.db`.
- **Topic.** A 32-byte id with a per-epoch symmetric key. Messages on a topic are encrypted under the current epoch key. Topic names (e.g. `home.notes`) are a CLI-side convenience that maps to a random id at creation time.
- **Host.** A `wires-host` process is a blind multi-tenant relay: it persists ciphertext per tenant, serves replay, and routes by `topic_id → tenant`. It cannot decrypt anything.
- **Tenant.** A household paired with a host. Created via the `/wires/tenant/0` ALPN, signed by the root key. One tenant per root pubkey per host.

## Quick start: a local proof-of-concept in four terminals

This walks through running the full system on one machine. Open four terminal tabs. We use four data directories: `./host`, `./alice`, `./bob`, and (for observation) the host's data dir again.

### Tab 1 — `wires-host`

```bash
mkdir -p ./host
RUST_LOG=info wires-host --data-dir ./host
# → wires-host: EndpointId = <HOST_ID>
# → INFO wires_host: host ticket: <TICKET_BASE64>
# → wires-host: running. Press Ctrl-C to exit.
```

Leave it running for the rest of the walkthrough. The `host ticket: …` line is a base64-encoded `HostTicket` that agents need to pair with this host; you can also fetch it from a separate shell at any time with `wires-host --data-dir ./host ticket --no-qr` (prints base64 to stdout). Running `wires-host` with stderr attached to a TTY additionally emits a scannable QR of the same ticket; pass `--no-qr` to suppress it.

### Tab 2 — Alice, the operator

Alice is the root-key holder for this household. Capture the host ticket first (Tab 1 must already be running):

```bash
TICKET=$(wires-host --data-dir ./host ticket --no-qr)
```

```bash
# 1. Initialize Alice's data dir with a fresh local root.
wires --data-dir ./alice init --new-root
# → Generated local root pubkey: <ROOT_HEX>
# → Initialized at ./alice
# → Root pubkey: <ROOT_HEX>

# 2. Pair Alice's root with the host.
wires --data-dir ./alice host pair --ticket "$TICKET"
# → Paired with host <HOST_ID> (server_time=<MILLIS>)
# → Host info persisted to ./alice/config.toml

# 3. Create a topic. Auto-mints a self-cap because root.ed25519 is present.
wires --data-dir ./alice topic create home.notes
# → Created topic 'home.notes' with id <TOPIC_HEX>
# → Epoch key (share with peers via `wires pair-approve`): <EPOCH_HEX>
# → Minted self-cap: <ALICE_CAP_HEX>

# 4. Register the topic with the host so the host persists envelopes for it.
wires --data-dir ./alice host topic-register home.notes
# → Registered topic <TOPIC_HEX>

# 5. Check what the host reports for this tenant.
wires --data-dir ./alice host status
```

### Tab 3 — Bob, an invited agent

Bob is a second agent. Identity only — no root pubkey, no caps, no household awareness until Alice pairs him in.

```bash
# 1. Identity-only init. No root, no caps.
wires --data-dir ./bob init

# 2. Start a pair-listen window. Prints a PairRequest token and blocks
#    until Alice approves or the TTL (default 5 minutes) elapses.
wires --data-dir ./bob pair-listen \
  --role chat-agent \
  --description "Bob, a chat agent" \
  --request home.notes:read+write
# → Pair-listen window open for 300 seconds.
# → Share this token with the operator:
# → <BOB_TOKEN>
# → Waiting for pair-approve…
```

### Tab 2 again — Alice approves Bob

```bash
wires --data-dir ./alice pair-approve <BOB_TOKEN>
# → Pair request from agent <BOB_AGENT_HEX>
# →   role        : chat-agent
# →   description : Bob, a chat agent
# →   requested   :
# →     home.notes : read, write
# →   issued_at   : <MILLIS> (ms)
# →   expires_at  : <MILLIS> (Ns remaining)
# →   nonce       : <NONCE_HEX_PREFIX>...
# → Approve and grant? [y/N] y
# → Paired: cap <BOB_CAP_HEX> installed at <MILLIS> on agent <BOB_AGENT_HEX>
```

Bob's pair-listen exits with `Paired. Installed cap: <BOB_CAP_HEX>`. The grant carried Alice's root pubkey, the cap, the topic name and id, the current epoch key, and her host info — Bob is now a fully-onboarded household member.

Scope narrowing is available: `pair-approve --scope home.notes:read` to grant read-only, `pair-approve --topics home.notes` to whitelist a subset of requested topics, `pair-approve --no-host` to skip the host-info portion, `pair-approve --yes` to skip the confirmation prompt.

### Tab 3 again — Bob reads and Alice publishes

```bash
# Bob tails the topic. cat first replays any history the host has, then
# streams live events from gossip.
wires --data-dir ./bob cat home.notes --tail
# → (replay catch-up: N envelopes from host)
# → [waits for live events]
```

```bash
# Alice publishes from Tab 2. publish auto-dials the host (because
# config.toml has `host`), broadcasts over gossip, and writes locally.
wires --data-dir ./alice publish \
  --topic home.notes \
  --cap <ALICE_CAP_HEX> \
  --type agent.note \
  "hello from alice"
# → published seq=0 sender=<ALICE_AGENT_HEX> timestamp=<MILLIS>
```

Within a second or two Bob's `cat --tail` prints the message:

```
2026-05-15 14:42:01.234 <ALICE_AGENT_HEX_PREFIX> 0 | agent.note :: hello from alice
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

## Channels and DMs

Every paired agent gets the `channels.**` cap glob (Read+Write) by default,
so the channel surface is usable end-to-end once Alice has paired Bob via
`wires pair-approve`. Continuing the walkthrough:

```bash
# 1. Set your member metadata (kind/display-name/description). Persists to
#    me.json and is auto-attached to channels you join.
wires --data-dir ./alice me set --kind human --display-name "Alice"
wires --data-dir ./bob   me set --kind cli   --display-name "Bob's CLI"

# 2. Alice creates a named channel. A random topic_id + epoch key are
#    minted; the broad channels.** cap is auto-resolved for the publish.
wires --data-dir ./alice channel create coord --description "weekly grocery"
# → Created channel 'channels.coord' with id <TOPIC_HEX>

# 3. Alice invites Bob. This publishes a sealed __topic.history_grant
#    carrying the epoch key, then a public __channel.invite event.
wires --data-dir ./alice channel invite coord <BOB_AGENT_HEX>
# → Invited <BOB_AGENT_HEX> to channels.coord

# 4. Once Bob has replayed the channel from the host (any wires command
#    that joins the topic — `cat` works — drains pending envelopes), he
#    publishes his own __channel.member_meta to graduate from pending to
#    full member. `wires me set` already did this if his data dir had any
#    channels.* topics; otherwise re-running `wires me set` after replay
#    catches Bob up.

# 5. Inspect rosters.
wires --data-dir ./alice channel list           # channels alice is a full member of
wires --data-dir ./alice channel members coord  # full + pending roster

# 6. DMs. Topic_id and epoch key are derived deterministically from
#    sort(self, other, root_pubkey) via X25519 — no on-wire key exchange.
#    The lookup table is dm_roster.json, populated by `pair-approve` with
#    the requester's x25519 pubkey.
wires --data-dir ./alice dm open <BOB_AGENT_HEX> --message "hi bob"
wires --data-dir ./alice dm list
```

The MCP gateway exposes the same surface as tools: `wires_create_channel`,
`wires_list_channels`, `wires_channel_members`, `wires_invite_to_channel`,
`wires_dm_open`, `wires_set_member_meta` (see the MCP gateway section
below).

## Networking notes

- Transport is [iroh](https://www.iroh.computer) (`0.98`). Discovery uses iroh's N0 preset by default, plus mDNS on the LAN.
- Gossip runs over iroh-gossip on the topic id directly.
- Replay (catching up after downtime) uses a custom QUIC stream on ALPN `/wires/replay/0`.
- Tenant control (registration + topic register/unregister + status) uses ALPN `/wires/tenant/0` with length-prefixed JSON frames.
- Pairing (operator approving an agent) uses ALPN `/wires/pair/0` with a sealed, signed `PairGrant`.
- Host discovery is out-of-band: the host emits a base64 `HostTicket` on startup (and a terminal QR when stderr is a TTY) that carries the host's `endpoint_id`, direct addrs, and relay URL. Operators paste the ticket into `wires host pair --ticket <…>`; the `endpoint_id` is permanent while the addrs/relay are a short-TTL hint that iroh re-resolves as needed.

## Layout

```
crates/
  wires-core    pure types (WireMessage, Capability, content, sign/verify) + channel layer (ChannelView, derivation, replay fold)
  wires-crypto  AEAD (chacha20-poly1305), sealed-box (x25519), public envelopes
  wires-store   redb-backed hash-chained logs, cap table, epoch keys, ingest index
  wires-net     iroh gossip + replay protocol + tenant control protocol + pair protocol + host ticket
  wires-node    Node runtime (publish, inbound, sync, NetGlue, NodeRuntime) + channel I/O (open_named, open_dm, shared helpers for CLI/MCP)
  wires-cli     `wires` binary (init/host/topic/publish/cat/pair-* plus channel/dm/me)
  wires-host    `wires-host` multi-tenant relay (lib + bin: tenant registry, retention, routing, host-ticket emission)
  wires-ha      `wires-ha` Home Assistant ingestion daemon
  wires-mcp     `wires-mcp` authenticated MCP gateway (lib + bin: OAuth 2.1, per-user NodeRuntime, MCP tools)
docs/superpowers/
  specs/        design docs (substrate, hosted-service, iOS companion)
  plans/        implementation plans
```

## MCP gateway

`wires-mcp` exposes a small authenticated MCP surface so AI-agent clients
(Claude Desktop, Cursor, VS Code, etc.) can act on a household's behalf.
It pairs into each household as a normal wires agent — `wires-host`'s
blindness contract is unchanged.

### Operator walkthrough (running directly)

```bash
# 1. Generate a config.
cat >/etc/wires-mcp/config.toml <<EOF
public_url = "https://mcp.example.com"
bind = "127.0.0.1:3001"
data_dir = "/var/lib/wires-mcp"

# Optional. Defaults: ttl_secs = 3600 (1 h), max_bytes_per_user = 52428800 (50 MiB).
# ttl_secs must be > 0; max_bytes_per_user = 0 disables the byte cap.
# [retention]
# ttl_secs = 3600
# max_bytes_per_user = 52428800
EOF

# 2. Run the service.
wires-mcp serve

# 3. List onboarded users.
wires-mcp user-list

# 4. Remove a user (e.g. household-side cap was revoked).
wires-mcp user-delete <root_pubkey_hex>
```

Operators must put a TLS-terminating reverse proxy (nginx, caddy, etc.) in
front of `wires-mcp`; the binary speaks plain HTTP and assumes a trusted
upstream for TLS.

### Operator walkthrough (Docker + Tailscale Funnel)

> **Temporary.** This Docker + Funnel setup is a placeholder so we can dogfood
> the gateway against a real public HTTPS URL. The eventual alpha hosting
> story hasn't been chosen yet — expect this section to be replaced.

The current reference deploy packages `wires-host` and `wires-mcp` as a
two-service Docker Compose stack with Tailscale Funnel providing public
HTTPS. See [`docker/README.md`](docker/README.md) for the full walkthrough;
the short version:

```bash
# One-time per host: seed the wires-mcp config (edit public_url).
cp docker/wires-mcp.toml.example docker/wires-mcp.toml
${EDITOR:-nano} docker/wires-mcp.toml

# Build, start, and verify both services.
./docker/deploy.sh

# Publish both via Tailscale Funnel (wires-host on :10000, wires-mcp on :443).
./docker/funnel.sh up all
```

Subsequent rollouts: `git push origin main && ssh <host> ./docker/deploy.sh`.
The named volumes `wires-host-data` and `wires-mcp-data` carry iroh secrets,
tenant state, the gateway JWT signing key, and per-user agent data through
container recreates, so the host's `EndpointId` and the gateway's JWT
issuer survive rollouts.

### User walkthrough (from the user's perspective)

1. Add the MCP server URL `https://mcp.example.com` to your MCP client.
2. The client opens the gateway's `/oauth/authorize` page in a browser.
3. Two QR codes appear. First-time users scan the **left** one with the
   Wires iOS app and approve a new "MCP gateway" agent like any other agent.
   Returning users scan the **right** one to authenticate with their root
   key.
4. The browser redirects back; the MCP client now has an access token
   bound to the user's household root pubkey.
5. The client can call MCP tools against the user's agent's caps:
   - **Substrate:** `wires_list_topics`, `wires_publish`, `wires_tail`.
   - **Channels:** `wires_list_channels`, `wires_create_channel`,
     `wires_channel_members`, `wires_invite_to_channel`,
     `wires_dm_open`, `wires_set_member_meta`.

### Known limitations (v1)

- `keys rotate` archives the old key but doesn't keep it in JWKS for an
  overlap window — existing access tokens become unverifiable on the next
  process restart. Wait out access-token TTL before restarting after a
  rotation.
- A user's topic set is fixed at pair time. To grant a paired gateway
  agent access to a new topic, `__cap.revoke` the existing cap and re-pair
  (the substrate's gossip-borne `__cap.grant` distribution is not yet
  implemented).
- Per-MCP-client distinction lives in logs only, not on the wires bus.
- The end-to-end acceptance test (`tests/end_to_end.rs`, marked `#[ignore]`)
  is a structural scaffold; filling in the test body requires factoring
  the pair-approve helper out of `wires-cli` and is tracked separately.
- DMs are operator-initiated only. `PairGrant` doesn't yet carry the
  operator's x25519 pubkey, so a paired agent's `dm_roster.json` knows
  every requester it has approved but doesn't know the operator. The
  operator can `wires dm open <agent>` outbound; the reverse direction
  needs a PairGrant extension.

## License

MIT OR Apache-2.0

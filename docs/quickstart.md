# Quick start

End-to-end walkthrough of the wires substrate on one machine, in four
terminals. Builds on top of the [project README](../README.md) — make
sure you've run `cargo build --release` and that `wires` and
`wires-host` are on your `$PATH` (e.g. via
`cargo install --path crates/wires-cli` and
`cargo install --path crates/wires-host`).

We use four data directories: `./host`, `./alice`, `./bob`, and (later,
for observation) a copy of `./bob`.

## Tab 1 — `wires-host`

```bash
mkdir -p ./host
RUST_LOG=info wires-host --data-dir ./host
# → wires-host: EndpointId = <HOST_ID>
# → INFO wires_host: host ticket: <TICKET_BASE64>
# → wires-host: running. Press Ctrl-C to exit.
```

Leave it running for the rest of the walkthrough. The `host ticket: …`
line is a base64-encoded `HostTicket` that agents need to pair with this
host; you can also fetch it from a separate shell at any time with
`wires-host --data-dir ./host ticket --no-qr` (prints base64 to stdout).
Running `wires-host` with stderr attached to a TTY additionally emits a
scannable QR of the same ticket; pass `--no-qr` to suppress it.

## Tab 2 — Alice, the operator

Alice is the root-key holder for this fabric. Capture the host ticket
first (Tab 1 must already be running):

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

# 5. Check what the host reports for this fabric.
wires --data-dir ./alice host status
```

## Tab 3 — Bob, an invited agent

Bob is a second agent. Identity only — no root pubkey, no caps, no
fabric awareness until Alice pairs him in.

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

## Tab 2 again — Alice approves Bob

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

Bob's pair-listen exits with `Paired. Installed cap: <BOB_CAP_HEX>`.
The grant carried Alice's root pubkey, the cap, the topic name and id,
the current epoch key, and her host info — Bob is now a fully-onboarded
fabric member.

Scope narrowing is available:
`pair-approve --scope home.notes:read` to grant read-only,
`pair-approve --topics home.notes` to whitelist a subset of requested
topics, `pair-approve --no-host` to skip the host-info portion,
`pair-approve --yes` to skip the confirmation prompt.

## Tab 3 again — Bob reads and Alice publishes

```bash
# Bob tails the topic. `cat` first replays any history the host has, then
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
# iroh.secret  fabrics.redb  topic_index.redb  nonces.redb  fabrics/

ls ./host/fabrics
# <root_pubkey_hex>/        ← one directory per registered fabric

ls ./host/fabrics/<ROOT_HEX>
# log_<TOPIC_HEX>.redb      ← per-topic ciphertext log
# ingest_<ROOT_HEX>.redb    ← per-fabric FIFO eviction index
```

The host has zero per-fabric secrets — no caps, no epoch keys. Verify
with `ls`: you'll see only the four host-level redb files plus a
per-fabric subdir of opaque ciphertext logs. The host literally cannot
decrypt the content.

### Fabric status from the operator's side

```bash
wires --data-dir ./alice host status
```

Re-run after publishing a few messages — `bytes_stored` will grow,
`topic_count` reflects registered topics, and `oldest_retained_at`
advances forward as the retention budget evicts.

### Inspect on-disk per-fabric size

```bash
du -h ./host/fabrics/<ROOT_HEX>
```

This is what a hosted-service operator would graph per fabric.

## Resilience: kill the host and watch replay catch up

1. In Tab 2, publish several more messages over a few seconds.
2. In Tab 1, `Ctrl-C` the host.
3. In Tab 2, publish a few more — these go peer-to-peer (Alice + Bob
   still see each other via gossip) but are NOT persisted by the host
   because it's down.
4. Restart Tab 1: `wires-host --data-dir ./host`. The host reloads its
   `fabrics.redb` and `topic_index.redb`, re-subscribes to every
   previously-registered topic.
5. In a fresh Tab 4, run a "cold" Bob — copy `./bob` to `./bob2`, then
   `wires --data-dir ./bob2 cat home.notes`. The replay client pulls
   every message the host retains, and Bob2 sees everything published
   while the host was alive. Messages published while the host was down
   are visible to live Bob (via gossip) but not to cold Bob2 (because
   they were never persisted) — exactly the substrate's hash-chained
   "gap detection" property.

## Other useful commands

```bash
wires --data-dir ./alice host topic-unregister home.notes  # host stops persisting new envelopes
wires --data-dir ./alice revoke <CAP_HEX>                  # tomb a cap (substrate v1 — no gossip propagation yet)
wires --data-dir ./alice cat home.notes                    # no --tail: print local log and exit
```

## Channels and DMs

Every paired agent gets the `channels.**` cap glob (Read+Write) by
default, so the channel surface is usable end-to-end once Alice has
paired Bob via `wires pair-approve`. Continuing the walkthrough:

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
`wires_dm_open`, `wires_set_member_meta`. See
[`mcp-gateway.md`](mcp-gateway.md) for the gateway walkthrough.

## Networking notes

- Transport is [iroh](https://www.iroh.computer) (`0.98`). Discovery
  uses iroh's N0 preset by default, plus mDNS on the LAN.
- Gossip runs over iroh-gossip on the topic id directly.
- Replay (catching up after downtime) uses a custom QUIC stream on
  ALPN `/wires/replay/0`.
- Fabric control (registration + topic register/unregister + status)
  uses ALPN `/wires/fabric/0` with length-prefixed JSON frames.
- Pairing (operator approving an agent) uses ALPN `/wires/pair/0` with
  a sealed, signed `PairGrant`.
- Host discovery is out-of-band: the host emits a base64 `HostTicket`
  on startup (and a terminal QR when stderr is a TTY) that carries the
  host's `endpoint_id`, direct addrs, and relay URL. Operators paste
  the ticket into `wires host pair --ticket <…>`; the `endpoint_id` is
  permanent while the addrs/relay are a short-TTL hint that iroh
  re-resolves as needed.

# 15 — The channel is the directory: how a caller finds a host's key

**Lane:** D2 · **Depends on:** 12 (13 for the tool list source) · **Files:** `ChannelRecord::Host` in `library/channel/record.rs`, host announce in `wires/host/`, `wires/caller/tools.rs` resolution, `wires tools`

## Why

The human's question: *how does a client get the key in the first place?* Today,
by hand: someone copies a node id or ticket into `wires tools add`. The channel
already carries identity claims (who is who) and call records (who did what). It
should also carry **who serves what**, so joining the channel is the only thing
handed out of band (the invite from card 14).

## Design

- `ChannelRecord::Host { node, tools: [{ name, description }], at_ms }` (serde-default fields; the sender must equal `node`, the same rule as identity claims). A host publishes it at startup, when `host.json` changes, and every N minutes as a heartbeat (default 10).
- Caller: `wires tools` lists the tools announced on the channels it has joined: `db_query  on eacc34e0 (workbench)  Read-only SQL …`, marking stale hosts (no heartbeat within 3N).
- `wires call db_query -- …` resolves by name through the latest announcement; a name served by several hosts is ambiguous → error listing `host8/db_query` forms, and `wires call eacc34e0/db_query` picks one. `wires mcp` exposes the same set.
- Where the caller reads announcements: a resident `watch` keeps the store fresh; a cold `call`/`mcp` does a bounded catch-up from the join bootstrap peers (≤ 2 s), then uses the local store. Cache the resolved node + addresses in `tools.json`, which becomes a **cache and alias file**, never a required hand-written config.
- The admin's invite (card 14) is the only out-of-band artifact. Say this plainly in the README: *one invite, then everything (hosts, tools, identities, calls) is on the channel.*

## Visibility (the human, 2026-09-23): tools are visible only to those who can use them

- Seal each tool's announcement to exactly the members whose **verified** principal grants a role for it under the host's policy (reuse the per-recipient sealing of `SealedFabricKey`; the record can carry one sealed entry per allowed member). Everyone else sees only that a host announcement exists, not what's in it.
- When a new identity claim arrives on the channel and qualifies, re-announce so it's included. When someone loses access (a claim expires, or they're removed), the next announcement leaves them out.
- This is privacy, not security: the host still enforces on every call. `wires tools` shows only what you can use; a call to a tool you can't see still gets a proper denial.

## Acceptance

- [x] e2e: an analyst sees `db_query` in `wires tools`; an authenticated non-analyst doesn't see it, and calling it by name is denied with a reason.
- [x] e2e: host announces → a fresh caller that has only joined can `wires tools` and `wires call db_query` with no manual configuration; two hosts with the same tool → ambiguity error, then qualified call works; a host that stops → shown as stale.
- [x] `demo-remote-cli.sh` drops `tools add` entirely.
- [x] `bazel test //...`, lint, format check green.

## Notes

*2026-09-23, lane D2 (worker).* Commits: library (`HostAnnouncement`,
shared sealing) → merge of `aaron/remote-cli` (card 14) → host (announcer)
→ caller (directory + resolution, `wires tools`, call/mcp hooks) → demo →
docs/board.

### The record (`ChannelRecord::Host`, `library/channel/announce.rs`)

```json
{"wires":"record/v1","record":{"type":"host",
  "node":"<host node id hex>",           // must equal the envelope's sender
  "at_ms":1790139601602,                 // sender clock, ms
  "heartbeat_ms":600000,                 // stale after 3× this
  "open":{"tools":[{"name":"status","description":"…"}],   // what EVERY member may run
          "addrs":["127.0.0.1:58333",…],"relay_url":"…"},   // dial hints
  "sealed":["<hex blob>",…]}}            // one anonymous entry per member allowed more
```

A sealed entry is `ephemeral_x25519_pub(32) ‖ ChaCha20-Poly1305(ct+tag)` of a
`HostListing` JSON (`{tools, addrs, relay_url}`) space-padded to a multiple of
256 bytes. It is the `SealedFabricKey` construction, extracted from
`fabric_key.rs` as `seal_box`/`open_box` (crate-private, context-parameterized;
the fabric key's bytes and known-answer tests are unchanged) under its own
frozen context `"wires sealed-announcement v1"`; the AAD is canonical
`{format:1, host, at_ms}`, so an entry can't be lifted into another host's
announcement or an older one. Entries carry **no recipient id** and are
shuffled: a reader trial-opens each (one X25519 per entry).

### Who sees what (`wires/host/announce.rs`)

`Policy` gained `member_tools()` (default: none; `RoleTable`: tools whose
`allow` lists `member`) — those go in `open`, i.e. to the whole channel, which
is already encrypted to exactly the roster. For each node in the host's
identity index with a **fresh verified** principal (`IdentityGate::resolve`),
`allowed_tools(Some(p), node)` minus the open ones is sealed to that node; a
member with nothing further gets no entry. The `open` listing is always
present because it carries the dial hints (see the security note).

The announcer publishes through the tail loop's queue (one allocator) at
start, when the audience changes (`Identities` now signals principal changes
via a `Notify`; 150 ms debounce), when the host's newest fabric key changes
(polled each second — every `invite`/`remove` is a commit, and a member who
joined after the last announcement holds no key for it: late joiners never
read pre-join history), and on the heartbeat (10 min;
`WIRES_ANNOUNCE_HEARTBEAT_SECS` overrides, undocumented). An expired claim
drops out at the next heartbeat; a removed member drops out of the channel
key.

### The caller (`wires/caller/resolve.rs`)

- Cache: `$WIRES_HOME/directory.json` (`{channel, hosts:[{node, at_ms,
  heartbeat_ms, listing}]}`) — **not** `tools.json` (deviation: keeping the
  `ToolsConfig` struct that lane 19's code and tests construct unchanged).
  `tools.json` is now aliases only; an alias wins over the directory.
- Channel + bootstrap peers come from card 14's `join` (`channel.json` +
  the peer book) via `TopicContext::resolve` with an empty topic — no
  `--peer`, no ticket.
- Cold refresh (`refresh_on`, ≤ 2 s): fold the local log; join with the
  book's peers; one replay catch-up (adopting any re-key it missed first,
  then re-folding); then live messages until the name resolves. If a
  resident `wires watch` holds the log's redb lock, use the cache that watch
  keeps (`DirectoryHook` in the `Printer`, plus a full-log prime at start).
- `wires call X`: alias → cached directory (if X is listed by a live host,
  no network) → refresh → resolve. Rules: `host8/X` picks by id prefix; one
  live host listing X wins; several → `` `X` is served by 2 hosts; pick one:
  eacc34e0/X, 1234abcd/X ``; stale hosts only when no live one lists it; X
  listed to nobody **but exactly one host known → dial it anyway** (the host
  answers, or refuses with its reason — this is how a non-analyst gets
  `identity bob@other.org (from …) is in no role allowed to run db_query`).
- `wires mcp`: aliases + every visible tool of live hosts, computed once at
  startup; a name several hosts serve becomes `name-host8` (MCP names can't
  hold `/`), with `remote_tool` = the real name.
- `wires tools` (no subcommand): refresh, then `name  on host8[ (stale: last
  announced 12m ago)]  description`, then aliases; on stderr, `N host(s) on
  channel "ops" announce(s) nothing you may use: host8`. `add/list/rm` stay
  for aliases (`ToolsArgs.cmd` is now `Option`).

Sample, from the demo (analyst, then non-analyst):

```
$ wires tools            # alice@example.com, role analyst
db_query  on 21a41745  Read-only SQL (sqlite3) over the workbench's orders.db; …
$ wires tools            # bob@other.org, verified, no role
wires tools: 1 host on channel "ops" announces nothing you may use: 21a41745
$ wires call db_query -- 'select 1'     # exit 77
wires: denied by responder: identity bob@other.org (from http://127.0.0.1:60273) is in no role allowed to run db_query: analyst (email=*@example.com)
```

### Security note: what a non-allowed member still learns

It holds the channel key, so it reads the record's plaintext frame: **that the
host announced, from which node id, when (`at_ms`) and how often
(`heartbeat_ms`)**, the **number of sealed entries** (≈ how many members may
use more than the open tools) and **their sizes** (bucketed to 256 bytes, so
roughly how many tools each lists), the **open listing** (tools every member
may run anyway) and the **host's dial hints** (no secret from a member: the
host is its channel's bootstrap peer and in every invite's ticket). It does
not learn which tools are gated, their names or descriptions, or *who* the
entries are for (no recipient ids; shuffled; fresh ephemeral per entry).
Re-announcement timing leaks that *someone's* audience changed right after a
login. This is privacy, not access control: the host decides every call.
Non-members see nothing (channel encryption). A removed member keeps what it
already read; the next announcement goes out under the rotated key.

### Off-lane touches

- `library/membership/fabric_key.rs`: `seal_box`/`open_box` extracted
  (behavior-preserving; `cipher_for` takes the context).
- `wires/host/policy.rs` (`member_tools`), `identity.rs` (`changed()`,
  `nodes()`), `config.rs` (`descriptions()`), `audit.rs` (`Hosted.announcer`),
  `serve.rs` (builds the announcer).
- `wires/channel/watch.rs` (spawn/abort the announcer; `DirectoryHook`),
  `printer.rs` (`Printer.directory`, `Keyring.quiet`), `render.rs`
  (`📣 announces tools (open: status; 2 sealed entries)`).
- `wires/caller/call.rs`, `mcp.rs`: one line each (name resolution only).
- `wires/caller/mock_idp.rs`: honors `login_hint` (the demo signs the
  observer in as `bob@other.org`).
- `wires/main.rs`: help text for call/tools/mcp; `wires tools` runs async;
  `QUIET_LOG_FILTER` adds `wires::channel=error` (a cold call's directory
  node must not write mesh chatter to the remote CLI's stderr).
- `wires/e2e/onboard.rs`: fixtures made `pub(super)` for `e2e/directory.rs`.
- Demo: step 3 `wires tools` before login (host seen, no tools) replaces
  `tools add`; step 4 asserts the analyst now sees `db_query`; new step 4b:
  the observer logs in as `bob@other.org` and sees nothing, and `wires call
  db_query` exits 77 with the role reason. No provisioning lines touched.
- README: Quickstart step 4 ("one invite, then everything is on the
  channel"), command table, reachability bullet.

### Not done / follow-ups

- Members without a claim who never spoke are covered by `open`; a policy
  whose member-level tools depend on the caller node would need them sealed
  per node, and the host only knows nodes it has seen claims from.
- `wires mcp` computes its tool list once; `notifications/tools/list_changed`
  on a new announcement is a follow-up.
- Host labels (`on eacc34e0 (workbench)`): no name in the record yet; a
  `host.json` `"name"` in the open listing would do it.

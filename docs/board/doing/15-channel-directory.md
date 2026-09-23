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

- [ ] e2e: an analyst sees `db_query` in `wires tools`; an authenticated non-analyst doesn't see it, and calling it by name is denied with a reason.
- [ ] e2e: host announces → a fresh caller that has only joined can `wires tools` and `wires call db_query` with no manual configuration; two hosts with the same tool → ambiguity error, then qualified call works; a host that stops → shown as stale.
- [ ] `demo-remote-cli.sh` drops `tools add` entirely.
- [ ] `bazel test //...`, lint, format check green.

## Notes

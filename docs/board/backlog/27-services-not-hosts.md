# 27 — Services, not hosts; drop the channel

**Lane:** S3 · **Depends on:** 25 merged · **Blocks:** 26, the recording · **Decides:** [card 22](../done/22-gossip-role-OPEN.md) · **Files:** repo-wide (`library/`, `wires/`, demo scripts, README, CLAUDE.md, executive summary)

## Why (the human, 2026-09-23)

The requirements are: **only users authorized for a service can call it**, and
**users can list the services available to them**. The channel (gossip mesh,
fabric keys, re-keys, sealed announcements, replay, admission, broadcast
identity claims and records) does neither; it's a leftover of the "group chat
for agents" idea and is about 20k of 47k Rust lines. And *"the user shouldn't
care which host it's on, they should care what service they're calling."*

## The model

- **Service**: what people and agents address by name (`orders-db`, `deploy`). It has a name, a description, allowed roles, and the hosts that implement it.
- **Host**: where a service runs. Invisible to callers unless they ask (`--verbose`). A service can have several hosts (failover); moving it changes nothing for callers.
- **Admin-signed state** (one versioned, root-signed document, extending today's roster): the **members** (node ids), which members are **hosts**, the **service registry** (`name → { description, allow: [roles], hosts: [node ids] }`), and the **role definitions** (the matcher table from card 13, moved here). Only the admin can bind a name to a host, which closes tool-name squatting.
- **`host.json` shrinks** to "how I implement the services I'm assigned": `{ "version": 2, "services": { "orders-db": { "command": [...], "cwd": ..., "env": ... } } }` plus local trust settings (IdP issuers/audiences). A host may add **stricter** local rules (`"also_require": [...]`), never looser. It refuses to serve a name the registry doesn't assign to it.
- **Naming:** "tools" becomes **"services"** in the CLI and docs: `wires services` (list), `wires call <service> -- …`, `wires watch <service>`. `wires mcp` exposes each service as an MCP tool (compatibility only).

## Flows

1. **Distribution:** `wires join` delivers the current signed state. When it changes (`invite`, `remove`, `wires service add|rm|set` on the admin), the admin **pushes** it by key to every member (reuse card 23's direct dial plus queue), and members also **pull** it from the admin, or from any host that holds a newer copy, on a cold command if it's older than N minutes. Verify root signature and monotonic version; never accept older.
2. **Listing:** `wires services` evaluates the caller's verified identity against the registry **locally**: no network, no broadcast. It shows name, description, and why it's allowed (role). Services you can't use are not shown.
3. **Calling:** resolve name → one of its hosts (prefer reachable/last-good; try the next on dial failure). Dial by key and present in the handshake the membership, the signed-state version, and the IdP ID token (nonce-bound, as now). The host checks, in order: member of the current signed state → the registry allows this caller's role for this service → any stricter local rule → run. The refusal reasons stay precise.
4. **Identity:** the ID token travels in the handshake; `wires login` just stores it locally (no `--topic`). Hosts verify with the JWKS fetcher as today.
5. **Removal:** `wires remove` bumps the signed state and pushes it to hosts first. A removed member is refused on its next call. There is no key rotation to do, because there is no shared encryption key any more.
6. **Push (card 23):** unchanged in spirit. Hosts push by key; `wires inbox` fetches from the hosts of the services you use. Authorization uses the registry.
7. **Records:** leave the channel (card 26, reworded per service).

## Delete

The gossip mesh and topic node; `library/channel/*` (topic, envelope, chain, admission, replay, record's channel use, announce); `wires/channel/*` except what `watch`/`inbox` still need; fabric keys and sealed keys; Rekey and the proof directory; sealed host announcements and the directory cache (`directory.json`); broadcast identity claims; the committed-roster Merkle privacy **if** nothing still needs inclusion proofs (a signed member list suffices; record the reasoning). Plumbing under `wires advanced` that only served these.

## Parallel plan (integrator)

1. **27.0 types first (one worker, short):** the signed-state document (members, hosts, roles, service registry) with signature/versioning/verification in `library`, the handshake change (membership + state version + ID token), and the `host.json` v2 shape, as compiling stubs with docs, plus tests red.
2. Then fan out in parallel:
   - **27a distribution:** admin commands (`service add|rm|set`, `invite`/`remove` bump state), push/pull of signed state, `join` delivering it.
   - **27b caller:** `wires services` (local evaluation), name → host resolution with failover, identity in the handshake, `mcp` over services, `login` without `--topic`.
   - **27c host:** registry-driven authorization plus stricter local rules, refusing unassigned names, inbox/push authorization from the registry.
   - **27d delete + docs:** remove the channel machinery once a/b/c no longer use it; rewrite the demos, README, `docs/demo.md`, the executive summary and CLAUDE.md.

## Acceptance

- [ ] e2e: Alice (analyst) sees `orders-db` in `wires services` and can call it; Bob (not analyst) sees nothing and is refused by name; two hosts implement `orders-db` and a call succeeds with one of them down; a non-host member can't serve `orders-db` (the host refuses to start, and callers never resolve to it); `remove alice` → her next call is refused, with no restart; `wires inbox` push still works.
- [ ] Nothing is broadcast: a member who makes no calls receives no traffic about others' calls or services (measure it).
- [ ] `demo-remote-cli.sh` and the push demo rewritten for services; README, `docs/demo.md`, `docs/executive-summary.md` and CLAUDE.md updated (roles table, "where each guarantee lives"). Record the before/after LOC in Notes.
- [ ] Tests, clippy, fmt green (Cargo).

## Notes

# 31 — Inbox: callbacks to the caller that asked, in every client (CLI and MCP)

**Lane:** P3 · **Depends on:** 28 (steps 1–2), 30 · **Status:** **parked
2026-09-24**: three open questions below (§ Parked), the last with no good
answer yet. No push code has moved · **Files:** `wires/host/push.rs`,
`wires/host/gate.rs` (push decisions), `wires/host/control.rs`,
`wires/caller/inbox.rs`, `wires/caller/mcp.rs`, `wires/gateway/`,
`library/calls/push.rs`, protocol.md §7, usage, README

## Parked (2026-09-24)

Planning the build against the code turned up three places where D1–D6 and
the code don't meet. The human parked the card on the third: "this last
question means we should probably park card 31 until we have a better
answer."

1. **Stranding of operator pushes (D1b/D3).** "Refuse at send unless the
   recipient may call a service here" needs the recipient's principal. A host
   knows only the *last* principal a node presented, and the gateway presents
   many from one node. Candidate: `wires inbox` (and the gateway) fetch from
   **every host in the signed state**, so an operator push needs only "a
   current member" and nothing can strand. That also removes D3's
   "service moved hosts" caveat. Cost: more fan-out, and any admin-named host
   can leave a note in any member's mailbox.
2. **Direct dial vs D1 (D6).** A direct delivery that honors D1 needs the
   receiver to present its ID token back to the host (the gateway: one token
   per live user). Candidate: drop the dial and the caller's inbox receiver.
   "Listening" becomes an open long poll, which the host already answers the
   moment a push is queued. That leaves one delivery path (a fetch, with the
   caller's token), and the caller exposes no inbound ALPN.
3. **Who sees the MCP `inbox` tool (open, the blocker).** The card says the tool
   appears "only for callers with a service that calls back (`"push": true`)".
   But `push: true` lives in the host's `host.json`, which a caller never sees,
   so a caller can't know which of its services call back. The options on the
   table were "always list it" (every MCP user pays for a tool that may never
   return anything) and "a `callbacks` flag on the registry's Service" (the
   admin declares it, and the signed-state format changes). Neither is
   convincing. The deeper question is whether "this service calls back" is a
   property of the service (the registry's) or of an implementation (the
   host's), and what a caller should be told before it calls.

## Why (the human, 2026-09-24)

"I don't feel like the delivery semantics for the inbox are fully fleshed
out. Is it at most once? At least once? Does it deliver to all? What happens
when something is listening? Does it queue?" An MCP client should also be
able to poll the server for its inbox, so callbacks work in the clients
people already use (card 30's stance).

On who gets a push: "the nature of these callbacks are specific to the
caller. I'm triggering a deploy and I want a callback when the deploy is
complete. It should go to the agent, the machine, that initiated that first
call, not to everyone, because that message may be meaningless to all the
other nodes."

## Today, precisely

A host queues a message for one **node key**. It leaves the queue only when
the recipient acknowledges it.

| | Behavior | Designed or accidental |
|---|---|---|
| Host → mailbox | At least once: resend until `ack`; the receiver drops ids it has seen (unread + last 1024 read) | Designed |
| Mailbox → reader | At most once: `take_unread` renames to `read/` *before* printing | Accidental |
| Listening receiver | The host dials at send (3 s); only `wires inbox --wait` accepts | Designed |
| Nobody listening | Queued (survives restart), TTL 24 h (≤ 7 d), fetched by the next `wires inbox` (long poll ≤ 25 s) | Designed |
| "To all" | `--to <role>` fans out at send to one copy per **node** whose principal this host has *already seen* | Accidental (per-node index) |
| Which hosts a fetch asks | Hosts of services the caller may call | Accidental |
| Loss | Host drops oldest past 64 per recipient; mailbox evicts past 256 unread; both logged or noted | Designed, but invisible to the reader |
| Two readers, one node | Each message goes to one of them (rename race) | Accidental |

**The four problems:**
- **(a) Stranding.** A host can queue for you under `push.allow` while serving you no service. A fetch never asks it, so the message dies at TTL unless a `--wait` is running when the host dials.
- **(b) A node alone isn't the caller.** Queues are per key, and the gateway (one node, many people) mixes users. The caller is a node *and* the person it presented.
- **(c) Role push reaches only principals the host has seen** since it started.
- **(d) Reading consumes,** and it marks read before printing, so a crash loses the message.

## Proposal (decisions for the human, each with a recommendation)

The principle: **a push is a callback, and a callback belongs to the caller
that asked for it.** It means something to the agent, on the machine, that
started the work, and to nobody else. Not to every device the person owns,
and not to everyone in a role.

### D1. A push answers a call, and goes to that call's caller

- Every push is sent through a **call's** push capability (card 28 L2a: `serve` gives each call's child a token that can push only to that call's caller). It is addressed to that caller: the dialing **node** *and* the verified **principal** it presented.
- A host delivers it only to a presenter that is that node **and** whose token verifies to that principal. For a CLI agent, that is exactly the agent that made the call. Through the gateway (one node, many people), node = the gateway and principal = the web user, so it reaches exactly that user.
- The message carries the **call id and service** it answers, so the agent can match it to what it started ("deploy #41, called 14:02: done").
- **No fan-out** to the person's other devices, and **no role or broadcast addressing**, for anyone.

### D1b. The host operator can still push to one machine

The human (2026-09-24): "Agree, keep operator push."

- The operator socket keeps `wires push --to <node-id>`: a node id only, no roles, no broadcast. It is a separate path from call callbacks, for a person running the host who wants to tell a particular machine something.
- It goes to that **node's** mailbox and is not tied to a principal, because the operator is addressing a machine. It still passes the recipient-is-a-current-member check, and it names no call or service (the reader shows `operator push` instead).
- **The gateway is an ordinary node here; no special case.** An operator push to its node id lands in the gateway node's own mailbox, and whoever runs the gateway reads it with `wires inbox` against the gateway's keystore. Web users never see it: they read only the callbacks addressed to their (gateway node, principal), through the MCP `inbox` tool (D4).
- For D3: an operator push can only come from a host of a service the recipient may call. A push from any other host is refused at send, so it can't strand.
- This removes (b), and (c) entirely: a host never enumerates who is in a role, because it only answers a caller it has already verified. **Recommend.**

### D2. At least once to the caller's mailbox; removed on its ack

- **At least once** from host to mailbox. The host keeps a push until **that** caller acks it: resent on each fetch or direct dial, deduplicated by `(from, id)`.
- Then it's gone from the host. There is exactly one recipient, so no per-device tracking is needed.
- The *capability* lives for the call plus a grace period (10 min today). The *message* lives until TTL (24 h default, ≤ 7 d), so a callback sent an hour into a deploy can still be fetched the next day.
  - Open question: should the grace period be settable per service, for long jobs? **Recommend per-service in `host.json`, default 10 min.**
- **Caveat: a next-day fetch needs a fresh sign-in, for now.** Delivery requires a token that verifies to the calling principal, and Google tokens last about an hour. So fetching a callback after that needs a new `wires login`, until card 29's day-pass exists. The gateway has the same limit: a web user reconnects, then calls `inbox`.

### D3. Pushes come only from hosts of services you called, so a fetch finds them all

- A capability belongs to a call of a service the caller was allowed to call. So today's fetch set, "hosts of services I may call", contains every host that can hold a push for me **by construction**: (a) can't happen.
  - One edge case: a caller removed from the service after the call. Its pending pushes are dropped, logged as `denied`.
  - **Caveat: a service that moves hosts strands the callbacks queued on its old host.** The caller stops fetching from a host that no longer serves anything it may call. Accepted for now. The admin moving a service should let the old host run until its queues drain or expire.
- `push.allow` in `host.json` becomes a per-service switch (`"push": true` on the services that call back). Who receives is decided by D1: the caller, already admitted to that service.
- This also covers card 28 §7's receiver rule: accept `deliver` only from hosts of services this node may call, with a fresh state.

### D4. The mailbox belongs to the caller: one reader, read once, crash-safe

- The local mailbox stays single-reader (read = consume), stated as such.
- Fix the accidental ordering: print, **then** mark read, so a crash re-shows a message instead of losing it. End to end that's at least once, with duplicates suppressed by id.
- The gateway keeps one mailbox **per principal**: each web user's callbacks are theirs alone.

### D5. Order and loss are stated, and loss is visible

- **Order:** FIFO per (host, caller); nothing across hosts. Each message carries its host, service, call and `at_ms`.
- **Caps:** per caller *per call* at the host (a chatty job can't crowd out other calls' callbacks), oldest dropped. Per-sender caps in the mailbox; evict by local receive time. These are card 28 §7's fixes, moved here.
- **Loss is visible:** `deliver` carries `dropped: n` since the last ack, and the reader prints it. When the state advances, a removed member's queue is purged (card 28 §7).

### D6. Listening vs not listening stays as it is

If the caller has a live receiver (`wires inbox --wait`, or the gateway serving that web user), the host dials it at push time. Otherwise the push waits for the caller's next fetch (long poll ≤ 25 s).

## The MCP inbox

One tool, the same everywhere: **`inbox`**, `{ wait_seconds?: 0–25, limit?: 1–32 }`.

- It returns unread callbacks, oldest first, as text lines (`<time>  from host <id> (verified)  <service> call <call-id>  <subject>  <body>`), plus `structuredContent`. It marks them read.
- With `wait_seconds`, it long-polls first. The cap is 25 s, under Cloudflare's 100 s proxy timeout.
- **`wires mcp` (stdio):** the tool is `wires inbox --json`, fetching as this node.
- **`wires gateway`:** the gateway fetches from the hosts of the user's services, presenting **that user's** token.
  - Hosts return the callbacks for calls this user made through the gateway (node = gateway, principal = user).
  - The gateway acks, then holds them in that user's mailbox until the tool returns them.
  - To the model this is at most once: MCP has no ack, so a lost HTTP response loses what it carried. The alternative is an explicit `inbox_ack(ids)` tool. **Recommend no ack tool** (simpler), with the loss stated in the tool description.
- **Later, only if clients use it:** a `wires://inbox` resource with `notifications/resources/updated` on `subscriptions/listen`, so a client knows when to call `inbox`. Unverified whether Claude.ai subscribes; the tool alone is enough.
- The tool appears only for callers with a service that calls back (`"push": true`).

## Replaces in card 28 (drop these there; nobody builds push twice)

- **§4:**
  - "Push and fetch decide on the token presented in that exchange" → D1.
  - "Queue entries carry the admitted principal and are delivered only to a presenter whose token verifies to it" → D1 (the caller is node + principal).
  - (§4's "mine by principal" for `watch` stays in card 28.)
- **§7, all of it:**
  - receiver accepts `deliver` only from hosts of services it may call, plus a fresh state → D3;
  - `--to` limited to allowed roles, with counts not names → **moot**: D1 removes role addressing, and D1b keeps only `--to <node-id>`;
  - per-sender mailbox caps, evict by receive time, dedup by `(from, id)`, host cap per originating service → D5 (the host cap becomes per call);
  - purge a removed member's queue when the state advances → D5.
- **Kept from card 28 as built:** the per-call push capability (L2a), the only way a *service* pushes, addressed by D1 to the call's node + principal. The operator socket's `push` form stays, narrowed to `--to <node-id>` (D1b).

## Acceptance

- [ ] Human agrees D1–D6 and the MCP shape (or amends them).
- [ ] Tests, each failing first:
  - a callback reaches only the calling node, and only while it presents the calling principal (not the same person on another node, not another person on the same node);
  - through the gateway, users A and B each get only their own calls' callbacks;
  - a message names the call and service it answers;
  - a service can push only through a live call capability; the operator can push only `--to <node-id>`, and never to a role;
  - an operator push to the gateway's node reaches the gateway's own `wires inbox`, and no web user;
  - a crash between print and mark re-shows the message rather than losing it;
  - `dropped: n` surfaces;
  - a removed member's queue is purged on state advance.
- [ ] `inbox` MCP tool in `wires mcp` and `wires gateway`; e2e for both (gateway: two users, long poll).
- [ ] protocol.md §7 rewritten to D1–D6. README's "both directions" bullet reworded to callbacks: the host answers the agent that asked, even after the call has ended.
- [ ] `make demo` (push demo) green, using the call capability only.

## Notes

- 2026-09-24, the human: "no need for role or broadcast messages". D1 is
  agreed. Then (relayed by the audit session): "Agree, keep operator push".
  That's D1b: `--to <node-id>` only, per node. Then "the MCP gateway should
  just function as an addressable node; the default wiring should work": no
  gateway special case. Operator pushes to its node are the gateway
  operator's to read. D1–D6 and the MCP inbox are agreed. D2–D6 and the MCP shape stand as recommended unless amended; the
  per-service capability grace (D2) is still open.

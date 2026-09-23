# 23 — Push to callers: `wires inbox`

**Lane:** I · **Depends on:** 21 merged (both touch the host) · **Files:** `library/calls/` (push record + frame), new `wires/caller/inbox.rs`, `wires/host/push.rs` (new), `wires/host/config.rs` (a `push` section), render, docs

## Why

MCP's 2026-07-28 spec removed server-initiated streams, and its long-running-work
extension is poll-based (`tasks/get`) (MCP spec blog, https://blog.modelcontextprotocol.io/posts/2026-07-28/; summarised in `docs/executive-summary.md`).
Everyone else pushes with webhooks, which need the **receiver** to have a public,
routable HTTPS endpoint; an agent on a laptop, in a sandbox, or behind NAT has
none. Today an agent can call things, but nothing can call the agent back.

Wires can: the caller is addressed by **key**, not IP, and iroh reaches it
through relays or hole-punching. A host can push to an authenticated, authorized
caller with neither side exposing anything. The push is stamped with the host
identity the caller verified, gated by policy, and recorded like a call.

**The human's constraint (2026-09-23): no harness changes.** The inbox is a
command any agent can run on a loop.

## Design

**Caller side**
- `wires inbox` prints pending messages (one line each, or `--json`), marks them read, and exits 0; exits 0 with no output when empty. This is a **local read**, so a loop of checks costs no network.
- `wires inbox --wait [--timeout D]` blocks until at least one message arrives, prints it, and exits. For harnesses with background tasks (a Claude Code background command re-invokes the agent on exit), waiting costs zero model turns.
- `wires inbox --serve` (or folded into `wires watch`): a resident receiver on a new ALPN (`wires/inbox/1`) that accepts pushes and writes them to the local mailbox (`$WIRES_HOME/inbox/`, 0700). It accepts only from roster members that are hosts under policy (use the current roster/directory; don't wait for card 22's host list). The mailbox is bounded, with oldest-first eviction and a note.
- **No resident receiver?** `wires inbox` (and `--wait`) first **fetches** queued messages from the hosts in the caller's directory, a bounded catch-up like `call`'s cold path, then reads the mailbox. So a caller that's asleep or has no daemon still gets its messages, and "check on a loop" works with no process left running.
- `wires inbox` output carries the **verified sender** (host node + name), the host's own timestamp, a subject, and the body: `2026-09-23 16:04 ci@51442ef9  build-41  failed: test_orders_total …`. Pushed content is untrusted input to a model; the line format should make "who sent this" impossible to miss. Note this in the docs.

**Host side**
- `host.json` gains `"push": { "allow": ["analyst", …] }`, meaning the roles that may receive pushes from this host (default deny, as with tools). Validated like the rest (`deny_unknown_fields`).
- A host-local API to send: `wires push --to <node-id|role> --subject S [--ttl D] -- <body or stdin>`, reaching the resident `serve` over its control socket (the same single-allocator discipline as audit). Tools can address their caller: the host already injects `WIRES_CALLER_NODE` into each tool's env, so a tool that starts background work can later run `wires push --to "$WIRES_CALLER_NODE" …`. Native services (the long-term direction) call the same API in-process.
- Delivery: the host **queues per recipient** (bounded, TTL default 24h) and tries a direct dial to the recipient's inbox ALPN (by key, relay allowed). If that fails, the message stays queued for the recipient's next `wires inbox` fetch. Each attempt is at-least-once; the caller de-duplicates by message id.
- Authorization at send time **and** at delivery/fetch time (the recipient must still be a member and still hold an allowed role; removal cuts pushes the way it cuts calls).
- **Audit:** every push produces a host-signed record on the audit channel (`⇢ ci → gotwalt@gmail.com  build-41  delivered|queued|expired`), carrying the subject but not the body (by default; `"push": {"log_body": true}` to include it).

**Deliberately not decided here:** whether delivery should ride the gossip channel instead of direct dial plus a host queue. This card uses the direct path so it works whichever way card 22 goes, and notes in its Notes what the channel path would change.

## Acceptance

- [x] Unit + proptest: the push record/frame codec, mailbox bounds and eviction, `host.json` `push` validation, dedupe by id.
- [x] e2e: a resident receiver gets a push within 1 s; with no receiver, `wires inbox` later fetches it from the host queue; a removed member gets nothing (neither delivery nor fetch) and the attempt is denied on the channel; a role not in `push.allow` can't receive; TTL expiry is recorded.
- [x] `wires inbox --wait` exits on the first message, and exits with a distinct code on `--timeout`.
- [x] Extend `demo-remote-cli.sh` with one push step.
- [x] `bazel test //...`, lint, format check green.

## Notes

*2026-09-23, lane I (worker).*

### Commands

```
# host (inside a tool: --to "$WIRES_CALLER_NODE"; or a role: --to analyst)
workbench$ wires push --to <node-id|role> --subject build-41 [--ttl 90m] -- "failed: test_orders_total"
queued     alice@example.com (4b82e1a5)  bab91f4d502e7cef2518e7be90bb93b9
# caller (exit 0; 124 on --wait --timeout; 77 when every host refused)
laptop$ wires inbox [--wait [--timeout 10m]] [--json]
2026-09-23 17:13:14Z  from host bccf1595 (verified)  build-41  failed: test_orders_total
# observer
17:13:17 bccf1595 ⇢ bab9 → alice@example.com (4b82…) [analyst] "build-41" queued
17:13:17 bccf1595 ⇢ bab9 → alice@example.com (4b82…) [analyst] "build-41" fetched
17:13:25 bccf1595 ⇢ 7f5d → 4b82… "after-removal" denied: 4b82e1a5 is not in the channel's current roster
```

`wires push` hands a `{"push":{to,subject,body,ttl_secs}}` request to the
running `serve` over its control socket (reply `{"pushed":{"results":[…]}}`);
exit 0 if any recipient was accepted, 77 if all were refused. The body is
the trailing args, else stdin. `wires inbox` is a caller command beside
`call` (help lists it under Caller; `push` under Host).

### Wire format (`library/calls/push.rs`, ALPN `wires/inbox/1`)

`InboxFrame`: 4-byte BE length + canonical JSON tagged by `type`:
`hello{membership, proof?}`, `fetch{wait_ms}`, `deliver{messages[≤32]}`,
`ack{ids[≤32]}`, `denied{reason}`; frame ≤ 4 MiB, checked from the prefix
before allocating. `PushMessage{id (16B hex), from, to, subject (1–128 B,
no control chars), body (≤16 KiB UTF-8), at_ms, expires_ms}`.
- Direct: host dials the caller **by key** (bare `EndpointAddr`, relay /
  discovery allowed), `hello` → `deliver`; receiver answers `ack` or `denied`.
- Fetch: caller dials the host, `hello` → `fetch{wait_ms}`; host answers
  `deliver` (possibly empty; long poll capped at 25 s) or `denied`; caller
  `ack`s; only acked ids leave the queue.
- A receiver keeps only messages with `from ==` the authenticated peer,
  `to ==` itself, not expired.

Record: `AuditRecord::Push{id, to, principal?, role?, subject, outcome:
queued|delivered|fetched|expired|dropped|denied, reason?, body? (only with
"push":{"log_body":true}), at_ms}` — one per milestone; rendered `⇢`.

### Bounds

Host: ≤64 queued per recipient (oldest dropped, recorded `dropped`); TTL
default 24 h, max 7 d, swept every 1 s (recorded `expired`); direct attempt
≤3 s inside `wires push`; queue persisted to `$WIRES_HOME/push-queue.json`
(0600). Caller mailbox `$WIRES_HOME/inbox/` (0700): `new/` ≤256 unread
(oldest evicted, with a note printed by the next `wires inbox`), `read/` last
1024 ids kept for de-dup; every write/mark-read is a rename.

### Delivery semantics

At least once per attempt, de-duplicated by id at the caller (unread *and*
recently read), so effectively once for display; at most once printed even
with two concurrent `wires inbox` (mark-read is a rename that only one
wins). Ordered by the host's `at_ms` per mailbox, not globally. No
retry loop on the host: a message is pushed once directly (at send), then
waits for a fetch — by `wires inbox`, or by a resident `wires watch`, which
fetches from every known host at start and every 60 s (and stops asking a
host that refused it, for that run). With a resident watch, `wires inbox`
is a pure local read (it detects the watch by its control socket).

### Authorization

`host.json` `"push": {"allow": [roles], "log_body": bool}` —
`deny_unknown_fields`, roles validated like a tool's `allow`, needs a
`channel`; absent = nobody. `Policy::decide_push` (default deny; `RoleTable`
tries `push.allow` in order) plus the card-21 `CurrentRoster` view, checked
**at send, at direct delivery, and at fetch** (fetch also runs the session's
membership + roster gate via new `transport::check_member`, so a removed
member gets `roster inclusion rejected: not in the current roster (removed
at version N)`). A roster refusal drops that member's queue (`denied`
records) and the refused fetch is a ✗ record on the channel. **Deviation:**
a *policy* refusal of a fetch (member in no allowed role) is answered but
not recorded — every member's resident watch polls hosts, and those
denials would fill the channel. Send-time policy refusals are recorded.
The receiver accepts deliveries only from members in its current roster
that have announced as hosts on the channel (`directory.json`).

### What would change if delivery rode the channel instead

- Store-and-forward and catch-up come free (replay), so no host queue, no
  fetch ALPN, no persistence file; a sleeping caller gets pushes on its next
  catch-up, and every record is already hash-chained.
- But the channel is encrypted to the **whole roster**: a push would be
  readable by every member unless sealed per recipient (as card 15 seals
  announcements) — and even sealed, size/timing/recipient-count leak, and
  the body would live in every member's log forever (no TTL, no deletion).
- Authorization at delivery time disappears: once published, a removed
  member who already holds the key can read it; revocation only protects
  messages sealed after the re-key. Today's "checked at fetch" becomes
  "checked at send" only.
- Latency depends on gossip mesh membership (the caller must be joined);
  direct dial works for a caller that is not on the mesh at all.
- 64 KiB gossip message cap vs 16 KiB body here: fine either way.
- The observer would see pushes themselves rather than records about them.
So the channel is the better *transport for records* and for broadcast
("to every analyst"), the direct path better for private, revocable,
per-caller messages. That is input for card 22.

### Tests

Library: `push.rs` (shape, bounds, round-trip/split proptests, decode never
panics), `audit.rs` push record. Binary: `host::push` (queue bounds proptest,
remove/expire/purge, report), `caller::inbox` (dedupe, eviction + note,
exactly-once proptest, evictions proptest, one-line escaping, UTC dates,
flag parsing, locked mode), `host::config` (push validation, summary,
decision), `render` (⇢ line). e2e `e2e/push.rs`: resident receiver
delivered ≤1 s; queued → fetched; long poll answered by a later push; bob
(no role) denied at send + fetch; 1 s TTL recorded `expired`; removed member
refused at fetch (on the channel), queue dropped, next send denied.
`--wait` exit-on-message and exit 124 on `--timeout` are asserted in the
demo (CLI level), not unit tests.
Numbers: `wires_test` 413 (was 394), `library_test` 295 (was 286),
`library_doc_test` 54 (was 49). Lint and `format.check` green. Demo green
(`--quiet`, 32 s): new step 6b (timeout 124, push queued, `inbox` line,
⇢ queued/fetched, `--wait` woken by a second push) and step 7 asserts push
and inbox after removal both exit 77. One run of
`e2e::directory::…stopped_host_go_stale` timed out under heavy machine load
(other worktrees building); green on re-run, untouched by this card.

### Off-lane touches / follow-ups

`transport.rs` (`check_member`), `announce.rs` untouched (reused
`roster_view`), `ipc.rs` (push request/response, `spawn_with`),
`watch.rs` (inbox ALPN: receiver or host fetch side; resident fetch task),
`resolve.rs` (`caller_context`/`fresh_directory` now `pub(crate)`),
`admin/commit.rs` (`Ttl::duration`), e2e fixtures (`push: None`,
`serve_pushing`), README, `docs/agent-sandbox.md`, fixture host.json.
Not done: host display name in the inbox line (no `name` in host.json yet —
the line shows `host <id8> (verified)`); `wires inbox --serve` (folded into
`wires watch` instead); `wires mcp` doesn't expose the inbox; the host never
retries a direct delivery (a resident receiver's 60 s fetch covers it);
`wires inbox --wait` with an empty directory never re-refreshes it.

# 23 — Push to callers: `wires inbox`

**Lane:** I · **Depends on:** 21 merged (both touch the host) · **Files:** `library/calls/` (push record + frame), new `wires/caller/inbox.rs`, `wires/host/push.rs` (new), `wires/host/config.rs` (a `push` section), render, docs

## Why

MCP's 2026-07-28 spec removed server-initiated streams, and its long-running-work
extension is poll-based (`tasks/get`) (`docs/research/…/lane-2-agent-protocols.md`).
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

- [ ] Unit + proptest: the push record/frame codec, mailbox bounds and eviction, `host.json` `push` validation, dedupe by id.
- [ ] e2e: a resident receiver gets a push within 1 s; with no receiver, `wires inbox` later fetches it from the host queue; a removed member gets nothing (neither delivery nor fetch) and the attempt is denied on the channel; a role not in `push.allow` can't receive; TTL expiry is recorded.
- [ ] `wires inbox --wait` exits on the first message, and exits with a distinct code on `--timeout`.
- [ ] Extend `demo-remote-cli.sh` with one push step.
- [ ] `bazel test //...`, lint, format check green.

## Notes

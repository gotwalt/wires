# 11 — Camera blockers from the real-Google run

**Lane:** H · **Depends on:** 04, 05, 07 · **Files:** `wires/replay.rs`, the tail loop in `wires/main.rs` (`run_tail`) and `wires/audit.rs` forwarding, `wires/login.rs` (callback), `wires/tools.rs` (`tools add`)

## Context

Real Google login, 2026-09-23 (integrator, loopback; `.claude/g/`): with
`serve --require-idp 'iss=https://accounts.google.com,email=gotwalt@gmail.com'`
the pre-login call was refused (77, `✗` on the channel), `wires login --topic ops`
succeeded, the observer printed
`🪪 identity ecc8c1cf is gotwalt@gmail.com (verified by https://accounts.google.com)`,
and the next call ran and was logged with the email. Card 04's real-Google box can
be ticked. Three things would ruin the recording:

## 1. Audit records stall 20 s after a login (must fix)

`wires login --topic ops` brings up a one-shot node, publishes, and exits. The
responder then runs a replay pass against that departed peer, which takes the
full 20 s timeout, and the **audit records of the next call are held until it
finishes** (call at ~03:14:13, `▶`/`■` stamped 03:14:33, right as
`replay pass against ecc8… timed out after 20s` is logged). The same thing will
happen after any one-shot `publish`.

- Catch-up must never block the loop that seals/appends/broadcasts
  `PublishRequest`s (audit forwarding included). Run replay passes as a separate
  task whose results are fed back, or otherwise make sure publishing proceeds
  while a pass is in flight.
- Stop picking a peer that just said goodbye / closed its connection as a replay
  target, and cut the per-pass timeout for peers learned only from a one-shot
  publisher (or make the timeout adaptive), so the log isn't full of 20 s timeouts.
- Regression e2e: a one-shot publisher joins, publishes, exits; a call made right
  afterwards produces a `Started` on an observer within 2 s.

## 2. Safari shows "Can't connect to the server" after sign-in

The login still completes, but the browser shows an error page instead of
"signed in". `await_callback` writes the 200 page and drops the `TcpStream`
without a graceful shutdown (unread request bytes → RST), and returns right
away, closing the listener, so a second or speculative connection from the
browser finds nothing listening.

- After writing the page: `shutdown()` the write half and drain/ignore the rest
  of the request before dropping it.
- Keep answering the listener for about 3 s after success (serve the same
  "signed in" page to any `/callback` hit, 404 anything else) in a background
  task, while the login continues.
- Check it by hand with Safari if possible; otherwise add a test with a client that
  sends the request plus extra bytes and asserts it reads a full 200 response.

## 3. `tools add` can't take the audit ticket

The demo decodes the base64 ticket to fish out the loopback port. Add
`wires tools add NAME --topic-ticket <ticket>` (or accept a topic ticket in
`--node`'s place), filling `node` and `addrs` from the ticket's peer entry for the
responder. Update `.scripts/demo-remote-cli.sh` to use it.

## Acceptance

- [ ] Regression e2e for (1) is green; `.scripts/demo-remote-cli.sh --quiet` is still green and shows no replay-timeout WARN lines in the responder log after login.
- [ ] Test for (2); card Notes say whether it was checked in Safari.
- [ ] (3) is implemented and the demo script uses it.
- [ ] `bazel test //...`, lint (`bazel build --config=lint //...`), format check green.

## Notes

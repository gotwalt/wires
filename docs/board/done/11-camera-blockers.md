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

- [x] Regression e2e for (1) is green; `.scripts/demo-remote-cli.sh --quiet` is still green and shows no replay-timeout WARN lines in the responder log after login.
- [x] Test for (2); card Notes say whether it was checked in Safari.
- [x] (3) is implemented and the demo script uses it.
- [x] `bazel test //...`, lint (`bazel build --config=lint //...`), format check green.

## Notes

**Worker, 2026-09-22.**

### 1. The stall: root cause and fix

`run_tail` awaited `catch_up_and_print` inline in its `select!`. The same loop is the
single seq allocator, and `serve --audit-topic`'s records reach it as `PublishRequest`s
on the control-socket mpsc (`audit::forward`). So any pass that waited on a peer held
every call record. The one-shot login node was still in the responder's `Admitted`
registry after it exited, because admissions last until the TTL. A pass scheduled by
its `NeighborUp` debounce therefore dialed a dead endpoint and took the full
`REPLAY_PASS_TIMEOUT`.

- **Catch-up is a task now** (`wires/main.rs`, `spawn_catch_up` / `print_caught_up`).
  Only one runs at a time. The timer arm is gated on `catching_up.is_none()`, and
  when a task finishes it re-arms `CATCHUP_INTERVAL`, with `arm` keeping the sooner
  deadline, so a gap or neighbor that asked for a pass mid-flight still gets one.
  The startup pass is spawned the same way. Printing switched from the hwm
  before/after diff, which is wrong with concurrent appends, to the envelopes the
  pass itself inserted: `replay::catch_up_collect` → `CaughtUp { counts, fresh }`.
  `catch_up` still exists as a thin wrapper, used by tests.
- **Departed peers aren't dialed.** `Admitted::replay_targets(version)` is
  `peers_since` minus peers whose tracked connections have all closed
  (`close_reason().is_some()`). Such a peer is skipped, not evicted: its admission
  stands. `attach_conn`/`insert` prune closed handles, so a returning peer becomes
  a target again.
- **Adaptive-ish timeout:** `REPLAY_CONNECT_TIMEOUT` (5 s) bounds the dial + stream
  open inside the 20 s pass.
- Gap healing, periodic catch-up, the round/budget bounds, and the epoch-bounded
  dial set are unchanged. Spec §6 in `docs/phase2-topics.md` was updated (off-lane,
  docs only).
- **Testability:** `run_tail` → `run_tail_on(…, bind)` (an `AsyncFnOnce` node
  binder), so e2e drives the production loop over a hermetic endpoint.
- **Tests** (`wires/e2e.rs` §8):
  - `a_stalled_replay_pass_does_not_hold_back_call_records`: an admitted peer
    whose replay server accepts and then stalls. A call made while R's pass is
    stuck on it must put `Started` on the observer within 2 s. It was red before
    the fix, failing at the 2 s assertion.
  - `a_departed_one_shot_publisher_does_not_delay_the_next_call`: the card's
    scenario. P joins, publishes, and exits. P drops out of `replay_targets` but
    stays admitted, and the next call's `Started` arrives within 2 s.
- **Demo:** the responder log shows no replay-timeout or `replay pass failed` lines.
  The demo's 10 s run is shorter than the 20 s timeout, so it couldn't have shown
  the stall anyway. The e2e tests are the real regression guard.

### 2. Safari callback

`await_callback` now takes the listener by value. Every answered connection is
drained before it is dropped (read and discarded until EOF, at most 2 s / 64 KiB).
On success, `linger_signed_in` keeps answering for `CALLBACK_LINGER` (3 s) in the
background: `/callback` gets the same page and anything else gets a 404.

- `the_signed_in_page_survives_unread_request_bytes` sends the request plus 32 KiB
  of extra bytes. It was red before the fix: `ECONNRESET` on macOS.
- `the_listener_keeps_answering_briefly_after_sign_in` covers the linger window.
- **Not checked by hand in Safari.** This was a headless worker.

### 3. `tools add --topic-ticket`

It fills `node`, `addrs`, and `relay_url` from the ticket's single peer entry. It also
sets `audit_topic` from the ticket name when none is set. It refuses tickets with 0 or
≥2 peers; for ≥2, it says to use `--node`. It's exclusive with `--ticket` and `--node`.
The demo script now uses it and checks that `tools.json` names the workbench key.
README step 4 still shows `--node`, which is right for the relay path and was left
alone (not my lane).

### Results

- `bazel test //...`: green (wires_test 310 tests; library 253).
- Lint: only the existing `HeadSource::None` dead-code warning.
- Format check: green.
- Demo: green in 10.2 s `--quiet`. The unmodified base (`bdff926`) also takes
  10.1 s on this machine today, so this change costs no time.

**Pre-existing flake (not touched):**
`library` `envelope::tests::republishing_a_slot_with_different_content_never_reuses_the_keystream`
failed once in a `--nocache_test_results` rerun. With 1-byte overlapping payloads,
the ct-xor/pt-xor inequality fails by chance (1/256).

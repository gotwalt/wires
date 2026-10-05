# 48 — An edit right after a directory restarts reaches only one of two

**Depends on:** — · **Status:** review; scheduled (the human, 2026-10-05: "solve that observation") · **Files:** `wires/admin/propagate.rs`, `wires/policy/fetch.rs` (`publish_all`), `wires/directory/{serve,node}.rs`, `wires/host/serve.rs`, `wires/e2e/`

## What was seen

During [card 43](../done/43-accuracy-sweep.md)'s docs sweep, in two hand runs
of the walkthrough (two hosts, both also directories, on loopback with the
stand-in IdP): the first admin edit made right after the workbench's `wires
serve` was stopped and started again reported `published to 1 of 2
directory(ies)`, naming the workbench as not reached, and exited 0. The
later edits reached both. `.scripts/demo-remote-cli.sh` asserts `published
to 2 of 2` after its own restart and passes, so the window is narrow. The
Rust reviewer looked in `wires/policy/` and `wires/directory/` and did not
find the cause.

## Why it matters

A ban is an edit. A directory that misses a publish keeps serving the old
policy to the hosts that follow it until its replica catches it up or the
next publish arrives, and the admin's command says only "1 of 2" on stderr
with exit 0. If the miss is a race in our code, a removal can silently reach
half the network.

## Leads (none confirmed)

- The admin dials a directory by key. After a restart the node binds a new
  port; on loopback the address comes from the `hints` file (`run/hint`,
  rewritten at start), so an admin dialing in the gap may hold the old
  address and time out. Off loopback the same gap would be discovery lag.
- The restarted directory may refuse or drop a publish while it is still
  loading `directory.redb`, signing its first `Fresh` or taking its replica's
  catch-up.
- `publish_all`'s per-directory budget and what it does with a dial that
  fails fast versus one that times out.
- Whether the replica subscription then delivers the missed head, and how
  long that takes (the walkthrough's later edits reaching both does not show
  the missed one arrived).

## Do

1. Reproduce it in an e2e test (restart a directory, publish at once, in a
   loop until it misses), and say exactly which step fails.
2. Fix it if it is ours (a retry inside the publish budget, a directory that
   accepts publishes as soon as it listens, an address the admin re-resolves),
   or say plainly why it is inherent and bounded.
3. Decide what the admin should hear. Today: a note on stderr and exit 0 when
   at least one directory took it. A removal that missed a directory may
   deserve a louder line, or a retry.
4. Confirm the missed directory catches up by replica, and how fast; put the
   number in `docs/fabric.md`.

## Notes

**The cause (found, ours to fix).** The admin could not *find* the restarted directory by its key,
and tried each directory once. Nothing in the directory refuses or drops a publish: it never
sees one. Reproduced with the release binaries (two `wires serve` hosts that are also
directories, loopback, the stand-in IdP; restart the workbench, `wires role set …` at once, debug
logs on the admin), every time:

- **With n0 discovery only** (no `hints` file): 4 of 4 edits missed it, the dial failing in ~2 s
  with `dialing directory …: No addressing information available`. A node's discovery record is
  not resolvable for about 3 s after it starts: an edit 2 s after the restart still missed, one
  3 s after reached both. The same lag made the *first* `wires policy push` right after `wires
  serve` reach none (and print the first-run note).
- **With a stale `hints` line** (the admin's file still naming the old port): 4 of 4 missed, the
  dial spending its whole 5 s `DIAL_TIMEOUT` on the old port (`publish failed: no answer within
  5s`). iroh looks a key up only when a dial begins (`trigger_address_lookup`, iroh 1.2
  `remote_state.rs`), so a record published meanwhile isn't used. 15 s after the restart the same
  stale line reached both (the lookup then finds the relay address).
- **With the hints refreshed** after the restart (what `.scripts/demo-remote-cli.sh` does): 8 of 8
  reached both. That is why the demo passes.
- The restarted workbench's log shows no publish arriving; it took the version 1–7 ms after the
  spare did, from its subscription to the spare.

**The fix.** `publish_retrying` (`wires/policy/fetch.rs`): a directory the first try could not dial
is tried again, 1 s apart, until it takes the publish or 15 s (`PUBLISH_BUDGET`) from the first
try have passed. Each new dial looks the key up again. Which directories are retried
(`fetch::Retry`): an edit retries those in `reached.json` (they have taken a publish before), so
an edit made before any directory runs (the first run) still doesn't wait; `wires policy push`
retries every directory. A directory that *answered* with a refusal is not retried (new
`PublishReport::refused`; the line names it as "refused by", no longer "not reached"). After the
fix, the same repro: n0 only 4 of 4 reached both (edit 4.3–4.9 s); stale hint 3 of 3 (8 s: one
dial timeout, then the retry). Cost: an edit while a directory that took publishes before is down
now waits 15 s before reporting it (was ~5 s). Not done: re-reading the `hints` file between tries
(a script rewrites it before the edit anyway), a shorter dial timeout for publishes.

**Regression tests** (`wires/e2e/restart.rs`, ~9 s together, deterministic): the admin's address
book is its own `MemoryLookup`, standing in for discovery and the hints file, and learns the
restarted directory's new address 1.5 s after the restart; every publish binds a fresh endpoint,
as each command does. `an_edit_right_after_a_directory_restarts_reaches_it` (a single try misses
it, not refused; the admin's publish reaches 2 of 2); `a_stale_address_costs_one_dial_timeout_then_the_next_try_finds_it`;
`a_directory_that_missed_an_edit_takes_it_from_another_by_replica`. With `PUBLISH_BUDGET` set to 0
the first two fail with the observed `published to 1 of 2`.

**What the admin hears.** Decided: exit 0 whenever at least one directory took the edit, a
removal included, after the retries; exit 1 when none did (as before). A non-zero exit would say
the removal didn't happen, but it is signed, stored and in force at every directory that took it
and every host following those, and rerunning `wires remove` makes no difference. What changed is
that the line is no longer quiet about the consequence: `policy version N: published to 1 of 2
directory(ies); not reached: 3420e2ea…; until it has version N, hosts that follow it decide under
the policy before it. It takes this one from a directory that did as soon as it reaches one;
`wires policy push` re-publishes it`. A removal gets no separate wording: a ban travels exactly as
every edit does.

**Catch-up by replica, measured.** A directory that missed an edit takes it from another as soon
as the other takes it, when its replica subscription is open: about 40 ms in the loopback test
(debug build), 1–7 ms with the release binaries above (there the host's own follow subscription
delivered it first). A restarted directory opens its subscriptions as it starts (about 1 s with n0
discovery: `following the policy` 1.08 s after the restart), and one that subscribes after the
publish gets the whole policy at once. The bound is the replica's reconnect pause, up to 30 s,
when it couldn't reach any other directory for a while. In `docs/fabric.md` (§6, "Change
policy") and `docs/protocol.md` §4 (Replicas).

**If card 45 deletes replicas:** the retry stands on its own (it is the admin's dial, nothing
replica-specific). But a directory that still misses an edit after 15 s would then hold the old
policy until the next publish that reaches it, and the line's "It takes this one from a directory
that did" becomes false: 45 must change that sentence, and should then consider exit 1 (or a
longer retry) for a miss, since nothing else would heal it.

**Docs.** `docs/protocol.md` §4 (Publish: the retry, its budget, who is retried, the line; Replicas:
how fast) and §8 (`reached.json`). `docs/fabric.md` §4.3 item 4 (the 15 s), §6 "Change policy"
(the retry and the catch-up number), §8 (the admin's publishes). No other narrative statement I
found became false: `usage.md`, `deployment.md`, `demo.md` and the README quote only `published to
K of K` lines, and their exit-code statements still hold.

**Acceptance run** (2026-10-05): `cargo test --workspace` green (145 library, 412 wires,
doctests); `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --all --check`
clean; `.scripts/demo-remote-cli.sh --quiet` and `.scripts/demo-push.sh --quiet` pass. No shell
script changed.

**Lane notes.** Touched outside the listed files: `wires/admin/mod.rs` (`run_edit_with`, so
`policy push` can retry every directory), `wires/directory/tests.rs` and `wires/e2e/first_run.rs`
(the new `Retry` argument; first_run's `policy push` uses `Retry::Every`), and the board README's
lane row.

**After review (four findings, fixed on top of e5f534b).** These supersede what is above where
they differ.
1. *Busy is not a refusal.* A directory with every admitted slot taken answers
   `Denied { reason: BUSY }`. That now counts as a miss and is tried again; only other refusals
   are final. The match compares against the shared constant `directory::node::BUSY`. A dedicated
   answer would change the wire format, and the constant is the one both sides use. Test:
   `e2e::restart::a_busy_directory_is_tried_again`, which fails without the change.
2. *A directory the edit drops* (`wires directory rm`) is still published to once, so a running
   one learns it was dropped. It is never tried again, and its miss is reported apart: "not
   reached, and dropped by this edit: X…", with no catch-up sentence, because the others refuse
   it as a replica once they hold the new head. It doesn't count toward "reached none" (new
   `PublishReport::dropped`). Test:
   `e2e::restart::a_dead_directory_the_edit_drops_is_tried_once_and_not_waited_for` (one try,
   exit 0), plus the line's unit test.
3. *No answer is dropped at the deadline.* A retry round is no longer cut off by a timeout. No
   round starts after the 15 s budget, and one already started finishes. Each exchange is bounded
   (item 4), so a directory that stored the policy is never reported missed for want of its
   answer.
4. *Every exchange is bounded* (`directory/wire.rs` `exchange`, also used by `ask`): 5 s to dial,
   then 10 s for opening the stream, the writes and the answer, so 15 s at most. A publish's worst
   case is therefore the 15 s budget plus one exchange, 30 s, and `docs/protocol.md` §4 says so.
   Test: `directory::wire::tests::a_directory_that_never_answers_is_given_up_on` (a peer that
   takes the connection and never reads, with 8 MiB of frames, so the writes block); ends in about
   10 s.

`docs/protocol.md` §4 rewritten to match (busy, dropped directories, the exchange bound, the
30 s worst case, exit 1 unless every miss is a dropped directory). Rerun: `cargo test --workspace`
green (145 library, 415 wires, doctests); clippy `-D warnings` and `cargo fmt --check` clean; both
demo scripts pass.

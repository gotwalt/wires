# 48 — An edit right after a directory restarts reaches only one of two

**Depends on:** — · **Status:** backlog; scheduled (the human, 2026-10-05: "solve that observation") · **Files:** `wires/admin/propagate.rs`, `wires/policy/fetch.rs` (`publish_all`), `wires/directory/{serve,node}.rs`, `wires/host/serve.rs`, `wires/e2e/`

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

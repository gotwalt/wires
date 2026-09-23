# 21 — Camera polish from the second two-machine run

**Lane:** P2 · **Depends on:** 12–20 · **Files:** `wires/channel/render.rs` / `watch.rs` (1), admin command logging (2), `wires/host/transport.rs` denial text (3), `wires/host/` announcer (4)

See the "Second two-machine run" section of `docs/board/doing/08-demo-two-machine.md` for evidence.

- [ ] **1. Heartbeat noise:** `watch` prints a `📣` line only when a host's announcement content changes (tools, sealed-entry count, addresses), not for unchanged heartbeats. `--json` may keep emitting them all.
- [ ] **2. Quiet admin commands:** `invite`, `remove` and `init` use the quiet log filter (like `call`), so the admission WARNs from their one-shot node don't reach stderr unless `RUST_LOG` is set.
- [ ] **3. Removal reason:** when the caller's proof targets an older version and the directory for the current head doesn't list it, the refusal says `not in the current roster (removed at version N)` (sent to the caller and written to the channel), instead of `stale inclusion proof…`.
- [ ] **4. Seal only to current members:** host announcements seal to (current roster members) ∩ (policy-allowed verified principals). After `remove`, the re-announcement must carry 0 entries for the removed node. Add a regression e2e.
- [ ] `bazel test //...`, lint, format check green; `demo-remote-cli.sh --quiet` green.

## Notes

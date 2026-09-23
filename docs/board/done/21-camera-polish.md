# 21 — Camera polish from the second two-machine run

**Lane:** P2 · **Depends on:** 12–20 · **Files:** `wires/channel/render.rs` / `watch.rs` (1), admin command logging (2), `wires/host/transport.rs` denial text (3), `wires/host/` announcer (4)

See the "Second two-machine run" section of `docs/board/doing/08-demo-two-machine.md` for evidence.

- [x] **1. Heartbeat noise:** `watch` prints a `📣` line only when a host's announcement content changes (tools, sealed-entry count, addresses), not for unchanged heartbeats. `--json` may keep emitting them all.
- [x] **2. Quiet admin commands:** `invite`, `remove` and `init` use the quiet log filter (like `call`), so the admission WARNs from their one-shot node don't reach stderr unless `RUST_LOG` is set.
- [x] **3. Removal reason:** when the caller's proof targets an older version and the directory for the current head doesn't list it, the refusal says `not in the current roster (removed at version N)` (sent to the caller and written to the channel), instead of `stale inclusion proof…`.
- [x] **4. Seal only to current members:** host announcements seal to (current roster members) ∩ (policy-allowed verified principals). After `remove`, the re-announcement must carry 0 entries for the removed node. Add a regression e2e.
- [x] `bazel test //...`, lint, format check green; `demo-remote-cli.sh --quiet` green.

## Notes

*2026-09-23, lane P2 (worker).* Commits: items 3+4 (with the red-first e2e),
then items 1+2, then the card.

**4 — root cause.** The host's identity index (`host/identity.rs`) keeps a
verified claim until the token expires; nothing drops it on removal. The
announcer built its audience from `identities.nodes()` × policy with no roster
check, and the re-key poll (a new fabric key) re-announced under the new key —
still sealing to the removed node. **Fix:** `announce::CurrentRoster`, read
per audience computation through a `RosterView` over the same `HeadSource` the
session gate enforces: no head → unfiltered (plumbing); the proof directory
for *exactly* the head → only its members (each proof re-verified against the
head); no directory for the head but the host's own proof is current →
`JoinedAtHead`, unfiltered (a host invited at the current head has seen no
commit since, so every claim it could read was sealed under the head's key by
a current member; a removal is a commit whose Rekey leaves a directory);
otherwise `Unknown` → seal to nobody until the directory arrives (fail
closed). `serve.rs` now builds the announcer after `ServeConfig` is `Arc`'d
(one head source for gate and announcer). Regression e2e:
`e2e::directory::after_remove_the_host_seals_nothing_to_the_removed_member`
(red before the fix at "no entry opens for the removed alice").

**Call authorization has no such gap.** `transport::authorize` runs
`roster_gate` (fresh head per connection, `?` on failure) before identity
resolution and `Policy::decide`, so a removed member with a still-fresh
analyst claim is refused by the roster, never reaching the policy. The e2e
pins it: Alice's claim is verified and analyst, and her refusal starts with
`roster inclusion rejected:`. Both paths depend on the host having adopted the
new head (~1 RTT after the Rekey), and they read the same head.

**3 — removal reason.** New `library::Error::RemovedFromRoster { proof, head }`
from `check_roster_inclusion_via` when a stale presented proof's node is absent
from the directory for exactly the enforced head. Text: `not in the current
roster (removed at version N)` when the proof is one commit behind; otherwise
`removed after version P; head is version N` (the verifier knows absence from
the head, not which commit in between). Leaks nothing new: the caller knows it
was removed, and the head version was already in the old "stale" text. Without
a directory for the head it stays "stale inclusion proof" (can't tell removal
from a missed re-key). Residual: a directory missing a chunk of a >32-member
Rekey would mislabel a stale member as removed (same refusal either way). Also
applies to topic admission (same function).

**1 — heartbeats.** `render::ShownHosts` in `Printer` remembers the last
`HostSummary` (open listing incl. dial hints, sealed-entry count, heartbeat)
per host; human output prints a `📣` only on change; `--json` emits all.

**2 — quiet admin.** `init`/`invite`/`remove` use `QUIET_LOG_FILTER`; their
notes (who the re-key reached) are unchanged.

**Evidence** (`WIRES_ANNOUNCE_HEARTBEAT_SECS=2 demo-remote-cli.sh --quiet
--keep`): 12 announcements published, observer printed 3 `📣` lines (0 → 1
sealed after login, 1 → 0 after `remove agent`); refusal `roster inclusion
rejected: not in the current roster (removed at version 5)`; `remove.err` /
`invite.err` hold only the notes.

**Off-lane:** `library/error.rs`, `library/membership/rekey.rs` (item 3);
`host/serve.rs` (announcer wiring); `e2e/idp.rs`, `e2e/mod.rs`,
`channel/watch.rs` (one `shown:` line per `Printer` literal); README's two
sample refusal lines. Pre-existing clippy warning in `host/policy.rs:397`
(redundant closure) left alone.

**Numbers.** `wires_test` 394 (was 391 incl. the new e2e), `library_test` 286
(+2), `library_doc_test` 49; lint, `format.check` green; demo green, 20 s.


# 43 — Accuracy sweep: nothing says what is no longer true

**Stage:** 4 · **Depends on:** [39](39-premise-and-story.md), [40](40-cut-records.md), [41](41-idp-membership.md), [42](42-caller-identity-for-services.md) merged · **Status:** done (merged into `simplify` 2026-10-05) · **Files:** all of them, read-mostly

## Why (the human, 2026-10-05)

"We'll want to pay special attention to documentation, comments, and other
side effects that may no longer be accurate after this changeset." Cards
40–42 delete three concepts that were threaded through every layer, and card
39 rewrites every narrative doc. Each worker checked its own lane; this card
is the check by someone who didn't write the change.

## What to check, each against the code as merged

1. **Docs**: every claim, command, flag, file name, environment variable,
   exit code, default, number and quoted output in `README.md`, `docs/*.md`,
   `docs/blog/`, `docs/board/README.md`, the open cards, `CLAUDE.md`,
   `bench/**/REPORT.md` and `deploy/gateway/`. A benchmark report is a record
   of a past run: don't rewrite its results; add a dated note where its setup
   no longer matches the code.
2. **Comments and rustdoc**: module docs (`//!`), item docs (`///`),
   inline comments and doctests across `library/`, `wires/`, `bindings/`
   that describe a removed concept, a removed step, an old name, or a
   guarantee the code no longer gives. Card references ("card 26", "card
   35") that now point at removed behaviour.
3. **User-facing text**: `--help` and `--help-all` for every command, the
   snapshots, the MCP `instructions` and tool descriptions, every error and
   refusal message, the "next step" each error ends with (does that command
   still exist?).
4. **Names left behind**: types, functions, fields, files, constants and
   tests named for a removed concept (`membership_fabric`, `state_version`,
   `check_member`, `RemoteTool`, "responder", `policy-checked.txt`, …).
   Rename where it is cheap and local; list the rest.
5. **Scripts and config**: `.scripts/*` (narration text too), fixtures,
   `Makefile`, `Dockerfile`, `deploy/gateway/*`, `bench/**/*.sh` and `*.py`,
   `bindings/**/examples`, `.githooks`.
6. **Dead code and dependencies**: functions, types, error variants,
   features and crates nothing uses any more (`cargo machete` if available,
   else by reading `Cargo.toml` against the imports).
7. **Tests that still pass for the wrong reason**: a test whose name or
   comment describes removed behaviour, or which asserts a file or message
   is absent that can no longer exist.

Fix what is wrong. For a finding that needs a decision, don't guess: list it
in *Notes* with the file and line.

## Input from the workers of cards 39–42 (unverified leads; check each)

- **protocol.md vs code.** §7 and §8 say the operator socket is `run/serve.sock` in the keystore;
  `wires/host/control.rs` (`short_socket_path`) falls back to `$TMPDIR/wires-<uid>/<hash>.sock`
  when the keystore path is too long. §8's file modes: `policy.json.lock` and `directory.redb`
  were seen created 0664 and a caller's `jwks/` 0775, where the table says 0600: decide which is
  the bug (the code, most likely). "registry" for the policy survives in §3, §4, §5 and §7, and
  "fabric" in §4 prose.
- **Stale snapshots.** `wires/snapshots/invite.txt` and `invite.all.txt` describe a command that
  no longer exists; `help_snapshots.rs` doesn't notice orphan files. Delete them, and make the
  test fail on an orphan.
- **Help text.** `wires push --help` says "(logged)"; a push is only traced at `debug`. The
  premise paragraph (`help::PREMISE`, also the MCP `instructions`) says "admin-signed list";
  the word is *policy* (card 39 item 6; the board's premise now says so too). `wires remove` /
  `restore` help mentions `label=<node id>` where naming a node for the first time makes no
  sense.
- **A possible bug.** After `wires restore` on a host that is also a directory, the host logged
  `policy subscription: the update doesn't apply to the held policy: … removes person_ban:… which
  isn't held; asking for the whole policy`, then resynced: its follow loop held an older copy
  than its own directory had adopted. It recovers; find out why it happens.
- **A tight test.** `e2e::follow::an_edit_reaches_every_subscribed_host_within_2s_as_one_update`
  failed once at 2.07 s on a loaded machine and passes alone. Say whether 2 s is a claim the docs
  make (then keep it and make the test robust) or only a test budget.
- **Docs.** `docs/usage.md`, `docs/deployment.md` and `docs/fabric.md` carry `<!-- sweep: … -->`
  markers where output or a number had to wait for card 47: re-capture each from a real run and
  remove the marker. `usage.md`'s cast list still calls the observer "signed in but in no role"
  (after card 47 she is not in the network). The walkthrough's failover line and bob's login
  output were not captured from the run. `deployment.md`'s sudoers sketch is untested. The
  README's "Neither keeps a log of calls for you" follows three alternatives, not two.
  `bench/state-scale/REPORT.md` and `model.py` model badges and readers; `bench/REPORT.md` and
  `bench/push/REPORT.md` say "registry" in their setup notes (dated reports: add a note, don't
  rewrite results).
- **Not run by anyone yet on the final code:** `.scripts/demo-native-service.sh --lang node`
  after card 41; the bench `up.sh` scripts against real Google.

## Acceptance

- [ ] `cargo test --workspace`, clippy `-D warnings`, `cargo fmt --all --check`, shellcheck and shfmt green; the demo scripts pass in `--quiet`.
- [ ] `git grep -niE 'badge|membership|invite|wires watch|watch_records|call.log|audit|otlp|reader|record-marks|issued\.json|ledger'` returns only deliberate hits, each listed in *Notes* with why it stays.
- [ ] *Notes* holds the findings: fixed, and left for the human.

## Notes

Four reviewers who wrote none of the change, one per kind of file (2026-10-05), then the
integrator's final run.

**Fixed.**
- `docs/protocol.md`: about 60 claims corrected against the code, six unstated limits added to §9.
- Narrative docs: every quoted output re-captured from the current binary; card 47's fourteen
  user-visible changes applied; all `sweep:` markers resolved; links checked.
- Rust: comments and rustdoc in about 60 files; help text and snapshots (orphan snapshots now fail
  the test); dead code removed (`allowed_services`, `Grant`, `Policy::hosts`, redb's `current`
  table and stored `Fresh`, an unused dependency); five tests that passed for the wrong reason.
- Scripts: demo narration and assertions, the three bench `up.sh` scripts run end to end against
  the stand-in IdP, a `demo-push` make target, `deploy/gateway/.env.example`'s `issuer set` command.
- Code defects found by the sweep, each with a test: keystore files and directories created wider
  than 0600 / 0700 (one writer now, `keystore::write_private`); a resync after `wires restore` on a
  host that is also a directory; `wires call` with no token dialing a directory; a directory
  serving an expired policy; a refused call not marking the view as behind; the gateway telling a
  user no role matches to "try again"; `wires inbox` exiting 0 when not admitted; three log lines
  for one refusal; an unreachable IdP costing a fetch per token; no silence timeout on a replica
  subscription.

**Final run** (integrator, quiet machine, `simplify` at the merge): clippy `-D warnings`, `cargo
fmt --check`, shellcheck and shfmt clean; `cargo test --workspace` green (145 library, 409 wires,
doctests); all four demo runs pass (`demo-remote-cli`, `demo-push`, native service in Python and
TypeScript).

**Left for the human.**
- The removed-host window is the policy head's lifetime (90 days by default). A shorter default
  narrows it and makes the admin re-sign more often ([card 45](../backlog/45-trim-policy-sync.md)).
- `Matcher` has optional signed fields, against protocol.md §1 (not exploitable: the items hash
  re-serializes). Smallest fix: plain strings with empty meaning "any", and a new item format.
- Renames not done because they cross the wire or forty files: `StateVersion` / `state_version`
  → policy version; `Error::FabricMismatch`; `library::registry`; `caller/jwks.rs` is shared by
  host, directory and gateway. `RemoteTool` goes with [card 44](../backlog/44-cut-aliases-and-overrides.md).
- Unexplained: in two hand runs, the first admin edit after restarting a host that is also a
  directory reached 1 of 2 directories (exit 0, "not reached").
- Trace-capture tests can miss events when tests run in parallel (seen once in
  `push::tests::a_banned_persons_fetch_drops_the_queue`; passes on rerun). The e2e tests don't
  assert the per-call log line for the same reason.
- Benchmarks were not re-run on this code. Their setup signs in once and a Google sign-in lasts an
  hour, so a full run can outlast it. `bench/bench.py`'s wires-only prompt says "tool name".
- A service run as a separate Unix user can't reach its push socket (0700, owned by `serve`'s
  user); `deployment.md`'s sudoers sketch is untested.
- Unreachable branches kept: the `None`-principal paths in `call_trace`, `Identities::record` and
  `authorize`.
- `CLAUDE.md` still says "The goal is a sharp demo for the MCP team"; MCP is now a bridge.
- `wires mcp` still speaks five MCP protocol versions for older clients.
- The demo recording is gone from the README and must be redone ([card 08](../doing/08-demo-two-machine.md)).

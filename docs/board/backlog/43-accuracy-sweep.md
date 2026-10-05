# 43 — Accuracy sweep: nothing says what is no longer true

**Stage:** 4 · **Depends on:** [39](39-premise-and-story.md), [40](../done/40-cut-records.md), [41](../done/41-idp-membership.md), [42](../done/42-caller-identity-for-services.md) merged · **Status:** backlog · **Files:** all of them, read-mostly

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

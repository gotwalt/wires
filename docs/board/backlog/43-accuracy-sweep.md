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

## Acceptance

- [ ] `cargo test --workspace`, clippy `-D warnings`, `cargo fmt --all --check`, shellcheck and shfmt green; the demo scripts pass in `--quiet`.
- [ ] `git grep -niE 'badge|membership|invite|wires watch|watch_records|call.log|audit|otlp|reader|record-marks|issued\.json|ledger'` returns only deliberate hits, each listed in *Notes* with why it stays.
- [ ] *Notes* holds the findings: fixed, and left for the human.

## Notes

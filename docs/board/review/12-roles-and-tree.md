# 12 — Organize by role: CLI surface and file tree

**Lane:** R · **Depends on:** 11 merged · **Blocks:** 13, 14, 15 (they build on the new layout) · **Files:** everything under `wires/` and `library/` (moves), `.scripts/`, `CLAUDE.md` layout section, `README.md` command table

## Why

The human's feedback (2026-09-23): it isn't clear which layer does what, for
example where IdP enforcement lives. `wires --help` lists 14 commands, most of
them plumbing (`grant`, `member`, `roster`, `import`, `connect`, `publish`,
`keygen`); `wires/` is 30 flat files with a 4.5k-line `main.rs`. The code should
read like the product: **four roles**.

| Role | Does | Commands (after 12–15) |
|---|---|---|
| **admin** | holds the root key, decides who's in | `init`, `invite`, `remove` |
| **host** | runs CLIs, decides what's exposed and who may call (IdP policy) | `serve host.json` |
| **caller** | an agent or person running remote CLIs | `join`, `login`, `call`, `tools`, `mcp` (MCP is backward compatibility only) |
| **observer** | watches calls | `watch <channel>` |

## Tasks (mechanical: no behaviour change except the removals listed)

- [x] **Remove single-command serve and `wires connect`**: `serve -- <cmd>`, the `Frame::Handshake`-only exec path in `serve_session`, `--scope`-matched single-command grants, `connect`, and their tests, keeping the equivalent coverage through `--expose`. Also remove `.scripts/connect.sh`, `serve-rg.sh`, `demo-mcp.sh`, `fake-mcp-server.py`, `demo-revoke.sh`, `demo-topic.sh`, `demo-topic-revoke.sh`. Keep `demo-remote-cli.sh` and `soak-topic.sh`. (MCP is a *caller-side* compatibility adapter, `wires mcp`, not something hosts serve.)
- [x] **CLI**: top-level help shows only the role commands. Everything else moves under `wires advanced <cmd>` (`keygen`, `grant`, `member`, `roster`, `revoke`, `import`, `publish`), unchanged. Rename `tail` → `watch` (keep `tail` as a hidden alias under `advanced`). Group commands in `--help` by role (clap `next_help_heading` or `help_template`).
- [x] **`wires/` tree by role**: `wires/host/` (serve, session transport, audit emission, idp_policy, identity index), `wires/caller/` (call, mcp, tools, login, jwks), `wires/channel/` (topics, admission, replay, store, ipc, render, idp_view), `wires/admin/` (keystore, roster/member/grant/import commands). `main.rs` shrinks to arg parsing and dispatch (< 400 lines); each role's clap `Args` live with the role. Tests move with their code; `e2e*.rs` go to `wires/tests_e2e/` or similar.
- [x] **`library/` tree**: `library/membership/` (identity, membership, roster, grant, ticket, policy, fabric_key), `library/channel/` (topic, envelope, chain, admission, replay, record), `library/calls/` (session, invoke, audit, idp). `lib.rs` re-exports stay identical, so the public API doesn't change.
- [x] BUILD: `srcs = glob(["**/*.rs"])` where needed; `rust_doc_test` still runs.
- [x] `CLAUDE.md` Architecture: update the "each package holds its *.rs files directly" line to describe the role folders. `README.md`: command table by role (a full README rewrite comes in card 17).

## Acceptance

- [x] `bazel test //...`, lint, format check green; `.scripts/demo-remote-cli.sh --quiet` green (updated for `watch` / `advanced`).
- [x] `wires --help` fits on one screen and shows the four roles.
- [x] `git diff --stat` shows mostly renames (`git log --follow` still works on moved files; use `git mv`).

## Notes

*2026-09-22, lane R (worker).* Branch commits, in order: envelope proptest
fix → removals → **pure `git mv`** (does not build alone, on purpose) → module
paths → CLI + `main.rs` split → scripts → docs.

**Removals.** `ServeConfig::{scope, command}` are gone; `scope: Option<Scope>`
became `require_grant: bool` (a grant must be `tool:<name>` or `tool:*`, as
before for `--expose`). `serve_session` always reads a `Frame::Invoke` after
the handshake (no invoke → `DENY_INVOKE_REQUIRED`, as before for multi-tool);
the stray-invoke path and `DENY_SINGLE_COMMAND` are gone. `connect_io` /
`connect_on` / `dial_on` folded into `call_on` (the one dialer). The audit
`"stdio"` tool name (`audit::stdio_tool`) is gone with the mode. `serve` with
nothing exposed refuses to start (`--expose` is
`required_unless_present = "expose_file"`). The transport/e2e tests that ran
single-command sessions now run the identical checks through one exposed tool
(`TEST_TOOL`, `tool_map`, `opening()` in transport's tests; `cat_tool()` in
e2e) — only `single_command_responder_refuses_an_invoke` was deleted.
`.scripts/BUILD` only wrapped `connect.sh`/`serve-rg.sh`, so it is deleted
too. The `Frame` enum in `library` is untouched (public API).
`HeadSource::None` is now test-only (`#[cfg_attr(not(test), allow(dead_code))]`
— the CLI's "no head yet" is an unarmed `Keystore` source).

**CLI.** The top-level `--help` is a hand-written `help_template` (clap can't
put subcommands under several headings);
`main::tests::help_lists_every_visible_command` fails if it drifts from
`Command`. Admin currently shows only `advanced` — card 14 adds
`init`/`invite`/`remove` under that heading. `wires advanced tail` is a hidden
alias of `watch`. Every remedy message and doc now says
`wires advanced import …` / `wires watch` (perl over `wires/` and `library/`
docs and strings); stderr banners say `wires watch:` (nothing greps them).

**Where things live now** (for 13/14/15):
- `host/serve.rs` — `ServeArgs`, `serve_cmd`, `serve_identities`,
  `audit_context_in`. Card 13: add `host/config.rs` (host.json) and
  `host/policy.rs` beside `idp_policy.rs`; `transport::authorize` is still the
  one place every check runs. Card 15: `host/announce.rs`.
- `caller/` — `call`, `mcp`, `tools`, `login`, `jwks`, `mock_idp`. Card 15:
  `caller/resolve.rs`; card 14: `join` here.
- `admin/` — `keystore.rs` (now also `token_arg` and `preflight`), `keys.rs`
  (keygen/grant/member/revoke), `roster.rs`, `import.rs`. Card 14:
  `init`/`invite`/`remove` as siblings, added to `Command` and to the Admin
  heading of `HELP_TEMPLATE` in `main.rs`.
- `channel/` — `context.rs` (`TopicArgs`, `TopicContext`), `local.rs`
  (`append_local`, `open_topic_store`, `current_fabric_key`), `printer.rs`
  (`Keyring`, `Printer`), `peers.rs` (`PeerBook`), `watch.rs` (the resident
  loop: `watch_cmd`, `run_tail`, `run_tail_on`, `publish_from_tail`),
  `publish.rs`, plus topics/admission/replay/store/ipc/render/idp_view.
- `advanced.rs` — the `wires advanced` enum + dispatch. `testutil.rs` —
  `temp_dir`, `fabric_fixture`, `commit_args`, `Member`/`provisioned`.
- Folders in `wires/` are `mod.rs` modules (each `mod.rs` says what the role
  does and where the next cards land). Folders in `library/` are **not**
  modules: `lib.rs` declares every module at the crate root with
  `#[path = "membership/grant.rs"]` etc., so `library::grant::…` paths and the
  re-exports are unchanged (a real `membership/` module would also have
  collided with `membership.rs`).

**Numbers.** `main.rs` 4559 → 349 lines. Tests: `wires_test` 312 (309 before:
+3 CLI tests), `library_test` 253, `library_doc_test` 45; lint and
`format.check` green; `demo-remote-cli.sh --quiet` green (11 s). Overall
`git diff --stat 70aa329..` is 74 files, +5629/−7332: the 38 moves are 100%
renames (`git log --follow` works); most of the rest is `main.rs` being split
into new files and the README reference being trimmed.

**Docs.** README: command table by role plus an `advanced` table, Layout by
role folder; the Flow A / Flow B / MCP-bridge-verification / rg quick-try
sections went with `connect`; the revoke gif stays with a note (card 08
re-records). `docs/deployment.md` got an "examples predate card 12" banner
rather than a rewrite; `docs/testing.md`'s live-session recipe points at the
demo. Historical docs (restart.md, storytelling.md, phase2-topics.md,
archive/) still name the removed scripts — left as history.

Final tree (`.rs` only):

```
library/  lib.rs error.rs codec.rs
  membership/  identity membership roster grant ticket policy fabric_key
  channel/     topic envelope chain admission replay record
  calls/       session invoke audit idp idp_vectors
wires/    main.rs advanced.rs testutil.rs
  admin/    mod keystore keys roster import
  host/     mod serve transport audit identity idp_policy
  caller/   mod call mcp tools login jwks mock_idp
  channel/  mod context local printer peers watch publish
            topics admission replay store ipc render idp_view
  e2e/      mod (was e2e.rs) idp (was e2e_idp.rs)
```

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

- [ ] **Remove single-command serve and `wires connect`**: `serve -- <cmd>`, the `Frame::Handshake`-only exec path in `serve_session`, `--scope`-matched single-command grants, `connect`, and their tests, keeping the equivalent coverage through `--expose`. Also remove `.scripts/connect.sh`, `serve-rg.sh`, `demo-mcp.sh`, `fake-mcp-server.py`, `demo-revoke.sh`, `demo-topic.sh`, `demo-topic-revoke.sh`. Keep `demo-remote-cli.sh` and `soak-topic.sh`. (MCP is a *caller-side* compatibility adapter, `wires mcp`, not something hosts serve.)
- [ ] **CLI**: top-level help shows only the role commands. Everything else moves under `wires advanced <cmd>` (`keygen`, `grant`, `member`, `roster`, `revoke`, `import`, `publish`), unchanged. Rename `tail` → `watch` (keep `tail` as a hidden alias under `advanced`). Group commands in `--help` by role (clap `next_help_heading` or `help_template`).
- [ ] **`wires/` tree by role**: `wires/host/` (serve, session transport, audit emission, idp_policy, identity index), `wires/caller/` (call, mcp, tools, login, jwks), `wires/channel/` (topics, admission, replay, store, ipc, render, idp_view), `wires/admin/` (keystore, roster/member/grant/import commands). `main.rs` shrinks to arg parsing and dispatch (< 400 lines); each role's clap `Args` live with the role. Tests move with their code; `e2e*.rs` go to `wires/tests_e2e/` or similar.
- [ ] **`library/` tree**: `library/membership/` (identity, membership, roster, grant, ticket, policy, fabric_key), `library/channel/` (topic, envelope, chain, admission, replay, record), `library/calls/` (session, invoke, audit, idp). `lib.rs` re-exports stay identical, so the public API doesn't change.
- [ ] BUILD: `srcs = glob(["**/*.rs"])` where needed; `rust_doc_test` still runs.
- [ ] `CLAUDE.md` Architecture: update the "each package holds its *.rs files directly" line to describe the role folders. `README.md`: command table by role (a full README rewrite comes in card 17).

## Acceptance

- [ ] `bazel test //...`, lint, format check green; `.scripts/demo-remote-cli.sh --quiet` green (updated for `watch` / `advanced`).
- [ ] `wires --help` fits on one screen and shows the four roles.
- [ ] `git diff --stat` shows mostly renames (`git log --follow` still works on moved files; use `git mv`).

## Notes

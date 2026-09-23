# 07 — Loopback demo script

**Lane:** E · **Depends on:** 01–05 · **Files:** new `.scripts/demo-remote-cli.sh`, `.scripts/BUILD` if needed, seed data under `.scripts/fixtures/`

## Goal

One self-asserting script that stands up the whole story on one machine, in the
style of `.scripts/demo-mcp.sh` (`--quiet`, `--keep`, fresh `mktemp -d`, never
touches `~/.config/wires`, narrated by default).

## Script

1. Keystores: `root` (you), `workbench` (responder), `agent` (caller), `observer`.
2. Roster: all three members; commit; import proofs + fabric keys.
3. Seed a small SQLite `orders.db` fixture.
4. `workbench`: `wires serve --expose 'db_query=sqlite3 -safe -readonly orders.db' --audit-topic ops --require-idp …` (mock issuer for the scripted run; real Google in card 08).
5. `observer`: `wires tail ops` in the background, output captured.
6. `agent`: `wires login` (mock) → `wires call db_query -- "select count(*) from orders"`
   → assert output; then the same through `wires mcp` over pipes (JSON-RPC).
7. Assert the observer saw: identity line (verified), `▶` + `■` for both calls, with the
   agent's email.
8. Negative: `wires call db_query -- ".shell id"` → sqlite `-safe` refuses; logged with nonzero exit.
9. Revoke: root removes `agent`, commits, imports head on workbench (and observer).
   Next call exits 77, zero stdout bytes; observer shows `✗ … denied`.
10. Print a 5-line summary of what was proven.

## Acceptance

- [x] Green twice in a row from a clean checkout; < 30 s with `--quiet`.
- [x] Wired into `bazel test` if the existing demo scripts are (check `.scripts/BUILD`); otherwise documented in README quickstart.

## Notes

**Worker, 2026-09-22.** `./.scripts/demo-remote-cli.sh` (+ `.scripts/fixtures/orders.sql`).
Two runs in a row from a clean state, each green in 6.5 s and 7.4 s with `--quiet`. A narrated
run takes about 1 min. `--with-claude` was green once (`claude -p` answered "umbrella" and
its SQL showed up on the channel as `▶ … alice@example.com … db_query "SELECT customer, SUM(total) …"`).

### What it asserts (in order)

1. The workbench `serve --expose 'db_query=sqlite3 -safe -readonly -header -column DB' --audit-topic ops
   --require-idp 'iss=<mock>,email=*@example.com' --oidc-audience wires-test-client` prints its
   ticket. The agent dials `--node WB --addr 127.0.0.1:<port from the ticket>`.
2. The observer runs `tail ops --peer <ticket>` with `WIRES_OIDC_ISSUER`/`WIRES_OIDC_AUDIENCE` set to the mock.
3. Before login: `wires call` exits 77 with `no identity claim`, 0 bytes out, and
   `✗ <ag4>… db_query denied: no identity claim for <ag8>` shows up on the observer.
4. `wires login --topic ops --peer <ticket> --issuer <mock> --client-id … --no-browser`, with `curl -L` on
   the printed URL standing in for the browser. The observer shows
   `🪪 identity <ag8> is alice@example.com (verified by <mock>)`.
5. The args call, the stdin call, and an MCP `tools/call` (`wires mcp` over a FIFO:
   initialize → tools/list → tools/call) each return the right rows. Each `▶` names the email and
   the SQL. For the stdin call, the SQL is in the `■` line's `stdin "…"`. Each `■ <id> exit 0` is
   pinned to its `▶` by call id. The args call's stderr is empty.
6. `.shell id`: sqlite3 prints `cannot run .shell in safe mode` and exits 1 (not 77), no `uid=` shows
   up, and `▶ … ".shell id"` + `■ <id> exit 1` are on the channel.
7. Revoke: `roster remove` + `commit` + `import` v2 on the workbench and the observer. The next call exits 77
   with 0 stdout bytes, and the observer shows `✗ <ag4>… db_query denied: roster inclusion rejected: stale …`.
   The workbench and observer pids are still alive and unchanged.
8. A 6-line summary: reach, identity, observable, contained, revoke, restarts.

### Mock IdP: a feature-gated second build, not a new crate or pip

The card 04 issuer (`wires/mock_idp.rs`) was `#[cfg(test)]`. It depends on `login.rs`'s
HTTP helpers and `Pkce`, so lifting it into its own crate would mean moving those too. Instead,
`//wires:wires_dev` is the same `srcs`/deps with `crate_features = ["dev-mock-idp"]`, which compiles
`mod mock_idp` and a hidden `wires dev-mock-idp --email E` subcommand (prints `issuer <url>` and
`client_id <id>`, then serves until killed). `//wires` and `//wires:image` are unchanged, and
`wires --help` has no trace of it. Cost: a second compile of the wires crate (~1 min cold). Everything
the demo proves runs on the shipped `bazel-bin/wires/wires`. Only the IdP process is `wires_dev`.
`wires login` needed no change, because `--no-browser` prints the URL and the mock's `/authorize` 302s
straight to the loopback callback.

### Bazel test: not wired, following suit

`.scripts/BUILD` only has `sh_binary` targets for `connect`/`serve-rg`. No `demo-*.sh` is
a Bazel test, because they need real sockets, a real `sqlite3`, and `bazel-bin` binaries. This one is
documented in README "What runs today" and the demo status note instead (README only).

### Bug found and fixed (small, in scope): `wires call` hung when run from a terminal

`serve_session` awaited the dialer's stdin pump after the child exited. When the caller's stdin
never reaches EOF (a terminal, or the harness socket my first narrated run had), a
`wires call db_query -- "select …"` printed its rows and then hung until Ctrl-D. The `■` was never
written either. It only showed up under the narrated run. The fix is one line in `wires/transport.rs`:
abort the stdin task once the child is reaped (the dialer already aborts its side on `Exit`).
The regression test `session_ends_when_the_child_exits_with_dialer_stdin_still_open` (duplex
stdin held open) was red before the fix and is green after. Off-lane: `wires/transport.rs` (lane A/G).

### Other observations (not fixed)

- `--allowedTools` in `claude -p` is variadic and swallows a following prompt. The script uses
  `--allowedTools=mcp__wires__db_query`. Card 08 should do the same.
- In the hung run the responder logged `replay pass … timed out after 20s` against the agent's
  departed one-shot login node every ~80 s. It's harmless, but it's noise in `serve`'s stderr on camera.
- `wires tools add` has no way to take the audit ticket, so the script base64-decodes the ticket to
  get the `127.0.0.1` port. For card 08, over the relay, `--node` alone should be enough.

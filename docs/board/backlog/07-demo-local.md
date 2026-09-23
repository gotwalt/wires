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

- [ ] Green twice in a row from a clean checkout; < 30 s with `--quiet`.
- [ ] Wired into `bazel test` if the existing demo scripts are (check `.scripts/BUILD`); otherwise documented in README quickstart.

## Notes

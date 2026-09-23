# 10 — Fixes from the first live run

**Lane:** G · **Depends on:** 01–04 · **Files:** `library/audit.rs` (Finished fields only), `wires/audit.rs` (stdin tap), `wires/transport.rs` (stdin pump only), `wires/render.rs` (Finished line only), `wires/mcp.rs` (schema text), `wires/ipc.rs` (socket path), logging init in `wires/main.rs`

## Context

First end-to-end run (2026-09-22, integrator, loopback): a headless `claude -p`
session with `wires mcp` answered a question by calling `db_query` three times
against `sqlite3 -safe -readonly` behind `serve --expose … --audit-topic ops`,
and an observer's `wires tail ops` showed every call live. It works. It
also turned up these problems:

## 1. Stdin is invisible to observers (the important one)

Claude sent its SQL on **stdin**, not as `args`. The observer saw
`▶ b7c0 aad4… db_query` with no query at all: the most interesting part of the
call wasn't logged. A skeptic will notice this right away.

- Add to `AuditRecord::Finished`: `stdin_bytes: u64`, `stdin_digest: OutputDigest`,
  and `stdin_head: Option<String>`, which holds the first 4 KiB of stdin
  (lossy UTF-8, truncated on a char boundary, `None` if empty). All serde-default
  so older records still parse. Tap the Stdin frames in the responder's pump the
  same way stdout is tapped (reuse `OutputHasher`).
- Render: `■ b7c0 exit 0 · 8 ms · stdin "select customer, sum(total) …" · 92 B out · blake3 09b7…`
  (collapse whitespace, cap ~80 chars on the line; full text in `--json`).
- `wires mcp` schema text: describe `args` as the primary way to pass input
  ("arguments appended to the remote command, e.g. the SQL statement") and
  `stdin` as secondary. Don't remove stdin.

## 2. Log noise on every call

`wires call` prints `ERROR iroh::socket::transports::relay: relay_recv_channel closed`
(sometimes twice) on stderr when a call ends normally. Default the logging filter
so iroh's teardown chatter stays below the default level for `call`, `mcp` and
`connect` (e.g. `iroh=off` unless `RUST_LOG` is set), and check that `wires call`
leaves stderr clean on success.

## 3. Control socket path too long → responder dies

With a deep `$WIRES_HOME`, `serve --audit-topic` (and `tail`) exits with
`path must be shorter than SUN_LEN`. macOS caps it at 104 bytes. If the socket
path would be too long, fall back to a short path under
`$TMPDIR`/`/tmp` (`wires-<uid>/<16-hex-of-blake3(full path)>.sock`, dir 0700),
and make sure `publish` finds it the same way. Test with a 120-char home.

## Acceptance

- [ ] Unit/proptest: Finished round-trips with and without the new fields; an old record without them still parses; stdin_head is truncated on a char boundary.
- [ ] e2e: a call that sends its input on stdin → observer's Finished has the right stdin_bytes/digest/head.
- [ ] `wires call` against a loopback responder: stderr empty on success.
- [ ] Long `$WIRES_HOME` (>104-byte socket path): `serve --audit-topic` runs, and `publish` reaches it.
- [ ] `bazel test //...`, lint, format check green.

## Notes

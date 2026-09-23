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

- [x] Unit/proptest: Finished round-trips with and without the new fields; an old record without them still parses; stdin_head is truncated on a char boundary.
- [x] e2e: a call that sends its input on stdin → observer's Finished has the right stdin_bytes/digest/head.
- [x] `wires call` against a loopback responder: stderr empty on success.
- [x] Long `$WIRES_HOME` (>104-byte socket path): `serve --audit-topic` runs, and `publish` reaches it.
- [x] `bazel test //...`, lint, format check green.

## Notes

**1. Stdin.** `library::StdinCapture` (OutputHasher + first `STDIN_HEAD_MAX` =
4096 bytes) and `library::stdin_head` (lossy UTF-8; a char split by the cap is
dropped, not shown as U+FFFD; the byte cap is re-applied after decoding because
replacement chars grow the text). `OutputDigest::empty()` is the serde default
for `stdin_digest`, so an old Finished reads as "no stdin" (bytes 0, empty
digest, head `None`). `stdin_head` is omitted from JSON when `None`.
`wires/audit.rs::tap_stdin(Option<&CallAudit>) -> StdinTap` is fed explicitly in
`serve_session`'s stdin task (search `// audit: stdin`), *before* the write to
the child, so it records what the caller sent even if the child stops reading.
Render: `render::stdin_preview` collapses whitespace, caps at 80 chars, appends
` …` when cut (or when `stdin_bytes` exceeds the head), and Debug-quotes it so
control chars and quotes are escaped. The stdin segment is omitted when there
was no stdin. The existing card-02 e2e already piped its input on stdin; it now
asserts the three stdin fields.

**2. Log noise.** `init_quiet_logging()` (`warn,iroh=off`) for `call`, `mcp`
and `connect`; everything else keeps `warn,wires=info`. The quiet filter also
drops wires' own `info` lines ("dialing…", "remote child exited"), since the
card asks for an empty stderr on success. `iroh=off` matches `iroh_gossip` /
`iroh_relay` too (EnvFilter targets match by prefix). `$RUST_LOG` still
overrides. Live check (loopback `serve --expose … --audit-topic ops`, 8 calls,
with and without stdin): exit 0, **0 bytes** on stderr every time.

**3. Socket path.** `ipc::socket_path` keeps `<home>/run/<16hex>.sock` when it
fits (`fits_sockaddr`: len < `SUN_PATH_BYTES`, 104 macOS / 108 Linux), else
`short_socket_path` → `$TMPDIR/wires-<uid>/<16 hex of BLAKE3(full path)>.sock`,
falling to `/tmp/…` if `$TMPDIR` is itself too deep. uid = owner of the home dir
(no libc dep). BLAKE3 via `library::OutputHasher` (wires has no blake3 dep).
`ensure_private_dir` now also refuses a socket dir that is a symlink or still
has group/other bits after the chmod (another user could pre-create
`/tmp/wires-<uid>`). Live check: 118-char home → responder bound
`/var/folders/…/T/wires-501/ef1f….sock` (dir `drwx------`), `wires publish`
from that home reached it (seq 0), and a call's records followed on the channel.

**Off-lane touches.** `wires/main.rs` test
`preflight_resolves_a_provisioned_member` asserted the socket is under the home;
the Bazel sandbox home is deep enough to take the fallback, so it now asserts
`ctx.socket_path() == ipc::socket_path(&home, topic)`. `library/record.rs` test
sample gained the new fields.

**Flake seen once:** `e2e::every_call_and_refusal_lands_on_the_audit_topic`
failed one `bazel test //...` run (first dial: "reading frame length:
connection lost") while gazelle was compiling alongside; 4/4 isolated reruns
and the next full run passed. Looks like load-sensitive loopback timing, not
this change.

**Tests:** library 253 + doctests 45, wires 286, all green. Lint (`bazel build
--config=lint //...`): only the pre-existing `HeadSource::None` dead-code
warning. Format check clean.

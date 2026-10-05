# 40 — Cut the call log, OTLP export and `wires watch`

**Stage:** 1 (parallel with [42](42-caller-identity-for-services.md)) · **Depends on:** — · **Status:** backlog · **Files:** `library/calls/{audit,call_log}.rs`, `wires/host/{audit,call_log,otlp,record_stream}.rs`, `wires/caller/watch_records.rs`, `wires/e2e/records.rs`, and their hooks in `wires/host/{transport,gate,serve,config,native,push,capability}.rs`, `library/services/{entry,view,signed_policy,access}.rs`, `wires/admin/service.rs`, `wires/caller/{call,services,view}.rs`, `wires/directory/`, `wires/gateway/`, `wires/lib.rs`, `wires/help.rs`, `wires/snapshots/`, `bindings/`, `.scripts/`, `docs/protocol.md`

## Why (the human, 2026-10-05)

"I think we can cut the signed log / otlp / watch for now. It's not
compelling enough in its current form and a future re-envisioning might
help." The premise no longer has records in it
([board](../README.md)). The log is also the largest thing on the host that
is not the call: about 6k lines with its tests, a second ALPN, a file that is
unique to each host (which is what makes a host stateful), and two defects
found in review (after day 30 nearly every append rewrites the whole log on
the thread that gates each call; a call refused on a log timeout still
leaves a `started` record behind).

## What goes

- **The signed, hash-linked call log**: `AuditRecord`, `LogEntry`, the chain,
  `call-log.jsonl`, retention and pruning, `AuditSink`, `CallAudit`, the
  `Started`-before-spawn gate and its timeout, the stdout hash and the stdin
  capture taps in the bridge.
- **OTLP export**: `wires/host/otlp.rs`, `host.json`'s `audit` section.
- **The record stream and `wires watch`**: ALPN `wires/records/1`,
  `record_stream.rs`, `watch_records.rs`, `record-marks.json`, hidden links,
  anchors and marks, per-person record isolation.
- **Readers**: `Service.readers`, `--reader`, the `call` / `read` marks on a
  view entry (every entry in a view is one the caller may call), the reader
  role in the docs. This changes signed bodies: follow protocol.md §1 (a new
  format discriminant; an old verifier rejects it).
- **Push bodies in the log**: `host.json`'s `push.log_body`.
- Everything that only existed to feed the above. `CallId` stays only if
  push or the native API still need it after the cut; decide and say so in
  *Notes*.

## What stays

- **One ordinary log line per call**, through `tracing`, at `info`: when a
  call ends (service, caller node, the person's issuer / subject / email,
  role, exit code, duration, bytes out) and when an identified caller is
  refused (the same, with the reason). No argv, no stdin, no signature, no
  file of its own. An operator who wants a record points their log collector
  at `wires serve`'s output. A refusal of a caller with no valid identity is
  traced as today.
- Push, the inbox and the per-call push capability, unchanged in behaviour.
- The gate, unchanged in what it decides.

## Do, in this order

1. `docs/protocol.md`: delete §8 and every reference to records, readers,
   `watch`, OTLP and the log across the other sections; add one line to §10
   (limits) saying wires keeps no call record beyond the host's ordinary log
   line, and that a signed record is a future design.
2. Types and tests, then the code (CLAUDE.md order). Delete the tests of
   deleted behaviour; add a test that a call and a refusal each emit the log
   line with the fields above.
3. `wires --help`, `--help-all`, the snapshots (`WIRES_BLESS=1 cargo test -p
   wires help_snapshots`; the diff is the review), every error message that
   says "log", "record", "watch" or "reader".
4. `.scripts/`: all three demo scripts and their fixtures, narration
   included (the narrated run is the screencast), `bindings/` examples, and
   anything in `bench/` that calls `wires watch` or sets `--reader`.
5. Grep for what's left (rule: a deletion is finished when nothing mentions
   it): `watch`, `reader`, `record`, `audit`, `call log`, `call-log`,
   `otlp`, `OTLP`, `hash-link`, `blake3` where it meant the output hash,
   `record-marks`, `wires/records/1`, `log_body`. Fix code, comments and
   help in your lane; list hits in the narrative docs in *Notes*.

## Acceptance

- [ ] `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`, shellcheck and shfmt (via `uvx`, see the board rules) all green.
- [ ] `.scripts/demo-remote-cli.sh --quiet` and `.scripts/demo-push.sh --quiet` pass; `.scripts/demo-native-service.sh --lang python` and `--lang node` pass or the reason they couldn't run here is in *Notes*.
- [ ] No ALPN `wires/records/1`, no `wires watch`, no `call-log.jsonl`, no `readers` in a signed body.
- [ ] `docs/protocol.md` describes exactly what the code does.
- [ ] *Notes* lists every statement in the narrative docs this card made false (file and line or heading).

## Notes

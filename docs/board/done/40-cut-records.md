# 40 — Cut the call log, OTLP export and `wires watch`

**Stage:** 1 (parallel with [42](42-caller-identity-for-services.md)) · **Depends on:** — · **Status:** done (merged into `simplify` 2026-10-05) · **Files:** `library/calls/{audit,call_log}.rs`, `wires/host/{audit,call_log,otlp,record_stream}.rs`, `wires/caller/watch_records.rs`, `wires/e2e/records.rs`, and their hooks in `wires/host/{transport,gate,serve,config,native,push,capability}.rs`, `library/services/{entry,view,signed_policy,access}.rs`, `wires/admin/service.rs`, `wires/caller/{call,services,view}.rs`, `wires/directory/`, `wires/gateway/`, `wires/lib.rs`, `wires/help.rs`, `wires/snapshots/`, `bindings/`, `.scripts/`, `docs/protocol.md`

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

- [x] `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`, shellcheck and shfmt (via `uvx`, see the board rules) all green.
- [x] `.scripts/demo-remote-cli.sh --quiet` and `.scripts/demo-push.sh --quiet` pass; `.scripts/demo-native-service.sh --lang python` and `--lang node` pass or the reason they couldn't run here is in *Notes*.
- [x] No ALPN `wires/records/1`, no `wires watch`, no `call-log.jsonl`, no `readers` in a signed body.
- [x] `docs/protocol.md` describes exactly what the code does.
- [x] *Notes* lists every statement in the narrative docs this card made false (file and line or heading).

## Notes

### Decisions (worker, 2026-10-05)

- **`CallId` is gone**, and `Call::id()` with it (Rust, Python `id()`,
  TypeScript `id()`). After the cut only the log used it: push needs the
  capability's caller, not a call id, so the capability no longer binds to
  a call (`bind_call` removed) and `PushCommand` / the queue `Entry` carry no
  `call`. Old `push-queue.json` files with a `call` field still load (the
  field is ignored).
- **The log line** is `wires/host/call_trace.rs`: `call finished` at
  `info` with `service`, `caller`, `issuer`, `subject`, `email`, `role`,
  `exit`, `duration_ms`, `bytes_out`; `call refused` at `info` with the
  same minus role/exit/duration/bytes, plus `reason`, only when the host
  verified an identity. A refusal of an admitted caller with no identity
  is `debug`. "Bytes out" is stdout plus stderr bytes sent to the caller.
  `session accepted` moved from `info` to `debug`, and `service exited;
  closing session` is gone, so a call is exactly one `info` line.
- **Push milestones** (`queued`, `delivered`, …) are traced at `debug`
  (id, recipient, subject, reason; never the body). Behaviour unchanged.
- **Signed bodies:** `SignedEntry` is format 2 (`ENTRY_V2`); format 1 is
  refused with `UnsupportedVersion`, and a `readers` field is refused at
  decode (`Service` denies unknown fields). The policy head stays format 3
  (its shape didn't change; the entries inside it did). A view is
  `{head, entries: [SignedEntry]}`; `ViewEntry` and the `call`/`read`
  marks are gone, so `wires services --json` lost its `call`/`read`
  fields. **This is a breaking change for existing networks:** a
  `policy.json`, `view.json` or `directory.redb` written before it doesn't
  parse; re-`init` a test network after merging (card 41 breaks it again).
- `host.json`'s `audit` section and `push.log_body` are now unknown keys,
  so a host.json that still has them is refused (`unknown field`), not
  silently ignored.
- `docs/protocol.md`: §8 deleted and the sections after it **renumbered**
  (Keystore is §8, Known limits §9); internal references updated. The log
  line is specified in §5 (it is part of the session); the limit is in §9.
  The premise paragraph at the top now states the 2026-10-05 premise.
- `wires/caller/hello.rs`: `with_membership` was used only by `wires
  watch`; deleted. The module keeps `stored_token`.
- The `wires --help` premise (`help::PREMISE`, also the MCP instructions)
  no longer says the host records the call.
- The demo personas: the observer is now `carol@partner.example`, signed
  in but in no role (it was `sec@audit.example`, role `security`, a
  reader). demo-remote-cli lost its step 6 (watch); its steps 7–9 are now
  6–8. demo-push lost its step 5; step 6 is now 5.
- Log-line assertions are in unit tests (`host/call_trace.rs`,
  `host/transport.rs` in-memory sessions). I tried them in the iroh e2e
  tests too, but a thread-local tracing capture there misses host-side
  events when the e2e tests run in parallel (reliable alone, flaky in the
  full run), so the e2e tests assert behaviour only.

### Narrative-doc statements this card made false (for cards 39/43)

- `README.md` § How it works, lines 57–61 (signed record of each call;
  readers; `wires watch`) and 68 ("and records"); § wires and a remote MCP
  server, line 149 (**Record of calls** row); § Limits, lines 165–166
  (withhold or truncate its own log).
- `docs/usage.md` § Roles line 16 (**reader** row); § Where each guarantee
  lives line 30 (**Records** row); § Walkthrough lines 40 and 63 (observer
  `sec@audit.example`, `role set security`), 87 (`--reader security`), 190
  (view marked `read`), 220–243 (step 6, the reader reads the records); §
  Host: native services lines 277–278 (`wires watch`, "the same call
  log"); line 372 (the host's log through `wires watch`); § Why it's built
  this way lines 437–438 (signed, hash-linked log a reader asks for); §
  Known trade-offs lines 513–517 (revoked grant takes records), 540
  (`wires watch` staleness), 547–548 (withhold or truncate its log), 555
  (`watch` isn't an MCP tool); § Reference: line 593 (quotes the old
  premise "records the call"), 597 (`watch` in the caller commands), 614
  (`[--reader role]…`), 628 (**reader** row), 663–664 (`push.log_body`,
  `audit.otlp`), 695 (link `protocol.md#9-keystore…`: the keystore is now
  §8), 696 (`record-marks.json`), 729 (`calls/` holds audit records and the
  call log).
- `docs/fabric.md` § 1 line 27 (a host signs its call records); § 2 lines
  40 (host signs every call into its own log, serves the record stream),
  42 (**Reader** row); § 4.1 lines 82–83 (host/caller files around the
  log and `record-marks.json`, if listed there); § 5 line 147 (**Call
  records** row), 163 (record stream to a reader); § 6 lines 207–209
  (**Watch** flow); § 7 line 216 (`wires/records/1`); § 9 lines 258–261
  (`wires watch`, call logs as hash chains, card 09).
- `docs/demo.md` § Cheat sheet lines 22, 25, 36–37 (reader pane, step 5
  `wires watch`); § Rebuttals lines 48, 51 (gateway logs vs the host's log;
  can't the host edit its log); § Cast line 65 (reader); § Before
  recording lines 74–75, 102, 108 (`role set security`, `--reader
  security`), 114–119 (reader keystore), 127; § The recording line 149
  (three panes incl. reader), 199 ("writes each call into its own signed
  log"); § 5 The reader reads the records (lines 209–228); § 5b line 278
  (`wires watch` shows the chain); § Closing line 320 ("every call
  recorded"); § Things not to say lines 333–338 (records, readers, hash
  links).
- `docs/deployment.md` § What you deploy line 14 (**Reader** row), 20
  ("isn't written to the call log"), 30 (a reader); § Run services as a
  separate Unix user line 67 (node key signs the call log); § Keystore and
  secrets line 91 (`call-log.jsonl`); § Reachability lines 171, 176
  (readers' hints, `watch`); § A web gateway lines 225 ("records it"), 242
  (`watch` not offered).
- `docs/executive-summary.md` § The problem line 16 (records of what agents
  did — the claim wires answered it); § What Wires is line 27 (**Reader**);
  § What's been demonstrated line 40 ("records kept by each host"); § Why
  it's built this way line 67 (host writes the signed, hash-linked log); §
  Honest limits line 76 (withhold or truncate its log).
- `docs/testing.md` § Automated tests line 22 (audit records and the call
  log); § The live demo line 59 (a reader on `wires watch`; the demo's
  steps are renumbered).
- `docs/agent-sandbox.md` lines 20, 69–70, 157, 183 (the host's call record
  of argv / stdin count, digest and head).
- Outside the narrative list but stale: `CLAUDE.md` § Project Overview line
  49 ("push, the call log and record stream, hints" as protocol.md's
  contents) — I changed only the architecture section, as instructed;
  `bench/state-scale/REPORT.md` lines 21, 127–137 (reader roles, the
  record stream and `wires watch` in its table; a dated report, left as
  is). The blog post (`docs/blog/introducing-wires.md`) has no hit.

### Verification (worker, 2026-10-05, this machine: Linux, Node 22.22, uv)

- `cargo test --workspace`: green (library 154 unit + 50 doctests and
  examples; wires 384; bindings 3 + 2). Baseline was 177 / 437: the
  difference is the deleted call-log, record-stream, watch and OTLP tests.
- `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt
  --all --check`: clean.
- `uvx --from shellcheck-py shellcheck` and `uvx --from shfmt-py shfmt -d`
  over every tracked `*.sh` and `.githooks/pre-commit`: clean.
- `.scripts/demo-remote-cli.sh --quiet`, `.scripts/demo-push.sh --quiet`,
  `.scripts/demo-native-service.sh --lang python` and `--lang node`: all
  pass. A `--keep` run of demo-remote-cli shows the spare's `wires serve`
  output holding `call finished service=orders-db … email="alice@example.com"
  role=analyst exit=0 duration_ms=4 bytes_out=27` for the failover call.

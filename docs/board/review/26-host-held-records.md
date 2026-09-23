# 26 — Call records: host-held signed logs, streamed per service to authorized readers

**Lane:** H2 · **Depends on:** 27 merged (services, not hosts; no channel) · **Blocks:** the recording (card 08) · **Files:** `wires/host/audit.rs` and log storage, a new record-stream protocol, `wires/channel/watch.rs`, `host.json` (`audit` section), render, `demo-remote-cli.sh`, docs

## Why (the human, 2026-09-23)

Every member of the org channel currently receives, stores and can decrypt
every call record: caller identity, argv, the first 4 KiB of stdin. *"Unintentionally
receiving an entire organization's tool call data is bad and a huge bandwidth
suck."* Sealing records per reader would fix reading but not delivery. See
[card 22](../done/22-gossip-role-OPEN.md), "Decision input".

## Split for parallel work (2026-09-23)

- **26a (can start now, independent of 27):** the host-side log store (append-only, signed, hash-linked, retention, sequence numbers, tamper detection) and the optional OTLP exporter, as self-contained modules with their own tests. Emit into them from the existing audit path.
- **26b (after 27):** the `watch <service>` record-stream protocol, reader authorization from the registry, `--mine`, and removal of records from everything else.

## Design

- **The host keeps its own log.** An append-only store of `AuditRecord`s, each **signed by the host key and hash-linked** to the previous one (reuse `library` chain/envelope pieces where they fit; records no longer need channel encryption, only signatures). Bounded retention in `host.json` (default 30 days). Stable per-record sequence numbers.
- **Who may read (the service's registry entry, card 27):** `"audit": { "readers": ["security"] }` names roles that may stream **all** records. **Every caller may stream its own** records (matched by verified node id). Everyone else is refused. Default deny.
- **Reading = subscribing to a host directly.**
  - `wires watch <service>` resolves the service's hosts through the signed registry (card 27), dials each by key on a record-stream ALPN, sends `since=<seq>`, and gets backlog then live records (like card 23's long-poll/stream), merged into one stream per service; the user never names a host. `wires watch` with no argument watches every service whose records it may read.
  - `wires watch --mine` shows only your own calls.
  - Verify each record's signature and hash link on receipt; report gaps and forks loudly.
  - The watcher remembers its high-water mark per host, so a restart resumes.
- **OTel export (optional, host side):** `"audit": { "otlp": "http://collector:4318" }` sends each record as an OTLP log record (attributes: caller node, principal email/iss/sub, role, tool, argv, exit, duration, stdout digest, host id, record hash and signature), so orgs with a SIEM get it where their other logs live. Keep it minimal and behind the config key; no exporter unless configured.
- The broadcast channel is gone after card 27, so records exist only in host logs, subscriber copies and OTel.
- **Push records (card 23)** follow the same path: in the host log, streamed to the recipient and readers, not broadcast.

## Acceptance

- [ ] e2e: Bob (member, not a reader) calls nothing and receives **zero bytes** of Alice's call records, both on the channel and via `watch`. Alice's `watch --mine` sees her calls. A `security` reader sees all. A reader who starts late gets the backlog. A tampered record (flip a byte in the host store) is detected by the watcher.
- [ ] Bandwidth check: with N calls, the channel traffic reaching a non-reader stays constant; record the numbers in Notes.
- [ ] OTel: with a local collector (or a mock OTLP HTTP endpoint in the test), records arrive with the listed attributes.
- [ ] `demo-remote-cli.sh` gains an auditor observer (`security` role) and asserts a plain member sees nothing.
- [ ] README "where each guarantee lives" and `docs/executive-summary.md` updated: observability means host-signed records, streamed to authorized readers and exported to OTel. Say plainly that records are no longer replicated at write time (the trade-off in card 22).
- [ ] Tests, lint, format green (Cargo after card 25).

## Notes

### 26a done (2026-09-23)

- **Pure types** in `library/calls/call_log.rs` (`library::call_log`, re-exported): `LogEntry { v, host, seq: LogSeq, prev: EntryHash, at_ms, record: AuditRecord, sig }`. The host signs `"wires/call-log/v1\0"` plus the canonical JSON of every field except `sig`. `EntryHash` = BLAKE3(signed bytes ‖ sig), so the hash covers the signature and a re-signed entry counts as a different entry. `verify_chain(host, after: Option<ChainPoint>, entries)` returns the new tip or a `ChainBreak`: `WrongHost`, `BadSignature` (a flipped byte), `Malformed`, `BadGenesis`, `Gap`, `BrokenLink` (a substituted predecessor), `Fork` (two entries for one slot, including against the reader's anchor) or `OutOfOrder`. An exact repeat is skipped, so overlapping batches are fine. A pruned log verifies from its first entry, and from a reader's anchor it is fully checked. `Retention` defaults to 30 days.
- **Storage:** `wires/host/call_log.rs` writes an append-only JSON-lines file, `$WIRES_HOME/call-log.jsonl`, and fsyncs every entry. I chose it over redb because the access pattern is "everything after seq N", the entries verify themselves (open re-verifies the whole chain), it can be read with `jq`, and it adds no dependency while card 25 is trimming them. On open, a torn last line is truncated; any other break refuses to open ("move it aside"). Retention rewrites the kept suffix to a temp file, then renames it into place. It runs on open and whenever the oldest entry ages out. The newest entry is always kept, so seq never restarts.
- **OTLP:** `wires/host/otlp.rs` sends POSTs to `<endpoint>/v1/logs` in OTLP/JSON, up to 64 records per POST, from a 1024-entry `try_send` queue. When the queue is full, the entry is dropped with a warning. Failures are not retried. Each record's body is the signed entry JSON, so it can be verified inside a SIEM. Attributes: `wires.record.{kind,seq,hash,prev,signature}`, `wires.host.node`, `wires.call.id`, `wires.caller.node`, `wires.principal.{email,iss,sub}`, `wires.role`, `wires.tool`, `wires.argv` (array), `wires.exit`, `wires.duration_ms`, `wires.stdout.{digest,bytes}`, `wires.denied.reason`, `wires.push.{to,subject,outcome}`. Each attribute is present only when the record carries it: `finished` records have no caller or tool and pair with their `started` record by `wires.call.id`.
- **Hook:** in `serve.rs`, the sink is now always created, and `call_log::start` runs a blocking tee that appends to the log, offers the entry to the exporter, and `try_send`s to the channel publisher when there is a channel. As a result, a host with no `channel` also records calls now; before this change it recorded nothing. `host.json` gains only `"audit": {"otlp": "…"}` (`deny_unknown_fields`, http/https validated). Channel publishing is untouched.
- **For 26b:** `call_log::read(path)` plus `verify_chain` are the backlog/catch-up primitives. The watch protocol, `readers` and `--mine` are not built.

### 26b done (2026-09-23)

- **Host, `wires/host/record_stream.rs`:** ALPN `wires/records/1`, registered in `serve::services_router` (every v2 host). One bi-stream of length-prefixed JSON frames: the reader sends `Open { hello, services, since, mine, follow }` (the same `Hello` a call presents); the host checks membership credential → fresh state → member → ID token (`ServicesHost::principal`), then grants per requested service assigned to it `all` (a role in `service.readers` admits the caller, and no `--mine`) or `mine`. A non-member gets `Denied` and nothing else. Then it sends the backlog after `since`, `CaughtUp`, and with `follow` it polls the log file (200 ms) and sends new entries until the reader hangs up.
- **What a reader is sent:** every entry, either **in full** (signed, as stored, tagged with its service) or as a hidden **link** `{prev, hash}` with no content, caller, service or time. Links let the reader check the chain across entries it can't see, so a flipped byte anywhere in the file is caught: `BadSignature` on a visible entry, `BrokenLink` on a hidden one. The cost is about 140 B per hidden entry. `Finished` inherits its `Started`'s service and caller. Service-less records (a push, a refusal before naming a service) go to their subject and to anyone holding `all` on that host.
- **Caller, `wires/caller/watch_records.rs`:** `wires watch [<service>…] [--mine] [--json] [--once] [--relay-url]`. It resolves hosts from the signed state (no args: every service in it), dials each by key, and checks every item (`Chain`: `verify_chain` per entry plus link checks). It merges the backlog from every host by `at_ms`, then streams live. On a break it prints `wires: ALERT: host <id>'s call log does not verify: …`, stops reading that host and exits 1. It exits 77 when every host refused. Marks are the verified tip per host **and view** (services + `--mine`) in `$WIRES_HOME/record-marks.json`, so a restart resumes. The render (`▶ ■ ✗ ⇢`) is copied from `channel/render.rs`, prefixed `HH:MM:SS <service>`; `--json` prints `{service, host, seq, entry}` with the signed entry.
- **e2e** (`wires/e2e/records.rs`, loopback, real call log): sam (`security`, reader) starts late and gets the backlog of all 5 records; alice `--mine` gets her 4; bob (member, not a reader) gets only his own refusal and zero of `status`; a stranger is refused; sam's second run resumes from his mark; a follower gets a live record; a flipped byte in `call-log.jsonl` gives `BadSignature` for sam and `BrokenLink` for bob.
- **Merge with 27d:** `main.rs`'s `Watch` variant now points at `caller::watch_records`, and the channel tail survives only as `advanced tail`. The old parse test in `channel/watch.rs` was repointed at `advanced tail`; take 27d's deletion of that file. `record_stream` uses no `channel/*`. `watch_cmd` uses `pick::Hints::load`, which still reads channel peer books, so keep whatever 27d leaves as the hint source.
- **Not done (rest of 26):** the OTLP collector acceptance test, the bandwidth numbers, the demo's auditor observer, and the README/executive-summary wording.

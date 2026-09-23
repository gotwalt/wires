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

# 09 — Stretch: witness for the host-held call log

**Lane:** stretch · **Depends on:** 26

## Goal

Close the known limit in [protocol.md](../../protocol.md) §8: a host can
withhold or truncate its own call log, and a rewrite is detectable only
against a copy someone holds. A witness is a member that holds that copy, so
an infra team can show "the log is complete and untampered" from something
other than the host.

*Rewritten 2026-09-23 after card 27 deleted the channel; the original sketch
(a key-less node on the gossip topic) is in git history.*

## Sketch

- Entries are already signed by the host and hash-linked (`LogEntry`,
  `verify_chain`), and `wires watch` keeps a per-host mark and alarms on a
  tampered, missing or forked entry.
- A witness is a reader (a service's `readers` role) that follows the record
  stream continuously and exports a signed checkpoint `(host, seq, hash)`
  per host, so a later truncation or rewrite contradicts a checkpoint someone
  else holds.
- Open question for the human: should a witness see argv and identities (a
  plain reader does), or only hashes, which needs a redacted stream?

## Acceptance

- [ ] The witness detects a dropped, truncated or forked entry from a host and says which.

## Notes

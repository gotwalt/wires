# 09 — Transparency-log records and a witness

**Lane:** R · **Depends on:** 26, [36](../doing/36-directory.md) · **Status:** backlog; reshaped 2026-09-24 to take in the records half of the old card 29

## Goal

Close the known limit in [protocol.md](../../protocol.md) §8: a host can withhold or truncate its
own call log, and a rewrite is detectable only against a copy someone holds. Make the log a
standard transparency log, so that copy is small, standard and held by someone other than the host.

## Design (Certificate Transparency RFC 9162; C2SP `tlog-checkpoint`/`tlog-witness`; Sigstore Rekor)

- **Replace the hash chain with a Merkle log.** The host signs a **checkpoint** (tree size plus root
  hash); a reader asks for a **consistency proof** from the checkpoint it holds. That fixes, by
  construction, what card 28 only patches: rollback below a reader's mark, pruning that looks like
  tampering, and marks kept per query.
- **The witness is the directory by default.** Hosts hand their checkpoints to a directory
  (card 36), which co-signs them in the `tlog-witness` shape. The directory holds checkpoints only
  (a few hundred bytes per host per interval), never record content, so it doesn't become the owner
  of the records the pitch says no gateway owns. A security team can run its own witness the same
  way.
- **Non-readers get nothing about other people's calls:** no hidden links, so no count and no
  timing. They get their own entries with inclusion proofs.

## Open questions

- Checkpoint interval (per entry, or every N seconds), and whether a host refuses calls when no
  witness has co-signed for a while (a `strict` mode, like card 36's freshness rule).
- Should a witness other than the directory see argv and identities (a plain reader does), or only
  checkpoints?

## Acceptance

- [ ] `watch` detects a rollback and reports pruning as retention, not tampering, from checkpoints.
- [ ] A host that truncates or rewrites its log contradicts a checkpoint the directory co-signed,
      and `watch` says which host and where.
- [ ] A caller in no `readers` role learns nothing about other people's entries (no count, no
      timing).

## Notes

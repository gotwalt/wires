# 09 — Stretch: key-less witness

**Lane:** stretch · **Depends on:** 02

## Goal

"Observable at the infra layer" taken literally: a node that stores, orders, and
verifies call records (signature + per-publisher hash chain) **without** holding
the channel key — so an infra team can prove "the log is complete and
untampered" without being able to read argv or identities.

## Sketch

- Envelopes are already signed over ciphertext and hash-linked (`library/envelope.rs`,
  `library/chain.rs`), and ingest stores before it can decrypt (`KeyVersionUnknown`).
- A `wires witness <topic>` mode: admitted to gossip + replay (roster member) but never
  imports a fabric key; exports a signed checkpoint `(publisher, seq, hash)` per publisher.
- Open question for the human: should witnesses be a roster *role* (admitted without a
  sealed key), which touches `roster commit`?

## Acceptance

- [ ] Witness detects a dropped or forked record from a responder and says which.

## Notes

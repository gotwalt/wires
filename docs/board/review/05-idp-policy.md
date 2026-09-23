# 05 — `serve --require-idp`: gate calls on verified identity

**Lane:** F · **Depends on:** 01, 02, 04 · **Files:** `wires/transport.rs` (authorize), `wires/audit.rs`, `wires/main.rs` (serve args)

## Goal

The responder only runs a tool for callers whose node key is bound to an
acceptable IdP identity — and the audit record names the person, not the key.
Two IdPs on one channel = federation.

## Design

- The responder's topic node (from card 02) keeps an in-memory index
  `NodeId → latest verified Principal`, fed by every `ChannelRecord::Identity`
  on the audit topic (verify on ingest with card 04's `verify_claim`; drop failures
  with a log line).
- `--require-idp 'iss=https://accounts.google.com,email=*@example.com'`
  (repeatable = OR; within one flag, all keys must match). Keys: `iss`, `email`
  (glob on `*@domain` only), `org`, `group`. `--oidc-audience` lists accepted `aud`s.
- In `authorize`: after the roster/grant checks pass, look up the caller. No claim →
  `Denied("no identity claim for <node>; run \`wires login --topic <t>\`")`; expired →
  `Denied("identity claim expired …")`; mismatch → `Denied("identity <email> not allowed …")`.
- `AuditRecord::Started.principal` is filled from the index whenever one exists
  (even without `--require-idp`), so the observer sees names.
- Claims can arrive *after* a caller first dials; the lookup is per call, so the
  next call succeeds once the claim lands — no restart.

## Acceptance

- [ ] Unit: policy parser + matcher (proptest over emails/globs), each denial reason.
- [ ] e2e (mock issuer): caller without claim denied → logs in → next call allowed; audit
      `Started.principal.email` set; second mock issuer with a different domain allowed by
      a second `--require-idp` (federation) and a third denied.
- [ ] `bazel test //...`, `aspect lint //...`, format check green.

## Notes

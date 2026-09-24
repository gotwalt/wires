# 35 — Badges and bans: members leave the signed state

**Lane:** D1 · **Depends on:** 28 · **Status:** backlog (next after 08), designed 2026-09-24 · **Files:** `library/services/{state,access}.rs`, `library/membership/`, `wires/admin/{init,invite,remove,keystore}.rs`, `wires/host/{gate,push,record_stream}.rs`, `wires/state/`, `wires/caller/{join,call,inbox}.rs`, `wires/gateway/mod.rs`, protocol.md §2–4, [fabric.md](../../fabric.md)

The first of three cards (35 → [36](36-directory.md) → [37](37-caller-views.md)) that replace
"every node holds the whole signed state" with a directory. Together they supersede the
distribution half of [card 29](29-person-identity.md). The architecture they build toward is
[docs/fabric.md](../../fabric.md).

## Why

[`bench/state-scale/REPORT.md`](../../../bench/state-scale/REPORT.md): about 80% of the signed
state is the member list, and two thirds of edits are membership changes. Every `invite` is a
state edit, so one new laptop makes every node download the whole org's node list again. Taking
members out of the state cuts each node's metadata traffic about 5× (a caller at 10k users: 39 MB
→ 7 MB a day) before anything else changes, and the directory cards build on it.

Precedents: Nebula and SSH certificate authorities admit by a CA-signed certificate plus a
revocation list, not a guest list.

## Decisions

- **A node is admitted by its badge.** The badge is today's root-signed `Membership` (`fabric`,
  `member`, `issued`, `not_after`), unchanged. The gate's "is a member" becomes: the badge
  passes `check_inclusion` and the node is not banned. Everywhere the code asks `is_member`
  (the gate, push, the record stream, the state responder, inbox delivery, the gateway) asks this.
- **The state loses `members` and `hosts`.** A host is a node that some service's `hosts` names,
  as today (it is already derived). New signed format (`format: 2`); a format-1 state is refused
  (pre-alpha: no compatibility).
- **Removal is a ban.** `wires remove` adds `bans: { NodeId → until }` to the state, where `until`
  is the removed badge's `not_after`, so a ban never outlives the badge it cancels. Every edit
  drops bans whose `until` has passed. The admin keeps a local ledger (`issued.json`: node id →
  label, `not_after`) so it knows `until`; a node missing from the ledger is banned for the longest
  badge lifetime the admin allows (`--ttl` cap, default 30 days).
- **`invite` is not an edit.** It mints a badge and records it in the ledger; the state's version
  doesn't move and nothing is pushed. The invite token still carries the (now small) state until
  card 37 shrinks it to keys only.
- **A caller never dials a banned host.** With its state current, `wires call` skips a host in
  `bans` before sending `Hello`/`Invoke`, which closes "a removed host still sees argv" for any
  caller holding the ban.
- Badge lifetime stays 30 days by default. Renewal is still missing; it is an open question on
  [card 36](36-directory.md), because the directory is where renewal would live.

## Acceptance

- [ ] Onboarding 1,000 nodes changes no state version and sends nothing to hosts (test).
- [ ] The serialized state's size does not depend on the number of badges issued (test).
- [ ] A banned node is refused at the gate (`not a member of this network`), by the record stream,
      by push and by inbox delivery; the refusal is traced, not logged, as today.
- [ ] A ban drops out at the first edit after its `until`.
- [ ] `wires call` never sends `Invoke` to a host its state bans.
- [ ] protocol.md §2–4 describe badges and bans; `bench/state-scale/model.py`'s *badges* rows
      still describe the result.

## Notes

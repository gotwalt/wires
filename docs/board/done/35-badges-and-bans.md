# 35 — Badges and bans: members leave the signed state

**Lane:** D1 · **Depends on:** 28 · **Status:** review (2026-09-24, `worker/35-badges`), designed 2026-09-24 · **Files:** `library/services/{state,access}.rs`, `library/membership/`, `wires/admin/{init,invite,remove,keystore}.rs`, `wires/host/{gate,push,record_stream}.rs`, `wires/state/`, `wires/caller/{join,call,inbox}.rs`, `wires/gateway/mod.rs`, protocol.md §2–4, [fabric.md](../../fabric.md)

The first of three cards (35 → [36](../done/36-directory.md) → [37](../backlog/37-caller-views.md)) that replace
"every node holds the whole signed state" with a directory. Together they supersede the
distribution half of [card 29](../backlog/29-person-identity.md). The architecture they build toward is
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
  [card 36](../done/36-directory.md), because the directory is where renewal would live.

## Acceptance

- [x] Onboarding 1,000 nodes changes no state version and sends nothing to hosts (test).
- [x] The serialized state's size does not depend on the number of badges issued (test).
- [x] A banned node is refused at the gate (`not a member of this network`), by the record stream,
      by push and by inbox delivery; the refusal is traced, not logged, as today.
- [x] A ban drops out at the first edit after its `until`.
- [x] `wires call` never sends `Invoke` to a host its state bans.
- [x] protocol.md §2–4 describe badges and bans; `bench/state-scale/model.py`'s *badges* rows
      still describe the result.

## Notes

### Worker notes (2026-09-24, branch `worker/35-badges`)

**Where each acceptance item is tested.**

- Onboarding 1,000 nodes / state size: `admin::invite::tests::onboarding_a_thousand_nodes_edits_nothing_and_pushes_nothing`
  (1,000 `invite`s through `run_if_edited_in` with a counting push: 0 pushes, stored state
  byte-identical, every invite's state the same size; a `remove` then pushes once).
- Banned node refused: the gate (`host::transport` tests: a genuine but banned badge hears
  `NOT_ADMITTED`, is never token-verified, and 200 of the 1,000-knock flood are banned with nothing
  logged; `e2e::services_host::a_removed_member_is_refused_on_the_next_call`), the record stream
  (`e2e::records`: a banned reader refused outright, and a following reader banned mid-stream),
  push (`host::push::tests::a_push_to_a_banned_node_is_denied`, and the fetch test
  `a_banned_or_badgeless_fetch_is_refused_unlogged_and_unverified`), inbox delivery
  (`caller::inbox` test: a banned node's genuine badge is refused), and the state responder
  (`state::sync` tests).
- A ban drops out: `admin::service::tests::a_ban_drops_out_at_the_first_edit_after_its_until`,
  plus `State::prune_bans` unit and property tests.
- `wires call` never dials a banned host: `caller::call::tests::a_banned_host_is_never_dialed`
  (the banned host, listed first and remembered as last-good, sees no `Hello`) and
  `caller::pick` tests.

**Decisions.**

- **`issued.json` replaces `names.json`** (folded, not kept beside it): node → `{label?,
  not_after}`, `0600`, in `wires/admin/ledger.rs`. The ledger keeps the *latest* `not_after` per
  node, so a ban outlives every badge the admin minted for it; `remove` forgets the node.
- **Badge cap**: `init`/`invite --ttl` is refused above 30 days (`Ttl::MAX_BADGE`), so a ban on a
  node the ledger doesn't know (now + 30 days) outlives any badge this admin could have minted. The
  card said "`--ttl` cap, default 30 days"; I made it a constant, not a flag (nothing asked for a
  configurable cap; easy to add).
- **Two invites do edit** (and push, via `admin::run_if_edited`, which pushes only when the stored
  version moved): re-inviting a banned node lifts its ban (else its new badge would be useless),
  and an invite from an expired stored state re-signs it (a joiner can't install an expired
  state). Everything else about `invite` is no edit.
- **`State` format 2**: `{format, fabric, version, issued, not_after, bans, roles, services}`.
  `members` and `hosts` are gone; `State::hosts()` derives the host set from services. `validate`
  refuses a service host that is banned, so `remove` still strips the node from every service.
  `is_host` / `assigns` are also false for a banned node (belt and braces for the caller).
  `STATE_CONTEXT` is unchanged (`wires/state/v1\0`); the signed `format` separates the formats.
- **Admission is one library function**: `library::check_admitted(badge, root, state, caller,
  now)` = `check_inclusion` + `Error::Banned { until }`. `authorize` checks only the ban
  (`Refusal::NotAMember` became `Refusal::Banned`); the badge is the gate's, before it.
- **Push by node id**: `decide_push` checks the ban and then the `push.allow` role, which needs a
  principal the host verified from that node, and a host only verifies a token after admitting the
  node's badge. So a node that never presented a badge here is in no role. (A badge that expired
  after its token was verified still gets pushes until that token expires, about an hour.)
- **State sync (`wires/state/1`) needed a badge**: the dialer now opens every exchange with
  `hello {membership}`; the responder admits by badge and the bans in its held copy (fresh or
  not) before reading the second frame. This dropped the old "an offer must vouch for the dialer"
  logic: a host whose copy expired simply adopts a newer offer from any admitted node. Card 36
  retires this protocol anyway.
- The web gateway refuses to start only when its state bans it (its badge is checked by the
  credentials preflight as before).

**Docs.** protocol.md §2–4 rewritten (§2 is now "Membership: badges and bans"), plus the spots in
§5–10 that said the state lists members; usage.md (roles, guarantees, walkthrough version
numbers, command table, trade-offs), deployment.md, README, executive summary, demo.md,
CLAUDE.md, the board README's non-negotiables. fabric.md untouched: nothing I built contradicts
it (its "member list" row in §9 is now true of "Today"). `bench/state-scale/model.py`: the
*badges* rows now use a measured `ban` size and no per-host bytes (a host is only its entries in
services' `hosts`); `member`/`host` stay as frozen format-1 sizes for the *today* rows.

**For 36b.** `State` is still one blob; the directory's `ban` items map 1:1 onto `bans`
(node → until), and `prune_bans` is the GC rule. The ledger (`issued.json`) is admin-local and
is what `remove` reads for `until`; card 36's renewal question lands there too. Every gate goes
through `ServicesHost::check_member` → `library::check_admitted`, so a host slice needs only its
bans to keep admitting correctly. `StateFrame::Hello` is the one wire change to `wires/state/1`
(retire it with the rest).

**Touched outside this lane (links only):** `docs/fabric.md` line 3, `docs/board/backlog/29-person-identity.md`
and `docs/board/done/36-directory.md` link to this card, which moved to `review/`; nothing else
in fabric.md changed.

**Results at the end:** `cargo test --workspace` green (library 123 + 44 doctests, wires 366),
`make lint` green (clippy `-D warnings`, shellcheck), `cargo fmt --all --check` clean, `make demo`
green (all 15 checks, including step 9: the removed agent gets exit 77 and its push says
`banned until`).

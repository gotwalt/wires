# 37 — Caller views: each caller holds only what it may use

**Lane:** D3 · **Depends on:** [36](../doing/36-directory.md) · **Status:** backlog, designed 2026-09-24 · **Files:** `wires/directory/` (views, search, resolve), `library/calls/session.rs` (`HelloAck`), `wires/caller/{join,services,call,mcp,inbox,watch,pick}.rs`, `wires/gateway/`, `wires/admin/invite.rs`, `library/membership/invite.rs`, protocol.md §3–5, usage.md, [fabric.md](../../fabric.md)

## Why

Callers are over 95% of a fabric's nodes and use about 1% of its policy. Today each one holds the
whole state and re-downloads it whenever it changed; at 10k users that is 39 MB a day per caller
([`bench/state-scale/REPORT.md`](../../../bench/state-scale/REPORT.md)), and every agent's machine
holds the org chart, which the premise says agents must not observe. The human (2026-09-24): keep
services visible only to those who may use them ("the name leak problem"), and add search, since
even a filtered catalog outgrows a model's context.

## Decisions

- **A view is a list of signed entries.** The root signs the policy, and each service entry, like
  a badge (card 36d): a view is the head, `Fresh`, and the root-signed service entries
  (`SignedEntry`) whose `allow` (call) or `readers` (read) admits the caller's verified principal,
  each marked `call` and/or `read` (`library::View`, `ViewEntry`). Each entry verifies on its own
  under the root, as a badge does. It holds no role, no ban and no other service. The directory
  computes it on request (`SignedPolicy::view_for(principal, query)`), after verifying the ID
  token itself against the signed `issuer` items; nothing per user is stored. With no verified
  principal the view is empty (no role admits).
- **Newest entry wins.** Each entry carries the version at which it last changed. A caller keeps
  the newest version of each and refuses an older one (`View::apply`). A caller holding a stale
  entry is safe: the host decides every call from its whole, current policy and refuses one it
  doesn't serve.
- **`wires/directory/1` serves** `view {have, query?}` → `view {view, fresh}` (or `view_update`,
  or `current`), the whole view or the entries matching `query` by name and description, and
  `resolve {service}` → a one-entry or empty view. The frames exist (card 36d); the directory
  answers `denied` until this card. A request is traced, not logged.
- **Callers stop holding the state.** `policy.json` and the cold fetch go; the caller keeps
  `view.json`. `wires services [query]` reads it, refreshing first if it is older than a day or
  its head is behind (next point).
- **The call handshake carries the news.** `HelloAck` gains the host's head version. When it is
  newer than the caller's view, it also carries the called service's signed entry (and the head),
  so the caller checks the host is still assigned before sending stdin (replacing today's
  `newer_policy` check), then refreshes its view after the call. One-shot commands get no other
  background traffic.
- **Long-running clients subscribe.** `wires mcp`, the gateway and `inbox --wait` hold a `view`
  subscription (card 36's `wires/directory-sub/1`: `view` first, then `view_update {head, changed,
  removed}` per new head, applied with `View::apply`; a failed apply resubscribes with `have: 0`),
  so a grant or a revocation reaches them in seconds; `wires mcp` sends MCP
  `notifications/tools/list_changed`.
- **Search in MCP.** When a view holds more than 40 services, `wires mcp` and the gateway expose a
  `search_services` tool instead of listing every service in `tools/list`.
- **The gateway** asks for one view per web user, with that user's ID token (nonce bound to the
  gateway node, as today), and holds one subscription per live session.
- **Inbox and watch use the view.** `inbox` fetches from the hosts of the view's services and
  accepts a direct delivery only from one of them. `watch` reads from the hosts of the services the
  view marks `read` (and, for the caller's own records, `call`).
- **The invite shrinks** to the badge, the root key and the directory ids: about 800 B at any size.
  `wires join` stores them and asks a directory for the head; the view comes after `wires login`.

## Acceptance

- [ ] A caller's keystore holds no role, no ban, no node id other than its services' hosts and the
      directories, and no service it may not use (test).
- [ ] An invite token is under 1 KB at any fabric size (test).
- [ ] `wires call` on an unchanged fabric makes no connection besides the call itself.
- [ ] A new grant reaches a running `wires mcp` as `tools/list_changed` within 2 s; a revoked
      grant disappears from its tool list within 2 s.
- [ ] `wires services orders` finds a service by name or description; `search_services` does the
      same in MCP.
- [ ] `bench/state-scale/model.py`'s *apex* caller rows describe the result.
- [ ] protocol.md, usage.md and the README describe views; "every member holds the whole state" is
      gone from every limits list.

## Open questions

- Does the directory log view requests (who asked to see what) for the security team, or only trace
  them? Leaning to trace: a view grants nothing, and the host logs every call.
- The 40-service threshold for `search_services` is a guess; measure with the token benchmark
  (card 16).

## Notes

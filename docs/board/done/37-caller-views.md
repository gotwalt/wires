# 37 — Caller views: each caller holds only what it may use

**Lane:** D3 · **Depends on:** [36](../done/36-directory.md) · **Status:** review (built 2026-09-24, branch `worker/37-caller-views`), designed 2026-09-24 · **Files:** `wires/directory/` (views, search, resolve), `library/calls/session.rs` (`HelloAck`), `wires/caller/{join,services,call,mcp,inbox,watch,pick}.rs`, `wires/gateway/`, `wires/admin/invite.rs`, `library/membership/invite.rs`, protocol.md §3–5, usage.md, [fabric.md](../../fabric.md)

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
- **Login rides in the invite** (the human, 2026-09-24, via the integrator). The invite carries the
  fabric's login settings: the issuer and OAuth client id from the policy's signed `issuer` items
  (the one the admin marks for login, else the first), plus, only when the admin supplied one, a
  **public** desktop-client secret (`--public-client-secret` on `init` and `issuer set`; never a
  confidential one). `wires join` stores them; a bare `wires login` uses them; flags and
  `$WIRES_OIDC_*` still override. The invite stays under 1 KB.

## Acceptance

- [x] A caller's keystore holds no role, no ban, no node id other than its services' hosts and the
      directories, and no service it may not use (test).
- [x] An invite token is under 1 KB at any fabric size (test).
- [x] `wires call` on an unchanged fabric makes no connection besides the call itself.
- [x] A new grant reaches a running `wires mcp` as `tools/list_changed` within 2 s; a revoked
      grant disappears from its tool list within 2 s.
- [x] `wires services orders` finds a service by name or description; `search_services` does the
      same in MCP.
- [x] `bench/state-scale/model.py`'s *apex* caller rows describe the result.
- [x] protocol.md, usage.md and the README describe views; "every member holds the whole state" is
      gone from every limits list.
- [x] After `wires join <token>`, `wires login` needs no `--issuer` / `--client-id` (test with the
      mock IdP); the demo scripts drop those flags for callers; usage.md's walkthrough shows
      `wires login` bare.

## Open questions

- Does the directory log view requests (who asked to see what) for the security team, or only trace
  them? Leaning to trace: a view grants nothing, and the host logs every call.
- The 40-service threshold for `search_services` is a guess; measure with the token benchmark
  (card 16).

## Notes

**Built (2026-09-24, branch `worker/37-caller-views`, merged with 36c).**

- **The directory answers views** (`wires/directory/node.rs`, `sub_view.rs`). `answer_caller`
  verifies the `hello`'s ID token itself (a `KeyFetcher` with keys in memory only, under the held
  policy's `issuer` items and their audiences, the nonce bound to the iroh key), then cuts
  `view_for(principal, query)`: `view {have}` → `current`, a `view_update` from a head
  `directory.redb` still keeps (`policy_at`, 36c), or the whole view; `view {query}` → a searched
  whole view; `resolve` → one entry or none. Traced (`debug`), not logged. A `view` subscription
  verifies the principal once, sends the whole view first (whatever `have` says: the directory
  keeps nothing per subscriber), then a `view_update` against the view it sent last per new head,
  and `fresh` beats. **Per the integrator:** `policy {have}` and `subscribe {kind: policy}` now
  answer `denied` to a node the held policy names neither as a host nor as a directory
  (`Directory::holds_whole`, tests in `directory/tests.rs`).
- **Callers hold `view.json`** (`wires/caller/view.rs`: `HeldView {view, fresh, checked, seen}`,
  `refresh`, `resolve`, `follow`). No `policy.json`: `refresh_cold`, `check_once`, `newer_head`,
  `refresh_loop`, `store::is_stale`, `store::require` are gone (36c handed these over). A node that
  holds `policy.json` (admin, host, directory) cuts its view locally for its own verified identity.
  `wires services [query]` refreshes when the view is over a day old, expired, or behind a head a
  host reported; `wires call` refreshes only a missing or expired view, dials from the entry,
  `resolve`s a name the view lacks, and after a call whose `HelloAck` reported a newer head notes
  it and refreshes (an update, from a kept head).
- **`HelloAck {membership, state_version, head?, entry?}`** (`library/calls/session.rs`):
  `HelloAck::assigns(root, held, service, host)` is the caller's check before stdin. The host's side
  in `transport.rs` is four lines; `on_ack` now takes the ack.
- **MCP**: `serve_following` announces `notifications/tools/list_changed` between replies when a
  new tool list differs (`initialize` declares `listChanged` only when following); past 40
  services, `tools/list` offers `search_services` and **`call_service`** (a tool that calls a found
  service by name: without it, clients that call only listed tools couldn't use a search result).
  A service is still callable by its own name.
- **Gateway**: `Backend::view(session)`; `Keystored` keeps one `follow` per live session (keyed by
  the ID token, dropped when it expires), views in memory; `PresentingCaller` dials from the
  user's view (`call_entry`). Its policy refresh loop and ban check are gone (a banned gateway is
  refused by every directory and host).
- **Invite v4** `{format, membership, directories (≤ 2), login?, policy?}` and **login settings**
  (`LoginSettings`, `PublicClientSecret`; admin side `wires/admin/login_client.rs`,
  `login-client.json`: the issuer invites name, `init`'s unless `issuer set --login`, else the
  policy's first; public secrets from `--public-client-secret`, never signed). `join` stores
  `directories.json` and `login.json`, and for a caller asks for the head; `login` resolves flag →
  env → invite, and refreshes the view (forgetting the old one).
- **Deviations, and why.**
  1. *A host's or directory's invite still carries the whole policy* (only for a node the policy
     already names as one). A directory can't fetch its first copy from itself, and a host that
     joins before any directory runs would otherwise start with nothing; both hold the whole policy
     anyway. A caller's never does.
  2. *At most two directory ids* in an invite: with Google-sized login settings the token is
     979 B, and each further id adds about 90 B; the head the joiner fetches lists them all.
  3. *A name not in the view exits 1*, not 77: nothing was dialed, and 77 means a host refused. The
     message says to `wires login` when there's no token. The demo's step 2 asserts this.
  4. *`wires services` shows the roles a service allows* (`(analyst)`), not "the role that admits
     you": a view carries no role definitions. It lists entries marked `call`; read-only entries
     are for `watch`. `--json` has `allow: [...]` instead of `role`.
  5. *`wires watch` asks only about services in the view*, so a caller's own records of a service
     that left its view are no longer its to read (listed in usage.md's trade-offs).
  6. The subscription's principal is verified once; the directory doesn't end it at the token's
     `exp` (a view grants nothing; the host checks the token on every call).
- **Outside my lane** (small, as noted): `wires/policy/{fetch,store}.rs` (the removals above),
  `wires/directory/tests.rs` (fetch as a host; a caller is refused the policy), `sub_policy.rs`'s
  tests (ask as the directory), `wires/admin/{init,service,mod}.rs` (the two flags, the module),
  `wires/e2e/{records,services_host,mod}.rs` (callers hold views), `library/examples/policy_sizes.rs`
  (caller costs), the push and native-service demos (each lists its host as the directory),
  `bench/state-scale/`, fabric.md, README, executive-summary, the board README. `CLAUDE.md`'s
  overview still says the whole policy "is card 37's to fix"; not touched (not in my brief).
- **Measured** (`policy_sizes`, 25-entry view): caller invite **979 B** (Google-sized client id and
  public secret, two directory ids; test: < 1 KB at 0/100/1,000 services and 9 directories);
  `view.json` **16,775 B**; `view` frame **16,763 B**; a `HelloAck` carrying news **1,549 B**. The
  model: a one-shot caller receives 6 KB (team) to 271 KB (*large*) a day, `wires mcp` 56–102 KB.
- **Checks:** `cargo test --workspace` 405 + 177 + doctests passed, 0 failed; `make lint` clean;
  `cargo fmt --all --check` clean; `make demo` all `[ok]` (123 s); `demo-push.sh` and
  `demo-native-service.sh --lang python|node` pass.

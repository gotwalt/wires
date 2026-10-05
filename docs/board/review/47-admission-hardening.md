# 47 — Admission hardening after card 41's review

**Stage:** 2b · **Depends on:** [41](../done/41-idp-membership.md) · **Status:** review · **Files:** `library/network/admission.rs`, `library/services/{item,role,access,signed_policy}.rs`, `library/calls/idp.rs`, `wires/host/{gate,push,transport,identity}.rs`, `wires/directory/{node,serve,sub_view,sub_policy}.rs`, `wires/caller/{call,view,inbox,login,services}.rs`, their tests, `wires/e2e/`, `wires/snapshots/`, `.scripts/`, `docs/protocol.md` §2–5, §7, §9

## Why

Card 41 made the IdP sign-in the only thing that admits a caller. An
independent review of it (2026-10-05) confirmed the gates hold for a token
bound to another key, forged, expired or from an untrusted issuer, and
found five places where "anyone the IdP verifies" is now too wide. With a
public OAuth client (Google's "Desktop app"), anyone with an account at the
IdP can obtain a token that verifies.

## Decisions

1. **You are in the network if a role matches you.** A caller is admitted
   only if its token verifies (as today), it carries a **verified email**,
   neither the node nor the person is banned, **and at least one role in the
   signed policy matches the principal**. Anyone else hears the one fixed
   `NOT_ADMITTED` text, from hosts (sessions, inbox fetches) and from
   directories (requests and subscriptions). One function decides this
   (`check_admitted`), used at every gate. Caller-side wording: a signed-in
   node that hears it says what a person can act on ("no role in this
   network matches <email>, or you were removed: ask your admin"), and
   `wires login` says so right after a sign-in that the network doesn't
   admit.
2. **A person ban can't be sidestepped by leaving the email out**, because
   admission requires one (1). protocol.md §3 stops presenting a node ban as
   a way to keep a person out: a new key is one `WIRES_HOME` away. A node ban
   removes a host or directory machine, or one specific key.
3. **A host tells an admitted caller nothing about services it may not
   call.** When the policy's `allow` does not admit the caller for the named
   service, when no such service exists, or when nobody is allowed: one fixed
   refusal, the caller's own `no service named <name> that you may call`
   wording, no role names, no policy version. The detail goes to the host's
   trace. A service the caller *is* allowed keeps its specific refusals
   (the host's `also_require`, not assigned to this host). The inbox
   fetch's refusal names no `push.allow` role either.
4. **A directory's subscriptions can't be exhausted by callers.** Hosts and
   replicas (keys the policy names) get their own pool, apart from callers'
   view subscriptions; view subscriptions are capped per node; a view
   subscription ends when its ID token expires (the client re-subscribes
   with a fresh one, as `wires mcp` and the gateway already re-sign-in) and
   when the person or node is banned or no role matches any more.
5. **The removed-host window, said truthfully.** A caller dials from the view
   it holds. `wires call` refreshes a view older than a day when a directory
   answers, and `wires inbox` gets the same rule (today it never checks). But
   with no directory reachable, or when the removed machine was itself a
   directory the stale head still lists (it can vouch for its own old head),
   the caller keeps its view: the hard bound is the policy head's
   `not_after` (90 days by default), not a day. protocol.md §5 and §9 and the
   comment on `VIEW_MAX_AGE_SECS` say exactly that. Calls keep working with
   every directory down; that property is not traded away here.
   ([Card 45](45-trim-policy-sync.md) is where freshness gets rethought.)
6. **Small ones:** `IdToken`'s `Debug` never prints the token (and so no
   frame that holds one does); protocol.md §7 says what the code does with a
   banned person's queued pushes; §4's hello timing matches the code (10 s
   for the stream, then 10 s for the `hello`); a unit test for refusing a
   push at send to a banned person.

Not in this card: the node-keyed push queue (a push queued for a node is
handed to whoever next fetches from it) is [card 31](31-inbox-delivery.md)'s.

## Acceptance

- [x] Tests for each refusal: a verified token no role matches (session, inbox fetch, directory `view` / `resolve` / view subscription) hears `NOT_ADMITTED`; a token with no verified email is refused even under an `issuer=`-only role; a caller in one role probing a service it isn't allowed, and one that doesn't exist, hears the same bytes; 4,097 view subscriptions cannot stop a host subscribing; a view subscription ends at its token's expiry; `wires inbox` refreshes a day-old view.
- [x] `cargo test --workspace`, clippy `-D warnings`, `cargo fmt --all --check`, shellcheck, shfmt green; `.scripts/demo-remote-cli.sh --quiet` and `.scripts/demo-push.sh --quiet` pass (the signed-in-but-no-role persona's steps change).
- [x] `docs/protocol.md` describes exactly what the code does; *Notes* lists every statement elsewhere this card made false.

## Notes

### What changed (worker, 2026-10-05)

- **Decision 1 (a role must match you).** `library::check_admitted(policy,
  caller, principal)` now decides, in order: node ban → `Banned`; no verified
  email → `NoVerifiedEmail` (new `Error`); person ban → `Banned`; no role in
  the policy matches → `NoRole` (new `Error`, via new
  `Policy::any_role_admits`). It is the one function at every gate: the host's
  session gate and inbox fetch (`ServicesHost::admit_caller`), `gate::admit`
  (again, before anything a removed caller could learn), `decide_push` and
  `push_recipients`, and the directory (`Directory::admit` keeps a principal
  only if it passes; a view subscription re-checks it on every head). A named
  host or directory is still recognized by its key, never by a token.
  `Identities::verify_token` no longer records; `admit_caller` records a
  principal only once admitted, so outsiders and strangers can't grow the
  identity index.
- **Decision 2 (no email-less sidestep).** Admission requires a verified
  email, and `signed_policy::admits` (the one role-matching rule) never
  matches a principal without one, so `issuer=`-only, `org=` and `group=`
  matchers can't admit one anywhere (gate, views, push, `also_require`).
  protocol.md §3/§9 and `wires/admin/remove.rs` say a person is removed by
  email; a node ban removes a machine or one key.
- **Decision 3 (quiet refusals).** `GateRefusal::Registry` is gone:
  `NotAdmitted { why }` (says `NOT_ADMITTED`) and `NotCallable { service,
  refusal }` (says `gate::not_callable`: ``no service named `<name>` that you
  may call``; the `Refusal` goes to the host's trace as `refused by the
  registry`). The gate now runs `authorize` **before** `assigns`, so a service
  the caller may not call is never told apart by "not assigned to this host".
  The inbox fetch's push refusal is the fixed `gate::INBOX_REFUSED`.
- **Decision 4 (subscription pools).** `Directory::view_subscribers` is a pool
  apart from `subscribers` (policy + replica); both sized by
  `--max-subscribers` (default 4,096 each). `Directory::view_slot` also caps
  one person (issuer + subject) at `MAX_VIEW_SUBSCRIPTIONS_PER_PERSON` = 16.
  `sub_view::serve` ends the stream at the token's `exp` (`SIGN_IN_EXPIRED`)
  and, when a head no longer admits the subscriber, sends a `view_update`
  emptying its view and then `NOT_ADMITTED`.
  **Deviation:** the card says "capped per node"; the gateway holds one view
  subscription per live web user from its one node, so a per-node cap would
  cap the gateway's users. The cap is per person, which also stops one person
  using many keys. Say so if per node was meant.
- **Decision 5 (the true bound).** New `view::usable` / `usable_with` (the
  rule `wires call` had, now shared): `wires inbox` refreshes a stale view
  before fetching, and never dials from an expired one (`Fetcher::targets`).
  Not fail-closed: a refresh no directory answers leaves the view. protocol.md
  §4, §5, §9, `VIEW_MAX_AGE_SECS` and the `call`/`view` module docs say the
  hard bound is the head's `not_after` (90 days), and why (a removed
  directory can vouch for its own old head).
- **Decision 6 (small ones).** `IdToken`'s `Debug` prints `IdToken(<redacted,
  N bytes>)`, so `Hello`, `Frame`, the inbox and directory hellos and the
  gateway's `Session` can't print a token (proptest in `library::session`).
  protocol.md §7 and the code agree: a banned **person's** fetch now drops the
  queue too (code changed: `NotAdmitted::banned`). §4 says 10 s for the
  stream, then 10 s for the `hello` (doc changed, code as it was). Unit test
  `push::tests::a_push_to_a_banned_person_is_denied_at_send`.
- **Caller-side wording.** `caller::hello::explain_not_admitted` reads the
  caller's own stored token (unverified, never sent) and turns a responder's
  `NOT_ADMITTED` into what the person can act on. Used by `wires call` (in
  `exit_with`), `wires mcp` (`WiresCaller::call`), `wires inbox` (per-host
  lines and the final 77), `wires services` and `wires login`. `view::refresh`
  marks its error with `view::NotAdmitted` when a directory refused admission
  and none gave a view; directory `denied` answers are now a typed
  `view::Refused`.
- **Tests added** (each refusal): `admission::tests::*` (4 + proptest),
  `signed_policy::tests::roles_admit_only_verified_principals_of_their_issuer`
  (no email), `session::tests::debug_never_prints_the_id_token`,
  `gate::tests::{a_service_you_may_not_call_sounds_like_one_that_does_not_exist,
  no_role_or_no_email_is_not_admitted}`,
  `transport::tests::a_verified_token_no_role_matches_or_without_an_email_is_not_admitted`,
  `push::tests::{a_fetch_from_a_person_no_role_matches_is_not_admitted,
  an_admitted_fetcher_push_allow_refuses_hears_no_role_name,
  a_push_to_a_banned_person_is_denied_at_send,
  a_banned_persons_fetch_drops_the_queue}`,
  `directory::tests::{a_verified_token_no_role_matches_hears_not_admitted,
  view_subscriptions_cannot_stop_a_host_subscribing,
  view_subscriptions_are_capped_per_person,
  a_view_subscription_ends_at_its_tokens_expiry,
  a_view_subscription_ends_on_a_ban_and_when_the_directory_is_unlisted}`,
  `sub_view::tests::*`, `hello::tests::a_signed_in_caller_says_what_its_person_can_act_on`,
  `e2e::views::{a_day_old_view_is_refreshed_before_call_and_inbox_dial_from_it,
  a_signed_in_person_no_role_matches_is_told_so}`; e2e expectations updated in
  `services_host`, `native`. Two notes on fidelity: the "4,097 view
  subscriptions" test holds the 4,096 view permits directly and opens the
  4,097th for real (4,096 real QUIC connections is too heavy for a unit run);
  the "inbox refreshes a day-old view" test exercises `view::usable_with`,
  which `inbox_cmd` calls (driving `inbox_cmd` itself needs a real endpoint).
- **Test fixtures:** `MockIdp::mint_for(who, with_email, nonce, exp)`;
  directory tests' `Fabric` defines role `member` (`*@example.com`); test
  principals that had `email: None` got one.
- **Scripts:** `demo-remote-cli.sh` step 3b (the outsider is told at sign-in,
  `wires services` exits 1, `wires call` exits 1, all with the new sentence;
  summary line); `demo-native-service.sh` (bob@other.example's refusal). No
  bench script needed a change (none has an outsider or greps a changed text).

### User-visible changes, old → new (for the docs sweep, cards 39/43)

1. **The host/directory refusal `NOT_ADMITTED`:** ``not admitted to this
   network; sign in with `wires login` `` → ``not admitted to this network:
   sign in with `wires login`, or ask your admin for a role``. It is now also
   what a person the IdP verifies but no role matches hears, and a sign-in with
   no verified email, from hosts **and** directories.
2. **Signed in but no role matches = not in the network.** Before: such a
   person was admitted, got an empty view, `wires services` listed nothing
   (exit 0, "no service allows you (policy version N); ask your admin for a
   role that may call one"), and `wires call` said ``no service named `X`
   that you may call; see `wires services` `` (exit 1). Now:
   - `wires login`: the sign-in is kept (exit 0) and it adds `wires login:
     signed in as <email>, but not admitted to this network: no role in this
     network matches <email>, or you were removed: ask your admin`; for a token
     with no verified email also `wires login: your IdP gave no verified email
     for <sub at iss>, and this network admits only a verified email: ask your
     admin`.
   - `wires services`: exit 1, `wires: not admitted to this network: no role in
     this network matches <email>, or you were removed: ask your admin`.
   - `wires call`: with no view, exit 1 with that sentence; from a held view
     the host refuses: exit 77, `wires: denied by host: not admitted to this
     network: no role in this network matches <email>, or you were removed:
     ask your admin`.
   - Variants, from the caller's own token: no verified email → `not admitted
     to this network: your sign-in carries no verified email, and this network
     admits only a verified email: ask your admin`; expired → `not admitted to
     this network: your sign-in has expired; run `wires login``; no token →
     `not admitted to this network: not signed in: run `wires login``.
   - `wires mcp` tool results and `wires inbox` lines say the same.
3. **A removed person**, at a directory: was an empty view (and an emptying
   update on a live subscription, which stayed open); now `NOT_ADMITTED`, and
   a live view subscription gets the emptying update then ends with
   `NOT_ADMITTED`. Removal from `wires call` after removal now reads `denied by
   host: not admitted to this network: no role … or you were removed: ask
   your admin` (exit 77 as before).
4. **One fixed refusal for services you may not call:** `unknown service: X`,
   `service X allows no role`, `<who> is in no role allowed to call X
   (roles)`, `X needs a verified identity in role …; run wires login` → all
   ``no service named `X` that you may call`` (`wires call` appends `; see
   `wires services``). No role names, no policy version. And because the
   registry is checked before the host assignment, a host that isn't assigned
   a service the caller **may not** call says this too (was `service X is not
   assigned to this host (signed policy version N)`); a service the caller may
   call keeps `not assigned …` and the `also_require` sentence.
5. **Inbox fetch refusal:** `inbox fetch refused: <who> is in no role allowed
   to receive pushes (roles)` / `receiving pushes needs a verified identity in
   role …` / `… push.allow is empty …` / `… policy … is not fresh …` →
   `inbox fetch refused: this host does not push to you`.
6. **`wires push` (operator), new reason:** `<node> is no longer admitted by
   the current signed policy (version N): <why>` for a recipient whose known
   person lost every role (or has no email). A banned one still reads
   `… is removed by the current signed policy (version N)`.
7. **Directory subscriptions:** one shared cap of 4,096 → two pools of 4,096
   each (hosts and replicas; callers' views), `--max-subscribers` sets both
   (help: "How many hosts and replicas may subscribe at once, and, apart, how
   many callers' views (one more is refused)"). New: at most **16 view
   subscriptions per person** (`you have 16 view subscriptions open here
   already`). New: a view subscription **ends at its ID token's `exp`**
   (``your sign-in has expired; run `wires login` ``) and when the person is
   no longer admitted. A view subscription from a peer with no admitted
   principal: ``a view subscription needs an ID token that verifies; run
   `wires login` `` → `NOT_ADMITTED`.
8. **`wires inbox`** now refreshes a stale view (older than a day, head
   expired, newer head seen) before fetching, as `wires call` does; prints
   `wires inbox: <why>` when it can't and holds none; never dials from an
   expired view.
9. **The removed-host window:** docs and comments said "at most a day"
   (`wires call` refreshing day-old views); true bound is the view's head's
   `not_after` (90 days by default) when no directory answers or the removed
   host was itself a directory the old head lists.
10. **Push queues:** a banned person's fetch now drops what is queued for that
    node (was: only a banned node's).
11. **Identity index:** a host remembers a caller's principal only once
    admitted (was: any token that verified), so `push --to <role>` can only
    reach admitted people.
12. **`IdToken` Debug:** prints `IdToken(<redacted, N bytes>)`.
13. **Role matchers** (`issuer=` alone, `org=`, `group=`) never match a
    sign-in with no verified email; "`issuer=…` alone admits anyone that IdP
    verified" now means "… who carries a verified email".
14. **protocol.md §4 hello timing:** "the stream must open and the hello
    arrive within 10 s" → 10 s for the stream, then 10 s for the hello (code
    unchanged).

### Narrative-doc statements this card made false (most lines are also stale from card 41)

- `docs/usage.md`: 163 (an outsider has an empty view), 255 and 706–708
  (refusal texts), 536 (views older than a day; true bound), 613 (`issuer=…`
  alone admits anyone that IdP verified: needs a verified email; no role ⇒
  not in the network), 617 (`--max-subscribers` meaning), 623 (`wires
  services` for someone not admitted exits 1 with the sentence), 625 (MCP
  refusal text), 667–670 (`… is in no role allowed to call orders-db
  (analyst)` is no longer said to the caller; the fixed sentence instead),
  460 (removed node's pushes: a removed person's too).
- `docs/fabric.md`: 39 (one subscriber cap of 4,096 → two pools and a
  per-person cap of 16), 205 (a day old: the true bound).
- `docs/deployment.md`: 152 (`--max-subscribers` caps each pool), 192–196
  (removal text; a person is removed by email, a node ban doesn't keep a
  person out), 239 (the gateway's node alone is in no role: still true, but
  "in no role" no longer means "admitted with nothing").
- `docs/demo.md`: 32, 41, 314 (refusal texts), and any step that shows the
  signed-in-but-no-role persona seeing an empty list.
- `README.md`, `docs/executive-summary.md`, `docs/blog/introducing-wires.md`:
  any sentence that says anyone the IdP verifies is in (now: anyone a role
  matches), or that a removed caller sees an empty list.
- `docs/agent-sandbox.md`, `docs/testing.md`: no hit found.

### Verified (2026-10-05, on this branch)

- `cargo test --workspace`: 147 library, 403 wires, 3 bindings, 48 + 3 + 3
  doctests: green. `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo fmt --all --check`: clean. shellcheck and shfmt (`uvx`) over every
  tracked `*.sh` and `.githooks/pre-commit`: clean.
- `.scripts/demo-remote-cli.sh --quiet` (92 s) and `.scripts/demo-push.sh
  --quiet` (34 s): pass. `.scripts/demo-native-service.sh --lang python` and
  `--lang node`: pass.
- `e2e::follow::an_edit_reaches_every_subscribed_host_within_2s_as_one_update`
  passed in every full run here.

### Files outside the card's list

`wires/caller/hello.rs` (the caller-side sentence), `wires/caller/mock_idp.rs`
(`mint_for`, test-only), `wires/caller/mcp.rs` untouched but `WiresCaller`
in `call.rs` now rewrites its refusal, `wires/lib.rs` (`exit_with`),
`wires/help.rs` (`refusal_step` for the fixed sentence),
`wires/help_snapshots.rs`, `wires/admin/remove.rs` (module doc only),
`wires/caller/pick.rs` (a test principal), `library/calls/session.rs` (a
test), `library/services/view.rs` and `library/lib.rs` (doctests and crate
docs). `docs/board/README.md`'s lane table still says card 47 is backlog: the
integrator's to edit.

# 47 — Admission hardening after card 41's review

**Stage:** 2b · **Depends on:** [41](../done/41-idp-membership.md) · **Status:** doing · **Files:** `library/network/admission.rs`, `library/services/{item,role,access,signed_policy}.rs`, `library/calls/idp.rs`, `wires/host/{gate,push,transport,identity}.rs`, `wires/directory/{node,serve,sub_view,sub_policy}.rs`, `wires/caller/{call,view,inbox,login,services}.rs`, their tests, `wires/e2e/`, `wires/snapshots/`, `.scripts/`, `docs/protocol.md` §2–5, §7, §9

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

- [ ] Tests for each refusal: a verified token no role matches (session, inbox fetch, directory `view` / `resolve` / view subscription) hears `NOT_ADMITTED`; a token with no verified email is refused even under an `issuer=`-only role; a caller in one role probing a service it isn't allowed, and one that doesn't exist, hears the same bytes; 4,097 view subscriptions cannot stop a host subscribing; a view subscription ends at its token's expiry; `wires inbox` refreshes a day-old view.
- [ ] `cargo test --workspace`, clippy `-D warnings`, `cargo fmt --all --check`, shellcheck, shfmt green; `.scripts/demo-remote-cli.sh --quiet` and `.scripts/demo-push.sh --quiet` pass (the signed-in-but-no-role persona's steps change).
- [ ] `docs/protocol.md` describes exactly what the code does; *Notes* lists every statement elsewhere this card made false.

## Notes

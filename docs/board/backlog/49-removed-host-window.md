# 49 — The removed-host window

**Depends on:** decide together with [45](45-trim-policy-sync.md) · **Status:** backlog; a design question to think through first (the human, 2026-10-05: it "seems like a practical problem") · **Files:** `library/calls/session.rs`, `library/services/fresh.rs`, `wires/caller/{call,view,inbox}.rs`, `wires/host/{transport,freshness,follow}.rs`, `docs/protocol.md` §4–5, §9

## The problem

A caller dials from the view it holds. When the admin takes a machine off a
service, or bans it, a caller whose view predates that edit still dials it,
and in the first message hands it the caller's ID token and the call's
arguments. If the machine under-reports its policy version in `HelloAck`, it
gets stdin too and answers the call
([card 41](../done/41-idp-membership.md)'s review,
[card 47](../done/47-admission-hardening.md) decision 5).

How long the window stays open today:

- `wires call` and `wires inbox` refresh a view older than a day, **when a
  directory answers**. `wires mcp` and the gateway follow by subscription.
- With no directory reachable, the caller keeps its view.
- If the removed machine was also a directory (the first-run shape: one
  workbench is both), the caller's stale head still lists it, so it can answer
  the refresh with `current` and a `Fresh` it signs for its own old head.
- So the hard bound is the policy head's `not_after`: **90 days by default**.
  Before card 41 the same hole was bounded by the 30-day badge.

What the removed machine gets: the ID token (bound to the caller's key, so
useless inside wires, but a bearer token for about an hour to anything else
that accepts this OAuth client's audience), the arguments, and possibly
stdin; and it can return whatever output it likes to an agent that trusts it.

This is the case removal exists for: a host you no longer trust.

## Options

1. **A shorter policy lifetime.** Days, not 90. Narrows every path at once.
   Cost: the root key must re-sign that often, and the admin is a one-shot
   command on a machine that holds the root; nothing renews a head today. A
   network whose admin is away for a week stops.
2. **The host proves it is current before it is told anything.** The host
   already follows a directory and holds a directory-signed `Fresh` for its
   head, good for `fresh_secs` (15 minutes by default). Have the host speak
   first: its head, the service's signed entry, and a `Fresh` signed by a
   directory **other than itself**. The caller sends its token and arguments
   only after checking them. An honest directory signs `Fresh` only for its
   newest head, so a removed host has nothing to show within 15 minutes of
   the edit reaching the directories. Costs: one more flight in the
   handshake; with every directory down hosts can't prove freshness, so the
   existing `lenient` / `strict` setting would decide for callers too; a
   one-directory network where that directory is also the host has no "other"
   directory to sign.
3. **Callers fail closed on an old view.** Refuse to dial when no directory
   has vouched for the view within a policy-set age. Cost: gives up "calls
   keep working with every directory down", and does not by itself stop a
   removed directory vouching for its own old head (needs "a directory other
   than the host being dialed", or more than one).
4. **Vouching needs more than one directory.** A refresh counts only if a
   directory other than the dialed host, or k of n, answers. Helps only
   networks with several directories.

Option 2 is the one that closes the window rather than narrowing it, and it
does so with an object the code already has.

## The tension with card 45

[Card 45](45-trim-policy-sync.md) proposes deleting `Fresh`, the beat and
`lenient` / `strict`, because under the default a `Fresh` changes no decision
today. Option 2 here is the first thing that would make `Fresh` decide
something. Think this card through before building 45: either `Fresh` stays
and earns its place, or 45 goes ahead and this card needs a different answer.

## Questions to settle

- Is a 15-minute window acceptable, and is `fresh_secs` the right knob?
- What should a one-machine network (host and directory together) do?
- Does the extra flight matter for call latency? Measure on loopback and over
  a relay.
- Should the caller stop sending the ID token in the first message whatever
  else is decided?
- Does `wires inbox` need the same proof before it presents a token to a host?

## Notes

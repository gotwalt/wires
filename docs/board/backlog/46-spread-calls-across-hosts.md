# 46 — Spread calls across a service's hosts

**Depends on:** — · **Status:** backlog, not scheduled (drafted from the 2026-10-04/05 review; the human hasn't decided) · **Files:** `wires/caller/pick.rs`, `wires/caller/call.rs`, `docs/usage.md`

## Why

The human (2026-10-04): "wires allows a relatively stateless host, and
allows for horizontal scalability for any given service." The code gives
failover, not scale: `candidates()` tries the host that last answered, then
the admin's order, and moves on only when a dial fails. With three hosts,
every caller's traffic goes to the first until it is down.

## Proposal

- Order a service's hosts at random per call (or per caller, seeded by its
  key), keeping "next host on a dial failure, never on a refusal".
  `last-good.json` then only demotes a host that just failed to answer.
- Say what is still per-host state: the push queue (a push queued on one
  host is fetched from that host), and whatever a native service keeps in
  memory. [Card 31](31-inbox-delivery.md)'s single delivery path is the
  place to settle the first.

Small: tens of lines and a property test. Until it lands, the docs say
"fails over", not "scales out" ([card 39](../done/39-premise-and-story.md)).

## Notes

# 46 — Spread calls across a service's hosts

**Depends on:** — · **Status:** review (worker, 2026-10-05) · **Files:** `wires/caller/pick.rs`, `wires/caller/call.rs`, `docs/usage.md`

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

**Worker, 2026-10-05 (branch `worker/46-spread-calls`).**

- **Random per call, not per caller.** `pick::candidates` shuffles the
  service's hosts with an injected `Rng` (`rand::rng()` in `call_entry`; a
  seeded `StdRng` in tests) on every call. Per call spreads load best: a
  single busy agent (one caller, many calls) spreads too, which a per-caller
  seed would pin to one host, and it needs no state. The cost: a service that
  keeps state between calls answers from whichever host the call landed on
  (now stated in protocol.md and usage.md).
- **`last-good.json` is gone; `unanswered.json` replaces it.** It maps
  host → when it last failed to answer this caller's dial; a host there for
  under `DEMOTE_SECS` (60 s) goes last (oldest failure first). Keyed by host,
  not service: a host that is down is down for all its services. Without it,
  a down host is tried first in 1 of n calls, each costing the 10 s dial
  timeout; with it, one timeout a minute per caller. Recorded after an
  answered call: the hosts tried before the one that answered are noted, the
  one that answered is cleared, expired entries dropped. A call no host
  answered records nothing (every host failing changes no relative order).
  A dial that connected and then failed mid-stream also records nothing.
  Renamed rather than kept because the content and meaning changed, and
  there is no compatibility to keep.
- **Next host only on a dial failure, never on a refusal**: unchanged
  (`transport::call_service_on`); `a_refusal_does_not_fail_over` now has both
  hosts refuse in their own words and asserts exactly one was asked.
- **`wires inbox` is unaffected.** It already fetches from every host of
  every service in the view (`pick::hosts_of`), so a push queued on whichever
  host ran the call is fetched; a push on a host that is down waits there.
  An inbox fetch also teaches every host the caller's identity, which is what
  `wires push --to <role>` needs: with random choice a caller's identity is
  known only to the hosts it called or fetched from. Both are stated in
  protocol.md §5 *What stays on one host* and §9, and usage.md *Known
  trade-offs* (card 31 pointer kept). No fix needed.
- **Tests:** proptests (the order is always a permutation, recently failed
  hosts last in failure order; every healthy host comes first within 200
  draws, and with all failed the oldest is first), examples (300 seeded draws
  over 3 hosts each come first 60..140 times; a failed host goes last until
  the window passes and an answer clears it; `note` semantics; file round
  trip), and the call test now loops until the random order tries the dead
  host first, then checks it is recorded and the answering host is not.
  No doctests: everything here is `pub(crate)`.
- **Files outside the card's list**, kept minimal: `wires/Cargo.toml`
  (`rand`, already a workspace dep), `wires/admin/keystore.rs` (a test's
  file name), `wires/admin/service.rs` (`--host` help: "Repeatable: calls
  spread across them"; module example comment), `wires/caller/mod.rs`
  (module list line), `wires/snapshots/service-{add,set}{,.all}.txt`
  (blessed). `call.rs`: the import, the `candidates`/`record` lines, three
  doc comments and the two tests; nothing near `RemoteTool`/`ToolTarget`.
- **Narrative sentences now false** (not edited; card 39/43 style rewrite):
  - README.md:142-143 "If a service has several hosts and one is down, the
    call goes to the next" (still true but undersells: calls spread), and
    README.md:279-280 "Several hosts for one service means failover, not more
    capacity".
  - docs/fabric.md:65 (host row: "the caller tries the next host in the
    service's list when a dial fails" — the list is now in random order) and
    :83 (`last-good.json` → `unanswered.json`).
  - docs/executive-summary.md:129 "Several hosts per service give failover,
    not more capacity."
  - docs/demo.md:55 rebuttal "Two hosts, so it scales? No: a second host is
    failover…", :263-269 narration "That's failover; calls don't spread
    across them", :310 the banned phrase "Scales horizontally… A second host
    is failover" (now allowed for stateless services, with the per-host-state
    caveat), :63 "for the failover beat".
  - docs/deployment.md:139-140 "callers fail over between them. They don't
    spread calls, so more hosts add no capacity."
  - docs/agent-sandbox.md:100 lists `last-good.json` (now
    `unanswered.json`).
  - The blog post makes no host-count claim; testing.md:77 ("failover to
    the spare") stays true.
- Green: `cargo test --workspace`, clippy `-D warnings`, `cargo fmt
  --check`, `.scripts/demo-remote-cli.sh --quiet`, `.scripts/demo-push.sh
  --quiet`. No shell changed.

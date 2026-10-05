# 49 — The removed-host window

**Depends on:** decide together with [45](../backlog/45-trim-policy-sync.md) · **Status:** review (built; decided by the human, 2026-10-05); 45 builds on it · **Files:** `library/calls/session.rs`, `library/services/fresh.rs`, `wires/caller/{call,view,inbox}.rs`, `wires/host/{transport,freshness,follow}.rs`, `docs/protocol.md` §4–5, §9

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

[Card 45](../backlog/45-trim-policy-sync.md) proposes deleting `Fresh`, the beat and
`lenient` / `strict`, because under the default a `Fresh` changes no decision
today. Option 2 here is the first thing that would make `Fresh` decide
something. Think this card through before building 45: either `Fresh` stays
and earns its place, or 45 goes ahead and this card needs a different answer.

## Decision (the human, 2026-10-05)

Option 2, with these answers to the questions below: "I think 15m is ok. I
think one machine networks need to work just fine. i think fail close."

- **The host speaks first; the caller sends nothing until it has checked.**
  Today `Hello` (the ID token) and `Invoke` (the arguments) go out before the
  host says a word; that order goes. On a new session the host sends its
  root-signed head and a current `Fresh` for it, and no entries (a stranger
  learns a version and who vouched, nothing about services). The caller
  checks: the `Fresh` verifies, is within `until`, is for that head, and is
  signed by one of that head's directories **other than the dialed host**;
  the head's version is at least its view's. Same version: its own view says
  whether this host serves the service. Newer: it refreshes its view from a
  directory before deciding. Any failure is a dial failure (move to the next
  host, card 46's rule), not a refusal, and nothing was sent.
- **The window is `fresh_secs`, 15 minutes by default.** It is the knob.
- **A cached proof costs no extra flight.** The caller keeps each host's last
  proof; while it is within `until` and matches its view, it sends `Hello` and
  `Invoke` at once, as today. The extra round trip is paid only on the first
  call to a host in each window. Measure both on loopback and over a relay.
- **Fail closed.** With no directory able to vouch (all down, or the host cut
  off from them), the caller does not send the token: the call fails with a
  sentence saying no directory has vouched for this host recently. Calls no
  longer keep working with every directory down. `lenient` / `strict` goes:
  this is the only behaviour, decided at the caller, and the host's own
  `strict` gate check is redundant.
- **One-machine networks work just fine.** When the head lists exactly one
  directory and it is the dialed host, the caller accepts that host's own
  `Fresh`. Fail-closed costs nothing there: if its directory is down, so is
  the host. The cost is stated in protocol §9: in such a network removal of
  that machine is bounded by the head's `not_after`, and an admin who needs
  removal to hold runs a second directory (say so in the walkthrough, since
  first-run is this shape).
- **`wires inbox` gets the same check** before it presents a token to a host,
  and so do `wires mcp` and the gateway, which dial through the same path.

## Questions to settle (answered above)

- Is a 15-minute window acceptable, and is `fresh_secs` the right knob?
- What should a one-machine network (host and directory together) do?
- Does the extra flight matter for call latency? Measure on loopback and over
  a relay.
- Should the caller stop sending the ID token in the first message whatever
  else is decided?
- Does `wires inbox` need the same proof before it presents a token to a host?

## Notes

### Built (worker, 2026-10-05)

**The wire** (`wires/session/2`, `wires/inbox/4`; protocol.md §5 *The host's proof*, §7).

- The host always speaks first: on accepting a stream it re-reads its policy (none readable:
  `Denied host configuration error`, as before) and sends `Proof` (session tag 13; inbox
  `proof {proof}`): `HostProof {head, fresh: [Fresh]}`, its root-signed head and every *current*
  `Fresh` it holds for it, one per directory, at most 16. No entries.
- A QUIC stream reaches the host only once the dialer writes, so the caller opens one of two ways:
  - **`Open`** (tag 12, empty; inbox `open {}`) when it holds no current word for this host. It
    reads the proof and checks it (`HostProof::check` + the view): head verifies under the root
    and hasn't expired; no older than the view's (same version: same `HeadHash`); some `Fresh`
    `vouches` (verifies for that head, current, signer ≠ dialed host unless the head lists exactly
    `[host]`); the view lists the host for the service (inbox: for some service). A **newer** head
    makes it refresh its view from a directory first (8 s budget, inside the host's 10 s handshake
    timeout) and check again against the refreshed view. Only then `Hello` + `Invoke` (or
    `hello` + `fetch`). Any failure: a dial failure (`Unvouched`), nothing but `Open` sent, next
    host, recorded in `unanswered.json` by card 46's rule (a host tried before the one that
    answered).
  - **`Hello` + `Invoke` at once** (the cached path) when the view's `FreshSet` holds a current
    `Fresh` for the view's head from a directory other than this host, and the view lists the
    host. No extra flight. It still reads the proof before stdin: an older head or another head at
    the view's version stops the call (exit 1, no stdin); its own cached words count beside the
    host's (the host's may lapse a moment after the caller's was checked).
- **"Each host's last proof" became "the newest `Fresh` per directory, with the view"** (a
  `FreshSet` in `view.json`, 0600 via `write_private`). A `Fresh` vouches for a head, not for a
  host, so one host's proof (or the caller's own refresh, or its view subscription) covers every
  host of that head except the signer itself. Strictly better than a per-host cache, same bound.
  Every `Fresh` a checked proof carries that vouches for the view's head is kept; the gateway
  keeps them in memory, shared across its users (`Sink::Shared`).
- **A host holding a newer `Fresh` than the cached one** doesn't matter for the window: the
  cached one bounds it the same (≤ `fresh_secs` after its `at`). It is kept (it extends the
  cache). A proof showing a **newer head** after the caller has spoken needs no directory's word:
  the head must verify under the root, it is noted (`note_seen`), and `HelloAck::assigns` decides
  as before. Requiring a fresh word there would only turn an honest host's refusal (77) into a
  local failure (demo step 8 showed it: the spare, now the only live directory, held the new head
  with only its own word).
- `FreshSet` (library, `services/fresh.rs`): newest per signer by (version, current, until), at
  most 16 signers, verifies nothing on the way in and everything on use. The host's
  `Freshness` is one too (`fresh.json` is now a JSON list), so a host that is also a directory
  keeps the other directory's word beside its own (it used to keep only the best one, which was
  often its own).
- Exit code: **1** for fail-closed (a local failure: nothing was sent), with
  `no directory has vouched for a host of \`<svc>\` recently, so nothing was sent (…); the
  network's directories may be down or out of reach: try again later, or ask your admin`
  (`vouch::all_unvouched`, in `wires/snapshots/errors.txt`). `wires inbox` prints the same
  sentence on stderr when every host failed so (its exit code is unchanged).
- Deleted: `FreshnessMode`, `Settings.freshness`, `policy settings --freshness`, the strict
  validation (`directory rm` / `remove` of the last directory), `GateRefusal::Unvouched`,
  `freshness::STALE` / `Vouched`, `ServicesHost::check_vouched`. The settings item's body changed,
  so the policy head is **format 5** (4 refused, `UnsupportedVersion`). `Keystore` derives `Clone`
  (admin lane, one line: the caller's refresher holds one).
- Hosts hold a current `Fresh` at all times as before: a non-directory host gets one per beat from
  the directory it follows; a host that is the only directory signs its own (`vouch_from_local`),
  checked by `a_one_machine_network_calls_its_host`. A host that can't prove itself traces it
  (warn, at most every 10 s).

**Tests for the attack** (all green): `caller::call::a_removed_host_vouching_for_its_own_old_head_is_sent_nothing`
(fake host X, node-banned, also a directory, shows its old head with its own current `Fresh` and
the other directory's lapsed one: no `Hello`, no `Invoke`, no stdin; exit 1 with the sentence),
`a_host_the_current_head_drops_is_sent_nothing_and_another_serves` (X shows the *current* head with
a valid other-directory `Fresh`: the caller refreshes, X isn't listed, nothing sent, Y serves, X in
`unanswered.json`), `e2e::follow::a_node_banned_host_that_is_a_directory_gets_no_token` and
`a_host_dropped_from_the_service_gets_no_token` (real directory, real honest host, real `wires
call` path; the caller's old word lapses after `fresh_secs` = 3 s), `with_every_directory_down_calls_fail_closed_until_one_is_back`,
`a_one_machine_network_calls_its_host`, `a_caller_waits_for_a_proof_once_then_speaks_at_once`
(first frame `open`, then `hello`), unit and proptests in `library` (`proof.rs`, `fresh.rs`) and
`caller::vouch`.

**The extra flight, measured** (`e2e::follow::measure_the_extra_flight`, `#[ignore]`d; release
build; a new connection per call to a real host running `echo`; p50 from the dial):

| path | loopback (200 calls) | n0 relay only, both ends relay-only (30 calls) |
|---|---|---|
| connected | 0.9 ms | 63 ms |
| `Open`, then the proof, then the call | 3.0 ms | 199.6 ms |
| speaking at once (cached) | 3.1 ms | 139.9 ms |

So the uncached path costs one round trip (~60 ms through the relay here: one relay RTT;
invisible on loopback, where the host's token check and exec dominate). It is paid once per
`fresh_secs` window per head, and not at all by a caller whose view subscription or refresh is
under 15 minutes old, unless it calls the directory that vouched (then once). In a debug build the
host's per-connection policy read dominates (≈60 ms) on both paths.

**Decisions a reviewer should look at.**

- **Two-directory networks where both directories are the hosts** (the demo's shape: workbench and
  spare): with one down, calls to the other fail closed once the callers' cached words lapse
  (≤ `fresh_secs`), because the live one can only show its own word. That is the decided rule
  (fail closed; only a one-directory network trusts its host), but card 08's step 7 ("workbench
  down → answered by the spare") holds only within 15 minutes of the workbench going down. A third
  directory (or a directory that isn't a host) makes it hold. The demo passes as scripted (the
  caller holds the workbench's word).
- **A removed directory can vouch for others' old heads** (protocol §9): the check stops a host
  vouching for itself, not one removed/compromised directory vouching for a removed host (any
  head from before its removal lists it). k-of-n would close it; out of scope.
- The gateway does not refresh on a newer head (dial failure: the user's subscription catches up);
  `wires inbox` refreshes (it has a `Refresher`).
- `HelloAck` still carries the head and entry when newer, though the proof now carries the head
  too: left for card 45 to trim.

**What card 45 must know.** `Fresh` now decides: keep `Fresh`, the beat, `FreshSet` and the
directories' signing; `fresh_secs` is the removed-host window and `beat_secs` must stay well under
it (a host needs a current one at all times; with `fresh = 3 × beat` a host survives two missed
beats). `lenient`/`strict` and the host's gate check are already gone (item 2's remainder: the
settings item is `{beat_secs, fresh_secs}`; deriving the beat from `fresh_secs` would be a format
change again). Callers' view subscriptions (item 3) are one of the three ways a caller holds a
current word for the cached path; dropping them means `wires mcp` / the gateway pay the extra flight
once per window per head instead (and the gateway, which neither refreshes nor resolves, would need
a refresh path: today a newer head is a dial failure there). Replicas (item 3) don't matter to
this card. `view.json`'s `fresh` is now a list; `fresh.json` is a list.

**Narrative statements now false** (not rewritten, per the rules):

- README.md 284–294: "Calls don't need one [a directory]: each host decides from its own copy";
  "A caller dials from the view it holds … receives their ID token and arguments … the hard bound
  is the policy's expiry (90 days by default)".
- docs/usage.md 613–625 ("A removed host still sees a stale caller's token and argv" … "hard bound
  is the policy's expiry"); 651–656 ("With every directory down, hosts keep deciding … `lenient` …
  `--freshness strict`"); 734 (`wires policy settings [--freshness lenient|strict]` row); the
  walkthrough should say, per the Decision, that a one-machine network's removal is bounded by
  `not_after` and a second directory makes removal hold.
- docs/fabric.md 66 ("Every directory | Calls keep working … under `lenient` … under `strict`");
  82 (`fresh.json`, "the newest `Fresh`": now one per directory); 151 and 232 (`wires/inbox/3`);
  231 (`wires/session/1`); the "never decides a call … calls keep working" sentence wherever it
  appears.
- docs/deployment.md 148–150 ("calls keep working with every directory down"), 197–202 ("When no
  directory answers … `lenient` … `--freshness strict`").
- docs/testing.md 37 ("the `lenient` / `strict` …" e2e description).
- docs/board/README.md: the card 45 row still says "`lenient`/`strict` go" (they are gone).
- bench/state-scale (dated model) mentions the settings item's shape; not touched.

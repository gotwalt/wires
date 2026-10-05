# 45 — One way to keep policy copies in step

**Depends on:** [41](../done/41-idp-membership.md) · **Status:** review (built on card 49's branch, 2026-10-05), **built with [card 49](49-removed-host-window.md)**, which is decided · **Files:** `library/services/{policy_update,fresh,item,view}.rs`, `library/directory/frames.rs`, `wires/directory/`, `wires/policy/`, `wires/host/{follow,freshness,gate}.rs`, `wires/caller/view.rs`, `wires/admin/settings.rs`

## Why

The directory stays: it is how a caller gets from a service name to a
machine. What surrounds it was sized by a model of 10k–50k users
([`bench/state-scale/REPORT.md`](../../../bench/state-scale/REPORT.md)),
whose own finding 7 is that the simple design was fine at demo size. The
review counted eleven ways a copy is kept in step (five for hosts, six for
callers), and every delta path already falls back to sending the whole
thing.

## Proposal, largest first

1. **Send whole policies and whole views.** Delete `PolicyUpdate`,
   `ViewUpdate`, `ViewDigest`, the 16-head history in `directory.redb` (and
   the `redb` dependency: `policy.json` already holds the newest). Cost: a
   host receives the whole policy per edit (7 KB at team size, 67 KB at
   1k users) instead of about 1.5 KB.
2. **Delete `Fresh`, the beat, `lenient` / `strict` and the settings item.**
   Under the default (`lenient`) a `Fresh` changes no decision; every one is
   consumed by the node that received it directly from its signer over an
   authenticated connection. If "refuse when cut off from every directory"
   is wanted, a host can keep an in-memory time it last heard from one.
3. **Drop directory replicas and caller view subscriptions.** A directory
   that missed a publish catches up at the next one or `policy push`; an MCP
   client learns of a grant at its next call or a poll, not within a second.

Together about 2.25k non-test lines and five concepts (delta, digest,
`Fresh`, replica, view subscription), with removal as prompt as it is today
under the default setting.

## Since this was drafted (cards 41, 43 and 47)

- **Read [card 49](49-removed-host-window.md) first.** Its strongest option makes `Fresh` decide
  something (a host proving it is current before a caller tells it anything), and item 2 below
  deletes `Fresh`. Decide the two together.
- Already gone: `directory.redb`'s `current` table and its stored `Fresh` (a beat writes nothing
  to disk now).
- New since: callers' view subscriptions have their own pool and a cap of 16 per person, and end
  at the token's expiry (card 47); a replica subscription has a silence timeout (card 43). Item 3
  below would delete both mechanisms.
- A host that is also a directory used to resync when its follow loop saw an update it already
  held; fixed in card 43 (`Follower::take` skips it). One fewer reason the delta path misfires.
- The ALPNs are `wires/directory/2` and `wires/directory-sub/2`.

## Decided with card 49 (the human, 2026-10-05)

Card 49 keeps `Fresh`: a caller now needs one, signed by a directory other
than the host it dials, before it sends a token. So **item 2 changes**:
`Fresh` and the directory's beat stay (hosts must hold a current `Fresh` at
all times); `lenient` / `strict` and the host's gate check on freshness go
(the caller fails closed instead); the settings item shrinks to `beat_secs`
and `fresh_secs`, or to `fresh_secs` alone if the beat interval can be
derived from it. Items 1 and 3 go ahead as written. Build 49 first, then 45,
or both on one branch: they share `fresh.rs`, `host/freshness.rs` and
`caller/view.rs`.

## Notes

### Built (worker, 2026-10-05), on card 49's branch (efa12ee)

**Wire.** `wires/directory/3` and `wires/directory-sub/3` (both bumped, no compat). Protocol §2
(a new admission row), §3 (*Views*: everything travels whole), §4 (rewritten), §5–§9 updated first.

1. **Whole policies and whole views.** Deleted `PolicyUpdate` (`library/services/policy_update.rs`,
   `SignedPolicy::update_from/apply`), `ViewUpdate`, `View::update_to/apply`, `ViewDigest`
   (`VIEW_DIGEST_CONTEXT`), the answers `policy_update`/`view_update`, `view {have, held}` (now
   `view {query?}`, always whole), `SubscriptionKind` (now `subscribe {have}`), `directory.redb`
   (`wires/directory/db.rs`, its 16-head history) and the **`redb` dependency** (gone from
   `Cargo.lock`). A directory's store is the node's own `policy.json` (`Directory::accept` adopts
   into it with `adopt_if_newer`, then re-reads it), so a host that is also a directory has one copy.
   `policy {have}` answers `current` or the whole policy; the subscription sends the whole policy
   when its head is newer than what the subscriber has, else a `fresh` beat (each encoded once per
   head and `Fresh`, held in `Current`; `FrameCache` gone). Cost per edit per host: the whole
   policy (asserted in `an_edit_reaches_every_subscribed_host_within_2s_as_the_whole_policy`).
2. **`Fresh`, the beat, `FreshSet`, `beat_secs`, `fresh_secs` stay**, untouched. The settings item
   was already `{beat_secs, fresh_secs}` after 49; deriving the beat from `fresh_secs` would be
   another format bump to save one field, so it stays.
3. **No replicas, no view subscriptions.** Deleted `replicate`/`follow`/`take_from_replica` (the
   replica loop), `sub_view.rs`, the callers' pool (`view_subscribers`, `ViewSlot`,
   `MAX_VIEW_SUBSCRIPTIONS_PER_PERSON`) and `view::follow`. Only a named node (host or directory)
   subscribes; an admitted caller hears `VIEW_NOT_POLICY`. `--max-subscribers` is one pool (help
   snapshot re-blessed).

**Host follow with whole policies** (`wires/host/follow.rs`, about half its old size): take
`policy` (verify, its `Fresh` vouches, adopt if newer) and `fresh` (keep if for the held head).
Resync (`have: 0`) is gone. New rule: **a frame for a head older than the host's means that
directory is behind** (it missed a publish, and with no replicas it stays behind, unable to vouch
for the host's head): the host passes it over at once (`Behind`, `FollowStats::behind`), as it does
a `denied` or a policy it can't take. The directory now sends its beat even to a subscriber ahead
of it (it used to send nothing until it caught up), so this shows at once. A host that is also a
directory adopts through its own `Directory::accept` (`Follower::directory`, replacing
`runs_directory`), so its directory serves what the host follows: the only way a directory catches
up without a publish, and it is the host's one subscription, not a second mechanism. The demo's
remove step: the publish reaches both directories (card 48's retry), and each pushes the whole
policy to its followers at once.

**A publish that misses a running directory exits 1** (card 48's open question, decided). Nothing
heals that directory now, and hosts following it keep deciding under the old policy (admitting a
removed person, say) until a publish reaches it, so exit 0 would be false. The rule
(`Propagation::from_publish(result, running)`, `PublishReport::missed_running`): **exit 1 when a
directory the new head lists, and that has taken a publish from this admin before
(`reached.json`), still missed it after the retries**, whatever the others did. The line now says
`…hosts that follow it decide under the policy before it, and nothing but a publish brings it:
wires policy push re-publishes it once it is back` (card 48's "It takes this one from a directory
that did" is gone), and the failure says the policy is stored and in force at K directories and
names the ones to re-push to. A directory never reached still fails nothing (the first run, or one
just `directory add`ed that doesn't run yet). Retrying longer was rejected: every edit would block
while a directory is down. Tests: `an_edit_a_running_directory_missed_fails_though_another_took_it`,
`e2e::restart::a_directory_that_missed_an_edit_holds_the_old_one_and_the_edit_fails`,
`directory::tests::a_directory_that_missed_a_publish_stays_behind_until_the_next`.

**Long-running callers poll** (`view::poll`, `view::POLL` = 60 s): `wires mcp` and `wires inbox
--wait` ask for the whole view every minute (sooner while they hold none), keep `view.json`, and
`mcp` still sends `list_changed`. A grant reaches `wires mcp` within a minute, not a second (the
e2e test polls every 200 ms). **The gateway** keeps each web user's view in memory
(`gateway::Views`) and asks again at the user's first request after 60 s; a directory's
`NOT_ADMITTED` drops it. **The refresh path for a newer head** (card 49's gap): `Refresher` is now
a closure (`Refresher::keystore(ks, endpoint, root, token)` for `call`/`inbox`; the gateway's asks
for that user's view and updates its cache), and `PresentingCaller` hands one to `Vouching`, so a
host showing a newer head makes the gateway refresh instead of failing the dial. Card 49's checks
are called, not changed.

**Scope addition (49's security review): a directory proves itself before it hears a token.** A
caller opens with `open {}`; the directory answers `proof {proof}` (a `HostProof`: its head and the
current `Fresh`es it holds, its own and, on a host+directory, the host's `Freshness`; no entries)
and only then reads `hello` + request on the same stream (`Directory::proof`, `wire::open`,
`wire::Opened::ask`). The caller (`view::ask_proven`, `view::directory_vouched`) asks every
directory for its proof at once and checks each with `HostProof::check` against its view's head
(holding no view: the head verifies, hasn't expired, and a `Fresh` vouches), **and requires the head
to list the dialed directory** (else a removed directory could replay the others' current words
with the current head). The `Fresh`es counted are the proof's, the view's, and every other
directory's proof in the round, so two directories at one head vouch for each other. Directories
are tried as their proofs arrive (nothing waits for a slow one; with `fresh_secs` = 3 s in tests,
waiting let words lapse). Every token-bearing directory request goes this way: `refresh` (login,
services, call, inbox, `mcp`'s poll, `Vouching`'s newer-head refresh), `resolve`, the gateway.
`wire::ask` no longer takes a token (hosts and the admin present none); tests of the directory's own
admission use `#[cfg(test)] ask_presenting`. Tests:
`view::tests::a_directory_is_told_nothing_without_another_directorys_current_word` (own word only,
lapsed, behind the view, unlisted with copied words, the one-directory case),
`e2e::views::a_removed_or_lagging_directory_is_told_no_token` (a fake directory X counts any frame
after `open`: removed and vouching for its old head; removed but showing the current head with Y's
and Z's current words; listed but behind the caller's view: told nothing each time, and the refresh
is served by Y, vouched for by Z), `directory::tests::a_directory_shows_its_proof_before_a_caller_presents_a_token`.

**Consequences a reviewer should weigh.**

- **A refresh needs two directories' words** (or the one-directory case). A *pure* directory holds
  only its own `Fresh`; with several listed and only one up, callers can't refresh their views (they
  keep the one they hold, whose cached words lapse within `fresh_secs`). A directory that is also a
  host shows its host's words too (the demo's shape: workbench and spare each hold the other's), so
  it survives the other going down for `fresh_secs`. Card 49's attack test had to start the second
  honest directory (`a_removed_host_that_is_a_directory_gets_nothing`): with one of two directories
  up, the refresh to the newer head now fails closed.
- A refresh costs one more round trip (the proofs, in parallel) and dials every listed directory.
- `HelloAck` still carries the head and entry when newer (card 49's Notes asked 45 to trim it):
  left alone, since it is 49's handshake, under review.

**Touched outside the listed files** (minimal): `wires/caller/vouch.rs` (`Refresher` became a
closure type plus `Refresher::keystore`; `refresh_to` calls it; no check changed),
`wires/caller/{call,inbox,mcp}.rs` (call sites; one call test's fake directory shows a proof),
`wires/gateway/{mod,mcp_http}.rs`, `wires/admin/{propagate,keystore}.rs`, `wires/host/{serve,mod}.rs`,
`library/{lib,error}.rs`, `library/examples/policy_sizes.rs` (drops the `update_*` keys, which
`bench/state-scale/model.py` reads), `library/network/admission.rs` (a comment),
`deploy/gateway/compose.yml` (a comment), `.scripts/demo-remote-cli.sh` (header comment),
`docs/board/README.md` (this card's row). Not touched: `library/calls/proof.rs`, `fresh.rs`,
`host/freshness.rs`, `transport.rs`, `admin/service.rs`, `remove.rs` (card 49's fixes).
`docs/board/review/49-removed-host-window.md` still links `../backlog/45-…` (now `review/`).

**Narrative statements now false** (not rewritten, per the rules; line numbers on this branch):
`README.md` 159; `docs/usage.md` 36, 311, 645, 736–745, 800 (subscriptions, replicas, "within
seconds"); `docs/fabric.md` 36, 55, 81, 102–105, 145–161, 176–177, 195–208, 233–250 (replicas,
`directory.redb`, deltas, view subscriptions, `wires/directory/2`); `docs/deployment.md` 62, 119,
136–147, 182–195, 244; `docs/demo.md` 54; `docs/testing.md` 37, 46–50; `CLAUDE.md` 178–179
(`directory.redb`, `wires/directory/2`, `wires/directory-sub/2`); `bench/state-scale/REPORT.md`
18–149 and `model.py` (deltas, view updates, replicas: a dated model). Also anything saying a
caller's token goes to a directory on first contact, that the gateway follows views by
subscription, or that an edit some directory missed exits 0.

**Size.** Against efa12ee: Rust +1765 −3366 (net **−1601**; −1583 outside `e2e/` and
`directory/tests.rs`); everything but docs +1772 −3376 (net −1604); `Cargo.lock` −10;
`protocol.md` +158 −179.

**Acceptance run** (2026-10-05): `cargo test --workspace` green (150 library, 399 wires, 1 ignored,
doctests); `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --all --check`
clean; shellcheck clean; `.scripts/demo-remote-cli.sh --quiet` (193 s) and `.scripts/demo-push.sh
--quiet` pass.

### Merged with card 49's review fixes (fab5ec3)

- **Directories asked** (49 #4): the view's head's, then the network string's, in `refresh`,
  `resolve`, `wires mcp`'s poll and the gateway; every one, from either list, proves itself first,
  and the head it shows must list it. **The one-directory rule applies to directories too**
  (`directory_vouched(.., known, ..)`): a directory's own word counts only while the network string
  names no other, as 49 made it for hosts (the stricter of the two).
- **Newer-head refresh** (49 #1, #6): kept 49's "the refresh must reach the host's version, then
  `Same`, else dial failure"; `Refresher::keystore` and the gateway's closure feed it, and their
  failures are dial failures there. A lagging or removed directory is now told nothing during that
  refresh (its proof is behind or self-vouched), which 49's tests now assert.
- **Resolve** (49 #3): both checks stand: a directory whose proof is behind the view is told
  nothing, and 49's floor (`held.version().max(seen)`) refuses an older one-entry view from one
  that passed; the test covers each.
- `Freshness::proof` lost its `me` argument in 49; `Directory::proof` follows. 49's `fresh_secs`
  cap and last-directory refusal needed nothing from 45.
- protocol.md: §4 says the token goes only to a proven directory, §5–§6 that hosts and directories
  both prove first, and §9's "directories are told the token before they prove anything" is now
  "directories are held to the hosts' rule".

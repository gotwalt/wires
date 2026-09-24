# State scale: how much metadata each node moves

*Modeled 2026-09-24 at 655a96c; the *badges* and *apex* rows re-modeled after
card 35 built badges (the state's measured ban entry, and no host list), and
the *apex* rows again after card 36d (hosts hold the whole policy; no Merkle
proofs), and the *apex* caller rows after card 37 (views, as built).
`python3 bench/state-scale/model.py`
(`--email-roles`). Byte sizes were measured from real signed states by the
`state_sizes` example (deleted with the one-blob state by card 36b; in git
history at 055ac46), and the *apex* ones by `policy_sizes`; rates are
assumptions, listed in `model.py`'s `ASSUMPTIONS`.*

**The question.** Today every node holds the whole admin-signed state and
re-fetches it after every edit (protocol.md §3–4). How much does each node
receive, per day, as the org grows, and what would a persistent directory
(apex) save?

**Measured sizes** (serialized signed JSON): a member 67 B, a host 134 B (both
format 1, before card 35), a ban 78 B (format 2), a service entry 318 B (80-character description, 2 hosts, 2 allow roles,
1 reader role), a role with one group matcher 73 B, each further email matcher
75 B, a membership 361 B. In the signed policy (card 36d, `policy_sizes`): the
root-signed head 540 B, a `Fresh` 446 B, a service item 610 B (the same entry,
now root-signed on its own), a role item 101 B, a ban item 115 B; the whole
policy is 67 KB at 100 services, 667 KB at 1k and 3.3 MB at 5k (with 30, 300
and 1,500 open bans), which the model reproduces within 1%.

**Main assumptions:** 2 nodes per user; 0.1% of nodes join or leave per day;
1% of services edited per day; a caller is active 8 h/day; 3 KB per iroh
handshake (not measured); a caller may use 30 services; in the apex design,
**measured** by `policy_sizes` (card 36d): a 475 B freshness beat every 5 min;
a `policy_update` per edit of 1.7 KB (one changed service) or 1.2 KB (one new
ban), the new head, its `Fresh` and the changed item, which every host
receives, since every host holds the whole policy; a caller's view entry 630 B
(its signed entry and marks). Callers as card 37 built them: a one-shot caller
sends nothing in the background; a call whose host has a newer head gets it
in the `HelloAck` (1.5 KB with the service's entry), and the caller then asks
a directory for what changed (a `view_update`, about 1 KB plus 630 B per
changed entry, and a dial), at most once per active 10-minute window. `wires
mcp` (up 8 h/day) holds a subscription: its whole view once, a beat every
5 min, and a `view_update` per new head. The caller's invite is measured
(979 B with a Google-sized client id and public secret, two directory ids).

## Results (group roles)

| | team | company | enterprise | large |
|---|---|---|---|---|
| users / services / hosts | 50 / 10 / 5 | 1,000 / 100 / 50 | 10,000 / 1,000 / 500 | 50,000 / 5,000 / 1,000 |
| nodes | 105 | 2,050 | 20,500 | 101,000 |
| **Today** |  |  |  |  |
| every node holds | 11.3 KB | 174.5 KB | 1.7 MB | 8.5 MB (over frame cap) |
| edits/day | 1 | 3 | 30 | 151 |
| invite token | 15.6 KB | 233.2 KB | 2.3 MB | 11.3 MB |
| each caller receives /day | 160.0 KB | 664.6 KB | 39.4 MB | 390.5 MB |
| each host receives /day | 457.6 KB | 978.4 KB | 53.5 MB | 1.3 GB |
| each host sends callers /day | 3.2 MB | 26.6 MB | 1.6 GB | 39.0 GB |
| admin sends /day | 71.7 KB | 27.1 MB | 26.6 GB | 1.3 TB |
| whole network /day | 18.4 MB | 1.4 GB | 842.0 GB | 41.6 TB |
| **Badges only** (members leave the state) |  |  |  |  |
| every node holds | 4.1 KB | 36.2 KB | 357.2 KB | 1.8 MB |
| edits/day | 1 | 2 | 20 | 100 |
| invite token | 5.9 KB | 48.8 KB | 476.7 KB | 2.4 MB |
| each caller receives /day | 152.9 KB | 220.7 KB | 6.0 MB | 75.1 MB |
| each host receives /day | 450.4 KB | 519.6 KB | 7.7 MB | 179.5 MB |
| each host sends callers /day | 3.1 MB | 8.8 MB | 242.0 MB | 7.5 GB |
| admin sends /day | 35.5 KB | 4.0 MB | 3.6 GB | 179.4 GB |
| whole network /day | 17.6 MB | 471.3 MB | 128.5 GB | 7.9 TB |
| **Apex** (directory; hosts hold the policy; callers views) |  |  |  |  |
| apex holds | 7.4 KB | 67.3 KB | 666.3 KB | 3.3 MB |
| each host holds | 7.4 KB | 67.3 KB | 666.3 KB | 3.3 MB |
| a host's first sync | 7.8 KB | 67.8 KB | 666.8 KB | 3.3 MB |
| each caller holds | 7.3 KB | 19.9 KB | 19.9 KB | 19.9 KB |
| invite token | 979 B | 979 B | 979 B | 979 B |
| each one-shot caller receives /day | 5.7 KB | 11.6 KB | 114.6 KB | 271.3 KB |
| each subscribed caller (MCP) receives /day | 56.2 KB | 69.2 KB | 75.3 KB | 102.0 KB |
| each host receives /day | 138.5 KB | 139.7 KB | 165.6 KB | 280.0 KB |
| apex sends /day | 1.3 MB | 30.2 MB | 2.4 GB | 27.4 GB |
| whole network /day | 1.3 MB | 30.2 MB | 2.4 GB | 27.4 GB |

With email-list roles (Google has no groups claim; 30 people per role), today's
state is about 1.3× larger (10.7 MB at *large*). In the apex design the extra
bytes stay in the policy the apex and each host hold (5.5 MB at *large*, a
host's one-time first sync); host updates and caller views don't change.

## Findings

1. **The surge is membership, not services.** About 80% of today's state is
   the member list, and two thirds of edits are membership changes. When one
   laptop joins, every node downloads the whole org's node list again. Per-node
   cost grows with the org's size times its edit rate.
2. **Callers are the bulk of the traffic.** A host sends callers about 30×
   what it receives from the admin: every caller re-downloads the whole
   state once per active 10-minute window that saw an edit.
3. **The invite token breaks first.** It embeds the whole state: 233 KB at
   1k users, too big to paste into Slack.
4. **The 4 MiB frame cap is crossed at about 60k nodes** (the *large* tier),
   where sync fails outright.
5. **Badges alone cut per-node traffic about 5–6×,** but it still grows with
   the org (75 MB per caller per day at *large*). Card 35 built this.
6. **The apex makes per-node cost nearly flat:** a one-shot caller receives
   6 KB (team) to 271 KB (*large*) a day, almost all of it a dial and a
   `HelloAck` per new head it notices (at *large* the policy changes about
   100 times a day); a subscribed `wires mcp` 56–102 KB, mostly the beat.
   Each caller holds 20 KB (its view), and its invite is under 1 KB. A host receives 140 KB (team) to 280 KB (*large*) a day.
   Each host holds the whole root-signed policy (67 KB at *company*, 3.3 MB at
   *large*), fetched once; after that its traffic is the 5-minute freshness
   beat (137 KB/day) plus one 1.2–1.7 KB `policy_update` per edit anywhere in
   the fabric (the new head and the changed item, checked against the head's
   one signature). So it grows with the edit rate, not with the number of
   nodes. The whole network costs what one apex sends.
7. **Today is fine at the demo size.** At *team* scale every number is small;
   the design only breaks past about 1k users.

Churn scales the *today* and *badges* rows roughly linearly; it doesn't change
the shape, the invite size or the frame cap.

This replaces card 29's estimate (1.4 TB to onboard 10k people onto 200
hosts) and its claim that host refreshes cost H² dials: a pull stops at the
first host that confirms the copy is current (`a_pull_stops_at_the_first_current_answer`),
so a quiet fabric costs about one dial per host per 10 minutes.

## Where the syndicated state is read today, and what replaces it

Every row is a place a node reads its own full copy of the state. With a
directory, each row reads something smaller, or asks.

| Reader | Uses the full copy for | With a directory |
|---|---|---|
| host gate (`host/gate.rs`) | caller is a member; service assigned here; `authorize` | badge + the ban list; its own copy of the **whole policy**, kept by `policy_update` deltas |
| host record stream | readers roles; membership | the same copy |
| host push (`decide_push`) | recipient is a member; `push.allow` roles | badge + bans; the roles `host.json` names, in the same copy |
| host `StateResponder`, `refresh_loop` | serving and fetching state | **gone**: one `policy` subscription to the directory |
| `wires call`, `mcp`, gateway | service → hosts, failover order | the caller's **view** (root-signed entries it may use), cached |
| caller checks `HelloAck` | the state still assigns the service to that host | the host presents its own root-signed entry in `HelloAck`; no directory needed |
| `wires services`, `tools/list` | `allowed_services` over the whole state | the view (built, card 37); `wires services <query>` and MCP `search_services` search it |
| `wires inbox` | hosts to fetch from; who may deliver (`is_host`) | hosts in the view; only a host of a service in the view may deliver (built) |
| `wires watch` | hosts of the services it reads | the view (read grants included) |
| caller cold pull | freshness | **gone** (built): `HelloAck` carries the host's head version, and its head and entry when newer; the view is refreshed only then |
| admin push to every host | distribution | one publish to the directory; hosts learn it by subscription |
| `invite` / `join` | the whole state in the token | badge (its `fabric` is the root key), up to two directory ids and the login settings (979 B, built) |

Nothing in the table needs the directory to *decide* a call: hosts decide from
their own copy of the policy, callers dial from their cached view. The directory is on the
path for joining, for learning about changes, and for search.

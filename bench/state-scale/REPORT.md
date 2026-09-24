# State scale: how much metadata each node moves

*Modeled 2026-09-24 at 655a96c. `python3 bench/state-scale/model.py`
(`--email-roles`, `--measure`). Byte sizes are measured from real signed
states by `cargo run -q --release -p library --example state_sizes`; rates
are assumptions, listed in `model.py`'s `ASSUMPTIONS`.*

**The question.** Today every node holds the whole admin-signed state and
re-fetches it after every edit (protocol.md §3–4). How much does each node
receive, per day, as the org grows, and what would a persistent directory
(apex) save?

**Measured sizes** (serialized signed JSON): a member 67 B, a host 134 B, a
service entry 318 B (80-character description, 2 hosts, 2 allow roles,
1 reader role), a role with one group matcher 73 B, each further email matcher
75 B, a membership 361 B.

**Main assumptions:** 2 nodes per user; 0.1% of nodes join or leave per day;
1% of services edited per day; a caller is active 8 h/day; 3 KB per iroh
handshake (not measured); a caller may use 30 services; in the apex design, a
150 B signature per entry, a 300 B freshness timestamp every 5 min, views
revalidated hourly.

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
| every node holds | 4.8 KB | 42.9 KB | 423.9 KB | 1.9 MB |
| edits/day | 1 | 2 | 20 | 100 |
| invite token | 6.8 KB | 57.7 KB | 565.6 KB | 2.6 MB |
| each caller receives /day | 153.5 KB | 233.9 KB | 7.2 MB | 80.7 MB |
| each host receives /day | 451.1 KB | 533.1 KB | 9.0 MB | 192.8 MB |
| each host sends callers /day | 3.1 MB | 9.4 MB | 286.0 MB | 8.1 GB |
| admin sends /day | 38.8 KB | 4.6 MB | 4.3 GB | 192.7 GB |
| whole network /day | 17.6 MB | 499.1 MB | 151.9 GB | 8.5 TB |
| **Apex** (directory; slices; views) |  |  |  |  |
| apex holds | 5.6 KB | 51.2 KB | 506.9 KB | 2.5 MB |
| each host holds | 2.8 KB | 5.7 KB | 27.0 KB | 124.1 KB |
| each caller holds | 5.3 KB | 14.6 KB | 14.6 KB | 14.6 KB |
| invite token | 785 B | 785 B | 785 B | 785 B |
| each caller receives /day | 25.3 KB | 29.2 KB | 29.2 KB | 29.2 KB |
| each host receives /day | 86.4 KB | 86.6 KB | 88.1 KB | 94.9 KB |
| apex sends /day | 3.0 MB | 62.7 MB | 627.8 MB | 3.0 GB |
| whole network /day | 3.0 MB | 62.7 MB | 627.8 MB | 3.0 GB |

With email-list roles (Google has no groups claim; 30 people per role), today's
state is about 1.3× larger (10.7 MB at *large*). In the apex design the extra
bytes stay on the apex (4.7 MB) and in host slices (189 KB at *large*); caller
views don't change.

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
5. **Badges alone cut per-node traffic about 5×,** but it still grows with
   the org (81 MB per caller per day at *large*).
6. **The apex makes per-node cost flat:** about 29 KB per caller and 90 KB per
   host per day at every size, and most of that is handshakes and
   heartbeats, not data. The whole network costs what one apex sends.
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
| host gate (`host/gate.rs`) | caller is a member; service assigned here; `authorize` | badge + the ban list; its **slice** (own entries, the roles they name) |
| host record stream | readers roles; membership | slice |
| host push (`decide_push`) | recipient is a member; `push.allow` roles | badge + bans; the roles `host.json` names, in the slice |
| host `StateResponder`, `refresh_loop` | serving and fetching state | **gone**: one long poll to the directory |
| `wires call`, `mcp`, gateway | service → hosts, failover order | the caller's **view** (root-signed entries it may use), cached |
| caller checks `HelloAck` | the state still assigns the service to that host | the host presents its own root-signed entry in `HelloAck`; no directory needed |
| `wires services`, `tools/list` | `allowed_services` over the whole state | the view; search at the directory for large catalogs |
| `wires inbox` | hosts to fetch from; who may deliver (`is_host`) | hosts in the view; a deliverer presents its signed entry |
| `wires watch` | hosts of the services it reads | the view (read grants included) |
| caller cold pull | freshness | **gone**: `HelloAck` carries the directory's version; revalidate only when it moved |
| admin push to every host | distribution | one publish to the directory; hosts learn it by long poll |
| `invite` / `join` | the whole state in the token | badge + root key + directory keys (≈ 800 B) |

Nothing in the table needs the directory to *decide* a call: hosts decide from
their slice, callers dial from their cached view. The directory is on the
path for joining, for learning about changes, and for search.

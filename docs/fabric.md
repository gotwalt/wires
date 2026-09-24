# The fabric: how it is hosted, persisted and kept in sync

*Target architecture, agreed 2026-09-24; built by cards [35](board/done/35-badges-and-bans.md),
[36](board/doing/36-directory.md) and [37](board/backlog/37-caller-views.md). The protocol as
built today is [protocol.md](protocol.md); §9 below lists what is built and what changes. The numbers come from
[`bench/state-scale/`](../bench/state-scale/REPORT.md). User-facing copy says "network";
"fabric" is the internal word, and the name of the signed field.*

## 1. What a fabric is

**A fabric is one root key and everything it signs.** Nothing else defines it: no server, no
address, no account. Every node checks everything against the root's public key, which the invite
introduces.

The root signs three kinds of thing:

- **Badges.** "Node K is in this fabric until T." One per machine (laptop, agent, host).
- **The policy.** Roles (who, by IdP claims), services (who may call and read each, and which hosts
  run it), bans, trusted IdPs, settings, and the list of directory nodes. Versioned: each admin
  edit is version N+1.
- **Delegations** it chooses to make (later): day-passes (card 29), enrollment (card 18).

Everything else is signed by the node that produced it: a host signs its call records, and a
directory signs freshness timestamps. The IdP signs ID tokens.

## 2. The nodes and their jobs

Every node is an iroh endpoint whose id is its Ed25519 public key. Nodes find each other through
n0 DNS/pkarr discovery and the relays (or a local hints file), and every connection is
authenticated by key. The jobs:

| Node | Job | Runs | Must be up? |
|---|---|---|---|
| **Admin** | Holds the root key; signs badges and policy; publishes each edit to the directories. | One-shot commands (`init`, `invite`, `remove`, `issuer`, `role`, `service`, `directory add\|rm`, `state push`). | Only to change something. |
| **Directory** | Holds the newest policy; signs a freshness timestamp every 5 min; gives each host its slice and each caller its view; streams changes to subscribers. **Never decides a call.** | `wires serve` on a node the policy lists in `directories`, or `wires directory serve` alone (no `host.json`). ALPNs `wires/directory/1`, `wires/directory-sub/1`. | For joining, changes, discovery and freshness. Not for calls. |
| **Host** | Runs services; decides every call from its own slice; signs every call into its own log; serves the record stream and push. | `wires serve host.json`, or an app embedding `wires::Host`. ALPNs `wires/session/1`, `wires/records/1`, `wires/inbox/2`. | For its services' calls. |
| **Caller** | Calls services by name, as a person verified by their IdP. | `wires call` (one-shot), `wires mcp`, `wires gateway` (long-running), `wires inbox`. | Only while calling. |
| **Reader** | A caller the policy names in a service's `readers`; reads its records in full. | `wires watch`. | Only while reading. |

One machine can do several jobs: in a small fabric one always-on host is also the directory
(`wires serve` runs the directory too when the policy lists its node). The loopback demo makes
both of its hosts directories, so a removal reaches both at once.

**Outside wires** a fabric also relies on its IdP (for `wires login` and the keys hosts use to
check ID tokens) and on iroh's discovery and relays (n0's public ones, or your own).

## 3. What must be running

| To… | You need |
|---|---|
| **call a service** | one reachable host of that service. Nothing else: the host decides from its slice on disk, and the caller dials from its cached view. |
| **join, change policy, revoke, list or search services** | one reachable directory. |
| **keep bans current everywhere** | a directory reachable by every host (hosts subscribe; a ban arrives in seconds). |
| **keep the fabric alive** | the admin signs a new head before the current one expires (default 90 days), and new badges before old ones expire (default 30 days; renewal is card 36's open question). |

**Recommended:** two directories on different machines (either can also be a host, or run
`wires directory serve` alone).

### When something is down

| Down | Effect |
|---|---|
| A host | Its services fail over to their other hosts (the caller tries the next host in the service's list when a dial fails). |
| Every directory | Calls keep working. Nobody new can join; edits and bans don't spread; views and searches can't refresh. After 15 min, hosts' freshness lapses: under `lenient` (default) they keep deciding and report staleness; under `strict` they refuse calls until a directory is back. |
| The admin | Nothing, until something needs changing or a head or badge approaches expiry. |
| The IdP | Existing ID tokens keep working until they expire (about an hour for Google); nobody can sign in. |
| iroh relays / n0 discovery | Nodes with a direct path or a hints entry still connect; others can't find each other. |
| Everything, then restart | See §4.3. |

## 4. What persists where

### 4.1 On each node

| Node | What it keeps | If lost |
|---|---|---|
| **Admin** | `root.seed`: **the fabric's whole authority**. The full policy (every item, the newest head). `issued.json`: each badge it minted, with its label and expiry. | `root.seed` lost: the fabric can't be changed and dies when its head and badges expire. See §4.4. Policy lost: pull it back from any directory. |
| **Directory** | `directory.redb`: recent heads, the items they name, the newest `Fresh`. Its own badge and `node.seed`. | Rebuild from a replica (it catches up by itself) or by `wires state push` from the admin. Nothing is unique to it. |
| **Host** | `policy/`: its slice (the head, `Fresh`, its own items with proofs). `call-log.jsonl`: every call, signed and hash-linked, kept 30 days. `push-queue.json`, `host.json`, badge, `node.seed`. | Slice: fetched again from a directory. **Call log: unique to this host**; export it over OTLP, or wait for card 09, which gives checkpoints to a witness. |
| **Caller** | Badge, `node.seed`, `view.json` (its own services), `idp-token.jwt`, `last-good.json`, `record-marks.json`, `inbox/`. | View: fetched again. Badge or seed: a new invite. |

Nothing about the fabric is stored "in the network". n0 DNS and the relays hold only short-lived
address records.

### 4.2 What is deliberately not kept anywhere

- **A member list.** There isn't one: a node is in by its badge. The admin's `issued.json` is a
  private ledger, not policy.
- **Per-user views.** A directory computes a view on request from the policy and the caller's ID
  token, then forgets it.
- **Verified identities, outside a host's memory.** A host remembers the principal a node last
  presented to it, in memory only.

### 4.3 Everything off, then on

1. **Directories** load `directory.redb`, sign a new `Fresh` and accept subscriptions.
2. **Hosts** load their slice and start serving at once, even before a directory answers. They
   subscribe to a directory and receive anything published while they were off.
3. **Callers** use `view.json`. The first call's `HelloAck` tells them whether the policy moved.
4. **If the admin edited while directories were off**, the edit's `wires state push` failed
   (exit 1) and the change is only on the admin. It spreads when the admin re-runs `state push`.

A fabric survives any length of downtime, **except expiry**. If the head (90 days) or the badges
(30 days) expired meanwhile, nodes refuse to use them until the admin signs new ones. The clock is
the one thing a restart can't fix.

### 4.4 The root key

For the alpha, **the root key is a file**: `root.seed`, mode 0600, in the admin's keystore. There's
no key ceremony, no backup root and no rotation, so a fabric can be started with one command and
understood in one sentence. This is a deliberate trade-off that needs more attention before wires
holds anything valuable:

- **If it's lost**, nothing breaks at once: hosts and directories keep working under the policy
  they hold. But nobody can change the policy or issue badges, and the fabric stops when its head
  (90 days) or its badges (30 days) expire. Recovery is a new fabric: `wires init`, then re-invite
  every node (an invite is about 800 B, card 37) and re-add the services.
- **If it leaks**, whoever holds it can admit any node and rewrite the policy. Recovery is the same:
  a new fabric.
- **What guards it today:** it never leaves the admin's machine; `wires serve` and
  `wires directory serve` refuse to run from a keystore that holds it; a host or directory never needs
  it. Copying the file somewhere safe is the whole backup story.
- **Later** (not scheduled): a hardware-backed or passkey root, a root that names its own
  successor (as TUF allows), and narrow delegations so the root signs less often (cards 18, 29).

## 5. How metadata moves

Every kind of metadata, who signs it, who holds it, and how it gets there:

| Metadata | Signed by | Held by | Moves | When |
|---|---|---|---|---|
| Root public key | — | every node | in the invite | once |
| Badge | root | its own node | in the invite; shown in every handshake | join; renewal |
| Directory list | root (in the head) | every node | invite; every head | edits |
| Policy head (version, Merkle root) | root | directories, hosts, callers | admin → directories (`publish`); directory → hosts (subscription); directory → callers (view); host → caller (`HelloAck` version) | each edit |
| Service items | root (via the head) | directories: all. Hosts: those naming them. Callers: those they may use. | slice and view, with proofs | edits to those services |
| Roles | root (via the head) | directories; hosts: the roles their services and `host.json` name | slice | edits to those roles |
| Bans | root (via the head) | directories; every host | slice | each removal; dropped at badge expiry |
| Trusted IdPs (`issuer` items) | root (via the head) | directories, hosts | slice | edits |
| Freshness (`Fresh`) | a directory | hosts, callers | subscription beat every 5 min; with each view | continuous |
| ID token | the IdP | the caller | in each call's `Hello`, and each view request | per call |
| Verified principal | checked by the host or directory | host memory | never sent | — |
| Call records | the host | the host | record stream, to a reader who asks and may see them | on `wires watch` |
| Log checkpoints (card 09) | the host; co-signed by a witness | host, directory | host → directory | periodically |
| Push messages | — (sent over an authenticated connection) | host queue, then the caller | `wires/inbox/2`, direct or fetched | on push |
| Addresses | iroh (pkarr) | n0 DNS, relays; local hints | iroh discovery | continuous, outside wires |

### Who talks to whom

```
                       publish (each edit)
   admin  ─────────────────────────────────────▶  directory ◀──replica──▶ directory
                                                   │     ▲
                     subscription: slice + Fresh   │     │  view / search / resolve
                  ┌────────────────────────────────┘     │  (subscription for mcp, gateway)
                  ▼                                       │
                host  ◀──────── call (Hello, Invoke) ─── caller
                  │    ──── HelloAck: head version ───▶
                  └─── record stream ───▶ reader (wires watch)
```

Nothing is broadcast. Every arrow is a direct, key-authenticated connection, and each carries only
what the receiving node may hold.

### Why not gossip

A gossip topic delivers every message to every member and tells each member its neighbours' keys.
That would hand every agent the metadata the directory exists to keep from it. It also needs every
member online and forwarding, and most callers are one-shot processes. Policy has one author (the
root), so its copies never need merging. Real-time updates come from the directory's
subscriptions, which carry each subscriber only its own slice or view (card 36, "Not gossip").

## 6. The flows

- **Start a fabric.** `wires init` makes the root key and signs version 1. The admin names a
  directory (`wires directory add <node>`), invites that node, and it starts `serve`.
- **Join.** The admin runs `wires invite <node id>`: a badge plus the root key and directory ids,
  about 800 B. The policy doesn't change. The new node runs `wires join`, then `wires login`, then
  fetches its view.
- **Change policy.** An admin edit signs head N+1 and publishes it to every directory. Directories
  push the changed items to the subscribed hosts that hold them, and every host gets the new head
  and `Fresh`. Subscribed callers (`mcp`, gateway) get their changed view. One-shot callers learn at
  their next call.
- **Revoke.** `wires remove <node>` adds a ban (until the node's badge would expire). Every
  subscribed host has it within seconds and refuses the node's next connection.
- **Call.** The caller picks a host from its view and dials it with `Hello` (badge, ID token) and
  `Invoke`. The host checks the badge and bans, verifies the token, and checks the service is
  assigned to it and allowed for the caller. It logs `Started`, runs the service, and logs
  `Finished`. `HelloAck` carries the host's head version, so a caller whose view is behind refreshes
  it afterwards.
- **Discover.** `wires services [query]` reads the view, refreshing it from a directory when it's
  behind or a day old. In MCP, `tools/list` (or `search_services` for large views) serves the same
  view.
- **Watch.** A reader streams records from the hosts of the services its view marks `read`, and
  checks each host's chain (later: checkpoints against the witness, card 09).

## 7. ALPNs

| ALPN | Served by | Carries |
|---|---|---|
| `wires/session/1` | hosts | calls |
| `wires/records/1` | hosts | the record stream |
| `wires/inbox/2` | hosts; callers in `inbox --wait` | push delivery and fetch |
| `wires/directory/1` | directories | `publish`, `head`, `slice`, `view`, `resolve`; and, temporarily (card 36b, until hosts hold slices and callers views), `policy {have}`: the whole signed policy. `slice`, `view`, `resolve` are refused until cards 36c and 37. |
| `wires/directory-sub/1` | directories | subscriptions: `slice` (hosts, 36c), `view` (long-running callers, 37), `replica` (other directories; built in 36b) |
| ~~`wires/state/1`~~ | — | retired by card 36 |

## 8. What it costs

Metadata received per node per day, at 10k users, 1k services and 500 hosts
([`bench/state-scale/`](../bench/state-scale/REPORT.md)):

| | Today | This design |
|---|---|---|
| each caller | 39 MB | 29 KB |
| each host | 54 MB (plus 1.6 GB sent to callers) | 195 KB |
| the admin sends | 27 GB | one publish per directory per edit |
| invite token | 2.3 MB | about 800 B |

A caller's cost is the same at 50 users and 50k. A host's is the 5-minute freshness beat
(137 KB a day) plus a 2.8 KB update per edit (every edit moves the head), so it grows with the
edit rate, not the number of nodes: 140 KB a day at 50 users, 430 KB at 50k. Sizes are measured
from the library (card 36a).

## 9. Before, now, and this design

Card 35 is built, and card 36b (the directory mode) is built on `aaron/directory`; card 36c (host
slices and subscriptions, freshness modes) and card 37 (caller views) are next.

| Before cards 35–36 | Now (after 36b; protocol.md) | This design | Card |
|---|---|---|---|
| The state lists every member; `invite` is an edit | Badges; `remove` is a ban; `invite` edits nothing | same | 35 ✓ |
| One signed blob, pushed whole to every host | A root-signed head over items, published to the directories (`directory.redb`, replicas); the admin dials no host | each host gets only its slice | 36b ✓, 36c |
| Hosts re-check every 10 min and search peers | Hosts fetch at start and check a directory's `head` every beat (5 min), then fetch the **whole** policy with the temporary `policy {have}` request | one slice subscription to a directory; lenient / strict freshness | 36b ✓, 36c |
| The state expires in 30 days | Heads last 90 days; directories sign a `Fresh` every beat (nothing enforces it yet) | freshness decides, per `settings.freshness` | 36b ✓, 36c |
| Issuers configured per host in `host.json` | Signed `issuer` items; `host.json` can only narrow them | same | 36b ✓ |
| Every caller holds the whole state and pulls it before commands | Every caller holds the whole policy and fetches it from a directory when its copy is 10 min old, or gets it in `HelloAck` | each caller holds its view; learns of changes in `HelloAck` or by subscription | 37 |
| The invite carries the whole state | The invite carries the whole signed policy (its head lists the directories) | badge, root key and directory ids | 37 |
| Hash-chained logs, checked against a reader's marks | same | Merkle logs with checkpoints, witnessed by the directory | 09 |

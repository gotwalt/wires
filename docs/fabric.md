# The fabric: how it is hosted, persisted and kept in sync

*The architecture as built (cards [35](board/done/35-badges-and-bans.md),
[36](board/done/36-directory.md), [36d](board/done/36d-no-merkle-policy.md) and
[37](board/done/37-caller-views.md)): who runs what, what each node keeps, and how each kind of
metadata moves. The wire-level spec is [protocol.md](protocol.md); §9 lists what changed from the
earlier design. The numbers come from [`bench/state-scale/`](../bench/state-scale/REPORT.md).
User-facing copy says "network"; "fabric" is the internal word, and the name of the signed
field.*

## 1. What a fabric is

**A fabric is one root key and everything it signs.** Nothing else defines it: no server, no
address, no account. Every node checks everything against the root's public key, which the invite
introduces.

The root signs three kinds of thing:

- **Badges.** "Node K is in this fabric until T." One per machine (laptop, agent, host).
- **The policy.** Roles (who, by IdP claims), services (who may call and read each, and which hosts
  run it), bans, trusted IdPs, settings, and the list of directory nodes. Versioned: each admin
  edit is version N+1. **The root signs the policy, and each service entry, like a badge:** one
  signature on the head covers a hash of every item, and each service entry also carries its own,
  so a caller can hold and check just the services it may use.
- **Delegations** it may make later (not built): day-passes (card 29), enrollment (card 18).

Everything else is signed by the node that produced it: a host signs its call records, and a
directory signs freshness timestamps. The IdP signs ID tokens.

## 2. The nodes and their jobs

Every node is an iroh endpoint whose id is its Ed25519 public key. Nodes find each other through
n0 DNS/pkarr discovery and the relays (or a local hints file), and every connection is
authenticated by key. The jobs:

| Node | Job | Runs | Must be up? |
|---|---|---|---|
| **Admin** | Holds the root key; signs badges and policy; publishes each edit to the directories. | One-shot commands (`init`, `invite`, `remove`, `issuer`, `role`, `service`, `directory add\|rm`, `policy push`). | Only to change something. |
| **Directory** | Holds the newest policy; signs a freshness timestamp every 5 min (the policy's `beat_secs`); gives each host the whole policy and each caller its view; streams changes to subscribers (at most 4,096, `--max-subscribers`). **Never decides a call.** | `wires serve` on a node the policy lists in `directories` (decided when it starts), or `wires directory serve` alone (no `host.json`). Both refuse a keystore that holds `root.seed`. ALPNs `wires/directory/1`, `wires/directory-sub/1`. | For joining, changes, discovery and freshness. Not for calls. |
| **Host** | Runs services; decides every call from its own copy of the whole policy; signs every call into its own log; serves the record stream and push. | `wires serve host.json`, or an app embedding `wires::Host`. ALPNs `wires/session/1`, `wires/records/1`, `wires/inbox/2`. | For its services' calls. |
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
| **call a service** | one reachable host of that service. Nothing else: the host decides from its policy on disk, and the caller dials from its cached view. |
| **join, change policy, revoke, list or search services** | one reachable directory. |
| **keep bans current everywhere** | a directory reachable by every host (hosts subscribe; a ban arrives in seconds). |
| **keep the fabric alive** | the admin signs a new head before the current one expires (default 90 days), and new badges before old ones expire (default 30 days; there is no renewal yet: a node gets a new badge by a new invite). |

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
| **Admin** | `root.seed`: **the fabric's whole authority**. `policy.json`: the whole signed policy, which every edit starts from. `issued.json`: each badge it minted, with its label and expiry. `login-client.json`: the login settings invites carry. Its own badge (`membership.json`) and `node.seed`. | `root.seed` lost: the fabric can't be changed and dies when its head and badges expire. See §4.4. `policy.json` lost: copy it back from any host or directory (it is root-signed, so any copy verifies); there is no command that fetches it. |
| **Directory** | `directory.redb`: the last 16 heads (for deltas), the items they name, the newest `Fresh`; a copy of the newest policy in `policy.json`. Its own badge (`membership.json`) and `node.seed`. | Rebuild from a replica (it catches up by itself) or by `wires policy push` from the admin. Nothing is unique to it. |
| **Host** | `policy.json`: the whole signed policy (the head and every item; the head's one signature covers them all), and `fresh.json`, the newest `Fresh` that vouches for it. `call-log.jsonl`: every call, signed and hash-linked, kept 30 days. `push-queue.json`, `host.json`, its badge (`membership.json`), `node.seed`. | Policy: fetched again from a directory. **Call log: unique to this host**; export it over OTLP, or wait for card 09, which gives checkpoints to a witness. |
| **Caller** | Its badge (`membership.json`), `node.seed`, `view.json` (its own services: root-signed entries, each checked alone), `directories.json` and `login.json` (from its invite), `idp-token.jwt`, `last-good.json`, `record-marks.json`, `inbox/`. No `policy.json`. | View: fetched again. Badge or seed: a new invite. |

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
2. **Hosts** load their policy and start serving at once, even before a directory answers. They
   subscribe to a directory and receive anything published while they were off (one
   `policy_update`, or the whole policy if the directory no longer keeps their version).
3. **Callers** use `view.json`. The first call's `HelloAck` tells them whether the policy moved.
4. **If the admin edited while directories were off**, the edit's publish failed (exit 1) and the
   change is only on the admin. It spreads when the admin runs `wires policy push`.

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
  every node (a caller's invite is under 1 KB, card 37) and re-add the services.
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
| Policy head (version, hash of every item) | root | directories, hosts, callers | admin → directories (`publish`); directory → hosts (subscription); directory → callers (view); host → caller (`HelloAck` version) | each edit |
| Service entries | root, each on its own (and covered by the head's hash) | directories and hosts: all. Callers: those they may use. | hosts: the whole policy, then a `policy_update` with each changed entry; callers: their view | edits to those services |
| Roles | root (via the head) | directories, hosts | the whole policy, then `policy_update` | edits to roles |
| Bans | root (via the head) | directories, hosts | the whole policy, then `policy_update` | each removal; dropped at badge expiry |
| Trusted IdPs (`issuer` items) | root (via the head) | directories, hosts | the whole policy, then `policy_update` | edits |
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
        subscription: policy_update + Fresh   │     │  view / search / resolve
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
subscriptions, which carry each subscriber only what it may hold: a host the policy, a caller its
view (card 36, "Not gossip").

## 6. The flows

- **Start a fabric.** `wires init` makes the root key and signs version 1, trusting one IdP. The
  admin names a directory (`wires directory add <node id>`), then invites that node: since the
  policy already lists it, its token also carries the whole policy. The node joins and runs
  `wires directory serve` (or `wires serve host.json`, if it is also a host).
- **Join.** The admin runs `wires invite <node id>`: a badge (which names the root key), up to two
  directory ids and the login settings, under 1 KB (979 B with Google-sized settings). The policy
  doesn't change. The new node runs `wires join`, then a bare `wires login` (the invite named the
  IdP), which fetches its view.
- **Change policy.** An admin edit signs head N+1, re-signing only the service entries it changed,
  and publishes it to every directory. Directories send every subscribed host a `policy_update`:
  the new head, its `Fresh` and the changed items. The host applies it to its copy and checks the
  result against the head's one signature; any mismatch, and it fetches the whole policy.
  Subscribed callers (`mcp`, gateway) get their changed view entries. One-shot callers learn at
  their next call.
- **Revoke.** `wires remove <node>` adds a ban (until the node's badge would expire) and drops the
  node from every service's hosts and from the directories. Every subscribed host has it within
  seconds and refuses the node's next connection; so does every directory.
- **Call.** The caller picks a host from its view and dials it with `Hello` (badge, ID token) and
  `Invoke`. The host checks the badge and bans, verifies the token, and checks the service is
  assigned to it and allowed for the caller. It logs `Started`, runs the service, and logs
  `Finished`. `HelloAck` carries the host's head version; when it is newer than the caller's view,
  it also carries the service's signed entry, which the caller checks before sending stdin, and the
  caller refreshes its view afterwards. A name missing from the view is `resolve`d at a directory
  first.
- **Discover.** `wires services [query]` reads the view, refreshing it from a directory when it's
  behind, expired or a day old. In MCP, `tools/list` serves the same view; past 40 services it
  offers `search_services` and `call_service` instead.
- **Watch.** A reader streams records from the hosts of the services its view marks `read` (and,
  for its own person's records, `call`), and checks each host's chain against its marks
  (`record-marks.json`). Checkpoints against a witness are card 09.

## 7. ALPNs

| ALPN | Served by | Carries |
|---|---|---|
| `wires/session/1` | hosts | calls |
| `wires/records/1` | hosts | the record stream |
| `wires/inbox/2` | hosts; callers in `inbox --wait` | push delivery and fetch |
| `wires/directory/1` | directories | `publish` (from the admin), `head`, `policy {have}` (the whole policy, only for a node the policy names as a host or directory; answered with `policy`, `policy_update` or `current`), `view` and `resolve` (a caller's signed entries, cut for its verified ID token) |
| `wires/directory-sub/1` | directories | subscriptions: `policy` (hosts: the whole policy or a delta first, then a `policy_update` per new head and `fresh` beats), `view` (long-running callers: the whole view, then `view_update`s), `replica` (other directories the policy lists) |

## 8. What it costs

Metadata received per node per day, at 10k users, 1k services and 500 hosts
([`bench/state-scale/`](../bench/state-scale/REPORT.md)):

| | Before (every node held the whole signed state) | Now |
|---|---|---|
| each caller | 39 MB | 115 KB one-shot (a dial and a `HelloAck` per new head it notices), 75 KB with `wires mcp` subscribed |
| each host | 54 MB (plus 1.6 GB sent to callers) | 166 KB, after a first sync of the whole policy (667 KB) |
| the admin sends | 27 GB | one publish per directory per edit |
| invite token | 2.3 MB | 979 B (badge, two directory ids, Google-sized login settings) |

A caller holds its view (20 KB for 25 services) at any size, and receives 6 KB (team) to 271 KB
(*large*) a day, almost all of it handshakes that report a new head: it grows with the edit rate,
not the number of nodes. A host holds the whole policy (67 KB at 100
services, 3.3 MB at 5k), fetched once; after that it receives the 5-minute freshness beat (137 KB a
day) plus one 1.2–1.7 KB `policy_update` per edit (the new head, its `Fresh` and the changed item),
so it grows with the edit rate, not the number of nodes: 140 KB a day at 50 users, 280 KB at 50k.
Sizes are measured from the library (card 36d).

## 9. What changed from the earlier design

Until card 34, one root-signed *state* listed every member, role and service; the admin pushed it
whole to every host after each edit, hosts re-checked it every 10 minutes and searched their peers
for newer copies (`wires/state/1`), and every caller held and re-downloaded all of it. Cards 35–37
replaced that:

| Before | Now | Card |
|---|---|---|
| The state lists every member; `invite` is an edit | A node is in by its badge; `remove` is a ban; `invite` edits nothing | 35 |
| One signed blob, pushed whole to every host | A root-signed head over a hash of the items, and root-signed service entries, published to the directories (`directory.redb`, replicas); the admin dials no host | 36, 36d |
| Hosts re-check every 10 min and search peers | One `policy` subscription to the first directory that answers (the others are failover), carrying `policy_update` deltas and a `Fresh` every beat; an edit arrives in well under a second | 36 |
| The state expires in 30 days | Heads last 90 days; a host keeps the newest `Fresh` for its head (`fresh.json`); when it lapses, `settings.freshness` decides (`lenient` keeps deciding and traces it, `strict` refuses calls) | 36 |
| Issuers configured per host in `host.json` | Signed `issuer` items; `host.json` can only narrow them | 36 |
| Every caller holds the whole state and pulls it before commands | Each caller holds its view (`view.json`) and learns of a new head in `HelloAck`; `wires mcp`, gateway sessions and `inbox --wait` subscribe; `wires services <query>` and MCP `search_services` search it | 37 |
| The invite carries the whole state | A caller's invite is its badge, up to two directory ids and the login settings, under 1 KB; a host's or directory's also carries the policy | 37 |

Not built yet: `lenient` staleness shows in the host's trace, not in `wires watch`; a host keeps
one subscription at a time, so failover costs a dial per dead directory; a node newly listed in
`directories` runs the directory mode only after `wires serve` restarts; badges can't be renewed
(re-invite); call logs are hash chains, not Merkle logs with witnessed checkpoints (card 09).

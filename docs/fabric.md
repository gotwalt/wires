# The network: who runs what, what each node keeps, how the policy moves

*The architecture as built. The wire-level spec is [protocol.md](protocol.md); commands are in
[usage.md](usage.md). This file keeps its old name; "fabric" survives only as the name of the
signed field that names a network's root key.*

## 1. What a network is

**A network is one root key and the policy it signs.** Nothing else defines it: no server, no
address, no account, and no list of members. Every node checks everything against the root's
public key, which the **network string** introduces (`wires network` prints it; it is the same for
every node and not secret).

The root signs one thing: **the policy**. It says which IdPs are trusted, which roles exist (who, by
IdP claims), which services exist (who may call each, and which hosts run it), who is removed
(people and nodes), the settings, and which nodes are directories. It is versioned: each admin edit
is version N+1. One signature on the **head** covers a hash of every item, and each service entry
also carries a root signature of its own, so a caller can hold and check just the services it may
use.

Two other parties sign:

- **The IdP** signs ID tokens. A person's ID token, bound to their node's key, is the only
  credential a caller presents. No node holds a credential the admin minted for it.
- **A directory** signs freshness timestamps (`Fresh`) for the head it holds.

## 2. The nodes and their jobs

Every node is an iroh endpoint whose id is its Ed25519 public key. Nodes find each other through
n0 DNS/pkarr discovery and the relays (or a local hints file), and every connection is
authenticated by key.

| Node | Job | Runs | ALPNs it serves | Must be up? |
|---|---|---|---|---|
| **Admin** | Holds the root key; signs the policy; publishes each edit to the directories. | One-shot commands: `init`, `network`, `issuer`, `role`, `service`, `directory add\|rm`, `remove`, `restore`, `policy push`, `policy settings`. | none | Only to change something. |
| **Directory** | Holds the newest policy; signs a `Fresh` every `beat_secs` (default 300 s); gives each host the whole policy and each caller its view; streams changes to subscribers in two pools of 4,096 each by default (`--max-subscribers`): hosts and other directories in one, long-running callers' views in the other, at most 16 per person, each ending when its ID token expires. **Never decides a call.** | `wires serve` on a node the policy (or, holding none yet, the network string) lists as a directory, or `wires directory serve` alone (no `host.json`). Both refuse a keystore that holds `root.seed`. | `wires/directory/2`, `wires/directory-sub/2` | For sign-in views, edits, removals and freshness. Not for calls. |
| **Host** | Runs services; decides every call from its own copy of the whole policy; writes one log line per call to its own output; queues and sends pushes. | `wires serve host.json`, or an app embedding `wires::Host`. | `wires/session/1`, `wires/inbox/3` | For its services' calls. |
| **Caller** | Calls services by name, as a person their IdP verified. | `wires call` (one-shot), `wires services`, `wires inbox`; `wires mcp` and `wires gateway` (long-running; the gateway calls for each web user). | `wires/inbox/3` while `wires inbox --wait` runs | Only while calling. |

One machine can do several jobs: in a small network one always-on host is also the directory
(`wires serve` runs the directory too when the policy lists its node). The loopback demo makes both
of its hosts directories, so a removal reaches both at once.

**Outside wires** a network also relies on its IdP (for `wires login`, and for the keys hosts and
directories check ID tokens with) and on iroh's discovery and relays (n0's public ones, or your
own).

## 3. What must be running

| To… | You need |
|---|---|
| **call a service** | one reachable host of that service, and an unexpired ID token. Nothing else: the host decides from its policy on disk, and the caller dials from its view. |
| **sign in, list or search services** | the IdP (to sign in) and one reachable directory (to cut the view). |
| **change the policy, or remove someone** | the admin's machine, and one reachable directory to publish to. |
| **keep removals current everywhere** | a directory reachable by every host (hosts subscribe; an edit arrives within a second). |
| **keep the network alive** | the admin signs a new head before the current one expires (default 90 days; nothing renews it automatically). |

**Recommended:** two directories on different machines (either can also be a host, or run
`wires directory serve` alone).

### When something is down

| Down | Effect |
|---|---|
| A host | Its services fail over to their other hosts: the caller tries the next host in the service's list when a dial fails. A service with one host is down with it. |
| Every directory | Calls keep working. Edits and removals don't spread; views and searches can't refresh (`wires call` and `wires inbox` fall back to the view they hold); a caller with no view yet can't call. A host that holds no policy can't start. After `fresh_secs` (default 15 min) hosts' freshness lapses: under `lenient` (the default) they keep deciding and trace the lapse; under `strict` they refuse calls until a directory is back. |
| The admin | Nothing, until something needs changing or the head approaches expiry. |
| The IdP | ID tokens already issued keep working until they expire (about an hour for Google); nobody can sign in; a host that has not fetched the issuer's keys since it started can't verify anyone. |
| iroh relays / n0 discovery | Nodes with a direct path or a hints entry still connect; others can't find each other. |
| Everything, then restart | See §4.3. |

## 4. What persists where

### 4.1 On each node

Every keystore file, its mode and holder: [protocol.md §8](protocol.md#8-keystore-wires_home-else-xdg_config_homewires-else-configwires).

| Node | What it keeps | If lost |
|---|---|---|
| **Admin** | `root.seed`: **the network's whole authority**. `policy.json`: the whole signed policy, which every edit starts from. `labels.json` (its names for nodes), `login-client.json` (which IdP the network string names, and its public client secret), `reached.json` (the directories that have taken a publish), `node.seed`. | `root.seed` lost: see §4.4. `policy.json` lost: copy it back from any host or directory (it is root-signed, so any copy verifies); no command fetches it. |
| **Directory** | `directory.redb`: the last 16 heads (for updates) and the items they name; a copy of the newest policy in `policy.json`; `network.json`, `node.seed`. | Rebuilt from a replica (it catches up by itself) or by the admin's `wires policy push`. Nothing is unique to it but its key, which the policy names. |
| **Host** | `policy.json`: the whole signed policy; `fresh.json`, the newest `Fresh` that vouches for it; `push-queue.json`; `network.json`, `node.seed`; `run/` (the operator's push socket and its hint line). Plus `host.json`, wherever the operator keeps it. | Policy: fetched again from a directory. Queue: pushes not yet delivered are lost. |
| **Caller** | `node.seed`, `network.json`, `view.json` (its own services: root-signed entries, each checked alone), `idp-token.jwt` (and `idp-refresh-token`), `last-good.json`, `inbox/`, `jwks/`. No `policy.json`. | View: fetched again. Token: `wires login`. Seed: a new node; sign in again with `wires login <network>`. |
| **Web gateway** | As a caller, plus `gateway-client-key` and `gateway-sessions.json`. Its users' views are in memory only. | Sessions: users sign in again. |

Nothing about the network is stored "in the network". n0 DNS and the relays hold only short-lived
address records.

### 4.2 What is deliberately not kept anywhere

- **A member list.** There isn't one: a person is in by their IdP sign-in and a role that admits
  them, and a machine by the policy naming its key.
- **Per-user views.** A directory computes a view on request from the policy and the caller's
  verified ID token, then forgets it.
- **Verified identities, outside a host's memory.** A host remembers the principal a node was last
  admitted with, in memory only.
- **A record of calls.** A host writes one ordinary log line per call to `wires serve`'s own
  output, and nothing else: no file, nothing signed, nothing a caller can read back.

### 4.3 Everything off, then on

1. **Directories** load `directory.redb`, sign a new `Fresh` and accept subscriptions.
2. **Hosts** load their policy and start serving at once, even before a directory answers. They
   subscribe to a directory and receive anything published while they were off (one
   `policy_update`, or the whole policy if the directory no longer keeps their version).
3. **Callers** use `view.json`. The first call's `HelloAck` tells them whether the policy moved; a
   view older than a day is refreshed before dialing (by `wires call` and `wires inbox`) when a
   directory answers, and kept when none does, until the policy it came from expires.
4. **If the admin edited while directories were off**, the edit's publish failed (exit 1, after
   trying each directory for 15 s) and the change is only on the admin. It spreads when the admin
   runs `wires policy push`.

A network survives any length of downtime, **except expiry**. If the head (90 days by default)
expired meanwhile, nodes refuse to use it until the admin signs a new one with any edit, and
callers sign in again once their ID tokens have expired. The clock is the one thing a restart
can't fix.

### 4.4 The root key

For now, **the root key is a file**: `root.seed`, mode 0600, in the admin's keystore. There's no
key ceremony, no backup root and no rotation, so a network can be started with one command and
understood in one sentence. This is a deliberate trade-off that needs more attention before wires
holds anything valuable:

- **If it's lost**, nothing breaks at once: hosts and directories keep deciding under the policy
  they hold. But nobody can change the policy, and the network stops when its head expires
  (90 days by default). Recovery is a new network: `wires init`, the roles and services again, a
  new network string, and every node joining it from a keystore that holds no other network's
  string (one network per keystore).
- **If it leaks**, whoever holds it can rewrite the policy: trust another IdP, grant any role, name
  any host. Recovery is the same: a new network.
- **What guards it today:** it never leaves the admin's machine; `wires serve` and
  `wires directory serve` refuse to run from a keystore that holds it, and `wires join` refuses to
  join one; a host or directory never needs it. Copying the file somewhere safe is the whole backup
  story.
- **Later** (not scheduled): a hardware-backed or passkey root, a root that names its own
  successor (as TUF allows), and narrow delegations so the root signs less often (cards 18, 29).

## 5. How the policy and everything else moves

| What | Signed by | Held by | Moves | When |
|---|---|---|---|---|
| Root public key, first directories, sign-in settings | — (the network string is unsigned; trust on first use) | every node but the admin (`network.json`) | out of band: a wiki, a message | once, at `wires join` or `wires login <network>` |
| Directory list | root (in the head) | every node | every head; the network string carries the first two | edits |
| Policy head (version, hash of every item) | root | directories, hosts; callers (in their view) | admin → directories (`publish`); directory → hosts (subscription); directory → callers (view); host → caller (`HelloAck`) | each edit |
| Service entries | root, each on its own (and covered by the head's hash) | directories and hosts: all. Callers: those they may call. | hosts: the whole policy, then a `policy_update` with each changed entry; callers: their view | edits to those services |
| Roles, issuers, bans, settings | root (via the head) | directories, hosts | the whole policy, then `policy_update` | edits |
| Freshness (`Fresh`) | a directory | hosts, callers | subscription beat every `beat_secs`; with each view | continuous |
| ID token | the IdP | the caller (and, for one call, the host and the service it runs) | in each call's `Hello`, each view request, each inbox fetch; to the service as `WIRES_ID_TOKEN` | per call |
| Verified principal | checked by the host or directory | host memory | to the service as `WIRES_CALLER`; never on the wire | per call |
| Push messages | — (sent over an authenticated connection) | host queue, then the caller | `wires/inbox/3`, direct or fetched | on push |
| Addresses | iroh (pkarr) | n0 DNS, relays; local hints | iroh discovery | continuous, outside wires |

### Who talks to whom

```
                       publish (each edit)
   admin  ─────────────────────────────────────▶  directory ◀──replica──▶ directory
                                                   │     ▲
        subscription: policy_update + Fresh        │     │  view / search / resolve
                  ┌────────────────────────────────┘     │  (subscription for mcp, gateway, inbox --wait)
                  ▼                                       │
                host  ◀──────── call (Hello, Invoke) ─── caller
                  │    ──── HelloAck: head version ───▶
                  └────────── push (or fetch) ────────▶
```

Nothing is broadcast. Every arrow is a direct, key-authenticated connection, and each carries only
what the receiving node may hold.

### Why not gossip

A gossip topic delivers every message to every member and tells each member its neighbours' keys.
That would hand every agent the metadata the directory exists to keep from it. It also needs every
member online and forwarding, and most callers are one-shot processes. The policy has one author
(the root), so its copies never need merging. Updates come from the directory's subscriptions,
which carry each subscriber only what it may hold: a host the policy, a caller its view.

## 6. The flows

- **Start a network.** `wires init` makes the root key and signs version 1, trusting one IdP. The
  admin defines roles, names a directory (`wires directory add workbench=<node id>`), registers
  services, and prints the network string (`wires network`). The directory's node runs `wires
  join <network>` and `wires serve host.json` (or `wires directory serve`); it starts empty and
  says it is waiting for the admin's first publish. The admin runs `wires policy push`: the one
  bootstrap step. Until a directory has taken a publish, an edit that reaches none is a note, not
  a failure.
- **Join.** A caller runs `wires login <network>`: it stores the string, signs in with the IdP the
  string names (the ID token's `nonce` is a hash of the node's key), and asks a directory for its
  view. A host or directory runs `wires join <network>`, which contacts nobody; the admin names it
  in the policy by its key. The policy doesn't change when a caller joins.
- **Change policy.** An admin edit signs head N+1, re-signing only the service entries it changed,
  and publishes it to every directory. One it can't dial is tried again for up to 15 s (a
  directory that has just restarted can't be found by its key for about 3 s); one that still
  missed it takes the edit from another directory by its replica subscription (about 40 ms after
  the other took it, in the loopback test `wires/e2e/restart.rs`), and until then the hosts
  following it decide under the policy before it. Directories send every subscribed host a
  `policy_update`: the new head, its `Fresh` and the changed items. The host applies it to its
  copy and checks the result against the head's one signature; any mismatch, and it fetches the
  whole policy.
  Subscribed callers (`wires mcp`, gateway sessions, `wires inbox --wait`) get their changed view
  entries, and a subscriber no longer admitted gets an emptied view and the subscription ends.
  One-shot callers learn at their next call, or when their view is a day old.
- **Remove.** `wires remove alice@example.com` adds a person ban: every host refuses that person
  from any machine, and every directory refuses them a view. `wires remove <node>` takes a host or
  directory machine out: it adds a node ban and drops the node from every service's hosts and
  from the directories. Neither expires;
  `wires restore` lifts one. Every subscribed host has the new policy within a second and refuses
  the next call.
- **Call.** The caller picks a host from its view (the one that last answered first) and dials it
  with `Hello` (its view's head version and its ID token) and `Invoke` (service and argv). The
  host verifies the token and admits the caller (a verified email, no ban, some role matches),
  checks that a role in the service's `allow` admits it and only then that the service is
  assigned to this host, applies `host.json`'s `also_require`, and runs the service. `HelloAck`
  carries the host's head version; when it is newer than the caller's view, it also carries the
  service's signed entry, which the caller checks before sending stdin, and the caller refreshes
  its view afterwards. A refusal marks the view as behind, so the caller's next command refreshes
  it first. A name missing from the view
  is `resolve`d at a directory first.
- **Discover.** `wires services [query]` reads the view, refreshing it from a directory when it is
  behind, expired or a day old. In MCP, `tools/list` serves the same view; past 40 services it
  offers `search_services` and `call_service` instead.
- **Push.** A service pushes to its caller through its call's push capability, or the host's
  operator with `wires push`. The host dials the caller's key (a running `wires inbox --wait`
  accepts it) or queues the message for the caller's next `wires inbox` fetch.

## 7. ALPNs

| ALPN | Served by | Carries |
|---|---|---|
| `wires/session/1` | hosts | calls |
| `wires/inbox/3` | hosts; callers in `inbox --wait` | push delivery and fetch |
| `wires/directory/2` | directories | `publish` (from anyone; taken only if root-signed and newer), `policy {have}` (the whole policy, only for a node the policy names as a host or directory; answered with `policy`, `policy_update` or `current`), `view` and `resolve` (a caller's signed entries, cut for its verified ID token) |
| `wires/directory-sub/2` | directories | subscriptions: `policy` (hosts: the whole policy or an update first, then a `policy_update` per new head and `fresh` beats), `view` (long-running callers: the whole view, then `view_update`s), `replica` (other directories the policy lists) |

## 8. What it costs

What each node receives grows with the rate of edits, not with the number of nodes:

- **A host** fetches the whole policy once, then receives a `fresh` beat every `beat_secs` and one
  small `policy_update` per edit (the new head, its `Fresh` and the changed item).
- **A one-shot caller** sends nothing in the background. It holds its view (the services it may
  call), learns of a new head in a call's `HelloAck`, and then asks a directory for what changed.
  `wires mcp` holds a subscription: the whole view once, then a beat and an update per new head.
- **The admin** sends one publish per directory per edit (again, for up to 15 s, to one it can't
  dial that has taken a publish before).

`cargo run -q --release -p library --example policy_sizes` builds real signed policies and
measures them. At 1,000 services (and 300 bans) it printed: the whole policy 647 KB (65 KB at
100 services, 3.2 MB at 5,000), a `policy_update` for one changed service 1.7 KB and for one new
ban 1.2 KB, a freshness beat 475 B, a `HelloAck` carrying a new head and one entry 1.2 KB, a
caller's `view.json` for 25 services 16 KB, and a network string 578 B. The per-day model in
[`bench/state-scale/`](../bench/state-scale/REPORT.md) was made for an earlier design and has not
been redone.

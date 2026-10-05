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
| **Directory** | Holds the newest policy (in the node's own `policy.json`); signs a `Fresh` every `beat_secs` (default 300 s); sends each host that follows it the whole policy on every edit and a `Fresh` every beat (at most 4,096 followers by default, `--max-subscribers`); proves itself current to a caller before the caller sends its ID token, then gives it its view. **Never decides a call.** | `wires serve` on a node the policy (or, holding none yet, the network string) lists as a directory, or `wires directory serve` alone (no `host.json`). Both refuse a keystore that holds `root.seed`. | `wires/directory/3`, `wires/directory-sub/3` | For views, edits and removals, and for calls: a caller tells a host nothing without a directory's current `Fresh`, so with every directory down calls stop within `fresh_secs`. |
| **Host** | Runs services; shows each caller its proof (its head and the directories' current `Fresh`es) before the caller sends anything; decides every call from its own copy of the whole policy; writes one log line per call to its own output; queues and sends pushes. | `wires serve host.json`, or an app embedding `wires::Host`. | `wires/session/2`, `wires/inbox/4` | For its services' calls. |
| **Caller** | Calls services by name, as a person their IdP verified. | `wires call` (one-shot), `wires services`, `wires inbox`; `wires mcp` and `wires gateway` (long-running; the gateway calls for each web user). | `wires/inbox/4` while `wires inbox --wait` runs | Only while calling. |

One machine can do several jobs: in a small network one always-on host is also the directory
(`wires serve` runs the directory too when the policy lists its node). There, callers take that
machine's own `Fresh`, since there is no other directory to ask, so removing that machine holds
only at the policy's expiry ([protocol.md §9](protocol.md#9-known-limits)). To add a second
directory, start it and run `wires policy push` right after `wires directory add`: until it
vouches, the first machine can vouch only for itself under a policy that lists two, and calls
fail closed within `fresh_secs`. The loopback demo makes
both of its hosts directories, so a removal reaches both at once, and each vouches for the other.

**Outside wires** a network also relies on its IdP (for `wires login`, and for the keys hosts and
directories check ID tokens with) and on iroh's discovery and relays (n0's public ones, or your
own).

## 3. What must be running

| To… | You need |
|---|---|
| **call a service** | one reachable host of that service, an unexpired ID token, and a directory other than that host that has vouched for the host's policy within `fresh_secs` (15 minutes by default; in a one-machine network, the host's own word). The host decides from its policy on disk, and the caller dials from its view; the directory's `Fresh` reaches the caller in the host's proof or with its view, so a call is usually the only connection. |
| **sign in, list or search services** | the IdP (to sign in) and one reachable directory (to cut the view) that can show another directory's current `Fresh` for its head (or, as the network's one directory, its own). |
| **change the policy, or remove someone** | the admin's machine, and one reachable directory to publish to. |
| **keep removals current everywhere** | every directory up when the admin publishes (one that misses an edit holds the old policy until `wires policy push`; the edit exits 1), and a directory reachable by every host (hosts follow one and get each edit as soon as it takes it). |
| **keep the network alive** | the admin signs a new head before the current one expires (default 90 days; nothing renews it automatically). |

**Recommended:** at least two directories on different machines, so that removal holds within
`fresh_secs`. If a host outage mustn't stop calls, don't let your only two directories be your
hosts: with one down, the other can show only its own word, and calls to it stop within
`fresh_secs`. Run a third directory, or one on a node that hosts nothing (`wires directory
serve`).

### When something is down

| Down | Effect |
|---|---|
| A host | Its services keep answering from their other hosts: each call orders a service's hosts at random and tries the next when a dial fails, and a host that failed to answer a caller in the last minute goes last for that caller. A service with one host is down with it. What the host kept between calls (a service's state, its push queue) waits there until it is back. |
| Every directory | Calls stop within `fresh_secs` (default 15 min): callers keep calling on the `Fresh` they and the hosts hold until it lapses, then fail closed (exit 1, `no directory has vouched for a host of … recently, so nothing was sent`) until a directory is back. Edits and removals don't spread; views and searches can't refresh; a caller with no view yet can't call. A host that holds no policy can't start. |
| One directory of several | Hosts following it move to another. A directory that hosts nothing, left alone, can show only its own `Fresh`, so callers can't refresh their views from it (they keep the ones they hold). A directory that is also a host shows the other's word too, until it lapses. Where the only two directories are the hosts, calls to the one left stop within `fresh_secs`. |
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
| **Directory** | `policy.json`: the newest policy and its whole store (no history; on a node that is also a host, the one copy both use); `network.json`, `node.seed`. Its `Fresh` is in memory only. | Restored by the admin's `wires policy push` (or, on a node that is also a host, from the directory that host follows). Nothing is unique to it but its key, which the policy names. |
| **Host** | `policy.json`: the whole signed policy; `fresh.json`, the newest `Fresh` per directory that vouches for it (what it shows callers first); `push-queue.json`; `network.json`, `node.seed`; `run/` (the operator's push socket and its hint line). Plus `host.json`, wherever the operator keeps it. | Policy: fetched again from a directory. Queue: pushes not yet delivered are lost. |
| **Caller** | `node.seed`, `network.json`, `view.json` (its own services: root-signed entries, each checked alone, and the newest `Fresh` per directory it has seen), `idp-token.jwt` (and `idp-refresh-token`), `unanswered.json` (hosts that recently failed to answer it), `inbox/`, `jwks/`. No `policy.json`. | View: fetched again. Token: `wires login`. Seed: a new node; sign in again with `wires login <network>`. |
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

1. **Directories** read `policy.json`, sign a new `Fresh` and accept followers.
2. **Hosts** load their policy and serve at once, even before a directory answers; callers talk to
   a host once a directory's `Fresh` for its head is current (from `fresh.json`, or the first
   frame from the directory it follows). Each host follows a directory and receives the whole
   policy if one was published while it was off.
3. **Callers** use `view.json`. A host's proof, or the first call's `HelloAck`, tells them whether
   the policy moved; a view older than a day is refreshed before dialing (by `wires call` and
   `wires inbox`) when a directory proves itself and answers, and kept when none does. Either way a
   caller sends a host nothing until a current `Fresh` vouches for that host's head.
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
| Policy head (version, hash of every item) | root | directories, hosts; callers (in their view) | admin → directories (`publish`); directory → hosts (subscription); directory → callers (its proof, the view); host → caller (its proof, `HelloAck`) | each edit |
| Service entries | root, each on its own (and covered by the head's hash) | directories and hosts: all. Callers: those they may call. | hosts: the whole policy, on every edit; callers: their whole view | edits to those services |
| Roles, issuers, bans, settings | root (via the head) | directories, hosts | the whole policy, on every edit | edits |
| Freshness (`Fresh`) | a directory | hosts, callers | to hosts: a beat every `beat_secs`; to callers: with each view, and in each host's or directory's proof | continuous |
| ID token | the IdP | the caller (and, for one call, the host and the service it runs) | in each call's `Hello`, each view request, each inbox fetch, each only after that host or directory proved itself current; to the service as `WIRES_ID_TOKEN` | per call |
| Verified principal | checked by the host or directory | host memory | to the service as `WIRES_CALLER`; never on the wire | per call |
| Push messages | — (sent over an authenticated connection) | host queue, then the caller | `wires/inbox/4`, direct or fetched | on push |
| Addresses | iroh (pkarr) | n0 DNS, relays; local hints | iroh discovery | continuous, outside wires |

### Who talks to whom

```
                       publish (each edit)
   admin  ─────────────────────────────────────▶  directory      directory
                                                   │     ▲
        subscription: whole policy + Fresh         │     │  proof, then view / search / resolve
                  ┌────────────────────────────────┘     │  (mcp, gateway, inbox --wait: every 60 s)
                  ▼                                       │
                host  ───── proof: head + Fresh ──────▶ caller
                  │   ◀──────── call (Hello, Invoke) ───
                  │    ──── HelloAck: head version ───▶
                  └────────── push (or fetch) ────────▶
```

Nothing is broadcast. Every arrow is a direct, key-authenticated connection, and each carries only
what the receiving node may hold.

### Why not gossip

A gossip topic delivers every message to every member and tells each member its neighbours' keys.
That would hand every agent the metadata the directory exists to keep from it. It also needs every
member online and forwarding, and most callers are one-shot processes. The policy has one author
(the root), so its copies never need merging. A host gets the whole policy from the directory it
follows, and a caller asks a directory for its view: each receives only what it may hold.

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
  and publishes it to every directory. One it can't dial, or that answers that it is busy, is
  tried again for up to 15 s (a directory that has just restarted can't be found by its key for
  about 3 s), when it has taken a publish from this admin before; a directory the edit drops is
  tried once. Directories don't replicate: when a listed directory that has taken a publish
  before still missed it, the edit exits 1, and that directory, and the hosts following it, hold
  the policy before it until `wires policy push` reaches it (a directory that is also a host may
  take it sooner, from the directory its host follows; a host whose directory is behind it moves
  to another). It also keeps vouching for the old policy, so a host the edit removed can still
  show its word and be called by callers on the old policy: after a missed publish, run `wires
  policy push` once the directory is back. Directories send every host that follows them the whole new policy and its
  `Fresh`. `wires mcp` and `wires inbox --wait` ask for their view every 60 s, and the gateway at
  a web user's first request after 60 s, so a grant or revocation reaches them within a minute.
  One-shot callers learn at their next call (from the host's proof or `HelloAck`), or when their
  view is a day old.
- **Remove.** `wires remove alice@example.com` adds a person ban: every host refuses that person
  from any machine, and every directory refuses them a view. `wires remove <node>` takes a host or
  directory machine out: it adds a node ban and drops the node from every service's hosts and
  from the directories. Neither expires;
  `wires restore` lifts one. Every host following a directory that took the edit has the new
  policy as soon as that directory does, and refuses the next call. Callers tell a removed host
  nothing once the last `Fresh` for the old head lapses (`fresh_secs`), provided every directory
  took the edit: one that missed it keeps vouching for the old head until `wires policy push`
  reaches it (the limits are in [protocol.md §9](protocol.md#9-known-limits)). Removing the last
  directory is refused.
- **Call.** The caller picks one of the service's hosts from its view at random (one that failed
  to answer it in the last minute goes last; the next is tried only when a dial fails) and dials
  it. The host speaks first: its proof, its root-signed head and the current `Fresh`es it holds.
  The caller sends nothing until a `Fresh` from a directory other than that host vouches for that
  head (a one-machine network takes the host's own) and its view lists the host; holding such a
  word already, it doesn't wait for the proof. A proof that doesn't check out is a dial failure,
  and the next host is tried; when none checks out, the call fails closed (exit 1). Then it sends
  `Hello` (its view's head version and its ID token) and `Invoke` (service and argv). The host
  verifies the token and admits the caller (a verified email, no ban, some role matches),
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
| `wires/session/2` | hosts | calls: the host's proof first, then the call |
| `wires/inbox/4` | hosts; callers in `inbox --wait` | push delivery and fetch (a fetch, like a call, starts with the host's proof) |
| `wires/directory/3` | directories | `publish` (from anyone; taken only if root-signed and newer), `policy {have}` (the whole policy, only for a node the policy names as a host or directory; answered with `policy` or `current`), `view` and `resolve` (a caller's signed entries, cut for its verified ID token, after the directory's proof) |
| `wires/directory-sub/3` | directories | a host or directory following the policy: the whole policy when a newer head is held, else a `fresh` beat |

## 8. What it costs

What each node receives grows with the rate of edits, not with the number of nodes:

- **A host** fetches the whole policy once, then receives a `fresh` beat every `beat_secs` and the
  whole policy again per edit.
- **A one-shot caller** sends nothing in the background. It holds its view (the services it may
  call), learns of a new head in a host's proof or a call's `HelloAck`, and then asks a directory
  for its whole view again. The first call to a host in each `fresh_secs` window that no `Fresh`
  it holds covers waits one round trip more for the host's proof. `wires mcp` and `wires inbox
  --wait` ask for the whole view every 60 s.
- **The admin** sends one publish per directory per edit (again, for up to 15 s, to one it can't
  dial or that is busy, when it has taken a publish before; at most 30 s in all).

`cargo run -q --release -p library --example policy_sizes` builds real signed policies and
measures them. At 1,000 services (and 300 bans) it printed (2026-10-05): the whole policy 647 KB
(65 KB at 100 services, 3.2 MB at 5,000), which is what a host receives per edit, a freshness beat
475 B, a `HelloAck` carrying a new head and one entry 1.2 KB, a caller's `view.json` for 25
services 16 KB, and a network string 578 B. The per-day model in
[`bench/state-scale/`](../bench/state-scale/REPORT.md) was made for an earlier design (deltas,
view subscriptions, replicas) and has not been redone.

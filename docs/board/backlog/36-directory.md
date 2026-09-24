# 36 — The directory: where the fabric's policy lives

**Lane:** D2 · **Depends on:** [35](../review/35-badges-and-bans.md) · **Status:** backlog, designed 2026-09-24 · **Files:** `library/services/` (policy head, items, Merkle proofs, freshness), `library/directory/` (new: frames), `wires/directory/` (new: the mode, its redb store, subscriptions), `wires/host/{serve,gate}.rs`, `wires/state/` (retired), `wires/admin/`, protocol.md §3–4, [fabric.md](../../fabric.md)

## Why (the human, 2026-09-24)

"We need to find a way to dramatically reduce fabric chatter, likely by having persistent
apex/directory nodes that are used where the syndicated data is used today." And: "this should
be a mode on its own ALPNs", "back it using redb".

Today every host is an equal mirror of the whole signed state. The admin dials every host after
every edit, every host re-checks every 10 minutes, and no node knows which peer is current, so a
node that missed a push searches. [`bench/state-scale/REPORT.md`](../../../bench/state-scale/REPORT.md):
with a directory, each host holds only its own slice and receives about 90 KB a day at any org
size, against 54 MB (10k users) or 1.3 GB (50k) today. The fabric also gets a lasting home: the
directory is what survives when every host and caller is off.

## What the directory is

A node the root-signed policy names in `directories`. It holds the newest policy, signs a
freshness timestamp every few minutes, and hands each host its slice (and, card 37, each caller
its view). **It never decides a call.** Hosts decide from their slice, so calls keep working
with every directory down.

It is trusted for availability and freshness only. Everything it serves is root-signed and proved
against a root-signed head, so it can't forge or mix policy. It can withhold (bounded by the
freshness rule below), and it sees who asks for what (traced, not logged).

## Decisions

### A mode on its own ALPNs, not a native service

A native service (card 33) is reached through the call gate: badge, IdP token, then the
registry's `allow` roles, with a `Started`/`Finished` in the call log. That fits work done for a
person. It doesn't fit the directory:

- **Hosts aren't people.** Every role needs a verified IdP identity (card 28), and a host asking
  for its slice has none, nor does a new node before `wires login`. Passing `allow` would need a
  machine role, which card 28 removed on purpose.
- **Log noise.** 500 hosts' 5-minute beats are about 144k call-log entries a day.
- **Shape.** A subscription that streams updates, and typed signed items, don't fit stdin/stdout.

So the directory is a mode, like state sync and the record stream: `serve` runs it when the policy
lists its node in `directories`, and **`wires directory serve` runs it alone** on a node that hosts
nothing (the human, 2026-09-24: ship both in this card). `wires directory serve` takes no `host.json`;
it needs only a keystore that joined the fabric and is listed in `directories`, and it refuses the
admin's keystore, as `serve` does.
Its gate is the badge (and bans); what it returns is filtered by the requester's role in the fabric
(directory, host, admin-delivered head) and, for views (card 37), by the verified IdP principal.

### Not gossip

A gossip topic (iroh-gossip) was considered for real-time updates and rejected:

- **It leaks.** Every subscriber receives every message, and each topic member learns its
  neighbours' node ids. That is the org-chart exposure cards 35–37 exist to remove; filtering per
  subscriber is impossible in a broadcast.
- **It makes every node do work.** A topic member stays online and forwards others' messages.
  Most callers are one-shot CLI processes; they can't be members.
- **Nothing here has many writers.** Policy has one author (the root), and its copies need no
  merging.

Real time comes from **directory-held subscriptions** instead: long-lived QUIC streams that carry
each subscriber only its own slice or view. An idle subscription costs a keepalive. If a directory
ever holds more subscribers than it can (far beyond the modeled 1,000 hosts), an opaque
"version N exists" beacon over gossip could fan out the wake-up, with content still fetched per
node. Not now.

### Policy: a root-signed head over proved items

The state becomes a **head** over **items**, so any subset can be handed out and checked:

```
PolicyHead { format: 3, fabric, version, issued, not_after,
             directories: [NodeId], items_root: Hash, item_count }   signed by the root
Item       { kind: role | service | ban | issuer | settings, key, body }
```

- Items are leaves of a blake3 Merkle tree, sorted by `(kind, key)`. A node given an item and its
  inclusion proof knows it belongs to that exact head, so a directory can't serve one item from
  an older version under a newer head. The fabric branch's committed roster (PR #7, in git
  history) is prior art for the tree.
- `directories` sits in the head itself: every node needs it, and it must be readable before
  any proof.
- `issuer` items carry each trusted IdP (issuer, client id, accepted audiences), moving them from
  `host.json` into signed policy (card 29 asked for this). `host.json` can still narrow them.
- `settings` holds the freshness rule and its intervals.
- Head `not_after` defaults to 90 days (`--state-ttl`): the freshness timestamp, not the head's
  expiry, is what keeps copies current.
- Monotonic as today: a node adopts a head only if it verifies, is fresh, and is newer.

### Freshness: the directory's timestamp (TUF's timestamp role)

- Every 5 minutes each directory signs `Fresh { fabric, version, head_hash, at, until }` with its
  node key (`until` = at + 15 minutes). It is valid because the root-signed head lists that key in
  `directories`.
- A host that holds a current `Fresh` knows its policy is the newest.
- **When `Fresh` lapses** (no directory reachable), `settings.freshness` decides:
  - `lenient` (default): keep deciding under the held head until its `not_after`, and report the
    staleness in the host's trace and in `wires watch`. Calls never depend on the directory.
  - `strict`: refuse calls (`Denied`: `this host's policy is stale`) until a `Fresh` arrives.
    Bans are then honoured within 15 minutes everywhere, at the cost of the directory becoming
    a dependency for calls.

### The store: redb

`directory.redb` in the directory's keystore:

| Table | Key → value |
|---|---|
| `heads` | version → signed head (last 16 kept, for deltas) |
| `items` | leaf hash → item bytes (garbage-collected when no kept head names them) |
| `current` | `(kind, key)` → leaf hash, for the newest head |
| `meta` | `version`, the latest `Fresh` |

One writer (a publish), many readers (slices, views, subscriptions reading snapshots). A restart
reloads the newest head, signs a new `Fresh`, and serves. Hosts and callers keep plain files; only
the directory needs a database.

### ALPNs

- **`wires/directory/1`**: one request per stream, after `hello {badge, id_token?}`.
  - `publish {head, items}`: from anyone. Accepted when the head verifies, is newer, and the items
    hash to `items_root`, as `offer` is today. The admin publishes this way.
  - `head {}`: the newest head and `Fresh`, to any badge holder.
  - `slice {have, roles}`: a host's slice (below). `view` and `resolve` are card 37.
- **`wires/directory-sub/1`**: subscriptions.
  - `subscribe {kind: slice | replica | view, have}` → a stream of `update {head, fresh, items,
    proofs}` when the subscriber's part changed, and `fresh {…}` beats every 5 minutes.
  - A capped number of subscribers per directory (default 4,096); one over the cap is refused and
    falls back to asking `slice` every 5 minutes.

### Host slices

A host subscribes to every directory (the first that answers wins; the rest stay as warm
failover). Its slice is: the head, `Fresh`, and with proofs, the service items naming it, the roles
those items' `allow` and `readers` name, the roles `host.json` names (`also_require`,
`push.allow`, sent as `roles`), every ban, every issuer, and settings. A host holds no other
service and no other role. It stores the slice in its keystore (`policy/`) and decides from it on
restart before any directory answers.

### The root key stays a file

The human, 2026-09-24: no key ceremony in the alpha. `root.seed` stays a 0600 file in the
admin's keystore, as today: no backup root, no rotation, no delegation chain for the root itself.
This is a known trade-off ([fabric.md §4.4](../../fabric.md#44-the-root-key)), not a gap to fill
in this card. The only root-adjacent key this card adds is each directory's own node key, which
signs `Fresh`, and it is trusted only because the root-signed head lists it.

### Naming directories, and a fabric's first one

- `wires directory add|rm <node>` (admin) edits the head's `directories`, like `service` edits
  services; `wires directory serve` (on the directory node) runs the mode. Both sit under one noun
  so neither shadows the other.
  At least one is required once any other node has joined.
- A new fabric: `wires init`, `wires invite <node>` and `wires directory add <node>`; the node
  joins and starts `serve`, and the admin's publish gives it the policy. In the demo, workbench is
  both the host and the directory.

### Replicas and publishing

- The admin publishes each edit to every directory. `wires state push` re-publishes. An edit exits
  1 when no directory accepted it, as a push that reached no host does today.
- Each directory subscribes to the others as `replica` and adopts any newer head, so a directory
  that missed a publish catches up. No consensus: there is one author, and "newer" is a version
  number.
- Losing every directory loses nothing: the admin's keystore holds the full policy, and
  `wires state push` to a new directory rebuilds it.

### What this retires

`StateResponder` and `wires/state/1`, the host's 10-minute `refresh_loop` and start-up catch-up,
and the admin's push to every host. Callers keep their full state and cold pull until
[card 37](37-caller-views.md).

## Acceptance

- [ ] An admin edit reaches every subscribed host that needs it within 2 s, and a host whose slice
      didn't change receives only the new head and `Fresh` (test with a counting responder).
- [ ] A host's keystore holds no service item that doesn't name it and no role it doesn't need.
- [ ] With every directory stopped, calls keep working under `lenient`; under `strict` they are
      refused once `Fresh` lapses, and served again once a directory is back.
- [ ] A directory restarted from `directory.redb` serves the same head and a new `Fresh`.
- [ ] A tampered item, an item proved under an older head, an older head and a `Fresh` from a key
      not in `directories` are each refused.
- [ ] A directory that missed a publish catches up from a replica.
- [ ] `wires directory serve` serves a fabric on a node with no `host.json`, and refuses to start from
      the admin's keystore or on a node the head doesn't list.
- [ ] `bench/state-scale/model.py`'s *apex* host rows describe the result.
- [ ] protocol.md rewritten for the head, items, freshness and both ALPNs; `wires/state/1` removed.

## Open questions

- **Badge renewal.** Badges expire (30 days) and only the root can sign one. Either the admin runs
  `wires renew` periodically against the directory's list of expiring badges, or the root
  delegates a narrow renewal key to the directories (card 18's front desk). Until decided, badges
  are re-issued by invite.

## Notes

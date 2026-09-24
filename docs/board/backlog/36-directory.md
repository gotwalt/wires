# 36 — The directory: where the fabric's policy lives

**Lane:** D2 · **Depends on:** [35](../done/35-badges-and-bans.md) · **Status:** backlog, designed 2026-09-24 · **Files:** `library/services/` (policy head, items, Merkle proofs, freshness), `library/directory/` (new: frames), `wires/directory/` (new: the mode, its redb store, subscriptions), `wires/host/{serve,gate}.rs`, `wires/state/` (retired), `wires/admin/`, protocol.md §3–4, [fabric.md](../../fabric.md)

## Why (the human, 2026-09-24)

"We need to find a way to dramatically reduce fabric chatter, likely by having persistent
apex/directory nodes that are used where the syndicated data is used today." And: "this should
be a mode on its own ALPNs", "back it using redb".

Today every host is an equal mirror of the whole signed state. The admin dials every host after
every edit, every host re-checks every 10 minutes, and no node knows which peer is current, so a
node that missed a push searches. [`bench/state-scale/REPORT.md`](../../../bench/state-scale/REPORT.md):
with a directory, each host holds only its own slice and receives 140–430 KB a day (measured
sizes, card 36a), against 54 MB (10k users) or 1.3 GB (50k) today. The fabric also gets a lasting home: the
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

**36a (2026-09-24, branch `worker/36a-policy-types`): the pure `library` types.** No `wires/`
changes; `state.rs`, `access.rs` and `membership/` untouched (card 35's lane).

- **Modules.** `library/services/`: `item` (`Item`, `ItemKey`, `Ban`, `IssuerConfig`,
  `Settings`, `FreshnessMode`), `merkle` (`ItemTree`, `ItemHash`, `ItemsRoot`, `InclusionProof`,
  `ProofPath`), `head` (`PolicyHead`, `SignedPolicyHead`, `HeadHash`), `signed_policy`
  (`Policy`, `SignedPolicy`), `parts` (`Slice`, `View`, `ViewEntry`, `ProvedItem`), `fresh`
  (`Fresh`). `library/directory/frames.rs` is `library::directory` (`DirectoryRequest`,
  `DirectoryAnswer`, `SubRequest`, `SubFrame`, both ALPNs). The module isn't called `policy`
  (taken by `check_inclusion`) or `slice` (shadows the primitive in doc links).
- **`Policy` mirrors `State`.** Typed maps (`roles`, `services`, `bans`, `issuers`, one
  `settings`) the admin edits, and `sign` → `SignedPolicy { head, items }`, so an edit can't make
  two items with one key or a second settings item. `Policy::from_items` is the inverse.
- **Validation** carries over the state's rules (defined roles, matchers with an issuer, each
  host once) and tightens one: **every matcher must name an issuer that has an `issuer` item.**
  36b's `init` must therefore sign an issuer item (Google by default) before any role.
- **Proofs** are `{index, path}`: the sides come from the index and the head's `item_count`, so
  a proof is bound to one position in one tree. The path travels as one base64url string
  (a third smaller than hex strings). An odd node carries up unchanged (CT rule).
- **`Fresh`** is one type with its `sig` inline (like `Membership`), names its signer
  (`directory`), and vouches for one head by version **and** `HeadHash` (blake3 of the signed
  head's canonical JSON). `is_current(now)` allows `CLOCK_SKEW_SECS` before `at`.
- **Frames.** `publish` is the only request that may exceed 16 KiB (`PUBLISH_BODY_PREFIX`,
  checked from the body's first bytes); everything is at most 16 MiB. `head {}` is a braced
  variant because serde ignores unknown fields on unit variants. `resolve` is answered with a
  one-entry (or empty) `view`. `current {fresh}` answers a `slice`/`view` whose `have` is the
  newest. Subscriptions send the subscriber's **whole** part under a new head
  (`slice`/`view`/`replica`) or a `fresh` beat.
- **Measured** (`cargo run --release -p library --example policy_sizes`): head 558 B;
  `Fresh` 446 B (475 B as a beat frame; the model's `timestamp` is 300); a service item 349 B,
  with its proof 860 B at 1k services (depth 11) and 946 B at 5k (depth 13), so a proof costs
  511–597 B per item against the model's `entry_sig` 150. A 30-service view is 27–30 KB. A host
  slice is **184 KB** at 1k services / 300 open bans and **1.06 MB** at 5k / 1,500 bans: bans
  are most of it, since every host holds every ban with its own proof.
- **For 36b, a gap in "a host whose slice didn't change receives only the new head and
  `Fresh`":** every edit changes `items_root`, so the proofs a host holds no longer verify under
  the new head. Keeping old-head proofs under a new head is the version mixing the tree exists to
  prevent (a directory could keep serving a revoked role with a current `Fresh`). Either every
  update re-proves the host's whole slice (184 KB × edits a day at 1k services, far over the
  model's 88 KB/day), or 36b adds one of: (a) a **multiproof** over all a host's items (the bans,
  issuers and settings are one contiguous leaf range, so they cost about 2·log n hashes; an
  unchanged slice then costs head + `Fresh` + a few KB), or (b) a root-signed change list in the
  head (`previous` head hash + changed keys with their new leaf hashes), which lets a host carry
  unchanged items forward with no proof at all. (a) stays inside the Merkle module; (b) changes
  the signed head format.

**36a follow-up (2026-09-24, branch `worker/36a2-multiproof`): multiproofs and part updates.**
The integrator chose (a). This supersedes the per-item proofs, the whole-part subscription
updates and the 184 KB / 1.06 MB slice figures above.

- **`MultiProof`** (`merkle`): `{leaves: [LeafRange {start, len}], hashes: ProofHashes}`: the
  proved indices as ascending ranges with at least a one-leaf gap between them (one encoding per
  set), plus the sibling hashes the set doesn't determine itself, each sent once, as one
  base64url string. Prover and verifier share one walk (level by level, left to right), so they
  agree on hash order by construction. `ItemTree::prove_many`, `MultiProof::verify` /
  `verify_items` / `indices` (range lengths are checked against `count` before anything is
  expanded). A single leaf's multiproof is exactly its `InclusionProof` path.
- **Parts carry one multiproof.** `Slice {head, items, proof}` and
  `View {head, entries: [ViewEntry {item, call, read}], proof}`. `ProvedItem` is gone.
  `view_for(principal, query)` takes the search query, so a searched view is proved as a set of
  its own. `View::matching(query)` only reads a view; it doesn't change it.
- **Updates.** `SliceUpdate` / `ViewUpdate {head, changed, removed, proof}`. `proof` covers the
  holder's **whole** resulting set under the new head. `Slice::update_to(newer)` diffs two
  parts; `SignedPolicy::slice_update(from, host, extra_roles)` / `view_update(from, principal)`
  are the directory side (it recomputes `from` from the older policy the subscriber's `have`
  names). `Slice::apply(update, root)` / `View::apply` rebuild held + changed − removed and
  verify it all. They refuse a head that doesn't verify or is older, the removal of an unheld
  key, a key named twice, and a result that doesn't prove (a withheld or tampered change fails
  here). The holder then asks for the whole part. After `apply`, every held item is proved
  under the new head. A directory can still *withhold*, including by a false `removed`, which
  is no more than a full part allows; `Fresh` bounds it.
- **Frames.** `SubFrame` and `DirectoryAnswer` gain `slice_update` and `view_update`. The whole
  `slice` / `view` stays for first sync and after a failed `apply`: subscribe again with
  `have: 0`.
- **Bans, aligned with card 35.** `Policy::ban` (the later `until` wins) and
  `Policy::prune_bans(now)` (drops `until < now`) mirror `State::ban` / `prune_bans`; a test
  checks they give the same verdicts. One difference for 36b: `State::is_banned(node)` ignores
  the clock (a ban holds until pruned), while `Policy::is_banned` / `Slice::is_banned(node,
  now)` also expire at `until`. Both give the same answer while the badge the ban cancels is
  still valid (both are inclusive of `until`), so after that the difference can't admit anyone.
- **Measured** (`cargo run -q --release -p library --example policy_sizes`, frames include
  the `Fresh`):

  | | 100 services | 1k services, 300 bans | 5k services, 1,500 bans |
  |---|---|---|---|
  | whole host slice (items) | 7.5 KB (44) | **39.5 KB** (314) | **182 KB** (1,516) |
  | its multiproof | 983 B, 20 hashes | 1.7 KB, 37 hashes | 3.5 KB, 78 hashes |
  | update, host's slice unchanged | 2.1 KB | **2.8 KB** | **4.6 KB** |
  | update, one of its services changed | 2.4 KB | 3.1 KB | 4.9 KB |
  | update, one new ban | 2.2 KB | 2.9 KB | 4.7 KB |
  | view, 25 services | 11.4 KB | 12.4 KB | 13.0 KB |

  Per-item proof overhead in a whole slice falls from 511–597 B to about 5 B at 1k
  services (1.7 KB over 314 items). What remains is the items themselves: at 5k services, 1,500
  bans are most of the 182 KB, and that is a first-sync cost. At 1k services and about 20 edits a
  day, the updates come to about 60 KB a day plus 288 beats × 475 B ≈ 137 KB of `Fresh`. The
  beat, not the policy, now dominates a host's daily traffic, against the model's 288 × 300 B.

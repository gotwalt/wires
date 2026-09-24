# The wires protocol

This document describes the protocol as the code implements it today: `library/` (pure types and
codecs) and `wires/` (the iroh transport and CLI).

**What outranks what.** The premise outranks this document, and this document outranks the code.
The premise: remote CLIs are distributed securely over iroh; IdP authentication and authorization
keep out anyone who isn't allowed; agents can't observe each other's work, and the isolation
boundary is the verified person (the IdP principal); `wires watch` lets the people the registry
names as readers observe calls, in full, for logging and compliance. If the code disagrees with
this document, the code is the bug, unless this document breaks the premise, in which case both
are fixed. What the premise needs and the code doesn't do yet is listed in §10.

The architecture around it (who runs what, what each node keeps, and how each kind of metadata
moves) is [fabric.md](fabric.md). Usage, roles and the demo are in [usage.md](usage.md), [the board](board/README.md) and
[demo.md](demo.md). Deployment and testing are in [deployment.md](deployment.md) and
[testing.md](testing.md).

## 1. Ground rules

| Rule | Where |
|---|---|
| A node is an Ed25519 key, and `NodeId` is its 32-byte public key. The iroh `SecretKey` is the same seed, so the iroh endpoint id **is** the `NodeId`. | `library/membership/identity.rs`, `transport::secret_key` |
| **The caller is always `to_node_id(conn.remote_id())`**, the key iroh authenticated. It is never a wire field. Every gate below is sound only because of this. | every responder |
| A network is named by its root key: the `fabric` field every credential signs is `root.node_id()`. | `Membership::mint`, `Policy::new` |
| Signed objects sign a domain-separation prefix (where they have one) followed by `canonical_bytes(body)`: canonical JSON with keys sorted by `serde_json`'s default `BTreeMap` ordering. `preserve_order` and `arbitrary_precision` must never be enabled. | `library/codec.rs` |
| Every signed body carries a signed format discriminant and a fixed, complete set of fields. **An optional signed field is not allowed**, because an absent field and a present default sign different bytes; "none" is an empty value. A new format gets a separate body, and an old verifier rejects it with `UnsupportedVersion`. Signed types refuse unknown fields at decode. | membership, policy head, items, service entry, `Fresh`, call-log entry |
| Every signed credential signs its own authority (`fabric`), and `verify(root)` requires `fabric == root`. | membership, policy head, service entry, `Fresh` |
| Tokens are base64url-no-pad of canonical JSON. Wire frames are a 4-byte big-endian length followed by a body; the length is checked before the body is allocated. Frame envelopes are unsigned, so `skip_serializing_if` is safe in them. | all codecs |
| `alg` is always `Ed25519`. `not_after` is inclusive, and a credential is expired when `now > not_after`. Times are unix seconds, except `*_ms` fields. | all |

Every node binds one iroh endpoint (`presets::N0`: n0 DNS/pkarr discovery and relays) and is dialed
**by key**. Addresses are never authority; see §9 for the optional local hints file.

## 2. Membership: badges and bans

`Membership { version: 1, fabric, member, issued, not_after, alg, sig }` is signed by the root: the
node's **badge**. It answers two questions: which network the node belongs to, and which node it is.
`init` and `invite` mint it, for at most 30 days (`--ttl`, default `30d`).

`check_inclusion(m, fabric_root, caller, now)` checks, in order: `m.verify(fabric_root)` (algorithm,
version, the `fabric` pin, signature); `m.member == caller` (`SubjectMismatch`, so a badge is not
transferable); `now <= not_after` (`Expired`).

**A node is admitted by its badge and not being banned.** `check_admitted(m, fabric_root, policy,
caller, now)` (`library/membership/policy.rs`) is `check_inclusion`, then `Banned { until }` if the
signed policy holds a ban for `caller` (§3). Every gate asks this and nothing else about who is in:
the session gate (§5), the record stream (§8), push and inbox fetch on a host, a caller's inbox
receiving a delivery (§7), the directory (§4) and the web gateway. The signed policy lists no
members, so admitting a node is minting its badge, not an edit, and removing one is a ban that lasts
until its badge would have expired anyway.

A badge is public. It holds no secret, so presenting it before the peer is verified is safe.

## 3. The admin-signed policy

One versioned policy, signed by the root, says everything the network agrees on: the trusted IdPs,
the roles, the services and which hosts run each, the bans, the settings, and which nodes are
directories. It lists no members (§2). **The root signs the policy, and each service entry, like
a badge**: a root-signed **head** over **items**, where each service item is also signed by the root
on its own (`library/services/{head,item,entry,signed_policy}.rs`):

```
PolicyHead { format: 3, fabric, version: StateVersion(u64), issued, not_after,
             directories: [NodeId], items_hash: ItemsHash }
SignedPolicyHead { head, alg, sig }
SignedEntry { format: 1, fabric, version, name: ServiceName,
              service: Service { description, allow: [RoleName], hosts: [NodeId],
                                 readers: [RoleName] },
              alg, sig }
Item = role     { key: RoleName,    body: [Matcher] }
     | service  SignedEntry          // {"kind": "service", ...the entry's fields}
     | ban      { key: NodeId,      body: { until } }
     | issuer   { key: Issuer,      body: { client_id, audiences: [Audience] } }
     | settings {                   body: { freshness, beat_secs, fresh_secs } }
SignedPolicy { head: SignedPolicyHead, items: [Item] }   // items sorted by (kind, key), each key once
```

- **Signed bytes:** the head signs `"wires/policy-head/v1\0"` followed by canonical JSON of
  `{alg, head}`. `items_hash` is blake3 of `"wires/policy-items/v1\0"` ‖ the canonical JSON array
  of the items, in key order, so one signature covers the whole set: no item can be changed,
  dropped, added, or taken from another version. A service entry signs `"wires/service-entry/v1\0"`
  ‖ canonical JSON of every field but `sig`. The prefixes separate them from each other, from
  memberships, `Fresh` (§4) and call-log entries.
- **An entry's `version`** is the policy version at which it last changed. An edit re-signs only
  the entries it changes (`Policy::sign_after` the stored policy); the others keep their signature
  and version. So a caller holding a subset of entries (its view, card 37) can check each one alone
  against the root, and keep the newest version of each.
- **`SignedPolicy::verify(root)`**, the one check for a whole policy: the head's algorithm,
  format 3, the `fabric == root` pin and signature; the items are strictly in key order and hash to
  `items_hash` (`ItemsMismatch`); every service entry verifies on its own under the root, at a
  version no later than the head's; then `Policy::validate`. **`check_fresh(now)`**: `Expired`
  when `now > not_after`. An expired policy admits nobody until the admin signs a newer one.
- **Updates** (`library/services/policy_update.rs`). `PolicyUpdate { head, changed: [Item],
  removed: [ItemKey] }` moves a whole policy to a newer head: `new.update_from(&old)` computes it,
  `old.apply(&update, root)` rebuilds the item set (held + changed − removed), recomputes the hash
  and checks the new head's signature and each changed entry. Any mismatch (an item tampered with,
  withheld or added, an older head) is an error, and the holder asks for the whole policy. A
  **view** (`library/services/view.rs`) is `{head, entries: [ViewEntry {entry: SignedEntry, call,
  read}]}`: a caller's services, each verifying alone; `SignedPolicy::view_for(principal, query)`
  cuts it, and `View::apply(ViewUpdate {head, changed, removed: [ServiceName]}, root)` refuses an
  entry older than the one held.
- **`Policy::validate`** (run by `sign` and `verify`): no directory listed twice; every role has
  at least one matcher, and **every matcher names an issuer that has an `issuer` item**; every
  issuer is non-blank and accepts at least one audience; every role a service's `allow` or
  `readers` names is defined (there is no built-in role); every service host is listed once and
  is not banned; `settings.beat_secs > 0` and `fresh_secs >= beat_secs`.
- **Hosts are derived.** A host is a node some service's `hosts` names (`Policy::hosts`); there is
  no host list. `is_host` and `assigns(service, host)` are false for a banned node.
- **Bans.** A `ban` item maps a removed node to `until`, unix seconds: the removed badge's
  `not_after` (Admin surface below). A banned node is admitted nowhere this policy is held,
  whatever badge it presents (`bans_node`: a ban holds until an edit prunes it). After `until` its
  badge has expired anyway, so every edit drops the bans whose `until` has passed (`prune_bans`).
- **Issuers.** Each `issuer` item is a trusted IdP: its exact `iss`, the OAuth `client_id`
  `wires login` signs in under, and the `aud` values hosts accept from it. A host's `host.json`
  can narrow them, never widen them (§6).
- **Settings.** One item: `freshness` (`lenient`, the default, or `strict`: what a host does when
  no directory has vouched for its policy recently, §4 *Freshness at the host*), `beat_secs`
  (default 300: how often a directory signs a `Fresh` and beats its subscriptions) and `fresh_secs`
  (default 900: how long a `Fresh` is good for). The admin sets them with `wires policy settings`.
  `strict` needs at least one directory listed (nothing else could vouch, and every host would
  refuse every call), so validation refuses `strict` with no directory, whichever edit would
  make it so: `policy settings`, or `directory rm` or `remove` of the last directory.
- **Versioning.** Every admin edit (`init`, `remove`, `service`, `role`, `issuer`, `directory
  add|rm`, and the rare `invite` below) is the stored policy changed, expired bans dropped,
  `version + 1`, `issued = now`, `not_after = max(now + --policy-ttl, the stored policy's
  not_after)` (default `90d`: an edit never shortens the policy's life; a directory's `Fresh`, not
  the head's expiry, is what says a copy is current), re-signed. `--ttl` on `init` and `invite` is
  the minted **badge's** lifetime only.
- **Monotonic copies.** Every node keeps its newest verified copy in `policy.json`, written only
  through `adopt_if_newer(ks, candidate, root, now)`: the candidate must verify, be fresh, and be
  strictly newer (same network, higher version). The re-read, check and write happen under one
  exclusive file lock (`policy.json.lock`), so a removed node presenting a genuine older policy
  (one from before its ban) can't roll a node back.
- **Names.** `ServiceName` is `[a-z][a-z0-9_-]*`, at most 64 bytes; the session's `Invocation`
  names one. `RoleName` is 1–64 of `[A-Za-z0-9_.-]`.
- **Roles.** A role is an OR of matchers; a matcher is an AND of its keys over the caller's verified
  IdP principal: `issuer` (exact, **required**, and trusted by an `issuer` item), `email` (exact,
  or `*@domain`), `org` (Google's `hd`), `group`. Because every matcher names its issuer, a token
  another trusted issuer minted for the same email never satisfies it. `issuer=…` alone is "anyone
  that IdP verified". There is no built-in role: **with no verified principal, no role admits**
  (`role_admits`).
- **`authorize(policy, caller, principal, service)`** (`library/services/access.rs`), in order:
  the caller is not banned (`Banned`; its badge is the gate's, before this); the service exists
  (`UnknownService`); it allows some role (`NobodyAllowed`); the first role in `allow` that admits
  the caller's verified principal is returned (`NotInRole`, whose text asks for `wires login` when
  there is no principal). A host's gate runs it on every call; a caller never does (it holds no
  roles): what it may use is its view (§4 *Views*).

The policy is not secret from the machines the admin placed: directories and hosts hold all of it
(host node ids, banned node ids, role matchers, trusted IdPs, service names and descriptions, the
directories), and so does the admin. It names no other member (card 35). **A caller holds only its
view** (card 37, §4): the root-signed entries of the services its verified person may call or
read, and the head. No role, no ban, no other service, and no node id but its services' hosts and
the directories.

### Admin surface

The admin commands and their flags are in [usage.md § Commands by role](usage.md#commands-by-role).

- **`init`** mints the admin's own node's badge and signs version 1: one `issuer` item (`--issuer`,
  default `https://accounts.google.com`; `--client-id`, else `$WIRES_OIDC_CLIENT_ID`, required;
  `--audience`, repeatable, default the client id), the default settings, no roles, no services,
  no bans, no directories. That issuer is the one invites tell `wires login` to use;
  `--public-client-secret` records its client's **public** secret (a Google "Desktop app"
  client's) for invites to carry.
- **`issuer set <iss> --client-id <id> [--audience <aud>]… [--public-client-secret S] [--login]`**
  trusts an IdP (or changes one); `--login` makes it the one invites name. **`issuer rm <iss>`**
  stops trusting one, refused while a role's matcher names it. Which issuer invites name, and each
  public secret, stay in the admin's keystore (`login-client.json`, §9), not in the signed policy:
  every host holds the policy, and none needs them.
- **`directory add <node>`** lists an invited, unbanned node in the head's `directories` (once);
  **`directory rm <node>`** drops it.
- **`invite <node>` is not an edit.** It mints the node's badge, records it in the admin's
  ledger, `issued.json` (§9: node → label, latest `not_after`), and puts it in the node's token
  (below): the version doesn't move and nothing is published. Two cases do edit, and then
  publish: re-inviting a node the policy bans lifts the ban (the ledger then keeps the later of the
  old and new badges' expiries), and a stored policy that has expired is re-signed (a joiner can't
  install an expired one).
- **`remove <node>`** is a ban: `until` is the ledger's `not_after` for the node, or, for a node the
  ledger doesn't know, now plus the longest badge lifetime (30 days), which outlives any badge the
  admin could have minted for it. It also drops the node from every service's `hosts` and from
  `directories`, and from the ledger. Removing a node already banned is refused.
- **`role`** and **`service`** edit the roles and the registry; a `--host` must be a node in the
  ledger, and not banned.
- **`policy settings [--freshness lenient|strict] [--beat-secs N] [--fresh-secs N]`** edits the
  settings item; with no flag it prints the settings and edits nothing.

Every edit takes `--policy-ttl` and ends with the publish in §4. `wires policy push` changes nothing:
it re-publishes the stored policy to every directory.

`Invite { format: 4, membership, directories: [NodeId], login?: LoginSettings { issuer,
client_id, public_client_secret? }, policy?: SignedPolicy }` (`library/membership/invite.rs`) is
everything a new node needs: its badge (whose `fabric` is the root key), the first two of the
head's directories (where it asks for the head, its view, and, a host, the policy), and the login
settings: the issuer invites name, its `client_id` from the policy's `issuer` item, and its public
secret if the admin gave one (never a confidential one: the token is not a secret). A caller's
token is about 1 KB at any fabric size (979 B with a Google-sized client id and secret; a test
holds it under 1 KB). **Only a node the policy already names as a host or a directory gets
`policy`**, the whole signed policy: it holds the whole policy anyway, and a directory can't fetch
its first copy from itself. `Invite::verify(me, now)` requires the badge to verify under its own
`fabric`, name `me` and be unexpired; with a policy, that the policy verifies under the same root,
is fresh and doesn't ban `me` (`check_admitted`). `wires join` stores the membership, the directory
ids (`directories.json`) and the login settings (`login.json`), adopts a policy that rides along
(never rolling back a newer one), and, for a caller, asks a directory for the head (`head {}`,
stored as an empty view: no entry until `wires login`). The token works as **trust on first use**,
because it introduces the root; what vouches for the admin is whatever carried the token out of
band (see [card 18](board/backlog/18-front-door-OPEN.md)).

## 4. The directory: `wires/directory/1` and `wires/directory-sub/1`

A **directory** is a node the head lists in `directories` (`wires/directory/`). It holds the newest
policy, signs a freshness timestamp for it, takes a newer policy from anyone admitted, follows the
other directories, and answers hosts and callers. **It never decides a call**: hosts decide from
their own copy, so calls keep working with every directory down. It is trusted for availability and
freshness only; everything it serves is root-signed. `wires serve` runs it on the same endpoint when
the policy it holds at start lists its node; `wires directory serve` runs it alone, on a node with
no `host.json`, and refuses the admin's keystore (one holding `root.seed`) and a node the policy it
holds doesn't list.

**Freshness.** A directory signs `Fresh { format: 1, fabric, directory, version, head: HeadHash,
at, until, alg, sig }` with its own node key over `"wires/fresh/v1\0"` ‖ canonical JSON of the
other fields: at open, on every head it accepts, and every `settings.beat_secs`, valid for
`settings.fresh_secs` (`until = at + fresh_secs`). `HeadHash` is blake3 of the signed head's
canonical JSON, so a `Fresh` vouches for one exact head. It is valid only because the root-signed
head lists its signer (`Fresh::verify` refuses any other key, `NotADirectory`). A directory whose
held head doesn't list it signs none and answers `head` and `policy` with a refusal.

**The store** (`directory.redb`, in the directory's keystore; redb):

| Table | Key → value |
|---|---|
| `heads` | version → the signed head and its items' content-hash keys, in order (the last 16 kept) |
| `items` | content hash (blake3 of the item's JSON) → the item (dropped when no kept head names it) |
| `current` | item key (`kind:key`) → content hash, for the newest head |
| `meta` | `version` (the newest head's), `fresh` (the latest `Fresh`) |

One writer, many readers. A policy is stored only if it is strictly newer, in one transaction. A
restart reloads the newest head and signs a new `Fresh`. When the node's own `policy.json` is
newer (it joined with an invite), the store is seeded from it.

**Accepting a policy** (`Directory::accept`): `SignedPolicy::verify` under the root (§3), the head
fresh, strictly newer than the held head. Then it is stored, adopted into the directory node's own
`policy.json` (so a host that is also a directory decides under what it serves), a `Fresh` is
signed for it, and subscribers are woken. An older or equal one changes nothing.

**`wires/directory/1`.** Frames are a 4-byte length then canonical JSON tagged by `type`
(`library/directory/frames.rs`), at most 16 MiB; the `hello` is at most 16 KiB whatever it opens
with, and a request after it over 16 KiB must open as a `publish` (`{"head":`, checked before the
rest is read), so only an admitted node can make a directory read a large body. One request per
connection: the dialer sends `hello {badge, id_token?}` then one request, and gets one answer (5 s
to dial, 10 s per frame).

- **Admission first.** `check_admitted` (§2) under the held policy (`check_inclusion` when it holds
  none yet). Anyone not admitted hears only `not a member of this network`; the detail is traced,
  throttled, and logged nowhere. At most 16 connections, on both ALPNs together, are undecided at
  once (one more is closed unanswered): from the connection until its `hello` is decided, and the
  stream must open and the `hello` arrive within 10 s. An admitted peer gives up its undecided slot
  at once and takes one of 64 slots for admitted work (reading and answering its request, which for
  a view may wait on the IdP's keys, or reading its `subscribe`); one more hears `denied` (`this
  directory is busy; try again or ask another`).
- `publish {head, items}`: from any admitted node. Accepted as above, it answers
  `published {version}` with the version it now holds (the published one, or a newer one it
  already had); refused, `denied {reason}`. The admin publishes this way.
- `head {}` → `head {head, fresh}`.
- `policy {have}`: the whole policy, **only for a node the held policy names as a host or a
  directory** (card 37; anyone else hears `denied`: `the whole policy is for the network's hosts
  and directories; a caller asks for its view`): `current {fresh}` when `have` is the newest (or
  newer than the directory's); `policy_update {update, fresh}`, the `PolicyUpdate` from the head at
  `have` (`update_from` against the head kept in `directory.redb`), when `have` is one of the 16
  kept heads; else the whole `policy {policy, fresh}` (`have` 0, too old, or unknown).
- `view {have, query?}` and `resolve {service}`: a caller's view, below.

**Views** (card 37). The directory verifies the ID token the caller presented in its `hello`
itself, as a host does (§6): the held policy's `issuer` items and their audiences, the IdP's keys
fetched and held in memory only, the nonce bound to the iroh-authenticated key. Then it cuts the
view from the held policy, `SignedPolicy::view_for(principal, query)`: the root-signed service
entries whose `allow` (marked `call`) or `readers` (marked `read`) has a role admitting the
principal. With no token, or one that doesn't verify, no role admits and the view is empty (the
head alone). Nothing per user is stored, and a request is **traced, not logged**: a view grants
nothing, and the host logs every call.

- `view {have, query: none, held?}`: `held` is the `ViewDigest` of the view the caller holds
  (blake3 over `"wires/view-digest/v1\0"` ‖ the view's canonical JSON). With a verified principal
  and a `held` that names exactly the view the directory would diff from: `current {fresh}` when
  `have` is the newest and `held` is the view now; a `view_update {update, fresh}` (`ViewUpdate
  {head, changed: [ViewEntry], removed: [ServiceName]}`, the principal's view at the kept head
  `have` diffed against the view now) when `have` is one of the kept heads and `held` is the view
  at it. Anything else gets the whole `view {view, fresh}`: no `held`, one that doesn't match (a
  view cut for another identity, or the empty one `wires join` stores), and any request without a
  verified principal (the empty view, whole, so a caller whose token has lapsed can't keep
  entries it held).
- `view {have, query: q}`: the entries whose name or description contains `q` (ignoring ASCII
  case), always a whole `view`.
- `resolve {service}`: a `view` holding that one service, or no entry (it doesn't exist, or the
  caller may not use it: the two are not told apart).

A caller applies a `view_update` with `View::apply` (the head verifies and is not older; each
changed entry verifies alone and is not older than the one held; removed names were held), and
takes a `view` when it verifies (`View::verify`: the head, and each entry on its own under the
root, at a version no later than the head's) and its `Fresh` vouches for its head. A directory can
withhold an entry or serve a stale view (a `Fresh` bounds how stale); neither lets anyone call
anything, since the host decides every call from its whole policy.

**`wires/directory-sub/1`.** The dialer sends `hello`, then `subscribe {kind, have}`, where `kind`
is `policy` (a host), `replica` (another directory) or `view` (a long-running caller). A directory
serves at most 4,096 subscribers of any kind (`wires directory serve --max-subscribers`); one
more is refused with `denied`.

- **`policy`**, only from a node the held policy names as a host or a directory (anyone else
  hears the `denied` above). The first frame comes at once: `fresh {fresh}` when `have` is the newest, else
  what `policy {have}` would answer (`policy_update {update, fresh}` from a kept head, or the whole
  `policy {policy, fresh}`). Then, for every head the directory adopts (a publish, or a replica
  catching up), one `policy_update` from the version the subscriber was last sent, and a `fresh`
  beat every `settings.beat_secs` in between. A subscriber ahead of the directory gets nothing
  until the directory catches up. Subscribers at one version share one encoded frame, so a publish
  costs the directory one diff per version its subscribers hold, not one per subscriber. The
  stream ends with `denied` when the head stops listing this node (it can no longer vouch), and
  when a head no longer admits the subscriber (its badge is checked again, and the head's bans:
  `not a member of this network`) or no longer names it as a host or a directory (the refusal
  above).
- **`replica`**, only from a node the held head lists as a directory: `policy {policy, fresh}`
  when the held version is newer than `have`, else `fresh {fresh}`; then the same on every
  change. It ends with `denied` if the subscriber stops being listed.
- **`view`**, from any admitted node, for the principal its `hello`'s ID token verifies as when
  the subscription opens (`wires/directory/sub_view.rs`): the whole `view {view, fresh}` first,
  whatever `have` says (the directory keeps nothing per subscriber, so it can't know which view a
  `have` refers to); then, for every head it adopts, a `view_update {update, fresh}` against the
  view it sent last, and a `fresh` beat in between. A subscriber that can't apply an update
  subscribes again and takes the whole view. The stream ends with `denied` when a head no longer
  admits the subscriber (badge and bans, as above) or stops listing this node. `wires mcp`, each
  live gateway session and `wires inbox --wait` hold one.

**Replicas.** Each directory subscribes to every other directory its head lists, as `replica`,
reconnecting after a failure with a pause growing from 1 s to 30 s. A `policy` frame is taken when
its head verifies under the root, its `Fresh` vouches for that head, and it is newer; then it is
accepted as above. So a directory that missed a publish catches up from another. There is no
consensus: one author, and "newer" is a version number.

**Publish (admin).** After every admin edit, and on `wires policy push`, the admin dials,
concurrently, every directory the new head lists plus every directory the head before the edit
listed (so a directory the edit drops learns it), never itself, and sends `publish`. It dials no
host. A directory counts as delivered when it answers `published` with at least the offered
version. Stderr says `policy version N: published to K of D directory(ies)`, naming any not
reached. **When D > 0 and K = 0 the command exits 1** (after printing its result, e.g. the invite
token): the new policy is stored on the admin and nowhere else. `wires policy push` re-publishes
it. With no directory at all, the line says so and nothing fails; a new node gets the policy in its
invite token.

**Following (hosts).** A running host subscribes as `policy` (`wires/host/follow.rs`) to the
first directory its held head lists that answers, never itself, trying the one it last followed
first and then the others in the head's order; the list is re-read from the held policy on every
reconnect, so a directory the admin adds is followed without a restart. It takes each frame:

- `policy {policy, fresh}`: the head verifies under the root, the `Fresh` vouches for it, and
  `adopt_if_newer` takes it if newer;
- `policy_update {update, fresh}`: `SignedPolicy::apply(update, root)` on the held copy (the
  items' hash and the root's one signature on the new head, each changed entry's own signature),
  the `Fresh` vouches for the new head, then `adopt_if_newer`;
- `fresh {fresh}`: kept if it vouches for the held head (one for another version, from a directory
  behind this host, is skipped).

Any frame it can't take (an update that doesn't apply, a policy that doesn't verify) makes it
subscribe again at once with `have: 0` and take the whole policy; a second failure in a row moves
it to the next directory. When the stream ends (the directory stopped, was unlisted, or sent
nothing for two beats plus 10 s) it reconnects, pausing from 1 s up to the beat (at most 30 s)
while none answers. The subscription never holds up serving: a host restarted with `policy.json`
decides from it before any directory answers. A host that is itself a directory keeps the `Fresh`
its own directory signs (its replica loop keeps its copy in step with the others). A host that the
policy newly lists as a directory runs the directory mode only after a restart (it traces so).

**Freshness at the host.** The host keeps the newest `Fresh` that vouches for its held head (by
version, then a current one over one that isn't current, then `until`: one from a directory
whose clock runs ahead never displaces a current one) in memory and in `fresh.json` (0600), read
back at start if it still vouches for the head on disk. Before each call's registry check the gate asks whether a **current**
`Fresh` (`Fresh::is_current(now)`) names the exact head it decides under, and
`settings.freshness` decides when none does:

- **`lenient`** (default): decide under the held head as usual, until its `not_after`, and trace
  the lapse (a warning at most every 10 s; none when the head lists no directory). Calls never
  depend on a directory.
- **`strict`**: refuse the call with `this host's policy is stale: no directory has vouched for it
  recently; try again later` (exit 77 at the caller), until a current `Fresh` arrives; then serve
  again. A ban is then honoured on every host within `fresh_secs` of its publish, at the cost of
  the directories becoming a dependency for calls. The refusal comes after the badge and ban check
  and the ID token, so it is an admitted caller's refusal and is written to the call log like any
  other (one record per refused call: the log shows which calls the host refused while it could
  not vouch for its policy).

Push and the record stream decide under the held policy whatever its freshness.

**Fetch (a host's start).** `fetch` asks the directories the held head lists, in order, never
itself, for `policy {have}`, and stops at the first answer that settles it:

- a `policy` whose `Fresh` verifies against **that** policy's head, and which `adopt_if_newer`
  takes (verified, fresh, newer), is adopted; so is the held policy with a `policy_update`
  applied, when its `Fresh` vouches for the result;
- `current {fresh}` counts only when the `Fresh` verifies against the **held** head and is current
  (`at` at most 60 s ahead, `now <= until`): this node is up to date.

Only those two settle it. A refusal, a `Fresh` from a key the head doesn't list, a lapsed one, or
an older policy doesn't, and the next directory is asked. So a lying directory can only fail to
help.

A `serve` whose preflight fails (a host assigned a service while it was offline) fetches from a
directory for at most 8 s and preflights again; while it serves it follows the subscription above.
A node never adopts an older or unverifiable policy. A host that was offline when a service was
assigned to it catches up at `serve` start from a directory, or by joining with a fresh invite
(re-joining never rolls back).

**Callers keep their view current** (card 37; `wires/caller/view.rs`). A caller stores
`view.json` (§9): the view, the newest `Fresh` for its head, when a directory last vouched for it,
and the newest head version a host reported. The directories it asks are its view's head's (else
the ones `wires join` stored), never itself. A node that holds the whole policy (the admin's, a
host's, a directory's) cuts its own view from it instead of asking.

- **`wires join`** asks for the head (an empty view); **`wires login`** asks for the view under
  the new identity, forgetting the old one.
- **One-shot commands make no background traffic.** `wires call` dials from the view as it is,
  and learns of a newer policy only in the call's handshake: `HelloAck` carries the host's head
  version, and when it is newer than the view's, the head and the called service's entry (§5).
  The caller then refreshes its view after the call (`view {have, held}`: an update from a kept
  head).
  A name the view doesn't hold is asked of a directory with `resolve` before the call fails; a
  view that is missing or expired is refreshed first. So on an unchanged fabric a call is the only
  connection.
- **`wires services`** reads `view.json`, refreshing first when it is older than a day, its head
  has expired, or a host reported a newer head.
- **Long-running callers subscribe** (`view` above): `wires mcp` (and sends MCP
  `notifications/tools/list_changed` when its tools change), one subscription per live gateway
  session (with that user's ID token; the gateway holds no policy), and `wires inbox --wait`. They
  keep `view.json` in step (the gateway's per-user views stay in memory).

## 5. Sessions: `wires/session/1`

A session is one bidirectional QUIC stream on ALPN `wires/session/1`. Codec:
`library/calls/session.rs`. Transport: `wires/host/transport.rs`.

| Tag | Frame | Body | Direction |
|---|---|---|---|
| 8 | `Hello` | canonical JSON `{membership, state_version, id_token?}` (`state_version`: the head version of the caller's view) | caller → host |
| 7 | `Invoke` | canonical JSON `Invocation {service, argv}` | caller → host, right after `Hello`, without waiting |
| 9 | `HelloAck` | canonical JSON `{membership, state_version, head?, entry?}` (the host's own; `head` and `entry` only when its version is newer than the caller's) | host → caller |
| 6 | `Denied` | UTF-8 reason (at most 512 bytes) | host → caller, terminal |
| 1/2/3 | `Stdin`/`Stdout`/`Stderr` | raw chunk (at most 64 KiB when pumped) | stdin: caller → host; stdout/stderr: host → caller |
| 4 | `Exit` | i32, big-endian | host → caller, terminal |

Any other tag decodes as `BadFrame`.

**The host** reads `Hello` (10 s timeout, at most 64 KiB) and `Invoke` (at most 512 KiB: the
largest valid `Argv`, JSON-escaped), then re-reads its signed policy **for this connection**, so a
removal applies on the next dial without a restart. Before it knows who is asking it holds at most 64
sessions open (one more is closed unanswered), and it sizes no buffer from a length prefix. The first
failure below is sent as `Denied` (`wires/host/gate.rs`):

1. The host holds a readable policy (else `host configuration error`).
2. **Admission, before anything else:** `check_admitted(hello.membership, trust_root, policy,
   caller, now)`: the badge and the bans (§2). Anyone else — no badge, someone else's, another
   network's, expired, banned — hears only `not a member of this network`: no reason, no policy
   version. Their
   token is never verified (no JWKS fetch, no identity-index entry), and the refusal is traced
   (throttled), **not** written to the call log, so strangers can't fill it.
3. **Identity.** The `id_token`, if any, is verified by the host itself (§6); the principal, or why
   there is none, is kept for the next steps. A token that fails is `your ID token could not be
   verified` or `the identity provider is unreachable from this host`; the detail is only in the
   host's trace.
4. **The gate** (`admit`): under `strict`, a current `Fresh` vouches for the held head (§4
   *Freshness at the host*) → the head hasn't expired → the service is registered → it is assigned to
   **this** host → `authorize` (the registry's `allow`) → every role in `host.json`'s `also_require`
   for it admits the caller too (it can only narrow; the refusal doesn't name those host-local roles).
   A refusal that a verified identity could change leads with why there is none (`no ID token
   presented; run \`wires login\``).
5. **Implementation.** Only an admitted caller learns whether this host implements the service,
   in `host.json` or natively (`service … is not implemented on this host`).

Every refusal from step 3 on (the caller is admitted) is logged as an `AuditRecord::Denied`.

The host then appends the call's `Started` to its call log and `fsync`s it (§8) — if it can't, the
call is refused (`this host can't record calls right now…`) and nothing runs — sends `HelloAck`
(when the caller's `state_version` is older: its root-signed head and the called service's root-signed entry, card 37) and execs the service's fixed argv
**with the caller's argv appended element by element, never through a shell** (after a `--` when
the service sets `end_of_options` in `host.json`, so a CLI that honours `--` takes none of the
caller's arguments as an option; it doesn't help a CLI that ignores `--`), in its `cwd`. The
child's environment is built from nothing (`env_clear`): only `PATH`, `LANG` and `LC_*` are
inherited from `serve`; then `host.json`'s `env`; then the server-derived `WIRES_CALLER_NODE`,
`WIRES_FABRIC_ROOT`, `WIRES_MEMBERSHIP_NOT_AFTER`, `WIRES_STATE_VERSION`, `WIRES_SERVICE`,
`WIRES_ROLE`, and, when verified, `WIRES_CALLER_EMAIL`. With `push` on, also
`WIRES_PUSH_SOCKET` and `WIRES_PUSH_TOKEN`, the call's push capability (§7), already bound to the
call's id before the child starts. The child never gets `WIRES_HOME`, `HOME`, agent sockets or
cloud credentials. If the connection closes, the host kills the child.

The child still runs as `serve`'s own Unix user. It is told neither `WIRES_HOME` nor where the
operator socket is (its push socket lives outside the keystore, §7), but it can still find the
keystore at its default path, so a service a caller can steer into reading or writing files can
reach whatever that user can, the host's keystore and operator socket included. `wires` does not
switch users itself; the operator does
([deployment.md](deployment.md#run-services-as-a-separate-unix-user)). Independently of that, the host fails closed on the parts of its
keystore a child could tamper with: it keeps the highest policy version it has decided under in
memory and refuses to decide under an older `policy.json` (`host configuration error`, logged
as a rollback), and it trusts only issuer keys it fetched itself (§6).

**Native services** (`wires/host/native.rs`, `wires/host/embed.rs`). An app can embed
the host (`wires::Host::builder(<keystore dir>)`, `.service(name, impl wires::Service)`, `.serve()`)
and implement services in-process. The wire, the gate, the log and the bridge are the ones above:
a native service is invoked by `Invoke`, reads the caller's stdin, writes stdout and stderr, and
its exit code is the call's. Callers can't tell it from a CLI. The handler runs as a tokio task
only after `Started` is fsynced and `HelloAck` is sent. It gets the verified caller as a type
(`Call`: node, principal, role, policy version, service, argv, call id) in place of the `WIRES_*`
variables. With push configured (`host.json` `push`, or the builder's `push_allow`), the host mints
the call's push capability as it does for a child and hands it over in-process:
`Call::push_to_caller(subject, body)` is checked against the same live-token registry (only this
call's caller, until the grace period after the call ends, §7), goes through `push.allow`, and is
logged naming the call. If the connection closes (or the host stops), a Rust handler's task is
aborted at its next `.await` and the call exits -1; a Python or JavaScript handler can't be
aborted, so its next read or write fails instead. If a handler panics, the call exits -1. Either
way the call gets its `Finished`, and its stdio is recorded like a child's (§8). `host.json`'s
`also_require` applies to CLI services only: a native service is gated by the signed policy alone,
and a handler wanting a stricter local rule checks `Call::role` or `Call::principal` itself. An
embedded host starts like `serve`: the signed policy must assign every service to it, CLI and
native, and a name can't be both (`build` refuses it). Its keystore, hints file included, is the
directory the app names; it reads neither `$WIRES_HOME` nor `$WIRES_NODE_SEED`. `serve_until`
returns once its shutdown future resolves and everything it started has stopped: the policy
check, the directory's loops (when it runs one), the protocol router with its sessions, and the
endpoint (closed). `Host::serve` is
`serve_until` Ctrl-C, which claims SIGINT process-wide; the bindings' `serve` doesn't listen for
it unless asked (`serve(handle_ctrl_c=True)`, `serve(true)`). The node
key lives in the app's memory (§9): a native service is the operator's own code, as trusted as
`serve`, so nothing isolates it from the key the way a child is kept away from it.
`bind_loopback()` binds the host's direct (IP) transport only on `127.0.0.1` and `::1`, with no
port mapping; callers elsewhere reach it through its relay. It exists for local demos: a host bound
so holds no network socket, so the macOS firewall doesn't prompt for an interpreter that can't be
signed. Other languages reach the same API through `wires-ffi` (UniFFI, Python; `bindings/`),
where a handler is a synchronous `call(call) -> int` on a thread of its own, and `wires-node`
(napi-rs, TypeScript; `bindings/node/`), where it is `(call) => number | Promise<number>` on
Node's event loop. In both, a handler that raises ends the call with exit 1 and the error on stderr.

**The caller** (`wires call`, `wires mcp`, the gateway) dials from its view (§4 *Views*), and
refuses to dial from an expired one (it refreshes first; failing that, exit 1: ask the admin for
`wires policy push` or a fresh invite). It takes the service's hosts from the service's root-signed
entry, the last host that answered (`last-good.json`) first, then the admin's order. A name the
view doesn't hold is asked of a directory (`resolve`); a name no directory resolves for this
caller, or whose entry is marked `read` only, ends the call before any dial (exit 1, with `run
wires login` when it isn't signed in). It
fails over to the next host **only when a dial fails** (10 s each); a host that answered has
decided. It sends `Hello` and `Invoke` together, then, before it forwards a byte of stdin,
**always** verifies the `HelloAck` membership with `check_inclusion(ack, own fabric,
authenticated host id, now)`, and, when the ack's `state_version` is newer than its view's,
`HelloAck::assigns`: the head verifies under the root at that version, and the service's entry
verifies under the root, names the called service, is no newer than the head, and still lists that
host. If not, the call stops there (exit 1, no stdin sent). After the call, a one-shot caller
refreshes its view (§4). The host already has the `Invoke` (argv) by then: a removed host that
still holds a valid badge sees the argv of a caller whose view predates the removal (a caller
holds no ban list; the admin's `remove` drops the node from every service's `hosts`, so a current
view never names it).

Exit codes: `Denied` → **77**, nothing on stdout. Local or transport failure (including the checks
above) → 1. Otherwise the remote exit code, **except that a remote 77 is reported as 1** with a
note on stderr, so 77 always means the host refused. A session that ends without `Exit` is an
error. Limits: 16 MiB largest frame once admitted (64 KiB `Hello` and 512 KiB `Invoke`
before); `Argv` holds at most 256 arguments and 64 KiB.

A `tools.json` alias pins a local name to one host (node id, optional addresses and relay) and a
`remote_tool` service name; it opens the same `Hello`, so the host still decides by its policy. A
service in the caller's view wins over an alias of the same name, and an alias is refused before
dialing unless the view's entry for its `remote_tool` service lists its host.

## 6. Identity

`wires login` runs OIDC (authorization code, PKCE, loopback redirect) with `nonce =
base64url(blake3::derive_key("wires oidc-nonce v1", node_id))`, verifies the token locally, and
stores it in `idp-token.jwt`. Nothing is published. The token travels in the session `Hello` and the
inbox `hello` (§7).

A host verifies it against the issuer's JWKS under the trust of the policy it decides under: the
policy's `issuer` items (§3), each with the audiences it accepts from that issuer, narrowed by
`host.json`'s optional `identity.issuers` (only the issuers it lists; for an entry that lists
`audiences`, only those of the policy's). `host.json` can't add an issuer or an audience. The trust
follows the policy: each time the host reads a newer one, it verifies under that one's issuers. `verify_claim` checks, in
order: `alg` is RS256 or ES256 and a JWKS key verifies the signature; `iss` matches exactly; an `aud`
value is accepted; `exp` and `iat` are within the 60 s clock skew; `nonce == for_node(caller)`.
`email` is used only when `email_verified` is true; `hd` becomes `org` only when `iss` is exactly
`https://accounts.google.com`; `groups` is kept. A host
remembers the latest verified principal per node (`wires/host/identity.rs`) and never lets a failure
or an older token displace it. It knows only the callers that presented a token **to it**, and it
verifies a token only from a node it admitted (§5 step 2). A host keeps issuer key sets **in
memory only** and never reads the `jwks/` disk cache, which anything running as its user could
write; callers keep that cache, and trust a disk entry for at most 24 h.

**A web gateway** (`wires gateway`) is one node that carries many principals: it asks the IdP
for each web user's ID token with `nonce = for_node(gateway)` and presents that user's token in the
`Hello` of each call it makes for them. Nothing on the wire changes; the host sees an admitted node
presenting a token bound to it. The gateway holds no policy (card 37): for each live session it
subscribes to that user's **view**, presenting the user's own ID token to a directory, which
verifies it and cuts the view (§4 *Views*); so it offers a user only services that a role admits
by that user's own verified principal, and a grant or revocation applies to their next request.
The gateway's node alone is in no role, and a banned gateway is refused by every directory and
host. It issues its own OAuth access tokens (opaque, bound to its
`/mcp`, expiring with the ID token) and no refresh tokens. Its MCP endpoint serves the 2026-07-28
Streamable HTTP binding and the legacy `initialize` era ([deployment.md](deployment.md)).

## 7. Push: `wires/inbox/2`

A host sends a `PushMessage { id, from, to, subject (≤128 B), body (≤16 KiB), at_ms, expires_ms }`
to a caller, addressed **by key**. Frames are length-prefixed canonical JSON tagged by `type`:
`hello {membership, id_token?}`, `fetch {wait_ms}`, `deliver {messages ≤ 32}`, `ack {ids}` and
`denied {reason}`, at most 4 MiB; a `hello` (and a host's `fetch`) is read before the peer is known,
so it may be at most 64 KiB. Two ways a message is delivered:

- **Direct:** the host dials the recipient (3 s budget). A running `wires inbox --wait` serves the
  inbox ALPN and accepts `deliver` only from a node whose badge verifies and that **hosts a service
  in its view** (card 37; it follows its view by subscription while it waits); any other dialer hears only `not a member of this
  network` (the reason is traced, throttled).
- **Fetch:** `wires inbox` dials the hosts of every service in its view (`hello` with its stored ID
  token, `fetch` held open for up to 25 s, `deliver`, then `ack`).

The host authorizes at send, at delivery and at fetch (`ServicesHost::decide_push`): the recipient
must not be banned by the current policy, and must be in the first registry role of `host.json`'s
`push.allow` that admits it (default: nobody). **The identity rule:** every role needs the recipient's verified
principal, which the host learns only when the recipient presents its token to it: on a call, or in
an inbox fetch, both of which it admitted by badge first. `--to <role>` names the nodes whose known
principal the role admits; a node with no verified identity here is in no role. A fetch is checked
like a call: at most 64 undecided at once, the badge and the bans first, and a node not admitted
hears only `not a member of this network`, has its token left unverified, and is traced, not
logged; a banned node's queue is dropped (each message logged `denied`), and a push to it or its
fetch is refused. A node holds at most 2 long polls open per host; an admitted node's policy
refusal is answered, not logged (`wires inbox` asks every host of its services).

A receiver refuses a message whose `from` is not the authenticated peer or whose `to` is not itself.
Delivery is at least once; the receiver removes duplicates by `PushId`. The host queues up to 64
messages per recipient (oldest dropped), in `push-queue.json`. The TTL defaults to 24 h and is at
most 7 d. Each milestone is an `AuditRecord::Push`.

`wires push` hands the message to the running `serve` over one of two local sockets (NDJSON,
`wires/host/control.rs`), each mode 0600 in a 0700 directory that the server and the operator's
client both check is owned by `geteuid()`:

- **The operator socket**, `run/serve.sock` in the keystore: `{"push":{to, subject, body,
  ttl_secs?}}` to any node or role. A service child is not told where it is (though one running as
  the host's user can find it at the keystore's default path, §5).
- **The child socket**, `push.sock` in a private `wires-<16 random hex>` directory (0700) that
  `serve` makes at start, outside the keystore, under `$XDG_RUNTIME_DIR` (else the temp dir, else
  `/tmp`), and removes at exit; so `WIRES_PUSH_SOCKET` names neither `WIRES_HOME` nor the operator
  socket. It carries a service pushing back to **its own caller**. With a
  `push` section in `host.json`, for every call `serve` mints a random 32-byte token (64 hex) and gives the child `WIRES_PUSH_SOCKET` and
  `WIRES_PUSH_TOKEN`; `wires push` sees the token and sends `{"caller_push":{token, push}}` (no
  keystore needed). The socket accepts it only for a live token and only with `to` equal to that
  call's caller node id (never a role or another node); the operator's `push` form is refused
  there. A token is live for the call and 10 minutes after it ends (`CAPABILITY_GRACE`), so a job
  the call started can still report; tokens are memory-only, so a restart kills them. The push
  still passes `push.allow`, and its records carry `call`, the call whose capability sent it.

This is push as built. Designed, parked ([card 31](board/backlog/31-inbox-delivery.md)): every
callback goes to the calling node **and** principal through the call's capability only, the
operator's `push` narrows to `--to <node-id>`, role addressing goes, and an `inbox` MCP tool
reaches `wires mcp` and the gateway.

## 8. Records

**The call log** (`library/calls/call_log.rs`, `wires/host/call_log.rs`). Every `AuditRecord` a host
produces (`started {call, caller, principal?, service, argv, state_version, role}` (the policy
version it was decided under) —
`finished {call, exit, duration_ms, stdout/stderr bytes, stdout_digest, stdin_bytes, stdin_digest, stdin_head ≤4 KiB}`, `denied {caller, principal?, service?, reason}`, `push {id, to,
principal?, role?, subject, outcome, reason?, body?, call?}`; a `principal` is the verified
`{issuer, subject, email?, …}`) becomes a `LogEntry { v: 1, host, seq, prev, at_ms, record,
sig }`: dense 0-based `seq`, `prev` the hash of the previous entry (zero at seq 0), signed by the
host over `"wires/call-log/v1\0"` ‖ canonical JSON of the other fields. `verify_chain` reports a bad
signature, a gap, a broken link or a fork. The log is `call-log.jsonl` (fsync per entry), re-verified
on open, pruned from the front after 30 days, and optionally exported over OTLP/HTTP
(`audit.otlp`: https, or plain http only to a loopback collector). A host can still withhold or truncate its own history; rewrites are detectable only
against a copy someone holds.

**Fail closed.** Every record is awaited until it is written and fsynced (at most 5 s), never dropped
to keep a session moving. A call's `started` is logged **before** its child is spawned; if it can't
be, the call is refused and doesn't run. `finished`, an admitted caller's `denied` and push records describe
something that already happened, so a failure is traced as an error and the session goes on; while
the log stays unwritable every new call fails its own `started` and is refused, and the host serves
again once an append succeeds (a failed append is cut off the file first). A `started` without a
`finished` means the end wasn't recorded, not that the call never ran. Refusals of peers that are not
admitted (no valid badge, or banned) are traced, not logged (§5), so no one outside the network can
write to it.

**The record stream** (`wires/records/1`, `wires/host/record_stream.rs`): length-prefixed JSON
frames. The reader sends `open {hello, services, since?, mine, follow}`. The host checks admission
first (the badge in `hello` and the bans, §2): a reader that isn't admitted gets `denied` with the
fixed text `not a member of this network` and nothing else (the detail is traced, throttled). Before it has decided, it reads an
`open` of at most 64 KiB, sizes no buffer from a length prefix, and holds at most 16 undecided
readers (one more is closed unanswered). Otherwise it answers `granted {scopes, tip?, first?}`: per requested service
assigned here, `all` when the reader's verified principal is in one of the service's `readers` roles
and it didn't ask for `mine`, else `mine`; `tip` is the log's newest `{seq, hash}` and `first` the
oldest seq it still holds. Then `batch`es of items after `since`, `caught_up`, and with `follow` more
batches as the log grows. A `follow` stream is re-decided (admission, freshness, readers) whenever the
host's signed policy changes and when the reader's ID token, the policy or its membership expires:
`denied` ends it when access is gone (including an ID token that expired: the reader logs in and
watches again), and a new `granted` precedes entries decided under a changed view.

Each entry is sent either **in full** (signed, as stored) or inside a `hidden` run carrying only its
`{prev, hash}` link, so the reader checks the chain across what it may not see. An entry is shown in
full when its service was requested and granted `all`, or when its service was requested and its
subject is the reader's **person**: the same verified principal (issuer and `sub`) the host verifies
for the reader now, whichever node either used. A reader with no verified principal sees nothing in
full. Subjects and services: `started` — its service, its `principal`; `finished` — its `started`'s (if
that was pruned, the entry is only a hidden link); `denied` — its service, its `principal` (no service:
shown only to its subject); `push` — the service of the call whose capability sent it (`call` → that
call's `started`), and the principal it was admitted for. An operator push (no `call`), or one whose
call's `started` was pruned, is shown only to its recipient.

What hidden links reveal: a reader in no `readers` role still learns how many entries each host it
reads logged, and under `follow`, when each was written (a run arrives as the entries are appended).
Not what, by whom, or for which service. ([Card 09](board/backlog/09-witness.md) would replace this with
checkpoints and inclusion proofs, and drop hidden links for non-readers.)

`wires watch` asks the hosts of the services in its view (card 37: those it may read in full, and those it may call, for its own records; with no service named, all of them) and merges their backlogs by time. It keeps, in `record-marks.json`, **one chain anchor
per host** (the furthest entry it verified there, under any view) and a **resume point per view** (the
services asked of that host, `mine`). A view resumes from its own point, and wherever its stream passes
the anchor the entry there must be the one verified before, and the next must link to it; entries
before the anchor are shown only once the anchor confirms them. So a rewrite is caught even by a view
that never saw that stretch. Against `granted`: a `tip` below the anchor is a rollback, and a different
hash at the anchor a fork; both are alarms. A `first` past the entry after the anchor is retention: a
notice (`host … pruned entries before seq N (retention)`), and the anchor restarts from what the host
still holds. Any alarm stops that host's stream (exit 1) and leaves its marks at the last good entry.
The service label a line shows is the reader's own, derived from signed records: a `started`'s service,
paired locally with its `finished` and the pushes naming its call; the host sends no label.

Nothing is broadcast: a record's content leaves a host only when a reader asks for it and may see it; any other admitted node asking gets its hash link.

## 9. Keystore (`$WIRES_HOME`, else `$XDG_CONFIG_HOME/wires`, else `~/.config/wires`)

| File | Mode | Holder | Content |
|---|---|---|---|
| `root.seed`, `node.seed` | 0600 | admin / every node | hex Ed25519 seed |
| `issued.json` | 0600 | admin | the ledger of badges it minted: node → label (for `remove` and `service --host`), latest `not_after` (how long a ban must last); never sent |
| `membership.json` | 0644 | every node | its badge (membership token) |
| `policy.json` (+ `.lock`) | 0600 | admin, host, directory | the newest verified signed policy (§3); **a caller holds none** |
| `view.json` | 0600 | caller (any node that calls) | its view: the head, the root-signed entries it may call or read, the newest `Fresh`, when a directory last vouched, the newest head a host reported (§4 *Views*) |
| `directories.json` | 0600 | every joined node | the invite's directory ids: where to ask before a head names them |
| `login.json` | 0600 | every joined node | the invite's login settings: issuer, client id, public client secret (`wires login`'s defaults) |
| `login-client.json` | 0600 | admin | which trusted IdP invites name, and each client's public secret; never signed, never published |
| `fresh.json` | 0600 | host | the newest `Fresh` for the held head (§4 *Freshness at the host*) |
| `directory.redb` | 0600 | directory | the directory's heads, items and latest `Fresh` (§4) |
| `idp-token.jwt`, `idp-refresh-token` | 0600 | caller | from `wires login` |
| `last-good.json` | 0600 | caller | service → the host that last answered |
| `hints` | — | any node | optional local dial hints (below) |
| `tools.json` | — | caller | locked mode; optional aliases |
| `inbox/` | 0700 | caller | `new/` (≤256 unread), `read/` (last 1024), `notes/` |
| `record-marks.json` | — | reader | `wires watch`: per host, the chain anchor, a resume point per view, recent call labels |
| `call-log.jsonl`, `push-queue.json` | — | host | §8, §7 |
| `gateway-client-key`, `gateway-sessions.json` | 0600 | web gateway | the key DCR client ids are MAC'd with; live web sessions keyed by token hash |
| `jwks/` | — | caller | cached issuer keys (a host never reads it, §6) |
| `run/serve.sock`, `run/hint` | 0600 | host | the operator's push socket; this host's own hint line |

The child socket for a call's push capability is not in the keystore: it lives in a private
directory `serve` makes per run (§7).

A host's or directory's keystore must not hold `root.seed`: `wires serve` and `wires directory
serve` refuse to start from the admin's keystore. Run each from its own (`WIRES_HOME=<dir> wires
id`, invite that node, join there).

**The seed in memory** (`library::NodeIdentity`). A loaded seed lives in a private field. It is
scrubbed when the identity drops, and the type has no `Clone`, `Debug` or `Serialize` (compile-fail
doctests hold this), so no code copies, logs or encodes it by accident. A second owner is an
explicit `duplicate()`; the raw seed comes out only through `expose_seed()`/`expose_seed_hex()`, as
copies scrubbed on drop. Reading `node.seed` and writing it both go through scrubbed buffers. This
guards against accidents in safe Rust, not against code in the same process: `unsafe` code, a
foreign-language runtime, a debugger running as the same user, or a core dump can read the key.
Rust moves can also leave stale stack copies that nothing scrubs. A seed passed by flag or
environment variable also stays in the process's argv or environment.

**Hints** (`wires/caller/pick.rs`). `$WIRES_HOME/hints` is local and unsigned: one line per node,
`<node id hex> <ip:port>…`, `#` comments, bad lines skipped. Every endpoint `wires` binds registers
it beside n0 discovery, so calls, directory requests, push and fetches all use it. `serve` writes its own line
to `run/hint`. A hint only says where to try; iroh still authenticates the key.

Every file above is written atomically: a temporary file created `O_EXCL` with mode 0600, widened
to the listed mode (only `membership.json`'s 0644) after the write, then renamed over the target. A
file with no listed mode is 0600. The keystore directory the policy store creates is 0700.
`directory.redb` is redb's own file.

Flags, environment variables and `--…-file` paths override the keystore, in that order of
precedence. Locked mode (`WIRES_LOCKED`) refuses the credential flags and the `WIRES_NODE_SEED` /
`WIRES_MEMBERSHIP` variables; it assumes the agent can't set its own environment.

## 10. Known limits

The full list, kept in one place, is [usage.md § Known trade-offs](usage.md#known-trade-offs). The
ones that bound this spec:

- Nothing renews memberships (30 days) or the policy head (90 days by default); an expired policy
  admits nobody, is served by no directory, and is dialed from by no caller.
- A host follows one directory at a time (the others are failover it dials only when that one
  is gone), and a host newly listed as a directory runs the directory mode only after a restart.
  Under `lenient`, a lapse shows only in the host's trace, not yet in `wires watch`.
- A caller holds only its view (card 37), but hosts and directories hold the whole policy (roles,
  services, host ids, bans, issuers, directories), and a directory sees who asks for which view
  (it traces, not logs, the requests). A directory can withhold an entry from a view, or serve a
  stale one within `Fresh`'s bound; the host still decides every call. A removed host whose badge
  hasn't expired still sees the argv of a caller whose view predates the removal. A caller's own
  records of a service no longer in its view (a revoked grant) are no longer its to read with
  `wires watch`. Until [card 09](board/backlog/09-witness.md): hidden record links (§8) tell a
  non-reader how many entries a host logged, and when.
- A host knows a caller's identity only once the caller presented its token to that host.
- A host can withhold or truncate its own log (§8).
- One network per keystore.

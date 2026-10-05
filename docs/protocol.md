# The wires protocol

This document describes the protocol as the code implements it today: `library/` (pure types and
codecs) and `wires/` (the iroh transport and CLI).

**What outranks what.** The premise outranks this document, and this document outranks the code.
The premise: an agent runs a CLI that lives on another machine as if it were local; the caller is
a person the IdP verified, who sees and can call only the services the admin-signed policy grants
them; the machine is reached by key, with no port or VPN; and a service can message its caller
back. If the code disagrees with this document, the code is the bug, unless this document breaks
the premise, in which case both are fixed. What the premise needs and the code doesn't do yet is
listed in §9.

The architecture around it (who runs what, what each node keeps, and how each kind of metadata
moves) is [fabric.md](fabric.md). Usage, roles and the demo are in [usage.md](usage.md), [the board](board/README.md) and
[demo.md](demo.md). Deployment and testing are in [deployment.md](deployment.md) and
[testing.md](testing.md).

## 1. Ground rules

| Rule | Where |
|---|---|
| A node is an Ed25519 key, and `NodeId` is its 32-byte public key. The iroh `SecretKey` is the same seed, so the iroh endpoint id **is** the `NodeId`. | `library/network/identity.rs`, `transport::secret_key` |
| **The caller is always `to_node_id(conn.remote_id())`**, the key iroh authenticated. It is never a wire field. Every gate below is sound only because of this. | every gate |
| A network is named by its root key: the `fabric` field every signed object signs is `root.node_id()`, and the network string (§2) names the same key. | `Policy::new`, `Network` |
| Signed objects sign a domain-separation prefix followed by `canonical_bytes(body)`: canonical JSON with keys sorted by `serde_json`'s default `BTreeMap` ordering. `preserve_order` and `arbitrary_precision` must never be enabled. | `library/codec.rs` |
| Every signed body carries a signed format discriminant and a fixed, complete set of fields. **An optional signed field is not allowed**, because an absent field and a present default sign different bytes; "none" is an empty value. A new format gets a separate body, and an old verifier rejects it with `UnsupportedVersion`. Signed types refuse unknown fields at decode. | policy head (its format covers the items), service entry, `Fresh` |
| Every signed object signs its network's root key (`fabric`): the head's and an entry's `verify(root)` require `fabric == root`, and `Fresh::verify(head)` requires the head's `fabric`. | policy head, service entry, `Fresh` |
| A changed wire format gets a new discriminant: a new frame tag or a new ALPN. Nothing reads an older format, and no keystore file of an older format is read: an old input fails with the ordinary parse or version error. | all codecs |
| Tokens are base64url-no-pad of canonical JSON. Wire frames are a 4-byte big-endian length followed by a body; the length is checked before the body is allocated. Frame envelopes are unsigned, so `skip_serializing_if` is safe in them. | all codecs |
| `alg` is always `ed25519` (`AlgorithmId::Ed25519`). `not_after` is inclusive, and a credential is expired when `now > not_after`. Times are unix seconds, except `*_ms` fields. | all |

Every node binds one iroh endpoint (`presets::N0`: n0 DNS/pkarr discovery and relays) and is dialed
**by key**. Addresses are never authority; see §8 for the optional local hints file.

## 2. Admission

**No node holds a credential the admin minted for it.** A person is admitted by their IdP, a
machine by the root-signed policy naming its key, and a policy by the root's signature.

| Who | Is admitted by | Checked where |
|---|---|---|
| **a caller** (any node acting for a person: `wires call`, `wires mcp`, `wires inbox`, the gateway for each web user) | an **ID token** (§6) from an issuer the held policy trusts, with an accepted audience, unexpired, whose `nonce` binds it to the iroh-authenticated key; and `check_admitted`: the token carries a **verified email**, the policy bans neither that node nor that person (§3 *Bans*), and **some role in the policy matches the person** | the session gate (§5), an inbox fetch (§7), every directory request and subscription that isn't a named node's (§4) |
| **a host**, to a caller | its key is in the root-signed entry of the service being called (from the caller's view, or the newer one the host sends in its `HelloAck`), and iroh authenticated that key | the caller, before stdin (§5) |
| **a host or a directory**, to a directory | the held policy names its key: as a host of some service (`Policy::is_host`) or in the head's `directories`, and does not ban it | the directory's `policy` request and subscriptions (§4) |
| **a directory**, to anyone | the root-signed head lists it, and its `Fresh` is signed by that key | `Fresh::verify` (§4) |
| **a policy** | it verifies under the root (`SignedPolicy::verify`), is fresh, and is newer than the one held | a directory's `publish`, every copy (`adopt_if_newer`, §3) |
| **a host delivering a push**, to a caller's inbox | it hosts a service in the caller's view | the caller's `wires inbox --wait` (§7) |

**You are in the network if a role matches you.** `check_admitted(policy, caller, principal)`
(`library/network/admission.rs`) is the one function that decides it, at every gate, in order:
`Banned` when the policy bans the node `caller`; `NoVerifiedEmail` when the principal carries no
verified email (§6); `Banned` when the policy bans the person (issuer and verified email); `NoRole`
when no role in the policy matches the principal (§3 *Roles*); else `Ok`. It assumes the principal
was verified for `caller` (the token's nonce binds it to the key iroh authenticated). So a caller
with no token is admitted nowhere (a host refuses it at the first message), and neither is a
person the IdP verified whom no role names: with a public OAuth client anyone with an account at
the IdP can get a token that verifies, and that alone admits nobody. Every refusal of admission,
from a host or a directory, is the one fixed text `not admitted to this network: sign in with
\`wires login\`, or ask your admin for a role` (`NOT_ADMITTED`); the reason goes only to the
host's or directory's trace (a host says instead when a token has only expired or the IdP is
unreachable, §5). A signed-in caller that hears it says what its person can act on (§5 *The
caller*).

**The network string** (`library/network/network.rs`) is everything a new node needs:
`Network { format: 1, root: NodeId, directories: [NodeId], login: LoginSettings { issuer,
client_id, public_client_secret? } }`, encoded as a token (base64url of canonical JSON). The
directories are the first two of the head's (`NETWORK_MAX_DIRECTORIES`): where a node asks for the
policy or its view, until it holds a head that names them all. The login settings are what `wires
login` signs in with: the issuer the admin chose (`init`, or `issuer set --login`), its `client_id`
from the policy's `issuer` item, and the client's public secret when the admin gave one (never a
confidential secret). The string is unsigned, the same for every node, and **not secret**: it can
sit in a wiki. It introduces the root, so it is **trust on first use**: whatever carried it out of
band vouches for the admin (see [card 18](board/backlog/18-front-door-OPEN.md)). `wires network`
prints it: the admin's is built from its policy and `login-client.json`, any joined node's is the
one it stored.

- **`wires join <network>`** stores it (`network.json`) and contacts nobody: what a host or a
  directory runs (they act for no person). It makes the node key first if there is none. Joining a
  keystore that holds another network's string is refused (one network per keystore), and so is
  the admin's own (its root key names its network); joining the same one again rewrites it.
- **`wires login <network>`** joins the same way, then signs in (§6) and asks a directory for the
  view: a caller's whole onboarding. A later sign-in is a bare `wires login`.

## 3. The admin-signed policy

One versioned policy, signed by the root, says everything the network agrees on: the trusted IdPs,
the roles, the services and which hosts run each, the bans, the settings, and which nodes are
directories. **The root signs the policy, and each service entry**: a
root-signed **head** over **items**, where each service item is also signed by the root on its own
(`library/services/{head,item,entry,signed_policy}.rs`):

```
PolicyHead { format: 4, fabric, version: StateVersion(u64), issued, not_after,   // version: +1 per edit
             directories: [NodeId], items_hash: ItemsHash }
SignedPolicyHead { head, alg, sig }
SignedEntry { format: 2, fabric, version, name: ServiceName,
              service: Service { description, allow: [RoleName], hosts: [NodeId] },
              alg, sig }
Item = role       { key: RoleName,    body: [Matcher] }
     | service    SignedEntry          // {"kind": "service", ...the entry's fields}
     | ban        { key: NodeId }                       // a removed node
     | person_ban { key: Person { issuer, email } }     // a removed person
     | issuer     { key: Issuer,      body: { client_id, audiences: [Audience] } }
     | settings   {                   body: { freshness, beat_secs, fresh_secs } }
SignedPolicy { head: SignedPolicyHead, items: [Item] }   // items sorted by (kind, key), each key once
```

- **Signed bytes:** the head signs `"wires/policy-head/v1\0"` followed by canonical JSON of
  `{alg, head}`. `items_hash` is blake3 of `"wires/policy-items/v1\0"` ‖ the canonical JSON array
  of the items, in key order, so one signature covers the whole set: no item can be changed,
  dropped, added, or taken from another version. A service entry signs `"wires/service-entry/v1\0"`
  ‖ canonical JSON of every field but `sig`. The prefixes separate them from each other and from
  `Fresh` (§4). A head of format 3 (whose bans carried an `until`) is refused
  (`UnsupportedVersion`), as is a format 1 service entry.
- **An entry's `version`** is the policy version at which it last changed. An edit re-signs only
  the entries it changes (`Policy::sign_after` the stored policy); the others keep their signature
  and version. So a caller holding a subset of entries (its view) can check each one alone
  against the root, and keep the newest version of each.
- **`SignedPolicy::verify(root)`**, the one check for a whole policy: the head's algorithm,
  format 4, the `fabric == root` pin and signature; the items are strictly in key order and hash to
  `items_hash` (`ItemsMismatch`); every service entry verifies on its own under the root, at a
  version no later than the head's; then `Policy::validate`. **`check_fresh(now)`**: `Expired`
  when `now > not_after`. An expired policy admits nobody until the admin signs a newer one.
- **Updates** (`library/services/policy_update.rs`). `PolicyUpdate { head, changed: [Item],
  removed: [ItemKey] }` moves a whole policy to a newer head: `new.update_from(&old)` computes it,
  `old.apply(&update, root)` rebuilds the item set (held + changed − removed), recomputes the hash
  and checks the new head's signature and each changed entry. Any mismatch (an item tampered with,
  withheld or added, an older head) is an error, and the holder asks for the whole policy. A
  **view** (`library/services/view.rs`) is `{head, entries: [SignedEntry]}`: the services a caller
  may call, each verifying alone; `SignedPolicy::view_for(node, principal, query)` cuts it (empty
  when the policy bans the node or the person, or no role matches), and `View::apply(ViewUpdate {head, changed:
  [SignedEntry], removed: [ServiceName]}, root)` refuses an entry older than the one held.
- **`Policy::validate`** (run by `sign` and `verify`): no directory listed twice; every role has
  at least one matcher, and **every matcher names an issuer that has an `issuer` item**; every
  issuer is non-blank and accepts at least one non-blank audience; every role a service's `allow`
  names is defined (there is no built-in role); every service host is listed once and
  is not banned; no banned node is a directory; every person ban names a non-blank issuer and a
  non-blank, lowercase email; `settings.beat_secs > 0` and `fresh_secs >= beat_secs`.
- **Hosts are derived.** A host is a node some service's `hosts` names (`Policy::hosts`); there is
  no host list. `is_host` and `assigns(service, host)` are false for a banned node.
- **Bans.** A `ban` item names a removed node; a `person_ban` item names a removed person by
  issuer and email. Neither expires: a ban holds until the admin lifts it (`wires restore`). A
  banned person is refused by every host and every directory from any node (`Policy::bans_person`).
  **Removing a person is a person ban**: a node ban doesn't keep a person out, since a new key is
  one `WIRES_HOME` away. A node ban removes a host or directory machine, or one specific key: that
  node is admitted nowhere this policy is held, whoever signs in on it (`Policy::bans_node`). A
  person ban matches a principal whose issuer is exactly the ban's and whose **verified** email
  (`email_verified`, §6) equals the ban's, ignoring ASCII case. A principal with no verified email
  matches no person ban, and so it can't sidestep one: admission requires a verified email (§2).
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
- **Versioning.** Every admin edit (`init`, `remove`, `restore`, `service`, `role`, `issuer`,
  `directory add|rm`, `policy settings`) is the stored policy changed, `version + 1`, `issued =
  now`, `not_after = max(now + --policy-ttl, the stored policy's not_after)` (default `90d`: an
  edit never shortens the policy's life; a directory's `Fresh`, not the head's expiry, is what says
  a copy is current), re-signed.
- **Monotonic copies.** Every node that holds the policy (the admin, hosts, directories) keeps its
  newest verified copy in `policy.json`, written only
  through `adopt_if_newer(ks, candidate, root, now)`: the candidate must verify, be fresh, and be
  strictly newer (same network, higher version). The re-read, check and write happen under one
  exclusive file lock (`policy.json.lock`), so a removed node presenting a genuine older policy
  (one from before its ban) can't roll a node back.
- **Names.** `ServiceName` is `[a-z][a-z0-9_-]*`, at most 64 bytes; the session's `Invocation`
  names one. `RoleName` is 1–64 of `[A-Za-z0-9_.-]`.
- **Roles.** A role is an OR of matchers; a matcher is an AND of its keys over the caller's verified
  IdP principal: `issuer` (exact, **required**, and trusted by an `issuer` item), `email` (an address,
  or `*@domain` for exactly that domain, ignoring ASCII case), `org` (Google's `hd`, ignoring ASCII
  case), `group` (exact). Because every matcher names its issuer, a token
  another trusted issuer minted for the same email never satisfies it. `issuer=…` alone is "anyone
  that IdP verified" (who carries a verified email). There is no built-in role: **with no verified
  principal, or one with no verified email, no role admits** (`role_admits`).
- **`authorize(policy, caller, principal, service)`** (`library/services/access.rs`), in order:
  neither the node nor the person is banned (`Banned`; the session gate checked this before, so this
  is a second guard); the service exists (`UnknownService`); it allows some role
  (`NobodyAllowed`); the first role in `allow` that admits the caller's verified principal is
  returned (`NotInRole`). A host's gate runs it on every call; the caller hears one sentence for the three refusals after
  `Banned`, and only the host's trace tells them apart (§5); a caller never runs it (it holds no roles): what it may
  use is its view (§4 *Views*).

The policy is not secret from the machines the admin placed: directories and hosts hold all of it
(host node ids, banned node ids and people, role matchers, trusted IdPs, service names and
descriptions, the directories), and so does the admin. **A caller holds only its view**
(§4): the root-signed entries of the services its verified person may call, and the head. No role,
no ban, no other service, and no node id but its services' hosts and the directories.

### Admin surface

The admin commands and their flags are in [usage.md § Commands by role](usage.md#commands-by-role).

- **`init`** makes the root key and the admin's node key and signs version 1: one `issuer` item
  (`--issuer`, default `https://accounts.google.com`; `--client-id`, else `$WIRES_OIDC_CLIENT_ID`,
  required; `--audience`, repeatable, default the client id), the default settings, no roles, no
  services, no bans, no directories. That issuer is the one the network string tells `wires login`
  to use; `--public-client-secret` records its client's **public** secret (a Google "Desktop app"
  client's) for the network string to carry. Nothing is published: there is no directory yet.
- **`network`** prints the network string (§2). On the admin it is built from the stored policy
  (the head's first two directories) and `login-client.json`; with no directory listed yet it
  still prints, and says on stderr that a node can't reach the policy through it until `directory
  add`. On any other node it prints the string `join` or `login` stored.
- **Labels.** Wherever the admin first names a node it may write `label=<node id>` (`directory add
  workbench=3ef7…`, `service add … --host workbench=3ef7…`); afterwards the bare label names it.
  A label is 1–64 of `[A-Za-z0-9_.-]`, is not itself a node id, and holds no `@`. Labels live in
  the admin's `labels.json` (§8), never in the policy: nothing on the wire carries one. Binding a
  label already bound to another node is refused; a bare 64-hex node id is always accepted.
- **`issuer set <iss> --client-id <id> [--audience <aud>]… [--public-client-secret S] [--login]`**
  trusts an IdP (or changes one); `--login` makes it the one the network string names. **`issuer
  rm <iss>`** stops trusting one, refused while a role's matcher names it or a person ban does.
  Which issuer the network string names, and each public secret, stay in the admin's keystore
  (`login-client.json`, §8), not in the signed policy: every host holds the policy, and none needs
  them.
- **`directory add <node>`** lists an unbanned node in the head's `directories` (once);
  **`directory rm <node>`** drops it. `add` says the node's next steps (the network string changed
  if this is one of the first two directories: `wires network` prints the new one): on a node that
  hosts a service, restart `wires serve`; on any other, `wires join <network>` there, then `wires
  serve` or `wires directory serve`, which starts empty and takes the policy from the admin's next
  publish.
- An edit on an admin that holds no `policy.json` is refused, naming the way back: it would sign a
  version 1 that every directory already holds newer. Copy `policy.json` from any host or directory
  (it verifies under the root on the way in).
- **`remove <who>`**: an email is a **person ban** (`--issuer`, default the issuer the network
  string names; the email is stored lowercase); a node id or label is a **node ban**, and the node
  is also dropped from every service's `hosts` and from `directories`. Removing someone already
  banned is refused, and so are a person under an issuer the policy doesn't trust and the admin's
  own node.
- **`restore <who>`** lifts a person or node ban. Refused when there is none. A restored node is
  not put back into any service's `hosts` or the `directories`: the admin adds it again.
- **`role`** and **`service`** edit the roles and the services; a `--host` is a node id or label,
  and not banned. **`role set`**'s `--issuer` (the issuer of a matcher that names none) defaults to
  the issuer the network string names.
- **`policy settings [--freshness lenient|strict] [--beat-secs N] [--fresh-secs N]`** edits the
  settings item; with no flag it prints the settings and edits nothing.

Every edit takes `--policy-ttl`, and every edit but `init` ends with the publish in §4. `wires policy push` changes nothing:
it re-publishes the stored policy to every directory.

## 4. The directory: `wires/directory/2` and `wires/directory-sub/2`

A **directory** is a node the head lists in `directories` (`wires/directory/`). It holds the newest
policy, signs a freshness timestamp for it, takes a newer policy from any publisher, follows the
other directories, and answers hosts and callers. **It never decides a call**: hosts decide from
their own copy, so calls keep working with every directory down. It is trusted for availability and
freshness only; everything it serves is root-signed.

`wires serve` runs it on the same endpoint when the policy it holds at start lists its node, or,
holding no policy yet, when its network string lists its node. `wires directory serve` runs it
alone, on a node with no `host.json`, under the same rule, and refuses the admin's keystore (one
holding `root.seed`), a keystore that joined no network, and a node neither lists.

**The first publish.** The first directory starts **empty**: it holds no policy, signs no `Fresh`,
admits nobody (no node is named, no issuer trusted), and answers every request but `publish`, and
every subscription, with ``this directory holds no policy yet: it is waiting for the admin's first
publish (`wires policy push`)``. It traces, once, that it is waiting for that publish (`wires policy push`, or the next
admin edit). A
`wires serve` whose directory is empty serves the directory at once and decides no call (`host
configuration error`) until a publish arrives that assigns its services; then it starts deciding,
with no restart. That is the network's one bootstrap step.

**Freshness.** A directory signs `Fresh { format: 1, fabric, directory, version, head: HeadHash,
at, until, alg, sig }` with its own node key over `"wires/fresh/v1\0"` ‖ canonical JSON of the
other fields: at open, on every head it accepts, and every `settings.beat_secs`, valid for
`settings.fresh_secs` (`until = at + fresh_secs`). `HeadHash` is blake3 of the signed head's
canonical JSON, so a `Fresh` vouches for one exact head. It is valid only because the root-signed
head lists its signer (`Fresh::verify` refuses any other key, `NotADirectory`). A directory whose
held head doesn't list it signs none and answers `policy` and views with a refusal.

**The store** (`directory.redb`, in the directory's keystore; redb):

| Table | Key → value |
|---|---|
| `heads` | version → the signed head and its items' content-hash keys, in order (the last 16 kept) |
| `items` | content hash (blake3 of the item's JSON) → the item (dropped when no kept head names it) |
| `meta` | `version` (the newest head's) |

One writer, many readers. A policy is stored only if it is strictly newer, in one transaction. A
restart reloads the newest head and signs a new `Fresh` (a `Fresh` is kept in memory only; a beat
writes nothing to disk). A directory whose newest head has expired signs no `Fresh`, admits nobody
and answers every request with `this directory holds only an expired policy (version N); try
again later`, until the admin publishes a newer one. When the node's own `policy.json` is
newer (it fetched one as a host), the store is seeded from it.

**Accepting a policy** (`Directory::accept`): `SignedPolicy::verify` under the root (§3), the head
fresh, strictly newer than the held head. Then it is stored, adopted into the directory node's own
`policy.json` (so a host that is also a directory decides under what it serves), a `Fresh` is
signed for it, and subscribers are woken. An older or equal one changes nothing.

**`wires/directory/2`.** Frames are a 4-byte length then canonical JSON tagged by `type`
(`library/directory/frames.rs`). Every request frame, the `hello` included, is at most 16 KiB;
only a publish's `items` frame (at most 16 MiB) is larger, and it is read only after the head it
belongs to verified. One request per connection: the dialer sends `hello {id_token?}` then one
request, and gets one answer (5 s to dial, 10 s per frame).

- **Admission first** (`Directory::admit`), under the held policy. The peer is **named** when the
  policy names its key as a host or a directory and doesn't ban it (a key, never a token); it is an
  admitted **caller** when its `id_token` verifies (§6: the held policy's `issuer` items and their
  audiences, the IdP's keys fetched and held in memory only, the nonce bound to the
  iroh-authenticated key, unexpired) **and** `check_admitted` passes (§2: a verified email, no ban
  on the node or the person, a role that matches). Either is admitted (a named node may present a
  token too; one that isn't admitted only means the named node holds no principal). Anyone else is
  a **publisher at most**: it may send only a `publish`, and any other request hears `NOT_ADMITTED`
  (§2), traced, throttled, logged nowhere: a stranger, a person the IdP verified whom no role
  names, and a banned person all hear the same bytes. With no policy held, nobody is named and no
  issuer is trusted, so only a publish is taken (anything else hears that the directory is empty,
  above). At most 16 connections, on both ALPNs together,
  are undecided at once (one more is closed unanswered): from the connection until its `hello` is
  decided (and, for a peer not admitted, until its one request is read and a publish's head
  checked); the stream must open within 10 s, and the
  `hello` arrive within 10 s after that. An admitted peer (or a publisher whose head verified, is fresh and is newer) gives up its undecided slot at
  once and takes one of 64 slots for admitted work (reading and answering its request, or reading
  its `subscribe`); one more hears `denied` (`this directory is busy; try again or ask another`).
- `publish {head}` then `items {items}`: from anyone. The directory checks the **head** first: it
  verifies under the root, it is fresh, and it is newer than the held head. If it isn't newer, the
  directory answers `published {version, head}` with what it holds, reading no items. If it doesn't
  verify, `denied {reason}`. Only a newer, root-signed head makes the directory read the `items`
  frame; then the whole policy is accepted as above (its items must hash to that head's
  `items_hash`) and it answers `published {version, head}`: the version it now holds and that
  head's `HeadHash`. The admin publishes this way, as a stranger: the root's signature is the
  whole check.
- `policy {have}`: the whole policy, **only for a named node** (anyone else hears `denied`: `the
  whole policy is for the network's hosts and directories; a caller asks for its view`): `current
  {fresh}` when `have` is the newest (or newer than the directory's); `policy_update {update,
  fresh}`, the `PolicyUpdate` from the head at `have` (`update_from` against the head kept in
  `directory.redb`), when `have` is one of the 16 kept heads; else the whole `policy {policy,
  fresh}` (`have` 0, too old, or unknown).
- `view {have, query?, held?}` and `resolve {service}`: a caller's view, below.

**Views.** The directory cuts a view from the held policy for the principal the caller's
`hello` token verified as (above), `SignedPolicy::view_for(caller, principal, query)`: the
root-signed service entries whose `allow` has a role admitting the principal. A banned or unknown
person never gets this far: admission refused them (`NOT_ADMITTED`). A named node with no admitted
principal gets the empty view. Nothing per user is stored, and a request is only
traced: a view grants nothing, and the host decides every call.

- `view {have, query: none, held?}`: `held` is the `ViewDigest` of the view the caller holds
  (blake3 over `"wires/view-digest/v1\0"` ‖ the view's canonical JSON). With a verified principal
  and a `held` that names exactly the view the directory would diff from: `current {fresh}` when
  `have` is the newest and `held` is the view now; a `view_update {update, fresh}` (`ViewUpdate
  {head, changed: [SignedEntry], removed: [ServiceName]}`, the principal's view at the kept head
  `have` diffed against the view now) when `have` is one of the kept heads and `held` is the view
  at it. Anything else gets the whole `view {view, fresh}`: no `held`, or one that doesn't match (a
  view cut for another identity).
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

**`wires/directory-sub/2`.** The dialer sends `hello`, then `subscribe {kind, have}`, where `kind`
is `policy` (a host), `replica` (another directory) or `view` (a long-running caller). Admission is
the `hello`'s, as above, except that a publisher is refused here (`NOT_ADMITTED`). **Two pools, so
callers can't exhaust hosts' subscriptions:** at most 4,096 `policy` and `replica` subscribers
(nodes the policy names), and, apart, at most 4,096 `view` subscribers (`wires directory serve
--max-subscribers N` sets both); within the view pool, at most 16 at once for one person (issuer
and subject: the gateway holds one per web user from its one node, so the cap is per person, not
per node). One more is refused with `denied` (`this directory's subscriber cap (N) is reached`, or
`you have 16 view subscriptions open here already`).

- **`policy`**, only from a named node (anyone else hears the `denied` above). The first frame
  comes at once: `fresh {fresh}` when `have` is the newest, else what `policy {have}` would answer
  (`policy_update {update, fresh}` from a kept head, or the whole `policy {policy, fresh}`). Then,
  for every head the directory adopts (a publish, or a replica catching up), one `policy_update`
  from the version the subscriber was last sent, and a `fresh` beat every `settings.beat_secs` in
  between. A subscriber ahead of the directory gets nothing until the directory catches up.
  Subscribers at one version share one encoded frame, so a publish costs the directory one diff per
  version its subscribers hold, not one per subscriber. The stream ends with `denied` when the head
  stops listing this node (it can no longer vouch), and when a head bans the subscriber
  (`NOT_ADMITTED`) or no longer names it as a host or a directory (the refusal above).
- **`replica`**, only from a node the held head lists as a directory: `policy {policy, fresh}`
  when the held version is newer than `have`, else `fresh {fresh}`; then the same on every
  change. It ends with `denied` if the subscriber stops being listed.
- **`view`**, only from an admitted caller, for the principal its `hello`'s ID token verified as
  when the subscription opens (`wires/directory/sub_view.rs`): the whole `view {view, fresh}`
  first, whatever `have` says (the directory keeps nothing per subscriber, so it can't know which
  view a `have` refers to); then, for every head it adopts, a `view_update {update, fresh}` against
  the view it sent last, and a `fresh` beat in between. A subscriber that can't apply an update
  subscribes again and takes the whole view. The stream ends with `denied`: when the head stops
  listing this node; **when the ID token expires** (its `exp`: `your sign-in has expired; run
  \`wires login\``; the client subscribes again with the token it holds then); and **when a head
  it adopts no longer admits the subscriber** (`check_admitted`: the node or person banned, or no
  role matches any more), after a `view_update` that empties its view, with `NOT_ADMITTED`.
  `wires mcp`, each live gateway session and
  `wires inbox --wait` hold one (`wires/caller/view.rs`): the first frame within 10 s, then each
  within the held `Fresh`'s lifetime plus that again (at most 10 s) of slack, or the stream is
  taken for dead; a `denied`, at once or ending the stream, moves it to the next directory at once,
  and each round ends with a pause of 1 s, growing to 30 s while no directory serves.

**Replicas.** Each directory subscribes to every other directory its head lists, as `replica`,
reconnecting after a failure with a pause growing from 1 s to 30 s. A `policy` frame is taken when
its head verifies under the root, its `Fresh` vouches for that head, and it is newer; then it is
accepted as above. So a directory that missed a publish catches up from another. There is no
consensus: one author, and "newer" is a version number.

**Publish (admin).** After every admin edit, and on `wires policy push`, the admin dials,
concurrently, every directory the new head lists plus every directory the head before the edit
listed (so a directory the edit drops learns it), never itself, and sends `publish`. It dials no
host. A directory counts as delivered when it answers `published` with the offered version and the
offered head's `HeadHash`. Stderr says `policy version N: published to K of D directory(ies)`,
naming any not reached. **When D > 0 and K = 0 the command exits 1**: the new policy is stored on
the admin and nowhere else. `wires policy push` re-publishes it. With no directory listed at all,
the line says the policy is stored here and that `wires directory add` comes next, and nothing
fails. Two exceptions:

- **The first run.** Until a directory the publish aims at has taken one from this admin
  (`reached.json`, §8), reaching none is a note, and exits 0: `policy version N is stored here; no
  directory has taken a publish yet. Once one runs (wires join <network>, then wires serve or wires
  directory serve on its node), run wires policy push`. So starting a network (`init`, `directory
  add`, edits, the directory's `join` and `serve`, `policy push`) errors nowhere; from the first
  publish a directory takes, reaching none exits 1 as above.
- **A stale copy.** A directory answering a newer version, or another head at the offered one,
  kept its own: this admin's `policy.json` is behind and the edit changed nothing there. The
  command exits 1 whatever the other directories did, saying to copy `policy.json` from any host
  or directory and make the edit again.

**Following (hosts).** A running host subscribes as `policy` (`wires/host/follow.rs`) to the
first directory its held head lists that answers, never itself, trying the one it last followed
first and then the others in the head's order; the list is re-read from the held policy on every
reconnect (the network string's while it holds none), so a directory the admin adds is followed
without a restart. It takes each frame:

- `policy {policy, fresh}`: the head verifies under the root, the `Fresh` vouches for it, and
  `adopt_if_newer` takes it if newer;
- `policy_update {update, fresh}`: `SignedPolicy::apply(update, root)` on the held copy (the
  items' hash and the root's one signature on the new head, each changed entry's own signature),
  the `Fresh` vouches for the new head, then `adopt_if_newer`;
- `fresh {fresh}`: kept if it vouches for the held head (one for another version, from a directory
  behind this host, is skipped).

Any frame it can't take (an update that doesn't apply, a policy that doesn't verify) makes it
subscribe again at once with `have: 0` and take the whole policy; a second failure in a row moves
it on: the next round, after the pause below, starts at the next directory. So does a `denied`, at once or ending
the stream (not named, no longer a host, the directory no longer one, or busy): the next
directory is tried at once. When the stream ends (the directory stopped, or sent nothing for two
beats plus 10 s) it reconnects, pausing from 1 s up to the beat (at most 30 s) while none answers,
so a host every directory refuses asks each at most once per pause. The subscription never holds up serving: a host restarted with `policy.json`
decides from it before any directory answers. A host that is itself a directory keeps the `Fresh`
its own directory signs (its replica loop keeps its copy in step with the others). A host that the
policy newly lists as a directory runs the directory mode only after a restart (it traces so).

**Freshness at the host.** The host keeps the newest `Fresh` that vouches for its held head (by
version, then a current one over one that isn't current, then `until`: one from a directory
whose clock runs ahead never displaces a current one) in memory and in `fresh.json` (0600), read
back at start if it still vouches for the head on disk. Before it authorizes each call the gate asks whether a **current**
`Fresh` (`Fresh::is_current(now)`) names the exact head it decides under, and
`settings.freshness` decides when none does:

- **`lenient`** (default): decide under the held head as usual, until its `not_after`, and trace
  the lapse (a warning at most every 10 s; none when the head lists no directory). Calls never
  depend on a directory.
- **`strict`**: refuse the call with `this host's policy is stale: no directory has vouched for it
  recently; try again later` (exit 77 at the caller), until a current `Fresh` arrives; then serve
  again. A ban is then honoured on every host within `fresh_secs` of its publish reaching the directory
  that host follows (§9), at the cost of
  the directories becoming a dependency for calls. The refusal comes after admission (the ID token
  and the bans), so it is an admitted caller's refusal, traced like any other (§5): the host's
  log shows which calls it refused while it could not vouch for its policy.

Push decides under the held policy whatever its freshness.

**Fetch (a host's start).** `fetch` asks the directories the held head lists (the network string's
when it holds none), in order, never itself, for `policy {have}`, and stops at the first answer
that settles it:

- a `policy` whose `Fresh` verifies against **that** policy's head, and which `adopt_if_newer`
  takes (verified, fresh, newer), is adopted; so is the held policy with a `policy_update`
  applied, when its `Fresh` vouches for the result;
- `current {fresh}` counts only when the `Fresh` verifies against the **held** head and is current
  (`at` at most 60 s ahead, `now <= until`): this node is up to date.

Only those two settle it. A refusal, a `Fresh` from a key the head doesn't list, a lapsed one, or
an older policy doesn't, and the next directory is asked. So a lying directory can only fail to
help.

A `serve` that is not a directory and whose preflight fails (it holds no policy yet, or one from
before a service was assigned to it) fetches from a directory for at most 8 s and preflights
again; failing that, it exits with the preflight's reason and the likely causes (no directory running,
nothing published, or the service not assigned to it). While it serves it follows the subscription above. A node never adopts an older or
unverifiable policy.

**Callers keep their view current** (`wires/caller/view.rs`). A caller stores
`view.json` (§8): the view, the newest `Fresh` for its head, when a directory last vouched for it,
and the newest head version a host reported. The directories it asks are its view's head's (else
the network string's), never itself. A node that holds the whole policy (the admin's, a host's, a
directory's) cuts its own view from it instead of asking.

- **`wires login`** asks for the view under the new identity, forgetting the old one. `wires join`
  asks for nothing.
- **One-shot commands make little background traffic.** `wires call` and `wires inbox` dial from
  the view as it is, unless it is **stale** (last vouched for more than a day ago, its head
  expired, or a host reported a newer head) or missing: then they refresh first (8 s for all the
  directories together). A refresh that no directory answers leaves the view as it is, and the
  command dials from it (calls keep working with every directory down; an expired head is never
  dialed from). It learns of
  a newer policy in the call's handshake: `HelloAck` carries the host's head version, and when it
  is newer than the view's, the head and the called service's entry (§5). The caller then
  refreshes its view after the call (`view {have, held}`: an update from a kept head). A name the
  view doesn't hold is asked of a directory with `resolve` before the call fails. So on an
  unchanged policy, within a day of the last refresh, a call is the only connection.
- **"Stale" is a day only while a directory answers truthfully.** The directories a caller asks
  are its view's head's. If none answers, the caller keeps its view; and a machine the admin
  removed that was itself a directory the stale head lists can still answer `current` with a
  `Fresh` it signs for that old head (the old head lists it, so the `Fresh` verifies), resetting
  the day. So the hard bound on how long a caller may dial from an old view is **the view's head's
  `not_after`** (90 days by default, §3 *Versioning*), not a day.
- **`wires services`** reads `view.json`, refreshing first when it is stale (as above). When no
  directory gave it a view and one refused this node (`NOT_ADMITTED`), it lists nothing and says what the
  person can act on (§5 *The caller*).
- **Long-running callers subscribe** (`view` above): `wires mcp` (and sends MCP
  `notifications/tools/list_changed` when its tools change), one subscription per live gateway
  session (with that user's ID token; the gateway holds no policy), and `wires inbox --wait`. They
  keep `view.json` in step (the gateway's per-user views stay in memory).

## 5. Sessions: `wires/session/1`

A session is one bidirectional QUIC stream on ALPN `wires/session/1`. Codec:
`library/calls/session.rs`. Transport: `wires/host/transport.rs`.

| Tag | Frame | Body | Direction |
|---|---|---|---|
| 10 | `Hello` | canonical JSON `{state_version, id_token}` (`state_version`: the head version of the caller's view; `id_token`: required) | caller → host |
| 7 | `Invoke` | canonical JSON `Invocation {service, argv}` | caller → host, right after `Hello`, without waiting |
| 11 | `HelloAck` | canonical JSON `{state_version, head?, entry?}` (the host's own; `head` and `entry` only when its version is newer than the caller's) | host → caller |
| 6 | `Denied` | UTF-8 reason (at most 512 bytes) | host → caller, terminal |
| 1/2/3 | `Stdin`/`Stdout`/`Stderr` | raw chunk (at most 64 KiB when pumped) | stdin: caller → host; stdout/stderr: host → caller |
| 4 | `Exit` | i32, big-endian | host → caller, terminal |

Any other tag, 8 and 9 included, decodes as `BadFrame`.

**The host** reads `Hello` and `Invoke` (10 s each; at most 64 KiB, and 512 KiB: the largest valid
`Argv`, JSON-escaped), then re-reads its signed policy **for this connection**, so a
removal applies on the next dial without a restart. Before it knows who is asking it holds at most 64
sessions open (one more is closed unanswered), and it sizes no buffer larger than 64 KiB from a
length prefix. A first frame that isn't a readable `Hello` (a `Hello` without an `id_token` is
unreadable), or a second that isn't an `Invoke`, is refused (`Denied`) with a short fixed reason (`first frame
was not a hello`, `unreadable hello`, `timed out waiting for hello`, `invoke required`), traced as
a stranger's. Then the first failure below is sent as `Denied` (`wires/host/gate.rs`):

1. The host holds a readable policy (else `host configuration error`).
2. **Admission, before anything else:** the `id_token` is verified by the host itself (§6), bound
   to the iroh-authenticated caller, then `check_admitted(policy, caller, principal)` (§2: a
   verified email, neither the node nor the person banned, a role that matches). A caller whose
   token is malformed, from an untrusted issuer, for another audience or another key,
   carries no verified email, who is banned, or whom no role matches, hears only `NOT_ADMITTED`
   (§2): no reason, no policy version. Only an admitted caller's principal enters the host's
   identity index (§6). A token
   that verifies but has expired hears `your sign-in has expired; run \`wires login\``; a host
   that can't fetch the issuer's keys says `the identity provider is unreachable from this host;
   try again later`. All three are traced at `debug`, with at most one `info` line per 10 s
   counting them, so strangers can't flood the host's log; none writes a log line of its own.
   Every key can still connect: a stranger costs the host one token check (keys are fetched only
   for an issuer the policy trusts, an unknown `kid` refetches at most once per issuer per
   rate-limit window, and a fetch that failed is not retried within it, §6).
3. **The gate** (`ServicesHost::decide`, then `admit`): under `strict`, a current `Fresh` vouches for the held head (§4
   *Freshness at the host*) → the head hasn't expired → `authorize` (the service is in the policy and
   its `allow` admits the caller) → it is assigned to **this** host → every role in `host.json`'s
   `also_require` for it admits the caller too (it can only narrow; the refusal doesn't name those
   host-local roles). **A host tells an admitted caller nothing about services it may not call:**
   no such service, one nobody is allowed, and one whose `allow` doesn't admit this caller all hear
   the same bytes, `no service named \`<name>\` that you may call`, with no role name and no
   policy version; which it was goes to the host's trace at `debug` (`refused by the signed
   policy`). Only for a
   service the caller *is* allowed does it hear the specific refusals after it (`service <name> is
   not assigned to this host (signed policy version N)`, the `also_require` sentence).
4. **Implementation.** Only an admitted caller learns whether this host implements the service,
   in `host.json` or natively (`service … is not implemented on this host`).

**The host's log line.** wires keeps no record of a call beyond one ordinary `tracing` line at
`info` in `serve`'s own output (`wires/host/call_trace.rs`): when an admitted call ends (`call
finished`: service, caller node, the person's issuer, subject and email, role, exit code,
`duration_ms`, and `bytes_out`, the bytes of stdout and stderr sent to the caller), and when an
admitted caller is refused from step 3 on (`call refused`: the same, without role, exit, duration and
bytes, with the reason it was sent). No argv, no stdin, no token, nothing signed, no file of its
own; an operator who wants a record points a log collector at `serve`'s output.

The host then sends `HelloAck`
(when the caller's `state_version` is older: its root-signed head and the called service's root-signed entry) and execs the service's fixed argv
**with the caller's argv appended element by element, never through a shell** (after a `--` when
the service sets `end_of_options` in `host.json`, so a CLI that honours `--` takes none of the
caller's arguments as an option; it doesn't help a CLI that ignores `--`), in its `cwd`. The
child's environment is built from nothing (`env_clear`): only `PATH`, `LANG` and `LC_*` are
inherited from `serve`; then `host.json`'s `env`; then the server-derived values, which always win
(`host.json` can't set a `WIRES_*` name): `WIRES_CALLER_NODE` (the caller's node key, what push
addresses), `WIRES_ID_TOKEN` (the caller's ID token, byte for byte as presented in this call's
`Hello`), `WIRES_CALLER` (the claims the host verified from it, as one JSON object with the fields of
`Principal`: `issuer`, `subject`, `not_after`, and `email`, `org`, `groups` when present, §6),
`WIRES_SERVICE`, `WIRES_ROLE` and `WIRES_CALLER_EMAIL` (the verified email). Every admitted call
has a verified identity with a verified email (admission requires one, §2), so all six are always
set, and `WIRES_CALLER` always carries `email`. With `push` on, also
`WIRES_PUSH_SOCKET` and `WIRES_PUSH_TOKEN`, the call's push capability (§7). The child never gets `WIRES_HOME`, `HOME`, agent sockets or
cloud credentials. If the connection closes, the host kills the child.

The child still runs as `serve`'s own Unix user. It is told neither `WIRES_HOME` nor where the
operator socket is (its push socket lives outside the keystore, §7), but it can still find the
keystore at its default path, so a service a caller can steer into reading or writing files can
reach whatever that user can, the host's keystore and operator socket included. `wires` does not
switch users itself; the operator does
([deployment.md](deployment.md#run-services-as-a-separate-unix-user)). Independently of that, the host fails closed on the parts of its
keystore a child could tamper with: it keeps the highest policy version it has decided under in
memory and refuses to decide under an older `policy.json` (`host configuration error`, traced
as a rollback), and it trusts only issuer keys it fetched itself (§6).

**Native services** (`wires/host/native.rs`, `wires/host/embed.rs`). An app can embed
the host (`wires::Host::builder(<keystore dir>)`, `.service(name, impl wires::Service)`, `.serve()`)
and implement services in-process. The wire, the gate, the log line and the bridge are the ones above:
a native service is invoked by `Invoke`, reads the caller's stdin, writes stdout and stderr, and
its exit code is the call's. Callers can't tell it from a CLI. The handler runs as a tokio task
only after `HelloAck` is sent. It gets the verified caller as a type
(`Call`: `caller`, `id_token`, `principal`, `role`, `service`, `args`) in place of the `WIRES_*`
variables: `Call::id_token` is the token a child gets as `WIRES_ID_TOKEN`, and `Call::principal`
the value it gets as `WIRES_CALLER`. With push configured (`host.json` `push`, or the builder's `push_allow`), the host mints
the call's push capability as it does for a child and hands it over in-process:
`Call::push_to_caller(subject, body)` is checked against the same live-token registry (only this
call's caller, until the grace period after the call ends, §7), and goes through `push.allow`. If the connection closes (or the host stops), a Rust handler's task is
aborted at its next `.await` and the call exits -1; a Python or JavaScript handler can't be
aborted, so its next read or write fails instead. If a handler panics, the call exits -1. Either
way the host writes the call's log line, as for a child. `host.json`'s
`also_require` applies to CLI services only: a native service is gated by the signed policy alone,
and a handler wanting a stricter local rule checks `Call::role` or `Call::principal` itself. An
embedded host starts like `serve`: its keystore must have joined a network (`network.json`), the
signed policy must assign every service to it, CLI and native, and a name can't be both (`build`
refuses it). Its keystore, hints file included, is the
directory the app names; it reads neither `$WIRES_HOME` nor `$WIRES_NODE_SEED`. `serve_until`
returns once its shutdown future resolves and everything it started has stopped: the policy
subscription, the directory's loops (when it runs one), the protocol router with its sessions, and the
endpoint (closed). `Host::serve` is
`serve_until` Ctrl-C, which claims SIGINT process-wide; the bindings' `serve` doesn't listen for
it unless asked (`serve(handle_ctrl_c=True)`, `serve(true)`). The node
key lives in the app's memory (§8): a native service is the operator's own code, as trusted as
`serve`, so nothing isolates it from the key the way a child is kept away from it.
`bind_loopback()` binds the host's direct (IP) transport only on `127.0.0.1` and `::1`, with no
port mapping; callers elsewhere reach it through its relay. It exists for local demos: a host bound
so holds no network socket, so the macOS firewall doesn't prompt for an interpreter that can't be
signed. Other languages reach the same API through `wires-ffi` (UniFFI, Python; `bindings/`),
where a handler is a synchronous `call(call) -> int` on a thread of its own, and `wires-node`
(napi-rs, TypeScript; `bindings/node/`), where it is `(call) => number | Promise<number>` on
Node's event loop. In both, a handler that raises ends the call with exit 1 and the error on stderr.

**The caller** (`wires call`, `wires mcp`, the gateway) needs an ID token before it dials: with
none stored (and none presented, for the gateway), the call ends at once (exit 1, `not signed in:
run \`wires login\``), and nothing is sent. It dials from its view (§4 *Views*), refreshing it first
when it is stale or missing. When the refresh fails it dials from a stale view that hasn't
expired; with none, exit 1 (`wires login`, or ask the admin for `wires policy push`). It takes the service's hosts from the service's root-signed entry and orders them **at
random, afresh for each call**, so a service's calls spread across its hosts; the admin's order
means nothing. A host that failed to answer this caller's dial in the last 60 s goes last
(`unanswered.json`, the oldest failure first), so a host that is down costs each caller one dial
timeout a minute, not one in every few calls. A name the view doesn't hold is asked
of a directory (`resolve`); a name no directory resolves for this caller ends the call before any
dial (exit 1). The gateway dials from each user's subscribed view, and neither refreshes it nor
resolves a name. It moves to the next host **only when a dial fails** (10 s each); a host that
answered has decided. When a call is answered, the hosts tried before the one that answered are
recorded in `unanswered.json` and the one that answered is cleared from it; a call no host answered
records nothing (every host failing tells the order nothing).

**What stays on one host.** Hosts share the signed policy and nothing else, so the next call may
land on another host. What a host keeps between calls stays on it: whatever a native service
or the CLI holds in memory or on that machine's disk (the `kv` example's map is per host); the
callers whose identity it has verified (§7 *The identity rule*: a host learns a caller's identity
only from that caller's call or inbox fetch to it, so `wires push --to <role>` from one host
reaches only the callers who have called or fetched from it); and its push queue (§7). A push is
queued on the host that sent it, and `wires inbox` asks every host of the services in its view, so
random host choice loses no push; one queued on a host that is down waits there until it is back
or the push expires. [Card 31](board/backlog/31-inbox-delivery.md) is where a single delivery path
gets settled. It sends `Hello` and `Invoke` together, then, before it forwards a byte of
stdin, checks the host: the key it dialed (which iroh authenticated) is one the root-signed entry
lists, and, when the ack's `state_version` is newer than its view's, `HelloAck::assigns`: the head
verifies under the root at that version, and the service's entry verifies under the root, names
the called service, is no newer than the head, and still lists that host. If not, the call stops
there (exit 1, no stdin sent). After the call, a one-shot caller refreshes its view when the host
reported a newer head (§4).

The host already has the `Hello` (the caller's ID token) and the `Invoke` (argv) by then, and
`assigns` trusts the version the host reports. So a host the admin removed (dropped from the
service's `hosts`, or node-banned) still receives the token and argv of a caller whose view
predates the removal, and the stdin too if it understates its version; a caller holds no ban list.
The window per caller is its view's: a current view never names the removed host, and `wires call`
refreshes a view older than a day before dialing **when a directory answers**. With no directory
reachable, or when the removed machine was itself a directory the old head lists (it can vouch for
its own old head, §4 *Callers keep their view current*), the caller keeps its view, so the hard
bound is the view's head's `not_after` (90 days by default). Calls keep working with every
directory down; that is the trade.

**What a signed-in caller says when it is not admitted.** A host or directory says only
`NOT_ADMITTED`. A caller holding an ID token says what its person can act on, from its own token
(read locally, never sent anywhere else): `not admitted to this network: no role in this network
matches <email>, or you were removed: ask your admin`; for a token with no verified email, `not
admitted to this network: your sign-in carries no verified email, and this network admits only a
verified email: ask your admin`; for an expired one, `not admitted to this network: your sign-in
has expired; run \`wires login\``. `wires call` (exit 77), `wires mcp`'s tool result, `wires
inbox` (exit 1 when a directory said so and no view is held; 77 when every host refused),
`wires services` (exit 1) and `wires login` (right after a sign-in the network doesn't
admit; the sign-in itself is kept, exit 0) all say it. A refusal by a host also marks the
caller's view as behind, so the next `wires services`, `wires call` or `wires inbox` refreshes it
first.

Exit codes: `Denied` → **77**, nothing on stdout. Local or transport failure (including the checks
above) → 1. Otherwise the remote exit code, **except that a remote 77 is reported as 1** with a
note on stderr, so 77 always means the host refused. `wires call` exits 2 before dialing when its `--jq` filter
doesn't compile or locked mode refuses, and 2 when the remote exited 0 but shaping its output
failed. A session that ends without `Exit` is an error. Limits: 16 MiB largest frame once admitted (64 KiB `Hello` and 512 KiB `Invoke`
before); `Argv` holds at most 256 arguments and 64 KiB.

A `tools.json` alias pins a local name to one host (node id, optional addresses and relay) and,
optionally, the service to ask for (`remote_tool`, else the local name); it opens the same `Hello`, so the host still decides by its policy. A
service in the caller's view wins over an alias of the same name, and an alias is refused before
dialing unless the view's entry for that service lists its host.

## 6. Identity

`wires login` runs OIDC (authorization code, PKCE, loopback redirect) with `nonce =
base64url(blake3::derive_key("wires oidc-nonce v1", node_id))`, verifies the token locally, and
stores it in `idp-token.jwt`. Nothing is published. The token travels in the session `Hello`, the
inbox fetch's `hello` (§7) and the directory `hello` (§4). **It is the only credential a caller
presents**: it is what admits the caller (§2).

A host verifies it against the issuer's JWKS under the trust of the policy it decides under: the
policy's `issuer` items (§3), each with the audiences it accepts from that issuer, narrowed by
`host.json`'s optional `identity.issuers` (only the issuers it lists; for an entry that lists
`audiences`, only those of the policy's). `host.json` can't add an issuer or an audience. The trust
follows the policy: each time the host reads a newer one, it verifies under that one's issuers. `verify_claim` checks, in
order: `alg` is RS256 or ES256 and a JWKS key verifies the signature; `iss` matches exactly; an `aud`
value is accepted; `exp`, and `iat` when present, are within the 60 s clock skew; `nonce == for_node(caller)`.
`email` is used only when `email_verified` is true; `hd` becomes `org` only when `iss` is exactly
`https://accounts.google.com`; `groups` is kept. A host
remembers the latest verified principal per node (`wires/host/identity.rs`) and never lets a failure
or an older token displace it. It knows only the callers that presented a token **to it**, and a
node enters that index only once it was **admitted** (§2: its token verified and `check_admitted`
passed; a token that fails, or a person the policy doesn't admit, leaves no entry, so strangers and
outsiders can't grow it). A host fetches keys only for an issuer its policy trusts,
refetches on an unknown `kid` at most once per issuer per rate-limit window (60 s), doesn't retry a
failed discovery or key fetch within that window (its error stands, so an unreachable IdP costs one
fetch per issuer per window, not one per token), keeps issuer key sets
**in memory only** and never reads the `jwks/` disk cache, which anything running as its user could
write; callers keep that cache, and trust a disk entry for at most 24 h.

**What a service gets.** Every service the host runs for an admitted call gets the caller's raw ID
token and the claims verified from it (§5: `WIRES_ID_TOKEN` and `WIRES_CALLER` for a child,
`Call::id_token` and `Call::principal` natively), whoever presented it: the caller's own token from
`wires call` and `wires mcp`, the web user's from the gateway. There is no opt-in. The service need
not verify it again (the host checked the signature, the audience and the binding to the caller's
key); it may, or hand it to a token exchange. What that hands over:

- The token is a bearer credential until its `exp` (about an hour with Google). Inside wires it is
  bound to the caller's key and useless from any other node; outside wires, any relying party that
  accepts this OAuth client's audience would accept it. Every service the caller calls holds it, as
  the host already did.
- A child's environment is readable by other processes of the same Unix user
  (`/proc/<pid>/environ`): one more reason to run services as a separate user
  ([deployment.md](deployment.md#run-services-as-a-separate-unix-user)).
- A call through the web gateway carries a token minted under the gateway's OAuth client, so its
  `aud` differs from a `wires login` token's.

**A web gateway** (`wires gateway`) is one node that carries many principals and holds no
credential of its own: it joins with the network string (`wires join <network>`), asks the IdP for
each web user's ID token with `nonce = for_node(gateway)`, and presents that user's token in the
`Hello` of each call it makes for them. Nothing on the wire changes; the host sees a node
presenting a token bound to it. The gateway holds no policy: for each live session it
subscribes to that user's **view**, presenting the user's own ID token to a directory, which
verifies it and cuts the view (§4 *Views*); so it offers a user only services that a role admits
by that user's own verified principal, and a grant or revocation applies to their next request.
A web user the network doesn't admit is refused at sign-in (`access_denied` at the OAuth
callback, HTTP 403 at `/mcp`: `not admitted to this network: no role in this network matches this
account, or it was removed: ask your admin`; the email is left out because the text returns to the
MCP client). A node-banned gateway is refused by every host and every directory (`NOT_ADMITTED`). It
issues its own OAuth access tokens (opaque, bound to its
`/mcp`, expiring with the ID token) and no refresh tokens. Its MCP endpoint serves the 2026-07-28
Streamable HTTP binding and the legacy `initialize` era ([deployment.md](deployment.md)).

## 7. Push: `wires/inbox/3`

A host sends a `PushMessage { id, from, to, subject (≤128 B), body (≤16 KiB), at_ms, expires_ms }`
to a caller, addressed **by key**. Frames are length-prefixed canonical JSON tagged by `type`:
`hello {id_token?}`, `fetch {wait_ms}`, `deliver {messages ≤ 32}`, `ack {ids ≤ 32}` and
`denied {reason}`, at most 4 MiB; a `hello` (and a host's `fetch`) is read before the peer is known,
so it may be at most 64 KiB. Two ways a message is delivered:

- **Direct:** the host dials the recipient (3 s budget) and opens with `hello {}` (a host acts for
  no person). A running `wires inbox --wait` serves the inbox ALPN and accepts `deliver` only from a
  node that **hosts a service in its view** (it follows its view by subscription while it
  waits); any other dialer hears only `NOT_ADMITTED` (§2; the reason is traced,
  throttled).
- **Fetch:** `wires inbox` dials the hosts of every service in its view (`hello` with its stored ID
  token, `fetch` held open for up to 25 s with `--wait`, else answered at once, `deliver`, then `ack`), refreshing the view first when
  it is stale, as `wires call` does (§4 *Callers keep their view current*). With no token stored it
  fetches nothing and says to run `wires login`.

The host authorizes at send, at delivery and at fetch (`ServicesHost::decide_push`): the
recipient's node must not be banned by the current policy, nor the person it last verified as
here, and it must be in the first role of `host.json`'s `push.allow` that admits it
(default: nobody). **The identity rule:** every role needs the recipient's verified principal,
which the host learns only when the recipient presents its token to it: on a call, or in an inbox
fetch. `--to <role>` names the nodes whose known principal the role admits; a node with no
verified identity here is in no role. A fetch is admitted like a call: at most 64 undecided at
once, its `hello`'s ID token verified and `check_admitted` first, and a node not admitted hears
only `NOT_ADMITTED` (§2; or the expired or unreachable sentence of §5) and is traced (throttled);
a banned node's or person's queue is dropped when it fetches (each message traced `denied`), and a
push to it, its delivery or its fetch is refused. A node holds at most 2 long polls open per host.
An admitted node that `push.allow` doesn't admit (or a host that pushes to no one, or can't decide
now) hears one fixed text, `inbox fetch refused: this host does not push to you`, naming no role;
the reason is traced at `debug` (`wires inbox` asks every host of its services).

A receiver refuses a message whose `from` is not the authenticated peer or whose `to` is not itself.
Delivery is at least once; the receiver removes duplicates by `PushId`. The host queues up to 64
messages per recipient (oldest dropped), in `push-queue.json`. The TTL defaults to 24 h and is at
most 7 d. Each milestone (`queued`, `delivered`, `fetched`, `expired`, `dropped`, `denied`) is
traced at `debug`, with the subject and never the body.

`wires push` hands the message to the running `serve` over one of two local sockets (NDJSON,
`wires/host/control.rs`), each mode 0600 in a 0700 directory that the server and the operator's
client both check is owned by `geteuid()`:

- **The operator socket**, `run/serve.sock` in the keystore, or, when that path is too long to bind
  as a unix socket (108 bytes or more on Linux, 104 on macOS), `wires-<uid>/<16 hex of blake3
  of the full path>.sock` under the temp dir, else `/tmp` (`<uid>` the keystore's owner), so every
  process that knows the keystore finds it: `{"push":{to, subject, body,
  ttl_secs?}}` to any node or role. A service child is not told where it is (though one running as
  the host's user can find it at the keystore's default path, §5).
- **The child socket**, `push.sock` in a private `wires-<16 random hex>` directory (0700) that
  `serve` makes at start when `host.json` has a `push` section, outside the keystore, under `$XDG_RUNTIME_DIR` (else the temp dir, else
  `/tmp`), and removes at exit; so `WIRES_PUSH_SOCKET` names neither `WIRES_HOME` nor the operator
  socket. It carries a service pushing back to **its own caller**. With a
  `push` section in `host.json`, for every call `serve` mints a random 32-byte token (64 hex) and gives the child `WIRES_PUSH_SOCKET` and
  `WIRES_PUSH_TOKEN`; `wires push` sees the token and sends `{"caller_push":{token, push}}` (no
  keystore needed). The socket accepts it only for a live token and only with `to` equal to that
  call's caller node id (never a role or another node); the operator's `push` form is refused
  there. A token is live for the call and 10 minutes after it ends (`CAPABILITY_GRACE`), so a job
  the call started can still report; tokens are memory-only, so a restart kills them. The push
  still passes `push.allow`.

This is push as built. Designed, parked ([card 31](board/backlog/31-inbox-delivery.md)): every
callback goes to the calling node **and** principal through the call's capability only, the
operator's `push` narrows to `--to <node-id>`, role addressing goes, and an `inbox` MCP tool
reaches `wires mcp` and the gateway.

## 8. Keystore (`$WIRES_HOME`, else `$XDG_CONFIG_HOME/wires`, else `~/.config/wires`)

| File | Mode | Holder | Content |
|---|---|---|---|
| `root.seed`, `node.seed` | 0600 | admin / every node | hex Ed25519 seed |
| `reached.json` | 0600 | admin | the directories that have taken a publish from this admin: until one a publish aims at has, reaching none is the first run, not a failure (§4) |
| `labels.json` | 0600 | admin | label → node id (§3 *Labels*); never signed, never sent |
| `network.json` | 0600 | every joined node but the admin | the network string `join` or `login` stored (§2): the root, up to two directories, the login settings |
| `policy.json` (+ `.lock`) | 0600 | admin, host, directory | the newest verified signed policy (§3); **a caller holds none** |
| `view.json` | 0600 | caller (any node that calls) | its view: the head, the root-signed entries it may call, the newest `Fresh`, when a directory last vouched, the newest head a host reported (§4 *Views*) |
| `login-client.json` | 0600 | admin | which trusted IdP the network string names, and each client's public secret; never signed, never published |
| `fresh.json` | 0600 | host | the newest `Fresh` for the held head (§4 *Freshness at the host*) |
| `directory.redb` | 0600 | directory | the directory's heads and items (§4) |
| `idp-token.jwt`, `idp-refresh-token` | 0600 | caller | from `wires login` |
| `unanswered.json` | 0600 | caller | host → when it last failed to answer this caller's dial; a host there under 60 s goes last (§5) |
| `hints` | — (the operator's; wires never writes it) | any node | optional local dial hints (below) |
| `tools.json` | — | caller | locked mode; optional aliases |
| `inbox/` | 0700 | caller | `new/` (≤256 unread), `read/` (last 1024), `notes/` |
| `push-queue.json` | — | host | §7 |
| `gateway-client-key`, `gateway-sessions.json` | 0600 | web gateway | the key DCR client ids are MAC'd with; live web sessions keyed by token hash |
| `jwks/` | — | caller | cached issuer keys (a host never reads it, §6) |
| `run/serve.sock`, `run/hint` | 0600 | host | the operator's push socket (under the temp dir when the keystore path is too long, §7); this host's own hint line |

The admin's root key is in `root.seed`; every other node learns it from `network.json`. The child
socket for a call's push capability is not in the keystore: it lives in a private directory `serve`
makes per run (§7).

A host's or directory's keystore must not hold `root.seed`: `wires serve` and `wires directory
serve` refuse to start from the admin's keystore. Run each from its own (`WIRES_HOME=<dir> wires
join <network>`).

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

Every file wires writes above is written atomically: a temporary file created `O_EXCL` with mode
0600, then renamed over the target (a seed is created `O_EXCL` 0600 in place, and never
overwritten). A file with no listed mode is 0600. A keystore directory wires creates is 0700 (an
existing one is left as it is). `directory.redb` is redb's own file, created 0600.

Flags, environment variables and `--…-file` paths override the keystore, in that order of
precedence. Locked mode (`WIRES_LOCKED`) refuses the credential flags, `--tools-file` and the `WIRES_NODE_SEED`
variable, and, for `wires call`, data on stdin unless `WIRES_LOCKED_STDIN=allow` (exit 2); it assumes the agent can't
set its own environment.

## 9. Known limits

The full list, kept in one place, is [usage.md § Known trade-offs](usage.md#known-trade-offs). The
ones that bound this spec:

- **The admin doesn't approve each machine.** Anyone the IdP verifies under a trusted client,
  whom a role admits, is in from any machine. A sign-in phished into binding an attacker's key
  (the attacker's nonce in the victim's sign-in) is admitted.
- **A stranger costs a token check**: any key can connect and
  make a host or directory verify one token (its keys fetched only for a trusted issuer, and
  refetched at most once per issuer per window).
- **The ID token is the only credential**, so its lifetime is every caller's: Google's tokens last
  about an hour and Google drops the `nonce` on refresh, so a caller signs in again each hour
  (`wires login`). Disabling someone at the IdP cuts them off within one token lifetime, with no
  wires action. A longer-lived credential, when it comes ([card 29](board/backlog/29-person-identity.md)),
  must be something `wires login` hands over, never a separate step.
- **Bans don't expire**, and they accumulate in the policy until the admin lifts them (`wires
  restore`). A person ban matches only a verified email, which is why admission requires one. A
  node ban doesn't keep a person out (a new key is one `WIRES_HOME` away): remove a person by
  email.
- Nothing renews the policy head (90 days by default); an expired policy admits nobody, is served
  by no directory, and is dialed from by no caller.
- A host follows one directory at a time (the others are failover it dials only when that one
  is gone), and a host newly listed as a directory runs the directory mode only after a restart.
  Under `lenient`, a lapse shows only in the host's trace.
- A caller holds only its view, but hosts and directories hold the whole policy (roles,
  services, host ids, bans, issuers, directories), and a directory sees who asks for which view
  (it only traces the requests). A directory can withhold an entry from a view, or serve a
  stale one within `Fresh`'s bound; the host still decides every call. A removed host still
  receives the ID token and argv (and, if it understates its policy version, the stdin) of a caller
  whose view predates the removal, until that caller's view is refreshed: a day after the last
  refresh when a directory answers, but with none reachable, or when the removed host was itself a
  directory the old head lists, until the view's head's `not_after` (90 days by default, §5).
  [Card 45](board/backlog/45-trim-policy-sync.md) is where freshness gets rethought.
- A host follows one directory, and that directory's `Fresh` is what says its copy is current. A
  directory machine the admin removed can ignore the publish and keep signing a `Fresh` for the old
  head (which still lists it): the hosts following it keep that head, vouched for even under
  `strict`, until its `not_after`, and so does a caller whose view's head lists it (above). An
  honest directory that missed a publish does the same until its replica catches up.
- A host knows a caller's identity only once the caller presented its token to that host.
- **Hosts share no state.** Calls to a service spread at random across its hosts, so a service
  that keeps state between calls (in memory, or on its machine's disk) answers from whichever host
  the call landed on, and a push sits on the host that sent it (§5 *What stays on one host*).
- **A queued push is addressed to the node, not the person.** The host queues by node key, and the
  next admitted fetch from that node (or delivery to its `wires inbox --wait`) whose person
  `push.allow` admits takes everything queued, including what was pushed while another person was
  signed in there. Only a ban drops the queue. [Card 31](board/backlog/31-inbox-delivery.md) is the
  fix.
- **The pre-authentication slots can be held by any key.** A directory has 16 undecided
  connections for both its ALPNs, a host 64 undecided sessions and 64 undecided inbox fetches; a
  slot is held until the opening frames arrive or time out (10 s each), with no per-key cap, so one
  key can keep them full and delay everyone else's admission. Open subscriptions and admitted
  sessions are unaffected.
- **A publish is open to any key.** Any key can make a directory verify one head signature, and any
  key holding a genuine root-signed head that isn't newer (every caller's view carries one) learns
  the version and `HeadHash` the directory holds from its `published` answer.
- **A later network string with the same root replaces the stored one whole**: the sign-in issuer,
  client id, public secret and directories. Whatever carries a string to a node vouches for those
  settings on every `join` or `login <network>`, not only the first. A forged directory can only
  fail to answer (everything it serves must be root-signed); a swapped issuer sends `wires login` to
  an IdP whose tokens no host or directory trusts.
- A service run as another Unix user than `serve` (as
  [deployment.md](deployment.md#run-services-as-a-separate-unix-user) recommends) can't connect to
  its `WIRES_PUSH_SOCKET`, whose directory is 0700 and owned by `serve`'s user, unless the operator
  opens it.
- wires keeps no record of a call beyond the host's ordinary log line (§5): nothing signed, and
  nothing a caller or an auditor can read back from a host. A signed call record is a future
  design.
- One network per keystore.

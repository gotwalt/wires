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
| **a caller** (any node acting for a person: `wires call`, `wires mcp`, `wires inbox`, the gateway for each web user) | an **ID token** (§6) from an issuer the held policy trusts, with an accepted audience, unexpired, whose `nonce` binds it to the iroh-authenticated key; and `check_admitted`: the token carries a **verified email**, the policy bans neither that node nor that person (§3 *Bans*), and **some role in the policy matches the person** | the session gate (§5), an inbox fetch (§7), every directory request that isn't a named node's (§4) |
| **a host**, to a caller | before the caller sends it anything: it shows a root-signed head no older than the caller's view and a current `Fresh` for that head from a directory **other than itself** (the head's one directory being itself is the exception), and the caller's view at that head lists its key for the service (§5 *The host's proof*); iroh authenticated that key | the caller, before its `Hello` (§5); again before stdin, against the `HelloAck` |
| **a directory**, to a caller | before the caller presents its ID token: its proof, by the host's rule above (a head no older than the caller's view that lists it, and a current `Fresh` for that head from another directory, or its own as the head's one directory while the network string names no other) | the caller, before its directory `hello` (§4) |
| **a host or a directory**, to a directory | the held policy names its key: as a host of some service (`Policy::is_host`) or in the head's `directories`, and does not ban it | the directory's `policy` request and subscription (§4) |
| **a directory**, to anyone | the root-signed head lists it, and its `Fresh` is signed by that key | `Fresh::verify` (§4); a caller takes a host's own `Fresh` only when the head lists that host as its one directory (`Fresh::vouches`, §5) |
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
PolicyHead { format: 5, fabric, version: StateVersion(u64), issued, not_after,   // version: +1 per edit
             directories: [NodeId], fresh_secs: u32, items_hash: ItemsHash }   // fresh_secs = settings
SignedPolicyHead { head, alg, sig }
SignedEntry { format: 2, fabric, version, name: ServiceName,
              service: Service { description, allow: [RoleName], hosts: [NodeId] },
              alg, sig }
Item = role       { key: RoleName,    body: [Matcher] }
     | service    SignedEntry          // {"kind": "service", ...the entry's fields}
     | ban        { key: NodeId }                       // a removed node
     | person_ban { key: Person { issuer, email } }     // a removed person
     | issuer     { key: Issuer,      body: { client_id, audiences: [Audience] } }
     | settings   {                   body: { beat_secs, fresh_secs } }
SignedPolicy { head: SignedPolicyHead, items: [Item] }   // items sorted by (kind, key), each key once
```

- **Signed bytes:** the head signs `"wires/policy-head/v1\0"` followed by canonical JSON of
  `{alg, head}`. `items_hash` is blake3 of `"wires/policy-items/v1\0"` ‖ the canonical JSON array
  of the items, in key order, so one signature covers the whole set: no item can be changed,
  dropped, added, or taken from another version. A service entry signs `"wires/service-entry/v1\0"`
  ‖ canonical JSON of every field but `sig`. The prefixes separate them from each other and from
  `Fresh` (§4). A head of format 4 (whose settings carried a freshness rule) or 3 (whose bans
  carried an `until`) is refused (`UnsupportedVersion`), as is a format 1 service entry.
- **An entry's `version`** is the policy version at which it last changed. An edit re-signs only
  the entries it changes (`Policy::sign_after` the stored policy); the others keep their signature
  and version. So a caller holding a subset of entries (its view) can check each one alone
  against the root.
- **`SignedPolicy::verify(root)`**, the one check for a whole policy: the head's algorithm,
  format 5, the `fabric == root` pin and signature; the items are strictly in key order and hash to
  `items_hash` (`ItemsMismatch`); every service entry verifies on its own under the root, at a
  version no later than the head's; the head's `fresh_secs` is the settings item's; then
  `Policy::validate`. **`check_fresh(now)`**: `Expired`
  when `now > not_after`. An expired policy admits nobody until the admin signs a newer one.
- **Views.** A **view** (`library/services/view.rs`) is `{head, entries: [SignedEntry]}`: the
  services a caller may call, each verifying alone; `SignedPolicy::view_for(node, principal,
  query)` cuts it (empty when the policy bans the node or the person, or no role matches).
  **Policies and views always travel whole**: a node that holds an older one replaces it with the
  newer one it is sent, and nothing is ever sent as a difference from what a node holds.
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
- **Settings.** One item: `beat_secs` (default 300: how often a directory signs a `Fresh` and
  beats its subscriptions) and `fresh_secs` (default 900: how long a `Fresh` is good for). The
  admin sets them with `wires policy settings`. `fresh_secs` is the **removed-host window**: a
  caller tells a host nothing until a current `Fresh` from another directory vouches for the head
  the host holds (§5 *The host's proof*), so a host the admin removed can be told something for at
  most `fresh_secs` after the edit reaches the directories, and with every directory down calls
  stop within it. The head carries it too (`fresh_secs`), so a caller holding only the head bounds
  every `Fresh` by it. An edit that would leave a network that listed a directory with none
  (`directory rm`, or `remove` of the last directory's node) is refused: with none, no caller would
  call any host.
- **Versioning.** Every admin edit (`init`, `remove`, `restore`, `service`, `role`, `issuer`,
  `directory add|rm`, `policy settings`) is the stored policy changed, `version + 1`, `issued =
  now`, `not_after = max(now + --policy-ttl, the stored policy's not_after)` (default `90d`: an
  edit never shortens the policy's life; a directory's `Fresh`, not the head's expiry, is what says
  a copy is current, §5 *The host's proof*), re-signed.
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
- **`policy settings [--beat-secs N] [--fresh-secs N]`** edits the settings item; with no flag it
  prints the settings and edits nothing.

Every edit takes `--policy-ttl`, and every edit but `init` ends with the publish in §4. `wires policy push` changes nothing:
it re-publishes the stored policy to every directory.

## 4. The directory: `wires/directory/3` and `wires/directory-sub/3`

A **directory** is a node the head lists in `directories` (`wires/directory/`). It holds the newest
policy, signs a freshness timestamp for it, takes a newer policy from any publisher, and answers
hosts and callers. **It never decides a call**: hosts decide from their own copy. But a caller
tells a host nothing without a directory's current word for the head that host holds (§5 *The
host's proof*), so with every directory down calls stop within `fresh_secs`. It is trusted for
availability and freshness only; everything it serves is root-signed.

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
head lists its signer (`Fresh::verify` refuses any other key, `NotADirectory`), and only for at
most the head's `fresh_secs` (`until - at`; longer is `FreshTooLong`, so a removed or compromised
directory can't sign one that lasts for ever). A directory whose
held head doesn't list it signs none and answers `policy` and views with a refusal. An honest
directory signs only for the newest head it holds: that is what lets a `Fresh` say a head is
current, and what a caller relies on before it tells a host anything (§5).

**The store** is the node's own `policy.json` (§3 *Monotonic copies*, §8): the newest policy and
nothing else, no history. On a node that is both a host and a directory it is the one copy both
decide and serve from. A `Fresh` is kept in memory only (a beat writes nothing to disk), and a
restart reads `policy.json` back and signs a new one. A directory whose newest head has expired
signs no `Fresh`, admits nobody and answers every request with `this directory holds only an
expired policy (version N); try again later`, until the admin publishes a newer one.

**Accepting a policy** (`Directory::accept`): `SignedPolicy::verify` under the root (§3), the head
fresh, strictly newer than the held head. Then it is adopted into `policy.json` (`adopt_if_newer`),
a `Fresh` is signed for it, and subscribers are woken. An older or equal one changes nothing. A
directory accepts from the admin's publish, and, on a node that is also a host, from that host's
own following of another directory (below).

**`wires/directory/3`.** Frames are a 4-byte length then canonical JSON tagged by `type`
(`library/directory/frames.rs`). Every request frame, the `hello` included, is at most 16 KiB;
only a publish's `items` frame (at most 16 MiB) is larger, and it is read only after the head it
belongs to verified. One request per connection: the dialer sends `hello {id_token?}` then one
request, and gets one answer (5 s to dial, 10 s per frame).

- **A caller's token goes only to a directory that has shown it is current**, by the rule a host
  shows it by (§5 *The host's proof*). A dialer that will present an ID token opens with `open {}`
  instead; the directory answers at once with `proof {proof}`, a `HostProof` (§5): its root-signed
  head and the current `Fresh`es it holds for it (its own and, on a node that is also a host, the
  ones that host holds, §4 *Freshness at the host*), and no entries. An empty directory, or one
  holding only an expired policy or one that doesn't list it, answers `denied` instead. Then the
  dialer sends `hello {id_token}` and its request. The caller (`wires/caller/view.rs`) asks every
  directory it would ask for its proof at once, and checks each with `HostProof::check`, against
  its view's head and the directory dialed (holding no view yet: the head verifies under the root
  and hasn't expired, and some `Fresh` vouches for it): the head is no older than the view's (at
  the same version, the same head), and a current `Fresh` signed by a directory **other than the
  one dialed** vouches for it, unless the head lists exactly that one directory and the network
  string names no other; and the head lists the directory dialed. The `Fresh`es it counts are the proof's, the ones its view holds, and the ones every other directory showed in
  the same round, so two directories at one head vouch for each other. As the proofs arrive, it sends
  its token and request to each directory whose proof checks out, one at a time, until one
  answers with a view it takes. A directory whose proof doesn't check out is a dial failure: it was
  sent `open` and nothing else. So a directory the admin removed, or one that missed the edit
  that removed a host, is never told a caller's token once its words have lapsed. Hosts,
  directories and the admin present no token, and open with `hello` at once.
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
  {fresh}` when `have` is the newest (or newer than the directory's), else the whole `policy
  {policy, fresh}`.
- `view {query?}` and `resolve {service}`: a caller's view, below.

**Views.** The directory cuts a view from the held policy for the principal the caller's
`hello` token verified as (above), `SignedPolicy::view_for(caller, principal, query)`: the
root-signed service entries whose `allow` has a role admitting the principal. A banned or unknown
person never gets this far: admission refused them (`NOT_ADMITTED`). A named node with no admitted
principal gets the empty view. Nothing per user is stored, and a request is only
traced: a view grants nothing, and the host decides every call.

- `view {}`: the whole view, `view {view, fresh}`.
- `view {query: q}`: the entries whose name or description contains `q` (ignoring ASCII case).
- `resolve {service}`: a `view` holding that one service, or no entry (it doesn't exist, or the
  caller may not use it: the two are not told apart).

A caller takes a `view` when it verifies (`View::verify`: the head, and each entry on its own
under the root, at a version no later than the head's) and its `Fresh` vouches for its head. A
directory can withhold an entry or serve a stale view (a `Fresh` bounds how stale); neither lets
anyone call anything, since the host decides every call from its whole policy.

**`wires/directory-sub/3`: a host follows the policy.** The dialer sends `hello`, then `subscribe
{have}` (the version it holds; 0: none). Only a **named** node may subscribe: an admitted caller
hears the `denied` above (a caller asks for its view), anyone else `NOT_ADMITTED`, a publisher
included. At most 4,096 subscribers at once (`wires directory serve --max-subscribers N`); one
more hears `denied` (`this directory's subscriber cap (N) is reached`). The directory sends, at
once and then on every change of what it holds (a new head, or a beat every
`settings.beat_secs`):

- `policy {policy, fresh}`, the whole policy, when its head is newer than the subscriber's `have`
  and than the last policy it sent this subscriber;
- else `fresh {fresh}`: its `Fresh` for its own head, even when the subscriber holds a newer one
  (so a subscriber learns the directory is behind it, below).

Every subscriber gets the same bytes for a head and its `Fresh`: each frame is encoded once, not
once per subscriber. The stream ends with `denied` when the head stops listing this node (it can
no longer vouch), and when a head bans the subscriber (`NOT_ADMITTED`) or no longer names it as a
host or a directory (the refusal above).

**There is no replication.** Directories don't follow each other. A directory that missed a publish
(down for longer than the admin's retries, below) holds the policy before it until a publish
reaches it: the admin's next edit, or `wires policy push`. A directory that is also a host takes a
newer head sooner, from the directory its host follows (below), since both read one
`policy.json`. There is no consensus: one author, and "newer" is a version number.

**Publish (admin).** After every admin edit, and on `wires policy push`, the admin dials,
concurrently, every directory the new head lists plus every directory the head before the edit
listed (so a directory the edit drops learns it), never itself, and sends `publish`. It dials no
host. A directory counts as delivered when it answers `published` with the offered version and the
offered head's `HeadHash`. Each exchange is bounded: 5 s to dial, then 10 s for the stream, the
frames and the answer. **A directory it could not dial, or that answered `BUSY` (its slots were
full), is tried again**, 1 s after each try, until it takes the publish or 15 s from the first
try have passed, when the new head lists it and it has taken a publish from this admin before
(`reached.json`, §8); `wires policy push` tries every directory the new head lists so. No try
starts after the 15 s, and a try already started finishes (an answer on its way is never
dropped), so a publish takes at most 30 s. Any other refusal is a decision, and is not tried
again. This covers a directory that has just restarted: it binds a new port, n0 discovery has no
record of it for about 3 s, and a stale `hints` line costs a whole 5 s dial; each new dial looks
the key up again. A directory never reached (the first run, below) is tried once, so an edit made
before any directory runs doesn't wait; so is a directory the edit drops. Stderr says `policy
version N: published to K of D directory(ies)`, naming each directory not reached, each that
refused, and each the edit dropped that it didn't reach. When a directory the new head lists
missed it, the line adds that hosts following that one decide under the policy before it until it
takes this one, that nothing else hands it on, and that `wires policy push` re-publishes it.
**The command exits 1 when a directory the new head lists, and that has taken a publish from this
admin before, missed it**, whatever the others did: nothing else will bring that directory the
edit, so the admin must, with `wires policy push` once it is back. The new policy is stored on the
admin and in force at every directory that took it. With no directory listed at all, the line
says the policy is stored here and that `wires directory add` comes next, and nothing fails. Two
exceptions:

- **The first run.** A directory that has never taken a publish from this admin (`reached.json`,
  §8) may not run yet: missing it fails nothing. When the publish reached no directory at all, the
  line is a note, and exits 0: `policy version N is stored here; no directory has taken a publish
  yet. Once one runs (wires join <network>, then wires serve or wires directory serve on its
  node), run wires policy push`. So starting a network (`init`, `directory add`, edits, the
  directory's `join` and `serve`, `policy push`) errors nowhere; a directory starts empty and takes
  the policy from the first publish that reaches it.
- **A stale copy.** A directory answering a newer version, or another head at the offered one,
  kept its own: this admin's `policy.json` is behind and the edit changed nothing there. The
  command exits 1 whatever the other directories did, saying to copy `policy.json` from any host
  or directory and make the edit again.

**Following (hosts).** A running host subscribes (`wires/host/follow.rs`) to the
first directory its held head lists that answers, never itself, trying the one it last followed
first and then the others in the head's order; the list is re-read from the held policy on every
reconnect (the network string's while it holds none), so a directory the admin adds is followed
without a restart. It takes each frame:

- `policy {policy, fresh}`: the head verifies under the root, the `Fresh` vouches for it, and
  `adopt_if_newer` takes it if newer (on a host that is also a directory, its directory accepts
  it, which adopts it);
- `fresh {fresh}`: kept if it vouches for the held head.

A frame for a head **older** than the one it holds means the directory is behind (it missed a
publish), and can't vouch for this host's head: the host passes it over for the next directory
at once. So it does a policy it can't take (one that doesn't verify, or has expired) and a
`denied`, at once or ending the stream (not named, no longer a host, the directory no longer one,
or busy); the next round starts after the directory passed over. When the stream ends (the
directory stopped, or sent nothing for two beats plus 10 s) it reconnects, pausing from 1 s up to
the beat (at most 30 s) while none answers, so a host every directory refuses asks each at most
once per pause. The subscription never holds up serving: a host restarted with `policy.json`
decides from it before any directory answers (a caller talks to it once a directory's `Fresh` for
that head is current, from `fresh.json` or the first frame). A host that is itself a directory
keeps the `Fresh` its own directory signs **and** the one of the directory it follows: a caller
takes its own only when the head lists it as the one directory. A host that is the one directory
signs its own at every beat. A host that the policy newly lists as a directory runs the directory
mode only after a restart (it traces so).

**Freshness at the host.** The host keeps, **per directory**, the newest `Fresh` that vouches
for its held head (`FreshSet`: by version, then a current one over one that isn't current, then
`until`: one from a directory whose clock runs ahead never displaces a current one; at most 16
directories), in memory and in `fresh.json` (0600, a JSON list), read back at start for those
that still vouch for the head on disk. It shows the current ones to every caller first, on a
session and on an inbox fetch (§5 *The host's proof*, §7). The host's own decisions don't depend
on them: whether a directory has vouched lately is the caller's check. When none from a directory
other than this host is current (or, as the head's one directory, none of its own), callers will
send it nothing (the host's follower traces the directories it can't reach).

**Fetch (a host's start).** `fetch` asks the directories the held head lists (the network string's
when it holds none), in order, never itself, for `policy {have}`, and stops at the first answer
that settles it:

- a `policy` whose `Fresh` verifies against **that** policy's head, and which `adopt_if_newer`
  takes (verified, fresh, newer), is adopted;
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
`view.json` (§8): the view, the newest `Fresh` per directory it has seen (from a directory, or in
a host's proof: §5), when a directory last vouched for it, and the newest head version a host
reported. A refresh asks for the whole view (`view {}`) of the directories its view's head lists
(else the network string's), never itself, in turn, and takes the first that verifies and is no
older than the one held. A node that holds the whole policy (the admin's, a host's, a
directory's) cuts its own view from it instead of asking.

- **`wires login`** asks for the view under the new identity, forgetting the old one. `wires join`
  asks for nothing.
- **One-shot commands make little background traffic.** `wires call` and `wires inbox` dial from
  the view as it is, unless it is **stale** (last vouched for more than a day ago, its head
  expired, or a host reported a newer head) or missing: then they refresh first (8 s for all the
  directories together). A refresh that no directory answers leaves the view as it is, and the
  command dials from it (an expired head is never dialed from; whether a host is told anything is
  its proof's to settle, §5). It learns of a newer policy in the call's handshake: a host's proof
  shows its head, and before the caller has spoken a newer one makes it refresh its view first
  (§5); `HelloAck` carries the host's head version, and when it is newer than the view's, the head
  and the called service's entry (§5). The caller then refreshes its view after the call. A name
  the view doesn't hold is asked of a directory with `resolve` (the one-entry view and the `Fresh`
  for its head) before the call fails. So on an unchanged policy, within a day of the last refresh
  and `fresh_secs` of the last `Fresh` the caller saw for its view, a call is the only connection.
- **"Stale" is a day, and it doesn't bound a removed host.** The directories a caller asks are
  its view's head's, then the network string's. If none passes its proof check and answers, the
  caller keeps its view. That is not what keeps a removed host or directory from being told
  anything: each shows its proof first, and a caller sends nothing until a current `Fresh` from a
  directory other than the one it dials vouches for the head that one holds (above, and §5 *The
  host's proof*), and, when a host shows a newer head, until a refresh has brought the view up to
  that head. So the window in which a machine the admin removed can still receive a caller's
  token, on a call, an inbox fetch or a view refresh, is `fresh_secs` (15 minutes by default) after
  the edit reaches the directories, within the limits §9 lists (a one-directory head, a removed
  directory vouching for others).
- **The directories asked are the view's head's, then the network string's** not among them, so a
  view from before a directory was added still reaches it. Each is held to the proof rule above;
  the one asked need not be listed by the caller's head, but must be by the head it shows.
- **`wires services`** reads `view.json`, refreshing first when it is stale (as above). When no
  directory gave it a view and one refused this node (`NOT_ADMITTED`), it lists nothing and says what the
  person can act on (§5 *The caller*).
- **Long-running callers ask again.** `wires mcp` and `wires inbox --wait` refresh their view every
  60 s while they run, keeping `view.json` in step (`wires mcp` sends MCP
  `notifications/tools/list_changed` when its tools change), so a grant or a revocation reaches
  them within a minute. The gateway keeps each web user's view in memory and asks for it again,
  with that user's ID token (the gateway holds no policy), at the user's first request after 60 s,
  and before it tells anything to a host whose proof shows a head newer than that view (§5 *The
  caller*).

## 5. Sessions: `wires/session/2`

A session is one bidirectional QUIC stream on ALPN `wires/session/2`. Codec:
`library/calls/session.rs` (the proof: `library/calls/proof.rs`). Transport:
`wires/host/transport.rs`; the caller's check: `wires/caller/vouch.rs`.

| Tag | Frame | Body | Direction |
|---|---|---|---|
| 13 | `Proof` | canonical JSON `HostProof {head, fresh: [Fresh]}` (the host's root-signed head and the current `Fresh`es it holds for it, at most 16; no entries) | host → caller, always the host's first frame |
| 12 | `Open` | empty | caller → host, first, when it waits for the proof before it says anything |
| 10 | `Hello` | canonical JSON `{state_version, id_token}` (`state_version`: the head version of the caller's view; `id_token`: required) | caller → host, after the proof checked out (or first, on a cached word: below) |
| 7 | `Invoke` | canonical JSON `Invocation {service, argv}` | caller → host, right after `Hello`, without waiting |
| 11 | `HelloAck` | canonical JSON `{state_version, head?, entry?}` (the host's own; `head` and `entry` only when its version is newer than the caller's) | host → caller |
| 6 | `Denied` | UTF-8 reason (at most 512 bytes) | host → caller, terminal |
| 1/2/3 | `Stdin`/`Stdout`/`Stderr` | raw chunk (at most 64 KiB when pumped) | stdin: caller → host; stdout/stderr: host → caller |
| 4 | `Exit` | i32, big-endian | host → caller, terminal |

Any other tag, 8 and 9 included, decodes as `BadFrame`.

**The host's proof** (card 49). A caller dials from its view, and a host the admin has since
removed (dropped from the service's `hosts`, or node-banned) is still in an old view. So **the host
speaks first, and the caller tells it nothing until it has checked**. A QUIC stream reaches the
host only once the dialer writes, so the caller opens the stream one of two ways, and the host
answers both by re-reading its signed policy **for this connection** (so a removal applies on the
next dial without a restart; none readable: `Denied` `host configuration error`, before anything
else) and sending `Proof` at once: that policy's head and every current `Fresh` it holds for it
(§4 *Freshness at the host*). A stranger learns a version and who vouched, nothing about services.

- **`Open`** (the caller holds no current word for this host): the caller reads the `Proof`
  (10 s, at most 64 KiB) and checks it (`HostProof::check`): the head verifies under the root and
  hasn't expired; it is no older than the view's head (`OlderHead`), and at the same version it is
  the same head; some `Fresh` in it vouches for it to a caller dialing this host (`Fresh::vouches`:
  it verifies for that head, is current, and is signed by a directory **other than the dialed
  host**, unless the head lists exactly one directory and it is the dialed host). At the view's
  version, the view decides whether this host serves the service (its entry lists the host);
  at a newer one, the caller first refreshes its view from a directory (8 s): the refreshed view
  must have **reached** the host's version (a lagging directory, or a removed one vouching for
  the old head, is told nothing and leaves the view behind, §4; and a view behind the host's head
  never decides), and the proof must then check out at the same version; then the
  same. A head listing only the dialed host counts as a one-machine network only while the
  network string names no other directory either. **Only then** does it send `Hello` and
  `Invoke`. Any failure (a refresh that fails or stays behind, no way to refresh, an unreadable
  proof) is a **dial failure**: nothing but `Open` was sent, and the next host is tried (below).
  One flight more than the cached path.
- **`Hello` and `Invoke` at once** (the cached path): the caller already holds, for its view's
  head, a current `Fresh` from a directory other than this host (one per directory, in
  `view.json`: from its own refresh, or an earlier host's or directory's proof; a `Fresh`
  vouches for a head, not a host, so one host's proof covers the others), and its view lists the
  host. It costs no extra flight. It still reads and checks the host's `Proof` before it sends a
  byte of stdin, its own words counting beside the host's: a head older than the view, or another
  head at its version, stops the call there (exit 1); a newer one is noted, and the `HelloAck`
  check below decides.

Every `Fresh` a checked proof carries that vouches for the view's head is kept with the view, so
only the first call in each `fresh_secs` window to a host no held `Fresh` covers pays the extra
flight. The window is `fresh_secs` (§3 *Settings*): an honest directory signs only for its newest
head, so once an edit has reached the directories a host it removed has nothing to show within
`fresh_secs`, and a removed host that is itself a directory can't vouch for its own old head.
**Fail closed:** with no directory able to vouch (all down, or the host cut off from them), the
caller sends no host its token, and the call fails (exit 1) saying `no directory has vouched for a
host of \`<service>\` recently, so nothing was sent (…); the network's directories may be down or out
of reach: try again later, or ask your admin`.

**The host** then reads the `Hello` (after an `Open`, or first) and `Invoke` (10 s each; at most
64 KiB, and 512 KiB: the largest valid `Argv`, JSON-escaped). Before it knows who is asking it holds
at most 64 sessions open (one more is closed unanswered), and it sizes no buffer larger than 64 KiB
from a length prefix. An opening that isn't a readable `Hello` (a `Hello` without an `id_token` is
unreadable), or a next frame that isn't an `Invoke`, is refused (`Denied`) with a short fixed reason (`first frame
was not a hello`, `unreadable hello`, `timed out waiting for hello`, `invoke required`), traced as
a stranger's. Then the first failure below is sent as `Denied` (`wires/host/gate.rs`):

1. The host holds a readable policy (checked before its proof, above).
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
3. **The gate** (`ServicesHost::decide`, then `admit`): the head hasn't expired → `authorize` (the service is in the policy and
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
directory the app names; it never reads `$WIRES_HOME`. `serve_until`
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

**The caller** (`wires call`, `wires mcp`, the gateway, and `wires inbox`'s fetch, §7) needs an ID token before it dials: with
none stored (and none presented, for the gateway), the call ends at once (exit 1, `not signed in:
run \`wires login\``), and nothing is sent. It dials from its view (§4 *Views*), refreshing it first
when it is stale or missing. When the refresh fails it dials from a stale view that hasn't
expired; with none, exit 1 (`wires login`, or ask the admin for `wires policy push`). It takes the service's hosts from the service's root-signed entry and orders them **at
random, afresh for each call**, so a service's calls spread across its hosts; the admin's order
means nothing. A host that failed to answer this caller's dial in the last 60 s goes last
(`unanswered.json`, the oldest failure first), so a host that is down costs each caller one dial
timeout a minute, not one in every few calls. A name the view doesn't hold is asked
of a directory (`resolve`); a name no directory resolves for this caller ends the call before any
dial (exit 1), and so does one resolved under a head older than the view (or than one a host has
shown it), whose `Fresh` would otherwise let the call speak at once (a directory holding such a
head is not even asked: its proof is behind the view, §4). The gateway dials from each user's
view, held in memory (§4 *Callers keep their view current*), and resolves no name; a host showing
a newer head than that view makes it refresh the user's view first, as `wires call` does, and the
refreshed view replaces the one it holds (a refresh that fails, or stays behind, is a dial failure
there too). The `Fresh`es hosts' proofs carry it keeps in memory, for all its users.
It moves to the next host **only when a dial fails** (10 s each), and a proof that doesn't check
out before anything was sent is one; a host that has the call has decided. When a call is
answered, the hosts tried before the one that answered are recorded in `unanswered.json` and the
one that answered is cleared from it; a call no host answered records nothing (every host failing
tells the order nothing).

Once it has spoken, and before it forwards a byte of stdin, the caller checks the host again: the
key it dialed (which iroh authenticated) is one the root-signed entry lists, and, when the ack's
`state_version` is newer than the view's the `Hello` named, `HelloAck::assigns`: the head verifies
under the root at that version, and the service's entry verifies under the root, names the called
service, is no newer than the head, and still lists that host. If not, the call stops there (exit
1, no stdin sent). After the call, a one-shot caller refreshes its view when the host reported a
newer head (§4).

**What stays on one host.** Hosts share the signed policy and nothing else, so the next call may
land on another host. What a host keeps between calls stays on it: whatever a native service
or the CLI holds in memory or on that machine's disk (the `kv` example's map is per host); the
callers whose identity it has verified (§7 *The identity rule*: a host learns a caller's identity
only from that caller's call or inbox fetch to it, so `wires push --to <role>` from one host
reaches only the callers who have called or fetched from it); and its push queue (§7). A push is
queued on the host that sent it, and `wires inbox` asks every host of the services in its view, so
random host choice loses no push; one queued on a host that is down waits there until it is back
or the push expires. [Card 31](board/backlog/31-inbox-delivery.md) is where a single delivery path
gets settled.

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
above, and a call no host could prove itself current for: nothing was sent) → 1. Otherwise the remote exit code, **except that a remote 77 is reported as 1** with a
note on stderr, so 77 always means the host refused. `wires call` exits 2 before dialing when its `--jq` filter
doesn't compile or locked mode refuses its stdin, and 2 when the remote exited 0 but shaping its output
failed. A session that ends without `Exit` is an error. Limits: 16 MiB largest frame once admitted (64 KiB `Hello` and 512 KiB `Invoke`
before); `Argv` holds at most 256 arguments and 64 KiB.

## 6. Identity

`wires login` runs OIDC (authorization code, PKCE, loopback redirect) with `nonce =
base64url(blake3::derive_key("wires oidc-nonce v1", node_id))`, verifies the token locally, and
stores it in `idp-token.jwt`. Nothing is published. The token travels in the session `Hello`, the
inbox fetch's `hello` (§7) and the directory `hello` (§4), and a host or a directory gets it only
once its proof checked out (§5 *The host's proof*, §4; within the limits of §9). **It is the only credential a caller
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
presenting a token bound to it. The gateway holds no policy: it asks a directory for each web
user's **view**, presenting the user's own ID token (only to a directory whose proof checked out,
§4), which verifies it and cuts the view (§4 *Views*), and asks again at the user's first request
after 60 s; so it offers a user only services that a role admits by that user's own verified
principal, and a grant or revocation applies to their requests within a minute.
A web user the network doesn't admit is refused at sign-in (`access_denied` at the OAuth
callback, HTTP 403 at `/mcp`: `not admitted to this network: no role in this network matches this
account, or it was removed: ask your admin`; the email is left out because the text returns to the
MCP client). A node-banned gateway is refused by every host and every directory (`NOT_ADMITTED`). It
issues its own OAuth access tokens (opaque, bound to its
`/mcp`, expiring with the ID token) and no refresh tokens. Its MCP endpoint serves the 2026-07-28
Streamable HTTP binding and the legacy `initialize` era ([deployment.md](deployment.md)).

## 7. Push: `wires/inbox/4`

A host sends a `PushMessage { id, from, to, subject (≤128 B), body (≤16 KiB), at_ms, expires_ms }`
to a caller, addressed **by key**. Frames are length-prefixed canonical JSON tagged by `type`:
`open {}`, `proof {proof}` (a `HostProof`, §5), `hello {id_token?}`, `fetch {wait_ms}`, `deliver
{messages ≤ 32}`, `ack {ids ≤ 32}` and `denied {reason}`, at most 4 MiB; an `open`, a `hello`, a
`fetch` and a `proof` are read before the peer is known (or proved current), so each may be at
most 64 KiB. Two ways a message is delivered:

- **Direct:** the host dials the recipient (3 s budget) and opens with `hello {}` (a host acts for
  no person). A running `wires inbox --wait` serves the inbox ALPN and accepts `deliver` only from a
  node that **hosts a service in its view** (it refreshes its view every 60 s while it
  waits); any other dialer hears only `NOT_ADMITTED` (§2; the reason is traced,
  throttled).
- **Fetch:** `wires inbox` dials the hosts of every service in its view. **The host speaks first**,
  as on a session (§5 *The host's proof*): its `proof`, and the fetcher presents its token only
  once that checks out against its view (the host must host some service in it): it opens with
  `open {}` and waits for the proof, or, holding a current word for that host already, with its
  `hello` at once and checks the proof before it reads a message. A host whose proof doesn't check
  out is sent nothing; when that is every host for want of a directory's word, `wires inbox` says
  so on stderr. Then `hello` with its stored ID token, `fetch` held open for up to 25 s with
  `--wait`, else answered at once, `deliver`, then `ack`, refreshing the view first when it is
  stale, as `wires call` does (§4 *Callers keep their view current*). With no token stored it
  fetches nothing and says to run `wires login`.

The host authorizes at send, at delivery and at fetch (`ServicesHost::decide_push`; a push
decides under the held policy, whatever a directory has said of it lately): the
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
| `reached.json` | 0600 | admin | the directories that have taken a publish from this admin: until one a publish aims at has, reaching none is the first run, not a failure; a publish tries one of these again when it could not dial it (§4) |
| `labels.json` | 0600 | admin | label → node id (§3 *Labels*); never signed, never sent |
| `network.json` | 0600 | every joined node but the admin | the network string `join` or `login` stored (§2): the root, up to two directories, the login settings |
| `policy.json` (+ `.lock`) | 0600 | admin, host, directory | the newest verified signed policy (§3), and a directory's whole store (§4); **a caller holds none** |
| `view.json` | 0600 | caller (any node that calls) | its view: the head, the root-signed entries it may call, the newest `Fresh` per directory it has seen (from a directory, or a host's or directory's proof, §4–5), when a directory last vouched, the newest head a host reported (§4 *Views*) |
| `login-client.json` | 0600 | admin | which trusted IdP the network string names, and each client's public secret; never signed, never published |
| `fresh.json` | 0600 | host | the newest `Fresh` per directory for the held head, a JSON list: what it shows callers first (§4 *Freshness at the host*) |
| `idp-token.jwt`, `idp-refresh-token` | 0600 | caller | from `wires login` |
| `unanswered.json` | 0600 | caller | host → when it last failed to answer this caller's dial; a host there under 60 s goes last (§5) |
| `hints` | — (the operator's; wires never writes it) | any node | optional local dial hints (below) |
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
Rust moves can also leave stale stack copies that nothing scrubs. A seed passed by `--node-seed`
also stays in the process's argv.

**Hints** (`wires/caller/pick.rs`). `$WIRES_HOME/hints` is local and unsigned: one line per node,
`<node id hex> <ip:port>…`, `#` comments, bad lines skipped. Every endpoint `wires` binds registers
it beside n0 discovery, so calls, directory requests, push and fetches all use it. `serve` writes its own line
to `run/hint`. A hint only says where to try; iroh still authenticates the key.

Every file wires writes above is written atomically: a temporary file created `O_EXCL` with mode
0600, then renamed over the target (a seed is created `O_EXCL` 0600 in place, and never
overwritten). A file with no listed mode is 0600. A keystore directory wires creates is 0700 (an
existing one is left as it is).

The environment is the one way to point `wires` at another keystore (`$WIRES_HOME`, else
`$XDG_CONFIG_HOME/wires`, else `~/.config/wires`). A caller's commands (`login`, `services`,
`call`, `mcp`, `inbox`) take no key, relay or keystore flag (`login`'s hidden flags set only the
IdP sign-in settings): they use the keystore's node
key and n0's relays. `serve` alone takes its node key ahead of the keystore (`--node-seed-file`,
or `--node-seed`), for a container that mounts its key; `serve`, `directory serve` and `gateway`
take `--relay-url` for a self-hosted relay. Locked mode (`WIRES_LOCKED`, set by the operator)
refuses a `wires call` whose stdin holds data, before dialing (exit 2): stdin can carry local files
to the host. It assumes the agent can't set its own environment.

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
- **Calls depend on the directories** (card 49): a caller sends a host nothing without a current
  `Fresh` from a directory other than that host, so with every directory down, or a host cut off
  from them, calls to it stop within `fresh_secs` (15 minutes by default). Fail closed is the
  trade for the removed-host window below. Refreshing a view is held to the same rule: a caller
  sends a directory its token only on a current `Fresh` from another directory (or when the head
  lists that one alone and the network string names no other), so with only one of several
  directories up, callers keep the views they
  hold, and the cached words in them lapse within `fresh_secs`.
- A caller holds only its view, but hosts and directories hold the whole policy (roles,
  services, host ids, bans, issuers, directories), and a directory sees who asks for which view
  (it only traces the requests). A directory can withhold an entry from a view, or serve a
  stale one within `Fresh`'s bound; the host still decides every call.
- **The removed-host window is `fresh_secs`.** A host the admin removed (dropped from a service,
  or node-banned) can still receive the ID token and arguments of a caller whose view predates the
  removal for up to `fresh_secs` after the edit reaches the directories: a `Fresh` an honest
  directory signed for the old head just before is current that long (the caller may hold one
  already, and speak at once). After that it can't show a current word for the head it holds, and
  on a session or an inbox fetch it is sent nothing (§5 *The host's proof*), except as the next
  three items say. A host's `Proof` is shown to anyone before admission, so it is **replayable
  material by design**: a removed host can show an honest host's current head and `Fresh`; that
  only makes the caller refresh its view to that head, which no longer lists it.
- **A one-machine network trusts its host's own word.** When the head lists exactly one directory
  and it is the host being dialed (the first-run shape: one workbench is both), the caller takes
  that host's own `Fresh`; there is no other directory to ask. Removing that machine is then
  bounded by the head's `not_after` (90 days by default), not `fresh_secs`. Running a second
  directory makes removal hold for callers that know of it: whose view's head lists it, or whose
  network string names it (`wires network` prints the new string after `directory add`; a caller
  that joined with the old one and hasn't refreshed since still trusts the machine's own word, and
  asks only it).
- **A removed directory can vouch for others' old heads.** A `Fresh` vouches for a head, not for a
  host, and is valid because the head lists its signer. A directory machine the admin removed keeps
  its key, and every head from before its removal still lists it: it can sign a current `Fresh`
  for such a head, and a host removed at or after that head can show it to a caller whose view is
  that old. The check stops a host vouching for itself, not two removed machines vouching for each
  other (or one compromised directory for any host); a k-of-n rule would. Such a directory, or a
  lagging honest one, can't move a caller's view backwards (a view is never replaced by an older
  one, and a refresh that stays behind the host's head decides nothing), but it can keep a stale
  view in place.
- **Directories are held to the hosts' rule** (card 45): a view refresh or `resolve` sends a
  directory the caller's ID token only after its proof checks out (§4), so a removed or lagging
  directory gets no token once its words have lapsed, with the same limits as hosts (the
  one-directory head and the removed directory vouching for others, above).
- **`wires inbox --wait` takes deliveries without a proof**: a host that delivers directly is
  admitted because it hosts a service in the receiver's view, so a removed host still in a stale
  view can push to it (no token goes to the host that way).
- A host follows one directory, and that directory's `Fresh` is what says its copy is current. A
  directory machine the admin removed can ignore the publish and keep signing a `Fresh` for the old
  head (which still lists it): the hosts following it keep that head, vouched for, until its
  `not_after` (above). An honest directory that missed a publish does the same until a publish
  reaches it (directories don't replicate, §4), though a host holding a newer head than its
  directory passes that one over. The admin hears of the miss (the edit exits 1) and re-publishes
  with `wires policy push`.
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
  slot is held until the opening frames arrive or time out (10 s each: up to 20 s for a session or
  fetch that opens with `Open` and then its `Hello`, 30 s with the `Invoke`), with no per-key cap,
  so one
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

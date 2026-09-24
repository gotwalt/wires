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

Usage, roles and the demo are in [usage.md](usage.md), [the board](board/README.md) and
[demo.md](demo.md). Deployment and testing are in [deployment.md](deployment.md) and
[testing.md](testing.md).

## 1. Ground rules

| Rule | Where |
|---|---|
| A node is an Ed25519 key, and `NodeId` is its 32-byte public key. The iroh `SecretKey` is the same seed, so the iroh endpoint id **is** the `NodeId`. | `library/membership/identity.rs`, `transport::secret_key` |
| **The caller is always `to_node_id(conn.remote_id())`**, the key iroh authenticated. It is never a wire field. Every gate below is sound only because of this. | every responder |
| The fabric is named by its root key: `fabric = root.node_id()`. | `Membership::mint`, `State::new` |
| Signed objects sign a domain-separation prefix (where they have one) followed by `canonical_bytes(body)`: canonical JSON with keys sorted by `serde_json`'s default `BTreeMap` ordering. `preserve_order` and `arbitrary_precision` must never be enabled. | `library/codec.rs` |
| Every signed body carries a signed format discriminant and a fixed, complete set of fields. **An optional signed field is not allowed**, because an absent field and a present default sign different bytes; "none" is an empty value. A new format gets a separate body, and an old verifier rejects it with `UnsupportedVersion`. Signed types refuse unknown fields at decode. | membership, state, call-log entry |
| Every signed credential signs its own authority (`fabric`), and `verify(root)` requires `fabric == root`. | membership, state |
| Tokens are base64url-no-pad of canonical JSON. Wire frames are a 4-byte big-endian length followed by a body; the length is checked before the body is allocated. Frame envelopes are unsigned, so `skip_serializing_if` is safe in them. | all codecs |
| `alg` is always `Ed25519`. `not_after` is inclusive, and a credential is expired when `now > not_after`. Times are unix seconds, except `*_ms` fields. | all |

Every node binds one iroh endpoint (`presets::N0`: n0 DNS/pkarr discovery and relays) and is dialed
**by key**. Addresses are never authority; see §9 for the optional local hints file.

## 2. Membership

`Membership { version: 1, fabric, member, issued, not_after, alg, sig }` is signed by the root. It
answers two questions: which fabric the node belongs to, and which node it is.

`check_inclusion(m, fabric_root, caller, now)` checks, in order: `m.verify(fabric_root)` (algorithm,
version, the `fabric` pin, signature); `m.member == caller` (`SubjectMismatch`, so a membership is
not transferable); `now <= not_after` (`Expired`).

A membership is public. It holds no secret, so presenting it before the peer is verified is safe.
It says the node *was* admitted; whether it is *still* in is the signed state's member set (§3).
There is no revocation list.

## 3. The admin-signed state

One versioned document, signed by the root, says everything the fabric agrees on
(`library/services/state.rs`):

```
State { format: 1, fabric, version: StateVersion(u64), issued, not_after,
        members: {NodeId}, hosts: {NodeId},
        roles: { RoleName → [Matcher] },
        services: { ServiceName → Service { description, allow: [RoleName],
                                            hosts: [NodeId], readers: [RoleName] } } }
SignedState { state, alg, sig }
```

- **Signed bytes:** `"wires/state/v1\0"` followed by canonical JSON of `{alg, state}`. The prefix
  separates it from memberships and call-log entries.
- **`State::validate`** (run by `sign` and `verify`): format is 1; `hosts ⊆ members`; every role
  has at least one matcher and every matcher names an issuer; every role a service's `allow` or
  `readers` names is defined (there is no built-in role); every service host is in `hosts`,
  listed once.
- **`SignedState::verify(root)`** checks the algorithm, the `fabric == root` pin, the signature,
  then `validate`. **`check_fresh(now)`**: `Expired` when `now > not_after`. An expired state admits
  nobody until the admin signs a newer one.
- **Versioning.** Every admin edit (`init`, `invite`, `remove`, `service add|set|rm`, `role
  set|rm`) is the stored state changed, `version + 1`, `issued = now`, `not_after = max(now +
  --state-ttl, the stored state's not_after)` (default `30d`: an edit never shortens the state's
  life), re-signed. `--ttl` on `init` and `invite` is the minted **membership's** lifetime only.
  The host set is **derived**: a member is a host exactly when some service names it.
- **Monotonic copies.** Every node keeps its newest verified copy in `state.json`, written only
  through `adopt_if_newer(ks, candidate, root, now)`: the candidate must verify, be fresh, and be
  strictly newer (`is_newer_than`: same fabric, higher version). The re-read, check and write happen
  under one exclusive file lock (`state.json.lock`), so a removed member presenting a genuine older
  state can't roll a node back.
- **Names.** `ServiceName` is `[a-z][a-z0-9_-]*`, at most 64 bytes (the same rules as the session's
  `ToolName`). `RoleName` is 1–64 of `[A-Za-z0-9_.-]`.
- **Roles.** A role is an OR of matchers; a matcher is an AND of its keys over the caller's verified
  IdP principal: `issuer` (exact, **required**), `email` (exact, or `*@domain`), `org` (Google's
  `hd`), `group`. Because every matcher names its issuer, a token another trusted issuer minted
  for the same email never satisfies it. `issuer=…` alone is "anyone that IdP verified". There is
  no built-in role: **with no verified principal, no role admits** (`role_admits`). `member` is an
  ordinary role name.
- **`authorize(state, caller, principal, service)`** (`library/services/access.rs`), in order: the
  caller is a member (`NotAMember`); the service exists (`UnknownService`); it allows some role
  (`NobodyAllowed`); the first role in `allow` that admits the caller's verified principal is
  returned (`NotInRole`, whose text asks for `wires login` when there is no principal). `allowed_services` runs it for
  every service: that is `wires services`, evaluated locally with no network.

The state is not secret. Every member holds all of it: member and host node ids, role matchers,
service names and descriptions. That is also why there is no Merkle-committed roster any more: it
existed to prove inclusion without showing the member set, and a member that must evaluate the
registry locally has to hold the set anyway.

### Admin surface

| Command | Effect on the state |
|---|---|
| `wires init [--ttl] [--state-ttl]` | New root and node keys, this node's membership, version 1 with this node as its one member. |
| `wires invite <node-id> [--name] [--ttl] [--state-ttl]` | Adds the member, mints its membership (valid for `--ttl`), prints one `Invite` token, pushes the state. |
| `wires remove <name\|id> [--state-ttl]` | Drops the member (and from every service's `hosts`), pushes the state. |
| `wires role set <name> [--issuer URL] [--state-ttl] <matcher>…` / `role rm <name>` | Defines or drops a role. A matcher is `*@example.com`, `alice@example.com`, or `issuer=…,email=…,org=…,group=…`; one without `issuer=` takes `--issuer` (default `https://accounts.google.com`). |
| `wires service add\|set <name> [--description] [--allow role]… [--host member]… [--reader role]…` / `service rm <name>` | Edits the registry. `--host` takes an `invite --name` label or a node id, and must be a member. |
| `wires state push` | Changes nothing: re-sends the stored state to every host (§4). |

Every edit but `init` takes `--state-ttl` and ends with the push in §4.

`Invite { format: 2, membership, state: SignedState, admin: NodeId }` is everything a new node needs.
`Invite::verify(me, now)` requires that the membership passes `check_inclusion` under its own
`fabric` and names `me`, and that the state verifies under that same root, is fresh, and lists `me`
as a member. `wires join` stores the membership, adopts the state (never rolling back a newer
one), and records `admin` in `state-admin.txt` as a place to pull from. The token is not secret.
It works as **trust on first use**, because the token introduces the root; what vouches for the
admin is whatever carried the token out of band (see
[card 18](board/backlog/18-front-door-OPEN.md)).

## 4. Moving the state: `wires/state/1`

Frames are length-prefixed canonical JSON tagged by `type`, at most 4 MiB
(`library/services/sync.rs`, `wires/state/sync.rs`): `offer {state}`, `have {version}`,
`denied {reason}`. One exchange per connection; 5 s to dial, 10 s for the answer.

- **Push.** After every admin edit, and on `wires state push`, the admin dials, concurrently,
  every **host** of the new state plus every host of the state before the edit (so a node that
  stops hosting learns it), never itself, and sends `offer`. Plain members aren't dialed: only
  `serve` runs the responder, so nothing listens there. The receiver's answer is `have` with the
  version it now holds; a host counts as delivered when that is at least the offered version.
  Stderr says `state version N: pushed to K of H host(s)`, naming any not reached. **When H > 0 and
  K = 0 the command exits 1** (after printing its result, e.g. the invite token): the new state is
  stored on the admin and in force nowhere. `wires state push` re-sends it. With no hosts at all
  there is nothing to reach and nothing fails; members get the state in their invite token.
- **Pull.** A cold command (`call`, `mcp`, `inbox`, and the hidden `tools` alias) whose copy was
  last checked more than 10 minutes ago (`state-checked.txt`) sends `have` to, in order, the hosts
  in `last-good.json` (the hosts it has called), every other host in its copy, then the admin, for
  at most 8 s. It **stops at the first answer that settles it**: a verified, fresh, newer `offer`
  (adopted), or a `have` at least its own version from a vouched peer (a host in its copy, or the
  admin in `state-admin.txt`). Only those two mark the copy checked; a refusal, a peer behind it,
  or an unvouched answer doesn't. A running `serve` does the same every 10 minutes, and once at
  start when its preflight fails (a host assigned a service while it was offline pulls it from the
  other hosts in its copy, then preflights again). `wires services` never pulls: it reads the
  local copy only.
- **Handshake.** A host whose state is newer than the version in a caller's `Hello` hands it back in
  `HelloAck.newer_state` (§5); the caller adopts it before sending stdin.
- **The responder** (`StateResponder`, on every `serve`). Any key can dial it, so it serves at
  most 16 exchanges at once (one more is closed unanswered) and sizes no buffer from a length
  prefix: a frame over 4 KiB must open as an `offer` (`{"state":`, checked before the rest is
  read), and nothing is over 4 MiB. A held copy that has expired vouches for nobody, and a dialer
  it doesn't list hears only `not admitted to this fabric` (no version, not whether the copy
  expired; the detail is traced, throttled). To an `offer` from a member of the fresh held copy it
  runs `adopt_if_newer`. Adopted: it marks its copy checked and answers `have`. Not adopted
  (older or equal): it answers `have` and does **not** mark its copy checked, so a removed member
  the copy still lists, replaying its old, still-fresh state, can't stop the host pulling the
  newer one. An `offer` from anyone else is taken only if it vouches for the dialer (a host whose
  copy expired or predates the dialer, catching up): the free checks first (this fabric, strictly
  newer than the held copy, fresh, listing the dialer), and only then the signature, once, by
  `adopt_if_newer`. To a `have`, the dialer must be a member of the held copy; then an expired copy
  is refused as expired (never served), and otherwise it answers `offer` when it holds a newer one,
  else `have`.

A node never adopts an older or unverifiable state, so a lying peer can only fail to help. A host
that was offline when a service was assigned to it catches up at `serve` start from another host,
or by joining with a fresh invite (re-joining never rolls back).

## 5. Sessions: `wires/session/3`

A session is one bidirectional QUIC stream on ALPN `wires/session/3`. Codec:
`library/calls/session.rs`. Transport: `wires/host/transport.rs`.

| Tag | Frame | Body | Direction |
|---|---|---|---|
| 8 | `Hello` | canonical JSON `{membership, state_version, id_token?}` | caller → host |
| 7 | `Invoke` | canonical JSON `Invocation {tool, argv}` | caller → host, right after `Hello`, without waiting |
| 9 | `HelloAck` | canonical JSON `{membership, state_version, newer_state?}` (the host's own) | host → caller |
| 6 | `Denied` | UTF-8 reason (at most 512 bytes) | host → caller, terminal |
| 1/2/3 | `Stdin`/`Stdout`/`Stderr` | raw chunk (at most 64 KiB when pumped) | stdin: caller → host; stdout/stderr: host → caller |
| 4 | `Exit` | i32, big-endian | host → caller, terminal |

Tags 0 and 5 (the channel-era `Handshake`/`HandshakeAck`) are retired and decode as `BadFrame`.

**The host** reads `Hello` (10 s timeout, at most 64 KiB) and `Invoke` (at most 512 KiB: the
largest valid `Argv`, JSON-escaped), then re-reads its signed state **for this connection**, so a
removal applies on the next dial without a restart. Before it knows who is asking it holds at most 64
sessions open (one more is closed unanswered), and it sizes no buffer from a length prefix. The first
failure below is sent as `Denied` (`wires/host/gate.rs`):

1. The host holds a readable state (else `responder configuration error`).
2. **Membership, before anything else:** `check_inclusion(hello.membership, trust_root, caller,
   now)` and the state lists `caller`. Anyone else — no credential, someone else's, another fabric's,
   expired, removed — hears only `not admitted to this fabric`: no reason, no state version. Their
   token is never verified (no JWKS fetch, no identity-index entry), and the refusal is traced
   (throttled), **not** written to the call log, so strangers can't fill it.
3. **Identity.** The `id_token`, if any, is verified by the host itself (§6); the principal, or why
   there is none, is kept for the next steps. A token that fails is `your ID token could not be
   verified` or `the identity provider is unreachable from this host`; the detail is only in the
   host's trace.
4. **The gate** (`admit`): the state is fresh → the service is registered → it is assigned to
   **this** host → `authorize` (the registry's `allow`) → every role in `host.json`'s `also_require`
   for it admits the caller too (it can only narrow; the refusal doesn't name those host-local roles).
   A refusal that a verified identity could change leads with why there is none (`no ID token
   presented; run \`wires login\``).
5. **Implementation.** Only an admitted caller learns whether `host.json` implements the service
   (`service … is not implemented on this host`).

Every refusal from step 3 on (the caller is a member) is logged as an `AuditRecord::Denied`.

The host then appends the call's `Started` to its call log and `fsync`s it (§8) — if it can't, the
call is refused (`this host can't record calls right now…`) and nothing runs — sends `HelloAck`
(with `newer_state` when the caller's `state_version` is older) and execs the service's fixed argv
**with the caller's argv appended element by element, never through a shell**, in its `cwd`. The
child's environment is built from nothing (`env_clear`): only `PATH`, `LANG` and `LC_*` are
inherited from `serve`; then `host.json`'s `env`; then the server-derived `WIRES_CALLER_NODE`,
`WIRES_FABRIC_ROOT`, `WIRES_MEMBERSHIP_NOT_AFTER`, `WIRES_STATE_VERSION`, `WIRES_SERVICE`,
`WIRES_TOOL`, `WIRES_ROLE`, and, when verified, `WIRES_CALLER_EMAIL`. With `push` on, also
`WIRES_PUSH_SOCKET` and `WIRES_PUSH_TOKEN`, the call's push capability (§7), already bound to the
call's id before the child starts. The child never gets `WIRES_HOME`, `HOME`, agent sockets or
cloud credentials. If the connection closes, the host kills the child.

The child still runs as `serve`'s own Unix user, so a service a caller can steer into reading or
writing files can reach whatever that user can, the host's keystore included. **Run services as a
separate Unix user** (for example, a `command` of `["sudo", "-u", "svc", "--", "tool"]`). `wires`
does not switch users itself, and a service running as another user can't reach the child socket
(§7, a 0700 directory) until the operator opens that directory to it. Independently of that, the host fails closed on the parts of its
keystore a child could tamper with: it keeps the highest state version it has decided under in
memory and refuses to decide under an older `state.json` (`responder configuration error`, logged
as a rollback), and it trusts only issuer keys it fetched itself (§6).

**The caller** (`wires call`, `wires mcp`) refuses to dial from an expired state (exit 1: ask the
admin for `wires state push` or a fresh invite). It takes the service's hosts from its state, the
last host that answered (`last-good.json`) first, then the admin's order. It fails over to the next
host **only when a dial fails** (10 s each); a host that answered has decided. It sends `Hello` and
`Invoke` together, then, before it forwards a byte of stdin, **always** verifies the `HelloAck`
membership with `check_inclusion(ack, own fabric, authenticated host id, now)` and adopts any
`newer_state` (`adopt_if_newer`); if that state fails to verify, or the state it now holds no
longer assigns the service to that host, the call stops there (exit 1, no stdin sent). The host
already has the `Invoke` (argv) by then: a removed host that still holds a valid membership sees
the argv; card 29's ban list closes that.

Exit codes: `Denied` → **77**, nothing on stdout. Local or transport failure (including the checks
above) → 1. Otherwise the remote exit code, **except that a remote 77 is reported as 1** with a
note on stderr, so 77 always means the host refused. A session that ends without `Exit` is an
error. Limits: 16 MiB largest frame once admitted (64 KiB `Hello` and 512 KiB `Invoke`
before); `Argv` holds at most 256 arguments and 64 KiB.

A `tools.json` alias pins a local name to one host (node id, optional addresses and relay) and a
`remote_tool` service name; it opens the same `Hello`, so the host still decides by its state. A
service registered in the state wins over an alias of the same name, and an alias is refused before
dialing unless the current state assigns its `remote_tool` service to its host.

## 6. Identity

`wires login` runs OIDC (authorization code, PKCE, loopback redirect) with `nonce =
base64url(blake3::derive_key("wires oidc-nonce v1", node_id))`, verifies the token locally, and
stores it in `idp-token.jwt`. Nothing is published. The token travels in the session `Hello` and the
inbox `hello` (§7).

A host verifies it against the issuer's JWKS under **its own** trust: `host.json`'s
`identity.issuers`, each with the audiences it accepts from that issuer. `verify_claim` checks, in
order: `alg` is RS256 or ES256 and a JWKS key verifies the signature; `iss` matches exactly; an `aud`
value is accepted; `exp` and `iat` are within the 60 s clock skew; `nonce == for_node(caller)`.
`email` is used only when `email_verified` is true; `hd` becomes `org` only when `iss` is exactly
`https://accounts.google.com`; `groups` is kept. A host
remembers the latest verified principal per node (`wires/host/identity.rs`) and never lets a failure
or an older token displace it. It knows only the callers that presented a token **to it**, and it
verifies a token only from a member of its state (§5 step 2). A host keeps issuer key sets **in
memory only** and never reads the `jwks/` disk cache, which anything running as its user could
write; callers keep that cache, and trust a disk entry for at most 24 h.

**A web gateway** (`wires gateway`) is one member node that carries many principals: it asks the IdP
for each web user's ID token with `nonce = for_node(gateway)` and presents that user's token in the
`Hello` of each call it makes for them. Nothing on the wire changes; the host sees a member node
presenting a token bound to it. The gateway offers a user only services that a role admits by
that user's own verified principal; the gateway's node alone is in no role. It issues its own OAuth access tokens (opaque, bound to its
`/mcp`, expiring with the ID token) and no refresh tokens. Its MCP endpoint serves the 2026-07-28
Streamable HTTP binding and the legacy `initialize` era ([deployment.md](deployment.md)).

## 7. Push: `wires/inbox/2`

A host sends a `PushMessage { id, from, to, subject (≤128 B), body (≤16 KiB), at_ms, expires_ms }`
to a caller, addressed **by key**. Frames are length-prefixed canonical JSON tagged by `type`:
`hello {membership, id_token?}`, `fetch {wait_ms}`, `deliver {messages ≤ 32}`, `ack {ids}` and
`denied {reason}`, at most 4 MiB; a `hello` (and a host's `fetch`) is read before the peer is known,
so it may be at most 64 KiB. Two ways a message is delivered:

- **Direct:** the host dials the recipient (3 s budget). A running `wires inbox --wait` serves the
  inbox ALPN and accepts `deliver` only from a member its signed state names as a **host**.
- **Fetch:** `wires inbox` dials the hosts of every service it may call (`hello` with its stored ID
  token, `fetch` held open for up to 25 s, `deliver`, then `ack`).

The host authorizes at send, at delivery and at fetch (`ServicesHost::decide_push`): the recipient
must be a member of the current state, in the first registry role of `host.json`'s `push.allow` that
admits it (default: nobody). **The identity rule:** every role needs the recipient's verified
principal, which the host learns only when the recipient presents its token to it: on a call, or in
an inbox fetch. `--to <role>` names the members whose known principal the role admits; a member
with no verified identity here is in no role. A fetch is checked like a call: at most 64 undecided
at once, membership first, and a non-member hears only `not admitted to this fabric`, has its token
left unverified, and is traced, not logged; a removed member's queue is dropped (each message logged
`denied`) and its fetch refused. A member holds at most 2 long polls open per host; a member's
policy refusal is answered, not logged (`wires inbox` asks every host of its services).

A receiver refuses a message whose `from` is not the authenticated peer or whose `to` is not itself.
Delivery is at least once; the receiver removes duplicates by `PushId`. The host queues up to 64
messages per recipient (oldest dropped), in `push-queue.json`. The TTL defaults to 24 h and is at
most 7 d. Each milestone is an `AuditRecord::Push`.

`wires push` hands the message to the running `serve` over one of two local sockets (NDJSON,
`wires/host/control.rs`), each mode 0600 in a 0700 directory that the server and the operator's
client both check is owned by `geteuid()`:

- **The operator socket**, `run/serve.sock`: `{"push":{to, subject, body, ttl_secs?}}` to any node
  or role. A service child is not told where it is.
- **The child socket**, `child/push.sock`: a service pushing back to **its own caller**. With a
  `push` section in `host.json`, for every call `serve` mints a random 32-byte token (64 hex) and gives the child `WIRES_PUSH_SOCKET` and
  `WIRES_PUSH_TOKEN`; `wires push` sees the token and sends `{"caller_push":{token, push}}` (no
  keystore needed). The socket accepts it only for a live token and only with `to` equal to that
  call's caller node id (never a role or another node); the operator's `push` form is refused
  there. A token is live for the call and 10 minutes after it ends (`CAPABILITY_GRACE`), so a job
  the call started can still report; tokens are memory-only, so a restart kills them. The push
  still passes `push.allow`, and its records carry `call`, the call whose capability sent it.

This is push as built. [Card 31](board/backlog/31-inbox-delivery.md) (agreed, not built) is the
next step: every callback goes to the calling node **and** principal through the call's
capability only, the operator's `push` narrows to `--to <node-id>`, role addressing goes, and an
`inbox` MCP tool reaches `wires mcp` and the gateway.

## 8. Records

**The call log** (`library/calls/call_log.rs`, `wires/host/call_log.rs`). Every `AuditRecord` a host
produces (`started {call, caller, principal?, tool, argv, roster_version?, role?}` — `roster_version`
carries the state version — `finished {call, exit, duration_ms, stdout/stderr bytes, stdout_digest,
stdin_bytes, stdin_digest, stdin_head ≤4 KiB}`, `denied {caller, principal?, tool?, reason}`, `push {id, to,
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
be, the call is refused and doesn't run. `finished`, a member's `denied` and push records describe
something that already happened, so a failure is traced as an error and the session goes on; while
the log stays unwritable every new call fails its own `started` and is refused, and the host serves
again once an append succeeds (a failed append is cut off the file first). A `started` without a
`finished` means the end wasn't recorded, not that the call never ran. Refusals of peers that are not
members of the state are traced, not logged (§5), so no one outside the fabric can write to it.

**The record stream** (`wires/records/1`, `wires/host/record_stream.rs`): length-prefixed JSON
frames. The reader sends `open {hello, services, since?, mine, follow}`. The host checks membership
first: a reader that isn't a current member gets `denied` with the fixed text `not admitted to this
fabric` and nothing else. Otherwise it answers `granted {scopes, tip?, first?}`: per requested service
assigned here, `all` when the reader's verified principal is in one of the service's `readers` roles
and it didn't ask for `mine`, else `mine`; `tip` is the log's newest `{seq, hash}` and `first` the
oldest seq it still holds. Then `batch`es of items after `since`, `caught_up`, and with `follow` more
batches as the log grows. A `follow` stream is re-decided (membership, freshness, readers) whenever the
host's signed state changes and when the reader's ID token, the state or its membership expires:
`denied` ends it when access is gone (including an ID token that expired: the reader logs in and
watches again), and a new `granted` precedes entries decided under a changed view.

Each entry is sent either **in full** (signed, as stored) or inside a `hidden` run carrying only its
`{prev, hash}` link, so the reader checks the chain across what it may not see. An entry is shown in
full when its service was requested and granted `all`, or when its service was requested and its
subject is the reader's **person**: the same verified principal (issuer and `sub`) the host verifies
for the reader now, whichever node either used. A reader with no verified principal sees nothing in
full. Subjects and services: `started` — its tool, its `principal`; `finished` — its `started`'s (if
that was pruned, the entry is only a hidden link); `denied` — its tool, its `principal` (no tool:
shown only to its subject); `push` — the service of the call whose capability sent it (`call` → that
call's `started`), and the principal it was admitted for. An operator push (no `call`), or one whose
call's `started` was pruned, is shown only to its recipient.

What hidden links reveal: a reader in no `readers` role still learns how many entries each host it
reads logged, and under `follow`, when each was written (a run arrives as the entries are appended).
Not what, by whom, or for which service. (Card 29 replaces this with checkpoints and inclusion proofs,
and drops hidden links for non-readers.)

`wires watch` merges the hosts' backlogs by time. It keeps, in `record-marks.json`, **one chain anchor
per host** (the furthest entry it verified there, under any view) and a **resume point per view** (the
services asked of that host, `mine`). A view resumes from its own point, and wherever its stream passes
the anchor the entry there must be the one verified before, and the next must link to it; entries
before the anchor are shown only once the anchor confirms them. So a rewrite is caught even by a view
that never saw that stretch. Against `granted`: a `tip` below the anchor is a rollback, and a different
hash at the anchor a fork; both are alarms. A `first` past the entry after the anchor is retention: a
notice (`host … pruned entries before seq N (retention)`), and the anchor restarts from what the host
still holds. Any alarm stops that host's stream (exit 1) and leaves its marks at the last good entry.
The service label a line shows is the reader's own, derived from signed records: a `started`'s tool,
paired locally with its `finished` and the pushes naming its call; the host sends no label.

Nothing is broadcast: a record's content leaves a host only when a reader asks for it and may see it; any other member asking gets its hash link.

## 9. Keystore (`$WIRES_HOME`, else `$XDG_CONFIG_HOME/wires`, else `~/.config/wires`)

| File | Mode | Holder | Content |
|---|---|---|---|
| `root.seed`, `node.seed` | 0600 | admin / every node | hex Ed25519 seed |
| `names.json` | 0600 | admin | local labels for `remove` and `service --host`; never sent |
| `membership.json` | 0644 | every node | membership token |
| `state.json` (+ `.lock`) | 0600 | every node | the newest verified signed state (§3) |
| `state-admin.txt`, `state-checked.txt` | 0600 | every node | where to pull from; when the copy was last checked |
| `idp-token.jwt`, `idp-refresh-token` | 0600 | caller | from `wires login` |
| `last-good.json` | 0600 | caller | service → the host that last answered |
| `hints` | — | any node | optional local dial hints (below) |
| `tools.json` | — | caller | locked mode; optional aliases |
| `inbox/` | 0700 | caller | `new/` (≤256 unread), `read/` (last 1024), `notes/` |
| `record-marks.json` | — | reader | `wires watch`: per host, the chain anchor, a resume point per view, recent call labels |
| `call-log.jsonl`, `push-queue.json` | — | host | §8, §7 |
| `jwks/` | — | caller | cached issuer keys (a host never reads it, §6) |
| `run/serve.sock`, `run/hint` | 0600 | host | the operator's push socket; this host's own hint line |
| `child/push.sock` | 0600 | host | the child socket for a call's push capability (§7) |

A host's keystore must not hold `root.seed`: `wires serve` refuses to start from the admin's
keystore. Run the host from its own (`WIRES_HOME=<dir> wires id`, invite that node, join there).

**Hints** (`wires/caller/pick.rs`). `$WIRES_HOME/hints` is local and unsigned: one line per node,
`<node id hex> <ip:port>…`, `#` comments, bad lines skipped. Every endpoint `wires` binds registers
it beside n0 discovery, so calls, state sync, push and fetches all use it. `serve` writes its own line
to `run/hint`. A hint only says where to try; iroh still authenticates the key.

Every file above is written atomically: a temporary file created `O_EXCL` with mode 0600, widened
to the listed mode (only `membership.json`'s 0644) after the write, then renamed over the target. A
file with no listed mode is 0600. The keystore directory the state store creates is 0700.

Flags, environment variables and `--…-file` paths override the keystore, in that order of
precedence. Locked mode (`WIRES_LOCKED`) refuses the credential flags and the `WIRES_NODE_SEED` /
`WIRES_MEMBERSHIP` variables; it assumes the agent can't set its own environment.

## 10. Known limits

- Nothing renews memberships or the state; a membership expires after its `--ttl`, the state after
  its `--state-ttl` (both default 30 days). An expired state admits nobody, is served by nobody, and
  is dialed from by no caller until the admin signs a newer one.
- The admin is a one-shot CLI and is pushed only to hosts: a plain member gets a new state by its
  next pull (from a host) or at a call's handshake. A host assigned a service while offline pulls
  it at `serve` start from another host in its copy; with none up, it needs a fresh invite.
- Known and accepted until [card 29](board/backlog/29-identity-and-scale.md):
  - Every member holds the whole state: every member id, every role's matchers (often people's
    emails) and every service. Agents learn the org chart, and the state grows with the number of
    members, so onboarding N people costs O(N) states of O(N) size to every host.
  - The caller checks the host's membership and that its own (newest) state assigns the service to
    that host, but only after the host already holds the `Invoke`: a removed host whose membership
    hasn't expired sees the argv (not stdin).
  - Hidden record links (§8) tell a non-reader how many entries a host logged, and when.
  - Google ID tokens last about an hour, and Google drops the `nonce` on refresh, so a person signs
    in again roughly hourly (a web gateway session ends with the token).
- A host knows a caller's identity only after the caller presented its token to that host, and
  indexes it per node, so push by role reaches only those callers (card 31 removes role push).
- A web gateway holds each signed-in user's gateway-bound ID token until it expires (~1 h). It
  offers tools only: push is keyed by node (card 31), and `watch` isn't an MCP tool.
- One fabric per keystore.

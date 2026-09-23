# The wires protocol

This document describes the protocol as the code implements it today: `library/` (pure types and
codecs) and `wires/` (the iroh transport and CLI). If this document and the code disagree, the
code is correct and this document should be fixed.

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
- **`State::validate`** (run by `sign` and `verify`): format is 1; `hosts ⊆ members`; `member` is
  built in and can't be defined; every role has at least one matcher and no empty matcher; every
  role a service's `allow` or `readers` names is defined (or `member`); every service host is in
  `hosts`, listed once.
- **`SignedState::verify(root)`** checks the algorithm, the `fabric == root` pin, the signature,
  then `validate`. **`check_fresh(now)`**: `Expired` when `now > not_after`. An expired state admits
  nobody until the admin signs a newer one.
- **Versioning.** Every admin edit (`init`, `invite`, `remove`, `service add|set|rm`, `role
  set|rm`) is the stored state changed, `version + 1`, `issued = now`, `not_after = now + --ttl`
  (default `30d`), re-signed. The host set is **derived**: a member is a host exactly when some
  service names it.
- **Monotonic copies.** Every node keeps its newest verified copy in `state.json`, written only
  through `adopt_if_newer(ks, candidate, root, now)`: the candidate must verify, be fresh, and be
  strictly newer (`is_newer_than`: same fabric, higher version). The re-read, check and write happen
  under one exclusive file lock (`state.json.lock`), so a removed member presenting a genuine older
  state can't roll a node back.
- **Names.** `ServiceName` is `[a-z][a-z0-9_-]*`, at most 64 bytes (the same rules as the session's
  `ToolName`). `RoleName` is 1–64 of `[A-Za-z0-9_.-]`.
- **Roles.** A role is an OR of matchers; a matcher is an AND of its keys over the caller's verified
  IdP principal: `issuer` (exact), `email` (exact, or `*@domain`), `org` (Google's `hd`), `group`.
  The built-in role `member` admits any member, with or without an identity.
- **`authorize(state, caller, principal, service)`** (`library/services/access.rs`), in order: the
  caller is a member (`NotAMember`); the service exists (`UnknownService`); it allows some role
  (`NobodyAllowed`); the first role in `allow` that admits the caller is returned (`NotInRole`,
  whose text asks for `wires login` when there is no principal). `allowed_services` runs it for
  every service: that is `wires services`, evaluated locally with no network.

The state is not secret. Every member holds all of it: member and host node ids, role matchers,
service names and descriptions. That is also why there is no Merkle-committed roster any more: it
existed to prove inclusion without showing the member set, and a member that must evaluate the
registry locally has to hold the set anyway.

### Admin surface

| Command | Effect on the state |
|---|---|
| `wires init [--ttl]` | New root and node keys, this node's membership, version 1 with this node as its one member. |
| `wires invite <node-id> [--name] [--ttl]` | Adds the member, mints its membership, prints one `Invite` token, pushes the state. |
| `wires remove <name\|id> [--ttl]` | Drops the member (and from every service's `hosts`), pushes hosts first. |
| `wires role set <name> <matcher>…` / `role rm <name>` | Defines or drops a role. A matcher is `*@example.com`, `alice@example.com`, or `issuer=…,email=…,org=…,group=…`. |
| `wires service add\|set <name> [--description] [--allow role]… [--host member]… [--reader role]…` / `service rm <name>` | Edits the registry. `--host` takes an `invite --name` label or a node id, and must be a member. |

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

- **Push.** After every admin edit, the admin dials every member but itself, **hosts first**
  (concurrently), then the rest, and sends `offer`. The receiver's answer is `have` with the version
  it now holds; a member counts as delivered when that is at least the offered version. Stderr says
  `state version N: pushed to K member(s)`, naming any not reachable.
- **Pull.** A cold command (`call`, `mcp`, `inbox`, and the hidden `tools` alias) whose copy was
  last checked more than 10 minutes ago (`state-checked.txt`) sends `have` to every host in its copy, then the admin, for at
  most 8 s; the first newer verified `offer` is adopted. A running `serve` does the same every 10
  minutes. `wires services` never pulls: it reads the local copy only.
- **Handshake.** A host whose state is newer than the version in a caller's `Hello` hands it back in
  `HelloAck.newer_state` (§5); the caller adopts it.
- **The responder** (`StateResponder`, on every `serve`): to an `offer`, it requires the dialer to
  be a member of the held copy or of the (verified) offered one, then runs `adopt_if_newer` and
  answers `have`. To a `have`, it requires the dialer to be a member of the held copy, and answers
  `offer` when it holds a newer one, else `have`. Anything else is `denied`.

A node never adopts an older or unverifiable state, so a lying peer can only fail to help. A host
that was offline when a service was assigned to it catches up by its next pull, or by joining with a
fresh invite (re-joining never rolls back).

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

**The host** reads `Hello` (10 s timeout) and `Invoke`, then re-reads its signed state **for this
connection**, so a removal applies on the next dial without a restart. The first failure below is
sent as `Denied` and logged as an `AuditRecord::Denied` (`wires/host/gate.rs`):

1. The host holds a readable state (else `responder configuration error`).
2. `check_inclusion(hello.membership, trust_root, caller, now)`: `membership rejected: …`.
3. **Identity.** The `id_token`, if any, is verified by the host itself (§6); the principal, or why
   there is none, is kept for the next steps.
4. **The gate** (`admit`): the state is fresh → the caller is a member (`not a member of the
   current signed state (version N)`) → the service is registered → it is assigned to **this** host
   → `authorize` (the registry's `allow`) → every role in `host.json`'s `also_require` for it admits
   the caller too (it can only narrow). A refusal that a verified identity could change leads with
   why there is none (`no ID token presented; run \`wires login\``).
5. **Implementation.** Only an admitted caller learns whether `host.json` implements the service
   (`service … is not implemented on this host`).

The host then sends `HelloAck` (with `newer_state` when the caller's `state_version` is older) and
execs the service's fixed argv **with the caller's argv appended element by element, never through
a shell**, in its `cwd`, with its `env`. It scrubs every inherited `WIRES_*`, then sets the
server-derived `WIRES_CALLER_NODE`, `WIRES_FABRIC_ROOT`, `WIRES_MEMBERSHIP_NOT_AFTER`,
`WIRES_STATE_VERSION`, `WIRES_SERVICE`, `WIRES_TOOL`, `WIRES_ROLE`, `WIRES_HOME` (the host's own, so
a service can `wires push`) and, when verified, `WIRES_CALLER_EMAIL`. If the connection closes, the
host kills the child.

**The caller** (`wires call`, `wires mcp`) takes the service's hosts from its state, the last host
that answered (`last-good.json`) first, then the admin's order. It fails over to the next host **only
when a dial fails** (10 s each); a host that answered has decided. It sends `Hello` and `Invoke`,
then **always** verifies the `HelloAck` membership with `check_inclusion(ack, own fabric,
authenticated host id, now)` before it forwards a byte of stdin. `Denied` → exit 77, nothing on
stdout; local or transport failure → 1; otherwise the remote exit code. A session that ends without
`Exit` is an error. Limits: 16 MiB largest frame; `Argv` holds at most 256 arguments and 64 KiB.

A `tools.json` alias pins a local name to one host (node id, optional addresses and relay) and a
`remote_tool` service name; it opens the same `Hello`, so the host still decides by its state.

## 6. Identity

`wires login` runs OIDC (authorization code, PKCE, loopback redirect) with `nonce =
base64url(blake3::derive_key("wires oidc-nonce v1", node_id))`, verifies the token locally, and
stores it in `idp-token.jwt`. Nothing is published. The token travels in the session `Hello` and the
inbox `hello` (§7).

A host verifies it against the issuer's JWKS under **its own** trust: `host.json`'s
`identity.issuers`, each with the audiences it accepts from that issuer. `verify_claim` checks, in
order: `alg` is RS256 or ES256 and a JWKS key verifies the signature; `iss` matches exactly; an `aud`
value is accepted; `exp` and `iat` are within the 60 s clock skew; `nonce == for_node(caller)`.
`email` is used only when `email_verified` is true; `hd` becomes `org`; `groups` is kept. A host
remembers the latest verified principal per node (`wires/host/identity.rs`) and never lets a failure
or an older token displace it. It knows only the callers that presented a token **to it**.

## 7. Push: `wires/inbox/2`

A host sends a `PushMessage { id, from, to, subject (≤128 B), body (≤16 KiB), at_ms, expires_ms }`
to a caller, addressed **by key**. Frames are length-prefixed canonical JSON tagged by `type`:
`hello {membership, id_token?}`, `fetch {wait_ms}`, `deliver {messages ≤ 32}`, `ack {ids}` and
`denied {reason}`, at most 4 MiB. Two ways a message is delivered:

- **Direct:** the host dials the recipient (3 s budget). A running `wires inbox --wait` serves the
  inbox ALPN and accepts `deliver` only from a member its signed state names as a **host**.
- **Fetch:** `wires inbox` dials the hosts of every service it may call (`hello` with its stored ID
  token, `fetch` held open for up to 25 s, `deliver`, then `ack`).

The host authorizes at send, at delivery and at fetch (`ServicesHost::decide_push`): the recipient
must be a member of the current state, in the first registry role of `host.json`'s `push.allow` that
admits it (default: nobody). **The identity rule:** `push.allow: ["member"]` needs no identity; any
other role needs the recipient's verified principal, which the host learns only when the recipient
presents its token to it: on a call, or in an inbox fetch. `--to <role>` names the members whose
known principal the role admits (`member`: every member). A removed member's queue is dropped
(logged `denied`) and its fetch refused.

A receiver refuses a message whose `from` is not the authenticated peer or whose `to` is not itself.
Delivery is at least once; the receiver removes duplicates by `PushId`. The host queues up to 64
messages per recipient (oldest dropped), in `push-queue.json`. The TTL defaults to 24 h and is at
most 7 d. `wires push` hands the message to the running `serve` over its control socket
(`run/serve.sock`, mode 0600 in a 0700 directory). Each milestone is an `AuditRecord::Push`.

## 8. Records

**The call log** (`library/calls/call_log.rs`, `wires/host/call_log.rs`). Every `AuditRecord` a host
produces (`started {call, caller, principal?, tool, argv, roster_version?, role?}` — `roster_version`
carries the state version — `finished {call, exit, duration_ms, stdout/stderr bytes, stdout_digest,
stdin_bytes, stdin_digest, stdin_head ≤4 KiB}`, `denied {caller, tool?, reason}`, `push {id, to,
subject, outcome, reason?, body?}`) becomes a `LogEntry { v: 1, host, seq, prev, at_ms, record,
sig }`: dense 0-based `seq`, `prev` the hash of the previous entry (zero at seq 0), signed by the
host over `"wires/call-log/v1\0"` ‖ canonical JSON of the other fields. `verify_chain` reports a bad
signature, a gap, a broken link or a fork. The log is `call-log.jsonl` (fsync per entry), re-verified
on open, pruned from the front after 30 days, and optionally exported over OTLP/HTTP
(`audit.otlp`). A host can still withhold or truncate its own history; rewrites are detectable only
against a copy someone holds.

**The record stream** (`wires/records/1`, `wires/host/record_stream.rs`): length-prefixed JSON
frames. The reader sends `open {hello, services, since?, mine, follow}`. The host answers `denied`
(not a member), or `granted {scopes}`: per requested service assigned here, `all` when the reader is
in one of the service's `readers` roles and didn't ask for `mine`, else `mine`. Then `batch`es of
items after `since`, `caught_up`, and with `follow` more batches as the log grows. Each entry is sent
either **in full** (signed, as stored) or inside a `hidden` run carrying only its `{prev, hash}`
link, so the reader checks the chain across what it may not see. An entry is shown in full when its
service was granted `all`, or when the reader is its subject (the caller of a call or refusal, the
recipient of a push). `wires watch` merges the hosts' backlogs by time and keeps its verified tip per
host in `record-marks.json`; a broken chain stops that host's stream with an alarm (exit 1).

Nothing is broadcast: a record leaves a host only when a reader asks for it and may see it.

## 9. Keystore (`$WIRES_HOME`, else `$XDG_CONFIG_HOME/wires`, else `~/.config/wires`)

| File | Mode | Holder | Content |
|---|---|---|---|
| `root.seed`, `node.seed` | 0600 | admin / every node | hex Ed25519 seed |
| `names.json` | 0600 | admin | local labels for `remove` and `service --host`; never sent |
| `membership.json` | 0644 | every node | membership token |
| `state.json` (+ `.lock`) | 0600 | every node | the newest verified signed state (§3) |
| `state-admin.txt`, `state-checked.txt` | — | every node | where to pull from; when the copy was last checked |
| `idp-token.jwt`, `idp-refresh-token` | 0600 | caller | from `wires login` |
| `last-good.json` | 0600 | caller | service → the host that last answered |
| `hints` | — | any node | optional local dial hints (below) |
| `tools.json` | — | caller | locked mode; optional aliases |
| `inbox/` | 0700 | caller | `new/` (≤256 unread), `read/` (last 1024), `notes/` |
| `record-marks.json` | — | reader | `wires watch` tips |
| `call-log.jsonl`, `push-queue.json`, `jwks/` | — | host | §8, §7, cached issuer keys |
| `run/serve.sock`, `run/hint` | 0600 | host | the push control socket; this host's own hint line |

**Hints** (`wires/caller/pick.rs`). `$WIRES_HOME/hints` is local and unsigned: one line per node,
`<node id hex> <ip:port>…`, `#` comments, bad lines skipped. Every endpoint `wires` binds registers
it beside n0 discovery, so calls, state sync, push and fetches all use it. `serve` writes its own line
to `run/hint`. A hint only says where to try; iroh still authenticates the key.

Flags, environment variables and `--…-file` paths override the keystore, in that order of
precedence.

## 10. Known limits

- Nothing renews memberships or the state; both expire after `--ttl` (default 30 days). An expired
  state admits nobody until the admin signs a newer one.
- The admin is a one-shot CLI: a member offline during a push gets the state by its next pull
  (from a host) or a fresh invite. A host that is assigned a service while offline can't start
  `serve` until it has the new state.
- Every member holds the whole state (member ids, roles, registry).
- A host knows a caller's identity only after the caller presented its token to that host, so push
  by role reaches only those callers.
- One fabric per keystore. The caller checks the host's membership, not whether the host is still
  in the state.

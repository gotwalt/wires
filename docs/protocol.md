# The wires protocol

This document describes the protocol as the code implements it today: `library/` (pure types and
codecs) and `wires/` (the iroh transport and CLI). If this document and the code disagree, the
code is correct and this document should be fixed.

> **Scheduled for removal.** [Card 27](board/backlog/27-services-not-hosts.md) replaces the
> channel (§6), fabric keys and re-keys (§7), and the records that ride the channel (§8) with
> admin-signed service registry state that is pushed and pulled directly. After card 27,
> [card 26](board/backlog/26-host-held-records.md) moves call records into host-held logs.
> §§1–5 (identity, membership, the committed roster, sessions, push) still apply. §§6–8
> describe code that is still in the tree but will be removed.

Usage, roles and the demo are in [README](../README.md), [the board](board/README.md) and
[demo.md](demo.md). Deployment and testing are in [deployment.md](deployment.md) and
[testing.md](testing.md).

## 1. Ground rules

| Rule | Where |
|---|---|
| A node is an Ed25519 key, and `NodeId` is its 32-byte public key. The iroh `SecretKey` is the same seed, so the iroh endpoint id **is** the `NodeId`. | `library/membership/identity.rs`, `transport::secret_key` |
| **The caller is always `to_node_id(conn.remote_id())`**, the key iroh authenticated. It is never a wire field. Every gate below is sound only because of this. | every responder |
| The fabric is named by its root key: `fabric = root.node_id()`. | `Membership::mint` |
| Signed objects sign `canonical_bytes(body)`, which is canonical JSON with keys sorted by `serde_json`'s default `BTreeMap` ordering. `preserve_order` and `arbitrary_precision` must never be enabled. | `library/codec.rs` |
| Every signed body carries a signed format discriminant and a fixed, complete set of fields. **An optional signed field is not allowed**, because an absent field and a present default sign different bytes. A v2 format gets a separate body, and a v1 verifier rejects it with `UnsupportedVersion`. | membership, head, sealed key, envelope |
| Every signed credential signs its own authority (`fabric`), and `verify(root)` requires `fabric == root`. | membership, head, sealed key |
| Tokens are base64url-no-pad of canonical JSON. Wire frames use a 4-byte big-endian length followed by a body. Frame envelopes are unsigned, so `skip_serializing_if` is safe in them. | all codecs |
| `alg` is always `Ed25519`. `not_after` is inclusive, and a credential is expired when `now > not_after`. Times are unix seconds, except `*_ms` fields. | all |

## 2. Membership

`Membership { version: 1, fabric, member, issued, not_after, alg, sig }` is signed by the root. It
answers two questions: which fabric the node belongs to, and which node it is.

`check_inclusion(m, fabric_root, caller, now)` checks, in order: `m.verify(fabric_root)` (algorithm,
version, the `fabric` pin, signature); `m.member == caller` (`SubjectMismatch`, so a membership is
not transferable); `now <= not_after` (`Expired`).

A membership is public. It holds no secret, so presenting it before the peer is verified is safe.
There is no revocation list. Removal happens only through the roster (§3).

## 3. The committed roster

The root keeps the member set (`Roster { fabric, version, members: BTreeSet<NodeId> }`) privately in
`roster.json` (mode 0600). Every change is published as a signed **head**:

```
RosterHead { format: 1, fabric, version: RosterVersion(u64), root: MerkleRoot,
             issued, not_after, alg, sig }            // signed by the fabric root
InclusionProof { member, version, path: [MerkleStep { hash, side: left|right }] }
```

- **The Merkle tree** is blake3 with RFC 6962 domain separation: leaf `blake3(0x00 ‖ node_id)`,
  node `blake3(0x01 ‖ l ‖ r)`, leaves sorted by byte value, an odd node carried up unchanged, and
  `blake3("")` for the empty set. The leaf is the bare `NodeId`, so re-issuing a membership with a
  new TTL does not change the head.
- **Privacy.** The head contains 32 bytes of root, a signature and timestamps. It reveals neither
  the size nor the members of the set. A proof reveals only its holder's id and `O(log n)` sibling
  hashes.
- **`Roster::commit(root, issued, not_after)`** is the only place the version is incremented. It
  bumps the version by 1, builds the tree, signs the head and returns every member's proof. Any
  change moves the root, so **every** proof is re-issued on every commit (see re-keys, §7).
- **`check_roster_inclusion(head, proof, root, caller, now)`** checks, in order: `head.verify(root)`;
  `now <= head.not_after` (`Expired`); `proof.member == caller` (`SubjectMismatch`);
  `proof.version == head.version` (`StaleProof`); `recompute_root == head.root` (`NotInRoster`).
- **Removal is omission.** `wires remove <name|id>` removes the member from `roster.json`,
  commits, and distributes the result. Every verifier that holds the new head refuses the removed
  node on its next dial. A verifier with no head configured falls back to membership and TTL only,
  so the membership TTL bounds that window.
- **Monotonic heads.** A stored head only ever advances. It is written through
  `adopt_if_newer(stored, candidate, root, now)`, a compare-and-swap. The candidate is adopted only
  if it is strictly newer, verifies under the root, and is fresh. The stored head is re-read, the
  check is run and the new head is written under one exclusive lock. Without the lock, a removed
  member presenting a genuine older head could win a race and roll a node back. A newer head with a
  nearer `not_after` still replaces an older one, because the root is the authority on the validity
  window. `advanced import --roster-head` refuses a rollback unless given `--force`.
- **TTL.** `init`, `invite` and `remove` sign heads and memberships with `--ttl`, which defaults to
  `30d` (units `s m h d w`). Nothing renews them automatically. An expired head admits nobody until
  the next commit.

### Admin surface

| Command | Effect |
|---|---|
| `wires init` | Creates the root key and this node's key, adds this node to the roster, commits, and records the channel name. |
| `wires invite <node-id> [--name] [--ttl] [--peer]` | Adds the node, commits, publishes the re-key (§7), and prints one **`Invite`** token on stdout. |
| `wires remove <name\|id> [--ttl]` | Removes the node, commits, and publishes the re-key. The removed node has no entry in it. |
| `wires id` / `wires join <token>` | The joiner prints its id, then installs the token. |
| `wires advanced member\|roster add\|remove\|commit\|head\|import\|publish` | The offline plumbing under the commands above. |

`Invite { format: 1, channel, membership, head, entry: RekeyEntry, peers }` bundles everything a new
node needs. `Invite::verify(me, now)` requires that the membership passes `check_inclusion` under
its own `fabric`, that the entry is for `me`, and that `{head, entry}` passes `Rekey::verify` under
that same root. It then opens the sealed key. The token is not a secret: every part is either public
or sealed to the invitee. It works as **trust on first use**, because the token introduces the root.
What vouches for the admin is the out-of-band channel the token travels over (see
[card 18](board/backlog/18-front-door-OPEN.md)).

## 4. Sessions: `wires/session/2`

A session is one bidirectional QUIC stream on ALPN `wires/session/2`. The protocol version is 2
because the handshake is mutual, so a peer speaking `/1` fails at connect time rather than
mid-handshake. Codec: `library/calls/session.rs`. Transport: `wires/host/transport.rs`.

| Tag | Frame | Body | Direction |
|---|---|---|---|
| 0 | `Handshake` | canonical JSON `{membership, proof?}` | dialer → host |
| 7 | `Invoke` | canonical JSON `Invocation {tool: ToolName, argv: Argv}` | dialer → host, right after the handshake without waiting for the ack |
| 5 | `HandshakeAck` | canonical JSON `{membership, proof?}` (the host's own) | host → dialer |
| 6 | `Denied` | UTF-8 reason (at most 512 bytes) | host → dialer, terminal |
| 1/2/3 | `Stdin`/`Stdout`/`Stderr` | raw chunk (at most 64 KiB when pumped) | stdin: dialer → host; stdout/stderr: host → dialer |
| 4 | `Exit` | i32, big-endian | host → dialer, terminal |

**The responder** reads the handshake and the invoke (the handshake times out after 10 s). It
re-reads its head source for **this connection**, so a commit takes effect on the next dial without
a restart. It then authorizes the caller in this order. The first failure is sent as `Denied` and
recorded as an `AuditRecord::Denied`:

1. `check_inclusion(membership, trust_root, caller, now)`. On failure: `membership rejected: …`.
2. **The roster gate**, only if a head is enforced. It runs `check_roster_inclusion_via(head, proof,
   directory, …)` (§7). On failure: `roster inclusion rejected: …`. Its version becomes
   `WIRES_ROSTER_VERSION`.
3. **Identity.** The caller's verified IdP principal, if the host has one. Today this comes from
   claims on the channel (§8).
4. **Host policy** (`host.json` roles and `allow`, deny by default). This sees the principal, the
   caller, the roster version, the tool and the argv.
5. **Tool lookup.** Only an authorized caller learns whether the tool exists (`unknown tool: <name>`).

The host then sends `HandshakeAck` and execs the tool's fixed argv **with the caller's argv
appended element by element, never through a shell**. It scrubs, then sets, the server-derived
`WIRES_CALLER_NODE`, `WIRES_FABRIC_ROOT`, `WIRES_MEMBERSHIP_NOT_AFTER`, `WIRES_ROSTER_VERSION` (when
a head is enforced) and `WIRES_TOOL`. If the connection closes, the host kills the child.

**Head sources** (`Fixed`, `File`, `Keystore`) fail closed: a missing or malformed `File` refuses
everyone. `Keystore` (`roster-head.json`) is unenforced until a head first appears, then fails closed.

**The dialer** (`wires call`, `wires mcp`) sends its handshake and invoke. It then **always**
verifies the `HandshakeAck` membership with `check_inclusion(ack, own membership.fabric,
authenticated target id, now)` before it forwards a byte of stdin (credential only: the host's
roster freshness is not checked, because a dialer's head may lag). `Denied` → exit 77, nothing on
stdout; local or transport failure → 1; otherwise the remote exit code. A session that ends without `Exit` is an error. Limits: 10 s dial timeout; 16 MiB largest frame;
`ToolName` is `[a-z][a-z0-9_-]*` of at most 64 bytes; `Argv` holds at most 256 arguments and 64 KiB.

## 5. Push: `wires/inbox/1`

A host sends a `PushMessage { id, from, to, subject (≤128 B), body (≤16 KiB), at_ms, expires_ms }`
to a caller, addressed **by key**. Frames are length-prefixed canonical JSON tagged by `type`: `hello
{membership, proof?}`, `fetch {wait_ms}`, `deliver {messages ≤ 32}`, `ack {ids}` and
`denied {reason}`. A frame is at most 4 MiB. There are two ways a message is delivered:

- **Direct:** the host dials the caller's resident `wires watch` (`hello`, `deliver`, then `ack`).
- **Fetch:** `wires inbox` dials the host (`hello`, `fetch` held open for up to 25 s, `deliver`,
  then `ack`).

On `hello`, the host runs `transport::check_member`, which is steps 1–2 of the session gate. It then
runs its `push.allow` roles. A receiver refuses a message whose `from` is not the authenticated
peer, or whose `to` is not itself. Delivery is at least once, and the receiver removes duplicates by
`PushId`. The host queues up to 64 messages per recipient. The TTL defaults to 24 h and is at most
7 d. Each milestone is an `AuditRecord::Push`.

## 6. The channel *(scheduled for removal by card 27)*

The channel is an iroh-gossip mesh per topic. Messages on it are end-to-end encrypted, signed and
hash-linked per publisher. Only roster members can join it. One iroh `Router` carries the gossip,
admission and replay ALPNs, plus the session and inbox ALPNs on a host or resident node. A second
`Router` would overwrite the first one's ALPN set.

**The topic id** is `blake3::derive_key("wires topic-id v1", fabric ‖ name_utf8)`, and it is also
the gossip topic id. Topics are derived, not created. `TopicTicket { fabric, name, peers }` is a
base64 bootstrap hint. It is **unsigned**: tampering with it can make a connection fail, but it can
never get anyone admitted.

**Admission** (`wires/topic-admit/1`) is required because gossip has no authorization hook.
`AdmitFrame::Request` and `AdmitFrame::Ack` both carry `{topic, head, proof}`. `Denied` carries a
reason. A frame is at most 64 KiB, and the codec rejects an over-long length prefix as soon as it
arrives. Both sides run the same `check_topic_admission_via(local, presented, proof, directory,
root, caller, now)`, which does two things:

- It adopts the presented head if `adopt_if_newer` accepts it. Admission therefore also spreads
  head advances.
- It runs `check_roster_inclusion_via` against the chosen head.

The runtime (`wires/channel/admission.rs`):

- It keeps an allowlist of **leases**, each expiring at `min(now + 300 s, head.not_after)` and
  renewed within a third of its TTL. `GatedGossip` closes gossip connections from peers that are not
  admitted; `attach_conn` checks the lease and records the connection under one lock.
- A watchdog runs every 30 s, re-checks every stored proof against the current head, and evicts
  failures (closing their connections).
- At most 64 admissions are in flight at once; dials and handshakes time out after 10 s.

**Fabric keys.** Each commit mints a fresh 32-byte `FabricKey`. A `SealedFabricKey { format: 1,
fabric, version, member, sealed, alg, sig }` is signed by the root and sealed to one member:
the member's Ed25519 key is converted to X25519 and met with a fresh ephemeral key, the AEAD key is
`blake3::derive_key("wires sealed-fabric-key v1", dh ‖ eph_pub ‖ member_pub)`, and the cipher is
ChaCha20-Poly1305 with a zero nonce (safe, since the key is unique per seal) and AAD `{format,
fabric, version, member, alg}`. Low-order member keys are refused, and the exchange must be
contributory.

Keys are kept forever in `keyring/<version>.key` (mode 0600). There is no ratchet: whoever
compromises a member's seed can read everything sealed to that member. The root does not keep the
plaintext key.

**The envelope** (`TopicEnvelope`, format 1):

```
{ format, topic, sender, seq: Seq(u64, dense from 0 per sender), prev_hash (ZERO iff seq 0),
  key_version: RosterVersion, timestamp (informational), nonce, ciphertext, alg, sig }
```

- Encrypt, then sign; the AAD is the canonical body with an empty ciphertext. The nonce is a
  **synthetic IV**, `derive_key("wires topic-envelope nonce v1", key ‖ slot ‖ plaintext)[..12]`,
  which `open` re-derives and checks. Why: a counter nonce reuses the keystream whenever a sequence
  number rolls back (a restored backup, a second home on the same seed); a synthetic IV also needs
  identical plaintext to repeat.
- `verify()` checks only the structure and the signature, so a node can store an envelope before it
  holds the key. `message_hash = blake3(signing_bytes)`.
- One resident process per (node, topic) allocates sequence numbers: `wires watch`, or `serve` with
  a channel. Other local publishers go through its control socket (`run/<topic-hex[..16]>.sock`).

**The chain.** `classify_link(env, state, held_hash_at_seq)` returns one of four results (there is
no fork choice):

| Result | Condition | Action |
|---|---|---|
| `Ok` | genesis with `prev_hash == ZERO`, or `seq == prev + 1` with a matching hash | store |
| `Duplicate` | same `(sender, seq)`, same hash | drop silently |
| `Gap` | `seq` skipped ahead | don't store; run a replay after a 2 s debounce |
| `Fork` | same slot with a different hash, a bad genesis, or a `prev_hash` mismatch | refuse and log |

**Ingest** runs **epoch floor → verify → classify → append**, then decrypts if the key is held
(otherwise the message is stored and shown once the key arrives).

- **The epoch floor applies only to live gossip.** An envelope with `key_version` below the enforced
  head's version is refused, and `publish` refuses to seal under an old key. This stops a removed
  member, which keeps its old keys, from injecting new traffic.
- **Replay is exempt from the floor**, so that chains which span a commit still link. What limits a
  removed member on the replay path is the dial set. It contains only peers admitted under the
  current head (`replay_targets`).

**Replay** (`wires/topic-replay/1`, peer-symmetric, no host): `Request {topic, hwm: {sender →
ChainState}, limit}`, answered by `Item(envelope)`* then `End`, or `Denied`; at most 1 MiB a frame.
If the server's hash at a presented high-water mark differs, it streams that sender **from
genesis**, so the requester sees the fork. The requester stops at its own limit and sends at most
1024 high-water marks, rotated between rounds. A pass has 20 s (5 s to connect); a catch-up runs at
most 32 rounds in 30 s, and watch also catches up every 60 s.

**Storage:** one redb database per topic, `topics/<topic-hex>.db` (tables `topic_log`, keyed
`sender‖seq_be`, and `topic_hwm`), plus peer hints in `topics/<hex>.peers.json`.

## 7. Re-keys *(scheduled for removal by card 27)*

A commit invalidates every member's proof and key at once. Instead of hand-copying files, the admin
publishes the commit on the channel:

```
Rekey { head, entries: [RekeyEntry { proof, key: SealedFabricKey }] }   // sorted by member
```

- **`Rekey::verify(root, now)`** checks the head's signature and freshness. For each entry it checks
  that the proof is for `head.version` and recomputes `head.root`, that the key is signed by the
  root, and that the key's member and version match the proof. It rejects duplicate members. A
  `Rekey` has no signature of its own. Whoever publishes or replays one can only advance a reader to
  a newer root-signed head and hand it a key the root sealed to it.
- **Chunking.** A record holds at most 32 entries (`REKEY_ENTRIES_PER_RECORD`), about 50 KiB, which
  keeps it under the 64 KiB `GOSSIP_MAX_MESSAGE`. A larger roster is split into several records for
  the same head.
- **Published under the outgoing key**, from the admin's node, **before** the admin installs the
  commit. The members it is for can open it only with the key they already hold, and their epoch
  floor accepts it. `roster.json` is bumped first, so a crash can never produce two commits with one
  version. A member that the commit removes can read the record. It learns the head and the
  survivors' ids and Merkle paths, but never the new key.
- **Adoption** (`wires/channel/rekey.rs`) runs on every received envelope, whatever its ingest
  verdict, and on everything a catch-up inserts. It installs in this order: own key → own proof →
  proof directory → head, through the compare-and-swap. A record for an older head only adds its key
  to the keyring. A record with no entry for this node still advances the head, which is how a
  removed node learns that it is out. A one-shot publish whose newest key is behind its head runs
  one catch-up first.
- **The proof directory** (`roster-directory.json`, mode 0600) holds the current head's proof for
  every member listed in its re-keys. `check_roster_inclusion_via(head, presented, directory, …)`
  accepts the caller if either:
  - the presented proof passes, or
  - the directory for **exactly** `head` lists a proof for `caller` that passes (after it is
    re-verified).

  This keeps a caller that missed a re-key (for example a one-shot `wires call`) admitted. It is as
  strong as the caller presenting the proof itself, because the caller is still the authenticated
  key. If a stale proof is not in the directory for that exact head, the result is
  `RemovedFromRoster`, not `StaleProof`. The session gate, topic admission and the watchdog all use
  this check.
- A member offline across a commit and never re-admitted by a peer holding the directory needs a
  fresh `wires invite`.

## 8. Channel records *(scheduled for removal by card 27)*

Machine-written metadata is sent as message text: `{"wires":"record/v1","record":{"type":…}}`. It
inherits the envelope's signature, encryption and hash link. Text that does not parse as a record is
displayed as a chat line.

| `type` | Payload | Sender rule | Consumed by |
|---|---|---|---|
| `audit` | `AuditRecord`: `started {call, caller, principal?, tool, argv, roster_version?, role?}`, `finished {call, exit, duration_ms, stdout/stderr bytes, stdout_digest, stdin_bytes, stdin_digest, stdin_head ≤4 KiB}`, `denied {caller, tool?, reason}`, `push {id, to, subject, outcome, reason?, body?}` | the host that ran the call; `caller` is the authenticated peer | `wires watch` |
| `identity` | `IdentityClaim {node, id_token}` | envelope sender **must equal** `node` | host identity gate, `watch` |
| `rekey` | `Rekey` (§7) | anyone; the record verifies itself | every resident node |
| `host` | `HostAnnouncement {node, at_ms, heartbeat_ms, open?, sealed[]}` | envelope sender **must equal** `node` | caller directory (`directory.json`), `watch` |

- **Call records** are best-effort: a full sink is logged and the call goes ahead. A host whose
  `host.json` names a `channel` refuses to start unless it holds membership, proof, head and key.
- **Identity claims.** `wires login` runs OIDC with `nonce = base64url(derive_key("wires
  oidc-nonce v1", node_id))`. With `--topic`, it publishes the claim. `verify_claim` checks, in
  order:
  `alg` is RS256 or ES256 and a JWKS key verifies the signature; `iss` matches exactly; an `aud`
  value is accepted; `exp` and `iat` are within the 60 s clock skew; `nonce == for_node(node)`.

  Each reader verifies the claim against the issuer's JWKS itself, so no wires attestor is involved.
  `email` is used only when `email_verified` is true. `hd` becomes `org`, and `groups` is kept. Card
  27 moves the ID token into the session handshake.
- **Host announcements.** The `open` listing (tools, addresses, relay) is visible to every member.
  Each `sealed` entry is a `HostListing` sealed anonymously to one member whose identity the host's
  policy allows more, using the same ephemeral-X25519 construction under `"wires sealed-announcement
  v1"` with AAD `{format, host, at_ms}`, padded to 256-byte buckets and shuffled. Readers
  trial-open the sealed entries. A host is stale after three missed heartbeats (default 600 s).
  Visibility is only about privacy: the host still decides every call.

## 9. Keystore (`$WIRES_HOME`, else `$XDG_CONFIG_HOME/wires`, else `~/.config/wires`)

| File | Mode | Holder | Content |
|---|---|---|---|
| `root.seed`, `node.seed` | 0600 | admin / every node | hex Ed25519 seed |
| `roster.json` | 0600 | admin | the full member set and version |
| `names.json` | 0600 | admin | local labels for `remove`; never sent on the wire |
| `membership.json` | 0644 | member | membership token |
| `roster-head.json` | 0644 | member / verifier | head token, only ever advanced by compare-and-swap |
| `inclusion-proof.json` | 0644 | member | own proof token |
| `roster-directory.json` | 0600 | verifier | proof directory (§7) |
| `keyring/<v>.key` | 0600 (dir 0700) | member | fabric key per version, kept forever |
| `channel.json` | 0644 | member | channel name from `init`/`join` |
| `topics/<hex>.db`, `topics/<hex>.peers.json` | 0600 | resident node | channel log, peer hints |
| `directory.json` | — | caller | host-announcement cache |

Flags, environment variables and `--…-file` paths override the keystore, in that order of
precedence.

## 10. Known limits

- Forward secrecy exists only at commit: keys rotate per commit, with no ratchet. Forks are
  detected but not resolved, and timestamps can't be verified.
- Gossip gating is inbound only. Outbound dials to peers learned through peer exchange are not
  gated.
- Removal takes effect at every node that holds the new head. A node that has not adopted it yet
  still stores the removed member's messages and can later serve them as history.
- Nothing renews heads or memberships. There is one fabric per keystore. The dialer checks the
  host's membership but not the host's roster freshness.

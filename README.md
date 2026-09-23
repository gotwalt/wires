# wires

> **Run a CLI on another machine from your agent. The machine is reached by
> public key, never by network path; the caller is authenticated by your IdP;
> and every call lands on an encrypted gossip channel that anyone you
> authorize can watch — without access to the caller or the machine running
> the CLI.**

## The demo

> **Status:** this whole story runs on one machine, self-asserting, as
> `./.scripts/demo-remote-cli.sh` (see [What runs today](#what-runs-today)),
> with a local stand-in IdP. The two-machine run with real Google sign-in is
> [card 08](docs/board/README.md#lanes).

1. **workbench** exposes one read-only SQL CLI and puts every call on the
   `ops` channel:
   `wires serve --expose 'db_query=sqlite3 -safe -readonly orders.db' --audit-topic ops --require-idp 'email=*@example.com' …`
2. **laptop**: Claude Code runs `wires call db_query -- "select count(*) from orders"`
   from its shell, or reaches the same tool through `wires mcp` in its MCP config.
3. **observer** holds no grant for the tool and no credential of either end;
   `wires tail ops` shows each call as it happens:
   ```
   ▶ 3fa2 alice@example.com (a1b2…) db_query "select count(*) from orders"
   ■ 3fa2 exit 0 · 41 ms · 3.1 KiB out · blake3 9c1e…
   ```
4. **revoke**: one `wires roster commit` without the agent. Its next call
   exits `77` with zero bytes on stdout, and the refusal is on the channel too:
   `✗ a1b2… db_query denied: membership rejected: revoked`.

## Why not…

| | |
|---|---|
| **…Tailscale?** | To reach an MCP server over Tailscale, the server has to listen on a port the agent's machine can reach. The service itself is exposed on the network, and its own auth is all that guards it. A wires responder exposes no service: it runs an allowlisted CLI per verified call, and that is all the agent's machine can reach. |
| **…an MCP gateway?** | A gateway's log belongs to whoever runs the gateway, and covers only the traffic routed through it. Here the record is written by the responder that ran the command — the one place the call can happen — signed by its key and hash-linked to the previous record. The agent can't forge it, and an observer reads it without the caller's or the responder's credentials. |
| **…MCP instead of CLIs?** | CLIs are the idiom models already know, one verb covers every tool, and pipes filter output before it reaches context. That is meaningfully more efficient than MCP tool schemas and JSON results, even after the 2026-07-28 rev. What CLIs have never had is an observability story; the channel is that story. `wires mcp` is there for clients that only speak MCP. |
| **…OAuth on each server?** | `wires login` binds your IdP's ID token to your node key (the OIDC `nonce` is a hash of the key) and publishes it on the channel as metadata. Every reader checks the IdP's signature itself: no wires-run attestor, no auth code in the CLI, and two organizations' IdPs can share one channel. |

## Quickstart

> **Status: in progress.** Steps 1–2 run today. Steps 3–5 use `serve --expose`,
> `--audit-topic`, `--require-idp`, `wires login`, `wires tools`, `wires call`
> and `wires mcp`, which are landing now ([cards 01–05](docs/board/README.md#lanes)).
> Build with `bazel build //wires` and put `bazel-bin/wires/wires` on `PATH`
> (copy it; `bazel-bin/` moves on `bazel clean`).

**1. Keys.** Each machine makes a node key; you (the person who decides who's
in) also make a root key, and keep it on your own machine.

```bash
wires keygen --save-node        # on workbench, laptop, observer — note each node_id
wires keygen --save-root        # on your machine only — note root_id
```

**2. The roster.** Sign the list of who's in. Per member, `commit` writes an
inclusion proof and that member's sealed copy of the channel's data key; each
member installs its four credentials with one `import`.

```bash
wires roster add --member "$WORKBENCH_ID"
wires roster add --member "$LAPTOP_ID"
wires roster add --member "$OBSERVER_ID"
wires roster commit --ttl 3600 --out ./proofs              # prints the head token
wires member --subject "$LAPTOP_ID" --ttl 3600 > laptop.pass

# on each member (laptop shown):
wires import --membership-file ./laptop.pass \
             --inclusion-proof-file "./proofs/$LAPTOP_ID.proof" \
             --roster-head "$HEAD" \
             --fabric-key-file "./proofs/$LAPTOP_ID.key"
```

**3. workbench: expose the CLI and log every call.** `--expose` takes
`name=command`; the command is split on whitespace and exec'd directly, never
through a shell, with the caller's arguments appended. sqlite3's `-safe` flag
disables its `.shell`/`.system` dot-commands — use it.

```bash
wires serve --trust-root "$ROOT_ID" --allow-any-member \
  --expose 'db_query=sqlite3 -safe -readonly /data/orders.db' \
  --audit-topic ops \
  --require-idp 'iss=https://accounts.google.com,email=*@example.com'
```

**4. laptop: log in once, then call.** `wires login` runs your IdP's browser
flow and publishes the resulting claim on `ops`; the responder admits the call
once that claim verifies against `--require-idp`.

```bash
wires login --topic ops
wires tools add db_query --node "$WORKBENCH_ID" --description "Read-only SQL over orders.db"
wires call db_query -- "select count(*) from orders"
```

For an MCP client, the whole config is:

```json
{ "mcpServers": { "workbench": { "command": "wires", "args": ["mcp"] } } }
```

**5. observer: watch.**

```bash
wires tail ops
```

To revoke: `wires roster remove --member "$LAPTOP_ID" && wires roster commit …`,
then import the new head on workbench. The next call is refused; no one
restarts anything.

## What runs today

Five unattended scripts stand up the working parts on loopback, each in a
fresh `mktemp -d` that never touches `~/.config/wires`. Each asserts its own
result, so a green run is a passing test, not a screenshot. All take
`--quiet` (assertions only) and `--keep` (leave the state dir).

```bash
bazel build //wires //wires:wires_dev
./.scripts/demo-remote-cli.sh     # the demo above: IdP-gated remote SQL, every call on the channel
./.scripts/demo-mcp.sh            # a stdio MCP server on "another machine", dialed by key
./.scripts/demo-revoke.sh         # one roster commit → the same dial dies, nothing restarted
./.scripts/demo-topic.sh          # two members on one encrypted channel, nobody in the middle
./.scripts/demo-topic-revoke.sh   # cut one member out mid-conversation
```

- **`demo-remote-cli.sh`** (~1 min narrated, ~8 s with `--quiet`): the
  [demo](#the-demo) end to end. An observer with no key to either end sees
  the IdP identity verified, then `▶`/`■` naming the caller's email and its
  SQL for `wires call` (args and stdin) and `wires mcp` calls. A caller with
  no identity is refused, `.shell id` is refused by `sqlite3 -safe`, and after
  one roster commit the next call exits `77` with zero bytes out. Each refusal
  shows up on the channel, and the responder never restarts. The IdP is a
  loopback mock that only the dev build (`//wires:wires_dev`) contains.
  `--with-claude` adds a headless `claude -p` turn through `wires mcp`. It is
  opt-in because it needs auth and costs money.
- **`demo-mcp.sh`** (~7 s): an unmodified stdio MCP server behind
  `wires serve`, reached with `wires connect`. The tool answers with the
  *caller's* node id, which it learned from the responder's environment
  injection, not from anything the request claimed. The script asserts every
  byte on the dialer's stdout parsed as JSON-RPC.
- **`demo-revoke.sh`** (~1 min narrated, ~7 s with `--quiet`): the
  responder's pid stays the same across the revocation, and the identical dial
  exits `77` with **zero bytes** on stdout and the reason on the dialer's
  stderr. `--mode roster` (default) advances the signed head; `--mode crl`
  appends to the responder's `crl.json`.
- **`demo-topic.sh`** / **`demo-topic-revoke.sh`**: the channel the calls will
  land on, exercised on its own. See
  [the channel](#the-channel-the-calls-land-on) below.

![revocation demo: the same dial before and after a roster head-advance — exit 77, zero bytes, responder never restarted](docs/demo-revoke.gif)

The recording is `demo-revoke.sh` as-is (the remote-CLI demo will replace it);
to re-record: `asciinema rec -c ./.scripts/demo-revoke.sh demo.cast && agg demo.cast docs/demo-revoke.gif`.

## The channel the calls land on

The audit channel is a **topic**: an end-to-end-encrypted log shared by the
members of a roster, with no server in the middle. `wires tail` is a resident
node (log, gossip mesh, admission, history replay) and `wires publish` puts a
message on it. A responder with `--audit-topic` is simply a member that
publishes call records; an observer is any member running `tail`.

```bash
wires tail ops                                        # → share to bootstrap: <ticket>
wires publish ops -m "deploying build 41" --peer "$TICKET"
```

The topic isn't created anywhere; every member computes the same name from
the roster it belongs to. Each line is stamped with the key that signed it,
and a member who was offline catches up from any other member, because every
`tail` serves history. The commit that removes a member re-keys everyone
else, so a removed member can't read what comes next. Design, threat model,
and revocation latencies: [docs/phase2-topics.md](docs/phase2-topics.md).

# Reference

## Setup dev environment

First, we recommend you setup a Bazel-based developer environment with homebrew.

1. Run `make setup`

This will install `bazelisk` and `direnv` and add all the bazel-controlled tools to the path in this directory.

## Usage

Everything in this section runs on this tree today: the `library` core
(identity, grants, **membership**, the committed roster, tickets, policy, topic
envelopes, the session frame codec), the `wires` multi-call binary, a
self-hosted `relay`, distroless OCI images, and an on-disk keystore. Every
session proves roster membership and hands the verified caller identity to
the served command (see [Membership](#membership-identity-on-every-session)).
The remote-CLI surface from the [quickstart](#quickstart) is added here as it
lands.

### Layout

Three flat Bazel packages in one Cargo workspace (build & test are Bazel-only —
`bazel build //...`, `bazel test //...`; see [CLAUDE.md](CLAUDE.md)):

- **`//library`** — the `library` crate: the pure, transport-free core — identity,
  grant, ticket, policy, and the session `Frame` codec. No iroh/tokio; property +
  unit + doctested.
- **`//wires`** — the multi-call binary: every subcommand, plus the iroh
  transport (`wires/transport.rs`), keystore (`wires/keystore.rs`), and the topic
  node (`wires/topics.rs`), so `library` stays pure.
- **`//relay`** — a self-hosted [`iroh-relay`](https://docs.rs/iroh-relay)
  rendezvous server.

Both binaries also build as distroless OCI images — `//wires:image` and
`//relay:image` (`bazel run //relay:image.load` to `docker load`).

### Build and test

Everything goes through Bazel (see [CLAUDE.md](CLAUDE.md) for the dependency
workflow — never `cargo build`/`cargo test`):

```bash
bazel build //...          # build the library + binaries
bazel test  //...          # unit + property + doctests + the loopback QUIC test
bazel run   //wires -- --help
```

Run a subcommand with `bazel run //wires -- <subcommand> …`, or build once and
call the binary directly at `bazel-bin/wires/wires`.

For production deployment — containers, Kubernetes manifests, and self-hosting
the relay — see [docs/deployment.md](docs/deployment.md); for the test suite and
manual recipes see [docs/testing.md](docs/testing.md).

**Try it locally in two terminals.** `.scripts/serve-rg.sh` provisions demo keys,
boots a responder running `rg`, and mints a ticket; `.scripts/connect.sh` pipes
its stdin over wires to that `rg` and prints the matches. Both log to stderr so
you can watch the handshake and session:

```bash
./.scripts/serve-rg.sh                                   # terminal 1
printf 'a\nTODO: ship it\nb\n' | ./.scripts/connect.sh   # terminal 2 → "2:TODO: ship it"
```

These two keep their state in a sticky `$WIRES_DEMO_DIR` (default
`/tmp/wires-demo`) so you can re-dial without re-provisioning. The unattended
[demos](#what-runs-today) use a fresh `mktemp -d` instead.
Every script in `.scripts/` runs directly from the repo root, not via
`bazel run //.scripts:…`.

### The command surface

| Command          | Role                      | What it does                                                                 |
| ---------------- | ------------------------- | ---------------------------------------------------------------------------- |
| `wires keygen`   | trust-root / host setup   | Generate (or re-derive) a **node key** and **root key**; print, and `--save-*` to the keystore |
| `wires grant`    | trust root (the human)    | Root-sign a scoped grant and emit a base64 **ticket**, optionally with `--addr`/`--relay-url` hints |
| `wires member`   | trust root (the human)    | Root-sign a **membership** for a node and emit a base64 token (`--save` to the keystore) |
| `wires roster`   | trust root (the human)    | Author a **committed roster**: `add`/`remove` members, `commit` a signed head + per-member proofs, `head` to print the current head token |
| `wires revoke`   | trust root / responder    | Add a subject to the CRL (keystore `crl.json` by default) and print it       |
| `wires import`   | anyone receiving creds    | Install a membership / inclusion proof / roster head / topic data key into the keystore, so later commands need no flags |
| `wires tail`     | any member (resident)     | Own a **topic**: the message log, the mesh, the admission gate, the replay server, and a control socket; print the transcript and its own bootstrap ticket |
| `wires publish`  | any member                | Put a message on a topic — through a running `tail`'s socket, or as a one-shot node when there isn't one |
| `wires serve`    | responder (the tool host) | Verify the dialer's **membership** (and, with `--scope`, a matching grant), exec a command, bridge its stdio — injecting the verified caller identity into the child |
| `wires connect`  | dialer (the agent side)   | Present the **membership** and dial a `--ticket` (scoped) or `--target` (inclusion-only), piping local stdin/stdout/stderr |

In progress ([board](docs/board/README.md)): `serve --expose` / `--audit-topic` /
`--require-idp`, `wires call`, `wires mcp`, `wires tools`, and `wires login`.

### Two keys

There are two Ed25519 keys with different jobs (see the design notes below):

- **Node key** — a node's iroh transport identity. Its public half *is* the
  node id you dial. Every participant (the responder host and each dialer) has
  one.
- **Root key** — the human trust root that signs grants. Its public node id is
  what a responder is told to `--trust-root`. It never touches iroh.

`keygen` emits both as `<label> <hex>` lines:

```bash
$ bazel run -q //wires -- keygen
node_seed 0202…0202   # 32-byte Ed25519 seed (secret) for the node key
node_id   8139…b394   # the node's public id — what others dial
root_seed 0101…0101   # secret seed for the root signing key
root_id   8a88…6f5c   # the trust-root id others verify against
```

Pass `--node-seed <hex>` / `--root-seed <hex>` to re-derive deterministically
instead of generating fresh keys.

### The keystore

So you don't paste private keys into every command (where they leak via `ps`,
shell history, and — for `serve`, which execs a child — the child's
environment), keys and the CRL live in a **keystore** directory, resolved as
`$WIRES_HOME`, else `$XDG_CONFIG_HOME/wires`, else `~/.config/wires`:

| File              | Written by           | Read by                          |
| ----------------- | -------------------- | -------------------------------- |
| `node.seed`       | `keygen --save-node` | `serve` / `connect` node key     |
| `root.seed`       | `keygen --save-root` | `grant` / `member` signing key   |
| `crl.json`        | `revoke` (default)   | `serve` revocation check         |
| `membership.json` | `member --save` / `import` | `connect` + `serve` membership |
| `roster.json`        | `roster add`/`commit` | the root's full member set (`0600`, private) |
| `roster-head.json`   | `roster commit` / `import` | `serve` (the signed head it enforces, public) |
| `inclusion-proof.json` | `import`            | `connect` (the member's own proof, public) |

`keygen --save-node` / `--save-root` write `0600` seed files (refusing to
clobber unless `--force`). On the tool host you save the node key; on the
operator's machine you save the root key:

```bash
# tool host / agent box:
bazel run -q //wires -- keygen --save-node      # writes ~/.config/wires/node.seed
# operator's machine (keep this one safe):
bazel run -q //wires -- keygen --save-root      # writes ~/.config/wires/root.seed
```

Every secret/CRL input resolves in the same order: **inline flag → environment
variable → `--…-file <path>` → keystore**. So with the keystore populated, the
commands below need no seed at all — and for Kubernetes you mount a `Secret` and
point at it with `--node-seed-file /etc/wires/node.seed` (the `--…-file` forms
exist for exactly that). The dialer's membership resolves the same way
(`--membership <token>` → `$WIRES_MEMBERSHIP` → `--membership-file` →
`membership.json`); unlike the seeds it is a *public* credential (mode `0644`).

### End-to-end: drive a remote `rg` over wires (Flow A)

Three roles, which may be three machines. Each saves its key to its own
keystore, so only the public **ids** (and the ticket) cross machines.

**1. The human mints the trust root** on their own machine (keep it safe):

```bash
bazel run -q //wires -- keygen --save-root   # note ROOT_ID; root.seed stays here
```

**2. Each host/agent makes and saves a node key:**

```bash
bazel run -q //wires -- keygen --save-node   # on the tool host → note SERVER_ID
bazel run -q //wires -- keygen --save-node   # on the agent box → note AGENT_ID
```

**3. The human admits the agent and grants it the tool.** First a
**membership** — the agent's scope-independent identity, required on every
session (explained [below](#membership-identity-on-every-session)) — then
a scoped **grant**. Both are root-signed; the root key comes from the keystore,
so no `--root-seed` is needed. These print a membership **token** and a
**ticket** (the address):

```bash
MEMBERSHIP=$(bazel run -q //wires -- member \
  --subject "$AGENT_ID" \
  --ttl     3600)

SERVER_MEMBERSHIP=$(bazel run -q //wires -- member \
  --subject "$SERVER_ID" \
  --ttl     3600)

TICKET=$(bazel run -q //wires -- grant \
  --subject "$AGENT_ID" \
  --target  "$SERVER_ID" \
  --scope   tools.rg \
  --ttl     3600)
```

Use `--not-after <unix>` instead of `--ttl` for an absolute expiry.

The **responder needs a membership too**: inclusion is mutual, and `serve`
presents its own in the handshake ack so a ticket-less dialer can verify the
service it just reached. Install it on the tool host before starting `serve`:

```bash
bazel run -q //wires -- import --membership "$SERVER_MEMBERSHIP"   # on the tool host
```

**4. The tool host serves the scope**, exec-scoped to one command, egress-only
(no inbound port). The node key comes from the keystore. A session is accepted
only if the caller presents a valid **membership** (signed by `--trust-root`,
for the authenticated caller, unexpired, not revoked) **and** a matching grant
(same root, subject equals the caller, scope matches, valid TTL, not revoked):

```bash
bazel run -q //wires -- serve \
  --trust-root "$ROOT_ID" \
  --scope      tools.rg \
  -- rg --line-number TODO
```

Everything after `--` is the child command (program + args) exec'd per session.

**5. The agent installs its membership once**, with `wires import`. After this
the dial takes no flags but the ticket — which is exactly what makes `wires
connect` droppable into an MCP client config:

```bash
bazel run -q //wires -- import --membership "$MEMBERSHIP"
# → wrote ~/.config/wires/membership.json
```

**6. The agent dials the ticket** — exactly like running a local stdio
program. It presents the installed membership and the ticket; its node key
comes from the keystore; its stdin is forwarded to the child; the child's
stdout/stderr stream back; its exit code becomes `connect`'s:

```bash
echo "search input" | bazel run -q //wires -- connect --ticket "$TICKET"
```

The dialer's node key **must** be both the membership's member and the grant's
subject (`AGENT_ID`) — the responder checks that the iroh-authenticated caller
equals each, so neither can be used by anyone else. The served `rg` is handed the
verified caller in its environment (`WIRES_CALLER_NODE` / `WIRES_FABRIC_ROOT`),
so a tool can authorize per caller with no extra round-trip. (If you'd rather not
use the keystore, every command also accepts secrets inline via `--node-seed` /
`--root-seed`, via `$WIRES_NODE_SEED` / `$WIRES_ROOT_SEED`, or from a file via
`--node-seed-file` / `--root-seed-file`; the membership likewise via
`--membership` / `$WIRES_MEMBERSHIP` / `--membership-file` — `import` just
writes the keystore copy for you so the dial stays flagless.)

### Membership: identity on every session

A **grant** authorizes one scope; a **membership** answers a different question —
*"is this node one of mine, and which one?"* — independent of any tool. The
human mints one per node with `wires member` (root-signed, non-transferable,
offline-verifiable against the pinned `--trust-root`), and the dialer presents it
on **every** session. A membership is a *public* credential: pass it inline with
`--membership`, via `$WIRES_MEMBERSHIP` / `--membership-file`, or save it to the
keystore as `membership.json`.

```bash
# The human (holds the root key) admits a node:
bazel run -q //wires -- member --subject "$AGENT_ID" --ttl 3600
```

It buys two things:

- **Verified identity delivered to the tool, with no extra round-trip.** Once a
  responder verifies the membership it injects the verified caller into the
  child's environment — `WIRES_CALLER_NODE` (the iroh-authenticated peer),
  `WIRES_FABRIC_ROOT` (the responder's own trust root), and
  `WIRES_MEMBERSHIP_NOT_AFTER`. The served binary finally learns *who* is driving
  it. These are server-derived, never a dialer claim, and any inherited `WIRES_*`
  is scrubbed before the child starts.
- **Inclusion-only responders.** Run `serve` *without* `--scope` (and with the
  explicit `--allow-any-member`) and any member may open a session; the
  served binary authorizes from the injected identity. This is the enterprise-MCP
  shape — one responder, per-caller authorization in the tool itself:

  ```bash
  bazel run -q //wires -- serve --trust-root "$ROOT_ID" --allow-any-member \
    -- my-mcp-server --config /etc/my-mcp.toml
  ```

  Without `--scope` *and* without `--allow-any-member`, `serve` refuses to start:
  execing for any member is an intentional authorization downgrade that must be
  asked for.

Membership says the root vouched for a node at issue time; the committed
roster below adds *current* membership.

### Committed roster: current membership + revocation everywhere

A membership says the root vouched for a node *at issue time* (bounded by its
TTL). The **committed roster** adds *current* membership: the root keeps a
versioned member set and signs a tiny 32-byte **head** (a Merkle root) whenever
it changes; a verifier holding the latest head checks a caller's **inclusion
proof** against it, offline, and learns *present* membership. Removing a member
and re-signing revokes it at every responder holding the new head, with no CRL to distribute. The head
leaks nothing about the set; a proof reveals only its holder's id and `O(log n)`
sibling hashes. Spec: [docs/committed-roster.md](docs/committed-roster.md).

```bash
# The human authors the roster (offline) and signs a head + per-member proofs.
bazel run -q //wires -- roster add --member "$MEMBER_ID"
bazel run -q //wires -- roster add --member "$SVC_ID"      # the service is a member too
bazel run -q //wires -- roster commit --ttl 3600 --out ./proofs
# → writes keystore roster-head.json, prints the head token, and emits
#   ./proofs/<node-id>.proof for each member.

# The same human mints each side's membership and copies the head out:
bazel run -q //wires -- member --subject "$SVC_ID"    --ttl 3600 >./svc-membership
bazel run -q //wires -- member --subject "$MEMBER_ID" --ttl 3600 >./member-membership
bazel run -q //wires -- roster head                                >./roster-head

# Each side installs what it needs, once, with `import` (no hand-copying into
# membership.json / inclusion-proof.json). On the service:
bazel run -q //wires -- import \
  --membership-file ./svc-membership \
  --inclusion-proof-file "./proofs/$SVC_ID.proof" \
  --roster-head-file ./roster-head
# On the member:
bazel run -q //wires -- import \
  --membership-file ./member-membership \
  --inclusion-proof-file "./proofs/$MEMBER_ID.proof"

# The service enforces the head it just installed (any member with a valid
# current proof may connect):
bazel run -q //wires -- serve --trust-root "$ROOT_ID" --allow-any-member \
  -- sh -c 'echo "caller=$WIRES_CALLER_NODE roster=$WIRES_ROSTER_VERSION"'

# The member dials — membership and proof come from its keystore:
bazel run -q //wires -- connect --target "$SVC_ID"
# → the child sees WIRES_CALLER_NODE and the WIRES_ROSTER_VERSION that admitted it.
```

Now `roster remove --member "$MEMBER_ID" && roster commit` and the *same* dial
is rejected — on the **next connection**, with no responder restart, because
`serve` re-reads `roster-head.json` per connection. The removed member is never
issued a newer proof: revocation here is omission, not a blocklist entry. Run
`./.scripts/demo-revoke.sh` to watch it happen end to end.

A commit bumps the version and therefore invalidates *every* member's proof,
including the service's own — so a head advance means re-distributing one small
proof per remaining member alongside the new head.

A ticket-less (`--target`) dialer also verifies the **responder's** membership
from the handshake ack before sending any stdin — *mutual inclusion*, so the
agent never streams to a service outside its roster.

### MCP over wires (Flow B) — no extra code

`serve` doesn't care whether the child is `rg` or an MCP server. Point `serve` at
your MCP server binary, and configure the MCP **client** to spawn `wires connect`
as its stdio server command. wires carries the JSON-RPC bytes opaquely.

On the server machine (e.g. inside a VPC; its secrets stay local):

```bash
bazel run -q //wires -- serve \
  --trust-root "$ROOT_ID" --scope mcp.myserver \
  -- my-mcp-server --config /etc/my-mcp.toml
```

On the agent machine, install the credentials once and put `wires` on `PATH`:

```bash
bazel run -q //wires -- import --membership "$MEMBERSHIP"
# and, if the responder enforces a roster head:
#   --inclusion-proof-file ./proofs/$AGENT_ID.proof

bazel build -c opt //wires && cp bazel-bin/wires/wires ~/.local/bin/wires
```

Copy, don't symlink: `bazel-bin/` is itself a symlink into the Bazel cache and
moves on `bazel clean`.

Then in the MCP client config, replace the local command with the dialer. After
the `import` above, the ticket is the *only* argument it needs:

```json
{
  "mcpServers": {
    "myserver": {
      "command": "wires",
      "args": ["connect", "--ticket", "<TICKET>"]
    }
  }
}
```

**GUI clients need absolute paths.** Claude Desktop (and anything else launched
from the Dock/Finder rather than a shell) spawns servers with a minimal `PATH`
and without your shell's environment — use `"command":
"/Users/you/.local/bin/wires"`. It also won't have `$XDG_CONFIG_HOME` set, so
the keystore it reads is `~/.config/wires`; run the `import` as the same user
the client runs as.

The client believes it launched a local stdio server; the server believes it was
launched locally. Neither knows a network is involved. (For a multi-tenant MCP
server, run the responder
[inclusion-only](#membership-identity-on-every-session) with
`--allow-any-member` and authorize each caller inside the server from
`WIRES_CALLER_NODE`.)

#### Verified against MCP 2026-07-28

wires is a byte-transparent stdio bridge: it never parses, rewrites, or buffers
JSON-RPC. What the [2026-07-28
rev](https://modelcontextprotocol.io/specification/2026-07-28) requires of a
*stdio server* is therefore a property of the bridge, not of the protocol. Each
of these was measured on a live session against this tree — reproduce with
`./.scripts/demo-mcp.sh`:

- **stdout carries only the server's bytes.** A captured session's stdout
  parsed line-for-line as JSON-RPC with nothing else in it; every failure path
  wrote zero bytes. `demo-mcp.sh` and `demo-revoke.sh` both assert this, and it
  is what makes the bridge safe to drop into a `command` field at all.
- **all diagnostics go to stderr** — wires' own logging, the remote child's
  stderr (forwarded back over the session), and denial reasons.
- **exit codes are meaningful.** The remote child's exit code becomes
  `connect`'s; a local or transport failure is `1`; an authorization refusal is
  **77**, with `wires: denied by responder: <reason>` on stderr.
- **full duplex before EOF.** Five `ping`s were issued one at a time on a single
  open session, each with a 400 ms pause and stdin never closed: first
  round trip ~34 ms, steady state ~3 ms on loopback. A long-lived client session
  behaves as if it had spawned the server locally, rather than as a batch pipe.
- **one child per session.** Two sequential dials against one responder exec'd
  two distinct child pids, and a dialer that disappears has its remote child
  killed rather than orphaned (covered by a test in `wires/transport.rs`).

Protocol-level features of the rev — stateless requests, the per-request
protocol version and client capabilities in `_meta`, `resultType` — ride through
untouched; conformance to *those* belongs to whatever MCP server you put behind
`wires serve`, not to wires. The bundled `.scripts/fake-mcp-server.py` exercises
them so the demos have something honest to talk to: it answers `tools/call` with
no prior `initialize` (stateless), returns a deterministic single-item
`tools/list`, stamps `resultType: "complete"` and
`io.modelcontextprotocol/serverInfo` on every result, and echoes the request's
protocol version back in the result's `_meta`.

Two caveats, stated plainly:

- The canonical request key is `io.modelcontextprotocol/protocolVersion`
  (camelCase), confirmed against the published spec's "Per-request protocol
  fields" table. The fake server *also* accepts
  `io.modelcontextprotocol/protocol-version`, `protocolVersion`, and
  `protocol-version` so hand-typed demo JSON still round-trips; only the first
  spelling is normative.
- A real MCP client has been driven against the bridge (2026-08-13): a
  headless Claude Code session (`claude -p --mcp-config …`) given only the
  config block above completed the full MCP handshake through
  `wires connect`, called the demo tool, and reported the responder-verified
  caller id. After a roster head-advance — responder not restarted — the
  identical session no longer saw the server at all: `wires connect` exited
  `77` at the handshake with zero bytes on stdout, so from the client's side
  the tool simply ceased to exist. Re-admitting the member (new commit +
  `wires import` of the fresh proof) restored it, same ticket and all.

### Revocation (offline)

Revocation is offline — no auth server, no token introspection endpoint. On the
tool host, `revoke` updates the keystore's `crl.json` in place, and `serve`
reads it by default, so revoking a subject is a one-liner:

```bash
# serve reads ~/.config/wires/crl.json automatically:
bazel run -q //wires -- serve --trust-root "$ROOT_ID" --scope tools.rg -- rg --line-number TODO

# ...and in another terminal, append a subject to that crl.json (idempotent):
bazel run -q //wires -- revoke --subject "$AGENT_ID"
```

**It takes effect on the next dial, with no responder restart.** `serve`
re-reads both `crl.json` and `roster-head.json` once per connection, so
`wires revoke` and `roster commit` land immediately; a session already open is
deliberately unaffected. A refused dial prints one line on the *dialer's*
stderr — `wires: denied by responder: membership rejected: revoked` — writes
zero bytes to stdout, and exits **77**. (Short TTLs remain worth setting, as
defense in depth for a responder you cannot reach.)

A responder started *before* any head was imported is not stuck at "no
enforcement": the keystore's `roster-head.json` is checked for on every
connection, so the first dial after `wires import --roster-head …` is the first
one gated on inclusion. (`--roster-head <token>` and `$WIRES_ROSTER_HEAD` are
the exception — an inline head is pinned for the process's life by definition.)

Caveat: once a responder has seen a head, *deleting* its `roster-head.json`
fails closed — every subsequent dial is denied with `responder configuration
error` until the file is restored.

The [committed roster](#committed-roster-current-membership--revocation-everywhere)
is the stronger of the two stories: instead of adding an id to a blocklist that
every responder must receive, the operator re-signs a head that simply omits the
member, and no newer inclusion proof will ever exist for them — revocation by
omission. `./.scripts/demo-revoke.sh` scripts both paths (`--mode roster`, the
default, and `--mode crl`).

To manage the CRL elsewhere (e.g. a Kubernetes ConfigMap mounted at a path),
`revoke --crl-file <path>` updates that file in place and `serve --crl-file
<path>` reads it; `--crl-json <literal>` is a one-shot transform printed to
stdout.

### Reachability: relays and direct addresses

By default `connect` resolves the target by node id via iroh's n0 discovery +
relays (needs outbound internet). Two ways to avoid that:

- **Self-hosted relay** — run the `relay` binary and point both ends at it with
  `--relay-url http://relay-host:3340` (see [docs/deployment.md](docs/deployment.md)).
- **Direct addresses in the ticket** — at grant time, embed where the responder
  is reachable so the dialer needs *no* discovery at all:

  ```bash
  bazel run -q //wires -- grant --subject "$AGENT_ID" --target "$SERVER_ID" \
    --scope tools.rg --ttl 3600 \
    --addr 198.51.100.7:4433 --relay-url http://relay-host:3340
  ```

  `--addr` (repeatable) and `--relay-url` are baked into the ticket. They are
  *unsigned hints*: iroh still authenticates the peer to the target's key, so a
  wrong address can only fail to connect, never impersonate. `serve` logs its
  node id and bound sockets at startup to help you fill these in.

### Other current limits

- **Discovery without hints:** a hintless ticket (no `--addr`) still relies on
  n0 DNS to resolve a node id to an address.
- **Scope is exact-match:** a grant's scope must equal the responder's `--scope`.
- **stdio framing is raw bytes:** `connect` sessions carry the child's stdio
  as-is. The old session-layer framing of this project, including a frame
  vocabulary that was never built, is archived in
  [docs/archive/session-layer-thesis.md](docs/archive/session-layer-thesis.md).

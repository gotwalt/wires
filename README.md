# Wires

# This is executable Markdown that's tested on CI.
# How is that possible? See https://gist.github.com/bwoods/1c25cb7723a06a076c2152a2781d4d49
set -o errexit -o nounset -o xtrace
alias ~~~=":<<'~~~sh'";:<<'~~~sh'
## What wires is — securely networked tools for agents

**Wires reframes how you harness an agent.** Today you give an agent power by
*co-locating* tools and secrets next to it: install binaries in its sandbox,
mount API keys into its environment, spawn MCP servers as local child
processes, hand it a shell. The agent can do whatever happens to sit beside it —
which couples capability to location and spills secrets into the agent's box.

Wires makes a tool a **capability you dial**, not a binary you bundle. Any
program's stdin/stdout becomes an authenticated, capability-scoped, revocable
network endpoint. Harnessing an agent becomes *granting it capabilities*: you
issue a non-transferable, human-rooted grant to reach one specific tool —
wherever that tool actually runs (a VPC, another machine, an air-gapped
enclave) — and the agent holds only that grant, never the tool's secrets. The
tool's database password or API key stays with the tool; revoke the grant and
the agent loses the tool, with no key rotation and nothing to re-image.

Because the session's native payload *is* stdio (and, one frame up, MCP),
"networking a tool" and "speaking to a tool" become the same act — your existing
CLIs and MCP servers work unmodified. It is `ssh user@host -- tool`, but the
address is a capability instead of an IP, the credential is an identity-bound
grant instead of a copyable key, and the far end is one scoped tool instead of a
whole shell.

→ Jump to [Usage](#usage) to run it; read the
[full thesis](#wires-as-a-session-layer-stdio-and-mcp-over-a-capability-addressed-network)
for the layer model and where it sits in the stack.

## Setup dev environment

First, we recommend you setup a Bazel-based developer environment with homebrew.

1. Run `make setup`

This will install `bazelisk` and `direnv` and add all the bazel-controlled tools to the path in this directory.

## Usage

> **Status:** the design is implemented end-to-end — the `library` core
> (identity, grants, **fabric membership**, tickets, policy, the session frame
> codec), the `wires` multi-call binary (`keygen` / `grant` / `member` /
> `revoke` / `pair` / `serve` / `connect`), a self-hosted `relay`, distroless OCI
> images, an on-disk keystore, direct-address tickets, and offline revocation.
> Every session also proves **fabric membership** and hands the verified caller
> identity to the served tool (see
> [Fabric membership](#fabric-membership-identity-on-every-session) and the
> companion [docs/fabric-vision.md](docs/fabric-vision.md)). What's left is
> convention, not plumbing: a standardized stdio-frame vocabulary (see the thesis
> at the bottom).

### Layout

Three flat Bazel packages in one Cargo workspace (build & test are Bazel-only —
`bazel build //...`, `bazel test //...`; see [CLAUDE.md](CLAUDE.md) and
[docs/rust-bazel-layout.md](docs/rust-bazel-layout.md)):

- **`//library`** — the `library` crate: the pure, transport-free core — identity,
  grant, ticket, policy, and the session `Frame` codec. No iroh/tokio; property +
  unit + doctested.
- **`//wires`** — the multi-call binary: the whole layer surface as subcommands.
  The iroh transport (`wires/transport.rs`), keystore (`wires/keystore.rs`), and
  pairing (`wires/pair.rs`) live here so `library` stays pure.
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

### The command surface

| Command          | Role                      | What it does                                                                 |
| ---------------- | ------------------------- | ---------------------------------------------------------------------------- |
| `wires keygen`   | trust-root / host setup   | Generate (or re-derive) a **node key** and **root key**; print, and `--save-*` to the keystore |
| `wires grant`    | trust root (the human)    | Root-sign a capability and emit a base64 **ticket**, optionally with `--addr`/`--relay-url` hints |
| `wires member`   | trust root (the human)    | Root-sign a **fabric membership** for a node and emit a base64 token (`--save` to the keystore) |
| `wires roster`   | trust root (the human)    | Author a **committed roster**: `add`/`remove` members, `commit` a signed head + per-member proofs, `head` to print the current head token |
| `wires revoke`   | trust root / responder    | Add a subject to the CRL (keystore `crl.json` by default) and print it       |
| `wires serve`    | responder (the tool host) | Verify the dialer's **membership** (and, with `--scope`, a matching grant), exec a command, bridge its stdio — injecting the verified caller identity into the child |
| `wires connect`  | dialer (the agent side)   | Present the **membership** and dial a `--ticket` (scoped) or `--target` (inclusion-only), piping local stdin/stdout/stderr |
| `wires pair`     | operator ⇄ requester      | Issue a grant over the wire: `accept` (operator consents) ⇄ `request` (node)  |

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
| `membership.json` | `member --save`      | `connect` fabric membership      |
| `roster.json`        | `roster add`/`commit` | the root's full member set (`0600`, private) |
| `roster-head.json`   | `roster commit`       | `serve --roster-head` (the signed head, public) |
| `inclusion-proof.json` | a member (file copy) | `connect --inclusion-proof` (the member's own path, public) |

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

**3. The human admits the agent to the fabric and grants it the tool.** First a
**membership** — the agent's scope-independent fabric identity, required on every
session (explained [below](#fabric-membership-identity-on-every-session)) — then
a scoped **grant**. Both are root-signed; the root key comes from the keystore,
so no `--root-seed` is needed. These print a membership **token** and a
capability **ticket** (the address):

```bash
MEMBERSHIP=$(bazel run -q //wires -- member \
  --subject "$AGENT_ID" \
  --ttl     3600)

TICKET=$(bazel run -q //wires -- grant \
  --subject "$AGENT_ID" \
  --target  "$SERVER_ID" \
  --scope   tools.rg \
  --ttl     3600)
```

Use `--not-after <unix>` instead of `--ttl` for an absolute expiry.

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

**5. The agent dials the capability** — exactly like running a local stdio
program. It presents its membership and the ticket; its node key comes from the
keystore; its stdin is forwarded to the child; the child's stdout/stderr stream
back; its exit code becomes `connect`'s:

```bash
echo "search input" | bazel run -q //wires -- connect \
  --ticket "$TICKET" --membership "$MEMBERSHIP"
```

The dialer's node key **must** be both the membership's member and the grant's
subject (`AGENT_ID`) — the responder checks that the iroh-authenticated caller
equals each, so neither can be used by anyone else. The served `rg` is handed the
verified caller in its environment (`WIRES_CALLER_NODE` / `WIRES_FABRIC_ROOT`),
so a tool can authorize per caller with no extra round-trip. (If you'd rather not
use the keystore, every command also accepts secrets inline via `--node-seed` /
`--root-seed`, via `$WIRES_NODE_SEED` / `$WIRES_ROOT_SEED`, or from a file via
`--node-seed-file` / `--root-seed-file`; the membership likewise via
`--membership` / `$WIRES_MEMBERSHIP` / `--membership-file`.)

### Fabric membership: identity on every session

A **grant** authorizes one scope; a **membership** answers a different question —
*"is this node part of my fabric, and who is it?"* — independent of any tool. The
human mints one per node with `wires member` (root-signed, non-transferable,
offline-verifiable against the pinned `--trust-root`), and the dialer presents it
on **every** session. A membership is a *public* credential: pass it inline with
`--membership`, via `$WIRES_MEMBERSHIP` / `--membership-file`, or save it to the
keystore as `membership.json`.

```bash
# The human (holds the root key) admits a node to the fabric:
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
  explicit `--allow-any-member`) and any fabric member may open a session; the
  served binary authorizes from the injected identity. This is the enterprise-MCP
  shape — one responder, per-caller authorization in the tool itself:

  ```bash
  bazel run -q //wires -- serve --trust-root "$ROOT_ID" --allow-any-member \
    -- my-mcp-server --config /etc/my-mcp.toml
  ```

  Without `--scope` *and* without `--allow-any-member`, `serve` refuses to start:
  execing for any member is an intentional authorization downgrade that must be
  asked for.

Membership is **slice 1** of a larger plan (committed rosters, then
delegation/federation) — see [docs/fabric-vision.md](docs/fabric-vision.md) and
[docs/provable-fabric-inclusion.md](docs/provable-fabric-inclusion.md).

### Committed roster: current membership + fabric-wide revocation

A membership says the root vouched for a node *at issue time* (bounded by its
TTL). The **committed roster** adds *current* membership: the root keeps a
versioned member set and signs a tiny 32-byte **head** (a Merkle root) whenever
it changes; a verifier holding the latest head checks a caller's **inclusion
proof** against it, offline, and learns *present* membership. Removing a member
and re-signing is fabric-wide revocation with no CRL to distribute. The head
leaks nothing about the set; a proof reveals only its holder's id and `O(log n)`
sibling hashes. This is **slice 2b** — see
[docs/committed-roster.md](docs/committed-roster.md); head/proof distribution
(gossip, sealed blobs, a blind node) is the deferred slice 2c.

```bash
# The human authors the roster (offline) and signs a head + per-member proofs.
bazel run -q //wires -- roster add --member "$MEMBER_ID"
bazel run -q //wires -- roster add --member "$SVC_ID"      # the service is a member too
bazel run -q //wires -- roster commit --ttl 3600 --out ./proofs
# → writes keystore roster-head.json, prints the head token, and emits
#   ./proofs/<node-id>.proof for each member.

# The service enforces the head (any member with a valid current proof may connect):
bazel run -q //wires -- serve --trust-root "$ROOT_ID" --allow-any-member \
  --roster-head-file ./roster-head.json \
  -- printenv WIRES_CALLER_NODE WIRES_ROSTER_VERSION

# The member dials, presenting its membership and inclusion proof:
bazel run -q //wires -- connect --target "$SVC_ID" \
  --inclusion-proof-file "./proofs/$MEMBER_ID.proof"
# → the child sees WIRES_CALLER_NODE and the WIRES_ROSTER_VERSION that admitted it.
# Now `roster remove --member "$MEMBER_ID" && roster commit` and the same dial is rejected.
```

A ticket-less (`--target`) dialer also verifies the **responder's** membership
from the handshake ack before sending any stdin — *mutual inclusion*, so the
agent never streams to a service outside its fabric.

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

In the MCP client config, replace the local command with the dialer (its node
key and membership come from the agent's keystore — drop `membership.json` there
once and the args stay clean; otherwise add `--membership <token>`):

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

The client believes it launched a local stdio server; the server believes it was
launched locally. Neither knows a network is involved. (For a multi-tenant MCP
server, run the responder
[inclusion-only](#fabric-membership-identity-on-every-session) with
`--allow-any-member` and authorize each caller inside the server from
`WIRES_CALLER_NODE`.)

### Pairing: issue a grant over the wire

`grant` requires pasting the subject's node id. `pair` collects it over an
authenticated channel instead: the requester dials the operator and announces a
scope; the operator consents and mints a ticket whose **subject is the
requester's iroh-authenticated node id** — so a paired ticket is
non-transferable by construction.

```bash
# Operator (holds the root key): listen, auto-consent once. Logs its node id +
# bound sockets so the requester knows where to dial.
bazel run -q //wires -- pair accept \
  --target "$SERVER_ID" --scope tools.rg --ttl 3600 --yes --once

# Requester (the agent box): dial the operator directly, print the issued ticket.
TICKET=$(bazel run -q //wires -- pair request \
  --operator "$OPERATOR_ID" --addr 198.51.100.9:4433 --scope tools.rg)
```

Drop `--yes` to be prompted per request (`grant '<scope>' to <node id>? [y/N]`),
and `--once` to keep serving. The operator reaches requesters / the requester
reaches the operator the same way as everywhere else — direct `--addr`,
`--relay-url`, or n0 discovery.

### Revocation (offline)

Revocation is offline: short grant TTLs plus a responder-side CRL. On the tool
host, `revoke` updates the keystore's `crl.json` in place, and `serve` reads it
by default — so revoking a subject is a one-liner:

```bash
# Append a subject to the keystore crl.json (idempotent):
bazel run -q //wires -- revoke --subject "$AGENT_ID"

# serve reads ~/.config/wires/crl.json automatically:
bazel run -q //wires -- serve --trust-root "$ROOT_ID" --scope tools.rg -- rg --line-number TODO
```

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
- **stdio framing is raw bytes:** the richer `tool.exec`/`tool.stdout` frame
  vocabulary in the thesis below is still a convention to build, not shipped.

# Wires as a session layer: stdio and MCP over a capability-addressed network

The clever core of wires is one idea: **a capability-addressed transport
whose native protocol data unit is stdio — and, one frame up, MCP.** This
document is just that idea and the two reference protocols that sit on it
(stdio-over-wires and MCP-over-wires).

> **Status.** The layer itself is built (see [Usage](#usage) above): the
> capability-addressed transport, the human-rooted grant model, and the
> dial-a-capability-get-a-stdio-session ALPN all run today on iroh. What remains
> *conceptual* is the richer reference **protocol** — the `tool.exec` /
> `tool.stdout` frame vocabulary below — which is a convention on the layer; the
> shipped bridge moves raw stdio bytes.

## The thesis

Every networking layer is defined by two choices: **what is the address,
and what is the protocol data unit (PDU).** Those two answers are what
make TCP "TCP" and HTTP "HTTP". For wires:

- **The address is a capability**, not an `(IP, port)`. You do not dial a
  *host*; you dial *a tool you have been granted the right to use*,
  identified by key and scoped by a non-transferable, human-issued grant.
- **The PDU is a stdio stream** (stdin / stdout / stderr / exit), and one
  frame up, an MCP message. The link's *native* content is exactly what
  agents and tools already speak.

That second choice is the move. Most systems treat stdio and MCP as
*application payload you happen to ship over a generic transport*. Wires
makes them the **native framing of a link layer**, so "networking a tool"
and "speaking to a tool" become the same act — there is no impedance
mismatch to bridge, because the wire already speaks pipes.

The one-line form:

> **Wires is the missing session layer of the agent stack: a
> capability-addressed, identity-bound transport whose native PDU is
> stdio and MCP. It makes any binary's stdin/stdout a first-class,
> location-independent network endpoint usable only by whoever you grant —
> turning "provision the tool next to the agent" into "dial the tool by
> capability, wherever it runs."**

## Where it sits in the stack

Walk the existing stack and the gap is precise:


| Layer                 | Address             | Credential                               | What you get                             | Gap for agent tooling                                   |
| ----------------------- | --------------------- | ------------------------------------------ | ------------------------------------------ | --------------------------------------------------------- |
| TCP/IP                | `(IP, port)`        | none                                     | byte pipe                                | no identity, location-bound                             |
| TLS                   | `(IP, port)` + cert | CA chain                                 | encrypted byte pipe                      | identity bolted on, still location-bound                |
| SSH                   | reachable IP        | copyable keypair (bearer)                | authenticated remote shell               | coarse (a whole shell), bearer auth, needs reachability |
| WireGuard / Tailscale | overlay IP          | device key                               | an IP network                            | still L3 — you then run protocols on top               |
| **wires**             | **a capability**    | **non-transferable, human-issued grant** | **an authenticated stdio / MCP session** | — this is the layer                                    |

Nothing above wires lets you say: *"this binary's stdin/stdout is now a
first-class network endpoint, addressable by a capability, reachable
wherever it runs, usable only by whoever I admitted."* That sentence is
the layer. It is SSH where the address is a capability instead of an IP,
the credential is an identity-bound grant instead of a copyable key, and
the far end is a scoped tool instead of a shell.

## The core: dial a capability, get a stream, speak stdio

The novel part wires actually has to add is small. iroh already provides
dial-by-key, NAT-traversing, encrypted, multiplexed QUIC streams. On top
of that, the session layer is:

> **an ALPN meaning "open a capability-scoped stdio/MCP session," plus
> the human-rooted, non-transferable capability model that decides who
> may dial what.**

A tool call is a **session**, not a broadcast: open → stream
stdin/stdout/stderr → close. It needs no persisted log, message broker, or
retention — just a direct, encrypted stream between the two endpoints.

```mermaid
flowchart LR
    subgraph before["Today: tool provisioned next to the agent"]
        a1["agent"] -->|"local exec()"| b1["binary"]
    end

    subgraph after["Wires: dial the tool by capability"]
        a2["agent"] -->|"dial capability"| s(["authenticated<br/>stdio session"])
        s -->|"stdin"| b2["binary<br/>(anywhere, egress-only)"]
        b2 -->|"stdout / stderr / exit"| s
    end
```
The binary is unchanged and unaware of wires. It reads stdin and writes
stdout/stderr exactly as always. The wrapper node is the adapter between
"process I/O" and "the session," and it owns the only new thing: an
identity, and the capability that says which channel/peer may drive it.

## Reference protocol 1: stdio-over-wires

A stdio tool node maps process I/O directly onto the session. The frames
(this is the *reference convention*, not part of the layer):


| Direction     | Process concept | Frame                                                          |
| --------------- | ----------------- | ---------------------------------------------------------------- |
| agent → tool | argv + stdin    | `tool.exec` (argv, optional stdin) / `tool.stdin` (more input) |
| tool → agent | stdout          | `tool.stdout` (chunk)                                          |
| tool → agent | stderr          | `tool.stderr` (chunk)                                          |
| tool → agent | exit code       | `tool.exit` (code)                                             |

Three interaction shapes fall out of the same session primitive:

- **One-shot** (`rg`, `git status`): one `tool.exec` in; a few
  `tool.stdout`/`tool.stderr` frames and a `tool.exit` out; stream closes.
- **Streaming** (`tail -f`, a build with progress): the tool keeps
  emitting `tool.stdout` as output arrives; the agent sees it live.
- **Interactive / long-running** (a REPL, a shell-like session): the
  agent feeds further `tool.stdin` while the process stays alive; a
  correlation id ties a stream of frames to one process instance.

Because CLIs are self-documenting, discovery needs no registry: an agent
dials the tool and runs `--help` to learn the surface, then uses it
directly. The project intends to publish a standard stdio-over-wires
frame format so tools and agents interoperate without negotiating — a
convention on the layer, not part of it.

## Reference protocol 2: MCP-over-wires

This is the cleanest proof the thesis sits at the right layer. An MCP
server is normally a **local binary** that the MCP client spawns as a
child process and talks to over stdio (JSON-RPC framed on stdin/stdout).
Because the wires session's native PDU *is* stdio, you can relocate that
binary to another machine and **MCP never notices** — no remote-transport
story to invent, no HTTP/SSE/OAuth bolt-on.

### What actually runs on each machine

Two thin wires nodes bracket the existing, unmodified pieces. Nothing
about the MCP client or the MCP server changes.

```mermaid
flowchart LR
    client["MCP client / agent<br/>(unmodified)"] -->|"spawns as a<br/>local stdio server"| shim["wires shim node<br/>(client machine)"]
    shim -->|"dial capability,<br/>open session"| resp["wires responder node<br/>(server machine, egress-only)"]
    resp -->|"spawn child,<br/>pipe stdio"| srv["MCP server binary<br/>(unmodified)"]
```
- On the **server machine** (e.g. inside a VPC): a wires **responder**
  node. It holds an identity and an installed grant, binds an iroh
  endpoint (egress-only, dialable by key, *no inbound port*), and listens
  on the session ALPN. On an inbound capability-scoped session it verifies
  the caller's grant, spawns the MCP server binary as a child process, and
  bridges the iroh stream byte-for-byte to the child's stdin/stdout/stderr.
- On the **client machine** (where the agent runs): a wires **shim** node.
  The MCP client spawns it exactly as it would spawn a local stdio MCP
  server. The shim holds the capability to dial the remote, opens a
  session, and pipes its own stdin/stdout to the iroh stream.

The MCP client believes it launched a local stdio server; the MCP server
believes it was launched locally by a client. Neither is aware of the
network between them. wires carries the JSON-RPC bytes opaquely — it never
parses MCP.

### What has to exist on the server machine

- the **MCP server binary** and everything it needs to do its job
  *locally* — its config and its secrets. The database password, API key,
  or service credential an MCP server uses **stays on that machine and
  never travels to the agent**; the agent only ever holds a capability to
  *reach* the server, not the secrets the server wields.
- the **wires responder binary** with a grant installed (issued once via
  the pairing flow).
- **outbound network egress** to reach a relay / rendezvous. No inbound
  ports, no public endpoint, no TLS certificate, no MCP-side auth layer.

### Why this is the right framing

This is essentially `ssh user@host -- mcp-server`, with the three
differences that make it a *layer* rather than a workaround: the address
is a **capability** instead of a reachable IP, the credential is a
**non-transferable identity-bound grant** instead of a copyable key, and
the exposure is scoped to **exactly that one binary** instead of a shell.
Your "local" MCP server now runs in a VPC, an air-gapped enclave, or on
another machine — and the MCP spec did not change at all.

MCP-over-wires as described here carries  an MCP *server's* stdio across
the session layer — and is the conceptual reference protocol, not a
shipped component.

## Agents like Claude Code are just endpoints

An agent is not special transport; it is another endpoint on the layer.
Claude Code stops being the box that *contains* its tools and becomes a
peer that **dials tools by capability.** Its right to drive a tool is the
grant it holds, not shell access, not a bundled binary, not an API key in
its environment.

```mermaid
sequenceDiagram
    autonumber
    participant Cl as Claude Code (endpoint)
    participant T as rg tool node

    Cl->>T: dial capability for tools.shell, open session
    Note over T: accept — verify grant, then run rg
    Cl->>T: tool.exec — argv rg TODO src/
    T->>Cl: tool.stdout — match in src/a.rs
    T->>Cl: tool.exit — code 0
    Note over Cl: had no local rg, networked to a node that did
```
## What the layer gives you for free

These are properties of the session layer itself — the agent and the tool
implement none of them:

- **Identity on every session.** The session is authenticated to the caller's
  key, and the caller proves **fabric membership**; the responder hands that
  verified identity to the served tool as environment variables
  (`WIRES_CALLER_NODE` / `WIRES_FABRIC_ROOT`). The tool knows *which* endpoint is
  driving it, cryptographically — never "whoever reached the socket."
- **Authorization is the address.** You can only dial a capability you
  hold. There is no separate auth layer in the tool; its access policy
  *is* who you granted the capability to.
- **Non-transferable, human-issued grants.** Authority is bound to an
  endpoint's key and rooted in one human's key. It cannot be copied or
  subleased the way an SSH key or API token can.
- **Instant revocation.** Withdraw the grant and the endpoint can no
  longer dial. No key rotation across every place a secret was cached.
- **End-to-end encryption + NAT traversal**, inherited from iroh: the
  tool is reachable egress-only, with no public endpoint, and the stream
  is encrypted between the two endpoints.
- **Multi-party as session fan-out.** Several agents — and a human
  watching — can attach to one tool session as additional observers of the
  same stream.

## Layer vs. convention

To keep the line clear:

- **Layer (the invention):** capability addressing, identity-bound
  non-transferable grants, the dial-a-capability-get-a-stdio-session
  ALPN, end-to-end encryption and NAT traversal via iroh.
- **Reference protocols (conventions on the layer):** the stdio-over-wires
  frame vocabulary (`tool.exec` / `tool.stdout` / `tool.stderr` /
  `tool.exit`, correlation ids), and MCP-over-wires (MCP's own JSON-RPC
  carried byte-for-byte on a stdio session). Two endpoints may negotiate
  something else; the layer does not care what flows on the session.

The point of the split is that you build identity, capability
authorization, encryption, and NAT traversal **once**, as a layer — and
then "make any stdin/stdout a secure, networked, revocable endpoint" and
"make a local MCP server remote" are both *reference protocols on that
layer*, not new protocols.

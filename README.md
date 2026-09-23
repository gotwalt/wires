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

1. **workbench** exposes one read-only SQL CLI to the `analyst` role
   (`*@example.com`, verified by the IdP) and puts every call on the `ops`
   channel: `wires serve host.json` (see [host.json](#hostjson-what-runs-and-who-may-run-it)).
2. **laptop**: Claude Code runs `wires call db_query -- "select count(*) from orders"`
   from its shell, or reaches the same tool through `wires mcp` in its MCP config.
3. **observer** holds no grant for the tool and no credential of either end;
   `wires watch ops` shows each call as it happens:
   ```
   ▶ 3fa2 alice@example.com (a1b2…) [analyst] db_query "select count(*) from orders"
   ■ 3fa2 exit 0 · 41 ms · 3.1 KiB out · blake3 9c1e…
   ```
4. **revoke**: one `wires advanced roster commit` without the agent. Its next call
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

> **Status:** every step runs today (`.scripts/demo-remote-cli.sh` runs them
> all on loopback). Steps 1–2 are admin plumbing under `wires advanced` until
> `init` / `invite` / `join` land ([card 14](docs/board/README.md#lanes)).
> Build with `bazel build //wires` and put `bazel-bin/wires/wires` on `PATH`
> (copy it; `bazel-bin/` moves on `bazel clean`).

**1. Keys.** Each machine makes a node key; you (the person who decides who's
in) also make a root key, and keep it on your own machine.

```bash
wires advanced keygen --save-node   # on workbench, laptop, observer — note each node_id
wires advanced keygen --save-root   # on your machine only — note root_id
```

**2. The roster.** Sign the list of who's in. Per member, `commit` writes an
inclusion proof and that member's sealed copy of the channel's data key; each
member installs its four credentials with one `import`.

```bash
wires advanced roster add --member "$WORKBENCH_ID"
wires advanced roster add --member "$LAPTOP_ID"
wires advanced roster add --member "$OBSERVER_ID"
wires advanced roster commit --ttl 3600 --out ./proofs     # prints the head token
wires advanced member --subject "$LAPTOP_ID" --ttl 3600 > laptop.pass

# on each member (laptop shown):
wires advanced import --membership-file ./laptop.pass \
                      --inclusion-proof-file "./proofs/$LAPTOP_ID.proof" \
                      --roster-head "$HEAD" \
                      --fabric-key-file "./proofs/$LAPTOP_ID.key"
```

**3. workbench: expose the CLI and log every call.** Everything the host
decides lives in one file, `host.json`: the tools, the channel, the IdPs it
trusts, and which roles may run which tool. A command is an argv, exec'd
directly and never through a shell, with the caller's arguments appended.
sqlite3's `-safe` flag disables its `.shell`/`.system` dot-commands, so use
it.

```json
{
  "version": 1,
  "channel": "ops",
  "identity": { "issuers": [
    { "issuer": "https://accounts.google.com", "audiences": ["<client id>.apps.googleusercontent.com"] }
  ] },
  "roles": { "analyst": [ { "email": "*@example.com" } ] },
  "tools": {
    "db_query": {
      "description": "Read-only SQL against the orders database",
      "command": ["sqlite3", "-safe", "-readonly", "/data/orders.db"],
      "allow": ["analyst"]
    }
  }
}
```

```bash
wires serve --check host.json   # validate; print who may run what, and which IdPs are trusted
wires serve host.json
```

**4. laptop: log in once, then call.** `wires login` runs your IdP's browser
flow and publishes the resulting claim on `ops`. The host admits the call once
that claim verifies and matches a role in the tool's `allow`.

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
wires watch ops
```

To revoke: `wires advanced roster remove --member "$LAPTOP_ID" && wires advanced
roster commit …`, then import the new head on workbench. The next call is refused; no one
restarts anything.

## What runs today

Two unattended scripts stand up the working parts on loopback, each in a
fresh `mktemp -d` that never touches `~/.config/wires`. Each asserts its own
result, so a green run is a passing test, not a screenshot. Both take
`--quiet` (assertions only) and `--keep` (leave the state dir).

```bash
bazel build //wires //wires:wires_dev
./.scripts/demo-remote-cli.sh     # the demo above: IdP-gated remote SQL, every call on the channel
./.scripts/soak-topic.sh          # one channel through a frozen node and a killed one; nothing lost or doubled
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
- **`soak-topic.sh`** (~2 min): the channel on its own — a publisher streams
  numbered messages to two readers; mid-run one is frozen past the QUIC idle
  timeout and the other is `kill -9`ed and restarted. Both must end with every
  message exactly once, in order. See
  [the channel](#the-channel-the-calls-land-on) below.

The recording below predates the reorganization: it shows the old
single-command dial being revoked. [Card 08](docs/board/README.md#lanes)
replaces it with a recording of the remote-CLI demo.

![revocation demo: the same dial before and after a roster head-advance — exit 77, zero bytes, responder never restarted](docs/demo-revoke.gif)

## The channel the calls land on

The audit channel is a **topic**: an end-to-end-encrypted log shared by the
members of a roster, with no server in the middle. `wires watch` is a resident
node (log, gossip mesh, admission, history replay) and `wires advanced publish`
puts a message on it by hand. A host with a `channel` in its `host.json` is
simply a member that publishes call records; an observer is any member running
`watch`.

```bash
wires watch ops                                                # → share to bootstrap: <ticket>
wires advanced publish ops -m "deploying build 41" --peer "$TICKET"
```

The topic isn't created anywhere; every member computes the same name from
the roster it belongs to. Each line is stamped with the key that signed it,
and a member who was offline catches up from any other member, because every
`watch` serves history. The commit that removes a member re-keys everyone
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
self-hosted `relay`, distroless OCI images, and an on-disk keystore. A fuller
rewrite of this reference around the four roles is
[card 17](docs/board/README.md#lanes).

### Layout

Three Bazel packages in one Cargo workspace (build & test are Bazel-only —
`bazel build //...`, `bazel test //...`; see [CLAUDE.md](CLAUDE.md)). Inside
each, the source is filed by role:

- **`//library`** — the `library` crate: the pure, transport-free core. No
  iroh/tokio; property + unit + doctested.
  - `membership/` — identity, membership, the committed roster, grants,
    tickets, the accept gates, the per-commit fabric key.
  - `channel/` — topic ids, envelopes, chain rules, admission, replay, and the
    records that ride a topic.
  - `calls/` — session frames, invocations, audit records, IdP identity claims.
- **`//wires`** — the multi-call binary. `main.rs` is parsing and dispatch;
  everything else lives with its role:
  - `admin/` — the keystore and the root's offline commands (`advanced keygen
    | grant | member | roster | revoke | import`).
  - `host/` — `serve`: the session transport, the caller checks, the IdP
    policy, and the audit records the host publishes.
  - `caller/` — `login`, `call`, `tools`, `mcp`.
  - `channel/` — the topic node every role meets on: `watch`, `advanced
    publish`, the log, admission, replay, rendering.
  - `e2e/` — the loopback integration tests.
- **`//relay`** — a self-hosted [`iroh-relay`](https://docs.rs/iroh-relay)
  rendezvous server.

Both binaries also build as distroless OCI images — `//wires:image` and
`//relay:image` (`bazel run //relay:image.load` to `docker load`).

### Build and test

Everything goes through Bazel (see [CLAUDE.md](CLAUDE.md) for the dependency
workflow — never `cargo build`/`cargo test`):

```bash
bazel build //...          # build the library + binaries
bazel test  //...          # unit + property + doctests + the loopback QUIC tests
bazel run   //wires -- --help
```

Run a subcommand with `bazel run //wires -- <subcommand> …`, or build once and
call the binary directly at `bazel-bin/wires/wires`.

For production deployment — containers, Kubernetes manifests, and self-hosting
the relay — see [docs/deployment.md](docs/deployment.md); for the test suite and
manual recipes see [docs/testing.md](docs/testing.md). Every script in
`.scripts/` runs directly from the repo root, not via `bazel run`.

### The command surface

`wires --help` lists only the role commands:

| Role         | Command          | What it does |
| ------------ | ---------------- | ------------ |
| **admin**    | `wires advanced` | The plumbing below. (`init` / `invite` / `remove` land with [card 14](docs/board/README.md#lanes).) |
| **host**     | `wires serve`    | `wires serve host.json`: expose the file's tools, verify every caller's membership and roster inclusion, admit it only if a role in the tool's `allow` matches (IdP identity or the built-in `member`), exec the tool per call, and publish a record of every call and refusal on the file's `channel`. `--check` validates the file and prints a summary |
| **caller**   | `wires login`    | Sign in with your IdP; the ID token is bound to this node's key and, with `--topic`, published on the channel |
|              | `wires call`     | Run a remote CLI from `tools.json`: stdio passes through, its exit code becomes `call`'s, a refusal exits `77` |
|              | `wires tools`    | Edit `tools.json`, the local map of remote CLIs (`add` / `list` / `rm`) |
|              | `wires mcp`      | Serve the `tools.json` CLIs as MCP tools over stdio, for clients that only speak MCP |
| **observer** | `wires watch`    | Own a **topic**: the message log, the mesh, the admission gate, the replay server and a control socket; print every call record, refusal and identity claim, and this node's bootstrap ticket |

`wires advanced` holds the rest, unchanged:

| Command                   | What it does |
| ------------------------- | ------------ |
| `wires advanced keygen`   | Generate (or re-derive) a **node key** and **root key**; print, and `--save-*` to the keystore |
| `wires advanced grant`    | Root-sign a grant (scope `tool:<name>` or `tool:*`) and emit a base64 **ticket**, optionally with `--addr`/`--relay-url` hints |
| `wires advanced member`   | Root-sign a **membership** for a node and emit a base64 token (`--save` to the keystore) |
| `wires advanced roster`   | Author a **committed roster**: `add`/`remove` members, `commit` a signed head + per-member proofs and sealed keys, `head` to print the current head token |
| `wires advanced revoke`   | Add a subject to the CRL (keystore `crl.json` by default) and print it |
| `wires advanced import`   | Install a membership / inclusion proof / roster head / sealed fabric key into the keystore, so later commands need no flags |
| `wires advanced publish`  | Put a message on a topic — through a running `watch`'s socket, or as a one-shot node when there isn't one |

(`wires advanced tail` is kept, hidden, as the old name of `wires watch`.)

### host.json: what runs and who may run it

`wires serve host.json` is the host's only form. The file:

| Key | Meaning |
| --- | ------- |
| `version` | Required, `1`. Unknown keys anywhere are an **error**, so an older host never silently misreads a newer file. |
| `channel` | The topic every call, refusal and exit is recorded on, and where callers' `wires login` claims are read. The host must be a provisioned member of it. It can be left out only when every tool allows nothing but `member`. |
| `identity.issuers` | The IdPs whose ID tokens the host verifies, each with the OAuth client ids (`audiences`) it accepts **from that issuer**. |
| `roles` | Name → a list of matchers, any of which may match (OR). A matcher's keys must all match (AND): `issuer` (exact), `email` (exact or `*@domain`), `org` (Google's `hd`), `group`. |
| `tools` | Name → `command` (argv), optional `description`, and `allow`: the roles that may run it, tried in order. |

Nothing is allowed by default. A tool with an empty `allow` refuses every call.
The built-in role `member` admits any roster member with no IdP requirement,
and it never applies unless a tool's `allow` lists it. An admitted call's
record names the role (`▶ 3fa2 alice@example.com (a1b2…) [analyst] db_query …`).
A refusal names the rule that failed:

```
✗ a1b2… db_query denied: identity bob@other.org (from https://accounts.google.com) is in no role allowed to run db_query: analyst (email=*@example.com)
✗ c3d4… db_query denied: no identity claim for c3d4e5f6; run `wires login --topic ops`; db_query needs a verified identity in role analyst (email=*@example.com)
```

The role table is one implementation of the host's `Policy` trait
(`wires/host/policy.rs`), which gets the whole call: the verified principal
with every claim the IdP signed, the caller's node, the roster version, the
tool and its arguments. An organization that needs rules a table can't express
(CEL or Rego over the claims, or a webhook to its own authorizer) would add a
second implementation behind a `"policy"` block in `host.json`. That block
doesn't exist yet; the table is v1.

The flags that remain are where the host's own credentials come from
(`--node-seed…`, `--membership…`, `--roster-head…`, `--crl…`), `--peer` to
bootstrap the channel, and `--relay-url`.

### Two keys

There are two Ed25519 keys with different jobs:

- **Node key** — a node's iroh transport identity. Its public half *is* the
  node id callers reach. Every participant (host, caller, observer) has one.
- **Root key** — the admin's trust root that signs memberships, grants and
  roster heads. A host trusts the root that signed its own membership. It
  never touches iroh.

`advanced keygen` emits both as `<label> <hex>` lines:

```bash
$ bazel run -q //wires -- advanced keygen
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
environment), keys and credentials live in a **keystore** directory, resolved
as `$WIRES_HOME`, else `$XDG_CONFIG_HOME/wires`, else `~/.config/wires`:

| File                   | Written by                         | Read by |
| ---------------------- | ---------------------------------- | ------- |
| `node.seed`            | `advanced keygen --save-node`      | every network command's node key |
| `root.seed`            | `advanced keygen --save-root`      | `advanced grant` / `member` / `roster commit` |
| `crl.json`             | `advanced revoke` (default)        | `serve` revocation check |
| `membership.json`      | `advanced member --save` / `import` | `call`, `mcp`, `watch`, `serve` |
| `roster.json`          | `advanced roster add` / `commit`   | the root's full member set (`0600`, private) |
| `roster-head.json`     | `advanced roster commit` / `import` | `serve` and `watch` (the signed head they enforce) |
| `inclusion-proof.json` | `advanced import`                  | `call`, `watch`, `serve` (this node's own proof) |
| `keyring/<v>.key`      | `advanced import --fabric-key…`    | `watch`, `serve` with a `channel` (the channel's data keys) |

Every secret/CRL input resolves in the same order: **inline flag → environment
variable → `--…-file <path>` → keystore**. So with the keystore populated,
commands need no seed at all — and for Kubernetes you mount a `Secret` and
point at it with `--node-seed-file /etc/wires/node.seed`.

### Membership, the roster, and revocation

A **membership** answers *"is this node one of mine, and which one?"*: it is
root-signed, non-transferable, and verified offline on every call against the
root that signed the host's own membership. A host that admits a caller injects the verified
identity into the tool's environment — `WIRES_CALLER_NODE`,
`WIRES_FABRIC_ROOT`, `WIRES_MEMBERSHIP_NOT_AFTER`, `WIRES_ROSTER_VERSION` and
`WIRES_TOOL` — server-derived, never a caller claim, with any inherited
`WIRES_*` scrubbed first.

The **committed roster** adds *current* membership: the root keeps a versioned
member set and signs a 32-byte **head** (a Merkle root) whenever it changes; a
host holding the latest head checks each caller's **inclusion proof** against
it, offline. Each commit also mints a fresh channel key sealed to every
remaining member. Removing a member and re-committing revokes it everywhere the
new head lands — by omission, not a blocklist — and a removed member cannot
read what is published after it. Spec:
[docs/committed-roster.md](docs/committed-roster.md).

**Revocation takes effect on the next call, with no host restart.** `serve`
re-reads `crl.json` and `roster-head.json` once per connection. A refused call
prints `wires: denied by responder: <reason>` on the caller's stderr, writes
zero bytes to stdout, exits **77**, and (when the host has a `channel`) the
refusal is on the channel. Once a host has seen a head, deleting its `roster-head.json`
fails closed. `.scripts/demo-remote-cli.sh` asserts the roster path end to end.

### Reachability: relays and direct addresses

By default a caller resolves the host by node id via iroh's n0 discovery +
relays (needs outbound internet). Two ways to avoid that:

- **Self-hosted relay** — run the `relay` binary and point both ends at it with
  `--relay-url http://relay-host:3340` (see [docs/deployment.md](docs/deployment.md)).
- **Direct addresses** — `wires tools add --topic-ticket <ticket>` takes the
  host's addresses from its channel ticket, and `advanced grant --addr … --relay-url
  …` bakes them into a grant ticket. They are *unsigned hints*: iroh still
  authenticates the peer to the host's key, so a wrong address can only fail
  to connect, never impersonate.

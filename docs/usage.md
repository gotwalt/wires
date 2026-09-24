# Using wires

The [README](../README.md) says what wires is and why. This is the rest: the
roles, where each guarantee lives, a full walkthrough with output, the design
choices, the limits, and the command reference. The wire-level spec is
[protocol.md](protocol.md).

## Roles

| Role | Decides | Commands |
|---|---|---|
| **admin** | who's in, which roles exist, which services run where, who may call and read each (root key) | `init`, `invite`, `remove`, `role set\|rm`, `service add\|set\|rm` |
| **host** | how it implements its assigned services; which IdPs it trusts; stricter local rules; push | `serve host.json`, `push` |
| **caller** | — runs services by name; MCP only for backward compatibility | `id`, `join`, `login`, `services`, `call`, `mcp`, `inbox` |
| **reader** | — any member; reads the records a service's `readers` role allows, or its own | `watch` |

Every role joins the same way: `wires id`, then `wires join <token>` with the admin's invite.

## Where each guarantee lives

| Guarantee | Lives in | Checked by |
|---|---|---|
| **Who's in** | The admin-signed state's member set (and each node's root-signed membership). Removal is a new state without the member. | The host, per connection, against its copy of the state (re-read every dial). |
| **Who may call what** | The state's registry: each service's `allow` roles, and the role definitions (matchers on the IdP identity). | The host, on every call. `wires services` evaluates the same table locally, for listing only. |
| **Stricter local rules** | `host.json`'s `also_require` roles per service. They can only narrow. | The host, after the registry. |
| **Who is calling** | Your IdP's ID token, bound to the caller's node key at `wires login` (the OIDC `nonce` is a hash of the key), presented in the session `Hello`. | The host, against the issuer's JWKS, under the issuers `host.json` trusts. No wires identity service. |
| **Reach** | The host's node key. Callers dial a key (iroh; n0 discovery, or an optional local `$WIRES_HOME/hints` file); the host binds UDP for QUIC and has no TCP listener. | iroh's handshake authenticates the key; the host then checks the membership and the state. |
| **Which host** | The registry's `hosts` for the service. Only the admin binds a name to a host, so no host can squat a name. | The caller (it dials only those hosts) and the host (it refuses to start, or to serve, a name not assigned to it). |
| **Records** | Each host's own call log: every call, refusal and push, signed by the host and hash-linked. | Readers, with `wires watch`: the service's `readers` roles see all of it, everyone else only their own calls; every entry and the chain are verified. |
| **Push** | The host dials the caller's key, or queues for the caller's `wires inbox` fetch. | The host, at send, delivery and fetch: a member of the state, in a `push.allow` role. |
| **Removal** | A new state, pushed hosts first. No shared key exists, so there is nothing to rotate. | Every host, on the removed member's next call or fetch. |

Nothing is broadcast: a member that takes part in no call receives no traffic about other members' calls, identities or services (the admin's state push aside).

## Walkthrough

Five `WIRES_HOME` directories stand in for five machines: **admin**,
**workbench** and **spare** (hosts), **agent** (alice@example.com, the
caller) and **observer** (sec@audit.example, a reader). Build with `cargo
build --release -p wires` (or `docker build .`) and put `target/release/wires`
on each machine's `PATH`. The output below is from `./.scripts/demo-remote-cli.sh`,
which runs this sequence on loopback with a stand-in IdP (`wires
dev-mock-idp`, from a build with `--features dev-mock-idp`) and asserts every
step. Node ids are shortened.

**1. admin: start, define roles.**

```console
admin$ wires init
fabric 57b09428…
node 23028cae…
state version 1 (1 member: this node)
next: on each joining machine run `wires id`, then here `wires invite <node-id> --name <label>`
admin$ wires role set analyst '*@example.com'
role analyst set (state version 2)
admin$ wires role set security sec@audit.example
role security set (state version 3)
```

**2. Hosts join, and the admin registers the service.** Each machine sends
its `wires id`; the admin sends back one token.

```console
workbench$ wires id
3ef72b11…
admin$ wires invite 3ef72b11… --name workbench        # likewise the spare
wires: invited 3ef72b11… as "workbench" (state version 4, 2 members)
wires: on the joining machine: wires join eyJhZG1pbiI6…
workbench$ wires join eyJhZG1pbiI6…
admin$ wires service add orders-db --description "Read-only SQL (sqlite3) over the orders database; …" \
         --allow analyst --reader security --host workbench --host spare
service orders-db added (state version 6)
wires: state version 6: pushed to 0 member(s); 2 not reachable now (3ef72b11…, 511de414…) — they pull it on their next command
```

The hosts weren't running, so the push missed them; a fresh `wires invite`
token catches a host up (re-joining never rolls a state back). The token
isn't a secret: it holds the invitee's membership and the signed state.

**3. The hosts serve.** `host.json` says only how each service runs here. A
command is an argv, exec'd directly and never through a shell, with the
caller's arguments appended; sqlite3's `-safe` turns off `.shell`.

```json
{
  "version": 2,
  "identity": { "issuers": [
    { "issuer": "https://accounts.google.com", "audiences": ["<client id>.apps.googleusercontent.com"] }
  ] },
  "services": {
    "orders-db": { "command": ["sqlite3", "-safe", "-readonly", "-header", "-column", "orders.db"] }
  },
  "push": { "allow": ["analyst"] }
}
```

```console
workbench$ wires serve --check host.json
host.json ok (version 2)
trusted issuers:
  https://accounts.google.com  audiences: <client id>.apps.googleusercontent.com
services (who may call each is in the admin-signed state):
  orders-db
    command: sqlite3 -safe -readonly -header -column orders.db
push: to roles analyst
workbench$ wires serve host.json
```

`serve` refuses to start unless its state assigns every service in the file
to it.

**4. The agent and the observer join.** Each invite is a new state, pushed to
both hosts:

```console
admin$ wires invite dd7e7237… --name agent
wires: invited dd7e7237… as "agent" (state version 9, 4 members)
wires: state version 9: pushed to 2 member(s); 1 not reachable now (dd7e7237…) — they pull it on their next command
agent$ wires join eyJhZG1pbiI6…
```

**5. agent: before sign-in, nothing; after, one service.**

```console
agent$ wires services
wires services: no service allows this node without a login (state v9)
agent$ wires call orders-db -- "select count(*) from orders"
wires: denied by responder: no ID token presented; run `wires login`; orders-db needs a verified identity in role analyst
agent$ echo $?
77
agent$ wires login --client-id <client id> --client-secret <secret>
wires login: node dd7e7237… is alice@example.com (token stored in …/idp-token.jwt, valid until unix …)
agent$ wires services
orders-db  Read-only SQL (sqlite3) over the orders database; pass the SQL statement as the argument.  (analyst)
agent$ wires call orders-db -- "select count(*) from orders"
count(*)
--------
       7
```

A signed-in member in no allowed role sees nothing, and naming the service
anyway is refused with the reason:

```console
observer$ wires services
wires services: no service allows sec@audit.example (state v10)
observer$ wires call orders-db -- "select 1"
wires: denied by responder: sec@audit.example is in no role allowed to call orders-db (analyst)
```

`--jq`, `--head` and `--max-bytes` are applied inside `wires call`; the host
never sees them, and the remote exit code passes through.

**6. The reader reads the records.** The observer is in `security`, the
service's `readers` role, so it sees every call and refusal, from the hosts'
own logs, with no key to either end:

```console
observer$ wires watch orders-db --once
21:13:08 orders-db ✗ dd7e… orders-db denied: no ID token presented; run `wires login`; …
21:13:09 orders-db ✗ f6d6… orders-db denied: sec@audit.example is in no role allowed to call orders-db (analyst)
21:13:09 orders-db ▶ 8bd5 alice@example.com (dd7e…) [analyst] orders-db "select count(*) from orders"
21:13:09 orders-db ■ 8bd5 exit 0 · 3 ms · 27 B out · blake3 8b4c…
21:13:11 orders-db ▶ 3b25 alice@example.com (dd7e…) [analyst] orders-db
21:13:11 orders-db ■ 3b25 exit 0 · 6 ms · stdin "select customer, sum(total) from orders group by customer order by 2 desc" · 126 B out · blake3 5e99…
21:13:15 orders-db ▶ 442f alice@example.com (dd7e…) [analyst] orders-db ".shell id"
21:13:15 orders-db ■ 442f exit 1 · 4 ms · 0 B out · blake3 af13…
```

The agent's own `wires watch` shows its calls and not the observer's refusal.

**7. Failover and removal.** With the workbench stopped, the same command is
answered by the spare (`wires call --verbose` says which host answered;
callers don't normally care). Then:

```console
admin$ wires remove agent
wires: state version 11: pushed to 2 member(s); 1 not reachable now (f6d6dae7…) — they pull it on their next command
removed dd7e7237… (agent) (state version 11, 4 members)
agent$ wires call orders-db -- "select count(*) from orders"
wires: denied by responder: not a member of the current signed state (version 11)
agent$ echo $?
77
```

The script also covers SQL on stdin, the same service through `wires mcp`,
`.shell id` refused by `sqlite3 -safe`, and a push:

```bash
./.scripts/demo-remote-cli.sh            # builds with cargo; narrated; --quiet for assertions only
./.scripts/demo-push.sh                  # a host calls the agent back (card 24)
```

## Why it's built this way

**The CLI first; MCP for backward compatibility only.** Models already know
CLIs, and a CLI lets the agent pick the fields it wants before anything
reaches context: `gh … --json tagName --jq …`, or `wires call`'s own
`--jq/--head/--max-bytes` for commands without a filter. That filtering, not
tool schemas, is where the measured difference comes from. Claude Code's
default tool search already keeps MCP schemas down to about 400 tokens. On
five read-only GitHub tasks (`bench/REPORT.md`):

| arm | median total input | Σ cost, 25 runs | accuracy | permission refusals |
|---|---|---|---|---|
| GitHub MCP server, Claude Code default (tool search on) | 21,088 | $1.87 | 25/25 | 0 |
| GitHub MCP server, tool search off | 30,630 | $1.40 | 25/25 | 0 |
| `wires call gh`, plus shell pipe helpers | 10,539 | $0.48 | 25/25 | 7 |
| bare `gh`, plus shell pipe helpers | 6,997 | $0.42 | 25/25 | 8 |
| `wires call gh` only, no shell (arm 5) | 10,713 | $0.39 | 25/25 | 0 |

Arm 5 shows the efficiency holds when `wires call` is the only thing the agent
is allowed to run. Caveats: n = 5 per cell, one model (Opus 5.5), one MCP
server (GitHub's, whose payloads are unusually large), and stripped-down
sessions, so the percentages overstate what a full session would see. An MCP
server with field selection would close much of this gap. `wires mcp` serves
the same services, with the same `jq`/`head`/`max_bytes` fields, to clients
that can only speak MCP.

**Services, not hosts.** A caller cares what it is calling, not where it
runs. The admin binds each name to its hosts in the signed state; the caller
tries the one that last answered, then the others, and fails over only when a
dial fails (a host that answered has decided). Moving a service changes
nothing for callers.

**Dial by key, not by host and port.** Tailscale gives the caller's machine a
network path to the host; its ACLs can narrow that to a port, and the service
on that port is then guarded by its own auth. Wires gives the caller a
key-addressed path to the services the state lets it call. On the host there
is no TCP listener and no firewall port opened; iroh binds UDP for QUIC
(direct, or through a relay), and unauthenticated peers are refused at the
handshake. In the two-machine run (card 08), `ss` on the host showed zero TCP
listeners and two UDP sockets.

**One signed state, checked locally.** Who's in, the roles and the registry
are one root-signed, versioned document that every member holds. Hosts decide
every call from their copy, re-read per connection, with no round-trip to an
auth server; callers list what they may call from theirs. A node never
accepts an older version, so a removal sticks.

**The host writes the log.** The record of a call is written by the process
that ran it, signed by its key and hash-linked, so the caller can't forge it
and no gateway owns it. It leaves the host only when a reader asks and the
registry lets it see.

**Identity is the IdP's own signature.** `wires login` puts the caller's key
hash in the OIDC `nonce`, so the ID token names the key it belongs to. The
host verifies it against the IdP's published keys, under the issuers its
`host.json` trusts. There's no wires-run attestor to trust and no auth code in
the CLI being run.

**Hosts can call the agent back.** A webhook needs the receiver to have a
public HTTPS endpoint, and an agent on a laptop or in a sandbox has none. A
caller here is addressed by its key, so a host can push to it with neither
side exposing anything: `wires push --to "$WIRES_CALLER_NODE" --subject
build-41 -- "failed: …"` from a service's background job (every service gets
its verified caller's id in that variable). The host dials the caller by key
(a running `wires inbox --wait` accepts it) and otherwise keeps it (24 h by
default) for the caller's next `wires inbox`. `host.json`'s `push.allow`
decides who may receive (default nobody), checked at send and again at
delivery or fetch, so a removed member gets nothing. Every inbox line starts
with the sender as the caller verified it, because a push is **untrusted
input to a model**:

```
2026-09-23 21:13:20Z  from host 3ef72b11 (verified)  build-41  failed: test_orders_total
```

## Giving an agent only `wires`

A Claude Code rule like `Bash(wires call:*)` is **not airtight** on its own.
Claude Code does check each part of a compound command, but it also
auto-allows read-only commands such as `cat` and `echo` inside the working
directory, and `< file` or a glob can send working-directory files to the
host as input. The agent can also pass `wires call`'s own override flags
(`--tools-file`, `--*-file`, `--relay-url`). Evidence and method:
[docs/agent-sandbox.md](agent-sandbox.md).

To make `wires` the boundary, use a structural setup:

- a container or sandbox whose `PATH` holds only `wires`, in an empty
  working directory with no secrets in the environment, with
  `WIRES_LOCKED=1` set (or `"locked": true` in a `tools.json` the agent
  can't write). Locked, `wires call`, `wires mcp` and `wires inbox` refuse
  every flag that would point them at other credentials, another tools map
  or another relay (`--tools-file`, `--*-seed*`, `--membership*`,
  `--relay-url`); only `--jq`, `--head`, `--max-bytes`, the service name and
  its arguments are accepted. `wires call` also refuses data on stdin, so
  `< file` can't ship a local file to the host; pass input as arguments, or
  set `WIRES_LOCKED_STDIN=allow` if your services need piped input.
- or `wires mcp` as the agent's only tool, with no Bash tool at all.

## Known trade-offs

- **Every member holds the whole state**: member and host node ids, role
  matchers, service names and descriptions. It is signed, not secret.
- **Memberships and the state don't renew yet.** They expire after `--ttl`
  (default 30 days); an expired state admits nobody. Any admin command signs
  a fresh state; re-issue memberships with `wires invite <id>`.
- **The admin is a one-shot command.** A member offline during a push gets
  the state by pulling from a host on its next command (after 10 minutes), or
  from a fresh invite; a host assigned a service while offline needs one of
  those before `serve` will start.
- **A host knows only the identities presented to it.** Push to a role
  reaches members that have called that host, or run `wires inbox`, since it
  started.
- **A host can withhold or truncate its own log.** Tampering and gaps are
  detectable, but only against a copy a reader already holds.

## Not yet

- **Joining by domain** (`wires join acmecorp.com`, a published root key, a
  front desk that admits by IdP rule). This is an open question and not
  designed ([card 18](board/backlog/18-front-door-OPEN.md)). Today the
  invite introduces the root key (trust on first use).
- **The recorded two-machine demo** with real Google sign-in and Claude Code
  as the agent ([card 08](board/doing/08-demo-two-machine.md);
  script in [docs/demo.md](demo.md)).
- Renewal of memberships and the state; `wires mcp` noticing a new state
  without a restart; a witness that holds copies of hosts' logs
  ([card 09](board/backlog/09-witness.md)).

## Reference

### Commands by role

`wires --help` lists these:

| Role | Command | What it does |
|---|---|---|
| **admin** | `wires init [--ttl 30d]` | Create the root key and this node, and sign state version 1 with this node as its one member. |
| | `wires invite <node-id> [--name l] [--ttl 30d]` | Add a node to the state, mint its membership, print its join token (stdout), push the new state. |
| | `wires remove <name\|node-id> [--ttl 30d]` | Drop a node (and from every service's hosts); push hosts first. Its next call is refused. |
| | `wires role set <name> <matcher>…` · `role rm <name>` | Define a role as an OR of matchers: `*@example.com`, `alice@example.com`, or `issuer=…,email=…,org=…,group=…` (all must hold). |
| | `wires service add\|set <name> [--description D] [--allow role]… [--host member]… [--reader role]…` · `service rm <name>` | Edit the registry. `--host` is an `invite --name` label or a node id; `set` replaces each list given. |
| **host** | `wires serve host.json` | Refuse to start unless the state assigns every service in the file here; then check every caller against the state, exec the service per call, and log every call, refusal and push. `--check` validates and prints what the file implements. |
| | `wires push --to <node-id\|role> --subject S [--ttl D] -- <body>` | Hand a message for a caller to this machine's running `serve` (body from stdin if none is given). Prints `delivered`, `queued` or `denied` per recipient; exits `77` if every recipient was refused. |
| **caller** | `wires id` | Print this node's id (creating its key on first use). |
| | `wires join <token>` | Install an invite: the membership and the signed state. |
| | `wires login` | Sign in with your IdP (Google by default; `--issuer`, `--client-id`, `--client-secret` or `WIRES_OIDC_*`) and store the key-bound ID token. |
| | `wires services [--verbose] [--json]` | List the services you may call and the role that admits you, evaluated locally. `--verbose` adds their hosts. |
| | `wires call <service> [--jq F] [--head N] [--max-bytes N] [--verbose] -- <args>` | Run a service by name (or a `tools.json` alias). Stdio passes through and its exit code becomes `call`'s. A refusal exits `77`. |
| | `wires mcp` | Serve the same services as MCP tools over stdio, for clients that can't run a CLI. |
| | `wires gateway --public-url https://… [--listen addr] [--client-id …]` | Serve them as a remote MCP server (Streamable HTTP + OAuth 2.1) for web clients such as Claude.ai. Each user signs in with Google through the gateway and calls with their own token ([deployment](deployment.md#a-web-gateway)). |
| | `wires inbox [--wait [--timeout D]] [--json]` | Fetch from the hosts of your services, print what they pushed (sender first), mark it read. `--wait` blocks until something arrives (and accepts direct pushes meanwhile); `--timeout` exits `124`; a refusal by every host exits `77`. |
| **reader** | `wires watch [service…] [--mine] [--once] [--json]` | Stream call records from your services' hosts, verified: all records of services whose `readers` role you're in, otherwise your own. |

For an MCP-only client, the whole config is:

```json
{ "mcpServers": { "wires": { "command": "wires", "args": ["mcp"] } } }
```

### host.json

| Key | Meaning |
|---|---|
| `version` | Required, `2`. Unknown keys anywhere are an **error**. Version 1 (tools and roles decided by the host) is refused. |
| `identity.issuers` | The IdPs whose ID tokens the host verifies, each with the OAuth client ids (`audiences`) it accepts **from that issuer**. |
| `services` | Name → `command` (argv, no shell; each call's arguments are appended), optional `cwd`, optional `env` (no `WIRES_*` names), and `also_require`: roles from the state the caller must **also** be in (only narrows). Every name must be assigned to this host by the state. |
| `push` | Optional. `allow`: the roles (from the state) whose members may receive `wires push` from this host (none by default). `log_body`: also log each push's body (default `false`: subject only). |
| `audit.otlp` | Optional. An OTLP/HTTP collector the call log is also exported to. |

Who may call a service is not in this file: it is the registry's `allow`. A
refusal names the rule that failed (`… is in no role allowed to call
orders-db (analyst)`, `service orders-db is not assigned to this host …`,
`not a member of the current signed state (version 11)`).

A host that admits a call passes the verified caller to the service as
environment: `WIRES_CALLER_NODE`, `WIRES_CALLER_EMAIL` (when verified),
`WIRES_FABRIC_ROOT`, `WIRES_MEMBERSHIP_NOT_AFTER`, `WIRES_STATE_VERSION`,
`WIRES_SERVICE`, `WIRES_TOOL`, `WIRES_ROLE`, and `WIRES_HOME` (the host's, so
a service can `wires push`). These are set by the host, never taken from the
caller, and any inherited `WIRES_*` is scrubbed first.

### The keystore

Each node's state is a directory: `$WIRES_HOME`, else
`$XDG_CONFIG_HOME/wires`, else `~/.config/wires`. Keep it short on macOS,
since a host's control socket lives under it and socket paths are limited to
104 bytes.

| File | Written by | Holds |
|---|---|---|
| `node.seed` | `id`, `init` | This node's secret key (0600). Its public half is the node id. |
| `root.seed`, `names.json` | `init`, `invite`, `remove` | The admin's root key and member labels (0600). Admin machine only. |
| `membership.json` | `init`, `join` | This node's root-signed membership. |
| `state.json`, `state-admin.txt`, `state-checked.txt` | `join`, pushes, pulls, admin commands | The newest verified signed state, where to pull it from, and when it was last checked. |
| `idp-token.jwt` | `login` | The caller's ID token (0600). |
| `last-good.json` | `call` | Which host last answered each service. |
| `hints` | you | Optional local dial hints (below). |
| `tools.json` | `tools add`, the operator | Locked mode; optional aliases. |
| `inbox/` | `inbox` | Pushed messages: `new/` unread (at most 256, oldest evicted with a note), `read/` the last 1024 (0700). |
| `record-marks.json` | `watch` | The last verified record per host. |
| `call-log.jsonl`, `push-queue.json`, `run/` | `serve` | A host's call log, undelivered pushes, control socket and own hint line. |
| `gateway-client-key`, `gateway-sessions.json` | `gateway` | The key DCR client ids are MAC'd with, and live web sessions keyed by token hash (0600). |

Secrets resolve **flag → environment variable → `--…-file` → keystore**, so
a container can mount its node key from a secret with `--node-seed-file`.

### Revocation

`serve` re-reads its signed state once per connection, so a removal takes
effect on the next call, with no restart. A refused call prints `wires:
denied by responder: <reason>` on stderr, writes nothing to stdout, exits
`77`, and is in the host's log. There is no shared key, so there is nothing
to rotate. The protocol as built: [docs/protocol.md](protocol.md).

### Reachability

By default a node is found by id through iroh's n0 discovery and relays,
which needs outbound internet. For a network without discovery, put hint
lines in `$WIRES_HOME/hints` (`<node id> <ip:port>…`, one per node; a
running `serve` writes its own to `run/hint`). To avoid n0's relays, run
upstream [`iroh-relay`](https://docs.rs/iroh-relay) yourself and pass
`--relay-url <its url>` ([docs/deployment.md](deployment.md)). Addresses
are unsigned hints: iroh still authenticates the peer's key, so a wrong
address can only fail to connect.

### Layout, build and test

Two crates in one Cargo workspace ([CLAUDE.md](../CLAUDE.md)):

- **`library/`**: the transport-free core. `membership/` (identity,
  membership, the invite), `calls/` (session frames, invocations, call
  records and the call log, IdP identity, pushes), `services/` (roles, the
  registry, the signed state, authorization, state sync).
- **`wires/`**: the binary, filed by role: `admin/`, `host/`, `caller/`,
  `state/` (the signed state on this node and how it moves), and `e2e/` for
  the loopback integration tests.

```bash
cargo build --workspace
cargo test --workspace                   # unit, property, e2e and doc tests
./.scripts/demo-remote-cli.sh --quiet    # the demo, as a test
docker build -t wires .                  # distroless image, native arch
```

`make help` lists the same as shortcuts. Deployment notes are in
[docs/deployment.md](deployment.md), tests in
[docs/testing.md](testing.md), and the benchmark in
[bench/REPORT.md](../bench/REPORT.md).

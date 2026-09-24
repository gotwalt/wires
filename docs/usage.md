# Using wires

The [README](../README.md) says what wires is and why. This is the rest: the
roles, where each guarantee lives, a full walkthrough with output, the design
choices, the limits, and the command reference. The wire-level spec is
[protocol.md](protocol.md).

## Roles

| Role | Decides | Commands |
|---|---|---|
| **admin** | who's in (it mints each node's badge, and bans), which IdPs are trusted, which roles exist, which services run where, who may call and read each, which nodes are directories (root key) | `init`, `invite`, `remove`, `issuer set\|rm`, `role set\|rm`, `service add\|set\|rm`, `directory add\|rm`, `policy push`, `policy settings` |
| **directory** | nothing: it holds the newest signed policy, vouches for its freshness, hands it whole to hosts, and hands each caller its view (the services that caller may use, cut for its verified identity); it never decides a call | `serve` (when the policy lists it), `directory serve` |
| **host** | how it implements its assigned services; stricter local rules (narrower IdPs, `also_require`); push | `serve host.json`, `push` |
| **caller** | — runs services by name; MCP (stdio, or the remote gateway) so wires works in the clients people already use | `id`, `join`, `login`, `services`, `call`, `mcp`, `inbox`, `gateway` |
| **reader** | — any signed-in caller; reads the records a service's `readers` role allows, or its own (by verified identity) | `watch` |

Every role joins the same way: `wires id`, then `wires join <token>` with the admin's invite.

## Where each guarantee lives

| Guarantee | Lives in | Checked by |
|---|---|---|
| **Who's in** | Each node's badge: its root-signed membership, minted by `wires invite` (at most 30 days). Removal is a ban in the admin-signed policy until that badge would expire; the policy lists no members. | The host, per connection: the badge, and the bans in its copy of the policy (re-read every dial). |
| **Who may call what** | The policy's registry: each service's `allow` roles, and the role definitions (matchers on the IdP identity, each naming its issuer). Every role needs a verified identity. | The host, on every call. A directory cuts each caller's view from the same table, for listing and dialing only. |
| **Stricter local rules** | `host.json`'s `also_require` roles per service. They can only narrow. | The host, after the registry. |
| **Who is calling** | Your IdP's ID token, bound to the caller's node key at `wires login` (the OIDC `nonce` is a hash of the key), presented in the session `Hello`. | The host, against the issuer's JWKS, under the issuers the policy trusts (`host.json` may narrow them). No wires identity service. |
| **Reach** | The host's node key. Callers dial a key (iroh; n0 discovery, or an optional local `$WIRES_HOME/hints` file); the host binds UDP for QUIC and has no TCP listener. | iroh's handshake authenticates the key (any key may connect); the host then checks the badge and the bans at the first message, and a key without a valid badge, or banned, hears only `not a member of this network`. |
| **Which host** | The registry's `hosts` for the service. Only the admin binds a name to a host, so no host can squat a name. | The caller (it dials only the hosts its view's root-signed entry lists) and the host (it refuses to start, or to serve, a name not assigned to it). |
| **Records** | Each host's own call log: every call, admitted caller's refusal and push (a knock from a node that isn't admitted is traced, not logged), signed by the host and hash-linked. | Readers, with `wires watch`: the service's `readers` roles see all of it; everyone else sees only the records of their own verified identity (issuer and subject, from any of their nodes) and a hash link for every other entry. Every entry and the chain are verified. |
| **Push** | The host dials the caller's key, or queues for the caller's `wires inbox` fetch. A service pushes only through its call's capability, to that call's caller. | The host, at send, delivery and fetch: not banned by the policy, in a `push.allow` role. |
| **Removal** | A new policy, published to the directories; hosts fetch it from one. No shared key exists, so there is nothing to rotate. | Each host that has the new policy, on the removed node's next call or fetch there. |

Nothing is broadcast: a node that takes part in no call receives no traffic about other nodes' calls. The policy lives on directories. **A caller holds only its view**: the root-signed entries of the services its verified person may call or read, which a directory cuts for its ID token. It holds no role, no ban, no other service, and no node id but its services' hosts and the directories. Hosts, directories and the admin hold the whole policy (every role matcher, service, host id, ban and directory; there is no list of members: a node is in by its badge); see [fabric.md](fabric.md).

## Walkthrough

Five `WIRES_HOME` directories stand in for five machines: **admin**,
**workbench** and **spare** (hosts), **agent** (alice@example.com, the
caller) and **observer** (sec@audit.example, a reader). Build with `cargo
build --release -p wires` (or `docker build .`) and put `target/release/wires`
on each machine's `PATH`. The output below is from `./.scripts/demo-remote-cli.sh`,
which runs this sequence on loopback with a stand-in IdP (`wires
dev-mock-idp`, from a build with `--features dev-mock-idp`) and asserts every
step. Node ids are shortened.

**1. admin: start, define roles.** The first policy trusts one IdP: Google
unless `--issuer` names another, with the OAuth client id `wires login` signs in
under (`--client-id`, or `$WIRES_OIDC_CLIENT_ID`) and, for a Google "Desktop
app" client, its public secret (`--public-client-secret`: not confidential;
never pass a confidential one). Every invite carries these, so a joiner's
`wires login` needs no flags. More IdPs with `wires issuer set`.

```console
admin$ wires init --client-id <client id>.apps.googleusercontent.com --public-client-secret <desktop secret>
network 57b09428…
node 23028cae…
policy version 1 (trusts https://accounts.google.com)
next: on each joining machine run `wires id`, then here `wires invite <node-id> --name <label>`; name a directory with `wires directory add <label>`
admin$ wires role set analyst '*@example.com'          # issuer: Google unless --issuer
role analyst set (policy version 2)
admin$ wires role set security sec@audit.example
role security set (policy version 3)
```

**2. Hosts join, become the directories, and the admin registers the
service.** Each machine sends its `wires id`; the admin sends back one token.
A **directory** holds the signed policy for everyone else: the admin publishes
each edit to it, hosts fetch it whole, and each caller asks it for its view.
Any node can be one; in this small network the two hosts are also the
directories.

```console
workbench$ wires id
3ef72b11…
admin$ wires invite 3ef72b11… --name workbench        # likewise the spare
wires: invited 3ef72b11… as "workbench" (badge until 1792702980; policy version 3 unchanged)
wires: on the joining machine: wires join eyJhZG1pbiI6…
admin$ wires directory add workbench                  # likewise the spare
admin$ wires service add orders-db --description "Read-only SQL (sqlite3) over the orders database; …" \
         --allow analyst --reader security --host workbench --host spare
wires: policy version 6: published to 0 of 2 directory(ies); not reached: 3ef72b11…, 511de414… (`wires policy push` re-publishes it)
service orders-db added (policy version 6)
wires: policy version 6 is signed and stored here, but reached none of its 2 directory(ies), so no host or caller can fetch it yet; run `wires policy push` once a directory is up
admin$ echo $?
1
workbench$ wires join eyJhZG1pbiI6…                  # a token from a fresh `wires invite`
```

The directories weren't running, so the publish missed them and the command
exits 1: the new policy is stored on the admin and nowhere else. Once a
directory is up, `wires policy push` re-publishes it. A host that starts on a
policy that doesn't assign it the service fetches a newer one from a directory
before giving up; here none is up yet, so the hosts join with a fresh `wires
invite` token: a node the policy names as a host or a directory gets the
whole current policy in its token (re-joining never rolls a policy back). An
invite edits nothing: it mints the node's badge (its membership, which is what
admits it). The token isn't a secret: the badge is bound to the invitee's key,
and nothing in it names another node.

**3. The hosts serve.** `host.json` says only how each service runs here. A
command is an argv, exec'd directly and never through a shell, with the
caller's arguments appended; sqlite3's `-safe` turns off `.shell`. The
optional `identity` section narrows the IdPs the policy trusts; it can't add
one.

```json
{
  "version": 2,
  "identity": { "issuers": [ { "issuer": "https://accounts.google.com" } ] },
  "services": {
    "orders-db": { "command": ["sqlite3", "-safe", "-readonly", "-header", "-column", "orders.db"] }
  },
  "push": { "allow": ["analyst"] }
}
```

```console
workbench$ wires serve --check host.json
host.json ok (version 2)
trusted issuers: the signed policy's, narrowed to
  https://accounts.google.com  audiences: the policy's
services (who may call each is in the admin-signed policy):
  orders-db
    command: sqlite3 -safe -readonly -header -column orders.db
push: to roles analyst
workbench$ wires serve host.json
```

`serve` refuses to start unless its policy assigns every service in the file
to it. Because the policy lists each host as a directory, `serve` runs the
directory on the same endpoint too. A node that hosts nothing runs one with
`wires directory serve`.

**4. The agent and the observer join.** An invite mints a badge and edits
nothing, so the hosts need no new policy: they admit any badge the root
signed. A caller's token is its badge, the ids of up to two directories and
the IdP to sign in with: under 1 KB, at any network size. It holds no policy.

```console
admin$ wires invite dd7e7237… --name agent
wires: invited dd7e7237… as "agent" (badge until 1792703101; policy version 6 unchanged)
agent$ wires join eyJhZG1pbiI6…
joined network 57b09428… as dd7e7237… (policy version 6)
next: `wires login` to sign in, then `wires services`
```

**5. agent: before sign-in, nothing; after, one service.** The agent holds a
**view**: the services its verified identity may use, each an entry the root
signed, cut by a directory for its ID token. Before it signs in, the view is
empty: no role admits a node with no identity, so it knows no host to dial.

```console
agent$ wires services
wires is a network for authenticated remote CLI calls. Each service is a
… (the premise, on stderr; stdout is empty)

wires services: nothing to list: this node is not signed in; run `wires login`
agent$ wires call orders-db -- "select count(*) from orders"
wires: no service named `orders-db` that you may call: this node is not signed in, and every service needs a verified identity; run `wires login`
agent$ echo $?
1
agent$ wires login
wires login: node dd7e7237… is alice@example.com (token stored in …/idp-token.jwt, valid until unix …)
wires login: 1 service(s) you may call (policy version 6); see `wires services`
agent$ wires services
orders-db  Read-only SQL (sqlite3) over the orders database; pass the SQL statement as the argument.  (analyst)
agent$ wires services orders          # search names and descriptions
orders-db  Read-only SQL (sqlite3) over the orders database; pass the SQL statement as the argument.  (analyst)
agent$ wires call orders-db -- "select count(*) from orders"
count(*)
--------
       7
```

`wires login` needed no flags: the invite named the IdP and its client. A
signed-in node in no allowed role sees nothing it may call. The observer may
read orders-db's records, so the service is in its view (marked `read`), and
naming it in a call reaches the host, which refuses it with the reason:

```console
observer$ wires services
wires is a network for authenticated remote CLI calls. …

wires services: no service allows you (policy version 6); ask your admin for a role that may call one
observer$ wires call orders-db -- "select 1"
wires: denied by host: sec@audit.example is in no role allowed to call orders-db (analyst); don't retry: ask your admin for access
```

`--jq`, `--head` and `--max-bytes` are applied inside `wires call`; the host
never sees them, and the remote exit code passes through.

**6. The reader reads the records.** The observer is in `security`, the
service's `readers` role, so it sees every call and refusal, from the hosts'
own logs, with no key to either end:

```console
observer$ wires watch orders-db --once
21:13:09 orders-db ✗ f6d6… orders-db denied: sec@audit.example is in no role allowed to call orders-db (analyst)
21:13:09 orders-db ▶ 8bd5 alice@example.com (dd7e…) [analyst] orders-db "select count(*) from orders"
21:13:09 orders-db ■ 8bd5 exit 0 · 3 ms · 27 B out · blake3 8b4c…
21:13:11 orders-db ▶ 3b25 alice@example.com (dd7e…) [analyst] orders-db
21:13:11 orders-db ■ 3b25 exit 0 · 6 ms · stdin "select customer, sum(total) from orders group by customer order by 2 desc" · 126 B out · blake3 5e99…
21:13:15 orders-db ▶ 442f alice@example.com (dd7e…) [analyst] orders-db ".shell id"
21:13:15 orders-db ■ 442f exit 1 · 4 ms · 0 B out · blake3 af13…
```

The agent's own `wires watch` shows its calls and not the observer's refusal.
"Its own" means its person's: the records whose verified identity (issuer and
subject) is the one the agent's ID token proves, from any node. That is the
isolation boundary: agents acting for different people can't see each
other's work, and two agents of one person can. For every other record the
agent gets only a hash link, so it can check the chain but learns only how
many entries there are and when they were written. Without a verified ID
token, a reader sees nothing in full. A push from the host operator belongs
to no service, so only its recipient sees its record.

**7. Failover and removal.** With the workbench stopped, the same command is
answered by the spare (`wires call --verbose` says which host answered;
callers don't normally care). Then:

```console
admin$ wires remove agent
wires: policy version 7: published to 2 of 2 directory(ies)
removed dd7e7237… (agent) (banned until 1792703101; policy version 7, 1 ban(s))
agent$ wires call orders-db -- "select count(*) from orders"
wires: denied by host: not a member of this network; don't retry: ask your admin for access
agent$ echo $?
77
```

Each host applies the removal from the moment it holds the new policy: at
once here, since both hosts are directories; a host that isn't one follows a
directory's subscription and has it within a second. The refusal is traced by the host, not written to its call
log: a banned key can't write to the log.

The script also covers SQL on stdin, the same service through `wires mcp`,
`.shell id` refused by `sqlite3 -safe`, and a push:

```bash
./.scripts/demo-remote-cli.sh            # builds with cargo; narrated; --quiet for assertions only
./.scripts/demo-push.sh                  # a host calls the agent back (card 24)
```

## Host: native services

A host can also be an app: it embeds the `wires` library, implements services
in its own process, and serves them. To a caller, a native service is a CLI
like any other (`wires call`, `wires mcp`, the gateway and `wires watch`
work unchanged): the same gate, the same call log, the same push. What the
handler gets beyond a CLI is a warm process (state kept across calls) and
the verified caller as a value (`call.principal()`, `call.role()`,
`call.id()`) rather than `WIRES_*` variables. Details and limits are in
[protocol.md §5](protocol.md).

**Keystore.** An embedded host is a node like any other, with a keystore
directory of its own that the app names (it reads nothing from
`$WIRES_HOME`):

```console
host$ WIRES_HOME=/var/lib/kv/wires wires id                     # its node id
admin$ wires invite <node id> --name kvhost
host$ WIRES_HOME=/var/lib/kv/wires wires join <token>
admin$ wires service add kv --allow analyst --host kvhost
```

The host refuses to start unless the signed policy assigns each of its
services to it. The node key is loaded into the app's memory: a native
service is the operator's own code, trusted as much as `wires serve`.

**Rust** (`wires/examples/kv/`, a key-value store with one namespace per
verified person):

```rust
struct Hello;

impl wires::Service for Hello {
    async fn call(&self, call: wires::Call, mut io: wires::CallIo) -> i32 {
        let line = format!("hello, {}\n", call.principal().name());
        io.stdout.write_all(line.as_bytes()).await.map_or(1, |()| 0)
    }
}

wires::Host::builder("/var/lib/kv/wires")
    .trust_issuer("https://accounts.google.com", ["….apps.googleusercontent.com"])
    .service("hello", Hello)
    .build()?
    .serve_until(shutdown) // or .serve(): until Ctrl-C
    .await
```

`.host_json(path)` also serves `host.json`'s CLI services from the same
host, and `.push_allow([roles])` enables `call.push_to_caller(subject,
body)`. When the caller disconnects, the handler's task is aborted.

**Python** (`bindings/python/examples/kv.py`; `make python` builds the
module into `target/python`). A handler is synchronous and runs on a
thread of its own:

```python
import wires

class Hello(wires.Service):
    def call(self, call):
        call.write_stdout(f"hello, {call.principal().email}\n".encode())
        return 0

host = (wires.HostBuilder("/var/lib/kv/wires")
        .trust_issuer("https://accounts.google.com", ["….apps.googleusercontent.com"])
        .service("hello", Hello())
        .build())
host.serve()   # until host.stop(); serve(handle_ctrl_c=True) also stops on Ctrl-C
```

**TypeScript** (`bindings/node/examples/kv.mts`; `make node` builds the npm
package `wires` into `target/node/wires`; Node >= 22.18). A handler is a
function on Node's event loop, and the stdio methods return Promises:

```ts
import { HostBuilder } from "wires";

const host = new HostBuilder("/var/lib/kv/wires")
  .trustIssuer("https://accounts.google.com", ["….apps.googleusercontent.com"])
  .service("hello", async (call) => {
    await call.writeStdout(Buffer.from(`hello, ${call.principal().email}\n`));
    return 0;
  })
  .build();
process.on("SIGTERM", () => host.stop());
await host.serve();   // until stop(); serve(true) also stops on Ctrl-C
```

In Python and TypeScript, an exception ends the call with exit 1 and its
message on the caller's stderr, like an uncaught exception in a CLI. A
handler there can't be aborted: when the caller disconnects, its next read
or write fails instead. The bindings' `serve` doesn't take Ctrl-C unless
asked, since that would claim the signal for the whole process; the
examples stop the host on SIGTERM or Ctrl-C themselves.

**The demo.** `make demo-python` and `make demo-node`
(`.scripts/demo-native-service.sh --lang python|node`) serve the kv example
on a loopback network and call it with the shipped `wires`: state kept
across calls, the handler's exit code, stderr and exceptions, a refused
caller, a push to `wires inbox`, the host's log through `wires watch`, and a
clean `stop()`.

## Why it's built this way

**The CLI where it's most efficient; MCP wherever people already work.** Models already know
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
server with field selection would close much of this gap.

MCP compatibility is a goal of its own: people should be able to use wires
in the clients where they already use remote tool calling. `wires mcp`
serves the same services, with the same `jq`/`head`/`max_bytes` fields, over
stdio (Claude Desktop, IDEs), and `wires gateway` serves them as a remote
MCP server (Claude.ai's connectors). The gateway presents each web user's
own ID token, so the host still verifies the IdP and applies the registry
(only roles that match the user's identity admit them), and its record names
the verified person as well as the gateway node that dialed. What it adds is
one listener and a party holding live sessions
([deployment.md § A web gateway](deployment.md#a-web-gateway)).

**Services, not hosts.** A caller cares what it is calling, not where it
runs. The admin binds each name to its hosts in the signed policy; the caller
tries the one that last answered, then the others, and fails over only when a
dial fails (a host that answered has decided). Moving a service changes
nothing for callers.

**Dial by key, not by host and port.** Tailscale gives the caller's machine a
network path to the host; its ACLs can narrow that to a port, and the service
on that port is then guarded by its own auth. Wires gives the caller a
key-addressed path to the services the policy lets it call. On the host there
is no TCP listener and no firewall port opened; iroh binds UDP for QUIC
(direct, or through a relay). Any key can open a connection, but one the
holds no valid badge, or is banned, is refused at its first message, before anything runs,
and costs the host little (small frames, no token check, nothing logged).
In the two-machine run (card 08), `ss` on the host showed zero TCP
listeners and two UDP sockets.

**One signed policy, checked locally.** The trusted IdPs, the roles, the
registry and the bans are one root-signed, versioned policy; each node's
root-signed badge says it is in. Directories hold it and vouch for its
freshness; hosts keep the whole policy, and each caller keeps its view: the
root-signed entries of the services it may use. Hosts decide every call from
their copy, re-read per connection, with no round-trip to an auth server or a
directory; callers list and dial from their view. A node never accepts
an older version, so a ban sticks.

**The host writes the log.** The record of a call is written by the process
that ran it, signed by its key and hash-linked, so the caller can't forge it
and no gateway owns it. It leaves the host only when a reader asks and the
registry lets it see.

**Identity is the IdP's own signature.** `wires login` puts the caller's key
hash in the OIDC `nonce`, so the ID token names the key it belongs to. The
host verifies it against the IdP's published keys, under the issuers the
signed policy trusts (its `host.json` may narrow them). There's no wires-run attestor to trust and no auth code in
the CLI being run.

**Hosts can call the agent back.** A webhook needs the receiver to have a
public HTTPS endpoint, and an agent on a laptop or in a sandbox has none. A
caller here is addressed by its key, so a host can push to it with neither
side exposing anything: `wires push --to "$WIRES_CALLER_NODE" --subject
build-41 -- "failed: …"` from a service's background job. Every service
gets its verified caller's id in that variable and, when `host.json` has a
`push` section, a per-call push capability (`WIRES_PUSH_SOCKET`,
`WIRES_PUSH_TOKEN`) that can push only to that caller, for the call and 10
minutes after it; the child never holds the host's keys. The host operator
can also push, by node id or role, from the host's own shell. The host dials the caller by key
(a running `wires inbox --wait` accepts it) and otherwise keeps it (24 h by
default) for the caller's next `wires inbox`. `host.json`'s `push.allow`
decides who may receive (default nobody), checked at send and again at
delivery or fetch, so a removed node gets nothing. Every inbox line starts
with the sender as the caller verified it, because a push is **untrusted
input to a model**:

```
2026-09-23 21:13:20Z  from host 3ef72b11 (verified)  build-41  failed: test_orders_total
```

That is push as built. Callbacks only to the node **and** person that made
the call, with no role addressing and an `inbox` MCP tool in `wires mcp` and
the gateway, are designed, parked ([card 31](board/backlog/31-inbox-delivery.md)).

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

- **Known and accepted until cards [09](board/backlog/09-witness.md) and [29](board/backlog/29-person-identity.md)**, and by design ([fabric.md](fabric.md)):
  - **Hosts and directories hold the whole policy**: host and banned node
    ids, role matchers (often people's emails), service names and
    descriptions, trusted IdPs, directories. It is signed, not secret, and
    lists no members. A caller holds only its view.
  - **A directory sees who asks for what.** It verifies each caller's ID
    token to cut its view, so it learns which person asks for which view
    (traced, not logged). It can withhold an entry or serve a stale view
    (a signed freshness timestamp bounds how stale), which makes a caller
    miss a service, never reach one it may not use: the host decides every
    call from its whole policy.
  - **A removed host still sees argv** while its badge is valid, from a
    caller whose view predates the removal: the caller sends the arguments
    with its `Hello` and stops before stdin only once the host's handshake
    shows a newer head whose entry no longer lists it.
  - **A revoked grant takes your old records with it.** `wires watch` reads
    the services in your view, so once a service leaves it, your own
    records there are no longer yours to read (its readers still see them).
  - **Hidden record links reveal count and timing** to a caller who isn't a
    service's reader (not content, caller or service).
  - **Google ID tokens last about an hour**, and Google drops the `nonce`
    (the key binding) on refresh, so people sign in again about hourly.
- **The root key is a file** (`root.seed` in the admin's keystore): no backup
  root, no rotation. Losing or leaking it means starting a new network and
  re-inviting everyone; it needs more attention before wires holds anything
  valuable ([fabric.md §4.4](fabric.md#44-the-root-key)).
- **Badges and the policy don't renew yet.** A badge expires after
  its `--ttl` (default 30 days), the policy after its `--policy-ttl` (default
  90 days); an expired policy admits nobody, and no caller dials from one.
  Any admin edit signs a fresh policy (never with an earlier expiry than the
  one it replaces); re-issue badges with `wires invite <id>`.
- **The admin is a one-shot command.** It publishes each edit to the
  directories only. An edit that reaches none exits 1; `wires policy push`
  re-publishes it. Hosts follow a directory's subscription and have each
  edit within a second; so do `wires mcp` and gateway sessions, for their
  views. A one-shot `wires call` learns of an edit in its next call's
  handshake and refreshes its view then; `wires services` refreshes a view
  older than a day. With no directory up, callers use the view they hold,
  and a host needs a fresh invite.
- **With every directory down, hosts keep deciding** from their copy under
  the default `lenient` freshness, and say so in their trace (not yet in
  `wires watch`); edits and bans don't spread until a directory is back.
  Under `wires policy settings --freshness strict` they refuse every call
  once the last directory's timestamp lapses (15 minutes by default), so a
  ban is honoured everywhere within that time or nothing is served.
- **A host knows only the identities presented to it.** Push to a role
  reaches callers that have called that host, or run `wires inbox`, since it
  started (card 31 removes role push).
- **A host can withhold or truncate its own log.** Tampering and gaps are
  detectable, but only against a copy a reader already holds.
- **A web gateway holds its users' live identities.** Each web user's token
  is bound to the gateway's key, so it's useless elsewhere, but the gateway
  can use it for anything that user may call until it expires (about an
  hour). There is no refresh (Google omits the `nonce` on refresh), so web
  sessions end with the token. It is the one piece that listens (HTTPS,
  behind a tunnel or proxy), and it offers tools only: push is addressed by
  node key, and `watch` isn't an MCP tool.
- **Only Google has been tested** as the IdP, though any OIDC issuer is
  configured the same way.
- **A relay may carry the traffic.** Reaching a host behind NAT can go
  through a public relay (n0's by default, or your own); the relay sees
  only end-to-end encrypted QUIC.
- **One network per keystore.** A node in two networks needs two
  `WIRES_HOME` directories.

## Not yet

- **Joining by domain** (`wires join acmecorp.com`, a published root key, a
  front desk that admits by IdP rule). This is an open question and not
  designed ([card 18](board/backlog/18-front-door-OPEN.md)). Today the
  invite introduces the root key (trust on first use).
- **The recorded two-machine demo** with real Google sign-in and Claude Code
  as the agent ([card 08](board/doing/08-demo-two-machine.md);
  script in [docs/demo.md](demo.md)).
- `login --for` and day-passes for headless agents
  ([card 29](board/backlog/29-person-identity.md)); transparency-log
  checkpoints witnessed by the directory ([card 09](board/backlog/09-witness.md));
  renewal of badges (open on card 36).
- **Callbacks to the caller that asked**: a callback goes only to the node
  and person that made the call, in every client. Designed, parked
  ([card 31](board/backlog/31-inbox-delivery.md)).

## Reference

### Commands by role

`wires --help` opens with the premise, the same paragraph `wires mcp` and
the gateway send as their MCP `instructions` and an empty `wires services`
prints:

> wires is a network for authenticated remote CLI calls. Each service is a
> command-line program on another machine, run by its name, never by host or
> address. Every call runs as you: your sign-in is checked against an
> admin-signed list of who may call what, and the machine that runs it
> records the call. A refusal ("denied by host", exit 77) is that policy, not
> a fault: don't retry or work around it; ask your admin for access.

Then it lists only the caller's commands (`services`, `call`, `login`,
`join`, `id`, `watch`, `inbox`, `mcp`). `wires --help-all` lists every
command below, by role. Each command's `--help` gives its examples, and its
exit codes or output shape where they matter; `wires <command> --help-all`
adds the flags `--help` hides: the credential overrides (`--node-seed[-file]`,
`--membership[-file]`, `--tools-file`, `login`'s `--issuer`, `--client-id` and
`--client-secret`), `--relay-url`, every `--policy-ttl`, and the gateway's
`--allow-origin` and `--trust-proxy-header`. The help text, the MCP text and
the key errors are snapshot-tested (`wires/snapshots/`).

| Role | Command | What it does |
|---|---|---|
| **admin** | `wires init [--issuer URL] [--client-id ID] [--audience A]… [--public-client-secret S] [--ttl 30d] [--policy-ttl 90d]` | Create the root key and this node, mint this node's badge, and sign policy version 1, trusting one IdP: `--issuer` (default `https://accounts.google.com`), whose OAuth client id `--client-id` (else `$WIRES_OIDC_CLIENT_ID`; required) `wires login` signs in under, and whose `--audience` values hosts accept (default: the client id). Invites tell `wires login` to use this IdP; `--public-client-secret` is its client's public (Desktop-app) secret, which invites carry and the signed policy doesn't. `--ttl` is this node's badge lifetime (at most 30 days), `--policy-ttl` the policy's. |
| | `wires invite <node-id> [--name l] [--ttl 30d] [--policy-ttl 90d]` | Mint the node's badge (valid for `--ttl`, at most 30 days), record it in the admin's ledger (`issued.json`), print its join token (stdout): the badge, up to two directory ids and the login settings (under 1 KB; a host or directory also gets the signed policy). Not a policy edit: nothing is published. Re-inviting a banned node lifts its ban (an edit, published; `--policy-ttl` applies). |
| | `wires remove <name\|node-id> [--policy-ttl 90d]` | Ban a node until its badge would expire (30 days for a node the ledger doesn't know), and drop it from every service's hosts and from the directories; publish. Its next call to a host that has the new policy is refused. |
| | `wires issuer set <iss> --client-id ID [--audience A]… [--public-client-secret S] [--login]` · `issuer rm <iss>` | Trust an IdP (or change its client id and accepted audiences; default audience: the client id), or stop trusting one no role names. `--login` makes it the IdP invites name; `--public-client-secret` as for `init`. Every role's matchers must name a trusted issuer. |
| | `wires directory add\|rm <name\|node-id>` | List a node (invited, not banned) as one of the network's directories, or stop listing it. |
| | `wires role set <name> [--issuer URL] [--policy-ttl] <matcher>…` · `role rm <name>` | Define a role as an OR of matchers: `*@example.com`, `alice@example.com`, or `issuer=…,email=…,org=…,group=…` (all must hold). Every matcher names its issuer, compared exactly: one without `issuer=` takes `--issuer` (default `https://accounts.google.com`). `issuer=…` alone admits anyone that IdP verified. `org` is Google's `hd`, read only from Google. The issuer must be one the policy trusts (`wires issuer set`). There is no built-in role: a node with no verified identity is in no role. |
| | `wires service add\|set <name> [--description D] [--allow role]… [--host node]… [--reader role]…` · `service rm <name>` | Edit the registry. `--host` is an `invite --name` label or a node id, of a node this admin invited and didn't ban; `set` replaces each list given. |
| | `wires policy push` | Re-publish the stored policy to every directory, e.g. after an edit that reached none. Exits 1 if the policy names directories and none took it. |
| | `wires policy settings [--freshness lenient\|strict] [--beat-secs N] [--fresh-secs N] [--policy-ttl 90d]` | Print the network's settings, or change them and publish. `--freshness`: what a host does when no directory has vouched for its policy recently (`lenient`, the default, keeps deciding and traces it; `strict` refuses every call until a directory is back). `--beat-secs` (default 300): how often a directory signs a freshness timestamp; `--fresh-secs` (default 900, at least the beat): how long one lasts. |
| **directory** | `wires directory serve [--max-subscribers 4096]` | Run this node's directory alone (no `host.json`), until Ctrl-C. Refuses the admin's keystore and a node the policy it holds doesn't list. |
| **host** | `wires serve host.json` | Refuse to start unless the policy assigns every service in the file here (fetching a newer one from a directory first if needed); then check every caller against the policy, exec the service per call, and log every call, admitted caller's refusal and push. It follows a directory's subscription for every edit (and, under `strict` freshness, refuses calls while no directory vouches for its policy), and runs the directory too when the policy lists this node. `--check` validates and prints what the file implements. |
| | `wires push --to <node-id\|role> --subject S [--ttl D] -- <body>` | Hand a message for a caller to this machine's running `serve` (body from stdin if none is given). From the operator's shell: to any node or role. From a service (it has `WIRES_PUSH_TOKEN`): only to that call's caller. Prints `delivered`, `queued` or `denied` per recipient; exits `77` if every recipient was refused. |
| **caller** | `wires id` | Print this node's id (creating its key on first use). |
| | `wires join <token>` | Install an invite: the badge (membership), the directory ids and the login settings (and, for a host or directory, the signed policy); a caller then asks a directory for the head. |
| | `wires login [--no-browser] [--callback-port N] [--refresh\|--reuse]` | Sign in with the IdP your invite named (the hidden flags `--issuer`, `--client-id`, `--client-secret` or `WIRES_OIDC_*` override it), store the key-bound ID token, and fetch your view: the services you may use. |
| | `wires services [query] [--verbose] [--json]` | List the services in your view you may call, one per line: `<name>  <description>  (<roles that may call>)`; a `query` keeps those whose name or description contains it. Nothing on stdout when there are none: stderr says why and what to do (with the premise, when the view is empty). `--json` prints one object per line, in a stable shape: `{"service","description","allow":[…],"call","read","hosts":<count>}`, plus `host_ids` with `--verbose`. Refreshes the view first when it is over a day old or a call saw a newer policy. `--verbose` adds the hosts. |
| | `wires call <service> [--jq F] [--head N] [--max-bytes N] [--verbose] -- <args>` | Run a service by name, from your view (a name it lacks is asked of a directory; or a `tools.json` alias, which a service in your view of the same name beats). Stdio passes through and its exit code becomes `call`'s, except that a remote exit `77` is reported as `1` (with a note on stderr). A refusal by the host exits `77`, with nothing on stdout; a service you may not use, a local or transport failure, an expired view, or a newer policy head (in the host's handshake) whose entry no longer lists that host exits `1`, before any stdin is sent; a usage error (a `--jq` filter that doesn't compile, a flag locked mode refuses) exits `2`. `--verbose` names the host that answered and prints every cause of an error. On an unchanged network the call is its only connection. |
| | `wires mcp` | Serve the same services as MCP tools over stdio (Claude Desktop, IDEs), following your view: a grant or revocation reaches the client as `tools/list_changed` within seconds. Each tool is a service, named as `wires services` lists it, and described by the first sentence of its registry description; the `instructions` are the premise plus how to pass arguments and filter output. Past 40 services it offers `search_services` and `call_service` instead of one tool each, whose descriptions state the refusal rule. A refusal is a tool error reading `denied by host: <reason>` and its next step. |
| | `wires gateway --public-url https://… [--listen addr] [--client-id …] [--client-secret-file F] [--issuer URL]` | Serve them as a remote MCP server (Streamable HTTP + OAuth 2.1) for web clients such as Claude.ai. Each user signs in with Google through the gateway and calls with their own token, from their own view (one subscription per live session) ([deployment](deployment.md#a-web-gateway)). |
| | `wires inbox [--wait [--timeout D]] [--json]` | Fetch from the hosts of your services, print what they pushed (sender first), mark it read. `--wait` blocks until something arrives (and accepts direct pushes meanwhile); `--timeout` exits `124`; a refusal by every host exits `77`. |
| **reader** | `wires watch [service…] [--mine] [--once] [--json]` | Stream call records from your services' hosts, verified: all records of services whose `readers` role you're in, otherwise your own (your verified identity's, from any node). A following stream is re-decided when the signed policy changes or your ID token expires, and ends with the refusal when access is gone (exit `77` when every host refused). A log rolled back below what you verified, or rewritten, is an alarm (exit 1); entries pruned past it (retention, 30 days) are a notice. Marks are kept per host, so any view catches a rewrite another view verified. The service each line names is derived from the signed records, not supplied by the host. |

Every command's error ends with the next step in one clause (`run \`wires
login\``, `see \`wires services\``, `ask your admin …`), and without
`--verbose` prints no stack of causes. A refusal prints the host's reason as
the host gave it, then a next step when the reason carries none (`… ; don't
retry: ask your admin for access`).

Every edit above signs a new policy valid for `--policy-ttl` from now (default
90 days), or until the current policy's expiry if that is later: an edit never
shortens the policy's life. It is published to the directories the policy
lists (and to any the policy before the edit listed); the admin dials no
host. When the policy names directories and **none** took it, the command
still prints its result (an `invite` still prints the token) but exits 1: the
new policy is stored on the admin and nowhere else until `wires policy push`
reaches a directory. With no directory listed yet, nothing fails.

For a stdio MCP client, the whole config is:

```json
{ "mcpServers": { "wires": { "command": "wires", "args": ["mcp"] } } }
```

### host.json

| Key | Meaning |
|---|---|
| `version` | Required, `2`; any other version is refused. Unknown keys anywhere are an **error**. |
| `identity.issuers` | Optional. Narrows the IdPs the signed policy trusts (`wires issuer set`) to those listed; an entry's optional `audiences` keeps only those of the policy's accepted audiences **from that issuer**. It can't add an issuer or an audience. Absent: the policy's, as signed. |
| `services` | Name → `command` (argv, no shell; each call's arguments are appended), optional `cwd`, optional `env` (no `WIRES_*` names), `also_require`: roles from the policy the caller must **also** be in (only narrows), and `end_of_options` (default `false`): put `--` between the command and the caller's arguments, so they can't be read as options by a CLI that honours `--` (it does nothing for one that doesn't). Every name must be assigned to this host by the policy. |
| `push` | Optional. `allow`: the roles (from the policy) whose members may receive `wires push` from this host (none by default). `log_body`: also log each push's body (default `false`: subject only). |
| `audit.otlp` | Optional. An OTLP/HTTP collector the call log is also exported to: `https://…`, or plain `http://` only to `localhost` / `127.0.0.1` / `[::1]`. |

Who may call a service is not in this file: it is the registry's `allow`. An
admitted caller's refusal names the rule that failed (`… is in no role allowed to call
orders-db (analyst)`, `service orders-db is not assigned to this host …`); a
key without a valid badge, or a banned one, hears only `not a member of this network`.

A service's environment starts empty: only `PATH`, `LANG` and `LC_*` are
inherited from `serve`, then the service's `env`, then what the host sets
from the verified call: `WIRES_CALLER_NODE`, `WIRES_CALLER_EMAIL` (when
verified), `WIRES_FABRIC_ROOT`, `WIRES_MEMBERSHIP_NOT_AFTER`,
`WIRES_STATE_VERSION`, `WIRES_SERVICE`, `WIRES_ROLE`, and, with
a `push` section, the call's push capability (`WIRES_PUSH_SOCKET`,
`WIRES_PUSH_TOKEN`). None of it is taken from the caller. The child gets no
`WIRES_HOME`, `HOME`, agent sockets or cloud credentials.

The child still runs as `serve`'s Unix user, so it can reach what that
user can, the host's keystore included: [run services as a separate Unix
user](deployment.md#run-services-as-a-separate-unix-user). A service's fixed
command must also be safe against any trailing arguments, including ones
spelled like options (`gh api -X DELETE …`). `"end_of_options": true` in
`host.json` puts `--` before them, which settles it for CLIs that honour
`--` and for no others.

### The keystore

Each node's keystore is a directory: `$WIRES_HOME`, else
`$XDG_CONFIG_HOME/wires`, else `~/.config/wires`. Keep it short on macOS,
since a host's control socket lives under it and socket paths are limited to
104 bytes. Every file in it, with its mode and holder, is listed in
[protocol.md § 9](protocol.md#9-keystore-wires_home-else-xdg_config_homewires-else-configwires).
After a `wires watch` alarm you have resolved, delete `record-marks.json` to
start over.

Secrets resolve **flag → environment variable → `--…-file` → keystore**, so
a container can mount its node key from a secret with `--node-seed-file`.

### Removal

`serve` re-reads its signed policy once per connection, so a removal takes
effect at each host on the next call after that host has the new policy, with
no restart. A refused call prints `wires: denied by host: <reason>` (and the
next step) on stderr, writes nothing to stdout and exits `77`. An admitted caller's refusal is in the
host's log; a removed node hears only `not a member of this network`, and
the host traces that instead of logging it. There is no shared key, so there
is nothing to rotate. The protocol as built: [docs/protocol.md](protocol.md).

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

One Cargo workspace ([CLAUDE.md](../CLAUDE.md)):

- **`library/`**: the transport-free core. `membership/` (identity,
  membership, the invite), `calls/` (session frames, invocations, call
  records and the call log, IdP identity, pushes), `services/` (roles, the
  registry, the signed policy: head, items, freshness; authorization), and
  `directory/` (the directory's frames).
- **`wires/`**: the binary (and the embedding API), filed by role:
  `admin/`, `host/`, `caller/`, `gateway/` (the remote MCP server),
  `directory/` (the directory: its store, its two ALPNs, `directory serve`),
  `policy/` (the signed policy on this node, published to and fetched from
  the directories), and `e2e/` for the
  loopback integration tests.
- **`bindings/`**: `wires-ffi` (Python, via UniFFI) and `bindings/node/`
  `wires-node` (TypeScript, via napi-rs), the embedding API in other
  languages; see [Host: native services](#host-native-services).

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

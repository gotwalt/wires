# Using wires

The [README](../README.md) says what wires is and why. This document is for
someone with a task: who runs which commands, a walkthrough from a real run,
how a host runs its services, how to give an agent only `wires`, the limits,
and the command reference. The wire-level spec is
[protocol.md](protocol.md); the architecture (who keeps what, how the
policy moves) is [fabric.md](fabric.md).

## Roles

| Role | Decides | Commands |
|---|---|---|
| **admin** | the trusted IdPs, the roles, which services run where, who may call each, who is removed, which nodes are directories (root key; one signed policy) | `init`, `network`, `issuer set\|rm`, `role set\|rm`, `service add\|set\|rm`, `directory add\|rm`, `remove`, `restore`, `policy push`, `policy settings` |
| **host** | how it implements its assigned services; stricter local rules (`host.json`) | `join`, `serve host.json`, `push` |
| **caller** | nothing: runs services by name; MCP (stdio, or the remote gateway) as the bridge from existing MCP clients | `id`, `login`, `services`, `call`, `inbox`, `mcp`, `gateway` |
| **directory** | nothing: it holds the newest root-signed policy and hands it whole to hosts, and to each caller its view (the services that caller may use, cut for its verified ID token); it never decides a call | `join`, `serve` (when the policy lists it), `directory serve` |

A caller joins by signing in: `wires login <network>`, where the network
string (`wires network` prints it) names the root key, the first
directories and the IdP to sign in with. It is the same for everyone and not
secret. A host or directory runs `wires join <network>`, and the admin names
it in the policy by its node id. Every role needs a verified identity, and
every role matcher names its issuer.

## Where each check happens

| What | Lives in | Checked by |
|---|---|---|
| **Who is calling** | The caller's ID token from your IdP, bound to the caller's node key at `wires login` (the OIDC `nonce` is a hash of the key), presented in every call's `Hello`. It is the only credential a caller has. | The host, against the issuer's published keys, under the issuers the policy trusts (`host.json` may narrow them). A token that is missing, forged, bound to another key, from an untrusted issuer or without a verified email, a banned person or node, and a person no role matches all hear only `not admitted to this network: sign in with \`wires login\`, or ask your admin for a role` (an expired token hears that the sign-in has expired); the caller's own `wires` turns that into what its person can act on. |
| **Who may call what** | The policy: each service's `allow` roles, and the roles (matchers on the verified identity, each naming its issuer). | The host, on every call. A directory cuts each caller's view from the same policy, for listing and dialing only. |
| **Stricter local rules** | `host.json`'s `also_require` roles per service. They can only narrow. | The host, after the policy. |
| **Which host** | The policy's `hosts` for the service. Only the admin binds a name to a host. | The caller (it dials only the hosts the service's root-signed entry lists) and the host (it refuses to start, or to serve, a name not assigned to it). |
| **Reach** | The host's node key. Callers dial a key (iroh: n0 discovery, or a local `hints` file); the host binds UDP for QUIC and has no TCP listener. | iroh authenticates the key. Any key may connect; it is refused at its first message unless its token verifies. |
| **Push** | The host dials the caller's key, or queues for the caller's `wires inbox` fetch. A service pushes only through its call's capability, to that call's caller. | The host, at send, delivery and fetch: admitted (not removed, a role matches), and in a `push.allow` role. |
| **Removal** | A person ban or a node ban in a new policy, published to the directories; each host follows a directory, which sends it each new policy whole. | Each host that has the new policy, on the removed person's or node's next call or fetch there. |

Nothing is broadcast. **A caller holds only its view**: the root-signed
entries of the services its verified person may call. It holds no role, no
ban, no other service, and no node id but its services' hosts and the
directories. Hosts, directories and the admin hold the whole policy.

## Walkthrough

Six `WIRES_HOME` directories stand in for six machines: **admin**,
**workbench** and **spare** (hosts, and the network's two directories),
**agent** (alice@example.com, the caller), **observer**
(carol@partner.example, whom the IdP verifies but no role matches, so she
is not in the network) and **bob**
(bob@example.com, an analyst the hosts' own rule leaves out). This is the
sequence `.scripts/demo-remote-cli.sh` runs and asserts, on loopback, with a
stand-in IdP (`wires dev-mock-idp`, only in a build with `--features
dev-mock-idp`). The output below is copied from a run of those steps, with
Google's issuer in place of the stand-in's loopback URL. Node ids, the
network string and the sign-in URL are shortened.

**1. admin: start the network, define roles.** The first policy trusts one
IdP: Google unless `--issuer` names another, with the OAuth client id
`wires login` signs in under (`--client-id`, or `$WIRES_OIDC_CLIENT_ID`)
and, for a Google "Desktop app" client, its public secret
(`--public-client-secret`; not confidential for that client type; never pass
a confidential one). The network string carries these, so a caller's
`wires login` needs no flags.

```console
admin$ wires init --client-id <client id> --public-client-secret <desktop secret>
network 735e6b45…
node 57e74c93…
policy version 1 (trusts https://accounts.google.com), stored here
next: run `wires id` on the machine that will be the directory, then `wires directory add <label>=<node id>` here; `wires network` prints the string every node joins with
admin$ wires role set analyst '*@example.com'
wires: policy version 2 is stored here: no directory to publish to yet (name one with `wires directory add <label>=<node id>`)
role analyst set (policy version 2)
admin$ wires role set oncall alice@example.com        # the hosts' own rule (step 3) names it
wires: policy version 3 is stored here: no directory to publish to yet (name one with `wires directory add <label>=<node id>`)
role oncall set (policy version 3)
```

A matcher with no `issuer=` takes `--issuer`, by default the IdP the network
string names.

**2. admin: name the directories and register the service.** A
**directory** holds the policy for everyone else: the admin publishes each
edit to it, hosts follow it, and each caller asks it for its view. Any node
can be one; here the two hosts are. Each machine sends its `wires id`; the
admin names it once as `label=<node id>` and by the label afterwards.

```console
workbench$ wires id
wires id: generated this node's key (node.seed)
63369039…
admin$ wires directory add workbench=63369039…        # likewise spare=10e4e2c2…
wires: policy version 4 is stored here; no directory has taken a publish yet. Once one runs (`wires join <network>`, then `wires serve` or `wires directory serve` on its node), run `wires policy push`
wires: next: on workbench, `wires join <network>` (the network string now names it: `wires network` prints it), then `wires serve host.json` or `wires directory serve`; it starts empty and takes this policy from `wires policy push`
directory 63369039… (workbench) added (policy version 4; 1 directory(ies))
admin$ wires service add orders-db --description "Read-only SQL (sqlite3) over the orders database; pass the SQL statement as the argument." \
         --allow analyst --host workbench --host spare
wires: policy version 6 is stored here; no directory has taken a publish yet. Once one runs (`wires join <network>`, then `wires serve` or `wires directory serve` on its node), run `wires policy push`
service orders-db added (policy version 6)
admin$ wires network
eyJkaXJlY3RvcmllcyI6WyI2MzM2OTAzOTM4…
```

No directory has taken a publish from this admin yet, so each edit says so
and succeeds: the policy is stored on the admin until a directory runs.
Once a directory has taken a publish, an edit that misses it exits 1, even
when another directory took the edit: nothing else brings that directory the
edit, so `wires policy push` re-publishes it once it is back.

**3. The hosts join and serve; the admin publishes once.** `host.json` says
only how each service runs here. A command is an argv, exec'd directly and
never through a shell, with the caller's arguments appended; sqlite3's
`-safe` turns off `.shell`. The optional `identity` section narrows the IdPs
the policy trusts; it can't add one. `also_require` names roles from the
policy a caller must be in as well: these hosts serve orders-db only to
analysts who are also in `oncall`.

```json
{
  "version": 2,
  "identity": { "issuers": [ { "issuer": "https://accounts.google.com" } ] },
  "services": {
    "orders-db": {
      "command": ["sqlite3", "-safe", "-readonly", "-header", "-column", "orders.db"],
      "also_require": ["oncall"]
    }
  },
  "push": { "allow": ["analyst"] }
}
```

```console
workbench$ wires join eyJkaXJlY3RvcmllcyI6WyI2MzM2OTAzOTM4…
joined network 735e6b45… as node 63369039…
next: a host runs `wires serve host.json`, a directory `wires directory serve` (the admin names this node by that id); a caller runs `wires login` instead
workbench$ wires serve --check host.json
host.json ok (version 2)
trusted issuers: the signed policy's, narrowed to
  https://accounts.google.com  audiences: the policy's
services (who may call each is in the admin-signed policy):
  orders-db
    command: sqlite3 -safe -readonly -header -column orders.db
    also requires: oncall
push: to roles analyst
workbench$ wires serve host.json                      # likewise the spare
 INFO wires::host::serve: this host is also a directory version=0
 …
 INFO wires::host::serve: waiting for the admin's first publish (`wires policy push`): this directory holds no policy yet
admin$ wires policy push
wires: policy version 6: published to 2 of 2 directory(ies)
```

and the workbench's log goes on:

```
 INFO wires::directory::node: directory: took a newer policy version=6
 INFO wires::host::serve: signed policy assigns every service to this host policy_version=6 services=1 native=0
```

That `policy push` is the network's one bootstrap step. `serve` decides no
call until its policy assigns every service in `host.json` to it. Because
the network string names each host as a directory, `serve` runs the
directory on the same endpoint. A node that hosts nothing runs one with
`wires directory serve`.

**4. agent: before it joins, nothing; then one command.** A machine that
has joined no network has nothing to list and nothing to dial:

```console
agent$ wires services
wires: no node key at …/agent/node.seed: a caller runs `wires login <network>`, a host or directory `wires join <network>`, with the string your admin prints with `wires network` (`wires id` makes the key alone)
agent$ wires call orders-db -- "select count(*) from orders"
wires: this node has not joined a network: run `wires login <network>` (a caller) or `wires join <network>` (a host or directory) with the string your admin prints with `wires network`
agent$ echo $?
1
```

`wires login <network>` joins and signs in: the caller's whole onboarding.
It opens the browser at the IdP (`--no-browser` prints the URL instead),
stores the key-bound ID token, and asks a directory for its **view**: the
services its verified identity may use, each an entry the root signed.

```console
agent$ wires login eyJkaXJlY3RvcmllcyI6WyI2MzM2OTAzOTM4…
wires login: joined network 735e6b45… (signing in next)
wires login: sign in at

  https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=…

wires login: node 08cff8c1… is alice@example.com (token stored in …/agent/idp-token.jwt, valid until unix 1791175076)
wires login: 1 service(s) you may call (policy version 6); see `wires services`
agent$ wires services
orders-db  Read-only SQL (sqlite3) over the orders database; pass the SQL statement as the argument.  (analyst)
agent$ wires services orders          # search names and descriptions
orders-db  Read-only SQL (sqlite3) over the orders database; pass the SQL statement as the argument.  (analyst)
agent$ wires call orders-db -- "select count(*) from orders"
count(*)
--------
7
agent$ echo "select customer, sum(total) from orders group by customer order by 2 desc" | wires call orders-db
customer  sum(total)
--------  ----------
umbrella  999.0
globex    329.24
acme      259.6
initech   42.0
```

A later sign-in (a Google ID token lasts about an hour) is a bare
`wires login`. `--jq`, `--head` and `--max-bytes` are applied inside
`wires call`; the host never sees them, and the remote exit code passes
through.

**5. Narrower callers.** The observer signs in the same way, and the IdP
verifies carol@partner.example, but no role in the policy matches her, so
she is not in the network. `wires login` keeps her sign-in and says so; a
directory refuses her a view, so she can list nothing, and her call stops on
her own machine (exit 1, no host dialed). A host would refuse her too.

```console
observer$ wires login eyJkaXJlY3RvcmllcyI6WyI2MzM2OTAzOTM4…
wires login: joined network 735e6b45… (signing in next)
…
wires login: node baaf7284… is carol@partner.example (token stored in …/observer/idp-token.jwt, valid until unix 1791175080)
wires login: signed in as carol@partner.example, but not admitted to this network: no role in this network matches carol@partner.example, or you were removed: ask your admin
observer$ wires services
wires: not admitted to this network: no role in this network matches carol@partner.example, or you were removed: ask your admin
observer$ echo $?
1
observer$ wires call orders-db -- "select 1"
wires: not admitted to this network: no role in this network matches carol@partner.example, or you were removed: ask your admin
observer$ echo $?
1
```

Bob is an analyst, so the policy admits him and his view lists orders-db.
The hosts' own rule also requires `oncall`, which he isn't in, so the host
refuses the call: exit 77, nothing on stdout.

```console
bob$ wires call orders-db -- "select 1"
wires: denied by host: bob@example.com is not admitted to orders-db by this host's own rules; don't retry: ask your admin for access
bob$ echo $?
77
```

**6. What the host writes down.** One ordinary log line per call, at
`info`, in `wires serve`'s own output (stderr), and nothing else: no argv,
no stdin, no token, no file of its own. From the workbench, for alice's
first call and bob's refusal:

```
 INFO wires::host::call_trace: call finished service=orders-db caller=08cff8c1… issuer="https://accounts.google.com" subject="…" email="alice@example.com" role=analyst exit=0 duration_ms=7 bytes_out=27
 INFO wires::host::call_trace: call refused service=orders-db caller=ce40632a… issuer="https://accounts.google.com" subject="…" email="bob@example.com" reason="bob@example.com is not admitted to orders-db by this host's own rules"
```

A caller the host could not admit (no valid token, removed, or no role
matches) gets no line of its own: the host traces those at `debug`, with at
most one `info` line per 10 seconds counting them. To keep a record, point a log collector at
`serve`'s output.

**7. The host calls back.** The workbench's operator (or a service, through
its call's push capability) pushes to the agent by key; the agent's
`wires inbox` fetches it. Every line starts with the sender as the caller
verified it, because a push is untrusted input to a model:

```console
workbench$ wires push --to 08cff8c1… --subject build-41 -- "failed: test_orders_total"
queued     alice@example.com (08cff8c1)  587cf1b33a9164e93bc28067cd4ae6be
agent$ wires inbox
2026-10-05 03:38:08Z  from host 63369039 (verified)  build-41  failed: test_orders_total
```

`wires inbox --wait` blocks until a message arrives, and accepts the host's
direct delivery meanwhile. `.scripts/demo-push.sh` runs the full callback: a
build service that returns at once and pushes its result later.

**8. Two hosts, and removal.** Calls to `orders-db` land on the workbench or
the spare at random, a new draw each call. With the workbench stopped, the
same command is answered by the spare (`--verbose` says which host answered;
callers don't normally care):

```console
agent$ wires call --verbose orders-db -- "select count(*) from orders"
count(*)
--------
7
wires: orders-db answered by host 10e4e2c2
```

The caller tries the next host only when a dial fails; a host that answered
has decided. When a call had to dial the stopped workbench before the spare
answered, the caller tries the workbench last for the next minute. Then the admin
removes alice, by email:

```console
admin$ wires remove alice@example.com
wires: policy version 7: published to 2 of 2 directory(ies)
removed alice@example.com (https://accounts.google.com) (policy version 7; 1 person ban; `wires restore` lifts it)
agent$ wires call orders-db -- "select count(*) from orders"
wires: denied by host: not admitted to this network: no role in this network matches alice@example.com, or you were removed: ask your admin
agent$ echo $?
77
agent$ wires inbox
wires inbox: host 10e4e2c2 refused: not admitted to this network: no role in this network matches alice@example.com, or you were removed: ask your admin
wires inbox: host 63369039 refused: not admitted to this network: no role in this network matches alice@example.com, or you were removed: ask your admin
wires: denied by host: not admitted to this network: no role in this network matches alice@example.com, or you were removed: ask your admin
```

A person ban holds on every machine that person signs in from. Each host
applies it from the moment it holds the new policy, with no restart: at once
here, since both hosts are directories; a host that isn't one follows a
directory, which sends it the new policy as soon as it takes the publish. A push to her is
refused at send too, and what a host had queued for her is dropped at her
next fetch. A directory now refuses her a view, but the view her machine
already holds stays until it is refreshed, so her own `wires services` can
still list orders-db; every host refuses her either way. `wires restore
alice@example.com` lifts the ban (policy version 8), and her next call
runs. `wires remove spare` would ban the node instead and drop it from every
service's hosts and from the directories; callers would tell it nothing once
the last word the workbench signed for the old policy lapsed (15 minutes at
most). That takes a second directory: in a one-machine network, where one
workbench is both host and directory, callers take that machine's own word,
so removing it holds only at the policy's expiry
([Known trade-offs](#known-trade-offs)). Two directories that are also the
only hosts, as here, have a cost too: with one down, calls to the other stop
within 15 minutes, which a third directory avoids.

Run it yourself:

```bash
./.scripts/demo-remote-cli.sh            # builds with Cargo; narrated; --quiet for assertions only; --keep keeps the keystores
./.scripts/demo-push.sh                  # a host calls the agent back
```

## Running a host

### host.json

| Key | Meaning |
|---|---|
| `version` | Required, `2`; any other version is refused. Unknown keys anywhere are an **error**. |
| `identity.issuers` | Optional. Narrows the IdPs the policy trusts (`wires issuer set`) to those listed; an entry's optional `audiences` keeps only those of the policy's accepted audiences **from that issuer**. It can't add an issuer or an audience. Absent: the policy's, as signed. |
| `services` | Name → `command` (argv, no shell; each call's arguments are appended), optional `cwd`, optional `env` (no `WIRES_*` names), `also_require`: roles from the policy the caller must **also** be in (only narrows), and `end_of_options` (default `false`): put `--` between the command and the caller's arguments, so a CLI that honours `--` can't read them as options (it does nothing for one that doesn't). Every name must be assigned to this host by the policy. |
| `push` | Optional. `allow`: the roles (from the policy) whose members may receive pushes from this host, tried in order (none by default). |

Who may call a service is not in this file: it is the policy's `allow`. A
refusal exits 77 at the caller. A host tells an admitted caller nothing
about a service it may not call: one it isn't allowed, one that doesn't
exist and one nobody is allowed all get the same sentence, with no role
names and no policy version (the reason goes to the host's trace), checked
before the host looks at whether the service is assigned to it:

```console
bob$ wires call orders-db -- "select 1"      # after the admin allows only oncall
wires: denied by host: no service named `orders-db` that you may call; see `wires services`
```

(A name missing from the caller's view gets the same sentence from the
caller's own `wires`, exit 1, before any host is dialed.) For a service the
caller may call, the host says why: its own rule (`… is not admitted to
orders-db by this host's own rules` for `also_require`), or a service the
policy doesn't assign here (`service orders-db is not assigned to this host
…`). A caller that isn't admitted hears only `not admitted to this network:
sign in with \`wires login\`, or ask your admin for a role`, which its own
`wires` turns into what its person can act on.

### What a service gets

A service's environment starts empty: only `PATH`, `LANG` and `LC_*` are
inherited from `serve`, then the service's `env`, then what the host sets
from the verified call, which always wins:

| Variable | Value |
|---|---|
| `WIRES_ID_TOKEN` | The caller's raw ID token, byte for byte as the caller presented it in this call. The host already verified it (signature, audience, binding to the caller's key); the service may use it, verify it again, or hand it to a token exchange. |
| `WIRES_CALLER` | The claims the host verified from that token, as one JSON object: `issuer`, `subject`, `not_after`, and `email`, `org`, `groups` when present. `jq -r .email` reads it. |
| `WIRES_CALLER_EMAIL` | The caller's verified email; absent when the token carries none. |
| `WIRES_CALLER_NODE` | The caller's node id: what `wires push --to` addresses. |
| `WIRES_SERVICE`, `WIRES_ROLE` | The service called, and the role that admitted the caller. |
| `WIRES_PUSH_SOCKET`, `WIRES_PUSH_TOKEN` | With a `push` section only: the call's push capability, which `wires push` uses to reach this call's caller and no one else, for the call and 10 minutes after it. |

The child gets no `WIRES_HOME`, `HOME`, agent sockets or cloud credentials,
and none of the host's keys. It does get the caller's ID token, which is a
bearer credential until it expires (about an hour with Google): bound to
the caller's key inside wires, but accepted by any relying party that
accepts this OAuth client's audience. A call through the web gateway
carries a token minted for the gateway's OAuth client, so its `aud` differs.

The child runs as `serve`'s Unix user, so it can reach what that user can,
the host's keystore included, and other processes of that user can read its
environment (`/proc/<pid>/environ`): [run services as a separate Unix
user](deployment.md#run-services-as-a-separate-unix-user). A service's fixed
command must also be safe against any trailing arguments, including ones
spelled like options (`gh api -X DELETE …`); `"end_of_options": true` puts
`--` before them, which settles it for CLIs that honour `--` and for no
others. If the caller disconnects, the host kills the child.

### Native services

A host can also be an app: it embeds the `wires` library, implements
services in its own process, and serves them. To a caller a native service
is like any other (`wires call`, `wires mcp` and the gateway work
unchanged): the same gate, the same log line, the same push. What the
handler gets beyond a CLI is a warm process (state kept across calls) and
the verified caller as a value: `call.principal()` (what a child gets as
`WIRES_CALLER`), `call.id_token()` (`WIRES_ID_TOKEN`), `call.role()`,
`call.caller()` (the node id) and `call.args()`. Details and limits are in
[protocol.md §5](protocol.md#5-sessions-wiressession2).

An embedded host is a node like any other, with a keystore directory of its
own that the app names (it never reads `$WIRES_HOME`):

```console
host$  WIRES_HOME=/var/lib/kv/wires wires join <network>      # prints its node id
admin$ wires service add kv --allow analyst --host kvhost=<node id>
```

It refuses to start unless the policy assigns each of its services to it.
The node key is loaded into the app's memory: a native service is the
operator's own code, trusted as much as `wires serve`.

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

`.trust_issuer` narrows the policy's IdPs, as `host.json`'s
`identity.issuers` does; leave it out to take the policy's.
`.host_json(path)` also serves `host.json`'s CLI services from the same
host, and `.push_allow([roles])` enables `call.push_to_caller(subject,
body)`. When the caller disconnects, the handler's task is aborted at its
next `.await`.

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

The ID token is `call.id_token()` in Python and `call.idToken()` in
TypeScript. In both, an exception ends the call with exit 1 and its message
on the caller's stderr, like an uncaught exception in a CLI. A handler there
can't be aborted: when the caller disconnects, its next read or write fails
instead. The bindings' `serve` doesn't take Ctrl-C unless asked, since that
would claim the signal for the whole process; the examples stop the host on
SIGTERM or Ctrl-C themselves.

`make demo-python` and `make demo-node`
(`.scripts/demo-native-service.sh --lang python|node`) serve the kv example
on a loopback network and call it with the shipped `wires`: state kept
across calls, the handler's exit code, stderr and exceptions, the caller's
identity and ID token (`whoami`), a refused caller, a push to
`wires inbox`, and a clean `stop()`.

## Why it is built this way

**Services, not hosts.** A caller cares what it is calling, not where it
runs. The admin binds each name to its hosts in the signed policy; the caller
tries them in a random order drawn for each call, and moves to the next only
when a dial fails. Moving a service changes nothing for callers, and adding a
host adds capacity: calls spread across the hosts. Hosts share nothing but
the policy, so that holds for a service that keeps no state between calls
(see *Known trade-offs*).

**Dial by key, not by host and port.** Tailscale gives the caller's machine
a network path to the host; you then trust every port on it, or narrow it
with ACLs and guard each service with its own auth. wires gives the caller a
key-addressed path to the services the policy lets that person call. On the
host there is no TCP listener and no firewall port opened; iroh binds UDP
for QUIC (direct, or through a relay). Any key can open a connection, but
one whose ID token doesn't verify is refused at its first message, before
anything runs. In the two-machine run (card 08), `ss` on the host showed
zero TCP listeners and two UDP sockets.

**One signed policy, checked locally.** The trusted IdPs, the roles, the
services and the bans are one root-signed, versioned policy. Directories hold
it and vouch for its freshness; hosts keep the whole policy and show that
word to each caller before it sends anything, and each caller keeps its
view. Hosts decide every call from their copy, re-read per
connection, with no round trip to an auth server or a directory. A node never
accepts an older version, so a ban sticks.

**Identity is the IdP's own signature.** `wires login` puts a hash of the
caller's key in the OIDC `nonce`, so the ID token names the key it belongs
to. The host verifies it against the IdP's published keys, under the issuers
the signed policy trusts. There's no wires-run identity service, and no
auth code in the CLI being run; the service gets the verified identity and
the token itself.

**Hosts can call the agent back.** A webhook needs the receiver to have a
public HTTPS endpoint, and an agent on a laptop or in a sandbox has none. A
caller here is addressed by its key, so a host can push to it with neither
side exposing anything: `wires push --to "$WIRES_CALLER_NODE" --subject
build-41 -- "failed: …"` from a service's background job, through the call's
push capability. The host's operator can also push, by node id or role. The
host dials the caller by key (a running `wires inbox --wait` accepts it) and
otherwise keeps the message (24 h by default, at most 7 days) for the
caller's next `wires inbox`. `host.json`'s `push.allow` decides who may
receive (default nobody), checked at send and again at delivery or fetch, so
a removed person gets nothing. Callbacks only to the node **and** person
that made the call, with no role addressing and an `inbox` MCP tool, are
designed and parked ([card 31](board/backlog/31-inbox-delivery.md)).

**MCP as a bridge.** `wires mcp` serves the same services, with the same
`jq`/`head`/`max_bytes` fields, over stdio (Claude Desktop, IDEs), and
`wires gateway` serves them as a remote MCP server (Claude on the web). The
gateway presents each web user's own ID token, so the host still verifies
the IdP and applies the policy. They carry existing MCP workflows over;
`wires call` is the CLI path. Why CLIs, with numbers, is in the
[README](../README.md) and [bench/REPORT.md](../bench/REPORT.md).

## Giving an agent only `wires`

A Claude Code rule like `Bash(wires call:*)` is **not airtight** on its own.
Claude Code does check each part of a compound command, but it also
auto-allows read-only commands such as `cat` and `echo` inside the working
directory, and `< file` or a glob can send working-directory files to the
host as input. Evidence and method:
[agent-sandbox.md](agent-sandbox.md).

To make `wires` the boundary, use a structural setup:

- a container or sandbox whose `PATH` holds only `wires`, in an empty
  working directory with no secrets in the environment, with
  `WIRES_LOCKED=1` set. A caller's commands take no key, relay or keystore
  flag (only the environment, which the operator sets, picks the keystore),
  so the one thing the lock adds is that `wires call` refuses data on stdin
  (exit 2, before dialing): `< file` can't ship a local file to the host.
  Pass input as arguments; an operator whose services need piped input
  leaves the lock off.
- or `wires mcp` as the agent's only tool, with no Bash tool at all.

## Known trade-offs

What wires does not do, or does with a cost, as built:

- **The admin does not approve each machine.** Anyone the IdP verifies under
  a trusted client, with a verified email, whom a role matches, is in from
  any machine they sign in on. A sign-in phished into binding an attacker's
  key (the attacker's nonce in the victim's sign-in) would be admitted.
- **The ID token is the only credential**, so its lifetime is every
  caller's. Google's last about an hour, and Google drops the `nonce` (the
  key binding) on refresh, so people run `wires login` again about hourly.
  Disabling someone at the IdP cuts them off within one token lifetime, with
  no wires action.
- **Every service gets the caller's ID token** (`WIRES_ID_TOKEN`), as the
  host does. Outside wires it is a bearer credential for this OAuth client's
  audience until it expires. A child's environment is readable by other
  processes of its Unix user.
- **No call record.** A host writes one log line per call to `serve`'s own
  output; nothing is signed, nothing is kept by wires, and nothing can be
  read back by a caller or an auditor. A host could leave out or alter its
  own lines.
- **Hosts share no state.** Calls to a service with several hosts land on
  one at random each time, so whatever a service keeps between calls (in a
  native service's memory, or on its machine's disk; the `kv` example's
  store) is per host, and the next call may not see it. A host knows a
  caller's identity only after that caller called it or ran `wires inbox`,
  so `wires push --to <role>` from one host reaches only those callers. A
  push is queued on the host that sent it; `wires inbox` asks every host,
  so none is missed, but one queued on a host that is down waits there
  ([card 31](board/backlog/31-inbox-delivery.md)). The spread is per call
  and blind to load: no host reports how busy it is.
- **Hosts and directories hold the whole policy**: host and banned node
  ids, removed people's emails, role matchers (often people's emails),
  service names and descriptions, trusted IdPs, directories. It is signed,
  not secret. A caller holds only its view.
- **A directory sees who asks for what.** It verifies each caller's ID token
  to cut its view, so it learns which person asks for which view (it only
  traces the requests). It can withhold an entry or serve a stale view (a
  signed freshness timestamp bounds how stale), which makes a caller miss a
  service, never reach one it may not use: the host decides every call.
- **A removed host can be told a call for up to 15 minutes.** A caller
  dials from the view it holds, so a machine removed from a service is still
  in the views of callers that haven't refreshed. A caller tells a host
  nothing without a word from a directory other than that host that the
  host's policy is current (the host shows its words first; a caller may
  already hold one), good for `fresh_secs` (15 minutes by default); an honest
  directory signs only for the newest policy, so once the edit reaches the
  directories a removed host has nothing to show within that window. Until
  then, a caller holding a word for the old policy can still send it the ID
  token and arguments.
- **A one-machine network trusts its machine's own word.** When the
  policy lists one directory and it is the host being dialed (the first run:
  one workbench is both), there is no other directory to ask, so removing
  that machine holds only at the policy's expiry (90 days by default). Run a
  second directory (`wires directory add`, then give callers the new
  `wires network` string) to make removal hold within `fresh_secs`. A
  directory machine the admin removed can still sign words for older
  policies that list it, so it can vouch for another removed host to a
  caller whose view is that old ([protocol.md §9](protocol.md#9-known-limits)).
- **A stranger costs a token check.** Any key can connect and make a host or
  directory verify one ID token (keys are fetched only for a trusted issuer,
  and refetched at most once per issuer per rate-limit window; a failed
  fetch is not retried within it).
- **Bans don't expire**, and accumulate in the policy until `wires restore`.
  A person ban matches the ban's issuer and the token's verified email.
  Remove a person by email; `wires remove <node>` is for taking a host or
  directory machine (or one specific key) out, not for keeping a person
  out.
- **The root key is a file** (`root.seed` in the admin's keystore): no backup
  root, no rotation. Losing or leaking it means starting a new network
  ([fabric.md §4.4](fabric.md#44-the-root-key)).
- **The policy doesn't renew itself.** It expires after `--policy-ttl`
  (default 90 days from the last edit); an expired policy admits nobody, and
  no caller dials from one. Any admin edit signs a fresh one (never with an
  earlier expiry than the one it replaces).
- **The admin is a one-shot command.** It publishes each edit to the
  directories only, retrying for about 15 seconds. An edit that misses a
  directory that has taken a publish before exits 1, even when another
  directory took it: directories don't replicate, so hosts following the
  one that missed it decide under the old policy until `wires policy push`
  re-publishes it (a directory that is also a host may catch up sooner,
  from the directory its host follows; until any directory has first taken
  a publish, reaching none is a note). Hosts follow a directory and get each
  edit, as the whole policy, as soon as that directory takes it. `wires
  mcp` and `wires inbox --wait` ask for their view every 60 seconds, and
  the gateway at each web user's first request after 60 seconds, so a grant
  or revocation reaches them within a minute. A one-shot `wires call`
  learns of an edit in its next call's handshake and refreshes its view
  then. A refusal by a host also marks the view as behind, so the next
  `wires services` or `wires call` refreshes it first.
- **Calls fail closed without a directory.** A caller sends a host nothing
  until a directory other than that host has vouched for the host's policy
  within `fresh_secs` (15 minutes by default). With every directory down,
  or a host cut off from them, calls to it fail (exit 1, `no directory has
  vouched for a host of … recently, so nothing was sent`) once the words
  callers hold lapse; edits and bans don't spread until a directory is
  back. In a network whose only two directories are also its hosts (the
  walkthrough's workbench and spare), the one left up can show only its own
  word, so with one down, calls to the other fail within 15 minutes. If a
  host outage mustn't stop calls, run a third directory, or one on a node
  that hosts nothing (`wires directory serve`). The same rule holds a
  caller's view refresh: a directory hears a caller's token only on another
  directory's current word, so with one of several directories up, callers
  keep the views they hold.
- **A host knows only the identities presented to it.** Push to a role
  reaches callers it has admitted (on a call or a `wires inbox` fetch) since
  it started (card 31 removes role push).
- **A service runs as `serve`'s Unix user** unless the operator switches
  users in its command ([deployment.md](deployment.md#run-services-as-a-separate-unix-user));
  isolating each call is an open question
  ([card 32](board/backlog/32-service-sandbox-OPEN.md)).
- **A web gateway holds its users' live identities.** Each web user's token
  is bound to the gateway's key, so it's useless to other nodes, but the
  gateway can use it for anything that user may call until it expires (about
  an hour). There is no refresh (Google omits the `nonce` on refresh), so web
  sessions end with the token. It is the one piece that listens (HTTPS,
  behind a tunnel or proxy), and it offers tools only: no push or inbox.
- **Only Google has been tested** as a real IdP, though any OIDC issuer is
  configured the same way.
- **A relay may carry the traffic.** Reaching a host behind NAT can go
  through a public relay (n0's by default, or your own); the relay sees
  only end-to-end encrypted QUIC.
- **One network per keystore.** A node in two networks needs two
  `WIRES_HOME` directories.
- **No compatibility promise.** This is research code: a new version may not
  read an older keystore or policy (re-`init` a test network after
  upgrading).

## Not yet

- **Joining by domain** (`wires login acmecorp.com`, the network string
  published under a domain). An open question, not designed
  ([card 18](board/backlog/18-front-door-OPEN.md)). Today the network
  string introduces the root key (trust on first use).
- **The recorded two-machine demo** with real Google sign-in and Claude Code
  as the agent ([card 08](board/doing/08-demo-two-machine.md); script in
  [demo.md](demo.md)).
- `login --for` and day-passes for headless agents, and a credential longer
  lived than an hour ([card 29](board/backlog/29-person-identity.md)).
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
> address. Every call runs as you: the machine that runs it checks your
> sign-in against an admin-signed policy of who may call what. A refusal
> ("denied by host", exit 77) is that policy, not a fault: don't retry or work
> around it; ask your admin for access.

Then it lists only the caller's everyday commands (`services`, `call`,
`login`, `inbox`, `mcp`). `wires --help-all` lists every command, by role.
Each command's `--help` gives its examples, and its exit codes or output
shape where they matter; `wires <command> --help-all` adds the flags `--help`
hides: `serve`'s `--node-seed[-file]`, `login`'s `--issuer`, `--client-id`
and `--client-secret`, `--relay-url` (on `serve`, `directory serve` and
`gateway`), every `--policy-ttl`, and the gateway's `--allow-origin` and
`--trust-proxy-header`. The help text, the MCP text and the key errors are
snapshot-tested (`wires/snapshots/`).

| Role | Command | What it does |
|---|---|---|
| **admin** | `wires init [--issuer URL] [--client-id ID] [--audience A]… [--public-client-secret S] [--policy-ttl 90d]` | Create the root key and this node, and sign policy version 1, trusting one IdP: `--issuer` (default `https://accounts.google.com`), whose OAuth client id `--client-id` (else `$WIRES_OIDC_CLIENT_ID`; required) `wires login` signs in under, and whose `--audience` values hosts accept (default: the client id). The network string names this IdP; `--public-client-secret` is its client's public (Desktop-app) secret, which the network string carries and the signed policy doesn't. Publishes nothing. |
| | `wires network` | Print the network string (stdout): the root key, the policy's first two directories and the sign-in settings. Not secret. With no directory listed yet it still prints, and warns on stderr. On any other node, the string it joined with. |
| | `wires issuer set <iss> --client-id ID [--audience A]… [--public-client-secret S] [--login]` · `issuer rm <iss>` | Trust an IdP (or change its client id and accepted audiences; default audience: the client id), or stop trusting one no role and no person ban names. `--login` makes it the IdP the network string names; `--public-client-secret` as for `init`. |
| | `wires role set <name> [--issuer URL] <matcher>…` · `role rm <name>` | Define a role as an OR of matchers: `*@example.com`, `alice@example.com`, or `issuer=…,email=…,org=…,group=…` (all must hold). Every matcher names its issuer, compared exactly: one without `issuer=` takes `--issuer` (default: the IdP the network string names), which must be trusted. `issuer=…` alone admits anyone that IdP verified who carries a verified email; no matcher admits a sign-in without one. `org` is Google's `hd`, read only from Google. There is no built-in role, and a person no role matches is not in the network. |
| | `wires service add\|set <name> [--description D] [--allow role]… [--host node]…` · `service rm <name>` | Edit the services. `--host` is `label=<node id>` the first time, then the label (or the id), of a node not banned; repeat it to spread calls across several. `set` replaces each list given. |
| | `wires directory add\|rm <node>` | List a node (not banned) as one of the network's directories, and print its next steps; or stop listing it. `label=<node id>` the first time. Removing the last directory is refused: with none, no caller would call any host. |
| | `wires remove <email\|node> [--issuer URL]` | An email: a person ban (`--issuer` defaults to the IdP the network string names): every host refuses that person from any machine, and every directory refuses them a view. A node id or label: a node ban, and the node is dropped from every service's hosts and from the directories (refused when it is the last directory: add another first). Neither expires. |
| | `wires restore <email\|node> [--issuer URL]` | Lift a person or node ban. A restored node is not put back into services or directories. |
| | `wires policy push` | Re-publish the stored policy to every directory: the first publish of a new network, or after an edit that missed a directory. Exits 1 if a directory that has taken a publish before misses this one too. |
| | `wires policy settings [--beat-secs N] [--fresh-secs N]` | Print the network's settings, or change them and publish. `--beat-secs` (default 300): how often a directory signs a freshness timestamp and sends it to the hosts that follow it; `--fresh-secs` (default 900, at least the beat): how long one lasts. `--fresh-secs` is the removed-host window: a caller tells a host nothing without a current timestamp from a directory other than that host, so a removed host is told nothing once the last one for the old policy lapses, and with every directory down calls stop within it. |
| **host** | `wires join <network>` | Store the network string (`network.json`), making the node key if there is none, and print the node id. Contacts nobody. Refuses the admin's keystore and one that joined another network. |
| | `wires serve host.json` | Serve every service in the file once the policy assigns it here (a host that is also a directory waits for the admin's first publish; one that isn't fetches from a directory for up to 8 s at start, and exits if none answers). Then check every caller against the policy, run the service per call, and write one log line per call. It follows a directory for every edit (the whole policy each time) and its freshness timestamps, which it shows each caller before the caller sends anything (callers send nothing to a host that has no current one), and runs the directory too when the policy lists this node. `--check` validates and prints what the file implements. |
| | `wires push --to <node-id\|role> --subject S [--ttl D] [-- <body>]` | Hand a message for a caller to this machine's running `serve` (body from stdin if none is given). From the operator's shell: to any node or role. From a service (it has `WIRES_PUSH_TOKEN`): only to that call's caller. Prints `delivered`, `queued` or `denied` per recipient; exits `77` if every recipient was refused. |
| **directory** | `wires directory serve [--max-subscribers N]` | Run this node's directory alone (no `host.json`), until Ctrl-C. `--max-subscribers` (default 4,096) caps how many hosts and directories may follow it at once (callers don't subscribe; they ask for their view). Refuses the admin's keystore, a keystore that joined no network, and a node neither the policy nor the network string lists. It starts empty and waits for the admin's first publish. |
| **caller** | `wires id` | Print this node's id (making its key on first use). |
| | `wires login [<network>] [--no-browser] [--callback-port N] [--refresh\|--reuse]` | The first time, with the network string: join, then sign in. Sign in with the IdP the network string names (the hidden `--issuer`, `--client-id`, `--client-secret` or `WIRES_OIDC_*` override it), store the key-bound ID token, and fetch your view. `--refresh` tries the stored refresh token first (with Google the refreshed token has no `nonce`, so it can't be used); `--reuse` re-checks the stored token. |
| | `wires services [query] [--verbose] [--json]` | List the services in your view, one per line: `<name>  <description>  (<roles that may call>)`; a `query` keeps those whose name or description contains it. Nothing on stdout when there are none: stderr says why and what to do (with the premise, when the view is empty). A person no role matches, or who was removed, exits `1`: `not admitted to this network: no role in this network matches <email>, or you were removed: ask your admin`. `--json` prints one object per line, `{"service","description","allow":[…],"hosts":<count>}`, plus `host_ids` with `--verbose`. Refreshes the view first when it is over a day old, expired, or a call the host ran saw a newer policy. `--verbose` adds the hosts. |
| | `wires call <service> [--jq F] [--head N] [--max-bytes N] [--verbose] -- <args>` | Run a service by name, from your view (a name it lacks is asked of a directory), on one of the service's hosts at random, moving to the next only when a dial fails. Stdio passes through and its exit code becomes `call`'s, except that a remote exit `77` is reported as `1` (with a note on stderr). A refusal by the host exits `77`, with nothing on stdout. No sign-in, a service you may not call, a local or transport failure, an expired view, no host that could show a directory's current word for its policy (`no directory has vouched for a host of … recently, so nothing was sent`), or a newer policy (in the host's handshake) whose entry no longer lists that host exits `1`, before any stdin is sent. A usage error (a `--jq` filter that fails, or data on stdin in locked mode) exits `2`. `--verbose` names the host that answered and prints every cause of an error. |
| | `wires inbox [--wait [--timeout D]] [--json]` | Fetch from the hosts of your services, print what they pushed (sender first), mark it read. `--wait` blocks until something arrives (and accepts direct pushes meanwhile); `--timeout` exits `124`; a refusal by every host exits `77`; not admitted to the network, with no view held, exits `1`. Refreshes a stale view first, as `call` does, and never dials from an expired one; with `--wait`, asks for the view again every 60 s. A host is sent the token only after it shows a directory's current word, as for `call`; when no host can, stderr says so. |
| | `wires mcp` | Serve the same services as MCP tools over stdio, asking for your view every 60 s: a grant or revocation reaches the client as `tools/list_changed` within a minute. Each tool is a service, named as `wires services` lists it, and described by the first sentence of its description; the `instructions` are the premise plus how to pass arguments and filter output. Past 40 services it offers `search_services` and `call_service` instead of one tool each. A refusal is a tool error reading `denied by host: <reason>` and its next step. |
| | `wires gateway --public-url https://… [--listen addr] [--client-id …] [--client-secret-file F] [--issuer URL]` | Serve them as a remote MCP server (Streamable HTTP + OAuth 2.1) for web clients such as Claude on the web. Each user signs in with the IdP through the gateway and calls with their own token, from their own view (held in memory and asked for again at the user's first request after 60 s) ([deployment](deployment.md#a-web-gateway)). |

Every command's error ends with the next step in one clause (`run \`wires
login\``, `see \`wires services\``, `ask your admin …`), and without
`--verbose` prints no stack of causes. A refusal prints the host's reason as
the host gave it, then a next step when the reason carries none (`… ; don't
retry: ask your admin for access`).

Every admin edit signs a new policy valid for `--policy-ttl` from now
(default 90 days), or until the current policy's expiry if that is later: an
edit never shortens the policy's life. It is published to the directories
the policy lists (and to any the policy before the edit listed); the admin
dials no host. A directory that has taken a publish before but can't be
dialed now (one that just restarted can't be found by its key for a few
seconds), or that answers that it is busy, is tried again each second for up
to 15 s, so an edit while such a directory is down takes 15 s before it
reports the miss (30 s at most); a directory the edit drops is tried once.
The line names each directory not reached. When a directory the new policy
lists has taken a publish from this admin before and still misses this one,
the command prints its result but exits 1, whatever the other directories
did: the policy is in force at the directories that took it, but nothing
else brings it to the one that missed it, and hosts following that one
decide under the old policy until `wires policy push` reaches it. A
directory that has never taken a publish (the first run, or one just added
that doesn't run yet) fails nothing; with no directory listed, reaching none
is a note and exits 0. A directory that holds a newer
policy than the admin's fails the edit whatever the others did: the admin's
`policy.json` is stale (copy it from any host or directory, then edit
again). So does any edit on an admin whose `policy.json` is gone.

For a stdio MCP client, the whole config is:

```json
{ "mcpServers": { "wires": { "command": "wires", "args": ["mcp"] } } }
```

### The keystore

Each node's keystore is a directory: `$WIRES_HOME`, else
`$XDG_CONFIG_HOME/wires`, else `~/.config/wires`. Every file in it, with its
mode and holder, is listed in
[protocol.md §8](protocol.md#8-keystore-wires_home-else-xdg_config_homewires-else-configwires).
The ones you will meet: `root.seed` (the admin only: the network's
authority), `node.seed` (every node's key), `network.json` (the network
string a node joined with), `policy.json` (the admin, hosts and
directories), `view.json` and `idp-token.jwt` (callers), and the admin's
`labels.json` (its names for nodes). A host's or directory's keystore must
not hold `root.seed`: run each from its own.

The environment picks the keystore, and every command takes its node key
from it; `serve` alone takes `--node-seed-file` (or `--node-seed`) ahead of
it, so a container can mount its node key from a secret.

### Removal

`wires remove alice@example.com` bans a person; `wires remove <label|node
id>` bans a node and drops it from every service's hosts and from the
directories. `serve` re-reads its signed policy once per connection, so a
removal takes effect at each host on the next call after that host has the
new policy, with no restart. The removed caller's call prints `wires: denied
by host: not admitted to this network: no role in this network matches
<email>, or you were removed: ask your admin`, writes nothing to stdout and
exits `77`; the host traces it at `debug`, not as a call line (a ban is not
told apart from no sign-in). A directory refuses a removed person a view; a view
she already holds stays until it is refreshed, and every host refuses her
either way. Pushes to a removed person or node are refused
at send, delivery and fetch, and a fetch by one drops what was queued for
it. There is no shared key, so there is nothing to rotate. `wires restore` lifts a ban.

### Reachability

By default a node is found by id through iroh's n0 discovery and relays,
which needs outbound internet. For a network without discovery, put hint
lines in `$WIRES_HOME/hints` (`<node id> <ip:port>…`, one per node; a
running `serve` writes its own to `run/hint`). To avoid n0's relays, run
upstream [`iroh-relay`](https://docs.rs/iroh-relay) yourself and pass
`--relay-url <its url>` to `serve`, `directory serve` and `gateway`; a
caller's commands take no relay flag
([deployment.md](deployment.md#reachability-and-discovery)).
Addresses are unsigned hints: iroh still authenticates the peer's key, so a
wrong address can only fail to connect.

### Layout, build and test

One Cargo workspace ([CLAUDE.md](../CLAUDE.md)):

- **`library/`**: the transport-free core. `network/` (node identity, the
  network string, admission), `calls/` (session frames, invocations, IdP
  identity, pushes, the host's proof), `services/` (roles, the signed
  policy: head, items, service entries, freshness, views; authorization), and
  `directory/` (the directory's frames).
- **`wires/`**: the binary (and the embedding API), filed by role:
  `admin/`, `host/`, `caller/`, `gateway/` (the remote MCP server),
  `directory/` (the directory: its proof, its two ALPNs, `directory serve`),
  `policy/` (the signed policy on this node, published to and fetched from
  the directories), and `e2e/` for the loopback integration tests.
- **`bindings/`**: `wires-ffi` (Python, via UniFFI) and `bindings/node/`
  `wires-node` (TypeScript, via napi-rs), the embedding API in other
  languages; see [Native services](#native-services).

```bash
cargo build --workspace
cargo test --workspace                   # unit, property, e2e and doc tests
./.scripts/demo-remote-cli.sh --quiet    # the demo, as a test
docker build -t wires .                  # distroless image, native arch
```

`make help` lists the same as shortcuts. Deployment notes are in
[deployment.md](deployment.md), tests in [testing.md](testing.md), and the
benchmark in [bench/REPORT.md](../bench/REPORT.md).

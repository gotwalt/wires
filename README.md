# wires

**Your tools are already CLIs. wires lets any agent in your organization run
them where they live: `wires login` says who you are (your IdP), `wires
services` lists what you may use, and `wires call` runs one by name, with no
port opened and no VPN.**

> **Experimental.** wires is research code. The protocol, the file formats
> and the commands change without notice, nothing is kept backwards
> compatible, and it has had no security review. Don't use it to protect
> anything that matters.

You have a sqlite database on your laptop. A colleague wants to ask it a
question from their agent, in the middle of their own work. Today you can
send them the file, stand up a server with a port and a login somewhere, or
write an MCP server for it. Each of those is a project, so usually the
question goes unasked.

With wires, their agent runs this:

```console
agent$ wires call orders-db -- "select customer, sum(total) from orders group by customer"
customer  sum(total)
--------  ----------
acme      259.6
globex    329.24
initech   42.0
umbrella  999.0
```

The query runs on your laptop, as them, and the answer comes back into their
session like any other command's output.

## Why CLIs

Agents work best with command lines. Models have seen far more shell than
tool-call JSON. A CLI's output can be cut down before it reaches the model's
context (`gh --jq`, `--json fields`, `head`). And CLIs compose. What stops
you from sharing a CLI with everyone in an organization is three things,
and wires is those three:

- **Who is calling.** `wires login` signs you in with your organization's
  IdP (Google, or another OIDC provider the admin trusts). The machine that
  runs the call checks that sign-in itself.
- **How they find it.** `wires services` lists the services you may call.
  You call one by its name. You never name a machine or handle its key.
- **How they reach it.** Every machine is reached by its public key, over an
  end-to-end encrypted connection, directly or through a relay. Both sides
  dial out: no inbound port, no VPN.

A service can also do one thing a local CLI can't: message its caller back,
after the call has ended.

## A quick tour

One admin, one host (the `workbench`, holding `orders.db`), one agent.

```console
# admin: create the network, say who may call what, and where it runs
admin$ wires init --client-id <your Google OAuth client id>
admin$ wires role set analyst '*@acme.com'
admin$ wires directory add workbench=2161f020032bd52d283a33399ca6364d5b41037a272bafe4b0d72eb69d5e961c
admin$ wires service add orders-db --description "Read-only SQL over orders" \
         --allow analyst --host workbench
admin$ wires network                  # one string, the same for everyone; not secret
eyJkaXJlY3RvcmllcyI6WyIyMTYxZjAy…

# host: join, then run the services the policy assigns it
workbench$ wires id                   # the node id the admin named above
2161f020032bd52d283a33399ca6364d5b41037a272bafe4b0d72eb69d5e961c
workbench$ wires join <network>
workbench$ wires serve host.json      # also the directory; waits for the first publish

# admin: publish the policy to the directory, once
admin$ wires policy push
wires: policy version 4: published to 1 of 1 directory(ies)

# agent: signing in is joining
agent$ wires login <network>          # opens the browser
wires login: 1 service(s) you may call (policy version 4); see `wires services`
agent$ wires services
orders-db  Read-only SQL over orders  (analyst)
agent$ wires call orders-db -- "select count(*) from orders"
count(*)
--------
7
```

`host.json` on the workbench says how `orders-db` runs. The host runs that
fixed command with the caller's arguments appended, with no shell:

```json
{
  "version": 2,
  "services": {
    "orders-db": { "command": ["sqlite3", "-safe", "-readonly", "-header", "-column", "orders.db"] }
  },
  "push": { "allow": ["analyst"] }
}
```

Later, the host messages the agent, and the admin removes a person:

```console
workbench$ wires push --to <the agent's node id> --subject build-41 -- "failed: test_orders_total"
agent$ wires inbox
2026-10-05 02:42:42Z  from host 2161f020 (verified)  build-41  failed: test_orders_total

admin$ wires remove alice@acme.com
agent$ wires call orders-db -- "select 1"
wires: denied by host: not admitted to this network; sign in with `wires login`
agent$ echo $?
77
```

*The output is from a run on one machine, with `wires dev-mock-idp` (a
stand-in IdP built only with `--features dev-mock-idp`) in place of Google,
so that run's `init` also named the stand-in with `--issuer`. Long ids and
the network string are cut short here. The `role set`, `directory add` and
`service add` edits each say that no directory has taken a publish yet;
`wires policy push` delivers the stored policy once one runs.
`./.scripts/demo-remote-cli.sh` runs the same steps, with two hosts, and
checks every result.*

## How it works

**The policy.** The admin holds the network's root key and signs one
versioned policy: which IdPs are trusted, which roles exist (matched on the
verified identity, for example `*@acme.com`), which services exist, which
hosts run each, who may call each, and who is removed. Every edit is a new
signed version, published by key to the network's directories. Hosts follow
a directory and hold the whole policy. An agent's machine holds only its
view: the services its person may call.

**A call.** `wires call` looks the service up in its view, dials one of its
hosts by key, and sends the caller's ID token in the first message. The ID
token is bound to the caller's key, so it is useless from any other machine.
The host verifies the IdP's signature itself, checks its own copy of the
policy, and runs the command. There is no auth server on the call path. A
refusal is exit 77 with nothing on stdout. If a service has several hosts
and one is down, the call goes to the next.

**The service knows who called.** The command gets the caller's verified
identity in its environment: `WIRES_CALLER` (the verified claims, as JSON),
`WIRES_CALLER_EMAIL`, `WIRES_ROLE`, and the ID token itself
(`WIRES_ID_TOKEN`), so the service can apply its own rules or exchange the
token. Otherwise it gets only `PATH`, the locale and what `host.json` sets:
none of the host's keys.

**Joining and removal.** The network string that `wires network` prints
holds the root key, the first directories and the sign-in settings. A
caller joins with `wires login <network>`, and is in the network if a role
in the policy matches them; there is no per-machine approval. `wires remove
<email>` removes a person, from every machine they use. (`wires remove
<node>` takes a host or directory machine out of the network.) Every host
refuses the person's next call once the new policy reaches it, usually
within seconds, with nothing to restart and no shared secret to rotate.

**Services in your own code.** An app can embed the host and serve calls
in-process, in Rust (`wires::Host`), Python or TypeScript
([bindings/](bindings/)). Callers can't tell a native service from a CLI.

## The service can message back

A webhook needs the receiver to listen, and an agent on a laptop doesn't. A
wires host sends a message to the caller's key instead, or holds it (24
hours by default) until the caller's next `wires inbox`. With a `push`
section in `host.json` whose roles admit the caller, each call's command
can message the caller that started it, even after the call has ended:

```console
# in a CI job the call started, on the host
wires push --to "$WIRES_CALLER_NODE" --subject build-41 -- "failed: test_orders_total"
```

`wires inbox --wait` sleeps until a message lands. An agent waiting on a
build this way spends one tool call, not a loop of status checks (numbers
below).

## MCP: a bridge

Many teams already reach remote tools through MCP clients. So every wires
service is also an MCP tool: `wires mcp` serves your services over stdio to
Claude Desktop and IDEs, and `wires gateway` is a remote MCP server that
Claude on the web adds as a custom connector, each user signing in as
themselves ([docs/deployment.md § A web gateway](docs/deployment.md#a-web-gateway)).
The host still verifies each person's own ID token.

The bridge exists to carry existing workflows over. `wires call` is where
the token savings are, and the bridge should someday be unnecessary.

## Measured

Our own benchmark: GitHub tasks in Claude Code, 5 tasks × 5 runs per setup,
every answer correct in every setup. Runs from 2026-09-23, on an earlier
version of wires ([bench/REPORT.md](bench/REPORT.md)):

| How the agent reached GitHub | Median input tokens | Cost, 25 runs |
|---|---|---|
| GitHub's MCP server (Claude Code's default, tool search on) | 21,088 | $1.87 |
| GitHub's MCP server, tool search off | 30,630 | $1.40 |
| bare `gh` | 6,997 | $0.42 |
| `wires call gh` | 10,539 | $0.48 |
| `wires call gh`, the agent allowed only `wires` | 10,713 | $0.39 |

The gap is not tool schemas: with tool search on, the 26 tool schemas cost
about 400 tokens (about 10.2k with it off). It is results: the MCP server
returned whole API objects, while the CLI let the model pick fields first.
Bare `gh` did a little better than `wires call gh`, so the saving belongs to
the CLI; wires' job is to make the CLI reachable. One model, one MCP server,
small n, stripped-down sessions; an MCP server with field selection would
close much of the gap. All five tasks read from one service, so this says
nothing yet about composition.

Others have found the same direction. Anthropic's
[Code execution with MCP](https://www.anthropic.com/engineering/code-execution-with-mcp)
(2025-11-04) names tool definitions and intermediate results as the two
costs, and cut one Drive-to-Salesforce workflow from 150,000 tokens to
2,000 by having the model drive tools as code. Cloudflare's
[Code Mode](https://blog.cloudflare.com/code-mode/) (2025-09-26): "LLMs have
seen a lot of code. They have not seen a lot of 'tool calls'." Scalekit's
[GitHub benchmark](https://www.scalekit.com/blog/mcp-vs-cli-use)
(2026-03-11) measured 4 to 32 times fewer tokens for the CLI than for
GitHub's MCP server over 75 runs, and argues MCP is still needed for
per-user authorization, tenant isolation and audit trails. wires is aimed at
the first two; it has no audit trail.

Waiting on a mock CI build, 5 runs per setup, also from 2026-09-23
([bench/push/REPORT.md](bench/push/REPORT.md)):

| How the agent waited | Turns | Input tokens (median) | Reaction |
|---|---|---|---|
| Polling (60 s → 300 s build) | 9 → 13 | about 28k → 39k | 20–178 s |
| `wires inbox --wait` | 4 | 15.4k, flat | about 2 s |

Checking `wires inbox` on a loop costs what polling costs; the saving comes
only from waiting on the push.

## Compared with what you have

**A remote MCP server** listens at a URL the client can reach, and is its
own OAuth resource server. Its results are whatever the server returns; the
protocol has no client-side field selection. It reaches a client only over
a stream the client holds open. wires runs a CLI, so the agent trims output
with the CLI's own flags or `wires call --jq/--head/--max-bytes`; one
admin-signed policy covers every service; `wires services` is a per-person
catalog; and a host can reach an agent that isn't connected. wires covers
only tools: no MCP prompts or resources.

**SSH, Tailscale SSH and Teleport** solve a different problem. They give a
person a login on a machine. wires gives a person a named service, wherever
it runs: the caller asks for `orders-db`, the admin decides which hosts run
it, and the caller has no account and no shell on any of them.

**Tailscale** gives the agent's machine a network route to the host, scoped
by machine and port, and whatever listens there still does its own sign-in.
A wires host opens no inbound port: an agent reaches only the services the
policy lets its person call, checked against their IdP sign-in on every
call.

**Neither keeps a log of calls for you.** The host writes one ordinary log
line per call (service, caller, verified email, role, exit code) to its own
output. wires keeps no other record of calls.

## Limits

- **The admin doesn't approve each machine.** Anyone your IdP verifies, and
  a role admits, is in from any machine. A phished sign-in that binds an
  attacker's key would be admitted.
- **The ID token is the only credential.** Google's last about an hour, so a
  caller runs `wires login` again each hour. Disabling someone at the IdP
  cuts them off within one token's life.
- **Every service a caller calls gets their ID token**, a bearer credential
  until it expires, and a service's command runs as the host's own Unix user
  unless the operator sets up another.
- **Several hosts for one service means failover**, not more capacity: a
  caller tries the next host only when it can't reach one.
- **Hosts and directories hold the whole policy** (roles, services, host
  keys, removals). A caller holds only its view, but a directory sees who
  asks for which view.
- **A directory must be running** to change the policy, remove someone or
  list services. Calls don't need one: each host decides from its own copy.
- **The policy expires** 90 days after the last edit by default, and nothing
  renews it on its own. Removals don't expire; they stay until `wires
  restore`.
- **A caller dials from the view it holds.** A host the admin took off a
  service can still be dialed by callers whose view is stale, and receives
  their ID token and arguments. `wires call` refreshes a view older than a
  day when a directory answers, but the hard bound is the policy's expiry
  (90 days by default).
- **Callbacks go to a caller's key**, not yet only to the caller that asked
  ([card 31](docs/board/backlog/31-inbox-delivery.md)).
- **Only Google has been tested** as the IdP. The web gateway listens over
  HTTPS and holds each signed-in user's token until it expires.

The full list: [docs/usage.md § Known trade-offs](docs/usage.md#known-trade-offs).

## More

- [docs/usage.md](docs/usage.md): the roles, a walkthrough with output,
  `host.json`, locking an agent down to `wires`, and the
  [commands by role](docs/usage.md#commands-by-role).
- [docs/protocol.md](docs/protocol.md): the protocol, as the code does it.
- [docs/executive-summary.md](docs/executive-summary.md): the product on one
  page.
- [docs/blog/introducing-wires.md](docs/blog/introducing-wires.md): the
  announcement post.

```bash
make install                             # wires on your PATH (~/.cargo/bin)
./.scripts/demo-remote-cli.sh            # the narrated loopback demo (--quiet: checks only)
```

## License

[MIT](LICENSE).

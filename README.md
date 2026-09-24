# wires

**Give your agent tools on other machines, the way it already uses tools on
its own: as CLIs.**

> **Experimental.** wires is a prototype for exploring these ideas, not
> production software: the protocol, the file formats and the commands will
> change without notice, and it has had no security review. Don't rely on it
> to protect anything that matters yet.

wires does the job of a remote MCP server: it lets an agent harness (Claude
Code, or anything that can run a command) use tools that live somewhere else.
The tool is a command-line program, the caller is a person your identity
provider vouches for, and the machine is reached by its public key, never by
a network path.

- **CLIs, not a new protocol.** `wires call orders-db -- "select …"` runs a
  command on the machine that has the database; stdin, stdout and the exit
  code pass through. Models already know how to use CLIs, and they trim
  output (`--jq`, `--head`) before it reaches their context. On GitHub tasks
  that halved input tokens against GitHub's MCP server, and cost went from
  $1.87 to $0.39 over 25 runs ([bench](bench/REPORT.md)).
- **Works in the MCP clients you already use.** The same services are MCP
  tools too: `wires mcp` over stdio (Claude Desktop, IDEs), and
  `wires gateway` as a remote MCP server that Claude.ai adds as a custom
  connector (MCP 2026-07-28, and the older `initialize` clients). A web user
  signs in with Google through the gateway; the host checks Google's
  signature for that person itself, admits them only through registry roles
  that match their identity, and records them as the verified principal of
  a call the gateway's node dialed. `wires call` stays the efficient path:
  the token savings above come from it.
- **Your IdP says who's calling.** `wires login` signs in with your OIDC
  provider and ties that sign-in to the agent's key. Every host checks the
  IdP's signature itself: a CLI caller has no wires account and no auth
  server in the way (the web gateway runs one, for MCP clients), and the CLI
  being run has no auth code.
- **Discovery by who you are.** An admin signs one registry: the services,
  the machines that run each, and the roles (matched on IdP identity, e.g.
  `*@acme.com`) that may call each. An agent's machine holds only its view,
  the services its person may use, and `wires services` lists them. The
  agent never names a machine, and a service with two hosts keeps answering
  when one is down.
- **Both directions.** The agent calls the host, and the host can message
  the agent later ("build 41 failed"), addressed by the agent's key, even
  when the agent isn't connected. A service does it with a push capability
  `serve` gives each call, which reaches only that call's caller. `wires
  inbox --wait` sleeps until it lands: 4 turns and about 2 s to react,
  against 9–13 turns of polling ([bench](bench/push/REPORT.md)).
- **Reached by key, and only the services you may call.** wires is built
  on [iroh](https://iroh.computer): machines dial each other by public key
  over QUIC, directly or through a relay. The caller gets a path to the
  services the signed registry lets its person call, and to nothing else on
  that machine. Any key can open a connection, but one the registry doesn't
  name is refused at its first message, before anything runs.

Since every call runs on a host that has checked who is calling, the host
also keeps a signed record of each call. Agents can't see each other's
work: a caller sees only the records of its own person (its verified
identity, from any of that person's machines). The people the registry names
as a service's readers see all of its records, in full (arguments, the
first 4 KiB of stdin, exit codes), with `wires watch`, for logging and
compliance.

![The loopback demo, narrated](docs/media/demo-remote-cli.gif)

*A recording of `./.scripts/demo-remote-cli.sh`: five keystores on one
machine over loopback, signing in through a mock IdP, not the two-machine run
([MP4](docs/media/demo-remote-cli.mp4)).*

## A quick tour

```console
# admin: one signed registry, published by key to a directory
admin$ wires init --client-id <your Google OAuth client id>
admin$ wires role set analyst '*@acme.com'
admin$ wires invite <node-id> --name workbench     # and one per machine
admin$ wires directory add workbench               # it also holds the registry for the others
admin$ wires service add orders-db --description "Read-only SQL over orders" \
         --allow analyst --host workbench

# host: how it runs the services the registry gives it
workbench$ wires join <token>
workbench$ wires serve host.json

# agent: sign in once, then call by name
agent$ wires join <token>
agent$ wires login                  # browser sign-in; the invite named the IdP
agent$ wires services
orders-db  Read-only SQL over orders  (analyst)
agent$ wires call orders-db -- "select count(*) from orders"
count(*)
--------
       7

# later, a CI job that call started messages the agent back by its key
# (serve gave the job a push capability that reaches only this caller)
workbench$ wires push --to "$WIRES_CALLER_NODE" --subject build-41 -- "failed: test_orders_total"
agent$ wires inbox --wait
2026-09-23 21:13:20Z  from host 3ef72b11 (verified)  build-41  failed: test_orders_total
```

The same services work from MCP clients: `wires mcp` in a stdio MCP config,
or `https://<gateway>/mcp` as a Claude.ai connector
([docs/deployment.md § A web gateway](docs/deployment.md#a-web-gateway)).
`wires remove <name>` pushes a ban to the hosts, and each host that has it
refuses that node's next call, with nothing to restart and no shared key to
rotate. An edit that reaches no host fails loudly, and `wires state
push` re-sends it.

## wires and a remote MCP server

Checked against the MCP specification, revision
[2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/changelog).
wires covers only MCP's tools; it has no prompts or resources.

| | Remote MCP server | wires |
|---|---|---|
| **What the agent calls** | A tool: JSON-RPC `tools/call` with a JSON Schema input; the result is content blocks or structured JSON. The protocol defines no client-side field selection, so trimming is up to each server's design. | A CLI: arguments in, stdout and exit code out. The agent trims with the CLI's own flags, or `wires call --jq/--head/--max-bytes`, before output reaches its context. |
| **Who's calling** | Optional OAuth 2.1: each server is a resource server and validates its own tokens. Enterprise IdP policy is an opt-in extension ([Enterprise-Managed Authorization](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization)). | The caller's OIDC ID token, bound to its key and checked by every host against the IdP's published keys. One admin-signed registry says which roles may call which service. |
| **Finding tools** | A configured URL or command per server; `tools/list` may vary with the caller's authorization. The public [MCP Registry](https://modelcontextprotocol.io/registry/about) (preview) lists public servers, not per user. | `wires services`: every service, across all hosts, that the signed registry lets this identity call. |
| **Server → agent** | Over a stream the client opened and holds: a request's response, or `subscriptions/listen` (task status arrives there as `notifications/tasks`; polling `tasks/get` is the default). Reaching a client that isn't connected is [working-group](https://modelcontextprotocol.io/community/triggers-events/charter) work, not in the spec. | The host dials the agent's key, or keeps the message (24 h by default) for its next `wires inbox`, so it works after the call has ended. `wires inbox --wait` blocks until one lands. |
| **Network** | stdio (a local subprocess) or Streamable HTTP (the server listens at a URL the client can reach). | Both sides dial out, by key, over QUIC (iroh), directly or through a relay. No inbound firewall rule on either side, and no TCP listener on the host (`wires login` binds a loopback port for the browser redirect; the optional web gateway listens over HTTPS). |
| **Record of calls** | No audit format; clients SHOULD log tool usage, and trace context can be propagated to OpenTelemetry. | The host signs a hash-linked record of every call and every member's refusal; the registry's readers stream it with `wires watch`, and each caller sees its own person's records. |

## Measured

GitHub tasks, 5 tasks × 5 runs each, every answer correct in every setup
([bench/REPORT.md](bench/REPORT.md)):

| How the agent reached GitHub | Median input tokens | Cost, 25 runs |
|---|---|---|
| GitHub's MCP server | 21,088 | $1.87 |
| `wires call gh`, the agent allowed only `wires` | 10,713 | $0.39 |

The saving is output size, not tool schemas: GitHub's MCP server returned whole API objects,
the CLI filtered first. One model, one MCP server, small n, stripped-down
sessions; an MCP server with field selection would close much of the gap.

Waiting on a mock CI build, 5 runs per setup ([bench/push/REPORT.md](bench/push/REPORT.md)):

| How the agent waited | Turns | Input tokens (median) | Reaction |
|---|---|---|---|
| Polling | 9 → 13 | about 28k → 39k | 20–178 s |
| `wires inbox --wait` | 4 | 15.4k, flat | about 2 s |

## Limits

It's a prototype (see the note at the top). The main limits:

- An agent's machine holds only its view: the services its person may use,
  each signed by the admin. But the hosts and directories hold the whole
  signed registry (every role's matchers, every service and its hosts, every
  ban; no member list), and a directory sees who asks for which view
  ([docs/fabric.md](docs/fabric.md)).
- Memberships and the registry expire (30 days by default) and don't renew
  on their own yet.
- A host can withhold or truncate its own log; tampering and gaps are
  detectable only against a copy a reader already holds.
- Only Google has been tested as the IdP. The web gateway is the one piece
  that listens, and it holds each signed-in user's token until it expires.
- Callbacks go to a caller by key, not yet only to the caller that asked:
  designed, parked ([card 31](docs/board/backlog/31-inbox-delivery.md)).

The full list: [docs/usage.md § Known trade-offs](docs/usage.md#known-trade-offs).

## More

- [docs/usage.md](docs/usage.md): the roles, where each guarantee lives, a
  full walkthrough with output, design choices, locking an agent down to
  `wires`, and the command reference.
- [docs/protocol.md](docs/protocol.md): the protocol spec.
- [docs/executive-summary.md](docs/executive-summary.md): the product in two
  pages.
- [docs/demo.md](docs/demo.md): the two-machine demo script.

```bash
cargo build --release -p wires           # target/release/wires
./.scripts/demo-remote-cli.sh            # the narrated loopback demo (--quiet: assertions only)
```

## License

[MIT](LICENSE).

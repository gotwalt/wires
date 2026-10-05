# wires: executive summary

*2026-10-05. Details: [README](../README.md) · board: [docs/board](board/README.md).*

## What it is

> **Your tools are already CLIs. wires lets any agent in your organization
> run them where they live: `wires login` says who you are (your IdP),
> `wires services` lists what you may use, and `wires call` runs one by
> name, with no port opened and no VPN.**

wires is experimental research code: no security review, and no backwards
compatibility from one version to the next.

## Why CLIs

Agents work best with command lines. Models have seen far more shell than
tool-call JSON; a CLI's output is cut down before it reaches the model's
context (`--jq`, `--json fields`, `head`); and CLIs compose. Others have
found the same direction: Anthropic's
[Code execution with MCP](https://www.anthropic.com/engineering/code-execution-with-mcp)
(2025-11-04) names tool definitions and intermediate results as the two
costs of tool calls; Cloudflare's [Code Mode](https://blog.cloudflare.com/code-mode/)
(2025-09-26) says "LLMs have seen a lot of code. They have not seen a lot of
'tool calls'"; Scalekit's [GitHub benchmark](https://www.scalekit.com/blog/mcp-vs-cli-use)
(2026-03-11) measured 4 to 32 times fewer tokens for the CLI than for
GitHub's MCP server, and argues MCP is still needed for per-user
authorization, tenant isolation and audit trails.

The catch is that a CLI lives on one machine, with its credentials. Three
things stop it from being shared across an organization, and wires is
those three:

- **Who is calling.** The caller signs in with the organization's IdP
  (`wires login`). The ID token is bound to the caller's key and sent with
  every call; the machine that runs the call verifies it itself, with no
  auth server on the call path. Signing in is the whole of joining: you are
  in the network if a role in the policy matches you.
- **How they find it.** One admin-signed policy says which services exist,
  which hosts run each, and which roles (matched on the verified identity,
  e.g. `*@acme.com`) may call each. `wires services` lists only what that
  person may call. Callers name services, never machines or keys.
- **How they reach it.** Every machine is reached by public key, end-to-end
  encrypted, directly or through a relay ([iroh](https://iroh.computer)).
  Both sides dial out: no inbound port, no VPN.

Plus one thing a local CLI can't do: **the service can message its caller
back**. A host sends a message to the caller's key, or holds it until the
caller's next `wires inbox`; an agent waiting in `wires inbox --wait` wakes
when it lands, with no endpoint of its own.

**MCP is a bridge.** `wires mcp` (stdio) and `wires gateway` (a remote MCP
server for Claude on the web) serve the same services to MCP clients, so a
team can start from the clients it has. They carry existing workflows over;
`wires call` is where the savings are, and the bridge should someday be
unnecessary.

## Who does what

- **Admin** (`init`, `role`, `service`, `issuer`, `directory`, `remove`,
  `restore`, `network`, `policy push`): holds the root key and signs the
  policy. Every edit is a new version, published by key to the network's
  directories. `wires network` prints the one string every machine joins
  with; it is not secret.
- **Host** (`join`, `serve host.json`, `push`): runs the services the policy
  assigns it. `host.json` says how each runs (a fixed command; the caller's
  arguments are appended, with no shell) and can add stricter local rules.
  It decides every call from its own copy of the policy.
- **Caller** (`login`, `services`, `call`, `inbox`, `mcp`, `gateway`): the
  agent, or the MCP client it runs in. It holds only its view: the services
  its person may call.
- **Directory** (usually a host doubling as one): holds the newest policy,
  hands it to hosts, cuts each caller its view, and signs a timestamp
  saying the policy is current, which a caller needs before it tells a host
  anything. It never decides a call.

## What's been shown

- **Two machines, 2026-09-23, on an earlier design:** a laptop and a Linux
  workstation reached by key through public relays, the host with no TCP
  listener and no opened port. After a real Google sign-in, a Claude Code
  session allowed to run only `wires` found the service, queried a remote
  database and answered correctly. A removal cut it off at its next call.
- **The current code, on one machine:** the first run in the README, every
  step exiting 0 and none repeated; a service with two hosts that keeps
  answering when one is down (for up to 15 minutes there, since the one
  down is the only other directory); a host pushing "build 41 failed" to the agent
  that started the build; a removed person refused at their next call (exit
  77). `.scripts/demo-remote-cli.sh` and `.scripts/demo-push.sh` check all
  of it on every run.
- The two-machine run on the current code, and its recording, are next
  ([card 08](board/doing/08-demo-two-machine.md)).

## What's been measured

Runs from 2026-09-23, on an earlier version of wires. GitHub tasks, 5 tasks
× 5 runs per setup, every answer correct ([bench/REPORT.md](../bench/REPORT.md)):

| How the agent reached GitHub | Median input tokens | Cost, 25 runs |
|---|---|---|
| GitHub's MCP server (tool search on, the default) | 21,088 | $1.87 |
| bare `gh` | 6,997 | $0.42 |
| `wires call gh`, the agent allowed only `wires` | 10,713 | $0.39 |

The gap is results, not schemas: with tool search on, the schemas cost about
400 tokens (about 10.2k with it off). The MCP server returned whole API
objects (a 48 KB release body), the CLI let the model pick fields first.
Bare `gh` did a little better than `wires call gh`: the saving belongs to the
CLI, and wires makes the CLI reachable. **Caveats:** one model, one MCP
server, n = 5, stripped-down sessions; a leaner MCP server would close much
of the gap; all five tasks read one service, so nothing here measures
composition.

Waiting on a mock CI build of 60 s or 300 s, 5 runs per setup
([bench/push/REPORT.md](../bench/push/REPORT.md)):

| How the agent waited | Turns | Input tokens (median) | Reaction after the build finished |
|---|---|---|---|
| Polling a status service, or `wires inbox` on a loop | 9 → 13 | about 28k → 39k | 20–178 s |
| `wires inbox --wait` | 4 | 15.4k, flat | about 2 s |

## Limits

- **The admin doesn't approve each machine.** Anyone the IdP verifies (with
  a verified email) and a role matches is in from any machine; a phished sign-in that binds an
  attacker's key would be admitted.
- **The ID token is the only credential.** Google's last about an hour, so
  callers sign in again each hour. Every service a caller calls receives that
  token.
- **No record of calls** beyond one ordinary log line per call in the host's
  output. A signed call record is a possible future design.
- **Hosts share nothing but the policy.** Calls spread at random across a
  service's hosts, so a service that keeps state between calls answers from
  whichever host the call landed on.
- **Hosts and directories hold the whole policy**; a caller holds only its
  view, but a directory sees who asks for which view.
- **Calls need a directory.** A caller sends a host nothing until the host
  shows that a directory other than itself vouched for its policy within 15
  minutes, so with every directory down, calls stop within 15 minutes. That
  is what keeps a removed host from being told anything after that window.
  A directory must also be up to change the policy, remove someone or fetch
  a caller's view.
- **Only Google has been tested** as the IdP.

The full list: [usage.md § Known trade-offs](usage.md#known-trade-offs).

## The next step

Re-run the two-machine demo on the current code, record it, and show it to
people who run remote tools for agents today. The kill criteria on the
[board](board/README.md) decide what follows: if no one wants remote CLIs by
service name, write it up and stop.

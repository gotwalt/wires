# Wires — Executive Summary

*2026-09-23. Replaces the 2026-08-15 summary, which pitched Wires as a group chat for people and their AI assistants. This version describes the pared-back product that the work since then produced and measured. Details: [README](../README.md) · board: [docs/board](board/README.md).*

## The problem

AI agents do their work by running tools. Today there are two ways to give an agent a tool that lives somewhere else, and each is missing something:

- **An MCP server.** A remote server listens at a URL the agent's machine can reach. Each server is its own OAuth resource server and validates tokens itself (IdP-centralized policy is an opt-in extension), and the protocol defines no audit record. Since the 2026-07-28 revision MCP is stateless: a server reaches a client only over a stream that client opened and holds, and long-running work is polled (`tasks/get`) or streamed over that listen stream. Reaching a client that isn't connected is working-group work, not in the spec.
- **A command-line tool.** Models already know CLIs, and CLIs let the agent filter output *before* it reaches context. But a CLI has to be installed next to the agent, together with its credentials, and nothing records who ran what.

Three things organizations are now asking for sit in that gap:

1. **Knowing which person an agent acts for.** Okta shipped "Okta for AI Agents" in April and bought Permiso for about $200M, citing 109 machine identities per human. OWASP's Agentic Top 10 lists per-agent identity, a human owner, least privilege, an immutable audit trail and a kill switch.
2. **Not exposing services.** OpenClaw, the fastest-growing open-source project in GitHub's history, is an agent people message. It produced 2026's first major agent security crisis: 135k exposed instances and one-click RCE.
3. **Records of what agents did.** EU AI Act Articles 12 and 26 made logging of AI system actions a legal requirement on 2 August 2026.

## What Wires is

> **Run a CLI on another machine from your agent, by service name. The machine is reached by public key, never by network path; the caller is authenticated by your IdP and checked against an admin-signed list of who may call what; and the machine that ran each call keeps a signed record of it that the people you name can read, without access to the caller or the machine.**

There are four roles, each with a few commands:

- **Admin** (`init`, `invite`, `remove`, `role`, `service`): signs one versioned document that says who's in, which roles exist (matched on IdP identity), which services exist, which hosts run each one, and who may call and read each. It is pushed to the machines by key.
- **Host** (`wires serve host.json`): implements the services assigned to it. One file says how each runs, which identity providers it trusts, and any stricter local rule; it checks every call against the signed list.
- **Caller** (`join`, `login`, `services`, `call`, `inbox`): the agent. `wires login` binds the person's IdP sign-in (Google in the demo; any OIDC issuer via `--issuer`) to the agent's key once. `wires services` shows only the services that person may call; the caller never names a machine, and a service can have several hosts.
- **Reader** (`watch`): a member the admin allows to read a service's records sees every call and refusal from the hosts' own logs, holding neither end's credentials. Everyone else sees only their own calls.

**The product is the CLI**, and MCP clients aren't left out: `wires mcp` serves the same services over stdio, and `wires gateway` serves them as a remote MCP server that Claude.ai connects to (MCP 2026-07-28 plus older clients). Each web user signs in with Google through the gateway, and every call carries that person's own token, so the host still verifies the IdP itself, admits by the same registry, and records the person as the caller. Adopting wires doesn't mean changing clients.

## What's been demonstrated (two machines, 2026-09-23)

A laptop and a Linux workstation, reached by key through public relays:

- The host had **no TCP listener and no opened firewall port**. Unauthenticated peers are refused at the handshake.
- Before signing in, the agent saw no tools, and calling one by name was refused with the reason. After a real Google sign-in, the tool appeared.
- A Claude Code session in locked mode, whose PATH held `wires` plus the system basics and which was only allowed to run `wires call` and the tool listing, found the tool, queried a remote database and answered correctly. Each query was logged under the person's email and role.
- `wires remove` cut the agent off at once, with no restart and no manual key rotation anywhere, and the refusal was on the log.

That run used the earlier design, where hosts published records to a shared encrypted channel. The current one (services in an admin-signed registry, records kept by each host) passes the same self-checking demo on one machine, plus: a service with two hosts that keeps answering when one is down, a reader who sees every call while the agent sees only its own, and a host **pushing** a message back to the agent that called it ("build 41 failed") with no endpoint on the agent's side, read with `wires inbox`. The two-machine run of this version, and its recording, is in progress ([card 08](board/doing/08-demo-two-machine.md)).

## What's been measured

GitHub tasks, 5 tasks × 5 runs each, all answers correct in every setup:

| How the agent reached GitHub | Median input tokens | Cost, 25 runs |
|---|---|---|
| GitHub's MCP server | 21,088 | $1.87 |
| `wires call gh`, agent limited to `wires` only | 10,713 | $0.39 |

Most of the saving is **not** tool descriptions (Claude Code's tool search already handles those). It's output size: GitHub's MCP server returned whole API objects (48 KB release notes, 52 KB of comments), while a CLI filters first (`--jq`), so the model sees about 256 bytes. With the agent limited to `wires` alone, there were zero permission refusals. **Caveats:** one model, one MCP server, small n, and stripped-down sessions, so real-session percentages will be smaller while the absolute savings carry over. A leaner MCP server would close part of the gap. Details: [bench/REPORT.md](../bench/REPORT.md).

Waiting on long work (a mock CI build of 60 s or 300 s, 5 runs per setup, all correct):

| How the agent waited | Turns | Input tokens (median) | Reaction after the build finished |
|---|---|---|---|
| Polling a status service, or `wires inbox` on a loop | 9 → 13 | about 28k → 39k | 20–178 s |
| `wires inbox --wait` (the host pushes to the agent's key) | 4 | 15.4k, flat | about 2 s |

Checking an inbox on a loop costs exactly what polling costs; the saving comes only from waiting on the push. Details: [bench/push/REPORT.md](../bench/push/REPORT.md).

## Why it's built this way

- **Reached by key.** Tailscale-style networks give the agent's machine a route to the host; Wires gives a route to the services a signed list lets the caller call, and nothing else.
- **Identity is the IdP's own signature**, tied to the agent's key and checked by the host. No Wires-run identity service exists to trust.
- **One signed list, checked locally.** Who's in, the roles and the services are one admin-signed document every machine holds. Hosts decide each call from it with no auth server; callers list what they may call from it. Only the admin can bind a service name to a host.
- **The host writes the log**, signed and hash-linked, so the agent can't forge it, and a reader the admin names needs nothing from either end. Nothing is broadcast: a record leaves a host only when an allowed reader asks.
- **A sandbox that allows only `wires`** gives CLI efficiency with a permission surface as narrow as MCP's. We tested this: a permission rule alone isn't airtight (the agent can still run `cat`, read files, and pass `wires`' own override flags), so `WIRES_LOCKED=1` makes `wires` refuse those flags itself.

## Honest limits

- **Joining an organization is still a hand-issued invite.** Joining by domain ("`wires join acmecorp.com`") is an open question, not yet designed.
- **Every member holds the whole signed list** (member keys, roles, service names). It is signed, not secret. Memberships and the list expire after 30 days and don't renew yet.
- **A host can withhold or truncate its own log.** Tampering and gaps are detectable only against a copy a reader holds (an OTel export, or a witness: [card 09](board/backlog/09-witness.md)).

## The next step

Show the two-machine demo to someone who builds MCP and note which part lands: **verified identity on every call**, **CLI efficiency without a shell**, **push to agents without an endpoint**, or **a call record the agent can't forge, kept by the machine that ran the call**. That answer decides what gets built next.

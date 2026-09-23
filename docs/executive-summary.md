# Wires — Executive Summary

*2026-09-23. Replaces the 2026-08-15 summary, which pitched Wires as a group chat for people and their AI assistants. This version describes the pared-back product that the work since then produced and measured. Details: [README](../README.md) · board: [docs/board](board/README.md).*

## The problem

AI agents do their work by running tools. Today there are two ways to give an agent a tool that lives somewhere else, and each is missing something:

- **An MCP server.** You expose a service on the network so the agent's machine can reach it, and you bolt authentication onto every server separately. Each server keeps its own log, if it keeps one at all. The protocol is strictly request/response: its 2026-07-28 revision removed server-initiated streams, and long-running work is **polled** (`tasks/get`).
- **A command-line tool.** Models already know CLIs, and CLIs let the agent filter output *before* it reaches context. But a CLI has to be installed next to the agent, together with its credentials, and nothing records who ran what.

Three things organizations are now asking for sit in that gap:

1. **Knowing which person an agent acts for.** Okta shipped "Okta for AI Agents" in April and bought Permiso for about $200M, citing 109 machine identities per human. OWASP's Agentic Top 10 lists per-agent identity, a human owner, least privilege, an immutable audit trail and a kill switch.
2. **Not exposing services.** OpenClaw, the fastest-growing open-source project in GitHub's history, is an agent people message. It produced 2026's first major agent security crisis: 135k exposed instances and one-click RCE.
3. **Records of what agents did.** EU AI Act Articles 12 and 26 made logging of AI system actions a legal requirement on 2 August 2026.

## What Wires is

> **Run a CLI on another machine from your agent. The machine is reached by public key, never by network path; the caller is authenticated by your IdP; and every call lands on an encrypted channel that anyone you authorize can watch, without access to the caller or the machine running the CLI.**

There are four roles, each with a few commands:

- **Admin** (`init`, `invite`, `remove`): decides who's in.
- **Host** (`wires serve host.json`): decides what runs and who may run it. One file lists the exposed CLIs, the trusted identity providers, and which roles may use which tool; everything else is denied.
- **Caller** (`join`, `login`, `tools`, `call`, `inbox`): the agent. `wires login` binds the person's Google/Okta sign-in to the agent's key once. `wires tools` shows only the tools that person may use.
- **Observer** (`watch`): sees every call, refusal and identity as it happens, and holds neither end's credentials.

`wires mcp` exists only so clients that can't run a command can still use the same tools. **The product is the CLI.**

## What's been demonstrated (two machines, 2026-09-23)

A laptop and a Linux workstation, reached by key through public relays:

- The host had **no TCP listener and no opened firewall port**. Unauthenticated peers are refused at the handshake.
- Before signing in, the agent saw no tools, and calling one by name was refused with the reason. After a real Google sign-in, the observer verified the identity **itself**, and the tool appeared.
- A Claude Code session in locked mode, whose PATH held `wires` plus the system basics and which was only allowed to run `wires call` and `wires tools`, found the tool, queried a remote database and answered correctly. The observer logged each query under the person's email and role.
- `wires remove` cut the agent off at once, with no restart and no manual key rotation anywhere, and the refusal was on the log.

On one machine so far (the self-checking demo script), a host **pushed** a message back to the agent that called it ("build 41 failed") with no endpoint on the agent's side. The agent read it with `wires inbox`, a plain command any agent can run, including after being offline when it was sent. The two-machine run of push is next.

## What's been measured

GitHub tasks, 5 tasks × 5 runs each, all answers correct in every setup:

| How the agent reached GitHub | Median input tokens | Cost, 25 runs |
|---|---|---|
| GitHub's MCP server | 21,088 | $1.87 |
| `wires call gh`, agent limited to `wires` only | 10,713 | $0.39 |

Most of the saving is **not** tool descriptions (Claude Code's tool search already handles those). It's output size: MCP returns whole API objects (48 KB release notes, 52 KB of comments), while a CLI filters first (`--jq`), so the model sees about 256 bytes. With the agent limited to `wires` alone, there were zero permission refusals. **Caveats:** one model, one MCP server, small n, and stripped-down sessions, so real-session percentages will be smaller while the absolute savings carry over. A leaner MCP server would close part of the gap.

## Why it's built this way

- **Reached by key.** Tailscale-style networks give the agent's machine a route to the host; Wires gives a route to one allowlisted CLI and nothing else.
- **Identity is the IdP's own signature**, tied to the agent's key, and checked by the host and every reader. No Wires-run identity service exists to trust.
- **The host writes the log**, signed and hash-linked, so the agent can't forge it and the observer needs nothing from either end.
- **A sandbox that allows only `wires`** gives CLI efficiency with a permission surface as narrow as MCP's. We tested this: a permission rule alone isn't airtight (the agent can still run `cat`, read files, and pass `wires`' own override flags), so `WIRES_LOCKED=1` makes `wires` refuse those flags itself.

## Honest limits

- **Joining an organization is still a hand-issued invite.** Joining by domain ("`wires join acmecorp.com`") is an open question, not yet designed.
- **Removing someone reveals the remaining member list to them**; memberships expire after 30 days and don't renew yet.
- **Open question:** whether the shared encrypted channel belongs in the core, or whether hosts should emit identity-stamped telemetry (OTel) directly. It turns on whether cross-organization audit or push to offline agents is the product. See [card 22](board/backlog/22-gossip-role-OPEN.md).
- **Any member can currently offer a tool under any name.** An admin-approved host list would close this.

## The next step

Show the two-machine demo to someone who builds MCP and note which part lands: **verified identity on every call**, **CLI efficiency without a shell**, **push to agents without an endpoint**, or **a log the host can't rewrite**. That answer decides card 22 and what gets built next.

# Board — remote CLIs, verified callers, observable calls

**The premise** (the human, 2026-09-23), which defines "correct": remote CLIs
are distributed securely over iroh; IdP authentication and authorization keep
out anyone who isn't allowed; agents can't observe each other's work (the
isolation boundary is the verified person, the IdP principal); and `wires
watch` lets the people the registry names as readers observe calls, in full,
for logging and compliance.

**Non-negotiables:** E2EE with a blind relay
(no host or relay holds a key it doesn't need; a service child is handed none
of the host's keystore, card 28, though it still runs as the host's user until
[card 32](backlog/32-service-sandbox-OPEN.md)); offline-verifiable membership
(no auth-server round-trip; removal is a root-signed ban that takes effect at
each host's next dial, card 35); **the premise
outranks the docs, and the docs outrank the code** (README and docs first,
code second: a disagreement is a code bug unless the doc breaks the
premise). **Kill criteria:** if no one wants
remote CLIs by key after the recorded demo, write it up and stop; if wires is
something we demo but never use ourselves, mothball it with a postmortem; if
MCP or A2A ships portable user identity plus infra-level call records, narrow
to what's still unserved or call it obsolete.

## The one idea

> **Run a CLI on another machine from your agent, by service name. The
> machine is reached by public key, never by network path; the caller is
> authenticated by your IdP and checked against an admin-signed list of who
> may call what; and the machine that ran each call keeps a signed record of
> it that the people you name can read — without access to the caller or the
> machine.**

Why each clause earns its place (the rebuttals it has to survive):

| Claim | Why it isn't "just use X" |
|---|---|
| **Reached by key, not network path** | Tailscale/VPN gives the agent's machine a route to the *host*; you then trust every port on it. Wires gives a route to *the services a signed list lets you call* and nothing else — there is no network path to widen. |
| **By service name** | The caller asks for `orders-db`, not a machine; the admin binds names to hosts (failover, moves, no squatting), and the caller never names or configures an address (iroh may still find a direct path, and a host's `run/hint` holds one). |
| **CLIs first; MCP too** | CLIs are the idiom models already know, one generic verb, and output is filtered *before* it hits context — measurably cheaper than MCP tool schemas + JSON results, even post-2026-07-28; `wires call` is that path. `wires mcp` (stdio) and `wires gateway` (a remote MCP server, for Claude.ai) serve the same services as MCP, so wires works in the clients people already use. What differs from any other MCP server: the host, not the server in front of it, verifies the caller's IdP token and checks the one signed registry, and the host keeps the signed record. |
| **IdP-authenticated caller, one signed list** | The ID token is bound to the node key (OIDC `nonce` = hash of the key) and presented in each call's handshake; the host verifies the IdP's signature itself (no wires attestor) and checks it against the admin-signed registry — one list of who may call what, not one per server. |
| **Recorded at the infra layer** | The *host* writes a signed, hash-chained record of every call, member's refusal, and exit — stamped with the caller identity it verified. The agent can't forge it, no gateway owns it, and a reader the registry names holds neither end's credentials. A CLI has no such story; an MCP gateway's log belongs to whoever runs the gateway. |

**Pitch rule:** every sentence in README / demo narration must survive one
honest line from someone who runs remote MCP servers behind Tailscale today.
(See [storytelling.md](../storytelling.md) §1.)

## Roles (card 27)

| Role | Decides | Commands |
|---|---|---|
| **admin** | who's in, the trusted IdPs, the roles, which services run where, who may call and read each, which nodes are directories (root key; one signed policy) | `init`, `invite`, `remove`, `issuer`, `role`, `service`, `directory add\|rm`, `policy push`, `policy settings` |
| **host** | how it implements its assigned services; stricter local rules (`host.json`: narrower IdPs, `also_require`) | `serve host.json`, `push` |
| **caller** | — runs services by name; MCP (stdio, or the remote gateway) so wires works in the clients people already use | `id`, `join`, `login`, `services`, `call`, `mcp`, `gateway`, `inbox` |
| **reader** | — any member: a service's `readers` role reads all its records, in full; everyone else their own person's (same issuer and subject, from any node) | `watch` |
| **directory** (card 36) | nothing: it holds the newest root-signed policy, signs its freshness, and hands the policy to hosts (whole once, then deltas by subscription) and callers (their view: the services each may use, cut for its verified ID token); it never decides a call | `serve` (when the policy lists it), `directory serve`; the admin names directories with `directory add\|rm` |

The IdP is *bound* at the caller (`login`) and *verified* at the host, against the admin-signed policy it holds. Every role needs a verified identity (there is no built-in `member` role), and every matcher names an issuer the policy trusts. The admin's invite is the only thing handed out of band (a caller's is its badge, directory ids and the IdP to sign in with, under 1 KB); every later policy is published by key to the directories, hosts follow it from one, and each caller holds only its view, refreshed when a call's handshake shows a newer head or followed by subscription (`wires mcp`, the gateway, `inbox --wait`). Nothing is broadcast; hosts and directories hold the whole policy ([fabric.md](../fabric.md): how the network is hosted, persisted and kept in sync).

## The demo we're building toward

1. **workbench** (no inbound ports): `wires serve host.json`, implementing `orders-db`, which the admin registered for role `analyst` (`wires service add orders-db --allow analyst --reader security --host workbench`).
2. **laptop**: Claude Code calling `wires call orders-db -- "…"` from Bash (and/or `wires mcp` in its MCP config).
3. **reader** (third terminal/machine, role `security`): `wires watch orders-db` — each call appears as `▶ … alice@corp (…) [analyst] orders-db "select …"`, then `■ … exit 0 · 41 ms · 3.1 KiB out`.
4. **Revoke**: one `wires remove agent` → the new policy is published to the directory the workbench also runs, and the workbench refuses the agent's next call (exit 77, `denied by host: not a member of this network`); the host traces that rather than logging it, since a banned key can't write to the log.

## Lanes

Open cards only; finished cards are in [done/](done/).

| Card | Lane | Depends on | Status | Summary |
|---|---|---|---|---|
| [08](doing/08-demo-two-machine.md) | E | — | doing | Real run: laptop ↔ workbench over relay, Claude Code as the agent, recording |
| [29](backlog/29-person-identity.md) | I2 | 36 | backlog | **Person identity for headless agents:** `login --for`, day-passes issued by a directory |
| [31](backlog/31-inbox-delivery.md) | P3 | 28, 30 | designed, parked | **Inbox delivery:** callbacks go to the caller that asked, through the call's push capability only; open questions on the card |
| [32](backlog/32-service-sandbox-OPEN.md) | — | — | open question | **Don't build:** run each service call in a rootless microVM so a service can't reach the host's keys |
| [18](backlog/18-front-door-OPEN.md) | — | — | open question | **Don't build:** front door, `wires join <domain>` (now pointing at the directory) |
| [09](backlog/09-witness.md) | R | 36 | backlog | **Transparency-log records:** Merkle call logs with checkpoints the directory witnesses; no hidden links for non-readers |

**Order:** 08 (recording; re-record the README demo) → 29 → 09. 31 and 32 are not scheduled.
The directory update (cards 35–38: badges and bans, the directory, caller views, help text for
LLMs; the why is [`bench/state-scale/REPORT.md`](../../bench/state-scale/REPORT.md)) is done.

## Rules for workers

- **Move your card**: `git mv docs/board/backlog/NN-*.md docs/board/doing/` when you start, to `review/` when your acceptance list is green. Only the integrator moves cards to `done/`.
- **Stay in your lane's files** (listed per card). If you must touch another lane's file, keep the diff minimal and say so in the card's *Notes* section.
- **CLAUDE.md order**: types/signatures → tests (proptest + examples, red) → implement → doctests → readability pass. Cargo: `cargo test --workspace`, `make lint` (clippy `-D warnings` + shellcheck) and `cargo fmt --check` green before `review/`.
- **Errors**: `library` uses `thiserror` (`library/error.rs`); the binary uses `anyhow`. Newtypes, not primitives, on public APIs.
- **Don't** merge from `archive/poc-2026-05` (reference it freely).
- Append what you learned / decided to the card's *Notes*; the integrator reads them at merge.

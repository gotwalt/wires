# Board — remote CLIs, verified callers, observable calls

*Opened 2026-09-22. Supersedes the phase plan in [restart.md](../restart.md)
for the current push; restart.md's non-negotiables (§7) still hold.*

## The one idea

> **Run a CLI on another machine from your agent. The machine is reached by
> public key, never by network path; the caller is authenticated by your IdP;
> and every call lands on an encrypted gossip channel that anyone you
> authorize can watch — without access to the caller or the machine
> running the CLI.**

Why each clause earns its place (the rebuttals it has to survive):

| Claim | Why it isn't "just use X" |
|---|---|
| **Reached by key, not network path** | Tailscale/VPN gives the agent's machine a route to the *host*; you then trust every port on it. Wires gives a route to *one allowlisted CLI* and nothing else — there is no network path to widen. |
| **CLIs, not MCP servers** | CLIs are the idiom models already know, one generic verb, and output is filtered by pipes *before* it hits context — meaningfully more efficient than MCP tool schemas + JSON results, even post-2026-07-28. `wires call` is the native path; `wires mcp` is the on-ramp for workflows that only speak MCP. |
| **IdP-authenticated caller** | The ID token is bound to the node key (OIDC `nonce` = hash of the key) and published on the channel. Every reader verifies the IdP's signature *itself* — no wires attestor to trust, and two orgs' IdPs can share one channel (federation). |
| **Observable at the infra layer** | The *responder* writes a signed, hash-chained record of every call, refusal, and exit — stamped with the caller identity it verified. The agent can't forge it, no gateway owns it, and an observer holds neither end's credentials. A CLI has no such story; an MCP gateway's log belongs to whoever runs the gateway. |

**Pitch rule:** every sentence in README / demo narration must survive one
honest line from someone who runs remote MCP servers behind Tailscale today.
(See [storytelling.md](../storytelling.md) §1.)

## Roles (2026-09-23)

| Role | Decides | Commands |
|---|---|---|
| **admin** | who's in (root key) | `init`, `invite`, `remove` |
| **host** | what runs and who may run it (`host.json`: tools + IdP policy) | `serve host.json` |
| **caller** | — runs remote CLIs; MCP only for backward compatibility | `join`, `login`, `call`, `tools`, `mcp` |
| **observer** | — | `watch` |

The IdP is *bound* at the caller (`login`), *enforced* at the host (`host.json`), and *verified independently* by every reader of the channel. The channel carries host announcements, identity claims, and call records; the admin's invite is the only thing handed out of band.

## The demo we're building toward

1. **workbench** (no inbound ports): `wires serve --expose db_query=… --audit-topic ops --require-idp …`
2. **laptop**: Claude Code, with `wires mcp` in its MCP config (and/or calling `wires call db_query …` from Bash).
3. **observer** (third terminal/machine): `wires tail ops` — each call appears live as `alice@corp ran db_query "select …" → exit 0, 41 ms, 3.1 KiB`.
4. **Revoke**: one `wires roster commit` → the agent's next call is refused, and the refusal is itself on the channel.

## Lanes

| Card | Lane | Depends on | Summary |
|---|---|---|---|
| [00](done/00-shared-types.md) | 0 | — | Shared types: `Invocation`, `AuditRecord`, `IdentityClaim`, `ChannelRecord`, `ServeConfig.{tools,audit}`, `tools.json` |
| [01](done/01-serve-expose.md) | A | 00 | `serve --expose name=cmd`: multi-tool responder, per-call argv |
| [02](done/02-audit-channel.md) | B | 00 | `serve --audit-topic`: responder hosts the topic node, publishes call records; `tail` renders them |
| [03](done/03-client-call-and-mcp.md) | C | 00 | `wires call` + `wires mcp` (stdio MCP server) over `tools.json` |
| [04](done/04-idp-login.md) | F | 00 | `wires login` (Google OIDC, nonce-bound), claim published on channel, independent verification |
| [05](done/05-idp-policy.md) | F | 01, 02, 04 | `serve --require-idp`: gate on verified claims; principal in audit records |
| [06](done/06-cleanup-and-pitch.md) | D | — | Cut noise, README rewritten around the one idea, restart.md reconciled |
| [07](done/07-demo-local.md) | E | 01–05 | Self-asserting loopback demo script (the gate for the two-machine run) |
| [08](doing/08-demo-two-machine.md) | E | 07 | Real run: laptop ↔ workbench over relay, Claude Code as the agent, recording |
| [10](done/10-live-run-fixes.md) | G | 01–04 | Live-run fixes: stdin in call records, quiet stderr, short control-socket path |
| [11](done/11-camera-blockers.md) | H | 04, 05, 07 | Camera blockers: 20 s audit stall after login, Safari callback error, `tools add --topic-ticket` |
| [12](done/12-roles-and-tree.md) | R | 11 | Organize by role: 4-role CLI (`advanced` for plumbing), role folders, drop single-command serve/connect + old demos |
| [13](done/13-host-json-policy.md) | P | 12 | `host.json`: tools + IdP roles + default deny; `Policy` seam for org rules later |
| [14](done/14-invite-join.md) | O | 12 | `init` / `invite` / `join` / `remove`; re-key distributed over the channel |
| [15](done/15-channel-directory.md) | D2 | 12, 13 | Hosts announce tools on the channel; callers resolve by name — one invite is the only out-of-band step |
| [17](done/17-readme-why.md) | docs | 12–16 | README: four roles, where each guarantee lives, why it's built this way; `docs/demo.md` |
| [19](done/19-no-shell-caller.md) | S | 12 | No-shell caller: `wires call --jq/--head/--max-bytes` in-process; wires-only sandbox recipe; benchmark arm 5 |
| [20](done/20-locked-caller.md) | S2 | 19 | Locked caller mode: `WIRES_LOCKED=1` rejects override flags so a sandboxed agent can't steer `wires call` |
| [21](done/21-camera-polish.md) | P2 | 12–20 | Camera polish: heartbeat noise, quiet admin commands, clear removal reason, seal announcements only to current members |
| [23](backlog/23-inbox.md) | I | 21 | Push to callers: `wires inbox` (local read / `--wait`), host `wires push`, queue + dial-back by key, `host.json` `push` roles, audited |
| [24](backlog/24-push-demo.md) | E2 | 23 | Push demo (deploy → callback → follow-up) + push-vs-poll benchmark |
| [25](backlog/25-cargo-and-strip.md) | X | 23, 24 | Down to essentials: Bazel → plain Cargo + Dockerfile; remove grants/tickets/CRL/relay/manual targets the product no longer uses |
| [22](backlog/22-gossip-role-OPEN.md) | — | parked | **Open question, don't build:** does the core need gossip? Admin-signed host list + direct discovery + OTel sinks; notes the tool-name-squatting weakness |
| [18](backlog/18-front-door-OPEN.md) | — | parked | **Open question, don't build:** apex key, invites, `wires join <domain>` |
| [16](done/16-token-benchmark.md) | bench | 01–03 | MCP (GitHub server, many tools; ± tool search) vs `gh` via `wires call` vs bare `gh`: 5 tasks × 5 runs |
| [09](backlog/09-witness.md) | stretch | 02 | Key-less witness: stores and verifies call records without decrypting them |

## Rules for workers

- **Move your card**: `git mv docs/board/backlog/NN-*.md docs/board/doing/` when you start, to `review/` when your acceptance list is green. Only the integrator moves cards to `done/`.
- **Stay in your lane's files** (listed per card). If you must touch another lane's file, keep the diff minimal and say so in the card's *Notes* section.
- **CLAUDE.md order**: types/signatures → tests (proptest + examples, red) → implement → doctests → readability pass. Bazel only. `bazel test //...`, `aspect lint //...` and `bazel run //tools/format:format.check` green before `review/`.
- **Errors**: `library` uses `thiserror` (`library/error.rs`); the binary uses `anyhow`. Newtypes, not primitives, on public APIs.
- **Don't** touch `archive/poc-2026-05`, the relay package, or anything iOS.
- Append what you learned / decided to the card's *Notes*; the integrator reads them at merge.

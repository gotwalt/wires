# Board — remote CLIs, verified callers, observable calls

*Opened 2026-09-22. Supersedes the 2026-08-13 restart plan (deleted by card
25; it is in the git log).*

**The premise** (the human, 2026-09-23), which defines "correct": remote CLIs
are distributed securely over iroh; IdP authentication and authorization keep
out anyone who isn't allowed; agents can't observe each other's work (the
isolation boundary is the verified person, the IdP principal); and `wires
watch` lets the people the registry names as readers observe calls, in full,
for logging and compliance.

**Non-negotiables** (carried over from the restart): E2EE with a blind relay
(no host or relay holds a key it doesn't need; a service child is handed none
of the host's keystore, card 28, though it still runs as the host's user until
[card 32](backlog/32-service-sandbox-OPEN.md)); offline-verifiable membership
(no auth-server round-trip; removal is a root-signed ban that takes effect at
each host's next dial, decided 2026-09-24, built by card 29; until then,
removal by omission); **the premise
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
| **admin** | who's in, the roles, which services run where, who may call and read each (root key; one signed state) | `init`, `invite`, `remove`, `role`, `service`, `state push` |
| **host** | how it implements its assigned services; trusted IdPs; stricter local rules (`host.json` v2) | `serve host.json`, `push` |
| **caller** | — runs services by name; MCP (stdio, or the remote gateway) so wires works in the clients people already use | `join`, `login`, `services`, `call`, `mcp`, `inbox`, `gateway` |
| **reader** | — any member: a service's `readers` role reads all its records, in full; everyone else their own person's (same issuer and subject, from any node) | `watch` |

The IdP is *bound* at the caller (`login`) and *verified* at the host, against the admin-signed state it holds. Every role needs a verified identity (there is no built-in `member` role), and every matcher names its issuer. The admin's invite is the only thing handed out of band; every later state is pushed by key to the hosts, and other members pull it from a host (or get it in a call's handshake). There is no channel, but every member still holds the whole state: card 29.

## The demo we're building toward

1. **workbench** (no inbound ports): `wires serve host.json`, implementing `orders-db`, which the admin registered for role `analyst` (`wires service add orders-db --allow analyst --reader security --host workbench`).
2. **laptop**: Claude Code calling `wires call orders-db -- "…"` from Bash (and/or `wires mcp` in its MCP config).
3. **reader** (third terminal/machine, role `security`): `wires watch orders-db` — each call appears as `▶ … alice@corp (…) [analyst] orders-db "select …"`, then `■ … exit 0 · 41 ms · 3.1 KiB out`.
4. **Revoke**: one `wires remove agent` → the new state is pushed to the workbench, which refuses the agent's next call (exit 77, `not admitted to this fabric`); the host traces that rather than logging it, since a key outside the state can't write to the log.

## Lanes

Each summary describes the surface at the time the card was done. Cards 25–27 deleted the channel (gossip topics, announcements, re-keys), `serve --expose`, `--audit-topic` and `wires tail`; the current surface is in [protocol.md](../protocol.md) and the [demo script](../demo.md).

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
| [23](done/23-inbox.md) | I | 21 | Push to callers: `wires inbox` (local read / `--wait`), host `wires push`, queue + dial-back by key, `host.json` `push` roles, audited |
| [24](done/24-push-demo.md) | E2 | 23 | Push demo (deploy → callback → follow-up) + push-vs-poll benchmark |
| [25](done/25-cargo-and-strip.md) | X | 23, 24 | Down to essentials: Bazel → plain Cargo + Dockerfile; remove grants/tickets/CRL/relay/manual targets and outdated docs (git history is the archive) |
| [27](done/27-services-not-hosts.md) | S3 | 25 | **Services, not hosts; drop the channel.** Admin-signed members + service registry; local `wires services`; identity in the handshake; delete gossip/fabric keys/re-keys/announcements (~20k LOC) |
| [26](done/26-host-held-records.md) | H2 | 27 | Call records: host-held signed log, `watch <service>` for authorized readers + own calls, optional OTel export |
| [28](done/28-audit-fixes.md) | A | 27, 26 | **Audit fixes (2026-09-23):** drop `member`, issuer-scoped matchers, service child can't reach host secrets (per-call push capability), fail-closed log, pre-auth caps, person-keyed records and re-decided `watch` streams, state-sync and caller fixes, docs sweep. Push delivery moved to 31 |
| [29](backlog/29-identity-and-scale.md) | I2 | 28 | **Identity and scale (design agreed):** machine badges + banned list, `login --for` + day-pass, per-caller views served by hosts, transparency-log checkpoints |
| [30](done/30-web-gateway.md) | W | 27, 26 | `wires gateway`: remote MCP (Streamable HTTP 2026-07-28 + OAuth 2.1) for Claude.ai; each call presents the web user's own gateway-bound Google token |
| [31](backlog/31-inbox-delivery.md) | P3 | 28, 30 | **Parked 2026-09-24** (open questions on the card; the blocker is how a caller learns which services call back). Design as agreed 2026-09-24, not built: callbacks go to the caller that asked (node + principal), through the call's push capability only; operator push `--to <node-id>` only; at least once to its mailbox; fetch set complete by construction; an `inbox` MCP tool in `wires mcp` and the gateway. Replaces card 28 §4 (push half) and §7 |
| [22](done/22-gossip-role-OPEN.md) | — | decided | **Decided 2026-09-23: drop the channel** → cards 27 and 26 |
| [32](backlog/32-service-sandbox-OPEN.md) | — | parked | **Open question, don't build:** run each service call in a rootless microVM (Firecracker or equivalent) so a service can't reach the host's keys |
| [18](backlog/18-front-door-OPEN.md) | — | parked | **Open question, don't build:** apex key, invites, `wires join <domain>` |
| [16](done/16-token-benchmark.md) | bench | 01–03 | MCP (GitHub server, many tools; ± tool search) vs `gh` via `wires call` vs bare `gh`: 5 tasks × 5 runs |
| [09](backlog/09-witness.md) | stretch | 26 | Witness: a reader that follows hosts' call logs and exports signed checkpoints, so a truncation or rewrite contradicts a copy the host doesn't control |

**Order (agreed 2026-09-23):** 24 → 25 (Cargo + strip) → 27 (services, not hosts; drop the channel) → 26 (host-held records) → recording (08, in progress: workbench on HEAD, dry run, record; see its Steps). **Then (2026-09-23 audit; order decided 2026-09-24):** 28 → 29 (identity and scale). 31 (inbox) is parked (2026-09-24) and 32 (service sandbox) is open; neither is scheduled.

## Rules for workers

- **Move your card**: `git mv docs/board/backlog/NN-*.md docs/board/doing/` when you start, to `review/` when your acceptance list is green. Only the integrator moves cards to `done/`.
- **Stay in your lane's files** (listed per card). If you must touch another lane's file, keep the diff minimal and say so in the card's *Notes* section.
- **CLAUDE.md order**: types/signatures → tests (proptest + examples, red) → implement → doctests → readability pass. Cargo: `cargo test --workspace`, `make lint` (clippy `-D warnings` + shellcheck) and `cargo fmt --check` green before `review/`.
- **Errors**: `library` uses `thiserror` (`library/error.rs`); the binary uses `anyhow`. Newtypes, not primitives, on public APIs.
- **Don't** touch `archive/poc-2026-05`, the relay package, or anything iOS.
- Append what you learned / decided to the card's *Notes*; the integrator reads them at merge.

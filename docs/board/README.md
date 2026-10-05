# Board — CLIs on other machines, for agents

**The premise** (the human, 2026-10-05), which defines "correct": agents work
best with CLIs. wires lets an agent run a CLI that lives on another machine
as if it were local. The caller is a person your IdP verified; they see and
can call only the services an admin-signed policy grants them; the machine is
reached by key, with no port or VPN; and a service can message its caller
back. MCP clients reach the same services through a bridge.

This replaces the premise of 2026-09-23. What changed, and why, is on cards
39–43 and 47 in [done/](done/): the signed call log and `wires watch` are cut
for now, a caller is admitted by its person's IdP sign-in and nothing else
(no badges, no invites; a role must match), and MCP is a bridge from existing
workflows, not a goal of its own. The code matches this page;
[card 43](done/43-accuracy-sweep.md) lists what was checked and what is left
for the human.

**Non-negotiables:** E2EE with a blind relay (no host or relay holds a key
it doesn't need; a service child is handed none of the host's keystore,
though it still runs as the host's user until
[card 32](backlog/32-service-sandbox-OPEN.md)); no auth-server round-trip on
a call (the host verifies the IdP's signature itself and decides from its own
copy of the signed policy); a user never handles a service's or a host's
key (the admin does, once per machine); **the premise outranks the docs, and
the docs outrank the code** (README and docs first, code second: a
disagreement is a code bug unless the doc breaks the premise). **Kill
criteria:** if no one wants remote CLIs by service name after the recorded
demo, write it up and stop; if wires is something we demo but never use
ourselves, mothball it with a postmortem; if MCP ships tool calls that cost
what a CLI costs (results filtered before they reach context, composed
without a round trip through the model) together with org identity and
discovery, narrow to what's still unserved or call it obsolete.

## The one idea

> **Your tools are already CLIs. wires lets any agent in your organization
> run them where they live: `wires login` says who you are (your IdP),
> `wires services` lists what you may use, and `wires call` runs one by
> name, with no port opened and no VPN.**

Why each clause earns its place (the rebuttals it has to survive):

| Claim | Why it isn't "just use X" |
|---|---|
| **CLIs, not tool calls** | Models have seen far more shell than tool-call JSON, a CLI's output is filtered before it reaches context (`--jq`, `--head`, the CLI's own flags), and CLIs compose without a round trip through the model. The MCP side's own fixes point the same way: Anthropic's code execution with MCP and Cloudflare's Code Mode both turn tools back into something the model drives as code. The claim that survives a skeptic is about **results**, not schemas: with tool search on, schemas cost about 400 tokens ([bench/REPORT.md](../../bench/REPORT.md)). |
| **Signed in with your IdP** | The ID token is bound to the caller's key (OIDC `nonce` = hash of the key) and presented in each call's handshake; the host verifies the IdP's signature itself and checks one admin-signed policy of who may call what. Signing in is the whole of joining: there is no per-machine invite. The service gets the caller's identity too (`WIRES_ID_TOKEN`, and the verified claims). |
| **By service name** | SSH, Tailscale SSH and Teleport give a person a login on a machine. wires gives a person a named service, wherever it runs: the caller asks for `orders-db`, the admin binds names to hosts, `wires services` is the catalog, and no account or shell exists on the host. |
| **Reached by key** | Tailscale gives the agent's machine a route to the host; you then trust every port on it. wires gives a route to the services the signed policy lets that person call and nothing else. Both sides dial out. |
| **The service can message back** | A webhook needs the receiver to listen; an agent on a laptop can't. MCP reaches a client only over a stream the client holds open. A wires host pushes to the caller's key, or holds the message for its next `wires inbox`. |
| **MCP is a bridge** | `wires mcp` (stdio) and `wires gateway` (remote, for Claude on the web) serve the same services to MCP clients, so a team can start from the clients it has. They exist to carry existing workflows over; `wires call` is where the savings are, and the bridge should someday be unnecessary. |

**Pitch rule:** every sentence in README / demo narration must survive one
honest line from someone who runs remote MCP servers behind Tailscale today.
(See [storytelling.md](../storytelling.md) §1.)

## Roles

| Role | Decides | Commands |
|---|---|---|
| **admin** | the trusted IdPs, the roles, which services run where, who may call each, who is removed, which nodes are directories (root key; one signed policy) | `init`, `network`, `issuer`, `role`, `service`, `directory add\|rm`, `remove`, `restore`, `policy push`, `policy settings` |
| **host** | how it implements its assigned services; stricter local rules (`host.json`) | `join`, `serve host.json`, `push` |
| **caller** | — runs services by name; MCP (stdio, or the remote gateway) as the bridge | `id`, `login`, `services`, `call`, `inbox`, `mcp`, `gateway` |
| **directory** | nothing: it holds the newest root-signed policy and hands it whole to hosts and to each caller as its view (the services that caller may use, cut for its verified ID token); it never decides a call | `join`, `serve` (when the policy lists it), `directory serve` |

A caller joins by signing in: `wires login <network>`, where the network
string (the root key, the directory ids, the sign-in settings) is the same
for everyone and not secret. Hosts and directories are named by key in the
signed policy, by the admin. Every role needs a verified identity, and every
role matcher names its issuer. Hosts and directories hold the whole policy;
a caller holds only its view ([fabric.md](../fabric.md)).

## The demo we're building toward

1. **workbench** (no inbound ports): `wires serve host.json`, implementing `orders-db`, which the admin registered for role `analyst`.
2. **laptop**: `wires login <network>`, then Claude Code calling `wires call orders-db -- "…"` from Bash.
3. **The host calls back**: a job the call started pushes "build 41 failed" to the agent's key; `wires inbox --wait` wakes.
4. **Remove**: one `wires remove alice@acme.com` → the new policy reaches the workbench through its directory, and the workbench refuses her next call (exit 77).

## Lanes

Open cards only; finished cards are in [done/](done/).

| Card | Stage | Depends on | Status | Summary |
|---|---|---|---|---|
| [08](doing/08-demo-two-machine.md) | last | all of the above | doing | Real run: laptop ↔ workbench over relay, Claude Code as the agent; re-record |
| [29](backlog/29-person-identity.md) | — | — | backlog, not scheduled | **Person identity for headless agents:** `login --for`, day-passes |
| [31](backlog/31-inbox-delivery.md) | — | — | designed, parked | **Inbox delivery:** callbacks go to the caller that asked; one delivery path |
| [32](backlog/32-service-sandbox-OPEN.md) | — | — | open question | **Don't build:** run each service call in a rootless microVM |
| [18](backlog/18-front-door-OPEN.md) | — | — | open question | **Don't build:** `wires login <domain>`, the network string published under a domain |

**Order** (the human, 2026-10-05): 44, 46, 48, 49 and 45 are done, and
the narrative docs and `CLAUDE.md` match them (the goal sentence's new
wording awaits the human's OK); next is 08, the demo, last. **For 08:** with
the workbench and the spare both host and directory, the spare answers with
the workbench down only while its last word is current (15 minutes); a
directory-only node would remove that limit ([demo.md](../demo.md) step 5b). **Skipped for now:** re-running the benchmarks
(not run on this code; their setup signs in once and a Google sign-in lasts
an hour). What else the last pass left open is in
[card 43](done/43-accuracy-sweep.md)'s Notes. 39–50 are done.

## Rules for workers

- **Move your card**: `git mv docs/board/backlog/NN-*.md docs/board/doing/` when you start, to `review/` when your acceptance list is green. Only the integrator moves cards to `done/`.
- **Stay in your lane's files** (listed per card). If you must touch another lane's file, keep the diff minimal and say so in the card's *Notes* section.
- **Who owns which doc** (cards 40–42): a code card updates `docs/protocol.md` first (it is the spec), then the code, its comments, the help text and snapshots, and every script and test that would otherwise break. It does **not** rewrite the narrative docs (README, `usage.md`, `fabric.md`, `executive-summary.md`, `demo.md`, `deployment.md`, `testing.md`, `agent-sandbox.md`, the blog post): it lists every statement it made false in its card's *Notes*, and cards 39 and 43 rewrite them once.
- **CLAUDE.md order**: types/signatures → tests (proptest + examples, red) → implement → doctests → readability pass. Cargo: `cargo test --workspace`, `make lint` (clippy `-D warnings` + shellcheck) and `cargo fmt --check` green before `review/`. Where `shellcheck` / `shfmt` aren't installed: `uvx --from shellcheck-py shellcheck …` and `uvx --from shfmt-py shfmt …`.
- **A deletion is finished when nothing mentions it.** After removing a concept, grep for its names (types, files, flags, env vars, the words in comments and error text) and fix or delete every hit in your lane; list the ones outside it in *Notes*.
- **Errors**: `library` uses `thiserror` (`library/error.rs`); the binary uses `anyhow`. Newtypes, not primitives, on public APIs.
- **Don't** merge from `archive/poc-2026-05` (reference it freely).
- Append what you learned / decided to the card's *Notes*; the integrator reads them at merge.

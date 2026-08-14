# Restarting wires

*2026-08-13. Written after a review of both revisions of this project and the
MCP 2026-07-28 spec, to decide whether wires is still worth building and, if
so, from where. Conclusion: yes — re-found on the james-core lineage, aim at
`main`'s thesis, drop the token-economics argument entirely.*

---

## 1. The diagnosis: two theses, not two drafts

This repo contains two revisions that look like a draft and a rewrite but are
actually **duals** — each holds one half of a coherent product:

| | `main` (archived PoC) | `james-core` + `aaron/committed-roster-impl` |
|---|---|---|
| Thesis | "A private group chat that machines can read and write to, hosted by a server that cannot." | "The missing session layer: dial a capability, get an authenticated stdio stream." |
| Shape | Persistent, multiway, E2EE topics; blind host; OAuth/MCP gateway; iOS app | Point-to-point sessions; identity-bound grants; offline membership proofs; revocation by omission |
| Size | 29,157 Rust LOC (10 crates) + 6,220 Swift | 6,344 Rust LOC (3 Bazel packages) |
| What it got right | The **product**: multiway comms among agents, tools, and one human | The **foundation**: identity, grants, committed roster, revocation, small codebase |
| What it got wrong | Sprawled (iOS, OAuth AS, HA daemon, deploy stack) before the core sang; never finished membership (`__cap.*` propagation, epoch distribution) | Discarded multiway entirely — "an agent is not special transport"; multi-party reduced to session fan-out |

The fresh-start commit (`13905ef`) deleted 373 files and, with them, the
thesis. The rewrite didn't refine the idea; it swapped it for its dual. That
is why `main` *feels* cleaner despite being 5× the code: main had the right
product, james-core has the right foundation.

Neither branch ever wrote down a token-cost argument (verified by grep — the
word "token" appears only in crypto/OAuth senses). The pitch that motivated
the project was never committed to paper, which is how the plot got lost.

## 2. What died: the token-economics argument

The original framing — "CLI-like calling semantics instead of heavyweight
MCP, for reduced tokens" — does not survive MCP 2026-07-28:

- The protocol went **stateless** (no sessions, no initialize handshake).
- `tools/list` must return deterministic ordering, *explicitly for LLM
  prompt-cache hit rates*; list/read results carry `ttlMs`/`cacheScope`.
- Client-side patterns closed the rest of the gap: deferred tool loading,
  tool search, and code-execution-over-MCP all amortize schema cost.

CLI semantics retain a residual edge (pretrained idiom, one generic verb,
pipes that filter output *before* it reaches context) — but it's an edge a
shell wrapper over MCP mostly captures. "Cheaper MCP" is a wash that loses
to ecosystem gravity. **Drop this leg. Never lead with it again.**

## 3. What's alive: three structural gaps MCP widened

MCP keeps ruthlessly narrowing itself into a superb *tool protocol*, and the
2026-07-28 rev moved *away* from everything wires is about:

1. **Multiway.** MCP is strictly one client ↔ one server. The 2026 rev
   *removed* server-initiated requests (sampling deprecated; MRTR makes the
   client retry instead). There is no shared context for N agents plus a
   human, no push, no "agent notices something and tells the others."
   Google's A2A doesn't cover it either — task-oriented 1:1 delegation, not
   a fabric. Today people bodge this with Slack channels, shared git repos,
   and harness-proprietary session messaging. Every bodge is unencrypted,
   single-vendor, or both.

2. **Portable user identity.** MCP's new "federated auth" is Client ID
   Metadata Documents — federation of *client software* identity. The user
   is still an OAuth ceremony per server; there is no portable "this is
   Aaron." Wires' root-key-as-`sub` design (from the old `wires-mcp`) was
   already stronger than what MCP shipped.

3. **Revocation without token machinery.** The committed roster
   (blake3 Merkle root, root-signed head, offline inclusion proofs,
   revoke-by-omission) has no MCP analogue. MCP's story remains "the bearer
   token expires eventually."

Timing has inverted since May: harness vendors are each growing ad-hoc
agent-messaging layers. Within a year, one ships a proprietary version and
the neutral, E2EE, cross-machine substrate becomes much harder to argue
for. The window is a reason to move, not to wait.

## 4. The re-founded pitch

> **Your agents get a private, end-to-end-encrypted group chat — with each
> other, with your tools, and with you — and any MCP server can be dialed
> into it.**

Test for every future README/pitch sentence: it must make sense to someone
who already has Tailscale and an MCP config, **without** the words
"substrate," "fabric," or "capability-gated." If a phase's deliverable can't
be described in that register, the phase is wrong.

## 5. Order of operations

### Phase 0 — Re-found (docs and repo mechanics, ~a day) ✅ 2026-08-13

1. ✅ **Land the roster work.** `aaron/committed-roster-impl` merged into
   `james/what-is-wires-at-its-core` (PR #7, merge commit `808d433`).
2. ✅ **Swap trunks.** Old `main` tagged `archive/poc-2026-05`; `main` now
   points at the james-core lineage. The old tree stays reachable as the
   reference implementation and design archive — **never a merge source**.
3. ✅ **README rewritten around the pitch above**, with the session wedge
   (Phase 1) as the quickstart and `main`'s data-sovereignty argument
   (archived docs/tech_overview.md) ported into the "why" section.
4. ✅ This file lives at `docs/restart.md`; check off phases as they land.

### Phase 1 — The wedge: identity-bound remote MCP (~1–2 weeks)

*One-line demo: "Run any stdio MCP server on another machine as if it were
local — caller identity verified before the first byte, revocable without
rotating a single key, no OAuth bolt-on."*

Remote MCP auth is genuinely painful today (OAuth bolt-ons, bearer tokens in
config files, mcp-remote proxies), and MCP going stateless makes stdio
bridging *cleaner*. James-core is already ~90% of the way here
(`wires serve` / `wires connect`, mutual inclusion on ALPN `/2`).

1. ✅ **Drop-in `command` for any MCP client config.** `wires import`
   installs the membership / inclusion proof / roster head into the keystore,
   after which `wires connect --ticket <T>` needs no other flag. A dial that
   is refused now exits `77` and prints `wires: denied by responder:
   <reason>` on stderr instead of a transport-level mystery; a preflight check
   catches a ticket minted for another node before any connection opens.
2. ✅ **End-to-end demo**: `.scripts/demo-mcp.sh` — an unmodified stdio MCP
   server (`.scripts/fake-mcp-server.py`) behind `wires serve`, driven over a
   real session by a dialer holding only a ticket. It asserts that the
   captured stdout is byte-clean JSON-RPC and that the tool's answer carries
   the *verified* caller id. Not yet done: pointing a real Claude Code /
   Claude Desktop at a responder on a second machine (item 2's literal
   wording) — the config block is in the README, untested against a client.
3. ✅ **Revocation demo**: `.scripts/demo-revoke.sh` — same dial before and
   after, `--mode roster` (head advance) or `--mode crl`. The responder is
   never restarted; the second dial exits 77 with zero bytes on stdout. This
   needed the CRL and head to be re-read *per connection*, which is now how
   `serve` works.
4. ✅ Verified against MCP 2026-07-28 — see the README subsection. The
   per-request `_meta` key was confirmed against the published spec as
   `io.modelcontextprotocol/protocolVersion` (camelCase). Note `server/discover`
   does not appear in the shipped rev; the stateless per-request metadata does,
   and the bundled fake server exercises it.
5. ⬜ **Record the 5-minute demo** (asciinema or GIF) and put it at the top of
   the README. Neither `asciinema` nor `agg` is installed on the dev machine,
   so this is the one open item. Both scripts are written for capture —
   self-pacing, 80-column output, no prompts — and the README carries the
   `brew install asciinema agg && asciinema rec -c ./.scripts/demo-revoke.sh`
   line for whoever records it.

**Gate:** show the demo to two people who run remote MCP servers today. If
neither says "I want that," stop and re-examine before Phase 2.

### Phase 2 — The fabric minimum: multiway lands on the roster (~3–4 weeks)

*Port back the least of `main` that makes the group chat real. The roster is
the membership layer main never finished — inclusion proofs gate topic
entry, revocation is head-advance. This is the piece neither rev had: main
had topics without finished membership; james-core has membership without
topics.*

1. **Topics over iroh-gossip**, entry gated by roster inclusion proof.
   Reference (not merge): `main`'s `wires-net/src/gossip.rs`.
2. **Minimal persistence + replay**: per-publisher hash-chained log, enough
   for "catch up on what I missed." Reference: `wires-store` /
   `wires-net/src/replay.rs`. Resist porting epochs/retention/eviction until
   something needs them; key distribution rides the roster head.
3. **Human in the loop via CLI only**: `wires publish` / `wires tail`.
4. Explicitly **out of scope**: iOS app, OAuth gateway, HA daemon,
   Docker/Funnel deploy, blind-host retention machinery. Each returns only
   when something in-scope demands it.

**Gate:** you, personally, keep a topic open in a terminal for a week and
find it useful. If it's a demo you never reopen, Phase 3 won't save it.

### Phase 3 — Agents join the chat (~2 weeks)

*Close the loop: the MCP on-ramp in the other direction, so any harness
agent participates in the fabric without wires-native support.*

1. A tiny **`wires mcp-serve`**: an MCP server (stdio, three tools —
   `publish`, `tail`, `list_topics`) any agent harness can mount. This is
   the old `wires-mcp` gateway reduced to its essence — no OAuth AS, no
   JWTs; transport identity comes from the wires session it rides on.
2. **The flagship demo:** two Claude Code sessions on different machines
   plus you in a terminal, sharing one topic — an agent posts a finding,
   the other agent and you both see it, E2EE, no vendor in the middle.
3. Only after that demo works: revisit phone-as-authenticator and the
   consent UX (the one thing the old iOS work proved out worth keeping).

### Phase 4 — Decide what wires is *for* someone else (open-ended)

Alpha-hosting target, packaging, the return of a blind relay for
offline peers (`main`'s host, minus multi-fabric ambition), phone app.
Deliberately unplanned: Phases 1–3 will teach us which of these matters.
The old deploy stack (Docker + Funnel on workbench) stays retired — it was
always a placeholder.

## 6. Kill criteria (write them down now, while sober)

- If the Phase 1 gate fails twice (no one wants identity-bound remote MCP
  even after iteration), the session layer is a feature, not a product —
  fold the ideas into a blog post and stop.
- If, by end of Phase 2, the fabric is something you demo but never *use*,
  the multiway thesis is wrong for now — mothball with a written postmortem
  so the next restart doesn't re-lose the plot.
- If MCP or A2A ships genuine multiway + portable user identity, re-read
  §3 honestly and either narrow to what's still unserved or declare victory
  by obsolescence.

## 7. Non-negotiables carried over from both revs

- **E2EE with a blind relay** stays the security posture (main's invariant
  #3: the host verifies signatures, never holds caps or epoch keys).
- **Offline-verifiable membership** stays the auth posture (james-core's
  roster: no auth-server round-trip, revocation by omission).
- **The spec is the contract** — thesis and README first, code second.
  This document is the first artifact of that rule.

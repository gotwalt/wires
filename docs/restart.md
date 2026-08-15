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
   the *verified* caller id. A real client has now been driven through the
   bridge too (2026-08-13): a headless Claude Code session with only the
   README config block completed the MCP handshake, called the tool, and got
   the responder-verified caller id; after a roster head-advance (responder
   not restarted) the identical session saw no server at all (`connect` exit
   77, zero stdout bytes); re-admission restored it on the same ticket. Still
   untried: a second physical machine (loopback so far) and Claude Desktop.
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
5. ✅ **Demo recorded** (2026-08-13): `demo-revoke.sh` captured with
   asciinema, converted with agg, committed as `docs/demo-revoke.gif`, and
   embedded at the top of the README. Re-record with the one-liner in the
   README quickstart after any demo-visible change.

**Phase 1 is complete**, and its gate has been run.

**Gate:** show the demo to two people who run remote MCP servers today. If
neither says "I want that," stop and re-examine before Phase 2.

*Gate run 2026-08-14. Feedback: "interesting; value prop needs 10x clarity."
Nobody said "I want that"; nobody said no either. Assessed against
[storytelling.md §1](storytelling.md): that is the ceiling of a client–server
pitch, not a fixable demo. In a one-client/one-server shape the server
operator already holds every authority the wedge is selling — admit, refuse,
scope, revoke — so more polish buys a nicer implementation of something that
already works, not a clearer value prop. The kill criterion is "fails twice";
this is once, and the diagnosis points at the pitch's shape rather than at the
machinery, which is the case the criterion was written to distinguish.
Proceeded to Phase 2, where authority spans many peers and there is no server
to concede it to.*

*On the demo's story: three attempts to build a broader Phase 1 story slate
each died to a one-line rebuttal, because a one-client/one-server story sells
authorities the server operator already has. See
[docs/storytelling.md](storytelling.md) for the rebuttal test, what it killed,
and the demo-as-short-story process — pointed at Phases 2–3, not at
manufacturing more Phase 1 stories.*

### Phase 2 — The fabric minimum: multiway lands on the roster (~3–4 weeks)

*Port back the least of `main` that makes the group chat real. The roster is
the membership layer main never finished — inclusion proofs gate topic
entry, revocation is head-advance. This is the piece neither rev had: main
had topics without finished membership; james-core has membership without
topics.*

The implementation spec — written first, and the contract the code follows —
is [docs/phase2-topics.md](phase2-topics.md).

1. ✅ **Topics over iroh-gossip**, entry gated by roster inclusion proof.
   iroh-gossip has no auth hook, so admission is a mutual handshake on its own
   ALPN (`wires/topic-admit/1`) feeding an allowlist a `GatedGossip` wrapper
   consults before delegating; a 30 s watchdog re-checks every stored proof
   against a re-read head and evicts the peer — closing its connections — when
   a commit drops it. Head advances ride the handshake, written through a
   library-owned compare-and-swap so a rollback is a no-op. Topics are
   implicit (blake3 of fabric ‖ name): no `topic create`, no registry.
   `2d87c78`…`b5b50c1`, hardened in `7ddaad9`.
2. ✅ **Minimal persistence + replay**: one redb log per topic, hash-chained
   per publisher, with an `Ok`/`Duplicate`/`Gap`/`Fork` classifier (fork =
   detect and refuse; no fork choice). Replay is **peer-symmetric** on
   `wires/topic-replay/1` — every tail serves history, there is no host — and
   verifies a requester's high-water hashes, streaming a publisher from
   genesis when they disagree so divergence surfaces instead of hiding. A live
   gap schedules a debounced catch-up rather than dropping the message, and
   catch-up also runs periodically, so a hole whose only holder was asleep
   still heals. Epochs, retention, and eviction stayed out, as planned.
   `bc7ccca` (frames), `76182a1` (the redb log), `308dbb3` (the glue).
3. ✅ **Human in the loop via CLI only**: `wires tail` is the resident node
   (store + endpoint + gossip + admission + replay server + a unix control
   socket) and `wires publish` is either a client of that socket or a one-shot
   node of its own — the split that keeps exactly one sequence allocator per
   (node, topic). Backfill, `--json`, structural dedupe across live/replay/
   restart (print only on `Inserted`), exit 77 on refusal. `f545481`; demos in
   `c4e1dd4`, e2e suite in `5b0fef6`, integration gate in `49237a8`.
4. Explicitly **out of scope**: iOS app, OAuth gateway, HA daemon,
   Docker/Funnel deploy, blind-host retention machinery. Each returns only
   when something in-scope demands it. ✅ Held — none of them came back.

**Beyond the plan: E2EE from day one** (`549382e`…`7eeaa0a` in `//library`,
plumbed through the keystore and CLI in `f5d4934`). The wording above said only
"key distribution rides the roster head," which taken literally is plaintext on
the wire until some later phase. That contradicts the first non-negotiable in
§7, and it makes the deliverable unshowable: the pitch is
"a private, end-to-end-encrypted group chat," and a demo of an unencrypted one
argues for nothing. So `roster commit` now mints a data key per commit and
seals a copy to each member (X25519 → ChaCha20-Poly1305, root-signed, weak
recipient keys refused); `wires import --fabric-key-file <node-id>.key`
installs it. It also bought the revocation story: the commit that removes a
member re-keys everyone else in the same act, so confidentiality is immediate
rather than watchdog-latent. The costs are honest and written down — one more
file per member per commit, and rotation-at-commit is the only forward secrecy
there is (spec §10).

**Phase 2's build is complete** — spec §§1–9 implemented, `bazel test //...`
green, three self-asserting scripts (`.scripts/demo-topic.sh`,
`demo-topic-revoke.sh`, `soak-topic.sh`).

**Gate:** you, personally, keep a topic open in a terminal for a week and
find it useful. If it's a demo you never reopen, Phase 3 won't save it.

*Gate armed 2026-08-14. Nothing technical stands in front of it — there is no
remaining task, only the week itself: keep `wires tail` open on real work and
find out whether it gets reopened. Phase 3 waits on that answer, and so does
the second kill criterion below.*

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

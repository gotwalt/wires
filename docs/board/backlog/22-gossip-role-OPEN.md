# 22 — OPEN QUESTION: does the core need the gossip channel?

**Status:** discussed with the human on 2026-09-23 and written down, **not scheduled. Don't build anything from this card until it's decided.** The current demo (gossip channel for discovery, identity claims, re-keys and call records) stays as is.

## The question

The mature form of wires is probably **native services on the protocol**, not
proxies to third-party binaries (`gh`, `rg`), and a mature org would add
OTel/logging while building those services anyway. So does the observer role,
and with it the gossip channel, earn its place in the *core*, compared with
hosts doing their own observability over plain iroh connections?

The human's follow-up constraint: callers must be able to **discover tools
across many hosts in one org**. The integrator's answer is that this needs *a
directory*, not necessarily gossip.

## What the channel carries today

| Job | Why gossip fits or doesn't |
|---|---|
| Call records (observability) | Fits when many writers need no central party and a log the host operator can't rewrite matters, i.e. **across trust boundaries**. Within one org, OTel shipped to a SIEM gets most of it. |
| Tool discovery (sealed host announcements, card 15) | Poor fit. The data is small and slow-changing, and visibility is per caller. Sealing leaks existence, size and timing. |
| Identity claims (card 04/05) | Poor fit. The caller could present its ID token in the connection handshake instead. |
| Re-keys and the proof directory (card 14) | Admin-rooted state; a pull model would be simpler. |
| Multiway (agents reacting to each other) | The original thesis; not part of the current product direction. |

## Alternative architecture (sketch, not a decision)

1. **Hosts are admin-governed.** The admin's signed roster marks which members are **hosts** (or signs a separate host list). Callers get it with `join` and refresh it from the admin.
2. **Discovery is a direct question.** A caller asks each listed host "what may I run?" over a plain iroh connection. The host evaluates `host.json` live against the caller's verified identity and answers. Fan-out plus caching is fine for tens of hosts; an org with hundreds could run a **directory service**, which is itself a native wires service that hosts register with.
3. **Identity in the handshake.** The caller presents its nonce-bound ID token when it connects; nothing is published.
4. **Observability through pluggable sinks.** Keep the host-signed, hash-chained `AuditRecord` as the format and deliver it by **OTel (default)**, a file, or optionally the gossip channel. Records stay verifiable wherever they land (a SIEM included) by anyone holding the host's public key. The pitch: *identity-stamped telemetry: OTel records what a service claims about its caller; this records who the host cryptographically verified.*
5. **Revocation** by pulling the roster head from the admin, or by short-lived memberships.

## What we'd lose

- The independent, replicated log the host can't rewrite (it matters mostly for cross-org: a vendor running tools for you, or auditing third-party hosts on your agent's behalf).
- Zero-infrastructure observability (useful for demos and small teams).
- The multi-party element of the pitch. storytelling.md warns that one-client-one-server pitches die to a one-line rebuttal; the Phase 1 "identity-bound remote MCP" gate got "interesting, needs 10x clarity". The current pitch is stronger (IdP binding, measured CLI efficiency, the no-shell sandbox), but that's the risk.
- **Caller-side attestation** (not built): caller and host each record the call, and a shared channel lets a third party detect a host lying about what it ran. That's only possible with a shared log, and it's the strongest remaining argument for gossip.

## What we'd gain

- Most of the channel machinery leaves the core path: sealed announcements, Rekey chunking, the proof directory, replay/admission for discovery, and 64 KiB gossip messages.
- Discovery that is simpler and more private (non-allowed members learn nothing).
- An observability story an MCP audience recognises at once (OTel with verified identity).
- **Closes the name-squatting hole below.**

## Known weakness of the current design (true either way)

**Tool-name squatting.** Any roster member can run `wires serve` and announce a tool named, say, `db_query`. A rogue or compromised member can impersonate tools; a caller that resolves the impostor sends its input (possibly sensitive SQL) there. Today's only defence is the ambiguity error when two hosts announce the same name (card 15). An admin-signed host list (item 1 above) fixes it; so would admin-signed announcements in the gossip design.

## Suggested next step before deciding

Pitch the demo to the MCP contact and note which part lands: "identity-bound CLI with verified telemetry" (points to the simpler architecture) or "a log the host can't rewrite / shared across orgs" (points to keeping gossip).

## Input from card 23 (push, 2026-09-23)

Asynchronous push to intermittently online callers (store-and-forward, catch-up) is exactly what the channel already does. Card 23 builds push on a direct dial-back plus a host-side queue so that it doesn't prejudge this card, but push is the strongest argument yet for keeping *a* channel. Weigh it here.

## Related

- [18 — front door (OPEN)](18-front-door-OPEN.md): the directory and host-list question overlaps with how people and hosts enter the org.

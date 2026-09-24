# 30 — Web gateway: `wires gateway` for Claude.ai

**Lane:** W · **Depends on:** 27, 26 · **Opened:** 2026-09-23

## Goal

Claude.ai (web) calls wires services through a custom connector at
`https://wires.positivesum.ai/mcp`, fully compliant with MCP 2026-07-28
(plus the legacy `initialize` era), signing in with the Google login wires
already uses — and without weakening "the host verifies the IdP itself".

## Decisions

- **Pass-through identity (user's choice, 2026-09-23).** The gateway is one
  member node; each web user's Google ID token is minted with `nonce =
  for_node(gateway)` and presented unchanged in each call's `Hello`. No
  gateway-minted identity. Cost: sessions end with the ID token (~1 h; Google
  drops `nonce` on refresh), so no refresh tokens; the client reconnects.
- **`member` never admits a web user** (the gateway node is the member, not
  the person). Aligned with the audit's removal of `member` as an admitting
  role. A user admitted to nothing is refused at sign-in.
- **Tools and calls only.** Push, inbox and `watch --mine` are keyed by node
  on hosts today (audit finding), so they are not offered through the gateway.
- OAuth AS in-process: RFC 9728 / 8414 / 8707 / 9207, PKCE S256 only,
  Client ID Metadata Documents (SSRF-guarded) and stateless MAC'd DCR ids;
  consent page bound to a `SameSite=Strict` cookie.
- Streamable HTTP: JSON responses only, `405` for GET/DELETE, header–body
  validation (`HeaderMismatch` −32020), `UnsupportedProtocolVersion`
  −32022, `404` for unknown modern methods, Origin allow-list, no sessions
  minted. The shared core (`caller/mcp.rs`) gained `server/discover`,
  `ttlMs`/`cacheScope`, and legacy-only `ping`/`initialize`.
- Deploy: `deploy/gateway/compose.yml` (gateway + cloudflared) on workbench;
  tunnel `wires-alpha` + DNS + BIC exemption in positivesum/infra PR #17.

## Acceptance

- [x] `cargo test --workspace`, clippy `-D warnings`, fmt clean
- [x] e2e: DCR → consent → mock Google → code (+`state`, `iss`) → token →
      modern and legacy MCP; dialer receives the user's gateway-bound token
- [x] infra applied (break-glass local apply 2026-09-23: 5 added, 1 changed; merge PR #17 once CI billing is fixed)
- [ ] Google *Web application* client with `…/oauth/callback`; its id in the
      workbench host's `identity.issuers` audiences
- [x] gateway invited (`gateway`, b7b1289e…, state v9) + joined on workbench
- [ ] gateway `.env` on workbench; `docker compose up -d`
- [ ] Claude.ai connector added; `orders-db` called as gotwalt@gmail.com,
      the call in the host's log

## Notes

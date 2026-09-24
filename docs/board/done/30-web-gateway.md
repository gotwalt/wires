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
- [x] Google *Web application* client with `…/oauth/callback`; its id in the
      workbench host's `identity.issuers` audiences
- [x] gateway invited (`gateway`, b7b1289e…, state v9) + joined on workbench
- [x] gateway `.env` on workbench; `docker compose up -d`
- [x] docs: deployment.md § A web gateway; protocol.md §6 + limits; usage
      (roles, reference, keystore, trade-offs); README, executive summary and
      demo.md present MCP clients (stdio + gateway) as first-class, with the
      gateway's costs stated
- [x] Claude.ai connector added; `orders-db` called as gotwalt@gmail.com,
      the call in the host's log

## Notes

- 2026-09-24: live end to end. Claude.ai signed in as gotwalt@gmail.com and ran
  `orders-db` 4 times (exit 0). Each call is in the workbench host's signed
  log as caller = the gateway node, principal = the Google account.
- Files outside `wires/gateway/`: `caller/mcp.rs` (2026-07-28 core:
  `server/discover`, −32022, `ttlMs`/`cacheScope`, legacy-only
  `ping`/`initialize`, `with_negotiated`), `caller/call.rs`
  (`Credentials::presenting` + the `hello.id_token` override in `dial` and
  `call_service_with`), `caller/login.rs` (`exchange_code`; `token_request`
  builds its body before awaiting, for `Send`), `main.rs`, `Dockerfile`
  (nonroot-owned `/data` so a fresh volume is writable), `deploy/gateway/`.
- Integration with audit card 28: when `member` is deleted, drop the
  `!r.is_member()` filter in `web_grants` (the audit does this at merge) and
  re-run `cargo test -p wires gateway` and `e2e::gateway`. The live fabric
  then needs a fresh `wires init` + re-invites (state format change).
- Seam for audit card 29 (fetched per-caller views, day-passes): only
  `Gateway::tools_for` / `web_grants` compute what a user may call.
- Deploy facts: tunnel `wires-alpha` (infra PR #17, applied locally
  break-glass 2026-09-23 because CI is blocked on GitHub billing: merge it
  when CI runs). Workbench: `~/src/wires-gateway/deploy/gateway`, volume
  `wires_keystore`, gateway node `b7b1289e…` invited as `gateway` (state v9).
  The workbench host's `host.json` lists the web client id as an audience.
- Open: `deploy/gateway/.env` on workbench was created `664` (an earlier
  `touch`): `chmod 600` it. The audit's §1 (a service child can read the
  host's `node.seed` / plant JWKS) is reachable by any user the gateway
  admits, if a service can be made to read or write files; `orders-db` runs
  `sqlite3 -safe -readonly`. Audit lane L2a closes it.
- Not done: CORS headers (browser-based MCP clients like the Inspector would
  need them; Claude.ai calls from its servers); SSE responses (nothing
  streams); `subscriptions/listen` (no list-change notifications; clients
  re-list per `ttlMs`).
- 2026-09-24 review (integrator = the audit session): H1 consent bypass
  (the IdP callback wasn't bound to the consenting browser) fixed and
  deployed in 5c4a5e7; M1 (bounded memory + a per-address limit), M2
  (pinned, non-echoing metadata fetch), M3 (one shared endpoint, two-user
  concurrent e2e) and the lows in 8e79223, deployed. Docs now carry the
  user's MCP stance: MCP compatibility is a goal of its own (use wires where
  you already use remote tool calling), with `wires call` as the efficient
  path; the record's wording is "the person as the verified principal, the
  gateway node as the dialer". The live shared-endpoint path is exercised by
  the next real Claude.ai call (the e2e scripts the dial).

# 04 — `wires login`: IdP identity bound to the node key

**Lane:** F · **Depends on:** 00 · **Files:** `library/idp.rs`, new `wires/login.rs`, new `wires/jwks.rs`, `wires/render.rs` (identity rendering, after lane B creates it), `wires/main.rs` (login subcommand only), `Cargo.toml`/`Cargo.lock`/`BUILD` for new deps

## Goal

A person proves "this node key is me" with their existing IdP, once, and the
proof travels on the channel as metadata that **every reader verifies
independently** — no wires-run attestor, no per-server OAuth ceremony. Google
OIDC for the demo; nothing Google-specific in the types.

## Design

- **Binding:** authorization-code + PKCE flow with a loopback redirect
  (`http://127.0.0.1:<port>/callback`, opens the browser, prints the URL for
  headless use). `nonce = OidcNonce::for_node(node_id)` (implement the stub:
  base64url-nopad of `blake3::derive_key(OIDC_NONCE_CONTEXT, node bytes)`),
  `scope = openid email`. Google "Desktop app" client IDs come with a
  non-confidential client secret; read `WIRES_OIDC_CLIENT_ID` /
  `WIRES_OIDC_CLIENT_SECRET` / `WIRES_OIDC_ISSUER` (default
  `https://accounts.google.com`) from env or flags. **The human must create the
  Google OAuth client** — document the 4 clicks in Notes; don't block on it (the
  test suite uses a local mock issuer).
- **Output:** store the raw ID token in the keystore (`idp-token.jwt`, 0600) and
  publish `ChannelRecord::Identity(IdentityClaim{node, id_token})` to a topic given
  by `--topic` (through the resident tail's control socket if one is running,
  else a one-shot publish — same as `wires publish`).
- **Verification (`library/idp.rs` + `wires/jwks.rs`):**
  `verify_claim(&IdentityClaim, &Jwks, expected_audiences, now) -> Result<Principal>`
  in `library` (pure: parse compact JWS, RS256 + ES256 signature check against the
  JWK with matching `kid`, `iss` exact match, `aud` ∈ allowed, `exp`/`iat` with ±60 s
  skew, `nonce == for_node(claim.node)`, `email` only if `email_verified`, `hd` → `org`).
  Pick crates deliberately (e.g. `jsonwebtoken`, or `rsa`+`p256` directly) and
  justify in Notes; keep `library` free of networking. `wires/jwks.rs` does OIDC
  discovery → `jwks_uri` fetch with an in-memory + on-disk cache (TTL from
  `Cache-Control`, refetch on unknown `kid`), HTTPS only.
- **Rendering:** replace lane B's "unverified" identity line with the verified
  principal (or the precise reason verification failed) in `render.rs`.
- Tokens expire (~1 h for Google). `wires login --refresh` re-runs silently when a
  refresh token was granted; otherwise re-login. Stale claims render as `(expired)`.

## Acceptance

- [ ] Unit/proptest in `library`: known-answer JWS vectors (RS256, ES256) verify; any
      single-byte tamper fails; wrong nonce/aud/iss/expired each fail with distinct errors;
      `for_node` is deterministic and distinct per node.
- [ ] Hermetic mock issuer (local HTTP server in the test serving discovery + JWKS +
      token endpoint) drives the full `login` flow without a browser (inject the code).
- [ ] e2e: node A logs in against the mock, publishes the claim; observer O renders
      `alice@example.com` verified.
- [ ] Manual with real Google: `wires login` → claim on a topic → observer shows the
      Gmail address. Record the steps in Notes.
- [ ] `bazel test //...`, `aspect lint //...`, format check green.

## Notes

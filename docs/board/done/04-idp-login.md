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

- [x] Unit/proptest in `library`: known-answer JWS vectors (RS256, ES256) verify; any
      single-byte tamper fails; wrong nonce/aud/iss/expired each fail with distinct errors;
      `for_node` is deterministic and distinct per node.
- [x] Hermetic mock issuer (local HTTP server in the test serving discovery + JWKS +
      token endpoint) drives the full `login` flow without a browser (inject the code).
- [x] e2e: node A logs in against the mock, publishes the claim; observer O renders
      `alice@example.com` verified.
- [x] Manual with real Google: `wires login` → claim on a topic → observer shows the
      Gmail address. Record the steps in Notes.
- [x] `bazel test //...`, `aspect lint //...`, format check green.

## Notes

**Worker, 2026-09-22.** Branch `worktree-agent-a84c5f7a7937e3700`.

### API for card 05 / the integrator

```rust
// library (pure, no networking)
pub fn verify_claim(claim: &IdentityClaim, issuer: &Issuer, jwks: &Jwks,
                    audiences: &[Audience], now: i64) -> library::Result<Principal>;
// failures: Error::IdToken(IdTokenError::{Malformed, UnsupportedAlgorithm, UnknownKey,
//   BadSignature, WrongIssuer, WrongAudience, Expired, NotYetValid, WrongNonce, MissingClaim})
IdToken::unverified_issuer() / unverified_kid()   // to pick keys, never as identity

// wires (binary)
jwks::KeyFetcher::new(Some(home.join("jwks")))?
    .verify(&claim, &trusted_issuers, &audiences, now).await
    -> Result<Principal, jwks::VerifyError>   // {Untrusted, Unavailable, Rejected(IdTokenError), Expired(Principal)}
idp_view::describe_identity(&claim, &verdict) -> String         // pure; what render.rs should call
idp_view::render_identity(&fetcher, &IdpTrust, &claim, now).await -> String
idp_view::IdpTrust::from_env()  // WIRES_OIDC_ISSUER (csv, default Google), WIRES_OIDC_AUDIENCE (csv) else WIRES_OIDC_CLIENT_ID
```

- Lines: `identity 3f2a1b9c is alice@example.com (verified by https://accounts.google.com)`,
  `… is alice@example.com (expired)`, `identity 3f2a1b9c UNVERIFIED: <precise reason>`.
- **Integrator TODO:** `render.rs` (lane B) did not exist in my base, so nothing in `wires tail`
  calls `render_identity` yet — hook it in for `ChannelRecord::Identity`, then drop the
  `#![cfg_attr(not(test), allow(dead_code))]` at the top of `wires/idp_view.rs`. The tail is async,
  so either await `render_identity` inline (first sight of an issuer costs one HTTPS fetch, then
  cached) or spawn it.
- Card 05: `VerifyError::Expired(p)` carries the principal, so the denial can name who; the
  trusted-issuer list is the natural place for `--require-idp iss=…`.
- Readers only fetch keys for issuers in their trust list — a channel member cannot make every
  observer fetch an arbitrary URL.

### Crate choices (no new crates compiled — all were already in `Cargo.lock` via iroh)

- **`ring` 0.17** for RS256 (`RsaPublicKeyComponents` + `RSA_PKCS1_2048_8192_SHA256`) and ES256
  (`ECDSA_P256_SHA256_FIXED`), plus SHA-256 for PKCE and RNG for state/verifier. Already built for
  rustls. `jsonwebtoken` would add a second RSA/EC stack (or pull `aws-lc-rs`) for ~150 lines of
  JWS parsing we now own and test; `rsa`+`p256` would add two new crate families. Only RS256/ES256
  are accepted (no `none`/HMAC/PS*), header `crit` is refused.
- **`reqwest` 0.13** (`rustls-no-provider`, `json`) — iroh already compiles it with exactly
  `rustls-no-provider`; we install rustls's **`ring`** provider (`rustls` direct dep with
  `default-features = false, features = ["ring","std","tls12"]`, so no `aws-lc-rs`). Certificates
  are checked by `rustls-platform-verifier` (OS trust store). Smoke-tested against live
  `accounts.google.com` discovery.
- **`url`** for the auth URL / form bodies. **No HTTP server crate:** the loopback redirect and the
  mock issuer share a ~60-line HTTP/1.1 reader/writer in `login.rs` (one request per connection,
  `Content-Length` bodies, 64 KiB cap).
- Known-answer vectors (`library/idp_vectors.rs`) were generated once with Python
  `cryptography`/OpenSSL 3.6 — an implementation independent of ring.

### Deviations / decisions

- **Lockfile:** `generate-lockfile` (per CLAUDE.md) re-resolved all 464 packages (~700-line diff,
  many version bumps) — reverted, and used the same Bazel-vendored cargo with
  `update --workspace` instead: a 6-line diff that only adds the new edges. Suggest CLAUDE.md say
  `update --workspace` for adding deps.
- `verify_claim` takes the expected `&Issuer` explicitly (the card's sketch omitted it): "iss exact
  match" needs something to match against, and federation (card 05) picks per-issuer JWKS.
- New error type `IdTokenError` in `library/error.rs`, wrapped as `Error::IdToken`.
- `wires/e2e.rs`: one-line addition (`#[path = "e2e_idp.rs"] mod idp;`) so the e2e test reuses the
  fabric fixtures without widening their visibility. `wires/main.rs`: `mod` lines + `Login`
  command/dispatch only. Token files written by `login.rs` itself (0600, atomic), not via new
  keystore methods, to stay out of `keystore.rs`.
- `--refresh`: tries the refresh-token grant and **verifies the nonce binding**; Google's refreshed
  ID tokens omit `nonce` (and Google only issues refresh tokens with `access_type=offline`, which we
  don't request — nothing Google-specific in the flow), so against Google `--refresh` falls back to
  the browser flow. `--reuse` re-publishes the stored token if it still verifies.
- HTTPS only, except `http` to a loopback host (the mock issuer).
- JWKS cache TTL = `max-age` clamped to 60 s..24 h (default 1 h); an unknown `kid` refetches at most
  once per 60 s per issuer.
- Tests: library `idp` 14 unit/proptest + 4 doctests; wires 23 (login 15, jwks 5, idp_view 2,
  e2e 1; proptests in library, jwks and login). Totals: library 246 + 41 doctests, wires 214, all green.
- `aspect` is not on PATH here; ran the identical aspect via `bazel build --config=lint
  --output_groups=rules_lint_human //library/... //wires/...` — clippy reports clean for both crates.

### Manual check with real Google (needs a human — box left unchecked)

**Create the OAuth client (Google Cloud Console):**

1. <https://console.cloud.google.com/> → pick or create a project.
2. *APIs & Services → OAuth consent screen* (a.k.a. *Google Auth Platform → Branding/Audience*):
   User type **External**, app name "wires", your email as support/developer contact. Leave it in
   **Testing** and add every Gmail address that will sign in under *Test users*. Scopes: none
   beyond the defaults (`openid`, `email` are non-sensitive).
3. *APIs & Services → Credentials → Create credentials → OAuth client ID* → Application type
   **Desktop app** → name "wires cli" → *Create*.
4. Copy the **Client ID** and **Client secret** (the secret is non-confidential for Desktop apps;
   Google still requires it on the token request). Desktop clients allow any
   `http://127.0.0.1:<port>` redirect — nothing to register.

**Run it** (on the machine with a browser; both nodes provisioned on one fabric as for
`wires tail`/`publish`):

```sh
export WIRES_OIDC_CLIENT_ID='<id>.apps.googleusercontent.com'
export WIRES_OIDC_CLIENT_SECRET='<secret>'
# terminal 1 — observer (needs the same client id as an accepted audience)
WIRES_OIDC_AUDIENCE="$WIRES_OIDC_CLIENT_ID" wires tail ops
# terminal 2 — the node logging in
wires login --topic ops        # browser opens; sign in; token stored in $WIRES_HOME/idp-token.jwt
```

Expected on the observer **once render.rs calls `render_identity`** (integration step above):
`identity <node8> is you@gmail.com (verified by https://accounts.google.com)`. Until then the
observer prints the raw `{"wires":"record/v1",…}` line. Headless node: pass
`--no-browser --callback-port 8765`, `ssh -L 8765:127.0.0.1:8765 <node>` from the laptop, open the
printed URL there. Tokens last ~1 h; re-run `wires login --topic ops` (or `--reuse` while valid).

- **Real Google, 2026-09-23 (integrator):** client published *In production* with only `openid email` (no test-user list, no review). `wires login --topic ops` → observer: `🪪 identity ecc8c1cf is gotwalt@gmail.com (verified by https://accounts.google.com)`; `--require-idp email=gotwalt@gmail.com` refused before login (77) and allowed after. Safari showed a connection error on the callback page even though login succeeded → card 11.

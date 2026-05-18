# wires — MCP gateway design

**Status:** design, 2026-05-18.
**Depends on:** substrate v1, hosted service v1, responder-driven pairing v1, host-ticket discovery v1.
**Scope:** a new `wires-mcp` service that lets AI-agent clients (Claude Desktop, Cursor, VS Code, ChatGPT Desktop, etc.) speak to a household's wires substrate over an authenticated Model Context Protocol surface. This spec covers the OAuth surface, the iOS-as-authenticator consent flow, the MCP tool surface, the per-user wires-agent fleet, and the gateway's small bridge state. Search / indexing, per-session scope narrowing, topic creation through MCP, live notifications, and multi-household OAuth identities are explicitly out of scope.

---

## 1. Mental model

`wires-mcp` is a remote, multi-tenant **OAuth 2.1 Protected Resource and Authorization Server** that exposes a small MCP tool surface. Internally it operates a **fleet of wires agents**, exactly one per OAuth user, each paired into its respective household via the existing responder-driven pair flow. From the substrate's point of view, each of these agents is indistinguishable from a CLI session or `wires-ha`: same ed25519 + x25519 identity, same root-signed `Capability`, same `__caps` ingest, same gossip + replay over iroh.

The gateway is a **separate service**, not part of `wires-host`. `wires-host`'s blindness contract is preserved entirely — the gateway holds cleartext caps + epoch keys because it must in order to act for the user, but it joins the substrate the same way every other agent does and the host never sees the gateway as anything other than a peer publishing ciphertext envelopes. Co-locating the gateway binary on the same VPS as `wires-host` is purely an operational decision.

The gateway's *additional* trust footprint over what's already deployed is therefore:

- It holds, per OAuth user, a wires-agent keypair and the per-topic epoch keys necessary to decrypt and publish on that user's behalf.
- It holds an ed25519 token-signing key (the AS's JWT signer).
- It holds, per OAuth user, the household root pubkey it has bound them to — that pubkey IS the OAuth `sub`.

Everything else (capability semantics, host blindness, wire format, pair protocol) is unchanged. The "very small amount of state to connect the dots" is exactly: an OAuth subject → wires-agent-data-dir mapping, plus DCR client registrations, plus session/refresh-token tables. The per-user wires-agent data dirs themselves follow the existing `~/.wires` layout and live on the gateway's disk.

## 2. Scope of change

**Added:**

- `wires-mcp` — new crate (`crates/wires-mcp/`), `lib + bin`. The binary serves HTTPS for OAuth + MCP and supervises per-OAuth-user wires-agent runtimes.
- A new HTTPS endpoint on the gateway for the returning-user sign-in assertion (`POST /oauth/signin/assertion`) consumed by the iOS app. Pair-approve continues to use the existing `/wires/pair/0` ALPN unchanged.
- One new extension point on `wires-node::pair::NodePairHandler`: an `on_paired: Option<Arc<dyn Fn(PairInstallSummary) + Send + Sync>>` callback fired after a successful `install_grant`. The gateway uses this to learn the bound `root_pubkey_hex` and rename the temp data dir.

**Unchanged:**

- The substrate wire format, AEAD modes, capability model, and reserved message types.
- `wires-host` and its blindness contract.
- The responder-driven pair protocol over `/wires/pair/0`.
- All existing CLI surfaces (`wires init`, `wires pair-listen`, `wires pair-approve`, etc.).

**Crate layering.** Strictly bottom-up, as everywhere else:

`wires-mcp` depends on `wires-node`, `wires-net`, `wires-store`, `wires-crypto`, `wires-core` (it only needs the adjacent layer for most code; the convenience surface is `wires-node`). No new crate sits above `wires-mcp`. New external dependencies: `axum` for HTTPS (already implied by `wires-host`'s ticket-http surface), `jsonwebtoken` for JWT sign/verify. No new transitive crypto primitives.

## 3. Crate layout and on-disk structure

### 3.1 Module layout

```
crates/wires-mcp/
  Cargo.toml
  src/
    main.rs                       # clap, boots service + supervisor
    lib.rs                        # re-exports for tests
    config.rs                     # GatewayConfig: public URL, bind, data dir, token-key path
    error.rs                      # GatewayError (snafu, per project convention)
    store.rs                      # redb-backed gateway state
    tenants.rs                    # TenantSupervisor
    pair_bridge.rs                # first-time /authorize → NodePairHandler integration
    sign_in.rs                    # returning-user challenge + assertion verification
    oauth/
      prm.rs                      # /.well-known/oauth-protected-resource
      as_meta.rs                  # /.well-known/oauth-authorization-server
      jwks.rs                     # /.well-known/jwks.json
      register.rs                 # POST /oauth/register (DCR, RFC 7591)
      authorize.rs                # GET /oauth/authorize, GET /oauth/authorize/status/{id}
      token.rs                    # POST /oauth/token (auth-code + refresh grants)
      middleware.rs               # Bearer-token verifier for /mcp
    mcp/
      router.rs                   # /mcp endpoint (streamable HTTP)
      tools.rs                    # list_topics, publish, tail
  tests/
    oauth_unit.rs
    sign_in_unit.rs
    mcp_tools_unit.rs
    authorize_flow.rs             # integration: first-time + returning
    end_to_end.rs                 # #[ignore]: spawns wires-host + gateway + fake MCP client
```

### 3.2 Gateway on-disk layout

`--data-dir`, default `~/.wires-mcp`:

```
~/.wires-mcp/
  config.toml                                # GatewayConfig snapshot
  token_signing.ed25519                      # JWT signing key, mode 0600
  gateway.redb                               # users, oauth_clients, auth_sessions,
                                             # pending_pairs, pending_signins,
                                             # auth_codes, refresh_tokens, revoked_jtis
  pending_pairs/
    <session_id>/                            # mode 0700, ephemeral
      identity.ed25519                       # mode 0600
      identity.x25519                        # mode 0600
      iroh.secret                            # mode 0600
      config.toml
      caps.db                                # empty until pair completes
      keys_*.redb                            # empty
      topic_names.json                       # empty
      pair_pending.json                      # mode 0600
  users/
    <root_pubkey_hex>/                       # exactly the data dir produced by a
                                             # successful pair-install, no surprises
      config.toml
      identity.ed25519
      identity.x25519
      iroh.secret
      root.ed25519                           # absent — gateway-agents are not roots
      caps.db
      log_<topic_hex>.redb
      keys_<topic_hex>.redb
      topic_names.json
```

A `pending_pairs/<session_id>/` directory is created at first-time `/authorize` and is atomically renamed to `users/<root_pubkey_hex>/` on successful pair-install. Renames are filesystem-atomic when source and destination are on the same filesystem; the deploy assumes that's the case (`~/.wires-mcp/` is a single mount).

### 3.3 `gateway.redb` tables

```
users:            root_pubkey_hex -> { data_dir, created_at, last_seen }
oauth_clients:    client_id       -> { client_name, redirect_uris, grant_types, created_at, revoked: bool }
auth_sessions:    session_id      -> { client_id, redirect_uri, code_challenge,
                                       code_challenge_method, resource, state,
                                       kind: Pending | Done | Expired,
                                       issued_at, expires,
                                       on_done: Option<{ auth_code, sub }> }
pending_pairs:    session_id      -> { temp_data_dir, request_token_b64, ttl_expires }
pending_signins:  session_id      -> { challenge_nonce, ttl_expires }
auth_codes:       code            -> { session_id, sub, client_id, redirect_uri,
                                       code_challenge, issued_at, expires_at,
                                       consumed: bool }
refresh_tokens:   token_hash      -> { sub, client_id, issued_at, expires_at,
                                       rotated_to: Option<token_hash> }
revoked_jtis:     jti             -> { revoked_at }
```

All rows are small (≤ a few hundred bytes). Idle TTLs sweep `pending_*`, `auth_codes`, and `auth_sessions` on a background tick.

## 4. OAuth surface

The gateway is simultaneously the **Protected Resource** (the `/mcp` endpoint) and the **Authorization Server** (the `/oauth/*` endpoints). Token verification is offline (signature + claims + JTI revocation lookup), so there's no introspection endpoint.

### 4.1 Endpoints

| Method + Path | Purpose | Auth |
|---|---|---|
| `GET /.well-known/oauth-protected-resource` | RFC 9728 PRM. | Public |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 AS metadata. | Public |
| `GET /.well-known/jwks.json` | One EdDSA key, stable `kid`. | Public |
| `POST /oauth/register` | DCR (RFC 7591). Anonymous, rate-limited. | Public |
| `GET /oauth/authorize` | Renders the consent page (two QRs). | Public |
| `GET /oauth/authorize/status/{session_id}` | Browser-polled status. | Public, session-bound |
| `POST /oauth/signin/assertion` | iOS posts root-signed sign-in assertions here. | Self-validating |
| `POST /oauth/token` | Authorization-code + refresh-token grants. | Public, validated by code/refresh |
| `POST /mcp`, `GET /mcp`, `DELETE /mcp` | Streamable-HTTP MCP transport. | Bearer JWT |

### 4.2 PRM document (`/.well-known/oauth-protected-resource`)

```json
{
  "resource": "https://mcp.example.com",
  "authorization_servers": ["https://mcp.example.com"],
  "scopes_supported": ["mcp:wires"]
}
```

### 4.3 AS metadata (`/.well-known/oauth-authorization-server`)

```json
{
  "issuer": "https://mcp.example.com",
  "authorization_endpoint": "https://mcp.example.com/oauth/authorize",
  "token_endpoint": "https://mcp.example.com/oauth/token",
  "registration_endpoint": "https://mcp.example.com/oauth/register",
  "jwks_uri": "https://mcp.example.com/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"],
  "scopes_supported": ["mcp:wires"]
}
```

PKCE is required (`S256` only). `token_endpoint_auth_methods_supported: ["none"]` because clients are public — DCR returns no secret, PKCE is the only client-authentication. RFC 8707 `resource` parameter is required on `/oauth/authorize` and `/oauth/token`; the gateway refuses if it doesn't match its configured `issuer`.

### 4.4 DCR (`POST /oauth/register`)

Request:

```json
{
  "client_name": "Claude Desktop",
  "redirect_uris": ["http://localhost:33333/callback"],
  "grant_types": ["authorization_code", "refresh_token"]
}
```

Response:

```json
{
  "client_id": "<uuid v4>",
  "client_name": "Claude Desktop",
  "redirect_uris": ["http://localhost:33333/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_method": "none"
}
```

No `client_secret` returned — all clients are public. Rate-limited per source IP (default: 10 / hour); rate-limit response is RFC 6749 §5.2 `{"error": "temporarily_unavailable", ...}` with `Retry-After`.

### 4.5 Token format

Access tokens are JWTs signed by the gateway's `token_signing.ed25519` (EdDSA). Claims:

```json
{
  "iss": "https://mcp.example.com",
  "sub": "<root_pubkey_hex>",
  "aud": "https://mcp.example.com",
  "iat": 1747320000,
  "exp": 1747320900,
  "jti": "<uuid v4>",
  "scope": "mcp:wires",
  "client_id": "<DCR client_id>"
}
```

Default lifetime: 15 minutes. Refresh tokens are opaque random 256-bit values, stored in `refresh_tokens` keyed by their SHA-256 hash, single-use, rolling on every refresh, 30-day expiry. The middleware on `/mcp` verifies signature, `iss`, `aud`, `exp`, JTI not in `revoked_jtis`, and that `client_id` references a non-revoked DCR registration. Failures return `401 Unauthorized` with `WWW-Authenticate: Bearer realm="mcp", resource_metadata="<PRM_URL>"` so MCP clients can re-discover.

## 5. Consent flow

`/oauth/authorize` renders an HTML page showing **two QR codes** side by side: one for first-time pair, one for returning sign-in. The browser polls `/oauth/authorize/status/{session_id}` until either QR's path completes. iOS auto-detects which kind of QR it's looking at by the `kind` field in the decoded JSON envelope.

### 5.1 `/oauth/authorize` request

Standard OAuth 2.1:

```
GET /oauth/authorize?response_type=code
                    &client_id=<DCR_CLIENT_ID>
                    &redirect_uri=http://localhost:33333/callback
                    &scope=mcp:wires
                    &code_challenge=<base64url(S256(verifier))>
                    &code_challenge_method=S256
                    &resource=https://mcp.example.com
                    &state=<opaque>
```

Validations on receipt:

- `response_type=code`, otherwise `unsupported_response_type`.
- `client_id` exists and is not revoked.
- `redirect_uri` matches one of the client's registered URIs (exact).
- `scope` ⊆ `{"mcp:wires"}`. Anything else: `invalid_scope`.
- `code_challenge_method=S256`. Anything else: `invalid_request`.
- `resource` equals the gateway `issuer`. Anything else: `invalid_target` (RFC 8707).

If validation passes the gateway creates an `auth_sessions` row, generates a `session_id` (uuid v4), and renders the consent page.

### 5.2 First-time (pair) path

The QR encodes a standard `PairRequest` produced from a freshly generated agent identity in a temp data dir. The pair flow runs untouched over the existing `/wires/pair/0` ALPN.

1. Gateway creates `pending_pairs/<session_id>/` (mode 0700) and generates fresh `identity.ed25519`, `identity.x25519`, `iroh.secret`.
2. Gateway binds an **iroh endpoint** with the new `iroh.secret`, registers the standard `PairProtocol` on it.
3. Gateway constructs the `PairRequest`:
   - `role`: `"mcp-gateway"`.
   - `description`: `"MCP Gateway at <gateway_url> for '<client_name>'"` (the `client_name` was captured at DCR time).
   - `requested_scopes`: `[{"topic_name": "**", "rights": ["read", "write"]}]`. The operator narrows on iOS at approval time.
   - `dial`: the temp endpoint's `EndpointAddr`.
   - `nonce`, `issued_at`, `expires` per the existing pair-spec rules (default TTL 5 min).
   - signed by the temp `identity.ed25519`.
4. Encode as URL-safe base64, render as QR + base64 text on the consent page.
5. iOS scans → standard `pair-approve` UX (operator narrows topics if desired) → dials the temp endpoint over `/wires/pair/0` → sends a sealed `PairGrant`.
6. The gateway's `PairHandler` runs `install_grant` against the temp data dir. On success the `on_paired` callback fires with `{ root_pubkey_hex, cap_id, installed_at }`.
7. `pair_bridge` enforces:
   - `users/<root_pubkey_hex>/` MUST NOT already exist. If it does, fail with `AlreadyPaired` — the user should be using the sign-in QR.
8. Atomically rename `pending_pairs/<session_id>/` → `users/<root_pubkey_hex>/`. Insert `users` row. Open the `NodeRuntime` via `TenantSupervisor::bind`. Tear down the temp endpoint (it gets replaced by the supervisor's freshly-opened one — same iroh secret, same `EndpointId`).
9. Mark the `auth_session` `Done` with a fresh auth code (uuid v4, single-use, 60s TTL, bound to `code_challenge` + `redirect_uri` + `sub = root_pubkey_hex`).
10. The browser's next status poll receives `{kind: "done", code, state}` and the browser redirects to `<redirect_uri>?code=...&state=...`.

### 5.3 Returning (sign-in) path

The QR encodes a `SignInChallenge` consumed by the iOS app, which signs it with the household root and POSTs the assertion back.

`SignInChallenge` shape (canonical JSON, URL-safe base64-encoded for QR transport):

```json
{
  "version": 1,
  "kind": "wires.signin.v1",
  "gateway_url": "https://mcp.example.com",
  "session_id": "<uuid>",
  "nonce": "<32 random bytes, hex>",
  "issued_at": 1747320000,
  "expires": 1747320300
}
```

Stored in `pending_signins[session_id] = { nonce, ttl_expires }`.

iOS, on scanning:

1. Decodes, detects `kind: "wires.signin.v1"`.
2. Prompts the user: `"Sign into MCP Gateway at <gateway_url>? You'll be authenticated as <household label>."` Face ID gates the root-key access.
3. Signs the canonical JSON of the challenge (with a `signature` field zeroed before signing — same pattern as everywhere else in the project) using the household root `ed25519`.
4. `POST <gateway_url>/oauth/signin/assertion`:

```json
{
  "session_id": "<uuid>",
  "root_pubkey": "<hex>",
  "signature": "<hex>"
}
```

Gateway-side `/oauth/signin/assertion` handler:

1. Look up `pending_signins[session_id]`. If absent or expired: `404`.
2. Reconstruct the canonical challenge bytes from the stored `nonce` + `session_id` + gateway URL + window. Verify `signature` against the claimed `root_pubkey`. Tamper → `BadAssertionSignature` → `401`.
3. Look up `users[root_pubkey]`. If absent: `UnknownRootPubkey` → `404`.
4. Delete `pending_signins[session_id]` (single-use).
5. Mark the `auth_session` `Done` with a fresh auth code, `sub = root_pubkey`.

Browser's next status poll redirects.

**Why HTTPS, not iroh.** Sign-in is a one-shot signed assertion with no key material in flight and no side effects on the wires bus — POST is the right shape, and it avoids forcing iOS to dial an iroh endpoint for an OAuth flow. The pair flow stays on iroh because it carries epoch keys + caps and the existing protocol must remain untouched.

### 5.4 Status polling

```
GET /oauth/authorize/status/{session_id}
```

Returns one of:

- `{"kind": "pending"}` (HTTP 200, with `Cache-Control: no-store`)
- `{"kind": "done", "code": "...", "state": "...", "redirect_uri": "..."}` (HTTP 200)
- `{"kind": "expired"}` (HTTP 200)

The browser, on `done`, performs the redirect itself. Polling interval is the browser's choice; the gateway tolerates anywhere from 500 ms to 30 s and applies an internal long-poll wait (default 10 s) so well-behaved clients aren't loud.

### 5.5 Token exchange

`POST /oauth/token` accepts two grant types:

**`grant_type=authorization_code`:**

```
client_id=<DCR_CLIENT_ID>
&grant_type=authorization_code
&code=<AUTH_CODE>
&redirect_uri=<must match the original /authorize redirect_uri>
&code_verifier=<PKCE verifier; S256(verifier) must equal the stored code_challenge>
&resource=https://mcp.example.com
```

Validations: code exists in `auth_codes` and is unconsumed; `client_id` matches; `redirect_uri` matches; PKCE verifies; `resource` matches issuer. On success: mark code consumed, mint access token + refresh token, return:

```json
{
  "access_token": "<JWT>",
  "refresh_token": "<opaque>",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "mcp:wires"
}
```

**`grant_type=refresh_token`:**

```
client_id=<DCR_CLIENT_ID>
&grant_type=refresh_token
&refresh_token=<opaque>
&resource=https://mcp.example.com
```

Validations: refresh token exists in `refresh_tokens`, not yet rotated, not expired, `client_id` matches. On success: rotate (mark old `rotated_to: <new>`, insert new), mint a new access token + refresh token, return the same response shape.

## 6. MCP tool surface

Transport: **streamable HTTP only** (the gateway is remote; STDIO is irrelevant). Bearer-protected by the OAuth middleware. The middleware resolves the JWT's `sub` to `users[sub].data_dir`, asks the `TenantSupervisor` for an open `NodeRuntime`, and attaches it to the request scope.

Three tools in v1:

### 6.1 `wires.list_topics`

**Input schema:** `{}` (no parameters).

**Output:**

```json
{
  "topics": [
    {
      "topic_id":  "<32-byte hex>",
      "name":      "home.notes",
      "rights":    ["read", "write"],
      "cap_id":    "<16-byte hex>"
    }
  ]
}
```

Derived from the gateway-agent's local `caps.db` intersected with `topic_names.json`. Topics with a cap but no human name show `"name": null`.

### 6.2 `wires.publish`

**Input schema:**

```json
{
  "topic": { "type": "string", "description": "Topic name or 32-byte hex topic_id, required" },
  "text":  { "type": "string", "description": "The message, required" },
  "data":  { "type": "object", "description": "Optional structured payload" }
}
```

The `type` field is **not exposed** in v1 — the gateway substitutes the literal string `"message"` to satisfy the substrate's non-empty-`type` invariant in `CanonicalContent::validate`. If usage feedback later motivates exposing `type` (or relaxing the substrate invariant), it's a follow-on change scoped to its own design.

**Output:**

```json
{
  "topic_id":     "<hex>",
  "sender":       "<agent ed25519 hex>",
  "seq":          42,
  "prev_hash":    "<hex>",
  "timestamp":    1747320000123,
  "message_hash": "<hex>"
}
```

**Behavior:**

1. Resolve `topic`. Disambiguation rule: a string of exactly 64 lowercase hex characters that maps to a known `topic_id` in the gateway-agent's `caps.db` is treated as a topic_id; anything else is looked up in `topic_names.json`. Unresolved → `topic_not_found`.
2. Verify the gateway-agent has a cap covering this topic with `write` right. Otherwise `permission_denied`.
3. Defense in depth: refuse if `topic_id` is `__caps` (gateway agents must not mint or revoke caps via MCP).
4. Idempotently join the topic in gossip (`NodeRuntime::join_topic`), using the agent's stored `host.peer_hints` for bootstrap.
5. Build `CanonicalContent { type_: "message", text, data }`, call `NodeRuntime::publish_and_broadcast`.
6. Return envelope metadata.

### 6.3 `wires.tail`

**Input schema:**

```json
{
  "topic":  { "type": "string", "description": "Name or hex id, required" },
  "since":  { "type": "string", "description": "Opaque cursor from a previous tail; omit for full history" },
  "limit":  { "type": "integer", "description": "Max messages, default 100, max 500" }
}
```

**Output:**

```json
{
  "messages": [
    {
      "topic_id":  "<hex>",
      "sender":    "<hex>",
      "seq":       17,
      "prev_hash": "<hex>",
      "timestamp": 1747319900000,
      "kind":      "Standard",
      "content":   { "type": "...", "text": "...", "data": {...} }
    }
  ],
  "next_cursor": "<opaque base64>",
  "exhausted":   false
}
```

**Behavior:**

1. Resolve `topic` per the same disambiguation rule as §6.2. Verify `read` right.
2. If the topic isn't joined yet AND `since` is omitted, run `NodeRuntime::replay_from_host(topic_id)` first. Idempotent; failures (no host configured, no reachable host) are logged and tolerated.
3. Idempotently join in gossip so subsequent live messages accrue without an explicit step.
4. Decode the `since` cursor (base64-encoded canonical JSON of a per-sender hwm map, same shape as `ReplayRequest::hwm`). Empty cursor = genesis.
5. Walk the per-topic log, decrypt under the relevant epoch key, return up to `limit` messages in chain order per sender, interleaved by signed timestamp with `(sender, seq)` tie-break.
6. Skip Sealed-to-other-recipient messages (the gateway-agent can't decrypt). Skip reserved-type messages on non-`__caps` topics. Allow Public `__cap.revoke` / `__cap.root_rotation` events on `__caps` if the client explicitly requests `__caps`.
7. Compute `next_cursor`; set `exhausted: true` if local log has nothing further.

### 6.4 Errors as MCP responses

All tool errors return MCP `isError: true` with a single text content block formatted `<code>: <message>`. Codes are stable strings (`topic_not_found`, `permission_denied`, `reserved_topic`, `invalid_cursor`, `gateway_internal_error`). Internal error chains + `location` are logged server-side but not returned.

### 6.5 No audit mutation

The gateway does **not** mutate published content to embed per-MCP-client attribution. The `client_id` is recorded in gateway access logs. Per-client on-bus attribution, if wanted later, is a substrate-level concern (e.g., an `envelope.via` field) and out of scope here.

## 7. TenantSupervisor

Owns the live set of per-OAuth-user `NodeRuntime`s.

```rust
pub struct TenantSupervisor {
    data_dir_root: PathBuf,             // <data-dir>/users/
    runtimes: tokio::sync::Mutex<HashMap<RootPubkeyHex, RuntimeSlot>>,
    idle_ttl: Duration,                 // default 10 min
}

struct RuntimeSlot {
    runtime: Arc<NodeRuntime>,
    last_touched: Instant,
}
```

API:

- `get_or_open(sub: &RootPubkeyHex) -> Result<Arc<NodeRuntime>>` — cached or lazy-opened from `users/<sub>/`; updates `last_touched`. Errors with `UnknownUser` if the directory doesn't exist.
- `close_idle()` — background tick every minute. Closes slots with `last_touched > idle_ttl`. Idempotent.
- `bind(sub, source_dir)` — moves `source_dir` (a completed `pending_pairs/<session_id>/`) into `users/<sub>/` via `std::fs::rename`, opens the resulting `NodeRuntime`, inserts into the map.

**Iroh endpoint cost.** Each `NodeRuntime` binds its own iroh endpoint via `wires_net::bind_lan`. At v1 scale (single-digit to low-double-digit concurrent users on a single gateway), per-user endpoints are fine. Idle GC keeps the working set bounded. Sharing one iroh endpoint across users would require a `wires-node` refactor decoupling `Endpoint` from `Node`; explicitly v2.

**Concurrency.** The `Mutex` serializes open/close. Per-runtime concurrency is the existing `NodeRuntime`'s responsibility — already async-safe.

## 8. Pair-bridge hook

`wires-node::pair::NodePairHandler` gains one new optional field:

```rust
pub type OnPaired = dyn Fn(PairInstallSummary) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
                       + Send
                       + Sync;

pub struct NodePairHandler {
    // ... existing fields ...
    pub on_paired: Option<Arc<OnPaired>>,
}

pub struct PairInstallSummary {
    pub root_pubkey_hex: String,
    pub cap_id: [u8; 16],
    pub installed_at: i64,
}
```

If present, it's invoked **after** the install transaction commits to the temp data dir and **before** `PairFrame::Ack` is written. The callback returns a `Result`: on `Ok`, the handler proceeds to ack as usual; on `Err`, the handler returns `PairFrame::Reject(PairReject { code: PairRejectCode::AlreadyPaired or InternalError, message })` instead. The temp data dir is left in place and reaped by TTL — nothing globally visible was written, so this is safe. The error's `Display` impl is used as the `message`; the code is selected by the callback returning a typed error (gateway-defined `OnPairedError`).

The existing `wires-cli pair-listen` doesn't set this field; only the gateway does. Default behaviour is unchanged.

The gateway's callback runs the `pair_bridge` flow synchronously (it's already on a tokio worker):

1. Check `users` table for an existing entry under `PairInstallSummary.root_pubkey_hex`. If present → return `Err(OnPairedError::AlreadyPaired)`. The handler converts this to `Reject(AlreadyPaired)` and the operator is told to use the sign-in QR instead.
2. Rename `pending_pairs/<session_id>/` → `users/<root_pubkey_hex>/`. On filesystem error → `Err(OnPairedError::Internal(source))` → `Reject(InternalError)`.
3. Insert the `users` row in `gateway.redb`.
4. Call `TenantSupervisor::bind`.
5. Mint an auth code and flip `auth_session` to Done.
6. Return `Ok(())`. The handler writes `PairFrame::Ack`.

The browser's next status poll then receives the auth code and performs the redirect.

## 9. Operator admin CLI

`wires-mcp` subcommands:

| Command | Effect |
|---|---|
| `wires-mcp serve` | Default; runs the HTTPS service + supervisor. |
| `wires-mcp user-list` | Lists `(root_pubkey_hex, created_at, last_seen)` for every onboarded user. |
| `wires-mcp user-delete <root_pubkey_hex>` | Removes `users/<hex>/`, invalidates all refresh tokens for `sub=hex`, adds outstanding JTIs (where known) to `revoked_jtis`. Does NOT publish a `__cap.revoke` — that's an operator/iOS act. |
| `wires-mcp client-list` | Lists DCR-registered clients. |
| `wires-mcp client-revoke <client_id>` | Marks a DCR client revoked; the middleware rejects tokens carrying that `client_id` going forward. |
| `wires-mcp keys rotate` | Generates a new `token_signing.ed25519`, marks the old one verification-only in JWKS, signs new tokens with the new key. Old tokens remain valid until their natural expiry. |

## 10. Error handling

`GatewayError` follows the project's snafu convention strictly — every variant has `#[snafu(implicit)] location: Location`, no `message: String`, display strings end with `, at {location}`, external errors are leaves linked via `source`. Boundaries convert with `.context(...)` as usual.

Categories:

- **HTTP / transport.** `BindHttp { source }`, `ServeHttp { source }`.
- **OAuth protocol** (mapped to RFC 6749 / OAuth 2.1 error codes in HTTP responses; the wire response is `{"error": "<code>", "error_description": "..."}`):
  - `InvalidRequest`, `InvalidClient`, `InvalidGrant`, `InvalidScope`, `UnauthorizedClient`,
  - `UnsupportedGrantType`, `UnsupportedResponseType`, `InvalidResource` (RFC 8707).
- **Authorize session.** `UnknownSession`, `SessionExpired`, `AlreadyDone`, `BadPkce`, `RedirectUriMismatch`.
- **Pair bridge.** `PairBridge { source: PairError }`, `AlreadyPaired { root_pubkey_hex }`, `TempDataDirMove { source }`.
- **Sign-in.** `BadAssertionSignature`, `UnknownRootPubkey`, `ExpiredChallenge`.
- **Token.** `BadTokenSignature`, `ExpiredToken`, `BadAudience`, `RevokedJti`, `MissingScope`, `RevokedClient`.
- **Tenant supervisor.** `UnknownUser { sub }`, `OpenRuntime { source: NodeError }`.
- **MCP tool dispatch.** `TopicNotFound { topic }`, `PermissionDenied { topic_id_hex, right }`, `ReservedTopic { topic_id_hex }`, `InvalidCursor { source }`, `JoinTopic { source }`, `PublishFailed { source }`, `TailFailed { source }`.
- **Store.** `Redb { source }`, `Json { source }`, `Io { source }`.

OAuth-protocol errors render to the JSON `{"error":...}` shape per RFC 6749 §5.2. Tool errors render to MCP `isError: true` with `<code>: <message>` text. Internal locations are never returned to clients; they appear in server logs.

## 11. Logging and privacy

Per-request log lines include: method, path, status, response time, JTI prefix (first 8 chars), `sub` prefix (first 8 chars), `client_id`, MCP tool name (if any), topic_id prefix (if any). **Never** log: full tokens, full signatures, ephemeral X25519 secrets, epoch keys, message ciphertext, decrypted message content, nonces in full (prefix only), root_pubkey in full (prefix only). Same redaction discipline as the existing pair flow's `info!` lines.

## 12. Testing

### 12.1 Unit tests (no I/O)

In `wires-mcp::oauth`:

- JWT sign + verify round-trip with the gateway's EdDSA key.
- `iss` / `aud` / `exp` claim checks reject wrong values.
- Expired token rejected; revoked JTI rejected.
- PKCE `S256` round-trip; bad verifier rejected.
- PRM, AS metadata, and JWKS serialization match the RFC-shaped JSON.
- DCR parsing: `redirect_uris` required, returns a stable `client_id`, never returns `client_secret`.

In `wires-mcp::sign_in`:

- `SignInChallenge` canonical-JSON round-trip + URL-safe base64.
- Signature verifies for the claimed `root_pubkey`; tampering any field invalidates.
- Wrong-root signature → `BadAssertionSignature`.
- Replay across windows → `ExpiredChallenge` (challenge deleted after first use).

In `wires-mcp::mcp::tools`:

- `wires.publish` happy path: produces a valid `Standard` envelope on a real (in-process) `NodeRuntime`.
- `wires.publish` writes the default `type` value when none is provided.
- `wires.publish` to `__caps` → `ReservedTopic`.
- `wires.publish` without a write cap → `PermissionDenied`.
- `wires.tail` returns chronologically interleaved decrypted messages + a usable cursor.
- `wires.tail` with `since` resumes from the cursor.
- `wires.list_topics` reflects caps + names.

### 12.2 Integration tests (`tests/`)

Real iroh endpoints, `MemoryLookup` cross-registration to dodge pkarr warm-up:

- *First-time auth happy path.* A fake "iOS" task scans the `PairRequest`, dials `/wires/pair/0`, sends a valid `PairGrant`. Gateway moves the data dir; `/oauth/token` exchange succeeds; subsequent `wires.publish` lands on the bus.
- *Returning auth happy path.* After first-time success, a second `/authorize` arrives. Sign-in QR is rendered. Fake iOS POSTs a valid root-signed assertion. New token issued, same `sub`. Tool calls work.
- *Wrong-root sign-in.* Fake iOS posts an assertion signed by a different root pubkey. `UnknownRootPubkey`.
- *Parallel /authorize sessions.* Distinct session IDs, distinct temp data dirs, no cross-contamination.
- *Auth-code single-use.* Exchanging the same code twice → second call fails `invalid_grant`.
- *Refresh-token rotation.* Old refresh rejected after rotation.
- *Permission revoked mid-session.* Operator emits `__cap.revoke` on `__caps`; gateway-agent ingests it; next `wires.publish` returns `permission_denied`.
- *Idle GC.* TenantSupervisor closes a `NodeRuntime` after TTL; next call reopens transparently.

### 12.3 Acceptance scenarios (`#[ignore]`, `--ignored`)

- *End-to-end multi-process.* Spawn `wires-host`, an Alice CLI doing `wires init --new-root` + `host pair` + `topic create home.notes` + `host topic-register home.notes`, spawn `wires-mcp serve` with a public-ish address, drive a fake MCP client through `/authorize` → pair → token → `wires.publish` → `wires.tail`.
- *Operator narrows scopes at pair time.* Same with `pair-approve --scope home.notes:read`. `wires.publish` from MCP fails `permission_denied`; `wires.tail` succeeds.
- *User deletion.* After a successful pair, `wires-mcp user-delete <root_hex>` removes `users/<hex>/`, evicts tokens; subsequent token use fails `unauthorized`.

### 12.4 What we deliberately don't mock

`NodeRuntime`, iroh transport (in-memory variant for unit speed where applicable; real `bind_lan` for integration), redb stores in tempdirs, JWT crypto, AEAD crypto. Per the substrate spec's "spawn real nodes" discipline — mocks at this layer hide the bugs that actually bite.

## 13. v1 acceptance criteria

1. A user with no prior relationship to the gateway can complete first-time `/authorize` end-to-end (scan QR on iOS → approve → browser redirects with code → client exchanges for token).
2. The same user, on a second MCP client or after token expiry, can complete returning `/authorize` via the sign-in QR.
3. `wires.publish` from an MCP client lands on the wires bus as a `Standard`-mode envelope signed by the gateway-agent's `identity.ed25519`, with `cap_id` matching the installed cap. `wires-host` sees only ciphertext.
4. `wires.tail` returns those same messages with decrypted content + a cursor that, when fed back, resumes correctly.
5. `wires.list_topics` reflects exactly the caps the operator approved at pair time.
6. An attempt to publish to `__caps` is refused at the MCP boundary.
7. `wires-mcp user-delete <hex>` cleanly removes a user; their tokens stop working immediately.
8. Token verification on the hot path is offline (no DB round-trip beyond the JTI revocation check).

## 14. Out of scope

- **Search / indexing** across decrypted content.
- **Per-session scope narrowing.** Tokens represent the agent's full cap.
- **Topic creation, cap minting, cap revocation through MCP.** Operator/iOS only.
- **Live notifications** (server-pushed events). Polling only via `wires.tail`'s `since` cursor.
- **Multi-household per OAuth user.** One `sub` = one root pubkey.
- **Iroh-endpoint sharing across users.** Each `NodeRuntime` binds its own at v1 scale.
- **Cap-grant propagation through gossip.** Substrate-level gap inherited here; re-pair is the workaround in v1.
- **Self-service account deletion** via MCP. Operator CLI only.
- **Per-MCP-client distinction on the wire.** Logged, not embedded.
- **JWT introspection endpoint.** Verification is offline.
- **Federated AS.** Gateway is its own AS; no external IdP.
- **Migration tooling** for the gateway state to a different host (same operational concern as wires-host today).
- **MCP resource surface** (`resources/list`, `resources/read`). The three tools are the v1 contract; resources can be added later without protocol changes.
- **Exposing `type` in `wires.publish`.** Deferred until real usage tells us what would actually help.

## 15. Open questions for review

1. **Default token TTL.** Proposing 15 min access / 30 day rolling refresh. Reviewer: too short for assistant flows that idle mid-conversation, or too long for the threat model?
2. **Sign-in challenge TTL.** Proposing 5 min, mirroring `PairRequest`.
3. **`AuthSession` TTL.** Proposing 10 min on the consent page itself.
4. **DCR rate limiting.** Proposing 10 registrations / source IP / hour.
5. **Default `type` value.** Proposing the literal `"message"`. Open to a different default, or to making it operator-configurable.
6. **Idle-GC TTL** for quiescent `NodeRuntime`s. Proposing 10 min.
7. **Operator UX for `user-delete`.** Should it also try to publish a `__cap.revoke` if the operator's `root.ed25519` is colocated on the gateway box (it isn't, by design — roots live on iOS)? Recommend: no, keep clean separation. Operator does cap-revoke separately on iOS if they want to.
8. **Sign-in iOS UX.** What's shown to the user when scanning a sign-in QR vs. a pair QR? The two paths feel quite different from the operator's point of view; the iOS app needs a clear "this is sign-in" vs. "this is a new agent" affordance. Probably an iOS-side spec concern, but flagging here.

## 16. Notes on iOS-side work

This spec implies, but does not specify, two iOS app additions:

- A scanner path for the `SignInChallenge` QR (distinguishable from the existing `PairRequest` QR by the `kind` field), with a Face-ID-gated root-key sign and an HTTPS POST to the gateway URL the QR carries.
- A consent affordance distinguishing "approving a new gateway agent" (existing pair-approve UX) from "signing into a gateway we've already approved" (new flow). Both terminate in the same gateway-side state, but the user-visible meaning differs.

The iOS companion spec gets a follow-on revision once this design lands.

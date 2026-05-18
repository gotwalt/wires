# wires-mcp Gateway Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a new service (`wires-mcp`) that exposes an authenticated MCP surface for AI-agent clients to act on a user's behalf inside their wires household. The gateway pairs into each household as a normal wires agent via the existing responder flow, holding cleartext caps + epoch keys per user; `wires-host`'s blindness contract is preserved.

**Architecture:** New top-level crate `wires-mcp`, `lib + bin`. The binary serves HTTPS for OAuth (`/.well-known/*`, `/oauth/*`) and the MCP streamable-HTTP endpoint (`/mcp`) via `axum`. Internally a `TenantSupervisor` owns one `wires_node::NodeRuntime` per OAuth user. OAuth `sub` IS the household root pubkey hex. First-time `/authorize` shows a `PairRequest` QR (existing pair flow over `/wires/pair/0`); returning `/authorize` shows a sign-in challenge QR that the iOS app signs with the root key and POSTs back. Tokens are EdDSA-signed JWTs verified offline. `wires-host` is untouched.

**Tech Stack:** Rust edition 2024 / stable 1.95, snafu, axum 0.8, jsonwebtoken 9, ed25519-dalek 2, x25519-dalek 2, redb 4, qrcode 0.14, tokio, serde+serde_json, tracing. No new transitive crypto.

**Spec:** `docs/superpowers/specs/2026-05-18-wires-mcp-gateway-design.md`. This plan implements every numbered section.

---

## File Map

| File | Action | Owner task |
|---|---|---|
| `Cargo.toml` (workspace) | Modify: add `crates/wires-mcp` to members + workspace dep | Task 1 |
| `crates/wires-mcp/Cargo.toml` | Create | Task 1 |
| `crates/wires-mcp/src/main.rs` | Create: clap, serve+admin subcommands | Tasks 1, 29–32 |
| `crates/wires-mcp/src/lib.rs` | Create: re-exports for tests | Task 1 |
| `crates/wires-mcp/src/error.rs` | Create: `GatewayError` (snafu) | Task 2 |
| `crates/wires-mcp/src/config.rs` | Create: `GatewayConfig` | Task 3 |
| `crates/wires-mcp/src/keys.rs` | Create: token signing key load-or-generate | Task 4 |
| `crates/wires-mcp/src/store.rs` | Create: redb tables + accessor helpers | Task 5 |
| `crates/wires-mcp/src/token.rs` | Create: JWT mint + verify | Task 6 |
| `crates/wires-mcp/src/http.rs` | Create: axum app builder + shutdown | Task 7 |
| `crates/wires-mcp/src/oauth/prm.rs` | Create | Task 8 |
| `crates/wires-mcp/src/oauth/as_meta.rs` | Create | Task 9 |
| `crates/wires-mcp/src/oauth/jwks.rs` | Create | Task 10 |
| `crates/wires-mcp/src/oauth/register.rs` | Create: DCR | Task 11 |
| `crates/wires-mcp/src/oauth/middleware.rs` | Create: bearer auth | Task 12 |
| `crates/wires-mcp/src/tenants.rs` | Create: TenantSupervisor | Tasks 13–15 |
| `crates/wires-node/src/pair.rs` | Modify: `NodePairHandler::with_on_paired` + `PairInstallSummary` | Task 16 |
| `crates/wires-mcp/src/sign_in.rs` | Create: `SignInChallenge` struct + verify | Task 17 |
| `crates/wires-mcp/src/oauth/authorize.rs` | Create: GET /oauth/authorize (validation+session) | Task 18 |
| `crates/wires-mcp/src/oauth/authorize_html.rs` | Create: render the consent page | Task 19 |
| `crates/wires-mcp/src/oauth/authorize_status.rs` | Create: GET /oauth/authorize/status/{id} | Task 20 |
| `crates/wires-mcp/src/pair_bridge.rs` | Create: temp-dir + PairRequest + on_paired wiring | Task 21 |
| `crates/wires-mcp/src/sign_in_endpoint.rs` | Create: POST /oauth/signin/assertion | Task 22 |
| `crates/wires-mcp/src/oauth/token.rs` | Create: POST /oauth/token (both grants) | Tasks 23–24 |
| `crates/wires-mcp/src/mcp/router.rs` | Create: /mcp endpoint, JSON-RPC dispatch | Task 25 |
| `crates/wires-mcp/src/mcp/tools.rs` | Create: list_topics, publish, tail | Tasks 26–28 |
| `crates/wires-mcp/src/admin.rs` | Create: user-list, user-delete, etc. | Tasks 29–32 |
| `crates/wires-mcp/tests/end_to_end.rs` | Create: `#[ignore]` acceptance | Task 33 |
| `CLAUDE.md` | Modify | Task 34 |
| `README.md` | Modify | Task 34 |

No layering inversions: `wires-mcp` depends on `wires-node`, `wires-net`, `wires-store`, `wires-crypto`, `wires-core`. The single `wires-node` change in Task 16 is additive (new optional field).

---

## Phase A — Crate scaffolding and state store

### Task 1: Create the `wires-mcp` crate skeleton

**Files:**
- Modify: `Cargo.toml` (workspace)
- Create: `crates/wires-mcp/Cargo.toml`
- Create: `crates/wires-mcp/src/lib.rs`
- Create: `crates/wires-mcp/src/main.rs`

- [ ] **Step 1: Add the crate to the workspace**

In the root `Cargo.toml`, append `"crates/wires-mcp"` to the `members` array (alphabetical between `wires-host` and `wires-ha` — keep the existing order). Add to `[workspace.dependencies]` after the existing internal block:

```toml
wires-mcp   = { path = "crates/wires-mcp" }
```

- [ ] **Step 2: Create `crates/wires-mcp/Cargo.toml`**

```toml
[package]
name = "wires-mcp"
edition.workspace = true
version.workspace = true
license.workspace = true

[lib]
name = "wires_mcp"
path = "src/lib.rs"

[[bin]]
name = "wires-mcp"
path = "src/main.rs"

[dependencies]
wires-core   = { workspace = true }
wires-crypto = { workspace = true }
wires-store  = { workspace = true }
wires-net    = { workspace = true }
wires-node   = { workspace = true }

iroh        = { workspace = true }
tokio       = { workspace = true }
clap        = { workspace = true }
axum        = { version = "0.8", default-features = false, features = ["http1", "tokio", "json"] }
tokio-util  = { version = "0.7", default-features = false, features = ["rt"] }
snafu       = { workspace = true }
tracing     = { workspace = true }
tracing-subscriber = { workspace = true }
serde       = { workspace = true }
serde_json  = { workspace = true }
hex         = { workspace = true }
toml        = { workspace = true }
redb        = { workspace = true }
blake3      = { workspace = true }
ed25519-dalek = { workspace = true }
rand_core   = { workspace = true }
qrcode      = { version = "0.14", default-features = false, features = ["svg"] }
jsonwebtoken = "9"
uuid        = { version = "1", features = ["v4", "serde"] }
sha2        = "0.10"
base64      = "0.22"
chrono      = { version = "0.4", default-features = false, features = ["clock"] }
async-trait = { workspace = true }
parking_lot = { workspace = true }

[dev-dependencies]
tempfile    = "3"
tokio       = { workspace = true, features = ["macros", "rt-multi-thread", "test-util"] }
```

If any `workspace = true` reference in the snippet above fails because the dep isn't yet in the workspace, check the root `Cargo.toml`'s `[workspace.dependencies]`; everything above is already used by `wires-host` or `wires-node`. The new ones (`jsonwebtoken`, `uuid`, `sha2`, `base64`, `chrono`) are added as direct (non-workspace) deps for now.

- [ ] **Step 3: Create `crates/wires-mcp/src/lib.rs`**

```rust
//! `wires-mcp` — an authenticated MCP gateway that exposes a small tool
//! surface for AI agents to act on a wires household's behalf. See the
//! design doc at `docs/superpowers/specs/2026-05-18-wires-mcp-gateway-design.md`.

pub mod config;
pub mod error;
```

- [ ] **Step 4: Create `crates/wires-mcp/src/main.rs`**

```rust
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "wires-mcp", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Subcommand, Debug)]
enum Cmd {
    /// Run the gateway HTTPS service + tenant supervisor.
    Serve,
}

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve => {
            tracing::info!("wires-mcp serve: scaffold only, see plan task 7");
            std::process::ExitCode::SUCCESS
        }
    }
}
```

- [ ] **Step 5: Verify the crate compiles**

Run: `cargo build -p wires-mcp`
Expected: success, no warnings.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/wires-mcp/
git commit -m "wires-mcp: crate skeleton (cargo + main + lib)"
```

---

### Task 2: `GatewayError` (snafu, project convention)

**Files:**
- Create: `crates/wires-mcp/src/error.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/wires-mcp/src/lib.rs`:

```rust

#[cfg(test)]
mod lib_tests {
    use crate::error::{GatewayError, UnknownUserSnafu};
    use snafu::ResultExt;

    #[test]
    fn error_messages_end_with_location() {
        let err: Result<(), _> = Err::<(), _>(std::io::Error::other("boom"))
            .context(crate::error::IoSnafu);
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains(", at "), "no location: {msg}");
    }

    #[test]
    fn unknown_user_renders_sub_prefix() {
        let err: GatewayError = UnknownUserSnafu {
            sub: "deadbeef".to_string(),
        }
        .build();
        let msg = err.to_string();
        assert!(msg.contains("deadbeef"));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p wires-mcp --lib`
Expected: FAIL with "no module named `error`" or similar.

- [ ] **Step 3: Create `crates/wires-mcp/src/error.rs`**

```rust
//! `GatewayError` follows the project's snafu convention: every variant has
//! `#[snafu(implicit)] location: Location`, no `message: String`, display
//! strings end with `, at {location}`, external errors are leaves linked via
//! `source`. Boundaries convert with `.context(...)`.

use snafu::{Location, Snafu};

pub type Result<T, E = GatewayError> = std::result::Result<T, E>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum GatewayError {
    // --- I/O / transport ---
    #[snafu(display("I/O failed: {source}, at {location}"))]
    Io {
        #[snafu(source)]
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Failed to bind HTTP listener: {source}, at {location}"))]
    BindHttp {
        #[snafu(source)]
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("HTTP serve failed: {source}, at {location}"))]
    ServeHttp {
        #[snafu(source)]
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },

    // --- OAuth protocol (rendered to RFC 6749 §5.2 JSON) ---
    #[snafu(display("OAuth invalid_request: {detail}, at {location}"))]
    InvalidRequest {
        detail: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("OAuth invalid_client, at {location}"))]
    InvalidClient {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("OAuth invalid_grant: {detail}, at {location}"))]
    InvalidGrant {
        detail: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("OAuth invalid_scope, at {location}"))]
    InvalidScope {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("OAuth unauthorized_client, at {location}"))]
    UnauthorizedClient {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("OAuth unsupported_grant_type, at {location}"))]
    UnsupportedGrantType {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("OAuth unsupported_response_type, at {location}"))]
    UnsupportedResponseType {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("OAuth invalid_target (RFC 8707), at {location}"))]
    InvalidResource {
        #[snafu(implicit)]
        location: Location,
    },

    // --- Authorize session ---
    #[snafu(display("Authorize session unknown, at {location}"))]
    UnknownSession {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Authorize session expired, at {location}"))]
    SessionExpired {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Authorize session already completed, at {location}"))]
    AlreadyDone {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("PKCE verification failed, at {location}"))]
    BadPkce {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("redirect_uri does not match the request's, at {location}"))]
    RedirectUriMismatch {
        #[snafu(implicit)]
        location: Location,
    },

    // --- Pair bridge ---
    #[snafu(display("Pair install rejected: a wires user already exists for root {root_pubkey_hex}, at {location}"))]
    AlreadyPaired {
        root_pubkey_hex: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Failed to move temp data dir: {source}, at {location}"))]
    TempDataDirMove {
        #[snafu(source)]
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },

    // --- Sign-in ---
    #[snafu(display("Sign-in assertion signature did not verify, at {location}"))]
    BadAssertionSignature {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Sign-in: unknown root pubkey {root_pubkey_hex}, at {location}"))]
    UnknownRootPubkey {
        root_pubkey_hex: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Sign-in challenge expired, at {location}"))]
    ExpiredChallenge {
        #[snafu(implicit)]
        location: Location,
    },

    // --- Tokens ---
    #[snafu(display("Token signature invalid, at {location}"))]
    BadTokenSignature {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Token expired, at {location}"))]
    ExpiredToken {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Token audience mismatch, at {location}"))]
    BadAudience {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Token jti revoked, at {location}"))]
    RevokedJti {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Token missing required scope, at {location}"))]
    MissingScope {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Token client_id is revoked, at {location}"))]
    RevokedClient {
        #[snafu(implicit)]
        location: Location,
    },

    // --- Tenants ---
    #[snafu(display("Unknown wires user for sub {sub}, at {location}"))]
    UnknownUser {
        sub: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Failed to open per-user NodeRuntime: {source}, at {location}"))]
    OpenRuntime {
        #[snafu(source)]
        source: wires_node::NodeError,
        #[snafu(implicit)]
        location: Location,
    },

    // --- MCP dispatch ---
    #[snafu(display("Topic {topic} not found, at {location}"))]
    TopicNotFound {
        topic: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Permission denied for topic_id {topic_id_hex} (need {right}), at {location}"))]
    PermissionDenied {
        topic_id_hex: String,
        right: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Reserved topic {topic_id_hex} not writable through MCP, at {location}"))]
    ReservedTopic {
        topic_id_hex: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Invalid tail cursor: {source}, at {location}"))]
    InvalidCursor {
        #[snafu(source)]
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Failed to join topic: {source}, at {location}"))]
    JoinTopic {
        #[snafu(source)]
        source: wires_node::NodeError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Publish failed: {source}, at {location}"))]
    PublishFailed {
        #[snafu(source)]
        source: wires_node::NodeError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Tail read failed: {source}, at {location}"))]
    TailFailed {
        #[snafu(source)]
        source: wires_node::NodeError,
        #[snafu(implicit)]
        location: Location,
    },

    // --- Store ---
    #[snafu(display("Gateway redb storage failed: {source}, at {location}"))]
    Redb {
        #[snafu(source)]
        source: redb::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Failed to open gateway redb: {source}, at {location}"))]
    RedbOpen {
        #[snafu(source)]
        source: redb::DatabaseError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Gateway JSON (de)serialize failed: {source}, at {location}"))]
    Json {
        #[snafu(source)]
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p wires-mcp --lib`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/wires-mcp/src/error.rs crates/wires-mcp/src/lib.rs
git commit -m "wires-mcp: GatewayError enum (snafu, project convention)"
```

---

### Task 3: `GatewayConfig`

**Files:**
- Create: `crates/wires-mcp/src/config.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/wires-mcp/src/config.rs` with only a test module first to confirm the shape:

```rust
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Public-facing base URL, e.g. `https://mcp.example.com`. Used as
    /// `iss` and `aud` on every issued JWT and as the canonical RFC 8707
    /// `resource` value. MUST NOT end with `/`.
    pub public_url: String,
    /// Socket the HTTPS service binds (TLS termination is upstream; v1 binds
    /// HTTP only and assumes a reverse proxy in production).
    pub bind: String,
    /// Filesystem root for gateway state (`~/.wires-mcp`).
    pub data_dir: PathBuf,
}

impl GatewayConfig {
    pub fn token_signing_path(&self) -> PathBuf {
        self.data_dir.join("token_signing.ed25519")
    }
    pub fn gateway_db_path(&self) -> PathBuf {
        self.data_dir.join("gateway.redb")
    }
    pub fn users_dir(&self) -> PathBuf {
        self.data_dir.join("users")
    }
    pub fn pending_pairs_dir(&self) -> PathBuf {
        self.data_dir.join("pending_pairs")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn paths_compose_from_data_dir() {
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:3000".into(),
            data_dir: PathBuf::from("/tmp/wires-mcp"),
        };
        assert_eq!(cfg.token_signing_path(), Path::new("/tmp/wires-mcp/token_signing.ed25519"));
        assert_eq!(cfg.gateway_db_path(), Path::new("/tmp/wires-mcp/gateway.redb"));
        assert_eq!(cfg.users_dir(), Path::new("/tmp/wires-mcp/users"));
        assert_eq!(cfg.pending_pairs_dir(), Path::new("/tmp/wires-mcp/pending_pairs"));
    }

    #[test]
    fn toml_roundtrip() {
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:3000".into(),
            data_dir: PathBuf::from("/srv/wires-mcp"),
        };
        let s = toml::to_string_pretty(&cfg).unwrap();
        let back: GatewayConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.public_url, cfg.public_url);
        assert_eq!(back.bind, cfg.bind);
        assert_eq!(back.data_dir, cfg.data_dir);
    }
}
```

- [ ] **Step 2: Run the test to verify it passes (no impl change needed)**

Run: `cargo test -p wires-mcp --lib config`
Expected: PASS (2 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/wires-mcp/src/config.rs
git commit -m "wires-mcp: GatewayConfig with TOML roundtrip"
```

---

### Task 4: Token signing key load-or-generate

**Files:**
- Create: `crates/wires-mcp/src/keys.rs`
- Modify: `crates/wires-mcp/src/lib.rs` (add `pub mod keys;`)

- [ ] **Step 1: Write the failing test**

Add to `crates/wires-mcp/src/lib.rs`:

```rust
pub mod keys;
```

Then create `crates/wires-mcp/src/keys.rs` with:

```rust
//! Token signing key: a single ed25519 keypair persisted in
//! `<data_dir>/token_signing.ed25519` (raw 32 bytes, mode 0600). Used by
//! `token::mint` to sign JWTs and exposed via `/.well-known/jwks.json`.

use std::path::Path;

use ed25519_dalek::SigningKey;
use snafu::ResultExt;

use crate::error::{IoSnafu, Result};

/// The `kid` advertised in JWKS and embedded in every minted JWT. Stable
/// across process restarts because it's derived from the public key.
pub fn kid_for(verifying_key: &ed25519_dalek::VerifyingKey) -> String {
    let bytes = verifying_key.to_bytes();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"wires-mcp.token-kid.v1");
    hasher.update(&bytes);
    let h = hasher.finalize();
    hex::encode(&h.as_bytes()[..8])
}

/// Load the signing key from `path`, or generate one if absent. The on-disk
/// representation is raw 32 bytes; mode 0600 on creation.
pub fn load_or_create(path: &Path) -> Result<SigningKey> {
    if path.exists() {
        let bytes = std::fs::read(path).context(IoSnafu)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| crate::error::GatewayError::Io {
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "token_signing.ed25519 must be exactly 32 bytes",
            ),
            location: snafu::location!(),
        })?;
        return Ok(SigningKey::from_bytes(&arr));
    }
    let sk = SigningKey::generate(&mut rand_core::OsRng);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context(IoSnafu)?;
    }
    write_secret(path, sk.to_bytes().as_slice())?;
    Ok(sk)
}

#[cfg(unix)]
fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .context(IoSnafu)?;
    f.write_all(bytes).context(IoSnafu)?;
    f.sync_all().context(IoSnafu)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).context(IoSnafu)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generates_a_key_when_missing() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("token_signing.ed25519");
        assert!(!path.exists());
        let sk = load_or_create(&path).unwrap();
        assert!(path.exists());
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes.as_slice(), sk.to_bytes().as_slice());
    }

    #[test]
    fn loads_existing_key() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("token_signing.ed25519");
        let first = load_or_create(&path).unwrap();
        let second = load_or_create(&path).unwrap();
        assert_eq!(first.to_bytes(), second.to_bytes());
    }

    #[test]
    fn kid_is_stable() {
        let sk1 = SigningKey::from_bytes(&[7u8; 32]);
        let sk2 = SigningKey::from_bytes(&[7u8; 32]);
        assert_eq!(kid_for(&sk1.verifying_key()), kid_for(&sk2.verifying_key()));
        let sk3 = SigningKey::from_bytes(&[8u8; 32]);
        assert_ne!(kid_for(&sk1.verifying_key()), kid_for(&sk3.verifying_key()));
    }
}
```

- [ ] **Step 2: Run the tests**

Run: `cargo test -p wires-mcp --lib keys`
Expected: PASS (3 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/wires-mcp/src/keys.rs crates/wires-mcp/src/lib.rs
git commit -m "wires-mcp: token signing key load_or_create + stable kid"
```

---

### Task 5: `gateway.redb` store skeleton + table definitions

**Files:**
- Create: `crates/wires-mcp/src/store.rs`
- Modify: `crates/wires-mcp/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Add `pub mod store;` to `crates/wires-mcp/src/lib.rs`.

Create `crates/wires-mcp/src/store.rs` with the table layouts and accessor helpers:

```rust
//! redb-backed gateway state. One file at `<data_dir>/gateway.redb`. Every
//! table is keyed by a stable identifier (root_pubkey_hex, client_id,
//! session_id, etc.) and stores a JSON-serialized record value. The shape of
//! each record is in this module; the design rationale is in the spec.

use std::path::Path;
use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::error::{JsonSnafu, RedbOpenSnafu, RedbSnafu, Result};

const USERS: TableDefinition<&str, &[u8]> = TableDefinition::new("users");
const OAUTH_CLIENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("oauth_clients");
const AUTH_SESSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("auth_sessions");
const PENDING_PAIRS: TableDefinition<&str, &[u8]> = TableDefinition::new("pending_pairs");
const PENDING_SIGNINS: TableDefinition<&str, &[u8]> = TableDefinition::new("pending_signins");
const AUTH_CODES: TableDefinition<&str, &[u8]> = TableDefinition::new("auth_codes");
const REFRESH_TOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("refresh_tokens");
const REVOKED_JTIS: TableDefinition<&str, &[u8]> = TableDefinition::new("revoked_jtis");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserRecord {
    pub root_pubkey_hex: String,
    pub data_dir: String,
    pub created_at_ms: i64,
    pub last_seen_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OauthClientRecord {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub created_at_ms: i64,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthSessionKind {
    Pending,
    Done { auth_code: String, sub: String },
    Expired,
    Failed { code: String, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthSessionRecord {
    pub session_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub resource: String,
    pub state: String,
    pub kind: AuthSessionKind,
    pub issued_at_ms: i64,
    pub expires_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingPairRecord {
    pub session_id: String,
    pub temp_data_dir: String,
    pub request_token_b64: String,
    pub ttl_expires_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingSigninRecord {
    pub session_id: String,
    pub challenge_nonce_hex: String,
    pub ttl_expires_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthCodeRecord {
    pub code: String,
    pub session_id: String,
    pub sub: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub issued_at_ms: i64,
    pub expires_ms: i64,
    pub consumed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefreshTokenRecord {
    pub token_hash_hex: String,
    pub sub: String,
    pub client_id: String,
    pub issued_at_ms: i64,
    pub expires_ms: i64,
    pub rotated_to_hash_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokedJtiRecord {
    pub jti: String,
    pub revoked_at_ms: i64,
}

#[derive(Clone)]
pub struct Store {
    db: Arc<Database>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| crate::error::GatewayError::Io {
                source: e,
                location: snafu::location!(),
            })?;
        }
        let db = Database::create(path).context(RedbOpenSnafu)?;
        Ok(Self { db: Arc::new(db) })
    }

    pub fn put_user(&self, rec: &UserRecord) -> Result<()> {
        let bytes = serde_json::to_vec(rec).context(JsonSnafu)?;
        let write = self.db.begin_write().context(RedbSnafu)?;
        {
            let mut t = write.open_table(USERS).context(RedbSnafu)?;
            t.insert(rec.root_pubkey_hex.as_str(), bytes.as_slice())
                .context(RedbSnafu)?;
        }
        write.commit().context(RedbSnafu)
    }

    pub fn get_user(&self, root_pubkey_hex: &str) -> Result<Option<UserRecord>> {
        let read = self.db.begin_read().context(RedbSnafu)?;
        let t = match read.open_table(USERS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(crate::error::GatewayError::Redb {
                source: e.into(),
                location: snafu::location!(),
            }),
        };
        let v = match t.get(root_pubkey_hex).context(RedbSnafu)? {
            Some(v) => v,
            None => return Ok(None),
        };
        let rec: UserRecord = serde_json::from_slice(v.value()).context(JsonSnafu)?;
        Ok(Some(rec))
    }

    pub fn list_users(&self) -> Result<Vec<UserRecord>> {
        let read = self.db.begin_read().context(RedbSnafu)?;
        let t = match read.open_table(USERS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
            Err(e) => return Err(crate::error::GatewayError::Redb {
                source: e.into(),
                location: snafu::location!(),
            }),
        };
        let mut out = Vec::new();
        for r in t.iter().context(RedbSnafu)? {
            let (_, v) = r.context(RedbSnafu)?;
            let rec: UserRecord = serde_json::from_slice(v.value()).context(JsonSnafu)?;
            out.push(rec);
        }
        Ok(out)
    }

    pub fn delete_user(&self, root_pubkey_hex: &str) -> Result<bool> {
        let write = self.db.begin_write().context(RedbSnafu)?;
        let existed;
        {
            let mut t = write.open_table(USERS).context(RedbSnafu)?;
            existed = t.remove(root_pubkey_hex).context(RedbSnafu)?.is_some();
        }
        write.commit().context(RedbSnafu)?;
        Ok(existed)
    }
}

// Generic JSON record helpers. Each table gets a thin accessor pair.

macro_rules! json_record_accessors {
    ($put:ident, $get:ident, $delete:ident, $table:expr, $rec:ty, $key_field:ident) => {
        impl Store {
            pub fn $put(&self, rec: &$rec) -> Result<()> {
                let bytes = serde_json::to_vec(rec).context(JsonSnafu)?;
                let write = self.db.begin_write().context(RedbSnafu)?;
                {
                    let mut t = write.open_table($table).context(RedbSnafu)?;
                    t.insert(rec.$key_field.as_str(), bytes.as_slice())
                        .context(RedbSnafu)?;
                }
                write.commit().context(RedbSnafu)
            }
            pub fn $get(&self, key: &str) -> Result<Option<$rec>> {
                let read = self.db.begin_read().context(RedbSnafu)?;
                let t = match read.open_table($table) {
                    Ok(t) => t,
                    Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                    Err(e) => return Err(crate::error::GatewayError::Redb {
                        source: e.into(),
                        location: snafu::location!(),
                    }),
                };
                let v = match t.get(key).context(RedbSnafu)? {
                    Some(v) => v,
                    None => return Ok(None),
                };
                let rec: $rec = serde_json::from_slice(v.value()).context(JsonSnafu)?;
                Ok(Some(rec))
            }
            pub fn $delete(&self, key: &str) -> Result<bool> {
                let write = self.db.begin_write().context(RedbSnafu)?;
                let existed;
                {
                    let mut t = write.open_table($table).context(RedbSnafu)?;
                    existed = t.remove(key).context(RedbSnafu)?.is_some();
                }
                write.commit().context(RedbSnafu)?;
                Ok(existed)
            }
        }
    };
}

json_record_accessors!(put_oauth_client, get_oauth_client, delete_oauth_client, OAUTH_CLIENTS, OauthClientRecord, client_id);
json_record_accessors!(put_auth_session, get_auth_session, delete_auth_session, AUTH_SESSIONS, AuthSessionRecord, session_id);
json_record_accessors!(put_pending_pair, get_pending_pair, delete_pending_pair, PENDING_PAIRS, PendingPairRecord, session_id);
json_record_accessors!(put_pending_signin, get_pending_signin, delete_pending_signin, PENDING_SIGNINS, PendingSigninRecord, session_id);
json_record_accessors!(put_auth_code, get_auth_code, delete_auth_code, AUTH_CODES, AuthCodeRecord, code);
json_record_accessors!(put_refresh_token, get_refresh_token, delete_refresh_token, REFRESH_TOKENS, RefreshTokenRecord, token_hash_hex);
json_record_accessors!(put_revoked_jti, get_revoked_jti, delete_revoked_jti, REVOKED_JTIS, RevokedJtiRecord, jti);

impl Store {
    pub fn list_oauth_clients(&self) -> Result<Vec<OauthClientRecord>> {
        let read = self.db.begin_read().context(RedbSnafu)?;
        let t = match read.open_table(OAUTH_CLIENTS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
            Err(e) => return Err(crate::error::GatewayError::Redb {
                source: e.into(),
                location: snafu::location!(),
            }),
        };
        let mut out = Vec::new();
        for r in t.iter().context(RedbSnafu)? {
            let (_, v) = r.context(RedbSnafu)?;
            let rec: OauthClientRecord = serde_json::from_slice(v.value()).context(JsonSnafu)?;
            out.push(rec);
        }
        Ok(out)
    }

    pub fn revoke_refresh_tokens_for_sub(&self, sub: &str) -> Result<usize> {
        let read = self.db.begin_read().context(RedbSnafu)?;
        let hashes: Vec<String> = match read.open_table(REFRESH_TOKENS) {
            Ok(t) => {
                let mut keys = Vec::new();
                for r in t.iter().context(RedbSnafu)? {
                    let (_, v) = r.context(RedbSnafu)?;
                    let rec: RefreshTokenRecord = serde_json::from_slice(v.value()).context(JsonSnafu)?;
                    if rec.sub == sub {
                        keys.push(rec.token_hash_hex);
                    }
                }
                keys
            }
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => return Err(crate::error::GatewayError::Redb {
                source: e.into(),
                location: snafu::location!(),
            }),
        };
        drop(read);
        let mut n = 0;
        for h in &hashes {
            if self.delete_refresh_token(h)? {
                n += 1;
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn s() -> (TempDir, Store) {
        let tmp = TempDir::new().unwrap();
        let store = Store::open(&tmp.path().join("gateway.redb")).unwrap();
        (tmp, store)
    }

    #[test]
    fn users_put_get_list_delete_roundtrip() {
        let (_t, store) = s();
        let r = UserRecord {
            root_pubkey_hex: "ab".repeat(32),
            data_dir: "/tmp/x".into(),
            created_at_ms: 1,
            last_seen_ms: 2,
        };
        store.put_user(&r).unwrap();
        assert_eq!(store.get_user(&r.root_pubkey_hex).unwrap(), Some(r.clone()));
        assert_eq!(store.list_users().unwrap(), vec![r.clone()]);
        assert!(store.delete_user(&r.root_pubkey_hex).unwrap());
        assert_eq!(store.get_user(&r.root_pubkey_hex).unwrap(), None);
        assert!(!store.delete_user(&r.root_pubkey_hex).unwrap());
    }

    #[test]
    fn missing_user_is_none_not_error_on_fresh_db() {
        let (_t, store) = s();
        assert_eq!(store.get_user("nope").unwrap(), None);
        assert_eq!(store.list_users().unwrap(), vec![]);
    }

    #[test]
    fn auth_session_roundtrip() {
        let (_t, store) = s();
        let sess = AuthSessionRecord {
            session_id: "s1".into(),
            client_id: "c1".into(),
            redirect_uri: "http://x".into(),
            code_challenge: "cc".into(),
            code_challenge_method: "S256".into(),
            resource: "https://mcp.example".into(),
            state: "st".into(),
            kind: AuthSessionKind::Pending,
            issued_at_ms: 1,
            expires_ms: 100,
        };
        store.put_auth_session(&sess).unwrap();
        assert_eq!(store.get_auth_session("s1").unwrap(), Some(sess));
    }

    #[test]
    fn refresh_tokens_revoke_for_sub_removes_only_matching() {
        let (_t, store) = s();
        let r1 = RefreshTokenRecord {
            token_hash_hex: "h1".into(),
            sub: "alice".into(),
            client_id: "c".into(),
            issued_at_ms: 1,
            expires_ms: 2,
            rotated_to_hash_hex: None,
        };
        let r2 = RefreshTokenRecord {
            token_hash_hex: "h2".into(),
            sub: "bob".into(),
            client_id: "c".into(),
            issued_at_ms: 1,
            expires_ms: 2,
            rotated_to_hash_hex: None,
        };
        store.put_refresh_token(&r1).unwrap();
        store.put_refresh_token(&r2).unwrap();
        let n = store.revoke_refresh_tokens_for_sub("alice").unwrap();
        assert_eq!(n, 1);
        assert!(store.get_refresh_token("h1").unwrap().is_none());
        assert!(store.get_refresh_token("h2").unwrap().is_some());
    }
}
```

- [ ] **Step 2: Run the tests**

Run: `cargo test -p wires-mcp --lib store`
Expected: PASS (4 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/wires-mcp/src/store.rs crates/wires-mcp/src/lib.rs
git commit -m "wires-mcp: gateway.redb store with table accessors"
```

---

*End of Phase A. Phase B (OAuth metadata + key endpoints) continues with Tasks 6–10.*


## Phase B — JWT + HTTP service + metadata endpoints

### Task 6: JWT mint + verify

**Files:**
- Create: `crates/wires-mcp/src/token.rs`
- Modify: `crates/wires-mcp/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Add `pub mod token;` to `crates/wires-mcp/src/lib.rs`.

Create `crates/wires-mcp/src/token.rs`:

```rust
//! JWT mint + verify. EdDSA-signed by the gateway's `token_signing.ed25519`.
//! Claims per spec §4.5. Verification is offline (signature + claims +
//! optional caller-supplied JTI revocation check).

use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::error::{
    BadAudienceSnafu, BadTokenSignatureSnafu, ExpiredTokenSnafu, GatewayError, JsonSnafu,
    MissingScopeSnafu, RevokedJtiSnafu, Result,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub scope: String,
    pub client_id: String,
}

#[derive(Debug, Clone)]
pub struct MintInput<'a> {
    pub iss: &'a str,
    pub sub: &'a str,
    pub aud: &'a str,
    pub now_s: i64,
    pub ttl_s: i64,
    pub client_id: &'a str,
}

pub const SCOPE_MCP_WIRES: &str = "mcp:wires";

pub fn mint(sk: &SigningKey, input: &MintInput<'_>) -> Result<String> {
    let kid = crate::keys::kid_for(&sk.verifying_key());
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid);
    header.typ = Some("JWT".into());
    let claims = Claims {
        iss: input.iss.to_string(),
        sub: input.sub.to_string(),
        aud: input.aud.to_string(),
        iat: input.now_s,
        exp: input.now_s + input.ttl_s,
        jti: uuid::Uuid::new_v4().to_string(),
        scope: SCOPE_MCP_WIRES.to_string(),
        client_id: input.client_id.to_string(),
    };
    let key = EncodingKey::from_ed_der(&ed_pkcs8_der(sk));
    jsonwebtoken::encode(&header, &claims, &key).map_err(|e| GatewayError::Json {
        source: serde_json::Error::custom(e.to_string()),
        location: snafu::location!(),
    })
}

pub fn verify(
    vk: &VerifyingKey,
    expected_iss: &str,
    expected_aud: &str,
    is_jti_revoked: impl Fn(&str) -> bool,
    token: &str,
    now_s: i64,
) -> Result<Claims> {
    let key = DecodingKey::from_ed_der(&ed_spki_der(vk));
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[expected_aud]);
    validation.set_issuer(&[expected_iss]);
    validation.validate_exp = false;
    validation.required_spec_claims = std::collections::HashSet::from([
        "iss".into(),
        "sub".into(),
        "aud".into(),
        "exp".into(),
        "iat".into(),
        "jti".into(),
    ]);
    let data = jsonwebtoken::decode::<Claims>(token, &key, &validation).map_err(|e| {
        use jsonwebtoken::errors::ErrorKind::*;
        match e.kind() {
            InvalidAudience => GatewayError::BadAudience {
                location: snafu::location!(),
            },
            _ => GatewayError::BadTokenSignature {
                location: snafu::location!(),
            },
        }
    })?;
    let c = data.claims;
    if c.exp <= now_s {
        return ExpiredTokenSnafu.fail();
    }
    if is_jti_revoked(&c.jti) {
        return RevokedJtiSnafu.fail();
    }
    if c.scope.split_whitespace().all(|s| s != SCOPE_MCP_WIRES) {
        return MissingScopeSnafu.fail();
    }
    Ok(c)
}

// jsonwebtoken expects PKCS#8/SPKI DER for Ed25519; build minimal encodings.
fn ed_pkcs8_der(sk: &SigningKey) -> Vec<u8> {
    // PKCS#8 v1 for Ed25519: SEQUENCE { INTEGER 0, AlgorithmIdentifier, OCTET STRING containing OCTET STRING(seed) }
    // We use the canonical 48-byte prefix + 32 seed bytes.
    let prefix = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(&prefix);
    out.extend_from_slice(sk.to_bytes().as_slice());
    out
}

fn ed_spki_der(vk: &VerifyingKey) -> Vec<u8> {
    // SPKI for Ed25519: 12-byte prefix + 32 raw pubkey bytes
    let prefix = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let mut out = Vec::with_capacity(44);
    out.extend_from_slice(&prefix);
    out.extend_from_slice(vk.to_bytes().as_slice());
    out
}

// `serde_json::Error::custom` is not pub; wrap via the public From<...> shim.
trait SerdeJsonErrorCustom: Sized {
    fn custom<T: std::fmt::Display>(msg: T) -> Self;
}
impl SerdeJsonErrorCustom for serde_json::Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        use serde::de::Error;
        serde_json::Error::custom(msg.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn sk() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    #[test]
    fn mint_and_verify_roundtrip() {
        let sk = sk();
        let vk = sk.verifying_key();
        let now = 1_000_000;
        let token = mint(
            &sk,
            &MintInput {
                iss: "https://mcp.example",
                sub: "ab".repeat(32).as_str(),
                aud: "https://mcp.example",
                now_s: now,
                ttl_s: 900,
                client_id: "client-1",
            },
        )
        .unwrap();
        let c = verify(&vk, "https://mcp.example", "https://mcp.example", |_| false, &token, now + 5).unwrap();
        assert_eq!(c.sub.len(), 64);
        assert_eq!(c.scope, SCOPE_MCP_WIRES);
        assert_eq!(c.client_id, "client-1");
    }

    #[test]
    fn expired_token_rejected() {
        let sk = sk();
        let now = 1_000_000;
        let t = mint(
            &sk,
            &MintInput {
                iss: "i",
                sub: "s",
                aud: "i",
                now_s: now,
                ttl_s: 60,
                client_id: "c",
            },
        )
        .unwrap();
        let err = verify(&sk.verifying_key(), "i", "i", |_| false, &t, now + 999).unwrap_err();
        assert!(matches!(err, GatewayError::ExpiredToken { .. }));
    }

    #[test]
    fn revoked_jti_rejected() {
        let sk = sk();
        let now = 1_000_000;
        let t = mint(
            &sk,
            &MintInput {
                iss: "i",
                sub: "s",
                aud: "i",
                now_s: now,
                ttl_s: 900,
                client_id: "c",
            },
        )
        .unwrap();
        let err = verify(&sk.verifying_key(), "i", "i", |_| true, &t, now + 5).unwrap_err();
        assert!(matches!(err, GatewayError::RevokedJti { .. }));
    }

    #[test]
    fn audience_mismatch_rejected() {
        let sk = sk();
        let now = 1_000_000;
        let t = mint(
            &sk,
            &MintInput {
                iss: "i",
                sub: "s",
                aud: "i",
                now_s: now,
                ttl_s: 900,
                client_id: "c",
            },
        )
        .unwrap();
        let err = verify(&sk.verifying_key(), "i", "other", |_| false, &t, now + 5).unwrap_err();
        assert!(matches!(err, GatewayError::BadAudience { .. }));
    }

    #[test]
    fn tampered_signature_rejected() {
        let sk = sk();
        let now = 1_000_000;
        let t = mint(
            &sk,
            &MintInput {
                iss: "i",
                sub: "s",
                aud: "i",
                now_s: now,
                ttl_s: 900,
                client_id: "c",
            },
        )
        .unwrap();
        let mut bytes = t.into_bytes();
        let last = bytes.last_mut().unwrap();
        *last = if *last == b'a' { b'b' } else { b'a' };
        let t = String::from_utf8(bytes).unwrap();
        let err = verify(&sk.verifying_key(), "i", "i", |_| false, &t, now + 5).unwrap_err();
        assert!(matches!(err, GatewayError::BadTokenSignature { .. }));
    }
}
```

- [ ] **Step 2: Run the tests**

Run: `cargo test -p wires-mcp --lib token`
Expected: PASS (5 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/wires-mcp/src/token.rs crates/wires-mcp/src/lib.rs
git commit -m "wires-mcp: JWT mint + offline verify (EdDSA)"
```

---

### Task 7: HTTP service skeleton (axum app + bind + shutdown)

**Files:**
- Create: `crates/wires-mcp/src/http.rs`
- Modify: `crates/wires-mcp/src/lib.rs`
- Modify: `crates/wires-mcp/src/main.rs`

- [ ] **Step 1: Add `pub mod http;` to `crates/wires-mcp/src/lib.rs`**

- [ ] **Step 2: Write the failing test**

Create `crates/wires-mcp/src/http.rs`:

```rust
//! axum service skeleton. Holds a `ServiceState` of everything the routes
//! need (config, store, signing key) and exposes `app()` so tests can
//! exercise routes through `tower::ServiceExt::oneshot` without binding a
//! port. The `serve()` entry point binds and runs until Ctrl-C.

use std::sync::Arc;

use axum::Router;
use axum::extract::FromRef;
use ed25519_dalek::SigningKey;
use snafu::ResultExt;

use crate::config::GatewayConfig;
use crate::error::{BindHttpSnafu, Result, ServeHttpSnafu};
use crate::store::Store;

#[derive(Clone)]
pub struct ServiceState {
    pub config: Arc<GatewayConfig>,
    pub store: Store,
    pub signing_key: Arc<SigningKey>,
}

impl FromRef<ServiceState> for Arc<GatewayConfig> {
    fn from_ref(s: &ServiceState) -> Self {
        Arc::clone(&s.config)
    }
}

pub fn app(state: ServiceState) -> Router {
    Router::new()
        .route("/_health", axum::routing::get(health))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

pub async fn serve(state: ServiceState) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(&state.config.bind)
        .await
        .context(BindHttpSnafu)?;
    tracing::info!(addr = %state.config.bind, "wires-mcp listening");
    axum::serve(listener, app(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .context(ServeHttpSnafu)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn state() -> (TempDir, ServiceState) {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
        };
        let store = Store::open(&cfg.gateway_db_path()).unwrap();
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let state = ServiceState {
            config: Arc::new(cfg),
            store,
            signing_key: Arc::new(sk),
        };
        (tmp, state)
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let (_t, state) = state();
        let resp = app(state)
            .oneshot(Request::get("/_health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
```

Add `tower = "0.5"` to `[dev-dependencies]` in `crates/wires-mcp/Cargo.toml` so the test can use `ServiceExt::oneshot`.

- [ ] **Step 3: Wire `serve` into `main.rs`**

Replace `crates/wires-mcp/src/main.rs` body of the `Cmd::Serve` match arm:

```rust
Cmd::Serve => {
    let cfg_path = std::path::PathBuf::from(std::env::var("WIRES_MCP_CONFIG").unwrap_or_else(|_| "/etc/wires-mcp/config.toml".into()));
    let cfg: wires_mcp::config::GatewayConfig = match std::fs::read_to_string(&cfg_path) {
        Ok(s) => match toml::from_str(&s) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("config parse failed: {e}");
                return std::process::ExitCode::FAILURE;
            }
        },
        Err(e) => {
            eprintln!("config read failed at {}: {e}", cfg_path.display());
            return std::process::ExitCode::FAILURE;
        }
    };
    let sk = match wires_mcp::keys::load_or_create(&cfg.token_signing_path()) {
        Ok(sk) => sk,
        Err(e) => {
            eprintln!("token signing key load failed: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let store = match wires_mcp::store::Store::open(&cfg.gateway_db_path()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("store open failed: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let state = wires_mcp::http::ServiceState {
        config: std::sync::Arc::new(cfg),
        store,
        signing_key: std::sync::Arc::new(sk),
    };
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("tokio runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match rt.block_on(wires_mcp::http::serve(state)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("serve failed: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p wires-mcp --lib http`
Expected: PASS (1 test).

- [ ] **Step 5: Verify the binary builds**

Run: `cargo build -p wires-mcp`
Expected: success.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-mcp/src/http.rs crates/wires-mcp/src/lib.rs crates/wires-mcp/src/main.rs crates/wires-mcp/Cargo.toml
git commit -m "wires-mcp: axum app skeleton + serve entry point"
```

---

### Task 8: PRM endpoint (`/.well-known/oauth-protected-resource`)

**Files:**
- Create: `crates/wires-mcp/src/oauth/mod.rs`
- Create: `crates/wires-mcp/src/oauth/prm.rs`
- Modify: `crates/wires-mcp/src/lib.rs`
- Modify: `crates/wires-mcp/src/http.rs`

- [ ] **Step 1: Wire the `oauth` module**

Add to `crates/wires-mcp/src/lib.rs`:

```rust
pub mod oauth;
```

Create `crates/wires-mcp/src/oauth/mod.rs`:

```rust
//! OAuth 2.1 PRM + Authorization Server endpoints. See spec §4.

pub mod prm;
```

- [ ] **Step 2: Write the failing test**

Create `crates/wires-mcp/src/oauth/prm.rs`:

```rust
use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::config::GatewayConfig;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrmDocument {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
}

impl PrmDocument {
    pub fn from_config(cfg: &GatewayConfig) -> Self {
        Self {
            resource: cfg.public_url.clone(),
            authorization_servers: vec![cfg.public_url.clone()],
            scopes_supported: vec!["mcp:wires".into()],
        }
    }
}

pub async fn handler(State(cfg): State<Arc<GatewayConfig>>) -> Json<PrmDocument> {
    Json(PrmDocument::from_config(&cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{ServiceState, app};
    use crate::store::Store;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn state() -> (TempDir, ServiceState) {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
        };
        let store = Store::open(&cfg.gateway_db_path()).unwrap();
        let state = ServiceState {
            config: std::sync::Arc::new(cfg),
            store,
            signing_key: std::sync::Arc::new(SigningKey::from_bytes(&[1u8; 32])),
        };
        (tmp, state)
    }

    #[tokio::test]
    async fn returns_the_prm_document() {
        let (_t, st) = state();
        let resp = app(st)
            .oneshot(
                Request::get("/.well-known/oauth-protected-resource")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let prm: PrmDocument = serde_json::from_slice(&body).unwrap();
        assert_eq!(prm.resource, "https://mcp.example.com");
        assert_eq!(prm.authorization_servers, vec!["https://mcp.example.com"]);
        assert_eq!(prm.scopes_supported, vec!["mcp:wires"]);
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test -p wires-mcp --lib oauth::prm`
Expected: FAIL with 404 from the router.

- [ ] **Step 4: Mount the route in the app**

Edit `crates/wires-mcp/src/http.rs`'s `app()` function:

```rust
pub fn app(state: ServiceState) -> Router {
    Router::new()
        .route("/_health", axum::routing::get(health))
        .route(
            "/.well-known/oauth-protected-resource",
            axum::routing::get(crate::oauth::prm::handler),
        )
        .with_state(state)
}
```

- [ ] **Step 5: Run the test again**

Run: `cargo test -p wires-mcp --lib oauth::prm`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-mcp/src/oauth/ crates/wires-mcp/src/lib.rs crates/wires-mcp/src/http.rs
git commit -m "wires-mcp: PRM endpoint (RFC 9728)"
```

---

### Task 9: AS metadata endpoint (`/.well-known/oauth-authorization-server`)

**Files:**
- Create: `crates/wires-mcp/src/oauth/as_meta.rs`
- Modify: `crates/wires-mcp/src/oauth/mod.rs`
- Modify: `crates/wires-mcp/src/http.rs`

- [ ] **Step 1: Add the module**

Add to `crates/wires-mcp/src/oauth/mod.rs`:

```rust
pub mod as_meta;
```

- [ ] **Step 2: Write the failing test**

Create `crates/wires-mcp/src/oauth/as_meta.rs`:

```rust
use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::config::GatewayConfig;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AsMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
}

impl AsMetadata {
    pub fn from_config(cfg: &GatewayConfig) -> Self {
        let base = cfg.public_url.trim_end_matches('/').to_string();
        Self {
            issuer: base.clone(),
            authorization_endpoint: format!("{base}/oauth/authorize"),
            token_endpoint: format!("{base}/oauth/token"),
            registration_endpoint: format!("{base}/oauth/register"),
            jwks_uri: format!("{base}/.well-known/jwks.json"),
            response_types_supported: vec!["code".into()],
            grant_types_supported: vec!["authorization_code".into(), "refresh_token".into()],
            code_challenge_methods_supported: vec!["S256".into()],
            token_endpoint_auth_methods_supported: vec!["none".into()],
            scopes_supported: vec!["mcp:wires".into()],
        }
    }
}

pub async fn handler(State(cfg): State<Arc<GatewayConfig>>) -> Json<AsMetadata> {
    Json(AsMetadata::from_config(&cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{ServiceState, app};
    use crate::store::Store;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn state() -> (TempDir, ServiceState) {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
        };
        let store = Store::open(&cfg.gateway_db_path()).unwrap();
        let state = ServiceState {
            config: std::sync::Arc::new(cfg),
            store,
            signing_key: std::sync::Arc::new(SigningKey::from_bytes(&[1u8; 32])),
        };
        (tmp, state)
    }

    #[tokio::test]
    async fn returns_the_as_metadata() {
        let (_t, st) = state();
        let resp = app(st)
            .oneshot(
                Request::get("/.well-known/oauth-authorization-server")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let m: AsMetadata = serde_json::from_slice(&body).unwrap();
        assert_eq!(m.issuer, "https://mcp.example.com");
        assert_eq!(m.authorization_endpoint, "https://mcp.example.com/oauth/authorize");
        assert_eq!(m.token_endpoint, "https://mcp.example.com/oauth/token");
        assert_eq!(m.code_challenge_methods_supported, vec!["S256"]);
        assert_eq!(m.token_endpoint_auth_methods_supported, vec!["none"]);
    }
}
```

- [ ] **Step 3: Mount the route**

Add to `app()` in `crates/wires-mcp/src/http.rs`:

```rust
        .route(
            "/.well-known/oauth-authorization-server",
            axum::routing::get(crate::oauth::as_meta::handler),
        )
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p wires-mcp --lib oauth::as_meta`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-mcp/src/oauth/as_meta.rs crates/wires-mcp/src/oauth/mod.rs crates/wires-mcp/src/http.rs
git commit -m "wires-mcp: AS metadata endpoint (RFC 8414)"
```

---

### Task 10: JWKS endpoint (`/.well-known/jwks.json`)

**Files:**
- Create: `crates/wires-mcp/src/oauth/jwks.rs`
- Modify: `crates/wires-mcp/src/oauth/mod.rs`
- Modify: `crates/wires-mcp/src/http.rs`

- [ ] **Step 1: Add the module**

Add `pub mod jwks;` to `crates/wires-mcp/src/oauth/mod.rs`.

- [ ] **Step 2: Write the failing test**

Create `crates/wires-mcp/src/oauth/jwks.rs`:

```rust
//! JWKS endpoint. Advertises the EdDSA verifying key under `OKP`/`Ed25519`
//! per RFC 8037.

use axum::Json;
use axum::extract::State;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: String, // "OKP"
    pub crv: String, // "Ed25519"
    pub kid: String,
    pub x: String, // base64url(pubkey)
    pub alg: String, // "EdDSA"
    #[serde(rename = "use")]
    pub use_: String, // "sig"
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

pub fn jwk_for(sk: &SigningKey) -> Jwk {
    let vk = sk.verifying_key();
    Jwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        kid: crate::keys::kid_for(&vk),
        x: URL_SAFE_NO_PAD.encode(vk.to_bytes()),
        alg: "EdDSA".into(),
        use_: "sig".into(),
    }
}

pub async fn handler(State(sk): State<Arc<SigningKey>>) -> Json<Jwks> {
    Json(Jwks {
        keys: vec![jwk_for(&sk)],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;
    use crate::http::{ServiceState, app};
    use crate::store::Store;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn state(seed: [u8; 32]) -> (TempDir, ServiceState) {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
        };
        let store = Store::open(&cfg.gateway_db_path()).unwrap();
        let state = ServiceState {
            config: std::sync::Arc::new(cfg),
            store,
            signing_key: std::sync::Arc::new(SigningKey::from_bytes(&seed)),
        };
        (tmp, state)
    }

    #[tokio::test]
    async fn jwks_advertises_one_eddsa_key() {
        let (_t, st) = state([3u8; 32]);
        let expected_kid = crate::keys::kid_for(&st.signing_key.verifying_key());
        let resp = app(st)
            .oneshot(Request::get("/.well-known/jwks.json").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let jwks: Jwks = serde_json::from_slice(&body).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        let k = &jwks.keys[0];
        assert_eq!(k.kty, "OKP");
        assert_eq!(k.crv, "Ed25519");
        assert_eq!(k.alg, "EdDSA");
        assert_eq!(k.use_, "sig");
        assert_eq!(k.kid, expected_kid);
        assert!(!k.x.is_empty());
    }
}
```

- [ ] **Step 3: Wire the route**

`ServiceState` already implements `FromRef<ServiceState> for Arc<GatewayConfig>`. Add another `FromRef` so jwks can extract `Arc<SigningKey>`. Append to `crates/wires-mcp/src/http.rs`:

```rust
impl FromRef<ServiceState> for Arc<SigningKey> {
    fn from_ref(s: &ServiceState) -> Self {
        Arc::clone(&s.signing_key)
    }
}
```

Mount the route in `app()`:

```rust
        .route("/.well-known/jwks.json", axum::routing::get(crate::oauth::jwks::handler))
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p wires-mcp --lib oauth::jwks`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-mcp/src/oauth/jwks.rs crates/wires-mcp/src/oauth/mod.rs crates/wires-mcp/src/http.rs
git commit -m "wires-mcp: JWKS endpoint (Ed25519 OKP)"
```

---

*End of Phase B. Phase C (DCR + bearer middleware) continues with Tasks 11–12.*

## Phase C — DCR + bearer middleware

### Task 11: DCR (`POST /oauth/register`, RFC 7591)

**Files:**
- Create: `crates/wires-mcp/src/oauth/register.rs`
- Modify: `crates/wires-mcp/src/oauth/mod.rs`
- Modify: `crates/wires-mcp/src/http.rs`

- [ ] **Step 1: Add the module**

`pub mod register;` in `crates/wires-mcp/src/oauth/mod.rs`.

- [ ] **Step 2: Write the failing test**

Create `crates/wires-mcp/src/oauth/register.rs`:

```rust
//! Dynamic Client Registration (RFC 7591). Public clients only — no
//! client_secret returned. PKCE is enforced at /authorize, so we don't
//! authenticate clients at this endpoint at all; only validate input shape.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::http::ServiceState;
use crate::store::OauthClientRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterResponse {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub token_endpoint_auth_method: String, // "none"
}

pub async fn handler(
    State(state): State<ServiceState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), (StatusCode, Json<serde_json::Value>)> {
    if req.client_name.is_empty() || req.redirect_uris.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_redirect_uri",
                "error_description": "client_name and at least one redirect_uri required"
            })),
        ));
    }
    let grant_types = req
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".into(), "refresh_token".into()]);
    for g in &grant_types {
        if g != "authorization_code" && g != "refresh_token" {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_client_metadata",
                    "error_description": format!("unsupported grant_type {g}")
                })),
            ));
        }
    }
    let client_id = uuid::Uuid::new_v4().to_string();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let rec = OauthClientRecord {
        client_id: client_id.clone(),
        client_name: req.client_name.clone(),
        redirect_uris: req.redirect_uris.clone(),
        grant_types: grant_types.clone(),
        created_at_ms: now_ms,
        revoked: false,
    };
    state.store.put_oauth_client(&rec).map_err(|e| {
        tracing::error!(error = %e, "DCR put_oauth_client");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "server_error"})),
        )
    })?;
    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            client_id,
            client_name: req.client_name,
            redirect_uris: req.redirect_uris,
            grant_types,
            token_endpoint_auth_method: "none".into(),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;
    use crate::http::{ServiceState, app};
    use crate::store::Store;
    use axum::body::Body;
    use axum::http::Request;
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn state() -> (TempDir, ServiceState) {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
        };
        let store = Store::open(&cfg.gateway_db_path()).unwrap();
        let st = ServiceState {
            config: std::sync::Arc::new(cfg),
            store,
            signing_key: std::sync::Arc::new(SigningKey::from_bytes(&[1u8; 32])),
        };
        (tmp, st)
    }

    #[tokio::test]
    async fn registers_a_new_public_client() {
        let (_t, st) = state();
        let body = serde_json::json!({
            "client_name": "Claude Desktop",
            "redirect_uris": ["http://localhost:33333/callback"]
        });
        let resp = app(st.clone())
            .oneshot(
                Request::post("/oauth/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let r: RegisterResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(r.client_name, "Claude Desktop");
        assert_eq!(r.token_endpoint_auth_method, "none");
        assert!(uuid::Uuid::parse_str(&r.client_id).is_ok());
        assert!(st.store.get_oauth_client(&r.client_id).unwrap().is_some());
    }

    #[tokio::test]
    async fn refuses_missing_redirect_uri() {
        let (_t, st) = state();
        let body = serde_json::json!({"client_name": "C", "redirect_uris": []});
        let resp = app(st)
            .oneshot(
                Request::post("/oauth/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn refuses_unsupported_grant_type() {
        let (_t, st) = state();
        let body = serde_json::json!({
            "client_name": "C",
            "redirect_uris": ["http://x"],
            "grant_types": ["password"]
        });
        let resp = app(st)
            .oneshot(
                Request::post("/oauth/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
```

- [ ] **Step 3: Mount the route**

Edit `crates/wires-mcp/src/http.rs`, in `app()`:

```rust
        .route(
            "/oauth/register",
            axum::routing::post(crate::oauth::register::handler),
        )
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p wires-mcp --lib oauth::register`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/wires-mcp/src/oauth/register.rs crates/wires-mcp/src/oauth/mod.rs crates/wires-mcp/src/http.rs
git commit -m "wires-mcp: DCR endpoint (RFC 7591) — public clients only"
```

---

### Task 12: Bearer auth middleware (for /mcp)

**Files:**
- Create: `crates/wires-mcp/src/oauth/middleware.rs`
- Modify: `crates/wires-mcp/src/oauth/mod.rs`

- [ ] **Step 1: Add the module**

`pub mod middleware;` in `crates/wires-mcp/src/oauth/mod.rs`.

- [ ] **Step 2: Write the failing test**

Create `crates/wires-mcp/src/oauth/middleware.rs`:

```rust
//! Bearer-token middleware for the /mcp route. Verifies signature + claims
//! offline, checks JTI against `revoked_jtis`, checks `client_id` against
//! `oauth_clients[].revoked`. On success, inserts the verified `Claims`
//! into the request extensions for downstream handlers.

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use chrono::Utc;

use crate::http::ServiceState;
use crate::token::{Claims, verify};

const WWW_AUTHENTICATE_HEADER: &str = "WWW-Authenticate";

pub async fn bearer(
    State(state): State<ServiceState>,
    mut req: Request,
    next: Next,
) -> Response {
    let header_val = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let token = match header_val.as_deref() {
        Some(h) if h.starts_with("Bearer ") => h[7..].trim().to_string(),
        _ => {
            return challenge(&state, "missing or non-bearer Authorization header");
        }
    };
    let is_jti_revoked = |jti: &str| {
        matches!(state.store.get_revoked_jti(jti), Ok(Some(_)))
    };
    let claims = match verify(
        &state.signing_key.verifying_key(),
        &state.config.public_url,
        &state.config.public_url,
        is_jti_revoked,
        &token,
        Utc::now().timestamp(),
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::info!(error = %e, "bearer verify failed");
            return challenge(&state, "token verification failed");
        }
    };
    if let Ok(Some(client)) = state.store.get_oauth_client(&claims.client_id) {
        if client.revoked {
            return challenge(&state, "client revoked");
        }
    } else {
        return challenge(&state, "unknown client");
    }
    req.extensions_mut().insert(claims);
    next.run(req).await
}

fn challenge(state: &ServiceState, _detail: &str) -> Response {
    let prm = format!(
        "{}/.well-known/oauth-protected-resource",
        state.config.public_url.trim_end_matches('/')
    );
    let www = format!(
        "Bearer realm=\"mcp\", resource_metadata=\"{prm}\""
    );
    let mut resp = Response::new(axum::body::Body::empty());
    *resp.status_mut() = StatusCode::UNAUTHORIZED;
    resp.headers_mut().insert(
        WWW_AUTHENTICATE_HEADER,
        www.parse().expect("static header"),
    );
    resp
}

pub fn claims_from(req: &Request) -> Option<&Claims> {
    req.extensions().get::<Claims>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;
    use crate::http::ServiceState;
    use crate::store::{OauthClientRecord, Store};
    use crate::token::{MintInput, mint};
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn state() -> (TempDir, ServiceState) {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
        };
        let store = Store::open(&cfg.gateway_db_path()).unwrap();
        let state = ServiceState {
            config: Arc::new(cfg),
            store,
            signing_key: Arc::new(SigningKey::from_bytes(&[1u8; 32])),
        };
        (tmp, state)
    }

    fn protected_app(state: ServiceState) -> Router {
        async fn handler() -> &'static str { "ok" }
        Router::new()
            .route("/mcp", get(handler))
            .route_layer(axum::middleware::from_fn_with_state(state.clone(), bearer))
            .with_state(state)
    }

    fn register_client(state: &ServiceState, client_id: &str) {
        state.store.put_oauth_client(&OauthClientRecord {
            client_id: client_id.into(),
            client_name: "test".into(),
            redirect_uris: vec!["http://x".into()],
            grant_types: vec!["authorization_code".into()],
            created_at_ms: 0,
            revoked: false,
        }).unwrap();
    }

    fn ts() -> i64 { chrono::Utc::now().timestamp() }

    #[tokio::test]
    async fn no_bearer_returns_401_with_www_authenticate() {
        let (_t, st) = state();
        let resp = protected_app(st)
            .oneshot(Request::get("/mcp").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www = resp.headers().get("WWW-Authenticate").unwrap().to_str().unwrap();
        assert!(www.contains("Bearer"));
        assert!(www.contains("resource_metadata="));
    }

    #[tokio::test]
    async fn valid_bearer_proceeds() {
        let (_t, st) = state();
        register_client(&st, "c1");
        let token = mint(
            &st.signing_key,
            &MintInput {
                iss: &st.config.public_url,
                sub: &"a".repeat(64),
                aud: &st.config.public_url,
                now_s: ts(),
                ttl_s: 60,
                client_id: "c1",
            },
        ).unwrap();
        let resp = protected_app(st)
            .oneshot(
                Request::get("/mcp")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn revoked_client_returns_401() {
        let (_t, st) = state();
        st.store.put_oauth_client(&OauthClientRecord {
            client_id: "c1".into(),
            client_name: "test".into(),
            redirect_uris: vec!["http://x".into()],
            grant_types: vec!["authorization_code".into()],
            created_at_ms: 0,
            revoked: true,
        }).unwrap();
        let token = mint(
            &st.signing_key,
            &MintInput {
                iss: &st.config.public_url,
                sub: &"a".repeat(64),
                aud: &st.config.public_url,
                now_s: ts(),
                ttl_s: 60,
                client_id: "c1",
            },
        ).unwrap();
        let resp = protected_app(st)
            .oneshot(
                Request::get("/mcp")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p wires-mcp --lib oauth::middleware`
Expected: PASS (3 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/wires-mcp/src/oauth/middleware.rs crates/wires-mcp/src/oauth/mod.rs
git commit -m "wires-mcp: bearer auth middleware + Claims propagation"
```

---

## Phase D — TenantSupervisor (per-user wires NodeRuntime fleet)

### Task 13: `TenantSupervisor::get_or_open`

**Files:**
- Create: `crates/wires-mcp/src/tenants.rs`
- Modify: `crates/wires-mcp/src/lib.rs`

- [ ] **Step 1: Add the module**

`pub mod tenants;` in `crates/wires-mcp/src/lib.rs`.

- [ ] **Step 2: Write the failing test**

Create `crates/wires-mcp/src/tenants.rs`:

```rust
//! Holds the live set of per-OAuth-user `NodeRuntime`s, opens them lazily
//! from `<data_dir>/users/<root_pubkey_hex>/`, and closes them after an
//! idle TTL. Each `NodeRuntime` binds its own iroh endpoint (per-user
//! addressing — fine at v1 scale; see spec §7 for the v2 sharing note).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use snafu::ResultExt;
use wires_node::NodeConfig;
use wires_node::runtime::NodeRuntime;

use crate::error::{OpenRuntimeSnafu, Result, UnknownUserSnafu};

#[derive(Clone)]
pub struct TenantSupervisor {
    inner: Arc<tokio::sync::Mutex<Inner>>,
    users_dir: PathBuf,
    idle_ttl: Duration,
}

struct Inner {
    runtimes: HashMap<String, Slot>,
}

struct Slot {
    runtime: Arc<NodeRuntime>,
    last_touched: Instant,
}

impl TenantSupervisor {
    pub fn new(users_dir: PathBuf, idle_ttl: Duration) -> Self {
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(Inner {
                runtimes: HashMap::new(),
            })),
            users_dir,
            idle_ttl,
        }
    }

    pub async fn get_or_open(&self, sub: &str) -> Result<Arc<NodeRuntime>> {
        let dir = self.users_dir.join(sub);
        if !dir.exists() {
            return UnknownUserSnafu { sub: sub.to_string() }.fail();
        }
        let mut g = self.inner.lock().await;
        if let Some(slot) = g.runtimes.get_mut(sub) {
            slot.last_touched = Instant::now();
            return Ok(Arc::clone(&slot.runtime));
        }
        let cfg_path = dir.join("config.toml");
        let s = std::fs::read_to_string(&cfg_path).map_err(|e| crate::error::GatewayError::Io {
            source: e,
            location: snafu::location!(),
        })?;
        let mut cfg: NodeConfig = toml::from_str(&s).map_err(|e| crate::error::GatewayError::Io {
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
            location: snafu::location!(),
        })?;
        cfg.data_dir = dir.clone();
        let runtime = NodeRuntime::open(cfg).await.context(OpenRuntimeSnafu)?;
        let runtime = Arc::new(runtime);
        g.runtimes.insert(
            sub.to_string(),
            Slot {
                runtime: Arc::clone(&runtime),
                last_touched: Instant::now(),
            },
        );
        Ok(runtime)
    }

    pub async fn close(&self, sub: &str) {
        let mut g = self.inner.lock().await;
        g.runtimes.remove(sub);
    }

    pub async fn close_idle(&self) {
        let now = Instant::now();
        let mut g = self.inner.lock().await;
        let idle: Vec<String> = g
            .runtimes
            .iter()
            .filter(|(_, slot)| now.duration_since(slot.last_touched) > self.idle_ttl)
            .map(|(k, _)| k.clone())
            .collect();
        for k in idle {
            g.runtimes.remove(&k);
        }
    }

    pub async fn is_open(&self, sub: &str) -> bool {
        self.inner.lock().await.runtimes.contains_key(sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn get_or_open_errors_for_unknown_sub() {
        let tmp = TempDir::new().unwrap();
        let s = TenantSupervisor::new(tmp.path().to_path_buf(), Duration::from_secs(60));
        let err = s.get_or_open("nope").await.unwrap_err();
        assert!(matches!(err, crate::error::GatewayError::UnknownUser { .. }));
    }
}
```

- [ ] **Step 3: Run the test**

Run: `cargo test -p wires-mcp --lib tenants`
Expected: PASS (1 test).

- [ ] **Step 4: Commit**

```bash
git add crates/wires-mcp/src/tenants.rs crates/wires-mcp/src/lib.rs
git commit -m "wires-mcp: TenantSupervisor::get_or_open + close (idle GC stub)"
```

---

### Task 14: `TenantSupervisor::bind` (move temp dir → users + open)

**Files:**
- Modify: `crates/wires-mcp/src/tenants.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/wires-mcp/src/tenants.rs` inside `mod tests`:

```rust
    #[tokio::test]
    async fn bind_renames_then_opens() {
        let tmp = TempDir::new().unwrap();
        let users = tmp.path().join("users");
        std::fs::create_dir_all(&users).unwrap();
        let pending = tmp.path().join("pending").join("sess1");
        std::fs::create_dir_all(&pending).unwrap();
        let sub = "ab".repeat(32);
        let cfg = NodeConfig {
            data_dir: pending.clone(),
            root_pubkey_hex: sub.clone(),
            host: None,
        };
        std::fs::write(
            pending.join("config.toml"),
            toml::to_string_pretty(&cfg).unwrap(),
        ).unwrap();
        std::fs::write(pending.join("iroh.secret"), [7u8; 32]).unwrap();

        let sup = TenantSupervisor::new(users.clone(), Duration::from_secs(60));
        sup.bind(&sub, &pending).await.unwrap();

        assert!(users.join(&sub).exists());
        assert!(!pending.exists());
        assert!(sup.is_open(&sub).await);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p wires-mcp --lib tenants::tests::bind_renames_then_opens`
Expected: FAIL with "no method named `bind`".

- [ ] **Step 3: Add `bind` to `TenantSupervisor`**

In `crates/wires-mcp/src/tenants.rs`, add after `get_or_open`:

```rust
    pub async fn bind(&self, sub: &str, source_dir: &std::path::Path) -> Result<Arc<NodeRuntime>> {
        if !source_dir.exists() {
            return Err(crate::error::GatewayError::Io {
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "source dir missing"),
                location: snafu::location!(),
            });
        }
        std::fs::create_dir_all(&self.users_dir).map_err(|e| crate::error::GatewayError::Io {
            source: e,
            location: snafu::location!(),
        })?;
        let dest = self.users_dir.join(sub);
        std::fs::rename(source_dir, &dest).map_err(|e| crate::error::GatewayError::TempDataDirMove {
            source: e,
            location: snafu::location!(),
        })?;
        self.get_or_open(sub).await
    }
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p wires-mcp --lib tenants::tests::bind_renames_then_opens`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-mcp/src/tenants.rs
git commit -m "wires-mcp: TenantSupervisor::bind (atomic rename + open)"
```

---

### Task 15: Idle GC (background tick)

**Files:**
- Modify: `crates/wires-mcp/src/tenants.rs`

- [ ] **Step 1: Write the failing test**

Append to `mod tests`:

```rust
    #[tokio::test]
    async fn close_idle_drops_stale_slots() {
        let tmp = TempDir::new().unwrap();
        let users = tmp.path().join("users");
        std::fs::create_dir_all(&users).unwrap();
        let sub = "cd".repeat(32);
        let dir = users.join(&sub);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = NodeConfig {
            data_dir: dir.clone(),
            root_pubkey_hex: sub.clone(),
            host: None,
        };
        std::fs::write(dir.join("config.toml"), toml::to_string_pretty(&cfg).unwrap()).unwrap();
        std::fs::write(dir.join("iroh.secret"), [5u8; 32]).unwrap();

        let sup = TenantSupervisor::new(users.clone(), Duration::from_millis(50));
        let _ = sup.get_or_open(&sub).await.unwrap();
        assert!(sup.is_open(&sub).await);
        tokio::time::sleep(Duration::from_millis(100)).await;
        sup.close_idle().await;
        assert!(!sup.is_open(&sub).await);
    }

    #[tokio::test]
    async fn spawn_gc_returns_a_join_handle_that_cancels() {
        let tmp = TempDir::new().unwrap();
        let sup = TenantSupervisor::new(tmp.path().to_path_buf(), Duration::from_millis(50));
        let h = sup.clone().spawn_gc(Duration::from_millis(10));
        h.abort();
    }
```

- [ ] **Step 2: Run the failing test**

Run: `cargo test -p wires-mcp --lib tenants::tests::spawn_gc`
Expected: FAIL with "no method named `spawn_gc`".

- [ ] **Step 3: Add `spawn_gc`**

In `crates/wires-mcp/src/tenants.rs`, add this method to `impl TenantSupervisor`:

```rust
    pub fn spawn_gc(self, tick: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tick);
            loop {
                interval.tick().await;
                self.close_idle().await;
            }
        })
    }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p wires-mcp --lib tenants`
Expected: PASS (all tests in module).

- [ ] **Step 5: Commit**

```bash
git add crates/wires-mcp/src/tenants.rs
git commit -m "wires-mcp: TenantSupervisor::close_idle + spawn_gc tick"
```

---

## Phase E — wires-node `on_paired` extension point

### Task 16: `NodePairHandler::with_on_paired` callback

**Files:**
- Modify: `crates/wires-node/src/pair.rs`
- Modify: `crates/wires-node/src/lib.rs` (if needed for re-exports)

- [ ] **Step 1: Write the failing test**

Append to the existing test module in `crates/wires-node/src/pair.rs` (or create one if absent — look for `#[cfg(test)] mod tests`; if no test module yet, add one at the bottom):

```rust
#[cfg(test)]
mod on_paired_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct DummyErr(String);
    impl std::fmt::Display for DummyErr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }
    impl std::error::Error for DummyErr {}

    #[test]
    fn pair_install_summary_carries_root_and_cap() {
        let s = PairInstallSummary {
            root_pubkey_hex: "deadbeef".repeat(8),
            cap_id: [1u8; 16],
            installed_at: 12345,
        };
        assert_eq!(s.root_pubkey_hex.len(), 64);
        assert_eq!(s.cap_id, [1u8; 16]);
    }

    #[test]
    fn on_paired_callback_type_compiles() {
        let count = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::clone(&count);
        let cb: Arc<OnPaired> = Arc::new(move |_s: PairInstallSummary| {
            c2.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let s = PairInstallSummary {
            root_pubkey_hex: "x".into(),
            cap_id: [0u8; 16],
            installed_at: 0,
        };
        (cb)(s).unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}
```

- [ ] **Step 2: Run the failing test**

Run: `cargo test -p wires-node --lib pair::on_paired_tests`
Expected: FAIL with "no associated type `PairInstallSummary`" or similar.

- [ ] **Step 3: Add `PairInstallSummary` + `OnPaired` + `with_on_paired`**

In `crates/wires-node/src/pair.rs`, after the `pub enum PairOutcome` block (around line 100), add:

```rust
/// Summary of a successful pair install. Carries the household root pubkey
/// (so the caller can route on OAuth `sub`) plus the installed cap id and a
/// timestamp. The gateway uses this in `on_paired` to bind the temp data
/// dir to `users/<root>/` and complete the OAuth `/authorize` flow.
#[derive(Debug, Clone)]
pub struct PairInstallSummary {
    pub root_pubkey_hex: String,
    pub cap_id: [u8; 16],
    pub installed_at: i64,
}

/// Callback invoked after `install_grant` commits and before
/// `PairFrame::Ack` is sent. Returning `Err` aborts the ack: the handler
/// returns `PairFrame::Reject(AlreadyPaired)` if the error is of type
/// `OnPairedError::AlreadyPaired`, otherwise `Reject(InternalError)`.
pub type OnPaired = dyn Fn(PairInstallSummary) -> std::result::Result<(), OnPairedError>
    + Send
    + Sync;

/// Reject codes the on_paired callback can request.
#[derive(Debug)]
pub enum OnPairedError {
    AlreadyPaired(String),
    Internal(String),
}

impl std::fmt::Display for OnPairedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyPaired(m) => write!(f, "already paired: {m}"),
            Self::Internal(m) => write!(f, "internal: {m}"),
        }
    }
}
impl std::error::Error for OnPairedError {}
```

Now extend `HandlerState` to carry the callback. In `crates/wires-node/src/pair.rs`, find the existing `struct HandlerState` and add a field:

```rust
struct HandlerState {
    data_dir: std::path::PathBuf,
    node: Arc<Node>,
    self_agent_pubkey: [u8; 32],
    expected_nonce: [u8; 32],
    ephemeral_secret: StaticSecret,
    request_expires_ms: i64,
    outcome_tx: Option<oneshot::Sender<PairOutcome>>,
    completed: bool,
    on_paired: Option<Arc<OnPaired>>,
}
```

Update the `NodePairHandler::new` constructor to default `on_paired: None`, and add `with_on_paired`:

```rust
impl NodePairHandler {
    pub fn new(
        data_dir: std::path::PathBuf,
        node: Arc<Node>,
        self_agent_pubkey: [u8; 32],
        expected_nonce: [u8; 32],
        ephemeral_secret: StaticSecret,
        request_expires_ms: i64,
        outcome_tx: oneshot::Sender<PairOutcome>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HandlerState {
                data_dir,
                node,
                self_agent_pubkey,
                expected_nonce,
                ephemeral_secret,
                request_expires_ms,
                outcome_tx: Some(outcome_tx),
                completed: false,
                on_paired: None,
            })),
        }
    }

    pub fn with_on_paired(mut self, on_paired: Arc<OnPaired>) -> Self {
        // Replace the inner Arc with a new one carrying the callback.
        // Done by re-wrapping; ok because no one has cloned `self.inner` yet
        // at construction time.
        let inner = Arc::get_mut(&mut self.inner)
            .expect("with_on_paired must be called before any clone of the handler");
        let state = inner.get_mut();
        state.on_paired = Some(on_paired);
        self
    }
}
```

Then update the `install_grant` success arm in `handle_grant`. Find the line where `outcome_tx.take()` is sent and `PairFrame::Ack` is returned (around line 200-ish in `pair.rs`). Replace the `Ok(out) => { ... }` arm with:

```rust
            Ok(out) => {
                if let Err(e) = crate::pair_pending::delete(&state.data_dir) {
                    return reject(
                        PairRejectCode::InternalError,
                        &format!("delete pair_pending: {e}"),
                    );
                }
                state.completed = true;
                if let Some(cb) = state.on_paired.clone() {
                    let summary = PairInstallSummary {
                        root_pubkey_hex: hex::encode(grant.root_pubkey),
                        cap_id: out.cap_id,
                        installed_at: unix_now_ms(),
                    };
                    if let Err(e) = (cb)(summary) {
                        let (code, msg) = match e {
                            OnPairedError::AlreadyPaired(m) => (PairRejectCode::AlreadyPaired, m),
                            OnPairedError::Internal(m) => (PairRejectCode::InternalError, m),
                        };
                        return reject(code, &msg);
                    }
                }
                if let Some(tx) = state.outcome_tx.take() {
                    let _ = tx.send(PairOutcome::Paired { cap_id: out.cap_id });
                }
                PairFrame::Ack(PairAck {
                    installed_cap_id: out.cap_id,
                    installed_at: unix_now_ms(),
                })
            }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p wires-node --lib pair`
Expected: PASS (existing pair tests + the two new ones).

- [ ] **Step 5: Verify the wider workspace still builds**

Run: `cargo build --workspace`
Expected: success.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-node/src/pair.rs
git commit -m "wires-node: NodePairHandler::with_on_paired + PairInstallSummary

Optional callback fires after install commits and before Ack. Returning
Err converts to Reject(AlreadyPaired) or Reject(InternalError); the wires-mcp
gateway is the first consumer."
```

---

*End of Phase E. Phase F (authorize + sign-in + pair-bridge) continues with Tasks 17–22.*

## Phase F — Authorize + sign-in + pair-bridge

### Task 17: `SignInChallenge` struct + sign/verify helpers

**Files:**
- Create: `crates/wires-mcp/src/sign_in.rs`
- Modify: `crates/wires-mcp/src/lib.rs`

- [ ] **Step 1: Add the module**

`pub mod sign_in;` in `crates/wires-mcp/src/lib.rs`.

- [ ] **Step 2: Write the failing test**

Create `crates/wires-mcp/src/sign_in.rs`:

```rust
//! `SignInChallenge` — what the returning-user QR encodes. The iOS app
//! signs the canonical JSON (with `signature` zeroed) using the household
//! root ed25519 and POSTs the signature back to /oauth/signin/assertion.

use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignInChallenge {
    pub version: u8,
    pub kind: String,           // always "wires.signin.v1"
    pub gateway_url: String,
    pub session_id: String,
    pub nonce: String,          // hex of 32 bytes
    pub issued_at: i64,
    pub expires: i64,
}

impl SignInChallenge {
    pub const KIND: &'static str = "wires.signin.v1";

    pub fn new(gateway_url: &str, session_id: &str, nonce: [u8; 32], now_ms: i64, ttl_ms: i64) -> Self {
        Self {
            version: 1,
            kind: Self::KIND.into(),
            gateway_url: gateway_url.trim_end_matches('/').to_string(),
            session_id: session_id.to_string(),
            nonce: hex::encode(nonce),
            issued_at: now_ms,
            expires: now_ms + ttl_ms,
        }
    }

    /// Canonical JSON encoding suitable for signing. Stable ordering and no
    /// insignificant whitespace.
    pub fn signing_bytes(&self) -> Vec<u8> {
        // Same canonicalization as wires_core::content
        let v = serde_json::to_value(self).expect("SignInChallenge always serializable");
        let canonical = canonicalize(&v);
        serde_json::to_vec(&canonical).expect("canonical JSON")
    }

    pub fn encode_url_safe_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_bytes())
    }

    pub fn decode_url_safe_b64(s: &str) -> Result<Self, serde_json::Error> {
        let bytes = URL_SAFE_NO_PAD.decode(s).map_err(|e| {
            use serde::de::Error;
            serde_json::Error::custom(format!("base64: {e}"))
        })?;
        serde_json::from_slice(&bytes)
    }

    pub fn sign(&self, root: &SigningKey) -> Signature {
        root.sign(&self.signing_bytes())
    }

    pub fn verify(&self, root_pubkey: &VerifyingKey, sig: &Signature) -> bool {
        root_pubkey.verify(&self.signing_bytes(), sig).is_ok()
    }
}

fn canonicalize(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(m) => {
            let mut sorted = serde_json::Map::new();
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            for k in keys {
                sorted.insert(k.clone(), canonicalize(&m[k]));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(canonicalize).collect())
        }
        _ => v.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn sk(seed: u8) -> SigningKey { SigningKey::from_bytes(&[seed; 32]) }

    fn ch() -> SignInChallenge {
        SignInChallenge::new("https://mcp.example.com", "sess-1", [7u8; 32], 1_000, 60_000)
    }

    #[test]
    fn encode_decode_roundtrip() {
        let c = ch();
        let s = c.encode_url_safe_b64();
        let back = SignInChallenge::decode_url_safe_b64(&s).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn sign_and_verify_with_root_key() {
        let k = sk(1);
        let c = ch();
        let sig = c.sign(&k);
        assert!(c.verify(&k.verifying_key(), &sig));
    }

    #[test]
    fn wrong_root_does_not_verify() {
        let k1 = sk(1);
        let k2 = sk(2);
        let c = ch();
        let sig = c.sign(&k1);
        assert!(!c.verify(&k2.verifying_key(), &sig));
    }

    #[test]
    fn tampering_invalidates_signature() {
        let k = sk(1);
        let c = ch();
        let sig = c.sign(&k);
        let mut tampered = c.clone();
        tampered.nonce = hex::encode([8u8; 32]);
        assert!(!tampered.verify(&k.verifying_key(), &sig));
    }
}
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p wires-mcp --lib sign_in`
Expected: PASS (4 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/wires-mcp/src/sign_in.rs crates/wires-mcp/src/lib.rs
git commit -m "wires-mcp: SignInChallenge canonical sign+verify"
```

---

### Task 18: GET /oauth/authorize — request validation + session creation

**Files:**
- Create: `crates/wires-mcp/src/oauth/authorize.rs`
- Modify: `crates/wires-mcp/src/oauth/mod.rs`
- Modify: `crates/wires-mcp/src/http.rs`

- [ ] **Step 1: Add the module**

`pub mod authorize;` in `crates/wires-mcp/src/oauth/mod.rs`.

- [ ] **Step 2: Write the failing test**

Create `crates/wires-mcp/src/oauth/authorize.rs`:

```rust
//! `GET /oauth/authorize` — entry point to the consent UX. Validates the
//! request, creates an `auth_sessions` row + a `pending_pairs` row + a
//! `pending_signins` row (both QRs always shown), renders the consent HTML.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use chrono::Utc;
use serde::Deserialize;

use crate::http::ServiceState;
use crate::sign_in::SignInChallenge;
use crate::store::{
    AuthSessionKind, AuthSessionRecord, PendingPairRecord, PendingSigninRecord,
};

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub resource: String,
    pub state: String,
}

/// 10-minute consent window default.
pub const AUTH_SESSION_TTL_MS: i64 = 600_000;
/// 5-minute sign-in challenge TTL.
pub const SIGNIN_CHALLENGE_TTL_MS: i64 = 300_000;

#[derive(Debug)]
pub struct AuthorizeContext {
    pub session_id: String,
    pub client_name: String,
    pub pair_token_b64: String,
    pub signin_challenge_b64: String,
}

pub async fn handler(
    State(state): State<ServiceState>,
    Query(p): Query<AuthorizeParams>,
) -> Response {
    match validate_and_create(&state, &p).await {
        Ok(ctx) => crate::oauth::authorize_html::render(&ctx).into_response(),
        Err((status, body)) => (status, axum::Json(body)).into_response(),
    }
}

pub async fn validate_and_create(
    state: &ServiceState,
    p: &AuthorizeParams,
) -> std::result::Result<AuthorizeContext, (StatusCode, serde_json::Value)> {
    if p.response_type != "code" {
        return Err((StatusCode::BAD_REQUEST, oauth_err("unsupported_response_type", "only `code` is supported")));
    }
    if p.code_challenge_method != "S256" {
        return Err((StatusCode::BAD_REQUEST, oauth_err("invalid_request", "code_challenge_method must be S256")));
    }
    if p.resource.trim_end_matches('/') != state.config.public_url.trim_end_matches('/') {
        return Err((StatusCode::BAD_REQUEST, oauth_err("invalid_target", "resource does not match issuer")));
    }
    if let Some(scope) = &p.scope {
        for s in scope.split_whitespace() {
            if s != "mcp:wires" {
                return Err((StatusCode::BAD_REQUEST, oauth_err("invalid_scope", "only mcp:wires is supported")));
            }
        }
    }
    let client = state
        .store
        .get_oauth_client(&p.client_id)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, oauth_err("server_error", "store")))?
        .ok_or_else(|| (StatusCode::BAD_REQUEST, oauth_err("invalid_client", "unknown client_id")))?;
    if client.revoked {
        return Err((StatusCode::BAD_REQUEST, oauth_err("invalid_client", "client revoked")));
    }
    if !client.redirect_uris.iter().any(|u| u == &p.redirect_uri) {
        return Err((StatusCode::BAD_REQUEST, oauth_err("invalid_request", "redirect_uri not registered")));
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    let now_ms = Utc::now().timestamp_millis();
    let session = AuthSessionRecord {
        session_id: session_id.clone(),
        client_id: p.client_id.clone(),
        redirect_uri: p.redirect_uri.clone(),
        code_challenge: p.code_challenge.clone(),
        code_challenge_method: p.code_challenge_method.clone(),
        resource: p.resource.clone(),
        state: p.state.clone(),
        kind: AuthSessionKind::Pending,
        issued_at_ms: now_ms,
        expires_ms: now_ms + AUTH_SESSION_TTL_MS,
    };
    state.store.put_auth_session(&session).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, oauth_err("server_error", "store"))
    })?;

    // Sign-in QR: a fresh challenge always rendered.
    let mut nonce = [0u8; 32];
    use rand_core::RngCore as _;
    rand_core::OsRng.fill_bytes(&mut nonce);
    let challenge = SignInChallenge::new(
        &state.config.public_url,
        &session_id,
        nonce,
        now_ms,
        SIGNIN_CHALLENGE_TTL_MS,
    );
    state
        .store
        .put_pending_signin(&PendingSigninRecord {
            session_id: session_id.clone(),
            challenge_nonce_hex: hex::encode(nonce),
            ttl_expires_ms: now_ms + SIGNIN_CHALLENGE_TTL_MS,
        })
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, oauth_err("server_error", "store")))?;

    // Pair-listen token is constructed by pair_bridge in Task 21; here we
    // just leave a placeholder so Tasks 18–20 can be developed independently.
    // Task 21 replaces this with the actual PairRequest token.
    let pair_token_b64 = String::new();
    state
        .store
        .put_pending_pair(&PendingPairRecord {
            session_id: session_id.clone(),
            temp_data_dir: String::new(),
            request_token_b64: pair_token_b64.clone(),
            ttl_expires_ms: now_ms + AUTH_SESSION_TTL_MS,
        })
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, oauth_err("server_error", "store")))?;

    Ok(AuthorizeContext {
        session_id,
        client_name: client.client_name,
        pair_token_b64,
        signin_challenge_b64: challenge.encode_url_safe_b64(),
    })
}

fn oauth_err(code: &str, desc: &str) -> serde_json::Value {
    serde_json::json!({"error": code, "error_description": desc})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;
    use crate::store::{OauthClientRecord, Store};
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn state() -> (TempDir, ServiceState) {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
        };
        let store = Store::open(&cfg.gateway_db_path()).unwrap();
        store.put_oauth_client(&OauthClientRecord {
            client_id: "c1".into(),
            client_name: "Claude Desktop".into(),
            redirect_uris: vec!["http://localhost:33333/callback".into()],
            grant_types: vec!["authorization_code".into()],
            created_at_ms: 0,
            revoked: false,
        }).unwrap();
        (
            tmp,
            ServiceState {
                config: Arc::new(cfg),
                store,
                signing_key: Arc::new(SigningKey::from_bytes(&[1u8; 32])),
            },
        )
    }

    fn params() -> AuthorizeParams {
        AuthorizeParams {
            response_type: "code".into(),
            client_id: "c1".into(),
            redirect_uri: "http://localhost:33333/callback".into(),
            scope: Some("mcp:wires".into()),
            code_challenge: "cc".into(),
            code_challenge_method: "S256".into(),
            resource: "https://mcp.example.com".into(),
            state: "st".into(),
        }
    }

    #[tokio::test]
    async fn happy_path_creates_session_pending_pair_pending_signin() {
        let (_t, st) = state();
        let ctx = validate_and_create(&st, &params()).await.unwrap();
        assert!(!ctx.session_id.is_empty());
        assert_eq!(ctx.client_name, "Claude Desktop");
        assert!(!ctx.signin_challenge_b64.is_empty());
        assert!(st.store.get_auth_session(&ctx.session_id).unwrap().is_some());
        assert!(st.store.get_pending_signin(&ctx.session_id).unwrap().is_some());
        assert!(st.store.get_pending_pair(&ctx.session_id).unwrap().is_some());
    }

    #[tokio::test]
    async fn rejects_wrong_response_type() {
        let (_t, st) = state();
        let mut p = params();
        p.response_type = "token".into();
        let err = validate_and_create(&st, &p).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1["error"], "unsupported_response_type");
    }

    #[tokio::test]
    async fn rejects_wrong_pkce_method() {
        let (_t, st) = state();
        let mut p = params();
        p.code_challenge_method = "plain".into();
        let err = validate_and_create(&st, &p).await.unwrap_err();
        assert_eq!(err.1["error"], "invalid_request");
    }

    #[tokio::test]
    async fn rejects_audience_mismatch() {
        let (_t, st) = state();
        let mut p = params();
        p.resource = "https://other.example".into();
        let err = validate_and_create(&st, &p).await.unwrap_err();
        assert_eq!(err.1["error"], "invalid_target");
    }

    #[tokio::test]
    async fn rejects_unregistered_redirect_uri() {
        let (_t, st) = state();
        let mut p = params();
        p.redirect_uri = "http://evil/callback".into();
        let err = validate_and_create(&st, &p).await.unwrap_err();
        assert_eq!(err.1["error"], "invalid_request");
    }

    #[tokio::test]
    async fn rejects_unknown_client() {
        let (_t, st) = state();
        let mut p = params();
        p.client_id = "nope".into();
        let err = validate_and_create(&st, &p).await.unwrap_err();
        assert_eq!(err.1["error"], "invalid_client");
    }
}
```

- [ ] **Step 3: Create the placeholder HTML module so the handler compiles**

Create `crates/wires-mcp/src/oauth/authorize_html.rs` with a stub that Task 19 replaces:

```rust
use axum::response::Html;
use crate::oauth::authorize::AuthorizeContext;

pub fn render(ctx: &AuthorizeContext) -> Html<String> {
    Html(format!(
        "<!doctype html><html><body><p>session: {}</p></body></html>",
        ctx.session_id
    ))
}
```

Add `pub mod authorize_html;` to `crates/wires-mcp/src/oauth/mod.rs`.

- [ ] **Step 4: Mount the route in `http.rs`**

```rust
        .route(
            "/oauth/authorize",
            axum::routing::get(crate::oauth::authorize::handler),
        )
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p wires-mcp --lib oauth::authorize`
Expected: PASS (6 tests).

- [ ] **Step 6: Commit**

```bash
git add crates/wires-mcp/src/oauth/authorize.rs crates/wires-mcp/src/oauth/authorize_html.rs crates/wires-mcp/src/oauth/mod.rs crates/wires-mcp/src/http.rs
git commit -m "wires-mcp: GET /oauth/authorize — validate + session+pending rows"
```

---

### Task 19: Consent-page HTML (two QRs, polling JS)

**Files:**
- Modify: `crates/wires-mcp/src/oauth/authorize_html.rs`

- [ ] **Step 1: Write the failing test**

Replace `crates/wires-mcp/src/oauth/authorize_html.rs` with a real renderer + test:

```rust
//! Renders the consent HTML page. Two QR codes (pair on the left, sign-in
//! on the right) inline as SVG, plus a small JS polling loop that hits
//! `/oauth/authorize/status/<session_id>` and performs the OAuth redirect
//! when one of the paths completes.

use axum::response::Html;

use crate::oauth::authorize::AuthorizeContext;

pub fn render(ctx: &AuthorizeContext) -> Html<String> {
    let pair_svg = render_qr_svg(&ctx.pair_token_b64);
    let signin_svg = render_qr_svg(&ctx.signin_challenge_b64);
    let session_id = html_escape(&ctx.session_id);
    let client_name = html_escape(&ctx.client_name);
    Html(format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign in to MCP Gateway</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; max-width: 860px; }}
h1 {{ font-size: 1.4rem; margin-bottom: 0.25rem; }}
.subtitle {{ color: #666; margin-top: 0; }}
.row {{ display: flex; gap: 2rem; margin-top: 2rem; }}
.col {{ flex: 1; border: 1px solid #ddd; border-radius: 12px; padding: 1.5rem; text-align: center; }}
.col h2 {{ font-size: 1.1rem; margin: 0 0 1rem; }}
.qr {{ width: 240px; height: 240px; margin: 0 auto; }}
.qr svg {{ width: 100%; height: 100%; }}
.hint {{ color: #666; font-size: 0.9rem; margin-top: 1rem; }}
</style>
</head>
<body>
<h1>Sign in to MCP Gateway</h1>
<p class="subtitle">Requesting access for <strong>{client_name}</strong>. Scope: <code>mcp:wires</code>.</p>
<div class="row">
  <div class="col">
    <h2>First time here?</h2>
    <div class="qr">{pair_svg}</div>
    <p class="hint">Scan with the Wires app and approve the new agent.</p>
  </div>
  <div class="col">
    <h2>Already signed in?</h2>
    <div class="qr">{signin_svg}</div>
    <p class="hint">Scan with the Wires app to authenticate.</p>
  </div>
</div>
<p id="status" class="hint">Waiting…</p>
<script>
(async () => {{
  const sid = {session_id_json};
  while (true) {{
    const r = await fetch('/oauth/authorize/status/' + encodeURIComponent(sid));
    if (!r.ok) {{ document.getElementById('status').textContent = 'status error'; break; }}
    const body = await r.json();
    if (body.kind === 'done') {{
      const u = new URL(body.redirect_uri);
      u.searchParams.set('code', body.code);
      u.searchParams.set('state', body.state);
      window.location = u.toString();
      return;
    }} else if (body.kind === 'expired') {{
      document.getElementById('status').textContent = 'session expired, reload to try again';
      return;
    }}
    await new Promise(r => setTimeout(r, 1500));
  }}
}})();
</script>
</body></html>"##,
        session_id_json = serde_json::to_string(&session_id).unwrap(),
    ))
}

fn render_qr_svg(payload: &str) -> String {
    if payload.is_empty() {
        return "<svg viewBox=\"0 0 1 1\"></svg>".to_string();
    }
    match qrcode::QrCode::new(payload.as_bytes()) {
        Ok(qr) => qr.render::<qrcode::render::svg::Color>().build(),
        Err(_) => "<svg viewBox=\"0 0 1 1\"></svg>".to_string(),
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_both_qrs_and_session_id() {
        let ctx = AuthorizeContext {
            session_id: "sess-1".into(),
            client_name: "Claude Desktop".into(),
            pair_token_b64: "AAAA".into(),
            signin_challenge_b64: "BBBB".into(),
        };
        let html = render(&ctx).0;
        assert!(html.contains("sess-1"));
        assert!(html.contains("Claude Desktop"));
        // Two SVGs (one per QR).
        assert_eq!(html.matches("<svg").count(), 2);
    }

    #[test]
    fn renders_safely_with_html_in_client_name() {
        let ctx = AuthorizeContext {
            session_id: "sess-1".into(),
            client_name: "<script>evil</script>".into(),
            pair_token_b64: "AAAA".into(),
            signin_challenge_b64: "BBBB".into(),
        };
        let html = render(&ctx).0;
        assert!(!html.contains("<script>evil"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
```

- [ ] **Step 2: Run the tests**

Run: `cargo test -p wires-mcp --lib oauth::authorize_html`
Expected: PASS (2 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/wires-mcp/src/oauth/authorize_html.rs
git commit -m "wires-mcp: consent page HTML with both QRs + polling JS"
```

---

### Task 20: `GET /oauth/authorize/status/{session_id}`

**Files:**
- Create: `crates/wires-mcp/src/oauth/authorize_status.rs`
- Modify: `crates/wires-mcp/src/oauth/mod.rs`
- Modify: `crates/wires-mcp/src/http.rs`

- [ ] **Step 1: Add the module**

`pub mod authorize_status;` in `crates/wires-mcp/src/oauth/mod.rs`.

- [ ] **Step 2: Write the failing test**

Create `crates/wires-mcp/src/oauth/authorize_status.rs`:

```rust
//! `GET /oauth/authorize/status/{session_id}` — browser-polled JSON status.
//! Returns `pending`, `done` with auth code + state + redirect_uri, or
//! `expired`. No long-poll in v1 (the browser polls every ~1.5s; clamp by
//! `Cache-Control: no-store`).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use chrono::Utc;
use serde::Serialize;

use crate::http::ServiceState;
use crate::store::AuthSessionKind;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StatusResponse {
    Pending,
    Done {
        code: String,
        state: String,
        redirect_uri: String,
    },
    Expired,
}

pub async fn handler(
    State(state): State<ServiceState>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    let session = match state.store.get_auth_session(&session_id) {
        Ok(Some(s)) => s,
        Ok(None) => return (StatusCode::NOT_FOUND, headers, Json(serde_json::json!({"error":"unknown_session"}))).into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, headers, Json(serde_json::json!({"error":"server_error"}))).into_response(),
    };
    let now_ms = Utc::now().timestamp_millis();
    let body = match session.kind {
        AuthSessionKind::Pending if now_ms >= session.expires_ms => StatusResponse::Expired,
        AuthSessionKind::Pending => StatusResponse::Pending,
        AuthSessionKind::Done { auth_code, .. } => StatusResponse::Done {
            code: auth_code,
            state: session.state,
            redirect_uri: session.redirect_uri,
        },
        AuthSessionKind::Expired => StatusResponse::Expired,
        AuthSessionKind::Failed { .. } => StatusResponse::Expired,
    };
    (StatusCode::OK, headers, Json(serde_json::to_value(body).unwrap())).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;
    use crate::http::app;
    use crate::store::{AuthSessionRecord, Store};
    use axum::body::Body;
    use axum::http::Request;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn state() -> (TempDir, ServiceState) {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
        };
        let store = Store::open(&cfg.gateway_db_path()).unwrap();
        (tmp, ServiceState {
            config: Arc::new(cfg),
            store,
            signing_key: Arc::new(SigningKey::from_bytes(&[1u8; 32])),
        })
    }

    fn put(state: &ServiceState, sid: &str, kind: AuthSessionKind, expires_ms: i64) {
        state.store.put_auth_session(&AuthSessionRecord {
            session_id: sid.into(),
            client_id: "c1".into(),
            redirect_uri: "http://x/cb".into(),
            code_challenge: "cc".into(),
            code_challenge_method: "S256".into(),
            resource: "https://mcp.example.com".into(),
            state: "st".into(),
            kind,
            issued_at_ms: 0,
            expires_ms,
        }).unwrap();
    }

    #[tokio::test]
    async fn pending_returns_pending() {
        let (_t, st) = state();
        put(&st, "sid-1", AuthSessionKind::Pending, Utc::now().timestamp_millis() + 60_000);
        let resp = app(st)
            .oneshot(Request::get("/oauth/authorize/status/sid-1").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["kind"], "pending");
    }

    #[tokio::test]
    async fn done_returns_code_state_redirect() {
        let (_t, st) = state();
        put(&st, "sid-2", AuthSessionKind::Done {
            auth_code: "AC-123".into(),
            sub: "deadbeef".repeat(8),
        }, Utc::now().timestamp_millis() + 60_000);
        let resp = app(st)
            .oneshot(Request::get("/oauth/authorize/status/sid-2").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["kind"], "done");
        assert_eq!(v["code"], "AC-123");
        assert_eq!(v["state"], "st");
        assert_eq!(v["redirect_uri"], "http://x/cb");
    }

    #[tokio::test]
    async fn pending_past_expiry_returns_expired() {
        let (_t, st) = state();
        put(&st, "sid-3", AuthSessionKind::Pending, 1); // long ago
        let resp = app(st)
            .oneshot(Request::get("/oauth/authorize/status/sid-3").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["kind"], "expired");
    }

    #[tokio::test]
    async fn unknown_session_is_404() {
        let (_t, st) = state();
        let resp = app(st)
            .oneshot(Request::get("/oauth/authorize/status/nope").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
```

- [ ] **Step 3: Mount the route**

```rust
        .route(
            "/oauth/authorize/status/:session_id",
            axum::routing::get(crate::oauth::authorize_status::handler),
        )
```

(Use `:session_id` with axum 0.8 — confirm by running the test; if 0.8 expects `{session_id}` syntax, switch accordingly.)

- [ ] **Step 4: Run the tests**

Run: `cargo test -p wires-mcp --lib oauth::authorize_status`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/wires-mcp/src/oauth/authorize_status.rs crates/wires-mcp/src/oauth/mod.rs crates/wires-mcp/src/http.rs
git commit -m "wires-mcp: GET /oauth/authorize/status/{id}"
```

---

### Task 21: Pair-bridge — temp data dir + PairRequest + on_paired wiring

**Files:**
- Create: `crates/wires-mcp/src/pair_bridge.rs`
- Modify: `crates/wires-mcp/src/lib.rs`
- Modify: `crates/wires-mcp/src/oauth/authorize.rs`
- Modify: `crates/wires-mcp/src/http.rs`

- [ ] **Step 1: Add the module**

`pub mod pair_bridge;` in `crates/wires-mcp/src/lib.rs`.

- [ ] **Step 2: Implement the bridge**

Create `crates/wires-mcp/src/pair_bridge.rs`:

```rust
//! First-time /authorize bridge: for each pending pair, generates a fresh
//! per-user wires agent identity into a temp data dir, binds an iroh
//! endpoint, registers the `/wires/pair/0` ALPN handler with an
//! `on_paired` callback that completes the OAuth flow.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use snafu::ResultExt;
use tokio::sync::oneshot;
use wires_net::pair::{PairManifest, RequestedScope, Right};
use wires_node::pair::{
    NodePairHandler, OnPaired, OnPairedError, PairInstallSummary, pair_listen, PairListenArgs,
};
use wires_node::{Node, NodeConfig};

use crate::error::{IoSnafu, OpenRuntimeSnafu, Result};
use crate::store::{AuthCodeRecord, AuthSessionKind, PendingPairRecord, UserRecord};
use crate::tenants::TenantSupervisor;

/// Default 5-minute pair TTL, matching the spec.
pub const PAIR_TTL: std::time::Duration = std::time::Duration::from_secs(300);
/// Default 60-second TTL for the auth code minted at pair completion.
pub const AUTH_CODE_TTL_MS: i64 = 60_000;

pub struct PairBridge {
    pending_pairs_dir: PathBuf,
    public_url: String,
    store: crate::store::Store,
    supervisor: TenantSupervisor,
}

impl PairBridge {
    pub fn new(
        pending_pairs_dir: PathBuf,
        public_url: String,
        store: crate::store::Store,
        supervisor: TenantSupervisor,
    ) -> Self {
        Self {
            pending_pairs_dir,
            public_url,
            store,
            supervisor,
        }
    }

    /// Generate a fresh agent identity, write it into a temp dir keyed by
    /// `session_id`, bind an iroh endpoint, register the pair protocol with
    /// an `on_paired` callback, return the base64 PairRequest token.
    pub async fn start(&self, session_id: &str, client_name: &str) -> Result<String> {
        std::fs::create_dir_all(&self.pending_pairs_dir).context(IoSnafu)?;
        let temp_dir = self.pending_pairs_dir.join(session_id);
        std::fs::create_dir_all(&temp_dir).context(IoSnafu)?;
        set_dir_mode_0700(&temp_dir);

        // identity.ed25519, identity.x25519, iroh.secret, config.toml.
        use rand_core::RngCore as _;
        let mut id_seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut id_seed);
        write_secret(&temp_dir.join("identity.ed25519"), &id_seed)?;
        let mut x_seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut x_seed);
        write_secret(&temp_dir.join("identity.x25519"), &x_seed)?;
        let mut iroh_seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut iroh_seed);
        write_secret(&temp_dir.join("iroh.secret"), &iroh_seed)?;

        let cfg = NodeConfig {
            data_dir: temp_dir.clone(),
            root_pubkey_hex: String::new(),
            host: None,
        };
        let s = toml::to_string_pretty(&cfg).map_err(|e| crate::error::GatewayError::Io {
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
            location: snafu::location!(),
        })?;
        std::fs::write(temp_dir.join("config.toml"), s).context(IoSnafu)?;

        // Open the per-temp-dir Node + endpoint
        let node = Arc::new(Node::open(cfg).context(OpenRuntimeSnafu)?);
        let endpoint = wires_net::bind_lan(
            iroh::SecretKey::from_bytes(&iroh_seed),
            vec![wires_net::pair::ALPN.to_vec()],
        )
        .await
        .map_err(|e| crate::error::GatewayError::Io {
            source: std::io::Error::other(format!("bind_lan: {e}")),
            location: snafu::location!(),
        })?;

        let agent_sk = SigningKey::from_bytes(&id_seed);
        let x25519_sk = x25519_dalek::StaticSecret::from(x_seed);
        let x25519_pk = x25519_dalek::PublicKey::from(&x25519_sk).to_bytes();

        let store = self.store.clone();
        let supervisor = self.supervisor.clone();
        let pending_dir_for_cb = temp_dir.clone();
        let session_id_for_cb = session_id.to_string();
        let public_url_for_cb = self.public_url.clone();

        let on_paired: Arc<OnPaired> = Arc::new(move |summary: PairInstallSummary| {
            // Synchronous; tokio block_on inside the callback. The callback
            // runs on a tokio worker (pair handler is async), but the
            // callback type itself is sync — we hop through a small runtime
            // block for the awaitable parts.
            let root_hex = summary.root_pubkey_hex.clone();
            if matches!(store.get_user(&root_hex), Ok(Some(_))) {
                return Err(OnPairedError::AlreadyPaired(format!(
                    "a wires user already exists for root {root_hex}; use sign-in"
                )));
            }
            // Move temp dir → users/<root_hex>/ and open the runtime.
            let runtime_open = futures::executor::block_on(supervisor.bind(&root_hex, &pending_dir_for_cb));
            if let Err(e) = runtime_open {
                return Err(OnPairedError::Internal(format!("bind: {e}")));
            }
            let now_ms = chrono::Utc::now().timestamp_millis();
            let user = UserRecord {
                root_pubkey_hex: root_hex.clone(),
                data_dir: format!("{}/users/{}", public_url_for_cb.trim_end_matches('/'), root_hex),
                created_at_ms: now_ms,
                last_seen_ms: now_ms,
            };
            if let Err(e) = store.put_user(&user) {
                return Err(OnPairedError::Internal(format!("put_user: {e}")));
            }
            // Mint auth code, flip session to Done.
            let code = uuid::Uuid::new_v4().to_string();
            let session = match store.get_auth_session(&session_id_for_cb) {
                Ok(Some(s)) => s,
                Ok(None) => return Err(OnPairedError::Internal("session vanished".into())),
                Err(e) => return Err(OnPairedError::Internal(format!("session get: {e}"))),
            };
            let updated = crate::store::AuthSessionRecord {
                kind: AuthSessionKind::Done {
                    auth_code: code.clone(),
                    sub: root_hex.clone(),
                },
                ..session
            };
            if let Err(e) = store.put_auth_session(&updated) {
                return Err(OnPairedError::Internal(format!("session put: {e}")));
            }
            let code_rec = AuthCodeRecord {
                code: code.clone(),
                session_id: session_id_for_cb.clone(),
                sub: root_hex.clone(),
                client_id: updated.client_id.clone(),
                redirect_uri: updated.redirect_uri.clone(),
                code_challenge: updated.code_challenge.clone(),
                issued_at_ms: now_ms,
                expires_ms: now_ms + AUTH_CODE_TTL_MS,
                consumed: false,
            };
            if let Err(e) = store.put_auth_code(&code_rec) {
                return Err(OnPairedError::Internal(format!("put_auth_code: {e}")));
            }
            Ok(())
        });

        // Build the manifest + start pair_listen using the same machinery
        // wires-cli uses.
        let manifest = PairManifest {
            role: "mcp-gateway".into(),
            description: format!("MCP Gateway at {} for '{}'", self.public_url, client_name),
            requested_scopes: vec![RequestedScope {
                topic_name: "**".into(),
                rights: vec![Right::Read, Right::Write],
            }],
        };

        // pair_listen builds the standard NodePairHandler internally. To
        // inject on_paired, we re-implement the small protocol-attach loop
        // here using the public types.
        let started = pair_listen(
            temp_dir.clone(),
            Arc::clone(&node),
            agent_sk,
            x25519_pk,
            endpoint.clone(),
            PairListenArgs {
                manifest,
                ttl: PAIR_TTL,
            },
        )
        .await
        .map_err(|e| crate::error::GatewayError::Io {
            source: std::io::Error::other(format!("pair_listen: {e}")),
            location: snafu::location!(),
        })?;

        // Hot-swap a handler with on_paired by re-binding the router. The
        // returned `started.router` already has the default handler running;
        // for v1 we accept this limitation and rely on a NodePairHandler
        // constructor override (see task 16's `with_on_paired` — we expose
        // a `pair_listen_with_on_paired` shim here that mirrors `pair_listen`
        // with the callback wired in).
        let _ = on_paired; // wired through the shim below
        let _ = started; // see note: production wiring uses the shim

        // Persist the token + temp dir for the consent page.
        let pending = PendingPairRecord {
            session_id: session_id.to_string(),
            temp_data_dir: temp_dir.to_string_lossy().into_owned(),
            request_token_b64: String::new(), // filled by Step 3
            ttl_expires_ms: chrono::Utc::now().timestamp_millis() + PAIR_TTL.as_millis() as i64,
        };
        self.store.put_pending_pair(&pending)?;
        Ok(String::new())
    }
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .context(IoSnafu)?;
        f.write_all(bytes).context(IoSnafu)?;
        f.sync_all().context(IoSnafu)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes).context(IoSnafu)
    }
}

#[cfg(unix)]
fn set_dir_mode_0700(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
}
#[cfg(not(unix))]
fn set_dir_mode_0700(_p: &Path) {}
```

**Note to the engineer:** The above leaves the `pair_listen` integration partially wired because `wires_node::pair::pair_listen` does not currently accept an `on_paired` argument. The clean implementation requires either:

(a) Adding a sibling `pair_listen_with_on_paired` function in `crates/wires-node/src/pair.rs` that constructs a `NodePairHandler::new(...).with_on_paired(...)`, or
(b) Inlining the body of `pair_listen` here (cloning ~60 LOC) and using `with_on_paired` directly.

**Pick (a).** Add this function next to `pub async fn pair_listen` in `crates/wires-node/src/pair.rs`:

```rust
pub async fn pair_listen_with_on_paired(
    data_dir: std::path::PathBuf,
    node: Arc<Node>,
    agent_sk: SigningKey,
    agent_x25519: [u8; 32],
    endpoint: iroh::Endpoint,
    args: PairListenArgs,
    on_paired: Arc<OnPaired>,
) -> crate::error::Result<PairListenStarted> {
    // Same body as `pair_listen`, but the `NodePairHandler::new(...)` line
    // is replaced with `.with_on_paired(on_paired)` chained at the end.
    // Implementer: copy-paste pair_listen, change only that one line.
    use crate::error::NodeError;
    let pending =
        crate::pair_pending::load(&data_dir).map_err(|source| NodeError::ConfigWrite {
            source,
            location: snafu::location!(),
        })?;
    let (nonce, ephemeral_sk, request_token, request_expires_ms) = if let Some(p) = pending {
        let nonce_arr = hex_to_arr32(&p.nonce_hex)?;
        let secret_arr = hex_to_arr32(&p.ephemeral_x25519_secret_hex)?;
        (
            nonce_arr,
            StaticSecret::from(secret_arr),
            p.request_token,
            p.expires_unix_ms,
        )
    } else {
        use rand_core::RngCore as _;
        let mut nonce = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let ephemeral_sk = StaticSecret::random_from_rng(rand_core::OsRng);
        let ephemeral_pk = XPub::from(&ephemeral_sk).to_bytes();
        let agent_pk = agent_sk.verifying_key().to_bytes();
        let now = unix_now_ms();
        let expires = now + args.ttl.as_millis() as i64;
        let dial = pair_dial_from(&endpoint);
        let mut req = PairRequest {
            version: 1,
            agent_pubkey: agent_pk,
            agent_x25519,
            ephemeral_x25519: ephemeral_pk,
            dial,
            manifest: args.manifest,
            nonce,
            issued_at: now,
            expires,
            signature: [0u8; 64],
        };
        req.sign(&agent_sk).map_err(|source| NodeError::PairListenSign {
            source: Box::new(source),
            location: snafu::location!(),
        })?;
        let token = req.encode().map_err(|source| NodeError::PairListenSign {
            source: Box::new(source),
            location: snafu::location!(),
        })?;
        crate::pair_pending::save(
            &data_dir,
            &crate::pair_pending::PairPending {
                version: 1,
                nonce_hex: hex::encode(nonce),
                ephemeral_x25519_secret_hex: hex::encode(ephemeral_sk.to_bytes()),
                expires_unix_ms: expires,
                request_token: token.clone(),
            },
        )
        .map_err(|source| NodeError::ConfigWrite {
            source,
            location: snafu::location!(),
        })?;
        (nonce, ephemeral_sk, token, expires)
    };

    let (outcome_tx, outcome_rx) = oneshot::channel();
    let handler = Arc::new(
        NodePairHandler::new(
            data_dir,
            node,
            agent_sk.verifying_key().to_bytes(),
            nonce,
            ephemeral_sk,
            request_expires_ms,
            outcome_tx,
        )
        .with_on_paired(on_paired),
    );
    let protocol = PairProtocol::new(handler);
    let router = iroh::protocol::Router::builder(endpoint)
        .accept(PAIR_ALPN, protocol)
        .spawn();
    Ok(PairListenStarted {
        request_token,
        outcome: outcome_rx,
        router,
    })
}
```

Then change `PairBridge::start` above to call `pair_listen_with_on_paired(..., on_paired)` instead of `pair_listen(...)`, set `pending.request_token_b64 = started.request_token.clone()`, and persist the router somewhere (a per-session `HashMap<String, iroh::protocol::Router>` field on `PairBridge`) so the endpoint stays bound for the TTL.

**Add a `routers` field to `PairBridge`:**

```rust
pub struct PairBridge {
    pending_pairs_dir: PathBuf,
    public_url: String,
    store: crate::store::Store,
    supervisor: TenantSupervisor,
    routers: Arc<parking_lot::Mutex<std::collections::HashMap<String, iroh::protocol::Router>>>,
}
```

Initialize in `new` and insert `started.router` keyed by `session_id` after `pair_listen_with_on_paired` returns.

- [ ] **Step 3: Wire `PairBridge` into `ServiceState` and the authorize handler**

Add to `crates/wires-mcp/src/http.rs`:

```rust
#[derive(Clone)]
pub struct ServiceState {
    pub config: Arc<GatewayConfig>,
    pub store: Store,
    pub signing_key: Arc<SigningKey>,
    pub supervisor: crate::tenants::TenantSupervisor,
    pub pair_bridge: Arc<crate::pair_bridge::PairBridge>,
}
```

In `crates/wires-mcp/src/oauth/authorize.rs::validate_and_create`, after `put_pending_signin`, replace the placeholder `pair_token_b64 = String::new()` block with:

```rust
    let pair_token_b64 = state
        .pair_bridge
        .start(&session_id, &client.client_name)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "pair_bridge.start");
            (StatusCode::INTERNAL_SERVER_ERROR, oauth_err("server_error", "pair_bridge"))
        })?;
```

- [ ] **Step 4: Update `ServiceState` construction in main.rs**

In `crates/wires-mcp/src/main.rs::Cmd::Serve`, after opening the store, before serving:

```rust
    let supervisor = wires_mcp::tenants::TenantSupervisor::new(
        cfg.users_dir(),
        std::time::Duration::from_secs(600),
    );
    let pair_bridge = std::sync::Arc::new(wires_mcp::pair_bridge::PairBridge::new(
        cfg.pending_pairs_dir(),
        cfg.public_url.clone(),
        store.clone(),
        supervisor.clone(),
    ));
    let state = wires_mcp::http::ServiceState {
        config: std::sync::Arc::new(cfg),
        store,
        signing_key: std::sync::Arc::new(sk),
        supervisor,
        pair_bridge,
    };
```

- [ ] **Step 5: Update all test helpers**

Every test in `crates/wires-mcp/src/` that constructs `ServiceState` directly needs to add `supervisor` and `pair_bridge` fields. Search for `ServiceState {` and add the new fields, using `tempfile::TempDir` for the supervisor's `users_dir`. Add a helper at the bottom of `crates/wires-mcp/src/http.rs` to reduce churn:

```rust
#[cfg(test)]
pub fn test_state(tmp: &std::path::Path) -> ServiceState {
    let cfg = GatewayConfig {
        public_url: "https://mcp.example.com".into(),
        bind: "127.0.0.1:0".into(),
        data_dir: tmp.to_path_buf(),
    };
    let store = Store::open(&cfg.gateway_db_path()).unwrap();
    let supervisor = crate::tenants::TenantSupervisor::new(
        cfg.users_dir(),
        std::time::Duration::from_secs(60),
    );
    let pair_bridge = std::sync::Arc::new(crate::pair_bridge::PairBridge::new(
        cfg.pending_pairs_dir(),
        cfg.public_url.clone(),
        store.clone(),
        supervisor.clone(),
    ));
    ServiceState {
        config: std::sync::Arc::new(cfg),
        store,
        signing_key: std::sync::Arc::new(SigningKey::from_bytes(&[1u8; 32])),
        supervisor,
        pair_bridge,
    }
}
```

Then replace the per-module `state()` test helpers with calls to `crate::http::test_state(...)`.

- [ ] **Step 6: Run the full test suite for the crate**

Run: `cargo test -p wires-mcp`
Expected: PASS.

- [ ] **Step 7: Run the full workspace build to catch wires-node breakage**

Run: `cargo build --workspace && cargo test -p wires-node --lib`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add crates/wires-mcp/src/pair_bridge.rs crates/wires-mcp/src/lib.rs crates/wires-mcp/src/oauth/authorize.rs crates/wires-mcp/src/http.rs crates/wires-mcp/src/main.rs crates/wires-node/src/pair.rs
git commit -m "wires-mcp: PairBridge for first-time /authorize

Generates per-session temp data dir + iroh endpoint + PairRequest QR.
on_paired callback (via wires-node::pair_listen_with_on_paired) moves
the data dir to users/<root>/, opens the NodeRuntime, mints the auth
code, and flips the session to Done."
```

---

### Task 22: `POST /oauth/signin/assertion`

**Files:**
- Create: `crates/wires-mcp/src/sign_in_endpoint.rs`
- Modify: `crates/wires-mcp/src/lib.rs`
- Modify: `crates/wires-mcp/src/http.rs`

- [ ] **Step 1: Add the module**

`pub mod sign_in_endpoint;` in `crates/wires-mcp/src/lib.rs`.

- [ ] **Step 2: Write the failing test**

Create `crates/wires-mcp/src/sign_in_endpoint.rs`:

```rust
//! `POST /oauth/signin/assertion` — iOS posts a root-signed assertion of a
//! prior `SignInChallenge`. On success: delete the pending row (single-use),
//! mint an auth code, flip the session to Done with `sub = root_pubkey_hex`.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::http::ServiceState;
use crate::sign_in::SignInChallenge;
use crate::store::{AuthCodeRecord, AuthSessionKind};

#[derive(Debug, Clone, Deserialize)]
pub struct SignInAssertion {
    pub session_id: String,
    pub root_pubkey: String, // hex
    pub signature: String,   // hex
}

#[derive(Debug, Clone, Serialize)]
pub struct SignInAck {
    pub ok: bool,
}

pub async fn handler(
    State(state): State<ServiceState>,
    Json(req): Json<SignInAssertion>,
) -> Result<(StatusCode, Json<SignInAck>), (StatusCode, Json<serde_json::Value>)> {
    let pending = state
        .store
        .get_pending_signin(&req.session_id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown_session"))?;
    let now_ms = Utc::now().timestamp_millis();
    if now_ms >= pending.ttl_expires_ms {
        return Err(err(StatusCode::BAD_REQUEST, "expired"));
    }
    let session = state
        .store
        .get_auth_session(&req.session_id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown_session"))?;
    if !matches!(session.kind, AuthSessionKind::Pending) {
        return Err(err(StatusCode::BAD_REQUEST, "already_done"));
    }

    // Reconstruct the original challenge and verify signature.
    let nonce: [u8; 32] = {
        let v = hex::decode(&pending.challenge_nonce_hex).map_err(|_| err(StatusCode::BAD_REQUEST, "bad_nonce"))?;
        v.try_into().map_err(|_| err(StatusCode::BAD_REQUEST, "bad_nonce"))?
    };
    let challenge = SignInChallenge::new(
        &state.config.public_url,
        &req.session_id,
        nonce,
        pending.ttl_expires_ms - crate::oauth::authorize::SIGNIN_CHALLENGE_TTL_MS,
        crate::oauth::authorize::SIGNIN_CHALLENGE_TTL_MS,
    );
    let root_arr: [u8; 32] = {
        let v = hex::decode(&req.root_pubkey).map_err(|_| err(StatusCode::BAD_REQUEST, "bad_root"))?;
        v.try_into().map_err(|_| err(StatusCode::BAD_REQUEST, "bad_root"))?
    };
    let vk = VerifyingKey::from_bytes(&root_arr).map_err(|_| err(StatusCode::BAD_REQUEST, "bad_root"))?;
    let sig_bytes = hex::decode(&req.signature).map_err(|_| err(StatusCode::BAD_REQUEST, "bad_signature"))?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| err(StatusCode::BAD_REQUEST, "bad_signature"))?;
    let sig = Signature::from_bytes(&sig_arr);
    if !challenge.verify(&vk, &sig) {
        return Err(err(StatusCode::UNAUTHORIZED, "bad_signature"));
    }

    // Single-use: delete the pending row.
    state
        .store
        .delete_pending_signin(&req.session_id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?;

    // The household must already have a user record on this gateway.
    if state.store.get_user(&req.root_pubkey).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?.is_none() {
        return Err(err(StatusCode::NOT_FOUND, "unknown_root_pubkey"));
    }

    // Mint auth code + flip session to Done.
    let code = uuid::Uuid::new_v4().to_string();
    let updated = crate::store::AuthSessionRecord {
        kind: AuthSessionKind::Done {
            auth_code: code.clone(),
            sub: req.root_pubkey.clone(),
        },
        ..session
    };
    let updated_redirect = updated.redirect_uri.clone();
    let updated_state = updated.state.clone();
    let updated_client_id = updated.client_id.clone();
    let updated_code_challenge = updated.code_challenge.clone();
    state.store.put_auth_session(&updated).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?;
    state.store.put_auth_code(&AuthCodeRecord {
        code,
        session_id: req.session_id,
        sub: req.root_pubkey,
        client_id: updated_client_id,
        redirect_uri: updated_redirect,
        code_challenge: updated_code_challenge,
        issued_at_ms: now_ms,
        expires_ms: now_ms + crate::pair_bridge::AUTH_CODE_TTL_MS,
        consumed: false,
    }).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?;
    let _ = updated_state;
    Ok((StatusCode::OK, Json(SignInAck { ok: true })))
}

fn err(status: StatusCode, code: &str) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({"error": code})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{ServiceState, app, test_state};
    use crate::sign_in::SignInChallenge;
    use crate::store::{AuthSessionRecord, OauthClientRecord, PendingSigninRecord, UserRecord};
    use axum::body::Body;
    use axum::http::Request;
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn setup() -> (TempDir, ServiceState, SigningKey, String) {
        let tmp = TempDir::new().unwrap();
        let st = test_state(tmp.path());
        let root = SigningKey::from_bytes(&[42u8; 32]);
        let root_pubkey_hex = hex::encode(root.verifying_key().to_bytes());
        st.store.put_user(&UserRecord {
            root_pubkey_hex: root_pubkey_hex.clone(),
            data_dir: "x".into(),
            created_at_ms: 0,
            last_seen_ms: 0,
        }).unwrap();
        st.store.put_oauth_client(&OauthClientRecord {
            client_id: "c1".into(),
            client_name: "C".into(),
            redirect_uris: vec!["http://x".into()],
            grant_types: vec!["authorization_code".into()],
            created_at_ms: 0,
            revoked: false,
        }).unwrap();
        let now_ms = Utc::now().timestamp_millis();
        let nonce = [9u8; 32];
        st.store.put_pending_signin(&PendingSigninRecord {
            session_id: "sid".into(),
            challenge_nonce_hex: hex::encode(nonce),
            ttl_expires_ms: now_ms + crate::oauth::authorize::SIGNIN_CHALLENGE_TTL_MS,
        }).unwrap();
        st.store.put_auth_session(&AuthSessionRecord {
            session_id: "sid".into(),
            client_id: "c1".into(),
            redirect_uri: "http://x".into(),
            code_challenge: "cc".into(),
            code_challenge_method: "S256".into(),
            resource: st.config.public_url.clone(),
            state: "st".into(),
            kind: AuthSessionKind::Pending,
            issued_at_ms: now_ms,
            expires_ms: now_ms + 60_000,
        }).unwrap();
        (tmp, st, root, root_pubkey_hex)
    }

    fn sign(root: &SigningKey, st: &ServiceState, nonce: [u8; 32], issued_at_ms: i64) -> String {
        let challenge = SignInChallenge::new(
            &st.config.public_url,
            "sid",
            nonce,
            issued_at_ms,
            crate::oauth::authorize::SIGNIN_CHALLENGE_TTL_MS,
        );
        hex::encode(challenge.sign(root).to_bytes())
    }

    #[tokio::test]
    async fn happy_path_mints_auth_code_and_marks_done() {
        let (_t, st, root, root_hex) = setup();
        let pending = st.store.get_pending_signin("sid").unwrap().unwrap();
        let nonce: [u8; 32] = hex::decode(&pending.challenge_nonce_hex).unwrap().try_into().unwrap();
        let issued = pending.ttl_expires_ms - crate::oauth::authorize::SIGNIN_CHALLENGE_TTL_MS;
        let sig = sign(&root, &st, nonce, issued);
        let body = serde_json::json!({"session_id": "sid", "root_pubkey": root_hex, "signature": sig});
        let resp = app(st.clone())
            .oneshot(Request::post("/oauth/signin/assertion")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())).unwrap())
            .await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let sess = st.store.get_auth_session("sid").unwrap().unwrap();
        match sess.kind {
            AuthSessionKind::Done { auth_code, sub } => {
                assert_eq!(sub, hex::encode(root.verifying_key().to_bytes()));
                assert!(st.store.get_auth_code(&auth_code).unwrap().is_some());
            }
            _ => panic!("expected Done"),
        }
        assert!(st.store.get_pending_signin("sid").unwrap().is_none());
    }

    #[tokio::test]
    async fn wrong_root_rejected() {
        let (_t, st, _root, _root_hex) = setup();
        let other = SigningKey::from_bytes(&[99u8; 32]);
        let other_hex = hex::encode(other.verifying_key().to_bytes());
        let pending = st.store.get_pending_signin("sid").unwrap().unwrap();
        let nonce: [u8; 32] = hex::decode(&pending.challenge_nonce_hex).unwrap().try_into().unwrap();
        let issued = pending.ttl_expires_ms - crate::oauth::authorize::SIGNIN_CHALLENGE_TTL_MS;
        let sig = sign(&other, &st, nonce, issued);
        let body = serde_json::json!({"session_id": "sid", "root_pubkey": other_hex, "signature": sig});
        let resp = app(st)
            .oneshot(Request::post("/oauth/signin/assertion")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())).unwrap())
            .await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND); // unknown_root_pubkey
    }

    #[tokio::test]
    async fn bad_signature_rejected() {
        let (_t, st, _root, root_hex) = setup();
        let body = serde_json::json!({
            "session_id": "sid",
            "root_pubkey": root_hex,
            "signature": hex::encode([0u8; 64]),
        });
        let resp = app(st)
            .oneshot(Request::post("/oauth/signin/assertion")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())).unwrap())
            .await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
```

- [ ] **Step 3: Mount the route**

```rust
        .route(
            "/oauth/signin/assertion",
            axum::routing::post(crate::sign_in_endpoint::handler),
        )
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p wires-mcp --lib sign_in_endpoint`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/wires-mcp/src/sign_in_endpoint.rs crates/wires-mcp/src/lib.rs crates/wires-mcp/src/http.rs
git commit -m "wires-mcp: POST /oauth/signin/assertion (root-signed)"
```

---

*End of Phase F. Phase G (token endpoint) continues with Tasks 23–24.*

## Phase G — Token endpoint

### Task 23: `POST /oauth/token` — authorization_code grant

**Files:**
- Create: `crates/wires-mcp/src/oauth/token.rs`
- Modify: `crates/wires-mcp/src/oauth/mod.rs`
- Modify: `crates/wires-mcp/src/http.rs`

- [ ] **Step 1: Add the module**

`pub mod token;` in `crates/wires-mcp/src/oauth/mod.rs`.

- [ ] **Step 2: Write the failing test**

Create `crates/wires-mcp/src/oauth/token.rs`:

```rust
//! `POST /oauth/token` — supports `authorization_code` and `refresh_token`
//! grants. PKCE-verified for `authorization_code`. Issues an EdDSA-signed
//! JWT plus an opaque refresh token. Refresh tokens rotate on every use.

use axum::Form;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::http::ServiceState;
use crate::store::{AuthCodeRecord, RefreshTokenRecord};
use crate::token::{MintInput, mint};

#[derive(Debug, Clone, Deserialize)]
pub struct TokenRequest {
    pub client_id: String,
    pub grant_type: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    pub resource: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str, // "Bearer"
    pub expires_in: i64,
    pub scope: &'static str, // "mcp:wires"
}

pub const ACCESS_TOKEN_TTL_S: i64 = 900;
pub const REFRESH_TOKEN_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;

pub async fn handler(
    State(state): State<ServiceState>,
    Form(req): Form<TokenRequest>,
) -> impl IntoResponse {
    if req.resource.trim_end_matches('/') != state.config.public_url.trim_end_matches('/') {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_target", "resource mismatch");
    }
    match req.grant_type.as_str() {
        "authorization_code" => handle_authorization_code(&state, &req).await,
        "refresh_token" => handle_refresh(&state, &req).await,
        _ => oauth_err(StatusCode::BAD_REQUEST, "unsupported_grant_type", ""),
    }
}

async fn handle_authorization_code(state: &ServiceState, req: &TokenRequest) -> axum::response::Response {
    let code = match &req.code {
        Some(c) => c.clone(),
        None => return oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "missing code"),
    };
    let redirect_uri = match &req.redirect_uri {
        Some(r) => r.clone(),
        None => return oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "missing redirect_uri"),
    };
    let verifier = match &req.code_verifier {
        Some(v) => v.clone(),
        None => return oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "missing code_verifier"),
    };
    let rec = match state.store.get_auth_code(&code) {
        Ok(Some(r)) => r,
        Ok(None) => return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "unknown code"),
        Err(_) => return oauth_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", ""),
    };
    if rec.consumed {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "code already used");
    }
    let now_ms = Utc::now().timestamp_millis();
    if now_ms > rec.expires_ms {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "code expired");
    }
    if rec.client_id != req.client_id {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "client mismatch");
    }
    if rec.redirect_uri != redirect_uri {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "redirect_uri mismatch");
    }
    if !pkce_ok(&rec.code_challenge, &verifier) {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE verification failed");
    }
    // Consume the code.
    let consumed = AuthCodeRecord { consumed: true, ..rec.clone() };
    if state.store.put_auth_code(&consumed).is_err() {
        return oauth_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "");
    }
    issue_tokens(state, &rec.sub, &rec.client_id).await
}

async fn handle_refresh(state: &ServiceState, req: &TokenRequest) -> axum::response::Response {
    let token = match &req.refresh_token {
        Some(t) => t.clone(),
        None => return oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "missing refresh_token"),
    };
    let hash = hex::encode(Sha256::digest(token.as_bytes()));
    let rec = match state.store.get_refresh_token(&hash) {
        Ok(Some(r)) => r,
        Ok(None) => return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "unknown refresh_token"),
        Err(_) => return oauth_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", ""),
    };
    if rec.rotated_to_hash_hex.is_some() {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "refresh_token already rotated");
    }
    let now_ms = Utc::now().timestamp_millis();
    if now_ms > rec.expires_ms {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "refresh_token expired");
    }
    if rec.client_id != req.client_id {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "client mismatch");
    }
    issue_tokens_and_rotate(state, &rec, &hash).await
}

async fn issue_tokens(state: &ServiceState, sub: &str, client_id: &str) -> axum::response::Response {
    let now_s = Utc::now().timestamp();
    let access_token = match mint(
        &state.signing_key,
        &MintInput {
            iss: &state.config.public_url,
            sub,
            aud: &state.config.public_url,
            now_s,
            ttl_s: ACCESS_TOKEN_TTL_S,
            client_id,
        },
    ) {
        Ok(t) => t,
        Err(_) => return oauth_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", ""),
    };
    let refresh_token = random_token();
    let refresh_hash = hex::encode(Sha256::digest(refresh_token.as_bytes()));
    let now_ms = Utc::now().timestamp_millis();
    if state.store.put_refresh_token(&RefreshTokenRecord {
        token_hash_hex: refresh_hash,
        sub: sub.into(),
        client_id: client_id.into(),
        issued_at_ms: now_ms,
        expires_ms: now_ms + REFRESH_TOKEN_TTL_MS,
        rotated_to_hash_hex: None,
    }).is_err() {
        return oauth_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "");
    }
    (StatusCode::OK, Json(TokenResponse {
        access_token,
        refresh_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL_S,
        scope: "mcp:wires",
    })).into_response()
}

async fn issue_tokens_and_rotate(
    state: &ServiceState,
    old: &RefreshTokenRecord,
    old_hash: &str,
) -> axum::response::Response {
    let now_s = Utc::now().timestamp();
    let access_token = match mint(
        &state.signing_key,
        &MintInput {
            iss: &state.config.public_url,
            sub: &old.sub,
            aud: &state.config.public_url,
            now_s,
            ttl_s: ACCESS_TOKEN_TTL_S,
            client_id: &old.client_id,
        },
    ) {
        Ok(t) => t,
        Err(_) => return oauth_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", ""),
    };
    let new_token = random_token();
    let new_hash = hex::encode(Sha256::digest(new_token.as_bytes()));
    let now_ms = Utc::now().timestamp_millis();
    if state.store.put_refresh_token(&RefreshTokenRecord {
        token_hash_hex: new_hash.clone(),
        sub: old.sub.clone(),
        client_id: old.client_id.clone(),
        issued_at_ms: now_ms,
        expires_ms: now_ms + REFRESH_TOKEN_TTL_MS,
        rotated_to_hash_hex: None,
    }).is_err() {
        return oauth_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "");
    }
    let mut rotated = old.clone();
    rotated.rotated_to_hash_hex = Some(new_hash);
    let _ = state.store.put_refresh_token(&rotated);
    let _ = old_hash;
    (StatusCode::OK, Json(TokenResponse {
        access_token,
        refresh_token: new_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL_S,
        scope: "mcp:wires",
    })).into_response()
}

fn random_token() -> String {
    use rand_core::RngCore as _;
    let mut buf = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

fn pkce_ok(challenge: &str, verifier: &str) -> bool {
    let digest = Sha256::digest(verifier.as_bytes());
    let candidate = URL_SAFE_NO_PAD.encode(digest);
    candidate == challenge
}

fn oauth_err(status: StatusCode, code: &str, desc: &str) -> axum::response::Response {
    (
        status,
        Json(serde_json::json!({"error": code, "error_description": desc})),
    ).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{ServiceState, app, test_state};
    use crate::store::{AuthCodeRecord, OauthClientRecord, UserRecord};
    use axum::body::Body;
    use axum::http::Request;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn setup_with_code(verifier: &str) -> (TempDir, ServiceState, String) {
        let tmp = TempDir::new().unwrap();
        let st = test_state(tmp.path());
        st.store.put_oauth_client(&OauthClientRecord {
            client_id: "c1".into(),
            client_name: "C".into(),
            redirect_uris: vec!["http://localhost/cb".into()],
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            created_at_ms: 0,
            revoked: false,
        }).unwrap();
        let sub = "ab".repeat(32);
        st.store.put_user(&UserRecord {
            root_pubkey_hex: sub.clone(),
            data_dir: "x".into(),
            created_at_ms: 0,
            last_seen_ms: 0,
        }).unwrap();
        let code = "AUTH-CODE-1".to_string();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        st.store.put_auth_code(&AuthCodeRecord {
            code: code.clone(),
            session_id: "sid".into(),
            sub: sub.clone(),
            client_id: "c1".into(),
            redirect_uri: "http://localhost/cb".into(),
            code_challenge: challenge,
            issued_at_ms: 0,
            expires_ms: Utc::now().timestamp_millis() + 60_000,
            consumed: false,
        }).unwrap();
        (tmp, st, code)
    }

    fn form_body(parts: &[(&str, &str)]) -> String {
        parts.iter().map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v))).collect::<Vec<_>>().join("&")
    }

    fn urlencode(s: &str) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
                _ => write!(&mut out, "%{:02X}", b).unwrap(),
            }
        }
        out
    }

    #[tokio::test]
    async fn auth_code_grant_happy_path() {
        let verifier = "v".repeat(43);
        let (_t, st, code) = setup_with_code(&verifier);
        let body = form_body(&[
            ("client_id", "c1"),
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "http://localhost/cb"),
            ("code_verifier", &verifier),
            ("resource", &st.config.public_url),
        ]);
        let resp = app(st.clone())
            .oneshot(Request::post("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body)).unwrap())
            .await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let r: TokenResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(!r.access_token.is_empty());
        assert!(!r.refresh_token.is_empty());
        assert_eq!(r.expires_in, ACCESS_TOKEN_TTL_S);
        // Code is now consumed.
        let r2 = st.store.get_auth_code(&code).unwrap().unwrap();
        assert!(r2.consumed);
    }

    #[tokio::test]
    async fn code_reuse_rejected() {
        let verifier = "v".repeat(43);
        let (_t, st, code) = setup_with_code(&verifier);
        let body = form_body(&[
            ("client_id", "c1"),
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "http://localhost/cb"),
            ("code_verifier", &verifier),
            ("resource", &st.config.public_url),
        ]);
        let _ = app(st.clone()).oneshot(Request::post("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body.clone())).unwrap()).await.unwrap();
        let resp = app(st).oneshot(Request::post("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body)).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn bad_pkce_rejected() {
        let (_t, st, code) = setup_with_code(&"v".repeat(43));
        let body = form_body(&[
            ("client_id", "c1"),
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "http://localhost/cb"),
            ("code_verifier", "wrong"),
            ("resource", &st.config.public_url),
        ]);
        let resp = app(st).oneshot(Request::post("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body)).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn audience_mismatch_rejected() {
        let (_t, st, code) = setup_with_code(&"v".repeat(43));
        let body = form_body(&[
            ("client_id", "c1"),
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "http://localhost/cb"),
            ("code_verifier", &"v".repeat(43)),
            ("resource", "https://other"),
        ]);
        let resp = app(st).oneshot(Request::post("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body)).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
```

- [ ] **Step 3: Mount the route**

```rust
        .route("/oauth/token", axum::routing::post(crate::oauth::token::handler))
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p wires-mcp --lib oauth::token`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/wires-mcp/src/oauth/token.rs crates/wires-mcp/src/oauth/mod.rs crates/wires-mcp/src/http.rs
git commit -m "wires-mcp: POST /oauth/token (authorization_code grant)"
```

---

### Task 24: `POST /oauth/token` — refresh_token rotation tests

**Files:**
- Modify: `crates/wires-mcp/src/oauth/token.rs`

- [ ] **Step 1: Append tests**

Inside the existing `mod tests` block in `crates/wires-mcp/src/oauth/token.rs`:

```rust
    async fn issue_initial_pair(st: &ServiceState) -> (String, String) {
        let verifier = "v".repeat(43);
        let (_dropme, _, code) = setup_with_code(&verifier);
        let _ = _dropme;
        // The helper writes to a fresh TempDir; instead, mirror its logic
        // onto our existing `st` so we share state across requests.
        let sub = "ab".repeat(32);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        st.store.put_auth_code(&AuthCodeRecord {
            code: code.clone(),
            session_id: "sid".into(),
            sub: sub.clone(),
            client_id: "c1".into(),
            redirect_uri: "http://localhost/cb".into(),
            code_challenge: challenge,
            issued_at_ms: 0,
            expires_ms: Utc::now().timestamp_millis() + 60_000,
            consumed: false,
        }).unwrap();
        let body = form_body(&[
            ("client_id", "c1"),
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "http://localhost/cb"),
            ("code_verifier", &verifier),
            ("resource", &st.config.public_url),
        ]);
        let resp = app(st.clone()).oneshot(Request::post("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body)).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let r: TokenResponse = serde_json::from_slice(&bytes).unwrap();
        (r.access_token, r.refresh_token)
    }

    #[tokio::test]
    async fn refresh_rotates_and_old_token_invalid() {
        let tmp = TempDir::new().unwrap();
        let st = test_state(tmp.path());
        st.store.put_oauth_client(&OauthClientRecord {
            client_id: "c1".into(),
            client_name: "C".into(),
            redirect_uris: vec!["http://localhost/cb".into()],
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            created_at_ms: 0,
            revoked: false,
        }).unwrap();
        let sub = "ab".repeat(32);
        st.store.put_user(&UserRecord {
            root_pubkey_hex: sub.clone(),
            data_dir: "x".into(),
            created_at_ms: 0,
            last_seen_ms: 0,
        }).unwrap();
        let (_at, rt) = issue_initial_pair(&st).await;

        // First refresh succeeds and rotates.
        let body = form_body(&[
            ("client_id", "c1"),
            ("grant_type", "refresh_token"),
            ("refresh_token", &rt),
            ("resource", &st.config.public_url),
        ]);
        let resp = app(st.clone()).oneshot(Request::post("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body.clone())).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Second refresh of the SAME token now rejected.
        let resp2 = app(st).oneshot(Request::post("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body)).unwrap()).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
    }
```

- [ ] **Step 2: Run the tests**

Run: `cargo test -p wires-mcp --lib oauth::token::tests::refresh_rotates_and_old_token_invalid`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-mcp/src/oauth/token.rs
git commit -m "wires-mcp: refresh_token rotation test"
```

---

## Phase H — MCP tool surface

### Task 25: `/mcp` JSON-RPC router

**Files:**
- Create: `crates/wires-mcp/src/mcp/mod.rs`
- Create: `crates/wires-mcp/src/mcp/router.rs`
- Modify: `crates/wires-mcp/src/lib.rs`
- Modify: `crates/wires-mcp/src/http.rs`

- [ ] **Step 1: Add the modules**

In `crates/wires-mcp/src/lib.rs`:

```rust
pub mod mcp;
```

Create `crates/wires-mcp/src/mcp/mod.rs`:

```rust
//! MCP transport (streamable HTTP) + tool dispatch.

pub mod router;
pub mod tools;
```

- [ ] **Step 2: Write the failing test**

Create `crates/wires-mcp/src/mcp/router.rs`:

```rust
//! Minimal MCP streamable-HTTP route. Accepts JSON-RPC 2.0 envelopes on
//! POST /mcp, dispatches `initialize`, `tools/list`, `tools/call` to the
//! handlers in `crate::mcp::tools`. Pulls the bound user's `NodeRuntime`
//! from the supervisor by the JWT's `sub`.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::http::ServiceState;
use crate::mcp::tools;
use crate::token::Claims;

#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

pub async fn handler(
    State(state): State<ServiceState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Json(req): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let id = req.id.unwrap_or(serde_json::Value::Null);
    let result = match req.method.as_str() {
        "initialize" => Ok(serde_json::json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "wires-mcp", "version": env!("CARGO_PKG_VERSION") }
        })),
        "tools/list" => Ok(tools::list_descriptors()),
        "tools/call" => tools::call(state, &claims, &req.params).await,
        _ => Err(JsonRpcError {
            code: -32601,
            message: format!("method not found: {}", req.method),
        }),
    };
    let resp = match result {
        Ok(v) => JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(v),
            error: None,
        },
        Err(e) => JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(e),
        },
    };
    (StatusCode::OK, Json(resp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{ServiceState, test_state};
    use crate::store::{OauthClientRecord, UserRecord};
    use crate::token::{MintInput, mint};
    use axum::body::Body;
    use axum::http::Request;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn bearer(state: &ServiceState, sub: &str, client_id: &str) -> String {
        mint(
            &state.signing_key,
            &MintInput {
                iss: &state.config.public_url,
                sub,
                aud: &state.config.public_url,
                now_s: chrono::Utc::now().timestamp(),
                ttl_s: 60,
                client_id,
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn initialize_returns_protocol_version() {
        let tmp = TempDir::new().unwrap();
        let st = test_state(tmp.path());
        let sub = "ab".repeat(32);
        st.store.put_user(&UserRecord {
            root_pubkey_hex: sub.clone(),
            data_dir: "x".into(),
            created_at_ms: 0,
            last_seen_ms: 0,
        }).unwrap();
        st.store.put_oauth_client(&OauthClientRecord {
            client_id: "c1".into(),
            client_name: "C".into(),
            redirect_uris: vec!["http://x".into()],
            grant_types: vec!["authorization_code".into()],
            created_at_ms: 0,
            revoked: false,
        }).unwrap();
        let token = bearer(&st, &sub, "c1");
        let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
        let resp = crate::http::app(st)
            .oneshot(
                Request::post("/mcp")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 1);
        assert_eq!(v["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn mcp_route_requires_bearer() {
        let tmp = TempDir::new().unwrap();
        let st = test_state(tmp.path());
        let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"});
        let resp = crate::http::app(st)
            .oneshot(
                Request::post("/mcp")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
```

Create a stub `crates/wires-mcp/src/mcp/tools.rs` so the router compiles:

```rust
use serde_json::Value;

use crate::http::ServiceState;
use crate::mcp::router::JsonRpcError;
use crate::token::Claims;

pub fn list_descriptors() -> Value {
    serde_json::json!({"tools": [
        {"name": "wires.list_topics", "description": "List topics this agent can access", "inputSchema": {"type":"object","properties":{}}},
        {"name": "wires.publish",     "description": "Publish a message to a topic",       "inputSchema": {"type":"object","properties":{"topic":{"type":"string"},"text":{"type":"string"},"data":{"type":"object"}},"required":["topic","text"]}},
        {"name": "wires.tail",        "description": "Read recent messages from a topic",  "inputSchema": {"type":"object","properties":{"topic":{"type":"string"},"since":{"type":"string"},"limit":{"type":"integer"}},"required":["topic"]}}
    ]})
}

pub async fn call(
    _state: ServiceState,
    _claims: &Claims,
    _params: &Value,
) -> Result<Value, JsonRpcError> {
    Err(JsonRpcError { code: -32601, message: "tools/call not yet wired (see Tasks 26–28)".into() })
}
```

- [ ] **Step 3: Mount the route with bearer middleware**

In `crates/wires-mcp/src/http.rs`'s `app()`:

```rust
        .route(
            "/mcp",
            axum::routing::post(crate::mcp::router::handler).layer(
                axum::middleware::from_fn_with_state(state.clone(), crate::oauth::middleware::bearer),
            ),
        )
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p wires-mcp --lib mcp::router`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/wires-mcp/src/mcp/ crates/wires-mcp/src/lib.rs crates/wires-mcp/src/http.rs
git commit -m "wires-mcp: /mcp JSON-RPC router (initialize + tools/list)"
```

---

### Task 26: `wires.list_topics` tool

**Files:**
- Modify: `crates/wires-mcp/src/mcp/tools.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/wires-mcp/src/mcp/tools.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{ServiceState, test_state};
    use crate::store::UserRecord;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;
    use tempfile::TempDir;
    use wires_core::cap::{Capability, CapId, Right};
    use wires_node::NodeConfig;
    use wires_node::runtime::NodeRuntime;

    async fn seed_user(tmp: &TempDir) -> (ServiceState, String) {
        let st = test_state(tmp.path());
        let sub_seed = [42u8; 32];
        let agent = SigningKey::from_bytes(&sub_seed);
        let root_seed = [99u8; 32];
        let root = SigningKey::from_bytes(&root_seed);
        let root_hex = hex::encode(root.verifying_key().to_bytes());
        let users_dir = st.config.users_dir();
        std::fs::create_dir_all(&users_dir).unwrap();
        let user_dir = users_dir.join(&root_hex);
        std::fs::create_dir_all(&user_dir).unwrap();
        let cfg = NodeConfig {
            data_dir: user_dir.clone(),
            root_pubkey_hex: root_hex.clone(),
            host: None,
        };
        std::fs::write(user_dir.join("config.toml"), toml::to_string_pretty(&cfg).unwrap()).unwrap();
        std::fs::write(user_dir.join("identity.ed25519"), agent.to_bytes()).unwrap();
        std::fs::write(user_dir.join("identity.x25519"), [1u8; 32]).unwrap();
        std::fs::write(user_dir.join("iroh.secret"), [2u8; 32]).unwrap();
        // Seed one cap and one topic name.
        let topic_id = [7u8; 32];
        let topic_hex = hex::encode(topic_id);
        let runtime = NodeRuntime::open(cfg).await.unwrap();
        let mut cap = Capability::new_unsigned(
            agent.verifying_key().to_bytes(),
            vec!["home.notes".into()],
            vec![Right::Read, Right::Write],
            0,
            None,
            CapId(uuid::Uuid::new_v4().into_bytes()),
        );
        cap.sign(&wires_core::cap::EnclaveRootSigner(root.clone())).unwrap();
        runtime.node.caps.upsert_grant(&cap).unwrap();
        wires_node::topic_names::upsert_entries(&user_dir, std::iter::once(("home.notes".to_string(), topic_id))).unwrap();
        st.store.put_user(&UserRecord {
            root_pubkey_hex: root_hex.clone(),
            data_dir: user_dir.to_string_lossy().into_owned(),
            created_at_ms: 0,
            last_seen_ms: 0,
        }).unwrap();
        st.supervisor.bind(&root_hex, &user_dir).await.ok(); // already there; ok
        let _ = topic_hex;
        drop(runtime);
        (st, root_hex)
    }

    #[tokio::test]
    async fn list_topics_returns_caps_and_names() {
        let tmp = TempDir::new().unwrap();
        let (st, root_hex) = seed_user(&tmp).await;
        let claims = Claims {
            iss: st.config.public_url.clone(),
            sub: root_hex,
            aud: st.config.public_url.clone(),
            iat: 0,
            exp: i64::MAX,
            jti: "j".into(),
            scope: crate::token::SCOPE_MCP_WIRES.into(),
            client_id: "c1".into(),
        };
        let params = serde_json::json!({"name": "wires.list_topics", "arguments": {}});
        let v = call(st, &claims, &params).await.unwrap();
        let arr = v["content"][0]["text"].as_str().unwrap();
        let body: serde_json::Value = serde_json::from_str(arr).unwrap();
        let topics = body["topics"].as_array().unwrap();
        assert!(topics.iter().any(|t| t["name"] == "home.notes"));
    }
}
```

NOTE: `EnclaveRootSigner` may not exist by that exact name — use whatever `wires_core::cap` exposes for signing with a `SigningKey` (search `crates/wires-core/src/cap.rs` and `crates/wires-core/src/signer.rs` for the concrete signer name; if the helper isn't pub, expose it for tests via `pub(crate)` or call `cap.sign(&SigningKeySigner(root))` if that's the pattern). The test confirms the surface; adjust the cap-minting line to match the actual API at implementation time.

- [ ] **Step 2: Implement `wires.list_topics` dispatch**

Replace `crates/wires-mcp/src/mcp/tools.rs` with a real `call` (keep `list_descriptors` from Task 25):

```rust
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::http::ServiceState;
use crate::mcp::router::JsonRpcError;
use crate::token::Claims;

pub fn list_descriptors() -> Value {
    serde_json::json!({"tools": [
        {"name": "wires.list_topics", "description": "List topics this agent can access", "inputSchema": {"type":"object","properties":{}}},
        {"name": "wires.publish",     "description": "Publish a message to a topic",       "inputSchema": {"type":"object","properties":{"topic":{"type":"string"},"text":{"type":"string"},"data":{"type":"object"}},"required":["topic","text"]}},
        {"name": "wires.tail",        "description": "Read recent messages from a topic",  "inputSchema": {"type":"object","properties":{"topic":{"type":"string"},"since":{"type":"string"},"limit":{"type":"integer"}},"required":["topic"]}}
    ]})
}

#[derive(Debug, Clone, Deserialize)]
pub struct CallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopicListing {
    pub topics: Vec<TopicEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopicEntry {
    pub topic_id: String,
    pub name: Option<String>,
    pub rights: Vec<String>,
    pub cap_id: String,
}

pub async fn call(state: ServiceState, claims: &Claims, params: &Value) -> Result<Value, JsonRpcError> {
    let p: CallParams = serde_json::from_value(params.clone()).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("invalid params: {e}"),
    })?;
    match p.name.as_str() {
        "wires.list_topics" => list_topics(&state, claims).await,
        other => Err(JsonRpcError {
            code: -32601,
            message: format!("unknown tool: {other}"),
        }),
    }
}

async fn list_topics(state: &ServiceState, claims: &Claims) -> Result<Value, JsonRpcError> {
    let runtime = state.supervisor.get_or_open(&claims.sub).await.map_err(|e| {
        JsonRpcError { code: -32000, message: format!("unknown_user: {e}") }
    })?;
    let caps = runtime.node.caps.all().map_err(|e| JsonRpcError {
        code: -32000,
        message: format!("caps: {e}"),
    })?;
    let names = wires_node::topic_names::load_map(&runtime.node.config.data_dir).unwrap_or_default();
    let mut topics = Vec::new();
    for (cap_id, entry) in caps {
        if entry.revoked {
            continue;
        }
        let cap = entry.cap;
        let rights: Vec<String> = cap.rights.iter().map(|r| match r {
            wires_core::cap::Right::Read => "read".to_string(),
            wires_core::cap::Right::Write => "write".to_string(),
        }).collect();
        for pattern in &cap.topics {
            for (name, topic_id) in &names {
                if let Ok(true) = wires_core::cap::glob_matches(pattern, name) {
                    topics.push(TopicEntry {
                        topic_id: hex::encode(topic_id),
                        name: Some(name.clone()),
                        rights: rights.clone(),
                        cap_id: hex::encode(cap_id.0),
                    });
                }
            }
        }
    }
    let body = TopicListing { topics };
    let text = serde_json::to_string(&body).map_err(|e| JsonRpcError { code: -32000, message: e.to_string() })?;
    Ok(serde_json::json!({"content": [{"type": "text", "text": text}], "isError": false}))
}
```

NOTE on `wires_node::topic_names::load_map` and `runtime.node.caps`: these may or may not be public APIs today. If they aren't, add `pub` to them in `wires-node` as part of this task, with a justification comment. Run `cargo build -p wires-mcp` to find any access errors, expose the minimum surface needed, and commit the wires-node visibility tweaks alongside this task.

- [ ] **Step 3: Run the test**

Run: `cargo test -p wires-mcp --lib mcp::tools`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-mcp/src/mcp/tools.rs
# Plus any wires-node visibility tweaks:
git add crates/wires-node/src/*.rs
git commit -m "wires-mcp: wires.list_topics tool

Maps the gateway-agent's caps × topic_names through the substrate's
glob_matches, returns the join as the MCP tool result. Adds pub
visibility on wires-node's topic_names::load_map + Node::caps where
needed."
```

---

### Task 27: `wires.publish` tool

**Files:**
- Modify: `crates/wires-mcp/src/mcp/tools.rs`

- [ ] **Step 1: Write the failing test**

In `crates/wires-mcp/src/mcp/tools.rs`'s `mod tests`, add:

```rust
    #[tokio::test]
    async fn publish_rejects_unknown_topic() {
        let tmp = TempDir::new().unwrap();
        let (st, root_hex) = seed_user(&tmp).await;
        let claims = Claims {
            iss: st.config.public_url.clone(),
            sub: root_hex,
            aud: st.config.public_url.clone(),
            iat: 0, exp: i64::MAX, jti: "j".into(),
            scope: crate::token::SCOPE_MCP_WIRES.into(),
            client_id: "c1".into(),
        };
        let params = serde_json::json!({
            "name": "wires.publish",
            "arguments": {"topic": "no.such.topic", "text": "hi"}
        });
        let v = call(st, &claims, &params).await.unwrap();
        assert_eq!(v["isError"], true);
        let text = v["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("topic_not_found"), "got: {text}");
    }

    #[tokio::test]
    async fn publish_refuses_caps_topic() {
        let tmp = TempDir::new().unwrap();
        let (st, root_hex) = seed_user(&tmp).await;
        let claims = Claims {
            iss: st.config.public_url.clone(),
            sub: root_hex.clone(),
            aud: st.config.public_url.clone(),
            iat: 0, exp: i64::MAX, jti: "j".into(),
            scope: crate::token::SCOPE_MCP_WIRES.into(),
            client_id: "c1".into(),
        };
        let caps_topic = wires_node::NodeConfig {
            data_dir: st.config.users_dir().join(&root_hex),
            root_pubkey_hex: root_hex.clone(),
            host: None,
        }
        .caps_topic_id();
        let params = serde_json::json!({
            "name": "wires.publish",
            "arguments": {"topic": hex::encode(caps_topic), "text": "x"}
        });
        let v = call(st, &claims, &params).await.unwrap();
        assert_eq!(v["isError"], true);
        let text = v["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("reserved_topic"), "got: {text}");
    }
```

- [ ] **Step 2: Implement `wires.publish`**

Add to `crates/wires-mcp/src/mcp/tools.rs`:

```rust
#[derive(Debug, Clone, Deserialize)]
struct PublishArgs {
    topic: String,
    text: String,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
struct PublishOutput {
    topic_id: String,
    sender: String,
    seq: u64,
    prev_hash: String,
    timestamp: i64,
    message_hash: String,
}

const DEFAULT_TYPE: &str = "message";

fn resolve_topic(runtime: &wires_node::runtime::NodeRuntime, topic: &str) -> Result<[u8; 32], String> {
    // 64-char lowercase hex → topic_id literal; else look up in topic_names.json.
    if topic.len() == 64 && topic.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
        let bytes = hex::decode(topic).map_err(|e| format!("topic_not_found: bad hex: {e}"))?;
        return bytes.try_into().map_err(|_| "topic_not_found".to_string());
    }
    let names = wires_node::topic_names::load_map(&runtime.node.config.data_dir)
        .unwrap_or_default();
    names
        .iter()
        .find_map(|(n, id)| (n == topic).then(|| *id))
        .ok_or_else(|| format!("topic_not_found: {topic}"))
}

fn topic_name_for_id(runtime: &wires_node::runtime::NodeRuntime, id: &[u8; 32]) -> Option<String> {
    let names = wires_node::topic_names::load_map(&runtime.node.config.data_dir).ok()?;
    names.into_iter().find_map(|(n, t)| (t == *id).then_some(n))
}

fn pick_cap_for(
    runtime: &wires_node::runtime::NodeRuntime,
    name_or_id: &str,
    topic_id: &[u8; 32],
    right: wires_core::cap::Right,
) -> Result<wires_core::cap::CapId, String> {
    let name = topic_name_for_id(runtime, topic_id).unwrap_or_else(|| name_or_id.to_string());
    let caps = runtime.node.caps.all().map_err(|e| format!("caps: {e}"))?;
    for (cid, entry) in caps {
        if entry.revoked { continue; }
        if entry.cap.allows(&name, right).is_ok() {
            return Ok(cid);
        }
    }
    Err(format!("permission_denied: no cap for {} with {:?}", hex::encode(topic_id), right))
}

async fn publish_tool(state: &ServiceState, claims: &Claims, args: PublishArgs) -> Result<Value, JsonRpcError> {
    let runtime = state.supervisor.get_or_open(&claims.sub).await.map_err(|e| {
        JsonRpcError { code: -32000, message: format!("unknown_user: {e}") }
    })?;
    let topic_id = match resolve_topic(&runtime, &args.topic) {
        Ok(t) => t,
        Err(msg) => return Ok(error_result(&msg)),
    };
    // Defense: refuse the __caps topic.
    let caps_topic = runtime.node.config.caps_topic_id();
    if topic_id == caps_topic {
        return Ok(error_result(&format!("reserved_topic: {}", hex::encode(topic_id))));
    }
    let cap_id = match pick_cap_for(&runtime, &args.topic, &topic_id, wires_core::cap::Right::Write) {
        Ok(c) => c,
        Err(msg) => return Ok(error_result(&msg)),
    };
    // Join + publish.
    if let Err(e) = runtime.join_topic(topic_id, vec![]).await {
        return Ok(error_result(&format!("join_topic: {e}")));
    }
    let content = wires_core::CanonicalContent {
        type_: DEFAULT_TYPE.into(),
        text: args.text,
        data: args.data,
    };
    let msg = runtime.publish_and_broadcast(topic_id, cap_id.0, content).await.map_err(|e| {
        JsonRpcError { code: -32000, message: format!("publish: {e}") }
    })?;
    let out = PublishOutput {
        topic_id: hex::encode(topic_id),
        sender: hex::encode(msg.sender),
        seq: msg.seq,
        prev_hash: hex::encode(msg.prev_hash),
        timestamp: msg.timestamp,
        message_hash: hex::encode(wires_core::chain::hash_envelope(&msg)),
    };
    let text = serde_json::to_string(&out).map_err(|e| JsonRpcError { code: -32000, message: e.to_string() })?;
    Ok(serde_json::json!({"content": [{"type": "text", "text": text}], "isError": false}))
}

fn error_result(msg: &str) -> Value {
    serde_json::json!({"content": [{"type": "text", "text": msg}], "isError": true})
}
```

Wire publish into `call`'s match arm alongside `list_topics`:

```rust
        "wires.publish" => {
            let args: PublishArgs = serde_json::from_value(p.arguments).map_err(|e| JsonRpcError {
                code: -32602,
                message: format!("invalid arguments: {e}"),
            })?;
            publish_tool(&state, claims, args).await
        }
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p wires-mcp --lib mcp::tools`
Expected: PASS (existing list_topics + the two new ones).

- [ ] **Step 4: Commit**

```bash
git add crates/wires-mcp/src/mcp/tools.rs
git commit -m "wires-mcp: wires.publish tool (default type='message', reserved-topic refusal)"
```

---

### Task 28: `wires.tail` tool

**Files:**
- Modify: `crates/wires-mcp/src/mcp/tools.rs`

- [ ] **Step 1: Write the failing test**

Append to `mod tests`:

```rust
    #[tokio::test]
    async fn tail_round_trips_a_published_message() {
        let tmp = TempDir::new().unwrap();
        let (st, root_hex) = seed_user(&tmp).await;
        let claims = Claims {
            iss: st.config.public_url.clone(),
            sub: root_hex,
            aud: st.config.public_url.clone(),
            iat: 0, exp: i64::MAX, jti: "j".into(),
            scope: crate::token::SCOPE_MCP_WIRES.into(),
            client_id: "c1".into(),
        };
        // Publish via the tool.
        let pub_params = serde_json::json!({
            "name": "wires.publish",
            "arguments": {"topic": "home.notes", "text": "hello"}
        });
        let _ = call(st.clone(), &claims, &pub_params).await.unwrap();
        // Tail.
        let tail_params = serde_json::json!({
            "name": "wires.tail",
            "arguments": {"topic": "home.notes"}
        });
        let v = call(st, &claims, &tail_params).await.unwrap();
        assert_eq!(v["isError"], false);
        let text = v["content"][0]["text"].as_str().unwrap();
        let body: serde_json::Value = serde_json::from_str(text).unwrap();
        let msgs = body["messages"].as_array().unwrap();
        assert!(msgs.iter().any(|m| m["content"]["text"] == "hello"));
        assert!(body.get("next_cursor").is_some());
    }
```

- [ ] **Step 2: Implement `wires.tail`**

Add to `crates/wires-mcp/src/mcp/tools.rs`:

```rust
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
struct TailArgs {
    topic: String,
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TailCursor {
    /// Sender hex → (seq, hash_hex)
    hwm: HashMap<String, (u64, String)>,
}

const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 500;

async fn tail_tool(state: &ServiceState, claims: &Claims, args: TailArgs) -> Result<Value, JsonRpcError> {
    let runtime = state.supervisor.get_or_open(&claims.sub).await.map_err(|e| {
        JsonRpcError { code: -32000, message: format!("unknown_user: {e}") }
    })?;
    let topic_id = match resolve_topic(&runtime, &args.topic) {
        Ok(t) => t,
        Err(msg) => return Ok(error_result(&msg)),
    };
    if pick_cap_for(&runtime, &args.topic, &topic_id, wires_core::cap::Right::Read).is_err() {
        return Ok(error_result(&format!("permission_denied: read on {}", hex::encode(topic_id))));
    }
    // Replay-on-first-tail if no cursor.
    let cursor: TailCursor = match &args.since {
        None => TailCursor::default(),
        Some(s) => match URL_SAFE_NO_PAD.decode(s).ok().and_then(|b| serde_json::from_slice(&b).ok()) {
            Some(c) => c,
            None => return Ok(error_result("invalid_cursor")),
        },
    };
    if args.since.is_none() {
        // Best-effort; ignore errors (no host, no peer hint, etc.)
        let _ = runtime.replay_from_host(topic_id).await;
    }
    // Idempotent join.
    let _ = runtime.join_topic(topic_id, vec![]).await;
    // Read decrypted history. Uses the per-topic log + the agent's cap-table.
    let limit = args.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let msgs = runtime.node.read_decrypted_since(&topic_id, &cursor.hwm, limit).map_err(|e| {
        JsonRpcError { code: -32000, message: format!("tail: {e}") }
    })?;
    let next_cursor = encode_cursor(&runtime, &topic_id, &cursor, &msgs);
    let body = serde_json::json!({
        "messages": msgs.iter().map(|m| serde_json::json!({
            "topic_id":  hex::encode(m.envelope.topic_id),
            "sender":    hex::encode(m.envelope.sender),
            "seq":       m.envelope.seq,
            "prev_hash": hex::encode(m.envelope.prev_hash),
            "timestamp": m.envelope.timestamp,
            "kind":      format!("{:?}", m.envelope.kind),
            "content":   m.content,
        })).collect::<Vec<_>>(),
        "next_cursor": next_cursor,
        "exhausted":   msgs.len() < limit,
    });
    let text = serde_json::to_string(&body).map_err(|e| JsonRpcError { code: -32000, message: e.to_string() })?;
    Ok(serde_json::json!({"content": [{"type": "text", "text": text}], "isError": false}))
}

fn encode_cursor(
    _runtime: &wires_node::runtime::NodeRuntime,
    _topic_id: &[u8; 32],
    prev: &TailCursor,
    msgs: &[wires_node::DecryptedMessage],
) -> String {
    let mut cur = prev.clone();
    for m in msgs {
        let sender = hex::encode(m.envelope.sender);
        let hash = hex::encode(wires_core::chain::hash_envelope(&m.envelope));
        cur.hwm.insert(sender, (m.envelope.seq, hash));
    }
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&cur).unwrap())
}
```

Wire into `call`:

```rust
        "wires.tail" => {
            let args: TailArgs = serde_json::from_value(p.arguments).map_err(|e| JsonRpcError {
                code: -32602,
                message: format!("invalid arguments: {e}"),
            })?;
            tail_tool(&state, claims, args).await
        }
```

**NOTE:** `Node::read_decrypted_since` and `DecryptedMessage` may not exist by those names. The implementer should:
1. Search `crates/wires-node/src/` for the existing decrypted-tail API (look at how `wires-cli`'s `cat` command implements it — it has to walk the log and decrypt under the cap-table).
2. If no public helper exists, factor one out from `wires-cli`'s `cat` into `wires-node` and re-use it here. This is the project's existing pattern (e.g. `replay_from_host` lives in `NodeRuntime` after being factored out of CLI code).
3. Adjust the test's expected fields to match the actual shape.

- [ ] **Step 3: Run the tests**

Run: `cargo test -p wires-mcp --lib mcp::tools::tests::tail_round_trips_a_published_message`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-mcp/src/mcp/tools.rs
# plus any wires-node refactor:
git add crates/wires-node/src/*.rs
git commit -m "wires-mcp: wires.tail tool (cursor-based pagination, lazy replay)"
```

---

*End of Phase H. Phase I (operator admin CLI) continues with Tasks 29–32.*

## Phase I — Operator admin CLI

### Task 29: `wires-mcp user-list`

**Files:**
- Create: `crates/wires-mcp/src/admin.rs`
- Modify: `crates/wires-mcp/src/lib.rs`
- Modify: `crates/wires-mcp/src/main.rs`

- [ ] **Step 1: Add the module**

`pub mod admin;` in `crates/wires-mcp/src/lib.rs`.

- [ ] **Step 2: Implement `user_list`**

Create `crates/wires-mcp/src/admin.rs`:

```rust
//! Operator admin actions, invoked via `wires-mcp <subcommand>`. Each one
//! opens the config + store directly (no HTTP) and prints to stdout.

use std::path::Path;

use crate::config::GatewayConfig;
use crate::error::{IoSnafu, Result};
use crate::store::Store;
use snafu::ResultExt;

pub fn load_config(path: &Path) -> Result<GatewayConfig> {
    let s = std::fs::read_to_string(path).context(IoSnafu)?;
    toml::from_str(&s).map_err(|e| crate::error::GatewayError::Io {
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
        location: snafu::location!(),
    })
}

pub fn user_list(cfg: &GatewayConfig) -> Result<()> {
    let store = Store::open(&cfg.gateway_db_path())?;
    let users = store.list_users()?;
    for u in &users {
        println!(
            "{}\tcreated={}\tlast_seen={}\tdir={}",
            u.root_pubkey_hex, u.created_at_ms, u.last_seen_ms, u.data_dir
        );
    }
    println!("{} user(s)", users.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::UserRecord;
    use tempfile::TempDir;

    #[test]
    fn user_list_runs_against_empty_store() {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
        };
        let _store = Store::open(&cfg.gateway_db_path()).unwrap();
        user_list(&cfg).unwrap();
    }

    #[test]
    fn user_list_shows_a_seeded_user() {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
        };
        let store = Store::open(&cfg.gateway_db_path()).unwrap();
        store.put_user(&UserRecord {
            root_pubkey_hex: "ab".repeat(32),
            data_dir: "/tmp/x".into(),
            created_at_ms: 1,
            last_seen_ms: 2,
        }).unwrap();
        user_list(&cfg).unwrap();
        assert_eq!(store.list_users().unwrap().len(), 1);
    }
}
```

- [ ] **Step 3: Wire `UserList` subcommand into `main.rs`**

In `crates/wires-mcp/src/main.rs`, expand `Cmd`:

```rust
#[derive(clap::Subcommand, Debug)]
enum Cmd {
    Serve,
    UserList { #[arg(long, default_value = "/etc/wires-mcp/config.toml")] config: std::path::PathBuf },
}
```

Match the new arm:

```rust
        Cmd::UserList { config } => {
            let cfg = match wires_mcp::admin::load_config(&config) {
                Ok(c) => c,
                Err(e) => { eprintln!("config: {e}"); return std::process::ExitCode::FAILURE; }
            };
            match wires_mcp::admin::user_list(&cfg) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => { eprintln!("user-list: {e}"); std::process::ExitCode::FAILURE }
            }
        }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p wires-mcp --lib admin && cargo build -p wires-mcp`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-mcp/src/admin.rs crates/wires-mcp/src/lib.rs crates/wires-mcp/src/main.rs
git commit -m "wires-mcp: user-list admin subcommand"
```

---

### Task 30: `wires-mcp user-delete <root_pubkey_hex>`

**Files:**
- Modify: `crates/wires-mcp/src/admin.rs`
- Modify: `crates/wires-mcp/src/main.rs`

- [ ] **Step 1: Add the test**

Append to `crates/wires-mcp/src/admin.rs` mod tests:

```rust
    #[test]
    fn user_delete_removes_users_dir_and_refresh_tokens() {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
        };
        let store = Store::open(&cfg.gateway_db_path()).unwrap();
        let sub = "cd".repeat(32);
        store.put_user(&UserRecord {
            root_pubkey_hex: sub.clone(),
            data_dir: "x".into(),
            created_at_ms: 0,
            last_seen_ms: 0,
        }).unwrap();
        store.put_refresh_token(&crate::store::RefreshTokenRecord {
            token_hash_hex: "h1".into(),
            sub: sub.clone(),
            client_id: "c".into(),
            issued_at_ms: 0,
            expires_ms: i64::MAX,
            rotated_to_hash_hex: None,
        }).unwrap();
        let user_dir = cfg.users_dir().join(&sub);
        std::fs::create_dir_all(&user_dir).unwrap();
        std::fs::write(user_dir.join("config.toml"), "x").unwrap();

        user_delete(&cfg, &sub).unwrap();
        assert!(!user_dir.exists());
        assert!(store.get_user(&sub).unwrap().is_none());
        assert!(store.get_refresh_token("h1").unwrap().is_none());
    }
```

- [ ] **Step 2: Implement `user_delete`**

Add to `crates/wires-mcp/src/admin.rs`:

```rust
pub fn user_delete(cfg: &GatewayConfig, root_pubkey_hex: &str) -> Result<()> {
    let store = Store::open(&cfg.gateway_db_path())?;
    let removed = store.delete_user(root_pubkey_hex)?;
    let n_tokens = store.revoke_refresh_tokens_for_sub(root_pubkey_hex)?;
    let user_dir = cfg.users_dir().join(root_pubkey_hex);
    let dir_removed = if user_dir.exists() {
        std::fs::remove_dir_all(&user_dir).context(IoSnafu)?;
        true
    } else {
        false
    };
    println!(
        "user-delete root={} user_row_removed={} dir_removed={} refresh_tokens_revoked={}",
        root_pubkey_hex, removed, dir_removed, n_tokens
    );
    Ok(())
}
```

- [ ] **Step 3: Wire the subcommand**

Extend `Cmd` in `main.rs`:

```rust
    UserDelete {
        root_pubkey_hex: String,
        #[arg(long, default_value = "/etc/wires-mcp/config.toml")]
        config: std::path::PathBuf,
    },
```

And the match arm:

```rust
        Cmd::UserDelete { root_pubkey_hex, config } => {
            let cfg = match wires_mcp::admin::load_config(&config) {
                Ok(c) => c,
                Err(e) => { eprintln!("config: {e}"); return std::process::ExitCode::FAILURE; }
            };
            match wires_mcp::admin::user_delete(&cfg, &root_pubkey_hex) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => { eprintln!("user-delete: {e}"); std::process::ExitCode::FAILURE }
            }
        }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p wires-mcp --lib admin::tests::user_delete`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-mcp/src/admin.rs crates/wires-mcp/src/main.rs
git commit -m "wires-mcp: user-delete admin subcommand"
```

---

### Task 31: `client-list` + `client-revoke`

**Files:**
- Modify: `crates/wires-mcp/src/admin.rs`
- Modify: `crates/wires-mcp/src/main.rs`

- [ ] **Step 1: Add the tests**

Append to `mod tests`:

```rust
    #[test]
    fn client_revoke_flips_the_flag() {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
        };
        let store = Store::open(&cfg.gateway_db_path()).unwrap();
        store.put_oauth_client(&crate::store::OauthClientRecord {
            client_id: "c1".into(),
            client_name: "C".into(),
            redirect_uris: vec!["http://x".into()],
            grant_types: vec!["authorization_code".into()],
            created_at_ms: 0,
            revoked: false,
        }).unwrap();
        client_revoke(&cfg, "c1").unwrap();
        let rec = store.get_oauth_client("c1").unwrap().unwrap();
        assert!(rec.revoked);
    }
```

- [ ] **Step 2: Implement `client_list` + `client_revoke`**

Add to `crates/wires-mcp/src/admin.rs`:

```rust
pub fn client_list(cfg: &GatewayConfig) -> Result<()> {
    let store = Store::open(&cfg.gateway_db_path())?;
    for c in store.list_oauth_clients()? {
        println!(
            "{}\trevoked={}\tname={}\turis={:?}",
            c.client_id, c.revoked, c.client_name, c.redirect_uris
        );
    }
    Ok(())
}

pub fn client_revoke(cfg: &GatewayConfig, client_id: &str) -> Result<()> {
    let store = Store::open(&cfg.gateway_db_path())?;
    let mut rec = store
        .get_oauth_client(client_id)?
        .ok_or_else(|| crate::error::GatewayError::Io {
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "unknown client_id"),
            location: snafu::location!(),
        })?;
    rec.revoked = true;
    store.put_oauth_client(&rec)?;
    println!("client {client_id} revoked");
    Ok(())
}
```

- [ ] **Step 3: Wire the subcommands**

```rust
    ClientList { #[arg(long, default_value = "/etc/wires-mcp/config.toml")] config: std::path::PathBuf },
    ClientRevoke {
        client_id: String,
        #[arg(long, default_value = "/etc/wires-mcp/config.toml")] config: std::path::PathBuf,
    },
```

Match arms mirror `UserList`/`UserDelete`.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p wires-mcp --lib admin`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-mcp/src/admin.rs crates/wires-mcp/src/main.rs
git commit -m "wires-mcp: client-list + client-revoke admin subcommands"
```

---

### Task 32: `wires-mcp keys rotate`

**Files:**
- Modify: `crates/wires-mcp/src/admin.rs`
- Modify: `crates/wires-mcp/src/main.rs`

- [ ] **Step 1: Add the test**

```rust
    #[test]
    fn keys_rotate_generates_new_key_and_archives_old() {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
        };
        let initial = crate::keys::load_or_create(&cfg.token_signing_path()).unwrap();
        keys_rotate(&cfg).unwrap();
        let after = crate::keys::load_or_create(&cfg.token_signing_path()).unwrap();
        assert_ne!(initial.to_bytes(), after.to_bytes());
        // Old key archived with a timestamp suffix.
        let archive_glob = cfg.data_dir.join("token_signing.ed25519.archived");
        // The implementation should produce *something* with that prefix.
        let archived = std::fs::read_dir(&cfg.data_dir).unwrap().any(|e| {
            let n = e.unwrap().file_name();
            n.to_string_lossy().starts_with("token_signing.ed25519.archived")
        });
        assert!(archived, "expected archived key in {:?}", archive_glob);
    }
```

- [ ] **Step 2: Implement `keys_rotate`**

Add to `crates/wires-mcp/src/admin.rs`:

```rust
pub fn keys_rotate(cfg: &GatewayConfig) -> Result<()> {
    let path = cfg.token_signing_path();
    if path.exists() {
        let now_s = chrono::Utc::now().timestamp();
        let archived = cfg.data_dir.join(format!("token_signing.ed25519.archived.{now_s}"));
        std::fs::rename(&path, &archived).context(IoSnafu)?;
        println!("archived old signing key to {}", archived.display());
    }
    let new = crate::keys::load_or_create(&path)?;
    println!(
        "new signing key kid = {}",
        crate::keys::kid_for(&new.verifying_key())
    );
    Ok(())
}
```

(Note: v1 ships *generation* only. The "verification-only old key in JWKS during overlap window" behavior described in the spec is a follow-up; for v1, tokens minted under the old key continue to verify only until process restart, since `verify` uses the in-memory key. Document this limitation in the README under task 34.)

- [ ] **Step 3: Wire the subcommand**

```rust
    KeysRotate { #[arg(long, default_value = "/etc/wires-mcp/config.toml")] config: std::path::PathBuf },
```

Match arm:

```rust
        Cmd::KeysRotate { config } => {
            let cfg = match wires_mcp::admin::load_config(&config) {
                Ok(c) => c,
                Err(e) => { eprintln!("config: {e}"); return std::process::ExitCode::FAILURE; }
            };
            match wires_mcp::admin::keys_rotate(&cfg) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => { eprintln!("keys rotate: {e}"); std::process::ExitCode::FAILURE }
            }
        }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p wires-mcp --lib admin::tests::keys_rotate`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-mcp/src/admin.rs crates/wires-mcp/src/main.rs
git commit -m "wires-mcp: keys rotate admin subcommand (archive + regenerate)"
```

---

## Phase J — End-to-end acceptance + docs

### Task 33: End-to-end acceptance test (`#[ignore]`)

**Files:**
- Create: `crates/wires-mcp/tests/end_to_end.rs`

- [ ] **Step 1: Write the test**

Create `crates/wires-mcp/tests/end_to_end.rs`:

```rust
//! End-to-end: drive a full /authorize → pair → token → publish → tail
//! round-trip against an in-process gateway, using a hand-rolled fake "iOS
//! pair-approver" task that scans the PairRequest token and dials
//! /wires/pair/0. Marked #[ignore] because it runs real iroh endpoints.

#![cfg(test)]

#[tokio::test]
#[ignore]
async fn first_time_pair_then_publish_then_tail() {
    // This test is the v1 acceptance criterion #3 from the spec, end to end.
    //
    // The implementer should:
    //   1. Spawn wires-mcp's HTTP service on a random port via http::serve
    //      (use `tokio::net::TcpListener::bind("127.0.0.1:0")` and pass it
    //      to a `serve_with_listener` helper added in this task).
    //   2. POST /oauth/register with a fake Claude Desktop client name.
    //   3. GET /oauth/authorize?... and capture the rendered HTML; pull the
    //      pair_token_b64 out of the page (the renderer already embeds it
    //      in a hidden meta tag for test-driving — add the tag in this task).
    //   4. Spawn a fake-iOS task: decodes the PairRequest token, generates
    //      a root SigningKey + a household topic, mints a Capability for the
    //      gateway-agent, builds a PairGrant, seals it with `wires_crypto`,
    //      signs with the root, dials /wires/pair/0 via `wires-net::pair::PairClient`,
    //      delivers the grant, awaits Ack.
    //   5. Poll /oauth/authorize/status/<sid> until `done`; extract `code`.
    //   6. POST /oauth/token with `code` + PKCE verifier → receive access token.
    //   7. POST /mcp with `tools/call wires.publish`; assert success.
    //   8. POST /mcp with `tools/call wires.tail`; assert the message comes back.
    //
    // See the responder-driven-pairing acceptance test for the closest
    // template:
    //   crates/wires-cli/tests/cli_pair_listen_approve.rs
    //
    // The "fake iOS" cap-mint + PairGrant assembly is identical to what
    // `wires-cli pair-approve` does internally; pull it into a helper in
    // wires-net or copy with attribution.

    // Skeleton — fill in by implementer.
    panic!("Implement per the README in this test file.");
}
```

- [ ] **Step 2: Add a `serve_with_listener` helper**

In `crates/wires-mcp/src/http.rs`, factor out:

```rust
pub async fn serve_with_listener(state: ServiceState, listener: tokio::net::TcpListener) -> Result<()> {
    tracing::info!(addr = ?listener.local_addr().ok(), "wires-mcp listening");
    axum::serve(listener, app(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .context(ServeHttpSnafu)
}
```

And rewrite `serve` to call `serve_with_listener` after binding.

- [ ] **Step 3: Add a hidden meta tag in the consent HTML to ease test capture**

In `crates/wires-mcp/src/oauth/authorize_html.rs::render`, inside `<head>`:

```html
<meta name="wires-mcp-session-id" content="{session_id}">
<meta name="wires-mcp-pair-token" content="{pair_token_b64}">
<meta name="wires-mcp-signin-challenge" content="{signin_challenge_b64}">
```

These are *only* useful for the acceptance test; they leak no secrets (the pair token is already designed to be QR-scannable and short-lived).

- [ ] **Step 4: Run the test under `--ignored`**

Run: `cargo test -p wires-mcp --test end_to_end -- --ignored --nocapture`
Expected: PASS (after the implementer fills in the steps above).

- [ ] **Step 5: Commit**

```bash
git add crates/wires-mcp/tests/end_to_end.rs crates/wires-mcp/src/http.rs crates/wires-mcp/src/oauth/authorize_html.rs
git commit -m "wires-mcp: end-to-end acceptance test (#[ignore])"
```

---

### Task 34: Update `CLAUDE.md` + `README.md`

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`

- [ ] **Step 1: Update `CLAUDE.md`'s Status section**

In `/Users/aaron/src/wires/CLAUDE.md`, append to the `## Status` bullet list:

```markdown
- **MCP gateway v1** — `wires-mcp` is a multi-tenant authenticated MCP gateway. It joins each household as a normal wires agent via the responder pair flow, exposes OAuth 2.1 (PRM + AS + DCR) with the household root pubkey as `sub` and iOS as the universal authenticator (pair QR for first-time, sign-in challenge QR for returning). MCP tools: `wires.list_topics`, `wires.publish`, `wires.tail`. Spec: `docs/superpowers/specs/2026-05-18-wires-mcp-gateway-design.md`.
```

In the **Authoritative docs** section, add:

```markdown
- **MCP gateway spec** — `docs/superpowers/specs/2026-05-18-wires-mcp-gateway-design.md`. PRM, AS, DCR, the two consent paths, the MCP tool surface.
- **MCP gateway plan** — `docs/superpowers/plans/2026-05-18-wires-mcp-gateway.md`. 34 tasks, fully landed.
```

In the **Crate layout** table, add a row:

```markdown
| `wires-mcp` | `lib + bin`. Authenticated MCP gateway. Holds one wires-agent data dir per OAuth user (`users/<root>/`) plus a small `gateway.redb` for OAuth state. Per-user `NodeRuntime`s are managed by `TenantSupervisor`. First-time `/authorize` runs the existing pair flow via a per-session iroh endpoint; returning `/authorize` accepts a root-signed challenge over HTTPS. Tokens are EdDSA JWTs, verified offline. |
```

- [ ] **Step 2: Update `README.md`**

In `/Users/aaron/src/wires/README.md`, after the existing CLI walkthrough, add a new section:

```markdown
## MCP gateway

`wires-mcp` exposes a small authenticated MCP surface so AI-agent clients
(Claude Desktop, Cursor, VS Code, etc.) can act on a household's behalf.
It pairs into each household as a normal wires agent — `wires-host`'s
blindness contract is unchanged.

### Operator walkthrough

```bash
# 1. Generate a config.
cat >/etc/wires-mcp/config.toml <<EOF
public_url = "https://mcp.example.com"
bind = "127.0.0.1:3001"
data_dir = "/var/lib/wires-mcp"
EOF

# 2. Run the service.
wires-mcp serve

# 3. List onboarded users.
wires-mcp user-list

# 4. Remove a user (e.g. household-side cap was revoked).
wires-mcp user-delete <root_pubkey_hex>
```

Operators must put a TLS-terminating reverse proxy (nginx, caddy, etc.) in
front of `wires-mcp`; the binary speaks plain HTTP and assumes a trusted
upstream for TLS.

### User walkthrough (from the user's perspective)

1. Add the MCP server URL `https://mcp.example.com` to your MCP client.
2. The client opens the gateway's `/oauth/authorize` page in a browser.
3. Two QR codes appear. First-time users scan the **left** one with the
   Wires iOS app and approve a new "MCP gateway" agent like any other agent.
   Returning users scan the **right** one to authenticate with their root
   key.
4. The browser redirects back; the MCP client now has an access token
   bound to the user's household root pubkey.
5. The client can call `wires.list_topics`, `wires.publish`, `wires.tail`
   against the user's agent's caps.

### Known limitations (v1)

- `keys rotate` archives the old key but doesn't keep it in JWKS for an
  overlap window — existing access tokens become unverifiable on the next
  process restart. Wait out access-token TTL before restarting after a
  rotation.
- A user's topic set is fixed at pair time. To grant a paired gateway
  agent access to a new topic, `__cap.revoke` the existing cap and re-pair
  (the substrate's gossip-borne `__cap.grant` distribution is not yet
  implemented).
- Per-MCP-client distinction lives in logs only, not on the wires bus.
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md README.md
git commit -m "docs: wires-mcp v1 status + operator/user walkthrough"
```

---

## Self-review (engineer-runnable: skim before starting Task 1)

1. **Spec coverage.**
   - §1 mental model → covered by Tasks 1–5 (crate + state) and Phase B (OAuth surface).
   - §2 scope of change → Task 16 covers the single `wires-node` addition.
   - §3 crate layout + on-disk → Tasks 1, 3, 5 establish the layout; Task 5 the redb tables.
   - §4 OAuth endpoints → Tasks 6–12, 18, 20, 22, 23 cover every endpoint.
   - §5 consent flow → Tasks 18 (validation), 19 (HTML), 20 (status), 21 (pair-bridge), 22 (signin).
   - §6 MCP tools → Tasks 25–28.
   - §7 TenantSupervisor → Tasks 13–15.
   - §8 pair-bridge hook → Task 16 + 21.
   - §9 admin CLI → Tasks 29–32.
   - §10 errors → Task 2 with additive `From` impls in subsequent tasks as needed.
   - §11 logging → handled in handlers; no separate task.
   - §12 testing → unit tests live with each task; integration test in Task 33.
   - §13 acceptance criteria → Task 33 enumerates them in the test skeleton.

2. **Placeholder scan.** A few callouts: Task 21 leaves the actual pair-listen wiring with a literal copy-from-pair_listen instruction (the function body is reproduced inline). Task 28's `Node::read_decrypted_since` API may need to be factored out from `wires-cli`'s `cat` command — flagged inline. Task 26's cap-signer reference (`EnclaveRootSigner`) is best-effort; the implementer adjusts to the actual signer type at that moment.

3. **Type consistency.** `Claims`, `MintInput`, `ServiceState`, `PendingPairRecord`, `AuthSessionKind` are referenced consistently across tasks. `PairInstallSummary` and `OnPairedError` introduced in Task 16 are consumed in Task 21. `TopicListing` / `TopicEntry` are local to Task 26's tool but `wires.list_topics` output shape matches §6.1 of the spec.

4. **Scope check.** 34 tasks for a single new crate that builds a multi-tenant OAuth AS + per-user wires-agent fleet + three MCP tools is in line with project precedent (the responder-driven pairing plan was 18 tasks for a single ALPN; this is roughly double the surface).

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-05-18-wires-mcp-gateway.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using `superpowers:executing-plans`, batch execution with checkpoints.

**Which approach?**

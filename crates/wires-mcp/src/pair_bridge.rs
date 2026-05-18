//! First-time /authorize bridge: for each pending pair, generates a fresh
//! per-user wires agent identity into a temp data dir, binds an iroh
//! endpoint, registers the `/wires/pair/0` ALPN handler with an
//! `on_paired` callback that completes the OAuth flow.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use snafu::ResultExt;
use wires_core::cap::Right;
use wires_net::pair::{ALPN as PAIR_ALPN, PairManifest, RequestedScope};
use wires_node::pair::{OnPaired, OnPairedError, PairInstallSummary, PairListenArgs, pair_listen_with_on_paired};
use wires_node::{Node, NodeConfig};
use x25519_dalek::{PublicKey as XPub, StaticSecret as XSecret};

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
    routers: Arc<parking_lot::Mutex<HashMap<String, iroh::protocol::Router>>>,
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
            routers: Arc::new(parking_lot::Mutex::new(HashMap::new())),
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

        // Generate identity.ed25519, identity.x25519, iroh.secret.
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

        // Write config.toml so Node::open can read it.
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

        // Open the per-temp-dir Node (sync) + iroh endpoint (async).
        let node = Arc::new(Node::open(cfg).context(OpenRuntimeSnafu)?);
        let endpoint = wires_net::bind_lan(
            iroh::SecretKey::from_bytes(&iroh_seed),
            vec![PAIR_ALPN.to_vec()],
        )
        .await
        .map_err(|e| crate::error::GatewayError::Io {
            source: std::io::Error::other(format!("bind_lan: {e}")),
            location: snafu::location!(),
        })?;

        let agent_sk = SigningKey::from_bytes(&id_seed);
        let x25519_pk = XPub::from(&XSecret::from(x_seed)).to_bytes();

        // Clone everything the callback needs (it runs sync inside the handler task).
        let store = self.store.clone();
        let supervisor = self.supervisor.clone();
        let users_dir_for_cb = self.supervisor.users_dir().to_path_buf();
        let pending_dir_for_cb = temp_dir.clone();
        let session_id_for_cb = session_id.to_string();

        let on_paired: Arc<OnPaired> = Arc::new(move |summary: PairInstallSummary| {
            // The callback type is `Fn(...) -> Result<(), OnPairedError>` (sync),
            // but `supervisor.bind` is async. We bridge via
            // `tokio::task::block_in_place` which is safe on the multi-thread
            // runtime that main.rs constructs with `tokio::runtime::Runtime::new()`.
            let root_hex = summary.root_pubkey_hex.clone();

            // Reject if a user record already exists (re-pair attempt).
            if matches!(store.get_user(&root_hex), Ok(Some(_))) {
                return Err(OnPairedError::AlreadyPaired(format!(
                    "a wires user already exists for root {root_hex}; use sign-in"
                )));
            }

            // Move temp dir → users/<root_hex>/ and open the NodeRuntime.
            let bind_result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(supervisor.bind(&root_hex, &pending_dir_for_cb))
            });
            if let Err(e) = bind_result {
                return Err(OnPairedError::Internal(format!("bind: {e}")));
            }

            let now_ms = chrono::Utc::now().timestamp_millis();
            let user = UserRecord {
                root_pubkey_hex: root_hex.clone(),
                // data_dir records the filesystem path to the user's data dir.
                data_dir: users_dir_for_cb
                    .join(&root_hex)
                    .to_string_lossy()
                    .into_owned(),
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
                ..session.clone()
            };
            if let Err(e) = store.put_auth_session(&updated) {
                return Err(OnPairedError::Internal(format!("session put: {e}")));
            }
            let code_rec = AuthCodeRecord {
                code: code.clone(),
                session_id: session_id_for_cb.clone(),
                sub: root_hex.clone(),
                client_id: session.client_id.clone(),
                redirect_uri: session.redirect_uri.clone(),
                code_challenge: session.code_challenge.clone(),
                issued_at_ms: now_ms,
                expires_ms: now_ms + AUTH_CODE_TTL_MS,
                consumed: false,
            };
            if let Err(e) = store.put_auth_code(&code_rec) {
                return Err(OnPairedError::Internal(format!("put_auth_code: {e}")));
            }

            // Delete the pending_pair record now that the flow is complete.
            let _ = store.delete_pending_pair(&session_id_for_cb);

            Ok(())
        });

        // Build the manifest + start pair_listen_with_on_paired.
        let manifest = PairManifest {
            role: "mcp-gateway".into(),
            description: format!(
                "MCP Gateway at {} for '{}'",
                self.public_url, client_name
            ),
            requested_scopes: vec![RequestedScope {
                topic_name: "**".into(),
                rights: vec![Right::Read, Right::Write],
            }],
        };

        let started = pair_listen_with_on_paired(
            temp_dir.clone(),
            Arc::clone(&node),
            agent_sk,
            x25519_pk,
            endpoint,
            PairListenArgs {
                manifest,
                ttl: PAIR_TTL,
            },
            on_paired,
        )
        .await
        .map_err(|e| crate::error::GatewayError::Io {
            source: std::io::Error::other(format!("pair_listen: {e}")),
            location: snafu::location!(),
        })?;

        let request_token = started.request_token.clone();

        // Keep the router alive (drives the endpoint) for the session TTL.
        self.routers
            .lock()
            .insert(session_id.to_string(), started.router);

        // Persist the token + temp dir for the consent page.
        let pending = PendingPairRecord {
            session_id: session_id.to_string(),
            temp_data_dir: temp_dir.to_string_lossy().into_owned(),
            request_token_b64: request_token.clone(),
            ttl_expires_ms: chrono::Utc::now().timestamp_millis() + PAIR_TTL.as_millis() as i64,
        };
        self.store.put_pending_pair(&pending).map_err(|e| {
            crate::error::GatewayError::Io {
                source: std::io::Error::other(format!("put_pending_pair: {e}")),
                location: snafu::location!(),
            }
        })?;

        Ok(request_token)
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

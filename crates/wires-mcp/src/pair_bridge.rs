//! First-time /authorize bridge: for each pending pair, generates a fresh
//! per-user wires agent identity into a temp data dir, binds an iroh
//! endpoint, registers the `/wires/pair/0` ALPN handler with an
//! `on_paired` callback that completes the OAuth flow.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use snafu::ResultExt;
use wires_core::cap::Right;
use wires_net::pair::{ALPN as PAIR_ALPN, PairManifest, RequestedScope};
use wires_node::pair::{
    OnPaired, OnPairedError, PairInstallSummary, PairListenArgs, pair_listen_with_on_paired,
};
use wires_node::{Node, NodeConfig};
use x25519_dalek::{PublicKey as XPub, StaticSecret as XSecret};

use crate::error::{IoSnafu, OpenRuntimeSnafu, Result};
use crate::store::{AuthCodeRecord, AuthSessionKind, PendingPairRecord, UserRecord};
use crate::tenants::TenantSupervisor;

/// Default 5-minute pair TTL, matching the spec.
pub const PAIR_TTL: Duration = Duration::from_secs(300);
/// Default 60-second TTL for the auth code minted at pair completion.
pub const AUTH_CODE_TTL_MS: i64 = 60_000;
/// Grace period after `on_paired` completes before the session's iroh
/// `Router` is shut down. Long enough for the substrate-level `PairFrame::Ack`
/// to drain on the wire; short enough that we don't hold OS sockets after the
/// browser has redirected.
pub const POST_PAIR_GRACE: Duration = Duration::from_secs(5);

struct RouterSlot {
    created_at: Instant,
    router: iroh::protocol::Router,
}

pub struct PairBridge {
    pending_pairs_dir: PathBuf,
    public_url: String,
    store: crate::store::Store,
    supervisor: TenantSupervisor,
    routers: Arc<parking_lot::Mutex<HashMap<String, RouterSlot>>>,
}

/// Cheap-Clone handle to the bits of `PairBridge` that the `on_paired`
/// callback needs. Lets the callback body live as a regular method —
/// unit-testable without spinning up an iroh dialer.
#[derive(Clone)]
pub(crate) struct PairBridgeHandle {
    store: crate::store::Store,
    supervisor: TenantSupervisor,
    users_dir: PathBuf,
    pending_dir: PathBuf,
    routers: Arc<parking_lot::Mutex<HashMap<String, RouterSlot>>>,
}

impl PairBridgeHandle {
    /// Called synchronously by the pair handler after `install_grant` commits.
    /// Renames the temp data dir to `users/<root>/`, records the user, mints
    /// the auth code, flips the session to `Done`, and schedules router
    /// shutdown after `POST_PAIR_GRACE`.
    ///
    /// Bridges sync→async for `supervisor.bind` via `tokio::task::block_in_place`,
    /// which requires the caller to be on a multi-thread tokio runtime (which
    /// `main.rs` builds via `Runtime::new()`).
    pub(crate) fn on_pair_complete(
        &self,
        summary: PairInstallSummary,
        session_id: &str,
    ) -> std::result::Result<(), OnPairedError> {
        let root_hex = summary.root_pubkey_hex.clone();

        if matches!(self.store.get_user(&root_hex), Ok(Some(_))) {
            return Err(OnPairedError::AlreadyPaired(format!(
                "a wires user already exists for root {root_hex}; use sign-in"
            )));
        }

        let bind_result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(self.supervisor.bind(&root_hex, &self.pending_dir))
        });
        if let Err(e) = bind_result {
            return Err(OnPairedError::Internal(format!("bind: {e}")));
        }

        let now_ms = chrono::Utc::now().timestamp_millis();
        let user = UserRecord {
            root_pubkey_hex: root_hex.clone(),
            data_dir: self
                .users_dir
                .join(&root_hex)
                .to_string_lossy()
                .into_owned(),
            created_at_ms: now_ms,
            last_seen_ms: now_ms,
        };
        if let Err(e) = self.store.put_user(&user) {
            return Err(OnPairedError::Internal(format!("put_user: {e}")));
        }

        let code = uuid::Uuid::new_v4().to_string();
        let session = match self.store.get_auth_session(session_id) {
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
        if let Err(e) = self.store.put_auth_session(&updated) {
            return Err(OnPairedError::Internal(format!("session put: {e}")));
        }
        let code_rec = AuthCodeRecord {
            code: code.clone(),
            session_id: session_id.to_string(),
            sub: root_hex.clone(),
            client_id: session.client_id.clone(),
            redirect_uri: session.redirect_uri.clone(),
            code_challenge: session.code_challenge.clone(),
            issued_at_ms: now_ms,
            expires_ms: now_ms + AUTH_CODE_TTL_MS,
            consumed: false,
        };
        if let Err(e) = self.store.put_auth_code(&code_rec) {
            return Err(OnPairedError::Internal(format!("put_auth_code: {e}")));
        }

        let _ = self.store.delete_pending_pair(session_id);

        // Schedule router shutdown after a short grace so the substrate-side
        // `PairFrame::Ack` has time to drain.
        let routers = Arc::clone(&self.routers);
        let sid = session_id.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(POST_PAIR_GRACE).await;
            let slot = routers.lock().remove(&sid);
            if let Some(slot) = slot {
                let _ = slot.router.shutdown().await;
            }
        });

        Ok(())
    }
}

/// Pure helper: pick the session_ids whose `created_at` is older than
/// `now - ttl`. Kept separate from `PairBridge` so the eviction policy is
/// testable without instantiating a real `iroh::protocol::Router`.
fn pick_expired<'a, I>(entries: I, now: Instant, ttl: Duration) -> Vec<String>
where
    I: IntoIterator<Item = (&'a String, &'a Instant)>,
{
    entries
        .into_iter()
        .filter_map(|(id, created_at)| {
            if now.saturating_duration_since(*created_at) >= ttl {
                Some(id.clone())
            } else {
                None
            }
        })
        .collect()
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
            retention: None,
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

        let session_id_for_cb = session_id.to_string();
        // The pair handler runs the callback sync; we delegate to a method on a
        // cheap-Clone handle so the body is unit-testable without iroh.
        let bridge_for_cb = self.handle(temp_dir.clone());
        let on_paired: Arc<OnPaired> = Arc::new(move |summary: PairInstallSummary| {
            bridge_for_cb.on_pair_complete(summary, &session_id_for_cb)
        });

        // Build the manifest + start pair_listen_with_on_paired.
        let manifest = PairManifest {
            role: "mcp-gateway".into(),
            description: format!("MCP Gateway at {} for '{}'", self.public_url, client_name),
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
        self.routers.lock().insert(
            session_id.to_string(),
            RouterSlot {
                created_at: Instant::now(),
                router: started.router,
            },
        );

        // Persist the token + temp dir for the consent page.
        let pending = PendingPairRecord {
            session_id: session_id.to_string(),
            temp_data_dir: temp_dir.to_string_lossy().into_owned(),
            request_token_b64: request_token.clone(),
            ttl_expires_ms: chrono::Utc::now().timestamp_millis() + PAIR_TTL.as_millis() as i64,
        };
        self.store
            .put_pending_pair(&pending)
            .map_err(|e| crate::error::GatewayError::Io {
                source: std::io::Error::other(format!("put_pending_pair: {e}")),
                location: snafu::location!(),
            })?;

        Ok(request_token)
    }

    /// Construct a cheap-Clone handle suitable for capturing in the
    /// `on_paired` callback. Holds the bits the callback needs (store,
    /// supervisor, routers map, users_dir, and the temp data_dir for this
    /// pair session) without coupling the callback to `&self`.
    fn handle(&self, pending_dir: PathBuf) -> PairBridgeHandle {
        PairBridgeHandle {
            store: self.store.clone(),
            supervisor: self.supervisor.clone(),
            users_dir: self.supervisor.users_dir().to_path_buf(),
            pending_dir,
            routers: Arc::clone(&self.routers),
        }
    }

    /// Drop the router for `session_id`, awaiting shutdown so the underlying
    /// iroh endpoint releases its OS socket. No-op if not tracked.
    pub async fn close_session(&self, session_id: &str) {
        let slot = self.routers.lock().remove(session_id);
        if let Some(slot) = slot {
            let _ = slot.router.shutdown().await;
        }
    }

    /// Drop every router whose age exceeds `ttl`. Used by the periodic
    /// sweeper to catch sessions abandoned mid-pair (user closed the tab
    /// before scanning the QR, etc).
    pub async fn close_expired(&self, ttl: Duration) {
        let now = Instant::now();
        let ids = {
            let g = self.routers.lock();
            pick_expired(g.iter().map(|(k, v)| (k, &v.created_at)), now, ttl)
        };
        for id in ids {
            self.close_session(&id).await;
        }
    }

    /// Number of routers currently being held alive. Used by tests and `idle_gc`.
    pub fn tracked_sessions(&self) -> usize {
        self.routers.lock().len()
    }

    /// Spawn a background sweeper that calls `close_expired(ttl)` every `tick`.
    /// Returns the join handle so the caller can cancel on shutdown.
    pub fn spawn_gc(self: Arc<Self>, tick: Duration, ttl: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tick);
            loop {
                interval.tick().await;
                self.close_expired(ttl).await;
            }
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;
    use crate::store::{AuthSessionKind, AuthSessionRecord, PendingPairRecord, Store};
    use tempfile::TempDir;

    fn seed_handle(
        tmp: &TempDir,
        session_id: &str,
    ) -> (PairBridgeHandle, std::path::PathBuf, std::path::PathBuf) {
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
            retention: None,
        };
        let store = Store::open(&cfg.gateway_db_path()).unwrap();
        let supervisor = TenantSupervisor::new(cfg.users_dir(), Duration::from_secs(60), None);
        let pending_dir = cfg.pending_pairs_dir().join(session_id);
        std::fs::create_dir_all(&pending_dir).unwrap();

        // Seed the auth_session row (Pending) the callback will flip to Done.
        let now_ms = chrono::Utc::now().timestamp_millis();
        store
            .put_auth_session(&AuthSessionRecord {
                session_id: session_id.into(),
                client_id: "c1".into(),
                redirect_uri: "http://localhost/cb".into(),
                code_challenge: "cc".into(),
                code_challenge_method: "S256".into(),
                resource: "https://mcp.example.com".into(),
                state: "st".into(),
                kind: AuthSessionKind::Pending,
                issued_at_ms: now_ms,
                expires_ms: now_ms + 60_000,
            })
            .unwrap();
        store
            .put_pending_pair(&PendingPairRecord {
                session_id: session_id.into(),
                temp_data_dir: pending_dir.to_string_lossy().into_owned(),
                request_token_b64: "TOKEN".into(),
                ttl_expires_ms: now_ms + 60_000,
            })
            .unwrap();

        // Write the minimum filesystem layout `NodeRuntime::open` requires so
        // `supervisor.bind` can rename + open the user runtime end-to-end.
        let cfg_node = wires_node::NodeConfig {
            data_dir: pending_dir.clone(),
            root_pubkey_hex: String::new(),
            host: None,
            retention: None,
        };
        std::fs::write(
            pending_dir.join("config.toml"),
            toml::to_string_pretty(&cfg_node).unwrap(),
        )
        .unwrap();
        std::fs::write(pending_dir.join("identity.ed25519"), [1u8; 32]).unwrap();
        std::fs::write(pending_dir.join("identity.x25519"), [2u8; 32]).unwrap();
        std::fs::write(pending_dir.join("iroh.secret"), [3u8; 32]).unwrap();

        let users_dir = cfg.users_dir();
        let handle = PairBridgeHandle {
            store,
            supervisor,
            users_dir: users_dir.clone(),
            pending_dir: pending_dir.clone(),
            routers: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        };
        (handle, pending_dir, users_dir)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn on_pair_complete_binds_user_and_flips_session() {
        // The callback uses `tokio::task::block_in_place` to drive the async
        // `supervisor.bind`. Regression test that we wire this up correctly
        // on a multi-thread runtime — and that the resulting state is what
        // the OAuth `/token` endpoint expects.
        let tmp = TempDir::new().unwrap();
        let session_id = "sess-1";
        let (handle, pending_dir, users_dir) = seed_handle(&tmp, session_id);
        let root_hex = "ab".repeat(32);

        let summary = PairInstallSummary {
            root_pubkey_hex: root_hex.clone(),
            cap_id: [9u8; 16],
            installed_at: 0,
        };
        handle.on_pair_complete(summary, session_id).unwrap();

        // Filesystem: temp dir moved into users/<root>/.
        assert!(!pending_dir.exists(), "pending dir should be renamed away");
        assert!(users_dir.join(&root_hex).exists(), "users/<root>/ exists");
        // Supervisor: user runtime is now open.
        assert!(handle.supervisor.is_open(&root_hex).await);
        // Store: user record + auth_code created; session flipped to Done.
        let user = handle.store.get_user(&root_hex).unwrap().unwrap();
        assert_eq!(user.root_pubkey_hex, root_hex);
        let session = handle.store.get_auth_session(session_id).unwrap().unwrap();
        let auth_code = match session.kind {
            AuthSessionKind::Done { auth_code, .. } => auth_code,
            other => panic!("session not Done: {other:?}"),
        };
        let code_rec = handle.store.get_auth_code(&auth_code).unwrap().unwrap();
        assert_eq!(code_rec.sub, root_hex);
        assert!(handle.store.get_pending_pair(session_id).unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn on_pair_complete_rejects_repaired_user() {
        let tmp = TempDir::new().unwrap();
        let session_id = "sess-2";
        let (handle, _pending_dir, _users_dir) = seed_handle(&tmp, session_id);
        let root_hex = "cd".repeat(32);
        handle
            .store
            .put_user(&UserRecord {
                root_pubkey_hex: root_hex.clone(),
                data_dir: "irrelevant".into(),
                created_at_ms: 0,
                last_seen_ms: 0,
            })
            .unwrap();

        let summary = PairInstallSummary {
            root_pubkey_hex: root_hex.clone(),
            cap_id: [9u8; 16],
            installed_at: 0,
        };
        let err = handle.on_pair_complete(summary, session_id).unwrap_err();
        assert!(matches!(err, OnPairedError::AlreadyPaired(_)));
    }

    #[test]
    fn pick_expired_returns_only_aged_entries() {
        let now = Instant::now();
        let young = now;
        let old = now - Duration::from_secs(120);
        let map: HashMap<String, Instant> =
            [("recent".to_string(), young), ("stale".to_string(), old)]
                .into_iter()
                .collect();
        let picked = pick_expired(map.iter(), now, Duration::from_secs(60));
        assert_eq!(picked, vec!["stale".to_string()]);
    }

    #[test]
    fn pick_expired_is_empty_when_all_young() {
        let now = Instant::now();
        let map: HashMap<String, Instant> = [("a".to_string(), now)].into_iter().collect();
        assert!(pick_expired(map.iter(), now, Duration::from_secs(60)).is_empty());
    }

    #[test]
    fn pick_expired_exact_boundary_is_evicted() {
        let now = Instant::now();
        let ttl = Duration::from_secs(60);
        let map: HashMap<String, Instant> = [("a".to_string(), now - ttl)].into_iter().collect();
        // Exactly `ttl` old is considered expired (>=).
        assert_eq!(pick_expired(map.iter(), now, ttl), vec!["a".to_string()]);
    }
}

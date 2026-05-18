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
    pub supervisor: crate::tenants::TenantSupervisor,
    pub pair_bridge: Arc<crate::pair_bridge::PairBridge>,
}

impl FromRef<ServiceState> for Arc<GatewayConfig> {
    fn from_ref(s: &ServiceState) -> Self {
        Arc::clone(&s.config)
    }
}

impl FromRef<ServiceState> for Arc<SigningKey> {
    fn from_ref(s: &ServiceState) -> Self {
        Arc::clone(&s.signing_key)
    }
}

pub fn app(state: ServiceState) -> Router {
    Router::new()
        .route("/_health", axum::routing::get(health))
        .route(
            "/.well-known/oauth-protected-resource",
            axum::routing::get(crate::oauth::prm::handler),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            axum::routing::get(crate::oauth::as_meta::handler),
        )
        .route("/.well-known/jwks.json", axum::routing::get(crate::oauth::jwks::handler))
        .route(
            "/oauth/register",
            axum::routing::post(crate::oauth::register::handler),
        )
        .route(
            "/oauth/authorize",
            axum::routing::get(crate::oauth::authorize::handler),
        )
        .route(
            "/oauth/authorize/status/{session_id}",
            axum::routing::get(crate::oauth::authorize_status::handler),
        )
        .route(
            "/oauth/signin/assertion",
            axum::routing::post(crate::sign_in_endpoint::handler),
        )
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

/// Construct a `ServiceState` backed by a temp directory for use in tests.
/// All modules that need a `ServiceState` in tests should use this helper
/// rather than building `ServiceState { ... }` by hand so that additions
/// to the struct don't require edits across every test.
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
    let pair_bridge = Arc::new(crate::pair_bridge::PairBridge::new(
        cfg.pending_pairs_dir(),
        cfg.public_url.clone(),
        store.clone(),
        supervisor.clone(),
    ));
    ServiceState {
        config: Arc::new(cfg),
        store,
        signing_key: Arc::new(SigningKey::from_bytes(&[1u8; 32])),
        supervisor,
        pair_bridge,
    }
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
        let st = test_state(tmp.path());
        (tmp, st)
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

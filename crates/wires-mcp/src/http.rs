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

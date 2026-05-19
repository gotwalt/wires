//! axum service skeleton. Holds a `ServiceState` of everything the routes
//! need (config, store, signing key) and exposes `app()` so tests can
//! exercise routes through `tower::ServiceExt::oneshot` without binding a
//! port. The `serve()` entry point binds and runs until Ctrl-C.

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::FromRef;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
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
    pub rate_limit: crate::rate_limit::RateLimiter,
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
    let oauth_routes = Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            axum::routing::get(crate::oauth::prm::handler),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            axum::routing::get(crate::oauth::as_meta::handler),
        )
        .route(
            "/.well-known/jwks.json",
            axum::routing::get(crate::oauth::jwks::handler),
        )
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
        .route(
            "/oauth/token",
            axum::routing::post(crate::oauth::token::handler),
        )
        .layer(axum::middleware::from_fn(log_oauth));

    Router::new()
        .route("/_health", axum::routing::get(health))
        .merge(oauth_routes)
        .route(
            "/mcp",
            axum::routing::post(crate::mcp::router::handler).layer(
                axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::oauth::middleware::bearer,
                ),
            ),
        )
        .with_state(state)
}

/// Debug middleware for `/oauth/*` and `/.well-known/*`: buffers the request
/// body and response body, logs both at `debug` level, then passes them
/// through. Enabled by setting `RUST_LOG=wires_mcp::http=debug`. Off by
/// default; do not leave on in production — request bodies may contain
/// short-lived secrets (auth codes, PKCE verifiers, refresh tokens).
async fn log_oauth(req: Request<Body>, next: Next) -> Response {
    const MAX_LOG_BODY: usize = 64 * 1024;
    let method = req.method().clone();
    let uri = req.uri().clone();
    let req_headers = format!("{:?}", req.headers());
    let (parts, body) = req.into_parts();
    let req_bytes = match to_bytes(body, MAX_LOG_BODY).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, method = %method, uri = %uri, "log_oauth: req body read failed");
            return axum::http::StatusCode::BAD_REQUEST.into_response();
        }
    };
    tracing::debug!(
        method = %method,
        uri = %uri,
        headers = %req_headers,
        body = %String::from_utf8_lossy(&req_bytes),
        "oauth request",
    );
    let req = Request::from_parts(parts, Body::from(req_bytes));
    let resp = next.run(req).await;
    let (resp_parts, resp_body) = resp.into_parts();
    let resp_headers = format!("{:?}", resp_parts.headers);
    let resp_bytes = match to_bytes(resp_body, MAX_LOG_BODY).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, method = %method, uri = %uri, "log_oauth: resp body read failed");
            return Response::from_parts(resp_parts, Body::empty());
        }
    };
    tracing::debug!(
        method = %method,
        uri = %uri,
        status = %resp_parts.status,
        headers = %resp_headers,
        body = %String::from_utf8_lossy(&resp_bytes),
        "oauth response",
    );
    Response::from_parts(resp_parts, Body::from(resp_bytes))
}

async fn health() -> &'static str {
    "ok"
}

pub async fn serve(state: ServiceState) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(&state.config.bind)
        .await
        .context(BindHttpSnafu)?;
    serve_with_listener(state, listener).await
}

pub async fn serve_with_listener(
    state: ServiceState,
    listener: tokio::net::TcpListener,
) -> Result<()> {
    tracing::info!(addr = ?listener.local_addr().ok(), "wires-mcp listening");
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
    let supervisor =
        crate::tenants::TenantSupervisor::new(cfg.users_dir(), std::time::Duration::from_secs(60));
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
        rate_limit: crate::rate_limit::RateLimiter::dcr_default(),
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

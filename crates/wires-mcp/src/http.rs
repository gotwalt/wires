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
    pub supervisor: crate::fabrics::FabricSupervisor,
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
    // JSON-bodied OAuth endpoints — small payloads, safe to buffer + log.
    let json_oauth_routes = Router::new()
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
            "/oauth/signin/assertion",
            axum::routing::post(crate::sign_in_endpoint::handler),
        )
        .route(
            "/oauth/session/probe",
            axum::routing::post(crate::oauth::session_probe::handler),
        )
        .route(
            "/oauth/token",
            axum::routing::post(crate::oauth::token::handler),
        )
        .layer(axum::middleware::from_fn(log_oauth));

    // HTML-bodied user-facing endpoints — bodies include an SVG QR and
    // are too large to buffer cheaply. Only log method/URI/status here.
    let html_oauth_routes = Router::new()
        .route(
            "/oauth/authorize",
            axum::routing::get(crate::oauth::authorize::handler),
        )
        .route(
            "/oauth/authorize/status/{session_id}",
            axum::routing::get(crate::oauth::authorize_status::handler),
        )
        .layer(axum::middleware::from_fn(log_oauth_brief));

    // Mount the MCP JSON-RPC handler at both `/` and `/mcp`. Real-world
    // MCP clients (Claude) treat the PRM `resource` URI — our `public_url`
    // — as the MCP endpoint URL itself and POST to `/`. We keep `/mcp` as
    // an alias so unit tests and any clients that hardcode that path keep
    // working.
    let mcp_handler = axum::routing::post(crate::mcp::router::handler).layer(
        axum::middleware::from_fn_with_state(state.clone(), crate::oauth::middleware::bearer),
    );

    Router::new()
        .route("/_health", axum::routing::get(health))
        .merge(json_oauth_routes)
        .merge(html_oauth_routes)
        .route("/", mcp_handler.clone())
        .route("/mcp", mcp_handler)
        .with_state(state)
}

/// Debug middleware for JSON-bodied OAuth endpoints: buffers the request
/// body and response body, logs both at `debug` level, then passes them
/// through. Enabled by setting `RUST_LOG=wires_mcp::http=debug`. Off by
/// default; do not leave on in production — request and response bodies
/// may contain short-lived secrets (auth codes, PKCE verifiers, refresh
/// tokens). Do NOT mount on HTML endpoints (e.g. /oauth/authorize) — the
/// SVG QR pushes payloads well beyond what we want to buffer in memory.
async fn log_oauth(req: Request<Body>, next: Next) -> Response {
    const MAX_LOG_BODY: usize = 1024 * 1024;
    let method = req.method().clone();
    let uri = req.uri().clone();
    let req_headers = format!("{:?}", req.headers());
    let (parts, body) = req.into_parts();
    let req_bytes = match to_bytes(body, MAX_LOG_BODY).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, method = %method, uri = %uri, "log_oauth: req body too large to buffer; failing closed");
            return (
                axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeded debug log buffer",
            )
                .into_response();
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
            // Body too large to buffer-and-replay. We've already consumed
            // the stream, so we cannot pass the original through. Surface
            // the failure as a 500 so the client sees a clear error rather
            // than a silent empty 200.
            tracing::warn!(error = %e, method = %method, uri = %uri, "log_oauth: resp body too large to buffer; mount log_oauth_brief instead for this route");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "response body exceeded debug log buffer",
            )
                .into_response();
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

/// Lightweight version of [`log_oauth`] for endpoints whose bodies are
/// large or sensitive in ways that don't help OAuth debugging (HTML
/// consent pages, status pages). Logs method, URI, request headers, and
/// response status — does not buffer or read bodies, so it passes
/// streamed bodies through unchanged.
async fn log_oauth_brief(req: Request<Body>, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let req_headers = format!("{:?}", req.headers());
    tracing::debug!(
        method = %method,
        uri = %uri,
        headers = %req_headers,
        "oauth request (brief)",
    );
    let resp = next.run(req).await;
    tracing::debug!(
        method = %method,
        uri = %uri,
        status = %resp.status(),
        "oauth response (brief)",
    );
    resp
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
        retention: None,
    };
    let store = Store::open(&cfg.gateway_db_path()).unwrap();
    let supervisor = crate::fabrics::FabricSupervisor::new(
        cfg.users_dir(),
        std::time::Duration::from_secs(60),
        None,
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

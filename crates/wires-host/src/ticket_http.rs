//! Always-on LAN HTTP server that exposes the host's `HostTicket` as a
//! QR-first web page plus two raw routes. Bound to `--http-bind` (default
//! `0.0.0.0:8089`); lives as long as the host process.
//!
//! See `docs/superpowers/specs/2026-05-18-wires-host-ticket-http-page-design.md`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use snafu::ResultExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use wires_net::HostTicket;

use crate::error::{HostError, HostTicketSnafu, HttpBindSnafu, HttpServeSnafu, Result};

struct AppState {
    endpoint: iroh::Endpoint,
    hint_ttl: Duration,
}

/// Bind a TCP listener, spawn the axum server, and return both the bound
/// address (resolved from the listener — important when `bind` uses port 0)
/// and the JoinHandle for the server task.
///
/// The server runs until `shutdown` is cancelled. Graceful shutdown drains
/// in-flight requests.
pub async fn spawn(
    endpoint: iroh::Endpoint,
    bind: SocketAddr,
    hint_ttl: Duration,
    shutdown: CancellationToken,
) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind(bind).await.context(HttpBindSnafu { bind })?;
    let bound = listener.local_addr().context(HttpBindSnafu { bind })?;
    let state = Arc::new(AppState { endpoint, hint_ttl });
    let router = build_router(state);
    let handle = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move { shutdown.cancelled().await })
            .await
            .context(HttpServeSnafu)?;
        Ok(())
    });
    Ok((bound, handle))
}

fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/ticket.txt", get(serve_txt))
        .with_state(state)
}

/// Build the current ticket from the live endpoint. Re-derived per request.
fn current_ticket(state: &AppState) -> Result<HostTicket> {
    HostTicket::from_endpoint(&state.endpoint, state.hint_ttl).context(HostTicketSnafu)
}

async fn serve_txt(State(state): State<Arc<AppState>>) -> Result<Response> {
    let ticket = current_ticket(&state)?;
    let body = ticket.encode().context(HostTicketSnafu)?;
    let mut resp = body.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

impl IntoResponse for HostError {
    fn into_response(self) -> Response {
        tracing::error!(error = %self, "ticket-http handler failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error rendering host ticket",
        )
            .into_response()
    }
}

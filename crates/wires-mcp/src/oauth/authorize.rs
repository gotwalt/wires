//! `GET /oauth/authorize` — entry point to the consent UX. Validates the
//! request, creates an `auth_sessions` row + a `pending_signins` row, and
//! renders the consent HTML with a single `SessionTicket` QR. Pair endpoint
//! allocation is deferred to `POST /oauth/session/probe`.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use serde::Deserialize;

use crate::http::ServiceState;
use crate::store::{
    AuthSessionKind, AuthSessionRecord, PendingSigninRecord,
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
    pub session_ticket_b64: String,
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

    // Persist the sign-in nonce eagerly (cheap). The probe endpoint will
    // reconstruct the full SignInChallenge from this stored nonce if the
    // root is a known user.
    let mut nonce = [0u8; 32];
    use rand_core::RngCore as _;
    rand_core::OsRng.fill_bytes(&mut nonce);
    state
        .store
        .put_pending_signin(&PendingSigninRecord {
            session_id: session_id.clone(),
            challenge_nonce_hex: hex::encode(nonce),
            ttl_expires_ms: now_ms + SIGNIN_CHALLENGE_TTL_MS,
        })
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, oauth_err("server_error", "store")))?;

    let ticket = crate::oauth::session_ticket::SessionTicket::new(
        &state.config.public_url,
        &session_id,
    );

    Ok(AuthorizeContext {
        session_id,
        client_name: client.client_name,
        session_ticket_b64: ticket.encode_url_safe_b64(),
    })
}

fn oauth_err(code: &str, desc: &str) -> serde_json::Value {
    serde_json::json!({"error": code, "error_description": desc})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::OauthClientRecord;
    use tempfile::TempDir;

    fn state() -> (TempDir, ServiceState) {
        let tmp = TempDir::new().unwrap();
        let st = crate::http::test_state(tmp.path());
        // Pre-populate the client used by all authorize tests.
        st.store.put_oauth_client(&OauthClientRecord {
            client_id: "c1".into(),
            client_name: "Claude Desktop".into(),
            redirect_uris: vec!["http://localhost:33333/callback".into()],
            grant_types: vec!["authorization_code".into()],
            created_at_ms: 0,
            revoked: false,
        }).unwrap();
        (tmp, st)
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
    async fn happy_path_creates_session_and_pending_signin() {
        let (_t, st) = state();
        let ctx = validate_and_create(&st, &params()).await.unwrap();
        assert!(!ctx.session_id.is_empty());
        assert_eq!(ctx.client_name, "Claude Desktop");
        assert!(!ctx.session_ticket_b64.is_empty());
        assert!(st.store.get_auth_session(&ctx.session_id).unwrap().is_some());
        assert!(st.store.get_pending_signin(&ctx.session_id).unwrap().is_some());
        // pending_pair is NOT created at /authorize — only at probe time.
        assert!(st.store.get_pending_pair(&ctx.session_id).unwrap().is_none());
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

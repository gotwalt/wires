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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
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
        token_type: "Bearer".into(),
        expires_in: ACCESS_TOKEN_TTL_S,
        scope: "mcp:wires".into(),
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
        token_type: "Bearer".into(),
        expires_in: ACCESS_TOKEN_TTL_S,
        scope: "mcp:wires".into(),
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
}

//! `POST /oauth/session/probe` — iOS posts its root_pubkey here after
//! scanning the consent-page QR. Gateway returns either the existing
//! sign-in challenge (known root) or lazily allocates + returns a fresh
//! pair token (unknown root). Idempotent per session_id.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::http::ServiceState;
use crate::sign_in::SignInChallenge;
use crate::store::AuthSessionKind;

#[derive(Debug, Clone, Deserialize)]
pub struct ProbeRequest {
    pub session_id: String,
    pub root_pubkey_hex: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProbeResponse {
    Signin { challenge_b64: String },
    Pair { pair_token_b64: String },
}

pub async fn handler(
    State(state): State<ServiceState>,
    Json(req): Json<ProbeRequest>,
) -> Result<(StatusCode, Json<ProbeResponse>), (StatusCode, Json<serde_json::Value>)> {
    // Validate hex shape early so a malformed body is a clean 400.
    let decoded = hex::decode(&req.root_pubkey_hex)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "bad_root_pubkey_hex"))?;
    if decoded.len() != 32 {
        return Err(err(StatusCode::BAD_REQUEST, "bad_root_pubkey_hex"));
    }

    let session = state
        .store
        .get_auth_session(&req.session_id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown_session"))?;
    let now_ms = Utc::now().timestamp_millis();
    if now_ms >= session.expires_ms {
        return Err(err(StatusCode::GONE, "expired"));
    }
    if !matches!(session.kind, AuthSessionKind::Pending) {
        return Err(err(StatusCode::BAD_REQUEST, "already_done"));
    }

    let user = state
        .store
        .get_user(&req.root_pubkey_hex)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?;

    if user.is_some() {
        // Known user → sign-in branch.
        let pending = state
            .store
            .get_pending_signin(&req.session_id)
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown_signin"))?;
        let nonce: [u8; 32] = hex::decode(&pending.challenge_nonce_hex)
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "bad_stored_nonce"))?
            .try_into()
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "bad_stored_nonce"))?;
        let issued_at = pending.ttl_expires_ms - crate::oauth::authorize::SIGNIN_CHALLENGE_TTL_MS;
        let challenge = SignInChallenge::new(
            &state.config.public_url,
            &req.session_id,
            nonce,
            issued_at,
            crate::oauth::authorize::SIGNIN_CHALLENGE_TTL_MS,
        );
        return Ok((StatusCode::OK, Json(ProbeResponse::Signin {
            challenge_b64: challenge.encode_url_safe_b64(),
        })));
    }

    // Unknown user → lazy pair allocation.
    let client = state
        .store
        .get_oauth_client(&session.client_id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid_client"))?;
    let token = state
        .pair_bridge
        .start(&req.session_id, &client.client_name)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "session_probe: pair_bridge.start");
            err(StatusCode::INTERNAL_SERVER_ERROR, "pair_alloc_failed")
        })?;
    Ok((StatusCode::OK, Json(ProbeResponse::Pair { pair_token_b64: token })))
}

fn err(status: StatusCode, code: &str) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({"error": code})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{ServiceState, app, test_state};
    use crate::store::{
        AuthSessionKind, AuthSessionRecord, OauthClientRecord, PendingSigninRecord, UserRecord,
    };
    use axum::body::Body;
    use axum::http::Request;
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn seed(tmp: &TempDir) -> ServiceState {
        let st = test_state(tmp.path());
        st.store.put_oauth_client(&OauthClientRecord {
            client_id: "c1".into(),
            client_name: "Claude Desktop".into(),
            redirect_uris: vec!["http://x/cb".into()],
            grant_types: vec!["authorization_code".into()],
            created_at_ms: 0,
            revoked: false,
        }).unwrap();
        let now_ms = Utc::now().timestamp_millis();
        st.store.put_auth_session(&AuthSessionRecord {
            session_id: "sid".into(),
            client_id: "c1".into(),
            redirect_uri: "http://x/cb".into(),
            code_challenge: "cc".into(),
            code_challenge_method: "S256".into(),
            resource: st.config.public_url.clone(),
            state: "st".into(),
            kind: AuthSessionKind::Pending,
            issued_at_ms: now_ms,
            expires_ms: now_ms + 60_000,
        }).unwrap();
        st.store.put_pending_signin(&PendingSigninRecord {
            session_id: "sid".into(),
            challenge_nonce_hex: hex::encode([7u8; 32]),
            ttl_expires_ms: now_ms + crate::oauth::authorize::SIGNIN_CHALLENGE_TTL_MS,
        }).unwrap();
        st
    }

    async fn probe(st: ServiceState, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let resp = app(st)
            .oneshot(Request::post("/oauth/session/probe")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())).unwrap())
            .await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({}));
        (status, json)
    }

    #[tokio::test]
    async fn unknown_root_returns_pair_token() {
        let tmp = TempDir::new().unwrap();
        let st = seed(&tmp);
        let unknown_root = hex::encode([3u8; 32]);
        let body = serde_json::json!({"session_id": "sid", "root_pubkey_hex": unknown_root});
        let (status, json) = probe(st, body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["kind"], "pair");
        assert!(json["pair_token_b64"].as_str().unwrap().len() > 0);
    }

    #[tokio::test]
    async fn known_root_returns_signin_challenge() {
        let tmp = TempDir::new().unwrap();
        let st = seed(&tmp);
        let root = SigningKey::from_bytes(&[42u8; 32]);
        let root_hex = hex::encode(root.verifying_key().to_bytes());
        st.store.put_user(&UserRecord {
            root_pubkey_hex: root_hex.clone(),
            data_dir: "x".into(),
            created_at_ms: 0,
            last_seen_ms: 0,
        }).unwrap();
        let body = serde_json::json!({"session_id": "sid", "root_pubkey_hex": root_hex});
        let (status, json) = probe(st, body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["kind"], "signin");
        assert!(json["challenge_b64"].as_str().unwrap().len() > 0);
    }

    #[tokio::test]
    async fn unknown_session_404s() {
        let tmp = TempDir::new().unwrap();
        let st = seed(&tmp);
        let body = serde_json::json!({"session_id": "missing", "root_pubkey_hex": hex::encode([1u8; 32])});
        let (status, _) = probe(st, body).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn malformed_hex_400s() {
        let tmp = TempDir::new().unwrap();
        let st = seed(&tmp);
        let body = serde_json::json!({"session_id": "sid", "root_pubkey_hex": "not_hex"});
        let (status, _) = probe(st, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

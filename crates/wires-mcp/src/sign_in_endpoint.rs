//! `POST /oauth/signin/assertion` — iOS posts a root-signed assertion of a
//! prior `SignInChallenge`. On success: delete the pending row (single-use),
//! mint an auth code, flip the session to Done with `sub = root_pubkey_hex`.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::http::ServiceState;
use crate::sign_in::SignInChallenge;
use crate::store::{AuthCodeRecord, AuthSessionKind};

#[derive(Debug, Clone, Deserialize)]
pub struct SignInAssertion {
    pub session_id: String,
    pub root_pubkey: String, // hex
    pub signature: String,   // hex
}

#[derive(Debug, Clone, Serialize)]
pub struct SignInAck {
    pub ok: bool,
}

pub async fn handler(
    State(state): State<ServiceState>,
    Json(req): Json<SignInAssertion>,
) -> Result<(StatusCode, Json<SignInAck>), (StatusCode, Json<serde_json::Value>)> {
    let pending = state
        .store
        .get_pending_signin(&req.session_id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown_session"))?;
    let now_ms = Utc::now().timestamp_millis();
    if now_ms >= pending.ttl_expires_ms {
        return Err(err(StatusCode::BAD_REQUEST, "expired"));
    }
    let session = state
        .store
        .get_auth_session(&req.session_id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown_session"))?;
    if !matches!(session.kind, AuthSessionKind::Pending) {
        return Err(err(StatusCode::BAD_REQUEST, "already_done"));
    }

    // Reconstruct the original challenge and verify signature.
    let nonce: [u8; 32] = {
        let v = hex::decode(&pending.challenge_nonce_hex).map_err(|_| err(StatusCode::BAD_REQUEST, "bad_nonce"))?;
        v.try_into().map_err(|_| err(StatusCode::BAD_REQUEST, "bad_nonce"))?
    };
    let challenge = SignInChallenge::new(
        &state.config.public_url,
        &req.session_id,
        nonce,
        pending.ttl_expires_ms - crate::oauth::authorize::SIGNIN_CHALLENGE_TTL_MS,
        crate::oauth::authorize::SIGNIN_CHALLENGE_TTL_MS,
    );
    let root_arr: [u8; 32] = {
        let v = hex::decode(&req.root_pubkey).map_err(|_| err(StatusCode::BAD_REQUEST, "bad_root"))?;
        v.try_into().map_err(|_| err(StatusCode::BAD_REQUEST, "bad_root"))?
    };
    let vk = VerifyingKey::from_bytes(&root_arr).map_err(|_| err(StatusCode::BAD_REQUEST, "bad_root"))?;
    let sig_bytes = hex::decode(&req.signature).map_err(|_| err(StatusCode::BAD_REQUEST, "bad_signature"))?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| err(StatusCode::BAD_REQUEST, "bad_signature"))?;
    let sig = Signature::from_bytes(&sig_arr);
    if !challenge.verify(&vk, &sig) {
        return Err(err(StatusCode::UNAUTHORIZED, "bad_signature"));
    }

    // Single-use: delete the pending row.
    state
        .store
        .delete_pending_signin(&req.session_id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?;

    // The household must already have a user record on this gateway.
    if state.store.get_user(&req.root_pubkey).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?.is_none() {
        return Err(err(StatusCode::NOT_FOUND, "unknown_root_pubkey"));
    }

    // Mint auth code + flip session to Done.
    let code = uuid::Uuid::new_v4().to_string();
    let updated = crate::store::AuthSessionRecord {
        kind: AuthSessionKind::Done {
            auth_code: code.clone(),
            sub: req.root_pubkey.clone(),
        },
        ..session
    };
    let updated_redirect = updated.redirect_uri.clone();
    let updated_state = updated.state.clone();
    let updated_client_id = updated.client_id.clone();
    let updated_code_challenge = updated.code_challenge.clone();
    state.store.put_auth_session(&updated).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?;
    state.store.put_auth_code(&AuthCodeRecord {
        code,
        session_id: req.session_id,
        sub: req.root_pubkey,
        client_id: updated_client_id,
        redirect_uri: updated_redirect,
        code_challenge: updated_code_challenge,
        issued_at_ms: now_ms,
        expires_ms: now_ms + crate::pair_bridge::AUTH_CODE_TTL_MS,
        consumed: false,
    }).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?;
    let _ = updated_state;
    Ok((StatusCode::OK, Json(SignInAck { ok: true })))
}

fn err(status: StatusCode, code: &str) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({"error": code})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{ServiceState, app, test_state};
    use crate::sign_in::SignInChallenge;
    use crate::store::{AuthSessionRecord, OauthClientRecord, PendingSigninRecord, UserRecord};
    use axum::body::Body;
    use axum::http::Request;
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn setup() -> (TempDir, ServiceState, SigningKey, String) {
        let tmp = TempDir::new().unwrap();
        let st = test_state(tmp.path());
        let root = SigningKey::from_bytes(&[42u8; 32]);
        let root_pubkey_hex = hex::encode(root.verifying_key().to_bytes());
        st.store.put_user(&UserRecord {
            root_pubkey_hex: root_pubkey_hex.clone(),
            data_dir: "x".into(),
            created_at_ms: 0,
            last_seen_ms: 0,
        }).unwrap();
        st.store.put_oauth_client(&OauthClientRecord {
            client_id: "c1".into(),
            client_name: "C".into(),
            redirect_uris: vec!["http://x".into()],
            grant_types: vec!["authorization_code".into()],
            created_at_ms: 0,
            revoked: false,
        }).unwrap();
        let now_ms = Utc::now().timestamp_millis();
        let nonce = [9u8; 32];
        st.store.put_pending_signin(&PendingSigninRecord {
            session_id: "sid".into(),
            challenge_nonce_hex: hex::encode(nonce),
            ttl_expires_ms: now_ms + crate::oauth::authorize::SIGNIN_CHALLENGE_TTL_MS,
        }).unwrap();
        st.store.put_auth_session(&AuthSessionRecord {
            session_id: "sid".into(),
            client_id: "c1".into(),
            redirect_uri: "http://x".into(),
            code_challenge: "cc".into(),
            code_challenge_method: "S256".into(),
            resource: st.config.public_url.clone(),
            state: "st".into(),
            kind: AuthSessionKind::Pending,
            issued_at_ms: now_ms,
            expires_ms: now_ms + 60_000,
        }).unwrap();
        (tmp, st, root, root_pubkey_hex)
    }

    fn sign(root: &SigningKey, st: &ServiceState, nonce: [u8; 32], issued_at_ms: i64) -> String {
        let challenge = SignInChallenge::new(
            &st.config.public_url,
            "sid",
            nonce,
            issued_at_ms,
            crate::oauth::authorize::SIGNIN_CHALLENGE_TTL_MS,
        );
        hex::encode(challenge.sign(root).to_bytes())
    }

    #[tokio::test]
    async fn happy_path_mints_auth_code_and_marks_done() {
        let (_t, st, root, root_hex) = setup();
        let pending = st.store.get_pending_signin("sid").unwrap().unwrap();
        let nonce: [u8; 32] = hex::decode(&pending.challenge_nonce_hex).unwrap().try_into().unwrap();
        let issued = pending.ttl_expires_ms - crate::oauth::authorize::SIGNIN_CHALLENGE_TTL_MS;
        let sig = sign(&root, &st, nonce, issued);
        let body = serde_json::json!({"session_id": "sid", "root_pubkey": root_hex, "signature": sig});
        let resp = app(st.clone())
            .oneshot(Request::post("/oauth/signin/assertion")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())).unwrap())
            .await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let sess = st.store.get_auth_session("sid").unwrap().unwrap();
        match sess.kind {
            AuthSessionKind::Done { auth_code, sub } => {
                assert_eq!(sub, hex::encode(root.verifying_key().to_bytes()));
                assert!(st.store.get_auth_code(&auth_code).unwrap().is_some());
            }
            _ => panic!("expected Done"),
        }
        assert!(st.store.get_pending_signin("sid").unwrap().is_none());
    }

    #[tokio::test]
    async fn wrong_root_rejected() {
        let (_t, st, _root, _root_hex) = setup();
        let other = SigningKey::from_bytes(&[99u8; 32]);
        let other_hex = hex::encode(other.verifying_key().to_bytes());
        let pending = st.store.get_pending_signin("sid").unwrap().unwrap();
        let nonce: [u8; 32] = hex::decode(&pending.challenge_nonce_hex).unwrap().try_into().unwrap();
        let issued = pending.ttl_expires_ms - crate::oauth::authorize::SIGNIN_CHALLENGE_TTL_MS;
        let sig = sign(&other, &st, nonce, issued);
        let body = serde_json::json!({"session_id": "sid", "root_pubkey": other_hex, "signature": sig});
        let resp = app(st)
            .oneshot(Request::post("/oauth/signin/assertion")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())).unwrap())
            .await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND); // unknown_root_pubkey
    }

    #[tokio::test]
    async fn bad_signature_rejected() {
        let (_t, st, _root, root_hex) = setup();
        let body = serde_json::json!({
            "session_id": "sid",
            "root_pubkey": root_hex,
            "signature": hex::encode([0u8; 64]),
        });
        let resp = app(st)
            .oneshot(Request::post("/oauth/signin/assertion")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())).unwrap())
            .await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

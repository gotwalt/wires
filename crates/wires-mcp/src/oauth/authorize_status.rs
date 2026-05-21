//! `GET /oauth/authorize/status/{session_id}` — browser-polled JSON status.
//! Returns `pending`, `done` with auth code + state + redirect_uri, or
//! `expired`. No long-poll in v1 (the browser polls every ~1.5s; clamp by
//! `Cache-Control: no-store`).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use chrono::Utc;
use serde::Serialize;

use crate::http::ServiceState;
use crate::store::AuthSessionKind;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StatusResponse {
    Pending,
    Done {
        code: String,
        state: String,
        redirect_uri: String,
    },
    Expired,
}

pub async fn handler(
    State(state): State<ServiceState>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    let session = match state.store.get_auth_session(&session_id) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                headers,
                Json(serde_json::json!({"error":"unknown_session"})),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                headers,
                Json(serde_json::json!({"error":"server_error"})),
            )
                .into_response();
        }
    };
    let now_ms = Utc::now().timestamp_millis();
    let body = match session.kind {
        AuthSessionKind::Pending if now_ms >= session.expires_ms => StatusResponse::Expired,
        AuthSessionKind::Pending => StatusResponse::Pending,
        AuthSessionKind::Done { auth_code, .. } => StatusResponse::Done {
            code: auth_code,
            state: session.state,
            redirect_uri: session.redirect_uri,
        },
        AuthSessionKind::Expired => StatusResponse::Expired,
        AuthSessionKind::Failed { .. } => StatusResponse::Expired,
    };
    (
        StatusCode::OK,
        headers,
        Json(serde_json::to_value(body).unwrap()),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::app;
    use crate::store::AuthSessionRecord;
    use axum::body::Body;
    use axum::http::Request;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn state() -> (TempDir, ServiceState) {
        let tmp = TempDir::new().unwrap();
        let st = crate::http::test_state(tmp.path());
        (tmp, st)
    }

    fn put(state: &ServiceState, sid: &str, kind: AuthSessionKind, expires_ms: i64) {
        state
            .store
            .put_auth_session(&AuthSessionRecord {
                session_id: sid.into(),
                client_id: "c1".into(),
                redirect_uri: "http://x/cb".into(),
                code_challenge: "cc".into(),
                code_challenge_method: "S256".into(),
                resource: "https://mcp.example.com".into(),
                state: "st".into(),
                kind,
                issued_at_ms: 0,
                expires_ms,
            })
            .unwrap();
    }

    #[tokio::test]
    async fn pending_returns_pending() {
        let (_t, st) = state();
        put(
            &st,
            "sid-1",
            AuthSessionKind::Pending,
            Utc::now().timestamp_millis() + 60_000,
        );
        let resp = app(st)
            .oneshot(
                Request::get("/oauth/authorize/status/sid-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["kind"], "pending");
    }

    #[tokio::test]
    async fn done_returns_code_state_redirect() {
        let (_t, st) = state();
        put(
            &st,
            "sid-2",
            AuthSessionKind::Done {
                auth_code: "AC-123".into(),
                sub: "deadbeef".repeat(8),
            },
            Utc::now().timestamp_millis() + 60_000,
        );
        let resp = app(st)
            .oneshot(
                Request::get("/oauth/authorize/status/sid-2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["kind"], "done");
        assert_eq!(v["code"], "AC-123");
        assert_eq!(v["state"], "st");
        assert_eq!(v["redirect_uri"], "http://x/cb");
    }

    #[tokio::test]
    async fn pending_past_expiry_returns_expired() {
        let (_t, st) = state();
        put(&st, "sid-3", AuthSessionKind::Pending, 1); // long ago
        let resp = app(st)
            .oneshot(
                Request::get("/oauth/authorize/status/sid-3")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["kind"], "expired");
    }

    #[tokio::test]
    async fn unknown_session_is_404() {
        let (_t, st) = state();
        let resp = app(st)
            .oneshot(
                Request::get("/oauth/authorize/status/nope")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}

//! Dynamic Client Registration (RFC 7591). Public clients only — no
//! client_secret returned. PKCE is enforced at /authorize, so we don't
//! authenticate clients at this endpoint at all; only validate input shape.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::http::ServiceState;
use crate::rate_limit::source_ip_key;
use crate::store::OauthClientRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterResponse {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub token_endpoint_auth_method: String, // "none"
}

pub async fn handler(
    State(state): State<ServiceState>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Response {
    let key = source_ip_key(&headers);
    if let Err(retry_after) = state.rate_limit.check(&key, std::time::Instant::now()) {
        let mut resp = (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "temporarily_unavailable",
                "error_description": "registration rate limit exceeded"
            })),
        )
            .into_response();
        if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
            resp.headers_mut().insert("retry-after", v);
        }
        return resp;
    }
    if req.client_name.is_empty() || req.redirect_uris.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_redirect_uri",
                "error_description": "client_name and at least one redirect_uri required"
            })),
        )
            .into_response();
    }
    let grant_types = req
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".into(), "refresh_token".into()]);
    for g in &grant_types {
        if g != "authorization_code" && g != "refresh_token" {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_client_metadata",
                    "error_description": format!("unsupported grant_type {g}")
                })),
            )
                .into_response();
        }
    }
    let client_id = uuid::Uuid::new_v4().to_string();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let rec = OauthClientRecord {
        client_id: client_id.clone(),
        client_name: req.client_name.clone(),
        redirect_uris: req.redirect_uris.clone(),
        grant_types: grant_types.clone(),
        created_at_ms: now_ms,
        revoked: false,
    };
    if let Err(e) = state.store.put_oauth_client(&rec) {
        tracing::error!(error = %e, "DCR put_oauth_client");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "server_error"})),
        )
            .into_response();
    }
    (
        StatusCode::CREATED,
        Json(RegisterResponse {
            client_id,
            client_name: req.client_name,
            redirect_uris: req.redirect_uris,
            grant_types,
            token_endpoint_auth_method: "none".into(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::app;
    use axum::body::Body;
    use axum::http::Request;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn state() -> (TempDir, crate::http::ServiceState) {
        let tmp = TempDir::new().unwrap();
        let st = crate::http::test_state(tmp.path());
        (tmp, st)
    }

    #[tokio::test]
    async fn registers_a_new_public_client() {
        let (_t, st) = state();
        let body = serde_json::json!({
            "client_name": "Claude Desktop",
            "redirect_uris": ["http://localhost:33333/callback"]
        });
        let resp = app(st.clone())
            .oneshot(
                Request::post("/oauth/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let r: RegisterResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(r.client_name, "Claude Desktop");
        assert_eq!(r.token_endpoint_auth_method, "none");
        assert!(uuid::Uuid::parse_str(&r.client_id).is_ok());
        assert!(st.store.get_oauth_client(&r.client_id).unwrap().is_some());
    }

    #[tokio::test]
    async fn refuses_missing_redirect_uri() {
        let (_t, st) = state();
        let body = serde_json::json!({"client_name": "C", "redirect_uris": []});
        let resp = app(st)
            .oneshot(
                Request::post("/oauth/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn rate_limit_blocks_after_max_with_retry_after() {
        use crate::rate_limit::RateLimiter;
        use std::time::Duration;
        let tmp = TempDir::new().unwrap();
        let mut st = crate::http::test_state(tmp.path());
        st.rate_limit = RateLimiter::new(2, Duration::from_secs(60));
        let body = serde_json::json!({
            "client_name": "Claude Desktop",
            "redirect_uris": ["http://localhost:33333/callback"]
        });
        for _ in 0..2 {
            let resp = app(st.clone())
                .oneshot(
                    Request::post("/oauth/register")
                        .header("content-type", "application/json")
                        .header("x-forwarded-for", "1.2.3.4")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
        }
        let resp = app(st.clone())
            .oneshot(
                Request::post("/oauth/register")
                    .header("content-type", "application/json")
                    .header("x-forwarded-for", "1.2.3.4")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let retry_after = resp
            .headers()
            .get("retry-after")
            .expect("retry-after header");
        let secs: u64 = retry_after.to_str().unwrap().parse().unwrap();
        assert!((1..=60).contains(&secs), "retry-after out of band: {secs}");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"], "temporarily_unavailable");
    }

    #[tokio::test]
    async fn rate_limit_buckets_per_source_ip() {
        use crate::rate_limit::RateLimiter;
        use std::time::Duration;
        let tmp = TempDir::new().unwrap();
        let mut st = crate::http::test_state(tmp.path());
        st.rate_limit = RateLimiter::new(1, Duration::from_secs(60));
        let body = serde_json::json!({
            "client_name": "Claude Desktop",
            "redirect_uris": ["http://localhost:33333/callback"]
        });
        // First source exhausts its quota.
        let resp = app(st.clone())
            .oneshot(
                Request::post("/oauth/register")
                    .header("content-type", "application/json")
                    .header("x-forwarded-for", "1.2.3.4")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        // Different source key is still fine.
        let resp = app(st)
            .oneshot(
                Request::post("/oauth/register")
                    .header("content-type", "application/json")
                    .header("x-forwarded-for", "9.9.9.9")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn refuses_unsupported_grant_type() {
        let (_t, st) = state();
        let body = serde_json::json!({
            "client_name": "C",
            "redirect_uris": ["http://x"],
            "grant_types": ["password"]
        });
        let resp = app(st)
            .oneshot(
                Request::post("/oauth/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}

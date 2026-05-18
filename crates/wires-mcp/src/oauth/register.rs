//! Dynamic Client Registration (RFC 7591). Public clients only — no
//! client_secret returned. PKCE is enforced at /authorize, so we don't
//! authenticate clients at this endpoint at all; only validate input shape.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::http::ServiceState;
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
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), (StatusCode, Json<serde_json::Value>)> {
    if req.client_name.is_empty() || req.redirect_uris.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_redirect_uri",
                "error_description": "client_name and at least one redirect_uri required"
            })),
        ));
    }
    let grant_types = req
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".into(), "refresh_token".into()]);
    for g in &grant_types {
        if g != "authorization_code" && g != "refresh_token" {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_client_metadata",
                    "error_description": format!("unsupported grant_type {g}")
                })),
            ));
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
    state.store.put_oauth_client(&rec).map_err(|e| {
        tracing::error!(error = %e, "DCR put_oauth_client");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "server_error"})),
        )
    })?;
    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            client_id,
            client_name: req.client_name,
            redirect_uris: req.redirect_uris,
            grant_types,
            token_endpoint_auth_method: "none".into(),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;
    use crate::http::{ServiceState, app};
    use crate::store::Store;
    use axum::body::Body;
    use axum::http::Request;
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn state() -> (TempDir, ServiceState) {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
        };
        let store = Store::open(&cfg.gateway_db_path()).unwrap();
        let st = ServiceState {
            config: std::sync::Arc::new(cfg),
            store,
            signing_key: std::sync::Arc::new(SigningKey::from_bytes(&[1u8; 32])),
        };
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
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
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

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::config::GatewayConfig;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AsMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
}

impl AsMetadata {
    pub fn from_config(cfg: &GatewayConfig) -> Self {
        let base = cfg.public_url.trim_end_matches('/').to_string();
        Self {
            issuer: base.clone(),
            authorization_endpoint: format!("{base}/oauth/authorize"),
            token_endpoint: format!("{base}/oauth/token"),
            registration_endpoint: format!("{base}/oauth/register"),
            jwks_uri: format!("{base}/.well-known/jwks.json"),
            response_types_supported: vec!["code".into()],
            grant_types_supported: vec!["authorization_code".into(), "refresh_token".into()],
            code_challenge_methods_supported: vec!["S256".into()],
            token_endpoint_auth_methods_supported: vec!["none".into()],
            scopes_supported: vec!["mcp:wires".into()],
        }
    }
}

pub async fn handler(State(cfg): State<Arc<GatewayConfig>>) -> Json<AsMetadata> {
    Json(AsMetadata::from_config(&cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::app;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn state() -> (TempDir, crate::http::ServiceState) {
        let tmp = TempDir::new().unwrap();
        let st = crate::http::test_state(tmp.path());
        (tmp, st)
    }

    #[tokio::test]
    async fn returns_the_as_metadata() {
        let (_t, st) = state();
        let resp = app(st)
            .oneshot(
                Request::get("/.well-known/oauth-authorization-server")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let m: AsMetadata = serde_json::from_slice(&body).unwrap();
        assert_eq!(m.issuer, "https://mcp.example.com");
        assert_eq!(
            m.authorization_endpoint,
            "https://mcp.example.com/oauth/authorize"
        );
        assert_eq!(m.token_endpoint, "https://mcp.example.com/oauth/token");
        assert_eq!(m.code_challenge_methods_supported, vec!["S256"]);
        assert_eq!(m.token_endpoint_auth_methods_supported, vec!["none"]);
    }
}

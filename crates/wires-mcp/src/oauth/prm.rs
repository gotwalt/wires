use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::config::GatewayConfig;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrmDocument {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
}

impl PrmDocument {
    pub fn from_config(cfg: &GatewayConfig) -> Self {
        Self {
            resource: cfg.public_url.clone(),
            authorization_servers: vec![cfg.public_url.clone()],
            scopes_supported: vec!["mcp:wires".into()],
        }
    }
}

pub async fn handler(State(cfg): State<Arc<GatewayConfig>>) -> Json<PrmDocument> {
    Json(PrmDocument::from_config(&cfg))
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
    async fn returns_the_prm_document() {
        let (_t, st) = state();
        let resp = app(st)
            .oneshot(
                Request::get("/.well-known/oauth-protected-resource")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let prm: PrmDocument = serde_json::from_slice(&body).unwrap();
        assert_eq!(prm.resource, "https://mcp.example.com");
        assert_eq!(prm.authorization_servers, vec!["https://mcp.example.com"]);
        assert_eq!(prm.scopes_supported, vec!["mcp:wires"]);
    }
}

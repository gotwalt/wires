//! Service-discovery HTTPS endpoint. v1 returns this host's own EndpointId;
//! sharding sub-projects extend the response payload.

use std::sync::Arc;

use axum::{Json, Router, routing::get};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryEndpoint {
    pub endpoint_id: String,
    pub relay: Option<String>,
    pub addrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    pub version: u8,
    pub endpoints: Vec<DiscoveryEndpoint>,
    pub ttl_seconds: u32,
}

pub struct DiscoveryState {
    pub response: DiscoveryResponse,
}

pub fn router(state: Arc<DiscoveryState>) -> Router {
    Router::new().route(
        "/v1/bootstrap",
        get({
            let state = Arc::clone(&state);
            move || {
                let state = Arc::clone(&state);
                async move { Json(state.response.clone()) }
            }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn bootstrap_returns_endpoint_list() {
        let state = Arc::new(DiscoveryState {
            response: DiscoveryResponse {
                version: 1,
                endpoints: vec![DiscoveryEndpoint {
                    endpoint_id: "abc".into(),
                    relay: Some("https://relay.example/".into()),
                    addrs: vec!["127.0.0.1:11204".into()],
                }],
                ttl_seconds: 300,
            },
        });
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/bootstrap")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 64_000)
            .await
            .unwrap();
        let parsed: DiscoveryResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.endpoints.len(), 1);
        assert_eq!(parsed.endpoints[0].endpoint_id, "abc");
    }
}

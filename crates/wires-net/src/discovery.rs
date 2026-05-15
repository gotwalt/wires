//! HTTPS service-discovery client. Spec §7 — fetches `/v1/bootstrap` and
//! converts the response into the `PeerHint` shape that `peer_hint` iterates.

use serde::Deserialize;
use snafu::ResultExt;

use crate::error::{DiscoveryFetchSnafu, Result};
use crate::peer_hint::PeerHint;

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryEndpoint {
    pub endpoint_id: String,
    #[serde(default)]
    pub relay: Option<String>,
    #[serde(default)]
    pub addrs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryResponse {
    pub version: u8,
    pub endpoints: Vec<DiscoveryEndpoint>,
    pub ttl_seconds: u32,
}

/// Fetch `url` and return its endpoints as `PeerHint`s. The response's
/// `endpoints[*]` map field-for-field onto `PeerHint`.
pub async fn fetch_endpoints(url: &str) -> Result<Vec<PeerHint>> {
    let resp = reqwest::get(url)
        .await
        .with_context(|_| DiscoveryFetchSnafu {
            url: url.to_string(),
        })?;
    let payload: DiscoveryResponse = resp.json().await.with_context(|_| DiscoveryFetchSnafu {
        url: url.to_string(),
    })?;
    Ok(payload
        .endpoints
        .into_iter()
        .map(|e| PeerHint {
            node_id: e.endpoint_id,
            addrs: e.addrs,
            relay: e.relay,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fetch_endpoints_decodes_minimal_response() {
        use axum::{Json, Router, routing::get};
        use serde_json::json;
        let app = Router::new().route(
            "/v1/bootstrap",
            get(|| async {
                Json(json!({
                    "version": 1,
                    "endpoints": [{
                        "endpoint_id": "abc",
                        "relay": null,
                        "addrs": ["127.0.0.1:11204"]
                    }],
                    "ttl_seconds": 300
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        let url = format!("http://{addr}/v1/bootstrap");
        let hints = fetch_endpoints(&url).await.unwrap();
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].node_id, "abc");
        assert_eq!(hints[0].addrs, vec!["127.0.0.1:11204".to_string()]);
    }
}

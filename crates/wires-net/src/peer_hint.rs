//! Peer-hint iteration for bootstrap consumers.
//!
//! An ordered list of `PeerHint`s is carried in pairing tokens and discovery
//! responses. A new agent should iterate them in order, attempting to dial
//! each, and proceed with the first one that succeeds. If every hint fails and
//! a `service_discovery_url` is available, [`first_reachable_with_discovery`]
//! refreshes the hint list from that URL and retries once.
//!
//! Higher-level bootstrap orchestration (cap parsing, gossip subscribe,
//! replay catch-up) is the concern of callers, not this helper.

use std::time::Duration;

use iroh::{Endpoint, EndpointId};
use serde::{Deserialize, Serialize};

/// A single peer hint: an iroh endpoint the caller can try to dial.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerHint {
    /// Hex of the iroh EndpointId.
    pub node_id: String,
    pub addrs: Vec<String>,
    pub relay: Option<String>,
}

/// Parse a 64-character hex string into an `EndpointId`. `PeerHint::node_id`
/// and the `endpoint_id` field of discovery responses are both stored as hex;
/// `EndpointId::FromStr` parses base32, so callers go through this helper.
pub fn endpoint_id_from_hex(s: &str) -> Option<EndpointId> {
    let bytes = hex::decode(s).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    EndpointId::from_bytes(&arr).ok()
}

/// Parse a 32-character hex string into a 16-byte capability id.
pub fn cap_id_from_hex(s: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

/// Iterate `peer_hints` in order, attempting to open a connection on `alpn`
/// (with `per_hint_timeout`). Returns the first `EndpointId` that succeeds,
/// or `None` if every hint failed.
pub async fn first_reachable(
    endpoint: &Endpoint,
    peer_hints: &[PeerHint],
    alpn: &[u8],
    per_hint_timeout: Duration,
) -> Option<EndpointId> {
    for hint in peer_hints {
        let Some(node_id) = endpoint_id_from_hex(&hint.node_id) else {
            tracing::warn!(node_id = %hint.node_id, "skipping hint with invalid endpoint_id hex");
            continue;
        };
        match tokio::time::timeout(per_hint_timeout, endpoint.connect(node_id, alpn)).await {
            Ok(Ok(_conn)) => return Some(node_id),
            Ok(Err(e)) => tracing::warn!(node_id = %hint.node_id, error = %e, "dial failed"),
            Err(_) => tracing::warn!(node_id = %hint.node_id, "dial timed out"),
        }
    }
    None
}

/// Like [`first_reachable`], but if every entry in `peer_hints` fails AND
/// `discovery_url` is `Some`, fetches fresh hints from that URL and retries.
/// Spec §6 fallback path.
pub async fn first_reachable_with_discovery(
    endpoint: &iroh::Endpoint,
    peer_hints: &[PeerHint],
    discovery_url: Option<&str>,
    alpn: &[u8],
    per_hint_timeout: std::time::Duration,
) -> Option<iroh::EndpointId> {
    if let Some(id) = first_reachable(endpoint, peer_hints, alpn, per_hint_timeout).await {
        return Some(id);
    }
    let url = discovery_url?;
    let fresh = match crate::discovery::fetch_endpoints(url).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, url, "discovery fetch failed");
            return None;
        }
    };
    first_reachable(endpoint, &fresh, alpn, per_hint_timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use iroh::endpoint::presets;

    #[tokio::test]
    async fn first_reachable_returns_none_for_no_hints_and_no_url() {
        let ep = iroh::Endpoint::builder(presets::N0)
            .secret_key(SecretKey::generate())
            .bind()
            .await
            .unwrap();
        let res = first_reachable_with_discovery(
            &ep,
            &[],
            None,
            b"/wires/tenant/0",
            std::time::Duration::from_millis(50),
        )
        .await;
        assert!(res.is_none());
    }

    /// No-op iroh protocol handler. `first_reachable` only needs the QUIC
    /// handshake to succeed (it drops the connection immediately); this
    /// handler exists so the iroh router will actually advertise & accept the
    /// test ALPN.
    #[derive(Debug)]
    struct NoopProto;
    impl iroh::protocol::ProtocolHandler for NoopProto {
        async fn accept(
            &self,
            _connection: iroh::endpoint::Connection,
        ) -> std::result::Result<(), iroh::protocol::AcceptError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn first_reachable_falls_back_to_discovery_url() {
        use axum::{Json, Router as AxumRouter, routing::get};
        use serde_json::json;
        // Boot a target endpoint we'll discover.
        let target_ep = iroh::Endpoint::builder(presets::N0)
            .secret_key(SecretKey::generate())
            .alpns(vec![b"/wires/test-alpn/0".to_vec()])
            .bind()
            .await
            .unwrap();
        let target_id_hex = hex::encode(target_ep.id().as_bytes());

        let _router = iroh::protocol::Router::builder(target_ep.clone())
            .accept(b"/wires/test-alpn/0", NoopProto)
            .spawn();

        // Serve a discovery response pointing at it.
        let id_for_handler = target_id_hex.clone();
        let app = AxumRouter::new().route(
            "/v1/bootstrap",
            get(move || {
                let id = id_for_handler.clone();
                async move {
                    Json(json!({
                        "version": 1,
                        "endpoints": [{ "endpoint_id": id, "relay": null, "addrs": [] }],
                        "ttl_seconds": 300
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        let url = format!("http://{addr}/v1/bootstrap");

        // Caller endpoint with no usable peer_hints.
        let caller_ep = iroh::Endpoint::builder(presets::N0)
            .secret_key(SecretKey::generate())
            .bind()
            .await
            .unwrap();
        let chosen = first_reachable_with_discovery(
            &caller_ep,
            &[],
            Some(&url),
            b"/wires/test-alpn/0",
            std::time::Duration::from_secs(5),
        )
        .await;
        assert!(chosen.is_some());
        assert_eq!(chosen.unwrap(), target_ep.id());
    }
}

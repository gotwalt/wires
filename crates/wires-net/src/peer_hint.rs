//! Peer-hint iteration for bootstrap consumers.
//!
//! An ordered list of `PeerHint`s is carried in pairing tokens and discovery
//! responses. A new agent should iterate them in order, attempting to dial
//! each, and proceed with the first one that succeeds via [`first_reachable`].
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

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use iroh::endpoint::presets;

    #[tokio::test]
    async fn first_reachable_returns_none_for_no_hints() {
        let ep = iroh::Endpoint::builder(presets::N0)
            .secret_key(SecretKey::generate())
            .bind()
            .await
            .unwrap();
        let res = first_reachable(
            &ep,
            &[],
            b"/wires/tenant/0",
            std::time::Duration::from_millis(50),
        )
        .await;
        assert!(res.is_none());
    }
}

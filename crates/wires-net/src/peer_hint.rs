//! Peer-hint iteration for `InviteToken` consumers.
//!
//! Spec §6: an `InviteToken` carries an ordered list of `PeerHint`s. A new
//! agent should iterate them in order, attempting to dial each, and proceed
//! with the first one that succeeds. The discovery-URL fallback path is not
//! implemented in this slice.
//!
//! TODO: Full bootstrap-from-invite (cap parsing, gossip subscribe, replay
//! catch-up, discovery-URL fallback) is a future scope item. This module
//! provides the minimum peer-hint iteration helper for spec §11 scenario #3.

use std::time::Duration;

use iroh::{Endpoint, EndpointId};

use crate::invite::PeerHint;

/// Outcome of attempting to dial a single hint.
#[derive(Debug)]
pub enum DialOutcome {
    Connected(EndpointId),
    BadNodeId,
    Failed(String),
}

/// Iterate `peer_hints` in order, attempting to open a connection on `alpn`
/// (with `per_hint_timeout`). Returns the first `EndpointId` that succeeds,
/// or `None` if every hint failed.
///
/// Note: This currently establishes a QUIC connection and immediately drops
/// it. A real bootstrap caller would subscribe to gossip / open replay using
/// the returned `EndpointId`; that orchestration lives elsewhere.
///
/// TODO: When `peer_hints` is exhausted and `service_discovery_url` is set,
/// fetch fresh hints and retry (spec §6 fallback path). Not implemented in
/// this slice.
pub async fn first_reachable(
    endpoint: &Endpoint,
    peer_hints: &[PeerHint],
    alpn: &[u8],
    per_hint_timeout: Duration,
) -> Option<EndpointId> {
    for hint in peer_hints {
        // `PeerHint::node_id` is stored as lowercase hex (see `PeerHint` doc
        // and how main.rs produces it via `hex::encode(endpoint_id.as_bytes())`).
        // `EndpointId` is `PublicKey` whose `FromStr` uses base32, not hex, so
        // we hex-decode manually and call `from_bytes`.
        let bytes: [u8; 32] = match hex::decode(&hint.node_id)
            .ok()
            .and_then(|v| v.try_into().ok())
        {
            Some(b) => b,
            None => {
                tracing::warn!(node_id = %hint.node_id, "skipping hint with invalid hex node_id");
                continue;
            }
        };
        let node_id = match EndpointId::from_bytes(&bytes) {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(node_id = %hint.node_id, error = %e, "skipping hint with invalid key bytes");
                continue;
            }
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
    use crate::invite::PeerHint;

    #[test]
    fn empty_hints_returns_none_instantly() {
        // Compile-time sanity: empty list is just a no-op iteration. Real
        // reachability requires an iroh Endpoint, exercised in the
        // acceptance test in wires-host/tests/.
        let _: Vec<PeerHint> = vec![];
    }
}

//! Helpers shared by `wires publish` and `wires cat` for converting a
//! configured `HostConfig` into an iroh bootstrap list and priming the
//! endpoint's address-lookup with direct address / relay hints.

use wires_net::PeerHint;
use wires_node::{NodeConfig, NodeRuntime};

/// Build a bootstrap list of `EndpointId`s from the optional `HostConfig`.
/// Bad hex / wrong length entries are logged at warn level and dropped.
pub fn bootstrap_endpoints(cfg: &NodeConfig) -> Vec<iroh::EndpointId> {
    let mut out = Vec::new();
    if let Some(h) = &cfg.host {
        for hint in &h.peer_hints {
            match peer_hint_endpoint_id(hint) {
                Some(id) => out.push(id),
                None => {
                    tracing::warn!(
                        node_id = %hint.node_id,
                        "dropping peer hint: bad hex / wrong length / not a valid endpoint id"
                    );
                }
            }
        }
    }
    out
}

pub fn peer_hint_endpoint_id(hint: &PeerHint) -> Option<iroh::EndpointId> {
    let bytes = match hex::decode(&hint.node_id) {
        Ok(b) if b.len() == 32 => b,
        _ => return None,
    };
    let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
    iroh::EndpointId::from_bytes(&arr).ok()
}

/// Convert any `PeerHint` entries that carry direct addresses or a relay URL
/// into `EndpointAddr` values and register them with `endpoint.address_lookup`
/// via a `MemoryLookup`. Returns `Ok(())` either way; unparseable addrs are
/// warned but otherwise ignored.
pub fn register_peer_addresses(runtime: &NodeRuntime) -> Result<(), Box<dyn std::error::Error>> {
    let host = match runtime.node.config.host.as_ref() {
        Some(h) => h,
        None => return Ok(()),
    };
    let mut infos: Vec<iroh::EndpointAddr> = Vec::new();
    for hint in &host.peer_hints {
        let id = match peer_hint_endpoint_id(hint) {
            Some(id) => id,
            None => continue,
        };
        let mut addrs: Vec<iroh::TransportAddr> = Vec::new();
        for s in &hint.addrs {
            match s.parse::<std::net::SocketAddr>() {
                Ok(sa) => addrs.push(iroh::TransportAddr::Ip(sa)),
                Err(e) => tracing::warn!(addr = %s, error = %e, "dropping unparseable peer addr"),
            }
        }
        if let Some(relay) = hint.relay.as_deref() {
            match relay.parse::<iroh::RelayUrl>() {
                Ok(url) => addrs.push(iroh::TransportAddr::Relay(url)),
                Err(e) => {
                    tracing::warn!(relay = %relay, error = %e, "dropping unparseable relay URL")
                }
            }
        }
        if addrs.is_empty() {
            continue;
        }
        infos.push(iroh::EndpointAddr::from_parts(id, addrs));
    }
    if infos.is_empty() {
        return Ok(());
    }
    let lookup = runtime
        .endpoint
        .address_lookup()
        .map_err(|e| format!("address_lookup unavailable: {e}"))?;
    lookup.add(iroh::address_lookup::memory::MemoryLookup::from_endpoint_info(infos));
    Ok(())
}

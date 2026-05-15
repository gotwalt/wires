use std::path::Path;

use wires_core::CanonicalContent;
use wires_net::PeerHint;
use wires_node::{NodeConfig, NodeRuntime};

pub async fn run(
    data_dir: &Path,
    topic: &str,
    cap: &str,
    type_: &str,
    text: &str,
    data: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
    let bootstrap = bootstrap_endpoints(&cfg)?;
    let runtime = NodeRuntime::open(cfg).await?;
    // If the config carries `PeerHint` entries with direct addresses or relay
    // info, prime the endpoint's address-lookup with them so gossip/replay can
    // dial without going through pkarr/DNS.
    register_peer_addresses(&runtime, &runtime.node.config)?;
    let topic_id = resolve_topic(data_dir, topic)?;
    let cap_id = decode_hex_16(cap)?;

    runtime.join_topic(topic_id, bootstrap).await?;
    // Give gossip a moment to converge with the bootstrap peer(s) before we
    // broadcast — otherwise our publish lands on an empty mesh and is dropped.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let mut content = CanonicalContent::new(type_, text);
    if let Some(d) = data {
        content = content.with_data(serde_json::from_str(d)?);
    }
    let msg = runtime
        .publish_and_broadcast(topic_id, cap_id, content)
        .await?;
    println!(
        "published seq={} sender={} timestamp={}",
        msg.seq,
        hex::encode(msg.sender),
        msg.timestamp
    );
    // Give gossip a moment to drain before exiting.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    Ok(())
}

pub fn resolve_topic(data_dir: &Path, topic: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if let Ok(bytes) = hex::decode(topic)
        && bytes.len() == 32
    {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }
    let map_path = data_dir.join("topic_names.json");
    let map: std::collections::HashMap<String, String> =
        serde_json::from_str(&std::fs::read_to_string(map_path)?)?;
    let hex_id = map
        .get(topic)
        .ok_or_else(|| format!("unknown topic '{topic}'"))?;
    let bytes = hex::decode(hex_id)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_hex_16(s: &str) -> Result<[u8; 16], Box<dyn std::error::Error>> {
    let bytes = hex::decode(s)?;
    if bytes.len() != 16 {
        return Err("cap_id must be 16 bytes (32 hex chars)".into());
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Build a bootstrap list of `EndpointId`s from the optional `HostConfig`,
/// silently skipping unparseable hints (the caller logs).
fn bootstrap_endpoints(
    cfg: &NodeConfig,
) -> Result<Vec<iroh::EndpointId>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    if let Some(h) = &cfg.host {
        for hint in &h.peer_hints {
            if let Some(id) = peer_hint_endpoint_id(hint) {
                out.push(id);
            }
        }
    }
    Ok(out)
}

fn peer_hint_endpoint_id(hint: &PeerHint) -> Option<iroh::EndpointId> {
    let bytes = match hex::decode(&hint.node_id) {
        Ok(b) if b.len() == 32 => b,
        _ => return None,
    };
    let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
    iroh::EndpointId::from_bytes(&arr).ok()
}

/// Convert any `PeerHint` entries that carry direct addresses or a relay URL
/// into `EndpointAddr` values and register them with `endpoint.address_lookup`
/// via a `MemoryLookup`. This lets gossip dial peers using the supplied hints
/// without first round-tripping to pkarr/DNS.
fn register_peer_addresses(
    runtime: &NodeRuntime,
    cfg: &NodeConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let host = match cfg.host.as_ref() {
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
            if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
                addrs.push(iroh::TransportAddr::Ip(sa));
            }
        }
        if let Some(relay) = hint.relay.as_deref()
            && let Ok(url) = relay.parse::<iroh::RelayUrl>()
        {
            addrs.push(iroh::TransportAddr::Relay(url));
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

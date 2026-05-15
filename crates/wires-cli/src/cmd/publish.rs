use std::path::Path;

use wires_core::CanonicalContent;
use wires_net::cap_id_from_hex;
use wires_node::{NodeConfig, NodeRuntime, resolve_topic};

use crate::cmd::publish_helpers::{bootstrap_endpoints, register_peer_addresses};

pub async fn run(
    data_dir: &Path,
    topic: &str,
    cap: &str,
    type_: &str,
    text: &str,
    data: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
    let bootstrap = bootstrap_endpoints(&cfg);
    let runtime = NodeRuntime::open(cfg).await?;
    // If the config carries `PeerHint` entries with direct addresses or relay
    // info, prime the endpoint's address-lookup with them so gossip/replay can
    // dial without going through pkarr/DNS.
    register_peer_addresses(&runtime)?;
    let topic_id = resolve_topic(data_dir, topic)?;
    let cap_id = cap_id_from_hex(cap).ok_or("cap_id must be 16 bytes (32 hex chars)")?;

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

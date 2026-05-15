use std::path::Path;

use snafu::ResultExt;
use wires_core::CanonicalContent;
use wires_net::cap_id_from_hex;
use wires_node::{NodeConfig, NodeRuntime, resolve_topic};

use crate::cmd::publish_helpers::{bootstrap_endpoints, register_peer_addresses};
use crate::error::{IoSnafu, JsonSnafu, NodeSnafu, Result, TomlParseSnafu};
use crate::invalid;

pub async fn run(
    data_dir: &Path,
    topic: &str,
    cap: &str,
    type_: &str,
    text: &str,
    data: Option<&str>,
) -> Result<()> {
    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let bootstrap = bootstrap_endpoints(&cfg);
    let runtime = NodeRuntime::open(cfg).await.context(NodeSnafu)?;
    register_peer_addresses(&runtime)?;
    let topic_id = resolve_topic(data_dir, topic).context(IoSnafu)?;
    let cap_id =
        cap_id_from_hex(cap).ok_or_else(|| invalid!("cap_id must be 16 bytes (32 hex chars)"))?;

    runtime
        .join_topic(topic_id, bootstrap)
        .await
        .context(NodeSnafu)?;
    // Give gossip a moment to converge with the bootstrap peer(s) before we
    // broadcast — otherwise our publish lands on an empty mesh and is dropped.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let mut content = CanonicalContent::new(type_, text);
    if let Some(d) = data {
        content = content.with_data(serde_json::from_str(d).context(JsonSnafu)?);
    }
    let msg = runtime
        .publish_and_broadcast(topic_id, cap_id, content)
        .await
        .context(NodeSnafu)?;
    println!(
        "published seq={} sender={} timestamp={}",
        msg.seq,
        hex::encode(msg.sender),
        msg.timestamp
    );
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    Ok(())
}

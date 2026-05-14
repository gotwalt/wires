use std::path::Path;

use wires_core::CanonicalContent;
use wires_node::{Node, NodeConfig};

pub async fn run(
    data_dir: &Path,
    topic: &str,
    cap: &str,
    type_: &str,
    text: &str,
    data: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
    let node = Node::open(cfg)?;
    let topic_id = resolve_topic(data_dir, topic)?;
    let cap_id = decode_hex_16(cap)?;
    let mut content = CanonicalContent::new(type_, text);
    if let Some(d) = data {
        content = content.with_data(serde_json::from_str(d)?);
    }
    let msg = node.publish_standard(topic_id, cap_id, content)?;
    println!(
        "published seq={} sender={} timestamp={}",
        msg.seq,
        hex::encode(msg.sender),
        msg.timestamp
    );
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

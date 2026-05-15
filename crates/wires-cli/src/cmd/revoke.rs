use std::path::Path;

use wires_node::{Node, NodeConfig};

pub async fn run(data_dir: &Path, cap_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
    let node = Node::open(cfg)?;
    let bytes = hex::decode(cap_id)?;
    if bytes.len() != 16 {
        return Err("cap_id must be 16 bytes (32 hex chars)".into());
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes);
    node.caps.mark_revoked(&id, &[0u8; 32])?;
    println!("Revoked cap {cap_id}");
    Ok(())
}

use std::path::Path;

use snafu::ResultExt;
use wires_net::cap_id_from_hex;
use wires_node::{Node, NodeConfig};

use crate::error::{IoSnafu, NodeSnafu, Result, StoreSnafu, TomlParseSnafu};
use crate::invalid;

pub async fn run(data_dir: &Path, cap_id: &str) -> Result<()> {
    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let node = Node::open(cfg).context(NodeSnafu)?;
    let id = cap_id_from_hex(cap_id)
        .ok_or_else(|| invalid!("cap_id must be 16 bytes (32 hex chars)"))?;
    node.caps
        .mark_revoked(&id, &[0u8; 32])
        .context(StoreSnafu)?;
    println!("Revoked cap {cap_id}");
    Ok(())
}

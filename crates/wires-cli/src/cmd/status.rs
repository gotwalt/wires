use std::path::Path;

use snafu::ResultExt;
use wires_node::{Node, NodeConfig};

use crate::error::{IoSnafu, NodeSnafu, Result, TomlParseSnafu};

pub async fn run(data_dir: &Path) -> Result<()> {
    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let node = Node::open(cfg.clone()).context(NodeSnafu)?;
    let pk_hex = hex::encode(node.ed_sk.verifying_key().to_bytes());
    println!("data_dir       : {}", data_dir.display());
    println!("root pubkey    : {}", cfg.root_pubkey_hex);
    println!("agent pubkey   : {pk_hex}");
    let firehose = hex::encode(cfg.firehose_topic_id());
    let caps = hex::encode(cfg.caps_topic_id());
    println!("firehose topic : {firehose}");
    println!("__caps topic   : {caps}");
    Ok(())
}

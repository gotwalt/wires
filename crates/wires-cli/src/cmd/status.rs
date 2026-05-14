use std::path::Path;

use wires_node::{Node, NodeConfig};

pub async fn run(data_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
    let node = Node::open(cfg.clone())?;
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

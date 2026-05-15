use std::path::Path;

use rand_core::{OsRng, RngCore};
use wires_node::{Node, NodeConfig};

pub async fn create(data_dir: &Path, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
    let node = Node::open(cfg)?;

    let mut topic_id = [0u8; 32];
    OsRng.fill_bytes(&mut topic_id);
    let mut epoch_key = [0u8; 32];
    OsRng.fill_bytes(&mut epoch_key);
    node.install_epoch_key(topic_id, 0, epoch_key)?;

    // Persist name → topic_id map
    let map_path = data_dir.join("topic_names.json");
    let mut map: std::collections::HashMap<String, String> = if map_path.exists() {
        serde_json::from_str(&std::fs::read_to_string(&map_path)?)?
    } else {
        std::collections::HashMap::new()
    };
    map.insert(name.to_string(), hex::encode(topic_id));
    std::fs::write(&map_path, serde_json::to_string_pretty(&map)?)?;

    println!("Created topic '{name}' with id {}", hex::encode(topic_id));
    println!(
        "Note: in v1, epoch keys are not distributed via gossip yet — share epoch key {} with peers manually.",
        hex::encode(epoch_key)
    );
    Ok(())
}

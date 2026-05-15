use std::path::Path;

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use wires_core::Capability;
use wires_core::cap::Right;
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

    // Auto-mint a self-cap when this data dir holds a root key and no existing
    // non-revoked cap covers (agent, topic, write).
    let root_path = data_dir.join("root.ed25519");
    if root_path.exists() {
        let root_bytes = std::fs::read(&root_path)?;
        if root_bytes.len() != 32 {
            return Err("root.ed25519 must be 32 bytes".into());
        }
        let root_sk = SigningKey::from_bytes(&root_bytes.try_into().unwrap());
        let agent_pk = node.ed_sk.verifying_key().to_bytes();

        let has_existing = node.caps.all()?.values().any(|entry| {
            !entry.revoked
                && entry.cap.agent == agent_pk
                && entry.cap.allows(name, Right::Write).is_ok()
        });

        if !has_existing {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis() as i64;
            let mut cap = Capability::new_unsigned(
                agent_pk,
                vec![name.to_string()],
                vec![Right::Read, Right::Write],
                now,
                None,
            );
            cap.sign(&root_sk)?;
            node.caps.upsert_grant(&cap)?;
            println!("Minted self-cap: {}", hex::encode(cap.cap_id.0));
        }
    }

    Ok(())
}

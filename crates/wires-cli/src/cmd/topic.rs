use std::path::Path;

use rand_core::{OsRng, RngCore};
use wires_core::Capability;
use wires_core::cap::Right;
use wires_net::unix_now_ms;
use wires_node::{Node, NodeConfig, load_root_signing_key, upsert_topic_names};

pub async fn create(data_dir: &Path, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
    let node = Node::open(cfg)?;

    let mut topic_id = [0u8; 32];
    OsRng.fill_bytes(&mut topic_id);
    let mut epoch_key = [0u8; 32];
    OsRng.fill_bytes(&mut epoch_key);
    node.install_epoch_key(topic_id, 0, epoch_key)?;

    upsert_topic_names(data_dir, [(name.to_string(), topic_id)])?;

    println!("Created topic '{name}' with id {}", hex::encode(topic_id));
    println!(
        "Epoch key (share with peers via `wires pair-approve`): {}",
        hex::encode(epoch_key)
    );

    // Auto-mint a self-cap when this data dir holds a root key and no existing
    // non-revoked cap covers (agent, topic, write).
    if data_dir.join("root.ed25519").exists() {
        let root_sk = load_root_signing_key(data_dir)?;
        let agent_pk = node.ed_sk.verifying_key().to_bytes();

        let has_existing = node.caps.all()?.values().any(|entry| {
            !entry.revoked
                && entry.cap.agent == agent_pk
                && entry.cap.allows(name, Right::Write).is_ok()
        });

        if !has_existing {
            let now = unix_now_ms();
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

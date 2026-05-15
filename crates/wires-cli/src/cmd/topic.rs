use std::path::Path;

use rand_core::{OsRng, RngCore};
use snafu::ResultExt;
use wires_core::Capability;
use wires_core::cap::Right;
use wires_net::unix_now_ms;
use wires_node::{Node, NodeConfig, load_root_signing_key, upsert_topic_names};

use crate::error::{CoreSnafu, IoSnafu, NodeSnafu, Result, StoreSnafu, TomlParseSnafu};

pub async fn create(data_dir: &Path, name: &str) -> Result<()> {
    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let node = Node::open(cfg).context(NodeSnafu)?;

    let mut topic_id = [0u8; 32];
    OsRng.fill_bytes(&mut topic_id);
    let mut epoch_key = [0u8; 32];
    OsRng.fill_bytes(&mut epoch_key);
    node.install_epoch_key(topic_id, 0, epoch_key)
        .context(NodeSnafu)?;

    upsert_topic_names(data_dir, [(name.to_string(), topic_id)]).context(NodeSnafu)?;

    println!("Created topic '{name}' with id {}", hex::encode(topic_id));
    println!(
        "Epoch key (share with peers via `wires pair-approve`): {}",
        hex::encode(epoch_key)
    );

    // Auto-mint a self-cap when this data dir holds a root key and no existing
    // non-revoked cap covers (agent, topic, write).
    if data_dir.join("root.ed25519").exists() {
        let root_sk = load_root_signing_key(data_dir).context(IoSnafu)?;
        let agent_pk = node.ed_sk.verifying_key().to_bytes();

        let has_existing = node.caps.all().context(StoreSnafu)?.values().any(|entry| {
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
            cap.sign(&root_sk).context(CoreSnafu)?;
            node.caps.upsert_grant(&cap).context(StoreSnafu)?;
            println!("Minted self-cap: {}", hex::encode(cap.cap_id.0));
        }
    }

    Ok(())
}

//! Pair-grant installation logic. Verifies a decrypted PairGrant and writes
//! every artifact Bob needs to become a fully-onboarded household member.

use std::path::Path;

use snafu::{ResultExt, ensure};
use wires_net::pair::{PairGrant, TopicNameEntry};

use crate::config::{HostConfig, NodeConfig};
use crate::error::{
    AgentMismatchSnafu, ConfigWriteSnafu, NodeError, Result, TopicNamesWriteSnafu,
    UnknownTopicSnafu, UpsertCapSnafu, VerifyCapSnafu,
};
use crate::node::Node;

pub struct InstallOutcome {
    pub cap_id: [u8; 16],
}

pub fn install_grant(
    data_dir: &Path,
    node: &Node,
    self_agent_pubkey: &[u8; 32],
    grant: &PairGrant,
) -> Result<InstallOutcome> {
    // 1. Cap target sanity: signed cap must name us.
    ensure!(&grant.cap.agent == self_agent_pubkey, AgentMismatchSnafu);
    // 2. Cap must be signed by the claimed root.
    grant.cap.verify(&grant.root_pubkey).context(VerifyCapSnafu)?;
    // 3. Every topic_key references a topic that also has a name entry.
    for tk in &grant.topic_keys {
        ensure!(
            grant.topic_names.iter().any(|n| n.topic_id == tk.topic_id),
            UnknownTopicSnafu { topic_id_hex: hex::encode(tk.topic_id) }
        );
    }

    // 4. config.toml — root pubkey + optional host info.
    let cfg_path = data_dir.join("config.toml");
    let mut cfg: NodeConfig = if cfg_path.exists() {
        let s = std::fs::read_to_string(&cfg_path).context(ConfigWriteSnafu)?;
        toml::from_str(&s).map_err(|e| NodeError::ConfigWrite {
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
            location: snafu::location!(),
        })?
    } else {
        NodeConfig {
            data_dir: data_dir.to_path_buf(),
            root_pubkey_hex: String::new(),
            host: None,
        }
    };
    cfg.root_pubkey_hex = hex::encode(grant.root_pubkey);
    if let Some(host) = &grant.host {
        cfg.host = Some(HostConfig {
            peer_hints: host.peer_hints.clone(),
            discovery_url: host.service_discovery_url.clone(),
        });
    }
    let toml_str = toml::to_string_pretty(&cfg).map_err(|e| NodeError::ConfigWrite {
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
        location: snafu::location!(),
    })?;
    std::fs::write(&cfg_path, toml_str).context(ConfigWriteSnafu)?;

    // 5. topic_names.json — merge new entries.
    write_topic_names(data_dir, &grant.topic_names)?;

    // 6. Epoch keys.
    for tk in &grant.topic_keys {
        node.install_epoch_key(tk.topic_id, tk.epoch, tk.key)?;
    }

    // 7. The cap itself, last so the invariant "keys present ⟹ cap present"
    //    never inverts.
    node.caps.upsert_grant(&grant.cap).context(UpsertCapSnafu)?;

    Ok(InstallOutcome {
        cap_id: grant.cap.cap_id.0,
    })
}

fn write_topic_names(data_dir: &Path, entries: &[TopicNameEntry]) -> Result<()> {
    let p = data_dir.join("topic_names.json");
    let mut map: std::collections::HashMap<String, String> = if p.exists() {
        let s = std::fs::read_to_string(&p).context(TopicNamesWriteSnafu)?;
        serde_json::from_str(&s).map_err(|e| NodeError::TopicNamesWrite {
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
            location: snafu::location!(),
        })?
    } else {
        std::collections::HashMap::new()
    };
    for entry in entries {
        map.insert(entry.name.clone(), hex::encode(entry.topic_id));
    }
    let serialized = serde_json::to_string_pretty(&map).expect("HashMap serializes");
    std::fs::write(&p, serialized).context(TopicNamesWriteSnafu)?;
    Ok(())
}

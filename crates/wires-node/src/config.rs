use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Filesystem root for persistent state (~/.wires by default).
    pub data_dir: PathBuf,
    /// Hex of the root pubkey for this household; needed to derive
    /// firehose/__caps topic ids.
    pub root_pubkey_hex: String,
    /// Optional peer hint(s) to dial on startup (typically the hosted node).
    pub bootstrap_peers: Vec<String>,
}

impl NodeConfig {
    pub fn firehose_topic_id(&self) -> [u8; 32] {
        derived_topic_id("wires.firehose.v1", &self.root_pubkey_hex)
    }
    pub fn caps_topic_id(&self) -> [u8; 32] {
        derived_topic_id("wires.caps.v1", &self.root_pubkey_hex)
    }
}

fn derived_topic_id(domain: &str, root_pubkey_hex: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    if let Ok(bytes) = hex::decode(root_pubkey_hex) {
        hasher.update(&bytes);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cfg(hex_pk: &str) -> NodeConfig {
        NodeConfig {
            data_dir: PathBuf::from("/tmp/wires-test"),
            root_pubkey_hex: hex_pk.to_string(),
            bootstrap_peers: vec![],
        }
    }

    #[test]
    fn derived_ids_are_deterministic() {
        let c1 = cfg("deadbeef");
        let c2 = cfg("deadbeef");
        assert_eq!(c1.firehose_topic_id(), c2.firehose_topic_id());
        assert_eq!(c1.caps_topic_id(), c2.caps_topic_id());
    }

    #[test]
    fn firehose_and_caps_topic_ids_differ() {
        let c = cfg("deadbeef");
        assert_ne!(c.firehose_topic_id(), c.caps_topic_id());
    }

    #[test]
    fn different_root_yields_different_topic_ids() {
        let a = cfg("aa");
        let b = cfg("bb");
        assert_ne!(a.firehose_topic_id(), b.firehose_topic_id());
    }
}

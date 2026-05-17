use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use wires_net::PeerHint;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Filesystem root for persistent state (~/.wires by default).
    pub data_dir: PathBuf,
    /// Hex of the root pubkey for this household; needed to derive
    /// firehose/__caps topic ids.
    pub root_pubkey_hex: String,
    /// Optional host this agent has paired with. `None` for purely
    /// peer-to-peer operation (no persistent relay, no replay catch-up).
    #[serde(default)]
    pub host: Option<HostConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    /// Peer hints harvested from discovery or an invite token. Tried in order
    /// when bootstrapping gossip and when dialing the tenant/replay ALPNs.
    pub peer_hints: Vec<PeerHint>,
}

impl NodeConfig {
    pub fn firehose_topic_id(&self) -> [u8; 32] {
        derived_topic_id("wires.firehose.v1", &self.root_pubkey_hex)
    }
    pub fn caps_topic_id(&self) -> [u8; 32] {
        derived_topic_id("wires.caps.v1", &self.root_pubkey_hex)
    }
}

/// Read the household root signing key from `<data_dir>/root.ed25519`.
/// Returns an error if the file is missing or not exactly 32 bytes — callers
/// surface the message verbatim since each path that needs this also wants to
/// instruct the operator to run `wires init --new-root`.
pub fn load_root_signing_key(data_dir: &Path) -> std::io::Result<SigningKey> {
    let bytes = std::fs::read(data_dir.join("root.ed25519"))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "root.ed25519 must be 32 bytes",
        )
    })?;
    Ok(SigningKey::from_bytes(&arr))
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
            host: None,
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

    #[test]
    fn host_config_round_trips_through_toml() {
        let cfg = NodeConfig {
            data_dir: PathBuf::from("/tmp/wires-test"),
            root_pubkey_hex: "deadbeef".into(),
            host: Some(HostConfig {
                peer_hints: vec![wires_net::PeerHint {
                    node_id: "ab".repeat(32),
                    addrs: vec!["127.0.0.1:11204".into()],
                    relay: None,
                }],
            }),
        };
        let s = toml::to_string_pretty(&cfg).unwrap();
        let back: NodeConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.root_pubkey_hex, "deadbeef");
        let h = back.host.expect("host must round-trip");
        assert_eq!(h.peer_hints.len(), 1);
    }

    #[test]
    fn legacy_config_without_host_deserializes() {
        let s = r#"
            data_dir = "/tmp/wires-test"
            root_pubkey_hex = "deadbeef"
        "#;
        let cfg: NodeConfig = toml::from_str(s).unwrap();
        assert!(cfg.host.is_none());
    }
}

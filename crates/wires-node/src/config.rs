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
    /// `None` = "no retention, behave as today" (CLI agents, `wires-ha`).
    /// `Some(_)` = wires-mcp gateway path: open IngestIndex, run sweeps.
    /// Marked `#[serde(skip)]` because the gateway injects it in code,
    /// never via per-user config.toml.
    #[serde(skip)]
    pub retention: Option<RetentionPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    /// Peer hints harvested from discovery or an invite token. Tried in order
    /// when bootstrapping gossip and when dialing the tenant/replay ALPNs.
    pub peer_hints: Vec<PeerHint>,
}

/// Per-user retention policy. When `Some(_)`, the runtime opens an
/// `IngestIndex` for the user, hooks record+sweep into inbound and publish,
/// runs a startup reconciliation pass, and starts a periodic 60 s sweep.
///
/// Deliberately not `Serialize`/`Deserialize` — built in code by the
/// gateway and injected into `NodeConfig` at runtime. The matching
/// `NodeConfig.retention` field is `#[serde(skip)]`, so per-user
/// `config.toml` files never carry retention state on disk.
#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    /// TTL after which a stored message becomes eligible for eviction.
    /// Must be > 0.
    pub ttl: std::time::Duration,
    /// Byte budget across all of this user's topics. 0 = no budget cap
    /// (TTL alone enforces). When > 0, after each TTL sweep the runtime
    /// also calls `evict_oldest_until(max_bytes_per_user)` to enforce the
    /// budget.
    pub max_bytes_per_user: u64,
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
            retention: None,
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
            retention: None,
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

    #[test]
    fn node_config_with_retention_field_constructs() {
        let cfg = NodeConfig {
            data_dir: PathBuf::from("/tmp/wires-test"),
            root_pubkey_hex: "deadbeef".into(),
            host: None,
            retention: Some(crate::config::RetentionPolicy {
                ttl: std::time::Duration::from_secs(3600),
                max_bytes_per_user: 52_428_800,
            }),
        };
        let r = cfg.retention.expect("retention must be set");
        assert_eq!(r.ttl, std::time::Duration::from_secs(3600));
        assert_eq!(r.max_bytes_per_user, 52_428_800);
    }

    #[test]
    fn node_config_toml_round_trip_drops_retention_field() {
        // `retention` is `#[serde(skip)]` — it's built by gateway code, not
        // read from per-user config.toml. Round-tripping through TOML therefore
        // resets it to None regardless of what was set in memory.
        let cfg = NodeConfig {
            data_dir: PathBuf::from("/tmp/wires-test"),
            root_pubkey_hex: "deadbeef".into(),
            host: None,
            retention: Some(crate::config::RetentionPolicy {
                ttl: std::time::Duration::from_secs(3600),
                max_bytes_per_user: 1024,
            }),
        };
        let s = toml::to_string_pretty(&cfg).unwrap();
        let back: NodeConfig = toml::from_str(&s).unwrap();
        assert!(
            back.retention.is_none(),
            "retention must be skipped on serde"
        );
    }

    #[test]
    fn node_config_without_retention_deserializes_to_none() {
        let s = r#"
            data_dir = "/tmp/wires-test"
            root_pubkey_hex = "deadbeef"
        "#;
        let cfg: NodeConfig = toml::from_str(s).unwrap();
        assert!(cfg.retention.is_none());
        assert!(cfg.host.is_none());
    }
}

//! `NodeRuntime` — owns an iroh Endpoint, gossip + replay glue, and a Node.
//! Provides the high-level `join_topic` / `publish_and_broadcast` /
//! `replay_from_host` surface used by `wires-cli` and `wires-ha`.

use std::collections::HashMap;
use std::sync::Arc;

use iroh::{Endpoint, SecretKey, endpoint::presets};
use parking_lot::Mutex;
use snafu::ResultExt;
use wires_net::{GossipHandle, load_or_create_secret};

use crate::config::NodeConfig;
use crate::error::{IoSnafu, NetSnafu, Result};
use crate::net_glue::NetGlue;
use crate::node::Node;

pub struct NodeRuntime {
    pub node: Arc<Node>,
    pub endpoint: Endpoint,
    pub glue: NetGlue,
    /// One gossip handle per joined topic. Populated by `join_topic` and
    /// consulted by `publish_and_broadcast` in subsequent tasks.
    #[allow(dead_code)]
    handles: Mutex<HashMap<[u8; 32], GossipHandle>>,
}

impl NodeRuntime {
    /// Open the underlying `Node`, load (or create) the per-data-dir iroh
    /// secret at `iroh.secret`, bind an Endpoint, and wire NetGlue.
    pub async fn open(config: NodeConfig) -> Result<Self> {
        let node = Arc::new(Node::open(config.clone())?);
        let secret_path = config.data_dir.join("iroh.secret");
        let secret = load_or_create_secret(&secret_path).context(NetSnafu)?;
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(SecretKey::from_bytes(&secret))
            .alpns(vec![wires_net::ALPN.to_vec()])
            .bind()
            .await
            .map_err(|e| std::io::Error::other(format!("endpoint bind: {e}")))
            .context(IoSnafu)?;
        let glue = NetGlue::new(endpoint.clone(), Arc::clone(&node.logs))
            .await
            .map_err(|e| std::io::Error::other(format!("net glue: {e}")))
            .context(IoSnafu)?;
        Ok(Self {
            node,
            endpoint,
            glue,
            handles: Mutex::new(HashMap::new()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn open_binds_an_endpoint_and_loads_a_node() {
        let tmp = TempDir::new().unwrap();
        let cfg = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            root_pubkey_hex: hex::encode([7u8; 32]),
            host: None,
        };
        let rt = NodeRuntime::open(cfg).await.unwrap();
        assert!(rt.endpoint.id().as_bytes().iter().any(|b| *b != 0));
        assert_eq!(rt.node.config.root_pubkey_hex.len(), 64);
    }
}

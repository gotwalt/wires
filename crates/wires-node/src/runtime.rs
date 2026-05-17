//! `NodeRuntime` — owns an iroh Endpoint, gossip + replay glue, and a Node.
//! Provides the high-level `join_topic` / `publish_and_broadcast` /
//! `replay_from_host` surface used by `wires-cli` and `wires-ha`.

use std::collections::HashMap;
use std::sync::Arc;

use iroh::{Endpoint, SecretKey};
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
    /// One gossip handle per joined topic, populated by `join_topic` and
    /// consumed by `publish_and_broadcast`.
    handles: Mutex<HashMap<[u8; 32], GossipHandle>>,
}

impl NodeRuntime {
    /// Open the underlying `Node`, load (or create) the per-data-dir iroh
    /// secret at `iroh.secret`, bind an Endpoint, and wire NetGlue.
    pub async fn open(config: NodeConfig) -> Result<Self> {
        let node = Arc::new(Node::open(config.clone())?);
        let secret_path = config.data_dir.join("iroh.secret");
        let secret = load_or_create_secret(&secret_path).context(NetSnafu)?;
        let endpoint = wires_net::bind_lan(
            SecretKey::from_bytes(&secret),
            vec![wires_net::ALPN.to_vec()],
        )
        .await
        .context(NetSnafu)?;
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

    /// Join `topic_id` on gossip (with optional `bootstrap` peer hints), and
    /// route inbound envelopes to `node.handle_inbound`. Idempotent: a second
    /// call returns the cached handle.
    pub async fn join_topic(
        &self,
        topic_id: [u8; 32],
        bootstrap: Vec<iroh::EndpointId>,
    ) -> Result<GossipHandle> {
        if let Some(h) = self.handles.lock().get(&topic_id) {
            return Ok(h.clone());
        }
        let handle = self
            .glue
            .subscribe_and_route(Arc::clone(&self.node), topic_id, bootstrap)
            .await?;
        self.handles.lock().insert(topic_id, handle.clone());
        Ok(handle)
    }

    /// Whether `topic_id` has been joined (debug/test helper).
    pub fn has_joined(&self, topic_id: &[u8; 32]) -> bool {
        self.handles.lock().contains_key(topic_id)
    }

    /// Publish a `Standard`-mode message and broadcast the resulting envelope
    /// to every joined peer on this topic. The topic must already have been
    /// joined via `join_topic`.
    pub async fn publish_and_broadcast(
        &self,
        topic_id: [u8; 32],
        cap_id: [u8; 16],
        content: wires_core::CanonicalContent,
    ) -> Result<wires_core::WireMessage> {
        let handle = self.handles.lock().get(&topic_id).cloned().ok_or_else(|| {
            crate::error::NodeError::Config {
                message: format!(
                    "publish_and_broadcast called on un-joined topic {}",
                    hex::encode(topic_id)
                ),
                location: snafu::location!(),
            }
        })?;
        let msg = self.node.publish_standard(topic_id, cap_id, content)?;
        let bytes = serde_json::to_vec(&msg).context(crate::error::SerdeSnafu)?;
        handle.broadcast(bytes).await.context(NetSnafu)?;
        Ok(msg)
    }

    /// Pull missing history for `topic_id` from the configured host via the
    /// replay ALPN, and feed each delivered envelope to `node.handle_inbound`.
    /// Errors with a configuration error if no host is set or if no usable
    /// peer hint is reachable.
    pub async fn replay_from_host(&self, topic_id: [u8; 32]) -> Result<usize> {
        let host =
            self.node
                .config
                .host
                .as_ref()
                .ok_or_else(|| crate::error::NodeError::Config {
                    message: "replay_from_host: no host configured".into(),
                    location: snafu::location!(),
                })?;
        let peer = wires_net::first_reachable_with_discovery(
            &self.endpoint,
            &host.peer_hints,
            None,
            wires_net::ALPN,
            std::time::Duration::from_secs(5),
        )
        .await
        .ok_or_else(|| crate::error::NodeError::Config {
            message: "replay_from_host: no reachable peer hint".into(),
            location: snafu::location!(),
        })?;
        self.glue
            .replay_from(Arc::clone(&self.node), topic_id, peer)
            .await
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

    #[tokio::test]
    async fn replay_from_host_errors_when_no_host_configured() {
        let tmp = TempDir::new().unwrap();
        let cfg = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            root_pubkey_hex: hex::encode([7u8; 32]),
            host: None,
        };
        let rt = NodeRuntime::open(cfg).await.unwrap();
        let topic = [9u8; 32];
        let err = rt.replay_from_host(topic).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no host configured"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn join_topic_registers_a_gossip_handle() {
        let tmp = TempDir::new().unwrap();
        let cfg = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            root_pubkey_hex: hex::encode([7u8; 32]),
            host: None,
        };
        let rt = NodeRuntime::open(cfg).await.unwrap();
        let topic = [1u8; 32];
        assert!(rt.join_topic(topic, vec![]).await.is_ok());
        // Second join is idempotent (returns the cached handle).
        assert!(rt.join_topic(topic, vec![]).await.is_ok());
        assert!(rt.has_joined(&topic));
    }
}

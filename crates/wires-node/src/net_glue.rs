//! Plug the iroh-based GossipNode and ReplayClient/Server into the local Node.

use std::sync::Arc;

use iroh::{Endpoint, EndpointId};
use snafu::ResultExt;
use wires_core::WireMessage;
use wires_net::replay::{ALPN, ReplayClient, ReplayProtocol, ReplayRequest};
use wires_net::{GossipHandle, GossipNode};

use crate::error::{NetSnafu, Result};
use crate::inbound::InboundCtx;
use crate::node::Node;
use crate::storage::TopicLogs;
use crate::sync::current_hwm_for_request;

pub struct NetGlue {
    pub gossip: GossipNode,
    pub replay_client: ReplayClient,
    pub endpoint: Endpoint,
    /// The iroh `Router` keeps inbound ALPN dispatch alive. Holding it here
    /// ensures the replay server stays up for the lifetime of the glue.
    _router: iroh::protocol::Router,
}

impl NetGlue {
    /// Construct over an existing iroh Endpoint and a TopicLogs to serve replay from.
    pub async fn new(endpoint: Endpoint, logs: Arc<TopicLogs>) -> Result<Self> {
        let gossip = GossipNode::new(endpoint.clone()).await.context(NetSnafu)?;
        let replay_protocol = ReplayProtocol::new(logs);
        let router = iroh::protocol::Router::builder(endpoint.clone())
            .accept(ALPN, replay_protocol)
            .spawn();
        let replay_client = ReplayClient::new(endpoint.clone());
        Ok(Self {
            gossip,
            replay_client,
            endpoint,
            _router: router,
        })
    }

    /// Subscribe to `topic_id` and route every received `WireMessage` to
    /// `node.handle_inbound`. Spawns a background task. Returns a
    /// [`GossipHandle`] so the caller can broadcast its own messages on the
    /// same topic.
    pub async fn subscribe_and_route(
        &self,
        node: Arc<Node>,
        topic_id: [u8; 32],
        bootstrap: Vec<EndpointId>,
    ) -> Result<GossipHandle> {
        let (handle, mut rx) = self
            .gossip
            .join(topic_id, bootstrap)
            .await
            .context(NetSnafu)?;
        let n = Arc::clone(&node);
        tokio::spawn(async move {
            while let Some(bytes) = rx.recv().await {
                let msg: WireMessage = match serde_json::from_slice(&bytes) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::warn!(error = %e, "bad gossip frame");
                        continue;
                    }
                };
                if let Err(e) = n.handle_inbound(msg) {
                    tracing::warn!(error = %e, "handle_inbound failed");
                }
            }
        });
        Ok(handle)
    }

    /// Pull missing history for `topic_id` from `peer` via the replay protocol.
    /// Each delivered message is fed to `node.handle_inbound`.
    pub async fn replay_from(
        &self,
        node: Arc<Node>,
        topic_id: [u8; 32],
        peer: EndpointId,
    ) -> Result<usize> {
        let log = node.logs.get_or_open(&topic_id)?;
        let keys = node.epoch_keys_for(&topic_id)?;
        let ctx = InboundCtx {
            topic_log: &log,
            epoch_keys: &keys,
            cap_table: &node.caps,
            self_x25519_sk: &node.x_sk,
            self_x25519_pk: &node.x_pk,
        };
        let hwm = current_hwm_for_request(&ctx)?;
        let req = ReplayRequest {
            topic_id,
            hwm,
            limit: 1024,
        };
        let mut rx = self
            .replay_client
            .request(peer, &req)
            .await
            .context(NetSnafu)?;
        let mut count = 0usize;
        while let Some(msg) = rx.recv().await {
            if let Err(e) = node.handle_inbound(msg) {
                tracing::warn!(error = %e, "handle_inbound from replay failed");
            } else {
                count += 1;
            }
        }
        Ok(count)
    }
}

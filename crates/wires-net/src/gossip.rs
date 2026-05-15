//! Thin wrapper around [`iroh_gossip`] providing subscribe/publish semantics.
//!
//! # Design
//!
//! [`GossipNode`] owns an [`iroh::Endpoint`] and the [`iroh_gossip::net::Gossip`] actor
//! spawned on top of it.  It also creates an [`iroh::protocol::Router`] that wires gossip
//! connections to the ALPN-based accept loop, so inbound gossip connections are handled
//! automatically.
//!
//! For each topic you call [`GossipNode::join`], which returns:
//! - A [`GossipHandle`] (wraps the iroh-gossip [`GossipSender`]) for publishing.
//! - A [`tokio::sync::mpsc::Receiver<Vec<u8>>`] that yields raw payloads from inbound
//!   [`Event::Received`] messages.  Neighbour up/down events and `Lagged` events are
//!   silently discarded (the caller only sees byte payloads).
//!
//! Publishing is done via [`GossipNode::publish`] or directly on the [`GossipHandle`].

use std::sync::Arc;

use bytes::Bytes;
use iroh::{Endpoint, EndpointId};
use iroh_gossip::{
    api::{Event, GossipSender},
    proto::TopicId,
};

// Re-export the iroh-gossip protocol handler and ALPN under wires-net's public
// surface so callers can wire the gossip protocol into their own combined
// `iroh::protocol::Router`.
pub use iroh_gossip::net::{GOSSIP_ALPN, Gossip};
use n0_future::StreamExt as _;
use snafu::ResultExt as _;
use tokio::sync::mpsc;

use crate::error::{GossipPublishSnafu, GossipSubscribeSnafu, NetError};

/// Capacity of the inbound message channel created per topic join.
const INBOUND_CHANNEL_CAP: usize = 256;

/// Handle for publishing messages into a joined gossip topic.
///
/// Obtained from [`GossipNode::join`].  Cheap to clone; all clones share the
/// same underlying sender.
#[derive(Debug, Clone)]
pub struct GossipHandle {
    sender: GossipSender,
}

impl GossipHandle {
    /// Broadcast `payload` to all peers on this topic.
    pub async fn broadcast(&self, payload: Vec<u8>) -> Result<(), NetError> {
        self.sender
            .broadcast(Bytes::from(payload))
            .await
            .map_err(anyhow::Error::from)
            .context(GossipPublishSnafu)?;
        Ok(())
    }
}

/// Wraps an [`iroh::Endpoint`], a [`Gossip`] actor, and (optionally) a protocol
/// [`Router`].
///
/// Create with [`GossipNode::new`] for the standalone case (the gossip ALPN is
/// served by a dedicated [`Router`] spawned internally), or with
/// [`GossipNode::new_without_router`] when the caller wants to register the
/// gossip protocol on its own combined router alongside other ALPNs. The
/// returned [`Gossip`] handler can be passed to `Router::builder(..).accept(..)`
/// by the caller in that case.
///
/// The router (if owned) is shut down when this value is dropped (via the
/// `AbortOnDrop` internal to iroh).
///
/// [`Router`]: iroh::protocol::Router
pub struct GossipNode {
    endpoint: Endpoint,
    gossip: Gossip,
    _router: Option<Arc<iroh::protocol::Router>>,
}

impl GossipNode {
    /// Wrap an already-bound [`Endpoint`], spawn a [`Gossip`] actor on top of it,
    /// and register the gossip ALPN with an iroh protocol router so that inbound
    /// connections are accepted.
    pub async fn new(endpoint: Endpoint) -> Result<Self, NetError> {
        let gossip = Gossip::builder().spawn(endpoint.clone());

        let router = iroh::protocol::Router::builder(endpoint.clone())
            .accept(GOSSIP_ALPN, gossip.clone())
            .spawn();

        // Eagerly check that the router actually started (Router::spawn is infallible
        // in iroh 0.98 but this makes the error surface explicit if that changes).
        let _ = router.endpoint();

        Ok(Self {
            endpoint,
            gossip,
            _router: Some(Arc::new(router)),
        })
    }

    /// Like [`GossipNode::new`], but does NOT spawn an internal protocol
    /// router. The returned [`Gossip`] handler must be registered with the
    /// caller's own [`iroh::protocol::Router`] on [`GOSSIP_ALPN`] (re-exported
    /// from `iroh_gossip::net`) so inbound gossip QUIC streams are dispatched
    /// correctly. Use this when the same endpoint must accept additional
    /// non-gossip ALPNs from a single router (e.g. wires-node multiplexes
    /// gossip and the replay protocol).
    pub async fn new_without_router(endpoint: Endpoint) -> Result<(Self, Gossip), NetError> {
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let node = Self {
            endpoint,
            gossip: gossip.clone(),
            _router: None,
        };
        Ok((node, gossip))
    }

    /// Access the underlying iroh endpoint (e.g. to obtain our [`EndpointId`]).
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Returns a handle that can be used to call `join` from another task. The
    /// underlying `iroh_gossip::Gossip` and endpoint are internally Arc-based, so this is a cheap
    /// clone. The router is held in an Arc to make this clonable.
    pub fn clone_for_subscribe(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            gossip: self.gossip.clone(),
            _router: self._router.as_ref().map(Arc::clone),
        }
    }

    /// Join a gossip topic.
    ///
    /// `topic_id` — 32-byte raw topic identifier.
    /// `bootstrap` — list of known peer [`EndpointId`]s to seed the membership.  May be
    ///   empty when opening a new topic (you will receive messages once peers join *you*).
    ///
    /// Returns:
    /// - A [`GossipHandle`] for broadcasting payloads.
    /// - An `mpsc::Receiver<Vec<u8>>` that yields raw inbound message payloads.
    ///   The receiver is fed by a background task that is cancelled when the
    ///   receiver is dropped (sender half will close, ending the background task).
    pub async fn join(
        &self,
        topic_id: [u8; 32],
        bootstrap: Vec<EndpointId>,
    ) -> Result<(GossipHandle, mpsc::Receiver<Vec<u8>>), NetError> {
        let iroh_topic = TopicId::from_bytes(topic_id);

        // subscribe returns immediately; joined() waits for the first peer
        // connection.  We use subscribe() (not subscribe_and_join) so we don't
        // block when bootstrap is empty — callers can wait on the first message.
        let topic = self
            .gossip
            .subscribe(iroh_topic, bootstrap)
            .await
            .map_err(anyhow::Error::from)
            .context(GossipSubscribeSnafu)?;

        let (sender, mut receiver) = topic.split();
        let handle = GossipHandle { sender };

        // Bridge iroh Stream<Event> → mpsc channel of raw payloads.
        let (tx, rx) = mpsc::channel::<Vec<u8>>(INBOUND_CHANNEL_CAP);
        tokio::spawn(async move {
            while let Some(result) = receiver.next().await {
                match result {
                    Ok(Event::Received(msg)) => {
                        // If the receiver was dropped, stop the task.
                        if tx.send(msg.content.to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {
                        // NeighborUp / NeighborDown / Lagged — not forwarded.
                    }
                    Err(_) => {
                        // Topic closed or lagged past channel capacity.
                        break;
                    }
                }
            }
        });

        Ok((handle, rx))
    }

    /// Broadcast `payload` into the topic identified by `handle`.
    ///
    /// Convenience wrapper around [`GossipHandle::broadcast`].
    pub async fn publish(&self, handle: &GossipHandle, payload: Vec<u8>) -> Result<(), NetError> {
        handle.broadcast(payload).await
    }
}

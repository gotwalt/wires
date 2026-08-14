//! The resident topic node: one endpoint, one router, one gossip mesh, and the
//! event stream `wires tail` prints from (spec §7.4).
//!
//! [`TopicNode::spawn`] binds the iroh endpoint and stands up everything the
//! multiway path needs on top of it; [`TopicNode::join`] subscribes to the
//! gossip topic and hands back a [`TopicSender`] plus a channel of
//! [`TopicEvent`]s. Everything above this module — the tail loop, the control
//! socket, the printer — talks to those two handles and never to iroh-gossip
//! directly.
//!
//! # One router, three ALPNs
//!
//! The single most expensive mistake available here is building a second
//! [`Router`] over the same endpoint. A router *replaces* the endpoint's ALPN
//! set when it spawns, so a second one silently unregisters the first one's
//! protocols and the symptom is not an error — it is a peer that connects, gets
//! `no matching ALPN`, and retries forever. So this module registers all three
//! protocols on **one** router:
//!
//! | ALPN | handler | why it is here |
//! |------|---------|----------------|
//! | [`GOSSIP_ALPN`](iroh_gossip::net::GOSSIP_ALPN) | [`GatedGossip`] | the mesh, behind the roster gate |
//! | [`TOPIC_ADMIT_ALPN`](library::TOPIC_ADMIT_ALPN) | [`AdmitHandler`] | the handshake that fills the gate |
//! | [`TOPIC_REPLAY_ALPN`](library::TOPIC_REPLAY_ALPN) | [`ReplayHandler`](crate::replay::ReplayHandler) | peer-symmetric catch-up |
//!
//! Gossip is registered **wrapped**, never bare: a raw `Gossip` on the router is
//! an open mesh that anyone who guesses the topic id can join, which is the
//! whole thing admission exists to prevent.
//!
//! # The event bridge
//!
//! iroh-gossip hands out a `GossipReceiver`; this module pumps it into an
//! [`mpsc`] channel of [`TopicEvent`] so the tail loop can `select!` over it
//! alongside the control socket and the redial timer. The channel is bounded at
//! [`EVENT_CHANNEL_CAP`] (256) — unbounded would turn a wedged printer into
//! unbounded memory — and the bridge **logs every drop** rather than discarding
//! silently: a message that never reached stdout must leave a trace, because
//! replay heals a gap in the *store* and a drop here is a gap in the *display*.
//!
//! [`TopicEvent::Lagged`] gets the same treatment for the same reason. When a
//! subscriber falls behind, iroh-gossip emits `Lagged` and closes the
//! subscription; the PoC trap was to treat that as a stream end and exit the
//! loop with no output at all, leaving a tail that looked alive and printed
//! nothing forever. Here the bridge forwards `Lagged` first, so the tail loop
//! can schedule a [`catch_up`](crate::replay::catch_up) and re-subscribe, and
//! logs at `warn` on the way out. Nothing about falling behind is silent.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use iroh::Endpoint;
use iroh::protocol::Router;
use iroh_gossip::api::{GossipReceiver, GossipSender};
use library::{
    InclusionProof, NodeId, NodeIdentity, TopicEnvelope, TopicId, TopicPeer, TopicTicket,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::admission::{ADMIT_RECHECK, AdmitHandler, Admitted, GatedGossip};
use crate::keystore::Keystore;
use crate::replay::{REPLAY_DEBOUNCE, REPLAY_LIMIT};
use crate::store::TopicStore;
use crate::transport::HeadSource;

/// How many [`TopicEvent`]s the bridge will buffer for the tail loop (spec
/// §7.4).
///
/// Bounded on purpose. The producer is the network and the consumer is a
/// terminal — the one arrangement where an unbounded channel converts a slow
/// reader into an out-of-memory kill. At 256 the buffer absorbs a replay burst
/// without dropping anything, and past it the bridge drops the *newest* event
/// and says so in the log, which is recoverable: the message is in the store,
/// and the next `catch_up` re-offers it.
pub const EVENT_CHANNEL_CAP: usize = 256;

/// Everything a [`TopicNode`] needs besides its signing identity.
///
/// The identity is *not* a field: it is the one secret in the set, and passing
/// it to [`TopicNode::spawn`] separately keeps it out of a struct that is
/// otherwise cheap to log, clone into a test fixture, and hold in a `Debug`
/// print (spec §7.4 spells the constructor as `spawn(identity, cfg)` for the
/// same reason).
///
/// Every interval in here is a field rather than a constant read at the point
/// of use, so the hermetic loopback tests run the whole node in milliseconds:
/// [`new`](Self::new) fills them with the production defaults and a test
/// overwrites the two it cares about.
pub struct TopicNodeConfig {
    /// The topic this node gates, stores, and subscribes to. One resident node
    /// serves exactly one topic — the store and the admission handler are both
    /// topic-scoped, and the control socket is named after it.
    pub topic: TopicId,
    /// The fabric root whose signatures on roster heads, inclusion proofs, and
    /// sealed keys are honored.
    pub fabric_root: NodeId,
    /// Where the roster head is read from, re-loaded per admission and per
    /// watchdog pass. Pair this with the keystore below — passive head
    /// distribution only works when the file written is the file read.
    pub head: Arc<HeadSource>,
    /// This node's own inclusion proof, presented in every admission.
    pub proof: InclusionProof,
    /// The keystore an adopted head is persisted to, and the keyring the tail
    /// loop opens envelopes with.
    pub keystore: Arc<Keystore>,
    /// The topic log. Owned by this process for as long as the node runs — redb
    /// locks it exclusively, which is what makes the resident tail the single
    /// seq allocator (spec §7).
    pub store: Arc<TopicStore>,
    /// A self-hosted relay to use instead of the n0 default, if any.
    pub relay_url: Option<String>,
    /// How often the admission watchdog re-checks stored admissions against the
    /// current head — the revocation-latency number (default
    /// [`ADMIT_RECHECK`]).
    pub admit_recheck: Duration,
    /// How long a live chain gap waits before triggering a catch-up pass
    /// (default [`REPLAY_DEBOUNCE`]).
    pub replay_debounce: Duration,
    /// Maximum items this node will stream in one replay pass (default
    /// [`REPLAY_LIMIT`]).
    pub replay_limit: u32,
    /// Capacity of the [`TopicEvent`] channel (default [`EVENT_CHANNEL_CAP`]).
    pub channel_cap: usize,
}

impl TopicNodeConfig {
    /// A config for `topic` under `fabric_root`, with the production defaults
    /// for every interval and bound. Override the fields a test needs to move.
    pub fn new(
        topic: TopicId,
        fabric_root: NodeId,
        head: Arc<HeadSource>,
        proof: InclusionProof,
        keystore: Arc<Keystore>,
        store: Arc<TopicStore>,
    ) -> Self {
        Self {
            topic,
            fabric_root,
            head,
            proof,
            keystore,
            store,
            relay_url: None,
            admit_recheck: ADMIT_RECHECK,
            replay_debounce: REPLAY_DEBOUNCE,
            replay_limit: REPLAY_LIMIT,
            channel_cap: EVENT_CHANNEL_CAP,
        }
    }
}

impl std::fmt::Debug for TopicNodeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TopicNodeConfig")
            .field("topic", &self.topic.hex())
            .field("fabric_root", &self.fabric_root.hex())
            .field("head", &self.head)
            .field("relay_url", &self.relay_url)
            .field("admit_recheck", &self.admit_recheck)
            .field("replay_debounce", &self.replay_debounce)
            .field("replay_limit", &self.replay_limit)
            .field("channel_cap", &self.channel_cap)
            .finish_non_exhaustive()
    }
}

/// One event from the topic, as the tail loop sees it.
///
/// A translation of iroh-gossip's `Event` into wires' own vocabulary: the
/// payload is a decoded [`TopicEnvelope`] rather than raw bytes (an
/// undecodable message is logged and dropped by the bridge, never surfaced),
/// and peers are [`NodeId`]s rather than iroh `EndpointId`s.
#[derive(Clone, Debug)]
pub enum TopicEvent {
    /// A message arrived on the mesh. Not yet verified, chain-checked, or
    /// decrypted — that is ingest's job (spec §6), and it is deliberately not
    /// done on the bridge task.
    Message(TopicEnvelope),
    /// A direct neighbor joined the mesh. The tail loop records it as a peer
    /// hint and, on the first one, stops waiting.
    NeighborUp(NodeId),
    /// A direct neighbor went away. Dropping to zero neighbors starts the
    /// redial backoff (spec §7).
    NeighborDown(NodeId),
    /// The subscription fell behind and messages were dropped by iroh-gossip.
    ///
    /// Terminal for the underlying subscription — iroh-gossip closes it — so
    /// the tail loop's response is a [`catch_up`](crate::replay::catch_up) and
    /// a fresh [`TopicNode::join`], never a quiet exit. See the module docs.
    Lagged,
}

/// The broadcast half of a joined topic.
///
/// Cheap to clone, so the control socket's publish path and the tail loop can
/// both hold one. Carries the topic it was joined on purely so a broadcast can
/// refuse an envelope addressed elsewhere rather than putting it on the wrong
/// mesh.
#[derive(Clone, Debug)]
pub struct TopicSender {
    /// The gossip sender for the subscribed topic.
    inner: GossipSender,
    /// The topic this sender is bound to.
    topic: TopicId,
}

impl TopicSender {
    /// Wrap a gossip sender for `topic`.
    pub(crate) fn new(inner: GossipSender, topic: TopicId) -> Self {
        Self { inner, topic }
    }

    /// The topic this sender broadcasts on.
    pub fn topic(&self) -> TopicId {
        self.topic
    }

    /// Broadcast one envelope to the mesh as canonical JSON
    /// ([`TopicEnvelope::to_wire`] — a binary channel, so no base64).
    ///
    /// Refuses an envelope whose `topic` is not [`topic`](Self::topic): sending
    /// it would publish one topic's ciphertext to another topic's subscribers,
    /// who cannot open it and would file it as an unreadable message from a
    /// member in good standing.
    ///
    /// Broadcasting is not storing. The caller appends to the log first, and
    /// only an [`Appended::Inserted`](crate::store::Appended) goes on the wire.
    pub async fn broadcast(&self, envelope: &TopicEnvelope) -> Result<()> {
        todo!("check envelope.topic == self.topic, encode to_wire, gossip broadcast")
    }

    /// Ask gossip to connect to `peers` — the redial path after the neighbor
    /// count hits zero, and how a ticket's hints reach the mesh after the
    /// initial join.
    pub async fn join_peers(&self, peers: &[NodeId]) -> Result<()> {
        todo!("map NodeId -> EndpointId and call GossipSender::join_peers")
    }
}

/// The resident node behind `wires tail`: endpoint, router, gated mesh,
/// admission gate, replay server, and topic log, all for one topic.
///
/// Owns the iroh endpoint and the [`Router`] registering all three ALPNs (see
/// the module docs), the [`Admitted`] registry those handlers share, the
/// admission watchdog task, and the bridge tasks feeding joined subscriptions.
/// Dropping it aborts the tasks; [`shutdown`](Self::shutdown) closes the mesh
/// and the endpoint politely first.
#[derive(Debug)]
pub struct TopicNode {
    /// The bound iroh endpoint. Also the source of this node's own address
    /// hints for [`ticket`](Self::ticket).
    endpoint: Endpoint,
    /// The one router. See the module docs on why there is exactly one.
    router: Router,
    /// The gossip handle, wrapped in its roster gate. Subscriptions go through
    /// [`GatedGossip::gossip`]; the wrapper itself is what the router holds.
    gossip: GatedGossip,
    /// The shared allowlist consulted by the gossip gate and the replay server
    /// and maintained by the admission handshake and the watchdog.
    admitted: Admitted,
    /// The admission handler — the router's [`TOPIC_ADMIT_ALPN`](library::TOPIC_ADMIT_ALPN)
    /// protocol *and* the client-side context every outbound
    /// [`admit_peer`](crate::admission::admit_peer) needs.
    admit: Arc<AdmitHandler>,
    /// The topic log, shared with the replay handler and the tail loop.
    store: Arc<TopicStore>,
    /// The topic this node serves.
    topic: TopicId,
    /// The fabric root, kept so [`ticket`](Self::ticket) can name the fabric
    /// without re-reading the membership.
    fabric_root: NodeId,
    /// The relay this node advertises in its own ticket, if any.
    relay_url: Option<String>,
    /// Capacity for the channels [`join`](Self::join) creates.
    channel_cap: usize,
    /// The admission watchdog, aborted on shutdown.
    watchdog: JoinHandle<()>,
    /// One bridge task per live [`join`](Self::join), aborted on shutdown. A
    /// plain mutex: pushing a handle is not an awaiting operation.
    bridges: Mutex<Vec<JoinHandle<()>>>,
}

impl TopicNode {
    /// Bind the endpoint and stand the node up: gossip, the admission gate and
    /// its watchdog, the replay server, and the single router carrying all
    /// three ALPNs.
    ///
    /// Does **not** join the topic or dial anyone — [`join`](Self::join) and
    /// [`admit_peer`](crate::admission::admit_peer) are separate steps, so a
    /// caller can admit its bootstrap peers (and learn it has been revoked,
    /// exit 77) before it ever subscribes.
    ///
    /// The identity is the endpoint's secret key, so this node's iroh
    /// `EndpointId` *is* its [`NodeId`] — which is what lets every handler take
    /// the authenticated `remote_id` as caller identity instead of trusting a
    /// wire field.
    pub async fn spawn(identity: &NodeIdentity, cfg: TopicNodeConfig) -> Result<Self> {
        todo!(
            "bind the endpoint; Gossip::builder().spawn(endpoint); wrap in GatedGossip; \
             build the AdmitHandler and ReplayHandler over one Admitted; register all \
             three ALPNs on ONE Router; spawn the watchdog"
        )
    }

    /// The topic this node serves.
    pub fn topic(&self) -> TopicId {
        self.topic
    }

    /// This node's own id (the endpoint's authenticated key).
    pub fn node_id(&self) -> NodeId {
        crate::transport::to_node_id(&self.endpoint.id())
    }

    /// The bound endpoint, for dialing admission and replay.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The admission handler, which doubles as the client-side context for
    /// [`admit_peer`](crate::admission::admit_peer).
    pub fn admit(&self) -> &Arc<AdmitHandler> {
        &self.admit
    }

    /// The shared allowlist — also the dial set for replay catch-up
    /// ([`Admitted::peers`]).
    pub fn admitted(&self) -> &Admitted {
        &self.admitted
    }

    /// The topic log.
    pub fn store(&self) -> &Arc<TopicStore> {
        &self.store
    }

    /// Subscribe to `topic` and start bridging its events.
    ///
    /// `topic` must be the topic this node was spawned for; a mismatch is an
    /// error rather than a second subscription, because the admission gate, the
    /// replay server, and the store are all bound to the spawned topic and a
    /// second topic would ride through them ungated and unstored.
    ///
    /// `bootstrap` is the peer hints to seed the mesh with — from tickets and
    /// from `topics/<hex>.peers.json`. They are hints only: gossip authenticates
    /// each peer, and the [`GatedGossip`] wrapper still refuses anyone who has
    /// not completed admission, so bootstrapping off a stale or hostile ticket
    /// cannot put a non-member in the mesh.
    ///
    /// Returns immediately, before any neighbor is up: waiting for the first
    /// [`TopicEvent::NeighborUp`] (with a timeout — never a blind sleep) is the
    /// caller's decision, because `wires publish` needs it and `wires tail`
    /// does not.
    pub async fn join(
        &self,
        topic: TopicId,
        bootstrap: &[TopicPeer],
    ) -> Result<(TopicSender, mpsc::Receiver<TopicEvent>)> {
        todo!(
            "reject a foreign topic; add peer addrs to the endpoint's address book; \
             subscribe_with_opts; split; spawn bridge_events; return (TopicSender, rx)"
        )
    }

    /// This node's own [`TopicTicket`] for `name`: the fabric, the name, and
    /// this node as a peer hint with its direct sockets and relay.
    ///
    /// What `wires tail` prints in its startup banner (`share to bootstrap:
    /// <token>`). Unsigned, and safe to be: it carries no authority, and a
    /// tampered copy can only fail to connect.
    ///
    /// `name` — not the [`TopicId`] — because the ticket is what lets a peer
    /// *derive* the id for itself and check it against its own fabric.
    pub fn ticket(&self, name: &str) -> Result<TopicTicket> {
        todo!("build a TopicTicket naming the fabric and name, with self as the only peer hint")
    }

    /// Leave the mesh and close the endpoint.
    ///
    /// Aborts the watchdog and the bridge tasks, shuts the router down (which
    /// shuts gossip down, sending `Disconnect` to neighbors instead of leaving
    /// them to time out), and closes the endpoint. The topic log is released
    /// with the [`TopicStore`], so the next `wires tail` can open it.
    pub async fn shutdown(self) -> Result<()> {
        todo!("abort watchdog + bridges, router.shutdown(), endpoint.close()")
    }
}

/// Pump one gossip subscription into `tx` as [`TopicEvent`]s.
///
/// The whole translation layer: `Received` bytes are decoded into a
/// [`TopicEnvelope`] (an undecodable one is logged at `warn` and dropped — it
/// cannot be verified, chained, or opened, so there is nothing downstream can
/// do with it), neighbor events are mapped to [`NodeId`], and `Lagged` is
/// forwarded before the task ends.
///
/// Never drops silently: a full channel logs, and a closed channel — the tail
/// loop has gone — ends the task at `debug`. See the module docs for why both
/// of those matter more here than the code volume suggests.
async fn bridge_events(recv: GossipReceiver, topic: TopicId, tx: mpsc::Sender<TopicEvent>) {
    todo!("map gossip events to TopicEvent, log every drop, forward Lagged before exiting")
}

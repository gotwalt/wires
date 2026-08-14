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

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures_core::Stream;
use iroh::Endpoint;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::protocol::Router;
use iroh_gossip::api::{Event as GossipEvent, GossipReceiver, GossipSender, JoinOptions};
use iroh_gossip::net::{GOSSIP_ALPN, Gossip};
use library::{
    InclusionProof, NodeId, NodeIdentity, TopicEnvelope, TopicId, TopicPeer, TopicTicket,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::admission::{
    ADMIT_RECHECK, AdmitHandler, Admitted, GatedGossip, admit_peer, spawn_watchdog,
};
use crate::keystore::Keystore;
use crate::replay::{REPLAY_DEBOUNCE, REPLAY_LIMIT, ReplayHandler};
use crate::store::TopicStore;
use crate::transport::{Denied, HeadSource, endpoint_id, secret_key, to_node_id};

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
        if envelope.topic != self.topic {
            bail!(
                "envelope is addressed to topic {} but this sender broadcasts on {}",
                envelope.topic.hex(),
                self.topic.hex()
            );
        }
        let wire = envelope
            .to_wire()
            .context("encoding the envelope for broadcast")?;
        self.broadcast_bytes(wire).await
    }

    /// Put raw bytes on the mesh.
    ///
    /// The one place [`broadcast`](Self::broadcast) actually reaches gossip, and
    /// the only way to put something on the wire that is *not* a well-formed
    /// [`TopicEnvelope`] — which is exactly what
    /// `bridge_survives_malformed_payload` needs, and why it is
    /// `pub(crate)` rather than public: nothing outside this crate should be
    /// able to broadcast bytes no receiver can parse.
    pub(crate) async fn broadcast_bytes(&self, bytes: Vec<u8>) -> Result<()> {
        self.inner
            .broadcast(bytes.into())
            .await
            .map_err(|e| anyhow!("broadcasting on topic {}: {e}", self.topic.hex()))
    }

    /// Ask gossip to connect to `peers` — the redial path after the neighbor
    /// count hits zero, and how a ticket's hints reach the mesh after the
    /// initial join.
    pub async fn join_peers(&self, peers: &[NodeId]) -> Result<()> {
        let ids = peers
            .iter()
            .map(endpoint_id)
            .collect::<Result<Vec<_>>>()
            .context("mapping peer ids for gossip")?;
        if ids.is_empty() {
            return Ok(());
        }
        self.inner
            .join_peers(ids)
            .await
            .map_err(|e| anyhow!("asking gossip to join peers on {}: {e}", self.topic.hex()))
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
    /// The endpoint's in-memory address book, so a bootstrap
    /// [`TopicPeer`]'s hints are resolvable when gossip dials it by bare
    /// `EndpointId`.
    ///
    /// iroh 1.0 has no `Endpoint::add_endpoint_addr`: address hints reach the
    /// endpoint through an [`AddressLookup`](iroh::address_lookup::AddressLookup)
    /// service, and [`MemoryLookup`] is the one that means "these are the
    /// addresses I was handed out of band". Without it a hermetic node — no
    /// DNS, no pkarr, no relay — can dial a ticket's peer directly (the addrs
    /// are on the [`EndpointAddr`](iroh::EndpointAddr)) but gossip, which dials
    /// by id alone, cannot.
    lookup: MemoryLookup,
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
        let lookup = MemoryLookup::new();
        let mut builder = Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(secret_key(identity))
            .address_lookup(lookup.clone());
        if let Some(url) = cfg.relay_url.as_deref() {
            let map = iroh::RelayMap::try_from_iter([url])
                .with_context(|| format!("parsing relay url {url}"))?;
            builder = builder.relay_mode(iroh::endpoint::RelayMode::Custom(map));
        }
        // No `.alpns(...)`: the router below sets the endpoint's ALPN set from
        // the protocols registered on it, and anything set here would be
        // replaced by that.
        let endpoint = builder
            .bind()
            .await
            .map_err(|e| anyhow!("binding the topic endpoint: {e}"))?;
        Self::spawn_on(endpoint, lookup, cfg).await
    }

    /// Stand the node up on an endpoint the caller already bound (see
    /// [`spawn`](Self::spawn), which is this plus the bind).
    ///
    /// The split exists for the same reason
    /// [`serve_on`](crate::transport::serve_on) does: the hermetic loopback
    /// tests bind with [`presets::Minimal`](iroh::endpoint::presets::Minimal) —
    /// no DNS, no pkarr, no relay, nothing that leaves the machine — and hand
    /// the endpoint in.
    ///
    /// `lookup` **must be the [`MemoryLookup`] registered on `endpoint`**. It is
    /// a parameter rather than something read back off the endpoint because
    /// iroh exposes no way to recover it, and a lookup this node writes into
    /// but the endpoint never reads is a bootstrap list that silently does
    /// nothing.
    pub async fn spawn_on(
        endpoint: Endpoint,
        lookup: MemoryLookup,
        cfg: TopicNodeConfig,
    ) -> Result<Self> {
        let admitted = Admitted::new();
        let gossip = GatedGossip::new(Gossip::builder().spawn(endpoint.clone()), admitted.clone());
        let admit = Arc::new(AdmitHandler {
            topic: cfg.topic,
            fabric_root: cfg.fabric_root,
            head: Arc::clone(&cfg.head),
            proof: cfg.proof.clone(),
            keystore: Arc::clone(&cfg.keystore),
            admitted: admitted.clone(),
            head_lock: Arc::new(Mutex::new(())),
        });
        let replay = Arc::new(ReplayHandler {
            topic: cfg.topic,
            store: Arc::clone(&cfg.store),
            admitted: admitted.clone(),
            limit: cfg.replay_limit,
        });

        // ONE router. See the module docs: a second one over this endpoint would
        // silently unregister these three.
        let router = Router::builder(endpoint.clone())
            .accept(GOSSIP_ALPN, gossip.clone())
            .accept(library::TOPIC_ADMIT_ALPN, Arc::clone(&admit))
            .accept(library::TOPIC_REPLAY_ALPN, replay)
            .spawn();
        let watchdog = spawn_watchdog(Arc::clone(&admit), cfg.admit_recheck);

        tracing::info!(
            node = %to_node_id(&endpoint.id()).hex(),
            topic = %cfg.topic.hex(),
            sockets = ?endpoint.bound_sockets(),
            admit_recheck = ?cfg.admit_recheck,
            "topic node up (gossip + admit + replay on one router)"
        );
        Ok(Self {
            endpoint,
            router,
            gossip,
            admitted,
            admit,
            store: cfg.store,
            topic: cfg.topic,
            fabric_root: cfg.fabric_root,
            relay_url: cfg.relay_url,
            channel_cap: cfg.channel_cap,
            watchdog,
            bridges: Mutex::new(Vec::new()),
            lookup,
        })
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
        if topic != self.topic {
            bail!(
                "this node serves topic {} and cannot join {}",
                self.topic.hex(),
                topic.hex()
            );
        }
        let bootstrap = self.admit_bootstrap(bootstrap).await?;

        // `subscribe`, not `subscribe_and_join`: with an empty bootstrap set the
        // joining form waits for a neighbor that is never going to arrive, and
        // the first `wires tail` on a topic has exactly that. Waiting is the
        // caller's decision (`wires publish` waits, `wires tail` does not).
        let sub = self
            .gossip
            .gossip()
            .subscribe_with_opts(
                iroh_gossip::proto::TopicId::from_bytes(*topic.as_bytes()),
                JoinOptions::with_bootstrap(bootstrap),
            )
            .await
            .map_err(|e| anyhow!("subscribing to topic {}: {e}", topic.hex()))?;
        let (send, recv) = sub.split();

        let (tx, rx) = mpsc::channel(self.channel_cap);
        let bridge = tokio::spawn(bridge_events(recv, topic, tx));
        self.bridges
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(bridge);
        Ok((TopicSender::new(send, topic), rx))
    }

    /// Record each bootstrap peer's hints and admit it, returning the ids that
    /// are worth handing to gossip.
    ///
    /// Admission comes **before** the subscription, not after, because the mesh
    /// is gated in both directions: an unadmitted peer's gossip connection is
    /// refused by the far side's [`GatedGossip`], and ours refuses its. Dialing
    /// the admit ALPN first is also what teaches this endpoint a path to the
    /// peer, so gossip's later dial — by bare `EndpointId`, with no hints — has
    /// somewhere to go.
    ///
    /// A peer that is merely *unreachable* is logged and skipped: a tail must
    /// still come up on a stale ticket, and replay makes it eventually
    /// consistent. A peer that **refuses** us is not skipped — a
    /// [`Denied`] is the roster saying this node is out, and the spec's answer
    /// to that is exit 77, not a quiet start on an empty mesh.
    async fn admit_bootstrap(&self, bootstrap: &[TopicPeer]) -> Result<Vec<iroh::EndpointId>> {
        let now = crate::now_unix();
        let mut ids = Vec::with_capacity(bootstrap.len());
        let mut failures = Vec::new();
        for peer in bootstrap {
            if peer.node == self.node_id() {
                continue;
            }
            let addr = match crate::transport::endpoint_addr(
                &peer.node,
                &peer.addrs,
                peer.relay_url.as_deref(),
            ) {
                Ok(addr) => addr,
                Err(e) => {
                    failures.push(format!("{}: {e:#}", peer.node.hex()));
                    continue;
                }
            };
            // Into the address book first, so the admission dial and every
            // gossip dial after it resolve the same way.
            self.lookup.add_endpoint_info(addr);

            if !self.admitted.is_admitted(peer.node, now)
                && let Err(e) = admit_peer(&self.endpoint, &self.admit, peer, now).await
            {
                if e.downcast_ref::<Denied>().is_some() {
                    return Err(e.context(format!(
                        "peer {} refused this node's admission",
                        peer.node.hex()
                    )));
                }
                tracing::warn!(
                    peer = %peer.node.hex(),
                    "bootstrap peer could not be admitted; continuing without it: {e:#}"
                );
                failures.push(format!("{}: {e:#}", peer.node.hex()));
                continue;
            }
            match endpoint_id(&peer.node) {
                Ok(id) => ids.push(id),
                Err(e) => failures.push(format!("{}: {e:#}", peer.node.hex())),
            }
        }
        if ids.is_empty() && !failures.is_empty() {
            tracing::warn!(
                "no bootstrap peer could be admitted ({}); joining an empty mesh",
                failures.join("; ")
            );
        }
        Ok(ids)
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
        let derived = TopicId::derive(self.fabric_root, name);
        if derived != self.topic {
            bail!(
                "topic name {name:?} derives to {} under this fabric, not the topic this node \
                 serves ({})",
                derived.hex(),
                self.topic.hex()
            );
        }
        let me = TopicPeer::new(self.node_id())
            .with_addrs(self.endpoint.bound_sockets())
            .with_relay_url(self.relay_url.clone());
        Ok(TopicTicket::new(self.fabric_root, name, vec![me]))
    }

    /// Leave the mesh and close the endpoint.
    ///
    /// Aborts the watchdog and the bridge tasks, shuts the router down (which
    /// shuts gossip down, sending `Disconnect` to neighbors instead of leaving
    /// them to time out), and closes the endpoint. The topic log is released
    /// with the [`TopicStore`], so the next `wires tail` can open it.
    pub async fn shutdown(self) -> Result<()> {
        self.watchdog.abort();
        for bridge in self
            .bridges
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .drain(..)
        {
            bridge.abort();
        }
        // The router shuts the protocols down, which is what sends gossip's
        // `Disconnect` to neighbors instead of leaving them to time us out.
        self.router
            .shutdown()
            .await
            .context("shutting the topic router down")?;
        self.endpoint.close().await;
        Ok(())
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
async fn bridge_events(mut recv: GossipReceiver, topic: TopicId, tx: mpsc::Sender<TopicEvent>) {
    loop {
        // `GossipReceiver` is a `Stream` and nothing else; polling it by hand
        // keeps the whole bridge on the crate's existing dependency set.
        let next = std::future::poll_fn(|cx| Pin::new(&mut recv).poll_next(cx)).await;
        let event = match next {
            Some(Ok(event)) => event,
            Some(Err(e)) => {
                tracing::warn!(topic = %topic.hex(), "gossip subscription failed: {e}");
                return;
            }
            None => {
                tracing::debug!(topic = %topic.hex(), "gossip subscription ended");
                return;
            }
        };
        let mapped = match event {
            GossipEvent::Received(message) => match TopicEnvelope::from_wire(&message.content) {
                Ok(envelope) => TopicEvent::Message(envelope),
                Err(e) => {
                    // Undecodable: it cannot be verified, chained, or opened, so
                    // there is nothing downstream could do with it. Logged
                    // rather than dropped in silence, and explicitly *not*
                    // fatal — one malformed payload from one peer must not take
                    // the whole tail off the mesh.
                    tracing::warn!(
                        topic = %topic.hex(),
                        from = %to_node_id(&message.delivered_from).hex(),
                        bytes = message.content.len(),
                        "dropping an undecodable gossip payload: {e}"
                    );
                    continue;
                }
            },
            GossipEvent::NeighborUp(id) => TopicEvent::NeighborUp(to_node_id(&id)),
            GossipEvent::NeighborDown(id) => TopicEvent::NeighborDown(to_node_id(&id)),
            GossipEvent::Lagged => {
                // Terminal for this subscription: forward it *first*, so the
                // tail loop can catch up and re-join, then end the task.
                if tx.send(TopicEvent::Lagged).await.is_err() {
                    tracing::debug!(topic = %topic.hex(), "event receiver gone; bridge ending");
                } else {
                    tracing::warn!(
                        topic = %topic.hex(),
                        "gossip subscription lagged; messages were dropped upstream"
                    );
                }
                return;
            }
        };
        match tx.try_send(mapped) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(dropped)) => {
                tracing::warn!(
                    topic = %topic.hex(),
                    event = ?dropped,
                    "event channel full; dropping an event (the store still has it — catch_up re-offers)"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::debug!(topic = %topic.hex(), "event receiver gone; bridge ending");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    use library::{FabricKey, MessageHash, NodeIdentity, Roster, RosterHead, Seq};
    use tokio::time::timeout;

    /// The outer bound on any single wait in this suite.
    ///
    /// Generous because a QUIC handshake plus a gossip join on a loaded machine
    /// is not instantaneous, and never reached in the passing case: every wait
    /// here is on an *event*, not on a clock. Nothing sleeps for a fixed
    /// duration except [`QUIET`], which is asserting an absence and has no
    /// other way to do it.
    const PATIENCE: Duration = Duration::from_secs(30);

    /// How long "nothing arrived" is given to be wrong.
    const QUIET: Duration = Duration::from_secs(2);

    /// A fresh directory per node, under Bazel's sandboxed temp when present.
    fn temp_dir() -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let base = std::env::var_os("TEST_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = base.join(format!("wires-topics-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The whole fabric in one value: the committed head, each member's proof,
    /// and the data key that commit would have sealed to them.
    struct Fabric {
        /// The fabric root, which signs the head and every proof.
        root: NodeIdentity,
        /// The committed head every node fixture enforces.
        head: RosterHead,
        /// Each member's inclusion proof under [`head`](Self::head).
        proofs: std::collections::HashMap<NodeId, InclusionProof>,
        /// The shared data key envelopes are sealed under.
        key: FabricKey,
        /// The one topic these fixtures serve.
        topic: TopicId,
    }

    impl Fabric {
        /// Commit a roster over `members` and mint their data key.
        fn of(members: &[NodeId]) -> Self {
            let root = NodeIdentity::from_seed([1u8; 32]);
            let mut roster = Roster::new(root.node_id());
            for m in members {
                roster.insert(*m);
            }
            let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
            Self {
                topic: TopicId::derive(root.node_id(), "ops"),
                root,
                head,
                proofs: proofs.into_iter().collect(),
                key: FabricKey::generate(),
            }
        }

        /// The fabric root's node id.
        fn id(&self) -> NodeId {
            self.root.node_id()
        }
    }

    /// A hermetic node: no DNS, no pkarr, no relay — nothing that leaves the
    /// machine. The [`presets::Minimal`](iroh::endpoint::presets::Minimal)
    /// idiom from `transport.rs`, plus the [`MemoryLookup`] that stands in for
    /// the discovery this endpoint deliberately does not have.
    async fn spawn_node(identity: &NodeIdentity, fabric: &Fabric) -> TopicNode {
        let dir = temp_dir();
        let keystore = Keystore::at(&dir);
        keystore.save_roster_head(&fabric.head).unwrap();
        keystore
            .save_fabric_key(fabric.head.version, &fabric.key)
            .unwrap();
        let store = Arc::new(TopicStore::open(&dir, fabric.topic).unwrap());
        let cfg = TopicNodeConfig::new(
            fabric.topic,
            fabric.id(),
            Arc::new(HeadSource::Keystore {
                path: keystore.path("roster-head.json"),
                armed: AtomicBool::new(false),
            }),
            fabric.proofs[&identity.node_id()].clone(),
            Arc::new(keystore),
            store,
        );
        let lookup = MemoryLookup::new();
        let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(secret_key(identity))
            .address_lookup(lookup.clone())
            .bind()
            .await
            .unwrap();
        TopicNode::spawn_on(endpoint, lookup, cfg).await.unwrap()
    }

    /// The endpoint's bound sockets with wildcard binds rewritten to localhost,
    /// so a hint reaches it without discovery (the `transport.rs` helper).
    fn localhost_socks(endpoint: &Endpoint) -> Vec<std::net::SocketAddr> {
        endpoint
            .bound_sockets()
            .into_iter()
            .map(|sock| match sock {
                std::net::SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
                    std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                        std::net::Ipv4Addr::LOCALHOST,
                        v4.port(),
                    ))
                }
                std::net::SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
                    std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                        std::net::Ipv6Addr::LOCALHOST,
                        v6.port(),
                        v6.flowinfo(),
                        v6.scope_id(),
                    ))
                }
                other => other,
            })
            .collect()
    }

    /// A bootstrap hint pointing at `node` over loopback.
    fn hint(node: &TopicNode) -> TopicPeer {
        TopicPeer::new(node.node_id()).with_addrs(localhost_socks(node.endpoint()))
    }

    /// Wait for the mesh to report a neighbor — never a sleep, which is the
    /// point: the publish that follows happens because gossip said it had
    /// somewhere to send, not because a timer expired.
    async fn wait_neighbor_up(rx: &mut mpsc::Receiver<TopicEvent>) -> NodeId {
        match timeout(PATIENCE, rx.recv())
            .await
            .expect("timed out waiting for a neighbor")
        {
            Some(TopicEvent::NeighborUp(peer)) => peer,
            Some(other) => panic!("expected a neighbor, got {other:?}"),
            None => panic!("the event bridge ended before any neighbor arrived"),
        }
    }

    /// Wait for the next message, skipping neighbor churn.
    async fn next_message(rx: &mut mpsc::Receiver<TopicEvent>) -> TopicEnvelope {
        loop {
            match timeout(PATIENCE, rx.recv())
                .await
                .expect("timed out waiting for a message")
            {
                Some(TopicEvent::Message(envelope)) => return envelope,
                Some(_) => continue,
                None => panic!("the event bridge ended before any message arrived"),
            }
        }
    }

    /// Seal `text` from `sender` as the `seq`-th message of its chain.
    fn sealed(
        sender: &NodeIdentity,
        fabric: &Fabric,
        seq: u64,
        prev: MessageHash,
        text: &str,
    ) -> TopicEnvelope {
        TopicEnvelope::seal(
            sender,
            fabric.topic,
            Seq(seq),
            prev,
            fabric.head.version,
            &fabric.key,
            0,
            text.as_bytes(),
        )
        .unwrap()
    }

    /// Two members, mutually admitted, exchange one sealed envelope over the
    /// gated mesh: the end-to-end shape of `wires publish` reaching `wires
    /// tail`.
    #[tokio::test]
    async fn two_admitted_nodes_exchange_envelope() {
        let (a, b) = (
            NodeIdentity::from_seed([2u8; 32]),
            NodeIdentity::from_seed([3u8; 32]),
        );
        let fabric = Fabric::of(&[a.node_id(), b.node_id()]);
        let node_a = spawn_node(&a, &fabric).await;
        let node_b = spawn_node(&b, &fabric).await;

        // A is first on the topic: an empty bootstrap must not block the join.
        let (send_a, mut rx_a) = node_a.join(fabric.topic, &[]).await.unwrap();
        // B joins off A's hint, which admits both sides in one handshake.
        let (_send_b, mut rx_b) = node_b.join(fabric.topic, &[hint(&node_a)]).await.unwrap();

        assert_eq!(wait_neighbor_up(&mut rx_a).await, b.node_id());
        assert_eq!(wait_neighbor_up(&mut rx_b).await, a.node_id());
        assert!(node_a.admitted().peers().contains(&b.node_id()));
        assert!(node_b.admitted().peers().contains(&a.node_id()));

        let envelope = sealed(&a, &fabric, 0, MessageHash::ZERO, "ship it");
        send_a.broadcast(&envelope).await.unwrap();

        let received = next_message(&mut rx_b).await;
        assert_eq!(received, envelope, "the envelope must cross unchanged");
        received.verify().expect("a member's signature verifies");
        assert_eq!(
            received.open(&fabric.key).unwrap(),
            b"ship it",
            "the shared fabric key opens it"
        );

        node_a.shutdown().await.unwrap();
        node_b.shutdown().await.unwrap();
    }

    /// The gate, at the level it is claimed to work: a node that never
    /// completed the admission handshake cannot reach iroh-gossip at all — its
    /// connection is closed, and the tail on the other side sees nothing.
    #[tokio::test]
    async fn unadmitted_gossip_connection_refused() {
        let b = NodeIdentity::from_seed([3u8; 32]);
        let outsider = NodeIdentity::from_seed([9u8; 32]);
        let fabric = Fabric::of(&[b.node_id()]);
        let node_b = spawn_node(&b, &fabric).await;
        let (_send_b, mut rx_b) = node_b.join(fabric.topic, &[]).await.unwrap();

        // C holds no proof and never dials the admit ALPN — it goes straight
        // for the mesh, which is exactly the attack the wrapper exists for.
        let c = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(secret_key(&outsider))
            .bind()
            .await
            .unwrap();
        let target = crate::transport::endpoint_addr(
            &node_b.node_id(),
            &localhost_socks(node_b.endpoint()),
            None,
        )
        .unwrap();

        match c.connect(target, GOSSIP_ALPN).await {
            Ok(conn) => {
                let reason = timeout(PATIENCE, conn.closed())
                    .await
                    .expect("the gate must close an unadmitted gossip connection");
                assert!(
                    format!("{reason}").contains("not admitted"),
                    "the close must say why, got: {reason}"
                );
            }
            // Refused before a stream ever opened is the same verdict.
            Err(e) => tracing::info!("refused at connect: {e:#}"),
        }

        assert!(
            !node_b.admitted().peers().contains(&outsider.node_id()),
            "an unadmitted dial must not put anyone in the registry"
        );
        assert!(
            timeout(QUIET, rx_b.recv()).await.is_err(),
            "the tail must see nothing at all from an unadmitted peer"
        );

        c.close().await;
        node_b.shutdown().await.unwrap();
    }

    /// A payload that is not a `TopicEnvelope` is logged and dropped by the
    /// bridge — it never reaches the tail, and it never takes the bridge with
    /// it. The two valid envelopes on either side of it are the proof.
    #[tokio::test]
    async fn bridge_survives_malformed_payload() {
        let (a, b) = (
            NodeIdentity::from_seed([2u8; 32]),
            NodeIdentity::from_seed([3u8; 32]),
        );
        let fabric = Fabric::of(&[a.node_id(), b.node_id()]);
        let node_a = spawn_node(&a, &fabric).await;
        let node_b = spawn_node(&b, &fabric).await;

        let (send_a, mut rx_a) = node_a.join(fabric.topic, &[]).await.unwrap();
        let (_send_b, mut rx_b) = node_b.join(fabric.topic, &[hint(&node_a)]).await.unwrap();
        wait_neighbor_up(&mut rx_a).await;
        wait_neighbor_up(&mut rx_b).await;

        // Not JSON, not an envelope, not anything.
        send_a
            .broadcast_bytes(b"\x00\x01 not an envelope".to_vec())
            .await
            .unwrap();

        let first = sealed(&a, &fabric, 0, MessageHash::ZERO, "still here");
        send_a.broadcast(&first).await.unwrap();
        assert_eq!(
            next_message(&mut rx_b).await,
            first,
            "the garbage must be dropped, never surfaced ahead of this"
        );

        // ...and the bridge is still pumping afterwards.
        let second = sealed(
            &a,
            &fabric,
            1,
            first.message_hash().unwrap(),
            "and still here",
        );
        send_a.broadcast(&second).await.unwrap();
        assert_eq!(next_message(&mut rx_b).await, second);

        node_a.shutdown().await.unwrap();
        node_b.shutdown().await.unwrap();
    }

    /// `join` refuses a topic this node was not spawned for: the gate, the
    /// replay server, and the store are all bound to the spawned topic, so a
    /// second one would ride through them ungated and unstored.
    #[tokio::test]
    async fn join_refuses_a_foreign_topic() {
        let a = NodeIdentity::from_seed([2u8; 32]);
        let fabric = Fabric::of(&[a.node_id()]);
        let node = spawn_node(&a, &fabric).await;
        let e = node
            .join(TopicId::derive(fabric.id(), "eng"), &[])
            .await
            .expect_err("a foreign topic must not be joinable");
        assert!(format!("{e:#}").contains("cannot join"), "{e:#}");
        node.shutdown().await.unwrap();
    }

    /// The banner ticket names this node at its real sockets, and round-trips
    /// through its text form to the same topic.
    #[tokio::test]
    async fn ticket_advertises_this_node_on_the_topic() {
        let a = NodeIdentity::from_seed([2u8; 32]);
        let fabric = Fabric::of(&[a.node_id()]);
        let node = spawn_node(&a, &fabric).await;

        let ticket = node.ticket("ops").unwrap();
        assert_eq!(ticket.fabric, fabric.id());
        assert_eq!(ticket.topic_id(), fabric.topic);
        assert_eq!(ticket.peers.len(), 1);
        assert_eq!(ticket.peers[0].node, node.node_id());
        assert_eq!(ticket.peers[0].addrs, node.endpoint().bound_sockets());
        assert_eq!(
            TopicTicket::decode(&ticket.encode().unwrap()).unwrap(),
            ticket
        );

        // A name that derives elsewhere is not this node's ticket to hand out.
        assert!(node.ticket("eng").is_err());
        node.shutdown().await.unwrap();
    }

    /// A sender refuses an envelope addressed to another topic rather than
    /// putting one topic's ciphertext on another topic's mesh.
    #[tokio::test]
    async fn a_sender_refuses_a_foreign_envelope() {
        let a = NodeIdentity::from_seed([2u8; 32]);
        let fabric = Fabric::of(&[a.node_id()]);
        let node = spawn_node(&a, &fabric).await;
        let (send, _rx) = node.join(fabric.topic, &[]).await.unwrap();

        let mut stray = sealed(&a, &fabric, 0, MessageHash::ZERO, "wrong mesh");
        stray.topic = TopicId::derive(fabric.id(), "eng");
        let e = send
            .broadcast(&stray)
            .await
            .expect_err("a foreign envelope must not be broadcast");
        assert!(format!("{e:#}").contains("addressed to topic"), "{e:#}");
        node.shutdown().await.unwrap();
    }
}

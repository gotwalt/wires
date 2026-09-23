//! The resident topic node: one endpoint, one router, one gossip mesh, and the
//! event stream `wires watch` prints from (spec §7.4).
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
//! | [`TOPIC_REPLAY_ALPN`](library::TOPIC_REPLAY_ALPN) | [`ReplayHandler`](crate::channel::replay::ReplayHandler) | peer-symmetric catch-up |
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
//! unbounded memory — and a full channel makes the bridge **wait**, never drop.
//! Dropping looks cheap and is not: the tail task is the only ingester, so a
//! dropped `Message` was never written to this node's log, and the bridge has no
//! way to schedule the catch-up that would fetch it again. Waiting pushes the
//! pressure up to iroh-gossip instead, which answers it with `Lagged` — the one
//! signal that *is* wired to a re-join and a catch-up.
//!
//! [`TopicEvent::Lagged`] gets the same treatment for the same reason. When a
//! subscriber falls behind, iroh-gossip emits `Lagged` and closes the
//! subscription; the PoC trap was to treat that as a stream end and exit the
//! loop with no output at all, leaving a tail that looked alive and printed
//! nothing forever. Here the bridge forwards `Lagged` first, so the tail loop
//! can schedule a [`catch_up`](crate::channel::replay::catch_up) and re-subscribe, and
//! logs at `warn` on the way out. Nothing about falling behind is silent.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures_core::Stream;
use iroh::Endpoint;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::protocol::{DynProtocolHandler, Router};
use iroh_gossip::api::{Event as GossipEvent, GossipReceiver, GossipSender, JoinOptions};
use iroh_gossip::net::{GOSSIP_ALPN, Gossip};
use library::{
    InclusionProof, NodeId, NodeIdentity, TopicEnvelope, TopicId, TopicPeer, TopicTicket,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::admin::keystore::Keystore;
use crate::channel::admission::{
    ADMIT_RECHECK, AdmitHandler, Admitted, GatedGossip, MAX_INFLIGHT_ADMISSIONS, admit_peer,
    spawn_watchdog,
};
use crate::channel::replay::{REPLAY_LIMIT, ReplayHandler};
use crate::channel::store::TopicStore;
use crate::host::transport::{Denied, HeadSource, endpoint_id, secret_key, to_node_id};

/// How many [`TopicEvent`]s the bridge will buffer for the tail loop (spec
/// §7.4).
///
/// Bounded on purpose. The producer is the network and the consumer is a
/// terminal — the one arrangement where an unbounded channel converts a slow
/// reader into an out-of-memory kill. At 256 the buffer absorbs a replay burst
/// without dropping anything, and past it the bridge *waits* rather than
/// dropping — the pressure travels up to iroh-gossip, which answers it with
/// `Lagged`, the one signal wired to a re-join and a catch-up.
pub const EVENT_CHANNEL_CAP: usize = 256;

/// How long [`TopicNode::join`] spends admitting bootstrap peers before it gives
/// the rest to the redial timer.
///
/// Startup and every re-join run this loop, and it is sequential: without a
/// budget, a peer book full of stale entries turns "join the mesh" into minutes
/// of dialing before the control socket is even usable.
pub const BOOTSTRAP_BUDGET: Duration = Duration::from_secs(30);

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
    /// Maximum items this node will stream in one replay pass (default
    /// [`REPLAY_LIMIT`]).
    pub replay_limit: u32,
    /// Capacity of the [`TopicEvent`] channel (default [`EVENT_CHANNEL_CAP`]).
    pub channel_cap: usize,
    /// Extra `(ALPN, handler)` pairs to register on the node's one router —
    /// how `serve --audit-topic` serves the session ALPN from this endpoint
    /// instead of binding a second one for the same key. Empty by default;
    /// an ALPN that collides with one of the three above is refused.
    pub protocols: Vec<(&'static [u8], Box<dyn DynProtocolHandler>)>,
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
            replay_limit: REPLAY_LIMIT,
            channel_cap: EVENT_CHANNEL_CAP,
            protocols: Vec::new(),
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
    /// the tail loop's response is a [`catch_up`](crate::channel::replay::catch_up) and
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
    ///
    /// `#[cfg(test)]`: the production path reads the field directly in
    /// [`broadcast`](Self::broadcast)'s guard, so this exists only for the
    /// fixtures that assert a sender came back bound to the topic they joined.
    #[cfg(test)]
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
    /// only an [`Appended::Inserted`](crate::channel::store::Appended) goes on the wire.
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

/// The resident node behind `wires watch`: endpoint, router, gated mesh,
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
    /// [`admit_peer`](crate::channel::admission::admit_peer) needs.
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
    /// [`admit_peer`](crate::channel::admission::admit_peer) are separate steps, so a
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
    /// [`serve_on`](crate::host::transport::serve_on) does: the hermetic loopback
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
            inflight: Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_ADMISSIONS)),
        });
        let replay = Arc::new(ReplayHandler {
            topic: cfg.topic,
            store: Arc::clone(&cfg.store),
            admitted: admitted.clone(),
            limit: cfg.replay_limit,
        });

        // ONE router. See the module docs: a second one over this endpoint would
        // silently unregister these three.
        let mut builder = Router::builder(endpoint.clone())
            .accept(GOSSIP_ALPN, gossip.clone())
            .accept(library::TOPIC_ADMIT_ALPN, Arc::clone(&admit))
            .accept(library::TOPIC_REPLAY_ALPN, replay);
        for (alpn, handler) in cfg.protocols {
            if [
                GOSSIP_ALPN,
                library::TOPIC_ADMIT_ALPN,
                library::TOPIC_REPLAY_ALPN,
            ]
            .contains(&alpn)
            {
                bail!(
                    "extra protocol {:?} would replace one of the topic node's own",
                    String::from_utf8_lossy(alpn)
                );
            }
            builder = builder.accept(alpn, handler);
        }
        let router = builder.spawn();
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
        crate::host::transport::to_node_id(&self.endpoint.id())
    }

    /// The bound endpoint, for dialing admission and replay.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The admission handler, which doubles as the client-side context for
    /// [`admit_peer`](crate::channel::admission::admit_peer).
    pub fn admit(&self) -> &Arc<AdmitHandler> {
        &self.admit
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
    /// caller's decision, because `wires advanced publish` needs it and `wires watch`
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
        // the first `wires watch` on a topic has exactly that. Waiting is the
        // caller's decision (`wires advanced publish` waits, `wires watch` does not).
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
        {
            let mut bridges = self
                .bridges
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // A week of re-joins would otherwise leave a week of finished handles
            // here, held only to be aborted at shutdown.
            bridges.retain(|handle| !handle.is_finished());
            bridges.push(bridge);
        }
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
    /// consistent. A [`Denied`] is different — it is a peer saying this node is
    /// not in the roster, which spec §7 answers with exit 77 — but it is only
    /// evidence when **nothing** admitted this node. One peer refusing is that
    /// peer's verdict, and a refusal is not even always about the roster: a peer
    /// that imported a commit this node has not yet answers `stale inclusion
    /// proof`, and a peer whose own head is briefly unreadable answers
    /// `responder configuration error`. So the refusal is carried to the end of
    /// the round and returned only if no peer admitted us.
    async fn admit_bootstrap(&self, bootstrap: &[TopicPeer]) -> Result<Vec<iroh::EndpointId>> {
        let now = crate::now_unix();
        let until = tokio::time::Instant::now() + BOOTSTRAP_BUDGET;
        let mut ids = Vec::with_capacity(bootstrap.len());
        let mut failures = Vec::new();
        let mut denial: Option<anyhow::Error> = None;
        for peer in bootstrap {
            if peer.node == self.node_id() {
                continue;
            }
            // Each handshake is bounded (`TOPIC_DIAL_TIMEOUT` +
            // `TOPIC_HANDSHAKE_TIMEOUT`), but a peer book with fifty stale
            // entries would still make a tail's startup — or a re-join in the
            // live loop — take minutes. The rest of the book is left to the
            // redial timer, which is designed for exactly that.
            if tokio::time::Instant::now() >= until {
                tracing::warn!(
                    remaining = bootstrap.len() - ids.len(),
                    "bootstrap budget spent; the redial timer will keep trying the rest"
                );
                break;
            }
            let addr = match crate::host::transport::endpoint_addr(
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
                    denial.get_or_insert(e.context(format!(
                        "peer {} refused this node's admission",
                        peer.node.hex()
                    )));
                    continue;
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
        if ids.is_empty()
            && let Some(denial) = denial
        {
            return Err(denial);
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
    /// What `wires watch` prints in its startup banner (`share to bootstrap:
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
            .with_addrs(ticket_addrs(&self.endpoint))
            .with_relay_url(self.relay_url.clone());
        Ok(TopicTicket::new(self.fabric_root, name, vec![me]))
    }

    /// Leave the mesh and close the endpoint.
    ///
    /// Aborts the watchdog and the bridge tasks, shuts the router down (which
    /// shuts gossip down, sending `Disconnect` to neighbors instead of leaving
    /// them to time out), and closes the endpoint. The topic log is released
    /// with the [`TopicStore`], so the next `wires watch` can open it.
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

/// The socket addresses to advertise in this node's [`TopicTicket`].
///
/// **Not `Endpoint::bound_sockets()`**, which is what the endpoint *bound* and
/// not what anyone can dial: with the default wildcard bind those are
/// `0.0.0.0:p` and `[::]:p`, and the unspecified address is not an address a
/// peer can connect to. Handing them out produced a ticket that failed between
/// machines always and on one machine intermittently — some stacks route a
/// connect to `0.0.0.0` to loopback, some let it time out — which reads as a
/// flaky mesh rather than as a bad hint.
///
/// So the primary source is [`Endpoint::addr`], iroh's own view of where this
/// endpoint is reachable (real interface addresses, discovered and kept
/// current). Loopback forms of the bound ports are appended behind it, because
/// two nodes on one machine are the demo, the soak, and most of development,
/// and on a host with no usable interface (an offline laptop, a sandboxed CI
/// runner) `addr()` is legitimately empty.
///
/// Every entry is a *hint*: iroh authenticates the far side to the ticket's
/// node id regardless of which address answered, so a hint that reaches the
/// wrong host fails the handshake rather than connecting to an impostor. The
/// cost of an extra one is a dial that fails fast.
fn ticket_addrs(endpoint: &Endpoint) -> Vec<std::net::SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    let mut addrs: Vec<SocketAddr> = endpoint.addr().ip_addrs().copied().collect();
    for sock in endpoint.bound_sockets() {
        let dialable = match sock {
            SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
                SocketAddr::from((Ipv4Addr::LOCALHOST, v4.port()))
            }
            SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
                SocketAddr::from((Ipv6Addr::LOCALHOST, v6.port()))
            }
            other => other,
        };
        if !addrs.contains(&dialable) {
            addrs.push(dialable);
        }
    }
    addrs
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
        // Backpressure, not a drop. The bridge used to `try_send` and log a
        // dropped event on a full channel, with the comment that "the store
        // still has it — catch_up re-offers": both halves were wrong. The tail
        // task is the only ingester, so a dropped `Message` was never written to
        // *this* node's log, and the drop happened on a task with no way to
        // schedule a catch-up — so if the dropped message was the newest from
        // its publisher, no later `Gap` would ever surface it and the line was
        // simply never printed. Waiting instead pushes the pressure one layer
        // up, where iroh-gossip answers it with `Lagged`, which *is* wired to a
        // re-join and a catch-up.
        if tx.send(mapped).await.is_err() {
            tracing::debug!(topic = %topic.hex(), "event receiver gone; bridge ending");
            return;
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
            Self::of_under([1u8; 32], members)
        }

        /// [`of`](Self::of) under an explicit root seed, for the tests that need
        /// two fabrics that do not recognise each other.
        fn of_under(root_seed: [u8; 32], members: &[NodeId]) -> Self {
            let root = NodeIdentity::from_seed(root_seed);
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
        spawn_node_with(identity, fabric, |_| {}).await
    }

    /// [`spawn_node`] with a hook over the config, for the one or two tests that
    /// need a non-default interval or channel size.
    async fn spawn_node_with(
        identity: &NodeIdentity,
        fabric: &Fabric,
        tweak: impl FnOnce(&mut TopicNodeConfig),
    ) -> TopicNode {
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
        let mut cfg = cfg;
        tweak(&mut cfg);
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
    /// gated mesh: the end-to-end shape of `wires advanced publish` reaching `wires
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
        assert!(node_a.admit().admitted.peers().contains(&b.node_id()));
        assert!(node_b.admit().admitted.peers().contains(&a.node_id()));

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
        let target = crate::host::transport::endpoint_addr(
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
            !node_b
                .admit()
                .admitted
                .peers()
                .contains(&outsider.node_id()),
            "an unadmitted dial must not put anyone in the registry"
        );
        assert!(
            timeout(QUIET, rx_b.recv()).await.is_err(),
            "the tail must see nothing at all from an unadmitted peer"
        );

        c.close().await;
        node_b.shutdown().await.unwrap();
    }

    /// One peer's refusal is that peer's verdict, not the roster's.
    ///
    /// `admit_bootstrap` used to return on the *first* `Denied`, which the tail
    /// reports as exit 77 ("you are off the roster"). But a peer that imported a
    /// commit before this node did answers `stale inclusion proof` to a member
    /// in good standing, and a peer whose own `roster-head.json` is briefly
    /// unreadable answers `responder configuration error` — so one misconfigured
    /// machine could take down every tail that had it in its peer book. The
    /// refusal only becomes a verdict when nothing admitted this node.
    #[tokio::test]
    async fn one_peers_refusal_does_not_stop_a_join_that_another_peer_admits() {
        let (a, b) = (
            NodeIdentity::from_seed([2u8; 32]),
            NodeIdentity::from_seed([3u8; 32]),
        );
        let d = NodeIdentity::from_seed([4u8; 32]);
        let stranger = NodeIdentity::from_seed([9u8; 32]);
        let ours = Fabric::of(&[a.node_id(), b.node_id(), d.node_id()]);
        // A node in a fabric that has never heard of us: it answers our request
        // with a `Denied`, exactly as a stale or misconfigured peer would.
        let theirs = Fabric::of_under([7u8; 32], &[stranger.node_id()]);

        let node_a = spawn_node(&a, &ours).await;
        let node_b = spawn_node(&b, &ours).await;
        let node_x = spawn_node(&stranger, &theirs).await;

        // The refusing peer is dialed first, so a "return on the first Denied"
        // never reaches the peer that would have admitted us.
        let (_send_b, mut rx_b) = node_b
            .join(ours.topic, &[hint(&node_x), hint(&node_a)])
            .await
            .expect("a member with one good peer must still join");
        let (_send_a, mut rx_a) = node_a.join(ours.topic, &[]).await.unwrap();
        assert_eq!(wait_neighbor_up(&mut rx_b).await, a.node_id());
        assert_eq!(wait_neighbor_up(&mut rx_a).await, b.node_id());
        assert!(
            !node_b
                .admit()
                .admitted
                .peers()
                .contains(&stranger.node_id())
        );

        // With *only* the refusing peer, the refusal is the whole answer — the
        // exit-77 path is intact.
        let node_c = spawn_node(&d, &ours).await;
        let refusal = node_c
            .join(ours.topic, &[hint(&node_x)])
            .await
            .expect_err("nothing admitted this node, so the denial stands");
        assert!(
            refusal.downcast_ref::<Denied>().is_some(),
            "the error must still be a policy refusal (exit 77), got: {refusal:#}"
        );

        node_a.shutdown().await.unwrap();
        node_b.shutdown().await.unwrap();
        node_c.shutdown().await.unwrap();
        node_x.shutdown().await.unwrap();
    }

    /// A slow reader costs latency, never a message.
    ///
    /// The bridge used to `try_send` and log a dropped event when the channel
    /// filled, with the comment that "the store still has it — catch_up
    /// re-offers". Both halves were wrong: the tail task is the only ingester,
    /// so a dropped `Message` was never written to this node's log at all, and
    /// the drop happened on a task with no way to schedule a catch-up — if the
    /// dropped message was the newest from its publisher, no later `Gap` would
    /// ever surface it and the line simply never appeared. The tail loop is
    /// routinely busy for exactly this long (a catch-up pass against a peer with
    /// a long history), so this is the ordinary case, not the pathological one.
    #[tokio::test]
    async fn a_full_event_channel_waits_rather_than_dropping_a_message() {
        let (a, b) = (
            NodeIdentity::from_seed([2u8; 32]),
            NodeIdentity::from_seed([3u8; 32]),
        );
        let fabric = Fabric::of(&[a.node_id(), b.node_id()]);
        let node_a = spawn_node(&a, &fabric).await;
        // B's bridge can buffer two events. Everything past that has to wait for
        // the reader, which is not reading yet.
        let node_b = spawn_node_with(&b, &fabric, |cfg| cfg.channel_cap = 2).await;

        let (send_a, mut rx_a) = node_a.join(fabric.topic, &[]).await.unwrap();
        let (_send_b, mut rx_b) = node_b.join(fabric.topic, &[hint(&node_a)]).await.unwrap();
        wait_neighbor_up(&mut rx_a).await;
        wait_neighbor_up(&mut rx_b).await;

        // Eight messages into a channel that holds two, with nobody draining.
        let mut sent = Vec::new();
        let mut prev = MessageHash::ZERO;
        for seq in 0..8u64 {
            let envelope = sealed(&a, &fabric, seq, prev, &format!("line {seq}"));
            prev = envelope.message_hash().unwrap();
            send_a.broadcast(&envelope).await.unwrap();
            sent.push(envelope);
        }

        // Now drain. Every one of them is still there, in order.
        let mut received = Vec::new();
        while received.len() < sent.len() {
            received.push(next_message(&mut rx_b).await);
        }
        assert_eq!(received, sent, "a full channel must not lose a message");

        node_a.shutdown().await.unwrap();
        node_b.shutdown().await.unwrap();
    }

    /// The check and the tracking are **one** operation, and a connection that
    /// loses the race is closed rather than left attached.
    ///
    /// The regression this pins: `GatedGossip::accept` used to call
    /// `is_admitted(peer)` and then `attach_conn(peer, conn)`, and `attach_conn`
    /// was a silent no-op for a peer that was not in the map. An eviction
    /// landing between the two removed the entry, the attach dropped the handle
    /// on the floor, and iroh-gossip got the connection anyway — a revoked peer
    /// with a live mesh connection that no later watchdog pass would even list,
    /// let alone close. A peer about to be removed only had to open connections
    /// in a loop until one landed in the window.
    #[tokio::test]
    async fn attaching_a_connection_is_the_admission_check() {
        let (a, b) = (
            NodeIdentity::from_seed([2u8; 32]),
            NodeIdentity::from_seed([3u8; 32]),
        );
        let fabric = Fabric::of(&[a.node_id(), b.node_id()]);
        let node_b = spawn_node(&b, &fabric).await;

        // Any real `Connection` will do: what is under test is the registry's
        // decision, not the bytes on it.
        let endpoint_a = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(secret_key(&a))
            .bind()
            .await
            .unwrap();
        let target = crate::host::transport::endpoint_addr(
            &node_b.node_id(),
            &localhost_socks(node_b.endpoint()),
            None,
        )
        .unwrap();
        let conn = timeout(
            PATIENCE,
            endpoint_a.connect(target, library::TOPIC_ADMIT_ALPN),
        )
        .await
        .expect("dial timed out")
        .expect("the admit ALPN is registered");

        let registry = Admitted::new();
        let entry = |expires| crate::channel::admission::AdmittedPeer {
            proof: fabric.proofs[&a.node_id()].clone(),
            version: fabric.head.version,
            expires,
            conns: Vec::new(),
        };

        assert!(
            !registry.attach_conn(a.node_id(), conn.clone(), 0),
            "a peer that is not in the registry is not admitted by attaching"
        );
        registry.insert(a.node_id(), entry(100));
        assert!(registry.attach_conn(a.node_id(), conn.clone(), 100));
        assert!(
            !registry.attach_conn(a.node_id(), conn.clone(), 101),
            "a lapsed lease refuses at the same edge `is_admitted` does"
        );

        // And the attach is what makes eviction able to close: the connection
        // tracked above dies with the peer.
        registry.evict(a.node_id());
        assert!(
            !registry.attach_conn(a.node_id(), conn.clone(), 100),
            "an evicted peer cannot re-attach without a fresh admission"
        );
        assert!(
            timeout(PATIENCE, conn.closed()).await.is_ok(),
            "evicting the peer must close the connection it was tracked on"
        );

        endpoint_a.close().await;
        node_b.shutdown().await.unwrap();
    }

    /// The pre-authorization surface is bounded: with every in-flight permit
    /// taken, a new admission dial is refused instead of buying a task and a
    /// 64 KiB buffer.
    ///
    /// `MAX_ADMIT_FRAME` bounds one frame, which was mistaken for bounding the
    /// surface — iroh spawns a task per accepted connection with no cap, so an
    /// attacker holding no credential at all could open thousands, write a
    /// length prefix on each, and stall.
    #[tokio::test]
    async fn the_pre_authorization_surface_is_bounded() {
        let (a, b) = (
            NodeIdentity::from_seed([2u8; 32]),
            NodeIdentity::from_seed([3u8; 32]),
        );
        let fabric = Fabric::of(&[a.node_id(), b.node_id()]);
        let node_a = spawn_node(&a, &fabric).await;
        let node_b = spawn_node(&b, &fabric).await;

        // Every permit B has, held by "handshakes" that are not going anywhere.
        let hogged = node_b
            .admit()
            .inflight
            .clone()
            .acquire_many_owned(MAX_INFLIGHT_ADMISSIONS as u32)
            .await
            .unwrap();

        let refused = timeout(
            PATIENCE,
            admit_peer(node_a.endpoint(), node_a.admit(), &hint(&node_b), 0),
        )
        .await
        .expect("the refusal must be prompt, not a hang");
        assert!(
            refused.is_err(),
            "a saturated pre-authorization surface admits nobody"
        );
        assert!(!node_b.admit().admitted.peers().contains(&a.node_id()));

        // Released, the very same dial succeeds — the bound is a bound, not a
        // broken gate.
        drop(hogged);
        timeout(
            PATIENCE,
            admit_peer(node_a.endpoint(), node_a.admit(), &hint(&node_b), 0),
        )
        .await
        .expect("admission timed out")
        .expect("both nodes are members under the same head");

        node_a.shutdown().await.unwrap();
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
        // Dialable hints, not the wildcard binds: every advertised address must
        // be one a peer can actually connect to (see `ticket_addrs`).
        assert!(!ticket.peers[0].addrs.is_empty());
        for addr in &ticket.peers[0].addrs {
            assert!(!addr.ip().is_unspecified(), "{addr} is not dialable");
        }
        // And the loopback form of every bound port is in there, so a second
        // node on this machine can reach it with no discovery at all.
        for sock in localhost_socks(node.endpoint()) {
            assert!(
                ticket.peers[0].addrs.contains(&sock),
                "{sock} missing from {:?}",
                ticket.peers[0].addrs
            );
        }
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

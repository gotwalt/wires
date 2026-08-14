//! The roster gate in front of the gossip mesh: the `wires/topic-admit/1`
//! handshake, the per-process allowlist it feeds, and the wrapper
//! [`ProtocolHandler`] that consults the allowlist before letting a connection
//! reach iroh-gossip.
//!
//! iroh-gossip has no authorization hook — anyone who can reach the endpoint and
//! speak its ALPN joins the swarm. So membership is proved out of band: a peer
//! dials [`TOPIC_ADMIT_ALPN`](library::TOPIC_ADMIT_ALPN), presents the roster
//! head it holds and its [`InclusionProof`], and gets back the responder's own
//! head and proof — one round trip, mutual admission, both sides deciding with
//! [`check_topic_admission`]. Success puts the peer in [`Admitted`], and
//! [`GatedGossip`] refuses any gossip connection from a node that is not in
//! there.
//!
//! Caller identity is never a wire field: it is `to_node_id(&conn.remote_id())`,
//! the key iroh authenticated. A frame that claimed to be someone else would be
//! claiming to be a key it cannot sign for.
//!
//! All three ALPNs — gossip, admit, replay — must be registered on **one**
//! [`iroh::protocol::Router`]. Two routers over one endpoint clobber each
//! other's ALPN set.
//!
//! # What revocation actually costs (spec §2.4)
//!
//! When the root commits a roster that removes a member, four different things
//! stop at four different times, and the demo asserts each one:
//!
//! 1. **Confidentiality: immediate.** That commit minted a fresh
//!    [`FabricKey`](library::FabricKey), sealed only to the members who
//!    survived. Nothing published after it is readable by the removed node,
//!    whatever it is still connected to.
//! 2. **Ingest integrity: immediate.** Envelopes are verified at ingest, and a
//!    removed member cannot mint ciphertext that opens under a key it does not
//!    hold. Its messages are refused, not merely ignored.
//! 3. **Mesh eviction: within one [`ADMIT_RECHECK`] interval** of this node
//!    holding the new head — the watchdog re-checks every stored proof against
//!    the freshly loaded head and evicts the ones that no longer verify,
//!    closing their tracked gossip connections. The gate is inbound, so a
//!    revoked peer also cannot re-admit itself: the next handshake is refused
//!    against the new head.
//! 4. **Residual, and deliberately not fixed here:** *outbound* dials are not
//!    gated. iroh-gossip's peer exchange can hand this node the address of a
//!    peer that has since been removed, and it will dial it. What that peer
//!    learns is bounded by (1) and (2) — it can neither read the traffic nor
//!    inject into it — so the honest deferral (spec §10) is to gate inbound
//!    connections only and say so, rather than to ship a half-gate that reads
//!    as complete.
//!
//! The head this all turns on spreads passively: an admission that presents a
//! strictly newer, verified, unexpired head causes this node to adopt it (spec
//! §2.2), which is why eviction latency is measured from "holds the new head"
//! and not from "the root committed".

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use iroh::Endpoint;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh_gossip::net::Gossip;
use library::{
    Admission, InclusionProof, NodeId, RosterHead, RosterVersion, TopicId, TopicPeer,
    check_topic_admission,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::keystore::Keystore;
use crate::transport::HeadSource;

/// How long an admission stands before it must be re-established.
///
/// A ceiling on how stale a decision can get if the watchdog dies or a head
/// never advances; the effective expiry is `min(now + ADMIT_TTL,
/// head.not_after)`, because a roster head that has expired must not keep
/// admitting anyone past its own validity window.
///
/// **Injectable.** Tests do not sleep on it: the constant is the default that
/// the resident node passes into [`AdmitHandler`], and every function that
/// applies it takes the deadline (or `now_unix`) as an argument, so a test can
/// admit a peer with an expiry one second in the past and watch the gate close.
pub const ADMIT_TTL: Duration = Duration::from_secs(300);

/// How often the watchdog re-checks stored admissions against the current head.
///
/// This interval *is* the revocation-latency number in the module docs: a
/// removed member stays in the mesh for at most this long after the node holds
/// the head that removed it.
///
/// **Injectable**, for the same reason and by the same route — the watchdog
/// takes its interval as a parameter ([`spawn_watchdog`]) and this constant is
/// only the default the CLI supplies. The eviction test injects milliseconds
/// and asserts the neighbor drops; nothing in the suite waits 30 seconds.
pub const ADMIT_RECHECK: Duration = Duration::from_secs(30);

/// One admitted peer: the credential it was admitted on, and the connections
/// that die with it.
#[derive(Debug)]
pub struct AdmittedPeer {
    /// The inclusion proof presented at admission. Retained because the
    /// watchdog re-checks *this* proof against the head as it moves — the
    /// admission is only as good as the roster it was made under.
    pub proof: InclusionProof,
    /// The roster version the admission was decided under.
    pub version: RosterVersion,
    /// When the admission lapses, unix seconds: `min(now + ADMIT_TTL,
    /// head.not_after)`.
    pub expires: i64,
    /// Live connections opened by this peer (gossip and admit), tracked so an
    /// eviction can close them instead of leaving a revoked member attached
    /// until it chooses to hang up.
    pub conns: Vec<Connection>,
}

/// The per-process allowlist: who has proved roster membership for this topic.
///
/// Cheap to clone — every clone shares one map — because the admit handler, the
/// gossip wrapper, the replay handler, and the watchdog all consult and mutate
/// the same registry. The lock is a plain [`std::sync::Mutex`]: every operation
/// on it is a map access plus, at most, a synchronous `Connection::close`, so
/// there is nothing to await while holding it.
#[derive(Clone, Debug, Default)]
pub struct Admitted {
    /// The shared map, keyed by the iroh-authenticated peer key.
    inner: Arc<Mutex<HashMap<NodeId, AdmittedPeer>>>,
}

impl Admitted {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `peer` currently holds an unexpired admission.
    ///
    /// `now_unix` is passed in rather than read from the clock so the expiry
    /// edge is testable.
    pub fn is_admitted(&self, peer: NodeId, now_unix: i64) -> bool {
        todo!("lock, look up, compare against expires")
    }

    /// Record (or replace) `peer`'s admission. A re-admission supersedes the
    /// old entry's credential while keeping its tracked connections alive: the
    /// peer proved itself again, so nothing needs to be torn down.
    pub fn insert(&self, peer: NodeId, entry: AdmittedPeer) {
        todo!("lock and upsert, preserving tracked conns")
    }

    /// Remove `peer` and close every connection tracked for it.
    ///
    /// Closing is the point. Dropping the entry alone would leave a revoked
    /// member's existing gossip connection in place — the gate is on *accept*,
    /// so a connection already through it is never re-checked.
    pub fn evict(&self, peer: NodeId) {
        todo!("lock, remove, close each tracked connection")
    }

    /// Track `conn` against an admitted `peer` so a later eviction closes it.
    /// A connection from a peer that is not admitted is not tracked.
    pub fn attach_conn(&self, peer: NodeId, conn: Connection) {
        todo!("lock and push onto the peer's conns")
    }

    /// A snapshot of every admission as `(peer, version, proof)`, for the
    /// watchdog to re-check without holding the lock across its work.
    pub fn snapshot(&self) -> Vec<(NodeId, RosterVersion, InclusionProof)> {
        todo!("lock and clone out the credentials")
    }

    /// The admitted peers, in id order — the dial set for replay catch-up.
    pub fn peers(&self) -> Vec<NodeId> {
        todo!("lock and collect the keys")
    }
}

/// The admission responder and the shared state every side of the gate needs:
/// what fabric to trust, what head to check against, what credential to present,
/// and where admitted peers are recorded.
///
/// Also the *client* side's context — admission is symmetric, so
/// [`request_admission`] and [`admit_peer`] read the same fields the responder
/// does. Registered on the router as the [`ProtocolHandler`] for
/// [`TOPIC_ADMIT_ALPN`](library::TOPIC_ADMIT_ALPN).
pub struct AdmitHandler {
    /// The topic being gated. An admission is scoped to one topic; a request
    /// naming a different one is refused rather than quietly admitted.
    pub topic: TopicId,
    /// The fabric root whose signatures on heads and proofs are honored.
    pub fabric_root: NodeId,
    /// Where the roster head comes from, **re-loaded per admission** (the
    /// [`HeadSource`] contract: it fails closed). This is what makes `wires
    /// import` of a newer head take effect on the next handshake rather than
    /// the next restart.
    pub head: Arc<HeadSource>,
    /// This node's own inclusion proof, presented in the request and the ack so
    /// the far side can gate us in turn.
    pub proof: InclusionProof,
    /// Where an adopted head is persisted (`roster-head.json`).
    pub keystore: Arc<Keystore>,
    /// The registry this handler admits into.
    pub admitted: Admitted,
    /// Serializes the read-modify-write behind head adoption. Held across the
    /// re-read, the [`adopt_if_newer`](library::adopt_if_newer) call, and the
    /// write — the compare-and-swap discipline spec §2.2 requires, without
    /// which two concurrent admissions can roll the stored head backwards.
    pub head_lock: Arc<Mutex<()>>,
}

impl std::fmt::Debug for AdmitHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmitHandler")
            .field("topic", &self.topic.hex())
            .field("fabric_root", &self.fabric_root.hex())
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}

impl AdmitHandler {
    /// Persist a head this node just decided to adopt, under the
    /// compare-and-swap rule (spec §2.2).
    ///
    /// Takes [`head_lock`](Self::head_lock), re-reads the stored head, re-runs
    /// [`adopt_if_newer`](library::adopt_if_newer) against *that* value, and
    /// writes only if the candidate is still an advance. Returns the head
    /// actually written, or `None` when the candidate lost the race — which is
    /// a normal outcome, not an error.
    ///
    /// Synchronous on purpose: the whole sequence is filesystem work, and a
    /// lock held across an await is how the "one exclusive lock" obligation
    /// gets quietly broken.
    pub fn persist_head(
        &self,
        candidate: &RosterHead,
        now_unix: i64,
    ) -> Result<Option<RosterHead>> {
        todo!("lock; re-read; adopt_if_newer; save_roster_head")
    }

    /// The expiry to record for an admission decided now against `head`:
    /// `min(now_unix + ADMIT_TTL, head.not_after)`.
    pub fn expiry(&self, head: &RosterHead, now_unix: i64) -> i64 {
        todo!("clamp now + ADMIT_TTL to head.not_after")
    }
}

impl ProtocolHandler for AdmitHandler {
    /// Serve one admission: authenticate the caller from the connection, run
    /// [`serve_admission`] over its bi-stream, and — on success — track the
    /// connection so an eviction can close it.
    ///
    /// A refusal is answered on the wire (an [`AdmitFrame::Denied`](library::AdmitFrame)
    /// carrying the reason) before the connection drops, so a removed member
    /// learns *why* it is out rather than seeing a connection failure.
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        todo!("remote_id -> caller; accept_bi; serve_admission; attach_conn")
    }
}

/// The gossip [`ProtocolHandler`], wrapped so a connection is admitted before
/// iroh-gossip ever sees it.
///
/// Inbound only, by design — see item 4 of the revocation story in the module
/// docs.
#[derive(Clone, Debug)]
pub struct GatedGossip {
    /// The real gossip protocol handler; everything admitted is delegated to it
    /// unchanged.
    inner: Gossip,
    /// The gate.
    admitted: Admitted,
}

impl GatedGossip {
    /// Wrap `inner`, gating it on `admitted`.
    pub fn new(inner: Gossip, admitted: Admitted) -> Self {
        Self { inner, admitted }
    }

    /// The wrapped gossip handle, for subscribing and broadcasting.
    pub fn gossip(&self) -> &Gossip {
        &self.inner
    }
}

impl ProtocolHandler for GatedGossip {
    /// Refuse a gossip connection from a node with no live admission — close it
    /// and warn — before delegating to [`Gossip`]. An admitted peer's
    /// connection is tracked in the registry first, so evicting the peer later
    /// tears this connection down with it.
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        todo!("is_admitted(remote_id)? attach_conn + delegate : close + warn")
    }

    /// Shut the wrapped gossip down with the router.
    async fn shutdown(&self) {
        todo!("delegate to the inner gossip handler")
    }
}

/// The responder half of the admission handshake over an established,
/// already-authenticated bi-stream (the [`serve_session`]-style split that makes
/// the exchange testable over an in-memory duplex, with no QUIC).
///
/// Reads the peer's `Request`, re-loads the head from
/// [`AdmitHandler::head`], runs [`check_topic_admission`] against the
/// iroh-authenticated `caller`, persists any adopted head through
/// [`AdmitHandler::persist_head`], records the peer in
/// [`AdmitHandler::admitted`], and answers with an `Ack` carrying this node's
/// own head and proof so the dialer can gate us in turn.
///
/// On refusal it writes a `Denied` frame carrying the reason and returns the
/// error; on success it returns the [`Admission`] it recorded. `caller` must
/// already be authenticated by whoever supplied the streams — this function
/// takes it on trust, exactly as [`crate::transport`] does.
///
/// Frames are bounded by the codec, not by this reader: an over-long length
/// prefix is rejected at [`library::MAX_ADMIT_FRAME`] on decode, which matters
/// here more than anywhere else because this is the one surface that must read
/// a whole frame *before* it can decide anything (spec §2.1).
pub async fn serve_admission<S, R>(
    send: S,
    recv: R,
    caller: NodeId,
    handler: &AdmitHandler,
    now_unix: i64,
) -> Result<Admission>
where
    S: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    todo!("read Request; check_topic_admission; persist; insert; write Ack or Denied")
}

/// The dialer half: send a `Request` bearing this node's head and proof, then
/// verify the responder's `Ack` with the same [`check_topic_admission`].
///
/// Mutual in one round trip — the dialer gates the responder just as hard as
/// the responder gates the dialer, so joining a topic cannot be used to attach
/// to a node outside the fabric. On success the responder is recorded in
/// [`AdmitHandler::admitted`] and any newer head it presented is persisted
/// through the same compare-and-swap; a `Denied` frame comes back as an error
/// carrying the responder's stated reason, which the CLI reports the way
/// `connect` reports a refusal (exit 77).
pub async fn request_admission<S, R>(
    send: S,
    recv: R,
    responder: NodeId,
    handler: &AdmitHandler,
    now_unix: i64,
) -> Result<Admission>
where
    S: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    todo!("write Request; read Ack or Denied; check_topic_admission; persist; insert")
}

/// Dial `peer` on the admit ALPN and run [`request_admission`] over a fresh
/// bi-stream.
///
/// The address hints in [`TopicPeer`] are only hints — iroh still authenticates
/// the far side to `peer.node`, which is why an unsigned [`TopicTicket`](library::TopicTicket)
/// is safe to pass around: a tampered one can fail to connect, never admit.
pub async fn admit_peer(
    endpoint: &Endpoint,
    handler: &AdmitHandler,
    peer: &TopicPeer,
    now_unix: i64,
) -> Result<Admission> {
    todo!("endpoint_addr + connect on TOPIC_ADMIT_ALPN; open_bi; request_admission")
}

/// Spawn the admission watchdog: every `interval`, re-load the head and re-check
/// every stored admission against it, evicting the ones that no longer verify.
///
/// This is the mechanism behind "mesh eviction within one interval" in the
/// module docs. `interval` is a parameter, not [`ADMIT_RECHECK`], so the
/// eviction test can run the loop in milliseconds; the CLI passes the constant.
///
/// The task runs until the handle is dropped or aborted. A head that cannot be
/// loaded is a *fail-closed* event — the [`HeadSource`] contract — and is
/// logged and treated as "admit nobody" rather than skipped, so a deleted head
/// file cannot silently freeze the allowlist in place.
pub fn spawn_watchdog(
    handler: Arc<AdmitHandler>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    todo!("tokio::spawn an interval loop over admitted.snapshot()")
}

/// Write one length-prefixed [`AdmitFrame`](library::AdmitFrame).
async fn write_admit_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    frame: &library::AdmitFrame,
) -> Result<()> {
    todo!("encode and write_all")
}

/// Read one length-prefixed [`AdmitFrame`](library::AdmitFrame), or `None` at a
/// clean end of stream. The codec refuses an over-long length prefix, so a peer
/// that has presented no credential yet cannot make this buffer without bound.
async fn read_admit_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<library::AdmitFrame>> {
    todo!("read the length prefix, then the body, then decode")
}

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
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use iroh::Endpoint;
use iroh::endpoint::{Connection, VarInt};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh_gossip::net::Gossip;
use library::{
    Admission, AdmitFrame, InclusionProof, NodeId, RosterHead, RosterVersion, TopicId, TopicPeer,
    check_roster_inclusion, check_topic_admission,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::keystore::Keystore;
use crate::transport::{Denied, HeadSource, to_node_id};

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

/// The QUIC application error code this gate closes connections with, so a peer
/// can tell a policy refusal apart from a transport failure.
const CLOSE_NOT_ADMITTED: u32 = 1;

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

    /// The map, recovering from a poisoned lock.
    ///
    /// A panic in one connection task must not turn the gate into a permanent
    /// error: the map's invariants are not broken by an unwind (every mutation
    /// is a single insert or remove), so the honest response to poisoning is to
    /// keep gating rather than to take the whole node down.
    fn guard(&self) -> MutexGuard<'_, HashMap<NodeId, AdmittedPeer>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether `peer` currently holds an unexpired admission.
    ///
    /// `now_unix` is passed in rather than read from the clock so the expiry
    /// edge is testable.
    pub fn is_admitted(&self, peer: NodeId, now_unix: i64) -> bool {
        self.guard()
            .get(&peer)
            .is_some_and(|entry| now_unix <= entry.expires)
    }

    /// Record (or replace) `peer`'s admission. A re-admission supersedes the
    /// old entry's credential while keeping its tracked connections alive: the
    /// peer proved itself again, so nothing needs to be torn down.
    pub fn insert(&self, peer: NodeId, mut entry: AdmittedPeer) {
        let mut map = self.guard();
        if let Some(previous) = map.remove(&peer) {
            entry.conns.extend(previous.conns);
        }
        map.insert(peer, entry);
    }

    /// Remove `peer` and close every connection tracked for it.
    ///
    /// Closing is the point. Dropping the entry alone would leave a revoked
    /// member's existing gossip connection in place — the gate is on *accept*,
    /// so a connection already through it is never re-checked.
    pub fn evict(&self, peer: NodeId) {
        let Some(entry) = self.guard().remove(&peer) else {
            return;
        };
        for conn in &entry.conns {
            conn.close(VarInt::from_u32(CLOSE_NOT_ADMITTED), b"admission revoked");
        }
    }

    /// Track `conn` against an admitted `peer` so a later eviction closes it.
    /// A connection from a peer that is not admitted is not tracked.
    pub fn attach_conn(&self, peer: NodeId, conn: Connection) {
        if let Some(entry) = self.guard().get_mut(&peer) {
            entry.conns.push(conn);
        }
    }

    /// A snapshot of every admission as `(peer, version, proof)`, for the
    /// watchdog to re-check without holding the lock across its work.
    pub fn snapshot(&self) -> Vec<(NodeId, RosterVersion, InclusionProof)> {
        let mut out: Vec<_> = self
            .guard()
            .iter()
            .map(|(peer, entry)| (*peer, entry.version, entry.proof.clone()))
            .collect();
        out.sort_by_key(|(peer, _, _)| *peer);
        out
    }

    /// The admitted peers, in id order — the dial set for replay catch-up.
    pub fn peers(&self) -> Vec<NodeId> {
        let mut out: Vec<NodeId> = self.guard().keys().copied().collect();
        out.sort();
        out
    }

    /// The peers whose admission has lapsed at `now_unix`, in id order.
    ///
    /// [`is_admitted`](Self::is_admitted) already refuses them at the gate; this
    /// is what lets the watchdog also *close* what a lapsed admission left
    /// attached, instead of leaving the connection up until the peer hangs up.
    fn expired(&self, now_unix: i64) -> Vec<NodeId> {
        let mut out: Vec<NodeId> = self
            .guard()
            .iter()
            .filter(|(_, entry)| now_unix > entry.expires)
            .map(|(peer, _)| *peer)
            .collect();
        out.sort();
        out
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
    ///
    /// The *startup* proof — the floor, not the last word. Every handshake asks
    /// [`load_proof`](Self::load_proof) instead, which prefers a newer one from
    /// the keystore, for the reason spelled out there.
    pub proof: InclusionProof,
    /// Where an adopted head is persisted (`roster-head.json`).
    ///
    /// **Must be the same file [`head`](Self::head) reads.** Passive head
    /// distribution (§2.2) only works if the head this writes is the head the
    /// next admission loads: pair this with [`HeadSource::Keystore`] over this
    /// keystore's `roster-head.json`. A `HeadSource::File` pointed elsewhere
    /// makes every adoption a write nobody reads, and a pinned
    /// `HeadSource::Fixed` (`--roster-head` / `$WIRES_ROSTER_HEAD`) deliberately
    /// overrides the file for the process's life — adoptions are still recorded
    /// for the *next* run, but do not take effect in this one.
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
    /// With no head stored at all there is nothing to compare against, so the
    /// candidate is held to the other half of the same predicate — it must
    /// verify under the fabric root and still be fresh — before it becomes the
    /// first stored head.
    ///
    /// Synchronous on purpose: the whole sequence is filesystem work, and a
    /// lock held across an await is how the "one exclusive lock" obligation
    /// gets quietly broken.
    pub fn persist_head(
        &self,
        candidate: &RosterHead,
        now_unix: i64,
    ) -> Result<Option<RosterHead>> {
        let _guard = self
            .head_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let stored = self
            .keystore
            .read_roster_head()
            .context("re-reading the stored roster head")?;
        let adopted = match &stored {
            Some(stored) => library::adopt_if_newer(stored, candidate, self.fabric_root, now_unix),
            None => {
                let usable =
                    candidate.verify(self.fabric_root).is_ok() && now_unix <= candidate.not_after;
                usable.then(|| candidate.clone())
            }
        };
        if let Some(head) = &adopted {
            self.keystore
                .save_roster_head(head)
                .context("persisting the adopted roster head")?;
            tracing::info!(
                version = head.version.0,
                previous = ?stored.as_ref().map(|h| h.version.0),
                "adopted a newer roster head presented at admission"
            );
        }
        Ok(adopted)
    }

    /// The expiry to record for an admission decided now against `head`:
    /// `min(now_unix + ADMIT_TTL, head.not_after)`.
    pub fn expiry(&self, head: &RosterHead, now_unix: i64) -> i64 {
        now_unix
            .saturating_add(ADMIT_TTL.as_secs() as i64)
            .min(head.not_after)
    }

    /// Resolve the head to decide against right now, failing closed.
    ///
    /// Topic admission is inclusion-only: with no head there is nothing to
    /// check a proof against, so "no head configured" is a refusal, not the
    /// membership-only fallback [`HeadSource::None`] means for `wires serve`.
    fn load_head(&self) -> Result<RosterHead> {
        match self.head.load()? {
            Some(head) => Ok(head),
            None => bail!("no roster head available; topic admission requires one"),
        }
    }

    /// This node's own inclusion proof to present right now: the keystore's, if
    /// it is for a strictly newer roster version than the one this handler
    /// started with, and the startup proof otherwise.
    ///
    /// **The mirror of [`load_head`](Self::load_head), and needed for the same
    /// reason.** Every `roster commit` invalidates *every* member's proof,
    /// including the survivors' — so the commit that removes one member hands
    /// each of the others a new `<node-id>.proof`, and `wires import` installs
    /// it. A resident `wires tail` that kept presenting the proof it read at
    /// startup would pair a freshly re-read head with a proof issued against
    /// the previous one, and the far side is right to refuse that: `stale
    /// inclusion proof: proof targets version 1, head is version 2`. The effect
    /// was that after any commit, a running tail could no longer be admitted by
    /// *anyone* until it was restarted — which is precisely the restart the
    /// revocation story (spec §2.4) claims not to need.
    ///
    /// Only *forward*: a keystore proof for an older version is ignored, so a
    /// pinned `--inclusion-proof` still wins over a stale file, and a keystore
    /// that has been rolled back cannot walk this node's credential backwards.
    /// A proof issued to some other node is ignored too — presenting it would
    /// be a refusal on the far side at best, since admission binds the proof to
    /// the connection's authenticated key.
    ///
    /// Failing to read the keystore is not fatal here: the startup proof is
    /// still a real credential, and a handshake attempted with it beats no
    /// handshake at all.
    fn load_proof(&self) -> InclusionProof {
        match self.keystore.read_inclusion_proof() {
            Ok(Some(fresh))
                if fresh.version > self.proof.version && fresh.member == self.proof.member =>
            {
                fresh
            }
            Ok(_) => self.proof.clone(),
            Err(e) => {
                tracing::warn!("re-reading this node's inclusion proof: {e:#}");
                self.proof.clone()
            }
        }
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
        let caller = to_node_id(&connection.remote_id());
        let (send, recv) = connection
            .accept_bi()
            .await
            .map_err(AcceptError::from_err)?;
        match serve_admission(send, recv, caller, self, crate::now_unix()).await {
            Ok(admission) => {
                // Tracked *after* the decision, so a refused peer never leaves
                // a connection in the registry — and kept alive by this task
                // until the peer hangs up or an eviction closes it.
                self.admitted.attach_conn(caller, connection.clone());
                tracing::info!(
                    caller = %caller.hex(),
                    version = admission.version.0,
                    "admitted to topic"
                );
                connection.closed().await;
            }
            Err(e) => {
                tracing::warn!(caller = %caller.hex(), "admission refused: {e:#}");
                // Give the peer a moment to read the `Denied` frame; dropping
                // the connection here would discard it, which is exactly the
                // silent failure the frame exists to replace.
                let _ = tokio::time::timeout(Duration::from_secs(5), connection.closed()).await;
            }
        }
        Ok(())
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
        let peer = to_node_id(&connection.remote_id());
        if !self.admitted.is_admitted(peer, crate::now_unix()) {
            tracing::warn!(
                peer = %peer.hex(),
                "gossip connection from a peer with no admission; closing"
            );
            connection.close(
                VarInt::from_u32(CLOSE_NOT_ADMITTED),
                b"not admitted to this topic",
            );
            return Err(AcceptError::from_boxed(
                anyhow!("peer {} is not admitted to this topic", peer.hex()).into(),
            ));
        }
        self.admitted.attach_conn(peer, connection.clone());
        self.inner.accept(connection).await
    }

    /// Shut the wrapped gossip down with the router.
    async fn shutdown(&self) {
        ProtocolHandler::shutdown(&self.inner).await;
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
///
/// [`serve_session`]: crate::transport
pub async fn serve_admission<S, R>(
    mut send: S,
    mut recv: R,
    caller: NodeId,
    handler: &AdmitHandler,
    now_unix: i64,
) -> Result<Admission>
where
    S: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    let (topic, presented, proof) = match read_admit_frame(&mut recv).await? {
        Some(AdmitFrame::Request { topic, head, proof }) => (topic, head, proof),
        // A peer is on the other end and spoke out of turn (or hung up): say so
        // on the wire before failing, so it need not guess.
        Some(_) => {
            let e = anyhow!("first frame was not an admission request");
            deny(&mut send, format!("{e:#}")).await;
            return Err(e);
        }
        None => {
            let e = anyhow!("connection closed before the admission request");
            deny(&mut send, format!("{e:#}")).await;
            return Err(e);
        }
    };
    if topic != handler.topic {
        let e = anyhow!("admission request names a different topic");
        deny(&mut send, format!("{e:#}")).await;
        return Err(e);
    }

    // Re-read the head for *this* admission, so a `wires import` between two
    // handshakes applies to the second one. A source we cannot read is fatal
    // here, and the caller is told only that we are misconfigured — never the
    // path, which would hand an unauthenticated peer our filesystem layout.
    let local = match handler.load_head() {
        Ok(head) => head,
        Err(e) => {
            tracing::warn!("roster head unusable: {e:#}");
            deny(&mut send, "responder configuration error".to_string()).await;
            return Err(e.context("loading the roster head"));
        }
    };

    let admission = match check_topic_admission(
        &local,
        &presented,
        &proof,
        handler.fabric_root,
        caller,
        now_unix,
    ) {
        Ok(admission) => admission,
        Err(e) => {
            let reason = format!("roster inclusion rejected: {e}");
            deny(&mut send, reason.clone()).await;
            return Err(anyhow!(reason));
        }
    };

    // The head the decision was made under — which is the presented one exactly
    // when it was an advance. Persisting is a separate compare-and-swap that may
    // find an even newer head already stored; that does not retroactively change
    // what this peer proved itself against.
    let decided_under = if admission.adopt.is_some() {
        &presented
    } else {
        &local
    };
    if let Some(candidate) = &admission.adopt
        && let Err(e) = handler.persist_head(candidate, now_unix)
    {
        tracing::warn!("cannot persist the adopted roster head: {e:#}");
        deny(&mut send, "responder configuration error".to_string()).await;
        return Err(e.context("persisting the adopted roster head"));
    }

    handler.admitted.insert(
        caller,
        AdmittedPeer {
            proof,
            version: admission.version,
            expires: handler.expiry(decided_under, now_unix),
            conns: Vec::new(),
        },
    );

    // Present the head our *own* proof was issued against, not the one we may
    // have just adopted: adopting a peer's newer head does not give us a proof
    // under it, and an ack pairing a new head with an old proof is a refusal
    // waiting to happen on the far side.
    write_admit_frame(
        &mut send,
        &AdmitFrame::Ack {
            topic: handler.topic,
            head: local,
            proof: handler.load_proof(),
        },
    )
    .await?;
    Ok(admission)
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
    mut send: S,
    mut recv: R,
    responder: NodeId,
    handler: &AdmitHandler,
    now_unix: i64,
) -> Result<Admission>
where
    S: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    // Fails closed on our side too: without a head we cannot judge the ack, and
    // an unjudged ack is an ungated peer.
    let local = handler
        .load_head()
        .context("loading the roster head to present")?;
    write_admit_frame(
        &mut send,
        &AdmitFrame::Request {
            topic: handler.topic,
            head: local.clone(),
            proof: handler.load_proof(),
        },
    )
    .await?;

    let (topic, presented, proof) = match read_admit_frame(&mut recv).await? {
        Some(AdmitFrame::Ack { topic, head, proof }) => (topic, head, proof),
        Some(AdmitFrame::Denied { reason }) => return Err(Denied::new(reason).into()),
        Some(AdmitFrame::Request { .. }) => bail!("responder answered with a request, not an ack"),
        None => bail!("responder closed the connection without answering"),
    };
    if topic != handler.topic {
        bail!("responder acknowledged a different topic");
    }

    let admission = check_topic_admission(
        &local,
        &presented,
        &proof,
        handler.fabric_root,
        responder,
        now_unix,
    )
    .with_context(|| format!("responder {} is not in the roster", responder.hex()))?;

    let decided_under = if admission.adopt.is_some() {
        &presented
    } else {
        &local
    };
    if let Some(candidate) = &admission.adopt {
        handler
            .persist_head(candidate, now_unix)
            .context("persisting the roster head the responder presented")?;
    }
    handler.admitted.insert(
        responder,
        AdmittedPeer {
            proof,
            version: admission.version,
            expires: handler.expiry(decided_under, now_unix),
            conns: Vec::new(),
        },
    );
    Ok(admission)
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
    let addr = crate::transport::endpoint_addr(&peer.node, &peer.addrs, peer.relay_url.as_deref())?;
    let conn = endpoint
        .connect(addr, library::TOPIC_ADMIT_ALPN)
        .await
        .map_err(|e| anyhow!("connecting to {} for admission: {e}", peer.node.hex()))?;
    // Not `peer.node`: what iroh authenticated is the only identity that counts,
    // and the two agree only because the dial succeeded.
    let responder = to_node_id(&conn.remote_id());
    let (send, recv) = conn.open_bi().await.context("opening admission stream")?;
    let admission = request_admission(send, recv, responder, handler, now_unix).await?;
    // Tracked so evicting this peer later closes the connection we opened.
    handler.admitted.attach_conn(responder, conn);
    Ok(admission)
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
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            recheck_admissions(&handler, crate::now_unix());
        }
    })
}

/// One watchdog pass: re-check every stored admission against a freshly loaded
/// head and evict the failures.
///
/// Split out from [`spawn_watchdog`] so the eviction path is asserted directly,
/// with no timer in the test. A head that will not load evicts *everyone*: the
/// alternative — leaving the allowlist as it stands — keeps admitting peers
/// against a head nobody can read.
fn recheck_admissions(handler: &AdmitHandler, now_unix: i64) {
    let head = match handler.load_head() {
        Ok(head) => Some(head),
        Err(e) => {
            tracing::warn!("roster head unusable; evicting every admission: {e:#}");
            None
        }
    };
    for (peer, _version, proof) in handler.admitted.snapshot() {
        let verdict = match &head {
            Some(head) => check_roster_inclusion(head, &proof, handler.fabric_root, peer, now_unix)
                .map_err(|e| e.to_string()),
            None => Err("no usable roster head".to_string()),
        };
        if let Err(reason) = verdict {
            tracing::warn!(peer = %peer.hex(), %reason, "admission no longer holds; evicting");
            handler.admitted.evict(peer);
        }
    }
    // A lapsed TTL is already refused at the gate, but its connections are not:
    // close them here rather than leave a stale peer attached.
    for peer in handler.admitted.expired(now_unix) {
        tracing::warn!(peer = %peer.hex(), "admission expired; evicting");
        handler.admitted.evict(peer);
    }
}

/// Tell the dialer *why* it was refused, then close our side.
///
/// Best-effort, like the session transport's: a peer that already vanished
/// simply never reads it, and the caller still returns the original error.
async fn deny<W: AsyncWrite + Unpin>(send: &mut W, reason: String) {
    let reason = crate::transport::truncate_reason(reason);
    let _ = write_admit_frame(send, &AdmitFrame::Denied { reason }).await;
    send.shutdown().await.ok();
}

/// Write one length-prefixed [`AdmitFrame`](library::AdmitFrame).
async fn write_admit_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    frame: &library::AdmitFrame,
) -> Result<()> {
    let bytes = frame.encode().context("encoding admission frame")?;
    w.write_all(&bytes)
        .await
        .context("writing admission frame")?;
    Ok(())
}

/// Read one length-prefixed [`AdmitFrame`](library::AdmitFrame), or `None` at a
/// clean end of stream. The codec refuses an over-long length prefix, so a peer
/// that has presented no credential yet cannot make this buffer without bound.
async fn read_admit_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<library::AdmitFrame>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("reading admission frame length"),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    // The bound is the codec's, applied before the allocation: this runs before
    // the peer has proved anything at all.
    if len > library::MAX_ADMIT_FRAME {
        bail!(
            "admission frame too large: {len} bytes (max {})",
            library::MAX_ADMIT_FRAME
        );
    }
    let mut full = Vec::with_capacity(4 + len);
    full.extend_from_slice(&len_buf);
    full.resize(4 + len, 0);
    r.read_exact(&mut full[4..])
        .await
        .context("reading admission frame body")?;
    match AdmitFrame::decode(&full)? {
        Some((frame, _)) => Ok(Some(frame)),
        None => bail!("truncated admission frame"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    use library::{NodeIdentity, Roster};

    /// A fresh directory per test, under Bazel's sandboxed temp when present.
    fn temp_dir() -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let base = std::env::var_os("TEST_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = base.join(format!("wires-admit-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The fabric root every fixture signs under.
    fn root() -> NodeIdentity {
        NodeIdentity::from_seed([1u8; 32])
    }

    /// This node (the responder in most tests).
    fn me() -> NodeIdentity {
        NodeIdentity::from_seed([2u8; 32])
    }

    /// The peer being admitted (or refused).
    fn peer() -> NodeIdentity {
        NodeIdentity::from_seed([3u8; 32])
    }

    /// Commit `members` under `root` and return the head plus a proof lookup.
    fn commit(
        roster: &mut Roster,
        root: &NodeIdentity,
    ) -> (RosterHead, HashMap<NodeId, InclusionProof>) {
        let (head, proofs) = roster.commit(root, 0, i64::MAX).unwrap();
        (head, proofs.into_iter().collect())
    }

    /// A roster over `members`, committed once.
    fn roster_of(root: &NodeIdentity, members: &[NodeId]) -> Roster {
        let mut roster = Roster::new(root.node_id());
        for m in members {
            roster.insert(*m);
        }
        roster
    }

    /// A handler whose head source is the keystore's `roster-head.json`, seeded
    /// with `head` — the shape the resident node actually runs, so a test can
    /// advance the head by writing the file.
    fn handler_with(
        dir: &std::path::Path,
        head: &RosterHead,
        proof: InclusionProof,
    ) -> AdmitHandler {
        let keystore = Keystore::at(dir);
        keystore.save_roster_head(head).unwrap();
        AdmitHandler {
            topic: TopicId::derive(root().node_id(), "ops"),
            fabric_root: root().node_id(),
            head: Arc::new(HeadSource::Keystore {
                path: keystore.path("roster-head.json"),
                armed: AtomicBool::new(false),
            }),
            proof,
            keystore: Arc::new(keystore),
            admitted: Admitted::new(),
            head_lock: Arc::new(Mutex::new(())),
        }
    }

    /// The text of the stored `roster-head.json` (the CAS tests compare it).
    fn stored_head_text(dir: &std::path::Path) -> String {
        std::fs::read_to_string(dir.join("roster-head.json")).unwrap()
    }

    /// Drive [`serve_admission`] over a one-shot in-memory pair: the request is
    /// pre-encoded into a cursor, the ack (or denial) lands in a `Vec`.
    async fn serve_once(
        handler: &AdmitHandler,
        caller: NodeId,
        request: AdmitFrame,
        now_unix: i64,
    ) -> (Result<Admission>, Vec<AdmitFrame>) {
        let recv = std::io::Cursor::new(request.encode().unwrap());
        let mut send: Vec<u8> = Vec::new();
        let result = serve_admission(&mut send, recv, caller, handler, now_unix).await;
        (result, decode_all(&send))
    }

    /// Decode every whole frame in `buf`.
    fn decode_all(mut buf: &[u8]) -> Vec<AdmitFrame> {
        let mut out = Vec::new();
        while let Ok(Some((frame, used))) = AdmitFrame::decode(buf) {
            out.push(frame);
            buf = &buf[used..];
        }
        out
    }

    /// The reason text of the single frame a refusal wrote.
    fn denial_reason(frames: &[AdmitFrame]) -> String {
        match frames {
            [AdmitFrame::Denied { reason }] => reason.clone(),
            other => panic!("expected exactly one Denied frame, got {other:?}"),
        }
    }

    // ------------------------------------------------------------- registry

    #[test]
    fn admissions_expire_at_their_recorded_deadline() {
        let admitted = Admitted::new();
        let mut roster = roster_of(&root(), &[peer().node_id()]);
        let (head, proofs) = commit(&mut roster, &root());
        admitted.insert(
            peer().node_id(),
            AdmittedPeer {
                proof: proofs[&peer().node_id()].clone(),
                version: head.version,
                expires: 100,
                conns: Vec::new(),
            },
        );
        assert!(
            admitted.is_admitted(peer().node_id(), 100),
            "the edge is in"
        );
        assert!(!admitted.is_admitted(peer().node_id(), 101));
        assert!(!admitted.is_admitted(me().node_id(), 0), "never admitted");
        assert_eq!(admitted.peers(), vec![peer().node_id()]);

        admitted.evict(peer().node_id());
        assert!(!admitted.is_admitted(peer().node_id(), 0));
        assert!(admitted.peers().is_empty());
        assert!(admitted.snapshot().is_empty());
        // Evicting an unknown peer is a no-op, not a panic.
        admitted.evict(me().node_id());
    }

    #[test]
    fn expiry_is_clamped_to_the_heads_validity_window() {
        let dir = temp_dir();
        let mut roster = roster_of(&root(), &[me().node_id()]);
        let (head, proofs) = commit(&mut roster, &root());
        let handler = handler_with(&dir, &head, proofs[&me().node_id()].clone());

        // The TTL is the binding limit under an effectively immortal head...
        assert_eq!(
            handler.expiry(&head, 1_000),
            1_000 + ADMIT_TTL.as_secs() as i64
        );
        // ...and the head's own window is the binding limit when it is nearer.
        let mut short = head.clone();
        short.not_after = 1_010;
        assert_eq!(handler.expiry(&short, 1_000), 1_010);
    }

    // ------------------------------------------------------------ handshake

    #[tokio::test]
    async fn mutual_admission_admits_both_sides_at_one_version() {
        let (root, me, peer) = (root(), me(), peer());
        let mut roster = roster_of(&root, &[me.node_id(), peer.node_id()]);
        let (head, proofs) = commit(&mut roster, &root);

        let responder_dir = temp_dir();
        let dialer_dir = temp_dir();
        let responder = Arc::new(handler_with(
            &responder_dir,
            &head,
            proofs[&me.node_id()].clone(),
        ));
        let dialer = handler_with(&dialer_dir, &head, proofs[&peer.node_id()].clone());

        let (d2r_w, d2r_r) = tokio::io::duplex(64 * 1024);
        let (r2d_w, r2d_r) = tokio::io::duplex(64 * 1024);
        let served = {
            let responder = Arc::clone(&responder);
            let caller = peer.node_id();
            tokio::spawn(async move { serve_admission(r2d_w, d2r_r, caller, &responder, 0).await })
        };
        let dialed = request_admission(d2r_w, r2d_r, me.node_id(), &dialer, 0)
            .await
            .expect("the responder is a member and acked");
        let served = served.await.unwrap().expect("the dialer is a member");

        assert_eq!(dialed.version, head.version);
        assert_eq!(served.version, head.version);
        assert_eq!(dialed.adopt, None, "same head — nothing to adopt");
        assert_eq!(served.adopt, None);
        assert!(responder.admitted.is_admitted(peer.node_id(), 0));
        assert!(dialer.admitted.is_admitted(me.node_id(), 0));
        // Neither side moved a head it already had.
        assert_eq!(stored_head_text(&responder_dir), head.encode().unwrap());
        assert_eq!(stored_head_text(&dialer_dir), head.encode().unwrap());
    }

    #[tokio::test]
    async fn a_non_member_is_denied_with_a_reason() {
        let (root, me) = (root(), me());
        let outsider = NodeIdentity::from_seed([9u8; 32]);
        // The outsider holds a perfectly well-formed proof — from a roster its
        // own root signed. Nothing about it is malformed; it is simply not ours.
        let other_root = NodeIdentity::from_seed([8u8; 32]);
        let mut theirs = roster_of(&other_root, &[outsider.node_id()]);
        let (their_head, their_proofs) = commit(&mut theirs, &other_root);

        let mut roster = roster_of(&root, &[me.node_id()]);
        let (head, proofs) = commit(&mut roster, &root);
        let dir = temp_dir();
        let handler = handler_with(&dir, &head, proofs[&me.node_id()].clone());

        let (result, frames) = serve_once(
            &handler,
            outsider.node_id(),
            AdmitFrame::Request {
                topic: handler.topic,
                head: their_head,
                proof: their_proofs[&outsider.node_id()].clone(),
            },
            0,
        )
        .await;

        assert!(result.is_err(), "an outsider must not be admitted");
        let reason = denial_reason(&frames);
        assert!(
            reason.contains("roster inclusion rejected"),
            "expected a roster-gate denial, got: {reason}"
        );
        assert!(!handler.admitted.is_admitted(outsider.node_id(), 0));
        assert_eq!(
            stored_head_text(&dir),
            head.encode().unwrap(),
            "a foreign head must never be adopted"
        );
    }

    #[tokio::test]
    async fn a_stale_proof_is_denied_naming_both_versions() {
        let (root, me, peer) = (root(), me(), peer());
        let mut roster = roster_of(&root, &[me.node_id(), peer.node_id()]);
        let (v1, v1_proofs) = commit(&mut roster, &root);
        let (v2, v2_proofs) = commit(&mut roster, &root);

        let dir = temp_dir();
        let handler = handler_with(&dir, &v2, v2_proofs[&me.node_id()].clone());

        // The peer is still a member; it just never re-imported its proof.
        let (result, frames) = serve_once(
            &handler,
            peer.node_id(),
            AdmitFrame::Request {
                topic: handler.topic,
                head: v1,
                proof: v1_proofs[&peer.node_id()].clone(),
            },
            0,
        )
        .await;

        assert!(result.is_err());
        let reason = denial_reason(&frames);
        assert!(
            reason.contains("stale inclusion proof")
                && reason.contains("version 1")
                && reason.contains("version 2"),
            "the denial must name both versions so the peer knows to re-import: {reason}"
        );
        assert!(!handler.admitted.is_admitted(peer.node_id(), 0));
    }

    #[tokio::test]
    async fn a_request_for_another_topic_is_refused() {
        let (root, me, peer) = (root(), me(), peer());
        let mut roster = roster_of(&root, &[me.node_id(), peer.node_id()]);
        let (head, proofs) = commit(&mut roster, &root);
        let dir = temp_dir();
        let handler = handler_with(&dir, &head, proofs[&me.node_id()].clone());

        let (result, frames) = serve_once(
            &handler,
            peer.node_id(),
            AdmitFrame::Request {
                topic: TopicId::derive(root.node_id(), "other"),
                head: head.clone(),
                proof: proofs[&peer.node_id()].clone(),
            },
            0,
        )
        .await;

        assert!(result.is_err());
        assert!(denial_reason(&frames).contains("different topic"));
        assert!(!handler.admitted.is_admitted(peer.node_id(), 0));
    }

    #[tokio::test]
    async fn an_unreadable_head_fails_closed_without_naming_the_path() {
        let (root, me, peer) = (root(), me(), peer());
        let mut roster = roster_of(&root, &[me.node_id(), peer.node_id()]);
        let (head, proofs) = commit(&mut roster, &root);
        let dir = temp_dir();
        let handler = handler_with(&dir, &head, proofs[&me.node_id()].clone());
        // The head this responder was enforcing is corrupted under it.
        std::fs::write(dir.join("roster-head.json"), "not-a-token").unwrap();

        let (result, frames) = serve_once(
            &handler,
            peer.node_id(),
            AdmitFrame::Request {
                topic: handler.topic,
                head,
                proof: proofs[&peer.node_id()].clone(),
            },
            0,
        )
        .await;

        assert!(
            result.is_err(),
            "a responder with no usable head admits nobody"
        );
        let reason = denial_reason(&frames);
        assert_eq!(reason, "responder configuration error");
        assert!(
            !reason.contains("roster-head") && !reason.contains(dir.to_str().unwrap()),
            "the refusal must not leak the responder's filesystem layout: {reason}"
        );
        assert!(!handler.admitted.is_admitted(peer.node_id(), 0));
    }

    #[tokio::test]
    async fn a_silent_peer_and_an_out_of_turn_frame_are_both_refused() {
        let (root, me, peer) = (root(), me(), peer());
        let mut roster = roster_of(&root, &[me.node_id(), peer.node_id()]);
        let (head, proofs) = commit(&mut roster, &root);
        let dir = temp_dir();
        let handler = handler_with(&dir, &head, proofs[&me.node_id()].clone());

        // Spoke out of turn: an `Ack` where a `Request` belongs.
        let (result, frames) = serve_once(
            &handler,
            peer.node_id(),
            AdmitFrame::Ack {
                topic: handler.topic,
                head,
                proof: proofs[&peer.node_id()].clone(),
            },
            0,
        )
        .await;
        assert!(result.is_err());
        assert!(denial_reason(&frames).contains("not an admission request"));

        // Hung up without saying anything.
        let mut send: Vec<u8> = Vec::new();
        let result = serve_admission(
            &mut send,
            std::io::Cursor::new(Vec::new()),
            peer.node_id(),
            &handler,
            0,
        )
        .await;
        assert!(result.is_err());
        assert!(denial_reason(&decode_all(&send)).contains("closed before"));
    }

    #[tokio::test]
    async fn an_over_long_length_prefix_is_refused_before_allocating() {
        let mut cursor = std::io::Cursor::new(vec![0xff, 0xff, 0xff, 0xff]);
        let e = read_admit_frame(&mut cursor)
            .await
            .expect_err("4 GiB of unauthenticated buffering must be refused");
        assert!(format!("{e:#}").contains("too large"));
    }

    // -------------------------------------------------- our own credential

    /// The regression behind [`AdmitHandler::load_proof`], found by
    /// `.scripts/demo-topic-revoke.sh`: a resident tail that kept presenting
    /// its startup proof paired it with a freshly re-read head one version
    /// ahead, and every peer correctly refused the mismatch — so a `roster
    /// commit` locked the running tail out of the mesh until it was restarted,
    /// which is the restart spec §2.4 promises is unnecessary.
    #[tokio::test]
    async fn an_imported_newer_proof_is_presented_without_a_restart() {
        let (root, me, peer) = (root(), me(), peer());
        let mut roster = roster_of(&root, &[me.node_id(), peer.node_id()]);
        let (v1, v1_proofs) = commit(&mut roster, &root);
        let (v2, v2_proofs) = commit(&mut roster, &root);

        let dir = temp_dir();
        let handler = handler_with(&dir, &v1, v1_proofs[&me.node_id()].clone());
        assert_eq!(handler.load_proof().version, v1.version, "nothing imported");

        // `wires import --inclusion-proof-file <me>.proof` from the v2 commit.
        handler
            .keystore
            .save_inclusion_proof(&v2_proofs[&me.node_id()])
            .unwrap();
        assert_eq!(
            handler.load_proof().version,
            v2.version,
            "the imported proof must be the one presented"
        );

        // And the far side accepts what we now present: v2 head, v2 proof.
        let theirs = handler_with(&temp_dir(), &v2, v2_proofs[&peer.node_id()].clone());
        let (result, _) = serve_once(
            &theirs,
            me.node_id(),
            AdmitFrame::Request {
                topic: theirs.topic,
                head: v2.clone(),
                proof: handler.load_proof(),
            },
            0,
        )
        .await;
        result.expect("a member presenting its current proof is admitted");
    }

    /// Only forward, and only ours: a keystore proof that is older, or issued
    /// to somebody else, must not displace the one this node started with.
    #[test]
    fn a_stale_or_foreign_keystore_proof_is_ignored() {
        let (root, me, peer) = (root(), me(), peer());
        let mut roster = roster_of(&root, &[me.node_id(), peer.node_id()]);
        let (v1, v1_proofs) = commit(&mut roster, &root);
        let (v2, v2_proofs) = commit(&mut roster, &root);

        let dir = temp_dir();
        let handler = handler_with(&dir, &v2, v2_proofs[&me.node_id()].clone());

        // Rolled back to the previous commit's proof: ignored.
        handler
            .keystore
            .save_inclusion_proof(&v1_proofs[&me.node_id()])
            .unwrap();
        assert_eq!(handler.load_proof().version, v2.version);
        assert_ne!(v1.version, v2.version, "the two commits differ");

        // Another member's proof, however new: ignored. Presenting it would be
        // refused anyway — admission binds the proof to the connection's key —
        // but this node must not try.
        let mut roster3 = roster;
        let (_, v3_proofs) = commit(&mut roster3, &root);
        handler
            .keystore
            .save_inclusion_proof(&v3_proofs[&peer.node_id()])
            .unwrap();
        let presented = handler.load_proof();
        assert_eq!(presented.member, me.node_id());
        assert_eq!(presented.version, v2.version);
    }

    // ------------------------------------------------------- head adoption

    #[tokio::test]
    async fn a_newer_valid_head_is_adopted_and_persisted() {
        let (root, me, peer) = (root(), me(), peer());
        let mut roster = roster_of(&root, &[me.node_id(), peer.node_id()]);
        let (v1, v1_proofs) = commit(&mut roster, &root);
        let (v2, v2_proofs) = commit(&mut roster, &root);

        let dir = temp_dir();
        let handler = handler_with(&dir, &v1, v1_proofs[&me.node_id()].clone());
        let before = stored_head_text(&dir);

        let (result, frames) = serve_once(
            &handler,
            peer.node_id(),
            AdmitFrame::Request {
                topic: handler.topic,
                head: v2.clone(),
                proof: v2_proofs[&peer.node_id()].clone(),
            },
            0,
        )
        .await;

        let admission = result.expect("a member presenting a newer head is admitted");
        assert_eq!(admission.version, v2.version);
        assert_eq!(admission.adopt.as_ref(), Some(&v2));
        assert!(handler.admitted.is_admitted(peer.node_id(), 0));
        assert!(matches!(frames.as_slice(), [AdmitFrame::Ack { .. }]));

        let after = stored_head_text(&dir);
        assert_ne!(before, after, "the adopted head must reach the keystore");
        assert_eq!(after, v2.encode().unwrap());
    }

    #[tokio::test]
    async fn a_newer_forged_head_is_refused_and_never_persisted() {
        let (root, me, peer) = (root(), me(), peer());
        let mut roster = roster_of(&root, &[me.node_id(), peer.node_id()]);
        let (v1, v1_proofs) = commit(&mut roster, &root);

        // An attacker's own root signs a "v9" roster in which it is a member.
        let attacker_root = NodeIdentity::from_seed([7u8; 32]);
        let mut forged = roster_of(&attacker_root, &[peer.node_id()]);
        let (mut forged_head, forged_proofs) = loop {
            let (head, proofs) = commit(&mut forged, &attacker_root);
            if head.version.0 >= 9 {
                break (head, proofs);
            }
        };
        // ...and relabels it as *our* fabric's, which the signature does not
        // survive: `RosterHead::verify` pins the fabric field it signed.
        forged_head.fabric = root.node_id();

        let dir = temp_dir();
        let handler = handler_with(&dir, &v1, v1_proofs[&me.node_id()].clone());
        let before = stored_head_text(&dir);

        let (result, frames) = serve_once(
            &handler,
            peer.node_id(),
            AdmitFrame::Request {
                topic: handler.topic,
                head: forged_head,
                proof: forged_proofs[&peer.node_id()].clone(),
            },
            0,
        )
        .await;

        assert!(result.is_err(), "an unsigned head advance must not admit");
        assert!(denial_reason(&frames).contains("roster inclusion rejected"));
        assert_eq!(
            stored_head_text(&dir),
            before,
            "a forged head must never be persisted"
        );
        assert!(!handler.admitted.is_admitted(peer.node_id(), 0));
    }

    #[tokio::test]
    async fn an_equal_version_head_admits_and_persists_nothing() {
        let (root, me, peer) = (root(), me(), peer());
        let mut roster = roster_of(&root, &[me.node_id(), peer.node_id()]);
        let (head, proofs) = commit(&mut roster, &root);
        let dir = temp_dir();
        let handler = handler_with(&dir, &head, proofs[&me.node_id()].clone());
        let before = stored_head_text(&dir);

        let (result, frames) = serve_once(
            &handler,
            peer.node_id(),
            AdmitFrame::Request {
                topic: handler.topic,
                head: head.clone(),
                proof: proofs[&peer.node_id()].clone(),
            },
            0,
        )
        .await;

        let admission = result.expect("the same head admits a member");
        assert_eq!(admission.version, head.version);
        assert_eq!(admission.adopt, None);
        assert!(matches!(frames.as_slice(), [AdmitFrame::Ack { .. }]));
        assert_eq!(stored_head_text(&dir), before, "nothing to write");
    }

    /// The compare-and-swap of spec §2.2, at the level it actually bites: two
    /// admissions read the same stored head, and the one holding the *older*
    /// advance lands second. A plain read-modify-write would roll the node back
    /// onto a roster the attacker is still a member of — and, worse, defeat the
    /// watchdog, which re-checks against whatever is stored.
    #[test]
    fn a_late_older_writer_cannot_roll_the_stored_head_back() {
        let (root, me) = (root(), me());
        let mut roster = roster_of(&root, &[me.node_id()]);
        let (v1, v1_proofs) = commit(&mut roster, &root);
        let (v2, _) = commit(&mut roster, &root);
        let (v3, _) = commit(&mut roster, &root);

        // v3 lands first; the writer still holding v2 finds it is no longer an
        // advance and writes nothing.
        let dir = temp_dir();
        let handler = handler_with(&dir, &v1, v1_proofs[&me.node_id()].clone());
        assert_eq!(handler.persist_head(&v3, 0).unwrap().as_ref(), Some(&v3));
        assert_eq!(handler.persist_head(&v2, 0).unwrap(), None);
        assert_eq!(stored_head_text(&dir), v3.encode().unwrap());

        // The other interleaving reaches the same place: both advances are
        // taken, in order, and the highest one is what is stored.
        let dir = temp_dir();
        let handler = handler_with(&dir, &v1, v1_proofs[&me.node_id()].clone());
        assert_eq!(handler.persist_head(&v2, 0).unwrap().as_ref(), Some(&v2));
        assert_eq!(handler.persist_head(&v3, 0).unwrap().as_ref(), Some(&v3));
        assert_eq!(stored_head_text(&dir), v3.encode().unwrap());
    }

    /// The same race driven through two real [`serve_admission`] calls sharing
    /// one keystore and one head lock: whichever completes last, the stored head
    /// is the newest one either peer presented.
    #[tokio::test]
    async fn racing_admissions_settle_on_the_newest_head() {
        let (root, me, peer) = (root(), me(), peer());
        let other = NodeIdentity::from_seed([4u8; 32]);
        let mut roster = roster_of(&root, &[me.node_id(), peer.node_id(), other.node_id()]);
        let (v3, v3_proofs) = commit(&mut roster, &root);
        let (v4, v4_proofs) = commit(&mut roster, &root);
        let (v5, v5_proofs) = commit(&mut roster, &root);

        for reversed in [false, true] {
            let dir = temp_dir();
            let handler = handler_with(&dir, &v3, v3_proofs[&me.node_id()].clone());

            let newer = serve_once(
                &handler,
                peer.node_id(),
                AdmitFrame::Request {
                    topic: handler.topic,
                    head: v5.clone(),
                    proof: v5_proofs[&peer.node_id()].clone(),
                },
                0,
            );
            let older = serve_once(
                &handler,
                other.node_id(),
                AdmitFrame::Request {
                    topic: handler.topic,
                    head: v4.clone(),
                    proof: v4_proofs[&other.node_id()].clone(),
                },
                0,
            );
            // Both orderings, because the attacker picks its own dial timing.
            if reversed {
                let (older, newer) = tokio::join!(older, newer);
                assert!(newer.0.is_ok(), "the v5 peer is a member under v5");
                drop(older);
            } else {
                let (newer, older) = tokio::join!(newer, older);
                assert!(newer.0.is_ok());
                drop(older);
            }

            assert_eq!(
                stored_head_text(&dir),
                v5.encode().unwrap(),
                "the stored head must be a highest-seen watermark (reversed={reversed})"
            );
        }
    }

    #[test]
    fn a_first_head_is_adopted_only_if_it_verifies() {
        let (root, me) = (root(), me());
        let mut roster = roster_of(&root, &[me.node_id()]);
        let (v1, v1_proofs) = commit(&mut roster, &root);

        // A handler whose keystore has no `roster-head.json` at all.
        let dir = temp_dir();
        let handler = handler_with(&dir, &v1, v1_proofs[&me.node_id()].clone());
        std::fs::remove_file(dir.join("roster-head.json")).unwrap();

        // Expired: the root's window is authoritative, so it is not adopted.
        let mut expired = v1.clone();
        expired.not_after = 10;
        assert_eq!(handler.persist_head(&expired, 11).unwrap(), None);
        assert!(!dir.join("roster-head.json").exists());

        // Forged: no signature of ours, no adoption.
        let mut forged = v1.clone();
        forged.version = RosterVersion(99);
        assert_eq!(handler.persist_head(&forged, 0).unwrap(), None);
        assert!(!dir.join("roster-head.json").exists());

        // Genuine: becomes the first stored head.
        assert_eq!(handler.persist_head(&v1, 0).unwrap().as_ref(), Some(&v1));
        assert_eq!(stored_head_text(&dir), v1.encode().unwrap());
    }

    // ----------------------------------------------------------- watchdog

    /// The revocation money shot at the unit level: a peer admitted under v1 is
    /// evicted once the node holds the v2 head that removed it — no dial from
    /// the peer required, and its tracked connections go with it.
    #[tokio::test]
    async fn the_watchdog_evicts_a_peer_the_head_no_longer_includes() {
        let (root, me, peer) = (root(), me(), peer());
        let mut roster = roster_of(&root, &[me.node_id(), peer.node_id()]);
        let (v1, v1_proofs) = commit(&mut roster, &root);

        let dir = temp_dir();
        let handler = handler_with(&dir, &v1, v1_proofs[&me.node_id()].clone());
        let (result, _) = serve_once(
            &handler,
            peer.node_id(),
            AdmitFrame::Request {
                topic: handler.topic,
                head: v1.clone(),
                proof: v1_proofs[&peer.node_id()].clone(),
            },
            0,
        )
        .await;
        result.expect("admitted under v1");
        assert!(handler.admitted.is_admitted(peer.node_id(), 0));

        // A pass against the head it was admitted under changes nothing.
        recheck_admissions(&handler, 0);
        assert!(handler.admitted.is_admitted(peer.node_id(), 0));

        // The root removes the peer and the new head lands in the keystore.
        roster.remove(&peer.node_id());
        let (v2, _) = commit(&mut roster, &root);
        handler.keystore.save_roster_head(&v2).unwrap();

        recheck_admissions(&handler, 0);
        assert!(
            !handler.admitted.is_admitted(peer.node_id(), 0),
            "the removed member must be out of the mesh"
        );
        assert!(handler.admitted.peers().is_empty());
        assert!(handler.admitted.snapshot().is_empty());
    }

    #[tokio::test]
    async fn the_watchdog_evicts_everyone_when_the_head_stops_loading() {
        let (root, me, peer) = (root(), me(), peer());
        let mut roster = roster_of(&root, &[me.node_id(), peer.node_id()]);
        let (v1, v1_proofs) = commit(&mut roster, &root);
        let dir = temp_dir();
        let handler = handler_with(&dir, &v1, v1_proofs[&me.node_id()].clone());
        let (result, _) = serve_once(
            &handler,
            peer.node_id(),
            AdmitFrame::Request {
                topic: handler.topic,
                head: v1,
                proof: v1_proofs[&peer.node_id()].clone(),
            },
            0,
        )
        .await;
        result.expect("admitted under v1");

        // The head the gate depends on is deleted out from under it.
        std::fs::remove_file(dir.join("roster-head.json")).unwrap();
        recheck_admissions(&handler, 0);
        assert!(
            handler.admitted.peers().is_empty(),
            "an unreadable head must not freeze the allowlist in place"
        );
    }

    #[tokio::test]
    async fn the_watchdog_evicts_a_lapsed_admission() {
        let (root, me, peer) = (root(), me(), peer());
        let mut roster = roster_of(&root, &[me.node_id(), peer.node_id()]);
        let (v1, v1_proofs) = commit(&mut roster, &root);
        let dir = temp_dir();
        let handler = handler_with(&dir, &v1, v1_proofs[&me.node_id()].clone());
        handler.admitted.insert(
            peer.node_id(),
            AdmittedPeer {
                proof: v1_proofs[&peer.node_id()].clone(),
                version: v1.version,
                expires: 100,
                conns: Vec::new(),
            },
        );

        // Still a member — but the admission itself has run out.
        recheck_admissions(&handler, 101);
        assert!(handler.admitted.peers().is_empty());
    }

    /// The spawned task does what the direct call does, at an injected interval
    /// measured in milliseconds. Nothing in this suite waits [`ADMIT_RECHECK`].
    #[tokio::test]
    async fn the_spawned_watchdog_evicts_on_its_own_interval() {
        let (root, me, peer) = (root(), me(), peer());
        let mut roster = roster_of(&root, &[me.node_id(), peer.node_id()]);
        let (v1, v1_proofs) = commit(&mut roster, &root);
        let dir = temp_dir();
        let handler = Arc::new(handler_with(&dir, &v1, v1_proofs[&me.node_id()].clone()));
        handler.admitted.insert(
            peer.node_id(),
            AdmittedPeer {
                proof: v1_proofs[&peer.node_id()].clone(),
                version: v1.version,
                expires: i64::MAX,
                conns: Vec::new(),
            },
        );

        roster.remove(&peer.node_id());
        let (v2, _) = commit(&mut roster, &root);
        handler.keystore.save_roster_head(&v2).unwrap();

        let task = spawn_watchdog(Arc::clone(&handler), Duration::from_millis(5));
        for _ in 0..200 {
            if handler.admitted.peers().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        task.abort();
        assert!(
            handler.admitted.peers().is_empty(),
            "the watchdog must evict within its own interval of the head landing"
        );
    }
}

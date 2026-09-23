//! Peer-symmetric catch-up: the `wires/topic-replay/1` server, the `catch_up`
//! client loop, and the ingest path both of them and the live mesh share
//! (spec §6.2).
//!
//! Gossip only carries what is happening now. Everything else — history from
//! before a node joined, the messages it missed while its laptop was shut, the
//! run behind a chain gap — arrives by *asking*: one bidirectional stream to an
//! admitted peer, a [`ReplayFrame::Request`](library::ReplayFrame) carrying this
//! node's high-water marks, a run of `Item`s back, then `End`.
//!
//! There is no host. Every `wires tail` runs [`ReplayHandler`] and every
//! `wires tail` runs [`catch_up`], so the node that has the history is whichever
//! one happens to have it. Nobody is a required participant.
//!
//! # Admission is the gate here too
//!
//! [`ReplayHandler`] consults the **same** [`Admitted`] registry as the gossip
//! wrapper, and refuses a requester that is not in it with a `Denied` frame
//! naming the reason. Without that, replay would be a side door around the
//! roster: the mesh would be gated and the entire history readable by anyone who
//! guessed a topic id. Serving is the more sensitive direction — a live mesh
//! leaks only what is said next, while a replay server hands over everything it
//! has — so the gate is checked before a single `Item` is written.
//!
//! Confidentiality does not rest on it: items are sealed under the fabric key,
//! and a peer without the key learns ciphertext. But it is the difference
//! between "your history is encrypted" and "your history is not handed out".
//!
//! # The hash in the high-water mark
//!
//! A request carries a [`ChainState`](library::ChainState) per publisher — a
//! sequence number **and the hash at it**, not just a number. The server checks
//! the presented hash against its own [`hash_at`](crate::store::TopicStore::hash_at),
//! and on a mismatch streams that publisher **from genesis** so the requester's
//! [`classify_link`](library::classify_link) reports a `Fork` instead of quietly
//! resuming from a divergent point. The PoC never checked, and divergence was
//! invisible.
//!
//! # Gaps, and the debounce
//!
//! A live message that lands ahead of its publisher's chain is a `Gap`. It is
//! **not** stored — storing it would either hide the hole (if the mark advanced
//! over it) or strand it (if it did not) — it is dropped, and a catch-up is
//! scheduled [`REPLAY_DEBOUNCE`] later. Replay fills the run, the dropped
//! message arrives again as an `Item`, and the chain heals in order. The delay
//! is a coalescing window: a burst of out-of-order deliveries is one pass, not
//! one pass per message.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::{Connection, VarInt};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr};
use library::{
    ChainState, LinkStatus, NodeId, ReplayFrame, Seq, TopicEnvelope, TopicId, classify_link,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::admission::{AdmitHandler, Admitted};
use crate::store::{Appended, TopicStore};
use crate::transport::{Denied, to_node_id};

/// How long a detected chain gap waits before triggering a catch-up pass.
///
/// The resident tail's own constant: `run_tail` folds a gap, a new neighbor, a
/// lag, and a successful redial into one pending catch-up deadline, so the
/// window coalesces every reason to replay rather than only this one. Tests
/// that need a fast window run their own ingest loop with their own duration —
/// there is deliberately no injectable knob here, because a debounce nothing
/// but a test reads is a knob that lies.
///
/// Two seconds is chosen to coalesce, not to be quick: reordered deliveries
/// arrive within milliseconds of each other, so one window swallows a burst,
/// and the cost of waiting is bounded — the messages are already in the
/// publisher's log and are re-offered by the very pass this schedules.
pub const REPLAY_DEBOUNCE: Duration = Duration::from_secs(2);

/// How many items a replay pass streams before ending, in either direction: the
/// server's cap on one response and the requester's `limit` hint.
///
/// A cap rather than "everything" because the requester loops until a pass adds
/// nothing — bounded passes keep one enormous history from monopolizing a
/// stream, and make progress visible between them. Also **injectable**, through
/// [`TopicNodeConfig::replay_limit`](crate::topics::TopicNodeConfig::replay_limit).
pub const REPLAY_LIMIT: u32 = 512;

/// How long one replay pass against one peer may take, dial included.
///
/// A pass is a request and a bounded run of items, so a peer that has anything
/// to say says it quickly. Without a deadline, an admitted peer that opens the
/// stream and then dribbles — or says nothing at all while its QUIC stack keeps
/// the connection alive — pins the catch-up task forever, and with it every
/// later catch-up (the tail runs one call at a time).
pub const REPLAY_PASS_TIMEOUT: Duration = Duration::from_secs(20);

/// How much of [`REPLAY_PASS_TIMEOUT`] the dial and the stream open may take.
///
/// A peer that is there answers a dial in well under a second over a known
/// path (replay is only asked of admitted peers, so the endpoint already has
/// one). A peer that is *gone* — a one-shot publisher that exited without its
/// close reaching us, a laptop that went to sleep — never answers, and waiting
/// the whole pass timeout for it only fills the log with 20 s timeouts. The
/// rest of the pass keeps the full budget.
pub const REPLAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The whole [`catch_up`] call's budget, across every peer and every round.
///
/// The loop's termination condition ("a round that inserted nothing") is
/// attacker-controlled: a peer with one genuinely new, correctly chained
/// envelope to hand over on every round keeps it productive forever. The budget
/// and [`MAX_CATCH_UP_ROUNDS`] are what make the call finite regardless; what
/// is left over is picked up by the next pass, which is scheduled anyway.
/// The tail runs a call as a task beside its loop, never inline — publishing
/// (call records included) must not wait on a peer — so this bounds how long
/// the *next* catch-up can be delayed, not how long the loop is unresponsive.
pub const CATCH_UP_BUDGET: Duration = Duration::from_secs(30);

/// The most rounds one [`catch_up`] call makes before returning, however
/// productive they are.
pub const MAX_CATCH_UP_ROUNDS: usize = 32;

/// How many per-publisher marks one `Request` carries.
///
/// [`hwm_all`](crate::store::TopicStore::hwm_all) grows with every distinct
/// sender ever stored, and `sender` is a wire field: an admitted member can mint
/// genesis envelopes under fresh keypairs, and at a few thousand of them the
/// request frame no longer fits [`MAX_REPLAY_FRAME`](library::MAX_REPLAY_FRAME)
/// — after which *every* replay this node attempts fails at encode, forever,
/// with the pollution on disk so a restart does not clear it. Catch-up is the
/// mechanism that heals gaps, so that is a permanent, remotely-triggerable
/// brick.
///
/// Capping the map keeps the frame encodable. Omitting a mark is safe, only
/// wasteful: the server answers an unclaimed publisher from genesis and the
/// requester classifies the run as duplicates. Successive rounds rotate the
/// window ([`hwm_window`]) so every publisher is claimed eventually.
pub const MAX_HWM_ENTRIES: usize = 1024;

/// The QUIC application error code a replay refusal closes with.
///
/// Deliberately the same number [`crate::admission`] closes an ungated gossip
/// connection with: from the peer's side both are the one condition "you are not
/// in this topic's roster", and a second code would only invite the two gates to
/// drift apart.
const CLOSE_NOT_ADMITTED: u32 = 1;

/// How long a refused requester is given to read its `Denied` frame before the
/// connection is dropped.
///
/// The frame is the entire point of refusing politely — a removed member must
/// learn *why* it is out — and returning from `accept` drops the connection,
/// which would discard whatever is still in flight. Mirrors the same wait in
/// [`crate::admission`].
const DENIAL_LINGER: Duration = Duration::from_secs(5);

/// The replay server: the router's handler for
/// [`TOPIC_REPLAY_ALPN`](library::TOPIC_REPLAY_ALPN).
///
/// Registered on the *same* [`Router`](iroh::protocol::Router) as gossip and
/// admission (see [`crate::topics`]), sharing the one [`Admitted`] registry the
/// admission handshake fills.
#[derive(Debug)]
pub struct ReplayHandler {
    /// The topic this server replays. A request naming another topic is
    /// refused, not answered from the wrong log.
    pub topic: TopicId,
    /// The log to read from — the same handle the resident node appends to.
    pub store: Arc<TopicStore>,
    /// The admission gate. A requester absent from it gets `Denied`.
    pub admitted: Admitted,
    /// Maximum items to stream in one pass, whatever the requester asks for:
    /// the peer's `limit` is a hint that may be undercut, never raised.
    pub limit: u32,
}

impl ProtocolHandler for ReplayHandler {
    /// Serve one replay request: authenticate the caller from the connection,
    /// check admission, and stream from the log.
    ///
    /// The caller is `to_node_id(&connection.remote_id())` — the key iroh
    /// authenticated — never a wire field, exactly as in
    /// [`crate::admission`].
    ///
    /// The gate runs **first**, before a byte of the request is read: an
    /// unadmitted peer gets a `Denied` frame on the stream it opened and nothing
    /// else. Reading first would mean parsing an unauthorized peer's
    /// attacker-chosen high-water-mark map for no reason.
    ///
    /// An admitted peer's connection then serves requests until it hangs up —
    /// one bidirectional stream per [`ReplayFrame::Request`], because
    /// [`catch_up`] makes several passes and a stream carries exactly one.
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        let caller = to_node_id(&connection.remote_id());
        // Checked and tracked in one locked operation (see
        // [`Admitted::attach_conn`]): an eviction racing this accept must not
        // leave a replay connection live and untracked, streaming this node's
        // whole history to a peer nobody can close.
        if !self
            .admitted
            .attach_conn(caller, connection.clone(), crate::now_unix())
        {
            tracing::warn!(
                caller = %caller.hex(),
                "replay request from a peer with no admission; refusing"
            );
            // Accepting the stream is not reading it: the peer opened one to
            // speak on, and it is the only place a reason can be written.
            if let Ok((mut send, _recv)) = connection.accept_bi().await {
                deny(&mut send, "not admitted".to_string()).await;
            }
            let _ = tokio::time::timeout(DENIAL_LINGER, connection.closed()).await;
            connection.close(
                VarInt::from_u32(CLOSE_NOT_ADMITTED),
                b"not admitted to this topic",
            );
            return Err(AcceptError::from_boxed(
                anyhow!("peer {} is not admitted to this topic", caller.hex()).into(),
            ));
        }
        // The attach above is also what lets an eviction close this connection:
        // a peer removed from the roster mid-stream stops being served rather
        // than running to the end of its pass.
        while let Ok((send, recv)) = connection.accept_bi().await {
            match serve_replay(send, recv, caller, self, crate::now_unix()).await {
                Ok(items) => {
                    tracing::debug!(caller = %caller.hex(), items, "served a replay pass");
                }
                Err(e) => {
                    tracing::warn!(caller = %caller.hex(), "replay pass refused: {e:#}");
                    // The refusal was already written; a peer that keeps asking
                    // after one gets nothing further on this connection.
                    let _ = tokio::time::timeout(DENIAL_LINGER, connection.closed()).await;
                    break;
                }
            }
        }
        Ok(())
    }
}

impl ReplayHandler {
    /// Envelopes to send for one publisher, given the mark the requester
    /// presented for it.
    ///
    /// The fork check lives here: when the presented hash disagrees with
    /// [`hash_at`](crate::store::TopicStore::hash_at) — or the requester claims
    /// a sequence this node has never seen — the answer is that publisher's
    /// chain **from genesis**, so the requester classifies the divergence
    /// instead of resuming past it.
    ///
    /// `limit` is what is left of this pass's budget, not the whole cap: the
    /// budget is spent across publishers in id order, so one chatty publisher
    /// cannot starve the others out of every pass forever (the requester loops,
    /// and each loop starts from a mark that has moved).
    fn items_for(
        &self,
        sender: NodeId,
        presented: Option<&ChainState>,
        limit: usize,
    ) -> Result<Vec<TopicEnvelope>> {
        let after = match presented {
            // Nothing claimed: everything this node has, from genesis.
            None => None,
            Some(state) => match self.store.hash_at(sender, state.seq)? {
                Some(held) if held == state.hash => Some(state.seq),
                held => {
                    // Either a different message at that sequence, or a
                    // sequence this node has never seen. Both mean the two
                    // sides disagree about history, and both are answered the
                    // same way: from the start, so the requester's classifier
                    // sees the divergence rather than a resume past it.
                    tracing::warn!(
                        sender = %sender.hex(),
                        seq = state.seq.0,
                        presented = %state.hash.hex(),
                        held = %held.map(|h| h.hex()).unwrap_or_else(|| "<none>".to_string()),
                        "replay requester's high-water hash disagrees; streaming from genesis"
                    );
                    None
                }
            },
        };
        self.store.read_after(sender, after, limit)
    }
}

/// Serve one replay exchange over an established, already-authenticated
/// bi-stream.
///
/// The duplex-testable half, like
/// [`serve_admission`](crate::admission::serve_admission): the whole protocol
/// runs over any `AsyncRead`/`AsyncWrite` pair, so the fork-from-genesis rule
/// and the admission refusal are asserted with no QUIC in the test.
///
/// Reads one `Request`, refuses it with a `Denied` frame if the topic is wrong
/// or `caller` is not admitted at `now_unix`, then writes up to
/// [`ReplayHandler::limit`] `Item`s followed by `End`. Returns the number of
/// items streamed.
///
/// `caller` must already be authenticated by whoever supplied the streams.
pub async fn serve_replay<S, R>(
    mut send: S,
    mut recv: R,
    caller: NodeId,
    handler: &ReplayHandler,
    now_unix: i64,
) -> Result<usize>
where
    S: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    // The gate again, not only in `accept`: this is the function that reads the
    // log, and a duplex caller (or a future transport) must not be able to reach
    // it around the connection-level check.
    if !handler.admitted.is_admitted(caller, now_unix) {
        let e = anyhow!("not admitted");
        deny(&mut send, format!("{e:#}")).await;
        return Err(e);
    }

    // Bounded like every other read on this surface: a peer that opens a stream
    // and then says nothing costs one deadline, not a task held forever.
    let first = crate::admission::within(
        REPLAY_PASS_TIMEOUT,
        &format!("the replay request from {}", caller.hex()),
        read_replay_frame(&mut recv),
    )
    .await?;
    let (topic, hwm, asked) = match first {
        Some(ReplayFrame::Request { topic, hwm, limit }) => (topic, hwm, limit),
        Some(_) => {
            let e = anyhow!("first frame was not a replay request");
            deny(&mut send, format!("{e:#}")).await;
            return Err(e);
        }
        None => {
            let e = anyhow!("connection closed before the replay request");
            deny(&mut send, format!("{e:#}")).await;
            return Err(e);
        }
    };
    if topic != handler.topic {
        let e = anyhow!("replay request names a different topic");
        deny(&mut send, format!("{e:#}")).await;
        return Err(e);
    }

    // The peer's `limit` is a hint that may be undercut, never raised: it is an
    // attacker-chosen number, and the server's own cap is what bounds the work
    // one stream can ask for.
    let mut budget = asked.min(handler.limit) as usize;
    let mut sent = 0usize;
    for sender in handler.store.senders().context("listing replay senders")? {
        if budget == 0 {
            break;
        }
        let items = handler
            .items_for(sender, hwm.get(&sender), budget)
            .with_context(|| format!("reading the log of {}", sender.hex()))?;
        for envelope in items {
            write_replay_frame(&mut send, &ReplayFrame::Item(envelope)).await?;
            sent += 1;
            budget -= 1;
        }
    }
    write_replay_frame(&mut send, &ReplayFrame::End).await?;
    send.shutdown().await.ok();
    Ok(sent)
}

/// What one [`catch_up`] call did — counts only, so a tail can log a pass in one
/// line and a test can assert progress without inspecting the store. The
/// envelopes themselves come back from [`catch_up_collect`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CatchUp {
    /// Admitted peers this call asked. Zero means there was nobody to ask —
    /// not an error, and not something to retry in a tight loop.
    pub peers: usize,
    /// Passes made in total. More than one per peer means a pass filled its
    /// limit and the loop went back for the rest.
    pub passes: usize,
    /// `Item` frames received across every pass.
    pub items: usize,
    /// Items that were new and are now in the log — the number the caller
    /// prints, and the one the loop's termination turns on.
    pub inserted: usize,
    /// Items already held. The steady-state outcome: two peers with the same
    /// history exchange duplicates and insert nothing.
    pub duplicates: usize,
    /// Items refused by ingest — a bad signature, the wrong topic, or a fork.
    /// Logged per item and counted here; a hostile peer cannot make a pass
    /// fail, only make it unproductive.
    pub refused: usize,
}

impl CatchUp {
    /// Fold another pass's counts into this one (`peers` is added by the
    /// caller, which knows how many it dialed).
    fn absorb(&mut self, other: CatchUp) {
        self.passes += other.passes;
        self.items += other.items;
        self.inserted += other.inserted;
        self.duplicates += other.duplicates;
        self.refused += other.refused;
    }
}

/// Ask every admitted peer for what this node is missing, until a full pass
/// adds nothing.
///
/// The dial set is [`Admitted::replay_targets`] at the roster version this node
/// currently enforces (spec §2.4.2) — replay is only ever requested from a peer
/// that completed the mutual admission handshake *under the current head*,
/// which is also why no address hints are needed here: the endpoint already has
/// a path to everyone in that registry. Peers that have hung up on every
/// connection are left out: they cannot answer, and asking costs a timeout.
///
/// `admit` is the same [`AdmitHandler`] the node serves with, used as the
/// client-side context (its `admitted` registry, its topic, its head): a peer
/// evicted by the watchdog mid-loop simply stops being asked.
///
/// Termination is "a full round over every peer inserted nothing", not a fixed
/// number of rounds: one pass is capped at `limit` items *in total* (spent
/// across publishers in id order), so a long history needs several, and a peer
/// that keeps answering with duplicates ends the loop rather than extending it.
/// A peer that fails mid-pass is logged and skipped — one unreachable peer must
/// not abort catch-up from the others.
#[cfg_attr(not(test), allow(dead_code))]
pub async fn catch_up(
    endpoint: &Endpoint,
    admit: &AdmitHandler,
    store: &TopicStore,
    topic: TopicId,
    limit: u32,
) -> Result<CatchUp> {
    Ok(catch_up_collect(endpoint, admit, store, topic, limit)
        .await?
        .counts)
}

/// What [`catch_up_collect`] returns: the counts, and every envelope the call
/// inserted.
#[derive(Clone, Debug, Default)]
pub struct CaughtUp {
    /// The same counts [`catch_up`] returns.
    pub counts: CatchUp,
    /// Every envelope this call inserted into the log, in arrival order. The
    /// only ones a tail prints for the call: an envelope is inserted exactly
    /// once, by whichever path (live, replay, own publish) got there first,
    /// so printing what *this* call inserted keeps "print on `Inserted`" exact
    /// even while the live path appends concurrently.
    pub fresh: Vec<TopicEnvelope>,
}

/// [`catch_up`], also handing back the envelopes it inserted.
///
/// What the resident tail runs: it performs the call in a task beside its
/// loop, so the loop cannot diff the high-water marks before and after — live
/// messages and its own publishes move them in between.
pub async fn catch_up_collect(
    endpoint: &Endpoint,
    admit: &AdmitHandler,
    store: &TopicStore,
    topic: TopicId,
    limit: u32,
) -> Result<CaughtUp> {
    // Fail closed, like every other reader of the head. The version is what
    // bounds *who* is asked: only peers whose admission was decided under the
    // roster this node currently enforces (spec §2.4), so a member the head no
    // longer includes is not a source of history even in the window before the
    // watchdog evicts it.
    let floor = admit
        .current_version()
        .context("resolving the current roster version for catch-up")?;
    let until = tokio::time::Instant::now() + CATCH_UP_BUDGET;
    let mut total = CatchUp {
        peers: admit.admitted.replay_targets(floor).len(),
        ..CatchUp::default()
    };
    let mut fresh = Vec::new();
    for round in 0..MAX_CATCH_UP_ROUNDS {
        // Re-read the registry every round rather than snapshotting once: the
        // watchdog can evict a peer mid-loop, and a revoked peer must stop
        // being asked at the next round, not at the end of the call. Peers
        // that hung up on every connection are skipped
        // ([`Admitted::replay_targets`]): they cannot answer.
        let peers = admit.admitted.replay_targets(floor);
        if peers.is_empty() {
            break;
        }
        let mut inserted_this_round = 0usize;
        for peer in peers {
            if tokio::time::Instant::now() >= until {
                tracing::warn!(
                    rounds = round,
                    "catch-up budget spent; the next pass picks up the rest"
                );
                return Ok(CaughtUp {
                    counts: total,
                    fresh,
                });
            }
            match replay_from(endpoint, peer, store, topic, limit, round, &mut fresh).await {
                Ok(pass) => {
                    inserted_this_round += pass.inserted;
                    total.absorb(pass);
                }
                // One unreachable (or hostile) peer must not abort catch-up
                // from the others; the round simply gets nothing from it.
                Err(e) => {
                    tracing::warn!(peer = %peer.hex(), "replay pass failed: {e:#}");
                }
            }
        }
        if inserted_this_round == 0 {
            break;
        }
    }
    Ok(CaughtUp {
        counts: total,
        fresh,
    })
}

/// One pass against one peer: dial the replay ALPN, run [`request_replay`] over
/// a fresh bi-stream, hang up.
///
/// A connection per pass rather than one held open across the loop, because a
/// pass is the unit that can fail: a peer that dies mid-history costs the round
/// one connect, and the next round re-dials with a mark that has already moved.
async fn replay_from(
    endpoint: &Endpoint,
    peer: NodeId,
    store: &TopicStore,
    topic: TopicId,
    limit: u32,
    round: usize,
    fresh: &mut Vec<TopicEnvelope>,
) -> Result<CatchUp> {
    // One deadline over the whole pass — dial, stream, and every frame read —
    // and a shorter one over the dial: a stalled peer costs a timeout, and a
    // departed one costs a short one.
    let pass = async {
        let dial = async {
            let conn = endpoint
                .connect(peer_addr(endpoint, peer).await?, library::TOPIC_REPLAY_ALPN)
                .await
                .map_err(|e| anyhow!("connecting to {} for replay: {e}", peer.hex()))?;
            let (send, recv) = conn.open_bi().await.context("opening a replay stream")?;
            Ok((conn, send, recv))
        };
        let (conn, send, recv) = crate::admission::within(
            REPLAY_CONNECT_TIMEOUT,
            &format!("dialing {} for replay", peer.hex()),
            dial,
        )
        .await?;
        let pass = request_replay(send, recv, store, topic, limit, round, fresh).await;
        conn.close(VarInt::from_u32(0), b"replay pass complete");
        pass
    };
    crate::admission::within(
        REPLAY_PASS_TIMEOUT,
        &format!("the replay pass against {}", peer.hex()),
        pass,
    )
    .await
}

/// The address to dial `peer` on, from what the endpoint already knows.
///
/// Replay is only ever requested from an *admitted* peer, and admission was a
/// connection — so the endpoint's remote map holds paths to it. Those paths are
/// attached as hints; the bare id is the fallback, which is all a discovery-
/// backed deployment needs. Either way iroh authenticates the far side to
/// `peer`'s key, so a wrong hint can only fail to connect.
async fn peer_addr(endpoint: &Endpoint, peer: NodeId) -> Result<EndpointAddr> {
    let id = crate::transport::endpoint_id(&peer)?;
    Ok(match endpoint.remote_info(id).await {
        Some(info) => EndpointAddr::from_parts(id, info.into_addrs().map(|addr| addr.into_addr())),
        None => EndpointAddr::new(id),
    })
}

/// One replay pass against one peer, over an established bi-stream.
///
/// Writes a `Request` carrying [`hwm_all`](crate::store::TopicStore::hwm_all),
/// then ingests `Item`s until `End`, pushing each one it inserted onto `fresh`. Every item goes through [`ingest`] — the
/// items are *not* trusted because they came from an admitted peer: a peer can
/// be a member in good standing and still relay a forged or forked envelope.
///
/// A `Denied` frame comes back as an error carrying the server's stated reason
/// (the same shape as an admission refusal), because the usual cause is this
/// node having been removed from the roster.
async fn request_replay<S, R>(
    mut send: S,
    mut recv: R,
    store: &TopicStore,
    topic: TopicId,
    limit: u32,
    round: usize,
    fresh: &mut Vec<TopicEnvelope>,
) -> Result<CatchUp>
where
    S: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    let hwm = hwm_window(
        store
            .hwm_all()
            .context("reading the local high-water marks")?,
        round,
    );
    write_replay_frame(&mut send, &ReplayFrame::Request { topic, hwm, limit }).await?;
    // Exactly one request rides this stream, so the write half is done.
    send.shutdown().await.ok();

    let mut pass = CatchUp {
        passes: 1,
        ..CatchUp::default()
    };
    // Publishers whose chain this pass has given up on. A refused item cannot be
    // chained past, so everything after it from the same publisher would only
    // gap; the run is dropped and the next pass re-asks from an unchanged mark.
    let mut stopped: HashSet<NodeId> = HashSet::new();
    loop {
        // The server clamps its own output; this clamps what the *client* will
        // take, which is a different promise. Nothing stops a hostile peer from
        // streaming items past the limit it was asked for — each one costs a
        // signature verification, and each distinct forged `sender` adds an
        // entry to `stopped` — so the requester ends the pass at its own budget
        // and re-asks from a mark that has moved.
        if pass.items >= limit as usize {
            tracing::warn!(
                items = pass.items,
                "replay peer streamed past the requested limit; ending the pass"
            );
            break;
        }
        match read_replay_frame(&mut recv).await? {
            Some(ReplayFrame::Item(envelope)) => {
                pass.items += 1;
                if stopped.contains(&envelope.sender) {
                    continue;
                }
                // No epoch floor on replayed items, and it is not an oversight:
                // a publisher's chain is dense, so refusing its pre-commit run
                // would leave every later message from it permanently
                // unlinkable — a late joiner, or any member offline across a
                // commit, could never catch up on anything again. History is
                // ingested; what bounds the *removed member* here is which
                // peers this node is willing to ask (see `catch_up`).
                match ingest(store, topic, &envelope, None) {
                    Ok(Ingested::Inserted) => {
                        pass.inserted += 1;
                        fresh.push(envelope);
                    }
                    Ok(Ingested::Duplicate) => pass.duplicates += 1,
                    // Replay is what heals gaps, so a gap *inside* a replay
                    // stream is not something to schedule more replay for: the
                    // peer answered from a point this node cannot link to.
                    // Noted, skipped, and left for the next pass.
                    Ok(Ingested::Gap { have }) => tracing::debug!(
                        sender = %envelope.sender.hex(),
                        seq = envelope.seq.0,
                        have = ?have.map(|s| s.0),
                        "replay item is ahead of the local chain; skipping"
                    ),
                    Err(e) => {
                        pass.refused += 1;
                        stopped.insert(envelope.sender);
                        tracing::warn!(
                            sender = %envelope.sender.hex(),
                            seq = envelope.seq.0,
                            "replay item refused; ignoring the rest of this publisher's run: {e:#}"
                        );
                    }
                }
            }
            Some(ReplayFrame::End) => break,
            Some(ReplayFrame::Denied { reason }) => return Err(Denied::new(reason).into()),
            Some(ReplayFrame::Request { .. }) => {
                bail!("replay server answered with a request, not items")
            }
            // A stream that ends without `End` is a peer that hung up mid-pass;
            // whatever was ingested stands, and the loop re-asks.
            None => break,
        }
    }
    Ok(pass)
}

/// The marks one request carries: at most [`MAX_HWM_ENTRIES`], taken as a
/// window that rotates with the round number.
///
/// `hwm_all` is unbounded — one entry per distinct sender ever stored, and
/// `sender` is a field an admitted peer chooses — while the request frame is
/// bounded by [`MAX_REPLAY_FRAME`](library::MAX_REPLAY_FRAME). Sending the whole
/// map is therefore a remotely-triggerable, permanent encode failure (see
/// [`MAX_HWM_ENTRIES`]); sending a window is not, and costs only duplicate items
/// for the publishers left out of it. Rotating the window by round means a
/// polluted log still converges: every publisher is claimed within
/// `ceil(n / MAX_HWM_ENTRIES)` rounds.
fn hwm_window(
    all: std::collections::BTreeMap<NodeId, ChainState>,
    round: usize,
) -> std::collections::BTreeMap<NodeId, ChainState> {
    if all.len() <= MAX_HWM_ENTRIES {
        return all;
    }
    let windows = all.len().div_ceil(MAX_HWM_ENTRIES);
    let skip = (round % windows) * MAX_HWM_ENTRIES;
    tracing::warn!(
        senders = all.len(),
        window = MAX_HWM_ENTRIES,
        skip,
        "the topic log holds more publishers than one replay request can claim; \
         asking for a rotating window"
    );
    all.into_iter().skip(skip).take(MAX_HWM_ENTRIES).collect()
}

/// What ingesting one envelope did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ingested {
    /// New, verified, in the log. The only outcome `wires tail` prints on —
    /// which is what makes deduplication across live, replay, and restart
    /// structural rather than a set of remembered ids.
    Inserted,
    /// Already held, byte for byte. Routine: the live and replay paths deliver
    /// the same message constantly.
    Duplicate,
    /// Ahead of this node's chain for that publisher, and therefore **not
    /// stored**. `have` is the sequence this node holds up to, `None` when it
    /// holds nothing from that publisher at all. The caller schedules a
    /// debounced [`catch_up`]; the message returns in order once the run
    /// before it lands.
    Gap {
        /// The last contiguous sequence held for this publisher.
        have: Option<Seq>,
    },
}

/// Ingest one envelope: **epoch → verify → classify → append**, in that order,
/// for both the live mesh and replay.
///
/// The order is the acceptance rule of spec §4.1, and each step exists to stop
/// the next one from being reached on bad input:
///
/// 0. The **epoch floor** (`floor`, spec §2.4): an envelope sealed under a
///    fabric key older than the roster version this node enforces is refused.
///    This is the step that makes revocation an *ingest* property rather than
///    only a confidentiality one. A signature proves who wrote a message, never
///    that they are still in the roster, and a removed member keeps every key
///    ever sealed to it — so without this check a member removed at v2 can go on
///    minting v1 envelopes that verify, chain, store, decrypt under the v1 key
///    every survivor also keeps, and print as authentic. There is nothing in an
///    envelope that distinguishes such a message from genuine pre-commit
///    history, so the rule has to be positional: once this node holds the head
///    that rotated the key, only the new epoch is accepted, on *every* path
///    (a permissive replay path would just be the same hole reached one hop
///    later). The cost, stated in spec §3: history sealed under a superseded
///    epoch that this node did not already hold is not retrofitted.
///    `None` disables the gate, for callers that have no head to enforce.
/// 1. [`verify`](library::TopicEnvelope::verify) — structure and signature
///    only. No decryption: an envelope whose `key_version` this node has no key
///    for is still storable, and a later `wires import` heals the display
///    without re-fetching anything. Deliberately not "and it must be from an
///    admitted peer": the *publisher* is authenticated by its signature, and
///    the peer that relayed it is a separate question already answered by the
///    gate.
/// 2. [`classify_link`](library::classify_link) against the stored
///    [`chain_state`](crate::store::TopicStore::chain_state) and the hash held
///    at that sequence — `Ok` and `Duplicate` proceed, `Gap` returns without
///    storing, and `Fork` is an **error**: detected, refused, logged, never
///    resolved (spec §4.2, no fork choice).
/// 3. [`append`](crate::store::TopicStore::append) — one write transaction over
///    the log and the high-water mark.
///
/// Wrong-topic envelopes are refused here rather than by the store, so the
/// error names the ingest path.
pub(crate) fn ingest(
    store: &TopicStore,
    topic: TopicId,
    envelope: &TopicEnvelope,
    floor: Option<library::RosterVersion>,
) -> Result<Ingested> {
    if envelope.topic != topic {
        bail!(
            "envelope is addressed to topic {} but this node is on {}",
            envelope.topic.hex(),
            topic.hex()
        );
    }
    if let Some(floor) = floor
        && envelope.key_version < floor
    {
        bail!(
            "envelope from {} is sealed under roster version {} but this node enforces version \
             {}: messages under a superseded fabric key are not accepted (the publisher must \
             `wires import --fabric-key-file <node-id>.key` for the current commit)",
            envelope.sender.hex(),
            envelope.key_version.0,
            floor.0
        );
    }
    envelope
        .verify()
        .with_context(|| format!("verifying an envelope from {}", envelope.sender.hex()))?;

    let sender = envelope.sender;
    let state = store
        .chain_state(sender)
        .with_context(|| format!("reading the chain state of {}", sender.hex()))?;
    let held = store
        .hash_at(sender, envelope.seq)
        .with_context(|| format!("reading the held hash of {}", sender.hex()))?;

    match classify_link(envelope, state, held).context("classifying the chain link")? {
        LinkStatus::Ok | LinkStatus::Duplicate => match store.append(envelope)? {
            Appended::Inserted => Ok(Ingested::Inserted),
            Appended::Duplicate => Ok(Ingested::Duplicate),
        },
        LinkStatus::Gap { have } => Ok(Ingested::Gap { have }),
        LinkStatus::Fork => bail!(
            "fork at sender {} seq {}: refusing the message (forks are detected and refused, \
             never resolved)",
            sender.hex(),
            envelope.seq.0
        ),
    }
}

// ---------------------------------------------------------------------------
// Frame I/O
// ---------------------------------------------------------------------------

/// Tell the requester *why* it was refused, then close our side.
///
/// Best-effort, like [`crate::admission`]'s: a peer that already vanished never
/// reads it, and the caller still returns the original error.
async fn deny<W: AsyncWrite + Unpin>(send: &mut W, reason: String) {
    let reason = crate::transport::truncate_reason(reason);
    let _ = write_replay_frame(send, &ReplayFrame::Denied { reason }).await;
    send.shutdown().await.ok();
}

/// Write one length-prefixed [`ReplayFrame`].
async fn write_replay_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &ReplayFrame) -> Result<()> {
    let bytes = frame.encode().context("encoding replay frame")?;
    w.write_all(&bytes).await.context("writing replay frame")?;
    Ok(())
}

/// Read one length-prefixed [`ReplayFrame`], or `None` at a clean end of stream.
///
/// The bound is the codec's [`library::MAX_REPLAY_FRAME`], applied before the
/// allocation: both unbounded collections in these frames (a request's
/// high-water-mark map and an item's ciphertext) are peer-chosen, and admission
/// is a large set.
async fn read_replay_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<ReplayFrame>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("reading replay frame length"),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > library::MAX_REPLAY_FRAME {
        bail!(
            "replay frame too large: {len} bytes (max {})",
            library::MAX_REPLAY_FRAME
        );
    }
    let mut full = Vec::with_capacity(4 + len);
    full.extend_from_slice(&len_buf);
    full.resize(4 + len, 0);
    r.read_exact(&mut full[4..])
        .await
        .context("reading replay frame body")?;
    match ReplayFrame::decode(&full)? {
        Some((frame, _)) => Ok(Some(frame)),
        None => bail!("truncated replay frame"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    use iroh::protocol::Router;
    use library::{
        FabricKey, InclusionProof, MessageHash, NodeIdentity, Roster, RosterHead, RosterVersion,
        TopicPeer, next_prev_hash,
    };

    use crate::admission::{AdmittedPeer, MAX_INFLIGHT_ADMISSIONS, admit_peer};
    use crate::keystore::Keystore;
    use crate::transport::{HeadSource, endpoint_addr, secret_key};

    /// Every awaited network step is bounded by this rather than by the test
    /// runner's patience: nothing in this suite sleeps waiting for a peer, and a
    /// hang must fail as a hang rather than as a build timeout.
    const DEADLINE: Duration = Duration::from_secs(20);

    /// A fresh directory per node, under Bazel's sandboxed temp when present.
    fn temp_dir() -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let base = std::env::var_os("TEST_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = base.join(format!("wires-replay-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A committed fabric: the root, one head, everyone's proof, that commit's
    /// data key, and the topic they all talk on.
    struct Fabric {
        root: NodeIdentity,
        head: RosterHead,
        proofs: HashMap<NodeId, InclusionProof>,
        key: FabricKey,
        topic: TopicId,
    }

    /// Commit `members` under a fixed root and mint that commit's fabric key.
    fn fabric(members: &[NodeId]) -> Fabric {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut roster = Roster::new(root.node_id());
        for m in members {
            roster.insert(*m);
        }
        let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let topic = TopicId::derive(root.node_id(), "ops");
        Fabric {
            root,
            head,
            proofs: proofs.into_iter().collect(),
            key: FabricKey::generate(),
            topic,
        }
    }

    /// One hermetic node: an endpoint with no discovery or relay, **one** router
    /// carrying the admit and replay ALPNs, and its own topic log.
    struct Node {
        identity: NodeIdentity,
        endpoint: Endpoint,
        admit: Arc<AdmitHandler>,
        store: Arc<TopicStore>,
        /// Held so the accept loop lives as long as the node does.
        _router: Router,
    }

    /// Stand up a node for `identity` in `fab`, serving replay with cap `limit`.
    async fn node(fab: &Fabric, identity: NodeIdentity, limit: u32) -> Node {
        let dir = temp_dir();
        let keystore = Keystore::at(&dir);
        keystore.save_roster_head(&fab.head).unwrap();
        let admitted = Admitted::new();
        let store = Arc::new(TopicStore::open_at(&dir.join("topic.db"), fab.topic).unwrap());
        let admit = Arc::new(AdmitHandler {
            topic: fab.topic,
            fabric_root: fab.root.node_id(),
            head: Arc::new(HeadSource::Keystore {
                path: keystore.path("roster-head.json"),
                armed: AtomicBool::new(false),
            }),
            proof: fab.proofs[&identity.node_id()].clone(),
            keystore: Arc::new(keystore),
            admitted: admitted.clone(),
            head_lock: Arc::new(Mutex::new(())),
            inflight: Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_ADMISSIONS)),
        });
        let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(secret_key(&identity))
            .bind()
            .await
            .unwrap();
        let replay = ReplayHandler {
            topic: fab.topic,
            store: Arc::clone(&store),
            admitted,
            limit,
        };
        let router = Router::builder(endpoint.clone())
            .accept(library::TOPIC_ADMIT_ALPN, Arc::clone(&admit))
            .accept(library::TOPIC_REPLAY_ALPN, replay)
            .spawn();
        Node {
            identity,
            endpoint,
            admit,
            store,
            _router: router,
        }
    }

    /// The endpoint's bound sockets with wildcard binds rewritten to localhost,
    /// so a dialer reaches it with no discovery service.
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

    /// `dialer` runs the real admission handshake against `responder`.
    ///
    /// Mutual, so both registries end up holding the other side — and the
    /// dialer's endpoint learns a path to the responder, which is exactly why
    /// [`catch_up`] needs no address hints of its own.
    async fn admit(dialer: &Node, responder: &Node) {
        let peer = TopicPeer {
            node: responder.identity.node_id(),
            addrs: localhost_socks(&responder.endpoint),
            relay_url: None,
        };
        tokio::time::timeout(
            DEADLINE,
            admit_peer(&dialer.endpoint, &dialer.admit, &peer, crate::now_unix()),
        )
        .await
        .expect("admission timed out")
        .expect("both sides are members");
    }

    /// Seal `text` as `who`'s next message and append it to `store`.
    fn publish(fab: &Fabric, who: &NodeIdentity, store: &TopicStore, text: &str) -> TopicEnvelope {
        let state = store.chain_state(who.node_id()).unwrap();
        let seq = match state {
            None => Seq::ZERO,
            Some(s) => s.seq.checked_next().unwrap(),
        };
        let env = TopicEnvelope::seal(
            who,
            fab.topic,
            seq,
            next_prev_hash(state),
            fab.head.version,
            &fab.key,
            0,
            text.as_bytes(),
        )
        .unwrap();
        store.append(&env).unwrap();
        env
    }

    /// Seal a genesis message without consulting any store — the only way to
    /// mint two *different* messages for one slot, which is what a fork is.
    fn seal_genesis(fab: &Fabric, who: &NodeIdentity, text: &str) -> TopicEnvelope {
        TopicEnvelope::seal(
            who,
            fab.topic,
            Seq::ZERO,
            MessageHash::ZERO,
            fab.head.version,
            &fab.key,
            0,
            text.as_bytes(),
        )
        .unwrap()
    }

    /// Every plaintext in `store`, in display order, asserting on the way that
    /// what was stored verifies and opens.
    fn transcript(fab: &Fabric, store: &TopicStore) -> Vec<String> {
        store
            .read_backfill(100)
            .unwrap()
            .into_iter()
            .map(|env| {
                env.verify().expect("a stored envelope must verify");
                String::from_utf8(env.open(&fab.key).expect("it must open")).unwrap()
            })
            .collect()
    }

    /// Decode every whole frame in `buf` (the duplex tests' output side).
    fn decode_all(mut buf: &[u8]) -> Vec<ReplayFrame> {
        let mut out = Vec::new();
        while let Ok(Some((frame, used))) = ReplayFrame::decode(buf) {
            out.push(frame);
            buf = &buf[used..];
        }
        out
    }

    /// A handler over `store` gating on a registry that holds `caller`.
    fn handler_admitting(
        fab: &Fabric,
        store: Arc<TopicStore>,
        caller: Option<NodeId>,
        limit: u32,
    ) -> ReplayHandler {
        let admitted = Admitted::new();
        if let Some(caller) = caller {
            admitted.insert(
                caller,
                AdmittedPeer {
                    proof: fab.proofs[&caller].clone(),
                    version: fab.head.version,
                    expires: i64::MAX,
                    conns: Vec::new(),
                },
            );
        }
        ReplayHandler {
            topic: fab.topic,
            store,
            admitted,
            limit,
        }
    }

    // -------------------------------------------------------------- the gate

    /// Replay is not a side door around the roster: a peer that never completed
    /// admission is refused *with a reason*, before the server reads its request
    /// and before a single item leaves the log.
    #[tokio::test]
    async fn replay_denied_without_admission() {
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let bob = NodeIdentity::from_seed([3u8; 32]);
        let fab = fabric(&[alice.node_id(), bob.node_id()]);
        let a = node(&fab, alice, REPLAY_LIMIT).await;
        let b = node(&fab, bob, REPLAY_LIMIT).await;
        publish(&fab, &a.identity, &a.store, "members only");

        // No admission handshake — straight to the replay ALPN.
        let addr =
            endpoint_addr(&a.identity.node_id(), &localhost_socks(&a.endpoint), None).unwrap();
        let conn = tokio::time::timeout(
            DEADLINE,
            b.endpoint.connect(addr, library::TOPIC_REPLAY_ALPN),
        )
        .await
        .expect("connect timed out")
        .expect("the ALPN is registered; the refusal is at the application layer");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        write_replay_frame(
            &mut send,
            &ReplayFrame::Request {
                topic: fab.topic,
                hwm: BTreeMap::new(),
                limit: 100,
            },
        )
        .await
        .unwrap();

        let frame = tokio::time::timeout(DEADLINE, read_replay_frame(&mut recv))
            .await
            .expect("the server must answer, not hang")
            .unwrap();
        match frame {
            Some(ReplayFrame::Denied { reason }) => {
                assert!(reason.contains("not admitted"), "got reason: {reason}");
            }
            other => panic!("expected a Denied frame, got {other:?}"),
        }
        assert!(
            b.store.hwm_all().unwrap().is_empty(),
            "nothing may have been streamed"
        );
    }

    /// The same refusal at the duplex seam, where the whole decision is visible
    /// with no QUIC: no request is parsed, and no `Item` is written.
    #[tokio::test]
    async fn serve_replay_denies_a_caller_absent_from_the_registry() {
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let bob = NodeIdentity::from_seed([3u8; 32]);
        let fab = fabric(&[alice.node_id(), bob.node_id()]);
        let dir = temp_dir();
        let store = Arc::new(TopicStore::open_at(&dir.join("topic.db"), fab.topic).unwrap());
        publish(&fab, &alice, &store, "members only");
        let handler = handler_admitting(&fab, store, None, REPLAY_LIMIT);

        let request = ReplayFrame::Request {
            topic: fab.topic,
            hwm: BTreeMap::new(),
            limit: 100,
        };
        let recv = std::io::Cursor::new(request.encode().unwrap());
        let mut send: Vec<u8> = Vec::new();
        let result = serve_replay(&mut send, recv, bob.node_id(), &handler, 0).await;

        assert!(result.is_err(), "an unadmitted caller gets nothing");
        match decode_all(&send).as_slice() {
            [ReplayFrame::Denied { reason }] => {
                assert!(reason.contains("not admitted"), "got reason: {reason}")
            }
            other => panic!("expected exactly one Denied frame, got {other:?}"),
        }
    }

    /// A request for another topic is refused rather than answered out of the
    /// wrong log.
    #[tokio::test]
    async fn serve_replay_refuses_a_foreign_topic() {
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let bob = NodeIdentity::from_seed([3u8; 32]);
        let fab = fabric(&[alice.node_id(), bob.node_id()]);
        let dir = temp_dir();
        let store = Arc::new(TopicStore::open_at(&dir.join("topic.db"), fab.topic).unwrap());
        publish(&fab, &alice, &store, "ours");
        let handler = handler_admitting(&fab, store, Some(bob.node_id()), REPLAY_LIMIT);

        let request = ReplayFrame::Request {
            topic: TopicId::derive(fab.root.node_id(), "someone-elses"),
            hwm: BTreeMap::new(),
            limit: 100,
        };
        let recv = std::io::Cursor::new(request.encode().unwrap());
        let mut send: Vec<u8> = Vec::new();
        let result = serve_replay(&mut send, recv, bob.node_id(), &handler, 0).await;

        assert!(result.is_err());
        assert!(
            matches!(decode_all(&send).as_slice(), [ReplayFrame::Denied { .. }]),
            "a foreign topic gets a refusal, never items"
        );
    }

    // -------------------------------------------------------------- catch-up

    /// A node that holds nothing converges on a peer's whole history — across
    /// two publishers, one of which is not even online — and everything it
    /// stores verifies and opens.
    #[tokio::test]
    async fn full_catch_up_from_empty() {
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let bob = NodeIdentity::from_seed([3u8; 32]);
        let carol = NodeIdentity::from_seed([4u8; 32]);
        let fab = fabric(&[alice.node_id(), bob.node_id(), carol.node_id()]);
        let a = node(&fab, alice, REPLAY_LIMIT).await;
        let b = node(&fab, bob, REPLAY_LIMIT).await;

        publish(&fab, &a.identity, &a.store, "one");
        publish(&fab, &a.identity, &a.store, "two");
        // Carol never connects: her chain reaches B only because A relays it.
        publish(&fab, &carol, &a.store, "hello from carol");

        admit(&b, &a).await;
        let counts = tokio::time::timeout(
            DEADLINE,
            catch_up(&b.endpoint, &b.admit, &b.store, fab.topic, REPLAY_LIMIT),
        )
        .await
        .expect("catch-up timed out")
        .unwrap();

        assert_eq!(counts.peers, 1);
        assert_eq!(counts.inserted, 3, "every message crossed");
        assert_eq!(counts.refused, 0);
        assert!(counts.passes >= 2, "the loop must confirm a quiet pass");
        assert_eq!(
            b.store.hwm_all().unwrap(),
            a.store.hwm_all().unwrap(),
            "the two logs agree, chain hashes included"
        );
        let mut lines = transcript(&fab, &b.store);
        lines.sort();
        assert_eq!(lines, vec!["hello from carol", "one", "two"]);
    }

    /// A node holding a prefix is sent only the suffix: the high-water mark in
    /// the request is what stops a peer from re-streaming what the requester
    /// already has.
    #[tokio::test]
    async fn incremental_catch_up() {
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let bob = NodeIdentity::from_seed([3u8; 32]);
        let fab = fabric(&[alice.node_id(), bob.node_id()]);
        let a = node(&fab, alice, REPLAY_LIMIT).await;
        let b = node(&fab, bob, REPLAY_LIMIT).await;

        let first = publish(&fab, &a.identity, &a.store, "one");
        let second = publish(&fab, &a.identity, &a.store, "two");
        let third = publish(&fab, &a.identity, &a.store, "three");
        // B was there for the first two and missed the third.
        b.store.append(&first).unwrap();
        b.store.append(&second).unwrap();

        admit(&b, &a).await;
        let caught = tokio::time::timeout(
            DEADLINE,
            catch_up_collect(&b.endpoint, &b.admit, &b.store, fab.topic, REPLAY_LIMIT),
        )
        .await
        .expect("catch-up timed out")
        .unwrap();
        let counts = caught.counts;

        assert_eq!(counts.items, 1, "only the missing message was sent");
        assert_eq!(counts.inserted, 1);
        assert_eq!(
            caught.fresh,
            vec![third],
            "the inserted envelope is handed back for printing, and nothing else"
        );
        assert_eq!(counts.duplicates, 0, "nothing below the mark came back");
        assert_eq!(transcript(&fab, &b.store), vec!["one", "two", "three"]);
    }

    /// The hash in the high-water mark is load-bearing: when the two sides hold
    /// different messages at the same sequence, the server streams that
    /// publisher from genesis and the requester's classifier calls it a fork —
    /// instead of both sides resuming past a divergence neither noticed.
    #[tokio::test]
    async fn hwm_hash_mismatch_streams_genesis() {
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let bob = NodeIdentity::from_seed([3u8; 32]);
        let carol = NodeIdentity::from_seed([4u8; 32]);
        let fab = fabric(&[alice.node_id(), bob.node_id(), carol.node_id()]);
        let a = node(&fab, alice, REPLAY_LIMIT).await;
        let b = node(&fab, bob, REPLAY_LIMIT).await;

        // Carol published two *different* genesis messages: A saw one, B the
        // other. Both are validly signed; the logs simply disagree.
        let a_side = seal_genesis(&fab, &carol, "what carol told alice");
        let b_side = seal_genesis(&fab, &carol, "what carol told bob");
        assert_ne!(
            a_side.message_hash().unwrap(),
            b_side.message_hash().unwrap()
        );
        a.store.append(&a_side).unwrap();
        b.store.append(&b_side).unwrap();

        admit(&b, &a).await;
        let counts = tokio::time::timeout(
            DEADLINE,
            catch_up(&b.endpoint, &b.admit, &b.store, fab.topic, REPLAY_LIMIT),
        )
        .await
        .expect("catch-up timed out")
        .unwrap();

        assert_eq!(
            counts.items, 1,
            "the mark said seq 0 was held, yet the server re-sent seq 0 from genesis"
        );
        assert_eq!(counts.refused, 1, "the divergence surfaced as a fork");
        assert_eq!(counts.inserted, 0);
        assert_eq!(
            b.store.hash_at(carol.node_id(), Seq::ZERO).unwrap(),
            Some(b_side.message_hash().unwrap()),
            "a fork is refused, never resolved: B keeps what it had"
        );
        assert_eq!(transcript(&fab, &b.store), vec!["what carol told bob"]);
    }

    /// The requester's `limit` is a hint the server may undercut: a peer asking
    /// for everything gets one server-sized pass and an `End`.
    #[tokio::test]
    async fn limit_clamp_respected() {
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let bob = NodeIdentity::from_seed([3u8; 32]);
        let fab = fabric(&[alice.node_id(), bob.node_id()]);
        let dir = temp_dir();
        let store = Arc::new(TopicStore::open_at(&dir.join("topic.db"), fab.topic).unwrap());
        publish(&fab, &alice, &store, "one");
        publish(&fab, &alice, &store, "two");
        publish(&fab, &alice, &store, "three");
        let handler = handler_admitting(&fab, store, Some(bob.node_id()), 2);

        let request = ReplayFrame::Request {
            topic: fab.topic,
            hwm: BTreeMap::new(),
            limit: u32::MAX,
        };
        let recv = std::io::Cursor::new(request.encode().unwrap());
        let mut send: Vec<u8> = Vec::new();
        let sent = serve_replay(&mut send, recv, bob.node_id(), &handler, 0)
            .await
            .unwrap();

        assert_eq!(sent, 2, "the server's own cap bounds the pass");
        let frames = decode_all(&send);
        assert_eq!(frames.len(), 3, "two items and an End: {frames:?}");
        assert!(matches!(frames[0], ReplayFrame::Item(_)));
        assert!(matches!(frames[1], ReplayFrame::Item(_)));
        assert_eq!(frames[2], ReplayFrame::End);
    }

    /// And the other direction: a requester asking for less than the server
    /// would send gets what it asked for.
    #[tokio::test]
    async fn a_requesters_smaller_limit_is_honored() {
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let bob = NodeIdentity::from_seed([3u8; 32]);
        let fab = fabric(&[alice.node_id(), bob.node_id()]);
        let dir = temp_dir();
        let store = Arc::new(TopicStore::open_at(&dir.join("topic.db"), fab.topic).unwrap());
        publish(&fab, &alice, &store, "one");
        publish(&fab, &alice, &store, "two");
        let handler = handler_admitting(&fab, store, Some(bob.node_id()), REPLAY_LIMIT);

        let request = ReplayFrame::Request {
            topic: fab.topic,
            hwm: BTreeMap::new(),
            limit: 1,
        };
        let recv = std::io::Cursor::new(request.encode().unwrap());
        let mut send: Vec<u8> = Vec::new();
        let sent = serve_replay(&mut send, recv, bob.node_id(), &handler, 0)
            .await
            .unwrap();
        assert_eq!(sent, 1);
    }

    /// A catch-up with nobody admitted is a no-op: not an error, and not a spin.
    #[tokio::test]
    async fn catch_up_with_no_peers_does_nothing() {
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let bob = NodeIdentity::from_seed([3u8; 32]);
        let fab = fabric(&[alice.node_id(), bob.node_id()]);
        let b = node(&fab, bob, REPLAY_LIMIT).await;
        let counts = tokio::time::timeout(
            DEADLINE,
            catch_up(&b.endpoint, &b.admit, &b.store, fab.topic, REPLAY_LIMIT),
        )
        .await
        .expect("an empty catch-up must return immediately")
        .unwrap();
        assert_eq!(counts, CatchUp::default());
    }

    // ---------------------------------------------------------------- ingest

    /// A message ahead of the chain is not stored: storing it would either hide
    /// the hole or strand the message. It is re-offered by replay once the run
    /// before it lands.
    #[test]
    fn ingest_leaves_a_gapped_message_unstored() {
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let fab = fabric(&[alice.node_id()]);
        let dir = temp_dir();
        let store = TopicStore::open_at(&dir.join("topic.db"), fab.topic).unwrap();

        let first = seal_genesis(&fab, &alice, "one");
        let second = TopicEnvelope::seal(
            &alice,
            fab.topic,
            Seq(1),
            first.message_hash().unwrap(),
            fab.head.version,
            &fab.key,
            0,
            b"two",
        )
        .unwrap();

        assert_eq!(
            ingest(&store, fab.topic, &second, None).unwrap(),
            Ingested::Gap { have: None }
        );
        assert!(store.hwm_all().unwrap().is_empty(), "nothing was stored");

        assert_eq!(
            ingest(&store, fab.topic, &first, None).unwrap(),
            Ingested::Inserted
        );
        assert_eq!(
            ingest(&store, fab.topic, &second, None).unwrap(),
            Ingested::Inserted,
            "the gap healed once its predecessor landed"
        );
        assert_eq!(
            ingest(&store, fab.topic, &second, None).unwrap(),
            Ingested::Duplicate,
            "re-delivery is routine, not an error"
        );
    }

    /// **Spec §2.4, claim 2.** A message sealed under a superseded fabric key is
    /// refused on the live path, and history is still ingestible on the replay
    /// path.
    ///
    /// The hole this closes: `ingest` was `verify → classify → append`, and a
    /// signature proves *who* wrote a message, never that they are still in the
    /// roster. A member removed at v2 keeps the v1 key that was sealed to it and
    /// every survivor keeps that key too (spec §3 keeps them forever), so the
    /// removed member could go on minting envelopes that verified, chained,
    /// stored, decrypted and **printed as authentic** — with nothing marking
    /// them as sealed under a dead epoch.
    ///
    /// The floor is not applied to replayed items, and that is a decision, not
    /// an omission: a publisher's chain is dense, so refusing its pre-commit run
    /// would leave every later message from it unlinkable forever — no late
    /// joiner and no member offline across a commit could ever catch up again.
    /// What bounds the removed member on that path is `peers_since`: catch-up
    /// only asks peers admitted under the roster this node now enforces.
    #[test]
    fn ingest_refuses_a_superseded_epoch_on_the_live_path() {
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let fab = fabric(&[alice.node_id()]);
        let dir = temp_dir();
        let store = TopicStore::open_at(&dir.join("topic.db"), fab.topic).unwrap();

        // The fixture's commit is v1; the node has since moved to v2.
        let v1 = fab.head.version;
        let v2 = RosterVersion(v1.0 + 1);
        let old = seal_genesis(&fab, &alice, "still here?");
        assert_eq!(old.key_version, v1);

        let refused = ingest(&store, fab.topic, &old, Some(v2))
            .expect_err("a message under a superseded key is not a message");
        let reason = format!("{refused:#}");
        assert!(
            reason.contains("superseded") && reason.contains("version 1"),
            "the refusal must name the epoch, not read as a signature failure: {reason}"
        );
        assert!(
            store.hwm_all().unwrap().is_empty(),
            "and nothing about it reaches the log"
        );

        // The same envelope is accepted where the floor does not apply: this is
        // ordinary history, and the chain needs it.
        assert_eq!(
            ingest(&store, fab.topic, &old, None).unwrap(),
            Ingested::Inserted
        );

        // A message under the *current* epoch is unaffected, and so is one from
        // a node running ahead of this one's head.
        let store2 = TopicStore::open_at(&dir.join("topic2.db"), fab.topic).unwrap();
        assert_eq!(
            ingest(&store2, fab.topic, &old, Some(v1)).unwrap(),
            Ingested::Inserted,
            "the floor is a floor, not an equality"
        );
    }

    /// The requester caps what it will take, not just what it asked for.
    ///
    /// A hostile peer can stream items past the limit it was given — each one
    /// costing a signature verification, and each distinct forged `sender`
    /// growing the `stopped` set — so the client ends the pass at its own
    /// budget. Nothing on the server's side of the stream is trusted to stop.
    #[tokio::test]
    async fn a_replay_peer_cannot_stream_past_the_requested_limit() {
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let fab = fabric(&[alice.node_id()]);
        let dir = temp_dir();
        // The source log the hostile "server" reads its items out of.
        let theirs = TopicStore::open_at(&dir.join("theirs.db"), fab.topic).unwrap();
        for i in 0..12 {
            publish(&fab, &alice, &theirs, &format!("item {i}"));
        }
        // A response of twelve items and no `End`, against a limit of three.
        let mut response: Vec<u8> = Vec::new();
        for env in theirs.read_after(alice.node_id(), None, 100).unwrap() {
            response.extend(ReplayFrame::Item(env).encode().unwrap());
        }

        let ours = TopicStore::open_at(&dir.join("ours.db"), fab.topic).unwrap();
        let mut request: Vec<u8> = Vec::new();
        let mut fresh = Vec::new();
        let pass = request_replay(
            &mut request,
            std::io::Cursor::new(response),
            &ours,
            fab.topic,
            3,
            0,
            &mut fresh,
        )
        .await
        .expect("an over-talkative peer is unproductive, not fatal");
        assert_eq!(fresh.len(), pass.inserted, "every insert is handed back");

        assert_eq!(
            pass.items, 3,
            "the pass stops at the requester's own budget"
        );
        assert_eq!(pass.inserted, 3);
        assert_eq!(
            ours.read_after(alice.node_id(), None, 100).unwrap().len(),
            3,
            "and only what it took is stored"
        );
    }

    /// The request's high-water map is capped and rotates.
    ///
    /// `hwm_all` grows with every distinct sender ever stored and `sender` is a
    /// wire field, so an admitted member minting genesis envelopes under fresh
    /// keypairs could push the request frame past `MAX_REPLAY_FRAME` — after
    /// which *every* replay from this node fails at encode, forever, with the
    /// pollution on disk so a restart does not clear it.
    #[test]
    fn the_high_water_map_is_capped_and_rotates() {
        let mut all = std::collections::BTreeMap::new();
        for i in 0..(MAX_HWM_ENTRIES * 2 + 7) {
            // Distinct ids, cheaply: the index in the first eight bytes.
            let mut raw = [0u8; 32];
            raw[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let id = NodeId::from_bytes(raw);
            all.insert(
                id,
                ChainState {
                    seq: Seq(i as u64),
                    hash: MessageHash::ZERO,
                },
            );
        }
        let total = all.len();

        let first = hwm_window(all.clone(), 0);
        assert_eq!(first.len(), MAX_HWM_ENTRIES, "the frame stays encodable");
        assert!(
            ReplayFrame::Request {
                topic: TopicId::derive(NodeIdentity::from_seed([1u8; 32]).node_id(), "ops"),
                hwm: first.clone(),
                limit: 64,
            }
            .encode()
            .is_ok(),
            "the whole point: the request still encodes"
        );

        // Successive rounds cover the rest, so a polluted log still converges.
        let mut seen: std::collections::BTreeSet<NodeId> = first.keys().copied().collect();
        for round in 1..total.div_ceil(MAX_HWM_ENTRIES) {
            seen.extend(hwm_window(all.clone(), round).keys().copied());
        }
        assert_eq!(seen.len(), total, "every publisher is claimed eventually");

        // A map that already fits is passed through untouched.
        let small: std::collections::BTreeMap<_, _> =
            all.into_iter().take(MAX_HWM_ENTRIES).collect();
        assert_eq!(hwm_window(small.clone(), 7), small);
    }

    /// Ingest verifies before it classifies: a tampered envelope never reaches
    /// the chain, where it could otherwise manufacture a "fork".
    #[test]
    fn ingest_refuses_a_tampered_or_foreign_envelope() {
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let fab = fabric(&[alice.node_id()]);
        let dir = temp_dir();
        let store = TopicStore::open_at(&dir.join("topic.db"), fab.topic).unwrap();

        let mut forged = seal_genesis(&fab, &alice, "one");
        forged.timestamp += 1;
        assert!(ingest(&store, fab.topic, &forged, None).is_err());
        assert!(store.hwm_all().unwrap().is_empty());

        // An envelope addressed to another topic is refused by the ingest path,
        // named as such, rather than filed under the wrong log.
        let elsewhere = Fabric {
            topic: TopicId::derive(fab.root.node_id(), "elsewhere"),
            ..fabric(&[alice.node_id()])
        };
        let stray = seal_genesis(&elsewhere, &alice, "not ours");
        assert!(ingest(&store, fab.topic, &stray, None).is_err());
    }
}

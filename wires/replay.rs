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

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use iroh::Endpoint;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use library::{NodeId, Seq, TopicEnvelope, TopicId};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::admission::{AdmitHandler, Admitted};
use crate::store::TopicStore;

/// How long a detected chain gap waits before triggering a catch-up pass.
///
/// **Injectable.** This is the default the resident node reads into
/// [`TopicNodeConfig::replay_debounce`](crate::topics::TopicNodeConfig::replay_debounce);
/// every code path that waits takes the duration as an argument, so
/// `live_gap_triggers_replay_and_heals` runs in milliseconds and no test in the
/// suite sleeps for two seconds.
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
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        todo!("authenticate the caller, accept_bi, serve_replay, log the outcome")
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
    fn items_for(
        &self,
        sender: NodeId,
        presented: Option<&library::ChainState>,
    ) -> Result<Vec<TopicEnvelope>> {
        todo!(
            "verify the presented hash against hash_at; from genesis on mismatch, else read_after"
        )
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
    send: S,
    recv: R,
    caller: NodeId,
    handler: &ReplayHandler,
    now_unix: i64,
) -> Result<usize>
where
    S: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    todo!("read Request; gate on topic + Admitted::is_admitted; stream Items; End")
}

/// What one [`catch_up`] call did — counts only, so a tail can log a pass in one
/// line and a test can assert progress without inspecting the store.
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
/// The dial set is [`Admitted::peers`] — replay is only ever requested from a
/// peer that completed the mutual admission handshake, which is also why no
/// address hints are needed here: the endpoint already has a path to everyone
/// in that registry.
///
/// `admit` is the same [`AdmitHandler`] the node serves with, used as the
/// client-side context (its `admitted` registry, its topic, its head): a peer
/// evicted by the watchdog mid-loop simply stops being asked.
///
/// Termination is "a full pass over every peer inserted nothing", not a fixed
/// number of rounds: one pass is capped at `limit` items per publisher, so a
/// long history needs several, and a peer that keeps answering with duplicates
/// ends the loop rather than extending it. A peer that fails mid-pass is logged
/// and skipped — one unreachable peer must not abort catch-up from the others.
pub async fn catch_up(
    endpoint: &Endpoint,
    admit: &AdmitHandler,
    store: &TopicStore,
    topic: TopicId,
    limit: u32,
) -> Result<CatchUp> {
    todo!(
        "loop over Admitted::peers, dial TOPIC_REPLAY_ALPN, request_replay, until a pass inserts nothing"
    )
}

/// One replay pass against one peer, over an established bi-stream.
///
/// Writes a `Request` carrying [`hwm_all`](crate::store::TopicStore::hwm_all),
/// then ingests `Item`s until `End`. Every item goes through [`ingest`] — the
/// items are *not* trusted because they came from an admitted peer: a peer can
/// be a member in good standing and still relay a forged or forked envelope.
///
/// A `Denied` frame comes back as an error carrying the server's stated reason
/// (the same shape as an admission refusal), because the usual cause is this
/// node having been removed from the roster.
async fn request_replay<S, R>(
    send: S,
    recv: R,
    store: &TopicStore,
    topic: TopicId,
    limit: u32,
) -> Result<CatchUp>
where
    S: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    todo!("write Request with hwm_all; ingest each Item; stop at End; map Denied to an error")
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

/// Ingest one envelope: **verify → classify → append**, in that order, for both
/// the live mesh and replay.
///
/// The order is the acceptance rule of spec §4.1, and each step exists to stop
/// the next one from being reached on bad input:
///
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
fn ingest(store: &TopicStore, topic: TopicId, envelope: &TopicEnvelope) -> Result<Ingested> {
    todo!(
        "verify() -> classify_link(chain_state, hash_at) -> append(); Gap stores nothing, Fork errors"
    )
}

//! Per-publisher hash chains: how a reader knows it has the whole story.
//!
//! Each publisher on a topic keeps its own log — 0-based, dense sequence
//! numbers, each envelope carrying the hash of its predecessor. There is no
//! global order and no consensus; the guarantee is per-sender and purely local:
//! given a sender's messages, a reader can tell *complete* from *truncated*
//! from *rewritten*.
//!
//! [`classify_link`] turns a freshly received envelope plus the reader's stored
//! [`ChainState`] into one of four verdicts:
//!
//! | verdict | meaning | what the caller does |
//! |---|---|---|
//! | [`LinkStatus::Ok`] | the expected next message | store it, display it |
//! | [`LinkStatus::Duplicate`] | already held, same hash | drop it silently — this is the dedupe that keeps live/replay/restart from double-printing |
//! | [`LinkStatus::Gap`] | seq jumped ahead | do **not** store; schedule a replay pass, the message comes back in order |
//! | [`LinkStatus::Fork`] | same slot, different content | refuse and log |
//!
//! A gap is never a silent drop-forever: replay ([`crate::replay`]) heals it.
//!
//! Fork handling is **detect and refuse**, not resolve. A fork means a sender's
//! key signed two different messages for one slot, which is either a bug or an
//! equivocating node; either way this layer will not pick a winner. Fork choice
//! is deferred.

use serde::{Deserialize, Serialize};

use crate::envelope::{MessageHash, Seq, TopicEnvelope};
use crate::error::Result;

/// A reader's high-water mark for one publisher: the last sequence number it
/// holds and that message's hash.
///
/// Serializable because it rides in [`ReplayFrame::Request`](crate::replay::ReplayFrame)
/// — the requester tells the server what it already has, and the hash lets the
/// server detect that the two disagree about history.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ChainState {
    /// The highest sequence number held for this publisher.
    pub seq: Seq,
    /// That message's [`TopicEnvelope::message_hash`].
    pub hash: MessageHash,
}

impl ChainState {
    /// The state after holding `seq` with link hash `hash`.
    pub fn new(seq: Seq, hash: MessageHash) -> Self {
        Self { seq, hash }
    }
}

/// How a received envelope relates to the chain the reader already holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkStatus {
    /// The expected next message: `seq == prev + 1` (or a well-formed genesis)
    /// and `prev_hash` matches what the reader holds.
    Ok,
    /// Already held: same `(sender, seq)` and the same hash. Idempotent
    /// re-delivery, not an error.
    Duplicate,
    /// The sequence jumped: the reader is missing at least one message.
    Gap {
        /// The highest sequence the reader holds for this sender, or `None`
        /// when it holds nothing at all.
        have: Option<Seq>,
    },
    /// Irreconcilable: a different message occupies a slot the reader already
    /// filled, a genesis with a non-zero `prev_hash`, or a `prev_hash` that
    /// does not match the held predecessor.
    Fork,
}

/// Classify `env` against the reader's chain state for that sender.
///
/// `state` is the reader's high-water mark for `env.sender` (`None` if it holds
/// nothing). `held_hash_at_seq` is the hash of the message the reader already
/// holds at `env.seq`, when it holds one — that is what separates a
/// [`LinkStatus::Duplicate`] from a [`LinkStatus::Fork`] for a backfilled slot.
///
/// This function is pure and does no signature checking: the caller runs
/// [`TopicEnvelope::verify`] first, since classifying an unauthenticated
/// envelope would let anyone manufacture a "fork".
pub fn classify_link(
    env: &TopicEnvelope,
    state: Option<ChainState>,
    held_hash_at_seq: Option<MessageHash>,
) -> Result<LinkStatus> {
    todo!("apply the genesis / next / duplicate / gap / fork truth table")
}

/// The `prev_hash` a publisher should stamp on its next message:
/// `state.hash`, or [`MessageHash::ZERO`] at genesis.
pub fn next_prev_hash(state: Option<ChainState>) -> MessageHash {
    todo!("ZERO when there is no state, else the state's hash")
}

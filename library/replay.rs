//! Replay: how a node that was away catches up, with no server to ask.
//!
//! Gossip only delivers what is happening now. A node that was offline, or that
//! hit a gap in a publisher's chain, fills in the rest by asking an *admitted
//! peer* directly over [`TOPIC_REPLAY_ALPN`]: one bidirectional stream per
//! request, [`ReplayFrame::Request`] out, a run of [`ReplayFrame::Item`]s back,
//! then [`ReplayFrame::End`].
//!
//! The protocol is **peer-symmetric**: every `wires tail` both serves replay
//! and requests it. There is no host, and no node is a required participant.
//!
//! The request carries the requester's high-water marks — a [`ChainState`] per
//! publisher, hash included, not just a sequence number. The hash is the point:
//! a server that finds its own message at that sequence hashing differently
//! streams that publisher **from genesis**, so the requester's
//! [`classify_link`](crate::chain::classify_link) surfaces the fork instead of
//! quietly resuming from a divergent point.
//!
//! Serving replay requires admission — the same allowlist that gates gossip —
//! so history is not readable by anyone who merely guesses a topic id.
//!
//! This module holds only the frames. The handler, the `catch_up` loop, and the
//! debounce that turns a live gap into a replay pass live in the `wires`
//! binary.

use std::collections::BTreeMap;

use crate::chain::ChainState;
use crate::envelope::TopicEnvelope;
use crate::error::Result;
use crate::identity::NodeId;
use crate::topic::TopicId;

/// The ALPN for the topic-replay protocol. Registered on the same iroh
/// `Router` as gossip and admission.
pub const TOPIC_REPLAY_ALPN: &[u8] = b"wires/topic-replay/1";

const TAG_REQUEST: u8 = 0;
const TAG_ITEM: u8 = 1;
const TAG_END: u8 = 2;
const TAG_DENIED: u8 = 3;

/// One framed message on a replay stream.
///
/// Same self-delimiting codec family as [`Frame`](crate::Frame) and
/// [`AdmitFrame`](crate::AdmitFrame) — 4-byte big-endian length, 1-byte tag,
/// tag-specific body — with its own tag space.
///
/// | tag | variant   | body                                     |
/// |-----|-----------|------------------------------------------|
/// | `0` | `Request` | canonical JSON of the request body       |
/// | `1` | `Item`    | canonical JSON of one envelope           |
/// | `2` | `End`     | empty                                    |
/// | `3` | `Denied`  | UTF-8 reason bytes                       |
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ReplayFrame {
    /// Requester → server: "here is everything I hold; send me the rest".
    Request {
        /// The topic being replayed.
        topic: TopicId,
        /// The requester's high-water mark per publisher. A publisher absent
        /// from the map means "I hold nothing from them; start at genesis".
        hwm: BTreeMap<NodeId, ChainState>,
        /// Maximum number of [`ReplayFrame::Item`]s the server should send in
        /// this pass; the requester loops until a pass adds nothing.
        limit: u32,
    },
    /// Server → requester: one stored envelope. Sent verbatim — the requester
    /// re-verifies and re-classifies it rather than trusting the sender.
    Item(TopicEnvelope),
    /// Server → requester: this pass is complete.
    End,
    /// Terminal refusal (e.g. the requester is not admitted), with a
    /// human-readable reason.
    Denied {
        /// Why the replay was refused.
        reason: String,
    },
}

impl ReplayFrame {
    /// Encode this frame to its length-prefixed wire bytes (see the type docs).
    pub fn encode(&self) -> Result<Vec<u8>> {
        todo!("tag + canonical JSON / reason bytes behind a 4-byte BE length")
    }

    /// Decode the first frame in `buf`.
    ///
    /// Returns `Ok(None)` until a whole frame has arrived,
    /// `Ok(Some((frame, consumed)))` otherwise, and
    /// [`crate::Error::BadFrame`] / [`crate::Error::Decode`] on a malformed
    /// frame. Never panics.
    pub fn decode(buf: &[u8]) -> Result<Option<(ReplayFrame, usize)>> {
        todo!("length check, tag dispatch, body parse")
    }
}

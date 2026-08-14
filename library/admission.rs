//! Topic admission: proving roster membership before the gossip mesh forms.
//!
//! iroh-gossip has no authorization hook — anyone who learns a topic id can
//! join the swarm. Wires therefore gates it from outside: before a peer is
//! allowed to speak gossip, it must complete a handshake on its own ALPN
//! ([`TOPIC_ADMIT_ALPN`]) proving it is in the fabric's committed roster. The
//! result feeds a per-process allowlist that a wrapper protocol handler
//! consults before delegating a connection to gossip.
//!
//! The handshake is **mutual in one round trip**: the dialer presents its head
//! and inclusion proof in [`AdmitFrame::Request`], and the responder answers
//! with its own in [`AdmitFrame::Ack`], which the dialer checks with the very
//! same [`check_topic_admission`]. Neither side takes the other's membership on
//! faith.
//!
//! This module holds the **pure** half — the frames and the decision. The
//! allowlist, the protocol handlers, the gossip wrapper, and the re-check
//! watchdog live in the `wires` binary, where async and iroh are allowed.
//!
//! # Why the envelope is unsigned
//!
//! [`AdmitFrame`] carries no signature of its own and, critically, **no caller
//! identity field**. The authority is inside: the [`RosterHead`] is root-signed
//! and the [`InclusionProof`] is checked by recomputing the head's Merkle root.
//! Who is presenting them is not something the wire gets a say in — the caller
//! is always `conn.remote_id()`, the key iroh authenticated.
//!
//! # Head selection and anti-rollback
//!
//! A peer may present a head newer than the local one. It is adopted only if it
//! is strictly newer, verifies under the fabric root, and is fresh; the caller
//! then persists it, which makes admission a passive distribution channel for
//! head advances. Because only strictly-newer verified heads are ever adopted,
//! the stored head is a highest-seen watermark and a rollback attempt is a
//! no-op. A proof against an older head fails with
//! [`crate::Error::StaleProof`]; the remedy is `wires import`.
//!
//! Note the CRL is **not** consulted here. On topics, revocation is head
//! advance and nothing else — one mechanism, no second list to keep in sync.

use crate::error::Result;
use crate::identity::NodeId;
use crate::roster::{InclusionProof, RosterHead, RosterVersion};
use crate::topic::TopicId;

/// The ALPN for the topic-admission handshake. Registered on the same iroh
/// `Router` as gossip and replay — a second `Router` would clobber the first's
/// ALPN set.
pub const TOPIC_ADMIT_ALPN: &[u8] = b"wires/topic-admit/1";

const TAG_REQUEST: u8 = 0;
const TAG_ACK: u8 = 1;
const TAG_DENIED: u8 = 2;

/// One framed message on the admission stream.
///
/// Same self-delimiting codec family as [`Frame`](crate::Frame) — 4-byte
/// big-endian length, 1-byte tag, tag-specific body — but its own enum and its
/// own tag space, so the two protocols can never be confused for one another.
///
/// | tag | variant   | body                              |
/// |-----|-----------|-----------------------------------|
/// | `0` | `Request` | canonical JSON of the admit body  |
/// | `1` | `Ack`     | canonical JSON of the admit body  |
/// | `2` | `Denied`  | UTF-8 reason bytes                |
///
/// `Request` and `Ack` are the same shape because admission is symmetric.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AdmitFrame {
    /// Dialer → responder: "here is my head and my proof; let me into this
    /// topic".
    Request {
        /// The topic being joined.
        topic: TopicId,
        /// The dialer's roster head (may be newer than the responder's).
        head: RosterHead,
        /// The dialer's inclusion proof against that head.
        proof: InclusionProof,
    },
    /// Responder → dialer on success: the responder's own head and proof, so
    /// the dialer can admit it in the same round trip.
    Ack {
        /// The topic being joined.
        topic: TopicId,
        /// The responder's roster head.
        head: RosterHead,
        /// The responder's inclusion proof against that head.
        proof: InclusionProof,
    },
    /// Terminal refusal with a human-readable reason (mirrors
    /// [`Frame::Denied`](crate::Frame::Denied)). Carries no secrets — the
    /// reason describes the caller's own credential.
    Denied {
        /// Why admission was refused (e.g. `roster inclusion rejected: …`).
        reason: String,
    },
}

impl AdmitFrame {
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
    pub fn decode(buf: &[u8]) -> Result<Option<(AdmitFrame, usize)>> {
        todo!("length check, tag dispatch, body parse")
    }
}

/// The outcome of a successful admission check.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Admission {
    /// The roster version the decision was made under — the caller stores it
    /// with the admitted peer so the watchdog can re-check against head moves.
    pub version: RosterVersion,
    /// `Some(head)` when the presented head was strictly newer than the local
    /// one and verified: the caller persists it, which is how head advances
    /// spread without a separate distribution channel. `None` means the local
    /// head was used as-is.
    pub adopt: Option<RosterHead>,
}

/// Decide whether `caller` may join a topic, given the head it presented.
///
/// Selects the head to check against — the presented one iff it is strictly
/// newer than `local_head`, verifies under `fabric_root`, and is fresh at
/// `now_unix`; otherwise `local_head` — then runs
/// [`check_roster_inclusion`](crate::check_roster_inclusion) with `proof` and
/// `caller` against it.
///
/// Like every other gate in this crate, this is **only safe when `caller` is a
/// cryptographically authenticated peer**: the proof shows a `NodeId` is in the
/// roster, and iroh's mutual auth is what shows the peer on the wire *is* that
/// `NodeId`.
///
/// Errors are the inclusion errors — [`crate::Error::NotInRoster`],
/// [`crate::Error::StaleProof`], [`crate::Error::SubjectMismatch`],
/// [`crate::Error::Expired`], [`crate::Error::InvalidSignature`].
pub fn check_topic_admission(
    local_head: &RosterHead,
    presented_head: &RosterHead,
    proof: &InclusionProof,
    fabric_root: NodeId,
    caller: NodeId,
    now_unix: i64,
) -> Result<Admission> {
    todo!("select the head (adopt strictly-newer verified fresh), then check inclusion")
}

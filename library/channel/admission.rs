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
//! is strictly newer *than the head it was compared against*, verifies under
//! the fabric root, and is fresh; the caller then persists it, which makes
//! admission a passive distribution channel for head advances. A proof against
//! an older head fails with [`crate::Error::StaleProof`]; the remedy is
//! `wires advanced import`.
//!
//! **"Strictly newer" is only monotone if the persist step says so.**
//! [`check_topic_admission`] compares against the `local_head` snapshot the
//! caller passed in, and that snapshot goes stale the moment another admission
//! adopts something. Two connections landing together — an honest peer with v5
//! in which an attacker was removed, the attacker itself with a genuine v4 in
//! which it is still a member — both read v3, both compute "advances", and a
//! plain read-modify-write persists whichever finishes last. The attacker
//! controls its own dial timing and retry count, so it can lose that race on
//! purpose until v4 lands after v5 and pins the victim on a roster it has been
//! removed from, defeating the watchdog that re-checks against the stored head.
//!
//! The fix is not more checking here; it is that the *write* must be a
//! compare-and-swap. [`adopt_if_newer`] is that comparison, re-run against the
//! head as freshly re-read under the caller's exclusive lock. Callers persist
//! through it and nothing else; then the stored head really is a highest-seen
//! watermark and a rollback attempt really is a no-op.
//!
//! One consequence is deliberate and worth naming: a genuinely root-signed
//! newer head with a *nearer* `not_after` displaces a longer-lived older one.
//! The root is the authority on both the member set and the validity window,
//! and preferring the older head would mean preferring a roster the root has
//! superseded — a removed member staying admitted is the worse failure. The
//! visible cost is that a nearly-expired advance can leave a node admitting
//! nobody until the next `wires advanced import`.
//!
//! Note the CRL is **not** consulted here. On topics, revocation is head
//! advance and nothing else — one mechanism, no second list to keep in sync.

use serde::{Deserialize, Serialize};

use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::identity::NodeId;
use crate::policy::check_roster_inclusion;
use crate::roster::{InclusionProof, RosterHead, RosterVersion};
use crate::topic::TopicId;

/// The ALPN for the topic-admission handshake. Registered on the same iroh
/// `Router` as gossip and replay — a second `Router` would clobber the first's
/// ALPN set.
pub const TOPIC_ADMIT_ALPN: &[u8] = b"wires/topic-admit/1";

/// The largest admission frame this protocol will encode or decode: 64 KiB.
///
/// The ceiling lives next to the codec, not in the reader, because
/// [`TOPIC_ADMIT_ALPN`] is the one surface that runs **before any
/// authorization**: the responder must read a whole
/// [`Request`](AdmitFrame::Request) before [`check_topic_admission`] can say
/// anything about the peer. Without a cap, `FF FF FF FF` followed by a dribble
/// of bytes makes the responder buffer 4 GiB per connection for free — a remote
/// OOM needing no credential at all. [`AdmitFrame::decode`] refuses an
/// over-long length prefix the instant the four length bytes land, so a reader
/// that stops on `Err` never allocates past this bound.
///
/// 64 KiB is roughly three orders of magnitude of headroom: the frame carries
/// one [`RosterHead`] plus one [`InclusionProof`], whose Merkle path is
/// logarithmic in the roster size (a million-member roster proves in twenty
/// hex-encoded hashes).
pub const MAX_ADMIT_FRAME: usize = 64 * 1024;

const TAG_REQUEST: u8 = 0;
const TAG_ACK: u8 = 1;
const TAG_DENIED: u8 = 2;

/// The wire body shared by [`AdmitFrame::Request`] and [`AdmitFrame::Ack`]:
/// which topic, the presenter's head, and its proof under that head.
///
/// Unsigned, and every field is mandatory — no `skip_serializing_if`, so there
/// is no way to present a half-filled credential. The authority lives in the
/// nested [`RosterHead`] (root-signed) and [`InclusionProof`] (checked by
/// recomputing the head's Merkle root), never in this envelope.
#[derive(Serialize, Deserialize)]
struct AdmitBody {
    topic: TopicId,
    head: RosterHead,
    proof: InclusionProof,
}

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
    ///
    /// ```
    /// use library::{AdmitFrame, NodeIdentity, Roster, TopicId};
    /// let root = NodeIdentity::from_seed([1u8; 32]);
    /// let member = NodeIdentity::from_seed([2u8; 32]).node_id();
    /// let mut roster = Roster::new(root.node_id());
    /// roster.insert(member);
    /// let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
    ///
    /// let f = AdmitFrame::Request {
    ///     topic: TopicId::from_bytes([7u8; 32]),
    ///     head,
    ///     proof: proofs[0].1.clone(),
    /// };
    /// let bytes = f.encode().unwrap();
    /// let (decoded, consumed) = AdmitFrame::decode(&bytes).unwrap().unwrap();
    /// assert_eq!(decoded, f);
    /// assert_eq!(consumed, bytes.len());
    /// // A partial buffer yields `None` until the whole frame has arrived.
    /// assert!(AdmitFrame::decode(&bytes[..bytes.len() - 1]).unwrap().is_none());
    /// ```
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        match self {
            AdmitFrame::Request { topic, head, proof } => {
                payload.push(TAG_REQUEST);
                let body = AdmitBody {
                    topic: *topic,
                    head: head.clone(),
                    proof: proof.clone(),
                };
                payload.extend_from_slice(&canonical_bytes(&body)?);
            }
            AdmitFrame::Ack { topic, head, proof } => {
                payload.push(TAG_ACK);
                let body = AdmitBody {
                    topic: *topic,
                    head: head.clone(),
                    proof: proof.clone(),
                };
                payload.extend_from_slice(&canonical_bytes(&body)?);
            }
            AdmitFrame::Denied { reason } => {
                payload.push(TAG_DENIED);
                payload.extend_from_slice(reason.as_bytes());
            }
        }
        if payload.len() > MAX_ADMIT_FRAME {
            return Err(Error::BadFrame);
        }
        let len: u32 = payload.len().try_into().map_err(|_| Error::BadFrame)?;
        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    /// Decode the first frame in `buf`.
    ///
    /// Returns `Ok(None)` until a whole frame has arrived,
    /// `Ok(Some((frame, consumed)))` otherwise, and
    /// [`crate::Error::BadFrame`] / [`crate::Error::Decode`] on a malformed
    /// frame. Never panics.
    ///
    /// A length prefix claiming more than [`MAX_ADMIT_FRAME`] bytes is
    /// [`crate::Error::BadFrame`] immediately — *not* `Ok(None)` — so a reader
    /// that stops on `Err` never buffers more than the cap. This is the whole
    /// memory bound on the pre-authorization surface; see [`MAX_ADMIT_FRAME`].
    pub fn decode(buf: &[u8]) -> Result<Option<(AdmitFrame, usize)>> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len > MAX_ADMIT_FRAME {
            return Err(Error::BadFrame);
        }
        let end = 4 + len;
        if buf.len() < end {
            return Ok(None);
        }
        let payload = &buf[4..end];
        let (&tag, body) = payload.split_first().ok_or(Error::BadFrame)?;
        let frame = match tag {
            TAG_REQUEST => {
                let b: AdmitBody = serde_json::from_slice(body).map_err(Error::Decode)?;
                AdmitFrame::Request {
                    topic: b.topic,
                    head: b.head,
                    proof: b.proof,
                }
            }
            TAG_ACK => {
                let b: AdmitBody = serde_json::from_slice(body).map_err(Error::Decode)?;
                AdmitFrame::Ack {
                    topic: b.topic,
                    head: b.head,
                    proof: b.proof,
                }
            }
            TAG_DENIED => AdmitFrame::Denied {
                reason: String::from_utf8(body.to_vec()).map_err(|_| Error::BadFrame)?,
            },
            _ => return Err(Error::BadFrame),
        };
        Ok(Some((frame, end)))
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
    ///
    /// Persist it **through [`adopt_if_newer`]**, under the same lock that
    /// re-reads the stored head — this value was judged against a snapshot, and
    /// a bare write of it is a rollback waiting for a concurrent admission.
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
///
/// ```
/// use library::{check_topic_admission, NodeIdentity, Roster};
/// let root = NodeIdentity::from_seed([1u8; 32]);
/// let member = NodeIdentity::from_seed([2u8; 32]).node_id();
/// let mut roster = Roster::new(root.node_id());
/// roster.insert(member);
/// let (v1, v1_proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
///
/// // The peer turns up holding a head one commit ahead of ours, and the
/// // proof it presents targets that head: admitted, and the head is adopted.
/// roster.insert(NodeIdentity::from_seed([3u8; 32]).node_id());
/// let (v2, v2_proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
/// let fresh = v2_proofs.iter().find(|(m, _)| *m == member).unwrap().1.clone();
/// let admission = check_topic_admission(&v1, &v2, &fresh, root.node_id(), member, 0).unwrap();
/// assert_eq!(admission.version, v2.version);
/// assert_eq!(admission.adopt.as_ref(), Some(&v2));
///
/// // A proof against a head we have already moved past is refused, not
/// // quietly accepted: the peer must re-import its proof.
/// let stale = v1_proofs.iter().find(|(m, _)| *m == member).unwrap().1.clone();
/// assert!(check_topic_admission(&v2, &v2, &stale, root.node_id(), member, 0).is_err());
/// ```
pub fn check_topic_admission(
    local_head: &RosterHead,
    presented_head: &RosterHead,
    proof: &InclusionProof,
    fabric_root: NodeId,
    caller: NodeId,
    now_unix: i64,
) -> Result<Admission> {
    // A head advance is only an advance if it is strictly newer, genuinely the
    // fabric root's, and still alive. Anything else — an older head, a
    // re-presentation of the one we hold, a forged "v+1", an expired commit —
    // leaves the local head in charge. The same predicate runs again in
    // `adopt_if_newer` when the caller actually writes, which is what makes the
    // stored head monotone under concurrent admissions.
    let adopt = adopt_if_newer(local_head, presented_head, fabric_root, now_unix);
    let head = if adopt.is_some() {
        presented_head
    } else {
        local_head
    };
    // The chosen head is re-verified here (freshness, fabric pin, signature)
    // together with the proof, so the local-head path fails closed too.
    check_roster_inclusion(head, proof, fabric_root, caller, now_unix)?;
    Ok(Admission {
        version: head.version,
        adopt,
    })
}

/// The compare-and-swap behind persisting an
/// [`Admission::adopt`]: `Some(candidate)` iff `candidate` is *still* a genuine
/// advance over `stored`, `None` otherwise (in which case the caller writes
/// nothing).
///
/// [`check_topic_admission`] judged the candidate against a snapshot taken when
/// the connection arrived. This re-judges it against the head as it is at the
/// moment of writing, which is the only comparison that makes the stored head
/// monotone. The caller's obligation is the ordinary one for a
/// compare-and-swap: **re-read `stored`, call this, and write, all under the
/// same exclusive lock** — otherwise two connections can still interleave a
/// read-modify-write and the later, older writer wins.
///
/// The candidate is fully re-verified here (root signature, fabric pin,
/// freshness), not taken on trust from the earlier decision: by the time a head
/// is being written to disk it may have crossed a task boundary, and a
/// re-verification costs one signature check.
///
/// ```
/// use library::{adopt_if_newer, NodeIdentity, Roster, RosterVersion};
/// let root = NodeIdentity::from_seed([1u8; 32]);
/// let member = NodeIdentity::from_seed([2u8; 32]).node_id();
/// let mut roster = Roster::new(root.node_id());
/// roster.insert(member);
///
/// let (v1, _) = roster.commit(&root, 0, i64::MAX).unwrap();
/// roster.insert(NodeIdentity::from_seed([3u8; 32]).node_id());
/// let (v2, _) = roster.commit(&root, 0, i64::MAX).unwrap();
///
/// // The advance is taken...
/// assert_eq!(adopt_if_newer(&v1, &v2, root.node_id(), 0).as_ref(), Some(&v2));
/// // ...and the racing writer that still believes v1 is current is a no-op,
/// // rather than rolling the stored head back a version.
/// assert_eq!(adopt_if_newer(&v2, &v1, root.node_id(), 0), None);
/// assert_eq!(adopt_if_newer(&v2, &v2, root.node_id(), 0), None);
/// ```
pub fn adopt_if_newer(
    stored: &RosterHead,
    candidate: &RosterHead,
    fabric_root: NodeId,
    now_unix: i64,
) -> Option<RosterHead> {
    let advances = candidate.version > stored.version
        && candidate.verify(fabric_root).is_ok()
        && now_unix <= candidate.not_after;
    advances.then(|| candidate.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use crate::roster::{MerkleRoot, Roster};
    use proptest::prelude::*;

    // ---------------------------------------------------------------- codec

    fn seed() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    fn topic() -> impl Strategy<Value = TopicId> {
        seed().prop_map(TopicId::from_bytes)
    }

    /// A genuinely committed head plus one member's proof under it — the only
    /// (head, proof) shape the wire ever legitimately carries.
    fn head_and_proof() -> impl Strategy<Value = (RosterHead, InclusionProof)> {
        (
            seed(),
            proptest::collection::vec(seed(), 1..5),
            any::<i64>(),
        )
            .prop_map(|(rs, ms, not_after)| {
                let root = NodeIdentity::from_seed(rs);
                let mut roster = Roster::new(root.node_id());
                for m in &ms {
                    roster.insert(NodeId::from_bytes(*m));
                }
                let (head, proofs) = roster.commit(&root, 0, not_after).unwrap();
                (head, proofs.into_iter().next().unwrap().1)
            })
    }

    /// An arbitrary frame of any variant.
    fn frame() -> impl Strategy<Value = AdmitFrame> {
        prop_oneof![
            (topic(), head_and_proof()).prop_map(|(topic, (head, proof))| AdmitFrame::Request {
                topic,
                head,
                proof
            }),
            (topic(), head_and_proof()).prop_map(|(topic, (head, proof))| AdmitFrame::Ack {
                topic,
                head,
                proof
            }),
            any::<String>().prop_map(|reason| AdmitFrame::Denied { reason }),
        ]
    }

    proptest! {
        /// Every frame survives an encode/decode round-trip, reporting the
        /// exact number of bytes it occupied.
        #[test]
        fn roundtrips(f in frame()) {
            let enc = f.encode().unwrap();
            let (dec, consumed) = AdmitFrame::decode(&enc).unwrap().unwrap();
            prop_assert_eq!(dec, f);
            prop_assert_eq!(consumed, enc.len());
        }

        /// Concatenated frames decode back, in order, off the same buffer.
        #[test]
        fn stream_splits(fs in proptest::collection::vec(frame(), 0..6)) {
            let mut buf = Vec::new();
            for f in &fs {
                buf.extend_from_slice(&f.encode().unwrap());
            }
            let mut out = Vec::new();
            let mut off = 0;
            while let Some((f, n)) = AdmitFrame::decode(&buf[off..]).unwrap() {
                out.push(f);
                off += n;
            }
            prop_assert_eq!(off, buf.len());
            prop_assert_eq!(out, fs);
        }

        /// Any strict prefix of a frame's bytes is "not yet complete".
        #[test]
        fn truncated_is_none(f in frame()) {
            let enc = f.encode().unwrap();
            for cut in 0..enc.len() {
                prop_assert!(AdmitFrame::decode(&enc[..cut]).unwrap().is_none());
            }
        }

        /// Arbitrary bytes decode to `Ok`/`Err`, never a panic.
        #[test]
        fn garbage_never_panics(b in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = AdmitFrame::decode(&b);
        }

        /// A well-formed length prefix wrapped around arbitrary body bytes —
        /// what a fuzzer on a live stream actually produces — still never
        /// panics, whichever tag it claims.
        #[test]
        fn framed_garbage_never_panics(
            tag in any::<u8>(),
            body in proptest::collection::vec(any::<u8>(), 0..96),
        ) {
            let mut buf = Vec::new();
            let len = (body.len() + 1) as u32;
            buf.extend_from_slice(&len.to_be_bytes());
            buf.push(tag);
            buf.extend_from_slice(&body);
            let _ = AdmitFrame::decode(&buf);
        }

        /// A denial's reason survives a round-trip verbatim, for any string.
        #[test]
        fn denied_reason_roundtrips(reason in any::<String>()) {
            let f = AdmitFrame::Denied { reason };
            let enc = f.encode().unwrap();
            let (dec, consumed) = AdmitFrame::decode(&enc).unwrap().unwrap();
            prop_assert_eq!(dec, f);
            prop_assert_eq!(consumed, enc.len());
        }

        /// `Request` and `Ack` are the same body under different tags: their
        /// encodings differ in exactly the one tag byte. That is what makes the
        /// handshake symmetric — and what keeps the two directions distinct.
        #[test]
        fn request_and_ack_differ_only_in_the_tag(t in topic(), hp in head_and_proof()) {
            let (head, proof) = hp;
            let req = AdmitFrame::Request { topic: t, head: head.clone(), proof: proof.clone() }
                .encode()
                .unwrap();
            let ack = AdmitFrame::Ack { topic: t, head, proof }.encode().unwrap();
            prop_assert_eq!(req.len(), ack.len());
            prop_assert_eq!(req[4], TAG_REQUEST);
            prop_assert_eq!(ack[4], TAG_ACK);
            prop_assert_eq!(&req[5..], &ack[5..]);
        }
    }

    #[test]
    fn denied_roundtrips_empty_ascii_and_unicode() {
        for reason in [
            "",
            "roster inclusion rejected: not a member of the roster",
            "refusé — 拒否 🚫",
        ] {
            let f = AdmitFrame::Denied {
                reason: reason.to_string(),
            };
            let enc = f.encode().unwrap();
            // Body is exactly the tag plus the reason's UTF-8 bytes.
            assert_eq!(enc[4], TAG_DENIED);
            assert_eq!(&enc[5..], reason.as_bytes());
            assert_eq!(AdmitFrame::decode(&enc).unwrap().unwrap().0, f);
        }
    }

    #[test]
    fn denied_with_invalid_utf8_is_bad_frame() {
        // len = 2: TAG_DENIED plus a lone 0xff, which is not valid UTF-8.
        assert!(matches!(
            AdmitFrame::decode(&[0, 0, 0, 2, TAG_DENIED, 0xff]),
            Err(Error::BadFrame)
        ));
    }

    #[test]
    fn empty_denied_has_known_layout() {
        // len = 1 (tag only); tag = 2.
        assert_eq!(
            AdmitFrame::Denied {
                reason: String::new()
            }
            .encode()
            .unwrap(),
            vec![0, 0, 0, 1, TAG_DENIED]
        );
    }

    #[test]
    fn unknown_tag_is_bad_frame() {
        // Tag 3 is one past this enum's space; tag 9 is far outside it.
        assert!(matches!(
            AdmitFrame::decode(&[0, 0, 0, 1, 3]),
            Err(Error::BadFrame)
        ));
        assert!(matches!(
            AdmitFrame::decode(&[0, 0, 0, 1, 9]),
            Err(Error::BadFrame)
        ));
    }

    /// The memory bound on the *pre-authorization* surface. An unadmitted peer
    /// that writes `FF FF FF FF` and then dribbles must be refused as soon as
    /// the length prefix lands: waiting for the body is exactly the 4-GiB
    /// buffer this cap exists to prevent, and on this ALPN the peer has
    /// presented no credential yet.
    #[test]
    fn an_oversized_length_prefix_is_refused_before_any_buffering() {
        assert!(matches!(
            AdmitFrame::decode(&[0xff, 0xff, 0xff, 0xff]),
            Err(Error::BadFrame)
        ));
        // One byte over is over; the cap itself is a legal frame size and so
        // still reports "not yet complete".
        let over = ((MAX_ADMIT_FRAME + 1) as u32).to_be_bytes();
        assert!(matches!(AdmitFrame::decode(&over), Err(Error::BadFrame)));
        let at = (MAX_ADMIT_FRAME as u32).to_be_bytes();
        assert!(AdmitFrame::decode(&at).unwrap().is_none());
    }

    /// The cap is symmetric: what cannot be decoded cannot be encoded either.
    #[test]
    fn an_oversized_frame_is_refused_by_encode() {
        let huge = AdmitFrame::Denied {
            reason: "x".repeat(MAX_ADMIT_FRAME + 1),
        };
        assert!(matches!(huge.encode(), Err(Error::BadFrame)));

        let big = AdmitFrame::Denied {
            reason: "x".repeat(MAX_ADMIT_FRAME - 1),
        };
        let enc = big.encode().unwrap();
        assert_eq!(enc.len(), 4 + MAX_ADMIT_FRAME);
        assert_eq!(AdmitFrame::decode(&enc).unwrap().unwrap().0, big);
    }

    /// A real `Request` — head plus inclusion proof — is orders of magnitude
    /// under the cap, so the bound is a DoS guard rather than a limit anyone
    /// legitimately runs into.
    #[test]
    fn a_real_request_is_far_under_the_cap() {
        let (head, proof) = fixture_head_and_proof();
        let enc = AdmitFrame::Request {
            topic: TopicId::from_bytes([0u8; 32]),
            head,
            proof,
        }
        .encode()
        .unwrap();
        assert!(
            enc.len() * 32 < MAX_ADMIT_FRAME,
            "a real admit frame is {} bytes; the cap is {MAX_ADMIT_FRAME}",
            enc.len()
        );
    }

    #[test]
    fn zero_length_frame_is_bad_frame() {
        // A frame with no payload at all has no tag byte to dispatch on.
        assert!(matches!(
            AdmitFrame::decode(&[0, 0, 0, 0]),
            Err(Error::BadFrame)
        ));
    }

    #[test]
    fn request_body_is_canonical_json_of_topic_head_proof() {
        let (head, proof) = fixture_head_and_proof();
        let t = TopicId::from_bytes([0x11u8; 32]);
        let enc = AdmitFrame::Request {
            topic: t,
            head: head.clone(),
            proof: proof.clone(),
        }
        .encode()
        .unwrap();
        assert_eq!(enc[4], TAG_REQUEST);
        let body: serde_json::Value = serde_json::from_slice(&enc[5..]).unwrap();
        assert_eq!(body["topic"], serde_json::json!(t.hex()));
        assert_eq!(body["head"]["version"], serde_json::json!(head.version.0));
        assert_eq!(
            body["proof"]["member"],
            serde_json::json!(proof.member.hex())
        );
        // Canonical JSON: keys sorted, no insignificant whitespace.
        let keys: Vec<&String> = body.as_object().unwrap().keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        assert!(!enc[5..].contains(&b' '));
    }

    #[test]
    fn a_truncated_body_is_a_decode_error_not_a_panic() {
        let (head, proof) = fixture_head_and_proof();
        let enc = AdmitFrame::Request {
            topic: TopicId::from_bytes([0u8; 32]),
            head,
            proof,
        }
        .encode()
        .unwrap();
        // Re-frame half the JSON body under an honest length prefix: complete
        // by the length header, unparseable as a body.
        let half = 5 + (enc.len() - 5) / 2;
        let payload = &enc[4..half];
        let mut buf = (payload.len() as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(payload);
        assert!(matches!(AdmitFrame::decode(&buf), Err(Error::Decode(_))));
    }

    // ------------------------------------------------------------- decision

    /// The instant every decision test is evaluated at.
    const NOW: i64 = 1000;
    /// A `not_after` comfortably after [`NOW`].
    const FRESH: i64 = 9999;
    /// A `not_after` before [`NOW`] — an expired head.
    const PAST: i64 = 500;
    /// The version of the head this node already holds.
    const LOCAL_VERSION: u64 = 3;

    fn fabric_root() -> NodeIdentity {
        NodeIdentity::from_seed([1u8; 32])
    }

    fn member() -> NodeId {
        NodeIdentity::from_seed([2u8; 32]).node_id()
    }

    fn other() -> NodeId {
        NodeIdentity::from_seed([3u8; 32]).node_id()
    }

    fn outsider() -> NodeId {
        NodeIdentity::from_seed([4u8; 32]).node_id()
    }

    /// Someone who cannot sign as the fabric root but tries anyway.
    fn imposter() -> NodeIdentity {
        NodeIdentity::from_seed([5u8; 32])
    }

    /// The member set committed at `version`: `member` and `other` throughout,
    /// plus `version` filler members, so every version has a distinct Merkle
    /// root and a proof issued at one version cannot recompute at another.
    fn member_set(version: u64) -> Vec<NodeId> {
        let mut set = vec![member(), other()];
        for i in 0..version {
            set.push(NodeId::from_bytes([0x80 + i as u8; 32]));
        }
        set
    }

    /// The genuine root-signed head at `version`, with every member's proof.
    fn commit_at(version: u64, not_after: i64) -> (RosterHead, Vec<(NodeId, InclusionProof)>) {
        let root = fabric_root();
        let mut roster = Roster::new(root.node_id());
        for m in member_set(version) {
            roster.insert(m);
        }
        roster.version = RosterVersion(version - 1);
        roster.commit(&root, 0, not_after).unwrap()
    }

    /// `who`'s genuine inclusion proof at `version`.
    fn proof_at(version: u64, who: NodeId) -> InclusionProof {
        commit_at(version, FRESH)
            .1
            .into_iter()
            .find(|(m, _)| *m == who)
            .expect("member of the committed set")
            .1
    }

    /// A structurally valid proof for `who` at `version` that recomputes to a
    /// root no real head ever committed — what a non-member can build for
    /// itself out of a roster only it believes in.
    fn bogus_proof(version: u64, who: NodeId) -> InclusionProof {
        let root = fabric_root();
        let mut roster = Roster::new(root.node_id());
        roster.insert(who);
        roster.version = RosterVersion(version - 1);
        roster
            .commit(&root, 0, FRESH)
            .unwrap()
            .1
            .into_iter()
            .next()
            .unwrap()
            .1
    }

    /// A head with the right shape and a signature the fabric root never made.
    fn forge(head: &RosterHead) -> RosterHead {
        let mut forged = head.clone();
        forged.sig = imposter().sign(b"not the fabric root's signature");
        forged
    }

    fn fixture_head_and_proof() -> (RosterHead, InclusionProof) {
        (commit_at(1, FRESH).0, proof_at(1, member()))
    }

    /// How the presented head's version compares to the local one.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Age {
        /// Version 2 — behind the local head.
        Older,
        /// Version 3 — the local head's own version.
        Equal,
        /// Version 4 — ahead of the local head.
        Newer,
    }

    /// What is wrong (or not) with the presented head itself.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Validity {
        /// Genuinely root-signed and fresh.
        Valid,
        /// Signed by someone who is not the fabric root.
        Forged,
        /// Genuinely root-signed but past its `not_after`.
        Expired,
    }

    /// Which proof the caller presents alongside the head.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ProofKind {
        /// The caller's genuine proof at the *presented* head's version.
        Fresh,
        /// The caller's genuine proof at version 1 — stale under any head here.
        Stale,
        /// A genuine proof, but for a different node than the caller.
        AnotherNode,
        /// A self-issued proof from a non-member, at the presented version.
        NonMember,
    }

    /// What the decision must be for a matrix cell.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Expect {
        /// Admitted at this roster version; `adopted` says whether the
        /// presented head was taken as the new local head.
        Admit {
            /// The roster version the admission was decided under.
            version: u64,
            /// Whether `adopt` carries the presented head.
            adopted: bool,
        },
        /// Denied: the proof targets a different version than the checked head.
        Stale {
            /// The proof's version.
            proof: u64,
            /// The checked head's version.
            head: u64,
        },
        /// Denied: the proof is not for the authenticated caller.
        SubjectMismatch,
        /// Denied: the proof does not recompute to the checked head's root.
        NotInRoster,
    }

    impl Age {
        fn version(self) -> u64 {
            match self {
                Age::Older => LOCAL_VERSION - 1,
                Age::Equal => LOCAL_VERSION,
                Age::Newer => LOCAL_VERSION + 1,
            }
        }
    }

    /// Materialize one matrix cell: the head as presented on the wire, the
    /// proof presented with it, and who the authenticated caller is.
    fn cell(age: Age, validity: Validity, kind: ProofKind) -> (RosterHead, InclusionProof, NodeId) {
        let v = age.version();
        let head = match validity {
            Validity::Valid => commit_at(v, FRESH).0,
            Validity::Forged => forge(&commit_at(v, FRESH).0),
            Validity::Expired => commit_at(v, PAST).0,
        };
        let (proof, caller) = match kind {
            ProofKind::Fresh => (proof_at(v, member()), member()),
            ProofKind::Stale => (proof_at(1, member()), member()),
            ProofKind::AnotherNode => (proof_at(v, other()), member()),
            ProofKind::NonMember => (bogus_proof(v, outsider()), outsider()),
        };
        (head, proof, caller)
    }

    /// The full decision matrix: {older, equal, newer} × {valid, forged,
    /// expired} × {fresh, stale, another node, non-member}, every expected
    /// outcome written out by hand rather than derived from the code under
    /// test.
    ///
    /// The local head is a genuine, fresh v3. Read a row as: a peer holding a
    /// head of this `Age` and `Validity` shows up presenting this proof.
    fn matrix() -> Vec<(Age, Validity, ProofKind, Expect)> {
        use Age::{Equal, Newer, Older};
        use ProofKind::{AnotherNode, Fresh, NonMember, Stale};
        use Validity::{Expired, Forged, Valid};
        let mut rows = Vec::new();

        // An older head is never adopted: every cell is decided against the
        // local v3, so the peer's v2-era proof reads as stale.
        for validity in [Valid, Forged, Expired] {
            rows.extend([
                (Older, validity, Fresh, Expect::Stale { proof: 2, head: 3 }),
                (Older, validity, Stale, Expect::Stale { proof: 1, head: 3 }),
                (Older, validity, AnotherNode, Expect::SubjectMismatch),
                (
                    Older,
                    validity,
                    NonMember,
                    Expect::Stale { proof: 2, head: 3 },
                ),
            ]);
        }

        // An equal-version head is never adopted either — not even a genuine
        // one — so the local head decides, and a current proof admits.
        for validity in [Valid, Forged, Expired] {
            rows.extend([
                (
                    Equal,
                    validity,
                    Fresh,
                    Expect::Admit {
                        version: 3,
                        adopted: false,
                    },
                ),
                (Equal, validity, Stale, Expect::Stale { proof: 1, head: 3 }),
                (Equal, validity, AnotherNode, Expect::SubjectMismatch),
                (Equal, validity, NonMember, Expect::NotInRoster),
            ]);
        }

        // A strictly newer, verified, fresh head IS adopted — and the peer
        // whose proof targets it is admitted at that new version.
        rows.extend([
            (
                Newer,
                Valid,
                Fresh,
                Expect::Admit {
                    version: 4,
                    adopted: true,
                },
            ),
            (Newer, Valid, Stale, Expect::Stale { proof: 1, head: 4 }),
            (Newer, Valid, AnotherNode, Expect::SubjectMismatch),
            (Newer, Valid, NonMember, Expect::NotInRoster),
        ]);

        // A newer head that does not verify, or that has expired, is NOT
        // adopted: the local v3 decides, so the v4 proof presented with it is
        // stale. This is the forged-advance / rollback cell.
        for validity in [Forged, Expired] {
            rows.extend([
                (Newer, validity, Fresh, Expect::Stale { proof: 4, head: 3 }),
                (Newer, validity, Stale, Expect::Stale { proof: 1, head: 3 }),
                (Newer, validity, AnotherNode, Expect::SubjectMismatch),
                (
                    Newer,
                    validity,
                    NonMember,
                    Expect::Stale { proof: 4, head: 3 },
                ),
            ]);
        }
        rows
    }

    #[test]
    fn matrix_is_the_whole_cross_product() {
        let rows = matrix();
        assert_eq!(rows.len(), 3 * 3 * 4, "every cell must be written out");
        let mut seen: Vec<(Age, Validity, ProofKind)> = Vec::new();
        for (a, v, k, _) in &rows {
            assert!(
                !seen.contains(&(*a, *v, *k)),
                "duplicate cell {a:?}/{v:?}/{k:?}"
            );
            seen.push((*a, *v, *k));
        }
    }

    #[test]
    fn decision_matrix() {
        let root = fabric_root().node_id();
        let local = commit_at(LOCAL_VERSION, FRESH).0;
        for (age, validity, kind, expect) in matrix() {
            let label = format!("{age:?}/{validity:?}/{kind:?}");
            let (presented, proof, caller) = cell(age, validity, kind);
            let got = check_topic_admission(&local, &presented, &proof, root, caller, NOW);
            match expect {
                Expect::Admit { version, adopted } => {
                    let admission =
                        got.unwrap_or_else(|e| panic!("{label}: expected admission, got {e:?}"));
                    assert_eq!(admission.version.0, version, "{label}: version");
                    assert_eq!(admission.adopt.is_some(), adopted, "{label}: adopt");
                    if adopted {
                        assert_eq!(
                            admission.adopt.as_ref(),
                            Some(&presented),
                            "{label}: the adopted head must be exactly what was presented"
                        );
                    }
                }
                // A denial returns no `Admission` at all, so nothing is
                // adopted: refusing the peer and refusing its head are one
                // event.
                Expect::Stale { proof: p, head: h } => assert!(
                    matches!(&got, Err(Error::StaleProof { proof, head }) if *proof == p && *head == h),
                    "{label}: expected StaleProof {{{p}, {h}}}, got {got:?}"
                ),
                Expect::SubjectMismatch => assert!(
                    matches!(got, Err(Error::SubjectMismatch)),
                    "{label}: expected SubjectMismatch, got {got:?}"
                ),
                Expect::NotInRoster => assert!(
                    matches!(got, Err(Error::NotInRoster)),
                    "{label}: expected NotInRoster, got {got:?}"
                ),
            }
        }
    }

    // The load-bearing cells again, on their own, so a regression names itself.

    #[test]
    fn newer_valid_head_admits_and_is_adopted() {
        let root = fabric_root().node_id();
        let local = commit_at(LOCAL_VERSION, FRESH).0;
        let presented = commit_at(LOCAL_VERSION + 1, FRESH).0;
        let proof = proof_at(LOCAL_VERSION + 1, member());
        let admission =
            check_topic_admission(&local, &presented, &proof, root, member(), NOW).unwrap();
        assert_eq!(admission.version, presented.version);
        assert_eq!(admission.adopt, Some(presented));
    }

    #[test]
    fn newer_forged_head_is_neither_admitted_nor_adopted() {
        let root = fabric_root().node_id();
        let local = commit_at(LOCAL_VERSION, FRESH).0;
        let forged = forge(&commit_at(LOCAL_VERSION + 1, FRESH).0);
        // The attacker presents a proof consistent with its own forged head.
        let proof = proof_at(LOCAL_VERSION + 1, member());
        let got = check_topic_admission(&local, &forged, &proof, root, member(), NOW);
        assert!(
            matches!(got, Err(Error::StaleProof { proof: 4, head: 3 })),
            "a forged advance must be judged against the local head, got {got:?}"
        );
        // And nothing was adopted: an adoption only ever rides out on a
        // successful `Admission`, and there is none.
        assert!(got.is_err());
    }

    #[test]
    fn newer_head_signed_by_an_imposter_root_is_not_adopted() {
        // A whole parallel fabric: the imposter signs its own roster and calls
        // it version 4. The `fabric` pin inside `RosterHead::verify` catches it.
        let root = fabric_root().node_id();
        let local = commit_at(LOCAL_VERSION, FRESH).0;
        let attacker = imposter();
        let mut roster = Roster::new(attacker.node_id());
        roster.insert(member());
        roster.version = RosterVersion(LOCAL_VERSION);
        let (presented, proofs) = roster.commit(&attacker, 0, FRESH).unwrap();
        assert_eq!(presented.version.0, LOCAL_VERSION + 1);
        let proof = proofs.into_iter().next().unwrap().1;
        let got = check_topic_admission(&local, &presented, &proof, root, member(), NOW);
        assert!(got.is_err(), "an imposter fabric must not admit: {got:?}");
    }

    #[test]
    fn a_rewritten_version_is_not_a_head_advance() {
        // The cheapest forgery: take the genuine local head and bump the
        // (signed) version field. The signature no longer covers it.
        let root = fabric_root().node_id();
        let local = commit_at(LOCAL_VERSION, FRESH).0;
        let mut rewritten = local.clone();
        rewritten.version = RosterVersion(LOCAL_VERSION + 9);
        assert!(rewritten.verify(root).is_err());
        // Presented with the proof that matches the real local head, the peer
        // is still admitted — against the local head, with no adoption.
        let proof = proof_at(LOCAL_VERSION, member());
        let admission =
            check_topic_admission(&local, &rewritten, &proof, root, member(), NOW).unwrap();
        assert_eq!(admission.adopt, None);
        assert_eq!(admission.version.0, LOCAL_VERSION);
    }

    #[test]
    fn equal_version_head_is_never_adopted() {
        let root = fabric_root().node_id();
        let local = commit_at(LOCAL_VERSION, FRESH).0;
        // Even byte-identical, even genuinely signed: not strictly newer.
        let proof = proof_at(LOCAL_VERSION, member());
        let admission =
            check_topic_admission(&local, &local.clone(), &proof, root, member(), NOW).unwrap();
        assert_eq!(admission.adopt, None);
        assert_eq!(admission.version.0, LOCAL_VERSION);
    }

    #[test]
    fn older_head_is_never_adopted() {
        let root = fabric_root().node_id();
        let local = commit_at(LOCAL_VERSION, FRESH).0;
        let older = commit_at(LOCAL_VERSION - 1, FRESH).0;
        // A peer that is behind gets refused, and its head never displaces
        // ours — the stored head is a highest-seen watermark.
        let proof = proof_at(LOCAL_VERSION - 1, member());
        let got = check_topic_admission(&local, &older, &proof, root, member(), NOW);
        assert!(matches!(got, Err(Error::StaleProof { proof: 2, head: 3 })));
        // Its *current* proof, though, still admits it against our head.
        let current = proof_at(LOCAL_VERSION, member());
        let admission =
            check_topic_admission(&local, &older, &current, root, member(), NOW).unwrap();
        assert_eq!(admission.adopt, None);
        assert_eq!(admission.version.0, LOCAL_VERSION);
    }

    #[test]
    fn newer_expired_head_is_not_adopted() {
        let root = fabric_root().node_id();
        let local = commit_at(LOCAL_VERSION, FRESH).0;
        let expired = commit_at(LOCAL_VERSION + 1, PAST).0;
        assert!(expired.verify(root).is_ok(), "the signature is genuine");
        let proof = proof_at(LOCAL_VERSION, member());
        let admission =
            check_topic_admission(&local, &expired, &proof, root, member(), NOW).unwrap();
        assert_eq!(admission.adopt, None, "a dead head is not a head advance");
        assert_eq!(admission.version.0, LOCAL_VERSION);
    }

    #[test]
    fn an_expired_local_head_admits_nobody() {
        // Fails closed: if the only head we can judge against has expired, no
        // proof against it is good enough.
        let root = fabric_root().node_id();
        let local = commit_at(LOCAL_VERSION, PAST).0;
        let proof = proof_at(LOCAL_VERSION, member());
        assert!(matches!(
            check_topic_admission(&local, &local.clone(), &proof, root, member(), NOW),
            Err(Error::Expired { not_after: PAST })
        ));
    }

    #[test]
    fn the_wrong_fabric_root_admits_nobody() {
        let local = commit_at(LOCAL_VERSION, FRESH).0;
        let proof = proof_at(LOCAL_VERSION, member());
        let wrong = imposter().node_id();
        assert!(matches!(
            check_topic_admission(&local, &local.clone(), &proof, wrong, member(), NOW),
            Err(Error::InvalidSignature)
        ));
    }

    // -------------------------------------------------- persistence (CAS)

    /// **The rollback race.** Two admissions land together, both having read
    /// v3: an honest peer carrying v5 (in which the attacker was removed) and
    /// the attacker carrying a genuine v4 (in which it is still a member). The
    /// attacker controls its own dial timing, so it arranges to write last.
    ///
    /// A bare write of `Admission::adopt` would leave the victim pinned on v4
    /// and the attacker admitted indefinitely, because the watchdog re-checks
    /// against the stored head. Persisting through `adopt_if_newer` — re-read
    /// under the lock — makes the late, older writer a no-op.
    #[test]
    fn a_late_older_writer_cannot_roll_the_stored_head_back() {
        let root = fabric_root().node_id();
        let v3 = commit_at(LOCAL_VERSION, FRESH).0;
        let v4 = commit_at(LOCAL_VERSION + 1, FRESH).0;
        let v5 = commit_at(LOCAL_VERSION + 2, FRESH).0;

        // Both handlers snapshot v3 and both are told to adopt.
        let honest = check_topic_admission(
            &v3,
            &v5,
            &proof_at(LOCAL_VERSION + 2, member()),
            root,
            member(),
            NOW,
        )
        .unwrap();
        let attacker = check_topic_admission(
            &v3,
            &v4,
            &proof_at(LOCAL_VERSION + 1, member()),
            root,
            member(),
            NOW,
        )
        .unwrap();
        assert_eq!(honest.adopt.as_ref(), Some(&v5));
        assert_eq!(attacker.adopt.as_ref(), Some(&v4));

        // The honest write lands first...
        let mut stored = v3.clone();
        if let Some(head) = adopt_if_newer(&stored, honest.adopt.as_ref().unwrap(), root, NOW) {
            stored = head;
        }
        assert_eq!(stored.version, v5.version);

        // ...and the attacker's deliberately-late write is refused.
        assert_eq!(
            adopt_if_newer(&stored, attacker.adopt.as_ref().unwrap(), root, NOW),
            None
        );
        assert_eq!(stored.version, v5.version);
    }

    proptest! {
        /// Applied in any order, any number of times, the stored head only ever
        /// moves forward — the "highest-seen watermark" claim, stated as a
        /// property rather than an aspiration.
        #[test]
        fn persisting_through_the_cas_is_monotone(order in proptest::collection::vec(1u64..7, 0..12)) {
            let root = fabric_root().node_id();
            let mut stored = commit_at(1, FRESH).0;
            for v in order {
                let candidate = commit_at(v, FRESH).0;
                let before = stored.version;
                if let Some(head) = adopt_if_newer(&stored, &candidate, root, NOW) {
                    prop_assert!(head.version > before);
                    stored = head;
                }
                prop_assert!(stored.version >= before);
            }
        }
    }

    #[test]
    fn the_cas_refuses_forged_and_expired_candidates() {
        let root = fabric_root().node_id();
        let stored = commit_at(LOCAL_VERSION, FRESH).0;

        // Newer but not the root's.
        let forged = forge(&commit_at(LOCAL_VERSION + 1, FRESH).0);
        assert_eq!(adopt_if_newer(&stored, &forged, root, NOW), None);

        // Newer, genuinely signed, but already dead.
        let expired = commit_at(LOCAL_VERSION + 1, PAST).0;
        assert!(expired.verify(root).is_ok());
        assert_eq!(adopt_if_newer(&stored, &expired, root, NOW), None);

        // Newer and genuine, but checked against a root we do not trust.
        let genuine = commit_at(LOCAL_VERSION + 1, FRESH).0;
        assert_eq!(
            adopt_if_newer(&stored, &genuine, imposter().node_id(), NOW),
            None
        );
        // ...and against the right root, it is taken.
        assert_eq!(adopt_if_newer(&stored, &genuine, root, NOW), Some(genuine));
    }

    /// The decision and the write agree by construction: whatever
    /// `check_topic_admission` offers for adoption, the CAS accepts against the
    /// same snapshot it was judged under. The CAS is a guard against the
    /// snapshot going stale, not a second, stricter policy.
    #[test]
    fn the_cas_agrees_with_the_decision_against_an_unchanged_snapshot() {
        let root = fabric_root().node_id();
        let local = commit_at(LOCAL_VERSION, FRESH).0;
        for (age, validity, kind, _) in matrix() {
            let (presented, proof, caller) = cell(age, validity, kind);
            let Ok(admission) =
                check_topic_admission(&local, &presented, &proof, root, caller, NOW)
            else {
                continue;
            };
            let cas = adopt_if_newer(&local, &presented, root, NOW);
            assert_eq!(
                admission.adopt, cas,
                "{age:?}/{validity:?}/{kind:?}: decision and write disagree"
            );
        }
    }

    proptest! {
        /// Tampering with any signed field of a *newer* presented head costs
        /// the peer its adoption: the tampered head no longer verifies, so the
        /// local head decides and the peer's newer proof reads as stale.
        #[test]
        fn tampering_any_signed_field_of_a_newer_head_denies_and_never_adopts(
            which in 0usize..6,
            noise in any::<u64>(),
        ) {
            let root = fabric_root().node_id();
            let local = commit_at(LOCAL_VERSION, FRESH).0;
            let genuine = commit_at(LOCAL_VERSION + 1, FRESH).0;
            let mut tampered = genuine.clone();
            match which {
                0 => tampered.format = 2,
                1 => tampered.fabric = imposter().node_id(),
                2 => tampered.version =
                    RosterVersion(genuine.version.0 ^ noise ^ 0x9e37_79b9),
                3 => tampered.root = MerkleRoot::from_bytes([0xab; 32]),
                4 => tampered.issued = genuine.issued.wrapping_add(1),
                _ => tampered.not_after = genuine.not_after.wrapping_add(1),
            }
            prop_assume!(tampered != genuine);
            prop_assume!(tampered.version.0 > LOCAL_VERSION);
            prop_assume!(tampered.not_after >= NOW);

            let proof = proof_at(LOCAL_VERSION + 1, member());
            let got = check_topic_admission(&local, &tampered, &proof, root, member(), NOW);
            prop_assert!(
                matches!(got, Err(Error::StaleProof { proof: 4, head: 3 })),
                "tampered field {} was admitted: {:?}", which, got
            );
        }

        /// Adoption happens only when the presented head is strictly newer,
        /// verifies under the fabric root, and is fresh — and what is adopted
        /// is exactly what was presented.
        #[test]
        fn adoption_requires_strictly_newer_verified_and_fresh(
            v in 1u64..7,
            forged in any::<bool>(),
            expired in any::<bool>(),
        ) {
            let root = fabric_root().node_id();
            let local = commit_at(LOCAL_VERSION, FRESH).0;
            let genuine = commit_at(v, if expired { PAST } else { FRESH }).0;
            let presented = if forged { forge(&genuine) } else { genuine };
            // Always the proof matching the presented head, so adoption is the
            // only thing that can vary.
            let proof = proof_at(v, member());

            if let Ok(admission) =
                check_topic_admission(&local, &presented, &proof, root, member(), NOW)
            {
                match &admission.adopt {
                    Some(adopted) => {
                        prop_assert!(v > LOCAL_VERSION, "adopted a non-advancing head");
                        prop_assert!(!forged, "adopted a head that does not verify");
                        prop_assert!(!expired, "adopted an expired head");
                        prop_assert_eq!(adopted, &presented);
                        prop_assert_eq!(admission.version, presented.version);
                    }
                    None => prop_assert_eq!(admission.version, local.version),
                }
            }
        }

        /// The caller is never taken from the wire: for any authenticated
        /// caller other than the proof's subject, admission is refused. This is
        /// the non-transferability of an inclusion proof.
        #[test]
        fn a_proof_never_admits_anyone_but_its_subject(cs in seed()) {
            let root = fabric_root().node_id();
            let local = commit_at(LOCAL_VERSION, FRESH).0;
            let proof = proof_at(LOCAL_VERSION, member());
            let caller = NodeId::from_bytes(cs);
            prop_assume!(caller != member());
            prop_assert!(matches!(
                check_topic_admission(&local, &local.clone(), &proof, root, caller, NOW),
                Err(Error::SubjectMismatch)
            ));
        }
    }
}

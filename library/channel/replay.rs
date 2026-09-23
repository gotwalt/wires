//! Replay: how a node that was away catches up, with no server to ask.
//!
//! Gossip only delivers what is happening now. A node that was offline, or that
//! hit a gap in a publisher's chain, fills in the rest by asking an *admitted
//! peer* directly over [`TOPIC_REPLAY_ALPN`]: one bidirectional stream per
//! request, [`ReplayFrame::Request`] out, a run of [`ReplayFrame::Item`]s back,
//! then [`ReplayFrame::End`].
//!
//! The protocol is **peer-symmetric**: every `wires watch` both serves replay
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

use serde::{Deserialize, Serialize};

use crate::chain::ChainState;
use crate::codec::canonical_bytes;
use crate::envelope::TopicEnvelope;
use crate::error::{Error, Result};
use crate::identity::NodeId;
use crate::topic::TopicId;

/// The ALPN for the topic-replay protocol. Registered on the same iroh
/// `Router` as gossip and admission.
pub const TOPIC_REPLAY_ALPN: &[u8] = b"wires/topic-replay/1";

/// The largest replay frame this protocol will encode or decode: 1 MiB.
///
/// Like [`MAX_ADMIT_FRAME`](crate::MAX_ADMIT_FRAME), the ceiling lives next to
/// the codec so the three readers in this codebase cannot each pick their own
/// (or forget). Replay runs *after* admission, so an unadmitted peer cannot
/// reach it — but "admitted" is a large set, and both unbounded collections in
/// these frames (the [`hwm`](ReplayFrame::Request) map and an envelope's
/// ciphertext) are attacker-chosen once a peer is in. A four-byte length prefix
/// with no cap lets any admitted peer make the server buffer 4 GiB per stream.
///
/// 1 MiB is generous for both shapes: one envelope carries a chat-sized
/// hex-encoded payload, and a high-water-mark map costs ~170 bytes per
/// publisher, so the cap clears several thousand publishers on one topic.
pub const MAX_REPLAY_FRAME: usize = 1024 * 1024;

const TAG_REQUEST: u8 = 0;
const TAG_ITEM: u8 = 1;
const TAG_END: u8 = 2;
const TAG_DENIED: u8 = 3;

/// The wire body of a [`ReplayFrame::Request`], serialized as one canonical-JSON
/// blob.
///
/// Unsigned, like the other frame envelopes in this crate: nothing here is an
/// authority claim. The topic is public to anyone already admitted, the
/// high-water marks are the requester's own state, and the limit is a hint the
/// server is free to undercut. Admission — not this frame — decides whether the
/// requester gets any history at all.
#[derive(Serialize, Deserialize)]
struct RequestBody {
    topic: TopicId,
    /// Keyed by [`NodeId`], which serializes as lowercase hex — a JSON object
    /// key, and a `BTreeMap` so the encoding is deterministic.
    hwm: BTreeMap<NodeId, ChainState>,
    limit: u32,
}

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
    ///
    /// ```
    /// use library::{ReplayFrame, TopicId};
    /// use std::collections::BTreeMap;
    ///
    /// // "I hold nothing on this topic — send me up to 128 messages."
    /// let req = ReplayFrame::Request {
    ///     topic: TopicId::from_bytes([7u8; 32]),
    ///     hwm: BTreeMap::new(),
    ///     limit: 128,
    /// };
    /// let bytes = req.encode().unwrap();
    /// let (decoded, consumed) = ReplayFrame::decode(&bytes).unwrap().unwrap();
    /// assert_eq!(decoded, req);
    /// assert_eq!(consumed, bytes.len());
    ///
    /// // A partial buffer yields `None` until the whole frame has arrived.
    /// assert!(ReplayFrame::decode(&bytes[..bytes.len() - 1]).unwrap().is_none());
    ///
    /// // `End` is a bare tag behind the 4-byte length prefix.
    /// assert_eq!(ReplayFrame::End.encode().unwrap(), vec![0, 0, 0, 1, 2]);
    /// ```
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        match self {
            ReplayFrame::Request { topic, hwm, limit } => {
                payload.push(TAG_REQUEST);
                let body = RequestBody {
                    topic: *topic,
                    hwm: hwm.clone(),
                    limit: *limit,
                };
                payload.extend_from_slice(&canonical_bytes(&body)?);
            }
            ReplayFrame::Item(envelope) => {
                payload.push(TAG_ITEM);
                // Deliberately the envelope's own wire accessor rather than a
                // second call to `canonical_bytes`: the two are byte-identical
                // today, and going through `to_wire` is what keeps them so if
                // the envelope's wire form ever changes.
                payload.extend_from_slice(&envelope.to_wire()?);
            }
            ReplayFrame::End => payload.push(TAG_END),
            ReplayFrame::Denied { reason } => {
                payload.push(TAG_DENIED);
                payload.extend_from_slice(reason.as_bytes());
            }
        }
        if payload.len() > MAX_REPLAY_FRAME {
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
    /// A length prefix claiming more than [`MAX_REPLAY_FRAME`] bytes is
    /// [`crate::Error::BadFrame`] immediately — *not* `Ok(None)` — so a reader
    /// that stops on `Err` never buffers more than the cap.
    pub fn decode(buf: &[u8]) -> Result<Option<(ReplayFrame, usize)>> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len > MAX_REPLAY_FRAME {
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
                let req: RequestBody = serde_json::from_slice(body).map_err(Error::Decode)?;
                ReplayFrame::Request {
                    topic: req.topic,
                    hwm: req.hwm,
                    limit: req.limit,
                }
            }
            TAG_ITEM => ReplayFrame::Item(TopicEnvelope::from_wire(body)?),
            TAG_END => {
                if !body.is_empty() {
                    return Err(Error::BadFrame);
                }
                ReplayFrame::End
            }
            TAG_DENIED => ReplayFrame::Denied {
                reason: String::from_utf8(body.to_vec()).map_err(|_| Error::BadFrame)?,
            },
            _ => return Err(Error::BadFrame),
        };
        Ok(Some((frame, end)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Ciphertext, ENVELOPE_V1, MessageHash, MessageNonce, Seq, TopicEnvelope};
    use crate::error::Error;
    use crate::grant::AlgorithmId;
    use crate::identity::Signature;
    use crate::roster::RosterVersion;
    use proptest::prelude::*;

    fn seed() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    fn bytes() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..256)
    }

    /// An arbitrary 64-byte signature. `Signature` is opaque bytes to this
    /// module — replay frames are unsigned envelopes around already-signed
    /// objects — so no keypair is needed to exercise the codec.
    fn signature() -> impl Strategy<Value = Signature> {
        (seed(), seed()).prop_map(|(a, b)| {
            let mut raw = [0u8; 64];
            raw[..32].copy_from_slice(&a);
            raw[32..].copy_from_slice(&b);
            Signature::from_bytes(raw)
        })
    }

    /// An arbitrary envelope, built field-by-field rather than via
    /// [`TopicEnvelope::seal`]: the codec must carry whatever bytes a peer
    /// hands it, and this module's tests must not depend on the crypto.
    fn envelope() -> impl Strategy<Value = TopicEnvelope> {
        (
            seed(),
            seed(),
            any::<u64>(),
            seed(),
            any::<u64>(),
            any::<i64>(),
            proptest::array::uniform12(any::<u8>()),
            bytes(),
            signature(),
        )
            .prop_map(
                |(topic, sender, seq, prev, key_version, timestamp, nonce, ct, sig)| {
                    TopicEnvelope {
                        format: ENVELOPE_V1,
                        topic: TopicId::from_bytes(topic),
                        sender: NodeId::from_bytes(sender),
                        seq: Seq(seq),
                        prev_hash: MessageHash::from_bytes(prev),
                        key_version: RosterVersion(key_version),
                        timestamp,
                        nonce: MessageNonce::from_bytes(nonce),
                        ciphertext: Ciphertext::from_bytes(ct),
                        alg: AlgorithmId::Ed25519,
                        sig,
                    }
                },
            )
    }

    fn chain_state() -> impl Strategy<Value = ChainState> {
        (any::<u64>(), seed())
            .prop_map(|(seq, hash)| ChainState::new(Seq(seq), MessageHash::from_bytes(hash)))
    }

    /// A high-water-mark map with `size` publishers in it.
    fn hwm(size: std::ops::Range<usize>) -> impl Strategy<Value = BTreeMap<NodeId, ChainState>> {
        proptest::collection::btree_map(seed().prop_map(NodeId::from_bytes), chain_state(), size)
    }

    fn request(size: std::ops::Range<usize>) -> impl Strategy<Value = ReplayFrame> {
        (seed(), hwm(size), any::<u32>()).prop_map(|(topic, hwm, limit)| ReplayFrame::Request {
            topic: TopicId::from_bytes(topic),
            hwm,
            limit,
        })
    }

    /// An arbitrary frame of any variant.
    fn frame() -> impl Strategy<Value = ReplayFrame> {
        prop_oneof![
            request(0..5),
            envelope().prop_map(ReplayFrame::Item),
            Just(ReplayFrame::End),
            any::<String>().prop_map(|reason| ReplayFrame::Denied { reason }),
        ]
    }

    /// A fixed envelope with recognisable field bytes, for known-answer tests.
    fn fixed_envelope() -> TopicEnvelope {
        TopicEnvelope {
            format: ENVELOPE_V1,
            topic: TopicId::from_bytes([0x11; 32]),
            sender: NodeId::from_bytes([0x22; 32]),
            seq: Seq(3),
            prev_hash: MessageHash::from_bytes([0x33; 32]),
            key_version: RosterVersion(9),
            timestamp: -5,
            nonce: MessageNonce::from_bytes([0x55; 12]),
            ciphertext: Ciphertext::from_bytes(vec![0xde, 0xad, 0xbe, 0xef]),
            alg: AlgorithmId::Ed25519,
            sig: Signature::from_bytes([0x44; 64]),
        }
    }

    proptest! {
        /// Every frame survives an encode/decode round-trip, reporting the
        /// exact number of bytes it occupied.
        #[test]
        fn roundtrips(f in frame()) {
            let enc = f.encode().unwrap();
            let (dec, consumed) = ReplayFrame::decode(&enc).unwrap().unwrap();
            prop_assert_eq!(dec, f);
            prop_assert_eq!(consumed, enc.len());
        }

        /// A request carrying a populated high-water-mark map round-trips with
        /// every publisher's sequence *and* hash intact — the hash is what lets
        /// the server detect a fork rather than silently resuming.
        #[test]
        fn populated_hwm_roundtrips(f in request(1..8)) {
            let enc = f.encode().unwrap();
            let (dec, consumed) = ReplayFrame::decode(&enc).unwrap().unwrap();
            prop_assert_eq!(&dec, &f);
            prop_assert_eq!(consumed, enc.len());
            match dec {
                ReplayFrame::Request { hwm, .. } => prop_assert!(!hwm.is_empty()),
                other => prop_assert!(false, "expected a Request, got {:?}", other),
            }
        }

        /// An `Item` carries its envelope verbatim, byte-identical fields and
        /// all — the requester re-verifies what it gets, so nothing may be
        /// normalized away in transit.
        #[test]
        fn item_carries_the_envelope_verbatim(env in envelope()) {
            let f = ReplayFrame::Item(env.clone());
            let enc = f.encode().unwrap();
            let (dec, _) = ReplayFrame::decode(&enc).unwrap().unwrap();
            prop_assert_eq!(dec, ReplayFrame::Item(env));
        }

        /// Concatenated frames decode back, in order, off the same buffer.
        #[test]
        fn stream_splits(fs in proptest::collection::vec(frame(), 0..8)) {
            let mut buf = Vec::new();
            for f in &fs {
                buf.extend_from_slice(&f.encode().unwrap());
            }
            let mut out = Vec::new();
            let mut off = 0;
            while let Some((f, n)) = ReplayFrame::decode(&buf[off..]).unwrap() {
                out.push(f);
                off += n;
            }
            prop_assert_eq!(off, buf.len());
            prop_assert_eq!(out, fs);
        }

        /// Reassembly off a growing stream: fed one byte at a time, the decoder
        /// yields `None` until a whole frame has arrived, then exactly the
        /// frames that were written, in order.
        #[test]
        fn reassembles_byte_by_byte(fs in proptest::collection::vec(frame(), 1..4)) {
            let mut wire = Vec::new();
            for f in &fs {
                wire.extend_from_slice(&f.encode().unwrap());
            }
            let mut buf: Vec<u8> = Vec::new();
            let mut out = Vec::new();
            for b in wire {
                buf.push(b);
                while let Some((f, n)) = ReplayFrame::decode(&buf).unwrap() {
                    out.push(f);
                    buf.drain(..n);
                }
            }
            prop_assert!(buf.is_empty());
            prop_assert_eq!(out, fs);
        }

        /// Any strict prefix of a frame's bytes is "not yet complete".
        #[test]
        fn truncated_is_none(f in frame()) {
            let enc = f.encode().unwrap();
            for cut in 0..enc.len() {
                prop_assert!(ReplayFrame::decode(&enc[..cut]).unwrap().is_none());
            }
        }

        /// Arbitrary bytes decode to `Ok`/`Err`, never a panic.
        #[test]
        fn garbage_never_panics(b in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = ReplayFrame::decode(&b);
        }

        /// Garbage behind a well-formed length prefix and a *valid* tag is
        /// still only ever `Ok`/`Err`.
        #[test]
        fn tagged_garbage_never_panics(
            tag in 0u8..5,
            b in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let mut buf = Vec::new();
            let len = (b.len() + 1) as u32;
            buf.extend_from_slice(&len.to_be_bytes());
            buf.push(tag);
            buf.extend_from_slice(&b);
            let _ = ReplayFrame::decode(&buf);
        }

        /// A refusal's reason survives a round-trip verbatim, for any string.
        #[test]
        fn denied_reason_roundtrips(reason in any::<String>()) {
            let f = ReplayFrame::Denied { reason };
            let enc = f.encode().unwrap();
            let (dec, consumed) = ReplayFrame::decode(&enc).unwrap().unwrap();
            prop_assert_eq!(dec, f);
            prop_assert_eq!(consumed, enc.len());
        }
    }

    #[test]
    fn end_has_known_layout() {
        // len = 1 (bare tag); tag = 2; no body.
        assert_eq!(
            ReplayFrame::End.encode().unwrap(),
            vec![0, 0, 0, 1, TAG_END]
        );
        assert_eq!(
            ReplayFrame::decode(&[0, 0, 0, 1, TAG_END])
                .unwrap()
                .unwrap(),
            (ReplayFrame::End, 5)
        );
    }

    /// Known answer pinning the request wire format: 4-byte big-endian length,
    /// tag `0`, then the canonical JSON of `{hwm, limit, topic}` with the hwm
    /// keyed by lowercase-hex node id.
    #[test]
    fn request_has_known_wire_bytes() {
        let node = NodeId::from_bytes([0x22; 32]);
        let mut hwm = BTreeMap::new();
        hwm.insert(
            node,
            ChainState::new(Seq(5), MessageHash::from_bytes([0x33; 32])),
        );
        let f = ReplayFrame::Request {
            topic: TopicId::from_bytes([0x11; 32]),
            hwm,
            limit: 7,
        };

        let body = format!(
            r#"{{"hwm":{{"{node}":{{"hash":"{hash}","seq":5}}}},"limit":7,"topic":"{topic}"}}"#,
            node = "22".repeat(32),
            hash = "33".repeat(32),
            topic = "11".repeat(32),
        );
        let mut expected = Vec::new();
        expected.extend_from_slice(&((body.len() + 1) as u32).to_be_bytes());
        expected.push(TAG_REQUEST);
        expected.extend_from_slice(body.as_bytes());

        assert_eq!(f.encode().unwrap(), expected);
        assert_eq!(ReplayFrame::decode(&expected).unwrap().unwrap().0, f);
    }

    /// Known answer pinning the item wire format: tag `1` then the envelope's
    /// canonical JSON (sorted keys, no whitespace, no base64 layer).
    #[test]
    fn item_has_known_wire_bytes() {
        let f = ReplayFrame::Item(fixed_envelope());
        let body = format!(
            concat!(
                r#"{{"alg":"ed25519","ciphertext":"deadbeef","format":1,"key_version":9,"#,
                r#""nonce":"{nonce}","prev_hash":"{prev}","sender":"{sender}","seq":3,"#,
                r#""sig":"{sig}","timestamp":-5,"topic":"{topic}"}}"#
            ),
            nonce = "55".repeat(12),
            prev = "33".repeat(32),
            sender = "22".repeat(32),
            sig = "44".repeat(64),
            topic = "11".repeat(32),
        );
        let mut expected = Vec::new();
        expected.extend_from_slice(&((body.len() + 1) as u32).to_be_bytes());
        expected.push(TAG_ITEM);
        expected.extend_from_slice(body.as_bytes());

        assert_eq!(f.encode().unwrap(), expected);
        assert_eq!(ReplayFrame::decode(&expected).unwrap().unwrap().0, f);
    }

    #[test]
    fn empty_hwm_request_roundtrips() {
        let f = ReplayFrame::Request {
            topic: TopicId::from_bytes([0u8; 32]),
            hwm: BTreeMap::new(),
            limit: 0,
        };
        let enc = f.encode().unwrap();
        assert_eq!(ReplayFrame::decode(&enc).unwrap().unwrap(), (f, enc.len()));
    }

    #[test]
    fn denied_roundtrips_empty_ascii_and_unicode() {
        for reason in ["", "not admitted to this topic", "refusé — 拒否 🚫"] {
            let f = ReplayFrame::Denied {
                reason: reason.to_string(),
            };
            let enc = f.encode().unwrap();
            // Body is exactly the tag plus the reason's UTF-8 bytes.
            assert_eq!(enc[4], TAG_DENIED);
            assert_eq!(&enc[5..], reason.as_bytes());
            assert_eq!(ReplayFrame::decode(&enc).unwrap().unwrap().0, f);
        }
    }

    #[test]
    fn denied_with_invalid_utf8_is_bad_frame() {
        // len = 2: TAG_DENIED plus a lone 0xff, which is not valid UTF-8.
        assert!(matches!(
            ReplayFrame::decode(&[0, 0, 0, 2, TAG_DENIED, 0xff]),
            Err(Error::BadFrame)
        ));
    }

    #[test]
    fn unknown_tag_is_bad_frame() {
        // len = 1, tag = 9 (unknown).
        assert!(matches!(
            ReplayFrame::decode(&[0, 0, 0, 1, 9]),
            Err(Error::BadFrame)
        ));
    }

    #[test]
    fn empty_payload_is_bad_frame() {
        // len = 0: no room even for a tag.
        assert!(matches!(
            ReplayFrame::decode(&[0, 0, 0, 0]),
            Err(Error::BadFrame)
        ));
    }

    #[test]
    fn end_with_a_body_is_bad_frame() {
        // `End` is a bare tag; trailing bytes mean the peer is speaking a
        // different protocol.
        assert!(matches!(
            ReplayFrame::decode(&[0, 0, 0, 2, TAG_END, 0]),
            Err(Error::BadFrame)
        ));
    }

    #[test]
    fn malformed_request_json_is_a_decode_error() {
        assert!(matches!(
            ReplayFrame::decode(&[0, 0, 0, 3, TAG_REQUEST, b'{', b'}']),
            Err(Error::Decode(_))
        ));
    }

    #[test]
    fn malformed_item_json_is_a_decode_error() {
        assert!(matches!(
            ReplayFrame::decode(&[0, 0, 0, 2, TAG_ITEM, b'x']),
            Err(Error::Decode(_))
        ));
    }

    #[test]
    fn short_and_absent_length_prefixes_are_none() {
        for buf in [&[][..], &[0][..], &[0, 0][..], &[0, 0, 0][..]] {
            assert!(ReplayFrame::decode(buf).unwrap().is_none());
        }
    }

    /// The memory bound on the reader. A peer that claims 4 GiB and then
    /// dribbles bytes must be refused the moment the length prefix lands, not
    /// waited on — waiting is what turns a four-byte write into a remote OOM.
    #[test]
    fn a_huge_length_prefix_is_refused_immediately() {
        assert!(matches!(
            ReplayFrame::decode(&[0xff, 0xff, 0xff, 0xff, TAG_END]),
            Err(Error::BadFrame)
        ));
        // One byte over the cap is over the cap; the cap itself still waits for
        // the body, since a frame that size is legal.
        let over = ((MAX_REPLAY_FRAME + 1) as u32).to_be_bytes();
        assert!(matches!(ReplayFrame::decode(&over), Err(Error::BadFrame)));
        let at = (MAX_REPLAY_FRAME as u32).to_be_bytes();
        assert!(ReplayFrame::decode(&at).unwrap().is_none());
    }

    /// The cap is symmetric: a frame too big to decode is too big to encode, so
    /// this side never emits something a conforming peer must drop.
    #[test]
    fn an_oversized_frame_is_refused_by_encode() {
        let huge = ReplayFrame::Denied {
            reason: "x".repeat(MAX_REPLAY_FRAME + 1),
        };
        assert!(matches!(huge.encode(), Err(Error::BadFrame)));

        // And the largest legal frame still round-trips.
        let big = ReplayFrame::Denied {
            reason: "x".repeat(MAX_REPLAY_FRAME - 1),
        };
        let enc = big.encode().unwrap();
        assert_eq!(enc.len(), 4 + MAX_REPLAY_FRAME);
        assert_eq!(ReplayFrame::decode(&enc).unwrap().unwrap().0, big);
    }
}

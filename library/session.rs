//! Session protocol frames and their self-delimiting wire codec.
//!
//! A session carries a small set of [`Frame`]s over a single bidirectional
//! stream: an opening [`Frame::Handshake`] that presents the dialer's grant,
//! then tagged stdio chunks ([`Frame::Stdin`] / [`Frame::Stdout`] /
//! [`Frame::Stderr`]) and a final [`Frame::Exit`] carrying the child's exit
//! code.
//!
//! This module is **pure and async-free**: [`Frame::encode`] produces the
//! length-prefixed bytes and [`Frame::decode`] parses one frame back out of a
//! buffer (returning `None` until a whole frame has arrived, so a reader can
//! split frames off a growing stream). The async glue that pumps these over an
//! iroh stream lives in the `wires` binary's transport module.
//!
//! # Wire format
//!
//! Each frame is a 4-byte big-endian length `N` followed by `N` payload bytes.
//! The payload is a 1-byte tag then a tag-specific body:
//!
//! | tag  | variant     | body                                       |
//! |------|-------------|--------------------------------------------|
//! | `0`  | `Handshake` | canonical-JSON of the handshake envelope   |
//! | `1`  | `Stdin`     | raw chunk bytes                            |
//! | `2`  | `Stdout`    | raw chunk bytes                            |
//! | `3`  | `Stderr`    | raw chunk bytes                            |
//! | `4`  | `Exit`      | 4-byte big-endian `i32`                    |
//! | `5`  | `HandshakeAck` | canonical-JSON of the ack envelope      |
//!
//! The handshake envelope is the canonical JSON of a [`Membership`] plus an
//! optional [`Grant`]. The envelope itself is *unsigned* — the signed objects
//! are the membership and grant nested inside, each with its own fixed signed
//! body — so omitting the absent grant via `skip_serializing_if` is safe here.

use serde::{Deserialize, Serialize};

use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::grant::Grant;
use crate::membership::Membership;
use crate::roster::InclusionProof;

const TAG_HANDSHAKE: u8 = 0;
const TAG_STDIN: u8 = 1;
const TAG_STDOUT: u8 = 2;
const TAG_STDERR: u8 = 3;
const TAG_EXIT: u8 = 4;
const TAG_HANDSHAKE_ACK: u8 = 5;

/// A chunk of stdio bytes carried in a [`Frame`].
///
/// A newtype rather than a bare `Vec<u8>` so the type system keeps stdio
/// payloads distinct from other byte blobs (per the project convention).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Chunk(Vec<u8>);

impl Chunk {
    /// Wrap owned bytes as a chunk.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the chunk's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The chunk's length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the chunk carries no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The unsigned wire envelope for a [`Frame::Handshake`]: a mandatory membership,
/// an optional scope grant, and an optional roster inclusion proof, serialized as
/// one canonical-JSON blob. `skip_serializing_if` is safe here precisely because
/// this struct is *not* signed — the membership, grant, and the head a proof is
/// checked against are each signed independently over their own fixed bodies.
#[derive(Serialize, Deserialize)]
struct HandshakeBody {
    membership: Membership,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grant: Option<Grant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof: Option<InclusionProof>,
}

/// The unsigned wire envelope for a [`Frame::HandshakeAck`]: the responder's own
/// membership and an optional inclusion proof.
#[derive(Serialize, Deserialize)]
struct HandshakeAckBody {
    membership: Membership,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof: Option<InclusionProof>,
}

/// One framed message on a capability-scoped session.
///
/// The `Handshake` variant (membership + optional grant) is much larger than the
/// stdio variants, but it is sent exactly once per session while the small
/// chunk frames dominate; boxing it would only add indirection to the
/// public API for no meaningful gain on the hot path.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Frame {
    /// Opening frame: the dialer presents its fabric membership (always), the
    /// matching grant for a scoped session, and a roster inclusion proof when a
    /// head-enforcing responder requires one.
    Handshake {
        /// The membership proving the dialer belongs to the fabric.
        membership: Membership,
        /// The grant authorizing a specific scope, when one is being requested.
        /// `None` for an inclusion-only session.
        grant: Option<Grant>,
        /// The dialer's roster inclusion proof, when presenting one.
        proof: Option<InclusionProof>,
    },
    /// First frame back from the responder: its own membership (so a ticket-less
    /// dialer can verify the service's fabric membership before streaming stdin)
    /// and, optionally, its own inclusion proof.
    HandshakeAck {
        /// The responder's membership.
        membership: Membership,
        /// The responder's inclusion proof, if it presents one.
        proof: Option<InclusionProof>,
    },
    /// A chunk of the child process's stdin.
    Stdin(Chunk),
    /// A chunk of the child process's stdout.
    Stdout(Chunk),
    /// A chunk of the child process's stderr.
    Stderr(Chunk),
    /// The child process's exit code.
    Exit(i32),
}

impl Frame {
    /// Encode this frame to its length-prefixed wire bytes (see the module docs).
    ///
    /// ```
    /// use library::{Chunk, Frame};
    /// let f = Frame::Stdout(Chunk::from_bytes(b"hi".to_vec()));
    /// let bytes = f.encode().unwrap();
    /// let (decoded, consumed) = Frame::decode(&bytes).unwrap().unwrap();
    /// assert_eq!(decoded, f);
    /// assert_eq!(consumed, bytes.len());
    /// // A partial buffer yields `None` until the whole frame has arrived.
    /// assert!(Frame::decode(&bytes[..bytes.len() - 1]).unwrap().is_none());
    /// ```
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        match self {
            Frame::Handshake {
                membership,
                grant,
                proof,
            } => {
                payload.push(TAG_HANDSHAKE);
                let body = HandshakeBody {
                    membership: membership.clone(),
                    grant: grant.clone(),
                    proof: proof.clone(),
                };
                payload.extend_from_slice(&canonical_bytes(&body)?);
            }
            Frame::HandshakeAck { membership, proof } => {
                payload.push(TAG_HANDSHAKE_ACK);
                let body = HandshakeAckBody {
                    membership: membership.clone(),
                    proof: proof.clone(),
                };
                payload.extend_from_slice(&canonical_bytes(&body)?);
            }
            Frame::Stdin(chunk) => {
                payload.push(TAG_STDIN);
                payload.extend_from_slice(chunk.as_bytes());
            }
            Frame::Stdout(chunk) => {
                payload.push(TAG_STDOUT);
                payload.extend_from_slice(chunk.as_bytes());
            }
            Frame::Stderr(chunk) => {
                payload.push(TAG_STDERR);
                payload.extend_from_slice(chunk.as_bytes());
            }
            Frame::Exit(code) => {
                payload.push(TAG_EXIT);
                payload.extend_from_slice(&code.to_be_bytes());
            }
        }
        let len: u32 = payload.len().try_into().map_err(|_| Error::BadFrame)?;
        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    /// Decode the first frame in `buf`.
    ///
    /// Returns `Ok(None)` if `buf` does not yet hold a complete frame (the
    /// caller should read more bytes and retry), `Ok(Some((frame, consumed)))`
    /// otherwise — where `consumed` is how many leading bytes the frame
    /// occupied — and [`Error::BadFrame`] / [`Error::Decode`] on a malformed
    /// frame. Never panics.
    pub fn decode(buf: &[u8]) -> Result<Option<(Frame, usize)>> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let end = 4 + len;
        if buf.len() < end {
            return Ok(None);
        }
        let payload = &buf[4..end];
        let (&tag, body) = payload.split_first().ok_or(Error::BadFrame)?;
        let frame = match tag {
            TAG_HANDSHAKE => {
                let hs: HandshakeBody = serde_json::from_slice(body).map_err(Error::Decode)?;
                Frame::Handshake {
                    membership: hs.membership,
                    grant: hs.grant,
                    proof: hs.proof,
                }
            }
            TAG_HANDSHAKE_ACK => {
                let ack: HandshakeAckBody = serde_json::from_slice(body).map_err(Error::Decode)?;
                Frame::HandshakeAck {
                    membership: ack.membership,
                    proof: ack.proof,
                }
            }
            TAG_STDIN => Frame::Stdin(Chunk::from_bytes(body.to_vec())),
            TAG_STDOUT => Frame::Stdout(Chunk::from_bytes(body.to_vec())),
            TAG_STDERR => Frame::Stderr(Chunk::from_bytes(body.to_vec())),
            TAG_EXIT => {
                let arr: [u8; 4] = body.try_into().map_err(|_| Error::BadFrame)?;
                Frame::Exit(i32::from_be_bytes(arr))
            }
            _ => return Err(Error::BadFrame),
        };
        Ok(Some((frame, end)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::Scope;
    use crate::identity::NodeIdentity;
    use proptest::prelude::*;

    fn seed() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    fn bytes() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..256)
    }

    /// An arbitrary frame of any variant, covering Handshake (grant/proof
    /// present or absent) and HandshakeAck (proof present or absent).
    fn frame() -> impl Strategy<Value = Frame> {
        prop_oneof![
            (
                seed(),
                seed(),
                "[a-z.]{1,16}",
                any::<i64>(),
                any::<bool>(),
                any::<bool>()
            )
                .prop_map(|(rs, ss, sc, na, with_grant, with_proof)| {
                    let root = NodeIdentity::from_seed(rs);
                    let member = NodeIdentity::from_seed(ss).node_id();
                    let membership = Membership::mint(&root, member, 0, na).unwrap();
                    let grant =
                        with_grant.then(|| Grant::mint(&root, member, Scope::new(sc), na).unwrap());
                    let proof = with_proof.then(|| {
                        let mut roster = crate::roster::Roster::new(root.node_id());
                        roster.insert(member);
                        let (_head, proofs) = roster.commit(&root, 0, na).unwrap();
                        proofs.into_iter().next().unwrap().1
                    });
                    Frame::Handshake {
                        membership,
                        grant,
                        proof,
                    }
                }),
            (seed(), seed(), any::<i64>(), any::<bool>()).prop_map(|(rs, ss, na, with_proof)| {
                let root = NodeIdentity::from_seed(rs);
                let member = NodeIdentity::from_seed(ss).node_id();
                let membership = Membership::mint(&root, member, 0, na).unwrap();
                let proof = with_proof.then(|| {
                    let mut roster = crate::roster::Roster::new(root.node_id());
                    roster.insert(member);
                    let (_head, proofs) = roster.commit(&root, 0, na).unwrap();
                    proofs.into_iter().next().unwrap().1
                });
                Frame::HandshakeAck { membership, proof }
            }),
            bytes().prop_map(|b| Frame::Stdin(Chunk::from_bytes(b))),
            bytes().prop_map(|b| Frame::Stdout(Chunk::from_bytes(b))),
            bytes().prop_map(|b| Frame::Stderr(Chunk::from_bytes(b))),
            any::<i32>().prop_map(Frame::Exit),
        ]
    }

    proptest! {
        /// Every frame survives an encode/decode round-trip, reporting the
        /// exact number of bytes it occupied.
        #[test]
        fn roundtrips(f in frame()) {
            let enc = f.encode().unwrap();
            let (dec, consumed) = Frame::decode(&enc).unwrap().unwrap();
            prop_assert_eq!(dec, f);
            prop_assert_eq!(consumed, enc.len());
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
            while let Some((f, n)) = Frame::decode(&buf[off..]).unwrap() {
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
                prop_assert!(Frame::decode(&enc[..cut]).unwrap().is_none());
            }
        }

        /// Arbitrary bytes decode to `Ok`/`Err`, never a panic.
        #[test]
        fn garbage_never_panics(b in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = Frame::decode(&b);
        }
    }

    #[test]
    fn exit_has_known_layout() {
        // len = 5 (tag + 4-byte code); tag = 4; code 0 = four zero bytes.
        assert_eq!(
            Frame::Exit(0).encode().unwrap(),
            vec![0, 0, 0, 5, TAG_EXIT, 0, 0, 0, 0]
        );
    }

    #[test]
    fn exit_roundtrips_negative() {
        let enc = Frame::Exit(-1).encode().unwrap();
        let (dec, _) = Frame::decode(&enc).unwrap().unwrap();
        assert_eq!(dec, Frame::Exit(-1));
    }

    #[test]
    fn empty_stdin_chunk_roundtrips() {
        let f = Frame::Stdin(Chunk::from_bytes(Vec::new()));
        let enc = f.encode().unwrap();
        assert_eq!(enc, vec![0, 0, 0, 1, TAG_STDIN]);
        assert_eq!(Frame::decode(&enc).unwrap().unwrap().0, f);
    }

    #[test]
    fn unknown_tag_is_bad_frame() {
        // len = 1, tag = 9 (unknown).
        assert!(matches!(
            Frame::decode(&[0, 0, 0, 1, 9]),
            Err(Error::BadFrame)
        ));
    }

    #[test]
    fn exit_with_wrong_body_length_is_bad_frame() {
        // len = 2: TAG_EXIT plus a single (too-short) code byte.
        assert!(matches!(
            Frame::decode(&[0, 0, 0, 2, TAG_EXIT, 0]),
            Err(Error::BadFrame)
        ));
    }
}

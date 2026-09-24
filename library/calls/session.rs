//! Session protocol frames and their self-delimiting wire codec.
//!
//! A session carries a small set of [`Frame`]s over a single bidirectional
//! stream: an opening [`Frame::Hello`] that presents the dialer's membership,
//! state version and ID token, then tagged stdio chunks ([`Frame::Stdin`] / [`Frame::Stdout`] /
//! [`Frame::Stderr`]) and a final [`Frame::Exit`] carrying the child's exit
//! code. A responder that refuses the handshake answers with a terminal
//! [`Frame::Denied`] carrying the human-readable reason instead of an ack, so
//! the dialer can say *why* it was turned away rather than reporting a bare
//! dropped connection.
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
//! | `0`  | —           | retired (the channel-era `Handshake`)      |
//! | `1`  | `Stdin`     | raw chunk bytes                            |
//! | `2`  | `Stdout`    | raw chunk bytes                            |
//! | `3`  | `Stderr`    | raw chunk bytes                            |
//! | `4`  | `Exit`      | 4-byte big-endian `i32`                    |
//! | `5`  | —           | retired (the channel-era `HandshakeAck`)   |
//! | `6`  | `Denied`    | UTF-8 reason bytes                         |
//! | `7`  | `Invoke`    | canonical-JSON of the [`Invocation`]       |
//! | `8`  | `Hello`     | canonical-JSON of the [`Hello`] (card 27)  |
//! | `9`  | `HelloAck`  | canonical-JSON of the [`HelloAck`] (card 27) |
//!
//! A dialer sends [`Frame::Invoke`] immediately after its `Hello`, without
//! waiting for the ack — the host reads both, authorizes them together, and
//! only then answers with `HelloAck` or `Denied`.
//!
//! [`Hello`] and [`HelloAck`] are unsigned envelopes: each part verifies on
//! its own (the membership under the root, the ID token under the IdP's keys
//! and its nonce binding to the iroh-authenticated caller, the state under
//! the root), so omitting an absent part via `skip_serializing_if` is safe.

use serde::{Deserialize, Serialize};

use crate::codec::{canonical_bytes, length_prefixed, split_frame};
use crate::error::{Error, Result};
use crate::idp::IdToken;
use crate::invoke::Invocation;
use crate::membership::Membership;
use crate::state::{SignedState, StateVersion};

const TAG_STDIN: u8 = 1;
const TAG_STDOUT: u8 = 2;
const TAG_STDERR: u8 = 3;
const TAG_EXIT: u8 = 4;
const TAG_DENIED: u8 = 6;
const TAG_INVOKE: u8 = 7;
const TAG_HELLO: u8 = 8;
const TAG_HELLO_ACK: u8 = 9;

/// The services-era opening frame (card 27), dialer → host, followed at once
/// by [`Frame::Invoke`]. Unsigned envelope: each part verifies on its own
/// (the membership under the root, the token under the IdP's keys and the
/// nonce binding to the iroh-authenticated caller).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    /// The dialer's root-signed membership.
    pub membership: Membership,
    /// The signed-state version the dialer holds (0: none). A host holding a
    /// newer one answers with it in [`HelloAck::newer_state`] or refuses a
    /// removed member; a host holding an older one pulls it.
    pub state_version: StateVersion,
    /// The dialer's IdP ID token (nonce-bound to its node key), when it has
    /// logged in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<IdToken>,
}

/// The host's answer to an admitted [`Hello`]: its own membership (the
/// dialer verifies it before sending stdin), its state version, and, when the
/// dialer's copy is older, the newer state so the dialer can adopt it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloAck {
    /// The host's root-signed membership.
    pub membership: Membership,
    /// The signed-state version the host decided under.
    pub state_version: StateVersion,
    /// The host's newer state, when the dialer's was older.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub newer_state: Option<SignedState>,
}

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

/// One framed message on a session.
///
/// The `Hello` variants are much larger than the stdio variants, but each is
/// sent exactly once per session while the small chunk frames dominate;
/// boxing them would only add indirection to the public API for no
/// meaningful gain on the hot path.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Frame {
    /// A chunk of the child process's stdin.
    Stdin(Chunk),
    /// A chunk of the child process's stdout.
    Stdout(Chunk),
    /// A chunk of the child process's stderr.
    Stderr(Chunk),
    /// The child process's exit code.
    Exit(i32),
    /// Terminal frame from the responder: the call was refused, with a
    /// human-readable reason. Sent instead of a `HelloAck`, after which the
    /// responder closes. Carries no secrets — the reason describes the dialer's
    /// own credential.
    Denied {
        /// Why the session was refused (e.g. `membership rejected: revoked`).
        reason: String,
    },
    /// Dialer → host, right after `Hello`: which service to run and the
    /// per-call arguments.
    Invoke(Invocation),
    /// The opening frame: membership, state version, ID token.
    Hello(Hello),
    /// The host's ack to an admitted [`Hello`].
    HelloAck(HelloAck),
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
    ///
    /// // A refusal round-trips its reason verbatim.
    /// let denied = Frame::Denied { reason: "membership rejected: revoked".into() };
    /// let bytes = denied.encode().unwrap();
    /// assert_eq!(Frame::decode(&bytes).unwrap().unwrap().0, denied);
    /// ```
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        match self {
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
            Frame::Denied { reason } => {
                payload.push(TAG_DENIED);
                payload.extend_from_slice(reason.as_bytes());
            }
            Frame::Invoke(invocation) => {
                payload.push(TAG_INVOKE);
                payload.extend_from_slice(&canonical_bytes(invocation)?);
            }
            Frame::Hello(hello) => {
                payload.push(TAG_HELLO);
                payload.extend_from_slice(&canonical_bytes(hello)?);
            }
            Frame::HelloAck(ack) => {
                payload.push(TAG_HELLO_ACK);
                payload.extend_from_slice(&canonical_bytes(ack)?);
            }
        }
        length_prefixed(&payload)
    }

    /// Decode the first frame in `buf`.
    ///
    /// Returns `Ok(None)` if `buf` does not yet hold a complete frame (the
    /// caller should read more bytes and retry), `Ok(Some((frame, consumed)))`
    /// otherwise — where `consumed` is how many leading bytes the frame
    /// occupied — and [`Error::BadFrame`] / [`Error::Decode`] on a malformed
    /// frame. Never panics.
    pub fn decode(buf: &[u8]) -> Result<Option<(Frame, usize)>> {
        let Some((payload, end)) = split_frame(buf) else {
            return Ok(None);
        };
        let (&tag, body) = payload.split_first().ok_or(Error::BadFrame)?;
        let frame = match tag {
            TAG_STDIN => Frame::Stdin(Chunk::from_bytes(body.to_vec())),
            TAG_STDOUT => Frame::Stdout(Chunk::from_bytes(body.to_vec())),
            TAG_STDERR => Frame::Stderr(Chunk::from_bytes(body.to_vec())),
            TAG_EXIT => {
                let arr: [u8; 4] = body.try_into().map_err(|_| Error::BadFrame)?;
                Frame::Exit(i32::from_be_bytes(arr))
            }
            TAG_DENIED => Frame::Denied {
                reason: String::from_utf8(body.to_vec()).map_err(|_| Error::BadFrame)?,
            },
            TAG_INVOKE => Frame::Invoke(serde_json::from_slice(body).map_err(Error::Decode)?),
            TAG_HELLO => Frame::Hello(serde_json::from_slice(body).map_err(Error::Decode)?),
            TAG_HELLO_ACK => Frame::HelloAck(serde_json::from_slice(body).map_err(Error::Decode)?),
            _ => return Err(Error::BadFrame),
        };
        Ok(Some((frame, end)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use proptest::prelude::*;

    fn seed() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    fn bytes() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..256)
    }

    /// An arbitrary frame of any variant.
    fn frame() -> impl Strategy<Value = Frame> {
        prop_oneof![
            bytes().prop_map(|b| Frame::Stdin(Chunk::from_bytes(b))),
            bytes().prop_map(|b| Frame::Stdout(Chunk::from_bytes(b))),
            bytes().prop_map(|b| Frame::Stderr(Chunk::from_bytes(b))),
            any::<i32>().prop_map(Frame::Exit),
            any::<String>().prop_map(|reason| Frame::Denied { reason }),
            (
                "[a-z][a-z0-9_-]{0,20}",
                proptest::collection::vec("[^\u{0}]{0,16}", 0..6)
            )
                .prop_map(|(service, args)| Frame::Invoke(crate::invoke::Invocation {
                    service: crate::registry::ServiceName::new(service).unwrap(),
                    argv: crate::invoke::Argv::new(args).unwrap(),
                })),
            (
                seed(),
                seed(),
                any::<u64>(),
                proptest::option::of("[a-zA-Z0-9._-]{1,40}")
            )
                .prop_map(|(rs, ss, v, token)| {
                    let root = NodeIdentity::from_seed(rs);
                    let member = NodeIdentity::from_seed(ss).node_id();
                    Frame::Hello(Hello {
                        membership: Membership::mint(&root, member, 0, 1).unwrap(),
                        state_version: StateVersion(v),
                        id_token: token.map(IdToken::new),
                    })
                }),
            (seed(), any::<u64>(), any::<bool>()).prop_map(|(rs, v, with_state)| {
                let root = NodeIdentity::from_seed(rs);
                let newer_state = with_state.then(|| {
                    let mut s = crate::state::State::new(root.node_id());
                    s.version = StateVersion(v);
                    s.sign(&root).unwrap()
                });
                Frame::HelloAck(HelloAck {
                    membership: Membership::mint(&root, root.node_id(), 0, 1).unwrap(),
                    state_version: StateVersion(v),
                    newer_state,
                })
            }),
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

        /// A denial's reason survives a round-trip verbatim, for any string.
        #[test]
        fn denied_reason_roundtrips(reason in any::<String>()) {
            let f = Frame::Denied { reason };
            let enc = f.encode().unwrap();
            let (dec, consumed) = Frame::decode(&enc).unwrap().unwrap();
            prop_assert_eq!(dec, f);
            prop_assert_eq!(consumed, enc.len());
        }
    }

    #[test]
    fn denied_roundtrips_empty_ascii_and_unicode() {
        for reason in ["", "membership rejected: revoked", "refusé — 拒否 🚫"] {
            let f = Frame::Denied {
                reason: reason.to_string(),
            };
            let enc = f.encode().unwrap();
            // Body is exactly the tag plus the reason's UTF-8 bytes.
            assert_eq!(enc[4], TAG_DENIED);
            assert_eq!(&enc[5..], reason.as_bytes());
            assert_eq!(Frame::decode(&enc).unwrap().unwrap().0, f);
        }
    }

    #[test]
    fn denied_with_invalid_utf8_is_bad_frame() {
        // len = 2: TAG_DENIED plus a lone 0xff, which is not valid UTF-8.
        assert!(matches!(
            Frame::decode(&[0, 0, 0, 2, TAG_DENIED, 0xff]),
            Err(Error::BadFrame)
        ));
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
    fn retired_handshake_tags_are_bad_frames() {
        assert!(matches!(
            Frame::decode(&[0, 0, 0, 3, 0, b'{', b'}']),
            Err(Error::BadFrame)
        ));
        assert!(matches!(
            Frame::decode(&[0, 0, 0, 3, 5, b'{', b'}']),
            Err(Error::BadFrame)
        ));
    }

    #[test]
    fn unknown_tag_is_bad_frame() {
        // len = 1, tag = 10 (unknown).
        assert!(matches!(
            Frame::decode(&[0, 0, 0, 1, 10]),
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

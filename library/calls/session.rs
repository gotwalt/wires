//! Session protocol frames and their self-delimiting wire codec.
//!
//! A session carries a small set of [`Frame`]s over a single bidirectional
//! stream: an opening [`Frame::Hello`] that presents the dialer's membership,
//! policy version and ID token, then tagged stdio chunks ([`Frame::Stdin`] / [`Frame::Stdout`] /
//! [`Frame::Stderr`]) and a final [`Frame::Exit`] carrying the child's exit
//! code. A host that refuses the handshake answers with a terminal
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
//! | `1`  | `Stdin`     | raw chunk bytes                            |
//! | `2`  | `Stdout`    | raw chunk bytes                            |
//! | `3`  | `Stderr`    | raw chunk bytes                            |
//! | `4`  | `Exit`      | 4-byte big-endian `i32`                    |
//! | `6`  | `Denied`    | UTF-8 reason bytes                         |
//! | `7`  | `Invoke`    | canonical-JSON of the [`Invocation`]       |
//! | `8`  | `Hello`     | canonical-JSON of the [`Hello`]            |
//! | `9`  | `HelloAck`  | canonical-JSON of the [`HelloAck`]         |
//!
//! Any other tag is a [`Error::BadFrame`].
//!
//! A dialer sends [`Frame::Invoke`] immediately after its `Hello`, without
//! waiting for the ack — the host reads both, authorizes them together, and
//! only then answers with `HelloAck` or `Denied`.
//!
//! [`Hello`] and [`HelloAck`] are unsigned envelopes: each part verifies on
//! its own (the membership under the root, the ID token under the IdP's keys
//! and its nonce binding to the iroh-authenticated caller, the head and the
//! service entry under the root), so omitting an absent part via
//! `skip_serializing_if` is safe.
//!
//! **The handshake carries the news** (card 37). A caller holds a view, not
//! the policy: its `Hello` names the head version of that view, and the
//! host's `HelloAck` names its own. When the host's is newer, the ack also
//! carries the host's root-signed head and the called service's root-signed
//! entry, so the caller checks the host is still assigned the service
//! ([`HelloAck::assigns`]) before it sends any stdin, then refreshes its
//! view after the call.

use serde::{Deserialize, Serialize};

use crate::codec::{canonical_bytes, length_prefixed, split_frame};
use crate::entry::SignedEntry;
use crate::error::{Error, Result};
use crate::head::{SignedPolicyHead, StateVersion};
use crate::identity::NodeId;
use crate::idp::IdToken;
use crate::invoke::Invocation;
use crate::membership::Membership;
use crate::registry::ServiceName;
use crate::signed_policy::check_entry_version;

const TAG_STDIN: u8 = 1;
const TAG_STDOUT: u8 = 2;
const TAG_STDERR: u8 = 3;
const TAG_EXIT: u8 = 4;
const TAG_DENIED: u8 = 6;
const TAG_INVOKE: u8 = 7;
const TAG_HELLO: u8 = 8;
const TAG_HELLO_ACK: u8 = 9;

/// The opening frame, dialer → host, followed at once
/// by [`Frame::Invoke`]. Unsigned envelope: each part verifies on its own
/// (the membership under the root, the token under the IdP's keys and the
/// nonce binding to the iroh-authenticated caller).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    /// The dialer's root-signed membership.
    pub membership: Membership,
    /// The head version of the dialer's view (0: none). A host holding a
    /// newer policy answers with its head and the called service's entry
    /// ([`HelloAck::head`], [`HelloAck::entry`]).
    pub state_version: StateVersion,
    /// The dialer's IdP ID token (nonce-bound to its node key), when it has
    /// logged in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<IdToken>,
}

/// The host's answer to an admitted [`Hello`]: its own membership (the
/// dialer verifies it before sending stdin), the head version it decided
/// under, and, when that is newer than the dialer's view, its head and the
/// called service's entry (see the module docs).
///
/// ```
/// use library::{HelloAck, Membership, NodeIdentity, Policy, Service, ServiceName, StateVersion};
/// let root = NodeIdentity::from_seed([1u8; 32]);
/// let host = NodeIdentity::from_seed([2u8; 32]).node_id();
/// let name = ServiceName::new("orders-db").unwrap();
/// let mut policy = Policy::new(root.node_id());
/// policy.version = StateVersion(5);
/// policy.not_after = i64::MAX;
/// policy.services.insert(name.clone(), Service {
///     description: String::new(), allow: vec![], hosts: vec![host], readers: vec![],
/// });
/// let signed = policy.sign(&root).unwrap();
/// let ack = HelloAck {
///     membership: Membership::mint(&root, host, 0, i64::MAX).unwrap(),
///     state_version: StateVersion(5),
///     head: Some(signed.head.clone()),
///     entry: signed.entries().next().cloned(),
/// };
/// // The caller's view is at version 3: the host is still assigned orders-db.
/// assert!(ack.assigns(root.node_id(), StateVersion(3), &name, host).unwrap());
/// // Another host is not.
/// let other = NodeIdentity::from_seed([3u8; 32]).node_id();
/// assert!(!ack.assigns(root.node_id(), StateVersion(3), &name, other).unwrap());
/// ```
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloAck {
    /// The host's root-signed membership.
    pub membership: Membership,
    /// The head version of the policy the host decided under.
    pub state_version: StateVersion,
    /// The host's root-signed head, when it is newer than the dialer's view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<SignedPolicyHead>,
    /// With `head`: the called service's root-signed entry under it (none
    /// if the policy no longer has the service).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<SignedEntry>,
}

impl HelloAck {
    /// Whether this ack lets a dialer whose view is at `held` go on with a
    /// call of `service` on `host` (the iroh-authenticated peer), under the
    /// fabric `root`. `Ok(true)` when the host's version is not newer than
    /// `held` (nothing new), or when its head and `service`'s entry verify
    /// under `root` and the entry still lists `host`; `Ok(false)` when the
    /// newer policy no longer assigns `service` to `host` (or no longer has
    /// it). `Err` when the ack reports a newer version without a head that
    /// verifies at that version, or carries an entry that doesn't verify,
    /// is for another service, or is newer than its head.
    pub fn assigns(
        &self,
        root: NodeId,
        held: StateVersion,
        service: &ServiceName,
        host: NodeId,
    ) -> Result<bool> {
        if self.state_version <= held {
            return Ok(true);
        }
        let head = self.head.as_ref().ok_or_else(|| {
            Error::InvalidPolicy(format!(
                "the host reports policy version {} without its head",
                self.state_version.0
            ))
        })?;
        head.verify(root)?;
        if head.head.version != self.state_version {
            return Err(Error::InvalidPolicy(format!(
                "the host's head is version {}, not the {} it reports",
                head.head.version.0, self.state_version.0
            )));
        }
        let Some(entry) = &self.entry else {
            return Ok(false);
        };
        if entry.name != *service {
            return Err(Error::InvalidPolicy(format!(
                "the host sent the entry of {}, not {service}",
                entry.name
            )));
        }
        check_entry_version(entry, head)?;
        entry.verify(root)?;
        Ok(entry.service.hosts.contains(&host))
    }
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
    /// Terminal frame from the host: the call was refused, with a
    /// human-readable reason. Sent instead of a `HelloAck`, after which the
    /// host closes. Carries no secrets — the reason describes the dialer's
    /// own credential.
    Denied {
        /// Why the session was refused (e.g. `not a member of this network`).
        reason: String,
    },
    /// Dialer → host, right after `Hello`: which service to run and the
    /// per-call arguments.
    Invoke(Invocation),
    /// The opening frame: membership, policy version, ID token.
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
    /// let denied = Frame::Denied { reason: "not a member of this network".into() };
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

    fn orders() -> ServiceName {
        ServiceName::new("orders-db").unwrap()
    }

    /// A policy at `version` in which `hosts` implement `orders-db`.
    fn signed_with(
        root: &NodeIdentity,
        version: u64,
        hosts: &[NodeId],
    ) -> crate::signed_policy::SignedPolicy {
        let mut p = crate::signed_policy::Policy::new(root.node_id());
        p.version = StateVersion(version);
        p.not_after = i64::MAX;
        p.services.insert(
            orders(),
            crate::registry::Service {
                description: String::new(),
                allow: vec![],
                hosts: hosts.to_vec(),
                readers: vec![],
            },
        );
        p.sign(root).unwrap()
    }

    /// An ack from `host` at `signed`'s version, with its news.
    fn ack(
        root: &NodeIdentity,
        host: NodeId,
        signed: &crate::signed_policy::SignedPolicy,
    ) -> HelloAck {
        HelloAck {
            membership: Membership::mint(root, host, 0, i64::MAX).unwrap(),
            state_version: signed.version(),
            head: Some(signed.head.clone()),
            entry: signed.entries().next().cloned(),
        }
    }

    #[test]
    fn an_ack_says_whether_the_host_is_still_assigned() {
        let root = NodeIdentity::from_seed([1; 32]);
        let host = NodeIdentity::from_seed([2; 32]).node_id();
        let other = NodeIdentity::from_seed([3; 32]).node_id();
        let r = root.node_id();
        let v5 = signed_with(&root, 5, &[host]);
        let ack5 = ack(&root, host, &v5);
        assert!(ack5.assigns(r, StateVersion(4), &orders(), host).unwrap());
        assert!(!ack5.assigns(r, StateVersion(4), &orders(), other).unwrap());
        // Nothing new: nothing to check, even with no head.
        let mut bare = ack5.clone();
        bare.head = None;
        bare.entry = None;
        assert!(bare.assigns(r, StateVersion(5), &orders(), other).unwrap());
        // Newer without a head: refused.
        assert!(bare.assigns(r, StateVersion(4), &orders(), host).is_err());
        // The service is gone: not assigned.
        let mut gone = ack5.clone();
        gone.entry = None;
        assert!(!gone.assigns(r, StateVersion(4), &orders(), host).unwrap());
        // A forged entry, another service's entry, another root, a head at
        // another version: refused.
        let mut forged = ack5.clone();
        forged.entry.as_mut().unwrap().service.hosts.push(other);
        assert!(
            forged
                .assigns(r, StateVersion(4), &orders(), other)
                .is_err()
        );
        let status = ServiceName::new("status").unwrap();
        assert!(ack5.assigns(r, StateVersion(4), &status, host).is_err());
        let rogue = NodeIdentity::from_seed([9; 32]).node_id();
        assert!(
            ack5.assigns(rogue, StateVersion(4), &orders(), host)
                .is_err()
        );
        let mut skewed = ack5;
        skewed.state_version = StateVersion(6);
        assert!(skewed.assigns(r, StateVersion(4), &orders(), host).is_err());
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
            (seed(), any::<u64>(), any::<bool>()).prop_map(|(rs, v, with_news)| {
                let root = NodeIdentity::from_seed(rs);
                let (head, entry) = if with_news {
                    let signed = signed_with(&root, v, &[root.node_id()]);
                    (Some(signed.head.clone()), signed.entries().next().cloned())
                } else {
                    (None, None)
                };
                Frame::HelloAck(HelloAck {
                    membership: Membership::mint(&root, root.node_id(), 0, 1).unwrap(),
                    state_version: StateVersion(v),
                    head,
                    entry,
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
    }

    #[test]
    fn denied_roundtrips_empty_ascii_and_unicode() {
        for reason in ["", "not a member of this network", "refusé — 拒否 🚫"] {
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
    fn empty_stdin_chunk_roundtrips() {
        let f = Frame::Stdin(Chunk::from_bytes(Vec::new()));
        let enc = f.encode().unwrap();
        assert_eq!(enc, vec![0, 0, 0, 1, TAG_STDIN]);
        assert_eq!(Frame::decode(&enc).unwrap().unwrap().0, f);
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

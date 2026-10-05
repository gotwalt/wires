//! The directory's two protocols (card 36): requests on [`DIRECTORY_ALPN`]
//! and a host's subscription on [`DIRECTORY_SUB_ALPN`].
//!
//! Hosts and directories hold the whole signed policy; a caller holds its
//! [`View`]: the services it may use, each a root-signed entry. Both travel
//! whole (card 45): a whole policy checks against its head's one signature,
//! and a view's entries each carry their own.
//!
//! **`wires/directory/3`**: one request per stream. The dialer sends
//! [`DirectoryRequest::Hello`] (its ID token when it acts for a person;
//! none from a host, a directory or the admin) then one request, and the
//! directory answers once:
//!
//! | request | answer |
//! |---|---|
//! | `publish {head}`, then `items {items}` only if asked for | `published {version, head}`: the version it now holds and that head's [`HeadHash`] |
//! | `policy {have}` | the whole policy for a host or directory: `policy {policy, fresh}`, or `current {fresh}` when `have` is the newest |
//! | `view {query?}` | the caller's whole view: `view {view, fresh}` |
//! | `resolve {service}` | `view {view, fresh}` holding just that service, or no entry |
//! | anything refused | `denied {reason}` |
//!
//! A dialer that will present an ID token first sends
//! [`DirectoryRequest::Open`] and reads the directory's
//! [`DirectoryAnswer::Proof`] (card 45): its head and the current `Fresh`es
//! it holds, the [`HostProof`] a host shows a caller (card 49). Only once
//! that checks out does it send its `hello` and request, so a directory the
//! admin removed, or one behind the caller's view, is never told a token.
//!
//! **`wires/directory-sub/3`**: the dialer sends `hello` then
//! [`SubRequest::Subscribe`] with the version it holds (only a host or a
//! directory may), and the directory streams [`SubFrame`]s: the whole
//! `policy` whenever its head is newer than what the subscriber has, else
//! its `fresh` for its own head (at once, and every beat), or a terminal
//! `denied`.
//!
//! Who is admitted is the directory's to decide (protocol §4): a node the
//! held policy names, a caller whose token verifies and whom
//! [`check_admitted`](crate::check_admitted) admits, and, for a `publish`
//! only, anyone, since the root's signature is the whole check. The caller
//! is always the iroh-authenticated key, never a field. Frames are a 4-byte
//! big-endian length then canonical JSON tagged by `type`. The length is
//! checked before anything is allocated: every request, the `hello`
//! included, is at most [`MAX_SMALL_DIRECTORY_FRAME`]; only the
//! [`DirectoryRequest::Items`] of a publish (at most
//! [`MAX_DIRECTORY_FRAME`]) is larger, and a directory reads it only after
//! the publish's head verified under the root and is newer than its own, so
//! nobody without a root-signed newer head can make it read a large body.
//!
//! ```
//! use library::{DirectoryRequest, StateVersion};
//! let req = DirectoryRequest::Policy { have: StateVersion(3) };
//! let bytes = req.encode().unwrap();
//! assert_eq!(DirectoryRequest::decode(&bytes).unwrap(), Some((req, bytes.len())));
//! ```

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::codec::{canonical_bytes, length_prefixed, prefix_len, split_frame};
use crate::error::{Error, Result};
use crate::fresh::Fresh;
use crate::head::{HeadHash, SignedPolicyHead, StateVersion};
use crate::idp::IdToken;
use crate::item::Item;
use crate::proof::HostProof;
use crate::registry::ServiceName;
use crate::signed_policy::SignedPolicy;
use crate::view::View;

/// The ALPN of the directory's request protocol.
pub const DIRECTORY_ALPN: &[u8] = b"wires/directory/3";

/// The ALPN of a host's subscription to the policy.
pub const DIRECTORY_SUB_ALPN: &[u8] = b"wires/directory-sub/3";

/// The largest frame either protocol accepts (a publish's `items`, or a
/// whole `policy` of a large network), checked from the length prefix before
/// allocating.
pub const MAX_DIRECTORY_FRAME: usize = 16 * 1024 * 1024;

/// The largest request but a publish's `items`: a `hello` (an ID token, a
/// few KB), a publish's signed head, or a small request.
pub const MAX_SMALL_DIRECTORY_FRAME: usize = 16 * 1024;

/// A dialer's frame on [`DIRECTORY_ALPN`]. See the module docs.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectoryRequest {
    /// Opens a stream whose dialer will present an ID token: the directory
    /// answers with its [`DirectoryAnswer::Proof`] first, and the dialer
    /// sends its `hello` only once that checks out.
    Open {},
    /// Opens every other stream, or follows the directory's proof.
    Hello {
        /// Its IdP ID token, nonce-bound to its node key, when it acts for
        /// a person (a view needs it; a host's policy and a publish don't).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id_token: Option<IdToken>,
    },
    /// A new signed policy's head, from anyone. When it verifies under the
    /// directory's root, is fresh and is newer than what it holds, the
    /// directory reads the [`Items`](Self::Items) frame that follows;
    /// otherwise it answers at once.
    Publish {
        /// The signed head.
        head: SignedPolicyHead,
    },
    /// The items of the policy whose head a [`Publish`](Self::Publish) just
    /// sent: read only after that head checked out. The only frame larger
    /// than [`MAX_SMALL_DIRECTORY_FRAME`].
    Items {
        /// Every item, in key order.
        items: Vec<Item>,
    },
    /// The whole signed policy, for a host or a directory (a node that holds
    /// all of it).
    Policy {
        /// The version the dialer holds (0: none).
        have: StateVersion,
    },
    /// The dialer's whole caller view (card 37): the services its verified
    /// identity may call.
    View {
        /// Only entries whose name or description match this.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        query: Option<String>,
    },
    /// One service, only if it is in the dialer's view (card 37).
    Resolve {
        /// The service.
        service: ServiceName,
    },
}

/// The directory's answer on [`DIRECTORY_ALPN`]. See the module docs.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectoryAnswer {
    /// The answer to [`DirectoryRequest::Open`]: the directory's head and
    /// the current `Fresh`es it holds for it, no entries. Not terminal: the
    /// dialer's `hello` and request follow.
    Proof {
        /// The proof.
        proof: HostProof,
    },
    /// A publish's head verified; this is the policy the directory now
    /// holds (the published one, or one it already had at that version or
    /// newer).
    Published {
        /// The directory's version.
        version: StateVersion,
        /// Its head's hash: the publisher compares it with its own to tell
        /// a stale copy at the same version.
        head: HeadHash,
    },
    /// The dialer's `have` is the newest head: nothing to send but freshness.
    Current {
        /// The directory's `Fresh` for that head.
        fresh: Fresh,
    },
    /// The whole signed policy.
    Policy {
        /// The newest signed policy.
        policy: SignedPolicy,
        /// The directory's `Fresh` for its head.
        fresh: Fresh,
    },
    /// A caller's view (or, for `resolve`, the one-entry or empty view).
    View {
        /// The view.
        view: View,
        /// The directory's `Fresh` for its head.
        fresh: Fresh,
    },
    /// Terminal refusal.
    Denied {
        /// Why, in words.
        reason: String,
    },
}

/// A subscriber's frame on [`DIRECTORY_SUB_ALPN`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SubRequest {
    /// Opens the stream, as on [`DIRECTORY_ALPN`] (a host presents no
    /// token).
    Hello {
        /// An ID token, if the dialer acts for a person.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id_token: Option<IdToken>,
    },
    /// Follow the policy.
    Subscribe {
        /// The version the subscriber holds (0: none): the whole policy
        /// comes at once when the directory's is newer.
        have: StateVersion,
    },
}

/// The directory's frames on a subscription.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SubFrame {
    /// The whole signed policy: its head is newer than what the subscriber
    /// has.
    Policy {
        /// The whole policy.
        policy: SignedPolicy,
        /// The `Fresh` for its head.
        fresh: Fresh,
    },
    /// A beat: the directory's `Fresh` for its own head (which may be older
    /// than the subscriber's: then the directory is behind it).
    Fresh {
        /// The new `Fresh`.
        fresh: Fresh,
    },
    /// Terminal refusal (or the subscriber cap is reached).
    Denied {
        /// Why, in words.
        reason: String,
    },
}

impl DirectoryRequest {
    /// Encode as length-prefixed canonical JSON.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_frame(self)
    }

    /// Decode the first frame in `buf`: `Ok(None)` until a whole frame has
    /// arrived; an error for a prefix over [`MAX_DIRECTORY_FRAME`] or a
    /// malformed body. A reader caps what it reads before this: at most
    /// [`MAX_SMALL_DIRECTORY_FRAME`] for anything but the `items` it asked
    /// for.
    ///
    /// ```
    /// use library::{DirectoryRequest, StateVersion};
    /// let req = DirectoryRequest::Hello { id_token: None };
    /// let bytes = req.encode().unwrap();
    /// assert_eq!(&bytes[4..], br#"{"type":"hello"}"#);
    /// assert_eq!(DirectoryRequest::decode(&bytes).unwrap(), Some((req, bytes.len())));
    /// ```
    pub fn decode(buf: &[u8]) -> Result<Option<(DirectoryRequest, usize)>> {
        decode_frame(buf, MAX_DIRECTORY_FRAME)
    }
}

impl DirectoryAnswer {
    /// Encode as length-prefixed canonical JSON.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_frame(self)
    }

    /// Decode the first frame in `buf` (at most [`MAX_DIRECTORY_FRAME`]).
    pub fn decode(buf: &[u8]) -> Result<Option<(DirectoryAnswer, usize)>> {
        decode_frame(buf, MAX_DIRECTORY_FRAME)
    }
}

impl SubRequest {
    /// Encode as length-prefixed canonical JSON.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_frame(self)
    }

    /// Decode the first frame in `buf` (at most
    /// [`MAX_SMALL_DIRECTORY_FRAME`]: a subscriber sends nothing large).
    pub fn decode(buf: &[u8]) -> Result<Option<(SubRequest, usize)>> {
        decode_frame(buf, MAX_SMALL_DIRECTORY_FRAME)
    }
}

impl SubFrame {
    /// Encode as length-prefixed canonical JSON.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_frame(self)
    }

    /// Decode the first frame in `buf` (at most [`MAX_DIRECTORY_FRAME`]).
    pub fn decode(buf: &[u8]) -> Result<Option<(SubFrame, usize)>> {
        decode_frame(buf, MAX_DIRECTORY_FRAME)
    }
}

/// Length-prefixed canonical JSON, refusing a body over
/// [`MAX_DIRECTORY_FRAME`].
fn encode_frame<T: Serialize>(frame: &T) -> Result<Vec<u8>> {
    let body = canonical_bytes(frame)?;
    if body.len() > MAX_DIRECTORY_FRAME {
        return Err(Error::BadFrame);
    }
    length_prefixed(&body)
}

/// The first whole frame in `buf`, refusing a prefix over `max` before
/// reading the body.
fn decode_frame<T: DeserializeOwned>(buf: &[u8], max: usize) -> Result<Option<(T, usize)>> {
    if prefix_len(buf).is_some_and(|len| len > max) {
        return Err(Error::BadFrame);
    }
    let Some((body, end)) = split_frame(buf) else {
        return Ok(None);
    };
    let frame = serde_json::from_slice(body).map_err(Error::Decode)?;
    Ok(Some((frame, end)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use crate::signed_policy::fixtures::*;
    use proptest::prelude::*;

    fn fresh(policy: &SignedPolicy) -> Fresh {
        Fresh::sign(&NodeIdentity::from_seed([30u8; 32]), &policy.head, 0, 900).unwrap()
    }

    /// A body of `len` bytes behind its prefix.
    fn raw(body: &[u8]) -> Vec<u8> {
        let mut buf = (body.len() as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(body);
        buf
    }

    fn requests() -> Vec<DirectoryRequest> {
        let signed = sample().sign(&root()).unwrap();
        vec![
            DirectoryRequest::Open {},
            DirectoryRequest::Hello { id_token: None },
            DirectoryRequest::Hello {
                id_token: Some(IdToken::new("a.b.c")),
            },
            DirectoryRequest::Publish {
                head: signed.head.clone(),
            },
            DirectoryRequest::Items {
                items: signed.items,
            },
            DirectoryRequest::Policy {
                have: StateVersion(2),
            },
            DirectoryRequest::View {
                query: Some("orders".into()),
            },
            DirectoryRequest::View { query: None },
            DirectoryRequest::Resolve {
                service: name("status"),
            },
        ]
    }

    #[test]
    fn requests_round_trip() {
        for r in requests() {
            let bytes = r.encode().unwrap();
            assert_eq!(
                DirectoryRequest::decode(&bytes).unwrap(),
                Some((r.clone(), bytes.len()))
            );
            assert_eq!(
                DirectoryRequest::decode(&bytes[..bytes.len() - 1]).unwrap(),
                None
            );
            assert_eq!(DirectoryRequest::decode(&bytes[..3]).unwrap(), None);
        }
        assert_eq!(
            DirectoryRequest::Hello { id_token: None }.encode().unwrap()[4..],
            br#"{"type":"hello"}"#[..]
        );
        assert_eq!(
            DirectoryRequest::Open {}.encode().unwrap()[4..],
            br#"{"type":"open"}"#[..]
        );
        assert_eq!(
            DirectoryRequest::Policy {
                have: StateVersion(7)
            }
            .encode()
            .unwrap()[4..],
            br#"{"have":7,"type":"policy"}"#[..]
        );
        assert_eq!(
            DirectoryRequest::View { query: None }.encode().unwrap()[4..],
            br#"{"type":"view"}"#[..]
        );
    }

    #[test]
    fn answers_and_subscription_frames_round_trip() {
        let signed = sample().sign(&root()).unwrap();
        let fresh = fresh(&signed);
        let view = signed.view_for(node(2), Some(&who("alice@example.com")), None);
        for a in [
            DirectoryAnswer::Proof {
                proof: HostProof {
                    head: signed.head.clone(),
                    fresh: vec![fresh.clone()],
                },
            },
            DirectoryAnswer::Published {
                version: StateVersion(3),
                head: signed.head.hash().unwrap(),
            },
            DirectoryAnswer::Current {
                fresh: fresh.clone(),
            },
            DirectoryAnswer::Policy {
                policy: signed.clone(),
                fresh: fresh.clone(),
            },
            DirectoryAnswer::View {
                view,
                fresh: fresh.clone(),
            },
            DirectoryAnswer::Denied {
                reason: "banned".into(),
            },
        ] {
            let bytes = a.encode().unwrap();
            assert_eq!(
                DirectoryAnswer::decode(&bytes).unwrap(),
                Some((a, bytes.len()))
            );
        }
        for f in [
            SubFrame::Policy {
                policy: signed.clone(),
                fresh: fresh.clone(),
            },
            SubFrame::Fresh { fresh },
            SubFrame::Denied {
                reason: "subscriber cap reached".into(),
            },
        ] {
            let bytes = f.encode().unwrap();
            assert_eq!(SubFrame::decode(&bytes).unwrap(), Some((f, bytes.len())));
        }
        for r in [
            SubRequest::Hello { id_token: None },
            SubRequest::Subscribe {
                have: StateVersion(1),
            },
        ] {
            let bytes = r.encode().unwrap();
            assert_eq!(SubRequest::decode(&bytes).unwrap(), Some((r, bytes.len())));
        }
    }

    /// Only a publish's items may be large: every other request, a
    /// publish's head included, fits the small limit a reader caps it at.
    #[test]
    fn only_a_publishs_items_are_large() {
        let mut p = sample();
        for b in 100..400u16 {
            let mut seed = [7u8; 32];
            seed[..2].copy_from_slice(&b.to_be_bytes());
            p.bans.insert(NodeIdentity::from_seed(seed).node_id());
        }
        let signed = p.sign(&root()).unwrap();
        let items = DirectoryRequest::Items {
            items: signed.items.clone(),
        }
        .encode()
        .unwrap();
        assert!(items.len() > MAX_SMALL_DIRECTORY_FRAME, "{}", items.len());
        assert!(DirectoryRequest::decode(&items).unwrap().is_some());
        let head = DirectoryRequest::Publish { head: signed.head }
            .encode()
            .unwrap();
        assert!(head.len() <= MAX_SMALL_DIRECTORY_FRAME);
        for r in requests() {
            if matches!(r, DirectoryRequest::Items { .. }) {
                continue;
            }
            let bytes = r.encode().unwrap();
            assert!(bytes.len() <= MAX_SMALL_DIRECTORY_FRAME, "{r:?}");
        }
    }

    #[test]
    fn oversized_prefixes_are_refused_early() {
        let over = ((MAX_DIRECTORY_FRAME + 1) as u32).to_be_bytes();
        assert!(DirectoryRequest::decode(&over).is_err());
        assert!(DirectoryAnswer::decode(&over).is_err());
        assert!(SubFrame::decode(&over).is_err());
        let over_small = ((MAX_SMALL_DIRECTORY_FRAME + 1) as u32).to_be_bytes();
        assert!(SubRequest::decode(&over_small).is_err());
    }

    /// The frames of the delta and replica paths (gone in card 45) are
    /// refused, as is anything unknown.
    #[test]
    fn unknown_frames_and_fields_are_refused() {
        for body in [
            r#"{"type":"offer"}"#,
            r#"{"type":"head"}"#,
            r#"{"type":"open","id_token":"x"}"#,
            r#"{"type":"hello","credential":"x"}"#,
            r#"{"type":"publish","head":{},"items":[]}"#,
            r#"{"type":"policy"}"#,
            r#"{"type":"policy","have":1,"x":2}"#,
            r#"{"type":"view","have":3}"#,
            r#"{"type":"view","held":"00"}"#,
            r#"{"type":"resolve","service":"Not A Name"}"#,
        ] {
            assert!(
                DirectoryRequest::decode(&raw(body.as_bytes())).is_err(),
                "{body}"
            );
        }
        for body in [
            r#"{"type":"subscribe","kind":"policy","have":0}"#,
            r#"{"type":"subscribe","kind":"replica","have":0}"#,
            r#"{"type":"subscribe"}"#,
        ] {
            assert!(SubRequest::decode(&raw(body.as_bytes())).is_err(), "{body}");
        }
        for body in [
            r#"{"type":"published"}"#,
            r#"{"type":"published","version":1}"#,
            r#"{"type":"policy_update","update":{},"fresh":{}}"#,
            r#"{"type":"view_update","update":{},"fresh":{}}"#,
        ] {
            assert!(DirectoryAnswer::decode(&raw(body.as_bytes())).is_err());
        }
        assert!(SubFrame::decode(&raw(br#"{"type":"view","view":{},"fresh":{}}"#)).is_err());
        assert!(SubFrame::decode(&raw(br#"{"type":"policy_update"}"#)).is_err());
    }

    #[test]
    fn the_alpns() {
        assert_eq!(DIRECTORY_ALPN, b"wires/directory/3");
        assert_eq!(DIRECTORY_SUB_ALPN, b"wires/directory-sub/3");
    }

    proptest! {
        #[test]
        fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = DirectoryRequest::decode(&data);
            let _ = DirectoryAnswer::decode(&data);
            let _ = SubRequest::decode(&data);
            let _ = SubFrame::decode(&data);
        }

        #[test]
        fn view_requests_round_trip(query in proptest::option::of("[a-z ]{0,16}")) {
            let r = DirectoryRequest::View { query };
            let bytes = r.encode().unwrap();
            prop_assert_eq!(DirectoryRequest::decode(&bytes).unwrap(), Some((r, bytes.len())));
        }

        /// Any whole policy survives the subscription frame and still
        /// verifies, with its `Fresh` vouching for its head.
        #[test]
        fn whole_policies_survive_the_frame(a in arb_policy()) {
            let mut a = a;
            a.directories = vec![node(30)];
            let signed = a.sign(&root()).unwrap();
            let frame = SubFrame::Policy { policy: signed.clone(), fresh: fresh(&signed) };
            let bytes = frame.encode().unwrap();
            let Some((SubFrame::Policy { policy, fresh }, _)) = SubFrame::decode(&bytes).unwrap() else {
                panic!("not a policy");
            };
            prop_assert!(fresh.verify(&policy.head).is_ok());
            prop_assert!(policy.verify(root().node_id()).is_ok());
            prop_assert_eq!(policy, signed);
        }
    }
}

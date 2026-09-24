//! The directory's two protocols (card 36): requests on [`DIRECTORY_ALPN`]
//! and subscriptions on [`DIRECTORY_SUB_ALPN`].
//!
//! **`wires/directory/1`**: one request per stream. The dialer sends
//! [`DirectoryRequest::Hello`] (its badge, and its ID token when it has one)
//! then one request, and the directory answers once:
//!
//! | request | answer |
//! |---|---|
//! | `publish {head, items}` | `published {version}`: the version it now holds |
//! | `head {}` | `head {head, fresh}` |
//! | `slice {have, roles}` | `slice_update {update, fresh}` from `have`; `slice {slice, fresh}` when `have` is 0 or no longer kept; `current {fresh}` when `have` is the newest |
//! | `view {have, query?}` | `view_update`, `view` or `current` the same way (a `query` always gets a whole `view`) |
//! | `resolve {service}` | `view {view, fresh}` holding that service, or none |
//! | `policy {have}` | **temporary** (card 36b): `policy {policy, fresh}`, the whole signed policy, or `current {fresh}` when `have` is the newest |
//! | anything refused | `denied {reason}` |
//!
//! `policy {have}` exists only while hosts and callers still hold the whole
//! policy: card 36c moves hosts to slices, card 37 callers to views, and
//! then it goes.
//!
//! **`wires/directory-sub/1`**: the dialer sends `hello` then
//! [`SubRequest::Subscribe`], and the directory streams [`SubFrame`]s: the
//! subscriber's whole part first (`slice`, `view`, or for another directory
//! the whole `replica`), then a `slice_update` / `view_update` (or a new
//! `replica`) for every new head, a `fresh` every beat, or a terminal
//! `denied`. A subscriber that can't apply an update (see
//! [`Slice::apply`](crate::Slice::apply)) subscribes anew with `have: 0` and
//! gets its whole part.
//!
//! As with [`crate::sync`], the caller is always the iroh-authenticated key,
//! never a field. Frames are a 4-byte big-endian length then canonical JSON
//! tagged by `type`. The length is checked before anything is allocated:
//! at most [`MAX_DIRECTORY_FRAME`], and a request over
//! [`MAX_SMALL_DIRECTORY_FRAME`] must be a `publish`
//! ([`PUBLISH_BODY_PREFIX`]), so nobody but a publisher (whose head the
//! directory then verifies) can make it read a large body.
//!
//! ```
//! use library::{DirectoryRequest, RoleName, StateVersion};
//! let req = DirectoryRequest::Slice {
//!     have: StateVersion(3),
//!     roles: vec![RoleName::new("oncall").unwrap()],
//! };
//! let bytes = req.encode().unwrap();
//! assert_eq!(DirectoryRequest::decode(&bytes).unwrap(), Some((req, bytes.len())));
//! ```

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::codec::{canonical_bytes, length_prefixed, prefix_len, split_frame};
use crate::error::{Error, Result};
use crate::fresh::Fresh;
use crate::head::SignedPolicyHead;
use crate::head::StateVersion;
use crate::idp::IdToken;
use crate::item::Item;
use crate::membership::Membership;
use crate::parts::{Slice, SliceUpdate, View, ViewUpdate};
use crate::registry::ServiceName;
use crate::role::RoleName;
use crate::signed_policy::SignedPolicy;

/// The ALPN of the directory's request protocol.
pub const DIRECTORY_ALPN: &[u8] = b"wires/directory/1";

/// The ALPN of the directory's subscriptions.
pub const DIRECTORY_SUB_ALPN: &[u8] = b"wires/directory-sub/1";

/// The largest frame either protocol accepts (a `publish` or a `replica` of
/// a large fabric), checked from the length prefix before allocating.
pub const MAX_DIRECTORY_FRAME: usize = 16 * 1024 * 1024;

/// The largest request that is not a `publish`: a `hello` (a badge and an ID
/// token, a few KB) or a small request.
pub const MAX_SMALL_DIRECTORY_FRAME: usize = 16 * 1024;

/// How the body of every encoded [`DirectoryRequest::Publish`] begins
/// (canonical JSON sorts `head` first); no other request's does. A directory
/// checks it before reading a request over [`MAX_SMALL_DIRECTORY_FRAME`].
pub const PUBLISH_BODY_PREFIX: &[u8] = br#"{"head":"#;

/// A dialer's frame on [`DIRECTORY_ALPN`]. See the module docs.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectoryRequest {
    /// Opens every stream: who the dialer is in the fabric.
    Hello {
        /// The dialer's root-signed badge.
        badge: Membership,
        /// Its IdP ID token, nonce-bound to its node key, when it has one
        /// (a view needs it; a host's slice doesn't).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id_token: Option<IdToken>,
    },
    /// A new signed policy, from anyone: accepted when it verifies under
    /// the directory's root, is fresh, and is newer than what it holds.
    Publish {
        /// The signed head.
        head: SignedPolicyHead,
        /// Every item, in key order.
        items: Vec<Item>,
    },
    /// The newest head and its `Fresh`.
    Head {},
    /// The dialer's host slice.
    Slice {
        /// The version the dialer holds (0: none).
        have: StateVersion,
        /// Extra roles the host needs (its `host.json` names them).
        roles: Vec<RoleName>,
    },
    /// The dialer's caller view (card 37).
    View {
        /// The version the dialer holds (0: none).
        have: StateVersion,
        /// Only entries whose name or description match this.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        query: Option<String>,
    },
    /// One service, only if it is in the dialer's view (card 37).
    Resolve {
        /// The service.
        service: ServiceName,
    },
    /// **Temporary** (card 36b; removed once hosts hold slices, card 36c,
    /// and callers views, card 37): the whole signed policy, for a node
    /// that still holds all of it.
    Policy {
        /// The version the dialer holds (0: none).
        have: StateVersion,
    },
}

/// The directory's answer on [`DIRECTORY_ALPN`]. See the module docs.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectoryAnswer {
    /// A publish was verified; this is the version the directory now holds
    /// (the published one, or a newer one it already had).
    Published {
        /// The directory's version.
        version: StateVersion,
    },
    /// The newest head.
    Head {
        /// The head.
        head: SignedPolicyHead,
        /// The directory's `Fresh` for it.
        fresh: Fresh,
    },
    /// The dialer's `have` is the newest head: nothing to send but freshness.
    Current {
        /// The directory's `Fresh` for that head.
        fresh: Fresh,
    },
    /// A host's slice.
    Slice {
        /// The slice.
        slice: Slice,
        /// The directory's `Fresh` for its head.
        fresh: Fresh,
    },
    /// What moves the dialer's slice (at its `have`) to the newest head.
    SliceUpdate {
        /// The update.
        update: SliceUpdate,
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
    /// What moves the dialer's view (at its `have`) to the newest head.
    ViewUpdate {
        /// The update.
        update: ViewUpdate,
        /// The directory's `Fresh` for its head.
        fresh: Fresh,
    },
    /// **Temporary** (card 36b): the whole signed policy, answering
    /// [`DirectoryRequest::Policy`].
    Policy {
        /// The newest signed policy.
        policy: SignedPolicy,
        /// The directory's `Fresh` for its head.
        fresh: Fresh,
    },
    /// Terminal refusal.
    Denied {
        /// Why, in words.
        reason: String,
    },
}

/// What a subscription follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionKind {
    /// A host's slice.
    Slice,
    /// Another directory's full copy.
    Replica,
    /// A long-running caller's view (card 37).
    View,
}

/// A subscriber's frame on [`DIRECTORY_SUB_ALPN`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SubRequest {
    /// Opens the stream, as on [`DIRECTORY_ALPN`].
    Hello {
        /// The subscriber's root-signed badge.
        badge: Membership,
        /// Its ID token, when it has one (a view needs it).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id_token: Option<IdToken>,
    },
    /// Follow a part of the policy.
    Subscribe {
        /// Which part.
        kind: SubscriptionKind,
        /// The version the subscriber holds (0: none): the first update
        /// comes at once when the directory's is newer.
        have: StateVersion,
        /// For a slice: the extra roles the host needs.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        roles: Vec<RoleName>,
    },
}

/// The directory's frames on a subscription.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SubFrame {
    /// The subscriber's whole slice: the first sync, or after an update it
    /// couldn't apply.
    Slice {
        /// The whole slice.
        slice: Slice,
        /// The `Fresh` for its head.
        fresh: Fresh,
    },
    /// A new head for a subscriber holding a slice: the changes and one
    /// proof over its whole resulting slice.
    SliceUpdate {
        /// The update.
        update: SliceUpdate,
        /// The `Fresh` for its head.
        fresh: Fresh,
    },
    /// The subscriber's whole view (first sync, or after a failed update).
    View {
        /// The whole view.
        view: View,
        /// The `Fresh` for its head.
        fresh: Fresh,
    },
    /// A new head (or new marks) for a subscriber holding a view.
    ViewUpdate {
        /// The update.
        update: ViewUpdate,
        /// The `Fresh` for its head.
        fresh: Fresh,
    },
    /// A new signed policy, for a replica.
    Replica {
        /// The whole policy.
        policy: SignedPolicy,
        /// The `Fresh` for its head.
        fresh: Fresh,
    },
    /// A beat: the held head is still the newest.
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
    /// arrived; an error for an oversized prefix (see
    /// [`length`](Self::length)) or a malformed body.
    pub fn decode(buf: &[u8]) -> Result<Option<(DirectoryRequest, usize)>> {
        if Self::length(buf)?.is_none() {
            return Ok(None);
        }
        decode_frame(buf, MAX_DIRECTORY_FRAME)
    }

    /// The body length the prefix at the start of `buf` announces, once it
    /// is safe to read: at once for a body up to
    /// [`MAX_SMALL_DIRECTORY_FRAME`], and for a larger one once its first
    /// bytes show it is a publish ([`PUBLISH_BODY_PREFIX`]); `Ok(None)`
    /// until then. [`Error::BadFrame`] when it is over
    /// [`MAX_DIRECTORY_FRAME`], or large and not a publish (refused from the
    /// first byte that differs, before the rest is read).
    ///
    /// ```
    /// use library::{DirectoryRequest, MAX_SMALL_DIRECTORY_FRAME};
    /// let head = DirectoryRequest::Head {}.encode().unwrap();
    /// assert_eq!(DirectoryRequest::length(&head).unwrap(), Some(head.len() - 4));
    /// // A large body that opens like anything but a publish is refused early.
    /// let mut big = ((MAX_SMALL_DIRECTORY_FRAME + 1) as u32).to_be_bytes().to_vec();
    /// big.extend_from_slice(br#"{"type""#);
    /// assert!(DirectoryRequest::length(&big).is_err());
    /// ```
    pub fn length(buf: &[u8]) -> Result<Option<usize>> {
        let Some(len) = prefix_len(buf) else {
            return Ok(None);
        };
        if len > MAX_DIRECTORY_FRAME {
            return Err(Error::BadFrame);
        }
        if len <= MAX_SMALL_DIRECTORY_FRAME {
            return Ok(Some(len));
        }
        let opening = &buf[4..buf.len().min(4 + PUBLISH_BODY_PREFIX.len())];
        if !PUBLISH_BODY_PREFIX.starts_with(opening) {
            return Err(Error::BadFrame);
        }
        Ok((opening.len() == PUBLISH_BODY_PREFIX.len()).then_some(len))
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
    use crate::item::Ban;
    use crate::signed_policy::fixtures::*;
    use proptest::prelude::*;

    fn badge() -> Membership {
        Membership::mint(&root(), node(10), 0, i64::MAX).unwrap()
    }

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
            DirectoryRequest::Hello {
                badge: badge(),
                id_token: None,
            },
            DirectoryRequest::Hello {
                badge: badge(),
                id_token: Some(IdToken::new("a.b.c")),
            },
            DirectoryRequest::Publish {
                head: signed.head.clone(),
                items: signed.items,
            },
            DirectoryRequest::Head {},
            DirectoryRequest::Slice {
                have: StateVersion(2),
                roles: vec![role("oncall")],
            },
            DirectoryRequest::View {
                have: StateVersion(0),
                query: Some("orders".into()),
            },
            DirectoryRequest::View {
                have: StateVersion(0),
                query: None,
            },
            DirectoryRequest::Resolve {
                service: name("status"),
            },
            DirectoryRequest::Policy {
                have: StateVersion(2),
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
            DirectoryRequest::Head {}.encode().unwrap()[4..],
            br#"{"type":"head"}"#[..]
        );
    }

    #[test]
    fn answers_and_subscription_frames_round_trip() {
        let signed = sample().sign(&root()).unwrap();
        let fresh = fresh(&signed);
        let slice = signed.slice_for_host(node(10), &[]).unwrap();
        let view = signed
            .view_for(Some(&who("alice@example.com")), None)
            .unwrap();
        let slice_update = slice.update_to(&slice);
        let view_update = view.update_to(&view);
        for a in [
            DirectoryAnswer::Published {
                version: StateVersion(3),
            },
            DirectoryAnswer::Head {
                head: signed.head.clone(),
                fresh: fresh.clone(),
            },
            DirectoryAnswer::Current {
                fresh: fresh.clone(),
            },
            DirectoryAnswer::Slice {
                slice: slice.clone(),
                fresh: fresh.clone(),
            },
            DirectoryAnswer::View {
                view: view.clone(),
                fresh: fresh.clone(),
            },
            DirectoryAnswer::SliceUpdate {
                update: slice_update.clone(),
                fresh: fresh.clone(),
            },
            DirectoryAnswer::ViewUpdate {
                update: view_update.clone(),
                fresh: fresh.clone(),
            },
            DirectoryAnswer::Policy {
                policy: signed.clone(),
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
            SubFrame::Slice {
                slice,
                fresh: fresh.clone(),
            },
            SubFrame::View {
                view,
                fresh: fresh.clone(),
            },
            SubFrame::SliceUpdate {
                update: slice_update,
                fresh: fresh.clone(),
            },
            SubFrame::ViewUpdate {
                update: view_update,
                fresh: fresh.clone(),
            },
            SubFrame::Replica {
                policy: signed,
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
            SubRequest::Hello {
                badge: badge(),
                id_token: Some(IdToken::new("a.b.c")),
            },
            SubRequest::Subscribe {
                kind: SubscriptionKind::Slice,
                have: StateVersion(1),
                roles: vec![role("oncall")],
            },
            SubRequest::Subscribe {
                kind: SubscriptionKind::Replica,
                have: StateVersion(0),
                roles: vec![],
            },
            SubRequest::Subscribe {
                kind: SubscriptionKind::View,
                have: StateVersion(0),
                roles: vec![],
            },
        ] {
            let bytes = r.encode().unwrap();
            assert_eq!(SubRequest::decode(&bytes).unwrap(), Some((r, bytes.len())));
        }
    }

    /// Only a publish may be large, and it announces itself; every other
    /// request fits the small limit and never opens like a publish.
    #[test]
    fn only_publishes_are_large_and_they_announce_themselves() {
        let mut p = sample();
        for b in 100..=255u8 {
            p.bans
                .insert(NodeIdentity::from_seed([b; 32]).node_id(), Ban { until: 1 });
        }
        let signed = p.sign(&root()).unwrap();
        let publish = DirectoryRequest::Publish {
            head: signed.head,
            items: signed.items,
        }
        .encode()
        .unwrap();
        assert!(
            publish.len() > MAX_SMALL_DIRECTORY_FRAME,
            "{}",
            publish.len()
        );
        assert!(publish[4..].starts_with(PUBLISH_BODY_PREFIX));
        assert!(DirectoryRequest::decode(&publish).unwrap().is_some());
        for r in requests() {
            if matches!(r, DirectoryRequest::Publish { .. }) {
                continue;
            }
            let bytes = r.encode().unwrap();
            assert!(bytes.len() <= MAX_SMALL_DIRECTORY_FRAME, "{r:?}");
            assert!(!bytes[4..].starts_with(PUBLISH_BODY_PREFIX), "{r:?}");
        }
    }

    #[test]
    fn a_large_request_that_is_not_a_publish_is_refused_before_its_body() {
        let body = format!(
            r#"{{"type":"view","have":0,"query":"{}"}}"#,
            "x".repeat(MAX_SMALL_DIRECTORY_FRAME)
        );
        let buf = raw(body.as_bytes());
        // Refused from the first bytes of the body, not after reading it all.
        assert!(DirectoryRequest::length(&buf[..4]).unwrap().is_none());
        assert!(DirectoryRequest::length(&buf[..4 + PUBLISH_BODY_PREFIX.len()]).is_err());
        assert!(DirectoryRequest::decode(&buf).is_err());
        // A small one's length is known from the prefix alone.
        let small = DirectoryRequest::Head {}.encode().unwrap();
        assert_eq!(
            DirectoryRequest::length(&small[..4]).unwrap(),
            Some(small.len() - 4)
        );
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

    #[test]
    fn unknown_frames_and_fields_are_refused() {
        for body in [
            r#"{"type":"offer"}"#,
            r#"{"type":"head","extra":1}"#,
            r#"{"type":"slice","have":1}"#,
            r#"{"type":"slice","have":1,"roles":[],"x":2}"#,
            r#"{"type":"resolve","service":"Not A Name"}"#,
        ] {
            assert!(
                DirectoryRequest::decode(&raw(body.as_bytes())).is_err(),
                "{body}"
            );
        }
        for body in [
            r#"{"type":"subscribe","kind":"everything","have":0}"#,
            r#"{"type":"subscribe","kind":"slice","have":0,"x":1}"#,
        ] {
            assert!(SubRequest::decode(&raw(body.as_bytes())).is_err(), "{body}");
        }
        assert!(DirectoryAnswer::decode(&raw(br#"{"type":"published"}"#)).is_err());
    }

    #[test]
    fn the_alpns() {
        assert_eq!(DIRECTORY_ALPN, b"wires/directory/1");
        assert_eq!(DIRECTORY_SUB_ALPN, b"wires/directory-sub/1");
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
        fn slice_requests_round_trip(have in any::<u64>(), roles in proptest::collection::vec("[a-z]{1,8}", 0..4)) {
            let r = DirectoryRequest::Slice {
                have: StateVersion(have),
                roles: roles.iter().map(|r| role(r)).collect(),
            };
            let bytes = r.encode().unwrap();
            prop_assert_eq!(DirectoryRequest::decode(&bytes).unwrap(), Some((r, bytes.len())));
        }
    }
}

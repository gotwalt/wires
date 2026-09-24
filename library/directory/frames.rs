//! The directory's two protocols (card 36): requests on [`DIRECTORY_ALPN`]
//! and subscriptions on [`DIRECTORY_SUB_ALPN`].
//!
//! Hosts and directories hold the whole signed policy; a caller holds its
//! [`View`]: the services it may use, each a root-signed entry. Nothing here
//! carries a proof: a whole policy checks against its head's one signature,
//! and a view's entries each carry their own.
//!
//! **`wires/directory/1`**: one request per stream. The dialer sends
//! [`DirectoryRequest::Hello`] (its badge, and its ID token when it has one)
//! then one request, and the directory answers once:
//!
//! | request | answer |
//! |---|---|
//! | `publish {head, items}` | `published {version}`: the version it now holds |
//! | `head {}` | `head {head, fresh}` |
//! | `policy {have}` | the whole policy for a host or directory: `policy {policy, fresh}`; `policy_update {update, fresh}` from a `have` the directory still keeps; `current {fresh}` when `have` is the newest |
//! | `view {have, query?}` | the caller's view: `view {view, fresh}`, `view_update {update, fresh}` or `current {fresh}` the same way (a `query` always gets a whole `view`) |
//! | `resolve {service}` | `view {view, fresh}` holding just that service, or no entry |
//! | anything refused | `denied {reason}` |
//!
//! **`wires/directory-sub/1`**: the dialer sends `hello` then
//! [`SubRequest::Subscribe`] (`policy` for a host, `replica` for another
//! directory, `view` for a long-running caller such as `wires mcp` or the
//! gateway), and the directory streams [`SubFrame`]s: the subscriber's whole
//! part first when its `have` is older (`policy` or `view`), then a
//! `policy_update` / `view_update` for every new head, a `fresh` every beat,
//! or a terminal `denied`. A subscriber that can't apply an update
//! ([`SignedPolicy::apply`](crate::SignedPolicy::apply),
//! [`View::apply`](crate::View::apply)) subscribes anew with `have: 0` and
//! gets its whole part.
//!
//! The caller is always the iroh-authenticated key, never a field. Frames
//! are a 4-byte big-endian length then canonical JSON tagged by `type`. The
//! length is checked before anything is allocated: at most
//! [`MAX_DIRECTORY_FRAME`]; the `hello` (read before its sender is admitted)
//! at most [`MAX_SMALL_DIRECTORY_FRAME`], whatever it opens with; and a
//! request after it over [`MAX_SMALL_DIRECTORY_FRAME`] must be a `publish`
//! ([`PUBLISH_BODY_PREFIX`]), so nobody but an admitted publisher (whose
//! head the directory then verifies) can make it read a large body.
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
use crate::head::SignedPolicyHead;
use crate::head::StateVersion;
use crate::idp::IdToken;
use crate::item::Item;
use crate::membership::Membership;
use crate::policy_update::PolicyUpdate;
use crate::registry::ServiceName;
use crate::signed_policy::SignedPolicy;
use crate::view::{View, ViewUpdate};

/// The ALPN of the directory's request protocol.
pub const DIRECTORY_ALPN: &[u8] = b"wires/directory/1";

/// The ALPN of the directory's subscriptions.
pub const DIRECTORY_SUB_ALPN: &[u8] = b"wires/directory-sub/1";

/// The largest frame either protocol accepts (a `publish`, or a whole
/// `policy` of a large fabric), checked from the length prefix before
/// allocating.
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
        /// (a view needs it; a host's policy doesn't).
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
    /// The whole signed policy, for a host or a directory (a node that holds
    /// all of it).
    Policy {
        /// The version the dialer holds (0: none).
        have: StateVersion,
    },
    /// The dialer's caller view (card 37): the services its verified
    /// identity may call or read.
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
    /// The whole signed policy.
    Policy {
        /// The newest signed policy.
        policy: SignedPolicy,
        /// The directory's `Fresh` for its head.
        fresh: Fresh,
    },
    /// What moves the dialer's whole policy (at its `have`) to the newest.
    PolicyUpdate {
        /// The update.
        update: PolicyUpdate,
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
    /// A host's whole policy.
    Policy,
    /// Another directory's whole policy (only from a directory the head
    /// lists).
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
        /// The version the subscriber holds (0: none): the first frame comes
        /// at once when the directory's is newer.
        have: StateVersion,
    },
}

/// The directory's frames on a subscription.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SubFrame {
    /// The whole signed policy, for a `policy` or `replica` subscriber: the
    /// first sync, or after an update it couldn't apply.
    Policy {
        /// The whole policy.
        policy: SignedPolicy,
        /// The `Fresh` for its head.
        fresh: Fresh,
    },
    /// A new head for a subscriber holding the whole policy: the items
    /// changed and the keys removed since its version.
    PolicyUpdate {
        /// The update.
        update: PolicyUpdate,
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
            DirectoryRequest::Policy {
                have: StateVersion(2),
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
        assert_eq!(
            DirectoryRequest::Policy {
                have: StateVersion(7)
            }
            .encode()
            .unwrap()[4..],
            br#"{"have":7,"type":"policy"}"#[..]
        );
    }

    #[test]
    fn answers_and_subscription_frames_round_trip() {
        let signed = sample().sign(&root()).unwrap();
        let mut next = sample();
        next.version = StateVersion(4);
        next.bans.insert(node(21), Ban { until: 900 });
        let next = next.sign_after(&root(), &signed).unwrap();
        let fresh = fresh(&next);
        let update = next.update_from(&signed);
        let alice = who("alice@example.com");
        let view = next.view_for(Some(&alice), None);
        let view_update = signed.view_for(Some(&alice), None).update_to(&view);
        for a in [
            DirectoryAnswer::Published {
                version: StateVersion(3),
            },
            DirectoryAnswer::Head {
                head: next.head.clone(),
                fresh: fresh.clone(),
            },
            DirectoryAnswer::Current {
                fresh: fresh.clone(),
            },
            DirectoryAnswer::Policy {
                policy: next.clone(),
                fresh: fresh.clone(),
            },
            DirectoryAnswer::PolicyUpdate {
                update: update.clone(),
                fresh: fresh.clone(),
            },
            DirectoryAnswer::View {
                view: view.clone(),
                fresh: fresh.clone(),
            },
            DirectoryAnswer::ViewUpdate {
                update: view_update.clone(),
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
                policy: next.clone(),
                fresh: fresh.clone(),
            },
            SubFrame::PolicyUpdate {
                update: update.clone(),
                fresh: fresh.clone(),
            },
            SubFrame::View {
                view,
                fresh: fresh.clone(),
            },
            SubFrame::ViewUpdate {
                update: view_update,
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
        for kind in [
            SubscriptionKind::Policy,
            SubscriptionKind::Replica,
            SubscriptionKind::View,
        ] {
            for r in [
                SubRequest::Hello {
                    badge: badge(),
                    id_token: Some(IdToken::new("a.b.c")),
                },
                SubRequest::Subscribe {
                    kind,
                    have: StateVersion(1),
                },
            ] {
                let bytes = r.encode().unwrap();
                assert_eq!(SubRequest::decode(&bytes).unwrap(), Some((r, bytes.len())));
            }
        }
        // What a subscriber does with a `policy_update`: apply it to its copy.
        assert_eq!(signed.apply(&update, root().node_id()).unwrap(), next);
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
            r#"{"type":"slice","have":1,"roles":[]}"#,
            r#"{"type":"policy"}"#,
            r#"{"type":"policy","have":1,"x":2}"#,
            r#"{"type":"resolve","service":"Not A Name"}"#,
        ] {
            assert!(
                DirectoryRequest::decode(&raw(body.as_bytes())).is_err(),
                "{body}"
            );
        }
        for body in [
            r#"{"type":"subscribe","kind":"everything","have":0}"#,
            r#"{"type":"subscribe","kind":"slice","have":0}"#,
            r#"{"type":"subscribe","kind":"policy","have":0,"roles":[]}"#,
        ] {
            assert!(SubRequest::decode(&raw(body.as_bytes())).is_err(), "{body}");
        }
        for body in [r#"{"type":"published"}"#, r#"{"type":"slice"}"#] {
            assert!(DirectoryAnswer::decode(&raw(body.as_bytes())).is_err());
        }
        assert!(SubFrame::decode(&raw(br#"{"type":"replica"}"#)).is_err());
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
        fn view_requests_round_trip(have in any::<u64>(), query in proptest::option::of("[a-z ]{0,16}")) {
            let r = DirectoryRequest::View { have: StateVersion(have), query };
            let bytes = r.encode().unwrap();
            prop_assert_eq!(DirectoryRequest::decode(&bytes).unwrap(), Some((r, bytes.len())));
        }

        /// Any update between two random policies survives the frame and
        /// still applies.
        #[test]
        fn policy_updates_survive_the_frame(a in arb_policy(), b in arb_policy()) {
            let old = a.sign(&root()).unwrap();
            let mut b = b;
            b.version = StateVersion(a.version.0 + 1);
            b.directories = vec![node(30)];
            let new = b.sign_after(&root(), &old).unwrap();
            let frame = SubFrame::PolicyUpdate { update: new.update_from(&old), fresh: fresh(&new) };
            let bytes = frame.encode().unwrap();
            let Some((SubFrame::PolicyUpdate { update, fresh }, _)) = SubFrame::decode(&bytes).unwrap() else {
                panic!("not a policy_update");
            };
            prop_assert!(fresh.verify(&update.head).is_ok());
            prop_assert_eq!(old.apply(&update, root().node_id()).unwrap(), new);
        }
    }
}

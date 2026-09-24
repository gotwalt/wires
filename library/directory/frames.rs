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
//! | `slice {have, roles}` | `slice {slice, fresh}`, or `current {fresh}` when `have` is the newest |
//! | `view {have, query?}` | `view {view, fresh}`, or `current {fresh}` |
//! | `resolve {service}` | `view {view, fresh}` holding that service, or none |
//! | anything refused | `denied {reason}` |
//!
//! **`wires/directory-sub/1`**: the dialer sends `hello` then
//! [`SubRequest::Subscribe`], and the directory streams [`SubFrame`]s: the
//! subscriber's whole part (`slice`, `view`, or for another directory the
//! whole `replica`) whenever its part changes under a new head, a `fresh`
//! every beat, or a terminal `denied`.
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
use crate::idp::IdToken;
use crate::item::Item;
use crate::membership::Membership;
use crate::registry::ServiceName;
use crate::role::RoleName;
use crate::signed_policy::SignedPolicy;
use crate::slice::{Slice, View};
use crate::state::StateVersion;

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
    Head,
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
    /// The subscriber's slice under a new head.
    Slice {
        /// The whole slice.
        slice: Slice,
        /// The `Fresh` for its head.
        fresh: Fresh,
    },
    /// The subscriber's view under a new head.
    View {
        /// The whole view.
        view: View,
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
        todo!("DirectoryRequest::decode {}", buf.len())
    }

    /// The body length the prefix at the start of `buf` announces, once its
    /// four bytes are there. [`Error::BadFrame`] when it is over
    /// [`MAX_DIRECTORY_FRAME`], or over [`MAX_SMALL_DIRECTORY_FRAME`] and the
    /// body's first bytes (once there) aren't [`PUBLISH_BODY_PREFIX`].
    pub fn length(buf: &[u8]) -> Result<Option<usize>> {
        todo!("DirectoryRequest::length {}", buf.len())
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
    todo!("encode_frame {}", std::any::type_name_of_val(frame))
}

/// The first whole frame in `buf`, refusing a prefix over `max` before
/// reading the body.
fn decode_frame<T: DeserializeOwned>(buf: &[u8], max: usize) -> Result<Option<(T, usize)>> {
    todo!("decode_frame {} {max}", buf.len())
}

#[cfg(test)]
mod tests {}

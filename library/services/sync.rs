//! Moving the signed state between nodes, by key.
//!
//! Two directions on one ALPN, [`STATE_ALPN`]:
//!
//! - **Push:** after every admin edit (and `wires state push`), the admin
//!   dials every host (only a running `serve` answers) and sends
//!   [`StateFrame::Offer`]; the receiver verifies it under its root, adopts
//!   it if [newer](crate::SignedState::is_newer_than), and answers
//!   [`StateFrame::Have`] with the version it now holds.
//! - **Pull:** a member whose copy has gone stale (last checked too long
//!   ago) dials the hosts in its copy (then the admin) and sends
//!   [`StateFrame::Have`]; the peer answers
//!   [`StateFrame::Offer`] when it holds a newer copy, else `Have`.
//!
//! A node never adopts an older or unverifiable state, so a peer that lies
//! can only fail to help. The caller is always the iroh-authenticated key;
//! non-members are answered [`StateFrame::Denied`].
//!
//! Frames are a 4-byte big-endian length then canonical JSON tagged by
//! `type`, at most [`MAX_STATE_FRAME`] bytes.
//!
//! ```
//! use library::{StateFrame, StateVersion};
//! let frame = StateFrame::Have { version: StateVersion(3) };
//! let bytes = frame.encode().unwrap();
//! assert_eq!(StateFrame::decode(&bytes).unwrap(), Some((frame, bytes.len())));
//! ```

use serde::{Deserialize, Serialize};

use crate::codec::{canonical_bytes, length_prefixed, prefix_len, split_frame};
use crate::error::{Error, Result};
use crate::state::{SignedState, StateVersion};

/// The ALPN the state push/pull protocol speaks.
pub const STATE_ALPN: &[u8] = b"wires/state/1";

/// The largest frame accepted (checked from the length prefix before
/// allocating).
pub const MAX_STATE_FRAME: usize = 4 * 1024 * 1024;

/// The largest frame that is not an [`StateFrame::Offer`]. A `Have` is
/// about 50 bytes and a `Denied` carries a short reason, so a reader that
/// hasn't yet seen an offer's opening bytes ([`OFFER_BODY_PREFIX`]) needs no
/// more than this.
pub const MAX_SMALL_STATE_FRAME: usize = 4 * 1024;

/// How the body of every encoded [`StateFrame::Offer`] begins: canonical
/// JSON sorts `state` before `type`. A reader checks these bytes before it
/// accepts a frame over [`MAX_SMALL_STATE_FRAME`], so only an offer can make
/// it read up to [`MAX_STATE_FRAME`].
///
/// ```
/// use library::{OFFER_BODY_PREFIX, StateFrame, StateVersion};
/// let have = StateFrame::Have { version: StateVersion(1) }.encode().unwrap();
/// assert!(!have[4..].starts_with(OFFER_BODY_PREFIX));
/// ```
pub const OFFER_BODY_PREFIX: &[u8] = br#"{"state":"#;

/// One frame of the state protocol. See the module docs.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum StateFrame {
    /// "Here is my copy": a push, or the answer to a pull from a peer that
    /// holds a newer one.
    Offer {
        /// The signed state.
        state: SignedState,
    },
    /// "This is the version I hold": a pull, or the answer to an offer.
    Have {
        /// The sender's current version (0: none yet).
        version: StateVersion,
    },
    /// Terminal refusal (the dialer is not a member).
    Denied {
        /// Why, in words.
        reason: String,
    },
}

impl StateFrame {
    /// Encode as length-prefixed canonical JSON.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let body = canonical_bytes(self)?;
        if body.len() > MAX_STATE_FRAME {
            return Err(Error::BadFrame);
        }
        length_prefixed(&body)
    }

    /// Decode the first frame in `buf`: `Ok(None)` until a whole frame has
    /// arrived; an error for an oversized prefix or a malformed body.
    pub fn decode(buf: &[u8]) -> Result<Option<(StateFrame, usize)>> {
        Self::length(buf)?;
        let Some((body, end)) = split_frame(buf) else {
            return Ok(None);
        };
        let frame = serde_json::from_slice(body).map_err(Error::Decode)?;
        Ok(Some((frame, end)))
    }

    /// The body length announced by the prefix at the start of `buf`, once
    /// its four bytes are there; [`Error::BadFrame`] when it is over
    /// [`MAX_STATE_FRAME`] (so a reader allocates nothing for it).
    pub fn length(buf: &[u8]) -> Result<Option<usize>> {
        let Some(len) = prefix_len(buf) else {
            return Ok(None);
        };
        if len > MAX_STATE_FRAME {
            return Err(Error::BadFrame);
        }
        Ok(Some(len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use crate::state::State;

    #[test]
    fn frames_round_trip() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let state = State::new(root.node_id()).sign(&root).unwrap();
        for f in [
            StateFrame::Offer { state },
            StateFrame::Have {
                version: StateVersion(7),
            },
            StateFrame::Denied {
                reason: "not a member".into(),
            },
        ] {
            let bytes = f.encode().unwrap();
            assert_eq!(StateFrame::decode(&bytes).unwrap(), Some((f, bytes.len())));
            assert_eq!(StateFrame::decode(&bytes[..bytes.len() - 1]).unwrap(), None);
        }
    }

    /// An offer's body always opens with [`OFFER_BODY_PREFIX`]; the other
    /// frames never do, and fit in [`MAX_SMALL_STATE_FRAME`] even with a
    /// worst-case (all control characters) 512-byte reason.
    #[test]
    fn only_offers_are_large_and_they_announce_themselves() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut s = State::new(root.node_id());
        s.members
            .extend((0..200u8).map(|i| NodeIdentity::from_seed([i; 32]).node_id()));
        let offer = StateFrame::Offer {
            state: s.sign(&root).unwrap(),
        }
        .encode()
        .unwrap();
        assert!(offer.len() > MAX_SMALL_STATE_FRAME, "{}", offer.len());
        assert!(offer[4..].starts_with(OFFER_BODY_PREFIX));
        for small in [
            StateFrame::Have {
                version: StateVersion(u64::MAX),
            },
            StateFrame::Denied {
                reason: "\u{1}".repeat(512),
            },
        ] {
            let bytes = small.encode().unwrap();
            assert!(bytes.len() <= MAX_SMALL_STATE_FRAME, "{}", bytes.len());
            assert!(!bytes[4..].starts_with(OFFER_BODY_PREFIX));
        }
    }

    #[test]
    fn oversized_prefix_is_refused_early() {
        let len = (MAX_STATE_FRAME as u32 + 1).to_be_bytes();
        assert!(StateFrame::decode(&len).is_err());
    }

    #[test]
    fn unknown_frames_and_fields_are_refused() {
        for body in [
            r#"{"type":"subscribe"}"#,
            r#"{"type":"have","version":1,"extra":2}"#,
        ] {
            let mut buf = (body.len() as u32).to_be_bytes().to_vec();
            buf.extend_from_slice(body.as_bytes());
            assert!(StateFrame::decode(&buf).is_err(), "{body}");
        }
    }

    proptest::proptest! {
        #[test]
        fn decode_never_panics(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256)) {
            let _ = StateFrame::decode(&data);
        }
    }
}

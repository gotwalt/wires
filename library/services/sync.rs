//! Moving the signed state between nodes, by key (card 27, lane **27a**).
//!
//! Two directions on one ALPN, [`STATE_ALPN`]:
//!
//! - **Push:** after `invite`, `remove` or `wires service add|rm|set`, the
//!   admin dials every member (hosts first) and sends
//!   [`StateFrame::Offer`]; the receiver verifies it under its root, adopts
//!   it if [newer](crate::SignedState::is_newer_than), and answers
//!   [`StateFrame::Have`] with the version it now holds.
//! - **Pull:** a member whose copy is older than N minutes dials the admin or
//!   any host and sends [`StateFrame::Have`]; the peer answers
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

use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::state::{SignedState, StateVersion};

/// The ALPN the state push/pull protocol speaks.
pub const STATE_ALPN: &[u8] = b"wires/state/1";

/// The largest frame accepted (checked from the length prefix before
/// allocating).
pub const MAX_STATE_FRAME: usize = 4 * 1024 * 1024;

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
        let len = u32::try_from(body.len()).map_err(|_| Error::BadFrame)?;
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode the first frame in `buf`: `Ok(None)` until a whole frame has
    /// arrived; an error for an oversized prefix or a malformed body.
    pub fn decode(buf: &[u8]) -> Result<Option<(StateFrame, usize)>> {
        let Some(len) = Self::length(buf)? else {
            return Ok(None);
        };
        let end = 4 + len;
        if buf.len() < end {
            return Ok(None);
        }
        let frame = serde_json::from_slice(&buf[4..end]).map_err(Error::Decode)?;
        Ok(Some((frame, end)))
    }

    /// The body length announced by the prefix at the start of `buf`, once
    /// its four bytes are there; [`Error::BadFrame`] when it is over
    /// [`MAX_STATE_FRAME`] (so a reader allocates nothing for it).
    pub fn length(buf: &[u8]) -> Result<Option<usize>> {
        let Some(prefix) = buf.get(..4) else {
            return Ok(None);
        };
        let len = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize;
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

    #[test]
    fn oversized_prefix_is_refused_early() {
        let len = (MAX_STATE_FRAME as u32 + 1).to_be_bytes();
        assert!(StateFrame::decode(&len).is_err());
    }

    #[test]
    fn unknown_frames_and_fields_are_refused() {
        for body in [
            r#"{"type":"gossip"}"#,
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

        #[test]
        fn have_round_trips(v in proptest::prelude::any::<u64>()) {
            let f = StateFrame::Have { version: StateVersion(v) };
            let bytes = f.encode().unwrap();
            proptest::prop_assert_eq!(StateFrame::decode(&bytes).unwrap(), Some((f, bytes.len())));
        }
    }
}

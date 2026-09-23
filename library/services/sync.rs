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
//! `type`, at most [`MAX_STATE_FRAME`] bytes. **Stub:** 27a implements the
//! codec; the types are fixed here so 27b/27c can reference them.

use serde::{Deserialize, Serialize};

use crate::error::Result;
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
        todo!("27a: state frame codec")
    }

    /// Decode the first frame in `buf`: `Ok(None)` until a whole frame has
    /// arrived; an error for an oversized prefix or a malformed body.
    pub fn decode(buf: &[u8]) -> Result<Option<(StateFrame, usize)>> {
        let _ = buf;
        todo!("27a: state frame codec")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use crate::state::State;

    #[test]
    #[ignore = "27a"]
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
    #[ignore = "27a"]
    fn oversized_prefix_is_refused_early() {
        let len = (MAX_STATE_FRAME as u32 + 1).to_be_bytes();
        assert!(StateFrame::decode(&len).is_err());
    }
}

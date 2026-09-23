//! The caller's half of the card-27 handshake (lane **27b**): build the
//! [`Hello`] from what this node holds: its membership, the version of its
//! signed state, and its stored ID token from `wires login` (no `--topic`;
//! the token travels in the handshake, not on a channel).

// Nothing calls this until lane 27b switches the dialer over.
#![allow(dead_code)]

use anyhow::Result;
use library::Hello;

use crate::admin::keystore::Keystore;

/// Build this node's [`Hello`]. A missing ID token is not an error (the host
/// decides whether the service needs one); a missing membership is.
pub(crate) fn build(ks: &Keystore) -> Result<Hello> {
    let _ = ks;
    todo!("27b: build the Hello")
}

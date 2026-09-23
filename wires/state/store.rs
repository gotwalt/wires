//! `$WIRES_HOME/state.json`: this node's newest verified [`SignedState`]
//! (lane 27a).
//!
//! Written only through [`adopt_if_newer`], a compare-and-swap under one
//! exclusive lock: re-read the stored copy, verify the candidate under the
//! root, require it to be strictly newer, write atomically. Without the lock
//! a removed member presenting a genuine older state could roll a node back
//! (the same race `adopt_if_newer` closes for roster heads today).

// Nothing calls these until lanes 27a/27b/27c wire them in.
#![allow(dead_code)]

use anyhow::Result;
use library::{NodeId, SignedState};

use crate::admin::keystore::Keystore;

/// The file name under `$WIRES_HOME`.
pub(crate) const STATE_FILE: &str = "state.json";

/// The stored state, verified under `root`; `None` if this node has none yet.
/// A present but invalid file is an error (fail closed).
pub(crate) fn read(ks: &Keystore, root: NodeId) -> Result<Option<SignedState>> {
    let _ = (ks, root);
    todo!("27a: read state.json")
}

/// Store `candidate` if it verifies under `root`, is fresh at `now`, and is
/// strictly newer than the stored copy. Returns whether it was adopted.
pub(crate) fn adopt_if_newer(
    ks: &Keystore,
    candidate: &SignedState,
    root: NodeId,
    now: i64,
) -> Result<bool> {
    let _ = (ks, candidate, root, now);
    todo!("27a: compare-and-swap state.json")
}

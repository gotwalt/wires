//! Moving the signed state by key over [`STATE_ALPN`](library::STATE_ALPN)
//! (lane 27a). The frames are [`library::StateFrame`].
//!
//! - [`push_all`]: after `invite` / `remove` / `service add|rm|set`, the
//!   admin offers the new state to every member, hosts first, and queues it
//!   for those it can't reach (card 23's direct dial plus queue).
//! - [`pull`]: a cold command whose copy is older than [`STALE_AFTER_SECS`]
//!   asks the admin or any host for a newer one.
//! - [`respond`]: the side a host, the admin or a resident node runs on the
//!   ALPN: answer a pull, adopt an offer.

// Nothing calls these until lane 27a wires them in.
#![allow(dead_code)]

use anyhow::Result;
use iroh::Endpoint;
use iroh::endpoint::Connection;
use library::{NodeId, SignedState, StateVersion};

use crate::admin::keystore::Keystore;

/// How old a local copy may be before a cold command pulls.
pub(crate) const STALE_AFTER_SECS: i64 = 5 * 60;

/// Who took an offered state and who didn't.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PushReport {
    /// Members now holding at least the offered version.
    pub(crate) delivered: Vec<NodeId>,
    /// Members that couldn't be reached (queued for retry).
    pub(crate) queued: Vec<NodeId>,
}

/// Offer `state` to each of `members` (hosts first).
pub(crate) async fn push_all(
    endpoint: &Endpoint,
    state: &SignedState,
    members: &[NodeId],
) -> Result<PushReport> {
    let _ = (endpoint, state, members);
    todo!("27a: push the signed state")
}

/// Ask `peers` in turn for a state newer than `have`; the first verified,
/// newer one is adopted and returned.
pub(crate) async fn pull(
    endpoint: &Endpoint,
    ks: &Keystore,
    peers: &[NodeId],
    have: StateVersion,
) -> Result<Option<SignedState>> {
    let _ = (endpoint, ks, peers, have);
    todo!("27a: pull the signed state")
}

/// Serve one incoming state-protocol connection.
pub(crate) async fn respond(conn: Connection, ks: &Keystore) -> Result<()> {
    let _ = (conn, ks);
    todo!("27a: answer state pushes and pulls")
}

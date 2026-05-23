//! Capability ticket: the on-the-wire address a dialer presents.

use serde::{Deserialize, Serialize};

use crate::grant::{Grant, Scope};
use crate::identity::NodeId;

/// What a dialer holds and presents: whom to dial plus the grant proving it
/// may. This bundle *is* the address in the capability-addressed model.
///
/// Placeholder shape — base64 encode/decode lands in a later step.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CapabilityTicket {
    /// The responder's iroh node id to dial.
    pub target: NodeId,
    /// The scope being requested.
    pub scope: Scope,
    /// The root-signed grant authorizing the dialer.
    pub grant: Grant,
}

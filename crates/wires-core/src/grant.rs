//! Capability grants: root-signed authority bound to a node + scope.

use serde::{Deserialize, Serialize};

use crate::identity::{NodeId, Signature};

/// A coarse capability scope (e.g. a named tool/endpoint).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Scope(String);

/// Signature scheme used to sign a grant (the root key is pluggable).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum AlgorithmId {
    /// Ed25519 — the zero-config default root scheme.
    Ed25519,
}

/// A root-signed capability: binds `subject` to `scope` until `not_after`.
///
/// Placeholder shape — minting and verification land in a later step.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Grant {
    /// The node this grant authorizes (non-transferable).
    pub subject: NodeId,
    /// What the subject may reach.
    pub scope: Scope,
    /// Expiry, unix seconds.
    pub not_after: i64,
    /// Which scheme `sig` was produced with.
    pub alg: AlgorithmId,
    /// Root signature over the grant body.
    pub sig: Signature,
}

//! Accept-time policy: TTL and revocation (CRL / allowlist).

use crate::identity::NodeId;

/// Time-to-live boundary for a grant (unix seconds).
///
/// Placeholder — checked at accept time in a later step.
pub struct Ttl {
    #[allow(dead_code)]
    pub not_after: i64,
}

/// A simple revocation list of revoked subject node ids.
///
/// Placeholder — consulted at accept time in a later step.
pub struct Crl {
    #[allow(dead_code)]
    revoked: Vec<NodeId>,
}

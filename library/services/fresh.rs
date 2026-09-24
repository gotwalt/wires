//! Freshness: a directory's signed "this head is the newest" (card 36; TUF's
//! timestamp role).
//!
//! Every [`Settings::beat_secs`](crate::Settings::beat_secs) each directory
//! signs a [`Fresh`] for the head it holds, good until `at +`
//! [`Settings::fresh_secs`](crate::Settings::fresh_secs). A node holding a
//! current `Fresh` for its head knows its policy is the newest; when it
//! lapses, the settings' [`FreshnessMode`](crate::FreshnessMode) decides.
//!
//! A `Fresh` is signed by the directory's own node key, never the root, and is
//! valid only because the root-signed head lists that key in `directories`
//! ([`Fresh::verify`]). It names the head by version and [`HeadHash`], so it
//! can't vouch for another head of the same version.
//!
//! - **Signed bytes:** [`FRESH_CONTEXT`] followed by the canonical JSON of
//!   every field but `sig`.
//! - **Format:** [`FRESH_V1`], signed; unknown fields are refused at decode.
//!
//! ```
//! use library::{Fresh, NodeIdentity, Policy, StateVersion};
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let dir = NodeIdentity::from_seed([2u8; 32]);
//! let mut policy = Policy::new(root.node_id());
//! policy.version = StateVersion(1);
//! policy.not_after = i64::MAX;
//! policy.directories.push(dir.node_id());
//! let head = policy.sign(&root).unwrap().head;
//! let fresh = Fresh::sign(&dir, &head, 1_000, 1_900).unwrap();
//! fresh.verify(&head).unwrap();
//! assert!(fresh.is_current(1_900));
//! assert!(!fresh.is_current(1_901));
//! ```

use serde::{Deserialize, Serialize};

use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::head::{HeadHash, SignedPolicyHead};
use crate::identity::{AlgorithmId, NodeId, NodeIdentity, Signature};
use crate::idp::CLOCK_SKEW_SECS;
use crate::state::StateVersion;

/// The current (and only) `Fresh` format.
pub const FRESH_V1: u8 = 1;

/// Domain-separation prefix of a `Fresh`'s signed bytes.
pub const FRESH_CONTEXT: &[u8] = b"wires/fresh/v1\0";

/// A directory's signed statement that `head` (version `version`) is the
/// newest policy it holds, from `at` until `until`. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fresh {
    /// Format discriminant; [`FRESH_V1`]. Signed.
    pub format: u8,
    /// The fabric (root key) the head belongs to.
    pub fabric: NodeId,
    /// The directory that signed it: must be in the head's `directories`.
    pub directory: NodeId,
    /// The head's version.
    pub version: StateVersion,
    /// The head's hash.
    pub head: HeadHash,
    /// When the directory signed it, unix seconds.
    pub at: i64,
    /// Good until, unix seconds, inclusive.
    pub until: i64,
    /// Which scheme `sig` was produced with.
    pub alg: AlgorithmId,
    /// The directory's signature over [`FRESH_CONTEXT`] ‖ the canonical body.
    pub sig: Signature,
}

impl Fresh {
    /// Sign a `Fresh` for `head` with the directory's node key.
    /// [`Error::NotADirectory`] if the head does not list `directory`;
    /// [`Error::InvalidPolicy`] if `until < at`.
    pub fn sign(
        directory: &NodeIdentity,
        head: &SignedPolicyHead,
        at: i64,
        until: i64,
    ) -> Result<Fresh> {
        todo!("Fresh::sign {} {head:?} {at} {until}", directory.node_id().hex())
    }

    /// Check it vouches for exactly `head` (a head the caller has already
    /// verified under its root): format and algorithm, the same fabric,
    /// version and [`HeadHash`] ([`Error::FreshMismatch`]), a signer the head
    /// lists in `directories` ([`Error::NotADirectory`]), `at <= until`, and
    /// the signature. Does not check the time
    /// ([`is_current`](Self::is_current)).
    pub fn verify(&self, head: &SignedPolicyHead) -> Result<()> {
        todo!("Fresh::verify {head:?}")
    }

    /// Whether it is current at `now`: `now <= until`, and `at` is no further
    /// in the future than [`CLOCK_SKEW_SECS`].
    pub fn is_current(&self, now: i64) -> bool {
        todo!("Fresh::is_current {now} {CLOCK_SKEW_SECS}")
    }
}

/// The signed portion of a [`Fresh`]: every field but `sig`.
#[derive(Serialize)]
struct SignedBody<'a> {
    format: u8,
    fabric: &'a NodeId,
    directory: &'a NodeId,
    version: StateVersion,
    head: &'a HeadHash,
    at: i64,
    until: i64,
    alg: &'a AlgorithmId,
}

impl Fresh {
    fn signed_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = FRESH_CONTEXT.to_vec();
        bytes.extend(canonical_bytes(&SignedBody {
            format: self.format,
            fabric: &self.fabric,
            directory: &self.directory,
            version: self.version,
            head: &self.head,
            at: self.at,
            until: self.until,
            alg: &self.alg,
        })?);
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {}

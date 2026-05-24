//! Capability grants: root-signed, identity-bound, scoped, expiring authority.
//!
//! A [`Grant`] binds a *subject* node key to a *scope* until `not_after`, signed
//! by the fabric root. It is non-transferable: a responder accepts it only when
//! the authenticated caller equals `subject` (see [`crate::policy`]).

use serde::{Deserialize, Serialize};

use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::identity::{NodeId, NodeIdentity, Signature};

/// The signed portion of a grant: every field except `sig`. Serialized to
/// canonical JSON to produce the exact bytes the root signs and a verifier
/// recomputes.
#[derive(Serialize)]
struct GrantBody<'a> {
    subject: &'a NodeId,
    scope: &'a Scope,
    not_after: i64,
    alg: &'a AlgorithmId,
}

/// A coarse capability scope — a named tool/endpoint the grant authorizes
/// (e.g. `"tools.rg"`).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Scope(String);

impl Scope {
    /// Wrap a scope name.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The scope name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Signature scheme a grant was signed with. The root key is pluggable; this
/// tag tells a verifier how to check `sig`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlgorithmId {
    /// Ed25519 — the zero-config default root scheme.
    Ed25519,
}

/// A root-signed capability binding `subject` to `scope` until `not_after`.
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
    /// Root signature over the canonical-JSON grant body (all fields but `sig`).
    pub sig: Signature,
}

impl Grant {
    /// Mint a grant: the fabric `root` signs the canonical body binding
    /// `subject` to `scope` until `not_after`.
    ///
    /// ```
    /// use library::{Grant, NodeIdentity, Scope};
    /// let root = NodeIdentity::from_seed([1u8; 32]);
    /// let agent = NodeIdentity::from_seed([2u8; 32]);
    /// let grant = Grant::mint(&root, agent.node_id(), Scope::new("tools.rg"), i64::MAX).unwrap();
    /// assert!(grant.verify(root.node_id()).is_ok());
    /// // A different root does not verify it.
    /// assert!(grant.verify(agent.node_id()).is_err());
    /// ```
    pub fn mint(
        root: &NodeIdentity,
        subject: NodeId,
        scope: Scope,
        not_after: i64,
    ) -> Result<Grant> {
        let alg = AlgorithmId::Ed25519;
        let body = GrantBody {
            subject: &subject,
            scope: &scope,
            not_after,
            alg: &alg,
        };
        let sig = root.sign(&canonical_bytes(&body)?);
        Ok(Grant {
            subject,
            scope,
            not_after,
            alg,
            sig,
        })
    }

    /// Verify this grant was signed by `root`.
    ///
    /// Checks the algorithm is supported and the signature covers the canonical
    /// body. Does **not** check TTL, revocation, or subject==caller — that is
    /// [`crate::policy::check_accept`].
    pub fn verify(&self, root: NodeId) -> Result<()> {
        if self.alg != AlgorithmId::Ed25519 {
            return Err(Error::UnsupportedAlgorithm);
        }
        let body = GrantBody {
            subject: &self.subject,
            scope: &self.scope,
            not_after: self.not_after,
            alg: &self.alg,
        };
        root.verify(&canonical_bytes(&body)?, &self.sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn seed() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    proptest! {
        /// A freshly minted grant verifies under the minting root.
        #[test]
        fn mint_then_verify_ok(rs in seed(), ss in seed(), scope in "[a-z.]{1,16}", not_after in any::<i64>()) {
            let root = NodeIdentity::from_seed(rs);
            let subject = NodeIdentity::from_seed(ss).node_id();
            let g = Grant::mint(&root, subject, Scope::new(scope), not_after).unwrap();
            prop_assert!(g.verify(root.node_id()).is_ok());
        }

        /// Tampering with any signed field breaks verification.
        #[test]
        fn tampered_scope_fails(rs in seed(), ss in seed(), scope in "[a-z.]{1,16}", not_after in any::<i64>()) {
            let root = NodeIdentity::from_seed(rs);
            let subject = NodeIdentity::from_seed(ss).node_id();
            let mut g = Grant::mint(&root, subject, Scope::new(scope), not_after).unwrap();
            g.scope = Scope::new("tampered.scope.value.too.long");
            prop_assert!(matches!(g.verify(root.node_id()), Err(crate::Error::InvalidSignature)));
        }

        /// A grant does not verify under a different root key.
        #[test]
        fn wrong_root_fails(rs in seed(), os in seed(), ss in seed(), scope in "[a-z.]{1,16}", not_after in any::<i64>()) {
            prop_assume!(rs != os);
            let root = NodeIdentity::from_seed(rs);
            let subject = NodeIdentity::from_seed(ss).node_id();
            let g = Grant::mint(&root, subject, Scope::new(scope), not_after).unwrap();
            prop_assert!(g.verify(NodeIdentity::from_seed(os).node_id()).is_err());
        }
    }

    #[test]
    fn algorithm_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&AlgorithmId::Ed25519).unwrap(),
            "\"ed25519\""
        );
    }
}

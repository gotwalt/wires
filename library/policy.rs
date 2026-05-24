//! Accept-time policy: signature, subject binding, TTL, and revocation.
//!
//! [`check_accept`] is the single gate a responder runs before honoring a
//! session: it ties together grant verification, the non-transferability check
//! (subject == authenticated caller), expiry, and the revocation list.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::grant::Grant;
use crate::identity::NodeId;

/// A revocation list of subject node ids whose grants must be refused.
///
/// Serializes as `{"revoked": [<hex node id>, …]}`, so a responder can persist
/// it and `wires revoke` can round-trip it as JSON.
#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Crl {
    revoked: Vec<NodeId>,
}

impl Crl {
    /// An empty revocation list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Revoke `subject` (idempotent).
    pub fn insert(&mut self, subject: NodeId) {
        if !self.contains(&subject) {
            self.revoked.push(subject);
        }
    }

    /// Whether `subject` is revoked.
    pub fn contains(&self, subject: &NodeId) -> bool {
        self.revoked.contains(subject)
    }

    /// The number of revoked subjects.
    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    /// Whether the revocation list is empty.
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }

    /// Parse a CRL from its JSON form (the inverse of [`to_json`](Self::to_json)).
    ///
    /// ```
    /// use library::Crl;
    /// let crl = Crl::from_json(r#"{"revoked":[]}"#).unwrap();
    /// assert!(crl.is_empty());
    /// ```
    pub fn from_json(s: &str) -> Result<Crl> {
        serde_json::from_str(s).map_err(Error::Decode)
    }

    /// Serialize the CRL to its JSON form.
    ///
    /// ```
    /// use library::{Crl, NodeIdentity};
    /// let mut crl = Crl::new();
    /// crl.insert(NodeIdentity::from_seed([1u8; 32]).node_id());
    /// let json = crl.to_json().unwrap();
    /// assert_eq!(Crl::from_json(&json).unwrap(), crl);
    /// ```
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(Error::Encode)
    }
}

/// Decide whether a responder should accept `grant` from `caller` right now.
///
/// Accepts iff the grant verifies under `root`, its subject equals `caller`,
/// `now_unix <= grant.not_after`, and the subject is not in `crl`. Returns the
/// specific [`crate::Error`] for whichever check fails first.
///
/// ```
/// use library::{check_accept, Crl, Grant, NodeIdentity, Scope};
/// let root = NodeIdentity::from_seed([1u8; 32]);
/// let agent = NodeIdentity::from_seed([2u8; 32]);
/// let grant = Grant::mint(&root, agent.node_id(), Scope::new("tools.rg"), i64::MAX).unwrap();
///
/// // Authenticated caller == subject, not expired, not revoked → accepted.
/// assert!(check_accept(&grant, root.node_id(), agent.node_id(), 0, &Crl::new()).is_ok());
///
/// // Revoke the subject → rejected.
/// let mut crl = Crl::new();
/// crl.insert(agent.node_id());
/// assert!(check_accept(&grant, root.node_id(), agent.node_id(), 0, &crl).is_err());
/// ```
pub fn check_accept(
    grant: &Grant,
    root: NodeId,
    caller: NodeId,
    now_unix: i64,
    crl: &Crl,
) -> Result<()> {
    grant.verify(root)?;
    if grant.subject != caller {
        return Err(Error::SubjectMismatch);
    }
    if now_unix > grant.not_after {
        return Err(Error::Expired {
            not_after: grant.not_after,
        });
    }
    if crl.contains(&grant.subject) {
        return Err(Error::Revoked);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::Scope;
    use crate::identity::NodeIdentity;
    use proptest::prelude::*;

    fn seed() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    proptest! {
        /// `check_accept` succeeds iff subject==caller ∧ now≤not_after ∧ ¬revoked.
        #[test]
        fn accept_iff_all_conditions(
            rs in seed(), ss in seed(), cs in seed(),
            scope in "[a-z.]{1,16}", not_after in any::<i64>(), now in any::<i64>(),
            same_caller in any::<bool>(), revoke in any::<bool>(),
        ) {
            let root = NodeIdentity::from_seed(rs);
            let subject = NodeIdentity::from_seed(ss).node_id();
            let caller = if same_caller { subject } else { NodeIdentity::from_seed(cs).node_id() };
            prop_assume!(same_caller || caller != subject);

            let grant = Grant::mint(&root, subject, Scope::new(scope), not_after).unwrap();
            let mut crl = Crl::new();
            if revoke { crl.insert(subject); }

            let ok = check_accept(&grant, root.node_id(), caller, now, &crl).is_ok();
            prop_assert_eq!(ok, same_caller && now <= not_after && !revoke);
        }

        /// A CRL survives a JSON round-trip unchanged.
        #[test]
        fn crl_json_roundtrips(seeds in proptest::collection::vec(seed(), 0..6)) {
            let mut crl = Crl::new();
            for s in &seeds {
                crl.insert(NodeIdentity::from_seed(*s).node_id());
            }
            let json = serde_json::to_string(&crl).unwrap();
            let back: Crl = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(crl, back);
        }
    }

    fn fixture(not_after: i64) -> (NodeIdentity, NodeId, Grant) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let subject = NodeIdentity::from_seed([2u8; 32]).node_id();
        let grant = Grant::mint(&root, subject, Scope::new("tools.rg"), not_after).unwrap();
        (root, subject, grant)
    }

    #[test]
    fn expired_is_rejected() {
        let (root, subject, grant) = fixture(100);
        assert!(matches!(
            check_accept(&grant, root.node_id(), subject, 101, &Crl::new()),
            Err(crate::Error::Expired { not_after: 100 })
        ));
    }

    #[test]
    fn revoked_is_rejected() {
        let (root, subject, grant) = fixture(i64::MAX);
        let mut crl = Crl::new();
        crl.insert(subject);
        assert!(matches!(
            check_accept(&grant, root.node_id(), subject, 0, &crl),
            Err(crate::Error::Revoked)
        ));
    }

    #[test]
    fn subject_mismatch_is_rejected() {
        let (root, _subject, grant) = fixture(i64::MAX);
        let other = NodeIdentity::from_seed([9u8; 32]).node_id();
        assert!(matches!(
            check_accept(&grant, root.node_id(), other, 0, &Crl::new()),
            Err(crate::Error::SubjectMismatch)
        ));
    }
}

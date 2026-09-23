//! Accept-time policy: signature, subject binding, TTL, and revocation.
//!
//! [`check_accept`] is the single gate a responder runs before honoring a
//! session: it ties together grant verification, the non-transferability check
//! (subject == authenticated caller), expiry, and the revocation list.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::grant::Grant;
use crate::identity::NodeId;
use crate::membership::Membership;
use crate::roster::{InclusionProof, RosterHead};

/// A revocation list of subject node ids whose grants must be refused.
///
/// Serializes as `{"revoked": [<hex node id>, …]}`, so a responder can persist
/// it and `wires advanced revoke` can round-trip it as JSON.
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

/// Decide whether a responder should accept `membership` from `caller` right now.
///
/// Accepts iff the membership verifies under `fabric_root` (signature, version,
/// algorithm, and the `fabric == fabric_root` pin), its `member` equals
/// `caller`, `now_unix <= not_after`, and the member is not in `crl`. Returns
/// the specific [`crate::Error`] for whichever check fails first.
///
/// Like [`check_accept`], this is **only safe when `caller` is a
/// cryptographically authenticated peer.** Non-transferability rests entirely on
/// iroh having authenticated the connection to `member`'s key; the credential
/// alone is bearer-ish and proves nothing about who is presenting it.
///
/// ```
/// use library::{check_inclusion, Crl, Membership, NodeIdentity};
/// let root = NodeIdentity::from_seed([1u8; 32]);
/// let member = NodeIdentity::from_seed([2u8; 32]);
/// let m = Membership::mint(&root, member.node_id(), 0, i64::MAX).unwrap();
///
/// // Authenticated caller == member, not expired, not revoked → accepted.
/// assert!(check_inclusion(&m, root.node_id(), member.node_id(), 0, &Crl::new()).is_ok());
///
/// // A different authenticated caller → non-transferability rejects it.
/// let other = NodeIdentity::from_seed([3u8; 32]).node_id();
/// assert!(check_inclusion(&m, root.node_id(), other, 0, &Crl::new()).is_err());
/// ```
pub fn check_inclusion(
    m: &Membership,
    fabric_root: NodeId,
    caller: NodeId,
    now_unix: i64,
    crl: &Crl,
) -> Result<()> {
    m.verify(fabric_root)?;
    if m.member != caller {
        return Err(Error::SubjectMismatch);
    }
    if now_unix > m.not_after {
        return Err(Error::Expired {
            not_after: m.not_after,
        });
    }
    if crl.contains(&m.member) {
        return Err(Error::Revoked);
    }
    Ok(())
}

/// Decide whether `proof` shows `caller` is a current member under `head`.
///
/// Accepts iff `head` verifies under `fabric_root`, the head is fresh
/// (`now_unix <= not_after`), the proof is for `caller`, it targets this head's
/// version, and the recomputed root matches `head.root`.
///
/// Like [`check_inclusion`], this is **only safe when `caller` is a
/// cryptographically authenticated peer** — the path proves a `NodeId` is in the
/// set; iroh's mutual auth proves the entity on the wire *is* that `NodeId`.
///
/// ```
/// use library::{check_roster_inclusion, NodeIdentity, Roster};
/// let root = NodeIdentity::from_seed([1u8; 32]);
/// let member = NodeIdentity::from_seed([2u8; 32]);
/// let mut roster = Roster::new(root.node_id());
/// roster.insert(member.node_id());
/// let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
/// let (_, proof) = &proofs[0];
/// assert!(check_roster_inclusion(&head, proof, root.node_id(), member.node_id(), 0).is_ok());
/// ```
pub fn check_roster_inclusion(
    head: &RosterHead,
    proof: &InclusionProof,
    fabric_root: NodeId,
    caller: NodeId,
    now_unix: i64,
) -> Result<()> {
    head.verify(fabric_root)?;
    if now_unix > head.not_after {
        return Err(Error::Expired {
            not_after: head.not_after,
        });
    }
    if proof.member != caller {
        return Err(Error::SubjectMismatch);
    }
    if proof.version != head.version {
        return Err(Error::StaleProof {
            proof: proof.version.0,
            head: head.version.0,
        });
    }
    if proof.recompute_root() != head.root {
        return Err(Error::NotInRoster);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::Scope;
    use crate::identity::NodeIdentity;
    use crate::membership::Membership;
    use crate::roster::{Roster, RosterVersion};
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

    proptest! {
        /// `check_inclusion` succeeds iff member==caller ∧ now≤not_after ∧
        /// ¬revoked ∧ the right fabric root (mirrors `accept_iff_all_conditions`).
        #[test]
        fn inclusion_iff_all_conditions(
            rs in seed(), ms in seed(), cs in seed(), os in seed(),
            not_after in any::<i64>(), now in any::<i64>(),
            same_caller in any::<bool>(), revoke in any::<bool>(), right_root in any::<bool>(),
        ) {
            let root = NodeIdentity::from_seed(rs);
            let member = NodeIdentity::from_seed(ms).node_id();
            let caller = if same_caller { member } else { NodeIdentity::from_seed(cs).node_id() };
            prop_assume!(same_caller || caller != member);
            let fabric_root = if right_root { root.node_id() } else { NodeIdentity::from_seed(os).node_id() };
            prop_assume!(right_root || fabric_root != root.node_id());

            let m = Membership::mint(&root, member, 0, not_after).unwrap();
            let mut crl = Crl::new();
            if revoke { crl.insert(member); }

            let ok = check_inclusion(&m, fabric_root, caller, now, &crl).is_ok();
            prop_assert_eq!(ok, right_root && same_caller && now <= not_after && !revoke);
        }
    }

    fn membership_fixture(not_after: i64) -> (NodeIdentity, NodeId, Membership) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let member = NodeIdentity::from_seed([2u8; 32]).node_id();
        let m = Membership::mint(&root, member, 0, not_after).unwrap();
        (root, member, m)
    }

    #[test]
    fn inclusion_member_mismatch_is_rejected() {
        let (root, _member, m) = membership_fixture(i64::MAX);
        let other = NodeIdentity::from_seed([9u8; 32]).node_id();
        assert!(matches!(
            check_inclusion(&m, root.node_id(), other, 0, &Crl::new()),
            Err(crate::Error::SubjectMismatch)
        ));
    }

    #[test]
    fn inclusion_expired_is_rejected() {
        let (root, member, m) = membership_fixture(100);
        assert!(matches!(
            check_inclusion(&m, root.node_id(), member, 101, &Crl::new()),
            Err(crate::Error::Expired { not_after: 100 })
        ));
    }

    #[test]
    fn inclusion_revoked_is_rejected() {
        let (root, member, m) = membership_fixture(i64::MAX);
        let mut crl = Crl::new();
        crl.insert(member);
        assert!(matches!(
            check_inclusion(&m, root.node_id(), member, 0, &crl),
            Err(crate::Error::Revoked)
        ));
    }

    fn roster_fixture(not_after: i64) -> (NodeIdentity, NodeId, RosterHead, InclusionProof) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let member = NodeIdentity::from_seed([2u8; 32]);
        let mut roster = Roster::new(root.node_id());
        roster.insert(member.node_id());
        roster.insert(NodeIdentity::from_seed([3u8; 32]).node_id());
        let (head, proofs) = roster.commit(&root, 0, not_after).unwrap();
        let proof = proofs
            .into_iter()
            .find(|(m, _)| *m == member.node_id())
            .unwrap()
            .1;
        (root, member.node_id(), head, proof)
    }

    #[test]
    fn roster_inclusion_accepts_a_current_member() {
        let (root, member, head, proof) = roster_fixture(i64::MAX);
        assert!(check_roster_inclusion(&head, &proof, root.node_id(), member, 0).is_ok());
    }

    #[test]
    fn roster_inclusion_rejects_wrong_caller() {
        let (root, _member, head, proof) = roster_fixture(i64::MAX);
        let other = NodeIdentity::from_seed([9u8; 32]).node_id();
        assert!(matches!(
            check_roster_inclusion(&head, &proof, root.node_id(), other, 0),
            Err(Error::SubjectMismatch)
        ));
    }

    #[test]
    fn roster_inclusion_rejects_expired_head() {
        let (root, member, head, proof) = roster_fixture(100);
        assert!(matches!(
            check_roster_inclusion(&head, &proof, root.node_id(), member, 101),
            Err(Error::Expired { not_after: 100 })
        ));
    }

    #[test]
    fn roster_inclusion_rejects_stale_proof() {
        // Commit again so the head advances to v2; the v1 proof is stale.
        let root = NodeIdentity::from_seed([1u8; 32]);
        let member = NodeIdentity::from_seed([2u8; 32]);
        let mut roster = Roster::new(root.node_id());
        roster.insert(member.node_id());
        let (_v1_head, v1_proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let v1_proof = v1_proofs.into_iter().next().unwrap().1;
        let (v2_head, _) = roster.commit(&root, 0, i64::MAX).unwrap();
        assert!(matches!(
            check_roster_inclusion(&v2_head, &v1_proof, root.node_id(), member.node_id(), 0),
            Err(Error::StaleProof { proof: 1, head: 2 })
        ));
    }

    #[test]
    fn roster_inclusion_rejects_non_member_path() {
        // A proof version-matched to the head, but whose root differs → NotInRoster.
        let root = NodeIdentity::from_seed([1u8; 32]);
        let member = NodeIdentity::from_seed([2u8; 32]);
        let mut roster = Roster::new(root.node_id());
        roster.insert(member.node_id());
        roster.insert(NodeIdentity::from_seed([5u8; 32]).node_id());
        let (_head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let proof = proofs
            .into_iter()
            .find(|(m, _)| *m == member.node_id())
            .unwrap()
            .1;
        // A different roster, committed to v1 (== proof.version) but a different root.
        let mut roster2 = Roster::new(root.node_id());
        roster2.insert(NodeIdentity::from_seed([6u8; 32]).node_id());
        roster2.insert(NodeIdentity::from_seed([7u8; 32]).node_id());
        roster2.version = RosterVersion(0);
        let (bad_head, _) = roster2.commit(&root, 0, i64::MAX).unwrap();
        assert_eq!(bad_head.version, proof.version);
        assert!(matches!(
            check_roster_inclusion(&bad_head, &proof, root.node_id(), member.node_id(), 0),
            Err(Error::NotInRoster)
        ));
    }
}

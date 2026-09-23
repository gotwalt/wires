//! Accept-time policy: signature, member binding, TTL, and roster inclusion.
//!
//! [`check_inclusion`] is the gate a responder runs on a caller's
//! [`Membership`]; [`check_roster_inclusion`] checks its proof against the
//! committed roster head. Removal is a roster commit that leaves the member
//! out (`wires remove`), so there is no separate revocation list.

use crate::error::{Error, Result};
use crate::identity::NodeId;
use crate::membership::Membership;
use crate::roster::{InclusionProof, RosterHead};

/// Decide whether a responder should accept `membership` from `caller` right now.
///
/// Accepts iff the membership verifies under `fabric_root` (signature, version,
/// algorithm, and the `fabric == fabric_root` pin), its `member` equals
/// `caller`, and `now_unix <= not_after`. Returns the specific
/// [`crate::Error`] for whichever check fails first.
///
/// This is **only safe when `caller` is a
/// cryptographically authenticated peer.** Non-transferability rests entirely on
/// iroh having authenticated the connection to `member`'s key; the credential
/// alone is bearer-ish and proves nothing about who is presenting it.
///
/// ```
/// use library::{check_inclusion, Membership, NodeIdentity};
/// let root = NodeIdentity::from_seed([1u8; 32]);
/// let member = NodeIdentity::from_seed([2u8; 32]);
/// let m = Membership::mint(&root, member.node_id(), 0, i64::MAX).unwrap();
///
/// // Authenticated caller == member and not expired → accepted.
/// assert!(check_inclusion(&m, root.node_id(), member.node_id(), 0).is_ok());
///
/// // A different authenticated caller → non-transferability rejects it.
/// let other = NodeIdentity::from_seed([3u8; 32]).node_id();
/// assert!(check_inclusion(&m, root.node_id(), other, 0).is_err());
/// ```
pub fn check_inclusion(
    m: &Membership,
    fabric_root: NodeId,
    caller: NodeId,
    now_unix: i64,
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
    use crate::identity::NodeIdentity;
    use crate::membership::Membership;
    use crate::roster::{Roster, RosterVersion};
    use proptest::prelude::*;

    fn seed() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    proptest! {
        /// `check_inclusion` succeeds iff member==caller ∧ now≤not_after ∧
        /// the right fabric root.
        #[test]
        fn inclusion_iff_all_conditions(
            rs in seed(), ms in seed(), cs in seed(), os in seed(),
            not_after in any::<i64>(), now in any::<i64>(),
            same_caller in any::<bool>(), right_root in any::<bool>(),
        ) {
            let root = NodeIdentity::from_seed(rs);
            let member = NodeIdentity::from_seed(ms).node_id();
            let caller = if same_caller { member } else { NodeIdentity::from_seed(cs).node_id() };
            prop_assume!(same_caller || caller != member);
            let fabric_root = if right_root { root.node_id() } else { NodeIdentity::from_seed(os).node_id() };
            prop_assume!(right_root || fabric_root != root.node_id());

            let m = Membership::mint(&root, member, 0, not_after).unwrap();
            let ok = check_inclusion(&m, fabric_root, caller, now).is_ok();
            prop_assert_eq!(ok, right_root && same_caller && now <= not_after);
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
            check_inclusion(&m, root.node_id(), other, 0),
            Err(crate::Error::SubjectMismatch)
        ));
    }

    #[test]
    fn inclusion_expired_is_rejected() {
        let (root, member, m) = membership_fixture(100);
        assert!(matches!(
            check_inclusion(&m, root.node_id(), member, 101),
            Err(crate::Error::Expired { not_after: 100 })
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

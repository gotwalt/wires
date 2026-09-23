//! Accept-time policy: signature, member binding, and TTL.
//!
//! [`check_inclusion`] is the gate a host runs on a caller's [`Membership`]
//! credential. Whether the member is *still* in is the admin-signed
//! [`State`](crate::State)'s member set: removal is a new state that leaves
//! the member out (`wires remove`), so there is no separate revocation list.

use crate::error::{Error, Result};
use crate::identity::NodeId;
use crate::membership::Membership;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use crate::membership::Membership;
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
}

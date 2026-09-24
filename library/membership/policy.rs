//! Accept-time policy: is this node admitted to the network right now?
//!
//! A node is admitted by its **badge** (its root-signed [`Membership`]) and
//! not being **banned** by the admin-signed [`Policy`]:
//!
//! - [`check_inclusion`]: the badge verifies under the network root, names
//!   the authenticated caller, and is unexpired;
//! - [`check_admitted`]: that, and the policy doesn't ban the caller. This
//!   is the question every gate asks (a host's call gate, push and inbox
//!   fetch, the record stream, a directory, a caller's inbox, the gateway).
//!
//! The policy lists no members: admitting a node is minting its badge, not
//! an edit. Removal is a ban (`wires remove`), which lasts until the removed
//! badge would have expired anyway.

use crate::error::{Error, Result};
use crate::identity::NodeId;
use crate::membership::Membership;
use crate::signed_policy::Policy;

/// Decide whether a host should accept `membership` from `caller` right now.
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

/// Decide whether `caller`, presenting badge `m`, is admitted under
/// `policy`: [`check_inclusion`] against `fabric_root`, then
/// [`Error::Banned`] if `policy` holds a ban for `caller`
/// ([`Policy::bans_node`]). Returns the first failure.
///
/// Doesn't check `policy` itself (verify it under `fabric_root`, and check
/// it is fresh, before deciding under it). As with [`check_inclusion`],
/// **`caller` must be the cryptographically authenticated peer.**
///
/// ```
/// use library::{check_admitted, Error, Membership, NodeIdentity, Policy};
/// let root = NodeIdentity::from_seed([1u8; 32]);
/// let alice = NodeIdentity::from_seed([2u8; 32]).node_id();
/// let badge = Membership::mint(&root, alice, 0, 100).unwrap();
/// let mut policy = Policy::new(root.node_id());
///
/// // Any badge the root signed admits: the policy needn't list anyone.
/// assert!(check_admitted(&badge, root.node_id(), &policy, alice, 0).is_ok());
///
/// // Removed: banned until the badge would have expired.
/// policy.ban(alice, badge.not_after);
/// assert!(matches!(
///     check_admitted(&badge, root.node_id(), &policy, alice, 0),
///     Err(Error::Banned { until: 100 })
/// ));
/// ```
pub fn check_admitted(
    m: &Membership,
    fabric_root: NodeId,
    policy: &Policy,
    caller: NodeId,
    now_unix: i64,
) -> Result<()> {
    check_inclusion(m, fabric_root, caller, now_unix)?;
    if let Some(ban) = policy.bans.get(&caller) {
        return Err(Error::Banned { until: ban.until });
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

    proptest! {
        /// `check_admitted` succeeds iff `check_inclusion` does and the
        /// policy doesn't ban the caller, whatever else it bans.
        #[test]
        fn admitted_iff_included_and_not_banned(
            ms in seed(),
            not_after in any::<i64>(), now in any::<i64>(),
            banned in any::<bool>(),
            others in proptest::collection::vec(seed(), 0..4),
        ) {
            let root = NodeIdentity::from_seed([1u8; 32]);
            let member = NodeIdentity::from_seed(ms).node_id();
            let m = Membership::mint(&root, member, 0, not_after).unwrap();
            let mut policy = Policy::new(root.node_id());
            for o in &others {
                let other = NodeIdentity::from_seed(*o).node_id();
                if other != member {
                    policy.ban(other, 7);
                }
            }
            if banned {
                policy.ban(member, not_after);
            }
            let included = check_inclusion(&m, root.node_id(), member, now).is_ok();
            let admitted = check_admitted(&m, root.node_id(), &policy, member, now);
            prop_assert_eq!(admitted.is_ok(), included && !banned);
            if included && banned {
                prop_assert!(matches!(admitted, Err(Error::Banned { .. })), "{:?}", admitted);
            }
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

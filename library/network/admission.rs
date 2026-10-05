//! Admission: is this caller in the network right now?
//!
//! No node holds a credential the admin minted for it. A caller is admitted
//! by its person's IdP sign-in: an ID token from an issuer the signed policy
//! trusts, bound to the caller's node key (its `nonce`), unexpired —
//! verified with [`verify_claim`](crate::verify_claim) — and then by not
//! being banned: [`check_admitted`] says whether the [`Policy`] bans that
//! node or that person. Every gate a caller passes asks it (a host's call
//! gate and inbox fetch); a directory cuts a banned caller an empty view
//! instead ([`SignedPolicy::view_for`](crate::SignedPolicy::view_for)).
//!
//! A host or a directory is admitted by the policy naming its key
//! ([`Policy::is_host`], the head's `directories`), never by a credential
//! of its own.

use crate::error::{Error, Result};
use crate::identity::NodeId;
use crate::idp::Principal;
use crate::signed_policy::Policy;

/// Decide whether `caller`, verified as `principal`, is admitted under
/// `policy`: [`Error::Banned`] when the policy bans the node `caller`
/// ([`Policy::bans_node`]) or the person `principal`
/// ([`Policy::bans_person`]), else `Ok`.
///
/// Doesn't check `policy` itself (verify it under the root, and check it is
/// fresh, before deciding under it), nor the token (`principal` must come
/// from a token [`verify_claim`](crate::verify_claim) bound to `caller`).
/// **`caller` must be the cryptographically authenticated peer**: the
/// token's nonce binding is only worth the key iroh authenticated.
///
/// ```
/// use library::{check_admitted, Error, Issuer, NodeIdentity, Person, Policy, Principal};
/// let root = NodeIdentity::from_seed([1u8; 32]);
/// let laptop = NodeIdentity::from_seed([2u8; 32]).node_id();
/// let alice = Principal {
///     issuer: "https://idp".into(), subject: "1".into(),
///     email: Some("alice@example.com".into()), org: None, groups: vec![], not_after: 0,
/// };
/// let mut policy = Policy::new(root.node_id());
///
/// // A verified person on any machine: the policy needn't list anyone.
/// assert!(check_admitted(&policy, laptop, &alice).is_ok());
///
/// // Removed: refused from this machine and from every other one.
/// policy.ban_person(Person::new(Issuer::new("https://idp"), "alice@example.com"));
/// assert!(matches!(check_admitted(&policy, laptop, &alice), Err(Error::Banned)));
/// let desktop = NodeIdentity::from_seed([3u8; 32]).node_id();
/// assert!(matches!(check_admitted(&policy, desktop, &alice), Err(Error::Banned)));
/// ```
pub fn check_admitted(policy: &Policy, caller: NodeId, principal: &Principal) -> Result<()> {
    if policy.bans_node(caller) || policy.bans_person(principal) {
        return Err(Error::Banned);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use crate::idp::Issuer;
    use crate::item::Person;
    use proptest::prelude::*;

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    fn who(issuer: &str, email: Option<&str>) -> Principal {
        Principal {
            issuer: issuer.into(),
            subject: "s".into(),
            email: email.map(Into::into),
            org: None,
            groups: vec![],
            not_after: i64::MAX,
        }
    }

    const EMAILS: [&str; 3] = ["alice@x.com", "bob@x.com", "eve@y.com"];
    const ISSUERS: [&str; 2] = ["https://a", "https://b"];

    proptest! {
        /// Admitted iff neither the node nor the person is banned, whatever
        /// else the policy bans.
        #[test]
        fn admitted_iff_neither_node_nor_person_is_banned(
            caller in 1u8..6,
            iss in 0usize..2,
            email in proptest::option::of(0usize..3),
            node_bans in proptest::collection::btree_set(1u8..6, 0..4),
            person_bans in proptest::collection::btree_set((0usize..2, 0usize..3), 0..4),
        ) {
            let root = NodeIdentity::from_seed([1u8; 32]);
            let mut policy = Policy::new(root.node_id());
            for n in &node_bans {
                policy.ban(node(*n));
            }
            for (i, e) in &person_bans {
                policy.ban_person(Person::new(Issuer::new(ISSUERS[*i]), EMAILS[*e]));
            }
            let p = who(ISSUERS[iss], email.map(|e| EMAILS[e]));
            let banned = node_bans.contains(&caller)
                || email.is_some_and(|e| person_bans.contains(&(iss, e)));
            let result = check_admitted(&policy, node(caller), &p);
            prop_assert_eq!(result.is_ok(), !banned);
            if banned {
                prop_assert!(matches!(result, Err(Error::Banned)), "{:?}", result);
            }
        }
    }

    #[test]
    fn a_person_ban_follows_the_person_not_the_machine() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut policy = Policy::new(root.node_id());
        policy.ban_person(Person::new(Issuer::new("https://a"), "Eve@Y.com"));
        let eve = who("https://a", Some("eve@y.com"));
        for n in 1..5 {
            assert!(check_admitted(&policy, node(n), &eve).is_err());
        }
        // The same address verified by another issuer is someone else.
        assert!(check_admitted(&policy, node(1), &who("https://b", Some("eve@y.com"))).is_ok());
        // An unverified email matches no person ban.
        assert!(check_admitted(&policy, node(1), &who("https://a", None)).is_ok());
    }

    #[test]
    fn a_node_ban_refuses_whoever_signs_in_on_it() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut policy = Policy::new(root.node_id());
        policy.ban(node(9));
        for email in EMAILS {
            assert!(check_admitted(&policy, node(9), &who("https://a", Some(email))).is_err());
            assert!(check_admitted(&policy, node(8), &who("https://a", Some(email))).is_ok());
        }
    }
}

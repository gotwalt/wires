//! Admission: is this caller in the network right now?
//!
//! No node holds a credential the admin minted for it. A caller is admitted
//! by its person's IdP sign-in: an ID token from an issuer the signed policy
//! trusts, bound to the caller's node key (its `nonce`), unexpired —
//! verified with [`verify_claim`](crate::verify_claim) — and then by
//! [`check_admitted`]: **you are in the network if a role matches you.** The
//! principal carries a verified email, the [`Policy`] bans neither that
//! node nor that person, and some role in the policy matches the person.
//! A token alone is not enough: with a public OAuth client anyone with an
//! account at the IdP can get one that verifies.
//!
//! Every gate a caller passes asks this one function: a host's call gate
//! and inbox fetch, and a directory's requests and view subscriptions.
//!
//! A host or a directory is admitted by the policy naming its key
//! ([`Policy::is_host`], the head's `directories`), never by a token or a
//! credential of its own.

use crate::error::{Error, Result};
use crate::identity::NodeId;
use crate::idp::Principal;
use crate::signed_policy::Policy;

/// Decide whether `caller`, verified as `principal`, is admitted under
/// `policy`, in order:
///
/// 1. [`Error::Banned`] when the policy bans the node `caller`
///    ([`Policy::bans_node`]);
/// 2. [`Error::NoVerifiedEmail`] when `principal` carries no verified email
///    (a person ban matches one, so it can't be sidestepped by leaving it
///    out);
/// 3. [`Error::Banned`] when the policy bans the person
///    ([`Policy::bans_person`]);
/// 4. [`Error::NoRole`] when no role in the policy matches the person
///    ([`Policy::any_role_admits`]);
///
/// else `Ok`. A host or directory tells none of these apart to the caller.
///
/// Doesn't check `policy` itself (verify it under the root, and check it is
/// fresh, before deciding under it), nor the token (`principal` must come
/// from a token [`verify_claim`](crate::verify_claim) bound to `caller`).
/// **`caller` must be the cryptographically authenticated peer**: the
/// token's nonce binding is only worth the key iroh authenticated.
///
/// ```
/// use library::{check_admitted, Error, Issuer, Matcher, NodeIdentity, Person, Policy, Principal,
///     RoleName};
/// let root = NodeIdentity::from_seed([1u8; 32]);
/// let laptop = NodeIdentity::from_seed([2u8; 32]).node_id();
/// let mut alice = Principal {
///     issuer: "https://idp".into(), subject: "1".into(),
///     email: Some("alice@example.com".into()), org: None, groups: vec![], not_after: 0,
/// };
/// let mut policy = Policy::new(root.node_id());
///
/// // Signed in, but no role names her: not in the network.
/// assert!(matches!(check_admitted(&policy, laptop, &alice), Err(Error::NoRole)));
///
/// // A role that matches anyone the IdP verified: in, from any machine.
/// policy.roles.insert(RoleName::new("staff").unwrap(), vec![Matcher::new("https://idp")]);
/// assert!(check_admitted(&policy, laptop, &alice).is_ok());
///
/// // Removed: refused from this machine and from every other one.
/// policy.ban_person(Person::new(Issuer::new("https://idp"), "alice@example.com"));
/// assert!(matches!(check_admitted(&policy, laptop, &alice), Err(Error::Banned)));
/// let desktop = NodeIdentity::from_seed([3u8; 32]).node_id();
/// assert!(matches!(check_admitted(&policy, desktop, &alice), Err(Error::Banned)));
///
/// // Leaving the email out doesn't get round the ban.
/// alice.email = None;
/// assert!(matches!(check_admitted(&policy, desktop, &alice), Err(Error::NoVerifiedEmail)));
/// ```
pub fn check_admitted(policy: &Policy, caller: NodeId, principal: &Principal) -> Result<()> {
    if policy.bans_node(caller) {
        return Err(Error::Banned);
    }
    if principal.email.is_none() {
        return Err(Error::NoVerifiedEmail);
    }
    if policy.bans_person(principal) {
        return Err(Error::Banned);
    }
    if !policy.any_role_admits(principal) {
        return Err(Error::NoRole);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use crate::idp::Issuer;
    use crate::item::Person;
    use crate::role::{Matcher, RoleName};
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

    /// A policy whose one role, `staff`, matches anyone issuer `a` verified.
    fn staffed() -> Policy {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut policy = Policy::new(root.node_id());
        policy.roles.insert(
            RoleName::new("staff").unwrap(),
            vec![Matcher::new(ISSUERS[0])],
        );
        policy
    }

    /// Which check [`check_admitted`] should fail, if any.
    #[derive(Debug, PartialEq, Eq)]
    enum Expect {
        Admitted,
        Banned,
        NoEmail,
        NoRole,
    }

    proptest! {
        /// Admitted iff the node isn't banned, the principal has a verified
        /// email, the person isn't banned, and a role matches; and the
        /// first failing check is the error.
        #[test]
        fn admitted_iff_every_check_passes_and_the_first_failure_is_the_error(
            caller in 1u8..6,
            iss in 0usize..2,
            email in proptest::option::of(0usize..3),
            node_bans in proptest::collection::btree_set(1u8..6, 0..4),
            person_bans in proptest::collection::btree_set((0usize..2, 0usize..3), 0..4),
        ) {
            let mut policy = staffed();
            for n in &node_bans {
                policy.ban(node(*n));
            }
            for (i, e) in &person_bans {
                policy.ban_person(Person::new(Issuer::new(ISSUERS[*i]), EMAILS[*e]));
            }
            let p = who(ISSUERS[iss], email.map(|e| EMAILS[e]));
            let expected = if node_bans.contains(&caller) {
                Expect::Banned
            } else if email.is_none() {
                Expect::NoEmail
            } else if email.is_some_and(|e| person_bans.contains(&(iss, e))) {
                Expect::Banned
            } else if iss != 0 {
                Expect::NoRole
            } else {
                Expect::Admitted
            };
            let got = match check_admitted(&policy, node(caller), &p) {
                Ok(()) => Expect::Admitted,
                Err(Error::Banned) => Expect::Banned,
                Err(Error::NoVerifiedEmail) => Expect::NoEmail,
                Err(Error::NoRole) => Expect::NoRole,
                Err(e) => panic!("an unexpected error: {e:?}"),
            };
            prop_assert_eq!(got, expected);
        }
    }

    #[test]
    fn a_person_ban_follows_the_person_not_the_machine() {
        let mut policy = staffed();
        policy.ban_person(Person::new(Issuer::new("https://a"), "Eve@Y.com"));
        let eve = who("https://a", Some("eve@y.com"));
        for n in 1..5 {
            assert!(matches!(
                check_admitted(&policy, node(n), &eve),
                Err(Error::Banned)
            ));
        }
        // Someone else at the same IdP is in.
        assert!(check_admitted(&policy, node(1), &who("https://a", Some("bob@x.com"))).is_ok());
    }

    /// A token with no verified email is refused even under a role that
    /// names only the issuer, or one that matches an `org` or a `group`:
    /// otherwise it would sidestep a person ban.
    #[test]
    fn no_verified_email_is_refused_even_under_an_issuer_only_role() {
        let mut policy = staffed();
        let no_email = who("https://a", None);
        assert!(matches!(
            check_admitted(&policy, node(1), &no_email),
            Err(Error::NoVerifiedEmail)
        ));
        let mut grouped = no_email.clone();
        grouped.groups = vec!["eng".into()];
        policy.roles.insert(
            RoleName::new("eng").unwrap(),
            vec![Matcher {
                group: Some("eng".into()),
                ..Matcher::new("https://a")
            }],
        );
        assert!(matches!(
            check_admitted(&policy, node(1), &grouped),
            Err(Error::NoVerifiedEmail)
        ));
    }

    /// A person the IdP verified whom no role names is not in the network,
    /// and neither is the same email from an issuer no role names.
    #[test]
    fn a_verified_person_no_role_matches_is_not_admitted() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let empty = Policy::new(root.node_id());
        let alice = who("https://a", Some("alice@x.com"));
        assert!(matches!(
            check_admitted(&empty, node(1), &alice),
            Err(Error::NoRole)
        ));
        let elsewhere = who("https://b", Some("alice@x.com"));
        assert!(matches!(
            check_admitted(&staffed(), node(1), &elsewhere),
            Err(Error::NoRole)
        ));
        assert!(check_admitted(&staffed(), node(1), &alice).is_ok());
    }

    #[test]
    fn a_node_ban_refuses_whoever_signs_in_on_it() {
        let mut policy = staffed();
        policy.ban(node(9));
        for email in EMAILS {
            assert!(check_admitted(&policy, node(9), &who("https://a", Some(email))).is_err());
            assert!(check_admitted(&policy, node(8), &who("https://a", Some(email))).is_ok());
        }
    }
}

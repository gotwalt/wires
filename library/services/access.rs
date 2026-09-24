//! Policy evaluation over the signed state: **may this caller call this
//! service**, and **which services may it call** (card 27).
//!
//! One function, two uses: a host runs [`authorize`] on every call (then its
//! own stricter `also_require`), and `wires services` runs
//! [`allowed_services`] locally to list what the caller may use. Both read
//! only the signed [`State`] and the caller's verified [`Principal`]; there
//! is no network and no clock (the principal handed in is already fresh).
//!
//! The host is the ground truth: [`allowed_services`] is defined in terms of
//! [`authorize`], so the listing never shows a service the host would refuse
//! on registry grounds (a host's `also_require` can still narrow it).

use std::fmt;

use crate::identity::NodeId;
use crate::idp::Principal;
use crate::registry::ServiceName;
use crate::role::RoleName;
use crate::state::State;

/// A service the caller may call, and the role that admits it (what `wires
/// services` shows as "why").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The service.
    pub service: ServiceName,
    /// The first role in the service's `allow` that admits the caller.
    pub role: RoleName,
}

/// Why [`authorize`] refused. The `Display` text is what the caller is told
/// and what the call log records, so each case is precise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The caller is not in the state's `members` (never joined, or removed).
    NotAMember,
    /// No service by that name is registered.
    UnknownService(ServiceName),
    /// The service's `allow` is empty: nobody may call it.
    NobodyAllowed(ServiceName),
    /// The caller is in none of the allowed roles. `principal` is the
    /// verified identity it presented (`None`: it presented none), so the
    /// message can say "log in" rather than "not allowed".
    NotInRole {
        /// The service.
        service: ServiceName,
        /// The roles that would have admitted it.
        allow: Vec<RoleName>,
        /// Who the caller verified as, if anyone (`email` or `sub`).
        principal: Option<String>,
    },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let roles = |allow: &[RoleName]| {
            allow
                .iter()
                .map(RoleName::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        };
        match self {
            Refusal::NotAMember => f.write_str("not a member of the current signed state"),
            Refusal::UnknownService(s) => write!(f, "unknown service: {s}"),
            Refusal::NobodyAllowed(s) => write!(f, "service {s} allows no role"),
            Refusal::NotInRole {
                service,
                allow,
                principal: Some(who),
            } => write!(
                f,
                "{who} is in no role allowed to call {service} ({})",
                roles(allow)
            ),
            Refusal::NotInRole {
                service,
                allow,
                principal: None,
            } => write!(
                f,
                "{service} needs a verified identity in role {}; run `wires login`",
                roles(allow)
            ),
        }
    }
}

/// Decide one call against the registry, in order: `caller` is a member →
/// `service` exists → the first role in its `allow` that admits the caller
/// (a defined role whose matchers match its verified `principal`; with no
/// principal, no role admits) → `Ok(role)`. The first failure is the
/// [`Refusal`].
///
/// Does **not** check that the service is assigned to any particular host
/// ([`State::assigns`]) or the host's own `also_require`: those are the
/// host's, on top of this.
///
/// ```
/// use library::{
///     authorize, Matcher, NodeIdentity, Principal, Refusal, RoleName, Service, ServiceName,
///     State,
/// };
///
/// let host = NodeIdentity::from_seed([2u8; 32]).node_id();
/// let mut state = State::new(NodeIdentity::from_seed([1u8; 32]).node_id());
/// state.members.insert(host);
/// state.hosts.insert(host);
/// let staff = RoleName::new("staff").unwrap();
/// state.roles.insert(staff.clone(), vec![Matcher::new("https://idp")]);
/// let status = ServiceName::new("status").unwrap();
/// state.services.insert(status.clone(), Service {
///     description: String::new(),
///     allow: vec![staff.clone()],
///     hosts: vec![host],
///     readers: vec![],
/// });
/// let alice = Principal {
///     issuer: "https://idp".into(), subject: "a".into(), email: None, org: None,
///     groups: vec![], not_after: 0, claims: Default::default(),
/// };
/// assert_eq!(authorize(&state, host, Some(&alice), &status), Ok(staff));
/// // A member with no verified identity is in no role.
/// assert!(matches!(
///     authorize(&state, host, None, &status),
///     Err(Refusal::NotInRole { principal: None, .. })
/// ));
/// let stranger = NodeIdentity::from_seed([9u8; 32]).node_id();
/// assert_eq!(authorize(&state, stranger, None, &status), Err(Refusal::NotAMember));
/// ```
pub fn authorize(
    state: &State,
    caller: NodeId,
    principal: Option<&Principal>,
    service: &ServiceName,
) -> Result<RoleName, Refusal> {
    if !state.is_member(caller) {
        return Err(Refusal::NotAMember);
    }
    let Some(svc) = state.services.get(service) else {
        return Err(Refusal::UnknownService(service.clone()));
    };
    if svc.allow.is_empty() {
        return Err(Refusal::NobodyAllowed(service.clone()));
    }
    if let Some(role) = svc
        .allow
        .iter()
        .find(|role| role_admits(state, role, principal))
    {
        return Ok(role.clone());
    }
    Err(Refusal::NotInRole {
        service: service.clone(),
        allow: svc.allow.clone(),
        principal: principal.map(|p| p.email.clone().unwrap_or_else(|| p.subject.clone())),
    })
}

/// Whether `role` admits a member presenting `principal`: a defined role
/// when one of its matchers matches the verified principal. With no
/// principal, no role admits; an undefined role never admits (a validated
/// state has none, but a failure here must deny).
pub fn role_admits(state: &State, role: &RoleName, principal: Option<&Principal>) -> bool {
    let (Some(p), Some(matchers)) = (principal, state.roles.get(role)) else {
        return false;
    };
    matchers.iter().any(|m| m.matches(p))
}

/// Every service [`authorize`] would admit `caller` to, with the admitting
/// role, in name order. Services it can't call are left out, not listed as
/// refused. A non-member gets nothing.
pub fn allowed_services(
    state: &State,
    caller: NodeId,
    principal: Option<&Principal>,
) -> Vec<Grant> {
    state
        .services
        .keys()
        .filter_map(|service| {
            authorize(state, caller, principal, service)
                .ok()
                .map(|role| Grant {
                    service: service.clone(),
                    role,
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use crate::registry::Service;
    use crate::role::Matcher;
    use crate::state::StateVersion;
    use proptest::prelude::*;

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    const ISS: &str = "https://idp.example";

    fn who(email: &str) -> Principal {
        Principal {
            issuer: ISS.into(),
            subject: email.into(),
            email: Some(email.into()),
            org: None,
            groups: vec![],
            not_after: i64::MAX,
            claims: Default::default(),
        }
    }

    fn name(s: &str) -> ServiceName {
        ServiceName::new(s).unwrap()
    }

    fn staff() -> RoleName {
        RoleName::new("staff").unwrap()
    }

    /// alice (2), bob (3) are members; host (4) serves `orders-db`
    /// (analyst: alice at [`ISS`]) and `status` (staff: anyone [`ISS`]
    /// verified); `locked` allows nobody.
    fn state() -> State {
        let mut s = State::new(node(1));
        s.version = StateVersion(1);
        s.not_after = i64::MAX;
        s.members.extend([node(2), node(3), node(4)]);
        s.hosts.insert(node(4));
        let analyst = RoleName::new("analyst").unwrap();
        s.roles.insert(
            analyst.clone(),
            vec![Matcher {
                email: Some("alice@example.com".parse().unwrap()),
                ..Matcher::new(ISS)
            }],
        );
        s.roles.insert(staff(), vec![Matcher::new(ISS)]);
        let svc = |allow: Vec<RoleName>| Service {
            description: String::new(),
            allow,
            hosts: vec![node(4)],
            readers: vec![],
        };
        s.services.insert(name("orders-db"), svc(vec![analyst]));
        s.services.insert(name("status"), svc(vec![staff()]));
        s.services.insert(name("locked"), svc(vec![]));
        s
    }

    #[test]
    fn analyst_may_call_orders_db() {
        let alice = who("alice@example.com");
        assert_eq!(
            authorize(&state(), node(2), Some(&alice), &name("orders-db")),
            Ok(RoleName::new("analyst").unwrap())
        );
    }

    #[test]
    fn refusals_are_precise() {
        let s = state();
        let bob = who("bob@example.com");
        assert_eq!(
            authorize(&s, node(9), None, &name("status")),
            Err(Refusal::NotAMember)
        );
        assert_eq!(
            authorize(&s, node(3), Some(&bob), &name("nope")),
            Err(Refusal::UnknownService(name("nope")))
        );
        assert_eq!(
            authorize(&s, node(3), Some(&bob), &name("locked")),
            Err(Refusal::NobodyAllowed(name("locked")))
        );
        assert!(matches!(
            authorize(&s, node(3), Some(&bob), &name("orders-db")),
            Err(Refusal::NotInRole {
                principal: Some(_),
                ..
            })
        ));
        assert!(matches!(
            authorize(&s, node(3), None, &name("orders-db")),
            Err(Refusal::NotInRole {
                principal: None,
                ..
            })
        ));
    }

    #[test]
    fn no_identity_no_role() {
        let r = authorize(&state(), node(3), None, &name("status"));
        assert!(
            matches!(
                r,
                Err(Refusal::NotInRole {
                    principal: None,
                    ..
                })
            ),
            "{r:?}"
        );
        assert!(r.unwrap_err().to_string().contains("wires login"));
        let bob = who("bob@example.com");
        assert_eq!(
            authorize(&state(), node(3), Some(&bob), &name("status")),
            Ok(staff())
        );
    }

    #[test]
    fn a_role_named_member_is_an_ordinary_role() {
        let mut s = state();
        let member = RoleName::new("member").unwrap();
        s.roles.insert(
            member.clone(),
            vec![Matcher {
                email: Some("alice@example.com".parse().unwrap()),
                ..Matcher::new(ISS)
            }],
        );
        s.services.get_mut(&name("status")).unwrap().allow = vec![member.clone()];
        s.validate().unwrap();
        assert!(authorize(&s, node(3), None, &name("status")).is_err());
        let bob = who("bob@example.com");
        assert!(authorize(&s, node(3), Some(&bob), &name("status")).is_err());
        let alice = who("alice@example.com");
        assert_eq!(
            authorize(&s, node(2), Some(&alice), &name("status")),
            Ok(member)
        );
    }

    #[test]
    fn the_same_email_from_another_issuer_is_not_admitted() {
        let mut alice = who("alice@example.com");
        alice.issuer = "https://partner-okta.example".into();
        assert!(matches!(
            authorize(&state(), node(2), Some(&alice), &name("orders-db")),
            Err(Refusal::NotInRole { .. })
        ));
        assert!(allowed_services(&state(), node(2), Some(&alice)).is_empty());
    }

    #[test]
    fn listing_shows_only_what_you_may_call() {
        let s = state();
        let alice = who("alice@example.com");
        let listed: Vec<_> = allowed_services(&s, node(2), Some(&alice))
            .into_iter()
            .map(|g| g.service)
            .collect();
        assert_eq!(listed, vec![name("orders-db"), name("status")]);
        let bob = who("bob@example.com");
        let listed: Vec<_> = allowed_services(&s, node(3), Some(&bob))
            .into_iter()
            .map(|g| g.service)
            .collect();
        assert_eq!(listed, vec![name("status")]);
        assert!(allowed_services(&s, node(3), None).is_empty());
        assert!(allowed_services(&s, node(9), Some(&alice)).is_empty());
    }

    #[test]
    fn first_admitting_role_wins_and_undefined_roles_deny() {
        let mut s = state();
        let analyst = RoleName::new("analyst").unwrap();
        s.services.get_mut(&name("status")).unwrap().allow = vec![analyst.clone(), staff()];
        let alice = who("alice@example.com");
        assert_eq!(
            authorize(&s, node(2), Some(&alice), &name("status")),
            Ok(analyst)
        );
        let bob = who("bob@example.com");
        assert_eq!(
            authorize(&s, node(3), Some(&bob), &name("status")),
            Ok(staff())
        );
        let ghost = RoleName::new("ghost").unwrap();
        assert!(!role_admits(&s, &ghost, Some(&alice)));
    }

    #[test]
    fn principal_without_email_is_named_by_subject() {
        let mut p = who("x");
        p.email = None;
        p.subject = "sub-42".into();
        assert!(matches!(
            authorize(&state(), node(3), Some(&p), &name("orders-db")),
            Err(Refusal::NotInRole { principal: Some(ref w), .. }) if w == "sub-42"
        ));
    }

    proptest! {
        /// The listing is exactly the services `authorize` admits, with the
        /// same role; a non-member is refused everything first.
        #[test]
        fn listing_agrees_with_authorize(
            caller in 1u8..12,
            email in prop::option::of(prop::sample::select(vec![
                "alice@example.com", "bob@example.com", "eve@evil.net",
            ])),
        ) {
            let s = state();
            let p = email.map(who);
            let listed = allowed_services(&s, node(caller), p.as_ref());
            for svc in s.services.keys() {
                let got = authorize(&s, node(caller), p.as_ref(), svc);
                let shown = listed.iter().find(|g| &g.service == svc);
                prop_assert_eq!(got.clone().ok(), shown.map(|g| g.role.clone()));
                if !s.is_member(node(caller)) {
                    prop_assert_eq!(got.clone(), Err(Refusal::NotAMember));
                }
                if p.is_none() {
                    prop_assert!(got.is_err(), "no identity, no role");
                }
                if let Ok(role) = got {
                    prop_assert!(s.services[svc].allow.contains(&role));
                    prop_assert!(role_admits(&s, &role, p.as_ref()));
                }
            }
        }
    }

    #[test]
    fn refusal_text_says_what_to_do() {
        let r = Refusal::NotInRole {
            service: name("orders-db"),
            allow: vec![RoleName::new("analyst").unwrap()],
            principal: None,
        };
        assert!(r.to_string().contains("wires login"));
    }
}

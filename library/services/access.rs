//! Policy evaluation over the signed policy: **may this caller call this
//! service**, and **which services may it call**.
//!
//! One function, two uses: a host runs [`authorize`] on every call (then its
//! own stricter `also_require`), and `wires services` runs
//! [`allowed_services`] locally to list what the caller may use. Both read
//! only the [`Policy`] (a verified [`SignedPolicy`](crate::SignedPolicy)'s
//! items) and the caller's verified [`Principal`]; there
//! is no network and no clock (the principal handed in is already fresh).
//!
//! Neither checks the caller's badge: that is the gate's, before this
//! ([`check_admitted`](crate::check_admitted)). Both do refuse a node the
//! policy bans, so a registry decision never admits a removed node.
//!
//! The host is the ground truth: [`allowed_services`] is defined in terms of
//! [`authorize`], so the listing never shows a service the host would refuse
//! on registry grounds (a host's `also_require` can still narrow it).

use std::fmt;

use crate::identity::NodeId;
use crate::idp::Principal;
use crate::registry::ServiceName;
use crate::role::RoleName;
use crate::signed_policy::Policy;

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
    /// The policy bans the caller: the admin removed it.
    Banned,
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
            Refusal::Banned => f.write_str("removed from this network"),
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

/// Decide one call against the registry, in order: `caller` is not banned →
/// `service` exists → the first role in its `allow` that admits the caller
/// (a defined role whose matchers match its verified `principal`; with no
/// principal, no role admits) → `Ok(role)`. The first failure is the
/// [`Refusal`].
///
/// Does **not** check that the service is assigned to any particular host
/// ([`Policy::assigns`]) or the host's own `also_require`: those are the
/// host's, on top of this.
///
/// ```
/// use library::{
///     authorize, Matcher, NodeIdentity, Policy, Principal, Refusal, RoleName, Service,
///     ServiceName,
/// };
///
/// let host = NodeIdentity::from_seed([2u8; 32]).node_id();
/// let mut state = Policy::new(NodeIdentity::from_seed([1u8; 32]).node_id());
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
///     groups: vec![], not_after: 0,
/// };
/// assert_eq!(authorize(&state, host, Some(&alice), &status), Ok(staff));
/// // A node with no verified identity is in no role.
/// assert!(matches!(
///     authorize(&state, host, None, &status),
///     Err(Refusal::NotInRole { principal: None, .. })
/// ));
/// let removed = NodeIdentity::from_seed([9u8; 32]).node_id();
/// state.ban(removed, i64::MAX);
/// assert_eq!(authorize(&state, removed, Some(&alice), &status), Err(Refusal::Banned));
/// ```
pub fn authorize(
    state: &Policy,
    caller: NodeId,
    principal: Option<&Principal>,
    service: &ServiceName,
) -> Result<RoleName, Refusal> {
    if state.bans_node(caller) {
        return Err(Refusal::Banned);
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

/// Whether `role` admits a node presenting `principal`: a defined role
/// when one of its matchers matches the verified principal. With no
/// principal, no role admits; an undefined role never admits (a validated
/// policy has none, but a failure here must deny).
pub fn role_admits(state: &Policy, role: &RoleName, principal: Option<&Principal>) -> bool {
    state.role_admits(role, principal)
}

/// Every service [`authorize`] would admit `caller` to, with the admitting
/// role, in name order. Services it can't call are left out, not listed as
/// refused. A banned node gets nothing.
pub fn allowed_services(
    state: &Policy,
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
    use crate::head::StateVersion;
    use crate::identity::NodeIdentity;
    use crate::registry::Service;
    use crate::role::Matcher;

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
        }
    }

    fn name(s: &str) -> ServiceName {
        ServiceName::new(s).unwrap()
    }

    fn staff() -> RoleName {
        RoleName::new("staff").unwrap()
    }

    /// alice (2), bob (3) call; host (4) serves `orders-db` (analyst:
    /// alice at [`ISS`]) and `status` (staff: anyone [`ISS`] verified);
    /// `locked` allows nobody; 9 is banned.
    fn state() -> Policy {
        let mut s = Policy::new(node(1));
        s.version = StateVersion(1);
        s.not_after = i64::MAX;
        s.ban(node(9), i64::MAX);
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
            authorize(&s, node(9), Some(&bob), &name("status")),
            Err(Refusal::Banned)
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
        // A node the policy never heard of is no different from alice.
        assert_eq!(allowed_services(&s, node(8), Some(&alice)).len(), 2);
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
}

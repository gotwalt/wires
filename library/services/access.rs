//! Policy evaluation over the signed state: **may this caller call this
//! service**, and **which services may it call** (card 27).
//!
//! One function, two uses: a host runs [`authorize`] on every call (then its
//! own stricter `also_require`), and `wires services` runs
//! [`allowed_services`] locally to list what the caller may use. Both read
//! only the signed [`State`] and the caller's verified [`Principal`]; there
//! is no network and no clock (the principal handed in is already fresh).
//!
//! **Lane 27c implements [`authorize`]** (the host is the ground truth);
//! [`allowed_services`] is defined in terms of it, so 27b gets it for free.
//! Until then both panic, and their tests are `#[ignore = "27c"]`.

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
/// (`member` admits any member; a defined role admits a caller whose
/// `principal` matches one of its matchers) → `Ok(role)`. The first failure
/// is the [`Refusal`].
///
/// Does **not** check that the service is assigned to any particular host
/// ([`State::assigns`]) or the host's own `also_require`: those are the
/// host's, on top of this.
pub fn authorize(
    state: &State,
    caller: NodeId,
    principal: Option<&Principal>,
    service: &ServiceName,
) -> Result<RoleName, Refusal> {
    let _ = (state, caller, principal, service);
    todo!("27c: registry authorization")
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

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    fn who(email: &str) -> Principal {
        Principal {
            issuer: "https://idp.example".into(),
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

    /// alice (2), bob (3) are members; host (4) serves `orders-db`
    /// (analyst) and `status` (member); `locked` allows nobody.
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
                ..Default::default()
            }],
        );
        let svc = |allow: Vec<RoleName>| Service {
            description: String::new(),
            allow,
            hosts: vec![node(4)],
            readers: vec![],
        };
        s.services.insert(name("orders-db"), svc(vec![analyst]));
        s.services
            .insert(name("status"), svc(vec![RoleName::member()]));
        s.services.insert(name("locked"), svc(vec![]));
        s
    }

    #[test]
    #[ignore = "27c"]
    fn analyst_may_call_orders_db() {
        let alice = who("alice@example.com");
        assert_eq!(
            authorize(&state(), node(2), Some(&alice), &name("orders-db")),
            Ok(RoleName::new("analyst").unwrap())
        );
    }

    #[test]
    #[ignore = "27c"]
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
    #[ignore = "27c"]
    fn member_role_needs_no_identity() {
        assert_eq!(
            authorize(&state(), node(3), None, &name("status")),
            Ok(RoleName::member())
        );
    }

    #[test]
    #[ignore = "27c"]
    fn listing_shows_only_what_you_may_call() {
        let s = state();
        let alice = who("alice@example.com");
        let listed: Vec<_> = allowed_services(&s, node(2), Some(&alice))
            .into_iter()
            .map(|g| g.service)
            .collect();
        assert_eq!(listed, vec![name("orders-db"), name("status")]);
        let listed: Vec<_> = allowed_services(&s, node(3), None)
            .into_iter()
            .map(|g| g.service)
            .collect();
        assert_eq!(listed, vec![name("status")]);
        assert!(allowed_services(&s, node(9), Some(&alice)).is_empty());
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

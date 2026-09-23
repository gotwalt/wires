//! Service name → host (card 27, lane **27b**). The caller never names a
//! host: it takes the service's `hosts` from the signed state, tries the
//! last one that worked first, then the rest in the admin's order, moving to
//! the next on a dial failure (not on a refusal: a host that refused has
//! decided). `--verbose` says which host answered.

// Nothing calls this until lane 27b switches `call`/`mcp` over.
#![allow(dead_code)]

use library::{NodeId, ServiceName, State};

/// The hosts to try for `service`, in order: `last_good` first if it still
/// implements it, then the registry's order. Empty if the service is unknown
/// or has no hosts.
pub(crate) fn candidates(
    state: &State,
    service: &ServiceName,
    last_good: Option<NodeId>,
) -> Vec<NodeId> {
    let _ = (state, service, last_good);
    todo!("27b: host order with failover")
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{NodeIdentity, RoleName, Service, StateVersion};

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    #[test]
    #[ignore = "27b"]
    fn last_good_first_then_registry_order() {
        let mut s = State::new(node(1));
        s.version = StateVersion(1);
        s.members.extend([node(2), node(3), node(4)]);
        s.hosts.extend([node(2), node(3)]);
        let name = ServiceName::new("orders-db").unwrap();
        s.services.insert(
            name.clone(),
            Service {
                description: String::new(),
                allow: vec![RoleName::member()],
                hosts: vec![node(2), node(3)],
                readers: vec![],
            },
        );
        assert_eq!(candidates(&s, &name, None), vec![node(2), node(3)]);
        assert_eq!(candidates(&s, &name, Some(node(3))), vec![node(3), node(2)]);
        assert_eq!(candidates(&s, &name, Some(node(4))), vec![node(2), node(3)]);
        let other = ServiceName::new("nope").unwrap();
        assert!(candidates(&s, &other, None).is_empty());
    }
}

//! The services-era call gate (card 27, lane **27c**): what a host checks on
//! every [`Hello`](library::Hello) + [`Invoke`](library::Frame::Invoke),
//! in order, the first failure being the refusal the caller hears and the
//! call log records:
//!
//! 1. the host's signed state is fresh ([`SignedState::check_fresh`]);
//! 2. the caller is a member of it (removal is omission; no restart needed,
//!    because the state is re-read per connection);
//! 3. the service is assigned to **this** host ([`State::assigns`](library::State::assigns));
//! 4. the registry allows the caller's role ([`library::authorize`]);
//! 5. the host's own `also_require` roles (`host.json` v2), which can only
//!    narrow.
//!
//! The caller's principal is verified before this runs (the ID token from
//! the `Hello`, nonce-bound to the iroh-authenticated caller, under the
//! host's `identity.issuers`), so this function is pure and clock-free
//! except for `now`.

// Nothing calls this until lane 27c switches the transport over.
#![allow(dead_code)]

use library::{NodeId, Principal, RoleName, ServiceName, SignedState, StateVersion};

use crate::host::config_v2::HostConfigV2;

/// A call the gate admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Admitted {
    /// The registry role that admitted the caller (recorded in the log).
    pub(crate) role: RoleName,
    /// The state version the decision was made under.
    pub(crate) state_version: StateVersion,
}

/// Run the checks in the module docs. `Err` is the refusal text.
pub(crate) fn admit(
    state: &SignedState,
    config: &HostConfigV2,
    me: NodeId,
    caller: NodeId,
    principal: Option<&Principal>,
    service: &ServiceName,
    now: i64,
) -> Result<Admitted, String> {
    let _ = (state, config, me, caller, principal, service, now);
    todo!("27c: registry gate")
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{NodeIdentity, Service, State};

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    /// Root 1; members 2 (caller) and 3 (this host); `status` (member) on 3.
    fn setup() -> (SignedState, HostConfigV2) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut s = State::new(root.node_id());
        s.version = StateVersion(5);
        s.not_after = 100;
        s.members.extend([node(2), node(3)]);
        s.hosts.insert(node(3));
        s.services.insert(
            ServiceName::new("status").unwrap(),
            Service {
                description: String::new(),
                allow: vec![RoleName::member()],
                hosts: vec![node(3)],
                readers: vec![],
            },
        );
        let cfg =
            HostConfigV2::parse(r#"{"version":2,"services":{"status":{"command":["true"]}}}"#)
                .unwrap();
        (s.sign(&root).unwrap(), cfg)
    }

    #[test]
    #[ignore = "27c"]
    fn member_role_admits_a_member() {
        let (s, cfg) = setup();
        let status = ServiceName::new("status").unwrap();
        let ok = admit(&s, &cfg, node(3), node(2), None, &status, 0);
        assert_eq!(ok.unwrap().state_version, StateVersion(5));
    }

    #[test]
    #[ignore = "27c"]
    fn refusals_in_order() {
        let (s, cfg) = setup();
        let status = ServiceName::new("status").unwrap();
        assert!(admit(&s, &cfg, node(3), node(2), None, &status, 101).is_err()); // expired
        assert!(admit(&s, &cfg, node(3), node(9), None, &status, 0).is_err()); // not a member
        assert!(admit(&s, &cfg, node(2), node(2), None, &status, 0).is_err()); // not assigned here
    }
}

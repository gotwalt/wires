//! Measures what each part of a signed state costs on the wire, for the
//! state-scale model (`bench/state-scale/model.py --measure`).
//!
//! Builds real [`SignedState`]s with the library, serializes them as they
//! travel (`serde_json`, the `offer` frame's body), and prints the marginal
//! bytes per ban, service, role and email matcher as one JSON line. The
//! state lists no members or hosts since card 35 (a host is only its entries
//! in services' `hosts`), so there is nothing per member to measure.
//!
//! ```text
//! cargo run -q --release -p library --example state_sizes
//! ```

use library::{
    Matcher, Membership, NodeId, NodeIdentity, RoleName, Service, ServiceName, SignedState, State,
    StateVersion,
};

const ISSUED: i64 = 1_790_000_000;
const NOT_AFTER: i64 = ISSUED + 30 * 86_400;

/// A deterministic node id for index `i`.
fn node(i: u64) -> NodeId {
    let mut seed = [7u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    NodeIdentity::from_seed(seed).node_id()
}

/// The shape of one state to measure.
#[derive(Clone, Copy)]
struct Shape {
    bans: u64,
    hosts: u64,
    services: u64,
    roles: u64,
    matchers_per_role: u64,
    email_roles: bool,
}

impl Shape {
    const BASE: Shape = Shape {
        bans: 0,
        hosts: 0,
        services: 0,
        roles: 3,
        matchers_per_role: 1,
        email_roles: false,
    };
}

/// The serialized size of a signed state of `shape`. Every service has an
/// 80-character description, 2 hosts, 2 allow roles and 1 reader role.
fn size(root: &NodeIdentity, shape: Shape) -> usize {
    let mut state = State::new(root.node_id());
    state.version = StateVersion(123_456);
    state.issued = ISSUED;
    state.not_after = NOT_AFTER;
    for i in 0..shape.bans {
        state.ban(node(1_000_000 + i), NOT_AFTER);
    }
    let hosts: Vec<NodeId> = (0..shape.hosts).map(node).collect();
    for r in 0..shape.roles {
        let matchers = (0..shape.matchers_per_role)
            .map(|j| {
                if shape.email_roles {
                    let email = format!("user{:05}@acme-corp.com", r * shape.matchers_per_role + j);
                    Matcher {
                        email: Some(email.parse().expect("a valid email")),
                        ..Matcher::new("https://accounts.google.com")
                    }
                } else {
                    Matcher {
                        group: Some(format!("eng-team-{r:04}")),
                        ..Matcher::new("https://acme.okta.com")
                    }
                }
            })
            .collect();
        state.roles.insert(role(r), matchers);
    }
    for s in 0..shape.services {
        let service = Service {
            description:
                "Read-only SQL against the orders replica; returns CSV. Filter with --where.".into(),
            allow: vec![role(s % shape.roles), role((s + 1) % shape.roles)],
            hosts: (0..2.min(shape.hosts))
                .map(|k| hosts[((s + k) % shape.hosts) as usize])
                .collect(),
            readers: vec![role((s + 2) % shape.roles)],
        };
        let name = ServiceName::new(format!("svc-{s:05}-orders-db")).expect("a valid name");
        state.services.insert(name, service);
    }
    let signed: SignedState = state.sign(root).expect("a valid state");
    serde_json::to_vec(&signed).expect("serializable").len()
}

fn role(i: u64) -> RoleName {
    RoleName::new(format!("role-{i:04}")).expect("a valid role name")
}

/// Marginal bytes per unit: `(size(with) - size(without)) / units`.
fn per(root: &NodeIdentity, without: Shape, with: Shape, units: u64) -> f64 {
    (size(root, with) as f64 - size(root, without) as f64) / units as f64
}

fn main() {
    let root = NodeIdentity::from_seed([9; 32]);
    let base = Shape::BASE;
    let n = 1_000;
    let with_hosts = Shape { hosts: 100, ..base };
    let emails = Shape {
        email_roles: true,
        ..base
    };
    let membership = Membership::mint(&root, node(5), ISSUED, NOT_AFTER).expect("a membership");
    let out = serde_json::json!({
        "base": size(&root, base),
        "ban": per(&root, base, Shape { bans: n, ..base }, n),
        "service": per(&root, with_hosts, Shape { services: n, ..with_hosts }, n),
        "role": per(&root, base, Shape { roles: 3 + n, ..base }, n),
        "email_matcher": per(&root, emails, Shape { matchers_per_role: 1 + n, ..emails }, 3 * n),
        "membership": serde_json::to_vec(&membership).expect("serializable").len(),
    });
    println!("{out}");
}

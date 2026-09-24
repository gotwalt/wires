//! Measures what the directory's frames cost on the wire (card 36d), for
//! `bench/state-scale/model.py`'s *apex* assumptions: a host's first sync
//! (the whole policy), its updates, the freshness beat, and a caller's view.
//!
//! Builds real signed policies with the library at the model's tiers, and
//! prints one JSON line per tier: the head, a `Fresh` and its beat frame, a
//! signed service entry, the whole policy (as published and as the frame a
//! host first receives), the `policy_update` frame for one changed service
//! and for one new ban, and a caller's view of about 25 services (entry
//! count and frame).
//!
//! ```text
//! cargo run -q --release -p library --example policy_sizes
//! ```

use library::{
    Audience, Ban, Fresh, Issuer, IssuerConfig, Item, Matcher, NodeId, NodeIdentity, Policy,
    Principal, RoleName, Service, ServiceName, SignedPolicy, StateVersion, SubFrame,
};

const ISSUED: i64 = 1_790_000_000;
const ISS: &str = "https://acme.okta.com";

/// A deterministic node id for index `i`.
fn node(i: u64) -> NodeId {
    NodeIdentity::from_seed(seed(i)).node_id()
}

fn seed(i: u64) -> [u8; 32] {
    let mut seed = [7u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    seed
}

fn role(i: u64) -> RoleName {
    RoleName::new(format!("role-{i:04}")).expect("a valid role name")
}

fn service_name(s: u64) -> ServiceName {
    ServiceName::new(format!("svc-{s:05}-orders-db")).expect("a valid name")
}

fn len<T: serde::Serialize>(value: &T) -> usize {
    serde_json::to_vec(value).expect("serializable").len()
}

/// A tier of the model: `services` (2 hosts each, 2 allow roles and 1
/// reader, an 80-character description), `hosts`, `services / 5` roles
/// (one group matcher each), and `bans` open bans.
struct Tier {
    name: &'static str,
    services: u64,
    hosts: u64,
    bans: u64,
}

/// Directory 0's identity (the policy lists directories 0 and 1).
fn directory() -> NodeIdentity {
    NodeIdentity::from_seed(seed(u64::MAX))
}

fn policy(root: &NodeIdentity, t: &Tier) -> Policy {
    let mut p = Policy::new(root.node_id());
    p.version = StateVersion(123_456);
    p.issued = ISSUED;
    p.not_after = ISSUED + 90 * 86_400;
    p.directories = vec![directory().node_id(), node(u64::MAX - 1)];
    p.issuers.insert(
        Issuer::new(ISS),
        IssuerConfig {
            client_id: Audience::new("0oa1b2c3d4e5f6g7h8i9"),
            audiences: vec![Audience::new("0oa1b2c3d4e5f6g7h8i9")],
        },
    );
    let roles = (t.services / 5).max(3);
    for r in 0..roles {
        p.roles.insert(
            role(r),
            vec![Matcher {
                group: Some(format!("eng-team-{r:04}")),
                ..Matcher::new(ISS)
            }],
        );
    }
    for s in 0..t.services {
        let service = Service {
            description:
                "Read-only SQL against the orders replica; returns CSV. Filter with --where.".into(),
            allow: vec![role(s % roles), role((s + 1) % roles)],
            hosts: (0..2)
                .map(|k| node(1_000_000 + (s + k) % t.hosts))
                .collect(),
            readers: vec![role((s + 2) % roles)],
        };
        p.services.insert(service_name(s), service);
    }
    for b in 0..t.bans {
        p.bans.insert(
            node(2_000_000 + b),
            Ban {
                until: ISSUED + 30 * 86_400,
            },
        );
    }
    p
}

fn fresh(head: &SignedPolicy) -> Fresh {
    Fresh::sign(&directory(), &head.head, ISSUED, ISSUED + 900).expect("a directory")
}

/// The bytes of the `policy_update` frame that moves `from` to `next`, with
/// its `Fresh`; and how many items it carries.
fn update_frame(from: &SignedPolicy, next: &SignedPolicy) -> (usize, usize) {
    let update = next.update_from(from);
    let items = update.changed.len() + update.removed.len();
    let frame = SubFrame::PolicyUpdate {
        update,
        fresh: fresh(next),
    };
    (frame.encode().expect("a frame").len(), items)
}

fn measure(root: &NodeIdentity, t: &Tier) -> serde_json::Value {
    let base = policy(root, t);
    let signed = base.sign(root).expect("a valid policy");
    let fresh = fresh(&signed);
    let service = signed
        .items
        .iter()
        .find(|i| matches!(i, Item::Service(_)))
        .expect("a service");

    // A caller in 2 roles: each role is in about 10 services' `allow` and 5
    // services' `readers`, so about 25 services admit it (the model assumes
    // 30 `visible_services`).
    let caller = Principal {
        issuer: ISS.into(),
        subject: "00u1a2b3c4".into(),
        email: Some("alice@acme-corp.com".into()),
        org: None,
        groups: (0..2).map(|r| format!("eng-team-{:04}", r * 2)).collect(),
        not_after: i64::MAX,
    };
    let view = signed.view_for(Some(&caller), None);

    // Two edits, each version + 1 and signed after the base, as the admin
    // signs: one service's description, and a new ban.
    let edit = |f: &dyn Fn(&mut Policy)| {
        let mut p = base.clone();
        p.version = StateVersion(p.version.0 + 1);
        f(&mut p);
        p.sign_after(root, &signed).expect("a valid policy")
    };
    let changed = update_frame(
        &signed,
        &edit(&|p: &mut Policy| {
            p.services
                .get_mut(&service_name(0))
                .expect("a service")
                .description =
                "Read-only SQL against the orders replica, now with a 30 s timeout.".into();
        }),
    );
    let banned = update_frame(
        &signed,
        &edit(&|p: &mut Policy| {
            p.bans.insert(
                node(3_000_000),
                Ban {
                    until: ISSUED + 30 * 86_400,
                },
            );
        }),
    );

    serde_json::json!({
        "tier": t.name,
        "services": t.services,
        "bans": t.bans,
        "items": signed.items.len(),
        "head": len(&signed.head),
        "fresh": len(&fresh),
        "fresh_beat_frame": SubFrame::Fresh { fresh: fresh.clone() }.encode().expect("a frame").len(),
        "service_entry": len(service),
        "policy": len(&signed),
        "policy_frame": SubFrame::Policy { policy: signed.clone(), fresh: fresh.clone() }
            .encode()
            .expect("a frame")
            .len(),
        "update_changed_service": changed.0,
        "update_changed_service_items": changed.1,
        "update_new_ban": banned.0,
        "update_new_ban_items": banned.1,
        "view_entries": view.entries.len(),
        "view_frame": SubFrame::View { view, fresh }.encode().expect("a frame").len(),
    })
}

fn main() {
    let root = NodeIdentity::from_seed([9; 32]);
    // The model's tiers ((users, services, hosts): company, enterprise,
    // large), with 30 days of removals as open bans (node churn 0.001 per
    // node per day, half of it removals, two nodes per user).
    for t in [
        Tier {
            name: "company",
            services: 100,
            hosts: 50,
            bans: 30,
        },
        Tier {
            name: "enterprise-1k",
            services: 1_000,
            hosts: 500,
            bans: 300,
        },
        Tier {
            name: "large-5k",
            services: 5_000,
            hosts: 1_000,
            bans: 1_500,
        },
    ] {
        println!("{}", measure(&root, &t));
    }
}

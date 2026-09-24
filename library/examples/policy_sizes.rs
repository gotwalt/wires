//! Measures what the directory's policy parts cost on the wire (card 36), to
//! check `bench/state-scale/model.py`'s *apex* assumptions (`entry_sig`, the
//! per-entry overhead, and `timestamp`, the freshness beat).
//!
//! Builds real signed policies with the library at the model's tiers, and
//! prints one JSON line per tier: the serialized head and `Fresh`, a service
//! item, a host's whole slice (its multiproof and the frame carrying it), a
//! caller's view of about 25 services, and the subscription update a host
//! receives when an edit leaves its slice unchanged, changes one of its
//! services, or adds a ban.
//!
//! ```text
//! cargo run -q --release -p library --example policy_sizes
//! ```

use library::{
    Audience, Ban, Fresh, Issuer, IssuerConfig, Item, Matcher, NodeId, NodeIdentity, Policy,
    Principal, RoleName, Service, ServiceName, SignedPolicy, Slice, StateVersion, SubFrame,
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
        let name = ServiceName::new(format!("svc-{s:05}-orders-db")).expect("a valid name");
        p.services.insert(name, service);
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

/// The bytes of the subscription frame that moves `from` to the host's slice
/// under `next`, with its `Fresh`; and how many items it changed.
fn update_frame(from: &Slice, next: &SignedPolicy, host: NodeId) -> (usize, usize) {
    let update = next.slice_update(from, host, &[]).expect("an update");
    let fresh = Fresh::sign(&directory(), &next.head, ISSUED, ISSUED + 900).expect("a directory");
    let changed = update.changed.len() + update.removed.len();
    let frame = SubFrame::SliceUpdate { update, fresh };
    (frame.encode().expect("a frame").len(), changed)
}

fn measure(root: &NodeIdentity, t: &Tier) -> serde_json::Value {
    let base = policy(root, t);
    let signed = base.sign(root).expect("a valid policy");
    let head = &signed.head;
    let fresh = Fresh::sign(&directory(), head, ISSUED, ISSUED + 900).expect("a directory");
    let host = node(1_000_000);
    let slice = signed.slice_for_host(host, &[]).expect("a slice");
    let service = slice
        .items
        .iter()
        .find(|i| matches!(i, Item::Service { .. }))
        .expect("the host runs a service");

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
    let view = signed.view_for(Some(&caller), None).expect("a view");

    // Three edits, each version + 1: one to a service this host doesn't
    // run, one to a service it does, and a new ban.
    let edit = |f: &dyn Fn(&mut Policy)| {
        let mut p = base.clone();
        p.version = StateVersion(p.version.0 + 1);
        f(&mut p);
        p.sign(root).expect("a valid policy")
    };
    let describe = |s: u64| {
        move |p: &mut Policy| {
            p.services
                .get_mut(&service_name(s))
                .expect("a service")
                .description =
                "Read-only SQL against the orders replica, now with a 30 s timeout.".into();
        }
    };
    let elsewhere = (0..t.services)
        .find(|s| !base.services[&service_name(*s)].hosts.contains(&host))
        .expect("a service elsewhere");
    let unchanged = update_frame(&slice, &edit(&describe(elsewhere)), host);
    let changed = update_frame(&slice, &edit(&describe(0)), host);
    let banned = update_frame(
        &slice,
        &edit(&|p: &mut Policy| {
            p.bans.insert(
                node(3_000_000),
                Ban {
                    until: ISSUED + 30 * 86_400,
                },
            );
        }),
        host,
    );

    serde_json::json!({
        "tier": t.name,
        "items": head.head.item_count,
        "head": len(head),
        "fresh": len(&fresh),
        "fresh_beat_frame": SubFrame::Fresh { fresh: fresh.clone() }.encode().expect("a frame").len(),
        "service_item": len(service),
        "slice_items": slice.items.len(),
        "slice_proof": len(&slice.proof),
        "slice_proof_hashes": slice.proof.hashes.hashes().len(),
        "slice": len(&slice),
        "slice_frame": SubFrame::Slice { slice, fresh: fresh.clone() }.encode().expect("a frame").len(),
        "view_entries": view.entries.len(),
        "view_proof": len(&view.proof),
        "view": len(&view),
        "update_unchanged": unchanged.0,
        "update_changed_service": changed.0,
        "update_changed_service_items": changed.1,
        "update_new_ban": banned.0,
        "update_new_ban_items": banned.1,
        "publish": len(&signed),
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

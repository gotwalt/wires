//! Measures what the directory's policy parts cost on the wire (card 36), to
//! check `bench/state-scale/model.py`'s *apex* assumptions (`entry_sig`, the
//! per-entry overhead, and `timestamp`, the freshness beat).
//!
//! Builds real signed policies with the library at the model's tiers, and
//! prints one JSON line per tier: the serialized head, `Fresh`, a service
//! item alone and with its proof, a ban with its proof, a host's whole slice,
//! a 30-service view, and the frames that carry them.
//!
//! ```text
//! cargo run -q --release -p library --example policy_sizes
//! ```

use library::{
    Audience, Ban, DirectoryAnswer, Fresh, Issuer, IssuerConfig, Item, Matcher, NodeId,
    NodeIdentity, Policy, Principal, ProvedItem, RoleName, Service, ServiceName, SignedPolicy,
    StateVersion, SubFrame,
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

fn policy(root: &NodeIdentity, t: &Tier) -> SignedPolicy {
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
    p.sign(root).expect("a valid policy")
}

fn measure(root: &NodeIdentity, t: &Tier) -> serde_json::Value {
    let signed = policy(root, t);
    let head = &signed.head;
    let fresh = Fresh::sign(&directory(), head, ISSUED, ISSUED + 900).expect("a directory");
    let host = node(1_000_000);
    let slice = signed.slice_for_host(host, &[]).expect("a slice");
    let proved = |pick: fn(&Item) -> bool| -> ProvedItem {
        slice
            .items
            .iter()
            .find(|p| pick(&p.item))
            .expect("the slice holds one")
            .clone()
    };
    let service = proved(|i| matches!(i, Item::Service { .. }));
    let ban = proved(|i| matches!(i, Item::Ban { .. }));

    // A caller in 15 roles: about 30 services' allow lists admit it.
    let caller = Principal {
        issuer: ISS.into(),
        subject: "00u1a2b3c4".into(),
        email: Some("alice@acme-corp.com".into()),
        org: None,
        groups: (0..15).map(|r| format!("eng-team-{:04}", r * 2)).collect(),
        not_after: i64::MAX,
    };
    let mut view = signed.view_for(Some(&caller)).expect("a view");
    view.entries.truncate(30);

    serde_json::json!({
        "tier": t.name,
        "items": head.head.item_count,
        "proof_depth": service.proof.path.hashes().len(),
        "head": len(head),
        "fresh": len(&fresh),
        "fresh_beat_frame": SubFrame::Fresh { fresh: fresh.clone() }.encode().expect("a frame").len(),
        "service_item": len(&service.item),
        "service_proved": len(&service),
        "ban_proved": len(&ban),
        "proof_overhead": len(&service) - len(&service.item),
        "slice_items": slice.items.len(),
        "slice": len(&slice),
        "view_entries": view.entries.len(),
        "view": len(&view),
        "slice_answer": DirectoryAnswer::Slice { slice, fresh: fresh.clone() }
            .encode().expect("a frame").len(),
        "current_answer": DirectoryAnswer::Current { fresh }.encode().expect("a frame").len(),
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

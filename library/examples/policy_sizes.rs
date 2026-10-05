//! Measures what the directory's frames cost on the wire (card 36d), for
//! `bench/state-scale/model.py`'s *apex* assumptions: the whole policy (what
//! a host receives on every edit, card 45), the freshness beat, and a
//! caller's view.
//!
//! Builds real signed policies with the library at the model's tiers, and
//! prints one JSON line per tier: the head, a `Fresh` and its beat frame, a
//! signed service entry, the whole policy (as published and as the frame a
//! host receives), and a caller's view of about 25 services (entry
//! count, frame and `view.json`), a `HelloAck` carrying news (card 37: the
//! head and one service entry), and the network string every node joins
//! with.
//!
//! ```text
//! cargo run -q --release -p library --example policy_sizes
//! ```

use library::{
    Audience, DirectoryAnswer, Fresh, HelloAck, Issuer, IssuerConfig, Item, LoginSettings, Matcher,
    Network, NodeId, NodeIdentity, Policy, Principal, PublicClientSecret, RoleName, Service,
    ServiceName, SignedPolicy, StateVersion, SubFrame,
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

/// A tier of the model: `services` (2 hosts each, 3 allow roles, an
/// 80-character description), `hosts`, `services / 5` roles
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
            allow: vec![
                role(s % roles),
                role((s + 1) % roles),
                role((s + 2) % roles),
            ],
            hosts: (0..2)
                .map(|k| node(1_000_000 + (s + k) % t.hosts))
                .collect(),
        };
        p.services.insert(service_name(s), service);
    }
    for b in 0..t.bans {
        p.bans.insert(node(2_000_000 + b));
    }
    p
}

fn fresh(head: &SignedPolicy) -> Fresh {
    Fresh::sign(&directory(), &head.head, ISSUED, ISSUED + 900).expect("a directory")
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

    // A caller in 2 roles: each role is in about 15 services' `allow`, so
    // about 25 services admit it (the model assumes 30 `visible_services`).
    let caller = Principal {
        issuer: ISS.into(),
        subject: "00u1a2b3c4".into(),
        email: Some("alice@acme-corp.com".into()),
        org: None,
        groups: (0..2).map(|r| format!("eng-team-{:04}", r * 2)).collect(),
        not_after: i64::MAX,
    };
    let view = signed.view_for(node(5_000_000), Some(&caller), None);

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
        "view_entries": view.entries.len(),
        "view_json": len(&serde_json::json!({
            "view": &view, "fresh": &fresh, "checked": ISSUED, "seen": 0,
        })),
        "view_frame": DirectoryAnswer::View { view, fresh: fresh.clone() }.encode().expect("a frame").len(),
        "hello_ack_news": len(&HelloAck {
            state_version: signed.version(),
            head: Some(signed.head.clone()),
            entry: signed.entries().next().cloned(),
        }),
        "network_string": network_string(root, &signed).len(),
    })
}

/// The network string: the root, the policy's first directory ids and
/// Google-sized login settings with a public client secret.
fn network_string(root: &NodeIdentity, signed: &SignedPolicy) -> String {
    let login = LoginSettings {
        issuer: Issuer::new(library::GOOGLE_ISSUER),
        client_id: Audience::new(concat!(
            "123456789012-",
            "abcdefghijklmnopqrstuvwxyz012345",
            ".apps.googleusercontent.com"
        )),
        public_client_secret: Some(PublicClientSecret::new(concat!(
            "GOCSPX",
            "-abcdefghijklmnopqrstuvwxyz01"
        ))),
    };
    Network::new(root.node_id(), signed.head.head.directories.clone(), login)
        .encode()
        .expect("a token")
}

fn main() {
    let root = NodeIdentity::from_seed([9; 32]);
    // The model's tiers ((users, services, hosts): company, enterprise,
    // large), with 30 days of removals as open bans (node churn 0.001 per
    // node per day, half of it removals, two nodes per user); bans no
    // longer expire, so this is a month's worth of open ones.
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

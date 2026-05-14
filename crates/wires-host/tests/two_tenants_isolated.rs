//! Two tenants register, each registers a distinct topic, each publishes
//! through the router. On-disk per-tenant directories are populated and
//! do not cross-contaminate.

use std::sync::Arc;

use tempfile::TempDir;
use wires_core::{MessageKind, WireMessage};
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::retention::Retention;
use wires_host::routing::{Router, WriteRateLimiter};
use wires_host::tenant_registry::{TenantRecord, TenantRegistry, TenantStatus};

fn mk_msg(topic: [u8; 32], sender: u8, seq: u64) -> WireMessage {
    WireMessage {
        topic_id: topic,
        epoch: 0,
        kind: MessageKind::Standard,
        sender: [sender; 32],
        cap_id: [0u8; 16],
        seq,
        prev_hash: [0u8; 32],
        timestamp: seq as i64,
        payload_len: 1,
        signature: [0u8; 64],
        ciphertext: vec![sender, seq as u8],
    }
}

#[test]
fn two_tenants_isolated() {
    let tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(tmp.path()));
    let retention = Arc::new(Retention::new(tmp.path(), Arc::clone(&logs)));
    let rate = Arc::new(WriteRateLimiter::new(1_000_000));
    let router = Router::new(
        Arc::clone(&registry),
        Arc::clone(&logs),
        Arc::clone(&retention),
        rate,
    );

    let root_a = [0xAAu8; 32];
    let root_b = [0xBBu8; 32];
    let topic_a = [0x11u8; 32];
    let topic_b = [0x22u8; 32];
    for (r, t) in [(root_a, topic_a), (root_b, topic_b)] {
        registry
            .insert_if_absent(
                &r,
                TenantRecord {
                    registered_at: 0,
                    status: TenantStatus::Active,
                    retention_budget_bytes: u64::MAX,
                },
            )
            .unwrap();
        registry.register_topic(&r, &t).unwrap();
    }

    router.route(&mk_msg(topic_a, 7, 0)).unwrap();
    router.route(&mk_msg(topic_b, 8, 0)).unwrap();

    let dir_a = tmp.path().join("tenants").join(hex::encode(root_a));
    let dir_b = tmp.path().join("tenants").join(hex::encode(root_b));
    assert!(
        dir_a
            .join(format!("log_{}.redb", hex::encode(topic_a)))
            .exists()
    );
    assert!(
        dir_b
            .join(format!("log_{}.redb", hex::encode(topic_b)))
            .exists()
    );
    assert!(
        !dir_a
            .join(format!("log_{}.redb", hex::encode(topic_b)))
            .exists()
    );
    assert!(
        !dir_b
            .join(format!("log_{}.redb", hex::encode(topic_a)))
            .exists()
    );
}

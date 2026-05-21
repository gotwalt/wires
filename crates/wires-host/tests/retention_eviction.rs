//! Publishing enough bytes for a fabric to exceed its retention budget causes
//! the oldest messages to be evicted; the underlying log reads return only
//! the surviving suffix.

use std::sync::Arc;

use tempfile::TempDir;
use wires_core::{MessageKind, WireMessage};
use wires_host::fabric_registry::{FabricRecord, FabricRegistry, FabricStatus};
use wires_host::per_fabric_logs::PerFabricLogs;
use wires_host::retention::Retention;
use wires_host::routing::{Router, WriteRateLimiter};

fn mk_msg(topic: [u8; 32], sender: u8, seq: u64, payload_size: usize) -> WireMessage {
    WireMessage {
        topic_id: topic,
        epoch: 0,
        kind: MessageKind::Standard,
        sender: [sender; 32],
        cap_id: [0u8; 16],
        seq,
        prev_hash: [0u8; 32],
        timestamp: seq as i64,
        payload_len: payload_size as u32,
        signature: [0u8; 64],
        ciphertext: vec![0u8; payload_size],
    }
}

#[test]
fn retention_eviction_drops_oldest_first() {
    let tmp = TempDir::new().unwrap();
    let registry = Arc::new(FabricRegistry::open(tmp.path()).unwrap());
    let logs = Arc::new(PerFabricLogs::new(tmp.path()));
    let retention = Arc::new(Retention::new(tmp.path(), Arc::clone(&logs)));
    let rate = Arc::new(WriteRateLimiter::new(1_000_000));

    let root = [9u8; 32];
    let topic = [5u8; 32];
    // Budget: ~3 messages worth.
    let probe = mk_msg(topic, 7, 0, 1024);
    let probe_bytes = serde_json::to_vec(&probe).unwrap().len() as u64;
    let budget = probe_bytes * 3;
    registry
        .insert_if_absent(
            &root,
            FabricRecord {
                registered_at: 0,
                status: FabricStatus::Active,
                retention_budget_bytes: budget,
            },
        )
        .unwrap();
    registry.register_topic(&root, &topic).unwrap();
    let router = Router::new(registry, Arc::clone(&logs), Arc::clone(&retention), rate);

    for seq in 0..6 {
        router.route(&mk_msg(topic, 7, seq, 1024)).unwrap();
    }

    // After 6 writes with budget = 3, retention bytes ≤ budget.
    assert!(retention.bytes_stored(&[9u8; 32]).unwrap() <= budget);
    let log = logs.get_or_open(&root, &topic).unwrap();
    let got = log.read_after(&[7u8; 32], None, 100).unwrap();
    assert!(
        got.len() <= 3,
        "expected at most 3 messages surviving, got {}",
        got.len()
    );
    // The surviving messages should be the most recent ones.
    let highest_seq = got.iter().map(|m| m.seq).max().unwrap();
    assert_eq!(highest_seq, 5);
}

//! Acceptance test for spec §11 scenario #2: `wires-host` restart with data dir
//! intact preserves tenants, topic registrations, and retained messages.

use std::sync::Arc;

use tempfile::TempDir;
use wires_core::{MessageKind, WireMessage};
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::retention::Retention;
use wires_host::routing::{Router, WriteRateLimiter};
use wires_host::tenant_registry::{TenantRecord, TenantRegistry, TenantStatus, TopicRegisterOutcome};

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

fn mk_msg_sized(topic: [u8; 32], sender: u8, seq: u64, payload_size: usize) -> WireMessage {
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
fn restart_preserves_tenants_topics_and_messages() {
    // ========== FIRST SESSION: Register and route ==========
    let tmp = TempDir::new().unwrap();
    let tmp_path = tmp.path().to_path_buf();

    {
        let registry = Arc::new(TenantRegistry::open(tmp_path.as_path()).unwrap());
        let logs = Arc::new(PerTenantLogs::new(tmp_path.as_path()));
        let retention = Arc::new(Retention::new(tmp_path.as_path(), Arc::clone(&logs)));
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

        // Register two tenants with one topic each.
        for (r, t) in [(root_a, topic_a), (root_b, topic_b)] {
            let rec = TenantRecord {
                registered_at: 1000,
                status: TenantStatus::Active,
                retention_budget_bytes: u64::MAX,
            };
            registry.insert_if_absent(&r, rec).unwrap();
            registry.register_topic(&r, &t).unwrap();
        }

        // Route one message to each tenant.
        router.route(&mk_msg(topic_a, 7, 0)).unwrap();
        router.route(&mk_msg(topic_b, 8, 0)).unwrap();

        // Verify in-memory state is correct.
        assert_eq!(registry.get(&root_a).unwrap().unwrap().registered_at, 1000);
        assert_eq!(registry.get(&root_b).unwrap().unwrap().registered_at, 1000);
        assert_eq!(
            registry.lookup_topic_tenant(&topic_a).unwrap(),
            Some(root_a)
        );
        assert_eq!(
            registry.lookup_topic_tenant(&topic_b).unwrap(),
            Some(root_b)
        );
        assert_eq!(registry.topic_count_for(&root_a).unwrap(), 1);
        assert_eq!(registry.topic_count_for(&root_b).unwrap(), 1);

        // Verify messages were routed.
        let log_a = logs.get_or_open(&root_a, &topic_a).unwrap();
        let log_b = logs.get_or_open(&root_b, &topic_b).unwrap();
        let msgs_a = log_a.read_after(&[7u8; 32], None, 10).unwrap();
        let msgs_b = log_b.read_after(&[8u8; 32], None, 10).unwrap();
        assert_eq!(msgs_a.len(), 1, "expected 1 message in tenant A's log");
        assert_eq!(msgs_b.len(), 1, "expected 1 message in tenant B's log");
        assert_eq!(msgs_a[0].seq, 0);
        assert_eq!(msgs_b[0].seq, 0);
    } // Drop handles; simulate host process stop.

    // ========== SECOND SESSION: Restart and verify persistence ==========
    {
        let registry = Arc::new(TenantRegistry::open(tmp_path.as_path()).unwrap());
        let logs = Arc::new(PerTenantLogs::new(tmp_path.as_path()));
        let retention = Arc::new(Retention::new(tmp_path.as_path(), Arc::clone(&logs)));
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

        // Verify tenants survived restart.
        let rec_a = registry.get(&root_a).unwrap();
        let rec_b = registry.get(&root_b).unwrap();
        assert!(rec_a.is_some(), "tenant A not found after restart");
        assert!(rec_b.is_some(), "tenant B not found after restart");
        assert_eq!(rec_a.unwrap().registered_at, 1000);
        assert_eq!(rec_b.unwrap().registered_at, 1000);

        // Verify topic registrations survived.
        assert_eq!(
            registry.lookup_topic_tenant(&topic_a).unwrap(),
            Some(root_a),
            "topic A not found for tenant A after restart"
        );
        assert_eq!(
            registry.lookup_topic_tenant(&topic_b).unwrap(),
            Some(root_b),
            "topic B not found for tenant B after restart"
        );

        // Verify topic counts survived.
        assert_eq!(
            registry.topic_count_for(&root_a).unwrap(),
            1,
            "tenant A should have 1 topic after restart"
        );
        assert_eq!(
            registry.topic_count_for(&root_b).unwrap(),
            1,
            "tenant B should have 1 topic after restart"
        );

        // Verify persisted messages are present.
        let log_a = logs.get_or_open(&root_a, &topic_a).unwrap();
        let log_b = logs.get_or_open(&root_b, &topic_b).unwrap();
        let msgs_a = log_a.read_after(&[7u8; 32], None, 10).unwrap();
        let msgs_b = log_b.read_after(&[8u8; 32], None, 10).unwrap();
        assert_eq!(
            msgs_a.len(),
            1,
            "expected 1 message in tenant A's log after restart"
        );
        assert_eq!(
            msgs_b.len(),
            1,
            "expected 1 message in tenant B's log after restart"
        );
        assert_eq!(msgs_a[0].seq, 0);
        assert_eq!(msgs_b[0].seq, 0);
        assert_eq!(&msgs_a[0].sender, &[7u8; 32]);
        assert_eq!(&msgs_b[0].sender, &[8u8; 32]);

        // Test idempotent re-registration of tenant: insert_if_absent should
        // return the original record if called again.
        let new_rec = TenantRecord {
            registered_at: 2000, // Different timestamp.
            status: TenantStatus::Suspended,
            retention_budget_bytes: 1000,
        };
        let returned = registry.insert_if_absent(&root_a, new_rec).unwrap();
        assert_eq!(
            returned.registered_at, 1000,
            "insert_if_absent should return original record, not new one"
        );
        assert_eq!(
            returned.status,
            TenantStatus::Active,
            "original tenant status should be preserved"
        );

        // Test idempotent re-registration of topic: register_topic called
        // again should return AlreadyOwned.
        let outcome = registry.register_topic(&root_a, &topic_a).unwrap();
        match outcome {
            TopicRegisterOutcome::AlreadyOwned => {
                // Expected.
            }
            _ => panic!("re-registering same topic should return AlreadyOwned, got {:?}", outcome),
        }

        // Route an additional message post-restart to verify router still works.
        router.route(&mk_msg(topic_a, 7, 1)).unwrap();
        let msgs_a_after = log_a.read_after(&[7u8; 32], None, 10).unwrap();
        assert_eq!(
            msgs_a_after.len(),
            2,
            "expected 2 messages after routing post-restart"
        );
        assert_eq!(msgs_a_after[1].seq, 1);
    }
}

#[test]
fn retention_persists_across_restart() {
    let tmp = TempDir::new().unwrap();
    let tmp_path = tmp.path().to_path_buf();

    // ========== FIRST SESSION: Exceed budget and trigger eviction ==========
    {
        let registry = Arc::new(TenantRegistry::open(tmp_path.as_path()).unwrap());
        let logs = Arc::new(PerTenantLogs::new(tmp_path.as_path()));
        let retention = Arc::new(Retention::new(tmp_path.as_path(), Arc::clone(&logs)));
        let rate = Arc::new(WriteRateLimiter::new(1_000_000));

        let root = [9u8; 32];
        let topic = [5u8; 32];

        // Determine budget: 3 messages worth.
        let probe = mk_msg_sized(topic, 7, 0, 1024);
        let probe_bytes = serde_json::to_vec(&probe).unwrap().len() as u64;
        let budget = probe_bytes * 3;

        registry
            .insert_if_absent(
                &root,
                TenantRecord {
                    registered_at: 0,
                    status: TenantStatus::Active,
                    retention_budget_bytes: budget,
                },
            )
            .unwrap();
        registry.register_topic(&root, &topic).unwrap();

        let router = Router::new(
            Arc::clone(&registry),
            Arc::clone(&logs),
            Arc::clone(&retention),
            rate,
        );

        // Route 6 messages (budget only holds ~3), triggering eviction.
        for seq in 0..6 {
            router.route(&mk_msg_sized(topic, 7, seq, 1024)).unwrap();
        }

        // Verify eviction happened: bytes ≤ budget.
        let bytes_stored = retention.bytes_stored(&root).unwrap();
        assert!(
            bytes_stored <= budget,
            "eviction should have triggered; stored {} > budget {}",
            bytes_stored,
            budget
        );

        // Verify only the latest messages remain (oldest were evicted).
        let log = logs.get_or_open(&root, &topic).unwrap();
        let msgs = log.read_after(&[7u8; 32], None, 100).unwrap();
        assert!(
            msgs.len() <= 3,
            "expected at most 3 messages surviving after eviction, got {}",
            msgs.len()
        );
        let highest_seq = msgs.iter().map(|m| m.seq).max().unwrap_or(0);
        assert_eq!(
            highest_seq, 5,
            "highest remaining seq should be 5 (most recent message)"
        );
    } // Drop handles; simulate host process stop.

    // ========== SECOND SESSION: Restart and verify eviction state persisted ==========
    {
        let registry = Arc::new(TenantRegistry::open(tmp_path.as_path()).unwrap());
        let logs = Arc::new(PerTenantLogs::new(tmp_path.as_path()));
        let retention = Arc::new(Retention::new(tmp_path.as_path(), Arc::clone(&logs)));
        let rate = Arc::new(WriteRateLimiter::new(1_000_000));
        let router = Router::new(
            Arc::clone(&registry),
            Arc::clone(&logs),
            Arc::clone(&retention),
            rate,
        );

        let root = [9u8; 32];
        let topic = [5u8; 32];

        // Re-fetch the original budget from the registry.
        let rec = registry.get(&root).unwrap().unwrap();
        let budget = rec.retention_budget_bytes;

        // Verify evicted messages do NOT reappear.
        let log = logs.get_or_open(&root, &topic).unwrap();
        let msgs_after_restart = log.read_after(&[7u8; 32], None, 100).unwrap();
        assert!(
            msgs_after_restart.len() <= 3,
            "previously evicted messages should not reappear; got {} messages",
            msgs_after_restart.len()
        );
        // The highest seq should still be 5 (no magical resurrection).
        let highest_after = msgs_after_restart
            .iter()
            .map(|m| m.seq)
            .max()
            .unwrap_or(0);
        assert_eq!(
            highest_after, 5,
            "highest seq after restart should still be 5"
        );

        // Route new messages post-restart.
        for seq in 6..10 {
            router.route(&mk_msg_sized(topic, 7, seq, 1024)).unwrap();
        }

        // Verify new messages are subject to the same budget: bytes ≤ budget.
        let bytes_after = retention.bytes_stored(&root).unwrap();
        assert!(
            bytes_after <= budget,
            "new messages should be subject to same budget; stored {} > budget {}",
            bytes_after,
            budget
        );

        // Verify that old survivors may have been evicted to make room for new ones.
        let final_msgs = log.read_after(&[7u8; 32], None, 100).unwrap();
        let highest_final = final_msgs.iter().map(|m| m.seq).max().unwrap_or(0);
        assert!(
            highest_final >= 6,
            "at least one post-restart message should be present"
        );
        assert!(
            final_msgs.len() <= 3,
            "budget constraint should still hold after new ingests"
        );
    }
}

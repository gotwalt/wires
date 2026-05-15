//! Acceptance tests for v1 criteria from the spec (§7).
//!
//! Run: `cargo test -p wires-node --test acceptance -- --ignored --nocapture`
//!
//! Each test simulates the relevant scenario at the Node API level, without
//! standing up real iroh networking. Real-network smoke testing is a manual
//! CLI exercise.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_core::cap::Right;
use wires_core::{CanonicalContent, Capability};
use wires_node::{Inbound, InboundCtx, Node, NodeConfig, drive_sync_pass};

fn open_node(tmp: TempDir, root_hex: &str) -> (TempDir, Arc<Node>) {
    let cfg = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        root_pubkey_hex: root_hex.to_string(),
        bootstrap_peers: vec![],
    };
    let n = Arc::new(Node::open(cfg).unwrap());
    (tmp, n)
}

fn mint_cap(
    root: &SigningKey,
    agent_pk: [u8; 32],
    topics: Vec<String>,
    rights: Vec<Right>,
) -> Capability {
    let mut cap = Capability::new_unsigned(agent_pk, topics, rights, 0, None);
    cap.sign(root).unwrap();
    cap
}

/// Criterion 1: Two agents on the same root publish/subscribe and see each
/// other's messages.
#[test]
#[ignore]
fn criterion_1_two_nodes_publish_subscribe() {
    let root = SigningKey::generate(&mut OsRng);
    let root_hex = hex::encode(root.verifying_key().to_bytes());
    let (_a_dir, a) = open_node(TempDir::new().unwrap(), &root_hex);
    let (_b_dir, b) = open_node(TempDir::new().unwrap(), &root_hex);

    let a_pk = a.ed_sk.verifying_key().to_bytes();
    let b_pk = b.ed_sk.verifying_key().to_bytes();
    let cap_a = mint_cap(
        &root,
        a_pk,
        vec!["home.test".into()],
        vec![Right::Read, Right::Write],
    );
    let cap_b = mint_cap(
        &root,
        b_pk,
        vec!["home.test".into()],
        vec![Right::Read, Right::Write],
    );
    a.caps.upsert_grant(&cap_a).unwrap();
    a.caps.upsert_grant(&cap_b).unwrap();
    b.caps.upsert_grant(&cap_a).unwrap();
    b.caps.upsert_grant(&cap_b).unwrap();

    let topic = [42u8; 32];
    let key = [7u8; 32];
    a.install_epoch_key(topic, 0, key).unwrap();
    b.install_epoch_key(topic, 0, key).unwrap();

    let m_a = a
        .publish_standard(
            topic,
            cap_a.cap_id.0,
            CanonicalContent::new("home.test", "hello from A"),
        )
        .unwrap();
    let m_b = b
        .publish_standard(
            topic,
            cap_b.cap_id.0,
            CanonicalContent::new("home.test", "hello from B"),
        )
        .unwrap();
    b.handle_inbound(m_a.clone()).unwrap();
    a.handle_inbound(m_b.clone()).unwrap();

    let log_a = a.logs.get_or_open(&topic).unwrap();
    let log_b = b.logs.get_or_open(&topic).unwrap();
    assert_eq!(log_a.read_all().unwrap().len(), 2);
    assert_eq!(log_b.read_all().unwrap().len(), 2);
}

/// Criterion 2: Offline-then-replay. A publishes 5; B has only 1; B re-syncs
/// and ends up with all 5.
#[test]
#[ignore]
fn criterion_2_replay_after_outage() {
    let root = SigningKey::generate(&mut OsRng);
    let root_hex = hex::encode(root.verifying_key().to_bytes());
    let (_a_dir, a) = open_node(TempDir::new().unwrap(), &root_hex);
    let (_b_dir, b) = open_node(TempDir::new().unwrap(), &root_hex);

    let a_pk = a.ed_sk.verifying_key().to_bytes();
    let cap = mint_cap(
        &root,
        a_pk,
        vec!["home.test".into()],
        vec![Right::Read, Right::Write],
    );
    a.caps.upsert_grant(&cap).unwrap();
    b.caps.upsert_grant(&cap).unwrap();

    let topic = [42u8; 32];
    let key = [7u8; 32];
    a.install_epoch_key(topic, 0, key).unwrap();
    b.install_epoch_key(topic, 0, key).unwrap();

    let m0 = a
        .publish_standard(topic, cap.cap_id.0, CanonicalContent::new("home.test", "1"))
        .unwrap();
    let _m1 = a
        .publish_standard(topic, cap.cap_id.0, CanonicalContent::new("home.test", "2"))
        .unwrap();
    let _m2 = a
        .publish_standard(topic, cap.cap_id.0, CanonicalContent::new("home.test", "3"))
        .unwrap();
    let _m3 = a
        .publish_standard(topic, cap.cap_id.0, CanonicalContent::new("home.test", "4"))
        .unwrap();
    let _m4 = a
        .publish_standard(topic, cap.cap_id.0, CanonicalContent::new("home.test", "5"))
        .unwrap();

    // B only sees the first message
    b.handle_inbound(m0).unwrap();

    // B re-syncs against A's logs (proxy for real replay RPC)
    let log_b = b.logs.get_or_open(&topic).unwrap();
    let keys_b = b.epoch_keys_for(&topic).unwrap();
    let ctx = InboundCtx {
        topic_log: &log_b,
        epoch_keys: &keys_b,
        cap_table: &b.caps,
        self_x25519_sk: &b.x_sk,
        self_x25519_pk: &b.x_pk,
    };
    drive_sync_pass(&ctx, &*a.logs, &topic).unwrap();

    let got = log_b.read_all().unwrap();
    assert_eq!(got.len(), 5);
    for (i, msg) in got.iter().enumerate() {
        assert_eq!(msg.seq, i as u64);
    }
}

/// Criterion 4: Revocation. Sender's prior messages still verify, but post-revoke
/// messages are refused at the receiver.
#[test]
#[ignore]
fn criterion_4_revocation_takes_effect() {
    let root = SigningKey::generate(&mut OsRng);
    let root_hex = hex::encode(root.verifying_key().to_bytes());
    let (_a_dir, a) = open_node(TempDir::new().unwrap(), &root_hex);
    let (_b_dir, b) = open_node(TempDir::new().unwrap(), &root_hex);

    let a_pk = a.ed_sk.verifying_key().to_bytes();
    let cap = mint_cap(
        &root,
        a_pk,
        vec!["home.test".into()],
        vec![Right::Read, Right::Write],
    );
    let cap_id = cap.cap_id.0;
    a.caps.upsert_grant(&cap).unwrap();
    b.caps.upsert_grant(&cap).unwrap();
    let topic = [42u8; 32];
    a.install_epoch_key(topic, 0, [7u8; 32]).unwrap();
    b.install_epoch_key(topic, 0, [7u8; 32]).unwrap();

    let m_pre = a
        .publish_standard(topic, cap_id, CanonicalContent::new("home.test", "before"))
        .unwrap();
    b.handle_inbound(m_pre).unwrap();

    // Revoke on B side
    b.caps.mark_revoked(&cap_id, &[0u8; 32]).unwrap();

    let m_post = a
        .publish_standard(topic, cap_id, CanonicalContent::new("home.test", "after"))
        .unwrap();
    let result = b.handle_inbound(m_post).unwrap();
    match result {
        Inbound::Rejected { reason, .. } => {
            assert!(reason.contains("cap"), "unexpected reason: {reason}")
        }
        other => panic!("expected rejection after revocation, got {other:?}"),
    }

    // Prior message stays in B's log; post-revoke is absent
    let log_b = b.logs.get_or_open(&topic).unwrap();
    let got = log_b.read_all().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].seq, 0);
}

/// Criterion 6: `cat` produces human-readable output — i.e. the decrypted
/// content includes `type` and `text` fields readable on the wire.
#[test]
#[ignore]
fn criterion_6_cat_is_human_readable() {
    let root = SigningKey::generate(&mut OsRng);
    let root_hex = hex::encode(root.verifying_key().to_bytes());
    let (_a_dir, a) = open_node(TempDir::new().unwrap(), &root_hex);

    let a_pk = a.ed_sk.verifying_key().to_bytes();
    let cap = mint_cap(
        &root,
        a_pk,
        vec!["home.test".into()],
        vec![Right::Read, Right::Write],
    );
    a.caps.upsert_grant(&cap).unwrap();
    let topic = [42u8; 32];
    a.install_epoch_key(topic, 0, [7u8; 32]).unwrap();

    let msg = a
        .publish_standard(
            topic,
            cap.cap_id.0,
            CanonicalContent::new("home.fridge.temp", "fridge at 38F"),
        )
        .unwrap();
    let outcome = a.handle_inbound(msg.clone()).unwrap();
    match outcome {
        Inbound::Accepted {
            content: Some(c), ..
        } => {
            assert_eq!(c.type_, "home.fridge.temp");
            assert!(c.text.contains("fridge"));
            assert!(c.text.contains("38F"));
        }
        other => panic!("expected accepted-with-content, got {other:?}"),
    }
}

/// Criterion 3: New agent bootstrapped later receives full history when given
/// the same epoch key. (In production the key arrives via a `__topic.history_grant`
/// event; here we install it directly to simulate.)
#[test]
#[ignore]
fn criterion_3_history_on_join() {
    let root = SigningKey::generate(&mut OsRng);
    let root_hex = hex::encode(root.verifying_key().to_bytes());
    let (_a_dir, a) = open_node(TempDir::new().unwrap(), &root_hex);

    let a_pk = a.ed_sk.verifying_key().to_bytes();
    let cap_a = mint_cap(
        &root,
        a_pk,
        vec!["home.test".into()],
        vec![Right::Read, Right::Write],
    );
    a.caps.upsert_grant(&cap_a).unwrap();
    let topic = [42u8; 32];
    let key = [7u8; 32];
    a.install_epoch_key(topic, 0, key).unwrap();

    for i in 0..10 {
        a.publish_standard(
            topic,
            cap_a.cap_id.0,
            CanonicalContent::new("home.test", format!("msg-{i}")),
        )
        .unwrap();
    }

    // New agent C bootstraps later
    let (_c_dir, c) = open_node(TempDir::new().unwrap(), &root_hex);
    let c_pk = c.ed_sk.verifying_key().to_bytes();
    let cap_c = mint_cap(
        &root,
        c_pk,
        vec!["home.test".into()],
        vec![Right::Read, Right::Write],
    );
    a.caps.upsert_grant(&cap_c).unwrap();
    c.caps.upsert_grant(&cap_a).unwrap();
    c.caps.upsert_grant(&cap_c).unwrap();
    c.install_epoch_key(topic, 0, key).unwrap();

    let log_c = c.logs.get_or_open(&topic).unwrap();
    let keys_c = c.epoch_keys_for(&topic).unwrap();
    let ctx = InboundCtx {
        topic_log: &log_c,
        epoch_keys: &keys_c,
        cap_table: &c.caps,
        self_x25519_sk: &c.x_sk,
        self_x25519_pk: &c.x_pk,
    };
    drive_sync_pass(&ctx, &*a.logs, &topic).unwrap();

    let got = log_c.read_all().unwrap();
    assert_eq!(got.len(), 10);

    // Confirm decryption succeeded for at least one (verifying the history_grant simulation worked)
    let one = got.first().unwrap();
    let outcome = c.handle_inbound(one.clone()).unwrap();
    match outcome {
        Inbound::Accepted {
            content: Some(c), ..
        } => {
            assert_eq!(c.type_, "home.test");
        }
        other => panic!("expected decrypted accept on history replay, got {other:?}"),
    }
}

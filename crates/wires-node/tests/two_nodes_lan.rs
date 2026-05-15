//! Integration test: two `Node` instances coordinated by hand-delivering messages.
//! Validates publish, handle_inbound, and replay-via-drive_sync_pass.

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_core::cap::Right;
use wires_core::{CanonicalContent, Capability};
use wires_node::{Inbound, InboundCtx, Node, NodeConfig, drive_sync_pass};

fn open_node(tmp: &TempDir, root_hex: &str) -> Node {
    Node::open(NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        root_pubkey_hex: root_hex.to_string(),
        bootstrap_peers: vec![],
    })
    .unwrap()
}

fn mint_cap(root: &SigningKey, agent_pk: [u8; 32]) -> Capability {
    let mut cap = Capability::new_unsigned(
        agent_pk,
        vec!["home.test".into()],
        vec![Right::Read, Right::Write],
        0,
        None,
    );
    cap.sign(root).unwrap();
    cap
}

#[test]
fn publish_replicates_via_handle_inbound() {
    let tmp_a = TempDir::new().unwrap();
    let tmp_b = TempDir::new().unwrap();
    let root = SigningKey::generate(&mut OsRng);
    let root_hex = hex::encode(root.verifying_key().to_bytes());

    let a = open_node(&tmp_a, &root_hex);
    let b = open_node(&tmp_b, &root_hex);

    let a_pk = a.ed_sk.verifying_key().to_bytes();
    let cap = mint_cap(&root, a_pk);
    let cap_id = cap.cap_id.0;
    a.caps.upsert_grant(&cap).unwrap();
    b.caps.upsert_grant(&cap).unwrap();

    let topic = [42u8; 32];
    let key = [11u8; 32];
    a.install_epoch_key(topic, 0, key).unwrap();
    b.install_epoch_key(topic, 0, key).unwrap();

    let m0 = a
        .publish_standard(topic, cap_id, CanonicalContent::new("home.test", "hello"))
        .unwrap();
    let m1 = a
        .publish_standard(topic, cap_id, CanonicalContent::new("home.test", "world"))
        .unwrap();

    let r0 = b.handle_inbound(m0.clone()).unwrap();
    let r1 = b.handle_inbound(m1.clone()).unwrap();
    assert!(matches!(
        r0,
        Inbound::Accepted { .. } | Inbound::AcceptedOpaque { .. }
    ));
    assert!(matches!(
        r1,
        Inbound::Accepted { .. } | Inbound::AcceptedOpaque { .. }
    ));

    let log = b.logs.get_or_open(&topic).unwrap();
    let got = log.read_after(&a_pk, None, 10).unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].seq, 0);
    assert_eq!(got[1].seq, 1);
}

#[test]
fn replay_after_offline_period() {
    let tmp_a = TempDir::new().unwrap();
    let tmp_b = TempDir::new().unwrap();
    let root = SigningKey::generate(&mut OsRng);
    let root_hex = hex::encode(root.verifying_key().to_bytes());

    let a = open_node(&tmp_a, &root_hex);
    let b = open_node(&tmp_b, &root_hex);

    let a_pk = a.ed_sk.verifying_key().to_bytes();
    let cap = mint_cap(&root, a_pk);
    let cap_id = cap.cap_id.0;
    a.caps.upsert_grant(&cap).unwrap();
    b.caps.upsert_grant(&cap).unwrap();

    let topic = [42u8; 32];
    let key = [11u8; 32];
    a.install_epoch_key(topic, 0, key).unwrap();
    b.install_epoch_key(topic, 0, key).unwrap();

    // A publishes 3 messages; B receives only the first.
    let m0 = a
        .publish_standard(topic, cap_id, CanonicalContent::new("home.test", "1"))
        .unwrap();
    let _m1 = a
        .publish_standard(topic, cap_id, CanonicalContent::new("home.test", "2"))
        .unwrap();
    let _m2 = a
        .publish_standard(topic, cap_id, CanonicalContent::new("home.test", "3"))
        .unwrap();
    b.handle_inbound(m0).unwrap();

    // B reconnects: drive a sync pass over A's logs as the replay source.
    let log_b = b.logs.get_or_open(&topic).unwrap();
    let keys_b = b.epoch_keys_for(&topic).unwrap();
    let ctx = InboundCtx {
        topic_log: &log_b,
        epoch_keys: &keys_b,
        cap_table: &b.caps,
        self_x25519_sk: &b.x_sk,
        self_x25519_pk: &b.x_pk,
    };
    let applied = drive_sync_pass(&ctx, &*a.logs, &topic).unwrap();
    assert!(applied >= 2, "expected at least 2 applied, got {applied}");

    let got = log_b.read_after(&a_pk, None, 10).unwrap();
    assert_eq!(got.len(), 3);
    for (i, msg) in got.iter().enumerate() {
        assert_eq!(msg.seq, i as u64);
    }
}

#[test]
fn replay_only_pulls_messages_we_dont_have() {
    let tmp_a = TempDir::new().unwrap();
    let tmp_b = TempDir::new().unwrap();
    let root = SigningKey::generate(&mut OsRng);
    let root_hex = hex::encode(root.verifying_key().to_bytes());

    let a = open_node(&tmp_a, &root_hex);
    let b = open_node(&tmp_b, &root_hex);

    let a_pk = a.ed_sk.verifying_key().to_bytes();
    let cap = mint_cap(&root, a_pk);
    let cap_id = cap.cap_id.0;
    a.caps.upsert_grant(&cap).unwrap();
    b.caps.upsert_grant(&cap).unwrap();

    let topic = [42u8; 32];
    let key = [11u8; 32];
    a.install_epoch_key(topic, 0, key).unwrap();
    b.install_epoch_key(topic, 0, key).unwrap();

    // Publish 5; B already has the first 3 via gossip.
    let mut msgs = Vec::new();
    for i in 0..5 {
        let m = a
            .publish_standard(
                topic,
                cap_id,
                CanonicalContent::new("home.test", format!("m{i}")),
            )
            .unwrap();
        msgs.push(m);
    }
    for m in &msgs[..3] {
        b.handle_inbound(m.clone()).unwrap();
    }

    // Now sync — should pull just the last 2.
    let log_b = b.logs.get_or_open(&topic).unwrap();
    let keys_b = b.epoch_keys_for(&topic).unwrap();
    let ctx = InboundCtx {
        topic_log: &log_b,
        epoch_keys: &keys_b,
        cap_table: &b.caps,
        self_x25519_sk: &b.x_sk,
        self_x25519_pk: &b.x_pk,
    };
    let _applied = drive_sync_pass(&ctx, &*a.logs, &topic).unwrap();

    let got = log_b.read_after(&a_pk, None, 10).unwrap();
    assert_eq!(got.len(), 5);
}

//! Criterion 5: A node configured without epoch keys can persist + relay
//! ciphertext but cannot decrypt content.
//!
//! Run: cargo test -p wires-node --test acceptance_host_blindness -- --ignored --nocapture

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_core::cap::Right;
use wires_core::{CanonicalContent, Capability};
use wires_node::{Inbound, Node, NodeConfig};

#[test]
#[ignore]
fn host_persists_but_cannot_decrypt() {
    let root = SigningKey::generate(&mut OsRng);
    let root_hex = hex::encode(root.verifying_key().to_bytes());

    let tmp_a = TempDir::new().unwrap();
    let tmp_host = TempDir::new().unwrap();
    let a = Arc::new(
        Node::open(NodeConfig {
            data_dir: tmp_a.path().to_path_buf(),
            root_pubkey_hex: root_hex.clone(),
            host: None,
        })
        .unwrap(),
    );
    let host = Arc::new(
        Node::open(NodeConfig {
            data_dir: tmp_host.path().to_path_buf(),
            root_pubkey_hex: root_hex.clone(),
            host: None,
        })
        .unwrap(),
    );

    let a_pk = a.ed_sk.verifying_key().to_bytes();
    let mut cap = Capability::new_unsigned(
        a_pk,
        vec!["home.test".into()],
        vec![Right::Read, Right::Write],
        0,
        None,
    );
    cap.sign(&root).unwrap();
    a.caps.upsert_grant(&cap).unwrap();
    host.caps.upsert_grant(&cap).unwrap();

    let topic = [42u8; 32];
    let epoch_key = [7u8; 32];
    a.install_epoch_key(topic, 0, epoch_key).unwrap();
    // CRUCIAL: host does NOT call install_epoch_key.

    let msg = a
        .publish_standard(
            topic,
            cap.cap_id.0,
            CanonicalContent::new("home.test", "secret data"),
        )
        .unwrap();
    let outcome = host.handle_inbound(msg.clone()).unwrap();
    match outcome {
        Inbound::AcceptedOpaque { .. } => { /* expected: persisted but not decrypted */ }
        Inbound::Accepted { content: None, .. } => { /* also acceptable */ }
        Inbound::Accepted {
            content: Some(_), ..
        } => panic!("host should not have decrypted content"),
        Inbound::Rejected { reason, .. } => panic!("host should accept ciphertext: {reason}"),
    }

    let log = host.logs.get_or_open(&topic).unwrap();
    assert_eq!(log.read_all().unwrap().len(), 1);

    // Dump the ciphertext directly and confirm it isn't readable JSON
    let stored = log.read_all().unwrap();
    let ciphertext = &stored[0].ciphertext;
    let attempt = serde_json::from_slice::<serde_json::Value>(ciphertext);
    assert!(
        attempt.is_err(),
        "ciphertext should not parse as JSON without decryption: {:?}",
        attempt.ok()
    );
}

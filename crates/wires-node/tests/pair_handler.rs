use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;
use tokio::sync::oneshot;
use wires_core::Capability;
use wires_core::cap::Right;
use wires_net::pair::{
    PairFrame, PairGrant, PairGrantEnvelope, PairHandler, PairRejectCode, TopicEpochKey,
    TopicNameEntry,
};
use wires_node::{Node, NodeConfig, NodePairHandler, PairOutcome};
use x25519_dalek::{PublicKey as XPub, StaticSecret as XSk};

struct Setup {
    handler: NodePairHandler,
    agent_pk: [u8; 32],
    ephemeral_pk: [u8; 32],
    outcome_rx: oneshot::Receiver<PairOutcome>,
}

fn fresh_setup(td: &TempDir, expected_nonce: [u8; 32]) -> Setup {
    let agent_sk = SigningKey::generate(&mut OsRng);
    let agent_pk = agent_sk.verifying_key().to_bytes();
    std::fs::write(td.path().join("identity.ed25519"), agent_sk.to_bytes()).unwrap();
    let xsk = XSk::random_from_rng(OsRng);
    std::fs::write(td.path().join("identity.x25519"), xsk.to_bytes()).unwrap();
    let cfg = NodeConfig {
        data_dir: td.path().to_path_buf(),
        root_pubkey_hex: String::new(),
        host: None,
    };
    std::fs::write(
        td.path().join("config.toml"),
        toml::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();
    let node = Arc::new(Node::open(cfg).unwrap());

    let ephemeral_sk = XSk::random_from_rng(OsRng);
    let ephemeral_pk = XPub::from(&ephemeral_sk).to_bytes();
    let (tx, rx) = oneshot::channel();
    let handler = NodePairHandler::new(
        td.path().to_path_buf(),
        node,
        agent_pk,
        expected_nonce,
        ephemeral_sk,
        i64::MAX,
        tx,
    );
    Setup {
        handler,
        agent_pk,
        ephemeral_pk,
        outcome_rx: rx,
    }
}

fn signed_cap(root_sk: &SigningKey, agent_pk: [u8; 32]) -> Capability {
    let mut cap = Capability::new_unsigned(
        agent_pk,
        vec!["home.notes".into()],
        vec![Right::Read, Right::Write],
        1_700_000_000_000,
        None,
    );
    cap.sign(root_sk).unwrap();
    cap
}

#[tokio::test]
async fn happy_path_returns_ack_and_signals_outcome() {
    let td = TempDir::new().unwrap();
    let nonce = [3u8; 32];
    let mut setup = fresh_setup(&td, nonce);
    let root_sk = SigningKey::generate(&mut OsRng);
    let topic_id = [44u8; 32];
    let grant = PairGrant {
        version: 1,
        root_pubkey: root_sk.verifying_key().to_bytes(),
        cap: signed_cap(&root_sk, setup.agent_pk),
        topic_keys: vec![TopicEpochKey {
            topic_id,
            epoch: 0,
            key: [8u8; 32],
        }],
        topic_names: vec![TopicNameEntry {
            topic_id,
            name: "home.notes".into(),
        }],
        host: None,
        nonce,
        issued_at: 1_700_000_000_000,
    };
    let env = PairGrantEnvelope::seal_and_sign(&grant, &setup.ephemeral_pk, &root_sk).unwrap();
    let frame = setup.handler.handle_grant(env).await;
    assert!(matches!(frame, PairFrame::Ack(_)));
    let outcome = setup.outcome_rx.try_recv().unwrap();
    assert!(matches!(outcome, PairOutcome::Paired { .. }));
}

#[tokio::test]
async fn wrong_recipient_yields_seal_undecryptable() {
    let td = TempDir::new().unwrap();
    let nonce = [3u8; 32];
    let setup = fresh_setup(&td, nonce);
    let root_sk = SigningKey::generate(&mut OsRng);
    let grant = PairGrant {
        version: 1,
        root_pubkey: root_sk.verifying_key().to_bytes(),
        cap: signed_cap(&root_sk, setup.agent_pk),
        topic_keys: vec![],
        topic_names: vec![],
        host: None,
        nonce,
        issued_at: 0,
    };
    // Seal to a different key (Mallory's) — Bob's ephemeral cannot open it.
    let mallory_pk = XPub::from(&XSk::random_from_rng(OsRng)).to_bytes();
    let env = PairGrantEnvelope::seal_and_sign(&grant, &mallory_pk, &root_sk).unwrap();
    let frame = setup.handler.handle_grant(env).await;
    match frame {
        PairFrame::Reject(r) => assert_eq!(r.code, PairRejectCode::SealUndecryptable),
        _ => panic!("expected Reject, got {frame:?}"),
    }
}

#[tokio::test]
async fn cap_for_wrong_agent_yields_cap_invalid() {
    let td = TempDir::new().unwrap();
    let nonce = [3u8; 32];
    let setup = fresh_setup(&td, nonce);
    let root_sk = SigningKey::generate(&mut OsRng);
    // Cap names a different agent, not setup.agent_pk.
    let grant = PairGrant {
        version: 1,
        root_pubkey: root_sk.verifying_key().to_bytes(),
        cap: signed_cap(&root_sk, [0xfe; 32]),
        topic_keys: vec![],
        topic_names: vec![],
        host: None,
        nonce,
        issued_at: 0,
    };
    let env = PairGrantEnvelope::seal_and_sign(&grant, &setup.ephemeral_pk, &root_sk).unwrap();
    let frame = setup.handler.handle_grant(env).await;
    match frame {
        PairFrame::Reject(r) => assert_eq!(r.code, PairRejectCode::CapInvalid),
        _ => panic!("expected Reject, got {frame:?}"),
    }
}

#[tokio::test]
async fn already_paired_after_first_success() {
    let td = TempDir::new().unwrap();
    let nonce = [3u8; 32];
    let setup = fresh_setup(&td, nonce);
    let root_sk = SigningKey::generate(&mut OsRng);
    let topic_id = [44u8; 32];
    let grant = PairGrant {
        version: 1,
        root_pubkey: root_sk.verifying_key().to_bytes(),
        cap: signed_cap(&root_sk, setup.agent_pk),
        topic_keys: vec![TopicEpochKey {
            topic_id,
            epoch: 0,
            key: [8u8; 32],
        }],
        topic_names: vec![TopicNameEntry {
            topic_id,
            name: "home.notes".into(),
        }],
        host: None,
        nonce,
        issued_at: 0,
    };
    let env = PairGrantEnvelope::seal_and_sign(&grant, &setup.ephemeral_pk, &root_sk).unwrap();
    let first = setup.handler.handle_grant(env.clone()).await;
    assert!(matches!(first, PairFrame::Ack(_)));
    let second = setup.handler.handle_grant(env).await;
    match second {
        PairFrame::Reject(r) => assert_eq!(r.code, PairRejectCode::AlreadyPaired),
        _ => panic!("expected AlreadyPaired, got {second:?}"),
    }
}

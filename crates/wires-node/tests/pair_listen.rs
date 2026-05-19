use std::sync::Arc;

use ed25519_dalek::SigningKey;
use iroh::endpoint::presets;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_core::Capability;
use wires_core::cap::Right;
use wires_net::pair::{
    PairClient, PairGrant, PairGrantEnvelope, PairManifest, PairRequest, RequestedScope,
    TopicEpochKey, TopicNameEntry,
};
use wires_node::{Node, NodeConfig, PairListenArgs, PairOutcome, pair_listen};
use x25519_dalek::{PublicKey as XPub, StaticSecret as XSk};

#[tokio::test]
async fn full_lifecycle_alice_dial_bob_install() {
    // Bob's side: init data dir, open Node, start pair_listen.
    let td = TempDir::new().unwrap();
    let agent_sk = SigningKey::generate(&mut OsRng);
    std::fs::write(td.path().join("identity.ed25519"), agent_sk.to_bytes()).unwrap();
    let xsk = XSk::random_from_rng(OsRng);
    let agent_x25519 = XPub::from(&xsk).to_bytes();
    std::fs::write(td.path().join("identity.x25519"), xsk.to_bytes()).unwrap();
    let cfg = NodeConfig {
        data_dir: td.path().to_path_buf(),
        root_pubkey_hex: String::new(),
        host: None,
        retention: None,
    };
    std::fs::write(
        td.path().join("config.toml"),
        toml::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();
    let node = Arc::new(Node::open(cfg).unwrap());

    let endpoint = iroh::Endpoint::builder(presets::N0).bind().await.unwrap();
    let bob_endpoint_id = endpoint.id();
    let started = pair_listen(
        td.path().to_path_buf(),
        node,
        agent_sk.clone(),
        agent_x25519,
        endpoint,
        PairListenArgs {
            manifest: PairManifest {
                role: "chat-agent".into(),
                description: "Bob".into(),
                requested_scopes: vec![RequestedScope {
                    topic_name: "home.notes".into(),
                    rights: vec![Right::Read, Right::Write],
                }],
            },
            ttl: std::time::Duration::from_secs(60),
        },
    )
    .await
    .unwrap();

    // The encoded token should decode and verify cleanly.
    let request = PairRequest::decode(&started.request_token).unwrap();
    request.verify().unwrap();

    // The dial's node_id should match the endpoint we started.
    assert_eq!(
        request.dial.node_id,
        hex::encode(bob_endpoint_id.as_bytes())
    );

    // pair_pending.json should exist on disk.
    assert!(td.path().join("pair_pending.json").exists());

    // Alice's side: forge a PairGrant, seal, sign, dial, await ack.
    let root_sk = SigningKey::generate(&mut OsRng);
    let mut cap = Capability::new_unsigned(
        request.agent_pubkey,
        vec!["home.notes".into()],
        vec![Right::Read, Right::Write],
        1_700_000_000_000,
        None,
    );
    cap.sign(&root_sk).unwrap();
    let topic_id = [44u8; 32];
    let grant = PairGrant {
        version: 1,
        root_pubkey: root_sk.verifying_key().to_bytes(),
        cap,
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
        nonce: request.nonce,
        issued_at: 1_700_000_000_000,
    };
    let env =
        PairGrantEnvelope::seal_and_sign(&grant, &request.ephemeral_x25519, &root_sk).unwrap();

    let alice_ep = iroh::Endpoint::builder(presets::N0).bind().await.unwrap();
    let client = PairClient::new(alice_ep);
    let cap_id_expected = grant.cap.cap_id.0;
    let ack = client.deliver_grant(&request.dial, env).await.unwrap();
    assert_eq!(ack.installed_cap_id, cap_id_expected);

    let outcome = started.outcome.await.unwrap();
    assert!(matches!(outcome, PairOutcome::Paired { .. }));

    // pair_pending.json should be cleaned up after successful install.
    assert!(!td.path().join("pair_pending.json").exists());

    // config.toml should now have the root pubkey set.
    let cfg_back: NodeConfig =
        toml::from_str(&std::fs::read_to_string(td.path().join("config.toml")).unwrap()).unwrap();
    assert_eq!(
        cfg_back.root_pubkey_hex,
        hex::encode(root_sk.verifying_key().to_bytes())
    );

    started.router.shutdown().await.ok();
}

#[tokio::test]
async fn resume_from_pair_pending_reuses_same_token() {
    let td = TempDir::new().unwrap();
    let agent_sk = SigningKey::generate(&mut OsRng);
    std::fs::write(td.path().join("identity.ed25519"), agent_sk.to_bytes()).unwrap();
    let xsk = XSk::random_from_rng(OsRng);
    let agent_x25519 = XPub::from(&xsk).to_bytes();
    std::fs::write(td.path().join("identity.x25519"), xsk.to_bytes()).unwrap();
    let cfg = NodeConfig {
        data_dir: td.path().to_path_buf(),
        root_pubkey_hex: String::new(),
        host: None,
        retention: None,
    };
    std::fs::write(
        td.path().join("config.toml"),
        toml::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();

    let manifest = PairManifest {
        role: "chat-agent".into(),
        description: "Bob".into(),
        requested_scopes: vec![RequestedScope {
            topic_name: "home.notes".into(),
            rights: vec![Right::Read],
        }],
    };

    // First call — creates pair_pending.json.
    let node1 = Arc::new(Node::open(cfg.clone()).unwrap());
    let ep1 = iroh::Endpoint::builder(presets::N0).bind().await.unwrap();
    let first = pair_listen(
        td.path().to_path_buf(),
        node1,
        agent_sk.clone(),
        agent_x25519,
        ep1,
        PairListenArgs {
            manifest: manifest.clone(),
            ttl: std::time::Duration::from_secs(60),
        },
    )
    .await
    .unwrap();
    let token_first = first.request_token.clone();
    first.router.shutdown().await.ok();

    // Second call — should resume from the saved pair_pending.json.
    let node2 = Arc::new(Node::open(cfg.clone()).unwrap());
    let ep2 = iroh::Endpoint::builder(presets::N0).bind().await.unwrap();
    let second = pair_listen(
        td.path().to_path_buf(),
        node2,
        agent_sk.clone(),
        agent_x25519,
        ep2,
        PairListenArgs {
            manifest: manifest.clone(),
            ttl: std::time::Duration::from_secs(120), // different TTL, but pending takes precedence
        },
    )
    .await
    .unwrap();
    let token_second = second.request_token.clone();
    second.router.shutdown().await.ok();

    // Both calls must produce the same token (resumed from pair_pending.json).
    assert_eq!(token_first, token_second);
}

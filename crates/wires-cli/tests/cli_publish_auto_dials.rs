//! After `wires init` + `wires host pair`, `wires publish` should both
//! write locally AND broadcast over gossip. We assert the second half by
//! standing up a second NodeRuntime subscribed to the topic and seeing the
//! event come through.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_core::Capability;
use wires_core::cap::Right;
use wires_node::{NodeConfig, NodeRuntime};

#[tokio::test]
async fn publish_broadcasts_via_gossip() {
    let _ = tracing_subscriber::fmt::try_init();
    let topic = [0x55u8; 32];
    let root = SigningKey::generate(&mut OsRng);
    let root_hex = hex::encode(root.verifying_key().to_bytes());

    // ---- subscriber NodeRuntime ----------------------------------------
    let sub_tmp = TempDir::new().unwrap();
    let sub_cfg = NodeConfig {
        data_dir: sub_tmp.path().to_path_buf(),
        root_pubkey_hex: root_hex.clone(),
        host: None,
        retention: None,
    };
    let sub = NodeRuntime::open(sub_cfg).await.unwrap();
    sub.node.install_epoch_key(topic, 0, [0x99u8; 32]).unwrap();
    // Bring the subscriber endpoint online so `addr()` returns a usable set
    // of direct addresses / a relay URL that the publisher can dial.
    tokio::time::timeout(Duration::from_secs(10), sub.endpoint.online())
        .await
        .expect("subscriber endpoint did not come online");
    sub.join_topic(topic, vec![]).await.unwrap();
    let mut sub_events = sub.node.subscribe();

    // ---- publisher dir, init + host config pointing at the subscriber ---
    let pub_tmp = TempDir::new().unwrap();
    std::fs::write(pub_tmp.path().join("root.ed25519"), root.to_bytes()).unwrap();
    // Open Node so identity files exist.
    let pub_node = wires_node::Node::open(NodeConfig {
        data_dir: pub_tmp.path().to_path_buf(),
        root_pubkey_hex: root_hex.clone(),
        host: None,
        retention: None,
    })
    .unwrap();
    pub_node.install_epoch_key(topic, 0, [0x99u8; 32]).unwrap();
    let pub_pk = pub_node.ed_sk.verifying_key().to_bytes();
    let mut cap = Capability::new_unsigned(
        pub_pk,
        vec![hex::encode(topic)],
        vec![Right::Read, Right::Write],
        0,
        None,
    );
    cap.sign(&root).unwrap();
    pub_node.caps.upsert_grant(&cap).unwrap();
    sub.node.caps.upsert_grant(&cap).unwrap();
    // Snapshot the subscriber's current direct addresses and relay URL so the
    // publisher can dial without going through pkarr/DNS — the CLI's
    // `publish::run` will pipe these into iroh's address-lookup.
    let sub_addr = sub.endpoint.addr();
    let mut hint_addrs: Vec<String> = Vec::new();
    let mut hint_relay: Option<String> = None;
    for t in &sub_addr.addrs {
        match t {
            iroh::TransportAddr::Ip(sa) => hint_addrs.push(sa.to_string()),
            iroh::TransportAddr::Relay(url) => hint_relay = Some(url.to_string()),
            _ => {}
        }
    }
    let cfg = NodeConfig {
        data_dir: pub_tmp.path().to_path_buf(),
        root_pubkey_hex: root_hex,
        host: Some(wires_node::HostConfig {
            peer_hints: vec![wires_net::PeerHint {
                node_id: hex::encode(sub.endpoint.id().as_bytes()),
                addrs: hint_addrs,
                relay: hint_relay,
            }],
        }),
        retention: None,
    };
    std::fs::write(
        pub_tmp.path().join("config.toml"),
        toml::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();

    drop(pub_node); // release the redb lock before re-opening via the CLI helper

    // Wait briefly for gossip mesh to converge.
    tokio::time::sleep(Duration::from_millis(300)).await;

    wires_cli::cmd::publish::run(
        pub_tmp.path(),
        &hex::encode(topic),
        &hex::encode(cap.cap_id.0),
        "agent.note",
        "hi from publish",
        None,
    )
    .await
    .unwrap();

    let event = tokio::time::timeout(Duration::from_secs(5), sub_events.recv())
        .await
        .expect("event did not arrive")
        .unwrap();
    assert_eq!(event.topic_id, topic);
    let c = event.content.expect("decryption should succeed");
    assert_eq!(c.text, "hi from publish");
    let _ = Arc::new(sub); // keep subscriber alive
}

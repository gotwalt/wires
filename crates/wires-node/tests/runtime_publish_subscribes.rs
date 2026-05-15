//! Two NodeRuntimes on the same machine join the same topic; one publishes,
//! the other observes the message via its broadcast event stream.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use iroh::address_lookup::memory::MemoryLookup;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_core::cap::Right;
use wires_core::{CanonicalContent, Capability};
use wires_node::{NodeConfig, NodeRuntime};

#[tokio::test]
async fn runtime_publish_reaches_peer_runtime() {
    let _ = tracing_subscriber::fmt::try_init();
    let root = SigningKey::generate(&mut OsRng);
    let root_hex = hex::encode(root.verifying_key().to_bytes());
    let topic = [0x42u8; 32];

    let alice_tmp = TempDir::new().unwrap();
    let bob_tmp = TempDir::new().unwrap();
    let alice_cfg = NodeConfig {
        data_dir: alice_tmp.path().to_path_buf(),
        root_pubkey_hex: root_hex.clone(),
        host: None,
    };
    let bob_cfg = NodeConfig {
        data_dir: bob_tmp.path().to_path_buf(),
        root_pubkey_hex: root_hex.clone(),
        host: None,
    };

    let alice = NodeRuntime::open(alice_cfg).await.unwrap();
    let bob = NodeRuntime::open(bob_cfg).await.unwrap();

    // Install matching epoch key on both nodes.
    let epoch_key = [0x99u8; 32];
    alice.node.install_epoch_key(topic, 0, epoch_key).unwrap();
    bob.node.install_epoch_key(topic, 0, epoch_key).unwrap();

    // Mint a cap for alice (so she can publish under the root) and install on both.
    let alice_pk = alice.node.ed_sk.verifying_key().to_bytes();
    let mut cap = Capability::new_unsigned(
        alice_pk,
        vec![hex::encode(topic)],
        vec![Right::Read, Right::Write],
        0,
        None,
    );
    cap.sign(&root).unwrap();
    alice.node.caps.upsert_grant(&cap).unwrap();
    bob.node.caps.upsert_grant(&cap).unwrap();

    // Make both endpoints online so each has a usable relay/transport address,
    // then cross-register their EndpointAddrs in a MemoryLookup on the peer.
    // This avoids depending on the n0 pkarr/DNS discovery roundtrip during the
    // test, which can take >5s on a cold machine.
    tokio::time::timeout(Duration::from_secs(10), alice.endpoint.online())
        .await
        .expect("alice endpoint did not come online");
    tokio::time::timeout(Duration::from_secs(10), bob.endpoint.online())
        .await
        .expect("bob endpoint did not come online");

    let alice_addr = alice.endpoint.addr();
    let bob_addr = bob.endpoint.addr();
    bob.endpoint
        .address_lookup()
        .unwrap()
        .add(MemoryLookup::from_endpoint_info(vec![alice_addr]));
    alice
        .endpoint
        .address_lookup()
        .unwrap()
        .add(MemoryLookup::from_endpoint_info(vec![bob_addr]));

    // Alice and Bob both join the topic; Bob bootstraps from Alice.
    alice.join_topic(topic, vec![]).await.unwrap();
    bob.join_topic(topic, vec![alice.endpoint.id()])
        .await
        .unwrap();

    // Subscribe Bob's event stream before publishing.
    let mut bob_events = bob.node.subscribe();

    // Wait briefly for the gossip mesh to converge.
    tokio::time::sleep(Duration::from_secs(1)).await;

    let content = CanonicalContent::new("agent.note", "hello bob");
    alice
        .publish_and_broadcast(topic, cap.cap_id.0, content)
        .await
        .unwrap();

    // Bob should observe the decrypted event within a short window.
    let event = tokio::time::timeout(Duration::from_secs(10), bob_events.recv())
        .await
        .expect("did not receive event in time")
        .unwrap();
    assert_eq!(event.topic_id, topic);
    let c = event.content.expect("decryption should succeed");
    assert_eq!(c.text, "hello bob");
}

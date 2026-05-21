//! End-to-end: register → register-topic → unregister → re-register.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use iroh::SecretKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_host::fabric_registry::{FabricHandlerConfig, FabricHandlerImpl, FabricRegistry};
use wires_host::per_fabric_logs::PerFabricLogs;
use wires_host::retention::Retention;
use wires_net::fabric::{ALPN as FABRIC_ALPN, FabricClient, FabricProtocol, FabricResponse};
use wires_net::unix_now_ms;

#[tokio::test]
async fn full_fabric_lifecycle_register_unregister_reregister() {
    let _ = tracing_subscriber::fmt::try_init();

    // --- Set up an in-memory host: registry + handler + endpoint + router. ---
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_path_buf();
    let registry = Arc::new(FabricRegistry::open(&data_dir).unwrap());
    let logs = Arc::new(PerFabricLogs::new(&data_dir));
    let retention = Arc::new(Retention::new(&data_dir, Arc::clone(&logs)));

    let host_ep = wires_net::bind_lan(SecretKey::generate(), vec![FABRIC_ALPN.to_vec()])
        .await
        .expect("bind_lan host");
    let host_id_bytes: [u8; 32] = host_ep.id().as_bytes().to_owned();

    let logs_cb = Arc::clone(&logs);
    let retention_cb = Arc::clone(&retention);
    let data_dir_cb = data_dir.clone();
    let handler = Arc::new(FabricHandlerImpl {
        registry: Arc::clone(&registry),
        retention: Arc::clone(&retention),
        host_endpoint_id: host_id_bytes,
        config: FabricHandlerConfig::default(),
        now_ms: Arc::new(unix_now_ms),
        on_topic_registered: Arc::new(|_root, _topic| {}),
        on_topic_unregistered: Arc::new(|_root, _topic| {}),
        on_fabric_unregistered: Arc::new(move |root, _topics| {
            logs_cb.clear_fabric(&root);
            retention_cb.clear_fabric(&root);
            let dir = data_dir_cb.join("fabrics").join(hex::encode(root));
            let _ = std::fs::remove_dir_all(&dir);
        }),
    });

    let _router = iroh::protocol::Router::builder(host_ep.clone())
        .accept(FABRIC_ALPN, FabricProtocol::new(Arc::clone(&handler)))
        .spawn();

    // --- Client side: a fresh signing key + endpoint + FabricClient. ---
    let caller_ep = wires_net::bind_lan(SecretKey::generate(), vec![])
        .await
        .expect("bind_lan caller");
    let client = FabricClient::new(caller_ep);
    let signing_key = SigningKey::generate(&mut OsRng);

    // 1. Register.
    let resp = client
        .register_fabric(host_ep.id(), &signing_key, &host_id_bytes, unix_now_ms())
        .await
        .unwrap();
    assert!(matches!(resp, FabricResponse::Register(ref r) if r.ok));

    // 2. Register a topic.
    let topic = [0x77u8; 32];
    let resp = client
        .register_topic(
            host_ep.id(),
            &signing_key,
            &topic,
            &host_id_bytes,
            unix_now_ms(),
        )
        .await
        .unwrap();
    assert!(matches!(resp, FabricResponse::TopicRegister(ref r) if r.ok));

    // Force the per-fabric log + retention to exist on disk by routing one
    // ingest through them (via direct API; no wire op needed for this test).
    let root_pubkey = signing_key.verifying_key().to_bytes();
    let _ = logs.get_or_open(&root_pubkey, &topic).unwrap();
    retention
        .on_append(&root_pubkey, &topic, &[0u8; 32], 0, 100, u64::MAX)
        .unwrap();
    let fabric_dir = data_dir.join("fabrics").join(hex::encode(root_pubkey));
    assert!(fabric_dir.exists(), "fabric dir should exist after appends");

    // 3. Unregister.
    let resp = client
        .unregister_fabric(host_ep.id(), &signing_key, &host_id_bytes, unix_now_ms())
        .await
        .unwrap();
    match resp {
        FabricResponse::Unregister(r) => {
            assert!(r.ok);
            // 1 caps-topic (auto-registered by handle_register) + 1 explicit
            // = 2 topics dropped.
            assert_eq!(r.topics_removed, 2);
        }
        other => panic!("expected Unregister, got {other:?}"),
    }
    // Registry rows gone.
    assert!(registry.get(&root_pubkey).unwrap().is_none());
    assert!(registry.lookup_topic_fabric(&topic).unwrap().is_none());
    // Filesystem cleanup happened via the on_fabric_unregistered callback.
    assert!(!fabric_dir.exists(), "fabric dir should be removed");

    // 4. Re-register against the same host with the same root key.
    let resp = client
        .register_fabric(host_ep.id(), &signing_key, &host_id_bytes, unix_now_ms())
        .await
        .unwrap();
    assert!(matches!(resp, FabricResponse::Register(ref r) if r.ok));
    assert!(registry.get(&root_pubkey).unwrap().is_some());

    // 5. Idempotent unregister: second call after re-register succeeds; a
    // *third* call (with no fabric present) returns ok:false.
    let resp = client
        .unregister_fabric(host_ep.id(), &signing_key, &host_id_bytes, unix_now_ms())
        .await
        .unwrap();
    assert!(matches!(resp, FabricResponse::Unregister(ref r) if r.ok));
    let resp = client
        .unregister_fabric(host_ep.id(), &signing_key, &host_id_bytes, unix_now_ms())
        .await
        .unwrap();
    match resp {
        FabricResponse::Unregister(r) => {
            assert!(!r.ok, "third call should report fabric not present");
            assert_eq!(r.topics_removed, 0);
        }
        other => panic!("expected Unregister, got {other:?}"),
    }
}

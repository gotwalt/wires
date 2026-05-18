//! Acceptance scenario: end-to-end tenant register via a host ticket.

use std::sync::Arc;

use iroh::SecretKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::retention::Retention;
use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
use wires_net::tenant::{ALPN as TENANT_ALPN, TenantProtocol, TenantResponse};

#[tokio::test]
#[ignore]
async fn end_to_end_register_via_host_ticket() {
    use ed25519_dalek::SigningKey;
    use wires_net::HostTicket;

    // ---- host setup ----------------------------------------------------
    let host_tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(host_tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(host_tmp.path()));
    let retention = Arc::new(Retention::new(host_tmp.path(), Arc::clone(&logs)));
    let host_ep = wires_net::bind_cloud(SecretKey::generate(), vec![TENANT_ALPN.to_vec()])
        .await
        .unwrap();
    let host_eid_bytes: [u8; 32] = host_ep.id().as_bytes().to_owned();
    let handler = Arc::new(TenantHandlerImpl {
        registry: Arc::clone(&registry),
        retention,
        host_endpoint_id: host_eid_bytes,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(|| {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64
        }),
        on_topic_registered: Arc::new(|_, _| {}),
        on_topic_unregistered: Arc::new(|_, _| {}),
        on_tenant_unregistered: Arc::new(|_, _| {}),
    });
    let _router = iroh::protocol::Router::builder(host_ep.clone())
        .accept(TENANT_ALPN, TenantProtocol::new(handler))
        .spawn();

    // ---- operator builds the ticket the iOS-app / CLI would scan -------
    let ticket = HostTicket::from_endpoint(&host_ep, std::time::Duration::from_secs(60)).unwrap();
    let token = ticket.encode().unwrap();

    // ---- fresh agent: init then pair -----------------------------------
    let agent_dir = TempDir::new().unwrap();
    let root = SigningKey::generate(&mut OsRng);
    std::fs::write(agent_dir.path().join("root.ed25519"), root.to_bytes()).unwrap();
    let cfg = wires_node::NodeConfig {
        data_dir: agent_dir.path().to_path_buf(),
        root_pubkey_hex: hex::encode(root.verifying_key().to_bytes()),
        host: None,
    };
    std::fs::write(
        agent_dir.path().join("config.toml"),
        toml::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();

    wires_cli::cmd::host::pair(agent_dir.path(), &token)
        .await
        .unwrap();

    // ---- assert tenant registered --------------------------------------
    let root_pubkey = root.verifying_key().to_bytes();
    assert!(registry.get(&root_pubkey).unwrap().is_some());
}

// Acceptance #1: two distinct tenants (representing two CLI agents under
// two different roots) on one host process. Each registers their own topic.
// Each publishes via gossip. The host persists each into the correct
// per-tenant directory. No cross-tenant content leakage.

use ed25519_dalek::SigningKey as DalekSk;
use std::time::Duration;
use tokio::sync::mpsc;
use wires_core::WireMessage;
use wires_host::routing::{Router as MsgRouter, WriteRateLimiter};
use wires_net::{ALPN as REPLAY_ALPN, GossipNode};

use iroh::{Endpoint, endpoint::presets};
use wires_net::tenant::TenantClient;

#[tokio::test]
#[ignore]
async fn two_tenants_share_one_host_no_leakage() {
    let _ = tracing_subscriber::fmt::try_init();
    let host_tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(host_tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(host_tmp.path()));
    let retention = Arc::new(Retention::new(host_tmp.path(), Arc::clone(&logs)));
    let rate = Arc::new(WriteRateLimiter::new(1_000));
    let router_state = Arc::new(MsgRouter::new(
        Arc::clone(&registry),
        Arc::clone(&logs),
        Arc::clone(&retention),
        Arc::clone(&rate),
    ));

    // Host endpoint with all three ALPNs (matches production main.rs setup
    // after Task 18.5's fix: GOSSIP_ALPN must be registered on the same Router
    // that owns TENANT_ALPN + REPLAY_ALPN, otherwise gossip QUIC handshakes
    // silently fail to dispatch).
    let host_ep = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .alpns(vec![
            TENANT_ALPN.to_vec(),
            REPLAY_ALPN.to_vec(),
            wires_net::GOSSIP_ALPN.to_vec(),
        ])
        .bind()
        .await
        .unwrap();
    let host_eid_bytes: [u8; 32] = host_ep.id().as_bytes().to_owned();

    // Gossip on the host using new_without_router so we can multiplex with
    // the tenant + replay ALPNs on one combined Router below.
    let (gossip, gossip_handler) = GossipNode::new_without_router(host_ep.clone())
        .await
        .unwrap();
    let _gossip_alive = gossip; // keep alive for the duration of the test
    let (subscribe_tx, mut subscribe_rx) = mpsc::unbounded_channel::<[u8; 32]>();
    let gossip_clone = _gossip_alive.clone_for_subscribe();
    {
        let router_state = Arc::clone(&router_state);
        tokio::spawn(async move {
            while let Some(topic_id) = subscribe_rx.recv().await {
                let Ok((_h, mut rx)) = gossip_clone.join(topic_id, vec![]).await else {
                    continue;
                };
                let router_state = Arc::clone(&router_state);
                tokio::spawn(async move {
                    while let Some(bytes) = rx.recv().await {
                        let Ok(msg) = serde_json::from_slice::<WireMessage>(&bytes) else {
                            continue;
                        };
                        if wires_core::verify_envelope(&msg).is_err() {
                            continue;
                        }
                        let _ = router_state.route(&msg);
                    }
                });
            }
        });
    }

    // Tenant handler with the matching subscribe hook.
    let subscribe_tx_for_handler = subscribe_tx.clone();
    let handler = Arc::new(TenantHandlerImpl {
        registry: Arc::clone(&registry),
        retention: Arc::clone(&retention),
        host_endpoint_id: host_eid_bytes,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(|| {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64
        }),
        on_topic_registered: Arc::new(move |_root, topic| {
            let _ = subscribe_tx_for_handler.send(topic);
        }),
        on_topic_unregistered: Arc::new(|_, _| {}),
        on_tenant_unregistered: Arc::new(|_, _| {}),
    });
    let _proto_router = iroh::protocol::Router::builder(host_ep.clone())
        .accept(wires_net::GOSSIP_ALPN, gossip_handler)
        .accept(TENANT_ALPN, TenantProtocol::new(handler))
        .spawn();

    // Bring the host endpoint online so peer endpoints have a concrete addr
    // to register in their MemoryLookup below (we don't want to depend on
    // pkarr/DNS for in-process tests).
    tokio::time::timeout(Duration::from_secs(10), host_ep.online())
        .await
        .expect("host endpoint did not come online");

    // Two tenants: distinct roots, distinct topic ids.
    let root_a = DalekSk::generate(&mut OsRng);
    let root_b = DalekSk::generate(&mut OsRng);
    let topic_a = [0xAAu8; 32];
    let topic_b = [0xBBu8; 32];

    let now = || {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    };

    // Tenant A endpoint + MemoryLookup pointing at host (avoids pkarr DNS).
    let caller_ep_a = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .alpns(vec![wires_net::GOSSIP_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), caller_ep_a.online())
        .await
        .expect("caller_ep_a did not come online");
    caller_ep_a
        .address_lookup()
        .unwrap()
        .add(iroh::address_lookup::memory::MemoryLookup::from_endpoint_info(vec![host_ep.addr()]));
    // The host also needs to be able to dial caller_ep_a back (gossip mesh
    // is bidirectional).
    host_ep.address_lookup().unwrap().add(
        iroh::address_lookup::memory::MemoryLookup::from_endpoint_info(vec![caller_ep_a.addr()]),
    );

    let client_a = TenantClient::new(caller_ep_a.clone());
    let r = client_a
        .register_tenant(host_ep.id(), &root_a, &host_eid_bytes, now())
        .await
        .unwrap();
    assert!(matches!(r, TenantResponse::Register(_)));
    let r = client_a
        .register_topic(host_ep.id(), &root_a, &topic_a, &host_eid_bytes, now())
        .await
        .unwrap();
    assert!(matches!(r, TenantResponse::TopicRegister(_)));

    // Tenant B endpoint + MemoryLookup.
    let caller_ep_b = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .alpns(vec![wires_net::GOSSIP_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), caller_ep_b.online())
        .await
        .expect("caller_ep_b did not come online");
    caller_ep_b
        .address_lookup()
        .unwrap()
        .add(iroh::address_lookup::memory::MemoryLookup::from_endpoint_info(vec![host_ep.addr()]));
    host_ep.address_lookup().unwrap().add(
        iroh::address_lookup::memory::MemoryLookup::from_endpoint_info(vec![caller_ep_b.addr()]),
    );

    let client_b = TenantClient::new(caller_ep_b.clone());
    let _ = client_b
        .register_tenant(host_ep.id(), &root_b, &host_eid_bytes, now())
        .await
        .unwrap();
    let _ = client_b
        .register_topic(host_ep.id(), &root_b, &topic_b, &host_eid_bytes, now())
        .await
        .unwrap();

    // Open per-publisher gossip from each caller, joining the host as bootstrap.
    let gossip_a = GossipNode::new(caller_ep_a.clone()).await.unwrap();
    let gossip_b = GossipNode::new(caller_ep_b.clone()).await.unwrap();
    let (handle_a, _rx_a) = gossip_a.join(topic_a, vec![host_ep.id()]).await.unwrap();
    let (handle_b, _rx_b) = gossip_b.join(topic_b, vec![host_ep.id()]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Manufacture and broadcast a Standard envelope on each side. We sign over
    // the canonical bytes and leave ciphertext empty — the host's
    // verify_envelope succeeds because the AAD/signature contract zeros
    // ciphertext + signature + payload_len per CLAUDE.md invariant #1.
    fn mk_envelope(topic: [u8; 32], sender_sk: &DalekSk, seq: u64) -> WireMessage {
        use wires_core::MessageKind;
        let mut msg = WireMessage {
            topic_id: topic,
            epoch: 0,
            kind: MessageKind::Standard,
            sender: sender_sk.verifying_key().to_bytes(),
            cap_id: [0u8; 16],
            seq,
            prev_hash: [0u8; 32],
            timestamp: seq as i64 * 1000,
            payload_len: 0,
            signature: [0u8; 64],
            ciphertext: vec![],
        };
        let bytes = msg.signing_bytes().expect("signing_bytes");
        use ed25519_dalek::Signer as _;
        msg.signature = sender_sk.sign(&bytes).to_bytes();
        msg
    }
    let msg_a = mk_envelope(topic_a, &root_a, 1);
    let msg_b = mk_envelope(topic_b, &root_b, 1);
    handle_a
        .broadcast(serde_json::to_vec(&msg_a).unwrap())
        .await
        .unwrap();
    handle_b
        .broadcast(serde_json::to_vec(&msg_b).unwrap())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Assert: on-disk per-tenant directories contain only their own log.
    let dir_a = host_tmp
        .path()
        .join("tenants")
        .join(hex::encode(root_a.verifying_key().to_bytes()));
    let dir_b = host_tmp
        .path()
        .join("tenants")
        .join(hex::encode(root_b.verifying_key().to_bytes()));
    let entries_a: Vec<_> = std::fs::read_dir(&dir_a).unwrap().flatten().collect();
    let entries_b: Vec<_> = std::fs::read_dir(&dir_b).unwrap().flatten().collect();
    let names_a: Vec<String> = entries_a
        .iter()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let names_b: Vec<String> = entries_b
        .iter()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names_a.iter().any(|n| n.contains(&hex::encode(topic_a))),
        "{names_a:?}"
    );
    assert!(
        names_b.iter().any(|n| n.contains(&hex::encode(topic_b))),
        "{names_b:?}"
    );
    assert!(!names_a.iter().any(|n| n.contains(&hex::encode(topic_b))));
    assert!(!names_b.iter().any(|n| n.contains(&hex::encode(topic_a))));
}

//! After `wires host pair`, `wires host topic-register <hex>` enrolls a
//! topic with the host. Subsequent inbound envelopes for that topic should
//! be routed and persisted.

use std::net::SocketAddr;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use iroh::{Endpoint, SecretKey, endpoint::presets};
use rand_core::OsRng;
use tempfile::TempDir;
use wires_host::http_discovery::{DiscoveryEndpoint, DiscoveryResponse, DiscoveryState};
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::retention::Retention;
use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
use wires_net::tenant::{ALPN as TENANT_ALPN, TenantProtocol};

#[tokio::test]
async fn topic_register_round_trip() {
    let host_tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(host_tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(host_tmp.path()));
    let retention = Arc::new(Retention::new(host_tmp.path(), Arc::clone(&logs)));
    let host_ep = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .alpns(vec![TENANT_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let host_eid: [u8; 32] = host_ep.id().as_bytes().to_owned();
    let handler = Arc::new(TenantHandlerImpl {
        registry: Arc::clone(&registry),
        retention,
        host_endpoint_id: host_eid,
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
    });
    let _router = iroh::protocol::Router::builder(host_ep.clone())
        .accept(TENANT_ALPN, TenantProtocol::new(handler))
        .spawn();

    let discovery_state = Arc::new(DiscoveryState {
        response: DiscoveryResponse {
            version: 1,
            endpoints: vec![DiscoveryEndpoint {
                endpoint_id: hex::encode(host_eid),
                relay: None,
                addrs: vec![],
            }],
            ttl_seconds: 300,
        },
    });
    let app = wires_host::http_discovery::router(discovery_state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    // Init + pair.
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
    wires_cli::cmd::host::pair(agent_dir.path(), &format!("http://{addr}/v1/bootstrap"))
        .await
        .unwrap();

    // Register a synthetic topic id.
    let topic = [0xCDu8; 32];
    wires_cli::cmd::host::topic_register(agent_dir.path(), &hex::encode(topic))
        .await
        .unwrap();
    let root_pubkey = root.verifying_key().to_bytes();
    assert_eq!(
        registry.lookup_topic_tenant(&topic).unwrap(),
        Some(root_pubkey)
    );

    // Unregister.
    wires_cli::cmd::host::topic_unregister(agent_dir.path(), &hex::encode(topic))
        .await
        .unwrap();
    assert!(registry.lookup_topic_tenant(&topic).unwrap().is_none());
}

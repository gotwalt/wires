//! Integration test: spin up a minimal tenant-only host in-process, build a
//! `HostTicket` from it, point `wires host pair` at it via `--ticket`, and
//! verify config.toml is updated with the host's peer hint.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use iroh::SecretKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::retention::Retention;
use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
use wires_net::HostTicket;
use wires_net::tenant::{ALPN as TENANT_ALPN, TenantProtocol};

#[tokio::test]
async fn host_pair_persists_host_to_config() {
    // ---- spin up a tenant-aware host -----------------------------------
    let host_tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(host_tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(host_tmp.path()));
    let retention = Arc::new(Retention::new(host_tmp.path(), Arc::clone(&logs)));
    let host_ep = wires_net::bind_cloud(SecretKey::generate(), vec![TENANT_ALPN.to_vec()])
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
        on_tenant_unregistered: Arc::new(|_, _| {}),
    });
    let _router = iroh::protocol::Router::builder(host_ep.clone())
        .accept(TENANT_ALPN, TenantProtocol::new(handler))
        .spawn();

    // Wait for the host endpoint to come online so its socket addresses are
    // populated and HostTicket::from_endpoint carries real addrs for the
    // client to register in its MemoryLookup (avoids pkarr/DNS in-process).
    tokio::time::timeout(std::time::Duration::from_secs(10), host_ep.online())
        .await
        .expect("host endpoint did not come online within 10s");

    // ---- build the host ticket the operator would scan ------------------
    let ticket = HostTicket::from_endpoint(&host_ep, std::time::Duration::from_secs(60)).unwrap();
    let token = ticket.encode().unwrap();

    // ---- run `wires init` then `wires host pair --ticket <T>` ----------
    let agent_dir = TempDir::new().unwrap();
    let root = SigningKey::generate(&mut OsRng);
    std::fs::write(agent_dir.path().join("root.ed25519"), root.to_bytes()).unwrap();
    let cfg = wires_node::NodeConfig {
        data_dir: agent_dir.path().to_path_buf(),
        root_pubkey_hex: hex::encode(root.verifying_key().to_bytes()),
        host: None,
        retention: None,
    };
    std::fs::write(
        agent_dir.path().join("config.toml"),
        toml::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();

    wires_cli::cmd::host::pair(agent_dir.path(), &token)
        .await
        .unwrap();

    // ---- assert config.toml gained host fields -------------------------
    let after: wires_node::NodeConfig =
        toml::from_str(&std::fs::read_to_string(agent_dir.path().join("config.toml")).unwrap())
            .unwrap();
    let h = after.host.expect("host should be set after pair");
    assert_eq!(h.peer_hints.len(), 1);
    assert_eq!(h.peer_hints[0].node_id, hex::encode(host_eid));

    // Tenant must be in the host's registry.
    let root_pubkey = root.verifying_key().to_bytes();
    assert!(registry.get(&root_pubkey).unwrap().is_some());
}

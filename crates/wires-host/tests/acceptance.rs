//! Acceptance: start the discovery HTTP service and a live iroh host with the
//! tenant protocol; a client fetches `/v1/bootstrap` via reqwest, parses the
//! endpoint list, dials the listed EndpointId, and registers.

use std::net::SocketAddr;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use iroh::{Endpoint, SecretKey, endpoint::presets};
use rand_core::OsRng;
use tempfile::TempDir;
use wires_host::http_discovery::{self, DiscoveryEndpoint, DiscoveryResponse, DiscoveryState};
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::retention::Retention;
use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
use wires_net::tenant::{
    ALPN as TENANT_ALPN, TenantClient, TenantProtocol, TenantRegisterRequest, TenantRequest,
    TenantResponse, register_signing_bytes,
};

fn endpoint_id_bytes(ep: &Endpoint) -> [u8; 32] {
    ep.id().as_bytes().to_owned()
}

#[tokio::test]
#[ignore]
async fn end_to_end_register_via_http_discovery() {
    let tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(tmp.path()));
    let retention = Arc::new(Retention::new(tmp.path(), Arc::clone(&logs)));

    let host_secret = SecretKey::generate();
    let host_ep = Endpoint::builder(presets::N0)
        .secret_key(host_secret)
        .alpns(vec![TENANT_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let host_eid_bytes = endpoint_id_bytes(&host_ep);

    let handler = Arc::new(TenantHandlerImpl {
        registry: Arc::clone(&registry),
        retention,
        host_endpoint_id: host_eid_bytes,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(|| 1_000_000i64),
        on_topic_registered: Arc::new(|_, _| {}),
        on_topic_unregistered: Arc::new(|_, _| {}),
    });
    let _router = iroh::protocol::Router::builder(host_ep.clone())
        .accept(TENANT_ALPN, TenantProtocol::new(handler))
        .spawn();

    // Spin up discovery HTTP service on an ephemeral port.
    let discovery_state = Arc::new(DiscoveryState {
        response: DiscoveryResponse {
            version: 1,
            endpoints: vec![DiscoveryEndpoint {
                endpoint_id: hex::encode(host_eid_bytes),
                relay: None,
                addrs: vec![],
            }],
            ttl_seconds: 300,
        },
    });
    let app = http_discovery::router(discovery_state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    // Client: fetch discovery, then register.
    let resp = reqwest::get(format!("http://{addr}/v1/bootstrap"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let payload: DiscoveryResponse = resp.json().await.unwrap();
    assert_eq!(payload.endpoints.len(), 1);
    let target_endpoint_id_hex = payload.endpoints[0].endpoint_id.clone();
    assert_eq!(target_endpoint_id_hex, hex::encode(host_eid_bytes));

    let client_secret = SecretKey::generate();
    let client_ep = Endpoint::builder(presets::N0)
        .secret_key(client_secret)
        .bind()
        .await
        .unwrap();
    let client = TenantClient::new(client_ep);

    let signing_key = SigningKey::generate(&mut OsRng);
    let root_pubkey = signing_key.verifying_key().to_bytes();
    let nonce = [11u8; 16];
    let bytes = register_signing_bytes(&root_pubkey, 1_000_000i64, &nonce, &host_eid_bytes);
    let sig = signing_key.sign(&bytes).to_bytes();
    let req = TenantRequest::Register(TenantRegisterRequest {
        version: 1,
        root_pubkey,
        timestamp: 1_000_000i64,
        nonce,
        signature: sig,
    });
    let resp = client.send(host_ep.id(), &req).await.unwrap();
    match resp {
        TenantResponse::Register(r) => assert!(r.ok),
        other => panic!("expected Register OK, got {:?}", other),
    }
    assert!(registry.get(&root_pubkey).unwrap().is_some());
}

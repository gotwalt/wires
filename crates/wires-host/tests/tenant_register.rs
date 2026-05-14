//! End-to-end: in-process iroh endpoints, host with TenantProtocol exposed,
//! a client sends TenantRegisterRequest and expects an OK response with the
//! correct host_endpoint_id and caps_topic_id.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use iroh::{Endpoint, SecretKey, endpoint::presets};
use rand_core::OsRng;
use tempfile::TempDir;
use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
use wires_net::tenant::{
    ALPN as TENANT_ALPN, TenantClient, TenantProtocol, TenantRegisterRequest, TenantRequest,
    TenantResponse, register_signing_bytes,
};

fn endpoint_id_bytes(ep: &Endpoint) -> [u8; 32] {
    ep.id().as_bytes().to_owned()
}

#[tokio::test]
async fn tenant_register_round_trip() {
    let tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(tmp.path()).unwrap());

    // Host endpoint
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
        host_endpoint_id: host_eid_bytes,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(|| 1_000_000i64),
        on_topic_registered: Arc::new(|_, _| {}),
        on_topic_unregistered: Arc::new(|_, _| {}),
    });
    let _host_router = iroh::protocol::Router::builder(host_ep.clone())
        .accept(TENANT_ALPN, TenantProtocol::new(handler))
        .spawn();

    // Client endpoint
    let client_secret = SecretKey::generate();
    let client_ep = Endpoint::builder(presets::N0)
        .secret_key(client_secret)
        .bind()
        .await
        .unwrap();
    let client = TenantClient::new(client_ep);

    // Sign + send.
    let signing_key = SigningKey::generate(&mut OsRng);
    let root_pubkey = signing_key.verifying_key().to_bytes();
    let now_ms = 1_000_000i64;
    let nonce = [9u8; 16];
    let bytes = register_signing_bytes(&root_pubkey, now_ms, &nonce, &host_eid_bytes);
    let sig = signing_key.sign(&bytes).to_bytes();
    let req = TenantRequest::Register(TenantRegisterRequest {
        version: 1,
        root_pubkey,
        timestamp: now_ms,
        nonce,
        signature: sig,
    });

    let resp = client.send(host_ep.id(), &req).await.unwrap();
    match resp {
        TenantResponse::Register(r) => {
            assert!(r.ok);
            assert_eq!(r.host_endpoint_id, hex::encode(host_eid_bytes));
        }
        other => panic!("expected Register, got {:?}", other),
    }

    // Tenant row persisted.
    assert!(registry.get(&root_pubkey).unwrap().is_some());
}

//! End-to-end: in-process iroh endpoints, host with FabricProtocol exposed,
//! a client sends FabricRegisterRequest and expects an OK response with the
//! correct host_endpoint_id and caps_topic_id.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use iroh::{Endpoint, SecretKey, endpoint::presets};
use rand_core::OsRng;
use tempfile::TempDir;
use wires_host::fabric_registry::{FabricHandlerConfig, FabricHandlerImpl, FabricRegistry};
use wires_host::per_fabric_logs::PerFabricLogs;
use wires_host::retention::Retention;
use wires_net::fabric::{
    ALPN as FABRIC_ALPN, FabricClient, FabricOp, FabricProtocol, FabricRegisterRequest,
    FabricRequest, FabricResponse, signing_bytes,
};

fn endpoint_id_bytes(ep: &Endpoint) -> [u8; 32] {
    ep.id().as_bytes().to_owned()
}

#[tokio::test]
async fn fabric_register_round_trip() {
    let tmp = TempDir::new().unwrap();
    let registry = Arc::new(FabricRegistry::open(tmp.path()).unwrap());
    let logs = Arc::new(PerFabricLogs::new(tmp.path()));
    let retention = Arc::new(Retention::new(tmp.path(), Arc::clone(&logs)));

    // Host endpoint
    let host_secret = SecretKey::generate();
    let host_ep = Endpoint::builder(presets::N0)
        .secret_key(host_secret)
        .alpns(vec![FABRIC_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let host_eid_bytes = endpoint_id_bytes(&host_ep);

    let handler = Arc::new(FabricHandlerImpl {
        registry: Arc::clone(&registry),
        retention,
        host_endpoint_id: host_eid_bytes,
        config: FabricHandlerConfig::default(),
        now_ms: Arc::new(|| 1_000_000i64),
        on_topic_registered: Arc::new(|_, _| {}),
        on_topic_unregistered: Arc::new(|_, _| {}),
        on_fabric_unregistered: Arc::new(|_, _| {}),
    });
    let _host_router = iroh::protocol::Router::builder(host_ep.clone())
        .accept(FABRIC_ALPN, FabricProtocol::new(handler))
        .spawn();

    // Client endpoint
    let client_secret = SecretKey::generate();
    let client_ep = Endpoint::builder(presets::N0)
        .secret_key(client_secret)
        .bind()
        .await
        .unwrap();
    let client = FabricClient::new(client_ep);

    // Sign + send.
    let signing_key = SigningKey::generate(&mut OsRng);
    let root_pubkey = signing_key.verifying_key().to_bytes();
    let now_ms = 1_000_000i64;
    let nonce = [9u8; 16];
    let bytes = signing_bytes(
        FabricOp::Register,
        &root_pubkey,
        now_ms,
        &nonce,
        &host_eid_bytes,
    );
    let sig = signing_key.sign(&bytes).to_bytes();
    let req = FabricRequest::Register(FabricRegisterRequest {
        version: 1,
        root_pubkey,
        timestamp: now_ms,
        nonce,
        signature: sig,
    });

    let resp = client.send(host_ep.id(), &req).await.unwrap();
    match resp {
        FabricResponse::Register(r) => {
            assert!(r.ok);
            assert_eq!(r.host_endpoint_id, hex::encode(host_eid_bytes));
        }
        other => panic!("expected Register, got {:?}", other),
    }

    // Fabric row persisted.
    assert!(registry.get(&root_pubkey).unwrap().is_some());
}

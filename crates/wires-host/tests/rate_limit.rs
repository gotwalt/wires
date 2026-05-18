//! Negative paths through the tenant control protocol and inbound router.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use tempfile::TempDir;
use wires_core::{MessageKind, WireMessage};
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::retention::Retention;
use wires_host::routing::{RouteOutcome, Router, WriteRateLimiter};
use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
use wires_net::tenant::{
    TenantErrorCode, TenantHandler, TenantOp, TenantRegisterRequest, TenantResponse, signing_bytes,
};

#[test]
fn handle_register_rejects_bad_signature() {
    let tmp = TempDir::new().unwrap();
    let reg = Arc::new(TenantRegistry::open(tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(tmp.path()));
    let retention = Arc::new(Retention::new(tmp.path(), Arc::clone(&logs)));
    let host_endpoint_id = [42u8; 32];
    let handler = TenantHandlerImpl {
        registry: Arc::clone(&reg),
        retention,
        host_endpoint_id,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(|| 1_000_000),
        on_topic_registered: Arc::new(|_, _| {}),
        on_topic_unregistered: Arc::new(|_, _| {}),
        on_tenant_unregistered: Arc::new(|_, _| {}),
    };
    let signing_key = SigningKey::generate(&mut OsRng);
    let root_pubkey = signing_key.verifying_key().to_bytes();
    let req = TenantRegisterRequest {
        version: 1,
        root_pubkey,
        timestamp: 1_000_000,
        nonce: [0u8; 16],
        signature: [0u8; 64], // garbage
    };
    match handler.handle_register(req) {
        TenantResponse::Error(e) => assert_eq!(e.code, TenantErrorCode::BadSignature),
        _ => panic!("expected BadSignature"),
    }
}

#[test]
fn handle_register_rejects_replayed_nonce() {
    let tmp = TempDir::new().unwrap();
    let reg = Arc::new(TenantRegistry::open(tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(tmp.path()));
    let retention = Arc::new(Retention::new(tmp.path(), Arc::clone(&logs)));
    let host_endpoint_id = [42u8; 32];
    let handler = TenantHandlerImpl {
        registry: Arc::clone(&reg),
        retention,
        host_endpoint_id,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(|| 1_000_000),
        on_topic_registered: Arc::new(|_, _| {}),
        on_topic_unregistered: Arc::new(|_, _| {}),
        on_tenant_unregistered: Arc::new(|_, _| {}),
    };
    let signing_key = SigningKey::generate(&mut OsRng);
    let root_pubkey = signing_key.verifying_key().to_bytes();
    let nonce = [0xCDu8; 16];
    let bytes = signing_bytes(
        TenantOp::Register,
        &root_pubkey,
        1_000_000,
        &nonce,
        &host_endpoint_id,
    );
    let sig = signing_key.sign(&bytes).to_bytes();
    let req = TenantRegisterRequest {
        version: 1,
        root_pubkey,
        timestamp: 1_000_000,
        nonce,
        signature: sig,
    };
    // First call succeeds.
    match handler.handle_register(req.clone()) {
        TenantResponse::Register(r) => assert!(r.ok),
        _ => panic!("expected Register OK"),
    }
    // Second call with same nonce → replayed.
    match handler.handle_register(req) {
        TenantResponse::Error(e) => assert_eq!(e.code, TenantErrorCode::ReplayedNonce),
        _ => panic!("expected ReplayedNonce"),
    }
}

#[test]
fn router_drops_envelope_for_unregistered_topic() {
    let tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(tmp.path()));
    let retention = Arc::new(Retention::new(tmp.path(), Arc::clone(&logs)));
    let rate = Arc::new(WriteRateLimiter::new(1_000));
    let router = Router::new(registry, logs, retention, rate);
    let msg = WireMessage {
        topic_id: [9u8; 32],
        epoch: 0,
        kind: MessageKind::Standard,
        sender: [3u8; 32],
        cap_id: [0u8; 16],
        seq: 0,
        prev_hash: [0u8; 32],
        timestamp: 0,
        payload_len: 1,
        signature: [0u8; 64],
        ciphertext: vec![0],
    };
    let outcome = router.route(&msg).unwrap();
    assert!(matches!(outcome, RouteOutcome::DroppedUnknownTopic));
}

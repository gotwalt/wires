//! Integration test: handle_status returns real topic_count, bytes_stored,
//! and oldest_retained_at after a tenant registers a topic and routes messages.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use tempfile::TempDir;
use wires_core::{MessageKind, WireMessage};
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::retention::Retention;
use wires_host::routing::{Router, WriteRateLimiter};
use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
use wires_net::tenant::{
    TenantHandler, TenantOp, TenantRegisterRequest, TenantResponse, TenantStatusRequest,
    TopicRegisterRequest, signing_bytes,
};

fn mk_msg(topic: [u8; 32], sender: [u8; 32], seq: u64, timestamp: i64) -> WireMessage {
    WireMessage {
        topic_id: topic,
        epoch: 0,
        kind: MessageKind::Standard,
        sender,
        cap_id: [0u8; 16],
        seq,
        prev_hash: [0u8; 32],
        timestamp,
        payload_len: 64,
        signature: [0u8; 64],
        ciphertext: vec![0u8; 64],
    }
}

#[test]
fn handle_status_returns_real_values() {
    let tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(tmp.path()));
    let retention = Arc::new(Retention::new(tmp.path(), Arc::clone(&logs)));
    let rate = Arc::new(WriteRateLimiter::new(1_000_000));

    let now_ms = 2_000_000i64;
    let host_endpoint_id = [77u8; 32];

    let signing_key = SigningKey::generate(&mut OsRng);
    let root_pubkey = signing_key.verifying_key().to_bytes();

    let handler = TenantHandlerImpl {
        registry: Arc::clone(&registry),
        retention: Arc::clone(&retention),
        host_endpoint_id,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(move || now_ms),
        on_topic_registered: Arc::new(|_, _| {}),
        on_topic_unregistered: Arc::new(|_, _| {}),
    };

    // 1. Register the tenant.
    let nonce1 = [0x01u8; 16];
    let reg_bytes = signing_bytes(
        TenantOp::Register,
        &root_pubkey,
        now_ms,
        &nonce1,
        &host_endpoint_id,
    );
    let reg_sig = signing_key.sign(&reg_bytes).to_bytes();
    let reg_resp = handler.handle_register(TenantRegisterRequest {
        version: 1,
        root_pubkey,
        timestamp: now_ms,
        nonce: nonce1,
        signature: reg_sig,
    });
    match reg_resp {
        TenantResponse::Register(r) => assert!(r.ok),
        other => panic!("expected Register OK, got {:?}", other),
    }

    // 2. Register an explicit topic.
    let topic = [0x55u8; 32];
    let nonce2 = [0x02u8; 16];
    let topic_reg_bytes = signing_bytes(
        TenantOp::TopicRegister(&topic),
        &root_pubkey,
        now_ms,
        &nonce2,
        &host_endpoint_id,
    );
    let topic_reg_sig = signing_key.sign(&topic_reg_bytes).to_bytes();
    let topic_resp = handler.handle_topic_register(TopicRegisterRequest {
        version: 1,
        root_pubkey,
        topic_id: topic,
        timestamp: now_ms,
        nonce: nonce2,
        signature: topic_reg_sig,
    });
    match topic_resp {
        TenantResponse::TopicRegister(r) => assert!(r.ok),
        other => panic!("expected TopicRegister OK, got {:?}", other),
    }

    // 3. Route two messages through Router so retention is populated.
    let sender = [0xAAu8; 32];
    let msg0_ts = 1_111_000i64;
    let msg1_ts = 2_222_000i64;
    let msg0 = mk_msg(topic, sender, 0, msg0_ts);
    let msg1 = mk_msg(topic, sender, 1, msg1_ts);
    let router = Router::new(
        Arc::clone(&registry),
        Arc::clone(&logs),
        Arc::clone(&retention),
        rate,
    );
    router.route(&msg0).unwrap();
    router.route(&msg1).unwrap();

    // 4. Query status.
    let nonce3 = [0x03u8; 16];
    let status_bytes = signing_bytes(
        TenantOp::Status,
        &root_pubkey,
        now_ms,
        &nonce3,
        &host_endpoint_id,
    );
    let status_sig = signing_key.sign(&status_bytes).to_bytes();
    let status_resp = handler.handle_status(TenantStatusRequest {
        version: 1,
        root_pubkey,
        timestamp: now_ms,
        nonce: nonce3,
        signature: status_sig,
    });

    match status_resp {
        TenantResponse::Status(s) => {
            // handle_register auto-creates the caps topic, so topic_count includes
            // the caps topic (1) plus our explicit topic (1) = 2.
            assert_eq!(
                s.topic_count, 2,
                "expected 2 registered topics (caps + explicit)"
            );
            assert!(
                s.bytes_stored > 0,
                "expected bytes_stored > 0, got {}",
                s.bytes_stored
            );
            // The oldest retained message is msg0 (seq=0, timestamp=msg0_ts).
            assert_eq!(
                s.oldest_retained_at, msg0_ts,
                "expected oldest_retained_at == msg0 timestamp"
            );
        }
        other => panic!("expected Status response, got {:?}", other),
    }
}

#[test]
fn handle_status_zero_when_no_messages() {
    let tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(tmp.path()));
    let retention = Arc::new(Retention::new(tmp.path(), Arc::clone(&logs)));

    let now_ms = 3_000_000i64;
    let host_endpoint_id = [88u8; 32];

    let signing_key = SigningKey::generate(&mut OsRng);
    let root_pubkey = signing_key.verifying_key().to_bytes();

    let handler = TenantHandlerImpl {
        registry: Arc::clone(&registry),
        retention: Arc::clone(&retention),
        host_endpoint_id,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(move || now_ms),
        on_topic_registered: Arc::new(|_, _| {}),
        on_topic_unregistered: Arc::new(|_, _| {}),
    };

    // Register tenant only — no messages routed.
    let nonce1 = [0x11u8; 16];
    let reg_bytes = signing_bytes(
        TenantOp::Register,
        &root_pubkey,
        now_ms,
        &nonce1,
        &host_endpoint_id,
    );
    let reg_sig = signing_key.sign(&reg_bytes).to_bytes();
    handler.handle_register(TenantRegisterRequest {
        version: 1,
        root_pubkey,
        timestamp: now_ms,
        nonce: nonce1,
        signature: reg_sig,
    });

    let nonce2 = [0x22u8; 16];
    let status_bytes = signing_bytes(
        TenantOp::Status,
        &root_pubkey,
        now_ms,
        &nonce2,
        &host_endpoint_id,
    );
    let status_sig = signing_key.sign(&status_bytes).to_bytes();
    let status_resp = handler.handle_status(TenantStatusRequest {
        version: 1,
        root_pubkey,
        timestamp: now_ms,
        nonce: nonce2,
        signature: status_sig,
    });

    match status_resp {
        TenantResponse::Status(s) => {
            assert_eq!(s.bytes_stored, 0);
            assert_eq!(s.oldest_retained_at, 0);
        }
        other => panic!("expected Status response, got {:?}", other),
    }
}

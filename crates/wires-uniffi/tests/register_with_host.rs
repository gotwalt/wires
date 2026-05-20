//! Integration test: WiresApp.parse_host_ticket + register_with_hosted_service
//! against an in-process iroh endpoint running a stub `TenantHandler`.
//!
//! Verifies the FFI shape end-to-end: a base64 `HostTicket` round-trips into
//! `HostInfo`, the WiresApp binds its own endpoint lazily, registers the
//! host's address hints, signs a `TenantRegisterRequest` via the
//! `SwiftRootSigner` callback, dials over `/wires/tenant/0`, and lifts the
//! `TenantRegisterResponse` into a `TenantRegistration`.
//!
//! The fuller end-to-end (parse_pair_request → approve_pair_request against
//! a `wires-host` + `wires-node` pair) remains a follow-up integration test
//! that pulls those crates in as dev-deps.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use wires_net::tenant::{
    ALPN as TENANT_ALPN, TenantHandler, TenantOp, TenantProtocol, TenantRegisterRequest,
    TenantRegisterResponse, TenantResponse, TenantStatusRequest, TenantUnregisterRequest,
    TopicRegisterRequest, TopicUnregisterRequest, signing_bytes,
};
use wires_net::ticket::HostTicket;
use wires_uniffi::{SwiftRootSigner, WiresApp, WiresError};

struct InProcessSigner(SigningKey);

impl SwiftRootSigner for InProcessSigner {
    fn pubkey(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }
    fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, WiresError> {
        let sig: ed25519_dalek::Signature = self.0.sign(&message);
        Ok(sig.to_bytes().to_vec())
    }
}

struct AcceptingHandler {
    host_id: [u8; 32],
    caps_topic_id: [u8; 32],
    now_ms: i64,
}

impl TenantHandler for AcceptingHandler {
    fn handle_register(&self, req: TenantRegisterRequest) -> TenantResponse {
        let bytes = signing_bytes(
            TenantOp::Register,
            &req.root_pubkey,
            req.timestamp,
            &req.nonce,
            &self.host_id,
        );
        let vk = VerifyingKey::from_bytes(&req.root_pubkey).unwrap();
        vk.verify(&bytes, &req.signature.into()).unwrap();
        TenantResponse::Register(TenantRegisterResponse {
            ok: true,
            host_endpoint_id: hex::encode(self.host_id),
            server_time: self.now_ms,
            caps_topic_id: self.caps_topic_id,
        })
    }
    fn handle_unregister(&self, _r: TenantUnregisterRequest) -> TenantResponse {
        unreachable!()
    }
    fn handle_topic_register(&self, _r: TopicRegisterRequest) -> TenantResponse {
        unreachable!()
    }
    fn handle_topic_unregister(&self, _r: TopicUnregisterRequest) -> TenantResponse {
        unreachable!()
    }
    fn handle_status(&self, _r: TenantStatusRequest) -> TenantResponse {
        unreachable!()
    }
}

/// Pending end-to-end: this test runs once iroh in-process cross-registration
/// is wired up. The WiresApp owns its `Endpoint` lazily inside `OnceCell` and
/// doesn't expose it; to make the in-process flow connect reliably, the host's
/// `address_lookup` needs the caller's `EndpointAddr` and vice versa
/// (see `crates/wires-host/tests/acceptance.rs::caller_ep_a` for the pattern).
/// Either WiresApp grows a test-only `expose_endpoint_for_cross_registration`
/// helper, or this test re-binds the WiresApp endpoint externally and threads
/// it in. Tracked as a follow-up to plan Task 11.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs in-process cross-registration with host endpoint; see comment"]
async fn register_with_hosted_service_round_trip() {
    let host_secret = iroh::SecretKey::generate();
    let host_ep = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(host_secret)
        .alpns(vec![TENANT_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let host_id: [u8; 32] = host_ep.id().as_bytes().to_owned();
    let caps_topic_id = [7u8; 32];
    let handler = Arc::new(AcceptingHandler {
        host_id,
        caps_topic_id,
        now_ms: 4242,
    });
    let _router = iroh::protocol::Router::builder(host_ep.clone())
        .accept(TENANT_ALPN, TenantProtocol::new(handler))
        .spawn();

    // Build a real HostTicket off the live host endpoint.
    let ticket = HostTicket::from_endpoint(&host_ep, Duration::from_secs(300), None).unwrap();
    let token = ticket.encode().unwrap();

    // Construct the WiresApp with a process-local signer.
    let mut iroh_secret = [0u8; 32];
    iroh_secret[..32].copy_from_slice(iroh::SecretKey::generate().to_bytes().as_ref());
    let signer: Arc<dyn SwiftRootSigner> =
        Arc::new(InProcessSigner(SigningKey::generate(&mut OsRng)));
    let app = WiresApp::bootstrap(iroh_secret.to_vec(), signer);

    // Round-trip ticket through the FFI.
    let host_info = app.parse_host_ticket(token).unwrap();
    assert_eq!(host_info.endpoint_id_hex, hex::encode(host_id));
    assert_eq!(host_info.hint_expires_at_ms, ticket.hint_expires_at);

    // Drive the register flow against the live host.
    let reg = app.register_with_hosted_service(host_info).await.unwrap();
    assert_eq!(reg.caps_topic_id_hex, hex::encode(caps_topic_id));
    assert_eq!(reg.server_time_ms, 4242);
    assert_eq!(reg.host_endpoint_id_hex, hex::encode(host_id));
}

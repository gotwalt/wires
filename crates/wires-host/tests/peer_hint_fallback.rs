//! Spec §11 scenario #3: peer_hints fallback. The agent tries a bogus
//! EndpointId first, then a real one, and successfully connects.

use std::sync::Arc;
use std::time::Duration;

use iroh::{Endpoint, SecretKey, endpoint::presets};
use wires_net::PeerHint;
use wires_net::peer_hint::first_reachable;
use wires_net::tenant::{
    ALPN as TENANT_ALPN, TenantErrorCode, TenantErrorResponse, TenantHandler, TenantProtocol,
    TenantRegisterRequest, TenantResponse, TenantStatusRequest, TenantUnregisterRequest,
    TopicRegisterRequest, TopicUnregisterRequest,
};

/// A stub handler that rejects all requests. Only used to satisfy
/// `TenantProtocol::new`; `first_reachable` drops the connection before
/// sending any request, so this code is never actually called in this test.
struct RejectAll;

impl TenantHandler for RejectAll {
    fn handle_register(&self, _req: TenantRegisterRequest) -> TenantResponse {
        TenantResponse::Error(TenantErrorResponse {
            code: TenantErrorCode::Internal,
            message: "test stub".into(),
        })
    }

    fn handle_unregister(&self, _req: TenantUnregisterRequest) -> TenantResponse {
        TenantResponse::Error(TenantErrorResponse {
            code: TenantErrorCode::Internal,
            message: "test stub".into(),
        })
    }

    fn handle_topic_register(&self, _req: TopicRegisterRequest) -> TenantResponse {
        TenantResponse::Error(TenantErrorResponse {
            code: TenantErrorCode::Internal,
            message: "test stub".into(),
        })
    }

    fn handle_topic_unregister(&self, _req: TopicUnregisterRequest) -> TenantResponse {
        TenantResponse::Error(TenantErrorResponse {
            code: TenantErrorCode::Internal,
            message: "test stub".into(),
        })
    }

    fn handle_status(&self, _req: TenantStatusRequest) -> TenantResponse {
        TenantResponse::Error(TenantErrorResponse {
            code: TenantErrorCode::Internal,
            message: "test stub".into(),
        })
    }
}

// A valid ed25519 public key whose bytes are all-zero except the last byte
// which is 1. This is a valid curve point (it will parse) but no host owns
// the corresponding secret key, so connections to it will fail/time out.
//
// NOTE: all-zeros (0x00…00) is NOT a valid ed25519 point, so we use a
// well-known valid-but-unowned key instead. We construct it from bytes to
// avoid hardcoding a base32 string.
fn bogus_endpoint_hex() -> String {
    // Use the canonical generator point bytes for ed25519. This is a valid
    // compressed Edwards point that iroh will accept for parsing, but nobody
    // owns the secret key.
    // Generator point in little-endian: 5866...6658
    let generator_bytes: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];
    hex::encode(generator_bytes)
}

#[tokio::test]
async fn peer_hint_fallback_picks_second_when_first_unreachable() {
    // Spin up a real host endpoint that advertises the tenant ALPN.
    // The handler is never invoked because `first_reachable` drops the
    // connection before opening a request stream.
    let host_secret = SecretKey::generate();
    let host_ep = Endpoint::builder(presets::N0)
        .secret_key(host_secret)
        .alpns(vec![TENANT_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let real_endpoint_hex = hex::encode(host_ep.id().as_bytes());

    let _router = iroh::protocol::Router::builder(host_ep.clone())
        .accept(TENANT_ALPN, TenantProtocol::new(Arc::new(RejectAll)))
        .spawn();

    // Client endpoint
    let client_secret = SecretKey::generate();
    let client_ep = Endpoint::builder(presets::N0)
        .secret_key(client_secret)
        .bind()
        .await
        .unwrap();

    let hints = vec![
        // hint[0]: a valid key nobody owns → connection will fail or time out
        PeerHint {
            node_id: bogus_endpoint_hex(),
            addrs: vec![],
            relay: None,
        },
        // hint[1]: the real host endpoint → connection will succeed
        PeerHint {
            node_id: real_endpoint_hex.clone(),
            addrs: vec![],
            relay: None,
        },
    ];

    let chosen = first_reachable(&client_ep, &hints, TENANT_ALPN, Duration::from_secs(5)).await;

    assert!(
        chosen.is_some(),
        "expected fallback to find the real endpoint"
    );
    let chosen_hex = hex::encode(chosen.unwrap().as_bytes());
    assert_eq!(
        chosen_hex, real_endpoint_hex,
        "should have skipped bogus and connected to real endpoint"
    );
}

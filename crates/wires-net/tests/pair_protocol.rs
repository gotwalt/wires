use std::sync::Arc;

use async_trait::async_trait;
use iroh::SecretKey;
use iroh::endpoint::presets;
use wires_net::pair::{
    ALPN, MAX_FRAME_LEN, PairAck, PairClient, PairDial, PairFrame, PairGrantEnvelope, PairHandler,
    PairProtocol, PairReject, PairRejectCode,
};

struct CannedAck;
#[async_trait]
impl PairHandler for CannedAck {
    async fn handle_grant(&self, _env: PairGrantEnvelope) -> PairFrame {
        PairFrame::Ack(PairAck {
            installed_cap_id: [0u8; 16],
            installed_at: 1,
        })
    }
}

struct CannedReject;
#[async_trait]
impl PairHandler for CannedReject {
    async fn handle_grant(&self, _env: PairGrantEnvelope) -> PairFrame {
        PairFrame::Reject(PairReject {
            code: PairRejectCode::NonceMismatch,
            message: "bad nonce".into(),
        })
    }
}

#[tokio::test]
async fn handler_returns_ack() {
    let server_ep = iroh::Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let server_id = server_ep.id();
    let proto = PairProtocol::new(Arc::new(CannedAck));
    let _router = iroh::protocol::Router::builder(server_ep)
        .accept(ALPN, proto)
        .spawn();

    let client_ep = iroh::Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .bind()
        .await
        .unwrap();
    let conn = client_ep.connect(server_id, ALPN).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let env = PairGrantEnvelope {
        root_pubkey: [0u8; 32],
        sealed_payload: vec![0xaa],
        signature: [0u8; 64],
    };
    wires_net::framing::write_frame(&mut send, &PairFrame::Grant(env))
        .await
        .unwrap();
    send.finish().ok();
    let frame: PairFrame =
        wires_net::framing::read_frame(&mut recv, MAX_FRAME_LEN)
            .await
            .unwrap();
    assert!(matches!(frame, PairFrame::Ack(_)));
}

#[tokio::test]
async fn handler_returns_reject() {
    let server_ep = iroh::Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let server_id = server_ep.id();
    let proto = PairProtocol::new(Arc::new(CannedReject));
    let _router = iroh::protocol::Router::builder(server_ep)
        .accept(ALPN, proto)
        .spawn();

    let client_ep = iroh::Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .bind()
        .await
        .unwrap();
    let conn = client_ep.connect(server_id, ALPN).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let env = PairGrantEnvelope {
        root_pubkey: [0u8; 32],
        sealed_payload: vec![0xbb],
        signature: [0u8; 64],
    };
    wires_net::framing::write_frame(&mut send, &PairFrame::Grant(env))
        .await
        .unwrap();
    send.finish().ok();
    let frame: PairFrame =
        wires_net::framing::read_frame(&mut recv, MAX_FRAME_LEN)
            .await
            .unwrap();
    match frame {
        PairFrame::Reject(r) => assert_eq!(r.code, PairRejectCode::NonceMismatch),
        _ => panic!("expected Reject"),
    }
}

#[tokio::test]
async fn client_deliver_grant_returns_ack() {
    let server_ep = iroh::Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let server_id = server_ep.id();
    let proto = PairProtocol::new(Arc::new(CannedAck));
    let _router = iroh::protocol::Router::builder(server_ep)
        .accept(ALPN, proto)
        .spawn();

    let client_ep = iroh::Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .bind()
        .await
        .unwrap();
    let client = PairClient::new(client_ep);
    let dial = PairDial {
        node_id: hex::encode(server_id.as_bytes()),
        addrs: vec![],
        relay: None,
    };
    let env = PairGrantEnvelope {
        root_pubkey: [0u8; 32],
        sealed_payload: vec![0xab],
        signature: [0u8; 64],
    };
    let ack = client.deliver_grant(&dial, env).await.unwrap();
    assert_eq!(ack.installed_cap_id, [0u8; 16]);
}

#[tokio::test]
async fn client_surfaces_reject_as_error() {
    let server_ep = iroh::Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let server_id = server_ep.id();
    let proto = PairProtocol::new(Arc::new(CannedReject));
    let _router = iroh::protocol::Router::builder(server_ep)
        .accept(ALPN, proto)
        .spawn();

    let client_ep = iroh::Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .bind()
        .await
        .unwrap();
    let client = PairClient::new(client_ep);
    let dial = PairDial {
        node_id: hex::encode(server_id.as_bytes()),
        addrs: vec![],
        relay: None,
    };
    let env = PairGrantEnvelope {
        root_pubkey: [0u8; 32],
        sealed_payload: vec![0xcd],
        signature: [0u8; 64],
    };
    let err = client.deliver_grant(&dial, env).await.unwrap_err();
    assert!(format!("{err}").contains("NonceMismatch"));
}

//! Smoke tests for `wires_net::bind_lan` and `wires_net::bind_cloud`.
//!
//! These only verify that the helpers return a usable iroh `Endpoint` —
//! actual mDNS discovery between peers is not exercised here, because it
//! requires multicast and a second cooperating peer. The existing
//! `peer_hint.rs` and `pair_protocol.rs` integration tests cover the
//! cross-endpoint paths.

use iroh::SecretKey;

const TEST_ALPN: &[u8] = b"/wires/test-bind/0";

#[tokio::test]
async fn bind_lan_returns_a_usable_endpoint() {
    let sk = SecretKey::generate();
    let expected_id = sk.public();
    let ep = wires_net::bind_lan(sk, vec![TEST_ALPN.to_vec()])
        .await
        .expect("bind_lan should succeed on a fresh OS");
    assert_eq!(ep.id(), expected_id);
    ep.close().await;
}

#[tokio::test]
async fn bind_cloud_returns_a_usable_endpoint() {
    let sk = SecretKey::generate();
    let expected_id = sk.public();
    let ep = wires_net::bind_cloud(sk, vec![TEST_ALPN.to_vec()])
        .await
        .expect("bind_cloud should succeed on a fresh OS");
    assert_eq!(ep.id(), expected_id);
    ep.close().await;
}

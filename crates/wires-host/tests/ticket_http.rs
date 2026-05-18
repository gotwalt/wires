//! Integration test for the wires-host ticket HTTP server.
//!
//! Spins up a single iroh endpoint and a `ticket_http::spawn` server on
//! 127.0.0.1:0, then GETs each route once. One iroh warm-up amortized
//! across all three assertions keeps the test runnable in CI cold-starts.

use std::time::Duration;

use iroh::SecretKey;
use tokio_util::sync::CancellationToken;
use wires_host::ticket_http;
use wires_net::HostTicket;

#[tokio::test]
async fn ticket_http_serves_all_three_routes() {
    let _ = tracing_subscriber::fmt::try_init();

    // Bring up an iroh endpoint. bind_lan pays the 5-30s cold-start cost
    // documented in the project CLAUDE.md. Matches the pattern in
    // wires-net/src/ticket.rs::from_endpoint_roundtrips_endpoint_id.
    let endpoint = wires_net::bind_lan(SecretKey::generate(), vec![])
        .await
        .expect("bind_lan failed");
    let endpoint_id_hex = hex::encode(endpoint.id().as_bytes());

    let shutdown = CancellationToken::new();
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (bound, handle) =
        ticket_http::spawn(endpoint.clone(), bind, Duration::from_secs(60), shutdown.clone())
            .await
            .expect("ticket_http::spawn failed");

    let client = reqwest::Client::new();

    // /ticket.txt — body decodes back to a HostTicket and the endpoint_id matches.
    let resp = client
        .get(format!("http://{bound}/ticket.txt"))
        .send()
        .await
        .expect("GET /ticket.txt failed");
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("")
            .starts_with("text/plain"),
        "expected text/plain content-type"
    );
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .map(|v| v.to_str().unwrap_or("")),
        Some("no-store"),
    );
    let body = resp.text().await.expect("body");
    let ticket = HostTicket::decode(body.trim()).expect("decode HostTicket");
    assert_eq!(ticket.endpoint_id, endpoint_id_hex);

    // /ticket.svg — SVG content with the right content-type and no-store cache header.
    let resp = client
        .get(format!("http://{bound}/ticket.svg"))
        .send()
        .await
        .expect("GET /ticket.svg failed");
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("")
            .starts_with("image/svg+xml"),
        "expected image/svg+xml content-type"
    );
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .map(|v| v.to_str().unwrap_or("")),
        Some("no-store"),
    );
    let body = resp.text().await.expect("body");
    assert!(
        body.starts_with("<?xml") || body.starts_with("<svg"),
        "expected SVG header, got {:?}",
        &body[..body.len().min(40)]
    );
    assert!(body.contains("<rect") || body.contains("<path"));

    // Task 6 extends this test in place below.

    shutdown.cancel();
    handle.await.expect("HTTP task panicked").expect("HTTP task returned error");
}

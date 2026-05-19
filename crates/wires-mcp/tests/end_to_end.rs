//! End-to-end acceptance: drive a full /authorize → pair → token → publish
//! → tail round-trip against an in-process gateway. Marked `#[ignore]` because
//! it spins up real iroh endpoints which need DNS/discovery and add 1-30s of
//! warm-up depending on environment. Run with `cargo test --workspace --
//! --ignored` (matches the project README and existing acceptance scenarios).
//!
//! Mirrors the 8-step driver in plan
//! `docs/superpowers/plans/2026-05-18-wires-mcp-gateway.md` (Task 33):
//!
//!   1. Spawn `http::serve_with_listener` on a random port.
//!   2. POST /oauth/register.
//!   3. GET /oauth/authorize; pull the pair token + session_id out of the
//!      consent HTML's `<meta>` tags.
//!   4. Act as the iOS operator: decode the PairRequest, mint a Capability
//!      for the gateway-agent against a fresh root SigningKey + topic, build
//!      a PairGrant, seal+sign, dial /wires/pair/0, await Ack. (The gateway's
//!      bridge `on_paired` callback completes the OAuth flow.)
//!   5. Poll /oauth/authorize/status/{session_id} until `done`; extract code.
//!   6. POST /oauth/token with PKCE verifier; receive access token.
//!   7. POST /mcp `tools/call wires_publish`; assert success.
//!   8. POST /mcp `tools/call wires_tail`; assert the published message comes
//!      back in the messages array.
//!
//! Test fixtures inline the cap-mint + PairGrant assembly rather than reusing
//! `wires-cli::cmd::pair_approve::run`, since `wires-mcp` can't depend on
//! `wires-cli` (crate layering).

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use iroh::SecretKey;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use wires_core::Capability;
use wires_core::cap::Right;
use wires_mcp::config::GatewayConfig;
use wires_mcp::http::{self, ServiceState};
use wires_mcp::pair_bridge::PairBridge;
use wires_mcp::rate_limit::RateLimiter;
use wires_mcp::store::Store;
use wires_mcp::tenants::TenantSupervisor;
use wires_net::pair::{
    PairClient, PairGrant, PairGrantEnvelope, PairRequest, TopicEpochKey, TopicNameEntry,
};
use wires_net::{bind_lan, unix_now_ms};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn first_time_pair_then_publish_then_tail() {
    let tmp = TempDir::new().unwrap();

    // ── 1. Spawn the gateway on a random loopback port ────────────────────────
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let public_url = format!("http://{local_addr}");

    let cfg = GatewayConfig {
        public_url: public_url.clone(),
        bind: local_addr.to_string(),
        data_dir: tmp.path().to_path_buf(),
        retention: None,
    };
    let store = Store::open(&cfg.gateway_db_path()).unwrap();
    let supervisor = TenantSupervisor::new(cfg.users_dir(), Duration::from_secs(60));
    let pair_bridge = Arc::new(PairBridge::new(
        cfg.pending_pairs_dir(),
        cfg.public_url.clone(),
        store.clone(),
        supervisor.clone(),
    ));
    let state = ServiceState {
        config: Arc::new(cfg),
        store,
        signing_key: Arc::new(SigningKey::from_bytes(&[7u8; 32])),
        supervisor,
        pair_bridge,
        rate_limit: RateLimiter::dcr_default(),
    };
    let server = tokio::spawn(http::serve_with_listener(state, listener));

    // ── 2. DCR ─────────────────────────────────────────────────────────────────
    let http_client = reqwest::Client::new();
    let dcr_resp = http_client
        .post(format!("{public_url}/oauth/register"))
        .json(&serde_json::json!({
            "client_name": "acceptance",
            "redirect_uris": ["http://localhost/cb"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(dcr_resp.status(), 201);
    let dcr_body: serde_json::Value = dcr_resp.json().await.unwrap();
    let client_id = dcr_body["client_id"].as_str().unwrap().to_string();

    // ── 3. /authorize → extract pair token + session_id from <meta> tags ──────
    let verifier = URL_SAFE_NO_PAD.encode(random_bytes(32));
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let auth_resp = http_client
        .get(format!("{public_url}/oauth/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", "http://localhost/cb"),
            ("scope", "mcp:wires"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("resource", &public_url),
            ("state", "st"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(auth_resp.status(), 200);
    let html = auth_resp.text().await.unwrap();
    let pair_token =
        extract_meta(&html, "wires-mcp-pair-token").expect("wires-mcp-pair-token meta tag missing");
    let session_id =
        extract_meta(&html, "wires-mcp-session-id").expect("wires-mcp-session-id meta tag missing");

    // ── 4. Fake-iOS: decode, mint cap, build grant, deliver over /wires/pair/0 ─
    let request = PairRequest::decode(&pair_token).unwrap();
    request.verify().unwrap();

    let root_sk = SigningKey::from_bytes(&[0x11; 32]);
    let root_pk = root_sk.verifying_key().to_bytes();
    let topic_id = [0x42u8; 32];
    let topic_name = "home.test".to_string();
    let epoch_key = [0x99u8; 32];

    let mut cap = Capability::new_unsigned(
        request.agent_pubkey,
        vec![topic_name.clone()],
        vec![Right::Read, Right::Write],
        unix_now_ms(),
        None,
    );
    cap.sign(&root_sk).unwrap();
    let grant = PairGrant {
        version: 1,
        root_pubkey: root_pk,
        cap,
        topic_keys: vec![TopicEpochKey {
            topic_id,
            epoch: 0,
            key: epoch_key,
        }],
        topic_names: vec![TopicNameEntry {
            topic_id,
            name: topic_name.clone(),
        }],
        host: None,
        nonce: request.nonce,
        issued_at: unix_now_ms(),
    };
    let envelope =
        PairGrantEnvelope::seal_and_sign(&grant, &request.ephemeral_x25519, &root_sk).unwrap();

    let dialer_endpoint = bind_lan(SecretKey::from_bytes(&random_bytes_32()), vec![])
        .await
        .unwrap();
    let pair_client = PairClient::new(dialer_endpoint);
    let _ack = pair_client
        .deliver_grant(&request.dial, envelope)
        .await
        .unwrap();

    // ── 5. Poll /oauth/authorize/status until done; extract code ──────────────
    let code = poll_until_done(&http_client, &public_url, &session_id).await;

    // ── 6. Authorization-code grant → access token ────────────────────────────
    let token_resp = http_client
        .post(format!("{public_url}/oauth/token"))
        .form(&[
            ("client_id", client_id.as_str()),
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "http://localhost/cb"),
            ("code_verifier", &verifier),
            ("resource", public_url.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(token_resp.status(), 200);
    let token_body: serde_json::Value = token_resp.json().await.unwrap();
    let access_token = token_body["access_token"].as_str().unwrap().to_string();

    // ── 7. wires_publish ──────────────────────────────────────────────────────
    let publish_resp = http_client
        .post(format!("{public_url}/mcp"))
        .bearer_auth(&access_token)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "wires_publish",
                "arguments": {"topic": &topic_name, "text": "hello world"}
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(publish_resp.status(), 200);
    let publish_body: serde_json::Value = publish_resp.json().await.unwrap();
    assert!(
        publish_body["result"]["isError"] != serde_json::Value::Bool(true),
        "publish reported isError=true: {publish_body}"
    );

    // ── 8. wires_tail must return the published message ───────────────────────
    let tail_resp = http_client
        .post(format!("{public_url}/mcp"))
        .bearer_auth(&access_token)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "wires_tail",
                "arguments": {"topic": &topic_name}
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(tail_resp.status(), 200);
    let tail_body: serde_json::Value = tail_resp.json().await.unwrap();
    let inner_text = tail_body["result"]["content"][0]["text"]
        .as_str()
        .expect("tail content[0].text");
    let parsed: serde_json::Value = serde_json::from_str(inner_text).unwrap();
    let msgs = parsed["messages"].as_array().unwrap();
    assert!(
        msgs.iter().any(|m| m["content"]["text"] == "hello world"),
        "no published message in tail: {parsed}"
    );

    server.abort();
}

async fn poll_until_done(client: &reqwest::Client, public_url: &str, session_id: &str) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let r = client
            .get(format!("{public_url}/oauth/authorize/status/{session_id}"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let v: serde_json::Value = r.json().await.unwrap();
        match v["kind"].as_str() {
            Some("done") => return v["code"].as_str().unwrap().to_string(),
            Some("pending") => {
                if std::time::Instant::now() >= deadline {
                    panic!("status stayed `pending` past deadline");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            other => panic!("unexpected status kind {other:?}: {v}"),
        }
    }
}

fn extract_meta(html: &str, name: &str) -> Option<String> {
    let needle = format!("name=\"{name}\"");
    let i = html.find(&needle)?;
    let after = &html[i..];
    let content_idx = after.find("content=\"")?;
    let start = i + content_idx + "content=\"".len();
    let end = html[start..].find('"')?;
    Some(html[start..start + end].to_string())
}

fn random_bytes(n: usize) -> Vec<u8> {
    use rand_core::RngCore as _;
    let mut buf = vec![0u8; n];
    rand_core::OsRng.fill_bytes(&mut buf);
    buf
}

fn random_bytes_32() -> [u8; 32] {
    use rand_core::RngCore as _;
    let mut buf = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut buf);
    buf
}

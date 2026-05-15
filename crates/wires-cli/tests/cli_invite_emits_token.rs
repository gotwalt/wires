//! `wires invite` should print a base64 `InviteToken` that decodes back into
//! a cap whose grantee is the local root, with peer_hints copied from
//! HostConfig.

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_net::{InviteToken, PeerHint};

#[tokio::test]
async fn invite_emits_invitetoken() {
    // Synthesize a paired config and root key in a fresh data dir.
    let dir = TempDir::new().unwrap();
    let root = SigningKey::generate(&mut OsRng);
    std::fs::write(dir.path().join("root.ed25519"), root.to_bytes()).unwrap();
    let cfg = wires_node::NodeConfig {
        data_dir: dir.path().to_path_buf(),
        root_pubkey_hex: hex::encode(root.verifying_key().to_bytes()),
        host: Some(wires_node::HostConfig {
            peer_hints: vec![PeerHint {
                node_id: "ab".repeat(32),
                addrs: vec!["127.0.0.1:11204".into()],
                relay: None,
            }],
            discovery_url: Some("https://discovery.example/v1/bootstrap".into()),
        }),
    };
    std::fs::write(
        dir.path().join("config.toml"),
        toml::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();
    // Pre-create the agent identity so `Node::open` can find it.
    let _ = wires_node::Node::open(cfg).unwrap();

    let invitee = SigningKey::generate(&mut OsRng);
    let token_str = wires_cli::cmd::invite::run_to_string(
        dir.path(),
        &hex::encode(invitee.verifying_key().to_bytes()),
        &["home.notes".to_string()],
        &["read".to_string(), "write".to_string()],
    )
    .await
    .unwrap();

    let decoded = InviteToken::decode(&token_str).unwrap();
    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.cap.agent, invitee.verifying_key().to_bytes());
    assert_eq!(decoded.peer_hints.len(), 1);
    assert_eq!(decoded.peer_hints[0].node_id.len(), 64);
    assert_eq!(
        decoded.service_discovery_url.as_deref(),
        Some("https://discovery.example/v1/bootstrap")
    );
}

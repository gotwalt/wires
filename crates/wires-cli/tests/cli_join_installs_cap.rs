//! `wires join <token>` should install the cap into caps.redb and copy the
//! peer hints into config.toml.

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_core::Capability;
use wires_core::cap::Right;
use wires_net::{InviteToken, PeerHint};
use wires_node::{Node, NodeConfig};

#[tokio::test]
async fn join_installs_cap_and_host_info() {
    // Inviter side: synthesize an InviteToken.
    let root = SigningKey::generate(&mut OsRng);
    let invitee = SigningKey::generate(&mut OsRng);
    let topic_name = "home.notes".to_string();

    let mut cap = Capability::new_unsigned(
        invitee.verifying_key().to_bytes(),
        vec![topic_name.clone()],
        vec![Right::Read, Right::Write],
        0,
        None,
    );
    cap.sign(&root).unwrap();
    let token = InviteToken {
        version: 1,
        cap: cap.clone(),
        peer_hints: vec![PeerHint {
            node_id: "ab".repeat(32),
            addrs: vec!["127.0.0.1:11204".into()],
            relay: None,
        }],
        service_discovery_url: Some("https://discovery.example/v1/bootstrap".into()),
        expires: i64::MAX,
        token_id: "tok-0".into(),
    };
    let encoded = token.encode().unwrap();

    // Invitee side: bare `wires init --root <hex>` simulated (no root.ed25519).
    let invitee_dir = TempDir::new().unwrap();
    let cfg = NodeConfig {
        data_dir: invitee_dir.path().to_path_buf(),
        root_pubkey_hex: hex::encode(root.verifying_key().to_bytes()),
        host: None,
    };
    std::fs::write(
        invitee_dir.path().join("config.toml"),
        toml::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();
    // Pre-create the agent identity so Node::open works.
    let _ = Node::open(cfg).unwrap();

    wires_cli::cmd::join::run(invitee_dir.path(), &encoded)
        .await
        .unwrap();

    // Verify cap landed in caps.redb.
    let cfg_after: NodeConfig =
        toml::from_str(&std::fs::read_to_string(invitee_dir.path().join("config.toml")).unwrap())
            .unwrap();
    let node = Node::open(cfg_after.clone()).unwrap();
    assert!(node.caps.get(&cap.cap_id.0).unwrap().is_some());

    // Verify host info was persisted.
    let h = cfg_after.host.expect("host should be set after join");
    assert_eq!(h.peer_hints.len(), 1);
    assert_eq!(
        h.discovery_url.as_deref(),
        Some("https://discovery.example/v1/bootstrap")
    );
}

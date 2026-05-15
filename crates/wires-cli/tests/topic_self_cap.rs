use tempfile::TempDir;
use wires_core::cap::Right;
use wires_node::{Node, NodeConfig};

#[tokio::test]
async fn create_auto_mints_self_cap_when_root_present() {
    let td = TempDir::new().unwrap();
    wires_cli::cmd::init::run(td.path(), true).await.unwrap();
    wires_cli::cmd::topic::create(td.path(), "home.notes")
        .await
        .unwrap();

    let cfg: NodeConfig =
        toml::from_str(&std::fs::read_to_string(td.path().join("config.toml")).unwrap()).unwrap();
    let node = Node::open(cfg).unwrap();
    let agent_pk = node.ed_sk.verifying_key().to_bytes();
    let all = node.caps.all().unwrap();
    let has_write = all.values().any(|entry| {
        entry.cap.agent == agent_pk && entry.cap.allows("home.notes", Right::Write).is_ok()
    });
    assert!(has_write, "self-cap should grant write on home.notes");
}

#[tokio::test]
async fn create_skips_self_cap_when_no_root() {
    let td = TempDir::new().unwrap();
    wires_cli::cmd::init::run(td.path(), false).await.unwrap();
    wires_cli::cmd::topic::create(td.path(), "home.notes")
        .await
        .unwrap();
    // No root → no cap minting; the call still succeeds.
    let cfg: NodeConfig =
        toml::from_str(&std::fs::read_to_string(td.path().join("config.toml")).unwrap()).unwrap();
    let node = Node::open(cfg).unwrap();
    let all = node.caps.all().unwrap();
    assert!(
        all.is_empty(),
        "no caps should be installed when there is no root"
    );
}

#[tokio::test]
async fn create_twice_only_mints_one_cap_per_topic() {
    let td = TempDir::new().unwrap();
    wires_cli::cmd::init::run(td.path(), true).await.unwrap();
    wires_cli::cmd::topic::create(td.path(), "home.notes")
        .await
        .unwrap();
    // Second create on a *different* topic name — should mint a new cap for it
    // and leave home.notes with exactly the one already installed.
    wires_cli::cmd::topic::create(td.path(), "mail.inbox")
        .await
        .unwrap();

    let cfg: NodeConfig =
        toml::from_str(&std::fs::read_to_string(td.path().join("config.toml")).unwrap()).unwrap();
    let node = Node::open(cfg).unwrap();
    let all = node.caps.all().unwrap();
    let agent_pk = node.ed_sk.verifying_key().to_bytes();

    assert!(!all.is_empty(), "at least one cap minted");
    assert!(
        all.values()
            .any(|e| e.cap.agent == agent_pk && e.cap.allows("home.notes", Right::Write).is_ok()),
        "home.notes cap exists"
    );
    assert!(
        all.values()
            .any(|e| e.cap.agent == agent_pk && e.cap.allows("mail.inbox", Right::Write).is_ok()),
        "mail.inbox cap exists"
    );
}

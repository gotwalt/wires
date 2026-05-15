use tempfile::TempDir;
use wires_node::NodeConfig;

#[tokio::test]
async fn init_writes_identity_only_by_default() {
    let td = TempDir::new().unwrap();
    wires_cli::cmd::init::run(td.path(), false).await.unwrap();
    assert!(td.path().join("identity.ed25519").exists());
    assert!(td.path().join("identity.x25519").exists());
    assert!(!td.path().join("root.ed25519").exists());
    let cfg: NodeConfig =
        toml::from_str(&std::fs::read_to_string(td.path().join("config.toml")).unwrap()).unwrap();
    assert!(cfg.root_pubkey_hex.is_empty());
}

#[tokio::test]
async fn init_new_root_writes_root_key() {
    let td = TempDir::new().unwrap();
    wires_cli::cmd::init::run(td.path(), true).await.unwrap();
    assert!(td.path().join("root.ed25519").exists());
    let cfg: NodeConfig =
        toml::from_str(&std::fs::read_to_string(td.path().join("config.toml")).unwrap()).unwrap();
    assert_eq!(cfg.root_pubkey_hex.len(), 64);
}

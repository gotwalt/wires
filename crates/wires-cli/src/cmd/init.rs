use std::path::Path;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use wires_node::{Node, NodeConfig};

pub async fn run(data_dir: &Path, root: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(data_dir)?;
    let root_hex = match root {
        Some(s) => s,
        None => {
            let sk = SigningKey::generate(&mut OsRng);
            let pk_hex = hex::encode(sk.verifying_key().to_bytes());
            std::fs::write(data_dir.join("root.ed25519"), sk.to_bytes())?;
            println!("Generated local root pubkey: {pk_hex}");
            pk_hex
        }
    };
    let cfg_path = data_dir.join("config.toml");
    let cfg = NodeConfig {
        data_dir: data_dir.to_path_buf(),
        root_pubkey_hex: root_hex.clone(),
        bootstrap_peers: vec![],
    };
    std::fs::write(&cfg_path, toml::to_string_pretty(&cfg)?)?;
    let _node = Node::open(cfg)?;
    println!("Initialized at {}", data_dir.display());
    println!("Root pubkey: {root_hex}");
    Ok(())
}

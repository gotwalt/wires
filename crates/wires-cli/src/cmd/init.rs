use std::path::Path;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use snafu::ResultExt;
use wires_node::{Node, NodeConfig};

use crate::error::{IoSnafu, NodeSnafu, Result, TomlSerializeSnafu};

pub async fn run(data_dir: &Path, new_root: bool) -> Result<()> {
    std::fs::create_dir_all(data_dir).context(IoSnafu)?;
    let root_pubkey_hex = if new_root {
        let sk = SigningKey::generate(&mut OsRng);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        std::fs::write(data_dir.join("root.ed25519"), sk.to_bytes()).context(IoSnafu)?;
        println!("Generated local root pubkey: {pk_hex}");
        pk_hex
    } else {
        String::new()
    };
    let cfg = NodeConfig {
        data_dir: data_dir.to_path_buf(),
        root_pubkey_hex: root_pubkey_hex.clone(),
        host: None,
    };
    let toml_str = toml::to_string_pretty(&cfg).context(TomlSerializeSnafu)?;
    std::fs::write(data_dir.join("config.toml"), toml_str).context(IoSnafu)?;
    let _node = Node::open(cfg).context(NodeSnafu)?;
    println!("Initialized at {}", data_dir.display());
    if root_pubkey_hex.is_empty() {
        println!(
            "(no root pinned — pair with an operator via `wires pair-listen` to attach to a household)"
        );
    } else {
        println!("Root pubkey: {root_pubkey_hex}");
    }
    Ok(())
}

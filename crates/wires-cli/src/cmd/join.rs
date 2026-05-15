//! `wires join <token>` — install an invite token: persist the cap and copy
//! the inviter's host hints into local config.

use std::path::Path;

use wires_net::InviteToken;
use wires_node::{HostConfig, Node, NodeConfig};

pub async fn run(data_dir: &Path, token: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cfg_path = data_dir.join("config.toml");
    let mut cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(&cfg_path)?)?;

    let parsed = InviteToken::decode(token)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;
    if parsed.expires <= now {
        return Err("invite token is expired".into());
    }

    // Verify cap signature against the local root pubkey. If verification
    // fails, the invite was signed by a different household's root.
    let root_bytes = hex::decode(&cfg.root_pubkey_hex)?;
    if root_bytes.len() != 32 {
        return Err("local config root_pubkey_hex is not 32 bytes".into());
    }
    let mut root_pk = [0u8; 32];
    root_pk.copy_from_slice(&root_bytes);
    parsed
        .cap
        .verify(&root_pk)
        .map_err(|e| format!("invite cap does not verify against local root: {e}"))?;

    // Install into the cap table.
    let node = Node::open(cfg.clone())?;
    node.caps.upsert_grant(&parsed.cap)?;

    // Persist host hints into config.
    cfg.host = Some(HostConfig {
        peer_hints: parsed.peer_hints,
        discovery_url: parsed.service_discovery_url,
    });
    std::fs::write(&cfg_path, toml::to_string_pretty(&cfg)?)?;

    println!(
        "Joined: cap {} installed; host info persisted.",
        hex::encode(parsed.cap.cap_id.0)
    );
    if !parsed.cap.topics.is_empty() {
        println!(
            "Note: epoch keys for {} topic(s) are not in the invite token; obtain them out-of-band before publishing.",
            parsed.cap.topics.len()
        );
    }
    Ok(())
}

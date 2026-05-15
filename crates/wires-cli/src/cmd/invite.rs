use std::path::Path;

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use wires_core::Capability;
use wires_core::cap::Right;
use wires_net::InviteToken;
use wires_node::{Node, NodeConfig};

/// Build an `InviteToken` and return its base64 form. Used both by the
/// `wires invite` CLI subcommand and by integration tests.
pub async fn run_to_string(
    data_dir: &Path,
    agent_pubkey: &str,
    topics: &[String],
    rights: &[String],
) -> Result<String, Box<dyn std::error::Error>> {
    let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
    let host = cfg
        .host
        .as_ref()
        .ok_or(
            "no host paired — run `wires host pair --discovery-url <URL>` before issuing invites",
        )?
        .clone();
    let node = Node::open(cfg)?;

    let root_bytes = std::fs::read(data_dir.join("root.ed25519"))?;
    if root_bytes.len() != 32 {
        return Err("root.ed25519 must be 32 bytes".into());
    }
    let root = SigningKey::from_bytes(&root_bytes.try_into().unwrap());

    let agent_bytes = hex::decode(agent_pubkey)?;
    if agent_bytes.len() != 32 {
        return Err("agent_pubkey must be 32 bytes (64 hex chars)".into());
    }
    let mut agent_pk = [0u8; 32];
    agent_pk.copy_from_slice(&agent_bytes);

    let rights_parsed: Vec<Right> = rights
        .iter()
        .map(|r| match r.as_str() {
            "read" => Ok(Right::Read),
            "write" => Ok(Right::Write),
            other => Err(format!("unknown right '{other}'")),
        })
        .collect::<Result<_, _>>()?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;
    let mut cap = Capability::new_unsigned(agent_pk, topics.to_vec(), rights_parsed, now, None);
    cap.sign(&root)?;
    node.caps.upsert_grant(&cap)?;

    let mut nonce_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut nonce_bytes);
    let token = InviteToken {
        version: 1,
        cap,
        peer_hints: host.peer_hints,
        service_discovery_url: host.discovery_url,
        expires: now + 7 * 24 * 60 * 60 * 1000, // 7d default
        token_id: hex::encode(nonce_bytes),
    };
    Ok(token.encode()?)
}

/// CLI entry point: print the cap_id (for self-cap publish flows) and the
/// invite token to stdout.
pub async fn run(
    data_dir: &Path,
    agent_pubkey: &str,
    topics: &[String],
    rights: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let token_str = run_to_string(data_dir, agent_pubkey, topics, rights).await?;
    let token = wires_net::InviteToken::decode(&token_str)?;
    println!("Minted capability:");
    println!("  cap_id : {}", hex::encode(token.cap.cap_id.0));
    println!("  agent  : {agent_pubkey}");
    println!("  topics : {topics:?}");
    println!("  rights : {rights:?}");
    println!();
    println!("Invite token (share with the invitee):");
    println!("{token_str}");
    Ok(())
}

use std::path::Path;

use ed25519_dalek::SigningKey;
use wires_core::Capability;
use wires_core::cap::Right;
use wires_node::{Node, NodeConfig};

pub async fn run(
    data_dir: &Path,
    agent_pubkey: &str,
    topics: &[String],
    rights: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
    let node = Node::open(cfg)?;

    let root_bytes_vec = std::fs::read(data_dir.join("root.ed25519"))?;
    if root_bytes_vec.len() != 32 {
        return Err("root.ed25519 must be 32 bytes".into());
    }
    let mut root_bytes = [0u8; 32];
    root_bytes.copy_from_slice(&root_bytes_vec);
    let root = SigningKey::from_bytes(&root_bytes);

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
    println!("Minted capability");
    println!("  cap_id : {}", hex::encode(cap.cap_id.0));
    println!("  agent  : {agent_pubkey}");
    println!("  topics : {topics:?}");
    println!("  rights : {rights:?}");
    Ok(())
}

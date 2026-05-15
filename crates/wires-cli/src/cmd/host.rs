//! `wires host *` subcommands. Each one loads the local root key from
//! `<data_dir>/root.ed25519`, opens a fresh iroh endpoint, dials a `TenantClient`,
//! and runs one request.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use iroh::{Endpoint, SecretKey, endpoint::presets};
use wires_net::tenant::{TenantClient, TenantResponse};
use wires_net::{fetch_endpoints, load_or_create_secret};
use wires_node::{HostConfig, NodeConfig};

pub async fn pair(data_dir: &Path, discovery_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Load existing config + root key.
    let cfg_path = data_dir.join("config.toml");
    let mut cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(&cfg_path)?)?;
    let root_bytes = std::fs::read(data_dir.join("root.ed25519"))?;
    if root_bytes.len() != 32 {
        return Err(
            "root.ed25519 must be 32 bytes — `wires invite` requires the local root.".into(),
        );
    }
    let root = SigningKey::from_bytes(&root_bytes.try_into().unwrap());

    // Fetch discovery; pick the first endpoint.
    let hints = fetch_endpoints(discovery_url).await?;
    let first = hints
        .first()
        .ok_or("discovery returned no endpoints")?
        .clone();
    let host_eid_bytes: [u8; 32] = {
        let v = hex::decode(&first.node_id)?;
        if v.len() != 32 {
            return Err("discovery endpoint_id not 32-byte hex".into());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    };
    let host_eid = iroh::EndpointId::from_bytes(&host_eid_bytes)
        .map_err(|e| format!("bad endpoint id from discovery: {e}"))?;

    // Bind our own endpoint, register, persist.
    let secret_path = data_dir.join("iroh.secret");
    let secret = load_or_create_secret(&secret_path)?;
    let ep = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::from_bytes(&secret))
        .bind()
        .await?;
    let client = TenantClient::new(ep);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
    let resp = client
        .register_tenant(host_eid, &root, &host_eid_bytes, now)
        .await?;
    match resp {
        TenantResponse::Register(r) if r.ok => {
            println!(
                "Paired with host {} (server_time={})",
                r.host_endpoint_id, r.server_time
            );
        }
        TenantResponse::Error(e) => {
            return Err(format!("host rejected: {:?} — {}", e.code, e.message).into());
        }
        other => return Err(format!("unexpected response: {other:?}").into()),
    }
    cfg.host = Some(HostConfig {
        peer_hints: vec![first],
        discovery_url: Some(discovery_url.to_string()),
    });
    std::fs::write(&cfg_path, toml::to_string_pretty(&cfg)?)?;
    println!("Host info persisted to {}", cfg_path.display());
    Ok(())
}

pub async fn topic_register(
    _data_dir: &Path,
    _topic: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("wires host topic-register: not implemented yet (Task 12)".into())
}

pub async fn topic_unregister(
    _data_dir: &Path,
    _topic: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("wires host topic-unregister: not implemented yet (Task 12)".into())
}

pub async fn status(_data_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Err("wires host status: not implemented yet (Task 13)".into())
}

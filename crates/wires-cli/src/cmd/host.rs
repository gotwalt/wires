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

async fn open_paired_client(
    data_dir: &Path,
) -> Result<(TenantClient, iroh::EndpointId, [u8; 32], SigningKey), Box<dyn std::error::Error>> {
    let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
    let host = cfg
        .host
        .as_ref()
        .ok_or("no host paired — run `wires host pair --discovery-url <URL>` first")?
        .clone();
    let first = host
        .peer_hints
        .first()
        .ok_or("paired host has no peer hints")?
        .clone();
    let host_eid_bytes: [u8; 32] = {
        let v = hex::decode(&first.node_id)?;
        if v.len() != 32 {
            return Err("host node_id not 32-byte hex".into());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    };
    let host_eid = iroh::EndpointId::from_bytes(&host_eid_bytes)
        .map_err(|e| format!("bad host endpoint id: {e}"))?;
    let root_bytes = std::fs::read(data_dir.join("root.ed25519"))?;
    let root = SigningKey::from_bytes(
        &root_bytes
            .try_into()
            .map_err(|_| "root.ed25519 not 32 bytes")?,
    );
    let secret = load_or_create_secret(&data_dir.join("iroh.secret"))?;
    let ep = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::from_bytes(&secret))
        .bind()
        .await?;
    Ok((TenantClient::new(ep), host_eid, host_eid_bytes, root))
}

fn parse_topic(data_dir: &Path, topic: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if let Ok(bytes) = hex::decode(topic)
        && bytes.len() == 32
    {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }
    let map_path = data_dir.join("topic_names.json");
    let map: std::collections::HashMap<String, String> =
        serde_json::from_str(&std::fs::read_to_string(map_path)?)?;
    let hex_id = map
        .get(topic)
        .ok_or_else(|| format!("unknown topic '{topic}'"))?;
    let bytes = hex::decode(hex_id)?;
    if bytes.len() != 32 {
        return Err("topic_names.json entry is not 32-byte hex".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

pub async fn topic_register(
    data_dir: &Path,
    topic: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let topic_id = parse_topic(data_dir, topic)?;
    let (client, host_eid, host_eid_bytes, root) = open_paired_client(data_dir).await?;
    let resp = client
        .register_topic(host_eid, &root, &topic_id, &host_eid_bytes, now_ms())
        .await?;
    match resp {
        TenantResponse::TopicRegister(r) if r.ok => {
            println!("Registered topic {}", hex::encode(r.topic_id));
            Ok(())
        }
        TenantResponse::Error(e) => {
            Err(format!("host rejected: {:?} — {}", e.code, e.message).into())
        }
        other => Err(format!("unexpected response: {other:?}").into()),
    }
}

pub async fn topic_unregister(
    data_dir: &Path,
    topic: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let topic_id = parse_topic(data_dir, topic)?;
    let (client, host_eid, host_eid_bytes, root) = open_paired_client(data_dir).await?;
    let resp = client
        .unregister_topic(host_eid, &root, &topic_id, &host_eid_bytes, now_ms())
        .await?;
    match resp {
        TenantResponse::TopicUnregister(r) if r.ok => {
            println!("Unregistered topic {}", hex::encode(r.topic_id));
            Ok(())
        }
        TenantResponse::Error(e) => {
            Err(format!("host rejected: {:?} — {}", e.code, e.message).into())
        }
        other => Err(format!("unexpected response: {other:?}").into()),
    }
}

pub async fn status(data_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let (client, host_eid, host_eid_bytes, root) = open_paired_client(data_dir).await?;
    let resp = client
        .tenant_status(host_eid, &root, &host_eid_bytes, now_ms())
        .await?;
    match resp {
        TenantResponse::Status(s) => {
            println!("Tenant status (as reported by host):");
            println!("  registered_at         : {}", s.registered_at);
            println!("  topic_count           : {}", s.topic_count);
            println!("  bytes_stored          : {}", s.bytes_stored);
            println!("  retention_budget      : {}", s.retention_budget_bytes);
            println!("  oldest_retained_at    : {}", s.oldest_retained_at);
            println!(
                "  write_rate_limit_per_sec : {}",
                s.write_rate_limit_per_sec
            );
            println!("  status                : {:?}", s.status);
            Ok(())
        }
        TenantResponse::Error(e) => {
            Err(format!("host rejected: {:?} — {}", e.code, e.message).into())
        }
        other => Err(format!("unexpected response: {other:?}").into()),
    }
}

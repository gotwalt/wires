//! `wires host *` subcommands. Each one loads the local root key from
//! `<data_dir>/root.ed25519`, opens a fresh iroh endpoint, dials a `TenantClient`,
//! and runs one request.

use std::path::Path;

use ed25519_dalek::SigningKey;
use iroh::{Endpoint, SecretKey, endpoint::presets};
use wires_net::tenant::{TenantClient, TenantResponse};
use wires_net::{endpoint_id_from_hex, fetch_endpoints, load_or_create_secret, unix_now_ms};
use wires_node::{HostConfig, NodeConfig, load_root_signing_key, resolve_topic};

pub async fn pair(data_dir: &Path, discovery_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Load existing config + root key.
    let cfg_path = data_dir.join("config.toml");
    let mut cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(&cfg_path)?)?;
    let root = load_root_signing_key(data_dir)?;

    // Fetch discovery; pick the first endpoint.
    let hints = fetch_endpoints(discovery_url).await?;
    let first = hints
        .first()
        .ok_or("discovery returned no endpoints")?
        .clone();
    let host_eid =
        endpoint_id_from_hex(&first.node_id).ok_or("discovery returned an invalid endpoint_id")?;
    let host_eid_bytes = *host_eid.as_bytes();

    // Bind our own endpoint, register, persist.
    let secret_path = data_dir.join("iroh.secret");
    let secret = load_or_create_secret(&secret_path)?;
    let ep = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::from_bytes(&secret))
        .bind()
        .await?;
    let client = TenantClient::new(ep);
    let resp = client
        .register_tenant(host_eid, &root, &host_eid_bytes, unix_now_ms())
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
    let host_eid = endpoint_id_from_hex(&first.node_id).ok_or("paired host has invalid node_id")?;
    let host_eid_bytes = *host_eid.as_bytes();
    let root = load_root_signing_key(data_dir)?;
    let secret = load_or_create_secret(&data_dir.join("iroh.secret"))?;
    let ep = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::from_bytes(&secret))
        .bind()
        .await?;
    Ok((TenantClient::new(ep), host_eid, host_eid_bytes, root))
}

pub async fn topic_register(
    data_dir: &Path,
    topic: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let topic_id = resolve_topic(data_dir, topic)?;
    let (client, host_eid, host_eid_bytes, root) = open_paired_client(data_dir).await?;
    let resp = client
        .register_topic(host_eid, &root, &topic_id, &host_eid_bytes, unix_now_ms())
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
    let topic_id = resolve_topic(data_dir, topic)?;
    let (client, host_eid, host_eid_bytes, root) = open_paired_client(data_dir).await?;
    let resp = client
        .unregister_topic(host_eid, &root, &topic_id, &host_eid_bytes, unix_now_ms())
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
        .tenant_status(host_eid, &root, &host_eid_bytes, unix_now_ms())
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

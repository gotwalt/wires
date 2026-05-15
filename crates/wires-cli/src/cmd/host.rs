//! `wires host *` subcommands. Each one loads the local root key from
//! `<data_dir>/root.ed25519`, opens a fresh iroh endpoint, dials a `TenantClient`,
//! and runs one request.

use std::path::Path;

use ed25519_dalek::SigningKey;
use iroh::{Endpoint, SecretKey, endpoint::presets};
use snafu::{ResultExt, location};
use wires_net::tenant::{TenantClient, TenantResponse};
use wires_net::{endpoint_id_from_hex, fetch_endpoints, load_or_create_secret, unix_now_ms};
use wires_node::{HostConfig, NodeConfig, load_root_signing_key, resolve_topic};

use crate::error::{
    CliError, HostRejectedSnafu, IoSnafu, NetSnafu, Result, TomlParseSnafu, TomlSerializeSnafu,
    UnexpectedResponseSnafu,
};
use crate::invalid;

pub async fn pair(data_dir: &Path, discovery_url: &str) -> Result<()> {
    let cfg_path = data_dir.join("config.toml");
    let raw = std::fs::read_to_string(&cfg_path).context(IoSnafu)?;
    let mut cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let root = load_root_signing_key(data_dir).context(IoSnafu)?;

    let hints = fetch_endpoints(discovery_url).await.context(NetSnafu)?;
    let first = hints
        .first()
        .ok_or_else(|| invalid!("discovery returned no endpoints"))?
        .clone();
    let host_eid = endpoint_id_from_hex(&first.node_id)
        .ok_or_else(|| invalid!("discovery returned an invalid endpoint_id"))?;
    let host_eid_bytes = *host_eid.as_bytes();

    let secret_path = data_dir.join("iroh.secret");
    let secret = load_or_create_secret(&secret_path).context(NetSnafu)?;
    let ep = bind_endpoint(secret).await?;
    let client = TenantClient::new(ep);
    let resp = client
        .register_tenant(host_eid, &root, &host_eid_bytes, unix_now_ms())
        .await
        .context(NetSnafu)?;
    match resp {
        TenantResponse::Register(r) if r.ok => {
            println!(
                "Paired with host {} (server_time={})",
                r.host_endpoint_id, r.server_time
            );
        }
        TenantResponse::Error(e) => return Err(host_rejected(e)),
        other => return unexpected(other),
    }
    cfg.host = Some(HostConfig {
        peer_hints: vec![first],
        discovery_url: Some(discovery_url.to_string()),
    });
    let toml_str = toml::to_string_pretty(&cfg).context(TomlSerializeSnafu)?;
    std::fs::write(&cfg_path, toml_str).context(IoSnafu)?;
    println!("Host info persisted to {}", cfg_path.display());
    Ok(())
}

async fn open_paired_client(
    data_dir: &Path,
) -> Result<(TenantClient, iroh::EndpointId, [u8; 32], SigningKey)> {
    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let host = cfg
        .host
        .as_ref()
        .ok_or_else(|| {
            invalid!("no host paired — run `wires host pair --discovery-url <URL>` first")
        })?
        .clone();
    let first = host
        .peer_hints
        .first()
        .ok_or_else(|| invalid!("paired host has no peer hints"))?
        .clone();
    let host_eid = endpoint_id_from_hex(&first.node_id)
        .ok_or_else(|| invalid!("paired host has invalid node_id"))?;
    let host_eid_bytes = *host_eid.as_bytes();
    let root = load_root_signing_key(data_dir).context(IoSnafu)?;
    let secret = load_or_create_secret(&data_dir.join("iroh.secret")).context(NetSnafu)?;
    let ep = bind_endpoint(secret).await?;
    Ok((TenantClient::new(ep), host_eid, host_eid_bytes, root))
}

async fn bind_endpoint(secret: [u8; 32]) -> Result<Endpoint> {
    Endpoint::builder(presets::N0)
        .secret_key(SecretKey::from_bytes(&secret))
        .bind()
        .await
        .map_err(|e| CliError::Endpoint {
            message: format!("bind: {e}"),
            location: location!(),
        })
}

pub async fn topic_register(data_dir: &Path, topic: &str) -> Result<()> {
    let topic_id = resolve_topic(data_dir, topic).context(IoSnafu)?;
    let (client, host_eid, host_eid_bytes, root) = open_paired_client(data_dir).await?;
    let resp = client
        .register_topic(host_eid, &root, &topic_id, &host_eid_bytes, unix_now_ms())
        .await
        .context(NetSnafu)?;
    match resp {
        TenantResponse::TopicRegister(r) if r.ok => {
            println!("Registered topic {}", hex::encode(r.topic_id));
            Ok(())
        }
        TenantResponse::Error(e) => Err(host_rejected(e)),
        other => unexpected(other),
    }
}

pub async fn topic_unregister(data_dir: &Path, topic: &str) -> Result<()> {
    let topic_id = resolve_topic(data_dir, topic).context(IoSnafu)?;
    let (client, host_eid, host_eid_bytes, root) = open_paired_client(data_dir).await?;
    let resp = client
        .unregister_topic(host_eid, &root, &topic_id, &host_eid_bytes, unix_now_ms())
        .await
        .context(NetSnafu)?;
    match resp {
        TenantResponse::TopicUnregister(r) if r.ok => {
            println!("Unregistered topic {}", hex::encode(r.topic_id));
            Ok(())
        }
        TenantResponse::Error(e) => Err(host_rejected(e)),
        other => unexpected(other),
    }
}

pub async fn status(data_dir: &Path) -> Result<()> {
    let (client, host_eid, host_eid_bytes, root) = open_paired_client(data_dir).await?;
    let resp = client
        .tenant_status(host_eid, &root, &host_eid_bytes, unix_now_ms())
        .await
        .context(NetSnafu)?;
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
        TenantResponse::Error(e) => Err(host_rejected(e)),
        other => unexpected(other),
    }
}

fn host_rejected(e: wires_net::tenant::TenantErrorResponse) -> CliError {
    HostRejectedSnafu {
        code: e.code,
        message: e.message,
    }
    .build()
}

fn unexpected(other: TenantResponse) -> Result<()> {
    Err(UnexpectedResponseSnafu {
        message: format!("{other:?}"),
    }
    .build())
}

//! `wires host *` subcommands. Each one loads the local root key from
//! `<data_dir>/root.ed25519`, opens a fresh iroh endpoint, dials a `TenantClient`,
//! and runs one request.

use std::path::Path;

use ed25519_dalek::SigningKey;
use iroh::{Endpoint, SecretKey};
use snafu::ResultExt;
use wires_net::tenant::{TenantClient, TenantResponse};
use wires_net::{endpoint_id_from_hex, load_or_create_secret, unix_now_ms};
use wires_node::{HostConfig, NodeConfig, load_root_signing_key, resolve_topic};
use tracing;

use crate::error::{
    CliError, HostRejectedSnafu, IoSnafu, NetSnafu, Result, TomlParseSnafu, TomlSerializeSnafu,
    UnexpectedResponseSnafu,
};
use crate::invalid;

pub async fn pair(data_dir: &Path, ticket_arg: &str) -> Result<()> {
    let cfg_path = data_dir.join("config.toml");
    let raw = std::fs::read_to_string(&cfg_path).context(IoSnafu)?;
    let mut cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let root = load_root_signing_key(data_dir).context(IoSnafu)?;

    let token = read_ticket_arg(ticket_arg)?;
    let ticket = wires_net::HostTicket::decode(&token).context(NetSnafu)?;
    let hint = ticket.to_peer_hint();
    let host_eid = endpoint_id_from_hex(&hint.node_id)
        .ok_or_else(|| invalid!("ticket carried an invalid endpoint_id"))?;
    let host_eid_bytes = *host_eid.as_bytes();

    let secret_path = data_dir.join("iroh.secret");
    let secret = load_or_create_secret(&secret_path).context(NetSnafu)?;
    let ep = bind_endpoint(secret).await?;
    register_hint_addrs(&ep, &hint);
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
        peer_hints: vec![hint],
        discovery_url: None,
    });
    let toml_str = toml::to_string_pretty(&cfg).context(TomlSerializeSnafu)?;
    std::fs::write(&cfg_path, toml_str).context(IoSnafu)?;
    println!("Host info persisted to {}", cfg_path.display());
    Ok(())
}

/// Accept either a raw base64 ticket or `@<path>` to read from a file.
fn read_ticket_arg(arg: &str) -> Result<String> {
    if let Some(path) = arg.strip_prefix('@') {
        let s = std::fs::read_to_string(path).context(IoSnafu)?;
        Ok(s.trim().to_string())
    } else {
        Ok(arg.trim().to_string())
    }
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
            invalid!("no host paired — run `wires host pair --ticket <STRING>` first")
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
    register_hint_addrs(&ep, &first);
    Ok((TenantClient::new(ep), host_eid, host_eid_bytes, root))
}

/// Register the addresses from a `PeerHint` into the endpoint's address-lookup
/// table so iroh can find the peer without falling back to pkarr/DNS. This is
/// equivalent to the `publish_helpers::register_peer_addresses` pattern used by
/// the gossip/replay path.
fn register_hint_addrs(ep: &Endpoint, hint: &wires_net::peer_hint::PeerHint) {
    let Some(id) = endpoint_id_from_hex(&hint.node_id) else {
        return;
    };
    let mut addrs: Vec<iroh::TransportAddr> = Vec::new();
    for s in &hint.addrs {
        match s.parse::<std::net::SocketAddr>() {
            Ok(sa) => addrs.push(iroh::TransportAddr::Ip(sa)),
            Err(e) => tracing::warn!(addr = %s, error = %e, "dropping unparseable peer addr"),
        }
    }
    if let Some(relay) = hint.relay.as_deref() {
        match relay.parse::<iroh::RelayUrl>() {
            Ok(url) => addrs.push(iroh::TransportAddr::Relay(url)),
            Err(e) => {
                tracing::warn!(relay = %relay, error = %e, "dropping unparseable relay URL")
            }
        }
    }
    if addrs.is_empty() {
        return;
    }
    let endpoint_addr = iroh::EndpointAddr::from_parts(id, addrs);
    if let Ok(lookup) = ep.address_lookup() {
        lookup.add(iroh::address_lookup::memory::MemoryLookup::from_endpoint_info(vec![
            endpoint_addr,
        ]));
    }
}

async fn bind_endpoint(secret: [u8; 32]) -> Result<Endpoint> {
    wires_net::bind_lan(SecretKey::from_bytes(&secret), vec![])
        .await
        .context(NetSnafu)
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

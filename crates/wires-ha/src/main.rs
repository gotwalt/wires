//! Home Assistant ingestion daemon.
//!
//! Connects to a Home Assistant WebSocket endpoint, subscribes to
//! `state_changed` events, and publishes each one onto a configured wires
//! topic. Participates in iroh-gossip and the replay protocol just like any
//! other wires agent, so peers see live messages and can pull history.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use iroh::{Endpoint, SecretKey, endpoint::presets};
use wires_net::{ALPN, load_or_create_secret};
use wires_node::{NetGlue, Node, NodeConfig};

mod ha;
mod ingest;

#[derive(Parser)]
#[command(
    name = "wires-ha",
    about = "Ingest Home Assistant state changes into a wires topic"
)]
struct Args {
    /// Wires data directory (must already be initialized with `wires init`).
    #[arg(long)]
    data_dir: PathBuf,

    /// Home Assistant WebSocket URL, e.g. ws://homeassistant.local:8123/api/websocket.
    #[arg(long)]
    ha_url: String,

    /// Path to a file containing a long-lived access token (whitespace stripped).
    #[arg(long)]
    token_file: PathBuf,

    /// Topic to publish to: human name (resolved via topic_names.json) or 64-char hex.
    #[arg(long)]
    topic: String,

    /// Capability id (32-char hex) authorizing writes to `--topic`.
    #[arg(long)]
    cap: String,

    /// Cap on the reconnect backoff between WebSocket sessions.
    #[arg(long, default_value = "60")]
    reconnect_secs_max: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();

    let cfg: NodeConfig =
        toml::from_str(&std::fs::read_to_string(args.data_dir.join("config.toml"))?)?;
    let node = Arc::new(Node::open(cfg.clone())?);

    let topic_id = resolve_topic(&args.data_dir, &args.topic)?;
    let cap_id = decode_hex_16(&args.cap)?;
    let access_token = std::fs::read_to_string(&args.token_file)?
        .trim()
        .to_string();
    if access_token.is_empty() {
        return Err("token file is empty".into());
    }

    let secret = load_or_create_secret(&args.data_dir.join("iroh.secret"))?;
    let iroh_sk = SecretKey::from_bytes(&secret);
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(iroh_sk)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;
    let endpoint_id = endpoint.id();
    tracing::info!(%endpoint_id, "wires-ha endpoint bound");

    // If this agent is paired with a host, register the target topic so the
    // host actually persists what we publish.
    if let Some(host) = cfg.host.as_ref()
        && let Some(first) = host.peer_hints.first()
    {
        match register_topic_best_effort(&endpoint, first, &topic_id, &args.data_dir).await {
            Ok(()) => tracing::info!(topic = %hex::encode(topic_id), "host topic-register OK"),
            Err(e) => {
                tracing::warn!(error = %e, "host topic-register failed; continuing peer-to-peer")
            }
        }
    }

    let glue = NetGlue::new(endpoint.clone(), Arc::clone(&node.logs)).await?;
    let gossip = glue
        .subscribe_and_route(Arc::clone(&node), topic_id, vec![])
        .await?;

    let ingest_node = Arc::clone(&node);
    let ingest_handle = tokio::spawn(ingest::run(
        ingest_node,
        gossip,
        topic_id,
        cap_id,
        args.ha_url,
        access_token,
        Duration::from_secs(args.reconnect_secs_max),
    ));

    tracing::info!(
        topic = %hex::encode(topic_id),
        "wires-ha running; Ctrl-C to exit"
    );
    tokio::signal::ctrl_c().await?;
    ingest_handle.abort();
    // Keep `glue` alive until shutdown so the replay router and gossip task
    // stay registered for the lifetime of the process.
    drop(glue);
    Ok(())
}

fn resolve_topic(
    data_dir: &Path,
    topic: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(bytes) = hex::decode(topic)
        && bytes.len() == 32
    {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }
    let map_path = data_dir.join("topic_names.json");
    let map: HashMap<String, String> = serde_json::from_str(&std::fs::read_to_string(map_path)?)?;
    let hex_id = map
        .get(topic)
        .ok_or_else(|| format!("unknown topic '{topic}'"))?;
    let bytes = hex::decode(hex_id)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_hex_16(s: &str) -> Result<[u8; 16], Box<dyn std::error::Error + Send + Sync>> {
    let bytes = hex::decode(s)?;
    if bytes.len() != 16 {
        return Err("cap_id must be 16 bytes (32 hex chars)".into());
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

async fn register_topic_best_effort(
    endpoint: &Endpoint,
    hint: &wires_net::PeerHint,
    topic_id: &[u8; 32],
    data_dir: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bytes = hex::decode(&hint.node_id)?;
    if bytes.len() != 32 {
        return Err("host node_id not 32-byte hex".into());
    }
    let arr: [u8; 32] = bytes.as_slice().try_into().unwrap();
    let host_eid = iroh::EndpointId::from_bytes(&arr)?;
    let root_bytes = std::fs::read(data_dir.join("root.ed25519"))?;
    if root_bytes.len() != 32 {
        return Err("root.ed25519 must be 32 bytes".into());
    }
    let root = ed25519_dalek::SigningKey::from_bytes(&root_bytes.try_into().unwrap());
    let client = wires_net::tenant::TenantClient::new(endpoint.clone());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;
    let resp = client
        .register_topic(host_eid, &root, topic_id, &arr, now)
        .await?;
    match resp {
        wires_net::tenant::TenantResponse::TopicRegister(r) if r.ok => Ok(()),
        other => Err(format!("host responded: {other:?}").into()),
    }
}

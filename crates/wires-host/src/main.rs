//! Blind relay/replay-server binary.
//!
//! Holds no root key, no epoch keys, no capabilities. Subscribes to topics
//! it's told about (`--topic <hex>`), persists ciphertext envelopes, and
//! serves the replay RPC for any client that has read rights.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use iroh::{endpoint::presets, Endpoint, SecretKey};
use wires_core::WireMessage;
use wires_net::{load_or_create_secret, GossipNode, ReplayProtocol, ALPN};
use wires_node::TopicLogs;

#[derive(Parser)]
#[command(name = "wires-host", about = "Blind relay/replay-server for the wires network")]
struct Args {
    #[arg(long)]
    data_dir: PathBuf,
    /// 32-byte hex topic_id to relay. May be specified multiple times.
    #[arg(long = "topic", value_name = "HEX")]
    topics: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    std::fs::create_dir_all(&args.data_dir)?;

    // iroh identity
    let secret_path = args.data_dir.join("iroh.secret");
    let secret = load_or_create_secret(&secret_path)?;
    let iroh_sk = SecretKey::from_bytes(&secret);
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(iroh_sk)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;
    let endpoint_id = endpoint.id();
    println!("wires-host: EndpointId = {endpoint_id}");

    // Storage + protocols
    let logs: Arc<TopicLogs> = Arc::new(TopicLogs::new(&args.data_dir));
    let gossip = GossipNode::new(endpoint.clone()).await?;
    let replay_protocol = ReplayProtocol::new(Arc::clone(&logs));

    // Register replay ALPN on the router. (GossipNode internally registers the gossip ALPN.)
    let _router = iroh::protocol::Router::builder(endpoint.clone())
        .accept(ALPN, replay_protocol)
        .spawn();

    // Subscribe to each topic, persist ciphertext on receipt
    for topic_hex in &args.topics {
        let bytes = hex::decode(topic_hex)?;
        if bytes.len() != 32 {
            return Err(format!("bad topic id (must be 32 bytes hex): {topic_hex}").into());
        }
        let mut topic_id = [0u8; 32];
        topic_id.copy_from_slice(&bytes);

        let logs_clone = Arc::clone(&logs);
        let (_handle, mut rx) = gossip.join(topic_id, vec![]).await?;
        tokio::spawn(async move {
            while let Some(bytes) = rx.recv().await {
                let msg: WireMessage = match serde_json::from_slice(&bytes) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::warn!(error = %e, "bad gossip frame at host");
                        continue;
                    }
                };
                // Host-layer coarse enforcement: only check signature. ACL
                // verification happens at the receiving agent on decrypt.
                if wires_core::verify_envelope(&msg).is_err() {
                    tracing::warn!("dropped unsigned/bad envelope at host");
                    continue;
                }
                let log = match logs_clone.get_or_open(&topic_id) {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::warn!(error = %e, "host failed to open log");
                        continue;
                    }
                };
                if let Err(e) = log.append(&msg) {
                    tracing::warn!(error = %e, "host append failed");
                }
            }
            tracing::info!("gossip receiver for topic {} closed", hex::encode(topic_id));
        });
        println!("wires-host: relaying topic {}", hex::encode(topic_id));
    }

    println!("wires-host: running. Press Ctrl-C to exit.");
    tokio::signal::ctrl_c().await?;
    Ok(())
}

//! Blind multi-tenant relay/replay-server. Topics arrive dynamically via the
//! tenant control protocol; no `--topic` flags.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use iroh::{Endpoint, SecretKey, endpoint::presets};
use tokio::sync::mpsc;
use wires_core::WireMessage;
use wires_host::http_discovery::{self, DiscoveryEndpoint, DiscoveryResponse, DiscoveryState};
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::replay_source::PerTenantReplaySource;
use wires_host::retention::Retention;
use wires_host::routing::{Router as MsgRouter, WriteRateLimiter};
use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
use wires_net::replay::{ALPN as REPLAY_ALPN, ReplayProtocol};
use wires_net::tenant::{ALPN as TENANT_ALPN, TenantProtocol};
use wires_net::{GossipNode, load_or_create_secret};

#[derive(Parser)]
#[command(
    name = "wires-host",
    about = "Blind multi-tenant relay for the wires network"
)]
struct Args {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long, default_value = "0.0.0.0:8443")]
    discovery_addr: SocketAddr,
    /// Public URL the discovery service advertises (e.g. https://wires.example).
    /// If omitted, defaults to `http://<discovery_addr>` (testing).
    #[arg(long)]
    public_url: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    std::fs::create_dir_all(&args.data_dir)?;

    // iroh identity ---------------------------------------------------------
    let secret_path = args.data_dir.join("iroh.secret");
    let secret = load_or_create_secret(&secret_path)?;
    let iroh_sk = SecretKey::from_bytes(&secret);
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(iroh_sk)
        .alpns(vec![TENANT_ALPN.to_vec(), REPLAY_ALPN.to_vec()])
        .bind()
        .await?;
    let endpoint_id = endpoint.id();
    let endpoint_id_bytes: [u8; 32] = endpoint_id.as_bytes().to_owned();
    println!("wires-host: EndpointId = {endpoint_id}");

    // Storage + state -------------------------------------------------------
    let registry = Arc::new(TenantRegistry::open(&args.data_dir)?);
    let logs = Arc::new(PerTenantLogs::new(&args.data_dir));
    let retention = Arc::new(Retention::new(&args.data_dir, Arc::clone(&logs)));
    let rate = Arc::new(WriteRateLimiter::new(1_000));
    let router_state = Arc::new(MsgRouter::new(
        Arc::clone(&registry),
        Arc::clone(&logs),
        Arc::clone(&retention),
        Arc::clone(&rate),
    ));

    // Gossip + dynamic subscribe channel -----------------------------------
    let gossip = GossipNode::new(endpoint.clone()).await?;
    let (subscribe_tx, mut subscribe_rx) = mpsc::unbounded_channel::<[u8; 32]>();

    // Spawn subscriber dispatcher: when the handler tells us about a new
    // topic, join it.
    let gossip_for_subscribe = gossip.clone_for_subscribe();
    {
        let router_state = Arc::clone(&router_state);
        tokio::spawn(async move {
            while let Some(topic_id) = subscribe_rx.recv().await {
                let (_handle, mut rx) = match gossip_for_subscribe.join(topic_id, vec![]).await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, topic = %hex::encode(topic_id), "gossip join failed");
                        continue;
                    }
                };
                let router_state = Arc::clone(&router_state);
                tokio::spawn(async move {
                    while let Some(bytes) = rx.recv().await {
                        let msg: WireMessage = match serde_json::from_slice(&bytes) {
                            Ok(m) => m,
                            Err(e) => {
                                tracing::warn!(error = %e, "bad gossip frame");
                                continue;
                            }
                        };
                        if wires_core::verify_envelope(&msg).is_err() {
                            tracing::warn!("dropped unsigned/bad envelope at host");
                            continue;
                        }
                        if let Err(e) = router_state.route(&msg) {
                            tracing::warn!(error = %e, "router error");
                        }
                    }
                });
            }
        });
    }

    // Tenant handler --------------------------------------------------------
    let subscribe_tx_clone = subscribe_tx.clone();
    let handler = Arc::new(TenantHandlerImpl {
        registry: Arc::clone(&registry),
        retention: Arc::clone(&retention),
        host_endpoint_id: endpoint_id_bytes,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(|| {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64
        }),
        on_topic_registered: Arc::new(move |_root, topic| {
            let _ = subscribe_tx_clone.send(topic);
        }),
        on_topic_unregistered: Arc::new(|_root, _topic| {
            // v1: subscription stays live; future spec adds a teardown signal.
        }),
    });

    // Register ALPNs --------------------------------------------------------
    let replay_protocol = ReplayProtocol::new(Arc::new(PerTenantReplaySource::new(
        Arc::clone(&registry),
        Arc::clone(&logs),
    )));
    let _router = iroh::protocol::Router::builder(endpoint.clone())
        .accept(REPLAY_ALPN, replay_protocol)
        .accept(TENANT_ALPN, TenantProtocol::new(Arc::clone(&handler)))
        .spawn();

    // HTTPS discovery -------------------------------------------------------
    let public_url = args
        .public_url
        .unwrap_or_else(|| format!("http://{}", args.discovery_addr));
    let discovery_state = Arc::new(DiscoveryState {
        response: DiscoveryResponse {
            version: 1,
            endpoints: vec![DiscoveryEndpoint {
                endpoint_id: hex::encode(endpoint_id_bytes),
                relay: None,
                addrs: vec![],
            }],
            ttl_seconds: 300,
        },
    });
    let discovery_app = http_discovery::router(discovery_state);
    let listener = tokio::net::TcpListener::bind(args.discovery_addr).await?;
    let actual_addr = listener.local_addr()?;
    tokio::spawn(async move {
        axum::serve(listener, discovery_app).await.ok();
    });
    println!("wires-host: discovery listening at {actual_addr} (public={public_url})");
    println!("wires-host: running. Press Ctrl-C to exit.");
    tokio::signal::ctrl_c().await?;
    Ok(())
}

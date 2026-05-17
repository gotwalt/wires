//! Blind multi-tenant relay/replay-server. Topics arrive dynamically via the
//! tenant control protocol; no `--topic` flags.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use humantime;
use iroh::SecretKey;
use tokio::sync::mpsc;
use wires_core::WireMessage;
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::replay_source::PerTenantReplaySource;
use wires_host::retention::Retention;
use wires_host::routing::{Router as MsgRouter, WriteRateLimiter};
use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
use wires_net::replay::{ALPN as REPLAY_ALPN, ReplayProtocol};
use wires_net::tenant::{ALPN as TENANT_ALPN, TenantProtocol};
use wires_net::{GOSSIP_ALPN, GossipNode, load_or_create_secret, unix_now_ms};

#[derive(Parser)]
#[command(
    name = "wires-host",
    about = "Blind multi-tenant relay for the wires network"
)]
struct Args {
    #[arg(long)]
    data_dir: PathBuf,

    /// TTL after which a ticket's addrs/relay are considered stale by
    /// consumers. The `endpoint_id` itself never expires.
    #[arg(long, global = true, default_value = "7d")]
    ticket_hint_ttl: humantime::Duration,
    /// Force-emit a terminal QR of the host ticket even if stderr is not a TTY.
    #[arg(long, global = true, conflicts_with = "no_qr")]
    qr: bool,
    /// Suppress terminal QR emission even if stderr is a TTY.
    #[arg(long, global = true)]
    no_qr: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Print the host's discovery ticket (base64 to stdout, optional QR to stderr) and exit.
    Ticket,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    std::fs::create_dir_all(&args.data_dir)?;

    if matches!(args.command, Some(Command::Ticket)) {
        run_ticket_subcommand(&args).await?;
        return Ok(());
    }

    // iroh identity ---------------------------------------------------------
    let secret_path = args.data_dir.join("iroh.secret");
    let secret = load_or_create_secret(&secret_path)?;
    let endpoint = wires_net::bind_cloud(
        SecretKey::from_bytes(&secret),
        vec![
            GOSSIP_ALPN.to_vec(),
            TENANT_ALPN.to_vec(),
            REPLAY_ALPN.to_vec(),
        ],
    )
    .await?;
    let endpoint_id = endpoint.id();
    let endpoint_id_bytes: [u8; 32] = endpoint_id.as_bytes().to_owned();
    println!("wires-host: EndpointId = {endpoint_id}");

    // Emit the host ticket on every startup. Operators copy/scan; TTY runs
    // additionally get a QR rendered to stderr.
    {
        use std::io::IsTerminal as _;
        let ticket = wires_net::HostTicket::from_endpoint(&endpoint, *args.ticket_hint_ttl)?;
        let encoded = ticket.encode()?;
        tracing::info!("host ticket: {encoded}");
        let show_qr = args.qr || (!args.no_qr && std::io::stderr().is_terminal());
        if show_qr {
            let art = ticket.render_qr_ansi()?;
            eprintln!();
            eprintln!("{art}");
        }
    }

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
    let (gossip, gossip_handler) = GossipNode::new_without_router(endpoint.clone()).await?;
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
                        // ed25519 verify + redb write transactions; off the
                        // tokio worker so a slow disk doesn't stall every
                        // other topic's receive loop on the same thread.
                        let router_state = Arc::clone(&router_state);
                        let res = tokio::task::spawn_blocking(move || {
                            let msg: WireMessage = match serde_json::from_slice(&bytes) {
                                Ok(m) => m,
                                Err(e) => {
                                    tracing::warn!(error = %e, "bad gossip frame");
                                    return;
                                }
                            };
                            if wires_core::verify_envelope(&msg).is_err() {
                                tracing::warn!("dropped unsigned/bad envelope at host");
                                return;
                            }
                            if let Err(e) = router_state.route(&msg) {
                                tracing::warn!(error = %e, "router error");
                            }
                        })
                        .await;
                        if let Err(e) = res {
                            tracing::error!(error = %e, "host inbound task panicked");
                        }
                    }
                });
            }
        });
    }

    // Resubscribe to every topic persisted in topic_index before any control
    // RPC can arrive. Otherwise a restarted host stays silent until each
    // tenant re-issues `topic-register`.
    for topic_id in registry.all_topic_ids()? {
        let _ = subscribe_tx.send(topic_id);
    }

    // Tenant handler --------------------------------------------------------
    let subscribe_tx_clone = subscribe_tx.clone();
    let handler = Arc::new(TenantHandlerImpl {
        registry: Arc::clone(&registry),
        retention: Arc::clone(&retention),
        host_endpoint_id: endpoint_id_bytes,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(unix_now_ms),
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
        .accept(GOSSIP_ALPN, gossip_handler)
        .accept(REPLAY_ALPN, replay_protocol)
        .accept(TENANT_ALPN, TenantProtocol::new(Arc::clone(&handler)))
        .spawn();

    println!("wires-host: running. Press Ctrl-C to exit.");
    tokio::signal::ctrl_c().await?;
    Ok(())
}

async fn run_ticket_subcommand(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::IsTerminal as _;

    let secret_path = args.data_dir.join("iroh.secret");
    let secret = load_or_create_secret(&secret_path)?;
    let endpoint = wires_net::bind_cloud(SecretKey::from_bytes(&secret), vec![]).await?;
    let ticket = wires_net::HostTicket::from_endpoint(&endpoint, *args.ticket_hint_ttl)?;
    let encoded = ticket.encode()?;
    println!("{encoded}");
    let show_qr = args.qr || (!args.no_qr && std::io::stderr().is_terminal());
    if show_qr {
        let art = ticket.render_qr_ansi()?;
        eprintln!();
        eprintln!("{art}");
    }
    Ok(())
}

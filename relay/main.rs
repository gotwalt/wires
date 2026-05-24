//! `relay` — a self-hosted iroh rendezvous server.
//!
//! Wraps `iroh-relay`'s server so two egress-only wires nodes with no inbound
//! reachability can find a path without depending on n0's public relays — the
//! piece a private / air-gapped network self-hosts.
//!
//! This runs the relay in **plain-HTTP** mode (no TLS): terminate TLS at a load
//! balancer / ingress, or run it inside a trusted network. Point a node at it
//! with `iroh`'s `RelayMode::Custom` (see the deployment docs).

use std::net::SocketAddr;

use anyhow::{Context, Result};
use clap::Parser;
use iroh_relay::server::{AccessConfig, Limits, RelayConfig, Server, ServerConfig};

/// relay: self-hosted rendezvous for egress-only nodes.
#[derive(Parser)]
#[command(name = "relay", version, about)]
struct Cli {
    /// Address to bind the plain-HTTP relay endpoint on.
    #[arg(long, default_value = "0.0.0.0:3340")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let relay = RelayConfig::<(), ()> {
        http_bind_addr: cli.listen,
        tls: None,
        limits: Limits::default(),
        key_cache_capacity: None,
        access: AccessConfig::Everyone,
    };
    let config = ServerConfig::<(), ()> {
        relay: Some(relay),
        quic: None,
        metrics_addr: None,
    };

    let mut server = Server::spawn(config)
        .await
        .context("starting the relay server")?;
    match server.http_addr() {
        Some(addr) => tracing::info!("wires relay listening on http://{addr}"),
        None => tracing::warn!("relay started without an HTTP address"),
    }

    // Run until the supervisor task ends (or the process is signalled).
    server
        .task_handle()
        .await
        .context("relay supervisor task")??;
    Ok(())
}

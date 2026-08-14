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
use iroh_relay::server::{RelayConfig, Server, ServerConfig};

/// relay: self-hosted rendezvous for egress-only nodes.
#[derive(Parser)]
#[command(name = "relay", version, about)]
struct Cli {
    /// Address to bind the plain-HTTP relay endpoint on.
    #[arg(long, default_value = "0.0.0.0:3340")]
    listen: SocketAddr,
}

/// Build the plain-HTTP relay server config bound to `listen`. Factored out so
/// it can be exercised in tests.
///
/// `RelayConfig::new` supplies exactly the posture we want: no TLS, default
/// rate limits, no key cache bound, and `AllowAll` access control. QUIC address
/// discovery and the metrics endpoint stay disabled.
fn server_config(listen: SocketAddr) -> ServerConfig {
    // `ServerConfig` and `RelayConfig` are `#[non_exhaustive]`, so they can only
    // be built through `Default` / `new` and then adjusted field by field.
    #[allow(clippy::field_reassign_with_default)]
    let mut config = ServerConfig::default();
    config.relay = Some(RelayConfig::new(listen));
    config
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

    let mut server = Server::spawn(server_config(cli.listen))
        .await
        .context("starting the relay server")?;
    match server.http_addr() {
        Some(addr) => tracing::info!("wires relay listening on http://{addr}"),
        None => tracing::warn!("relay started without an HTTP address"),
    }

    // Run until the supervisor task ends (or the process is signalled).
    server.join().await.context("relay supervisor task")??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The config actually spawns a relay that binds and reports an address.
    #[tokio::test]
    async fn server_binds_and_reports_an_address() {
        let listen = "127.0.0.1:0".parse().unwrap();
        let server = Server::spawn(server_config(listen)).await.unwrap();
        assert!(server.http_addr().is_some());
        server.shutdown().await.ok();
    }
}

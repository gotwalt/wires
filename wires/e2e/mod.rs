//! The integration tests: the whole stack — signed state, the `Hello`
//! handshake, the registry gate, exec and the stdio bridge, push — driven
//! over hermetic loopback QUIC.
//!
//! Every endpoint here binds with
//! [`presets::Minimal`](iroh::endpoint::presets::Minimal): no DNS, no pkarr,
//! no relay, nothing that leaves the machine. Peers find each other through
//! address hints over loopback ([`localhost_socks`]).
//!
//! - [`services_host`] — card 27's acceptance: a `host.json` v2 host decides
//!   every call by the admin-signed state (the registry's roles,
//!   `also_require`, removal with no restart, refusing unassigned services,
//!   push by the state), and nothing is broadcast to a bystander.
//! - [`records`] — card 26b: call records streamed from the host's own log
//!   to authorized readers (`wires watch`).
//! - [`gateway`] — `wires gateway`: a web MCP client signs in (OAuth, a mock
//!   Google) and calls as its user, over real HTTP.

use std::net::SocketAddr;
use std::time::Duration;

use iroh::Endpoint;

/// Card 27's host side: a `host.json` v2 host decides by the signed state.
mod services_host;

/// Card 26b: call records streamed from the host's log to authorized readers.
mod records;

/// `wires gateway`: OAuth sign-in and MCP over HTTP, end to end.
mod gateway;

/// The outer bound on any single wait here: generous, and never reached in
/// the passing case (every wait is on an event, not a clock).
const PATIENCE: Duration = Duration::from_secs(30);

/// The endpoint's bound sockets with wildcard binds rewritten to localhost, so a
/// hint reaches it with no discovery service (the `transport.rs` idiom).
fn localhost_socks(endpoint: &Endpoint) -> Vec<SocketAddr> {
    endpoint
        .bound_sockets()
        .into_iter()
        .map(|sock| match sock {
            SocketAddr::V4(v4) if v4.ip().is_unspecified() => SocketAddr::V4(
                std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, v4.port()),
            ),
            SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
                SocketAddr::V6(std::net::SocketAddrV6::new(
                    std::net::Ipv6Addr::LOCALHOST,
                    v6.port(),
                    v6.flowinfo(),
                    v6.scope_id(),
                ))
            }
            other => other,
        })
        .collect()
}

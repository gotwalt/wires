//! The **host** role: runs CLIs and decides what is exposed and who may call.
//!
//! A host is `wires serve host.json`: it binds the session ALPN (or rides its
//! channel's node), verifies every caller — fabric inclusion, the roster
//! head — then asks its policy (`host.json`'s roles) whether *this* caller
//! may run *this* tool, execs it and bridges its stdio. Every call, refusal,
//! and exit is published to the channel by the host itself, stamped with the
//! identity it verified and the role that admitted it.
//!
//! - [`serve`] — `wires serve host.json` / `--check`: credentials, the channel.
//! - [`config`] — `host.json`: parsing, validation, the `--check` summary.
//! - [`policy`] — the [`Policy`](policy::Policy) seam and v1's role table.
//! - [`transport`] — the session protocol: bind/dial, the handshake, the
//!   credential checks and the policy call (`authorize`), exec + stdio bridge.
//! - [`audit`] — the call records the host publishes to its channel.
//! - [`identity`] — the index of verified IdP claims and the per-call lookup.
//!
//! Where what comes next lands: announcing the host's tools on the channel in
//! `announce.rs` (card 15), filtered per member by
//! [`Policy::allowed_tools`](policy::Policy::allowed_tools).

pub mod audit;
pub mod config;
pub mod identity;
pub mod policy;
pub mod serve;
pub mod transport;

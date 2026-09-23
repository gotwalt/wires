//! The **host** role: runs CLIs and decides what is exposed and who may call.
//!
//! A host is `wires serve`: it binds the session ALPN (or rides its audit
//! topic's node), verifies every caller — fabric inclusion, the roster head,
//! a tool grant, and the IdP policy — then execs the invoked tool and bridges
//! its stdio. Every call, refusal, and exit is published to the audit channel
//! by the host itself, stamped with the identity it verified.
//!
//! - [`serve`] — `wires serve`: flags, credentials, the audit channel.
//! - [`transport`] — the session protocol: bind/dial, the handshake, the
//!   credential checks (`authorize`), exec + stdio bridge.
//! - [`audit`] — the call records the host publishes to its audit topic.
//! - [`identity`] — the index of verified IdP claims and the per-call gate.
//! - [`idp_policy`] — `--require-idp` rules.
//!
//! Where what comes next lands: `host.json` parsing in `config.rs` and the
//! `Policy` seam in `policy.rs` (card 13); announcing the host's tools on the
//! channel in `announce.rs` (card 15).

pub mod audit;
pub mod identity;
pub mod idp_policy;
pub mod serve;
pub mod transport;

//! The **channel**: the end-to-end encrypted gossip topic every role meets on.
//!
//! Hosts publish call records to it, callers publish identity claims to it,
//! and observers (`wires watch`) read it — holding neither the caller's nor
//! the host's credentials. A member node here stores, admits, replays and
//! renders; nothing in this folder knows what a tool is.
//!
//! - [`watch`] — `wires watch`: the resident node's loop (also the loop
//!   `serve --audit-topic` runs its channel on).
//! - [`publish`] — `wires advanced publish`, through the resident node or
//!   one-shot.
//! - [`context`] — the topic arguments and the credentials resolved for them.
//! - [`local`] — this node's own log: open it, pick the key, mint a message.
//! - [`printer`] — the keyring that opens envelopes and the line printer.
//! - [`peers`] — the persisted peer hints.
//! - [`topics`] — the resident topic node: endpoint, gossip, admission and
//!   replay handlers.
//! - [`admission`] — the roster gate in front of the mesh, and its watchdog.
//! - [`replay`] — peer-symmetric catch-up.
//! - [`store`] — the per-topic redb log (the single sequence allocator).
//! - [`ipc`] — the control socket a resident node takes publishes on.
//! - [`render`] — how call records and identity claims print.
//! - [`idp_view`] — which issuers/audiences a reader trusts, and how a
//!   verified identity prints.
//!
//! Where what comes next lands: re-key distribution (card 14) and the host
//! announcement / tool directory records (card 15).

pub mod admission;
pub mod context;
pub mod idp_view;
pub mod ipc;
pub mod local;
pub mod peers;
pub mod printer;
pub mod publish;
pub mod render;
pub mod replay;
pub mod store;
pub mod topics;
pub mod watch;

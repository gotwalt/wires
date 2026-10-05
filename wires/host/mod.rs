//! The **host** role: implements the services the signed policy assigns to it.
//!
//! A host is `wires serve host.json`: `host.json` (version 2) says how each
//! service runs here; the admin-signed policy says who may call it. Every
//! call is decided by the policy as it stands at that connection — the
//! caller's ID token, the bans and a role that admits it, the policy's roles
//! for the service, then any stricter local rule — and traced by the host as one ordinary log
//! line.
//!
//! - [`serve`] — `wires serve host.json` / `--check`: preflight, bind, serve.
//! - [`config`] — `host.json` (services it implements, local trust,
//!   `also_require`).
//! - [`gate`] — the call gate over the signed policy, and the
//!   [`ServicesHost`](gate::ServicesHost) a host decides with.
//! - [`transport`] — the session protocol: bind/dial, the `Hello`, exec and
//!   the stdio bridge.
//! - [`service`] — what the bridge runs for one call: anything with stdio
//!   and an exit code.
//! - [`native`] — services an app implements in-process (card 33): the
//!   public [`Service`](native::Service) trait and what a handler gets.
//! - [`embed`] — the public [`Host`](embed::Host) an app builds and serves.
//! - [`follow`] — the host's subscription to a directory: the whole policy
//!   per edit (card 45), and a `Fresh` every beat.
//! - [`freshness`] — the newest `Fresh` per directory for the held head
//!   (`fresh.json`): what the host shows a caller first (card 49).
//! - [`identity`] — the ID tokens callers presented, verified and indexed.
//! - [`call_trace`] — the one `tracing` line a call (or an admitted
//!   caller's refusal) leaves in `serve`'s output.
//! - [`push`] — `wires push`: messages to callers by key, queued, delivered
//!   or fetched, gated by the signed policy and `push.allow` (card 23).
//! - [`control`] — the local sockets `wires push` hands a push to `serve` on.
//! - [`capability`] — the per-call push token a service child gets instead of
//!   the host's keystore: it pushes only to that call's caller.

pub mod call_trace;
pub mod capability;
pub mod config;
pub mod control;
pub mod embed;
pub mod follow;
pub mod freshness;
pub mod gate;
pub mod identity;
pub mod native;
pub mod push;
pub mod serve;
pub mod service;
pub mod transport;

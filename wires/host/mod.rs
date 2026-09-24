//! The **host** role: implements the services the signed state assigns to it.
//!
//! A host is `wires serve host.json`: `host.json` (version 2) says how each
//! service runs here; the admin-signed state says who may call it. Every
//! call is decided by the state as it stands at that connection — membership,
//! the registry's role for the service, then any stricter local rule — and
//! logged by the host itself in its own signed call log.
//!
//! - [`serve`] — `wires serve host.json` / `--check`: preflight, bind, serve.
//! - [`config_v2`] — `host.json` v2 (services it implements, local trust,
//!   `also_require`).
//! - [`gate`] — the call gate over the signed state, and the
//!   [`ServicesHost`](gate::ServicesHost) a host decides with.
//! - [`transport`] — the session protocol: bind/dial, the `Hello`, exec and
//!   the stdio bridge.
//! - [`identity`] — the ID tokens callers presented, verified and indexed.
//! - [`audit`] — the call records the host keeps.
//! - [`call_log`] — the host's own signed, hash-linked log of those records,
//!   on disk with retention (card 26a).
//! - [`otlp`] — optional OTLP/HTTP export of that log (`audit.otlp`).
//! - [`push`] — `wires push`: messages to callers by key, queued, delivered
//!   or fetched, gated by the signed state and `push.allow` (card 23).
//! - [`control`] — the local sockets `wires push` hands a push to `serve` on.
//! - [`capability`] — the per-call push token a service child gets instead of
//!   the host's keystore: it pushes only to that call's caller.

pub mod audit;
pub mod call_log;
pub mod capability;
pub mod config_v2;
pub mod control;
pub mod gate;
pub mod identity;
pub mod otlp;
pub mod push;
pub mod record_stream;
pub mod serve;
pub mod transport;

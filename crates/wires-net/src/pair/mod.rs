//! Responder-driven pairing — ALPN `/wires/pair/0`.
//!
//! See `docs/superpowers/specs/2026-05-15-wires-responder-driven-pairing-design.md`.

pub mod client;
pub mod frames;
pub mod grant;
pub mod protocol;
pub mod request;

pub use client::PairClient;
pub use frames::{PairAck, PairFrame, PairReject, PairRejectCode};
pub use grant::{HostInfo, PairGrant, PairGrantEnvelope, TopicEpochKey, TopicNameEntry};
pub use protocol::{PairHandler, PairProtocol};
pub use request::{PairDial, PairManifest, PairRequest, RequestedScope};

pub const ALPN: &[u8] = b"/wires/pair/0";

/// Per-frame size cap for `/wires/pair/0`. Bounds the inbound allocation per
/// stream so a malicious dialer can't claim a 4 GiB Grant frame.
pub const MAX_FRAME_LEN: u32 = 64 * 1024;

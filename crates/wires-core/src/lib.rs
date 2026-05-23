//! `wires-core`: shared types for the wires session layer.
//!
//! This is a structural scaffold. The module layout mirrors the "Shared
//! mechanics" in `docs/new_plan.md` (identity, grant/capability, session
//! protocol, policy), but the types are placeholders — real crypto, the iroh
//! transport, and the session protocol land in later steps.

pub mod error;
pub mod grant;
pub mod identity;
pub mod policy;
pub mod session;
pub mod ticket;

pub use error::{Error, Result};

/// Crate version, surfaced so the binaries have something concrete to call
/// while the real surface is still being built out.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

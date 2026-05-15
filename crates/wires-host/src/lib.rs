//! Library crate for `wires-host`. The binary entry point lives in `main.rs`
//! and delegates here. Tests in `crates/wires-host/tests/` consume this lib.

pub mod error;
pub mod http_discovery;
pub mod per_tenant_logs;
pub mod replay_source;
pub mod retention;
pub mod routing;
pub mod tenant_registry;

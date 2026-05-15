//! `wires host *` subcommands. Each one loads the local root key from
//! `<data_dir>/root.ed25519`, opens a fresh iroh endpoint, dials a `TenantClient`,
//! and runs one request.

use std::path::Path;

pub async fn pair(
    _data_dir: &Path,
    _discovery_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("wires host pair: not implemented yet".into())
}

pub async fn topic_register(
    _data_dir: &Path,
    _topic: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("wires host topic-register: not implemented yet".into())
}

pub async fn topic_unregister(
    _data_dir: &Path,
    _topic: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("wires host topic-unregister: not implemented yet".into())
}

pub async fn status(_data_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Err("wires host status: not implemented yet".into())
}

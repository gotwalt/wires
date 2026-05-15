//! `wires join <token>` — install an invite token: persist the cap and copy
//! the inviter's host hints into local config.

use std::path::Path;

pub async fn run(_data_dir: &Path, _token: &str) -> Result<(), Box<dyn std::error::Error>> {
    Err("wires join: not implemented yet".into())
}

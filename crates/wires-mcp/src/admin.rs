//! Operator admin actions, invoked via `wires-mcp <subcommand>`. Each one
//! opens the config + store directly (no HTTP) and prints to stdout.

use std::path::Path;

use crate::config::GatewayConfig;
use crate::error::{IoSnafu, Result};
use crate::store::Store;
use snafu::ResultExt;

pub fn load_config(path: &Path) -> Result<GatewayConfig> {
    let s = std::fs::read_to_string(path).context(IoSnafu)?;
    toml::from_str(&s).map_err(|e| crate::error::GatewayError::Io {
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
        location: snafu::location!(),
    })
}

pub fn user_list(cfg: &GatewayConfig) -> Result<()> {
    let store = Store::open(&cfg.gateway_db_path())?;
    let users = store.list_users()?;
    for u in &users {
        println!(
            "{}\tcreated={}\tlast_seen={}\tdir={}",
            u.root_pubkey_hex, u.created_at_ms, u.last_seen_ms, u.data_dir
        );
    }
    println!("{} user(s)", users.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::UserRecord;
    use tempfile::TempDir;

    #[test]
    fn user_list_runs_against_empty_store() {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
        };
        // Create (and immediately drop) the store so the db file exists,
        // then let user_list open it exclusively.
        { let _store = Store::open(&cfg.gateway_db_path()).unwrap(); }
        user_list(&cfg).unwrap();
    }

    #[test]
    fn user_list_shows_a_seeded_user() {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
        };
        // Seed data, drop the handle, then let user_list open exclusively.
        {
            let store = Store::open(&cfg.gateway_db_path()).unwrap();
            store.put_user(&UserRecord {
                root_pubkey_hex: "ab".repeat(32),
                data_dir: "/tmp/x".into(),
                created_at_ms: 1,
                last_seen_ms: 2,
            }).unwrap();
        }
        user_list(&cfg).unwrap();
        // Re-open to verify the row is still there.
        let store2 = Store::open(&cfg.gateway_db_path()).unwrap();
        assert_eq!(store2.list_users().unwrap().len(), 1);
    }
}

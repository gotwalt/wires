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

pub fn keys_rotate(cfg: &GatewayConfig) -> Result<()> {
    let path = cfg.token_signing_path();
    if path.exists() {
        let now_s = chrono::Utc::now().timestamp();
        let archived = cfg.data_dir.join(format!("token_signing.ed25519.archived.{now_s}"));
        std::fs::rename(&path, &archived).context(IoSnafu)?;
        println!("archived old signing key to {}", archived.display());
    }
    let new = crate::keys::load_or_create(&path)?;
    println!(
        "new signing key kid = {}",
        crate::keys::kid_for(&new.verifying_key())
    );
    Ok(())
}

pub fn client_list(cfg: &GatewayConfig) -> Result<()> {
    let store = Store::open(&cfg.gateway_db_path())?;
    for c in store.list_oauth_clients()? {
        println!(
            "{}\trevoked={}\tname={}\turis={:?}",
            c.client_id, c.revoked, c.client_name, c.redirect_uris
        );
    }
    Ok(())
}

pub fn client_revoke(cfg: &GatewayConfig, client_id: &str) -> Result<()> {
    let store = Store::open(&cfg.gateway_db_path())?;
    let mut rec = store
        .get_oauth_client(client_id)?
        .ok_or_else(|| crate::error::GatewayError::Io {
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "unknown client_id"),
            location: snafu::location!(),
        })?;
    rec.revoked = true;
    store.put_oauth_client(&rec)?;
    println!("client {client_id} revoked");
    Ok(())
}

pub fn user_delete(cfg: &GatewayConfig, root_pubkey_hex: &str) -> Result<()> {
    let store = Store::open(&cfg.gateway_db_path())?;
    let removed = store.delete_user(root_pubkey_hex)?;
    let n_tokens = store.revoke_refresh_tokens_for_sub(root_pubkey_hex)?;
    let user_dir = cfg.users_dir().join(root_pubkey_hex);
    let dir_removed = if user_dir.exists() {
        std::fs::remove_dir_all(&user_dir).context(IoSnafu)?;
        true
    } else {
        false
    };
    println!(
        "user-delete root={} user_row_removed={} dir_removed={} refresh_tokens_revoked={}",
        root_pubkey_hex, removed, dir_removed, n_tokens
    );
    Ok(())
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
            retention: None,
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
            retention: None,
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

    #[test]
    fn user_delete_removes_users_dir_and_refresh_tokens() {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
            retention: None,
        };
        let sub = "cd".repeat(32);
        {
            let store = Store::open(&cfg.gateway_db_path()).unwrap();
            store.put_user(&UserRecord {
                root_pubkey_hex: sub.clone(),
                data_dir: "x".into(),
                created_at_ms: 0,
                last_seen_ms: 0,
            }).unwrap();
            store.put_refresh_token(&crate::store::RefreshTokenRecord {
                token_hash_hex: "h1".into(),
                sub: sub.clone(),
                client_id: "c".into(),
                issued_at_ms: 0,
                expires_ms: i64::MAX,
                rotated_to_hash_hex: None,
            }).unwrap();
        }
        let user_dir = cfg.users_dir().join(&sub);
        std::fs::create_dir_all(&user_dir).unwrap();
        std::fs::write(user_dir.join("config.toml"), "x").unwrap();

        user_delete(&cfg, &sub).unwrap();
        assert!(!user_dir.exists());

        // Re-open to verify rows were deleted.
        let store2 = Store::open(&cfg.gateway_db_path()).unwrap();
        assert!(store2.get_user(&sub).unwrap().is_none());
        assert!(store2.get_refresh_token("h1").unwrap().is_none());
    }

    #[test]
    fn client_revoke_flips_the_flag() {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
            retention: None,
        };
        {
            let store = Store::open(&cfg.gateway_db_path()).unwrap();
            store.put_oauth_client(&crate::store::OauthClientRecord {
                client_id: "c1".into(),
                client_name: "C".into(),
                redirect_uris: vec!["http://x".into()],
                grant_types: vec!["authorization_code".into()],
                created_at_ms: 0,
                revoked: false,
            }).unwrap();
        }
        client_revoke(&cfg, "c1").unwrap();
        let store2 = Store::open(&cfg.gateway_db_path()).unwrap();
        let rec = store2.get_oauth_client("c1").unwrap().unwrap();
        assert!(rec.revoked);
    }

    #[test]
    fn keys_rotate_generates_new_key_and_archives_old() {
        let tmp = TempDir::new().unwrap();
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:0".into(),
            data_dir: tmp.path().to_path_buf(),
            retention: None,
        };
        let initial = crate::keys::load_or_create(&cfg.token_signing_path()).unwrap();
        keys_rotate(&cfg).unwrap();
        let after = crate::keys::load_or_create(&cfg.token_signing_path()).unwrap();
        assert_ne!(initial.to_bytes(), after.to_bytes());
        // Old key archived with a timestamp suffix.
        let archive_glob = cfg.data_dir.join("token_signing.ed25519.archived");
        // The implementation should produce *something* with that prefix.
        let archived = std::fs::read_dir(&cfg.data_dir).unwrap().any(|e| {
            let n = e.unwrap().file_name();
            n.to_string_lossy().starts_with("token_signing.ed25519.archived")
        });
        assert!(archived, "expected archived key in {:?}", archive_glob);
    }
}

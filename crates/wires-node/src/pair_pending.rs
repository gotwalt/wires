//! On-disk persistence of an in-flight pair-listen attempt.
//!
//! Holds the nonce, ephemeral X25519 secret, expiry, and the original
//! PairRequest token at mode 0600. Present only while pair-listen is active;
//! deleted on successful pair-install or TTL expiry.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const FILE_NAME: &str = "pair_pending.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairPending {
    pub version: u8,
    pub nonce_hex: String,
    pub ephemeral_x25519_secret_hex: String,
    pub expires_unix_ms: i64,
    pub request_token: String,
}

pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

pub fn save(data_dir: &Path, p: &PairPending) -> std::io::Result<()> {
    let s = serde_json::to_string_pretty(p).expect("PairPending serializes");
    write_secret(&path(data_dir), s.as_bytes())
}

pub fn load(data_dir: &Path) -> std::io::Result<Option<PairPending>> {
    let p = path(data_dir);
    if !p.exists() {
        return Ok(None);
    }
    let s = std::fs::read_to_string(&p)?;
    let parsed = serde_json::from_str(&s)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Some(parsed))
}

pub fn delete(data_dir: &Path) -> std::io::Result<()> {
    let p = path(data_dir);
    if p.exists() {
        std::fs::remove_file(p)?;
    }
    Ok(())
}

#[cfg(unix)]
fn write_secret(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

#[cfg(not(unix))]
fn write_secret(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn save_load_delete_roundtrip() {
        let td = TempDir::new().unwrap();
        let p = PairPending {
            version: 1,
            nonce_hex: "aa".repeat(32),
            ephemeral_x25519_secret_hex: "bb".repeat(32),
            expires_unix_ms: 1_700_000_300_000,
            request_token: "tok".into(),
        };
        save(td.path(), &p).unwrap();
        assert!(path(td.path()).exists());
        let back = load(td.path()).unwrap().expect("present");
        assert_eq!(back.nonce_hex, p.nonce_hex);
        delete(td.path()).unwrap();
        assert!(!path(td.path()).exists());
        assert!(load(td.path()).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn save_uses_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        save(
            td.path(),
            &PairPending {
                version: 1,
                nonce_hex: "00".repeat(32),
                ephemeral_x25519_secret_hex: "11".repeat(32),
                expires_unix_ms: 0,
                request_token: "".into(),
            },
        )
        .unwrap();
        let mode = std::fs::metadata(path(td.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

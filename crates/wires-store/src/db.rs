use std::path::Path;

use redb::Database;
use snafu::ResultExt;

use crate::error::{FsSnafu, OpenDbSnafu, Result};

/// Open a topic log database, creating parent dirs as needed.
pub fn open_topic_log(root: &Path, topic_id_hex: &str) -> Result<Database> {
    let dir = root.join("topics").join(topic_id_hex);
    std::fs::create_dir_all(&dir).context(FsSnafu { path: dir.clone() })?;
    let path = dir.join("log.db");
    Database::create(&path).context(OpenDbSnafu { path: path.clone() })
}

pub fn open_topic_keys(root: &Path, topic_id_hex: &str) -> Result<Database> {
    let dir = root.join("topics").join(topic_id_hex);
    std::fs::create_dir_all(&dir).context(FsSnafu { path: dir.clone() })?;
    let path = dir.join("keys.db");
    Database::create(&path).context(OpenDbSnafu { path: path.clone() })
}

pub fn open_caps(root: &Path) -> Result<Database> {
    std::fs::create_dir_all(root).context(FsSnafu { path: root.to_path_buf() })?;
    let path = root.join("caps.db");
    Database::create(&path).context(OpenDbSnafu { path: path.clone() })
}

/// Compose a 40-byte key for the log table.
pub fn log_key(sender: &[u8; 32], seq: u64) -> [u8; 40] {
    let mut k = [0u8; 40];
    k[..32].copy_from_slice(sender);
    k[32..].copy_from_slice(&seq.to_be_bytes());
    k
}

pub fn parse_log_key(key: &[u8]) -> Option<([u8; 32], u64)> {
    if key.len() != 40 {
        return None;
    }
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&key[..32]);
    let mut seq_be = [0u8; 8];
    seq_be.copy_from_slice(&key[32..]);
    Some((sender, u64::from_be_bytes(seq_be)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn log_key_roundtrip() {
        let sender = [7u8; 32];
        let seq = 0x0123456789ABCDEF;
        let k = log_key(&sender, seq);
        let (s, q) = parse_log_key(&k).unwrap();
        assert_eq!(s, sender);
        assert_eq!(q, seq);
    }

    #[test]
    fn parse_log_key_rejects_wrong_length() {
        assert!(parse_log_key(&[0u8; 39]).is_none());
        assert!(parse_log_key(&[0u8; 41]).is_none());
    }

    #[test]
    fn opens_databases() {
        let tmp = TempDir::new().unwrap();
        let _log = open_topic_log(tmp.path(), "abc").unwrap();
        let _keys = open_topic_keys(tmp.path(), "abc").unwrap();
        let _caps = open_caps(tmp.path()).unwrap();
        // Verify files exist
        assert!(tmp.path().join("topics/abc/log.db").exists());
        assert!(tmp.path().join("topics/abc/keys.db").exists());
        assert!(tmp.path().join("caps.db").exists());
    }
}

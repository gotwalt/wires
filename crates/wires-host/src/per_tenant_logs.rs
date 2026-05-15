//! Per-tenant scoped TopicLogs. Each tenant gets a subdirectory under the host
//! data dir; per-topic redb files live inside as `log_<topic_hex>.redb`,
//! matching the host-spec storage layout (§5).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use redb::Database;
use snafu::ResultExt as _;
use wires_store::TopicLog;

use crate::error::{DbOpenSnafu, IoSnafu, Result};

type TopicLogCache = HashMap<([u8; 32], [u8; 32]), Arc<TopicLog>>;

pub struct PerTenantLogs {
    root: PathBuf,
    cache: RwLock<TopicLogCache>,
}

impl PerTenantLogs {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            cache: RwLock::new(HashMap::new()),
        }
    }

    pub fn tenant_dir(&self, root_pubkey: &[u8; 32]) -> PathBuf {
        self.root.join("tenants").join(hex::encode(root_pubkey))
    }

    pub fn get_or_open(
        &self,
        root_pubkey: &[u8; 32],
        topic_id: &[u8; 32],
    ) -> Result<Arc<TopicLog>> {
        {
            let map = self.cache.read().unwrap();
            if let Some(log) = map.get(&(*root_pubkey, *topic_id)) {
                return Ok(Arc::clone(log));
            }
        }
        let dir = self.tenant_dir(root_pubkey);
        std::fs::create_dir_all(&dir).context(IoSnafu)?;
        let path = dir.join(format!("log_{}.redb", hex::encode(topic_id)));
        let db = Database::create(&path).context(DbOpenSnafu)?;
        let log = Arc::new(TopicLog::new(Arc::new(db)));
        let mut map = self.cache.write().unwrap();
        // Re-check after taking the write lock (race between two readers).
        if let Some(existing) = map.get(&(*root_pubkey, *topic_id)) {
            return Ok(Arc::clone(existing));
        }
        map.insert((*root_pubkey, *topic_id), Arc::clone(&log));
        Ok(log)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use wires_core::{MessageKind, WireMessage};

    fn dummy_msg(sender: u8, seq: u64) -> WireMessage {
        WireMessage {
            topic_id: [1u8; 32],
            epoch: 0,
            kind: MessageKind::Standard,
            sender: [sender; 32],
            cap_id: [0u8; 16],
            seq,
            prev_hash: [0u8; 32],
            timestamp: seq as i64,
            payload_len: 1,
            signature: [0u8; 64],
            ciphertext: vec![1, 2, 3],
        }
    }

    #[test]
    fn separates_tenants_on_disk() {
        let tmp = TempDir::new().unwrap();
        let logs = PerTenantLogs::new(tmp.path());
        let root_a = [1u8; 32];
        let root_b = [2u8; 32];
        let topic = [9u8; 32];
        let log_a = logs.get_or_open(&root_a, &topic).unwrap();
        let log_b = logs.get_or_open(&root_b, &topic).unwrap();
        log_a.append(&dummy_msg(7, 0)).unwrap();
        log_b.append(&dummy_msg(8, 0)).unwrap();
        assert!(logs.tenant_dir(&root_a).exists());
        assert!(logs.tenant_dir(&root_b).exists());
        assert!(
            logs.tenant_dir(&root_a)
                .join(format!("log_{}.redb", hex::encode(topic)))
                .exists()
        );
        assert!(
            logs.tenant_dir(&root_b)
                .join(format!("log_{}.redb", hex::encode(topic)))
                .exists()
        );
    }
}

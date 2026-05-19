//! Per-tenant retention manager. Tracks an IngestIndex per tenant and applies
//! FIFO eviction against `PerTenantLogs` when the tenant's stored bytes exceed
//! its budget.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use snafu::ResultExt as _;
use wires_store::{IngestEntry, IngestIndex, open_ingest_index};

use crate::error::{Result, RetentionEvictionFailedSnafu, StoreSnafu};
use crate::per_tenant_logs::PerTenantLogs;

pub struct Retention {
    root: PathBuf,
    indices: RwLock<HashMap<[u8; 32], Arc<IngestIndex>>>,
    logs: Arc<PerTenantLogs>,
}

impl Retention {
    pub fn new(root: &Path, logs: Arc<PerTenantLogs>) -> Self {
        Self {
            root: root.to_path_buf(),
            indices: RwLock::new(HashMap::new()),
            logs,
        }
    }

    fn index_for(&self, root_pubkey: &[u8; 32]) -> Result<Arc<IngestIndex>> {
        {
            let map = self.indices.read().unwrap();
            if let Some(idx) = map.get(root_pubkey) {
                return Ok(Arc::clone(idx));
            }
        }
        let dir = self.root.join("tenants").join(hex::encode(root_pubkey));
        std::fs::create_dir_all(&dir).ok();
        let db = open_ingest_index(&dir, &hex::encode(root_pubkey)).context(StoreSnafu)?;
        let idx = Arc::new(IngestIndex::new(Arc::new(db)));
        let mut map = self.indices.write().unwrap();
        if let Some(existing) = map.get(root_pubkey) {
            return Ok(Arc::clone(existing));
        }
        map.insert(*root_pubkey, Arc::clone(&idx));
        Ok(idx)
    }

    /// Record an ingest and evict oldest entries if over budget. Returns the
    /// `IngestEntry`s that were evicted (and therefore had their per-topic
    /// log rows removed).
    pub fn on_append(
        &self,
        root_pubkey: &[u8; 32],
        topic_id: &[u8; 32],
        sender: &[u8; 32],
        seq: u64,
        bytes: u32,
        budget: u64,
    ) -> Result<Vec<IngestEntry>> {
        let idx = self.index_for(root_pubkey)?;
        idx.record(
            &IngestEntry {
                topic_id: *topic_id,
                sender: *sender,
                seq,
                bytes,
                ingested_at_ms: 0, // placeholder; overwritten by the explicit arg
            },
            wires_net::unix_now_ms(),
        )
        .context(StoreSnafu)?;
        let evicted = idx.evict_oldest_until(budget).context(StoreSnafu)?;
        for e in &evicted {
            let log = self.logs.get_or_open(root_pubkey, &e.topic_id)?;
            log.delete(&e.sender, e.seq)
                .context(RetentionEvictionFailedSnafu)?;
        }
        Ok(evicted)
    }

    pub fn bytes_stored(&self, root_pubkey: &[u8; 32]) -> Result<u64> {
        let idx = self.index_for(root_pubkey)?;
        idx.total_bytes().context(StoreSnafu)
    }

    /// Returns the host-side timestamp (ms) of the oldest retained message
    /// for this tenant, by reading the oldest IngestEntry, looking up the
    /// matching WireMessage, and returning its `timestamp`. Returns 0 if no
    /// entries exist for this tenant.
    pub fn oldest_retained_at(&self, root_pubkey: &[u8; 32]) -> Result<i64> {
        let idx = self.index_for(root_pubkey)?;
        let oldest = idx.oldest_entry().context(StoreSnafu)?;
        let Some(entry) = oldest else {
            return Ok(0);
        };
        let log = self.logs.get_or_open(root_pubkey, &entry.topic_id)?;
        let msgs = log
            .read_after(&entry.sender, entry.seq.checked_sub(1), 1)
            .context(StoreSnafu)?;
        Ok(msgs.first().map(|m| m.timestamp).unwrap_or(0))
    }

    /// Drop the cached `IngestIndex` for this tenant. The caller is responsible
    /// for then deleting `tenants/<root_pubkey_hex>/` on disk.
    pub fn clear_tenant(&self, root_pubkey: &[u8; 32]) {
        let mut map = self.indices.write().unwrap();
        map.remove(root_pubkey);
    }

    #[cfg(test)]
    pub fn cache_len(&self) -> usize {
        self.indices.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use wires_core::{MessageKind, WireMessage};

    fn msg(sender: u8, seq: u64, payload: u32) -> WireMessage {
        WireMessage {
            topic_id: [1u8; 32],
            epoch: 0,
            kind: MessageKind::Standard,
            sender: [sender; 32],
            cap_id: [0u8; 16],
            seq,
            prev_hash: [0u8; 32],
            timestamp: seq as i64,
            payload_len: payload,
            signature: [0u8; 64],
            ciphertext: vec![0u8; payload as usize],
        }
    }

    #[test]
    fn eviction_drops_oldest_when_over_budget() {
        let tmp = TempDir::new().unwrap();
        let logs = Arc::new(PerTenantLogs::new(tmp.path()));
        let retention = Retention::new(tmp.path(), Arc::clone(&logs));
        let root = [1u8; 32];
        let topic = [9u8; 32];

        // Append 3 messages to the underlying log AND record them in retention.
        let log = logs.get_or_open(&root, &topic).unwrap();
        let m0 = msg(7, 0, 100);
        let m1 = msg(7, 1, 100);
        let m2 = msg(7, 2, 100);
        log.append(&m0).unwrap();
        log.append(&m1).unwrap();
        log.append(&m2).unwrap();

        let b0 = serde_json::to_vec(&m0).unwrap().len() as u32;
        let b1 = serde_json::to_vec(&m1).unwrap().len() as u32;
        let b2 = serde_json::to_vec(&m2).unwrap().len() as u32;

        retention
            .on_append(&root, &topic, &[7u8; 32], 0, b0, u64::MAX)
            .unwrap();
        retention
            .on_append(&root, &topic, &[7u8; 32], 1, b1, u64::MAX)
            .unwrap();
        // Last append imposes a tight budget — should evict m0 and m1.
        let evicted = retention
            .on_append(&root, &topic, &[7u8; 32], 2, b2, b2 as u64)
            .unwrap();
        assert_eq!(evicted.len(), 2);
        assert_eq!(evicted[0].seq, 0);
        assert_eq!(evicted[1].seq, 1);

        // m0 and m1 must be gone from the underlying log; m2 survives.
        let survivors = log.read_after(&[7u8; 32], None, 10).unwrap();
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].seq, 2);
    }

    #[test]
    fn clear_tenant_drops_cached_index() {
        let tmp = TempDir::new().unwrap();
        let logs = Arc::new(PerTenantLogs::new(tmp.path()));
        let retention = Retention::new(tmp.path(), Arc::clone(&logs));
        let root_a = [1u8; 32];
        let root_b = [2u8; 32];
        let topic = [9u8; 32];

        // Force index creation for both tenants.
        retention
            .on_append(&root_a, &topic, &[7u8; 32], 0, 100, u64::MAX)
            .unwrap();
        retention
            .on_append(&root_b, &topic, &[7u8; 32], 0, 100, u64::MAX)
            .unwrap();
        assert_eq!(retention.cache_len(), 2);
        retention.clear_tenant(&root_a);
        assert_eq!(retention.cache_len(), 1);
    }
}

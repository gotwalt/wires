use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable};
use snafu::ResultExt;

use crate::error::{
    BeginTxnSnafu, CommitTxnSnafu, OpenTableSnafu, Result, StorageIoSnafu,
};
use crate::schema::{INGEST_INDEX, INGEST_META};

const META_KEY: &[u8] = b"m";

/// A single entry in the per-tenant ingest order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestEntry {
    pub topic_id: [u8; 32],
    pub sender: [u8; 32],
    pub seq: u64,
    pub bytes: u32,
}

pub struct IngestIndex {
    db: Arc<Database>,
}

impl IngestIndex {
    pub fn new(db: Arc<Database>) -> Self { Self { db } }

    /// Record an ingested message. Returns the assigned ingest_seq.
    pub fn record(&self, entry: &IngestEntry) -> Result<u64> {
        let write = self.db.begin_write().context(BeginTxnSnafu)?;
        let assigned = {
            let mut meta_t = write.open_table(INGEST_META).context(OpenTableSnafu)?;
            let (next_ingest, total_bytes) = read_meta(&meta_t)?;

            let mut value = [0u8; 76];
            value[0..32].copy_from_slice(&entry.topic_id);
            value[32..64].copy_from_slice(&entry.sender);
            value[64..72].copy_from_slice(&entry.seq.to_be_bytes());
            value[72..76].copy_from_slice(&entry.bytes.to_be_bytes());

            let key = next_ingest.to_be_bytes();

            let mut idx_t = write.open_table(INGEST_INDEX).context(OpenTableSnafu)?;
            idx_t.insert(&key[..], &value[..]).context(StorageIoSnafu)?;

            let new_total = total_bytes.saturating_add(entry.bytes as u64);
            write_meta(&mut meta_t, next_ingest.wrapping_add(1), new_total)?;

            next_ingest
        };
        write.commit().context(CommitTxnSnafu)?;
        Ok(assigned)
    }

    /// Sum of `bytes` across all currently-stored entries.
    pub fn total_bytes(&self) -> Result<u64> {
        let read = self.db.begin_read().context(BeginTxnSnafu)?;
        let table = read.open_table(INGEST_META).context(OpenTableSnafu)?;
        let (_next, total) = read_meta(&table)?;
        Ok(total)
    }

    /// Evict the oldest entries until `total_bytes() ≤ budget_bytes`. Returns the
    /// dropped entries in ingest order (oldest first).
    pub fn evict_oldest_until(&self, budget_bytes: u64) -> Result<Vec<IngestEntry>> {
        let write = self.db.begin_write().context(BeginTxnSnafu)?;
        let dropped;
        {
            let mut meta_t = write.open_table(INGEST_META).context(OpenTableSnafu)?;
            let (next_ingest, mut total) = read_meta(&meta_t)?;
            if total <= budget_bytes {
                drop(meta_t);
                write.commit().context(CommitTxnSnafu)?;
                return Ok(Vec::new());
            }

            let mut idx_t = write.open_table(INGEST_INDEX).context(OpenTableSnafu)?;

            // Collect keys to remove in order; we cannot mutate while iterating.
            let mut victim_keys: Vec<[u8; 8]> = Vec::new();
            let mut victim_entries: Vec<IngestEntry> = Vec::new();
            for entry_r in idx_t.iter().context(StorageIoSnafu)? {
                let (k, v) = entry_r.context(StorageIoSnafu)?;
                let mut kbuf = [0u8; 8];
                kbuf.copy_from_slice(k.value());
                let raw = v.value();
                if raw.len() < 76 { continue; }
                let mut topic_id = [0u8; 32]; topic_id.copy_from_slice(&raw[0..32]);
                let mut sender = [0u8; 32]; sender.copy_from_slice(&raw[32..64]);
                let mut sb = [0u8; 8]; sb.copy_from_slice(&raw[64..72]);
                let mut bb = [0u8; 4]; bb.copy_from_slice(&raw[72..76]);
                let bytes = u32::from_be_bytes(bb);
                let ent = IngestEntry {
                    topic_id, sender,
                    seq: u64::from_be_bytes(sb),
                    bytes,
                };
                total = total.saturating_sub(bytes as u64);
                victim_keys.push(kbuf);
                victim_entries.push(ent);
                if total <= budget_bytes { break; }
            }

            for k in &victim_keys {
                idx_t.remove(&k[..]).context(StorageIoSnafu)?;
            }
            write_meta(&mut meta_t, next_ingest, total)?;
            dropped = victim_entries;
        }
        write.commit().context(CommitTxnSnafu)?;
        Ok(dropped)
    }
}

fn read_meta<T: ReadableTable<&'static [u8], &'static [u8]>>(table: &T) -> Result<(u64, u64)> {
    match table.get(META_KEY).context(StorageIoSnafu)? {
        Some(g) => {
            let raw = g.value();
            if raw.len() < 16 {
                return Ok((0, 0));
            }
            let mut a = [0u8; 8]; a.copy_from_slice(&raw[..8]);
            let mut b = [0u8; 8]; b.copy_from_slice(&raw[8..16]);
            Ok((u64::from_be_bytes(a), u64::from_be_bytes(b)))
        }
        None => Ok((0, 0)),
    }
}

fn write_meta(
    table: &mut redb::Table<&[u8], &[u8]>,
    next_ingest: u64,
    total_bytes: u64,
) -> Result<()> {
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&next_ingest.to_be_bytes());
    buf[8..].copy_from_slice(&total_bytes.to_be_bytes());
    table.insert(META_KEY, &buf[..]).context(StorageIoSnafu)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_ingest_index;
    use tempfile::TempDir;

    fn entry(topic: u8, sender: u8, seq: u64, bytes: u32) -> IngestEntry {
        IngestEntry {
            topic_id: [topic; 32],
            sender: [sender; 32],
            seq,
            bytes,
        }
    }

    #[test]
    fn record_assigns_monotonic_ingest_seq() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
        let idx = IngestIndex::new(db);
        let a = idx.record(&entry(1, 9, 0, 100)).unwrap();
        let b = idx.record(&entry(1, 9, 1, 200)).unwrap();
        let c = idx.record(&entry(2, 8, 0, 50)).unwrap();
        assert_eq!(a, 0);
        assert_eq!(b, 1);
        assert_eq!(c, 2);
        assert_eq!(idx.total_bytes().unwrap(), 350);
    }

    #[test]
    fn evict_oldest_until_returns_dropped_in_order() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
        let idx = IngestIndex::new(db);
        idx.record(&entry(1, 9, 0, 100)).unwrap();
        idx.record(&entry(1, 9, 1, 200)).unwrap();
        idx.record(&entry(2, 8, 0, 50)).unwrap();
        idx.record(&entry(2, 8, 1, 75)).unwrap();
        // Total = 425. Evict until ≤ 75.
        let dropped = idx.evict_oldest_until(75).unwrap();
        assert_eq!(dropped.len(), 3); // oldest 100 + 200 + 50, leaving 75
        assert_eq!(dropped[0].seq, 0);
        assert_eq!(dropped[0].topic_id, [1u8; 32]);
        assert_eq!(dropped[1].seq, 1);
        assert_eq!(dropped[2].topic_id, [2u8; 32]);
        assert_eq!(idx.total_bytes().unwrap(), 75);
    }

    #[test]
    fn evict_oldest_until_noop_when_under_budget() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
        let idx = IngestIndex::new(db);
        idx.record(&entry(1, 9, 0, 100)).unwrap();
        let dropped = idx.evict_oldest_until(1000).unwrap();
        assert!(dropped.is_empty());
        assert_eq!(idx.total_bytes().unwrap(), 100);
    }
}

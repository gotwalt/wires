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
}

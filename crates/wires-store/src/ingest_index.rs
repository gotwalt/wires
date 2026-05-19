use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable};
use snafu::ResultExt;

use crate::error::{BeginTxnSnafu, CommitTxnSnafu, OpenTableSnafu, Result, StorageIoSnafu};
use crate::schema::{INGEST_INDEX, INGEST_META};

const META_KEY: &[u8] = b"m";

/// A single entry in the per-tenant ingest order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestEntry {
    pub topic_id: [u8; 32],
    pub sender: [u8; 32],
    pub seq: u64,
    pub bytes: u32,
    pub ingested_at_ms: i64,
}

pub struct IngestIndex {
    db: Arc<Database>,
}

impl IngestIndex {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Record an ingested message. Returns the assigned ingest_seq.
    ///
    /// `now_ms` must be a wall-clock millisecond timestamp (see
    /// `wires_net::unix_now_ms`). It is stored verbatim into the row's
    /// `ingested_at_ms` field so the index can later answer "evict everything
    /// older than X".
    pub fn record(&self, entry: &IngestEntry, now_ms: i64) -> Result<u64> {
        let write = self.db.begin_write().context(BeginTxnSnafu)?;
        let assigned = {
            let mut meta_t = write.open_table(INGEST_META).context(OpenTableSnafu)?;
            let (next_ingest, total_bytes) = read_meta(&meta_t)?;

            let mut value = [0u8; 84];
            value[0..32].copy_from_slice(&entry.topic_id);
            value[32..64].copy_from_slice(&entry.sender);
            value[64..72].copy_from_slice(&entry.seq.to_be_bytes());
            value[72..76].copy_from_slice(&entry.bytes.to_be_bytes());
            value[76..84].copy_from_slice(&now_ms.to_be_bytes());

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

    /// Return the oldest (lowest ingest_seq) entry still stored, or `None` if
    /// the index is empty.
    pub fn oldest_entry(&self) -> Result<Option<IngestEntry>> {
        let read = self.db.begin_read().context(BeginTxnSnafu)?;
        let table = match read.open_table(INGEST_INDEX) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => {
                return Err(crate::error::StoreError::OpenTable {
                    source: e,
                    location: snafu::location!(),
                });
            }
        };
        let mut iter = table.iter().context(StorageIoSnafu)?;
        let Some(first) = iter.next() else {
            return Ok(None);
        };
        let (_k, v) = first.context(StorageIoSnafu)?;
        Ok(decode_row(v.value()))
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
                let Some(ent) = decode_row(v.value()) else { continue };
                let bytes = ent.bytes;
                total = total.saturating_sub(bytes as u64);
                victim_keys.push(kbuf);
                victim_entries.push(ent);
                if total <= budget_bytes {
                    break;
                }
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

    /// Remove every entry whose `ingested_at_ms < deadline_ms`. Returns the
    /// dropped entries in ingest order (oldest first). O(k) in the number of
    /// expired entries — short-circuits at the first row whose timestamp is
    /// ≥ deadline.
    ///
    /// Iteration order is by ingest_seq (the redb table key), which is monotone
    /// in arrival time. The short-circuit therefore covers the common case
    /// where every newly-arrived row was timestamped close to "now" — a single
    /// out-of-order row (e.g. from a misbehaving clock) still gets cleaned up
    /// later when its predecessor would have been swept.
    pub fn evict_older_than(&self, deadline_ms: i64) -> Result<Vec<IngestEntry>> {
        let write = self.db.begin_write().context(BeginTxnSnafu)?;
        let dropped;
        {
            let mut meta_t = write.open_table(INGEST_META).context(OpenTableSnafu)?;
            let (next_ingest, mut total) = read_meta(&meta_t)?;

            let mut idx_t = write.open_table(INGEST_INDEX).context(OpenTableSnafu)?;
            let mut victim_keys: Vec<[u8; 8]> = Vec::new();
            let mut victim_entries: Vec<IngestEntry> = Vec::new();
            for entry_r in idx_t.iter().context(StorageIoSnafu)? {
                let (k, v) = entry_r.context(StorageIoSnafu)?;
                let Some(ent) = decode_row(v.value()) else { continue };
                if ent.ingested_at_ms >= deadline_ms {
                    break; // short-circuit
                }
                let mut kbuf = [0u8; 8];
                kbuf.copy_from_slice(k.value());
                total = total.saturating_sub(ent.bytes as u64);
                victim_keys.push(kbuf);
                victim_entries.push(ent);
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

/// Decode a serialized ingest-index row. Accepts both the legacy 76-byte
/// layout (decoded with `ingested_at_ms = 0`) and the current 84-byte layout.
/// Returns `None` for any shorter buffer.
fn decode_row(raw: &[u8]) -> Option<IngestEntry> {
    if raw.len() < 76 {
        return None;
    }
    let mut topic_id = [0u8; 32];
    topic_id.copy_from_slice(&raw[0..32]);
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&raw[32..64]);
    let mut sb = [0u8; 8];
    sb.copy_from_slice(&raw[64..72]);
    let mut bb = [0u8; 4];
    bb.copy_from_slice(&raw[72..76]);
    let ingested_at_ms = if raw.len() >= 84 {
        let mut tb = [0u8; 8];
        tb.copy_from_slice(&raw[76..84]);
        i64::from_be_bytes(tb)
    } else {
        0
    };
    Some(IngestEntry {
        topic_id,
        sender,
        seq: u64::from_be_bytes(sb),
        bytes: u32::from_be_bytes(bb),
        ingested_at_ms,
    })
}

fn read_meta<T: ReadableTable<&'static [u8], &'static [u8]>>(table: &T) -> Result<(u64, u64)> {
    match table.get(META_KEY).context(StorageIoSnafu)? {
        Some(g) => {
            let raw = g.value();
            if raw.len() < 16 {
                return Ok((0, 0));
            }
            let mut a = [0u8; 8];
            a.copy_from_slice(&raw[..8]);
            let mut b = [0u8; 8];
            b.copy_from_slice(&raw[8..16]);
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
            ingested_at_ms: 0,
        }
    }

    #[test]
    fn record_assigns_monotonic_ingest_seq() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
        let idx = IngestIndex::new(db);
        let a = idx.record(&entry(1, 9, 0, 100), 0).unwrap();
        let b = idx.record(&entry(1, 9, 1, 200), 0).unwrap();
        let c = idx.record(&entry(2, 8, 0, 50), 0).unwrap();
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
        idx.record(&entry(1, 9, 0, 100), 0).unwrap();
        idx.record(&entry(1, 9, 1, 200), 0).unwrap();
        idx.record(&entry(2, 8, 0, 50), 0).unwrap();
        idx.record(&entry(2, 8, 1, 75), 0).unwrap();
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
        idx.record(&entry(1, 9, 0, 100), 0).unwrap();
        let dropped = idx.evict_oldest_until(1000).unwrap();
        assert!(dropped.is_empty());
        assert_eq!(idx.total_bytes().unwrap(), 100);
    }

    #[test]
    fn oldest_entry_empty_returns_none() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
        let idx = IngestIndex::new(db);
        assert!(idx.oldest_entry().unwrap().is_none());
    }

    #[test]
    fn oldest_entry_returns_first_recorded() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
        let idx = IngestIndex::new(db);
        let e0 = entry(1, 9, 0, 100);
        let e1 = entry(2, 8, 1, 200);
        let e2 = entry(3, 7, 2, 50);
        idx.record(&e0, 0).unwrap();
        idx.record(&e1, 0).unwrap();
        idx.record(&e2, 0).unwrap();
        let oldest = idx.oldest_entry().unwrap().unwrap();
        assert_eq!(oldest, e0);
    }

    #[test]
    fn oldest_entry_advances_after_eviction() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
        let idx = IngestIndex::new(db);
        let e0 = entry(1, 9, 0, 100);
        let e1 = entry(2, 8, 1, 200);
        idx.record(&e0, 0).unwrap();
        idx.record(&e1, 0).unwrap();
        // Evict until ≤ 200 — evicts e0 (100 bytes), leaves e1 (200).
        idx.evict_oldest_until(200).unwrap();
        let oldest = idx.oldest_entry().unwrap().unwrap();
        assert_eq!(oldest, e1);
    }

    #[test]
    fn record_persists_ingested_at_ms() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
        let idx = IngestIndex::new(db);
        let e = IngestEntry {
            topic_id: [1u8; 32],
            sender: [9u8; 32],
            seq: 0,
            bytes: 100,
            ingested_at_ms: 1_700_000_000_000,
        };
        idx.record(&e, 1_700_000_000_000).unwrap();
        let oldest = idx.oldest_entry().unwrap().unwrap();
        assert_eq!(oldest.ingested_at_ms, 1_700_000_000_000);
        assert_eq!(oldest.bytes, 100);
    }

    #[test]
    fn evict_older_than_drops_stale_keeps_fresh() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
        let idx = IngestIndex::new(db);
        // Insert four entries with increasing timestamps.
        idx.record(&entry(1, 9, 0, 100), 1_000).unwrap();
        idx.record(&entry(1, 9, 1, 100), 2_000).unwrap();
        idx.record(&entry(2, 8, 0, 100), 3_000).unwrap();
        idx.record(&entry(2, 8, 1, 100), 4_000).unwrap();

        // Drop everything older than 2_500.
        let dropped = idx.evict_older_than(2_500).unwrap();
        assert_eq!(dropped.len(), 2);
        assert_eq!(dropped[0].seq, 0);
        assert_eq!(dropped[0].ingested_at_ms, 1_000);
        assert_eq!(dropped[1].seq, 1);
        assert_eq!(dropped[1].ingested_at_ms, 2_000);

        // total_bytes drops to 200 (two surviving entries × 100 bytes).
        assert_eq!(idx.total_bytes().unwrap(), 200);
        let surviving = idx.oldest_entry().unwrap().unwrap();
        assert_eq!(surviving.ingested_at_ms, 3_000);
    }

    #[test]
    fn evict_older_than_stops_at_first_fresh_row() {
        // The index is ordered by ingest_seq, which is monotone in
        // arrival time. evict_older_than must short-circuit as soon as it
        // hits a row with ingested_at_ms >= deadline — this is what makes
        // it O(k) instead of O(n).
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
        let idx = IngestIndex::new(db);
        idx.record(&entry(1, 9, 0, 50), 1_000).unwrap();
        idx.record(&entry(1, 9, 1, 50), 5_000).unwrap();
        idx.record(&entry(1, 9, 2, 50), 2_000).unwrap(); // arrives later, but timestamped earlier
        // deadline = 3_000 — the first row is stale, the second is fresh, so we
        // must stop after dropping just the first row.
        let dropped = idx.evict_older_than(3_000).unwrap();
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].seq, 0);
        // Two entries survive even though one of them is "stale" by timestamp,
        // because we short-circuited.
        assert_eq!(idx.total_bytes().unwrap(), 100);
    }

    #[test]
    fn evict_older_than_empty_index_is_noop() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
        let idx = IngestIndex::new(db);
        let dropped = idx.evict_older_than(1_000).unwrap();
        assert!(dropped.is_empty());
        assert_eq!(idx.total_bytes().unwrap(), 0);
    }

    #[test]
    fn decode_row_accepts_legacy_76_byte_layout() {
        // Build a 76-byte row by hand, decode it, expect ingested_at_ms = 0.
        let mut raw = [0u8; 76];
        raw[0..32].copy_from_slice(&[1u8; 32]);
        raw[32..64].copy_from_slice(&[9u8; 32]);
        raw[64..72].copy_from_slice(&7u64.to_be_bytes());
        raw[72..76].copy_from_slice(&100u32.to_be_bytes());
        let ent = decode_row(&raw).expect("legacy row should decode");
        assert_eq!(ent.topic_id, [1u8; 32]);
        assert_eq!(ent.sender, [9u8; 32]);
        assert_eq!(ent.seq, 7);
        assert_eq!(ent.bytes, 100);
        assert_eq!(ent.ingested_at_ms, 0);
    }
}

use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable};
use snafu::ResultExt;

use crate::error::{BeginTxnSnafu, CommitTxnSnafu, OpenTableSnafu, Result, StorageIoSnafu};
use crate::schema::EPOCH_KEYS;

pub type EpochKey = [u8; 32];

pub struct EpochKeyStore {
    db: Arc<Database>,
}

impl EpochKeyStore {
    /// Construct an EpochKeyStore over the given keys database. Ensures the
    /// EPOCH_KEYS table exists so subsequent reads on a fresh db don't fail.
    pub fn new(db: Arc<Database>) -> Result<Self> {
        let write = db.begin_write().context(BeginTxnSnafu)?;
        {
            let _ = write.open_table(EPOCH_KEYS).context(OpenTableSnafu)?;
        }
        write.commit().context(CommitTxnSnafu)?;
        Ok(Self { db })
    }

    pub fn put(&self, epoch: u32, key: &EpochKey) -> Result<()> {
        let write = self.db.begin_write().context(BeginTxnSnafu)?;
        {
            let mut t = write.open_table(EPOCH_KEYS).context(OpenTableSnafu)?;
            t.insert(epoch, &key[..]).context(StorageIoSnafu)?;
        }
        write.commit().context(CommitTxnSnafu)?;
        Ok(())
    }

    pub fn get(&self, epoch: u32) -> Result<Option<EpochKey>> {
        let read = self.db.begin_read().context(BeginTxnSnafu)?;
        let t = read.open_table(EPOCH_KEYS).context(OpenTableSnafu)?;
        Ok(t.get(epoch).context(StorageIoSnafu)?.and_then(|v| {
            let bytes = v.value();
            if bytes.len() != 32 {
                return None;
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(bytes);
            Some(out)
        }))
    }

    pub fn latest(&self) -> Result<Option<(u32, EpochKey)>> {
        let read = self.db.begin_read().context(BeginTxnSnafu)?;
        let t = read.open_table(EPOCH_KEYS).context(OpenTableSnafu)?;
        let mut best: Option<(u32, EpochKey)> = None;
        for entry in t.iter().context(StorageIoSnafu)? {
            let (k, v) = entry.context(StorageIoSnafu)?;
            let bytes = v.value();
            if bytes.len() != 32 {
                continue;
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(bytes);
            let epoch = k.value();
            if best.as_ref().map(|(e, _)| epoch > *e).unwrap_or(true) {
                best = Some((epoch, key));
            }
        }
        Ok(best)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_topic_keys;
    use tempfile::TempDir;

    #[test]
    fn put_and_get() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_topic_keys(tmp.path(), "abc").unwrap());
        let store = EpochKeyStore::new(db).unwrap();
        store.put(0, &[1u8; 32]).unwrap();
        store.put(1, &[2u8; 32]).unwrap();
        assert_eq!(store.get(0).unwrap().unwrap(), [1u8; 32]);
        assert_eq!(store.get(1).unwrap().unwrap(), [2u8; 32]);
        assert!(store.get(99).unwrap().is_none());
    }

    #[test]
    fn latest_returns_highest_epoch() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_topic_keys(tmp.path(), "abc").unwrap());
        let store = EpochKeyStore::new(db).unwrap();
        store.put(0, &[1u8; 32]).unwrap();
        store.put(2, &[3u8; 32]).unwrap();
        store.put(1, &[2u8; 32]).unwrap();
        let (e, k) = store.latest().unwrap().unwrap();
        assert_eq!(e, 2);
        assert_eq!(k, [3u8; 32]);
    }

    #[test]
    fn latest_empty_returns_none() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_topic_keys(tmp.path(), "abc").unwrap());
        let store = EpochKeyStore::new(db).unwrap();
        assert!(store.latest().unwrap().is_none());
    }

    #[test]
    fn put_replaces_existing_epoch() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_topic_keys(tmp.path(), "abc").unwrap());
        let store = EpochKeyStore::new(db).unwrap();
        store.put(0, &[1u8; 32]).unwrap();
        store.put(0, &[9u8; 32]).unwrap();
        assert_eq!(store.get(0).unwrap().unwrap(), [9u8; 32]);
    }
}

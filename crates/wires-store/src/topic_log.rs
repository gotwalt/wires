use std::collections::HashMap;
use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable};
use snafu::ResultExt;
use wires_core::{MessageHash, WireMessage};

use crate::db::log_key;
use crate::error::{
    BeginTxnSnafu, CommitTxnSnafu, CoreSnafu, DeserializeSnafu, OpenTableSnafu, Result,
    SerializeSnafu, StorageIoSnafu,
};
use crate::schema::{TOPIC_HWM, TOPIC_LOG};

pub type Pubkey = [u8; 32];

pub struct TopicLog {
    db: Arc<Database>,
}

impl TopicLog {
    pub fn new(db: Arc<Database>) -> Self { Self { db } }

    /// Insert a message. Idempotent: re-inserting the same (sender, seq) when the
    /// stored hash matches is a no-op returning false. Returns true if newly inserted.
    /// If a different message is already stored at the same (sender, seq), returns an
    /// error — the caller should have detected the fork via the chain link check.
    pub fn append(&self, msg: &WireMessage) -> Result<bool> {
        let key = log_key(&msg.sender, msg.seq);
        let value = serde_json::to_vec(msg).context(SerializeSnafu)?;
        let new_hash = msg.message_hash().context(CoreSnafu)?;

        let write = self.db.begin_write().context(BeginTxnSnafu)?;
        let inserted = {
            let mut log_t = write.open_table(TOPIC_LOG).context(OpenTableSnafu)?;
            // Resolve the existing entry into an owned value before mutating.
            let existing_bytes: Option<Vec<u8>> = log_t
                .get(&key[..])
                .context(StorageIoSnafu)?
                .map(|g| g.value().to_vec());
            if let Some(existing_raw) = existing_bytes {
                let existing_msg: WireMessage =
                    serde_json::from_slice(&existing_raw).context(DeserializeSnafu)?;
                let existing_hash = existing_msg.message_hash().context(CoreSnafu)?;
                if existing_hash == new_hash {
                    false
                } else {
                    // Fork attempt — different message at the same (sender, seq).
                    return Err(crate::error::StoreError::StorageIo {
                        source: redb::StorageError::Corrupted(
                            "topic_log fork: different message already stored at same (sender, seq)".into(),
                        ),
                        location: snafu::location!(),
                    });
                }
            } else {
                log_t.insert(&key[..], value.as_slice()).context(StorageIoSnafu)?;
                true
            }
        };

        if inserted {
            let mut hwm_t = write.open_table(TOPIC_HWM).context(OpenTableSnafu)?;
            let needs_update = match hwm_t.get(&msg.sender[..]).context(StorageIoSnafu)? {
                Some(v) => {
                    let bytes = v.value();
                    if bytes.len() >= 8 {
                        let mut s = [0u8; 8];
                        s.copy_from_slice(&bytes[..8]);
                        msg.seq > u64::from_be_bytes(s)
                    } else {
                        true
                    }
                }
                None => true,
            };
            if needs_update {
                let mut v = Vec::with_capacity(40);
                v.extend_from_slice(&msg.seq.to_be_bytes());
                v.extend_from_slice(&new_hash);
                hwm_t.insert(&msg.sender[..], v.as_slice()).context(StorageIoSnafu)?;
            }
        }

        write.commit().context(CommitTxnSnafu)?;
        Ok(inserted)
    }

    /// Get all messages from `sender` strictly after `after_seq` (None = from genesis), in order.
    pub fn read_after(
        &self,
        sender: &Pubkey,
        after_seq: Option<u64>,
        limit: usize,
    ) -> Result<Vec<WireMessage>> {
        let read = self.db.begin_read().context(BeginTxnSnafu)?;
        let table = read.open_table(TOPIC_LOG).context(OpenTableSnafu)?;
        let start_seq = after_seq.map(|s| s + 1).unwrap_or(0);
        let start = log_key(sender, start_seq);
        let mut end = [0u8; 40];
        end[..32].copy_from_slice(sender);
        end[32..].copy_from_slice(&u64::MAX.to_be_bytes());

        let mut out = Vec::new();
        let iter = table.range::<&[u8]>(&start[..]..=&end[..]).context(StorageIoSnafu)?;
        for entry in iter {
            let (_k, v) = entry.context(StorageIoSnafu)?;
            let msg: WireMessage =
                serde_json::from_slice(v.value()).context(DeserializeSnafu)?;
            out.push(msg);
            if out.len() >= limit { break; }
        }
        Ok(out)
    }

    /// Read every message across all senders, sorted by (timestamp, sender, seq).
    pub fn read_all(&self) -> Result<Vec<WireMessage>> {
        let read = self.db.begin_read().context(BeginTxnSnafu)?;
        let table = read.open_table(TOPIC_LOG).context(OpenTableSnafu)?;
        let mut out: Vec<WireMessage> = Vec::new();
        for entry in table.iter().context(StorageIoSnafu)? {
            let (_k, v) = entry.context(StorageIoSnafu)?;
            let msg: WireMessage =
                serde_json::from_slice(v.value()).context(DeserializeSnafu)?;
            out.push(msg);
        }
        out.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then_with(|| a.sender.cmp(&b.sender))
                .then_with(|| a.seq.cmp(&b.seq))
        });
        Ok(out)
    }

    /// Current high-water-mark per sender.
    pub fn hwm(&self) -> Result<HashMap<Pubkey, (u64, MessageHash)>> {
        let read = self.db.begin_read().context(BeginTxnSnafu)?;
        let table = read.open_table(TOPIC_HWM).context(OpenTableSnafu)?;
        let mut out = HashMap::new();
        for entry in table.iter().context(StorageIoSnafu)? {
            let (k, v) = entry.context(StorageIoSnafu)?;
            let key_bytes = k.value();
            let val_bytes = v.value();
            if key_bytes.len() != 32 || val_bytes.len() != 40 { continue; }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(key_bytes);
            let mut s = [0u8; 8];
            s.copy_from_slice(&val_bytes[..8]);
            let seq = u64::from_be_bytes(s);
            let mut h = [0u8; 32];
            h.copy_from_slice(&val_bytes[8..]);
            out.insert(pk, (seq, h));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_topic_log;
    use tempfile::TempDir;
    use wires_core::MessageKind;

    fn make(sender: Pubkey, seq: u64, prev: MessageHash) -> WireMessage {
        WireMessage {
            topic_id: [1u8; 32],
            epoch: 0,
            kind: MessageKind::Standard,
            sender,
            cap_id: [0u8; 16],
            seq,
            prev_hash: prev,
            timestamp: seq as i64,
            payload_len: 1,
            signature: [0u8; 64],
            ciphertext: vec![seq as u8],
        }
    }

    #[test]
    fn append_and_read() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_topic_log(tmp.path(), "abc").unwrap());
        let log = TopicLog::new(db);
        let sender = [7u8; 32];
        let m0 = make(sender, 0, [0u8; 32]);
        let m1 = make(sender, 1, m0.message_hash().unwrap());

        assert!(log.append(&m0).unwrap());
        assert!(log.append(&m1).unwrap());

        let got = log.read_after(&sender, None, 10).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].seq, 0);
        assert_eq!(got[1].seq, 1);
    }

    #[test]
    fn append_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_topic_log(tmp.path(), "abc").unwrap());
        let log = TopicLog::new(db);
        let m = make([7u8; 32], 0, [0u8; 32]);
        assert!(log.append(&m).unwrap());
        assert!(!log.append(&m).unwrap()); // already there → false
    }

    #[test]
    fn append_rejects_fork() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_topic_log(tmp.path(), "abc").unwrap());
        let log = TopicLog::new(db);
        let mut a = make([7u8; 32], 0, [0u8; 32]);
        a.timestamp = 1;
        let mut b = make([7u8; 32], 0, [0u8; 32]);
        b.timestamp = 2; // different message at same (sender, seq)
        assert!(log.append(&a).unwrap());
        assert!(log.append(&b).is_err());
    }

    #[test]
    fn read_after_skips_past_hwm() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_topic_log(tmp.path(), "abc").unwrap());
        let log = TopicLog::new(db);
        let sender = [7u8; 32];
        let m0 = make(sender, 0, [0u8; 32]);
        let m1 = make(sender, 1, m0.message_hash().unwrap());
        let m2 = make(sender, 2, m1.message_hash().unwrap());
        log.append(&m0).unwrap();
        log.append(&m1).unwrap();
        log.append(&m2).unwrap();
        let got = log.read_after(&sender, Some(0), 10).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].seq, 1);
    }

    #[test]
    fn hwm_tracks_latest_per_sender() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_topic_log(tmp.path(), "abc").unwrap());
        let log = TopicLog::new(db);
        let a = [7u8; 32];
        let b = [8u8; 32];
        let a0 = make(a, 0, [0u8; 32]);
        let b0 = make(b, 0, [0u8; 32]);
        let a1 = make(a, 1, a0.message_hash().unwrap());
        log.append(&a0).unwrap();
        log.append(&b0).unwrap();
        log.append(&a1).unwrap();
        let hwm = log.hwm().unwrap();
        assert_eq!(hwm.get(&a).unwrap().0, 1);
        assert_eq!(hwm.get(&b).unwrap().0, 0);
    }

    #[test]
    fn read_all_returns_timestamp_sorted() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_topic_log(tmp.path(), "abc").unwrap());
        let log = TopicLog::new(db);
        let a = [7u8; 32];
        let b = [8u8; 32];
        let mut a0 = make(a, 0, [0u8; 32]); a0.timestamp = 2;
        let mut b0 = make(b, 0, [0u8; 32]); b0.timestamp = 1;
        log.append(&a0).unwrap();
        log.append(&b0).unwrap();
        let all = log.read_all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].timestamp, 1);
        assert_eq!(all[1].timestamp, 2);
    }
}

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use snafu::ResultExt;
use wires_core::WireMessage;
use wires_net::replay::{Pubkey, ReplaySource};
use wires_store::{open_topic_log, TopicLog};

use crate::error::{Result, StoreSnafu};

/// Stores one TopicLog per topic_id, lazily opened.
pub struct TopicLogs {
    root: PathBuf,
    logs: RwLock<HashMap<[u8; 32], Arc<TopicLog>>>,
}

impl TopicLogs {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            logs: RwLock::new(HashMap::new()),
        }
    }

    pub fn get_or_open(&self, topic_id: &[u8; 32]) -> Result<Arc<TopicLog>> {
        if let Some(log) = self.logs.read().unwrap().get(topic_id).cloned() {
            return Ok(log);
        }
        let mut w = self.logs.write().unwrap();
        if let Some(log) = w.get(topic_id).cloned() {
            return Ok(log);
        }
        let hex_id = hex::encode(topic_id);
        let db = open_topic_log(&self.root, &hex_id).context(StoreSnafu)?;
        let log = Arc::new(TopicLog::new(Arc::new(db)));
        w.insert(*topic_id, Arc::clone(&log));
        Ok(log)
    }
}

impl ReplaySource for TopicLogs {
    fn read_after(
        &self,
        topic_id: &[u8; 32],
        sender: &Pubkey,
        after_seq: Option<u64>,
        limit: usize,
    ) -> std::result::Result<Vec<WireMessage>, Box<dyn std::error::Error + Send + Sync>> {
        let log = self.get_or_open(topic_id)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        log.read_after(sender, after_seq, limit)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    fn all_senders_for(
        &self,
        topic_id: &[u8; 32],
    ) -> std::result::Result<Vec<Pubkey>, Box<dyn std::error::Error + Send + Sync>> {
        let log = self.get_or_open(topic_id)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        let hwm = log.hwm()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        Ok(hwm.into_keys().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use wires_core::MessageKind;

    fn make(seq: u64) -> WireMessage {
        WireMessage {
            topic_id: [1u8; 32],
            epoch: 0,
            kind: MessageKind::Standard,
            sender: [7u8; 32],
            cap_id: [0u8; 16],
            seq,
            prev_hash: [0u8; 32],
            timestamp: seq as i64,
            payload_len: 0,
            signature: [0u8; 64],
            ciphertext: vec![],
        }
    }

    #[test]
    fn opens_lazily_and_caches() {
        let tmp = TempDir::new().unwrap();
        let logs = TopicLogs::new(tmp.path());
        let a = logs.get_or_open(&[1u8; 32]).unwrap();
        let b = logs.get_or_open(&[1u8; 32]).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        let _c = logs.get_or_open(&[2u8; 32]).unwrap();
    }

    #[test]
    fn replay_source_returns_after_offset() {
        let tmp = TempDir::new().unwrap();
        let logs = TopicLogs::new(tmp.path());
        let topic = [1u8; 32];
        let log = logs.get_or_open(&topic).unwrap();
        let m0 = make(0);
        let mut m1 = make(1);
        m1.prev_hash = m0.message_hash().unwrap();
        log.append(&m0).unwrap();
        log.append(&m1).unwrap();
        let got: Vec<_> = ReplaySource::read_after(&logs, &topic, &[7u8; 32], Some(0), 10).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].seq, 1);
    }
}

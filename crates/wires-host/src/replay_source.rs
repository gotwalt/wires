//! `ReplaySource` impl that routes per-fabric via the topic_index.

use std::sync::Arc;

use wires_core::WireMessage;
use wires_net::replay::{Pubkey, ReplaySource};

use crate::fabric_registry::FabricRegistry;
use crate::per_fabric_logs::PerFabricLogs;

pub struct PerFabricReplaySource {
    registry: Arc<FabricRegistry>,
    logs: Arc<PerFabricLogs>,
}

impl PerFabricReplaySource {
    pub fn new(registry: Arc<FabricRegistry>, logs: Arc<PerFabricLogs>) -> Self {
        Self { registry, logs }
    }
}

impl ReplaySource for PerFabricReplaySource {
    fn read_after(
        &self,
        topic_id: &[u8; 32],
        sender: &Pubkey,
        after_seq: Option<u64>,
        limit: usize,
    ) -> std::result::Result<Vec<WireMessage>, Box<dyn std::error::Error + Send + Sync>> {
        let root = match self.registry.lookup_topic_fabric(topic_id) {
            Ok(Some(r)) => r,
            Ok(None) => return Ok(vec![]),
            Err(e) => return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
        };
        let log = self
            .logs
            .get_or_open(&root, topic_id)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        log.read_after(sender, after_seq, limit)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    fn all_senders_for(
        &self,
        topic_id: &[u8; 32],
    ) -> std::result::Result<Vec<Pubkey>, Box<dyn std::error::Error + Send + Sync>> {
        let root = match self.registry.lookup_topic_fabric(topic_id) {
            Ok(Some(r)) => r,
            Ok(None) => return Ok(vec![]),
            Err(e) => return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
        };
        let log = self
            .logs
            .get_or_open(&root, topic_id)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        let hwm = log
            .hwm()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        Ok(hwm.into_keys().collect())
    }
}

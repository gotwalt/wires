//! Inbound envelope router: resolves topic → fabric, applies write-rate
//! limits, appends to per-fabric log, records in retention.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use snafu::ResultExt as _;
use wires_core::WireMessage;

use crate::error::{Result, StoreSnafu};
use crate::fabric_registry::{FabricRecord, FabricRegistry, FabricStatus};
use crate::per_fabric_logs::PerFabricLogs;
use crate::retention::Retention;

pub struct WriteRateLimiter {
    per_sec: u32,
    buckets: RwLock<HashMap<[u8; 32], (Instant, u32)>>,
}

impl WriteRateLimiter {
    pub fn new(per_sec: u32) -> Self {
        Self {
            per_sec,
            buckets: RwLock::new(HashMap::new()),
        }
    }

    /// Returns `true` if the request is within the per-fabric per-second cap.
    pub fn try_acquire(&self, root_pubkey: &[u8; 32]) -> bool {
        let mut map = self.buckets.write().unwrap();
        let now = Instant::now();
        let entry = map.entry(*root_pubkey).or_insert((now, 0));
        if now.duration_since(entry.0).as_secs() >= 1 {
            *entry = (now, 0);
        }
        if entry.1 >= self.per_sec {
            return false;
        }
        entry.1 += 1;
        true
    }
}

pub struct Router {
    registry: Arc<FabricRegistry>,
    logs: Arc<PerFabricLogs>,
    retention: Arc<Retention>,
    rate: Arc<WriteRateLimiter>,
}

#[derive(Debug)]
pub enum RouteOutcome {
    Appended,
    DroppedUnknownTopic,
    DroppedSuspended,
    DroppedRateLimited,
    DroppedDuplicate,
}

impl Router {
    pub fn new(
        registry: Arc<FabricRegistry>,
        logs: Arc<PerFabricLogs>,
        retention: Arc<Retention>,
        rate: Arc<WriteRateLimiter>,
    ) -> Self {
        Self {
            registry,
            logs,
            retention,
            rate,
        }
    }

    pub fn route(&self, msg: &WireMessage) -> Result<RouteOutcome> {
        let root_pubkey = match self.registry.lookup_topic_fabric(&msg.topic_id)? {
            Some(r) => r,
            None => return Ok(RouteOutcome::DroppedUnknownTopic),
        };
        let rec: FabricRecord = match self.registry.get(&root_pubkey)? {
            Some(r) => r,
            None => return Ok(RouteOutcome::DroppedUnknownTopic),
        };
        if rec.status == FabricStatus::Suspended {
            return Ok(RouteOutcome::DroppedSuspended);
        }
        if !self.rate.try_acquire(&root_pubkey) {
            return Ok(RouteOutcome::DroppedRateLimited);
        }
        // Signature verification happens in the caller (wires-host main loop)
        // because that uses wires_core::verify_envelope which is unchanged.

        let log = self.logs.get_or_open(&root_pubkey, &msg.topic_id)?;
        let inserted = log.append(msg).context(StoreSnafu)?;
        if !inserted {
            return Ok(RouteOutcome::DroppedDuplicate);
        }
        let bytes = serde_json::to_vec(msg).map(|v| v.len() as u32).unwrap_or(0);
        self.retention.on_append(
            &root_pubkey,
            &msg.topic_id,
            &msg.sender,
            msg.seq,
            bytes,
            rec.retention_budget_bytes,
        )?;
        Ok(RouteOutcome::Appended)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fabric_registry::{FabricRecord, FabricStatus};
    use tempfile::TempDir;
    use wires_core::{MessageKind, WireMessage};

    fn dummy_msg(topic: [u8; 32], sender: u8, seq: u64) -> WireMessage {
        WireMessage {
            topic_id: topic,
            epoch: 0,
            kind: MessageKind::Standard,
            sender: [sender; 32],
            cap_id: [0u8; 16],
            seq,
            prev_hash: [0u8; 32],
            timestamp: seq as i64,
            payload_len: 1,
            signature: [0u8; 64],
            ciphertext: vec![1, 2, 3, 4],
        }
    }

    fn router_with_one_fabric(tmp: &TempDir, topic: [u8; 32]) -> (Router, [u8; 32]) {
        let registry = Arc::new(FabricRegistry::open(tmp.path()).unwrap());
        let logs = Arc::new(PerFabricLogs::new(tmp.path()));
        let retention = Arc::new(Retention::new(tmp.path(), Arc::clone(&logs)));
        let rate = Arc::new(WriteRateLimiter::new(1_000_000));
        let root = [3u8; 32];
        registry
            .insert_if_absent(
                &root,
                FabricRecord {
                    registered_at: 0,
                    status: FabricStatus::Active,
                    retention_budget_bytes: u64::MAX,
                },
            )
            .unwrap();
        registry.register_topic(&root, &topic).unwrap();
        (Router::new(registry, logs, retention, rate), root)
    }

    #[test]
    fn unknown_topic_is_dropped() {
        let tmp = TempDir::new().unwrap();
        let registry = Arc::new(FabricRegistry::open(tmp.path()).unwrap());
        let logs = Arc::new(PerFabricLogs::new(tmp.path()));
        let retention = Arc::new(Retention::new(tmp.path(), Arc::clone(&logs)));
        let rate = Arc::new(WriteRateLimiter::new(1_000));
        let router = Router::new(registry, logs, retention, rate);
        let msg = dummy_msg([1u8; 32], 7, 0);
        let out = router.route(&msg).unwrap();
        assert!(matches!(out, RouteOutcome::DroppedUnknownTopic));
    }

    #[test]
    fn registered_topic_appends() {
        let tmp = TempDir::new().unwrap();
        let topic = [5u8; 32];
        let (router, _root) = router_with_one_fabric(&tmp, topic);
        let msg = dummy_msg(topic, 7, 0);
        let out = router.route(&msg).unwrap();
        assert!(matches!(out, RouteOutcome::Appended));
    }

    #[test]
    fn rate_limit_blocks_excess() {
        let tmp = TempDir::new().unwrap();
        let topic = [5u8; 32];
        let registry = Arc::new(FabricRegistry::open(tmp.path()).unwrap());
        let logs = Arc::new(PerFabricLogs::new(tmp.path()));
        let retention = Arc::new(Retention::new(tmp.path(), Arc::clone(&logs)));
        let rate = Arc::new(WriteRateLimiter::new(1)); // 1/sec
        let root = [3u8; 32];
        registry
            .insert_if_absent(
                &root,
                FabricRecord {
                    registered_at: 0,
                    status: FabricStatus::Active,
                    retention_budget_bytes: u64::MAX,
                },
            )
            .unwrap();
        registry.register_topic(&root, &topic).unwrap();
        let router = Router::new(registry, logs, retention, rate);

        let msg0 = dummy_msg(topic, 7, 0);
        let msg1 = dummy_msg(topic, 7, 1);
        assert!(matches!(
            router.route(&msg0).unwrap(),
            RouteOutcome::Appended
        ));
        assert!(matches!(
            router.route(&msg1).unwrap(),
            RouteOutcome::DroppedRateLimited
        ));
    }
}

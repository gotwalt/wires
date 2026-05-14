use std::collections::HashMap;

use snafu::ResultExt;
use wires_net::replay::{HwmEntry, ReplaySource};
use wires_store::StoreError;

use crate::error::{Result, StoreSnafu};
use crate::inbound::{Inbound, InboundCtx, process};

type Hwm = HashMap<[u8; 32], (u64, [u8; 32])>;

/// Read the hwm from the topic log, returning an empty map if the table has
/// not yet been created (i.e. no messages have ever been written).
fn read_hwm(ctx: &InboundCtx) -> Result<Hwm> {
    match ctx.topic_log.hwm() {
        Ok(m) => Ok(m),
        Err(StoreError::OpenTable {
            source: redb::TableError::TableDoesNotExist(_),
            ..
        }) => Ok(HashMap::new()),
        Err(e) => Err(e).context(StoreSnafu),
    }
}

/// Drive one sync pass over `source` for the given topic. Reads each sender's
/// messages past our local hwm and feeds them through `process()`.
///
/// Returns the count of accepted messages.
pub fn drive_sync_pass(
    ctx: &InboundCtx,
    source: &dyn ReplaySource,
    topic_id: &[u8; 32],
) -> Result<usize> {
    let hwm = read_hwm(ctx)?;
    let senders =
        source
            .all_senders_for(topic_id)
            .map_err(|e| crate::error::NodeError::Config {
                message: format!("replay source failure: {e}"),
                location: snafu::location!(),
            })?;

    let mut applied = 0usize;
    for sender in senders {
        let after = hwm.get(&sender).map(|(s, _)| *s);
        let batch = source
            .read_after(topic_id, &sender, after, 1024)
            .map_err(|e| crate::error::NodeError::Config {
                message: format!("replay source failure: {e}"),
                location: snafu::location!(),
            })?;
        for msg in batch {
            match process(ctx, msg)? {
                Inbound::Accepted { .. } | Inbound::AcceptedOpaque { .. } => applied += 1,
                Inbound::Rejected { reason, .. } => {
                    tracing::warn!(reason = %reason, "drop msg during sync");
                }
            }
        }
    }
    Ok(applied)
}

/// Build an `hwm` map (hex-keyed) suitable for `ReplayRequest::hwm`.
pub fn current_hwm_for_request(ctx: &InboundCtx) -> Result<HashMap<String, HwmEntry>> {
    let hwm = read_hwm(ctx)?;
    let mut out = HashMap::new();
    for (k, (seq, hash)) in hwm {
        out.insert(hex::encode(k), HwmEntry { seq, hash });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publish::{KeyingMaterial, PublishParams, build_message};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;
    use wires_core::cap::Right;
    use wires_core::{CanonicalContent, Capability, MessageKind, WireMessage};
    use wires_crypto::{X25519Public, X25519Secret};
    use wires_store::{
        CapTable, EpochKeyStore, TopicLog, open_caps, open_topic_keys, open_topic_log,
    };

    /// In-memory replay source for testing.
    struct MemSource {
        msgs: Mutex<Vec<WireMessage>>,
    }

    impl ReplaySource for MemSource {
        fn read_after(
            &self,
            topic_id: &[u8; 32],
            sender: &[u8; 32],
            after_seq: Option<u64>,
            limit: usize,
        ) -> std::result::Result<Vec<WireMessage>, Box<dyn std::error::Error + Send + Sync>>
        {
            let lock = self.msgs.lock().unwrap();
            let mut out: Vec<WireMessage> = lock
                .iter()
                .filter(|m| &m.topic_id == topic_id && &m.sender == sender)
                .filter(|m| after_seq.map(|s| m.seq > s).unwrap_or(true))
                .cloned()
                .collect();
            out.sort_by_key(|m| m.seq);
            out.truncate(limit);
            Ok(out)
        }
        fn all_senders_for(
            &self,
            topic_id: &[u8; 32],
        ) -> std::result::Result<Vec<[u8; 32]>, Box<dyn std::error::Error + Send + Sync>> {
            let lock = self.msgs.lock().unwrap();
            let mut senders: Vec<[u8; 32]> = lock
                .iter()
                .filter(|m| &m.topic_id == topic_id)
                .map(|m| m.sender)
                .collect();
            senders.sort();
            senders.dedup();
            Ok(senders)
        }
    }

    #[test]
    fn sync_applies_remote_messages() {
        let tmp = TempDir::new().unwrap();
        let log = TopicLog::new(Arc::new(open_topic_log(tmp.path(), "x").unwrap()));
        let keys = EpochKeyStore::new(Arc::new(open_topic_keys(tmp.path(), "x").unwrap())).unwrap();
        let caps = CapTable::new(Arc::new(open_caps(tmp.path()).unwrap()));
        let xsk = X25519Secret::random_from_rng(OsRng);
        let xpk = X25519Public::from(&xsk).to_bytes();

        let root = SigningKey::generate(&mut OsRng);
        let sender_sk = SigningKey::generate(&mut OsRng);
        let sender_pk = sender_sk.verifying_key().to_bytes();
        let mut cap = Capability::new_unsigned(
            sender_pk,
            vec!["__caps".into()],
            vec![Right::Write],
            0,
            None,
        );
        cap.sign(&root).unwrap();
        caps.upsert_grant(&cap).unwrap();

        let m0 = build_message(&PublishParams {
            topic_id: [1u8; 32],
            sender_sk: &sender_sk,
            cap_id: cap.cap_id.0,
            kind: MessageKind::Public,
            content: CanonicalContent::new("__cap.revoke", "a"),
            epoch: 0,
            seq: 0,
            prev_hash: [0u8; 32],
            timestamp: 1,
            keying: KeyingMaterial::Public,
        })
        .unwrap();
        let m1 = build_message(&PublishParams {
            topic_id: [1u8; 32],
            sender_sk: &sender_sk,
            cap_id: cap.cap_id.0,
            kind: MessageKind::Public,
            content: CanonicalContent::new("__cap.revoke", "b"),
            epoch: 0,
            seq: 1,
            prev_hash: m0.message_hash().unwrap(),
            timestamp: 2,
            keying: KeyingMaterial::Public,
        })
        .unwrap();

        let source = MemSource {
            msgs: Mutex::new(vec![m0, m1]),
        };
        let ctx = InboundCtx {
            topic_log: &log,
            epoch_keys: &keys,
            cap_table: &caps,
            self_x25519_sk: &xsk,
            self_x25519_pk: &xpk,
        };
        let applied = drive_sync_pass(&ctx, &source, &[1u8; 32]).unwrap();
        assert_eq!(applied, 2);

        // Second pass: log idempotently re-accepts but the count includes both since process()
        // returns Accepted/AcceptedOpaque for already-stored messages too. The point is no errors.
        let _ = drive_sync_pass(&ctx, &source, &[1u8; 32]).unwrap();
    }

    #[test]
    fn empty_source_returns_zero() {
        let tmp = TempDir::new().unwrap();
        let log = TopicLog::new(Arc::new(open_topic_log(tmp.path(), "x").unwrap()));
        let keys = EpochKeyStore::new(Arc::new(open_topic_keys(tmp.path(), "x").unwrap())).unwrap();
        let caps = CapTable::new(Arc::new(open_caps(tmp.path()).unwrap()));
        let xsk = X25519Secret::random_from_rng(OsRng);
        let xpk = X25519Public::from(&xsk).to_bytes();

        let source = MemSource {
            msgs: Mutex::new(vec![]),
        };
        let ctx = InboundCtx {
            topic_log: &log,
            epoch_keys: &keys,
            cap_table: &caps,
            self_x25519_sk: &xsk,
            self_x25519_pk: &xpk,
        };
        let applied = drive_sync_pass(&ctx, &source, &[1u8; 32]).unwrap();
        assert_eq!(applied, 0);
    }

    #[test]
    fn current_hwm_for_request_returns_hex_keyed_map() {
        let tmp = TempDir::new().unwrap();
        let log = TopicLog::new(Arc::new(open_topic_log(tmp.path(), "x").unwrap()));
        let keys = EpochKeyStore::new(Arc::new(open_topic_keys(tmp.path(), "x").unwrap())).unwrap();
        let caps = CapTable::new(Arc::new(open_caps(tmp.path()).unwrap()));
        let xsk = X25519Secret::random_from_rng(OsRng);
        let xpk = X25519Public::from(&xsk).to_bytes();

        let m = WireMessage {
            topic_id: [1u8; 32],
            epoch: 0,
            kind: MessageKind::Standard,
            sender: [7u8; 32],
            cap_id: [0u8; 16],
            seq: 0,
            prev_hash: [0u8; 32],
            timestamp: 0,
            payload_len: 0,
            signature: [0u8; 64],
            ciphertext: vec![],
        };
        log.append(&m).unwrap();

        let ctx = InboundCtx {
            topic_log: &log,
            epoch_keys: &keys,
            cap_table: &caps,
            self_x25519_sk: &xsk,
            self_x25519_pk: &xpk,
        };
        let map = current_hwm_for_request(&ctx).unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(&hex::encode([7u8; 32])));
    }
}

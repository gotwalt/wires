//! The `Node` is the agent-facing runtime. Owns identity keys, local storage,
//! and a broadcast channel for decrypted events. The networking (iroh endpoint,
//! gossip, replay client) is wired in by `NetGlue`.

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use parking_lot::Mutex;
use snafu::ResultExt;
use tokio::sync::broadcast;
use wires_core::{CanonicalContent, MessageKind, WireMessage};
use wires_crypto::{X25519Public, X25519Secret};
use wires_store::{CapTable, EpochKey, EpochKeyStore, open_caps, open_topic_keys};

use crate::config::NodeConfig;
use crate::error::{IoSnafu, NetSnafu, Result, StoreSnafu};
use crate::inbound::{Inbound, InboundCtx, process};
use crate::publish::{
    KeyingMaterial, PublishParams, build_message, current_epoch_key, next_seq_and_prev_hash,
};
use crate::storage::TopicLogs;
use wires_net::unix_now_ms;

pub struct Node {
    pub config: NodeConfig,
    pub ed_sk: SigningKey,
    pub x_sk: X25519Secret,
    pub x_pk: [u8; 32],
    pub logs: Arc<TopicLogs>,
    pub caps: Arc<CapTable>,
    keys_by_topic: Mutex<HashMap<[u8; 32], Arc<EpochKeyStore>>>,
    pub events_tx: broadcast::Sender<DecryptedEvent>,
    /// Serializes the read-build-append sequence in `publish_standard`. Without
    /// it, two concurrent publishes on the same (topic, sender) would both read
    /// the same hwm seq, encrypt under the same deterministic ChaCha20 nonce
    /// (derived from topic_id || sender || seq), and only fail at `log.append`
    /// — long after the AEAD key was reused. See substrate spec invariant #5.
    publish_lock: Mutex<()>,
}

#[derive(Debug, Clone)]
pub struct DecryptedEvent {
    pub topic_id: [u8; 32],
    pub msg: WireMessage,
    pub content: Option<CanonicalContent>,
}

/// A decrypted message returned by `Node::read_decrypted_since` for cursor-based
/// pagination (used by the MCP gateway's `wires.tail` tool).
#[derive(Debug, Clone)]
pub struct DecryptedMessage {
    pub envelope: WireMessage,
    pub content: Option<CanonicalContent>,
}

impl Node {
    pub fn open(config: NodeConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.data_dir).context(IoSnafu)?;
        let secret_path = config.data_dir.join("identity.ed25519");
        let secret = wires_net::load_or_create_secret(&secret_path).context(NetSnafu)?;
        let ed_sk = SigningKey::from_bytes(&secret);

        let x_path = config.data_dir.join("identity.x25519");
        let x_secret = wires_net::load_or_create_secret(&x_path).context(NetSnafu)?;
        let x_sk = X25519Secret::from(x_secret);
        let x_pk = X25519Public::from(&x_sk).to_bytes();

        let logs = Arc::new(TopicLogs::new(&config.data_dir));
        let caps_db = open_caps(&config.data_dir).context(StoreSnafu)?;
        let caps = Arc::new(CapTable::new(Arc::new(caps_db)));
        let (events_tx, _) = broadcast::channel::<DecryptedEvent>(1024);

        Ok(Self {
            config,
            ed_sk,
            x_sk,
            x_pk,
            logs,
            caps,
            keys_by_topic: Mutex::new(HashMap::new()),
            events_tx,
            publish_lock: Mutex::new(()),
        })
    }

    pub fn epoch_keys_for(&self, topic_id: &[u8; 32]) -> Result<Arc<EpochKeyStore>> {
        let mut m = self.keys_by_topic.lock();
        if let Some(e) = m.get(topic_id) {
            return Ok(Arc::clone(e));
        }
        let hex_id = hex::encode(topic_id);
        let db = open_topic_keys(&self.config.data_dir, &hex_id).context(StoreSnafu)?;
        let store = Arc::new(EpochKeyStore::new(Arc::new(db)).context(StoreSnafu)?);
        m.insert(*topic_id, Arc::clone(&store));
        Ok(store)
    }

    /// Publish a `Standard`-mode message to `topic_id` using `cap_id` (must be
    /// granted to this agent). Looks up the current epoch and the local hwm.
    pub fn publish_standard(
        &self,
        topic_id: [u8; 32],
        cap_id: [u8; 16],
        content: CanonicalContent,
    ) -> Result<WireMessage> {
        let _guard = self.publish_lock.lock();
        let log = self.logs.get_or_open(&topic_id)?;
        let keys = self.epoch_keys_for(&topic_id)?;
        let sender_pk = self.ed_sk.verifying_key().to_bytes();
        let (seq, prev_hash) = next_seq_and_prev_hash(&log, &sender_pk)?;
        let (epoch, epoch_key) = current_epoch_key(&keys, &topic_id)?;

        let msg = build_message(&PublishParams {
            topic_id,
            sender_sk: &self.ed_sk,
            cap_id,
            kind: MessageKind::Standard,
            content,
            epoch,
            seq,
            prev_hash,
            timestamp: unix_now_ms(),
            keying: KeyingMaterial::StandardEpochKey(&epoch_key),
        })?;
        log.append(&msg).context(StoreSnafu)?;
        let _ = self.events_tx.send(DecryptedEvent {
            topic_id,
            msg: msg.clone(),
            content: None,
        });
        Ok(msg)
    }

    /// Process an inbound message that arrived via gossip or replay.
    pub fn handle_inbound(&self, msg: WireMessage) -> Result<Inbound> {
        let log = self.logs.get_or_open(&msg.topic_id)?;
        let keys = self.epoch_keys_for(&msg.topic_id)?;
        let ctx = InboundCtx {
            topic_log: &log,
            epoch_keys: &keys,
            cap_table: &self.caps,
            self_x25519_sk: &self.x_sk,
            self_x25519_pk: &self.x_pk,
        };
        let outcome = process(&ctx, msg.clone())?;
        match &outcome {
            Inbound::Accepted { msg, content } => {
                let _ = self.events_tx.send(DecryptedEvent {
                    topic_id: msg.topic_id,
                    msg: msg.clone(),
                    content: content.clone(),
                });
            }
            Inbound::AcceptedOpaque { msg } => {
                let _ = self.events_tx.send(DecryptedEvent {
                    topic_id: msg.topic_id,
                    msg: msg.clone(),
                    content: None,
                });
            }
            Inbound::Rejected { .. } => {}
        }
        Ok(outcome)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<DecryptedEvent> {
        self.events_tx.subscribe()
    }

    /// Read all decrypted messages from `topic_id` that are strictly after the
    /// per-sender high-water marks in `hwm` (sender_hex → last seen seq).
    /// Returns up to `limit` messages sorted by (timestamp, sender, seq).
    ///
    /// This is the "tail" surface used by the MCP gateway. The hwm map starts
    /// empty (meaning "from genesis") and is advanced by the caller via the
    /// returned cursor after each call.
    ///
    /// Reads are side-effect free: they do not broadcast `DecryptedEvent`s to
    /// `subscribe()` listeners, since the events represent live traffic and a
    /// historical read shouldn't masquerade as one.
    pub fn read_decrypted_since(
        &self,
        topic_id: &[u8; 32],
        hwm: &std::collections::HashMap<String, (u64, String)>,
        limit: usize,
    ) -> Result<Vec<DecryptedMessage>> {
        let log = self.logs.get_or_open(topic_id)?;
        // Enumerate senders from the log's HWM map, then range-scan each.
        // Avoids loading the entire topic log into memory just to filter.
        let log_hwm = log.hwm().context(StoreSnafu)?;
        let mut flat: Vec<WireMessage> = Vec::new();
        for sender_pk in log_hwm.keys() {
            let after_seq = hwm.get(&hex::encode(sender_pk)).map(|(seq, _)| *seq);
            let msgs = log
                .read_after(sender_pk, after_seq, limit)
                .context(StoreSnafu)?;
            flat.extend(msgs);
        }
        flat.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then(a.sender.cmp(&b.sender))
                .then(a.seq.cmp(&b.seq))
        });
        flat.truncate(limit);
        // Decrypt-only path: runs `process` directly without going through
        // `handle_inbound` (which broadcasts).
        let mut out = Vec::with_capacity(flat.len());
        for msg in flat {
            let outcome = self.decrypt_only(msg.clone())?;
            let content = match outcome {
                crate::inbound::Inbound::Accepted { content, .. } => content,
                _ => None,
            };
            out.push(DecryptedMessage {
                envelope: msg,
                content,
            });
        }
        Ok(out)
    }

    /// Decrypt + validate a message without broadcasting an event. Used by
    /// `read_decrypted_since` so historical reads don't leak as live traffic
    /// to subscribers.
    fn decrypt_only(&self, msg: WireMessage) -> Result<Inbound> {
        let log = self.logs.get_or_open(&msg.topic_id)?;
        let keys = self.epoch_keys_for(&msg.topic_id)?;
        let ctx = InboundCtx {
            topic_log: &log,
            epoch_keys: &keys,
            cap_table: &self.caps,
            self_x25519_sk: &self.x_sk,
            self_x25519_pk: &self.x_pk,
        };
        process(&ctx, msg)
    }

    pub fn install_epoch_key(&self, topic_id: [u8; 32], epoch: u32, key: EpochKey) -> Result<()> {
        let keys = self.epoch_keys_for(&topic_id)?;
        keys.put(epoch, &key).context(StoreSnafu)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use tempfile::TempDir;
    use wires_core::Capability;
    use wires_core::cap::Right;

    fn open_node(tmp: &TempDir, root_hex: String) -> Node {
        let cfg = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            root_pubkey_hex: root_hex,
            host: None,
        };
        Node::open(cfg).unwrap()
    }

    #[tokio::test]
    async fn publish_appears_to_subscriber() {
        let tmp = TempDir::new().unwrap();
        let root = SigningKey::generate(&mut OsRng);
        let root_hex = hex::encode(root.verifying_key().to_bytes());
        let node = open_node(&tmp, root_hex);

        let sender_pk = node.ed_sk.verifying_key().to_bytes();
        let mut cap = Capability::new_unsigned(
            sender_pk,
            vec!["home.test".into()],
            vec![Right::Read, Right::Write],
            0,
            None,
        );
        cap.sign(&root).unwrap();
        let cap_id = cap.cap_id.0;
        node.caps.upsert_grant(&cap).unwrap();

        let topic_id = [42u8; 32];
        node.install_epoch_key(topic_id, 0, [9u8; 32]).unwrap();

        let mut sub = node.subscribe();
        let _msg = node
            .publish_standard(
                topic_id,
                cap_id,
                CanonicalContent::new("home.test", "hello"),
            )
            .unwrap();
        let ev = sub.recv().await.unwrap();
        assert_eq!(ev.topic_id, topic_id);
    }

    #[tokio::test]
    async fn read_decrypted_since_does_not_broadcast_historical_messages() {
        // Reading history must be side-effect-free: a separate live subscriber
        // shouldn't see historical messages re-broadcast as if they just
        // arrived. Regression test for the leak in the original implementation
        // where read_decrypted_since called handle_inbound (which broadcasts).
        let tmp = TempDir::new().unwrap();
        let root = SigningKey::generate(&mut OsRng);
        let root_hex = hex::encode(root.verifying_key().to_bytes());
        let node = open_node(&tmp, root_hex);

        let sender_pk = node.ed_sk.verifying_key().to_bytes();
        let mut cap = Capability::new_unsigned(
            sender_pk,
            vec!["home.test".into()],
            vec![Right::Read, Right::Write],
            0,
            None,
        );
        cap.sign(&root).unwrap();
        let cap_id = cap.cap_id.0;
        node.caps.upsert_grant(&cap).unwrap();

        let topic_id = [42u8; 32];
        node.install_epoch_key(topic_id, 0, [9u8; 32]).unwrap();

        // Publish two messages first (these broadcast — expected).
        node.publish_standard(
            topic_id,
            cap_id,
            CanonicalContent::new("home.test", "first"),
        )
        .unwrap();
        node.publish_standard(
            topic_id,
            cap_id,
            CanonicalContent::new("home.test", "second"),
        )
        .unwrap();

        // Now attach a fresh subscriber and read history.
        let mut sub = node.subscribe();
        let history = node
            .read_decrypted_since(&topic_id, &std::collections::HashMap::new(), 100)
            .unwrap();
        assert_eq!(history.len(), 2, "expected both messages in history");

        // The fresh subscriber must NOT see the historical messages — they
        // happened before subscribe() was called and the read should be
        // side-effect free.
        match sub.try_recv() {
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {}
            Ok(ev) => panic!("history leaked into live broadcast: {:?}", ev),
            Err(e) => panic!("unexpected channel state: {e:?}"),
        }
    }

    #[test]
    fn open_persists_identity_across_reopens() {
        let tmp = TempDir::new().unwrap();
        let cfg = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            root_pubkey_hex: "deadbeef".into(),
            host: None,
        };
        let node_a = Node::open(cfg.clone()).unwrap();
        let pk_a = node_a.ed_sk.verifying_key().to_bytes();
        drop(node_a);
        let node_b = Node::open(cfg).unwrap();
        let pk_b = node_b.ed_sk.verifying_key().to_bytes();
        assert_eq!(pk_a, pk_b);
    }

    #[test]
    fn install_and_lookup_epoch_key() {
        let tmp = TempDir::new().unwrap();
        let cfg = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            root_pubkey_hex: "deadbeef".into(),
            host: None,
        };
        let node = Node::open(cfg).unwrap();
        node.install_epoch_key([1u8; 32], 0, [7u8; 32]).unwrap();
        let keys = node.epoch_keys_for(&[1u8; 32]).unwrap();
        assert_eq!(keys.get(0).unwrap().unwrap(), [7u8; 32]);
    }

    #[tokio::test]
    async fn concurrent_publish_assigns_unique_seqs() {
        // Regression test for the publish race that would produce two messages
        // at the same seq under the same deterministic ChaCha20 nonce.
        let tmp = TempDir::new().unwrap();
        let root = SigningKey::generate(&mut OsRng);
        let root_hex = hex::encode(root.verifying_key().to_bytes());
        let node = Arc::new(open_node(&tmp, root_hex));

        let sender_pk = node.ed_sk.verifying_key().to_bytes();
        let mut cap = Capability::new_unsigned(
            sender_pk,
            vec!["home.test".into()],
            vec![Right::Read, Right::Write],
            0,
            None,
        );
        cap.sign(&root).unwrap();
        let cap_id = cap.cap_id.0;
        node.caps.upsert_grant(&cap).unwrap();

        let topic_id = [42u8; 32];
        node.install_epoch_key(topic_id, 0, [9u8; 32]).unwrap();

        let n: u64 = 32;
        let mut handles = Vec::with_capacity(n as usize);
        for i in 0..n {
            let node = Arc::clone(&node);
            handles.push(tokio::task::spawn_blocking(move || {
                node.publish_standard(
                    topic_id,
                    cap_id,
                    CanonicalContent::new("home.test", format!("msg-{i}")),
                )
                .unwrap()
            }));
        }
        let mut seqs: Vec<u64> = Vec::new();
        for h in handles {
            seqs.push(h.await.unwrap().seq);
        }
        seqs.sort();
        assert_eq!(seqs, (0..n).collect::<Vec<_>>());
    }
}

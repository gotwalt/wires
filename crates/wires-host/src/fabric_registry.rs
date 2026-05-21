//! Fabrics, topic→fabric index, and registration nonces.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::error::{
    CommitSnafu, DbOpenSnafu, IoSnafu, Result, SerdeSnafu, StorageIoSnafu, TableSnafu, TxnSnafu,
};

/// Key = root_pubkey (32 bytes). Value = JSON `FabricRecord`.
pub const FABRICS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("fabrics");

/// Key = topic_id (32 bytes). Value = root_pubkey (32 bytes).
pub const TOPIC_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("topic_index");

/// Key = root_pubkey (32) || nonce (16) = 48 bytes. Value = u64 BE expires_at_unix_ms.
pub const NONCES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("nonces");

/// Default per-fabric retention budget: 1 GiB.
pub const DEFAULT_RETENTION_BUDGET_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FabricStatus {
    Active,
    Suspended,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FabricRecord {
    pub registered_at: i64,
    pub status: FabricStatus,
    pub retention_budget_bytes: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TopicRegisterOutcome {
    Inserted,
    AlreadyOwned,
    Conflict { other_root: [u8; 32] },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricDeleteOutcome {
    /// Whether a fabric row was found before deletion.
    pub existed: bool,
    /// Every topic_id that was removed from the topic_index as part of this delete.
    pub topics_removed: Vec<[u8; 32]>,
}

pub struct FabricRegistry {
    pub root: PathBuf,
    fabrics_db: Arc<Database>,
    topic_index_db: Arc<Database>,
    nonces_db: Arc<Database>,
}

impl FabricRegistry {
    pub fn open(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root).context(IoSnafu)?;
        let fabrics_db =
            Arc::new(Database::create(root.join("fabrics.redb")).context(DbOpenSnafu)?);
        let topic_index_db =
            Arc::new(Database::create(root.join("topic_index.redb")).context(DbOpenSnafu)?);
        let nonces_db = Arc::new(Database::create(root.join("nonces.redb")).context(DbOpenSnafu)?);
        Ok(Self {
            root: root.to_path_buf(),
            fabrics_db,
            topic_index_db,
            nonces_db,
        })
    }

    /// Look up an existing fabric.
    pub fn get(&self, root_pubkey: &[u8; 32]) -> Result<Option<FabricRecord>> {
        let read = self.fabrics_db.begin_read().context(TxnSnafu)?;
        let table = match read.open_table(FABRICS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => {
                return Err(crate::error::HostError::Table {
                    source: e,
                    location: snafu::location!(),
                });
            }
        };
        match table.get(&root_pubkey[..]).context(StorageIoSnafu)? {
            Some(v) => {
                let rec: FabricRecord = serde_json::from_slice(v.value()).context(SerdeSnafu)?;
                Ok(Some(rec))
            }
            None => Ok(None),
        }
    }

    /// Insert a new fabric (idempotent: returns Ok with the existing record if
    /// already present).
    pub fn insert_if_absent(
        &self,
        root_pubkey: &[u8; 32],
        rec: FabricRecord,
    ) -> Result<FabricRecord> {
        if let Some(existing) = self.get(root_pubkey)? {
            return Ok(existing);
        }
        let json = serde_json::to_vec(&rec).context(SerdeSnafu)?;
        let write = self.fabrics_db.begin_write().context(TxnSnafu)?;
        {
            let mut t = write.open_table(FABRICS).context(TableSnafu)?;
            t.insert(&root_pubkey[..], json.as_slice())
                .context(StorageIoSnafu)?;
        }
        write.commit().context(CommitSnafu)?;
        Ok(rec)
    }

    pub fn lookup_topic_fabric(&self, topic_id: &[u8; 32]) -> Result<Option<[u8; 32]>> {
        let read = self.topic_index_db.begin_read().context(TxnSnafu)?;
        let table = match read.open_table(TOPIC_INDEX) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => {
                return Err(crate::error::HostError::Table {
                    source: e,
                    location: snafu::location!(),
                });
            }
        };
        match table.get(&topic_id[..]).context(StorageIoSnafu)? {
            Some(v) => {
                let raw = v.value();
                if raw.len() != 32 {
                    return Ok(None);
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(raw);
                Ok(Some(out))
            }
            None => Ok(None),
        }
    }

    pub fn register_topic(
        &self,
        root_pubkey: &[u8; 32],
        topic_id: &[u8; 32],
    ) -> Result<TopicRegisterOutcome> {
        let write = self.topic_index_db.begin_write().context(TxnSnafu)?;
        let outcome = {
            let mut table = write.open_table(TOPIC_INDEX).context(TableSnafu)?;
            let prior_data = table
                .get(&topic_id[..])
                .context(StorageIoSnafu)?
                .map(|guard| guard.value().to_vec());
            if let Some(raw) = prior_data {
                if raw == root_pubkey.as_slice() {
                    TopicRegisterOutcome::AlreadyOwned
                } else {
                    let mut other = [0u8; 32];
                    other.copy_from_slice(&raw);
                    TopicRegisterOutcome::Conflict { other_root: other }
                }
            } else {
                table
                    .insert(&topic_id[..], &root_pubkey[..])
                    .context(StorageIoSnafu)?;
                TopicRegisterOutcome::Inserted
            }
        };
        write.commit().context(CommitSnafu)?;
        Ok(outcome)
    }

    /// Every registered topic id. Used on host startup to resubscribe to the
    /// gossip mesh for all topics persisted from prior runs — without this,
    /// the host wakes up unsubscribed and silently misses traffic until each
    /// fabric re-registers.
    pub fn all_topic_ids(&self) -> Result<Vec<[u8; 32]>> {
        let read = self.topic_index_db.begin_read().context(TxnSnafu)?;
        let table = match read.open_table(TOPIC_INDEX) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => {
                return Err(crate::error::HostError::Table {
                    source: e,
                    location: snafu::location!(),
                });
            }
        };
        let mut out = Vec::new();
        for row in table.iter().context(StorageIoSnafu)? {
            let (k, _v) = row.context(StorageIoSnafu)?;
            let raw = k.value();
            if raw.len() == 32 {
                let mut id = [0u8; 32];
                id.copy_from_slice(raw);
                out.push(id);
            }
        }
        Ok(out)
    }

    /// Count the number of topics registered to `root_pubkey`.
    pub fn topic_count_for(&self, root_pubkey: &[u8; 32]) -> Result<u32> {
        let read = self.topic_index_db.begin_read().context(TxnSnafu)?;
        let table = match read.open_table(TOPIC_INDEX) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => {
                return Err(crate::error::HostError::Table {
                    source: e,
                    location: snafu::location!(),
                });
            }
        };
        let mut count = 0u32;
        for row in table.iter().context(StorageIoSnafu)? {
            let (_k, v) = row.context(StorageIoSnafu)?;
            if v.value() == root_pubkey.as_slice() {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }

    pub fn unregister_topic(&self, root_pubkey: &[u8; 32], topic_id: &[u8; 32]) -> Result<bool> {
        let write = self.topic_index_db.begin_write().context(TxnSnafu)?;
        let removed = {
            let mut table = write.open_table(TOPIC_INDEX).context(TableSnafu)?;
            let prior_data = table
                .get(&topic_id[..])
                .context(StorageIoSnafu)?
                .map(|guard| guard.value().to_vec());
            if let Some(raw) = prior_data {
                if raw == root_pubkey.as_slice() {
                    table.remove(&topic_id[..]).context(StorageIoSnafu)?;
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };
        write.commit().context(CommitSnafu)?;
        Ok(removed)
    }

    /// Remove the fabric row and every topic_index entry that maps to this
    /// `root_pubkey`. The two writes happen in separate transactions: topic
    /// index first (so routing stops immediately), then the fabric row. Each
    /// step is idempotent; calling on an unknown fabric returns
    /// `existed: false, topics_removed: vec![]`.
    pub fn delete_fabric(&self, root_pubkey: &[u8; 32]) -> Result<FabricDeleteOutcome> {
        // 1. Collect every topic_id owned by this fabric.
        let mut topics_removed: Vec<[u8; 32]> = Vec::new();
        {
            let read = self.topic_index_db.begin_read().context(TxnSnafu)?;
            match read.open_table(TOPIC_INDEX) {
                Ok(table) => {
                    for row in table.iter().context(StorageIoSnafu)? {
                        let (k, v) = row.context(StorageIoSnafu)?;
                        if v.value() == root_pubkey.as_slice() && k.value().len() == 32 {
                            let mut id = [0u8; 32];
                            id.copy_from_slice(k.value());
                            topics_removed.push(id);
                        }
                    }
                }
                Err(redb::TableError::TableDoesNotExist(_)) => {}
                Err(e) => {
                    return Err(crate::error::HostError::Table {
                        source: e,
                        location: snafu::location!(),
                    });
                }
            }
        }

        // 2. Remove every collected topic_id from the topic_index.
        if !topics_removed.is_empty() {
            let write = self.topic_index_db.begin_write().context(TxnSnafu)?;
            {
                let mut table = write.open_table(TOPIC_INDEX).context(TableSnafu)?;
                for topic in &topics_removed {
                    table.remove(&topic[..]).context(StorageIoSnafu)?;
                }
            }
            write.commit().context(CommitSnafu)?;
        }

        // 3. Delete the fabric row.
        let existed: bool = {
            let write = self.fabrics_db.begin_write().context(TxnSnafu)?;
            let was_present = {
                match write.open_table(FABRICS) {
                    Ok(mut table) => table
                        .remove(&root_pubkey[..])
                        .context(StorageIoSnafu)?
                        .is_some(),
                    Err(redb::TableError::TableDoesNotExist(_)) => false,
                    Err(e) => {
                        return Err(crate::error::HostError::Table {
                            source: e,
                            location: snafu::location!(),
                        });
                    }
                }
            };
            write.commit().context(CommitSnafu)?;
            was_present
        };

        Ok(FabricDeleteOutcome {
            existed,
            topics_removed,
        })
    }

    /// Returns `true` iff the (root_pubkey, nonce) pair was already seen within
    /// the TTL window. On `false`, the pair is recorded.
    pub fn nonce_seen(
        &self,
        root_pubkey: &[u8; 32],
        nonce: &[u8; 16],
        now_unix_ms: i64,
        ttl_ms: i64,
    ) -> Result<bool> {
        let mut key = [0u8; 48];
        key[0..32].copy_from_slice(root_pubkey);
        key[32..48].copy_from_slice(nonce);
        let expires_at = now_unix_ms.saturating_add(ttl_ms);

        let write = self.nonces_db.begin_write().context(TxnSnafu)?;
        let seen_recent = {
            let mut table = write.open_table(NONCES).context(TableSnafu)?;
            let prior = table.get(&key[..]).context(StorageIoSnafu)?;
            let recent = match prior.map(|g| g.value().to_vec()) {
                Some(raw) if raw.len() >= 8 => {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&raw[..8]);
                    let stored_expires = i64::from_be_bytes(buf);
                    stored_expires > now_unix_ms
                }
                _ => false,
            };
            if !recent {
                table
                    .insert(&key[..], &expires_at.to_be_bytes()[..])
                    .context(StorageIoSnafu)?;
            }
            recent
        };
        write.commit().context(CommitSnafu)?;
        Ok(seen_recent)
    }
}

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use wires_net::fabric::{
    FabricErrorCode, FabricErrorResponse, FabricOp, FabricRegisterRequest, FabricRegisterResponse,
    FabricResponse, FabricStatusKind, FabricStatusRequest, FabricStatusResponse,
    FabricUnregisterRequest, FabricUnregisterResponse, TopicRegisterRequest, TopicRegisterResponse,
    TopicUnregisterRequest, TopicUnregisterResponse, signing_bytes,
};

/// Tunable behaviour for `FabricHandlerImpl`.
#[derive(Clone, Copy)]
pub struct FabricHandlerConfig {
    pub max_clock_skew_ms: i64,
    pub nonce_ttl_ms: i64,
    pub write_rate_limit_per_sec: u32,
}

impl Default for FabricHandlerConfig {
    fn default() -> Self {
        Self {
            max_clock_skew_ms: 60_000,
            nonce_ttl_ms: 120_000,
            write_rate_limit_per_sec: 1_000,
        }
    }
}

pub struct FabricHandlerImpl {
    pub registry: Arc<FabricRegistry>,
    pub retention: Arc<crate::retention::Retention>,
    pub host_endpoint_id: [u8; 32],
    pub config: FabricHandlerConfig,
    pub now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
    pub on_topic_registered: Arc<dyn Fn([u8; 32], [u8; 32]) + Send + Sync>,
    pub on_topic_unregistered: Arc<dyn Fn([u8; 32], [u8; 32]) + Send + Sync>,
    /// Fires after a successful `handle_unregister` removes the fabric's row
    /// and topic_index entries. `Vec<[u8; 32]>` is the list of topic_ids that
    /// were dropped from the index. The host wires this to clear filesystem
    /// state for the fabric.
    #[allow(clippy::type_complexity)]
    pub on_fabric_unregistered: Arc<dyn Fn([u8; 32], Vec<[u8; 32]>) + Send + Sync>,
}

impl FabricHandlerImpl {
    fn caps_topic_id_for(root_pubkey: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"wires.caps.v1");
        h.update(root_pubkey);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }

    fn err(code: FabricErrorCode, message: &str) -> FabricResponse {
        FabricResponse::Error(FabricErrorResponse {
            code,
            message: message.to_string(),
        })
    }

    fn check_common(
        &self,
        root_pubkey: &[u8; 32],
        timestamp: i64,
        nonce: &[u8; 16],
        signature: &[u8; 64],
        signing_bytes: &[u8],
    ) -> std::result::Result<(), FabricResponse> {
        let now = (self.now_ms)();
        if (now - timestamp).abs() > self.config.max_clock_skew_ms {
            return Err(Self::err(
                FabricErrorCode::StaleTimestamp,
                "timestamp out of range",
            ));
        }
        let vk = match VerifyingKey::from_bytes(root_pubkey) {
            Ok(k) => k,
            Err(_) => return Err(Self::err(FabricErrorCode::BadSignature, "bad pubkey")),
        };
        let sig = Signature::from_bytes(signature);
        if vk.verify(signing_bytes, &sig).is_err() {
            return Err(Self::err(FabricErrorCode::BadSignature, "signature failed"));
        }
        match self
            .registry
            .nonce_seen(root_pubkey, nonce, now, self.config.nonce_ttl_ms)
        {
            Ok(true) => Err(Self::err(
                FabricErrorCode::ReplayedNonce,
                "nonce already seen",
            )),
            Ok(false) => Ok(()),
            Err(_) => Err(Self::err(FabricErrorCode::Internal, "nonce store error")),
        }
    }
}

impl wires_net::fabric::FabricHandler for FabricHandlerImpl {
    fn handle_register(&self, req: FabricRegisterRequest) -> FabricResponse {
        let sig_bytes = signing_bytes(
            FabricOp::Register,
            &req.root_pubkey,
            req.timestamp,
            &req.nonce,
            &self.host_endpoint_id,
        );
        if let Err(e) = self.check_common(
            &req.root_pubkey,
            req.timestamp,
            &req.nonce,
            &req.signature,
            &sig_bytes,
        ) {
            return e;
        }

        let now = (self.now_ms)();
        let rec = FabricRecord {
            registered_at: now,
            status: FabricStatus::Active,
            retention_budget_bytes: DEFAULT_RETENTION_BUDGET_BYTES,
        };
        if self
            .registry
            .insert_if_absent(&req.root_pubkey, rec)
            .is_err()
        {
            return Self::err(FabricErrorCode::Internal, "fabrics table write failed");
        }

        let caps_topic_id = Self::caps_topic_id_for(&req.root_pubkey);
        if matches!(
            self.registry
                .register_topic(&req.root_pubkey, &caps_topic_id),
            Ok(TopicRegisterOutcome::Inserted | TopicRegisterOutcome::AlreadyOwned),
        ) {
            (self.on_topic_registered)(req.root_pubkey, caps_topic_id);
        }

        FabricResponse::Register(FabricRegisterResponse {
            ok: true,
            host_endpoint_id: hex::encode(self.host_endpoint_id),
            server_time: now,
            caps_topic_id,
        })
    }

    fn handle_unregister(&self, req: FabricUnregisterRequest) -> FabricResponse {
        let sig_bytes = signing_bytes(
            FabricOp::Unregister,
            &req.root_pubkey,
            req.timestamp,
            &req.nonce,
            &self.host_endpoint_id,
        );
        if let Err(e) = self.check_common(
            &req.root_pubkey,
            req.timestamp,
            &req.nonce,
            &req.signature,
            &sig_bytes,
        ) {
            return e;
        }

        match self.registry.delete_fabric(&req.root_pubkey) {
            Ok(outcome) => {
                let n = outcome.topics_removed.len() as u32;
                if outcome.existed {
                    (self.on_fabric_unregistered)(req.root_pubkey, outcome.topics_removed);
                }
                FabricResponse::Unregister(FabricUnregisterResponse {
                    ok: outcome.existed,
                    topics_removed: n,
                })
            }
            Err(_) => Self::err(FabricErrorCode::Internal, "fabric delete failed"),
        }
    }

    fn handle_topic_register(&self, req: TopicRegisterRequest) -> FabricResponse {
        let sig_bytes = signing_bytes(
            FabricOp::TopicRegister(&req.topic_id),
            &req.root_pubkey,
            req.timestamp,
            &req.nonce,
            &self.host_endpoint_id,
        );
        if let Err(e) = self.check_common(
            &req.root_pubkey,
            req.timestamp,
            &req.nonce,
            &req.signature,
            &sig_bytes,
        ) {
            return e;
        }

        match self.registry.get(&req.root_pubkey) {
            Ok(Some(rec)) if rec.status == FabricStatus::Active => {}
            Ok(Some(_)) => return Self::err(FabricErrorCode::FabricSuspended, "fabric suspended"),
            Ok(None) => return Self::err(FabricErrorCode::FabricNotFound, "register fabric first"),
            Err(_) => return Self::err(FabricErrorCode::Internal, "fabric lookup failed"),
        }

        match self
            .registry
            .register_topic(&req.root_pubkey, &req.topic_id)
        {
            Ok(TopicRegisterOutcome::Inserted) | Ok(TopicRegisterOutcome::AlreadyOwned) => {
                (self.on_topic_registered)(req.root_pubkey, req.topic_id);
                FabricResponse::TopicRegister(TopicRegisterResponse {
                    ok: true,
                    topic_id: req.topic_id,
                })
            }
            Ok(TopicRegisterOutcome::Conflict { .. }) => Self::err(
                FabricErrorCode::TopicAlreadyRegistered,
                "topic owned by another fabric",
            ),
            Err(_) => Self::err(FabricErrorCode::Internal, "topic register write failed"),
        }
    }

    fn handle_topic_unregister(&self, req: TopicUnregisterRequest) -> FabricResponse {
        let sig_bytes = signing_bytes(
            FabricOp::TopicUnregister(&req.topic_id),
            &req.root_pubkey,
            req.timestamp,
            &req.nonce,
            &self.host_endpoint_id,
        );
        if let Err(e) = self.check_common(
            &req.root_pubkey,
            req.timestamp,
            &req.nonce,
            &req.signature,
            &sig_bytes,
        ) {
            return e;
        }

        match self
            .registry
            .unregister_topic(&req.root_pubkey, &req.topic_id)
        {
            Ok(true) => {
                (self.on_topic_unregistered)(req.root_pubkey, req.topic_id);
                FabricResponse::TopicUnregister(TopicUnregisterResponse {
                    ok: true,
                    topic_id: req.topic_id,
                })
            }
            Ok(false) => FabricResponse::TopicUnregister(TopicUnregisterResponse {
                ok: false,
                topic_id: req.topic_id,
            }),
            Err(_) => Self::err(FabricErrorCode::Internal, "topic unregister failed"),
        }
    }

    fn handle_status(&self, req: FabricStatusRequest) -> FabricResponse {
        let sig_bytes = signing_bytes(
            FabricOp::Status,
            &req.root_pubkey,
            req.timestamp,
            &req.nonce,
            &self.host_endpoint_id,
        );
        if let Err(e) = self.check_common(
            &req.root_pubkey,
            req.timestamp,
            &req.nonce,
            &req.signature,
            &sig_bytes,
        ) {
            return e;
        }

        let rec = match self.registry.get(&req.root_pubkey) {
            Ok(Some(rec)) => rec,
            _ => return Self::err(FabricErrorCode::FabricNotFound, "no such fabric"),
        };

        let topic_count = self.registry.topic_count_for(&req.root_pubkey).unwrap_or(0);
        let bytes_stored = self.retention.bytes_stored(&req.root_pubkey).unwrap_or(0);
        let oldest_retained_at = self
            .retention
            .oldest_retained_at(&req.root_pubkey)
            .unwrap_or(0);

        FabricResponse::Status(FabricStatusResponse {
            registered_at: rec.registered_at,
            topic_count,
            bytes_stored,
            retention_budget_bytes: rec.retention_budget_bytes,
            oldest_retained_at,
            write_rate_limit_per_sec: self.config.write_rate_limit_per_sec,
            status: match rec.status {
                FabricStatus::Active => FabricStatusKind::Active,
                FabricStatus::Suspended => FabricStatusKind::Suspended,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn insert_then_get_roundtrips() {
        let tmp = TempDir::new().unwrap();
        let reg = FabricRegistry::open(tmp.path()).unwrap();
        let root = [7u8; 32];
        assert!(reg.get(&root).unwrap().is_none());
        let rec = FabricRecord {
            registered_at: 1,
            status: FabricStatus::Active,
            retention_budget_bytes: DEFAULT_RETENTION_BUDGET_BYTES,
        };
        let got = reg.insert_if_absent(&root, rec.clone()).unwrap();
        assert_eq!(got.retention_budget_bytes, DEFAULT_RETENTION_BUDGET_BYTES);
        let read_back = reg.get(&root).unwrap().unwrap();
        assert_eq!(
            read_back.retention_budget_bytes,
            DEFAULT_RETENTION_BUDGET_BYTES
        );
        assert_eq!(read_back.status, FabricStatus::Active);
    }

    #[test]
    fn insert_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let reg = FabricRegistry::open(tmp.path()).unwrap();
        let root = [7u8; 32];
        let first = reg
            .insert_if_absent(
                &root,
                FabricRecord {
                    registered_at: 1,
                    status: FabricStatus::Active,
                    retention_budget_bytes: 100,
                },
            )
            .unwrap();
        let again = reg
            .insert_if_absent(
                &root,
                FabricRecord {
                    registered_at: 2,
                    status: FabricStatus::Suspended,
                    retention_budget_bytes: 200,
                },
            )
            .unwrap();
        // Idempotent — second insert returns the first record unchanged.
        assert_eq!(first.registered_at, again.registered_at);
        assert_eq!(again.retention_budget_bytes, 100);
    }

    #[test]
    fn topic_index_register_and_lookup() {
        let tmp = TempDir::new().unwrap();
        let reg = FabricRegistry::open(tmp.path()).unwrap();
        let root = [7u8; 32];
        let topic = [1u8; 32];
        assert!(reg.lookup_topic_fabric(&topic).unwrap().is_none());
        let outcome = reg.register_topic(&root, &topic).unwrap();
        assert!(matches!(outcome, TopicRegisterOutcome::Inserted));
        assert_eq!(reg.lookup_topic_fabric(&topic).unwrap(), Some(root));
        let again = reg.register_topic(&root, &topic).unwrap();
        assert!(matches!(again, TopicRegisterOutcome::AlreadyOwned));
    }

    #[test]
    fn topic_index_rejects_conflict() {
        let tmp = TempDir::new().unwrap();
        let reg = FabricRegistry::open(tmp.path()).unwrap();
        let root_a = [7u8; 32];
        let root_b = [8u8; 32];
        let topic = [1u8; 32];
        reg.register_topic(&root_a, &topic).unwrap();
        let conflict = reg.register_topic(&root_b, &topic).unwrap();
        assert!(matches!(conflict, TopicRegisterOutcome::Conflict { .. }));
    }

    #[test]
    fn all_topic_ids_returns_every_registered_topic() {
        let tmp = TempDir::new().unwrap();
        let reg = FabricRegistry::open(tmp.path()).unwrap();
        assert!(reg.all_topic_ids().unwrap().is_empty());

        let root_a = [7u8; 32];
        let root_b = [8u8; 32];
        let topic1 = [0x11u8; 32];
        let topic2 = [0x22u8; 32];
        let topic3 = [0x33u8; 32];
        reg.register_topic(&root_a, &topic1).unwrap();
        reg.register_topic(&root_a, &topic2).unwrap();
        reg.register_topic(&root_b, &topic3).unwrap();

        let mut got = reg.all_topic_ids().unwrap();
        got.sort();
        assert_eq!(got, vec![topic1, topic2, topic3]);
    }

    #[test]
    fn topic_count_for_returns_correct_count() {
        let tmp = TempDir::new().unwrap();
        let reg = FabricRegistry::open(tmp.path()).unwrap();
        let root_a = [0xAAu8; 32];
        let root_b = [0xBBu8; 32];
        let topic1 = [0x11u8; 32];
        let topic2 = [0x22u8; 32];
        let topic3 = [0x33u8; 32];

        // No topics registered yet.
        assert_eq!(reg.topic_count_for(&root_a).unwrap(), 0);

        reg.register_topic(&root_a, &topic1).unwrap();
        assert_eq!(reg.topic_count_for(&root_a).unwrap(), 1);
        assert_eq!(reg.topic_count_for(&root_b).unwrap(), 0);

        reg.register_topic(&root_a, &topic2).unwrap();
        reg.register_topic(&root_b, &topic3).unwrap();
        assert_eq!(reg.topic_count_for(&root_a).unwrap(), 2);
        assert_eq!(reg.topic_count_for(&root_b).unwrap(), 1);
    }

    #[test]
    fn nonce_first_seen_then_replay_detected() {
        let tmp = TempDir::new().unwrap();
        let reg = FabricRegistry::open(tmp.path()).unwrap();
        let root = [7u8; 32];
        let nonce = [3u8; 16];
        let now = 100_000i64;
        let ttl_ms = 120_000i64;
        assert!(!reg.nonce_seen(&root, &nonce, now, ttl_ms).unwrap());
        assert!(reg.nonce_seen(&root, &nonce, now + 1_000, ttl_ms).unwrap());
    }

    #[test]
    fn nonce_expires_past_ttl() {
        let tmp = TempDir::new().unwrap();
        let reg = FabricRegistry::open(tmp.path()).unwrap();
        let root = [7u8; 32];
        let nonce = [3u8; 16];
        let now = 100_000i64;
        let ttl_ms = 120_000i64;
        assert!(!reg.nonce_seen(&root, &nonce, now, ttl_ms).unwrap());
        // Re-use after TTL elapses should be allowed again.
        assert!(
            !reg.nonce_seen(&root, &nonce, now + ttl_ms + 1, ttl_ms)
                .unwrap()
        );
    }

    #[test]
    fn delete_fabric_drops_record_and_indexed_topics() {
        let tmp = TempDir::new().unwrap();
        let reg = FabricRegistry::open(tmp.path()).unwrap();
        let root_a = [0xAAu8; 32];
        let root_b = [0xBBu8; 32];
        let topic1 = [0x11u8; 32];
        let topic2 = [0x22u8; 32];
        let topic3 = [0x33u8; 32];

        reg.insert_if_absent(
            &root_a,
            FabricRecord {
                registered_at: 1,
                status: FabricStatus::Active,
                retention_budget_bytes: 100,
            },
        )
        .unwrap();
        reg.insert_if_absent(
            &root_b,
            FabricRecord {
                registered_at: 1,
                status: FabricStatus::Active,
                retention_budget_bytes: 100,
            },
        )
        .unwrap();
        reg.register_topic(&root_a, &topic1).unwrap();
        reg.register_topic(&root_a, &topic2).unwrap();
        reg.register_topic(&root_b, &topic3).unwrap();

        let dropped = reg.delete_fabric(&root_a).unwrap();
        assert!(dropped.existed);
        let mut topics = dropped.topics_removed;
        topics.sort();
        assert_eq!(topics, vec![topic1, topic2]);

        // Fabric A is gone; fabric B is intact.
        assert!(reg.get(&root_a).unwrap().is_none());
        assert!(reg.get(&root_b).unwrap().is_some());
        assert!(reg.lookup_topic_fabric(&topic1).unwrap().is_none());
        assert!(reg.lookup_topic_fabric(&topic2).unwrap().is_none());
        assert_eq!(reg.lookup_topic_fabric(&topic3).unwrap(), Some(root_b));
    }

    #[test]
    fn delete_fabric_unknown_returns_not_existed() {
        let tmp = TempDir::new().unwrap();
        let reg = FabricRegistry::open(tmp.path()).unwrap();
        let dropped = reg.delete_fabric(&[7u8; 32]).unwrap();
        assert!(!dropped.existed);
        assert!(dropped.topics_removed.is_empty());
    }

    #[test]
    fn handle_register_signs_and_records_fabric() {
        use crate::per_fabric_logs::PerFabricLogs;
        use ed25519_dalek::{Signer, SigningKey};
        use rand_core::OsRng;
        use std::sync::Arc;
        use wires_net::fabric::{FabricHandler, FabricRegisterRequest, FabricResponse};

        let tmp = TempDir::new().unwrap();
        let reg = Arc::new(FabricRegistry::open(tmp.path()).unwrap());
        let logs = Arc::new(PerFabricLogs::new(tmp.path()));
        let retention = Arc::new(crate::retention::Retention::new(tmp.path(), logs));

        let signing_key = SigningKey::generate(&mut OsRng);
        let root_pubkey = signing_key.verifying_key().to_bytes();
        let host_endpoint_id = [42u8; 32];
        let now_ms = 1_000_000i64;

        let handler = FabricHandlerImpl {
            registry: Arc::clone(&reg),
            retention,
            host_endpoint_id,
            config: FabricHandlerConfig::default(),
            now_ms: Arc::new(move || now_ms),
            on_topic_registered: Arc::new(|_root, _topic| {}),
            on_topic_unregistered: Arc::new(|_root, _topic| {}),
            on_fabric_unregistered: Arc::new(|_root, _topics| {}),
        };

        let nonce = [9u8; 16];
        let bytes = wires_net::fabric::signing_bytes(
            FabricOp::Register,
            &root_pubkey,
            now_ms,
            &nonce,
            &host_endpoint_id,
        );
        let sig = signing_key.sign(&bytes).to_bytes();

        let req = FabricRegisterRequest {
            version: 1,
            root_pubkey,
            timestamp: now_ms,
            nonce,
            signature: sig,
        };
        let resp = handler.handle_register(req);
        match resp {
            FabricResponse::Register(r) => {
                assert!(r.ok);
                assert_eq!(r.host_endpoint_id, hex::encode(host_endpoint_id));
            }
            other => panic!("expected Register response, got {:?}", other),
        }

        // Fabric row now exists.
        let rec = reg.get(&root_pubkey).unwrap().unwrap();
        assert_eq!(rec.status, FabricStatus::Active);
    }

    #[test]
    fn handle_unregister_drops_fabric_and_fires_hook() {
        use crate::per_fabric_logs::PerFabricLogs;
        use ed25519_dalek::{Signer, SigningKey};
        use rand_core::OsRng;
        use std::sync::Arc;
        use std::sync::Mutex;
        use wires_net::fabric::{
            FabricHandler, FabricRegisterRequest, FabricResponse, FabricUnregisterRequest,
        };

        let tmp = TempDir::new().unwrap();
        let reg = Arc::new(FabricRegistry::open(tmp.path()).unwrap());
        let logs = Arc::new(PerFabricLogs::new(tmp.path()));
        let retention = Arc::new(crate::retention::Retention::new(tmp.path(), logs));

        let signing_key = SigningKey::generate(&mut OsRng);
        let root_pubkey = signing_key.verifying_key().to_bytes();
        let host_endpoint_id = [42u8; 32];
        let now_ms = 1_000_000i64;

        type ObservedFabricUnregisters = Arc<Mutex<Vec<([u8; 32], Vec<[u8; 32]>)>>>;
        let observed: ObservedFabricUnregisters = Arc::new(Mutex::new(Vec::new()));
        let observed_for_cb = Arc::clone(&observed);

        let handler = FabricHandlerImpl {
            registry: Arc::clone(&reg),
            retention,
            host_endpoint_id,
            config: FabricHandlerConfig::default(),
            now_ms: Arc::new(move || now_ms),
            on_topic_registered: Arc::new(|_root, _topic| {}),
            on_topic_unregistered: Arc::new(|_root, _topic| {}),
            on_fabric_unregistered: Arc::new(move |root, topics| {
                observed_for_cb.lock().unwrap().push((root, topics));
            }),
        };

        // Register first so we have something to unregister.
        let nonce_reg = [1u8; 16];
        let bytes_reg = wires_net::fabric::signing_bytes(
            FabricOp::Register,
            &root_pubkey,
            now_ms,
            &nonce_reg,
            &host_endpoint_id,
        );
        let sig_reg = signing_key.sign(&bytes_reg).to_bytes();
        let _ = handler.handle_register(FabricRegisterRequest {
            version: 1,
            root_pubkey,
            timestamp: now_ms,
            nonce: nonce_reg,
            signature: sig_reg,
        });
        assert!(reg.get(&root_pubkey).unwrap().is_some());

        // Unregister.
        let nonce_un = [2u8; 16];
        let bytes_un = wires_net::fabric::signing_bytes(
            FabricOp::Unregister,
            &root_pubkey,
            now_ms,
            &nonce_un,
            &host_endpoint_id,
        );
        let sig_un = signing_key.sign(&bytes_un).to_bytes();
        let resp = handler.handle_unregister(FabricUnregisterRequest {
            version: 1,
            root_pubkey,
            timestamp: now_ms,
            nonce: nonce_un,
            signature: sig_un,
        });
        match resp {
            FabricResponse::Unregister(r) => {
                assert!(r.ok);
                // handle_register inserted the caps_topic_id for this fabric
                // (see FabricHandlerImpl::handle_register), so topics_removed
                // must reflect that.
                assert_eq!(r.topics_removed, 1);
            }
            other => panic!("expected Unregister, got {:?}", other),
        }
        // Fabric gone, hook fired with one topic.
        assert!(reg.get(&root_pubkey).unwrap().is_none());
        let obs = observed.lock().unwrap();
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].0, root_pubkey);
        assert_eq!(obs[0].1.len(), 1);
    }

    #[test]
    fn handle_unregister_unknown_fabric_returns_ok_false() {
        use crate::per_fabric_logs::PerFabricLogs;
        use ed25519_dalek::{Signer, SigningKey};
        use rand_core::OsRng;
        use std::sync::Arc;
        use wires_net::fabric::{FabricHandler, FabricResponse, FabricUnregisterRequest};

        let tmp = TempDir::new().unwrap();
        let reg = Arc::new(FabricRegistry::open(tmp.path()).unwrap());
        let logs = Arc::new(PerFabricLogs::new(tmp.path()));
        let retention = Arc::new(crate::retention::Retention::new(tmp.path(), logs));

        let signing_key = SigningKey::generate(&mut OsRng);
        let root_pubkey = signing_key.verifying_key().to_bytes();
        let host_endpoint_id = [42u8; 32];
        let now_ms = 1_000_000i64;

        let handler = FabricHandlerImpl {
            registry: Arc::clone(&reg),
            retention,
            host_endpoint_id,
            config: FabricHandlerConfig::default(),
            now_ms: Arc::new(move || now_ms),
            on_topic_registered: Arc::new(|_, _| {}),
            on_topic_unregistered: Arc::new(|_, _| {}),
            on_fabric_unregistered: Arc::new(|_, _| {}),
        };

        let nonce = [9u8; 16];
        let bytes = wires_net::fabric::signing_bytes(
            FabricOp::Unregister,
            &root_pubkey,
            now_ms,
            &nonce,
            &host_endpoint_id,
        );
        let sig = signing_key.sign(&bytes).to_bytes();
        let resp = handler.handle_unregister(FabricUnregisterRequest {
            version: 1,
            root_pubkey,
            timestamp: now_ms,
            nonce,
            signature: sig,
        });
        match resp {
            FabricResponse::Unregister(r) => {
                assert!(!r.ok);
                assert_eq!(r.topics_removed, 0);
            }
            other => panic!("expected Unregister, got {:?}", other),
        }
    }
}

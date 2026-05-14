//! Tenants, topic→tenant index, and registration nonces.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::error::{
    CommitSnafu, DbOpenSnafu, IoSnafu, Result, SerdeSnafu, StorageIoSnafu, TableSnafu, TxnSnafu,
};

/// Key = root_pubkey (32 bytes). Value = JSON `TenantRecord`.
pub const TENANTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("tenants");

/// Key = topic_id (32 bytes). Value = root_pubkey (32 bytes).
pub const TOPIC_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("topic_index");

/// Key = root_pubkey (32) || nonce (16) = 48 bytes. Value = u64 BE expires_at_unix_ms.
pub const NONCES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("nonces");

/// Default per-tenant retention budget: 1 GiB.
pub const DEFAULT_RETENTION_BUDGET_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TenantStatus {
    Active,
    Suspended,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantRecord {
    pub registered_at: i64,
    pub status: TenantStatus,
    pub retention_budget_bytes: u64,
}

#[derive(Debug)]
pub enum TopicRegisterOutcome {
    Inserted,
    AlreadyOwned,
    Conflict { other_root: [u8; 32] },
}

pub struct TenantRegistry {
    pub root: PathBuf,
    tenants_db: Arc<Database>,
    topic_index_db: Arc<Database>,
    #[allow(dead_code)]
    nonces_db: Arc<Database>,
}

impl TenantRegistry {
    pub fn open(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root).context(IoSnafu)?;
        let tenants_db = Arc::new(
            Database::create(root.join("tenants.redb")).context(DbOpenSnafu)?
        );
        let topic_index_db = Arc::new(
            Database::create(root.join("topic_index.redb")).context(DbOpenSnafu)?
        );
        let nonces_db = Arc::new(
            Database::create(root.join("nonces.redb")).context(DbOpenSnafu)?
        );
        Ok(Self { root: root.to_path_buf(), tenants_db, topic_index_db, nonces_db })
    }

    /// Look up an existing tenant.
    pub fn get(&self, root_pubkey: &[u8; 32]) -> Result<Option<TenantRecord>> {
        let read = self.tenants_db.begin_read().context(TxnSnafu)?;
        let table = match read.open_table(TENANTS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(crate::error::HostError::Table { source: e, location: snafu::location!() }),
        };
        match table.get(&root_pubkey[..]).context(StorageIoSnafu)? {
            Some(v) => {
                let rec: TenantRecord = serde_json::from_slice(v.value()).context(SerdeSnafu)?;
                Ok(Some(rec))
            }
            None => Ok(None),
        }
    }

    /// Insert a new tenant (idempotent: returns Ok with the existing record if
    /// already present).
    pub fn insert_if_absent(&self, root_pubkey: &[u8; 32], rec: TenantRecord) -> Result<TenantRecord> {
        if let Some(existing) = self.get(root_pubkey)? {
            return Ok(existing);
        }
        let json = serde_json::to_vec(&rec).context(SerdeSnafu)?;
        let write = self.tenants_db.begin_write().context(TxnSnafu)?;
        {
            let mut t = write.open_table(TENANTS).context(TableSnafu)?;
            t.insert(&root_pubkey[..], json.as_slice()).context(StorageIoSnafu)?;
        }
        write.commit().context(CommitSnafu)?;
        Ok(rec)
    }

    pub fn lookup_topic_tenant(&self, topic_id: &[u8; 32]) -> Result<Option<[u8; 32]>> {
        let read = self.topic_index_db.begin_read().context(TxnSnafu)?;
        let table = match read.open_table(TOPIC_INDEX) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(crate::error::HostError::Table {
                source: e, location: snafu::location!(),
            }),
        };
        match table.get(&topic_id[..]).context(StorageIoSnafu)? {
            Some(v) => {
                let raw = v.value();
                if raw.len() != 32 { return Ok(None); }
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
            let prior_data = table.get(&topic_id[..]).context(StorageIoSnafu)?
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
                table.insert(&topic_id[..], &root_pubkey[..]).context(StorageIoSnafu)?;
                TopicRegisterOutcome::Inserted
            }
        };
        write.commit().context(CommitSnafu)?;
        Ok(outcome)
    }

    pub fn unregister_topic(
        &self,
        root_pubkey: &[u8; 32],
        topic_id: &[u8; 32],
    ) -> Result<bool> {
        let write = self.topic_index_db.begin_write().context(TxnSnafu)?;
        let removed = {
            let mut table = write.open_table(TOPIC_INDEX).context(TableSnafu)?;
            let prior_data = table.get(&topic_id[..]).context(StorageIoSnafu)?
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn insert_then_get_roundtrips() {
        let tmp = TempDir::new().unwrap();
        let reg = TenantRegistry::open(tmp.path()).unwrap();
        let root = [7u8; 32];
        assert!(reg.get(&root).unwrap().is_none());
        let rec = TenantRecord {
            registered_at: 1,
            status: TenantStatus::Active,
            retention_budget_bytes: DEFAULT_RETENTION_BUDGET_BYTES,
        };
        let got = reg.insert_if_absent(&root, rec.clone()).unwrap();
        assert_eq!(got.retention_budget_bytes, DEFAULT_RETENTION_BUDGET_BYTES);
        let read_back = reg.get(&root).unwrap().unwrap();
        assert_eq!(read_back.retention_budget_bytes, DEFAULT_RETENTION_BUDGET_BYTES);
        assert_eq!(read_back.status, TenantStatus::Active);
    }

    #[test]
    fn insert_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let reg = TenantRegistry::open(tmp.path()).unwrap();
        let root = [7u8; 32];
        let first = reg.insert_if_absent(&root, TenantRecord {
            registered_at: 1,
            status: TenantStatus::Active,
            retention_budget_bytes: 100,
        }).unwrap();
        let again = reg.insert_if_absent(&root, TenantRecord {
            registered_at: 2,
            status: TenantStatus::Suspended,
            retention_budget_bytes: 200,
        }).unwrap();
        // Idempotent — second insert returns the first record unchanged.
        assert_eq!(first.registered_at, again.registered_at);
        assert_eq!(again.retention_budget_bytes, 100);
    }

    #[test]
    fn topic_index_register_and_lookup() {
        let tmp = TempDir::new().unwrap();
        let reg = TenantRegistry::open(tmp.path()).unwrap();
        let root = [7u8; 32];
        let topic = [1u8; 32];
        assert!(reg.lookup_topic_tenant(&topic).unwrap().is_none());
        let outcome = reg.register_topic(&root, &topic).unwrap();
        assert!(matches!(outcome, TopicRegisterOutcome::Inserted));
        assert_eq!(reg.lookup_topic_tenant(&topic).unwrap(), Some(root));
        let again = reg.register_topic(&root, &topic).unwrap();
        assert!(matches!(again, TopicRegisterOutcome::AlreadyOwned));
    }

    #[test]
    fn topic_index_rejects_conflict() {
        let tmp = TempDir::new().unwrap();
        let reg = TenantRegistry::open(tmp.path()).unwrap();
        let root_a = [7u8; 32];
        let root_b = [8u8; 32];
        let topic = [1u8; 32];
        reg.register_topic(&root_a, &topic).unwrap();
        let conflict = reg.register_topic(&root_b, &topic).unwrap();
        assert!(matches!(conflict, TopicRegisterOutcome::Conflict { .. }));
    }
}

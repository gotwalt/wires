use std::collections::HashMap;
use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable};
use snafu::ResultExt;
use wires_core::{CapId, Capability};

use crate::error::{
    BeginTxnSnafu, CommitTxnSnafu, DeserializeSnafu, OpenTableSnafu, Result, SerializeSnafu,
    StorageIoSnafu,
};
use crate::schema::{CAPS, REVOKED};

pub struct CapTable {
    db: Arc<Database>,
}

#[derive(Debug, Clone)]
pub struct CapEntry {
    pub cap: Capability,
    pub revoked: bool,
}

impl CapTable {
    pub fn new(db: Arc<Database>) -> Self {
        // Ensure both tables exist before any read transaction attempts to open them.
        let write = db.begin_write().expect("begin_write for CapTable init");
        write.open_table(CAPS).expect("create caps table");
        write.open_table(REVOKED).expect("create revoked table");
        write.commit().expect("commit CapTable init");
        Self { db }
    }

    pub fn upsert_grant(&self, cap: &Capability) -> Result<()> {
        let bytes = serde_json::to_vec(cap).context(SerializeSnafu)?;
        let write = self.db.begin_write().context(BeginTxnSnafu)?;
        {
            let mut t = write.open_table(CAPS).context(OpenTableSnafu)?;
            t.insert(&cap.cap_id.0[..], bytes.as_slice()).context(StorageIoSnafu)?;
        }
        write.commit().context(CommitTxnSnafu)?;
        Ok(())
    }

    pub fn mark_revoked(&self, cap_id: &CapId, revoke_hash: &[u8; 32]) -> Result<()> {
        let write = self.db.begin_write().context(BeginTxnSnafu)?;
        {
            let mut t = write.open_table(REVOKED).context(OpenTableSnafu)?;
            t.insert(&cap_id[..], &revoke_hash[..]).context(StorageIoSnafu)?;
        }
        write.commit().context(CommitTxnSnafu)?;
        Ok(())
    }

    pub fn get(&self, cap_id: &CapId) -> Result<Option<CapEntry>> {
        let read = self.db.begin_read().context(BeginTxnSnafu)?;
        let caps_t = read.open_table(CAPS).context(OpenTableSnafu)?;
        let cap = match caps_t.get(&cap_id[..]).context(StorageIoSnafu)? {
            Some(v) => serde_json::from_slice::<Capability>(v.value()).context(DeserializeSnafu)?,
            None => return Ok(None),
        };
        let revoked_t = read.open_table(REVOKED).context(OpenTableSnafu)?;
        let revoked = revoked_t.get(&cap_id[..]).context(StorageIoSnafu)?.is_some();
        Ok(Some(CapEntry { cap, revoked }))
    }

    pub fn all(&self) -> Result<HashMap<CapId, CapEntry>> {
        let read = self.db.begin_read().context(BeginTxnSnafu)?;
        let caps_t = read.open_table(CAPS).context(OpenTableSnafu)?;
        let revoked_t = read.open_table(REVOKED).context(OpenTableSnafu)?;
        let mut out = HashMap::new();
        for entry in caps_t.iter().context(StorageIoSnafu)? {
            let (k, v) = entry.context(StorageIoSnafu)?;
            let k_bytes = k.value();
            if k_bytes.len() != 16 { continue; }
            let mut cap_id = [0u8; 16];
            cap_id.copy_from_slice(k_bytes);
            let cap: Capability = serde_json::from_slice(v.value()).context(DeserializeSnafu)?;
            let revoked = revoked_t.get(&cap_id[..]).context(StorageIoSnafu)?.is_some();
            out.insert(cap_id, CapEntry { cap, revoked });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_caps;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use tempfile::TempDir;
    use wires_core::cap::Right;

    fn make_cap() -> (Capability, SigningKey) {
        let root = SigningKey::generate(&mut OsRng);
        let mut cap = Capability::new_unsigned(
            [9u8; 32],
            vec!["home.*".into()],
            vec![Right::Read],
            0,
            None,
        );
        cap.sign(&root).unwrap();
        (cap, root)
    }

    #[test]
    fn upsert_and_get() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_caps(tmp.path()).unwrap());
        let table = CapTable::new(db);

        let (cap, _) = make_cap();
        let cap_id = cap.cap_id.0;
        table.upsert_grant(&cap).unwrap();
        let entry = table.get(&cap_id).unwrap().unwrap();
        assert!(!entry.revoked);
        assert_eq!(entry.cap.cap_id.0, cap_id);
    }

    #[test]
    fn revocation_visible_via_get() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_caps(tmp.path()).unwrap());
        let table = CapTable::new(db);

        let (cap, _) = make_cap();
        table.upsert_grant(&cap).unwrap();
        table.mark_revoked(&cap.cap_id.0, &[7u8; 32]).unwrap();
        let entry = table.get(&cap.cap_id.0).unwrap().unwrap();
        assert!(entry.revoked);
    }

    #[test]
    fn unknown_cap_id_is_none() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_caps(tmp.path()).unwrap());
        let table = CapTable::new(db);
        assert!(table.get(&[0u8; 16]).unwrap().is_none());
    }

    #[test]
    fn all_returns_every_cap_with_revoked_flag() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_caps(tmp.path()).unwrap());
        let table = CapTable::new(db);

        let (cap_a, _) = make_cap();
        let (cap_b, _) = make_cap();
        table.upsert_grant(&cap_a).unwrap();
        table.upsert_grant(&cap_b).unwrap();
        table.mark_revoked(&cap_a.cap_id.0, &[1u8; 32]).unwrap();

        let all = table.all().unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.get(&cap_a.cap_id.0).unwrap().revoked);
        assert!(!all.get(&cap_b.cap_id.0).unwrap().revoked);
    }

    #[test]
    fn upsert_replaces_existing() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_caps(tmp.path()).unwrap());
        let table = CapTable::new(db);

        let (mut cap, root) = make_cap();
        table.upsert_grant(&cap).unwrap();
        // Re-sign with a different topic list, same cap_id
        cap.topics.push("mail.*".into());
        cap.sign(&root).unwrap();
        table.upsert_grant(&cap).unwrap();

        let entry = table.get(&cap.cap_id.0).unwrap().unwrap();
        assert!(entry.cap.topics.iter().any(|t| t == "mail.*"));
    }
}

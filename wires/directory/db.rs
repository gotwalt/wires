//! `directory.redb`: a directory's copy of the policy.
//!
//! | Table | Key → value |
//! |---|---|
//! | `heads` | version → `{head, items}`: the signed head and its items' content hashes, in order (the last [`KEEP_HEADS`] kept, for deltas) |
//! | `items` | content hash (hex) → the item's JSON (dropped when no kept head names it) |
//! | `current` | item key (`kind:key`) → content hash, for the newest head |
//! | `meta` | `version` (the newest head's), `fresh` (the latest [`Fresh`]) |
//!
//! One writer ([`DirectoryDb::store`], a publish), many readers. The caller
//! verifies a policy before storing it; [`DirectoryDb::store`] only keeps
//! heads strictly increasing, in one transaction, so a crash leaves either
//! the old head or the new one. A restart reloads the newest head
//! ([`DirectoryDb::current`]).
//!
//! Items are stored by a blake3 hash of their JSON: a storage key only,
//! independent of how the head commits to them (the signed head is what is
//! verified, by [`SignedPolicy::verify`], before anything is stored).

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};
use library::{Fresh, Item, SignedPolicy, SignedPolicyHead, StateVersion};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

/// The file name in the directory's keystore.
pub(crate) const DB_FILE: &str = "directory.redb";

/// How many heads (with their items) the store keeps: enough to compute a
/// delta from any of them (card 36c).
pub(crate) const KEEP_HEADS: usize = 16;

const HEADS: TableDefinition<u64, &[u8]> = TableDefinition::new("heads");
const ITEMS: TableDefinition<&str, &[u8]> = TableDefinition::new("items");
const CURRENT: TableDefinition<&str, &str> = TableDefinition::new("current");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

/// `meta` key: the newest head's version (8 bytes, big-endian).
const META_VERSION: &str = "version";
/// `meta` key: the latest `Fresh` (JSON).
const META_FRESH: &str = "fresh";

/// A `heads` value: the signed head and its items' storage keys, in order.
#[derive(Serialize, Deserialize)]
struct HeadRecord {
    head: SignedPolicyHead,
    items: Vec<String>,
}

/// An item's storage key: the blake3 hash of its JSON, hex.
fn item_key(item: &Item) -> Result<String> {
    Ok(blake3::hash(&serde_json::to_vec(item)?)
        .to_hex()
        .to_string())
}

/// The directory's store. See the module docs.
pub(crate) struct DirectoryDb {
    db: Database,
}

impl std::fmt::Debug for DirectoryDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectoryDb").finish_non_exhaustive()
    }
}

impl DirectoryDb {
    /// Open (or create) the store at `path`, with every table present.
    pub(crate) fn open(path: &Path) -> Result<DirectoryDb> {
        let db = Database::create(path).with_context(|| format!("opening {}", path.display()))?;
        let txn = db.begin_write()?;
        txn.open_table(HEADS)?;
        txn.open_table(ITEMS)?;
        txn.open_table(CURRENT)?;
        txn.open_table(META)?;
        txn.commit()?;
        Ok(DirectoryDb { db })
    }

    /// The newest head's version (0: none stored).
    pub(crate) fn version(&self) -> Result<StateVersion> {
        let txn = self.db.begin_read()?;
        let meta = txn.open_table(META)?;
        Ok(match meta.get(META_VERSION)? {
            Some(v) => StateVersion(u64::from_be_bytes(
                v.value()
                    .try_into()
                    .context("a corrupt version in directory.redb")?,
            )),
            None => StateVersion(0),
        })
    }

    /// The newest signed policy, rebuilt from its head and items; `None`
    /// before the first publish.
    pub(crate) fn current(&self) -> Result<Option<SignedPolicy>> {
        let version = self.version()?;
        if version.0 == 0 {
            return Ok(None);
        }
        self.policy_at(version)
    }

    /// The signed policy at `version`, if that head is still kept.
    pub(crate) fn policy_at(&self, version: StateVersion) -> Result<Option<SignedPolicy>> {
        let txn = self.db.begin_read()?;
        let heads = txn.open_table(HEADS)?;
        let Some(record) = heads.get(version.0)? else {
            return Ok(None);
        };
        let record: HeadRecord =
            serde_json::from_slice(record.value()).context("a corrupt head in directory.redb")?;
        let items = txn.open_table(ITEMS)?;
        let mut out = Vec::with_capacity(record.items.len());
        for key in &record.items {
            let bytes = items
                .get(key.as_str())?
                .with_context(|| format!("directory.redb lacks item {key}"))?;
            let item: Item = serde_json::from_slice(bytes.value())
                .context("a corrupt item in directory.redb")?;
            out.push(item);
        }
        Ok(Some(SignedPolicy {
            head: record.head,
            items: out,
        }))
    }

    /// The versions of the heads kept, oldest first.
    #[cfg(test)]
    pub(crate) fn kept(&self) -> Result<Vec<StateVersion>> {
        let txn = self.db.begin_read()?;
        let heads = txn.open_table(HEADS)?;
        let mut out = Vec::new();
        for entry in heads.iter()? {
            out.push(StateVersion(entry?.0.value()));
        }
        Ok(out)
    }

    /// Store `policy` (already verified) as the newest head, in one
    /// transaction: its items, its head, the `current` index; then drop the
    /// heads past [`KEEP_HEADS`] and every item no kept head names. Returns
    /// `false` (storing nothing) unless it is strictly newer than the stored
    /// head.
    pub(crate) fn store(&self, policy: &SignedPolicy) -> Result<bool> {
        let version = policy.version();
        let keys: Vec<String> = policy.items.iter().map(item_key).collect::<Result<_>>()?;
        let txn = self.db.begin_write()?;
        {
            let mut meta = txn.open_table(META)?;
            let held = match meta.get(META_VERSION)? {
                Some(v) => u64::from_be_bytes(
                    v.value()
                        .try_into()
                        .context("a corrupt version in directory.redb")?,
                ),
                None => 0,
            };
            if version.0 <= held {
                return Ok(false);
            }
            let mut items = txn.open_table(ITEMS)?;
            for (item, key) in policy.items.iter().zip(&keys) {
                let bytes = serde_json::to_vec(item)?;
                items.insert(key.as_str(), bytes.as_slice())?;
            }
            let mut heads = txn.open_table(HEADS)?;
            let record = serde_json::to_vec(&HeadRecord {
                head: policy.head.clone(),
                items: keys.clone(),
            })?;
            heads.insert(version.0, record.as_slice())?;
            let mut current = txn.open_table(CURRENT)?;
            current.retain(|_, _| false)?;
            for (item, key) in policy.items.iter().zip(&keys) {
                current.insert(item.key().to_string().as_str(), key.as_str())?;
            }
            meta.insert(META_VERSION, version.0.to_be_bytes().as_slice())?;

            // Keep the newest KEEP_HEADS heads, and the items they name.
            let versions: Vec<u64> = heads
                .iter()?
                .map(|e| e.map(|(k, _)| k.value()))
                .collect::<std::result::Result<_, _>>()?;
            let drop_below = versions.len().checked_sub(KEEP_HEADS).map(|n| versions[n]);
            if let Some(floor) = drop_below {
                heads.retain(|v, _| v >= floor)?;
                let mut named = BTreeSet::new();
                for entry in heads.iter()? {
                    let (_, record) = entry?;
                    let record: HeadRecord = serde_json::from_slice(record.value())
                        .context("a corrupt head in directory.redb")?;
                    named.extend(record.items);
                }
                items.retain(|key, _| named.contains(key))?;
            }
        }
        txn.commit()?;
        Ok(true)
    }

    /// The latest `Fresh` stored, if any (a restart signs a new one).
    #[cfg(test)]
    pub(crate) fn fresh(&self) -> Result<Option<Fresh>> {
        let txn = self.db.begin_read()?;
        let meta = txn.open_table(META)?;
        match meta.get(META_FRESH)? {
            Some(v) => Ok(Some(
                serde_json::from_slice(v.value()).context("a corrupt fresh in directory.redb")?,
            )),
            None => Ok(None),
        }
    }

    /// Store `fresh` as the latest.
    pub(crate) fn set_fresh(&self, fresh: &Fresh) -> Result<()> {
        let bytes = serde_json::to_vec(fresh)?;
        let txn = self.db.begin_write()?;
        txn.open_table(META)?.insert(META_FRESH, bytes.as_slice())?;
        txn.commit()?;
        Ok(())
    }

    /// How many items the store holds (for tests: garbage collection).
    #[cfg(test)]
    pub(crate) fn item_count(&self) -> Result<u64> {
        use redb::ReadableTableMetadata;
        let txn = self.db.begin_read()?;
        Ok(txn.open_table(ITEMS)?.len()?)
    }

    /// The `current` index: item key → content hash, for the newest head.
    #[cfg(test)]
    pub(crate) fn current_index(&self) -> Result<Vec<(String, String)>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(CURRENT)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            out.push((k.value().to_string(), v.value().to_string()));
        }
        Ok(out)
    }
}

/// [`DirectoryDb::store`], refusing a policy that isn't newer (for callers
/// that already decided it must be).
#[cfg(test)]
pub(crate) fn store_newer(db: &DirectoryDb, policy: &SignedPolicy) -> Result<()> {
    if !db.store(policy)? {
        anyhow::bail!("version {} is not newer", policy.version().0);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{Ban, NodeIdentity, Policy};
    use proptest::prelude::*;

    fn root() -> NodeIdentity {
        NodeIdentity::from_seed([1u8; 32])
    }

    /// Version `v`, banning node `b` for each `b` in `bans`.
    fn signed(v: u64, bans: &[u8]) -> SignedPolicy {
        let mut p = Policy::new(root().node_id());
        p.version = StateVersion(v);
        p.not_after = i64::MAX;
        for b in bans {
            p.bans.insert(
                NodeIdentity::from_seed([*b; 32]).node_id(),
                Ban { until: 1 },
            );
        }
        p.sign(&root()).unwrap()
    }

    fn db() -> DirectoryDb {
        DirectoryDb::open(&crate::testutil::temp_dir().join(DB_FILE)).unwrap()
    }

    #[test]
    fn an_empty_store_holds_nothing() {
        let db = db();
        assert_eq!(db.version().unwrap(), StateVersion(0));
        assert!(db.current().unwrap().is_none());
        assert!(db.fresh().unwrap().is_none());
    }

    #[test]
    fn stores_only_newer_heads_and_reloads_them() {
        let path = crate::testutil::temp_dir().join(DB_FILE);
        {
            let db = DirectoryDb::open(&path).unwrap();
            assert!(db.store(&signed(2, &[5])).unwrap());
            assert!(!db.store(&signed(2, &[6])).unwrap());
            assert!(!db.store(&signed(1, &[])).unwrap());
            assert_eq!(db.current().unwrap().unwrap(), signed(2, &[5]));
        }
        // A restart reads back the same head and items.
        let db = DirectoryDb::open(&path).unwrap();
        assert_eq!(db.version().unwrap(), StateVersion(2));
        let back = db.current().unwrap().unwrap();
        back.verify(root().node_id()).unwrap();
        assert_eq!(back, signed(2, &[5]));
        assert_eq!(db.current_index().unwrap().len(), back.items.len());
    }

    #[test]
    fn keeps_the_last_heads_and_collects_their_items() {
        let db = db();
        for v in 1..=(KEEP_HEADS as u64 + 4) {
            // Each version bans a node of its own: one new item per head.
            store_newer(&db, &signed(v, &[v as u8])).unwrap();
        }
        let kept = db.kept().unwrap();
        assert_eq!(kept.len(), KEEP_HEADS);
        assert_eq!(kept[0], StateVersion(5));
        assert!(db.policy_at(StateVersion(4)).unwrap().is_none());
        assert_eq!(
            db.policy_at(StateVersion(5)).unwrap().unwrap(),
            signed(5, &[5])
        );
        // One ban item per kept head, plus the one settings item they share.
        assert_eq!(db.item_count().unwrap(), KEEP_HEADS as u64 + 1);
    }

    #[test]
    fn the_latest_fresh_survives_a_restart() {
        let path = crate::testutil::temp_dir().join(DB_FILE);
        let dir = NodeIdentity::from_seed([30u8; 32]);
        let mut p = Policy::new(root().node_id());
        p.version = StateVersion(1);
        p.not_after = i64::MAX;
        p.directories = vec![dir.node_id()];
        let policy = p.sign(&root()).unwrap();
        let fresh = Fresh::sign(&dir, &policy.head, 10, 20).unwrap();
        {
            let db = DirectoryDb::open(&path).unwrap();
            db.store(&policy).unwrap();
            db.set_fresh(&fresh).unwrap();
        }
        assert_eq!(
            DirectoryDb::open(&path).unwrap().fresh().unwrap(),
            Some(fresh)
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(12))]

        /// Whatever order heads arrive in, the store ends at the highest and
        /// serves it intact.
        #[test]
        fn any_arrival_order_ends_at_the_newest(order in Just((1u64..=6).collect::<Vec<_>>()).prop_shuffle()) {
            let db = db();
            for v in &order {
                db.store(&signed(*v, &[*v as u8])).unwrap();
            }
            prop_assert_eq!(db.version().unwrap(), StateVersion(6));
            prop_assert_eq!(db.current().unwrap().unwrap(), signed(6, &[6]));
        }
    }
}

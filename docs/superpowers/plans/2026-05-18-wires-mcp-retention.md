# wires-mcp per-user retention Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound the on-disk size of `wires-mcp`'s per-user message logs with a TTL-based eviction policy and an optional per-user byte budget.

**Architecture:** Extend `wires-store::IngestIndex` with an `ingested_at_ms` column and an `evict_older_than` method. Add a `RetentionPolicy` to `wires-node::NodeConfig`; per-user `Node`s open an `IngestIndex` and run TTL+budget eviction after every inbound and publish, plus a 60 s periodic sweep from `NodeRuntime`. On first open, a reconciliation pass walks each per-topic `TopicLog` and inserts a fresh `IngestIndex` row for every entry that doesn't have one (this both backfills existing wires-mcp deploys and cleans up crash-orphaned rows). `wires-mcp::GatewayConfig` gains a `[retention]` section (defaults: ttl=1h, budget=50 MiB); `TenantSupervisor` injects the policy into each per-user `NodeConfig` before calling `NodeRuntime::open`. CLI/HA paths leave retention `None` and behave exactly as today.

**Tech Stack:** Rust, redb, tokio, snafu errors with `Location`, `wires_net::unix_now_ms()` as the single wall-clock source.

**Spec:** [docs/superpowers/specs/2026-05-18-wires-mcp-retention-design.md](../specs/2026-05-18-wires-mcp-retention-design.md).

---

## Conventions (apply to every task)

- Snafu errors only. Every new variant has `#[snafu(implicit)] location: Location`. Display strings end with `, at {location}`. No `message: String` fields except where existing variants already use them. Match the canonical pattern in `crates/wires-store/src/error.rs`, `crates/wires-node/src/error.rs`, `crates/wires-mcp/src/error.rs`.
- Centralize wall-clock reads on `wires_net::unix_now_ms()`. Do **not** add a new `now_ms()` helper. Do **not** sprinkle `SystemTime::now()` outside of `wires-net::time`.
- `wires-store::IngestIndex` rows go from 76 → 84 bytes. Decoding must accept both lengths (legacy 76-byte rows decode with `ingested_at_ms = 0`). New writes always emit 84 bytes.
- After each code change: `cargo build -p <crate>` then `cargo test -p <crate>` before committing.
- Commit one task per commit. Conventional-commit style messages (`feat:`, `refactor:`, `test:`).

---

### Task 1: wires-store — add `ingested_at_ms` to IngestEntry, length-tolerant decode

**Files:**
- Modify: `crates/wires-store/src/ingest_index.rs` (`IngestEntry` struct, `IngestIndex::record`, `oldest_entry`, `evict_oldest_until`, tests)
- Modify: `crates/wires-store/src/schema.rs` (update the `INGEST_INDEX` doc-comment)
- Modify: `crates/wires-host/src/retention.rs` (pass `unix_now_ms()` to `record` — keeps workspace build green)

- [ ] **Step 1: Update the `INGEST_INDEX` doc-comment in `schema.rs`**

Replace lines 31–33 of `crates/wires-store/src/schema.rs`:

```rust
/// Per-tenant FIFO index over ingested messages. Key = u64 BE ingest_seq.
/// Value layout (84 bytes):
///   [0..32]  topic_id
///   [32..64] sender
///   [64..72] seq            (BE u64)
///   [72..76] bytes          (BE u32)
///   [76..84] ingested_at_ms (BE i64)
/// Reads tolerate the legacy 76-byte layout (decoded with `ingested_at_ms = 0`).
pub const INGEST_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("ingest_index");
```

- [ ] **Step 2: Add `ingested_at_ms` field to `IngestEntry`**

In `crates/wires-store/src/ingest_index.rs`, replace the struct definition:

```rust
/// A single entry in the per-tenant ingest order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestEntry {
    pub topic_id: [u8; 32],
    pub sender: [u8; 32],
    pub seq: u64,
    pub bytes: u32,
    pub ingested_at_ms: i64,
}
```

- [ ] **Step 3: Update `IngestIndex::record` to take `now_ms` and write 84-byte rows**

Replace the existing `record` method:

```rust
/// Record an ingested message. Returns the assigned ingest_seq.
///
/// `now_ms` must be a wall-clock millisecond timestamp (see
/// `wires_net::unix_now_ms`). It is stored verbatim into the row's
/// `ingested_at_ms` field so the index can later answer "evict everything
/// older than X".
pub fn record(&self, entry: &IngestEntry, now_ms: i64) -> Result<u64> {
    let write = self.db.begin_write().context(BeginTxnSnafu)?;
    let assigned = {
        let mut meta_t = write.open_table(INGEST_META).context(OpenTableSnafu)?;
        let (next_ingest, total_bytes) = read_meta(&meta_t)?;

        let mut value = [0u8; 84];
        value[0..32].copy_from_slice(&entry.topic_id);
        value[32..64].copy_from_slice(&entry.sender);
        value[64..72].copy_from_slice(&entry.seq.to_be_bytes());
        value[72..76].copy_from_slice(&entry.bytes.to_be_bytes());
        value[76..84].copy_from_slice(&now_ms.to_be_bytes());

        let key = next_ingest.to_be_bytes();

        let mut idx_t = write.open_table(INGEST_INDEX).context(OpenTableSnafu)?;
        idx_t.insert(&key[..], &value[..]).context(StorageIoSnafu)?;

        let new_total = total_bytes.saturating_add(entry.bytes as u64);
        write_meta(&mut meta_t, next_ingest.wrapping_add(1), new_total)?;

        next_ingest
    };
    write.commit().context(CommitTxnSnafu)?;
    Ok(assigned)
}
```

- [ ] **Step 4: Add a length-tolerant row decoder and use it in `oldest_entry` + `evict_oldest_until`**

Add this free function near the bottom of `ingest_index.rs`, just above `read_meta`:

```rust
/// Decode a serialized ingest-index row. Accepts both the legacy 76-byte
/// layout (decoded with `ingested_at_ms = 0`) and the current 84-byte layout.
/// Returns `None` for any shorter buffer.
fn decode_row(raw: &[u8]) -> Option<IngestEntry> {
    if raw.len() < 76 {
        return None;
    }
    let mut topic_id = [0u8; 32];
    topic_id.copy_from_slice(&raw[0..32]);
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&raw[32..64]);
    let mut sb = [0u8; 8];
    sb.copy_from_slice(&raw[64..72]);
    let mut bb = [0u8; 4];
    bb.copy_from_slice(&raw[72..76]);
    let ingested_at_ms = if raw.len() >= 84 {
        let mut tb = [0u8; 8];
        tb.copy_from_slice(&raw[76..84]);
        i64::from_be_bytes(tb)
    } else {
        0
    };
    Some(IngestEntry {
        topic_id,
        sender,
        seq: u64::from_be_bytes(sb),
        bytes: u32::from_be_bytes(bb),
        ingested_at_ms,
    })
}
```

Replace the body of `oldest_entry` with:

```rust
pub fn oldest_entry(&self) -> Result<Option<IngestEntry>> {
    let read = self.db.begin_read().context(BeginTxnSnafu)?;
    let table = match read.open_table(INGEST_INDEX) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => {
            return Err(crate::error::StoreError::OpenTable {
                source: e,
                location: snafu::location!(),
            });
        }
    };
    let mut iter = table.iter().context(StorageIoSnafu)?;
    let Some(first) = iter.next() else {
        return Ok(None);
    };
    let (_k, v) = first.context(StorageIoSnafu)?;
    Ok(decode_row(v.value()))
}
```

In `evict_oldest_until`, replace the inline decode (the block beginning `let raw = v.value();` through the construction of `IngestEntry { topic_id, sender, seq: ..., bytes }`) with a single call to `decode_row`:

```rust
for entry_r in idx_t.iter().context(StorageIoSnafu)? {
    let (k, v) = entry_r.context(StorageIoSnafu)?;
    let mut kbuf = [0u8; 8];
    kbuf.copy_from_slice(k.value());
    let Some(ent) = decode_row(v.value()) else { continue };
    let bytes = ent.bytes;
    total = total.saturating_sub(bytes as u64);
    victim_keys.push(kbuf);
    victim_entries.push(ent);
    if total <= budget_bytes {
        break;
    }
}
```

- [ ] **Step 5: Fix all existing test helpers and call sites in `ingest_index.rs`**

The `entry()` helper at line ~199 has 4 fields; update to 5:

```rust
fn entry(topic: u8, sender: u8, seq: u64, bytes: u32) -> IngestEntry {
    IngestEntry {
        topic_id: [topic; 32],
        sender: [sender; 32],
        seq,
        bytes,
        ingested_at_ms: 0,
    }
}
```

Update every `idx.record(&entry(...))` call in this file to `idx.record(&entry(...), 0).unwrap()` (the existing tests don't care about the timestamp; passing `0` is fine).

- [ ] **Step 6: Add the round-trip tests for the new field**

Append to the `#[cfg(test)] mod tests` block in `ingest_index.rs`:

```rust
#[test]
fn record_persists_ingested_at_ms() {
    let tmp = TempDir::new().unwrap();
    let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
    let idx = IngestIndex::new(db);
    let e = IngestEntry {
        topic_id: [1u8; 32],
        sender: [9u8; 32],
        seq: 0,
        bytes: 100,
        ingested_at_ms: 1_700_000_000_000,
    };
    idx.record(&e, 1_700_000_000_000).unwrap();
    let oldest = idx.oldest_entry().unwrap().unwrap();
    assert_eq!(oldest.ingested_at_ms, 1_700_000_000_000);
    assert_eq!(oldest.bytes, 100);
}

#[test]
fn decode_row_accepts_legacy_76_byte_layout() {
    // Build a 76-byte row by hand, decode it, expect ingested_at_ms = 0.
    let mut raw = [0u8; 76];
    raw[0..32].copy_from_slice(&[1u8; 32]);
    raw[32..64].copy_from_slice(&[9u8; 32]);
    raw[64..72].copy_from_slice(&7u64.to_be_bytes());
    raw[72..76].copy_from_slice(&100u32.to_be_bytes());
    let ent = decode_row(&raw).expect("legacy row should decode");
    assert_eq!(ent.topic_id, [1u8; 32]);
    assert_eq!(ent.sender, [9u8; 32]);
    assert_eq!(ent.seq, 7);
    assert_eq!(ent.bytes, 100);
    assert_eq!(ent.ingested_at_ms, 0);
}
```

- [ ] **Step 7: Update wires-host to pass `unix_now_ms()` to `record`**

In `crates/wires-host/src/retention.rs`, replace the `record` call inside `on_append`:

```rust
idx.record(
    &IngestEntry {
        topic_id: *topic_id,
        sender: *sender,
        seq,
        bytes,
        ingested_at_ms: 0, // placeholder; overwritten by the explicit arg
    },
    wires_net::unix_now_ms(),
)
.context(StoreSnafu)?;
```

(The placeholder field is harmless — the row that gets written uses the explicit `now_ms` arg, not the field. The field exists so future host callers can pass a non-zero stamp if needed.)

Re-export `unix_now_ms` is already pulled in via `use wires_net::...` somewhere in this crate — if not, add `use wires_net::unix_now_ms;` to the imports at the top of the file (alongside the existing `wires_store` use). Adjust as required.

- [ ] **Step 8: Build and test wires-store + wires-host**

Run: `cargo build -p wires-store -p wires-host`
Expected: clean build.

Run: `cargo test -p wires-store -p wires-host`
Expected: all tests pass, including the two new `record_persists_ingested_at_ms` and `decode_row_accepts_legacy_76_byte_layout`.

- [ ] **Step 9: Commit**

```bash
git add crates/wires-store/src/ingest_index.rs crates/wires-store/src/schema.rs crates/wires-host/src/retention.rs
git commit -m "wires-store: add ingested_at_ms to IngestIndex rows (length-tolerant)"
```

---

### Task 2: wires-store — `evict_older_than` method

**Files:**
- Modify: `crates/wires-store/src/ingest_index.rs`

- [ ] **Step 1: Write the failing tests first**

Append to `#[cfg(test)] mod tests` in `ingest_index.rs`:

```rust
#[test]
fn evict_older_than_drops_stale_keeps_fresh() {
    let tmp = TempDir::new().unwrap();
    let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
    let idx = IngestIndex::new(db);
    // Insert four entries with increasing timestamps.
    idx.record(&entry(1, 9, 0, 100), 1_000).unwrap();
    idx.record(&entry(1, 9, 1, 100), 2_000).unwrap();
    idx.record(&entry(2, 8, 0, 100), 3_000).unwrap();
    idx.record(&entry(2, 8, 1, 100), 4_000).unwrap();

    // Drop everything older than 2_500.
    let dropped = idx.evict_older_than(2_500).unwrap();
    assert_eq!(dropped.len(), 2);
    assert_eq!(dropped[0].seq, 0);
    assert_eq!(dropped[0].ingested_at_ms, 1_000);
    assert_eq!(dropped[1].seq, 1);
    assert_eq!(dropped[1].ingested_at_ms, 2_000);

    // total_bytes drops to 200 (two surviving entries × 100 bytes).
    assert_eq!(idx.total_bytes().unwrap(), 200);
    let surviving = idx.oldest_entry().unwrap().unwrap();
    assert_eq!(surviving.ingested_at_ms, 3_000);
}

#[test]
fn evict_older_than_stops_at_first_fresh_row() {
    // The index is ordered by ingest_seq, which is monotone in
    // arrival time. evict_older_than must short-circuit as soon as it
    // hits a row with ingested_at_ms >= deadline — this is what makes
    // it O(k) instead of O(n).
    let tmp = TempDir::new().unwrap();
    let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
    let idx = IngestIndex::new(db);
    idx.record(&entry(1, 9, 0, 50), 1_000).unwrap();
    idx.record(&entry(1, 9, 1, 50), 5_000).unwrap();
    idx.record(&entry(1, 9, 2, 50), 2_000).unwrap(); // arrives later, but timestamped earlier
    // deadline = 3_000 — the first row is stale, the second is fresh, so we
    // must stop after dropping just the first row.
    let dropped = idx.evict_older_than(3_000).unwrap();
    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0].seq, 0);
    // Two entries survive even though one of them is "stale" by timestamp,
    // because we short-circuited.
    assert_eq!(idx.total_bytes().unwrap(), 100);
}

#[test]
fn evict_older_than_empty_index_is_noop() {
    let tmp = TempDir::new().unwrap();
    let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
    let idx = IngestIndex::new(db);
    let dropped = idx.evict_older_than(1_000).unwrap();
    assert!(dropped.is_empty());
    assert_eq!(idx.total_bytes().unwrap(), 0);
}
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `cargo test -p wires-store evict_older_than`
Expected: FAIL with "no method named `evict_older_than`".

- [ ] **Step 3: Implement `evict_older_than`**

Add this method on `impl IngestIndex` directly below `evict_oldest_until`:

```rust
/// Remove every entry whose `ingested_at_ms < deadline_ms`. Returns the
/// dropped entries in ingest order (oldest first). O(k) in the number of
/// expired entries — short-circuits at the first row whose timestamp is
/// ≥ deadline.
///
/// Iteration order is by ingest_seq (the redb table key), which is monotone
/// in arrival time. The short-circuit therefore covers the common case
/// where every newly-arrived row was timestamped close to "now" — a single
/// out-of-order row (e.g. from a misbehaving clock) still gets cleaned up
/// later when its predecessor would have been swept.
pub fn evict_older_than(&self, deadline_ms: i64) -> Result<Vec<IngestEntry>> {
    let write = self.db.begin_write().context(BeginTxnSnafu)?;
    let dropped;
    {
        let mut meta_t = write.open_table(INGEST_META).context(OpenTableSnafu)?;
        let (next_ingest, mut total) = read_meta(&meta_t)?;

        let mut idx_t = write.open_table(INGEST_INDEX).context(OpenTableSnafu)?;
        let mut victim_keys: Vec<[u8; 8]> = Vec::new();
        let mut victim_entries: Vec<IngestEntry> = Vec::new();
        for entry_r in idx_t.iter().context(StorageIoSnafu)? {
            let (k, v) = entry_r.context(StorageIoSnafu)?;
            let Some(ent) = decode_row(v.value()) else { continue };
            if ent.ingested_at_ms >= deadline_ms {
                break; // short-circuit
            }
            let mut kbuf = [0u8; 8];
            kbuf.copy_from_slice(k.value());
            total = total.saturating_sub(ent.bytes as u64);
            victim_keys.push(kbuf);
            victim_entries.push(ent);
        }

        for k in &victim_keys {
            idx_t.remove(&k[..]).context(StorageIoSnafu)?;
        }
        write_meta(&mut meta_t, next_ingest, total)?;
        dropped = victim_entries;
    }
    write.commit().context(CommitTxnSnafu)?;
    Ok(dropped)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p wires-store evict_older_than`
Expected: PASS for all three new tests.

Run: `cargo test -p wires-store`
Expected: all previously-passing tests still pass.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-store/src/ingest_index.rs
git commit -m "wires-store: add IngestIndex::evict_older_than"
```

---

### Task 3: wires-store — backfilled-flag helpers + `iter_all_entries`

**Files:**
- Modify: `crates/wires-store/src/ingest_index.rs`

- [ ] **Step 1: Write the failing tests**

Append to `#[cfg(test)] mod tests`:

```rust
#[test]
fn backfilled_flag_defaults_to_false() {
    let tmp = TempDir::new().unwrap();
    let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
    let idx = IngestIndex::new(db);
    assert!(!idx.is_backfilled().unwrap());
}

#[test]
fn set_backfilled_persists_across_reopens() {
    let tmp = TempDir::new().unwrap();
    {
        let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
        let idx = IngestIndex::new(db);
        assert!(!idx.is_backfilled().unwrap());
        idx.set_backfilled().unwrap();
        assert!(idx.is_backfilled().unwrap());
    }
    // Reopen and confirm persistence.
    let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
    let idx = IngestIndex::new(db);
    assert!(idx.is_backfilled().unwrap());
}

#[test]
fn iter_all_entries_returns_every_row() {
    let tmp = TempDir::new().unwrap();
    let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
    let idx = IngestIndex::new(db);
    idx.record(&entry(1, 9, 0, 100), 1_000).unwrap();
    idx.record(&entry(2, 8, 0, 200), 2_000).unwrap();
    idx.record(&entry(2, 8, 1, 200), 3_000).unwrap();
    let all = idx.iter_all_entries().unwrap();
    assert_eq!(all.len(), 3);
    let keys: std::collections::HashSet<_> = all
        .iter()
        .map(|e| (e.topic_id, e.sender, e.seq))
        .collect();
    assert!(keys.contains(&([1u8; 32], [9u8; 32], 0)));
    assert!(keys.contains(&([2u8; 32], [8u8; 32], 0)));
    assert!(keys.contains(&([2u8; 32], [8u8; 32], 1)));
}

#[test]
fn iter_all_entries_empty_index_returns_empty_vec() {
    let tmp = TempDir::new().unwrap();
    let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
    let idx = IngestIndex::new(db);
    assert!(idx.iter_all_entries().unwrap().is_empty());
}
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `cargo test -p wires-store backfilled iter_all_entries`
Expected: FAIL with "no method named …".

- [ ] **Step 3: Add a separate meta key for the backfilled flag**

Near the top of `ingest_index.rs`, just below the existing `const META_KEY: &[u8] = b"m";`:

```rust
const BACKFILLED_KEY: &[u8] = b"b";
```

- [ ] **Step 4: Add the new public methods**

Add these on `impl IngestIndex`, after `evict_older_than`:

```rust
/// Whether the one-time per-tenant backfill has already been performed.
/// Defaults to `false` on a fresh index.
pub fn is_backfilled(&self) -> Result<bool> {
    let read = self.db.begin_read().context(BeginTxnSnafu)?;
    let table = match read.open_table(INGEST_META) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(false),
        Err(e) => {
            return Err(crate::error::StoreError::OpenTable {
                source: e,
                location: snafu::location!(),
            });
        }
    };
    match table.get(BACKFILLED_KEY).context(StorageIoSnafu)? {
        Some(g) => Ok(g.value().first() == Some(&1)),
        None => Ok(false),
    }
}

/// Mark this index as backfilled. Idempotent.
pub fn set_backfilled(&self) -> Result<()> {
    let write = self.db.begin_write().context(BeginTxnSnafu)?;
    {
        let mut meta_t = write.open_table(INGEST_META).context(OpenTableSnafu)?;
        meta_t
            .insert(BACKFILLED_KEY, &[1u8][..])
            .context(StorageIoSnafu)?;
    }
    write.commit().context(CommitTxnSnafu)?;
    Ok(())
}

/// Return every stored entry, in ingest_seq order. O(n); intended for
/// startup reconciliation only.
pub fn iter_all_entries(&self) -> Result<Vec<IngestEntry>> {
    let read = self.db.begin_read().context(BeginTxnSnafu)?;
    let table = match read.open_table(INGEST_INDEX) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(e) => {
            return Err(crate::error::StoreError::OpenTable {
                source: e,
                location: snafu::location!(),
            });
        }
    };
    let mut out = Vec::new();
    for entry_r in table.iter().context(StorageIoSnafu)? {
        let (_k, v) = entry_r.context(StorageIoSnafu)?;
        if let Some(ent) = decode_row(v.value()) {
            out.push(ent);
        }
    }
    Ok(out)
}
```

- [ ] **Step 5: Run tests to verify pass**

Run: `cargo test -p wires-store`
Expected: PASS, including the four new tests.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-store/src/ingest_index.rs
git commit -m "wires-store: add backfilled flag + iter_all_entries on IngestIndex"
```

---

### Task 4: wires-node — `RetentionPolicy` type + `NodeConfig.retention`

**Files:**
- Modify: `crates/wires-node/src/config.rs`
- Modify: `crates/wires-node/src/lib.rs` (re-export `RetentionPolicy`)
- Modify: every `NodeConfig { ... }` struct literal across the workspace (see Step 5)

- [ ] **Step 1: Write the failing test**

Append to `#[cfg(test)] mod tests` in `crates/wires-node/src/config.rs`:

```rust
#[test]
fn node_config_with_retention_field_constructs() {
    let cfg = NodeConfig {
        data_dir: PathBuf::from("/tmp/wires-test"),
        root_pubkey_hex: "deadbeef".into(),
        host: None,
        retention: Some(crate::config::RetentionPolicy {
            ttl: std::time::Duration::from_secs(3600),
            max_bytes_per_user: 52_428_800,
        }),
    };
    let r = cfg.retention.expect("retention must be set");
    assert_eq!(r.ttl, std::time::Duration::from_secs(3600));
    assert_eq!(r.max_bytes_per_user, 52_428_800);
}

#[test]
fn node_config_toml_round_trip_drops_retention_field() {
    // `retention` is `#[serde(skip)]` — it's built by gateway code, not
    // read from per-user config.toml. Round-tripping through TOML therefore
    // resets it to None regardless of what was set in memory.
    let cfg = NodeConfig {
        data_dir: PathBuf::from("/tmp/wires-test"),
        root_pubkey_hex: "deadbeef".into(),
        host: None,
        retention: Some(crate::config::RetentionPolicy {
            ttl: std::time::Duration::from_secs(3600),
            max_bytes_per_user: 1024,
        }),
    };
    let s = toml::to_string_pretty(&cfg).unwrap();
    let back: NodeConfig = toml::from_str(&s).unwrap();
    assert!(back.retention.is_none(), "retention must be skipped on serde");
}

#[test]
fn node_config_without_retention_deserializes_to_none() {
    let s = r#"
        data_dir = "/tmp/wires-test"
        root_pubkey_hex = "deadbeef"
    "#;
    let cfg: NodeConfig = toml::from_str(s).unwrap();
    assert!(cfg.retention.is_none());
    assert!(cfg.host.is_none());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p wires-node node_config_with_retention_field_constructs`
Expected: FAIL (`RetentionPolicy` doesn't exist).

- [ ] **Step 3: Define `RetentionPolicy` and add the field**

In `crates/wires-node/src/config.rs`, after the existing `HostConfig` struct, add:

```rust
/// Per-user retention policy. When `Some(_)`, the runtime opens an
/// `IngestIndex` for the user, hooks record+sweep into inbound and publish,
/// runs a startup reconciliation pass, and starts a periodic 60 s sweep.
///
/// Deliberately not `Serialize`/`Deserialize` — built in code by the
/// gateway and injected into `NodeConfig` at runtime. The matching
/// `NodeConfig.retention` field is `#[serde(skip)]`, so per-user
/// `config.toml` files never carry retention state on disk.
#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    /// TTL after which a stored message becomes eligible for eviction.
    /// Must be > 0.
    pub ttl: std::time::Duration,
    /// Byte budget across all of this user's topics. 0 = no budget cap
    /// (TTL alone enforces). When > 0, after each TTL sweep the runtime
    /// also calls `evict_oldest_until(max_bytes_per_user)` to enforce the
    /// budget.
    pub max_bytes_per_user: u64,
}
```

Add `retention: Option<RetentionPolicy>` to `NodeConfig`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub data_dir: PathBuf,
    pub root_pubkey_hex: String,
    #[serde(default)]
    pub host: Option<HostConfig>,
    /// `None` = "no retention, behave as today" (CLI agents, `wires-ha`).
    /// `Some(_)` = wires-mcp gateway path: open IngestIndex, run sweeps.
    /// Marked `#[serde(skip)]` because the gateway injects it in code,
    /// never via per-user config.toml.
    #[serde(skip)]
    pub retention: Option<RetentionPolicy>,
}
```

- [ ] **Step 4: Update every `NodeConfig { ... }` struct literal to include `retention: None`**

The Rust compiler will list every offending site after `cargo build` once the new field is added. The known sites (verify with `rg 'NodeConfig \{' crates/`):

- `crates/wires-node/src/config.rs` (tests inside this file)
- `crates/wires-node/src/pair.rs`
- `crates/wires-node/src/runtime.rs` (3 sites in tests)
- `crates/wires-node/tests/pair_handler.rs`
- `crates/wires-node/tests/pair_listen.rs` (2 sites)
- `crates/wires-node/tests/runtime_publish_subscribes.rs` (2 sites)
- `crates/wires-node/tests/two_nodes_lan.rs`
- `crates/wires-node/tests/acceptance_host_blindness.rs` (2 sites)
- `crates/wires-cli/src/cmd/init.rs`
- `crates/wires-cli/tests/cli_publish_auto_dials.rs` (3 sites)
- `crates/wires-cli/tests/cli_host_pair.rs`
- `crates/wires-cli/tests/cli_host_topic_register.rs`
- `crates/wires-mcp/src/tenants.rs` (2 sites in tests)
- `crates/wires-mcp/src/pair_bridge.rs` (2 sites in tests)
- `crates/wires-mcp/src/mcp/tools.rs` (2 sites in tests)
- `crates/wires-host/tests/acceptance.rs`

Each occurrence gets a new line `retention: None,`. Example diff:

```rust
let cfg = NodeConfig {
    data_dir: tmp.path().to_path_buf(),
    root_pubkey_hex: "deadbeef".into(),
    host: None,
    retention: None,
};
```

- [ ] **Step 5: Re-export `RetentionPolicy` from the crate root**

In `crates/wires-node/src/lib.rs`, change the existing line:

```rust
pub use config::{HostConfig, NodeConfig, load_root_signing_key};
```

to:

```rust
pub use config::{HostConfig, NodeConfig, RetentionPolicy, load_root_signing_key};
```

- [ ] **Step 6: Build and test the workspace**

Run: `cargo build --workspace`
Expected: clean build.

Run: `cargo test -p wires-node config::`
Expected: the three new tests pass; existing tests still pass.

- [ ] **Step 7: Commit**

```bash
git add crates/wires-node/src/config.rs crates/wires-node/src/lib.rs \
        crates/wires-node/src/pair.rs crates/wires-node/src/runtime.rs \
        crates/wires-node/tests/ crates/wires-cli/ crates/wires-mcp/src/tenants.rs \
        crates/wires-mcp/src/pair_bridge.rs crates/wires-mcp/src/mcp/tools.rs \
        crates/wires-host/tests/acceptance.rs
git commit -m "wires-node: add RetentionPolicy to NodeConfig"
```

(Adjust the `git add` list if `cargo build` surfaces additional sites; the canonical list above is from the current main.)

---

### Task 5: wires-node — `Node` holds retention state; `Node::open` opens the IngestIndex

**Files:**
- Modify: `crates/wires-node/src/node.rs`

- [ ] **Step 1: Add the new fields to `Node`**

Find the `pub struct Node {` block in `crates/wires-node/src/node.rs` and add two fields just before `publish_lock`:

```rust
pub struct Node {
    pub config: NodeConfig,
    pub ed_sk: SigningKey,
    pub x_sk: X25519Secret,
    pub x_pk: [u8; 32],
    pub logs: Arc<TopicLogs>,
    pub caps: Arc<CapTable>,
    keys_by_topic: Mutex<HashMap<[u8; 32], Arc<EpochKeyStore>>>,
    pub events_tx: broadcast::Sender<DecryptedEvent>,
    /// Optional retention enforcement (gateway path). `None` for CLI/HA.
    pub retention: Option<crate::config::RetentionPolicy>,
    /// Per-user ingest index. Present iff `retention.is_some()`.
    pub ingest_index: Option<Arc<wires_store::IngestIndex>>,
    publish_lock: Mutex<()>,
}
```

Update the imports near the top of the file:

```rust
use wires_store::{CapTable, EpochKey, EpochKeyStore, IngestIndex, open_caps, open_ingest_index, open_topic_keys};
```

- [ ] **Step 2: Open the IngestIndex in `Node::open` when retention is set**

In the body of `Node::open`, after `let caps = Arc::new(CapTable::new(Arc::new(caps_db)));` and before the `let (events_tx, _) = ...`, add:

```rust
let (retention, ingest_index) = match &config.retention {
    Some(policy) => {
        let ingest_db =
            open_ingest_index(&config.data_dir, &config.root_pubkey_hex).context(StoreSnafu)?;
        let idx = Arc::new(IngestIndex::new(Arc::new(ingest_db)));
        (Some(policy.clone()), Some(idx))
    }
    None => (None, None),
};
```

Then include `retention` and `ingest_index` in the struct literal that follows:

```rust
Ok(Self {
    config,
    ed_sk,
    x_sk,
    x_pk,
    logs,
    caps,
    keys_by_topic: Mutex::new(HashMap::new()),
    events_tx,
    retention,
    ingest_index,
    publish_lock: Mutex::new(()),
})
```

- [ ] **Step 3: Build**

Run: `cargo build -p wires-node`
Expected: clean build (no test is added in this task — Task 6's sweep test exercises the field).

- [ ] **Step 4: Confirm existing tests still pass**

Run: `cargo test -p wires-node`
Expected: pass — the change is additive and `retention = None` keeps the rest of the runtime byte-identical.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-node/src/node.rs
git commit -m "wires-node: open per-user IngestIndex on Node::open when retention is configured"
```

---

### Task 6: wires-node — `Node::sweep` (TTL + budget eviction)

**Files:**
- Modify: `crates/wires-node/src/node.rs`

- [ ] **Step 1: Write the failing test**

Append to `#[cfg(test)] mod tests` in `node.rs`:

```rust
#[test]
fn sweep_evicts_ttl_expired_entries_and_their_topic_log_rows() {
    use std::time::Duration;
    let tmp = TempDir::new().unwrap();
    let root = SigningKey::generate(&mut OsRng);
    let root_hex = hex::encode(root.verifying_key().to_bytes());
    let cfg = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        root_pubkey_hex: root_hex,
        host: None,
        retention: Some(crate::config::RetentionPolicy {
            ttl: Duration::from_millis(100),
            max_bytes_per_user: 0,
        }),
    };
    let node = Node::open(cfg).unwrap();

    // Manually plant a row in the ingest_index with an old timestamp,
    // and a matching row in the topic log.
    let topic = [42u8; 32];
    let sender = [9u8; 32];
    let log = node.logs.get_or_open(&topic).unwrap();
    let msg = wires_core::WireMessage {
        topic_id: topic,
        epoch: 0,
        kind: wires_core::MessageKind::Public,
        sender,
        cap_id: [0u8; 16],
        seq: 0,
        prev_hash: [0u8; 32],
        timestamp: 0,
        payload_len: 0,
        signature: [0u8; 64],
        ciphertext: vec![],
    };
    log.append(&msg).unwrap();
    let bytes = serde_json::to_vec(&msg).unwrap().len() as u32;
    let ix = node.ingest_index.as_ref().expect("retention enabled");
    ix.record(
        &wires_store::IngestEntry {
            topic_id: topic,
            sender,
            seq: 0,
            bytes,
            ingested_at_ms: 0,
        },
        1_000, // timestamp deep in the past
    )
    .unwrap();

    // Sweep with now = 10_000; ttl = 100 ms → deadline = 9_900 — the entry
    // (ts = 1_000) is stale.
    node.sweep(10_000).unwrap();
    assert_eq!(ix.total_bytes().unwrap(), 0);
    assert!(log.read_after(&sender, None, 10).unwrap().is_empty());
}

#[test]
fn sweep_with_budget_evicts_oldest_when_over() {
    use std::time::Duration;
    let tmp = TempDir::new().unwrap();
    let root = SigningKey::generate(&mut OsRng);
    let root_hex = hex::encode(root.verifying_key().to_bytes());
    let cfg = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        root_pubkey_hex: root_hex,
        host: None,
        retention: Some(crate::config::RetentionPolicy {
            // huge TTL so only the budget enforces.
            ttl: Duration::from_secs(86_400),
            max_bytes_per_user: 200,
        }),
    };
    let node = Node::open(cfg).unwrap();
    let topic = [42u8; 32];
    let sender = [9u8; 32];
    let log = node.logs.get_or_open(&topic).unwrap();
    let ix = node.ingest_index.as_ref().unwrap();
    for seq in 0..5u64 {
        let m = wires_core::WireMessage {
            topic_id: topic,
            epoch: 0,
            kind: wires_core::MessageKind::Public,
            sender,
            cap_id: [0u8; 16],
            seq,
            prev_hash: [0u8; 32],
            timestamp: seq as i64,
            payload_len: 0,
            signature: [0u8; 64],
            ciphertext: vec![],
        };
        log.append(&m).unwrap();
        let b = serde_json::to_vec(&m).unwrap().len() as u32;
        ix.record(
            &wires_store::IngestEntry {
                topic_id: topic,
                sender,
                seq,
                bytes: b,
                ingested_at_ms: 1_000 + seq as i64,
            },
            1_000 + seq as i64,
        )
        .unwrap();
    }
    node.sweep(2_000).unwrap();
    // Budget = 200; per-entry bytes ≈ 200+, so we expect at most 1 entry to
    // remain (or possibly 0).
    let after = log.read_after(&sender, None, 100).unwrap();
    assert!(after.len() <= 1, "budget eviction left too much: {}", after.len());
    assert!(ix.total_bytes().unwrap() <= 200);
}

#[test]
fn sweep_is_noop_when_retention_disabled() {
    let tmp = TempDir::new().unwrap();
    let cfg = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        root_pubkey_hex: "deadbeef".into(),
        host: None,
        retention: None,
    };
    let node = Node::open(cfg).unwrap();
    assert!(node.ingest_index.is_none());
    node.sweep(123).unwrap(); // must not panic / error
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p wires-node sweep_`
Expected: FAIL with "no method named `sweep`".

- [ ] **Step 3: Implement `Node::sweep`**

Add the method on `impl Node` in `node.rs`:

```rust
/// Apply the configured retention policy: evict TTL-expired entries from
/// the ingest index and (if a byte budget is set) evict oldest entries
/// until the user is under budget. For each dropped entry, deletes the
/// matching per-topic `TopicLog` row.
///
/// No-op when `retention` is `None`. Safe to call concurrently with
/// inbound/publish — each step is a single redb write transaction.
pub fn sweep(&self, now_ms: i64) -> Result<()> {
    let Some(policy) = &self.retention else { return Ok(()); };
    let Some(ix) = &self.ingest_index else { return Ok(()); };

    let deadline = now_ms.saturating_sub(policy.ttl.as_millis() as i64);
    let dropped_ttl = ix.evict_older_than(deadline).context(StoreSnafu)?;
    for e in &dropped_ttl {
        self.delete_topic_log_entry(e)?;
    }

    if policy.max_bytes_per_user > 0 {
        let dropped_budget = ix
            .evict_oldest_until(policy.max_bytes_per_user)
            .context(StoreSnafu)?;
        for e in &dropped_budget {
            self.delete_topic_log_entry(e)?;
        }
    }
    Ok(())
}

fn delete_topic_log_entry(&self, e: &wires_store::IngestEntry) -> Result<()> {
    let log = self.logs.get_or_open(&e.topic_id)?;
    log.delete(&e.sender, e.seq).context(StoreSnafu)?;
    Ok(())
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p wires-node sweep_`
Expected: PASS for all three new tests.

Run: `cargo test -p wires-node`
Expected: existing tests still pass.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-node/src/node.rs
git commit -m "wires-node: Node::sweep — TTL + byte-budget eviction"
```

---

### Task 7: wires-node — record + sweep hook on inbound and publish

**Files:**
- Modify: `crates/wires-node/src/node.rs`

- [ ] **Step 1: Write the failing test**

Append to `#[cfg(test)] mod tests` in `node.rs`:

```rust
#[test]
fn publish_records_and_sweep_evicts_after_ttl_lapse() {
    use std::time::Duration;
    let tmp = TempDir::new().unwrap();
    let root = SigningKey::generate(&mut OsRng);
    let root_hex = hex::encode(root.verifying_key().to_bytes());
    let cfg = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        root_pubkey_hex: root_hex,
        host: None,
        retention: Some(crate::config::RetentionPolicy {
            ttl: Duration::from_millis(1),
            max_bytes_per_user: 0,
        }),
    };
    let node = Node::open(cfg).unwrap();

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
    node.publish_standard(
        topic_id,
        cap_id,
        CanonicalContent::new("home.test", "hello"),
    )
    .unwrap();

    let ix = node.ingest_index.as_ref().unwrap();
    assert!(ix.total_bytes().unwrap() > 0, "publish must record an entry");

    // Sleep past TTL, then call sweep — the entry must be evicted.
    std::thread::sleep(Duration::from_millis(5));
    node.sweep(wires_net::unix_now_ms()).unwrap();
    assert_eq!(ix.total_bytes().unwrap(), 0, "TTL sweep must drop the entry");
}

#[test]
fn handle_inbound_records_into_ingest_index() {
    // Construct a known-good envelope by publishing it on one node, then
    // hand the wire bytes to a second node and confirm its ingest_index
    // records the entry.
    let tmp1 = TempDir::new().unwrap();
    let tmp2 = TempDir::new().unwrap();
    let root = SigningKey::generate(&mut OsRng);
    let root_hex = hex::encode(root.verifying_key().to_bytes());

    let cfg_pub = NodeConfig {
        data_dir: tmp1.path().to_path_buf(),
        root_pubkey_hex: root_hex.clone(),
        host: None,
        retention: None,
    };
    let pub_node = Node::open(cfg_pub).unwrap();
    let pub_pk = pub_node.ed_sk.verifying_key().to_bytes();
    let mut cap = Capability::new_unsigned(
        pub_pk,
        vec!["home.test".into()],
        vec![Right::Read, Right::Write],
        0,
        None,
    );
    cap.sign(&root).unwrap();
    let cap_id = cap.cap_id.0;
    pub_node.caps.upsert_grant(&cap).unwrap();

    let topic_id = [42u8; 32];
    pub_node.install_epoch_key(topic_id, 0, [9u8; 32]).unwrap();
    let msg = pub_node
        .publish_standard(topic_id, cap_id, CanonicalContent::new("home.test", "hi"))
        .unwrap();

    // Now the receiver — retention enabled, will use pub_node's pubkey via cap grant.
    let cfg_rx = NodeConfig {
        data_dir: tmp2.path().to_path_buf(),
        root_pubkey_hex: root_hex,
        host: None,
        retention: Some(crate::config::RetentionPolicy {
            ttl: std::time::Duration::from_secs(3600),
            max_bytes_per_user: 0,
        }),
    };
    let rx_node = Node::open(cfg_rx).unwrap();
    rx_node.caps.upsert_grant(&cap).unwrap();
    rx_node.install_epoch_key(topic_id, 0, [9u8; 32]).unwrap();
    let outcome = rx_node.handle_inbound(msg).unwrap();
    matches!(outcome, crate::inbound::Inbound::Accepted { .. } | crate::inbound::Inbound::AcceptedOpaque { .. });
    let ix = rx_node.ingest_index.as_ref().unwrap();
    assert!(ix.total_bytes().unwrap() > 0, "inbound must record an entry");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p wires-node publish_records_and_sweep_evicts_after_ttl_lapse handle_inbound_records_into_ingest_index`
Expected: FAIL (publish/inbound don't currently record into the IngestIndex).

- [ ] **Step 3: Hook record + sweep into `publish_standard`**

In `Node::publish_standard`, after `log.append(&msg).context(StoreSnafu)?;` and before the `events_tx.send` call, add:

```rust
if let (Some(ix), Some(_)) = (&self.ingest_index, &self.retention) {
    let bytes = serde_json::to_vec(&msg).context(crate::error::SerdeSnafu)?.len() as u32;
    let now = wires_net::unix_now_ms();
    ix.record(
        &wires_store::IngestEntry {
            topic_id,
            sender: self.ed_sk.verifying_key().to_bytes(),
            seq: msg.seq,
            bytes,
            ingested_at_ms: now,
        },
        now,
    )
    .context(StoreSnafu)?;
    self.sweep(now)?;
}
```

- [ ] **Step 4: Hook record + sweep into `handle_inbound`**

In `Node::handle_inbound`, modify the `match &outcome` arms to call record+sweep for both `Accepted` and `AcceptedOpaque`. Replace the existing match with:

```rust
match &outcome {
    Inbound::Accepted { msg, content } => {
        self.record_and_sweep(msg)?;
        let _ = self.events_tx.send(DecryptedEvent {
            topic_id: msg.topic_id,
            msg: msg.clone(),
            content: content.clone(),
        });
    }
    Inbound::AcceptedOpaque { msg } => {
        self.record_and_sweep(msg)?;
        let _ = self.events_tx.send(DecryptedEvent {
            topic_id: msg.topic_id,
            msg: msg.clone(),
            content: None,
        });
    }
    Inbound::Rejected { .. } => {}
}
```

Then add the helper near `delete_topic_log_entry`:

```rust
fn record_and_sweep(&self, msg: &wires_core::WireMessage) -> Result<()> {
    let Some(ix) = &self.ingest_index else { return Ok(()); };
    if self.retention.is_none() {
        return Ok(());
    }
    let bytes = serde_json::to_vec(msg).context(crate::error::SerdeSnafu)?.len() as u32;
    let now = wires_net::unix_now_ms();
    ix.record(
        &wires_store::IngestEntry {
            topic_id: msg.topic_id,
            sender: msg.sender,
            seq: msg.seq,
            bytes,
            ingested_at_ms: now,
        },
        now,
    )
    .context(StoreSnafu)?;
    self.sweep(now)
}
```

- [ ] **Step 5: Build and run tests**

Run: `cargo test -p wires-node`
Expected: all tests pass, including the two new ones from this task.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-node/src/node.rs
git commit -m "wires-node: hook IngestIndex record + sweep into publish and inbound paths"
```

---

### Task 8: wires-node — startup reconciliation + backfill flag

**Files:**
- Modify: `crates/wires-node/src/node.rs`
- Modify: `crates/wires-node/src/storage.rs` (small helper: list every topic_id with a log on disk)

- [ ] **Step 1: Add a helper to enumerate persisted topic ids**

In `crates/wires-node/src/storage.rs`, add this method on `impl TopicLogs` (just below `get_or_open`):

```rust
/// List every topic_id that has a `topics/<hex>/log.db` on disk under
/// `root`. Used by `Node::reconcile_ingest_index` to walk pre-existing
/// logs. Returns `Ok(Vec::new())` if `root/topics/` does not yet exist.
pub fn persisted_topic_ids(&self) -> Result<Vec<[u8; 32]>> {
    let topics_root = self.root.join("topics");
    let mut out = Vec::new();
    let read_dir = match std::fs::read_dir(&topics_root) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(crate::error::NodeError::Io {
                source: e,
                location: snafu::location!(),
            });
        }
    };
    for entry in read_dir {
        let entry = entry.map_err(|e| crate::error::NodeError::Io {
            source: e,
            location: snafu::location!(),
        })?;
        let name = entry.file_name();
        let Some(hex_id) = name.to_str() else { continue };
        if hex_id.len() != 64 {
            continue;
        }
        let Ok(raw) = hex::decode(hex_id) else { continue };
        let Ok(arr) = <[u8; 32]>::try_from(raw.as_slice()) else { continue };
        // Only count directories that actually have a log.db.
        if entry.path().join("log.db").is_file() {
            out.push(arr);
        }
    }
    Ok(out)
}
```

(`root` field is already private; expose nothing else — only the new method is public.)

- [ ] **Step 2: Write the failing test**

Append to `#[cfg(test)] mod tests` in `node.rs`:

```rust
#[test]
fn reconcile_inserts_missing_index_rows_for_existing_log_entries() {
    use std::time::Duration;
    let tmp = TempDir::new().unwrap();
    let root_hex = "deadbeef".to_string();
    let topic = [42u8; 32];

    // First, open WITHOUT retention to write log entries. Then close.
    {
        let cfg = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            root_pubkey_hex: root_hex.clone(),
            host: None,
            retention: None,
        };
        let node = Node::open(cfg).unwrap();
        let log = node.logs.get_or_open(&topic).unwrap();
        for seq in 0..3u64 {
            let m = wires_core::WireMessage {
                topic_id: topic,
                epoch: 0,
                kind: wires_core::MessageKind::Public,
                sender: [9u8; 32],
                cap_id: [0u8; 16],
                seq,
                prev_hash: [0u8; 32],
                timestamp: seq as i64,
                payload_len: 0,
                signature: [0u8; 64],
                ciphertext: vec![],
            };
            log.append(&m).unwrap();
        }
    }

    // Now reopen WITH retention. Backfill should fire.
    let cfg = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        root_pubkey_hex: root_hex,
        host: None,
        retention: Some(crate::config::RetentionPolicy {
            ttl: Duration::from_secs(3600),
            max_bytes_per_user: 0,
        }),
    };
    let node = Node::open(cfg).unwrap();
    let ix = node.ingest_index.as_ref().unwrap();
    assert!(ix.is_backfilled().unwrap(), "first open must set the flag");
    let all = ix.iter_all_entries().unwrap();
    assert_eq!(all.len(), 3, "backfill must insert one row per log entry");
}

#[test]
fn reconcile_is_idempotent_on_second_open() {
    use std::time::Duration;
    let tmp = TempDir::new().unwrap();
    let root_hex = "deadbeef".to_string();
    let topic = [42u8; 32];

    let cfg = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        root_pubkey_hex: root_hex,
        host: None,
        retention: Some(crate::config::RetentionPolicy {
            ttl: Duration::from_secs(3600),
            max_bytes_per_user: 0,
        }),
    };
    {
        let node = Node::open(cfg.clone()).unwrap();
        // Append directly to the log to simulate an orphan (no index entry).
        let log = node.logs.get_or_open(&topic).unwrap();
        let m = wires_core::WireMessage {
            topic_id: topic,
            epoch: 0,
            kind: wires_core::MessageKind::Public,
            sender: [9u8; 32],
            cap_id: [0u8; 16],
            seq: 0,
            prev_hash: [0u8; 32],
            timestamp: 0,
            payload_len: 0,
            signature: [0u8; 64],
            ciphertext: vec![],
        };
        log.append(&m).unwrap();
    }
    // Reopen — must pick up the orphan even though the backfill flag is set.
    let node = Node::open(cfg).unwrap();
    let ix = node.ingest_index.as_ref().unwrap();
    let all = ix.iter_all_entries().unwrap();
    assert_eq!(all.len(), 1, "second open must reconcile orphan log entries");
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p wires-node reconcile_`
Expected: FAIL (no reconciliation runs yet).

- [ ] **Step 4: Implement reconciliation and call it from `Node::open`**

Add this method on `impl Node`:

```rust
/// Walk every per-topic `TopicLog` on disk and insert a fresh
/// `IngestIndex` row for any (topic_id, sender, seq) that isn't already
/// indexed. Used at open-time both as a one-shot backfill for pre-retention
/// deploys and as a permanent safety net for the inbound/sweep crash
/// window (IngestIndex remove committed but TopicLog delete not yet
/// applied → orphan log row).
///
/// Orphans get a fresh TTL window starting at `now_ms` and age out
/// normally. Idempotent; safe to call on every open.
fn reconcile_ingest_index(&self, now_ms: i64) -> Result<()> {
    let Some(ix) = &self.ingest_index else { return Ok(()); };
    let known: std::collections::HashSet<([u8; 32], [u8; 32], u64)> = ix
        .iter_all_entries()
        .context(StoreSnafu)?
        .into_iter()
        .map(|e| (e.topic_id, e.sender, e.seq))
        .collect();
    for topic_id in self.logs.persisted_topic_ids()? {
        let log = self.logs.get_or_open(&topic_id)?;
        let entries = log.read_all().context(StoreSnafu)?;
        for msg in entries {
            if known.contains(&(topic_id, msg.sender, msg.seq)) {
                continue;
            }
            let bytes = serde_json::to_vec(&msg).context(crate::error::SerdeSnafu)?.len() as u32;
            ix.record(
                &wires_store::IngestEntry {
                    topic_id,
                    sender: msg.sender,
                    seq: msg.seq,
                    bytes,
                    ingested_at_ms: now_ms,
                },
                now_ms,
            )
            .context(StoreSnafu)?;
        }
    }
    if !ix.is_backfilled().context(StoreSnafu)? {
        ix.set_backfilled().context(StoreSnafu)?;
    }
    Ok(())
}
```

Call it from `Node::open`, just before `Ok(Self { ... })`:

```rust
let result = Self {
    config,
    ed_sk,
    x_sk,
    x_pk,
    logs,
    caps,
    keys_by_topic: Mutex::new(HashMap::new()),
    events_tx,
    retention,
    ingest_index,
    publish_lock: Mutex::new(()),
};
result.reconcile_ingest_index(wires_net::unix_now_ms())?;
Ok(result)
```

(The `Self { ... }` ↔ `result` rename is so we can call a method on the constructed value before returning it.)

- [ ] **Step 5: Run tests**

Run: `cargo test -p wires-node reconcile_`
Expected: PASS.

Run: `cargo test -p wires-node`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-node/src/node.rs crates/wires-node/src/storage.rs
git commit -m "wires-node: reconcile IngestIndex against on-disk TopicLogs at open"
```

---

### Task 9: wires-node — `NodeRuntime` 60 s sweep timer

**Files:**
- Modify: `crates/wires-node/src/runtime.rs`

- [ ] **Step 1: Write the failing test**

Append to `#[cfg(test)] mod tests` in `runtime.rs`:

```rust
#[tokio::test]
async fn runtime_with_retention_opens_index_and_timer() {
    use std::time::Duration;
    let tmp = TempDir::new().unwrap();
    let cfg = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        root_pubkey_hex: hex::encode([7u8; 32]),
        host: None,
        retention: Some(crate::config::RetentionPolicy {
            ttl: Duration::from_secs(3600),
            max_bytes_per_user: 0,
        }),
    };
    let rt = NodeRuntime::open(cfg).await.unwrap();
    assert!(rt.node.ingest_index.is_some(), "IngestIndex must be opened");
    assert!(rt.has_sweep_task(), "sweep task must be running");
    drop(rt);
}

#[tokio::test]
async fn runtime_without_retention_skips_timer() {
    let tmp = TempDir::new().unwrap();
    let cfg = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        root_pubkey_hex: hex::encode([7u8; 32]),
        host: None,
        retention: None,
    };
    let rt = NodeRuntime::open(cfg).await.unwrap();
    assert!(rt.node.ingest_index.is_none());
    assert!(!rt.has_sweep_task());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p wires-node runtime_with_retention runtime_without_retention`
Expected: FAIL with "no method named `has_sweep_task`".

- [ ] **Step 3: Add the sweep task to `NodeRuntime`**

In `crates/wires-node/src/runtime.rs`, update the struct definition:

```rust
pub struct NodeRuntime {
    pub node: Arc<Node>,
    pub endpoint: Endpoint,
    pub glue: NetGlue,
    handles: Mutex<HashMap<[u8; 32], GossipHandle>>,
    sweep_task: Option<tokio::task::JoinHandle<()>>,
}
```

In `NodeRuntime::open`, after `let glue = NetGlue::new(...)?;` and before the `Ok(Self { ... })`, add:

```rust
let sweep_task = if node.retention.is_some() {
    let node_for_sweep = Arc::clone(&node);
    Some(tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        // The first tick fires immediately; skip it — open() already ran reconcile.
        interval.tick().await;
        loop {
            interval.tick().await;
            let n = Arc::clone(&node_for_sweep);
            let _ = tokio::task::spawn_blocking(move || {
                let _ = n.sweep(wires_net::unix_now_ms());
            })
            .await;
        }
    }))
} else {
    None
};
```

Update the struct literal in `Ok(Self { ... })` to include `sweep_task`.

Add a test helper and a `Drop` impl right after the `impl NodeRuntime { ... }` block:

```rust
#[cfg(test)]
impl NodeRuntime {
    pub fn has_sweep_task(&self) -> bool {
        self.sweep_task.is_some()
    }
}

impl Drop for NodeRuntime {
    fn drop(&mut self) {
        if let Some(h) = self.sweep_task.take() {
            h.abort();
        }
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p wires-node`
Expected: all tests pass, including the two new ones.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-node/src/runtime.rs
git commit -m "wires-node: NodeRuntime spawns 60s sweep task when retention is enabled"
```

---

### Task 10: wires-mcp — `GatewayConfig` gains `[retention]` section

**Files:**
- Modify: `crates/wires-mcp/src/config.rs`
- Modify: `crates/wires-mcp/src/error.rs` (new variant for invalid retention config)
- Modify: `crates/wires-mcp/Cargo.toml` (already depends on wires-node — verify only)

- [ ] **Step 1: Write the failing tests**

Append to `#[cfg(test)] mod tests` in `crates/wires-mcp/src/config.rs`:

```rust
#[test]
fn retention_defaults_apply_when_section_absent() {
    let s = r#"
        public_url = "https://mcp.example.com"
        bind = "127.0.0.1:3000"
        data_dir = "/srv/wires-mcp"
    "#;
    let cfg: GatewayConfig = toml::from_str(s).unwrap();
    let policy = cfg.retention_policy().unwrap();
    assert_eq!(policy.ttl, std::time::Duration::from_secs(3600));
    assert_eq!(policy.max_bytes_per_user, 52_428_800);
}

#[test]
fn retention_section_parses_both_fields() {
    let s = r#"
        public_url = "https://mcp.example.com"
        bind = "127.0.0.1:3000"
        data_dir = "/srv/wires-mcp"

        [retention]
        ttl_secs = 120
        max_bytes_per_user = 1024
    "#;
    let cfg: GatewayConfig = toml::from_str(s).unwrap();
    let policy = cfg.retention_policy().unwrap();
    assert_eq!(policy.ttl, std::time::Duration::from_secs(120));
    assert_eq!(policy.max_bytes_per_user, 1024);
}

#[test]
fn retention_max_bytes_zero_disables_budget_but_keeps_ttl() {
    let s = r#"
        public_url = "https://mcp.example.com"
        bind = "127.0.0.1:3000"
        data_dir = "/srv/wires-mcp"

        [retention]
        ttl_secs = 60
        max_bytes_per_user = 0
    "#;
    let cfg: GatewayConfig = toml::from_str(s).unwrap();
    let policy = cfg.retention_policy().unwrap();
    assert_eq!(policy.ttl, std::time::Duration::from_secs(60));
    assert_eq!(policy.max_bytes_per_user, 0);
}

#[test]
fn retention_ttl_zero_is_rejected() {
    let s = r#"
        public_url = "https://mcp.example.com"
        bind = "127.0.0.1:3000"
        data_dir = "/srv/wires-mcp"

        [retention]
        ttl_secs = 0
        max_bytes_per_user = 1024
    "#;
    let cfg: GatewayConfig = toml::from_str(s).unwrap();
    let err = cfg.retention_policy().err().expect("must reject ttl_secs = 0");
    assert!(matches!(err, crate::error::GatewayError::InvalidRetention { .. }));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p wires-mcp config::tests::retention_`
Expected: FAIL with "no method named `retention_policy`".

- [ ] **Step 3: Add the `InvalidRetention` error variant**

In `crates/wires-mcp/src/error.rs`, append (before the closing `}` of the enum):

```rust
#[snafu(display("Invalid [retention] config: {detail}, at {location}"))]
InvalidRetention {
    detail: String,
    #[snafu(implicit)]
    location: Location,
},
```

- [ ] **Step 4: Add the config types and `retention_policy()` method**

Replace the contents of `crates/wires-mcp/src/config.rs` (preserving existing items) with:

```rust
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use wires_node::RetentionPolicy;

use crate::error::{InvalidRetentionSnafu, Result};

const DEFAULT_TTL_SECS: u64 = 3600;
const DEFAULT_MAX_BYTES_PER_USER: u64 = 52_428_800; // 50 MiB

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub public_url: String,
    pub bind: String,
    pub data_dir: PathBuf,
    /// Per-user retention. Defaults apply when the `[retention]` section is
    /// absent (1 h TTL, 50 MiB byte budget).
    #[serde(default)]
    pub retention: Option<RetentionConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// TTL after which a stored message becomes eligible for eviction.
    /// Must be > 0.
    pub ttl_secs: u64,
    /// Byte budget across all of this user's topics. 0 = no budget cap.
    pub max_bytes_per_user: u64,
}

impl GatewayConfig {
    pub fn token_signing_path(&self) -> PathBuf {
        self.data_dir.join("token_signing.ed25519")
    }
    pub fn gateway_db_path(&self) -> PathBuf {
        self.data_dir.join("gateway.redb")
    }
    pub fn users_dir(&self) -> PathBuf {
        self.data_dir.join("users")
    }
    pub fn pending_pairs_dir(&self) -> PathBuf {
        self.data_dir.join("pending_pairs")
    }

    /// Resolve the effective `RetentionPolicy`: either the operator-supplied
    /// `[retention]` section (validated) or the workspace defaults.
    pub fn retention_policy(&self) -> Result<RetentionPolicy> {
        match &self.retention {
            None => Ok(RetentionPolicy {
                ttl: Duration::from_secs(DEFAULT_TTL_SECS),
                max_bytes_per_user: DEFAULT_MAX_BYTES_PER_USER,
            }),
            Some(c) => {
                if c.ttl_secs == 0 {
                    return InvalidRetentionSnafu {
                        detail: "ttl_secs must be > 0".to_string(),
                    }
                    .fail();
                }
                Ok(RetentionPolicy {
                    ttl: Duration::from_secs(c.ttl_secs),
                    max_bytes_per_user: c.max_bytes_per_user,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn paths_compose_from_data_dir() {
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:3000".into(),
            data_dir: PathBuf::from("/tmp/wires-mcp"),
            retention: None,
        };
        assert_eq!(cfg.token_signing_path(), Path::new("/tmp/wires-mcp/token_signing.ed25519"));
        assert_eq!(cfg.gateway_db_path(), Path::new("/tmp/wires-mcp/gateway.redb"));
        assert_eq!(cfg.users_dir(), Path::new("/tmp/wires-mcp/users"));
        assert_eq!(cfg.pending_pairs_dir(), Path::new("/tmp/wires-mcp/pending_pairs"));
    }

    #[test]
    fn toml_roundtrip() {
        let cfg = GatewayConfig {
            public_url: "https://mcp.example.com".into(),
            bind: "127.0.0.1:3000".into(),
            data_dir: PathBuf::from("/srv/wires-mcp"),
            retention: None,
        };
        let s = toml::to_string_pretty(&cfg).unwrap();
        let back: GatewayConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.public_url, cfg.public_url);
        assert_eq!(back.bind, cfg.bind);
        assert_eq!(back.data_dir, cfg.data_dir);
    }

    // (Tests added in Step 1 sit below.)
}
```

Append the four tests written in Step 1 to the `mod tests` block above (after `toml_roundtrip`).

- [ ] **Step 5: Fix any `GatewayConfig { ... }` struct literals in tests / examples**

Compile and chase the missing-field errors:

Run: `cargo build -p wires-mcp`

Likely sites (verify with `rg 'GatewayConfig \{' crates/`):
- `crates/wires-mcp/tests/end_to_end.rs`
- `crates/wires-mcp/src/pair_bridge.rs` (tests)
- `crates/wires-mcp/src/mcp/tools.rs` (tests)
- Anywhere `wires-mcp` is constructed in admin/tests/etc.

Each gets `retention: None,` added.

- [ ] **Step 6: Run tests**

Run: `cargo test -p wires-mcp config::tests::retention_`
Expected: PASS.

Run: `cargo test -p wires-mcp`
Expected: all existing tests still pass.

- [ ] **Step 7: Commit**

```bash
git add crates/wires-mcp/src/config.rs crates/wires-mcp/src/error.rs crates/wires-mcp/tests/end_to_end.rs \
        crates/wires-mcp/src/pair_bridge.rs crates/wires-mcp/src/mcp/tools.rs
git commit -m "wires-mcp: GatewayConfig.retention with defaults + ttl_secs > 0 validation"
```

(Adjust the file list based on what `cargo build` surfaces.)

---

### Task 11: wires-mcp — `TenantSupervisor` injects the retention policy

**Files:**
- Modify: `crates/wires-mcp/src/tenants.rs`
- Modify: `crates/wires-mcp/src/main.rs` (pass the resolved policy into `TenantSupervisor::new`)
- Modify: callers of `TenantSupervisor::new` in tests (`crates/wires-mcp/tests/end_to_end.rs`, etc.)

- [ ] **Step 1: Write the failing test**

Append to `#[cfg(test)] mod tests` in `crates/wires-mcp/src/tenants.rs`:

```rust
#[tokio::test]
async fn supervisor_injects_retention_into_per_user_runtime() {
    use std::time::Duration;
    let tmp = TempDir::new().unwrap();
    let users = tmp.path().join("users");
    std::fs::create_dir_all(&users).unwrap();
    let sub = "ab".repeat(32);
    let dir = users.join(&sub);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = NodeConfig {
        data_dir: dir.clone(),
        root_pubkey_hex: sub.clone(),
        host: None,
        retention: None, // per-user config.toml does not set retention
    };
    std::fs::write(dir.join("config.toml"), toml::to_string_pretty(&cfg).unwrap()).unwrap();
    std::fs::write(dir.join("iroh.secret"), [5u8; 32]).unwrap();

    let policy = wires_node::RetentionPolicy {
        ttl: Duration::from_secs(60),
        max_bytes_per_user: 1024,
    };
    let sup = TenantSupervisor::new(users.clone(), Duration::from_secs(60), Some(policy.clone()));
    let rt = sup.get_or_open(&sub).await.unwrap();
    assert!(
        rt.node.ingest_index.is_some(),
        "supervisor must inject retention so the user's Node opens an IngestIndex"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p wires-mcp supervisor_injects_retention_into_per_user_runtime`
Expected: FAIL with "wrong number of arguments to `new`".

- [ ] **Step 3: Extend `TenantSupervisor`**

In `crates/wires-mcp/src/tenants.rs`, add a field and constructor arg. Update the struct:

```rust
#[derive(Clone)]
pub struct TenantSupervisor {
    inner: Arc<tokio::sync::Mutex<Inner>>,
    users_dir: PathBuf,
    idle_ttl: Duration,
    retention: Option<wires_node::RetentionPolicy>,
}
```

Update `new`:

```rust
pub fn new(
    users_dir: PathBuf,
    idle_ttl: Duration,
    retention: Option<wires_node::RetentionPolicy>,
) -> Self {
    Self {
        inner: Arc::new(tokio::sync::Mutex::new(Inner {
            runtimes: HashMap::new(),
        })),
        users_dir,
        idle_ttl,
        retention,
    }
}
```

In `get_or_open`, after the per-user `cfg.data_dir = dir.clone();` line, add:

```rust
cfg.retention = self.retention.clone();
```

- [ ] **Step 4: Wire the policy through `main.rs`**

In `crates/wires-mcp/src/main.rs`, between the `cfg` load and the `wires_mcp::tenants::TenantSupervisor::new(...)` call, resolve the policy:

```rust
let retention_policy = match cfg.retention_policy() {
    Ok(p) => p,
    Err(e) => {
        eprintln!("config: {e}");
        return std::process::ExitCode::FAILURE;
    }
};
```

And update the `TenantSupervisor::new(...)` call:

```rust
let supervisor = wires_mcp::tenants::TenantSupervisor::new(
    cfg.users_dir(),
    std::time::Duration::from_secs(600),
    Some(retention_policy),
);
```

- [ ] **Step 5: Fix existing test callers of `TenantSupervisor::new`**

Every existing call site in this crate currently passes two args; chase compile errors. Sites (verify with `rg 'TenantSupervisor::new' crates/`):

- `crates/wires-mcp/src/tenants.rs` (the existing tests inside this file): pass `None` as the third arg.
- `crates/wires-mcp/tests/end_to_end.rs`: pass `None`.
- `crates/wires-mcp/src/pair_bridge.rs` (tests): pass `None`.

- [ ] **Step 6: Run tests**

Run: `cargo test -p wires-mcp`
Expected: all pass, including the new `supervisor_injects_retention_into_per_user_runtime`.

- [ ] **Step 7: Commit**

```bash
git add crates/wires-mcp/src/tenants.rs crates/wires-mcp/src/main.rs \
        crates/wires-mcp/tests/end_to_end.rs crates/wires-mcp/src/pair_bridge.rs
git commit -m "wires-mcp: TenantSupervisor injects retention policy into per-user NodeConfig"
```

---

### Task 12: wires-mcp — end-to-end retention test through the supervisor

**Files:**
- Modify: `crates/wires-mcp/src/tenants.rs` (additional integration test)

- [ ] **Step 1: Write the failing test**

Append to `#[cfg(test)] mod tests` in `crates/wires-mcp/src/tenants.rs`:

```rust
#[tokio::test]
async fn supervisor_retention_evicts_expired_user_messages() {
    use std::time::Duration;
    let tmp = TempDir::new().unwrap();
    let users = tmp.path().join("users");
    std::fs::create_dir_all(&users).unwrap();
    let sub = "cd".repeat(32);
    let dir = users.join(&sub);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = NodeConfig {
        data_dir: dir.clone(),
        root_pubkey_hex: sub.clone(),
        host: None,
        retention: None,
    };
    std::fs::write(dir.join("config.toml"), toml::to_string_pretty(&cfg).unwrap()).unwrap();
    std::fs::write(dir.join("iroh.secret"), [3u8; 32]).unwrap();

    // Tight TTL so we can sleep past it within the test.
    let policy = wires_node::RetentionPolicy {
        ttl: Duration::from_millis(50),
        max_bytes_per_user: 0,
    };
    let sup = TenantSupervisor::new(users.clone(), Duration::from_secs(60), Some(policy));
    let rt = sup.get_or_open(&sub).await.unwrap();
    let node = rt.node.clone();

    // Plant a row directly into the IngestIndex and the per-topic log.
    let topic = [42u8; 32];
    let sender = [9u8; 32];
    let log = node.logs.get_or_open(&topic).unwrap();
    let msg = wires_core::WireMessage {
        topic_id: topic,
        epoch: 0,
        kind: wires_core::MessageKind::Public,
        sender,
        cap_id: [0u8; 16],
        seq: 0,
        prev_hash: [0u8; 32],
        timestamp: 0,
        payload_len: 0,
        signature: [0u8; 64],
        ciphertext: vec![],
    };
    log.append(&msg).unwrap();
    let bytes = serde_json::to_vec(&msg).unwrap().len() as u32;
    let ix = node.ingest_index.as_ref().unwrap();
    ix.record(
        &wires_store::IngestEntry {
            topic_id: topic,
            sender,
            seq: 0,
            bytes,
            ingested_at_ms: wires_net::unix_now_ms(),
        },
        wires_net::unix_now_ms(),
    )
    .unwrap();

    // Sleep past TTL, then trigger the sweep.
    tokio::time::sleep(Duration::from_millis(80)).await;
    node.sweep(wires_net::unix_now_ms()).unwrap();

    assert_eq!(ix.total_bytes().unwrap(), 0);
    assert!(log.read_after(&sender, None, 10).unwrap().is_empty());
}
```

No new dependencies are required: `wires-mcp` already declares `wires-core`, `wires-store`, `wires-net`, and `wires-node` as regular `[dependencies]` (verify with `cat crates/wires-mcp/Cargo.toml`), so the fully-qualified paths used in the test (`wires_core::WireMessage`, `wires_store::IngestEntry`, `wires_net::unix_now_ms`) resolve directly.

- [ ] **Step 2: Run tests**

Run: `cargo test -p wires-mcp supervisor_retention_evicts_expired_user_messages`
Expected: PASS.

Run: `cargo test -p wires-mcp`
Expected: all tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-mcp/src/tenants.rs
git commit -m "wires-mcp: end-to-end test — TenantSupervisor enforces retention TTL"
```

---

### Task 13: docker — example config shows `[retention]` block

**Files:**
- Modify: `docker/wires-mcp.toml.example`

- [ ] **Step 1: Add the retention block**

Append to `docker/wires-mcp.toml.example`:

```
# Per-user retention policy. Defaults (ttl_secs = 3600, max_bytes_per_user
# = 52428800 = 50 MiB) apply if this block is omitted. `ttl_secs` must be
# > 0; `max_bytes_per_user = 0` disables the byte budget (TTL alone enforces).
#[retention]
#ttl_secs = 3600
#max_bytes_per_user = 52428800
```

- [ ] **Step 2: Commit**

```bash
git add docker/wires-mcp.toml.example
git commit -m "docker: document wires-mcp [retention] config block"
```

---

### Task 14: Full workspace verification + push to main

- [ ] **Step 1: Workspace build + tests**

Run: `cargo build --workspace`
Expected: clean build.

Run: `cargo test --workspace`
Expected: all tests pass. Take note of any new orange/yellow warnings — if they're from this work, fix them before pushing.

- [ ] **Step 2: Final git status**

Run: `git status`
Expected: clean working tree (everything committed).

Run: `git log --oneline origin/main..HEAD`
Expected: 13 commits (one per task above; some operators may have squashed sub-commits).

- [ ] **Step 3: Push**

The user has authorized direct pushes to main for this work. The auto-mode classifier may attempt to block — confirm only one push attempt; if it's rejected for a reason not related to authorization (CI failure, divergent remote), surface that to the user rather than retrying.

Run: `git push origin main`
Expected: success — branch advances on the remote.

---

## Self-review notes (writer)

- Spec coverage:
  - §"Storage schema change" → Tasks 1, 2, 3
  - §"`RetentionPolicy` and `NodeConfig` wiring" → Task 4
  - §"Eviction" + triggers → Tasks 5, 6, 7, 9
  - §"Ordering and crash safety" / §"Backfill" → Task 8 (single reconciliation routine, idempotent on every open, sets the flag on first run)
  - §"wires-mcp config" → Tasks 10, 13
  - §"Affected crates" — wires-store ✓ (1–3), wires-host ✓ (1, step 7), wires-node ✓ (4–9), wires-mcp ✓ (10–12), wires-cli + wires-ha ✓ (struct-literal updates in task 4 — behavior unchanged).
  - §"Testing" — every bullet has a corresponding test in tasks 1, 2, 6, 7, 8, 9, 10, 12.

- `now_ms()` home — picked `wires_net::unix_now_ms` (already exists, `SystemTime`-backed, used workspace-wide). No new helper added.

- Crash-safety ordering (`IngestIndex` remove before `TopicLog` delete) is preserved by `Node::sweep`: `evict_*` commits the index removal inside a redb txn, then the loop runs `TopicLog::delete` per dropped entry. `reconcile_ingest_index` covers the failure window.

- `retention.is_some()` ⇔ `ingest_index.is_some()` is enforced at `Node::open` construction and treated as an invariant by `sweep` / `record_and_sweep` (both check both).

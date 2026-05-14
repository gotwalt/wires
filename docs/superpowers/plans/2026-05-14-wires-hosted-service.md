# Wires Hosted Multi-Tenant Service — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `wires-host` from a self-hosted single-tenant appliance into a multi-tenant service that authenticated iOS apps can onboard against. Add a tenant-control ALPN, per-tenant rolling-retention storage, a new invite-token shape, and an HTTPS service-discovery endpoint — all while preserving the host's blindness contract.

**Architecture:** Bottom-up by crate. `wires-store` gains FIFO eviction primitives. `wires-net` adds a new ALPN (`/wires/tenant/0`) with request/response types, a `TenantClient`, and a `TenantProtocol` server-side handler; `InviteToken` is replaced outright. `wires-host` becomes a `lib + bin` crate housing a `TenantRegistry`, per-tenant storage, retention, routing, and an HTTPS discovery surface. Integration and acceptance tests live in `crates/wires-host/tests/`.

**Tech Stack:** Rust 2024, stable toolchain; iroh 0.98, iroh-gossip 0.98; redb 4; ed25519-dalek 2 + `rand_core::OsRng`; serde + serde_json; snafu; tokio; axum 0.8 (new).

**Spec:** [`docs/superpowers/specs/2026-05-14-wires-hosted-service-design.md`](../specs/2026-05-14-wires-hosted-service-design.md)

---

## File structure

```
crates/wires-store/src/
  topic_log.rs              # Modify: add delete, bytes_stored
  ingest_index.rs           # NEW: per-tenant FIFO eviction index
  schema.rs                 # Modify: add INGEST_INDEX, INGEST_META, TENANTS, TOPIC_INDEX, NONCES tables
  db.rs                     # Modify: add open helpers for new dbs
  lib.rs                    # Modify: re-export new items

crates/wires-net/src/
  framing.rs                # NEW: shared length-prefixed JSON helpers
  invite.rs                 # Rewrite: new InviteToken
  tenant.rs                 # NEW: ALPN, types, TenantClient, TenantProtocol, TenantHandler
  replay.rs                 # Modify: use framing.rs (optional, keep existing helpers if simpler)
  error.rs                  # Modify: add tenant error variants
  lib.rs                    # Modify: re-export tenant items

crates/wires-host/
  Cargo.toml                # Modify: add [lib], add axum, add wires-store features as needed
  src/lib.rs                # NEW: module root for testable code
  src/main.rs               # Rewrite: thin entry
  src/tenant_registry.rs    # NEW: tenants/topic_index/nonces tables + TenantHandler impl
  src/retention.rs          # NEW: per-tenant ingest index + eviction
  src/per_tenant_logs.rs    # NEW: tenant-scoped TopicLogs wrapper
  src/routing.rs            # NEW: inbound envelope dispatch
  src/http_discovery.rs     # NEW: axum service for /v1/bootstrap
  src/error.rs              # NEW: HostError variants

crates/wires-host/tests/
  tenant_register.rs        # NEW
  two_tenants_isolated.rs   # NEW
  retention_eviction.rs     # NEW
  rate_limit.rs             # NEW
  acceptance.rs             # NEW (`#[ignore]`)
```

---

## Phase 1: `wires-store` — eviction primitives

### Task 1: `TopicLog::bytes_stored`

**Files:**
- Modify: `crates/wires-store/src/topic_log.rs`

- [ ] **Step 1: Add failing test**

Append the following test to the `tests` module at the bottom of `crates/wires-store/src/topic_log.rs`:

```rust
#[test]
fn bytes_stored_sums_value_lengths() {
    let tmp = TempDir::new().unwrap();
    let db = Arc::new(open_topic_log(tmp.path(), "abc").unwrap());
    let log = TopicLog::new(db);
    let sender = [7u8; 32];
    let m0 = make(sender, 0, [0u8; 32]);
    let m1 = make(sender, 1, m0.message_hash().unwrap());
    log.append(&m0).unwrap();
    log.append(&m1).unwrap();
    let b = log.bytes_stored().unwrap();
    let expected = serde_json::to_vec(&m0).unwrap().len() + serde_json::to_vec(&m1).unwrap().len();
    assert_eq!(b as usize, expected);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p wires-store topic_log::tests::bytes_stored_sums_value_lengths`
Expected: FAIL — method `bytes_stored` not found on `TopicLog`.

- [ ] **Step 3: Implement `bytes_stored`**

In `crates/wires-store/src/topic_log.rs`, add this method on `impl TopicLog` (after `hwm`):

```rust
/// Total stored byte size across all entries in this topic's log.
pub fn bytes_stored(&self) -> Result<u64> {
    let read = self.db.begin_read().context(BeginTxnSnafu)?;
    let table = read.open_table(TOPIC_LOG).context(OpenTableSnafu)?;
    let mut total: u64 = 0;
    for entry in table.iter().context(StorageIoSnafu)? {
        let (_k, v) = entry.context(StorageIoSnafu)?;
        total = total.saturating_add(v.value().len() as u64);
    }
    Ok(total)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p wires-store topic_log::tests::bytes_stored_sums_value_lengths`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-store/src/topic_log.rs
git commit -m "wires-store: add TopicLog::bytes_stored"
```

---

### Task 2: `TopicLog::delete`

**Files:**
- Modify: `crates/wires-store/src/topic_log.rs`

- [ ] **Step 1: Add failing test**

Append to `crates/wires-store/src/topic_log.rs` `tests` module:

```rust
#[test]
fn delete_removes_entry_and_returns_bytes() {
    let tmp = TempDir::new().unwrap();
    let db = Arc::new(open_topic_log(tmp.path(), "abc").unwrap());
    let log = TopicLog::new(db);
    let sender = [7u8; 32];
    let m0 = make(sender, 0, [0u8; 32]);
    let m1 = make(sender, 1, m0.message_hash().unwrap());
    log.append(&m0).unwrap();
    log.append(&m1).unwrap();
    let m0_bytes = serde_json::to_vec(&m0).unwrap().len() as u64;

    let removed = log.delete(&sender, 0).unwrap();
    assert_eq!(removed, m0_bytes);

    let got = log.read_after(&sender, None, 10).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].seq, 1);
}

#[test]
fn delete_missing_returns_zero() {
    let tmp = TempDir::new().unwrap();
    let db = Arc::new(open_topic_log(tmp.path(), "abc").unwrap());
    let log = TopicLog::new(db);
    let removed = log.delete(&[9u8; 32], 42).unwrap();
    assert_eq!(removed, 0);
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test -p wires-store topic_log::tests::delete_`
Expected: FAIL — method `delete` not found.

- [ ] **Step 3: Implement `delete`**

In `crates/wires-store/src/topic_log.rs`, add (after `bytes_stored`):

```rust
/// Remove the entry for `(sender, seq)`. Returns the byte size of the removed
/// value, or 0 if no entry existed. Does **not** touch the HWM table — eviction
/// is intentionally invisible to the chain-tracking layer (the chain still
/// reads correctly for the surviving suffix; the prefix is simply gone).
pub fn delete(&self, sender: &Pubkey, seq: u64) -> Result<u64> {
    let key = log_key(sender, seq);
    let write = self.db.begin_write().context(BeginTxnSnafu)?;
    let removed_bytes = {
        let mut table = write.open_table(TOPIC_LOG).context(OpenTableSnafu)?;
        let prior = table.remove(&key[..]).context(StorageIoSnafu)?;
        prior.map(|g| g.value().len() as u64).unwrap_or(0)
    };
    write.commit().context(CommitTxnSnafu)?;
    Ok(removed_bytes)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p wires-store topic_log::tests::delete_`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add crates/wires-store/src/topic_log.rs
git commit -m "wires-store: add TopicLog::delete for eviction"
```

---

### Task 3: `IngestIndex` schema and table defs

**Files:**
- Modify: `crates/wires-store/src/schema.rs`
- Modify: `crates/wires-store/src/db.rs`

- [ ] **Step 1: Add tables to schema**

Read the current `crates/wires-store/src/schema.rs` to confirm the existing constant style. Then add at the bottom:

```rust
/// Per-tenant FIFO index over ingested messages. Key = u64 BE ingest_seq.
/// Value = 32 (topic_id) || 32 (sender) || 8 (seq BE) || 4 (bytes BE) = 76 bytes.
pub const INGEST_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("ingest_index");

/// Single-entry table holding (next_ingest_seq u64 BE) || (total_bytes u64 BE) = 16 bytes.
/// Keyed by a fixed marker byte (b"m"). Stored separately to make total-bytes
/// reads/writes cheap.
pub const INGEST_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("ingest_meta");
```

- [ ] **Step 2: Add `open_ingest_index` helper**

Read the current `crates/wires-store/src/db.rs` to match style. Then add this function next to `open_topic_log`:

```rust
/// Open the per-tenant ingest index db at `<root>/ingest_<tenant_hex>.redb`.
pub fn open_ingest_index(root: &Path, tenant_hex: &str) -> Result<Database> {
    if let Some(parent) = root.to_path_buf().parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::create_dir_all(root).context(StorageIoSnafu)?;
    let path = root.join(format!("ingest_{tenant_hex}.redb"));
    Database::create(path).context(DbOpenSnafu)
}
```

(Match the surrounding error-context style — use the same Snafu context types that `open_topic_log` uses. If `DbOpenSnafu` doesn't exist, use whatever Snafu context `open_topic_log` wraps redb open errors with.)

- [ ] **Step 3: Verify it compiles**

Run: `cargo build -p wires-store`
Expected: success.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-store/src/schema.rs crates/wires-store/src/db.rs
git commit -m "wires-store: add INGEST_INDEX + INGEST_META schema + open_ingest_index"
```

---

### Task 4: `IngestIndex` struct and `record`

**Files:**
- Create: `crates/wires-store/src/ingest_index.rs`
- Modify: `crates/wires-store/src/lib.rs`

- [ ] **Step 1: Add module declaration + re-export**

In `crates/wires-store/src/lib.rs`, add:

```rust
pub mod ingest_index;
pub use ingest_index::{IngestEntry, IngestIndex};
```

- [ ] **Step 2: Create the file with failing tests first**

Create `crates/wires-store/src/ingest_index.rs` with:

```rust
use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable};
use snafu::ResultExt;

use crate::error::{
    BeginTxnSnafu, CommitTxnSnafu, OpenTableSnafu, Result, StorageIoSnafu,
};
use crate::schema::{INGEST_INDEX, INGEST_META};

const META_KEY: &[u8] = b"m";

/// A single entry in the per-tenant ingest order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestEntry {
    pub topic_id: [u8; 32],
    pub sender: [u8; 32],
    pub seq: u64,
    pub bytes: u32,
}

pub struct IngestIndex {
    db: Arc<Database>,
}

impl IngestIndex {
    pub fn new(db: Arc<Database>) -> Self { Self { db } }

    /// Record an ingested message. Returns the assigned ingest_seq.
    pub fn record(&self, entry: &IngestEntry) -> Result<u64> {
        let write = self.db.begin_write().context(BeginTxnSnafu)?;
        let assigned = {
            let mut meta_t = write.open_table(INGEST_META).context(OpenTableSnafu)?;
            let (next_ingest, total_bytes) = read_meta(&meta_t)?;

            let mut value = [0u8; 76];
            value[0..32].copy_from_slice(&entry.topic_id);
            value[32..64].copy_from_slice(&entry.sender);
            value[64..72].copy_from_slice(&entry.seq.to_be_bytes());
            value[72..76].copy_from_slice(&entry.bytes.to_be_bytes());

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

    /// Sum of `bytes` across all currently-stored entries.
    pub fn total_bytes(&self) -> Result<u64> {
        let read = self.db.begin_read().context(BeginTxnSnafu)?;
        let table = read.open_table(INGEST_META).context(OpenTableSnafu)?;
        let (_next, total) = read_meta(&table)?;
        Ok(total)
    }
}

fn read_meta<T: ReadableTable<&'static [u8], &'static [u8]>>(table: &T) -> Result<(u64, u64)> {
    match table.get(META_KEY).context(StorageIoSnafu)? {
        Some(g) => {
            let raw = g.value();
            if raw.len() < 16 {
                return Ok((0, 0));
            }
            let mut a = [0u8; 8]; a.copy_from_slice(&raw[..8]);
            let mut b = [0u8; 8]; b.copy_from_slice(&raw[8..16]);
            Ok((u64::from_be_bytes(a), u64::from_be_bytes(b)))
        }
        None => Ok((0, 0)),
    }
}

fn write_meta(
    table: &mut redb::Table<&[u8], &[u8]>,
    next_ingest: u64,
    total_bytes: u64,
) -> Result<()> {
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&next_ingest.to_be_bytes());
    buf[8..].copy_from_slice(&total_bytes.to_be_bytes());
    table.insert(META_KEY, &buf[..]).context(StorageIoSnafu)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_ingest_index;
    use tempfile::TempDir;

    fn entry(topic: u8, sender: u8, seq: u64, bytes: u32) -> IngestEntry {
        IngestEntry {
            topic_id: [topic; 32],
            sender: [sender; 32],
            seq,
            bytes,
        }
    }

    #[test]
    fn record_assigns_monotonic_ingest_seq() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
        let idx = IngestIndex::new(db);
        let a = idx.record(&entry(1, 9, 0, 100)).unwrap();
        let b = idx.record(&entry(1, 9, 1, 200)).unwrap();
        let c = idx.record(&entry(2, 8, 0, 50)).unwrap();
        assert_eq!(a, 0);
        assert_eq!(b, 1);
        assert_eq!(c, 2);
        assert_eq!(idx.total_bytes().unwrap(), 350);
    }
}
```

- [ ] **Step 3: Run the test to verify it fails or compiles to first failure**

Run: `cargo test -p wires-store ingest_index::tests::record_assigns_monotonic_ingest_seq`
Expected: PASS (this task implements both test and code together because the type doesn't exist yet — there is no "pre-implementation" state to fail against).

If the test fails for unrelated reasons (e.g. Snafu context name mismatch), fix the Snafu context import lines until it passes.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-store/src/ingest_index.rs crates/wires-store/src/lib.rs
git commit -m "wires-store: add IngestIndex with record + total_bytes"
```

---

### Task 5: `IngestIndex::evict_oldest_until`

**Files:**
- Modify: `crates/wires-store/src/ingest_index.rs`

- [ ] **Step 1: Add failing test**

Append to the `tests` module in `crates/wires-store/src/ingest_index.rs`:

```rust
#[test]
fn evict_oldest_until_returns_dropped_in_order() {
    let tmp = TempDir::new().unwrap();
    let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
    let idx = IngestIndex::new(db);
    idx.record(&entry(1, 9, 0, 100)).unwrap();
    idx.record(&entry(1, 9, 1, 200)).unwrap();
    idx.record(&entry(2, 8, 0, 50)).unwrap();
    idx.record(&entry(2, 8, 1, 75)).unwrap();
    // Total = 425. Evict until ≤ 200.
    let dropped = idx.evict_oldest_until(200).unwrap();
    assert_eq!(dropped.len(), 3); // oldest 100 + 200 + 50, leaving 75
    assert_eq!(dropped[0].seq, 0);
    assert_eq!(dropped[0].topic_id, [1u8; 32]);
    assert_eq!(dropped[1].seq, 1);
    assert_eq!(dropped[2].topic_id, [2u8; 32]);
    assert_eq!(idx.total_bytes().unwrap(), 75);
}

#[test]
fn evict_oldest_until_noop_when_under_budget() {
    let tmp = TempDir::new().unwrap();
    let db = Arc::new(open_ingest_index(tmp.path(), "aa").unwrap());
    let idx = IngestIndex::new(db);
    idx.record(&entry(1, 9, 0, 100)).unwrap();
    let dropped = idx.evict_oldest_until(1000).unwrap();
    assert!(dropped.is_empty());
    assert_eq!(idx.total_bytes().unwrap(), 100);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p wires-store ingest_index::tests::evict_oldest_until`
Expected: FAIL — method not found.

- [ ] **Step 3: Implement**

In `crates/wires-store/src/ingest_index.rs`, add to `impl IngestIndex`:

```rust
/// Evict the oldest entries until `total_bytes() ≤ budget_bytes`. Returns the
/// dropped entries in ingest order (oldest first).
pub fn evict_oldest_until(&self, budget_bytes: u64) -> Result<Vec<IngestEntry>> {
    let write = self.db.begin_write().context(BeginTxnSnafu)?;
    let mut dropped = Vec::new();
    {
        let mut meta_t = write.open_table(INGEST_META).context(OpenTableSnafu)?;
        let (next_ingest, mut total) = read_meta(&meta_t)?;
        if total <= budget_bytes {
            write.commit().context(CommitTxnSnafu)?;
            return Ok(dropped);
        }

        let mut idx_t = write.open_table(INGEST_INDEX).context(OpenTableSnafu)?;

        // Collect keys to remove in order; we cannot mutate while iterating.
        let mut victim_keys: Vec<[u8; 8]> = Vec::new();
        let mut victim_entries: Vec<IngestEntry> = Vec::new();
        for entry_r in idx_t.iter().context(StorageIoSnafu)? {
            let (k, v) = entry_r.context(StorageIoSnafu)?;
            if total <= budget_bytes { break; }
            let mut kbuf = [0u8; 8];
            kbuf.copy_from_slice(k.value());
            let raw = v.value();
            if raw.len() < 76 { continue; }
            let mut topic_id = [0u8; 32]; topic_id.copy_from_slice(&raw[0..32]);
            let mut sender = [0u8; 32]; sender.copy_from_slice(&raw[32..64]);
            let mut sb = [0u8; 8]; sb.copy_from_slice(&raw[64..72]);
            let mut bb = [0u8; 4]; bb.copy_from_slice(&raw[72..76]);
            let bytes = u32::from_be_bytes(bb);
            let ent = IngestEntry {
                topic_id, sender,
                seq: u64::from_be_bytes(sb),
                bytes,
            };
            total = total.saturating_sub(bytes as u64);
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

- [ ] **Step 4: Run tests**

Run: `cargo test -p wires-store ingest_index::tests::evict_oldest_until`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add crates/wires-store/src/ingest_index.rs
git commit -m "wires-store: add IngestIndex::evict_oldest_until"
```

---

## Phase 2: `wires-net` — invite, tenant types, transport

### Task 6: Replace `InviteToken` with new shape

**Files:**
- Modify: `crates/wires-net/src/invite.rs`

- [ ] **Step 1: Replace the struct definition and tests**

Open `crates/wires-net/src/invite.rs`. Replace the struct and its tests so the whole file matches:

```rust
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use wires_core::Capability;

use crate::error::{Result, SerdeSnafu};

/// One-shot invite token bundling a signed capability and one-or-more peer
/// hints the recipient can dial to enter the gossip mesh.
///
/// Encoded as URL-safe base64 of canonical JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteToken {
    /// Schema version. Only `1` is currently valid; any other value is rejected
    /// at decode.
    pub version: u8,
    pub cap: Capability,
    /// Ordered list of peers to try. Receivers iterate in order.
    pub peer_hints: Vec<PeerHint>,
    /// Optional HTTPS service-discovery URL the receiver can fetch fresh hints
    /// from if every entry in `peer_hints` fails.
    pub service_discovery_url: Option<String>,
    pub expires: i64,
    /// Single-use token id — receivers SHOULD reject if seen before.
    pub token_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerHint {
    /// Hex of the iroh EndpointId.
    pub node_id: String,
    pub addrs: Vec<String>,
    pub relay: Option<String>,
}

impl InviteToken {
    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self).context(SerdeSnafu)?;
        Ok(base64url_encode(&json))
    }

    pub fn decode(token: &str) -> Result<Self> {
        let bytes = base64url_decode(token).map_err(|_| crate::error::NetError::Serde {
            source: serde_json::from_str::<()>("\"bad base64\"").unwrap_err(),
            location: snafu::location!(),
        })?;
        let tok: InviteToken = serde_json::from_slice(&bytes).context(SerdeSnafu)?;
        if tok.version != 1 {
            return Err(crate::error::NetError::Serde {
                source: serde_json::from_str::<()>("\"unsupported invite-token version\"")
                    .unwrap_err(),
                location: snafu::location!(),
            });
        }
        Ok(tok)
    }
}

// --- base64url (kept verbatim from the prior implementation) --------------

fn base64url_encode(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let chunks = bytes.chunks_exact(3);
    let rem = chunks.remainder().to_vec();
    for chunk in bytes.chunks_exact(3) {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        for i in (0..4).rev() {
            out.push(CHARS[((n >> (6 * i)) & 0x3F) as usize] as char);
        }
    }
    let _ = chunks;
    if !rem.is_empty() {
        let mut buf = [0u8; 3];
        for (i, b) in rem.iter().enumerate() { buf[i] = *b; }
        let n = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
        let chars_to_emit = match rem.len() { 1 => 2, 2 => 3, _ => unreachable!() };
        for i in (4 - chars_to_emit..4).rev() {
            out.push(CHARS[((n >> (6 * i)) & 0x3F) as usize] as char);
        }
    }
    out
}

fn base64url_decode(s: &str) -> std::result::Result<Vec<u8>, ()> {
    fn val(c: u8) -> std::result::Result<u32, ()> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err(()),
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i < bytes.len() {
        let mut got = 0;
        let mut chunk = [0u32; 4];
        for j in 0..4 {
            if i + j >= bytes.len() { break; }
            chunk[j] = val(bytes[i + j])?;
            got += 1;
        }
        if got == 0 { break; }
        let n = (chunk[0] << 18) | (chunk[1] << 12) | (chunk[2] << 6) | chunk[3];
        if got >= 2 { out.push(((n >> 16) & 0xFF) as u8); }
        if got >= 3 { out.push(((n >> 8) & 0xFF) as u8); }
        if got == 4 { out.push((n & 0xFF) as u8); }
        i += 4;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use wires_core::cap::Right;

    fn signed_cap() -> Capability {
        let root = SigningKey::generate(&mut OsRng);
        let mut cap = Capability::new_unsigned(
            [5u8; 32],
            vec!["home.*".into()],
            vec![Right::Read],
            0,
            Some(1_000_000),
        );
        cap.sign(&root).unwrap();
        cap
    }

    #[test]
    fn base64url_roundtrip() {
        let cases: &[&[u8]] = &[b"", b"a", b"ab", b"abc", b"abcd", b"abcde", b"abcdef",
            &[0u8, 255, 128, 1, 2, 3, 4, 5, 6, 7]];
        for input in cases {
            let encoded = base64url_encode(input);
            let back = base64url_decode(&encoded).unwrap();
            assert_eq!(&back, input, "roundtrip failed for {input:?}");
        }
    }

    #[test]
    fn invite_token_roundtrip() {
        let tok = InviteToken {
            version: 1,
            cap: signed_cap(),
            peer_hints: vec![
                PeerHint {
                    node_id: "deadbeef".into(),
                    addrs: vec!["127.0.0.1:11204".into()],
                    relay: None,
                },
                PeerHint {
                    node_id: "feedface".into(),
                    addrs: vec![],
                    relay: Some("https://relay.example/".into()),
                },
            ],
            service_discovery_url: Some("https://discovery.example/v1/bootstrap".into()),
            expires: 1_000_000,
            token_id: "tk-1".into(),
        };
        let encoded = tok.encode().unwrap();
        let back = InviteToken::decode(&encoded).unwrap();
        assert_eq!(back.token_id, "tk-1");
        assert_eq!(back.peer_hints.len(), 2);
        assert_eq!(back.peer_hints[1].relay.as_deref(), Some("https://relay.example/"));
        assert_eq!(back.service_discovery_url.as_deref(),
                   Some("https://discovery.example/v1/bootstrap"));
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let tok = InviteToken {
            version: 99,
            cap: signed_cap(),
            peer_hints: vec![],
            service_discovery_url: None,
            expires: 0,
            token_id: "x".into(),
        };
        let encoded = tok.encode().unwrap();
        assert!(InviteToken::decode(&encoded).is_err());
    }

    #[test]
    fn decode_rejects_invalid_base64() {
        assert!(InviteToken::decode("!!not-base64!!").is_err());
    }
}
```

Also update `crates/wires-net/src/lib.rs` to re-export `PeerHint`:

```rust
pub use invite::{InviteToken, PeerHint};
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p wires-net invite::`
Expected: PASS for all four tests.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-net/src/invite.rs crates/wires-net/src/lib.rs
git commit -m "wires-net: replace InviteToken with peer-hints shape (no v1 compat)"
```

---

### Task 7: Shared length-prefixed JSON framing

**Files:**
- Create: `crates/wires-net/src/framing.rs`
- Modify: `crates/wires-net/src/lib.rs`

- [ ] **Step 1: Create file with helpers**

Create `crates/wires-net/src/framing.rs`:

```rust
//! Length-prefixed JSON framing shared between replay and tenant protocols.
//!
//! Frame: `[u32 BE length][serde_json bytes]`. Length is the number of bytes
//! that follow, capped per-call by the caller.

use iroh::endpoint::{RecvStream, SendStream};
use serde::de::DeserializeOwned;
use serde::Serialize;
use snafu::ResultExt;

use crate::error::{IoSnafu, Result, SerdeSnafu};

pub async fn write_frame<T: Serialize>(send: &mut SendStream, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value).context(SerdeSnafu)?;
    let len = (bytes.len() as u32).to_be_bytes();
    send.write_all(&len).await.map_err(anyhow::Error::from).context(IoSnafu)?;
    send.write_all(&bytes).await.map_err(anyhow::Error::from).context(IoSnafu)?;
    Ok(())
}

pub async fn read_frame<T: DeserializeOwned>(
    recv: &mut RecvStream,
    max_len: u32,
) -> Result<T> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await
        .map_err(anyhow::Error::from).context(IoSnafu)?;
    let len = u32::from_be_bytes(len_buf);
    if len > max_len {
        return Err(crate::error::NetError::Io {
            source: anyhow::anyhow!("frame too large: {len} > {max_len}"),
            location: snafu::location!(),
        });
    }
    let mut buf = vec![0u8; len as usize];
    recv.read_exact(&mut buf).await
        .map_err(anyhow::Error::from).context(IoSnafu)?;
    let value = serde_json::from_slice(&buf).context(SerdeSnafu)?;
    Ok(value)
}
```

In `crates/wires-net/src/lib.rs`, add:

```rust
pub mod framing;
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo build -p wires-net`
Expected: success.

If `NetError::Io` doesn't exist with the structure used above, check `crates/wires-net/src/error.rs` for the existing Io variant and match its shape exactly (the existing `IoSnafu` context type is what the replay protocol uses).

- [ ] **Step 3: Commit**

```bash
git add crates/wires-net/src/framing.rs crates/wires-net/src/lib.rs
git commit -m "wires-net: extract length-prefixed JSON framing helpers"
```

---

### Task 8: `tenant.rs` — ALPN + request/response types

**Files:**
- Create: `crates/wires-net/src/tenant.rs`
- Modify: `crates/wires-net/src/lib.rs`
- Modify: `crates/wires-net/src/error.rs`

- [ ] **Step 1: Add error variants**

In `crates/wires-net/src/error.rs`, add new variants to `NetError` (preserve the existing snafu pattern with `location: Location`):

```rust
#[snafu(display("Tenant register failed: {source}, at {location}"))]
TenantRegisterFailed {
    #[snafu(source(from(anyhow::Error, Some)))]
    source: Option<anyhow::Error>,
    #[snafu(implicit)]
    location: snafu::Location,
},

#[snafu(display("Tenant stream closed unexpectedly, at {location}"))]
TenantStreamClosed {
    #[snafu(implicit)]
    location: snafu::Location,
},

#[snafu(display("Tenant protocol returned a bad response: {message}, at {location}"))]
TenantBadResponse {
    message: String,
    #[snafu(implicit)]
    location: snafu::Location,
},
```

Match the style of nearby variants — if the existing error file uses `#[snafu(source)] source: <ExternalError>` rather than `source(from(...))`, copy that exact pattern instead.

- [ ] **Step 2: Create `tenant.rs` with types**

Create `crates/wires-net/src/tenant.rs`:

```rust
//! Tenant control protocol — ALPN `/wires/tenant/0`.
//!
//! Synchronous request/response over a single QUIC bidi stream:
//!   client writes one length-prefixed JSON `TenantRequest`, closes send side;
//!   server writes one length-prefixed JSON `TenantResponse`, closes send side.

use serde::{Deserialize, Serialize};

pub const ALPN: &[u8] = b"/wires/tenant/0";

/// Max frame size — generous enough for any single request/response in this
/// protocol; tight enough to prevent abuse.
pub const MAX_FRAME_LEN: u32 = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TenantRequest {
    Register(TenantRegisterRequest),
    TopicRegister(TopicRegisterRequest),
    TopicUnregister(TopicUnregisterRequest),
    Status(TenantStatusRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TenantResponse {
    Register(TenantRegisterResponse),
    TopicRegister(TopicRegisterResponse),
    TopicUnregister(TopicUnregisterResponse),
    Status(TenantStatusResponse),
    Error(TenantErrorResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantRegisterRequest {
    pub version: u8,
    #[serde(with = "hex::serde")]
    pub root_pubkey: [u8; 32],
    pub timestamp: i64,
    #[serde(with = "hex::serde")]
    pub nonce: [u8; 16],
    #[serde(with = "hex::serde")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantRegisterResponse {
    pub ok: bool,
    pub host_endpoint_id: String,
    pub server_time: i64,
    #[serde(with = "hex::serde")]
    pub caps_topic_id: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicRegisterRequest {
    pub version: u8,
    #[serde(with = "hex::serde")]
    pub root_pubkey: [u8; 32],
    #[serde(with = "hex::serde")]
    pub topic_id: [u8; 32],
    pub timestamp: i64,
    #[serde(with = "hex::serde")]
    pub nonce: [u8; 16],
    #[serde(with = "hex::serde")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicRegisterResponse {
    pub ok: bool,
    #[serde(with = "hex::serde")]
    pub topic_id: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicUnregisterRequest {
    pub version: u8,
    #[serde(with = "hex::serde")]
    pub root_pubkey: [u8; 32],
    #[serde(with = "hex::serde")]
    pub topic_id: [u8; 32],
    pub timestamp: i64,
    #[serde(with = "hex::serde")]
    pub nonce: [u8; 16],
    #[serde(with = "hex::serde")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicUnregisterResponse {
    pub ok: bool,
    #[serde(with = "hex::serde")]
    pub topic_id: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantStatusRequest {
    pub version: u8,
    #[serde(with = "hex::serde")]
    pub root_pubkey: [u8; 32],
    pub timestamp: i64,
    #[serde(with = "hex::serde")]
    pub nonce: [u8; 16],
    #[serde(with = "hex::serde")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantStatusResponse {
    pub registered_at: i64,
    pub topic_count: u32,
    pub bytes_stored: u64,
    pub retention_budget_bytes: u64,
    pub oldest_retained_at: i64,
    pub write_rate_limit_per_sec: u32,
    pub status: TenantStatusKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatusKind {
    Active,
    Suspended,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantErrorResponse {
    pub code: TenantErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TenantErrorCode {
    BadSignature,
    StaleTimestamp,
    ReplayedNonce,
    TenantNotFound,
    TenantSuspended,
    TopicAlreadyRegistered,
    RegistrationRateLimited,
    Internal,
}

// --- canonical signing-byte builders ---------------------------------------

const REGISTER_DOMAIN: &[u8] = b"wires-tenant-register-v1\0";
const TOPIC_REGISTER_DOMAIN: &[u8] = b"wires-topic-register-v1\0";
const TOPIC_UNREGISTER_DOMAIN: &[u8] = b"wires-topic-unregister-v1\0";
const STATUS_DOMAIN: &[u8] = b"wires-tenant-status-v1\0";

pub fn register_signing_bytes(
    root_pubkey: &[u8; 32],
    timestamp: i64,
    nonce: &[u8; 16],
    host_endpoint_id: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(REGISTER_DOMAIN.len() + 32 + 8 + 16 + 32);
    out.extend_from_slice(REGISTER_DOMAIN);
    out.extend_from_slice(root_pubkey);
    out.extend_from_slice(&timestamp.to_le_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(host_endpoint_id);
    out
}

pub fn topic_register_signing_bytes(
    root_pubkey: &[u8; 32],
    topic_id: &[u8; 32],
    timestamp: i64,
    nonce: &[u8; 16],
    host_endpoint_id: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(TOPIC_REGISTER_DOMAIN.len() + 32 + 32 + 8 + 16 + 32);
    out.extend_from_slice(TOPIC_REGISTER_DOMAIN);
    out.extend_from_slice(root_pubkey);
    out.extend_from_slice(topic_id);
    out.extend_from_slice(&timestamp.to_le_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(host_endpoint_id);
    out
}

pub fn topic_unregister_signing_bytes(
    root_pubkey: &[u8; 32],
    topic_id: &[u8; 32],
    timestamp: i64,
    nonce: &[u8; 16],
    host_endpoint_id: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(TOPIC_UNREGISTER_DOMAIN.len() + 32 + 32 + 8 + 16 + 32);
    out.extend_from_slice(TOPIC_UNREGISTER_DOMAIN);
    out.extend_from_slice(root_pubkey);
    out.extend_from_slice(topic_id);
    out.extend_from_slice(&timestamp.to_le_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(host_endpoint_id);
    out
}

pub fn status_signing_bytes(
    root_pubkey: &[u8; 32],
    timestamp: i64,
    nonce: &[u8; 16],
    host_endpoint_id: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(STATUS_DOMAIN.len() + 32 + 8 + 16 + 32);
    out.extend_from_slice(STATUS_DOMAIN);
    out.extend_from_slice(root_pubkey);
    out.extend_from_slice(&timestamp.to_le_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(host_endpoint_id);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_serde_roundtrip() {
        let req = TenantRequest::Register(TenantRegisterRequest {
            version: 1,
            root_pubkey: [1u8; 32],
            timestamp: 12345,
            nonce: [9u8; 16],
            signature: [3u8; 64],
        });
        let json = serde_json::to_string(&req).unwrap();
        let back: TenantRequest = serde_json::from_str(&json).unwrap();
        match back {
            TenantRequest::Register(r) => {
                assert_eq!(r.timestamp, 12345);
                assert_eq!(r.root_pubkey, [1u8; 32]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn signing_bytes_change_with_each_field() {
        let base = register_signing_bytes(&[1u8; 32], 1, &[2u8; 16], &[3u8; 32]);
        let diff_root = register_signing_bytes(&[9u8; 32], 1, &[2u8; 16], &[3u8; 32]);
        let diff_ts = register_signing_bytes(&[1u8; 32], 2, &[2u8; 16], &[3u8; 32]);
        let diff_nonce = register_signing_bytes(&[1u8; 32], 1, &[7u8; 16], &[3u8; 32]);
        let diff_host = register_signing_bytes(&[1u8; 32], 1, &[2u8; 16], &[8u8; 32]);
        assert_ne!(base, diff_root);
        assert_ne!(base, diff_ts);
        assert_ne!(base, diff_nonce);
        assert_ne!(base, diff_host);
    }
}
```

In `crates/wires-net/src/lib.rs`:

```rust
pub mod tenant;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p wires-net tenant::tests`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-net/src/tenant.rs crates/wires-net/src/lib.rs crates/wires-net/src/error.rs
git commit -m "wires-net: add tenant protocol types + signing-byte builders"
```

---

### Task 9: `TenantHandler` trait + `TenantProtocol` (server-side)

**Files:**
- Modify: `crates/wires-net/src/tenant.rs`

- [ ] **Step 1: Define handler trait and protocol**

Append to `crates/wires-net/src/tenant.rs`:

```rust
use std::sync::Arc;

use iroh::endpoint::Connection;
use iroh::protocol::{ProtocolHandler, AcceptError};
use n0_future::boxed::BoxFuture;
use snafu::ResultExt as _;

use crate::error::{IoSnafu, Result};
use crate::framing::{read_frame, write_frame};

/// Business-logic hook the host wires in. All methods are synchronous and
/// pure-function from the protocol's perspective: validate, mutate state,
/// return the response. The protocol layer handles framing and stream
/// lifecycle.
pub trait TenantHandler: Send + Sync + 'static {
    fn handle_register(&self, req: TenantRegisterRequest) -> TenantResponse;
    fn handle_topic_register(&self, req: TopicRegisterRequest) -> TenantResponse;
    fn handle_topic_unregister(&self, req: TopicUnregisterRequest) -> TenantResponse;
    fn handle_status(&self, req: TenantStatusRequest) -> TenantResponse;
}

#[derive(Clone)]
pub struct TenantProtocol<H: TenantHandler> {
    handler: Arc<H>,
}

impl<H: TenantHandler> std::fmt::Debug for TenantProtocol<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantProtocol").finish_non_exhaustive()
    }
}

impl<H: TenantHandler> TenantProtocol<H> {
    pub fn new(handler: Arc<H>) -> Self { Self { handler } }

    pub(crate) async fn handle_one(&self, conn: Connection) -> Result<()> {
        let (mut send, mut recv) = conn.accept_bi().await
            .map_err(anyhow::Error::from).context(IoSnafu)?;
        let req: TenantRequest = read_frame(&mut recv, MAX_FRAME_LEN).await?;
        let resp = match req {
            TenantRequest::Register(r) => self.handler.handle_register(r),
            TenantRequest::TopicRegister(r) => self.handler.handle_topic_register(r),
            TenantRequest::TopicUnregister(r) => self.handler.handle_topic_unregister(r),
            TenantRequest::Status(r) => self.handler.handle_status(r),
        };
        write_frame(&mut send, &resp).await?;
        send.finish().ok();
        Ok(())
    }
}

impl<H: TenantHandler> ProtocolHandler for TenantProtocol<H> {
    fn accept(&self, connection: Connection) -> BoxFuture<std::result::Result<(), AcceptError>> {
        let me = self.clone();
        Box::pin(async move {
            if let Err(e) = me.handle_one(connection).await {
                tracing::warn!(error = %e, "tenant protocol handler error");
            }
            Ok(())
        })
    }
}
```

- [ ] **Step 2: Confirm it compiles**

Run: `cargo build -p wires-net`
Expected: success. If iroh's `ProtocolHandler` signature differs from above, mirror what `crates/wires-net/src/replay.rs` uses in its `ProtocolHandler` impl (the version constraints must match exactly).

- [ ] **Step 3: Commit**

```bash
git add crates/wires-net/src/tenant.rs
git commit -m "wires-net: add TenantHandler trait and TenantProtocol server"
```

---

### Task 10: `TenantClient` (client-side)

**Files:**
- Modify: `crates/wires-net/src/tenant.rs`

- [ ] **Step 1: Add the client**

Append to `crates/wires-net/src/tenant.rs`:

```rust
use iroh::{Endpoint, EndpointId};

#[derive(Clone)]
pub struct TenantClient {
    endpoint: Endpoint,
}

impl TenantClient {
    pub fn new(endpoint: Endpoint) -> Self { Self { endpoint } }

    pub async fn send(&self, peer: EndpointId, req: &TenantRequest) -> Result<TenantResponse> {
        let conn = self.endpoint.connect(peer, ALPN).await
            .map_err(anyhow::Error::from).context(IoSnafu)?;
        let (mut send, mut recv) = conn.open_bi().await
            .map_err(anyhow::Error::from).context(IoSnafu)?;
        write_frame(&mut send, req).await?;
        send.finish().ok();
        let resp: TenantResponse = read_frame(&mut recv, MAX_FRAME_LEN).await?;
        Ok(resp)
    }
}
```

Also add a re-export in `crates/wires-net/src/lib.rs`:

```rust
pub use tenant::{
    TenantClient, TenantHandler, TenantProtocol,
    TenantRequest, TenantResponse,
    TenantRegisterRequest, TenantRegisterResponse,
    TopicRegisterRequest, TopicRegisterResponse,
    TopicUnregisterRequest, TopicUnregisterResponse,
    TenantStatusRequest, TenantStatusResponse,
    TenantErrorResponse, TenantErrorCode, TenantStatusKind,
    register_signing_bytes, topic_register_signing_bytes,
    topic_unregister_signing_bytes, status_signing_bytes,
    ALPN as TENANT_ALPN,
};
```

- [ ] **Step 2: Confirm it compiles**

Run: `cargo build -p wires-net`
Expected: success.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-net/src/tenant.rs crates/wires-net/src/lib.rs
git commit -m "wires-net: add TenantClient and re-export tenant surface"
```

---

## Phase 3: `wires-host` — multi-tenant rewrite

### Task 11: Convert `wires-host` to `lib + bin`

**Files:**
- Modify: `crates/wires-host/Cargo.toml`
- Create: `crates/wires-host/src/lib.rs`
- Modify: `crates/wires-host/src/main.rs` (will become a thin re-export wrapper later)

- [ ] **Step 1: Update Cargo.toml**

In `crates/wires-host/Cargo.toml`, ensure both `[lib]` and `[[bin]]` are present. Add `axum = "0.8"` to dependencies (latest stable line; if a newer minor exists at impl time, use the latest non-pre-release version per `CLAUDE.md`).

```toml
[lib]
name = "wires_host"
path = "src/lib.rs"

[[bin]]
name = "wires-host"
path = "src/main.rs"

[dependencies]
# ... existing ...
axum = "0.8"
tokio = { workspace = true, features = ["full"] }
hex = { workspace = true }
```

(Adjust to match existing patterns. If `tokio`/`hex` are already in `[dependencies]`, leave them alone.)

- [ ] **Step 2: Create empty lib.rs**

Create `crates/wires-host/src/lib.rs`:

```rust
//! Library crate for `wires-host`. The binary entry point lives in `main.rs`
//! and delegates here. Tests in `crates/wires-host/tests/` consume this lib.

pub mod error;
pub mod tenant_registry;
pub mod per_tenant_logs;
pub mod retention;
pub mod routing;
pub mod http_discovery;
```

Modules will be filled in by subsequent tasks. The build will fail until each module exists.

- [ ] **Step 3: Create stub module files so the crate compiles**

For each of `error.rs`, `tenant_registry.rs`, `per_tenant_logs.rs`, `retention.rs`, `routing.rs`, `http_discovery.rs` under `crates/wires-host/src/`, create an empty file containing only:

```rust
//! Filled in by subsequent tasks.
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo build -p wires-host`
Expected: success.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-host/Cargo.toml crates/wires-host/src/lib.rs \
        crates/wires-host/src/error.rs crates/wires-host/src/tenant_registry.rs \
        crates/wires-host/src/per_tenant_logs.rs crates/wires-host/src/retention.rs \
        crates/wires-host/src/routing.rs crates/wires-host/src/http_discovery.rs
git commit -m "wires-host: scaffold lib crate with stub modules"
```

---

### Task 12: `HostError` enum

**Files:**
- Modify: `crates/wires-host/src/error.rs`

- [ ] **Step 1: Replace stub with the error type**

In `crates/wires-host/src/error.rs`:

```rust
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum HostError {
    #[snafu(display("Failed to open host db file: {source}, at {location}"))]
    DbOpen {
        source: redb::DatabaseError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Host storage I/O failed: {source}, at {location}"))]
    StorageIo {
        source: redb::StorageError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Failed to (de)serialize host record: {source}, at {location}"))]
    Serde {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Tenant signature invalid, at {location}"))]
    TenantSignatureInvalid {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Tenant suspended (root={root_hex}), at {location}"))]
    TenantSuspended {
        root_hex: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Retention eviction failed: {source}, at {location}"))]
    RetentionEvictionFailed {
        source: wires_store::error::StoreError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Store error: {source}, at {location}"))]
    Store {
        source: wires_store::error::StoreError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Redb txn boundary failed: {source}, at {location}"))]
    Txn {
        source: redb::TransactionError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Redb commit failed: {source}, at {location}"))]
    Commit {
        source: redb::CommitError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Redb table-open failed: {source}, at {location}"))]
    Table {
        source: redb::TableError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Filesystem I/O failed: {source}, at {location}"))]
    Io {
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, HostError>;
```

Check `crates/wires-store/src/error.rs` to confirm the exact name of its public error type (probably `StoreError`); if it differs, update `Source: wires_store::...` accordingly.

- [ ] **Step 2: Verify it compiles**

Run: `cargo build -p wires-host`
Expected: success.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-host/src/error.rs
git commit -m "wires-host: define HostError with snafu+Location pattern"
```

---

### Task 13: `tenant_registry` — schema and `TenantRecord`

**Files:**
- Modify: `crates/wires-host/src/tenant_registry.rs`

- [ ] **Step 1: Implement the data types and table defs**

In `crates/wires-host/src/tenant_registry.rs`:

```rust
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

pub struct TenantRegistry {
    pub root: PathBuf,
    tenants_db: Arc<Database>,
    topic_index_db: Arc<Database>,
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
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p wires-host tenant_registry::tests`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-host/src/tenant_registry.rs
git commit -m "wires-host: TenantRegistry::open/get/insert_if_absent"
```

---

### Task 14: `tenant_registry` — topic index

**Files:**
- Modify: `crates/wires-host/src/tenant_registry.rs`

- [ ] **Step 1: Add tests for topic index**

Append to the `tests` module:

```rust
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
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p wires-host tenant_registry::tests::topic_index_`
Expected: FAIL — `register_topic` / `TopicRegisterOutcome` not defined.

- [ ] **Step 3: Implement**

Add to `crates/wires-host/src/tenant_registry.rs`:

```rust
#[derive(Debug)]
pub enum TopicRegisterOutcome {
    Inserted,
    AlreadyOwned,
    Conflict { other_root: [u8; 32] },
}

impl TenantRegistry {
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
            let prior = table.get(&topic_id[..]).context(StorageIoSnafu)?;
            match prior.map(|g| g.value().to_vec()) {
                Some(raw) if raw == root_pubkey.as_slice() => TopicRegisterOutcome::AlreadyOwned,
                Some(raw) => {
                    let mut other = [0u8; 32];
                    other.copy_from_slice(&raw);
                    TopicRegisterOutcome::Conflict { other_root: other }
                }
                None => {
                    table.insert(&topic_id[..], &root_pubkey[..]).context(StorageIoSnafu)?;
                    TopicRegisterOutcome::Inserted
                }
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
            let prior = table.get(&topic_id[..]).context(StorageIoSnafu)?
                .map(|g| g.value().to_vec());
            if prior.as_deref() == Some(root_pubkey.as_slice()) {
                table.remove(&topic_id[..]).context(StorageIoSnafu)?;
                true
            } else {
                false
            }
        };
        write.commit().context(CommitSnafu)?;
        Ok(removed)
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p wires-host tenant_registry::tests::topic_index_`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-host/src/tenant_registry.rs
git commit -m "wires-host: topic_index register/lookup/unregister with conflict reporting"
```

---

### Task 15: `tenant_registry` — nonce replay protection

**Files:**
- Modify: `crates/wires-host/src/tenant_registry.rs`

- [ ] **Step 1: Add failing tests**

Append to `tests`:

```rust
#[test]
fn nonce_first_seen_then_replay_detected() {
    let tmp = TempDir::new().unwrap();
    let reg = TenantRegistry::open(tmp.path()).unwrap();
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
    let reg = TenantRegistry::open(tmp.path()).unwrap();
    let root = [7u8; 32];
    let nonce = [3u8; 16];
    let now = 100_000i64;
    let ttl_ms = 120_000i64;
    assert!(!reg.nonce_seen(&root, &nonce, now, ttl_ms).unwrap());
    // Re-use after TTL elapses should be allowed again.
    assert!(!reg.nonce_seen(&root, &nonce, now + ttl_ms + 1, ttl_ms).unwrap());
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p wires-host tenant_registry::tests::nonce_`
Expected: FAIL — `nonce_seen` not defined.

- [ ] **Step 3: Implement**

Add to `TenantRegistry`:

```rust
impl TenantRegistry {
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
                table.insert(&key[..], &expires_at.to_be_bytes()[..]).context(StorageIoSnafu)?;
            }
            recent
        };
        write.commit().context(CommitSnafu)?;
        Ok(seen_recent)
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p wires-host tenant_registry::tests::nonce_`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-host/src/tenant_registry.rs
git commit -m "wires-host: replay protection via nonces table with TTL"
```

---

### Task 16: `per_tenant_logs` — tenant-scoped `TopicLogs`

**Files:**
- Modify: `crates/wires-host/src/per_tenant_logs.rs`

- [ ] **Step 1: Implement**

In `crates/wires-host/src/per_tenant_logs.rs`:

```rust
//! Per-tenant scoped TopicLogs. Each tenant gets a subdirectory under the host
//! data dir; per-topic redb files live inside.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use snafu::ResultExt as _;
use wires_store::{open_topic_log, TopicLog};

use crate::error::{IoSnafu, Result, StoreSnafu};

pub struct PerTenantLogs {
    root: PathBuf,
    cache: RwLock<HashMap<([u8; 32], [u8; 32]), Arc<TopicLog>>>,
}

impl PerTenantLogs {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            cache: RwLock::new(HashMap::new()),
        }
    }

    pub fn tenant_dir(&self, root_pubkey: &[u8; 32]) -> PathBuf {
        self.root.join("tenants").join(hex::encode(root_pubkey))
    }

    pub fn get_or_open(
        &self,
        root_pubkey: &[u8; 32],
        topic_id: &[u8; 32],
    ) -> Result<Arc<TopicLog>> {
        {
            let map = self.cache.read().unwrap();
            if let Some(log) = map.get(&(*root_pubkey, *topic_id)) {
                return Ok(Arc::clone(log));
            }
        }
        let dir = self.tenant_dir(root_pubkey);
        std::fs::create_dir_all(&dir).context(IoSnafu)?;
        let db = open_topic_log(&dir, &hex::encode(topic_id)).context(StoreSnafu)?;
        let log = Arc::new(TopicLog::new(Arc::new(db)));
        let mut map = self.cache.write().unwrap();
        map.insert((*root_pubkey, *topic_id), Arc::clone(&log));
        Ok(log)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use wires_core::{MessageKind, WireMessage};

    fn dummy_msg(sender: u8, seq: u64) -> WireMessage {
        WireMessage {
            topic_id: [1u8; 32],
            epoch: 0,
            kind: MessageKind::Standard,
            sender: [sender; 32],
            cap_id: [0u8; 16],
            seq,
            prev_hash: [0u8; 32],
            timestamp: seq as i64,
            payload_len: 1,
            signature: [0u8; 64],
            ciphertext: vec![1, 2, 3],
        }
    }

    #[test]
    fn separates_tenants_on_disk() {
        let tmp = TempDir::new().unwrap();
        let logs = PerTenantLogs::new(tmp.path());
        let root_a = [1u8; 32];
        let root_b = [2u8; 32];
        let topic = [9u8; 32];
        let log_a = logs.get_or_open(&root_a, &topic).unwrap();
        let log_b = logs.get_or_open(&root_b, &topic).unwrap();
        log_a.append(&dummy_msg(7, 0)).unwrap();
        log_b.append(&dummy_msg(8, 0)).unwrap();
        assert!(logs.tenant_dir(&root_a).exists());
        assert!(logs.tenant_dir(&root_b).exists());
        assert!(logs.tenant_dir(&root_a).join(format!("log_{}.redb", hex::encode(topic))).exists());
        assert!(logs.tenant_dir(&root_b).join(format!("log_{}.redb", hex::encode(topic))).exists());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p wires-host per_tenant_logs::tests`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-host/src/per_tenant_logs.rs
git commit -m "wires-host: PerTenantLogs — TopicLog scoped per (root_pubkey, topic_id)"
```

---

### Task 17: `retention` — per-tenant ingest index manager

**Files:**
- Modify: `crates/wires-host/src/retention.rs`

- [ ] **Step 1: Implement**

In `crates/wires-host/src/retention.rs`:

```rust
//! Per-tenant retention manager. Tracks an IngestIndex per tenant and applies
//! FIFO eviction against `PerTenantLogs` when the tenant's stored bytes exceed
//! its budget.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use snafu::ResultExt as _;
use wires_store::{open_ingest_index, IngestEntry, IngestIndex};

use crate::error::{RetentionEvictionFailedSnafu, Result, StoreSnafu};
use crate::per_tenant_logs::PerTenantLogs;

pub struct Retention {
    root: PathBuf,
    indices: RwLock<HashMap<[u8; 32], Arc<IngestIndex>>>,
    logs: Arc<PerTenantLogs>,
}

impl Retention {
    pub fn new(root: &Path, logs: Arc<PerTenantLogs>) -> Self {
        Self {
            root: root.to_path_buf(),
            indices: RwLock::new(HashMap::new()),
            logs,
        }
    }

    fn index_for(&self, root_pubkey: &[u8; 32]) -> Result<Arc<IngestIndex>> {
        {
            let map = self.indices.read().unwrap();
            if let Some(idx) = map.get(root_pubkey) { return Ok(Arc::clone(idx)); }
        }
        let dir = self.root.join("tenants").join(hex::encode(root_pubkey));
        std::fs::create_dir_all(&dir).ok();
        let db = open_ingest_index(&dir, &hex::encode(root_pubkey)).context(StoreSnafu)?;
        let idx = Arc::new(IngestIndex::new(Arc::new(db)));
        let mut map = self.indices.write().unwrap();
        map.insert(*root_pubkey, Arc::clone(&idx));
        Ok(idx)
    }

    /// Record an ingest and evict oldest entries if over budget. Returns the
    /// `IngestEntry`s that were evicted (and therefore need their per-topic
    /// log rows removed).
    pub fn on_append(
        &self,
        root_pubkey: &[u8; 32],
        topic_id: &[u8; 32],
        sender: &[u8; 32],
        seq: u64,
        bytes: u32,
        budget: u64,
    ) -> Result<Vec<IngestEntry>> {
        let idx = self.index_for(root_pubkey)?;
        idx.record(&IngestEntry {
            topic_id: *topic_id,
            sender: *sender,
            seq,
            bytes,
        }).context(StoreSnafu)?;
        let evicted = idx.evict_oldest_until(budget).context(StoreSnafu)?;
        for e in &evicted {
            let log = self.logs.get_or_open(root_pubkey, &e.topic_id)?;
            log.delete(&e.sender, e.seq).context(RetentionEvictionFailedSnafu)?;
        }
        Ok(evicted)
    }

    pub fn bytes_stored(&self, root_pubkey: &[u8; 32]) -> Result<u64> {
        let idx = self.index_for(root_pubkey)?;
        idx.total_bytes().context(StoreSnafu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use wires_core::{MessageKind, WireMessage};

    fn msg(sender: u8, seq: u64, payload: u32) -> WireMessage {
        WireMessage {
            topic_id: [1u8; 32],
            epoch: 0,
            kind: MessageKind::Standard,
            sender: [sender; 32],
            cap_id: [0u8; 16],
            seq,
            prev_hash: [0u8; 32],
            timestamp: seq as i64,
            payload_len: payload,
            signature: [0u8; 64],
            ciphertext: vec![0u8; payload as usize],
        }
    }

    #[test]
    fn eviction_drops_oldest_when_over_budget() {
        let tmp = TempDir::new().unwrap();
        let logs = Arc::new(PerTenantLogs::new(tmp.path()));
        let retention = Retention::new(tmp.path(), Arc::clone(&logs));
        let root = [1u8; 32];
        let topic = [9u8; 32];

        // Append 3 messages to the underlying log AND record them in retention.
        let log = logs.get_or_open(&root, &topic).unwrap();
        let m0 = msg(7, 0, 100);
        let m1 = msg(7, 1, 100);
        let m2 = msg(7, 2, 100);
        log.append(&m0).unwrap();
        log.append(&m1).unwrap();
        log.append(&m2).unwrap();

        let b0 = serde_json::to_vec(&m0).unwrap().len() as u32;
        let b1 = serde_json::to_vec(&m1).unwrap().len() as u32;
        let b2 = serde_json::to_vec(&m2).unwrap().len() as u32;

        retention.on_append(&root, &topic, &[7u8; 32], 0, b0, u64::MAX).unwrap();
        retention.on_append(&root, &topic, &[7u8; 32], 1, b1, u64::MAX).unwrap();
        // Last append imposes a tight budget — should evict m0 and m1.
        let evicted = retention
            .on_append(&root, &topic, &[7u8; 32], 2, b2, b2 as u64)
            .unwrap();
        assert_eq!(evicted.len(), 2);
        assert_eq!(evicted[0].seq, 0);
        assert_eq!(evicted[1].seq, 1);

        // m0 and m1 must be gone from the underlying log; m2 survives.
        let survivors = log.read_after(&[7u8; 32], None, 10).unwrap();
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].seq, 2);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p wires-host retention::tests`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-host/src/retention.rs
git commit -m "wires-host: Retention — per-tenant FIFO eviction over PerTenantLogs"
```

---

### Task 18: `TenantHandler` impl on a composite host state

**Files:**
- Modify: `crates/wires-host/src/tenant_registry.rs` (add `TenantHandlerImpl`)
- Modify: `crates/wires-host/src/lib.rs`

- [ ] **Step 1: Add the handler struct + impl**

Append to `crates/wires-host/src/tenant_registry.rs`:

```rust
use blake3;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use wires_net::tenant::{
    register_signing_bytes, status_signing_bytes, topic_register_signing_bytes,
    topic_unregister_signing_bytes, TenantErrorCode, TenantErrorResponse,
    TenantRegisterRequest, TenantRegisterResponse, TenantRequest, TenantResponse,
    TenantStatusKind, TenantStatusRequest, TenantStatusResponse,
    TopicRegisterRequest, TopicRegisterResponse,
    TopicUnregisterRequest, TopicUnregisterResponse,
};

/// Tunable behaviour for `TenantHandlerImpl`.
#[derive(Clone, Copy)]
pub struct TenantHandlerConfig {
    pub max_clock_skew_ms: i64,
    pub nonce_ttl_ms: i64,
    pub write_rate_limit_per_sec: u32,
}

impl Default for TenantHandlerConfig {
    fn default() -> Self {
        Self {
            max_clock_skew_ms: 60_000,
            nonce_ttl_ms: 120_000,
            write_rate_limit_per_sec: 1_000,
        }
    }
}

pub struct TenantHandlerImpl {
    pub registry: Arc<TenantRegistry>,
    pub host_endpoint_id: [u8; 32],
    pub config: TenantHandlerConfig,
    pub now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
    pub on_topic_registered: Arc<dyn Fn([u8; 32], [u8; 32]) + Send + Sync>,
    pub on_topic_unregistered: Arc<dyn Fn([u8; 32], [u8; 32]) + Send + Sync>,
}

impl TenantHandlerImpl {
    fn caps_topic_id_for(root_pubkey: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"wires.caps.v1");
        h.update(root_pubkey);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }

    fn err(code: TenantErrorCode, message: &str) -> TenantResponse {
        TenantResponse::Error(TenantErrorResponse {
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
    ) -> std::result::Result<(), TenantResponse> {
        let now = (self.now_ms)();
        if (now - timestamp).abs() > self.config.max_clock_skew_ms {
            return Err(Self::err(TenantErrorCode::StaleTimestamp, "timestamp out of range"));
        }
        let vk = match VerifyingKey::from_bytes(root_pubkey) {
            Ok(k) => k,
            Err(_) => return Err(Self::err(TenantErrorCode::BadSignature, "bad pubkey")),
        };
        let sig = Signature::from_bytes(signature);
        if vk.verify(signing_bytes, &sig).is_err() {
            return Err(Self::err(TenantErrorCode::BadSignature, "signature failed"));
        }
        match self.registry.nonce_seen(root_pubkey, nonce, now, self.config.nonce_ttl_ms) {
            Ok(true) => Err(Self::err(TenantErrorCode::ReplayedNonce, "nonce already seen")),
            Ok(false) => Ok(()),
            Err(_) => Err(Self::err(TenantErrorCode::Internal, "nonce store error")),
        }
    }
}

impl wires_net::tenant::TenantHandler for TenantHandlerImpl {
    fn handle_register(&self, req: TenantRegisterRequest) -> TenantResponse {
        let signing_bytes = register_signing_bytes(
            &req.root_pubkey, req.timestamp, &req.nonce, &self.host_endpoint_id,
        );
        if let Err(e) = self.check_common(
            &req.root_pubkey, req.timestamp, &req.nonce, &req.signature, &signing_bytes,
        ) { return e; }

        let now = (self.now_ms)();
        let rec = TenantRecord {
            registered_at: now,
            status: TenantStatus::Active,
            retention_budget_bytes: DEFAULT_RETENTION_BUDGET_BYTES,
        };
        if self.registry.insert_if_absent(&req.root_pubkey, rec).is_err() {
            return Self::err(TenantErrorCode::Internal, "tenant table write failed");
        }

        let caps_topic_id = Self::caps_topic_id_for(&req.root_pubkey);
        if matches!(
            self.registry.register_topic(&req.root_pubkey, &caps_topic_id),
            Ok(TopicRegisterOutcome::Inserted | TopicRegisterOutcome::AlreadyOwned),
        ) {
            (self.on_topic_registered)(req.root_pubkey, caps_topic_id);
        }

        TenantResponse::Register(TenantRegisterResponse {
            ok: true,
            host_endpoint_id: hex::encode(self.host_endpoint_id),
            server_time: now,
            caps_topic_id,
        })
    }

    fn handle_topic_register(&self, req: TopicRegisterRequest) -> TenantResponse {
        let signing_bytes = topic_register_signing_bytes(
            &req.root_pubkey, &req.topic_id, req.timestamp, &req.nonce, &self.host_endpoint_id,
        );
        if let Err(e) = self.check_common(
            &req.root_pubkey, req.timestamp, &req.nonce, &req.signature, &signing_bytes,
        ) { return e; }

        match self.registry.get(&req.root_pubkey) {
            Ok(Some(rec)) if rec.status == TenantStatus::Active => {}
            Ok(Some(_)) => return Self::err(TenantErrorCode::TenantSuspended, "tenant suspended"),
            Ok(None) => return Self::err(TenantErrorCode::TenantNotFound, "register tenant first"),
            Err(_) => return Self::err(TenantErrorCode::Internal, "tenant lookup failed"),
        }

        match self.registry.register_topic(&req.root_pubkey, &req.topic_id) {
            Ok(TopicRegisterOutcome::Inserted) | Ok(TopicRegisterOutcome::AlreadyOwned) => {
                (self.on_topic_registered)(req.root_pubkey, req.topic_id);
                TenantResponse::TopicRegister(TopicRegisterResponse {
                    ok: true,
                    topic_id: req.topic_id,
                })
            }
            Ok(TopicRegisterOutcome::Conflict { .. }) => {
                Self::err(TenantErrorCode::TopicAlreadyRegistered, "topic owned by another tenant")
            }
            Err(_) => Self::err(TenantErrorCode::Internal, "topic register write failed"),
        }
    }

    fn handle_topic_unregister(&self, req: TopicUnregisterRequest) -> TenantResponse {
        let signing_bytes = topic_unregister_signing_bytes(
            &req.root_pubkey, &req.topic_id, req.timestamp, &req.nonce, &self.host_endpoint_id,
        );
        if let Err(e) = self.check_common(
            &req.root_pubkey, req.timestamp, &req.nonce, &req.signature, &signing_bytes,
        ) { return e; }

        match self.registry.unregister_topic(&req.root_pubkey, &req.topic_id) {
            Ok(true) => {
                (self.on_topic_unregistered)(req.root_pubkey, req.topic_id);
                TenantResponse::TopicUnregister(TopicUnregisterResponse {
                    ok: true, topic_id: req.topic_id,
                })
            }
            Ok(false) => TenantResponse::TopicUnregister(TopicUnregisterResponse {
                ok: false, topic_id: req.topic_id,
            }),
            Err(_) => Self::err(TenantErrorCode::Internal, "topic unregister failed"),
        }
    }

    fn handle_status(&self, req: TenantStatusRequest) -> TenantResponse {
        let signing_bytes = status_signing_bytes(
            &req.root_pubkey, req.timestamp, &req.nonce, &self.host_endpoint_id,
        );
        if let Err(e) = self.check_common(
            &req.root_pubkey, req.timestamp, &req.nonce, &req.signature, &signing_bytes,
        ) { return e; }

        let rec = match self.registry.get(&req.root_pubkey) {
            Ok(Some(rec)) => rec,
            _ => return Self::err(TenantErrorCode::TenantNotFound, "no such tenant"),
        };

        TenantResponse::Status(TenantStatusResponse {
            registered_at: rec.registered_at,
            topic_count: 0,                 // populated in a later task once routing tracks this
            bytes_stored: 0,
            retention_budget_bytes: rec.retention_budget_bytes,
            oldest_retained_at: 0,
            write_rate_limit_per_sec: self.config.write_rate_limit_per_sec,
            status: match rec.status {
                TenantStatus::Active => TenantStatusKind::Active,
                TenantStatus::Suspended => TenantStatusKind::Suspended,
            },
        })
    }
}
```

Add `blake3` to `crates/wires-host/Cargo.toml` dependencies if not already present (it's already in the workspace per CLAUDE.md, so use the workspace version).

- [ ] **Step 2: Verify it compiles**

Run: `cargo build -p wires-host`
Expected: success.

- [ ] **Step 3: Add a smoke test for `handle_register`**

Append to `tests` module in `crates/wires-host/src/tenant_registry.rs`:

```rust
#[test]
fn handle_register_signs_and_records_tenant() {
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use std::sync::Arc;
    use wires_net::tenant::{TenantHandler, TenantRegisterRequest, TenantRequest, TenantResponse};

    let tmp = TempDir::new().unwrap();
    let reg = Arc::new(TenantRegistry::open(tmp.path()).unwrap());

    let signing_key = SigningKey::generate(&mut OsRng);
    let root_pubkey = signing_key.verifying_key().to_bytes();
    let host_endpoint_id = [42u8; 32];
    let now_ms = 1_000_000i64;

    let handler = TenantHandlerImpl {
        registry: Arc::clone(&reg),
        host_endpoint_id,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(move || now_ms),
        on_topic_registered: Arc::new(|_root, _topic| {}),
        on_topic_unregistered: Arc::new(|_root, _topic| {}),
    };

    let nonce = [9u8; 16];
    let bytes = wires_net::tenant::register_signing_bytes(
        &root_pubkey, now_ms, &nonce, &host_endpoint_id,
    );
    let sig = signing_key.sign(&bytes).to_bytes();

    let req = TenantRegisterRequest {
        version: 1,
        root_pubkey,
        timestamp: now_ms,
        nonce,
        signature: sig,
    };
    let resp = handler.handle_register(req);
    match resp {
        TenantResponse::Register(r) => {
            assert!(r.ok);
            assert_eq!(r.host_endpoint_id, hex::encode(host_endpoint_id));
        }
        other => panic!("expected Register response, got {:?}", other),
    }

    // Tenant row now exists.
    let rec = reg.get(&root_pubkey).unwrap().unwrap();
    assert_eq!(rec.status, TenantStatus::Active);
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p wires-host tenant_registry::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-host/src/tenant_registry.rs crates/wires-host/Cargo.toml
git commit -m "wires-host: TenantHandlerImpl implements wires-net::TenantHandler"
```

---

### Task 19: Routing inbound gossip envelopes

**Files:**
- Modify: `crates/wires-host/src/routing.rs`

- [ ] **Step 1: Implement the inbound router**

In `crates/wires-host/src/routing.rs`:

```rust
//! Inbound envelope router: resolves topic → tenant, applies write-rate
//! limits, appends to per-tenant log, records in retention.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use snafu::ResultExt as _;
use wires_core::WireMessage;

use crate::error::{Result, StoreSnafu};
use crate::per_tenant_logs::PerTenantLogs;
use crate::retention::Retention;
use crate::tenant_registry::{TenantRegistry, TenantRecord, TenantStatus};

pub struct WriteRateLimiter {
    per_sec: u32,
    buckets: RwLock<HashMap<[u8; 32], (Instant, u32)>>,
}

impl WriteRateLimiter {
    pub fn new(per_sec: u32) -> Self {
        Self { per_sec, buckets: RwLock::new(HashMap::new()) }
    }

    /// Returns `true` if the request is within the per-tenant per-second cap.
    pub fn try_acquire(&self, root_pubkey: &[u8; 32]) -> bool {
        let mut map = self.buckets.write().unwrap();
        let now = Instant::now();
        let entry = map.entry(*root_pubkey).or_insert((now, 0));
        if now.duration_since(entry.0).as_secs() >= 1 {
            *entry = (now, 0);
        }
        if entry.1 >= self.per_sec { return false; }
        entry.1 += 1;
        true
    }
}

pub struct Router {
    registry: Arc<TenantRegistry>,
    logs: Arc<PerTenantLogs>,
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
        registry: Arc<TenantRegistry>,
        logs: Arc<PerTenantLogs>,
        retention: Arc<Retention>,
        rate: Arc<WriteRateLimiter>,
    ) -> Self {
        Self { registry, logs, retention, rate }
    }

    pub fn route(&self, msg: &WireMessage) -> Result<RouteOutcome> {
        let root_pubkey = match self.registry.lookup_topic_tenant(&msg.topic_id)? {
            Some(r) => r,
            None => return Ok(RouteOutcome::DroppedUnknownTopic),
        };
        let rec: TenantRecord = match self.registry.get(&root_pubkey)? {
            Some(r) => r,
            None => return Ok(RouteOutcome::DroppedUnknownTopic),
        };
        if rec.status == TenantStatus::Suspended {
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
        let bytes = serde_json::to_vec(msg)
            .map(|v| v.len() as u32)
            .unwrap_or(0);
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
    use tempfile::TempDir;
    use wires_core::{MessageKind, WireMessage};
    use crate::tenant_registry::{TenantRecord, TenantStatus};

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

    fn router_with_one_tenant(
        tmp: &TempDir,
        topic: [u8; 32],
    ) -> (Router, [u8; 32]) {
        let registry = Arc::new(TenantRegistry::open(tmp.path()).unwrap());
        let logs = Arc::new(PerTenantLogs::new(tmp.path()));
        let retention = Arc::new(Retention::new(tmp.path(), Arc::clone(&logs)));
        let rate = Arc::new(WriteRateLimiter::new(1_000_000));
        let root = [3u8; 32];
        registry.insert_if_absent(&root, TenantRecord {
            registered_at: 0,
            status: TenantStatus::Active,
            retention_budget_bytes: u64::MAX,
        }).unwrap();
        registry.register_topic(&root, &topic).unwrap();
        (Router::new(registry, logs, retention, rate), root)
    }

    #[test]
    fn unknown_topic_is_dropped() {
        let tmp = TempDir::new().unwrap();
        let registry = Arc::new(TenantRegistry::open(tmp.path()).unwrap());
        let logs = Arc::new(PerTenantLogs::new(tmp.path()));
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
        let (router, _root) = router_with_one_tenant(&tmp, topic);
        let msg = dummy_msg(topic, 7, 0);
        let out = router.route(&msg).unwrap();
        assert!(matches!(out, RouteOutcome::Appended));
    }

    #[test]
    fn rate_limit_blocks_excess() {
        let tmp = TempDir::new().unwrap();
        let topic = [5u8; 32];
        let registry = Arc::new(TenantRegistry::open(tmp.path()).unwrap());
        let logs = Arc::new(PerTenantLogs::new(tmp.path()));
        let retention = Arc::new(Retention::new(tmp.path(), Arc::clone(&logs)));
        let rate = Arc::new(WriteRateLimiter::new(1)); // 1/sec
        let root = [3u8; 32];
        registry.insert_if_absent(&root, TenantRecord {
            registered_at: 0,
            status: TenantStatus::Active,
            retention_budget_bytes: u64::MAX,
        }).unwrap();
        registry.register_topic(&root, &topic).unwrap();
        let router = Router::new(registry, logs, retention, rate);

        let msg0 = dummy_msg(topic, 7, 0);
        let msg1 = dummy_msg(topic, 7, 1);
        assert!(matches!(router.route(&msg0).unwrap(), RouteOutcome::Appended));
        assert!(matches!(router.route(&msg1).unwrap(), RouteOutcome::DroppedRateLimited));
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p wires-host routing::tests`
Expected: PASS (three tests).

- [ ] **Step 3: Commit**

```bash
git add crates/wires-host/src/routing.rs
git commit -m "wires-host: Router with topic→tenant lookup, rate limit, retention"
```

---

### Task 20: `http_discovery` — axum service

**Files:**
- Modify: `crates/wires-host/src/http_discovery.rs`

- [ ] **Step 1: Implement**

In `crates/wires-host/src/http_discovery.rs`:

```rust
//! Service-discovery HTTPS endpoint. v1 returns this host's own EndpointId;
//! sharding sub-projects extend the response payload.

use std::sync::Arc;

use axum::{routing::get, Json, Router};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryEndpoint {
    pub endpoint_id: String,
    pub relay: Option<String>,
    pub addrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    pub version: u8,
    pub endpoints: Vec<DiscoveryEndpoint>,
    pub ttl_seconds: u32,
}

pub struct DiscoveryState {
    pub response: DiscoveryResponse,
}

pub fn router(state: Arc<DiscoveryState>) -> Router {
    Router::new()
        .route("/v1/bootstrap", get({
            let state = Arc::clone(&state);
            move || {
                let state = Arc::clone(&state);
                async move { Json(state.response.clone()) }
            }
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn bootstrap_returns_endpoint_list() {
        let state = Arc::new(DiscoveryState {
            response: DiscoveryResponse {
                version: 1,
                endpoints: vec![DiscoveryEndpoint {
                    endpoint_id: "abc".into(),
                    relay: Some("https://relay.example/".into()),
                    addrs: vec!["127.0.0.1:11204".into()],
                }],
                ttl_seconds: 300,
            },
        });
        let app = router(state);
        let resp = app
            .oneshot(Request::builder().uri("/v1/bootstrap").body(Body::empty()).unwrap())
            .await.unwrap();
        assert_eq!(resp.status(), 200);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 64_000).await.unwrap();
        let parsed: DiscoveryResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.endpoints.len(), 1);
        assert_eq!(parsed.endpoints[0].endpoint_id, "abc");
    }
}
```

Add `tower` as a dev-dependency in `crates/wires-host/Cargo.toml`:

```toml
[dev-dependencies]
tower = { version = "0.5", features = ["util"] }
tokio = { workspace = true, features = ["macros", "rt-multi-thread"] }
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p wires-host http_discovery::tests`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-host/src/http_discovery.rs crates/wires-host/Cargo.toml
git commit -m "wires-host: http_discovery axum service for /v1/bootstrap"
```

---

### Task 21: New `main.rs`

**Files:**
- Rewrite: `crates/wires-host/src/main.rs`

- [ ] **Step 1: Replace `main.rs`**

Replace the contents of `crates/wires-host/src/main.rs` with:

```rust
//! Blind multi-tenant relay/replay-server. Topics arrive dynamically via the
//! tenant control protocol; no `--topic` flags.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use iroh::{endpoint::presets, Endpoint, SecretKey};
use tokio::sync::mpsc;
use wires_core::WireMessage;
use wires_host::http_discovery::{self, DiscoveryEndpoint, DiscoveryResponse, DiscoveryState};
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::retention::Retention;
use wires_host::routing::{Router as MsgRouter, WriteRateLimiter};
use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
use wires_net::replay::{ReplayProtocol, ReplaySource, ALPN as REPLAY_ALPN};
use wires_net::tenant::{TenantProtocol, ALPN as TENANT_ALPN};
use wires_net::{load_or_create_secret, GossipNode};

#[derive(Parser)]
#[command(name = "wires-host", about = "Blind multi-tenant relay for the wires network")]
struct Args {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long, default_value = "0.0.0.0:8443")]
    discovery_addr: SocketAddr,
    /// Public URL the discovery service advertises (e.g. https://wires.example).
    /// If omitted, defaults to `http://<discovery_addr>` (testing).
    #[arg(long)]
    public_url: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    std::fs::create_dir_all(&args.data_dir)?;

    // iroh identity ---------------------------------------------------------
    let secret_path = args.data_dir.join("iroh.secret");
    let secret = load_or_create_secret(&secret_path)?;
    let iroh_sk = SecretKey::from_bytes(&secret);
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(iroh_sk)
        .alpns(vec![TENANT_ALPN.to_vec(), REPLAY_ALPN.to_vec()])
        .bind()
        .await?;
    let endpoint_id = endpoint.id();
    let endpoint_id_bytes: [u8; 32] = endpoint_id.as_bytes().to_owned();
    println!("wires-host: EndpointId = {endpoint_id}");

    // Storage + state -------------------------------------------------------
    let registry = Arc::new(TenantRegistry::open(&args.data_dir)?);
    let logs = Arc::new(PerTenantLogs::new(&args.data_dir));
    let retention = Arc::new(Retention::new(&args.data_dir, Arc::clone(&logs)));
    let rate = Arc::new(WriteRateLimiter::new(1_000));
    let router_state = Arc::new(MsgRouter::new(
        Arc::clone(&registry),
        Arc::clone(&logs),
        Arc::clone(&retention),
        Arc::clone(&rate),
    ));

    // Gossip + dynamic subscribe channel -----------------------------------
    let gossip = GossipNode::new(endpoint.clone()).await?;
    let (subscribe_tx, mut subscribe_rx) = mpsc::unbounded_channel::<[u8; 32]>();

    // Spawn subscriber dispatcher: when the handler tells us about a new
    // topic, join it.
    {
        let gossip = gossip.clone_for_subscribe()
            .unwrap_or_else(|| panic!("GossipNode must expose a clone-for-subscribe handle; \
                                       see Task 22 for the supporting change in wires-net"));
        let router_state = Arc::clone(&router_state);
        tokio::spawn(async move {
            while let Some(topic_id) = subscribe_rx.recv().await {
                let (_handle, mut rx) = match gossip.join(topic_id, vec![]).await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, topic = %hex::encode(topic_id), "gossip join failed");
                        continue;
                    }
                };
                let router_state = Arc::clone(&router_state);
                tokio::spawn(async move {
                    while let Some(bytes) = rx.recv().await {
                        let msg: WireMessage = match serde_json::from_slice(&bytes) {
                            Ok(m) => m,
                            Err(e) => { tracing::warn!(error = %e, "bad gossip frame"); continue; }
                        };
                        if wires_core::verify_envelope(&msg).is_err() {
                            tracing::warn!("dropped unsigned/bad envelope at host"); continue;
                        }
                        if let Err(e) = router_state.route(&msg) {
                            tracing::warn!(error = %e, "router error");
                        }
                    }
                });
            }
        });
    }

    // Tenant handler --------------------------------------------------------
    let subscribe_tx_clone = subscribe_tx.clone();
    let handler = Arc::new(TenantHandlerImpl {
        registry: Arc::clone(&registry),
        host_endpoint_id: endpoint_id_bytes,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(|| chrono::Utc::now().timestamp_millis()),
        on_topic_registered: Arc::new(move |_root, topic| {
            let _ = subscribe_tx_clone.send(topic);
        }),
        on_topic_unregistered: Arc::new(|_root, _topic| {
            // v1: subscription stays live; future spec adds a teardown signal.
        }),
    });

    // Register ALPNs --------------------------------------------------------
    let replay_protocol = ReplayProtocol::new(PerTenantReplaySource::new(
        Arc::clone(&registry), Arc::clone(&logs),
    ));
    let _router = iroh::protocol::Router::builder(endpoint.clone())
        .accept(REPLAY_ALPN, replay_protocol)
        .accept(TENANT_ALPN, TenantProtocol::new(Arc::clone(&handler)))
        .spawn();

    // HTTPS discovery -------------------------------------------------------
    let public_url = args.public_url.unwrap_or_else(|| format!("http://{}", args.discovery_addr));
    let discovery_state = Arc::new(DiscoveryState {
        response: DiscoveryResponse {
            version: 1,
            endpoints: vec![DiscoveryEndpoint {
                endpoint_id: hex::encode(endpoint_id_bytes),
                relay: None,
                addrs: vec![],
            }],
            ttl_seconds: 300,
        },
    });
    let discovery_app = http_discovery::router(discovery_state);
    let listener = tokio::net::TcpListener::bind(args.discovery_addr).await?;
    let actual_addr = listener.local_addr()?;
    tokio::spawn(async move {
        axum::serve(listener, discovery_app).await.ok();
    });
    println!("wires-host: discovery listening at {actual_addr} (public={public_url})");
    println!("wires-host: running. Press Ctrl-C to exit.");
    tokio::signal::ctrl_c().await?;
    Ok(())
}

// `PerTenantReplaySource` is filled in by Task 23.
use wires_host::routing::Router as _;
mod per_tenant_replay {
    use super::*;
    pub struct PerTenantReplaySource;
    impl PerTenantReplaySource {
        pub fn new(_registry: Arc<TenantRegistry>, _logs: Arc<PerTenantLogs>) -> Self { Self }
    }
}
use per_tenant_replay::PerTenantReplaySource;
```

This file references two pieces that Task 22 and Task 23 fill in. The build will fail until those tasks are done. That is expected.

- [ ] **Step 2: Try to build (expect a failure)**

Run: `cargo build -p wires-host`
Expected: build errors referring to `GossipNode::clone_for_subscribe` and the `ReplaySource` impl for `PerTenantReplaySource`. Move on to Task 22 to resolve.

- [ ] **Step 3: Add `chrono` to host deps if missing**

In `crates/wires-host/Cargo.toml`, ensure `chrono` is present (used only for `Utc::now().timestamp_millis()`). If not present, add: `chrono = { version = "0.4", default-features = false, features = ["clock"] }`.

- [ ] **Step 4: Commit work-in-progress**

```bash
git add crates/wires-host/src/main.rs crates/wires-host/Cargo.toml
git commit -m "wires-host: rewrite main.rs (depends on tasks 22-23 to compile)"
```

---

### Task 22: `GossipNode::clone_for_subscribe`

**Files:**
- Modify: `crates/wires-net/src/gossip.rs`

- [ ] **Step 1: Add a method that returns a clone of the underlying `Gossip` actor**

In `crates/wires-net/src/gossip.rs`, on `impl GossipNode`, add:

```rust
/// Returns a handle that can be used to call `join` from another task. The
/// underlying `iroh_gossip::Gossip` is internally an Arc, so this is a cheap
/// clone.
pub fn clone_for_subscribe(&self) -> Option<GossipNode> {
    Some(GossipNode {
        endpoint: self.endpoint.clone(),
        gossip: self.gossip.clone(),
        _router: self._router.clone(),
    })
}
```

If `iroh::protocol::Router` is not `Clone` in this iroh version, refactor `GossipNode` to wrap `_router` in an `Arc<...>` and clone that instead. Adjust types until the impl compiles.

- [ ] **Step 2: Verify it compiles**

Run: `cargo build -p wires-net`
Expected: success.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-net/src/gossip.rs
git commit -m "wires-net: GossipNode::clone_for_subscribe for cross-task topic joins"
```

---

### Task 23: Per-tenant `ReplaySource`

**Files:**
- Modify: `crates/wires-host/src/lib.rs` (add `replay_source` module)
- Create: `crates/wires-host/src/replay_source.rs`
- Modify: `crates/wires-host/src/main.rs` (drop the stub, use the real type)

- [ ] **Step 1: Add module declaration**

In `crates/wires-host/src/lib.rs`, add:

```rust
pub mod replay_source;
```

- [ ] **Step 2: Implement**

Create `crates/wires-host/src/replay_source.rs`:

```rust
//! `ReplaySource` impl that routes per-tenant via the topic_index.

use std::sync::Arc;

use wires_core::WireMessage;
use wires_net::replay::{Pubkey, ReplaySource};

use crate::per_tenant_logs::PerTenantLogs;
use crate::tenant_registry::TenantRegistry;

pub struct PerTenantReplaySource {
    registry: Arc<TenantRegistry>,
    logs: Arc<PerTenantLogs>,
}

impl PerTenantReplaySource {
    pub fn new(registry: Arc<TenantRegistry>, logs: Arc<PerTenantLogs>) -> Self {
        Self { registry, logs }
    }
}

impl ReplaySource for PerTenantReplaySource {
    fn read_after(
        &self,
        topic_id: &[u8; 32],
        sender: &Pubkey,
        after_seq: Option<u64>,
        limit: usize,
    ) -> std::result::Result<Vec<WireMessage>, Box<dyn std::error::Error + Send + Sync>> {
        let root = match self.registry.lookup_topic_tenant(topic_id) {
            Ok(Some(r)) => r,
            Ok(None) => return Ok(vec![]),
            Err(e) => return Err(Box::new(e)),
        };
        let log = self.logs
            .get_or_open(&root, topic_id)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        log.read_after(sender, after_seq, limit)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    fn all_senders_for(
        &self,
        topic_id: &[u8; 32],
    ) -> std::result::Result<Vec<Pubkey>, Box<dyn std::error::Error + Send + Sync>> {
        let root = match self.registry.lookup_topic_tenant(topic_id) {
            Ok(Some(r)) => r,
            Ok(None) => return Ok(vec![]),
            Err(e) => return Err(Box::new(e)),
        };
        let log = self.logs
            .get_or_open(&root, topic_id)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        let hwm = log.hwm()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        Ok(hwm.into_keys().collect())
    }
}
```

- [ ] **Step 3: Update `main.rs` to use the real type**

In `crates/wires-host/src/main.rs`, remove the inline `per_tenant_replay` module and the `use wires_host::routing::Router as _;` workaround. Replace with:

```rust
use wires_host::replay_source::PerTenantReplaySource;
```

The `ReplayProtocol::new(PerTenantReplaySource::new(...))` line should now compile.

- [ ] **Step 4: Verify it compiles**

Run: `cargo build -p wires-host`
Expected: success.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-host/src/lib.rs crates/wires-host/src/replay_source.rs crates/wires-host/src/main.rs
git commit -m "wires-host: PerTenantReplaySource routes replay through topic_index"
```

---

## Phase 4: Integration tests

### Task 24: Integration test — single-tenant happy path

**Files:**
- Create: `crates/wires-host/tests/tenant_register.rs`

- [ ] **Step 1: Write the test**

Create `crates/wires-host/tests/tenant_register.rs`:

```rust
//! End-to-end: in-process iroh endpoints, host with TenantProtocol exposed,
//! a client sends TenantRegisterRequest and expects an OK response with the
//! correct host_endpoint_id and caps_topic_id.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use iroh::{endpoint::presets, Endpoint, SecretKey};
use rand_core::OsRng;
use tempfile::TempDir;
use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
use wires_net::tenant::{
    register_signing_bytes, TenantClient, TenantProtocol, TenantRegisterRequest, TenantRequest,
    TenantResponse, ALPN as TENANT_ALPN,
};

fn endpoint_id_bytes(ep: &Endpoint) -> [u8; 32] {
    ep.id().as_bytes().to_owned()
}

#[tokio::test]
async fn tenant_register_round_trip() {
    let tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(tmp.path()).unwrap());

    // Host endpoint
    let host_secret = SecretKey::generate(&mut OsRng);
    let host_ep = Endpoint::builder(presets::N0)
        .secret_key(host_secret)
        .alpns(vec![TENANT_ALPN.to_vec()])
        .bind()
        .await.unwrap();
    let host_eid_bytes = endpoint_id_bytes(&host_ep);

    let handler = Arc::new(TenantHandlerImpl {
        registry: Arc::clone(&registry),
        host_endpoint_id: host_eid_bytes,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(|| 1_000_000i64),
        on_topic_registered: Arc::new(|_, _| {}),
        on_topic_unregistered: Arc::new(|_, _| {}),
    });
    let _host_router = iroh::protocol::Router::builder(host_ep.clone())
        .accept(TENANT_ALPN, TenantProtocol::new(handler))
        .spawn();

    // Client endpoint
    let client_secret = SecretKey::generate(&mut OsRng);
    let client_ep = Endpoint::builder(presets::N0)
        .secret_key(client_secret)
        .bind()
        .await.unwrap();
    let client = TenantClient::new(client_ep);

    // Sign + send.
    let signing_key = SigningKey::generate(&mut OsRng);
    let root_pubkey = signing_key.verifying_key().to_bytes();
    let now_ms = 1_000_000i64;
    let nonce = [9u8; 16];
    let bytes = register_signing_bytes(&root_pubkey, now_ms, &nonce, &host_eid_bytes);
    let sig = signing_key.sign(&bytes).to_bytes();
    let req = TenantRequest::Register(TenantRegisterRequest {
        version: 1,
        root_pubkey,
        timestamp: now_ms,
        nonce,
        signature: sig,
    });

    let resp = client.send(host_ep.id(), &req).await.unwrap();
    match resp {
        TenantResponse::Register(r) => {
            assert!(r.ok);
            assert_eq!(r.host_endpoint_id, hex::encode(host_eid_bytes));
        }
        other => panic!("expected Register, got {:?}", other),
    }

    // Tenant row persisted.
    assert!(registry.get(&root_pubkey).unwrap().is_some());
}
```

- [ ] **Step 2: Run**

Run: `cargo test -p wires-host --test tenant_register -- --nocapture`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-host/tests/tenant_register.rs
git commit -m "wires-host: integration test for tenant register round-trip"
```

---

### Task 25: Integration test — two tenants isolated

**Files:**
- Create: `crates/wires-host/tests/two_tenants_isolated.rs`

- [ ] **Step 1: Write the test**

Create `crates/wires-host/tests/two_tenants_isolated.rs`:

```rust
//! Two tenants register, each registers a distinct topic, each publishes
//! through the router. On-disk per-tenant directories are populated and
//! do not cross-contaminate.

use std::sync::Arc;

use tempfile::TempDir;
use wires_core::{MessageKind, WireMessage};
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::retention::Retention;
use wires_host::routing::{Router, WriteRateLimiter};
use wires_host::tenant_registry::{TenantRecord, TenantRegistry, TenantStatus};

fn mk_msg(topic: [u8; 32], sender: u8, seq: u64) -> WireMessage {
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
        ciphertext: vec![sender, seq as u8],
    }
}

#[test]
fn two_tenants_isolated() {
    let tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(tmp.path()));
    let retention = Arc::new(Retention::new(tmp.path(), Arc::clone(&logs)));
    let rate = Arc::new(WriteRateLimiter::new(1_000_000));
    let router = Router::new(Arc::clone(&registry), Arc::clone(&logs), Arc::clone(&retention), rate);

    let root_a = [0xAAu8; 32];
    let root_b = [0xBBu8; 32];
    let topic_a = [0x11u8; 32];
    let topic_b = [0x22u8; 32];
    for (r, t) in [(root_a, topic_a), (root_b, topic_b)] {
        registry.insert_if_absent(&r, TenantRecord {
            registered_at: 0,
            status: TenantStatus::Active,
            retention_budget_bytes: u64::MAX,
        }).unwrap();
        registry.register_topic(&r, &t).unwrap();
    }

    router.route(&mk_msg(topic_a, 7, 0)).unwrap();
    router.route(&mk_msg(topic_b, 8, 0)).unwrap();

    let dir_a = tmp.path().join("tenants").join(hex::encode(root_a));
    let dir_b = tmp.path().join("tenants").join(hex::encode(root_b));
    assert!(dir_a.join(format!("log_{}.redb", hex::encode(topic_a))).exists());
    assert!(dir_b.join(format!("log_{}.redb", hex::encode(topic_b))).exists());
    assert!(!dir_a.join(format!("log_{}.redb", hex::encode(topic_b))).exists());
    assert!(!dir_b.join(format!("log_{}.redb", hex::encode(topic_a))).exists());
}
```

- [ ] **Step 2: Run**

Run: `cargo test -p wires-host --test two_tenants_isolated`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-host/tests/two_tenants_isolated.rs
git commit -m "wires-host: integration test for two-tenant filesystem isolation"
```

---

### Task 26: Integration test — retention eviction

**Files:**
- Create: `crates/wires-host/tests/retention_eviction.rs`

- [ ] **Step 1: Write the test**

Create `crates/wires-host/tests/retention_eviction.rs`:

```rust
//! Publishing enough bytes for a tenant to exceed its retention budget causes
//! the oldest messages to be evicted; the underlying log reads return only
//! the surviving suffix.

use std::sync::Arc;

use tempfile::TempDir;
use wires_core::{MessageKind, WireMessage};
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::retention::Retention;
use wires_host::routing::{Router, WriteRateLimiter};
use wires_host::tenant_registry::{TenantRecord, TenantRegistry, TenantStatus};

fn mk_msg(topic: [u8; 32], sender: u8, seq: u64, payload_size: usize) -> WireMessage {
    WireMessage {
        topic_id: topic,
        epoch: 0,
        kind: MessageKind::Standard,
        sender: [sender; 32],
        cap_id: [0u8; 16],
        seq,
        prev_hash: [0u8; 32],
        timestamp: seq as i64,
        payload_len: payload_size as u32,
        signature: [0u8; 64],
        ciphertext: vec![0u8; payload_size],
    }
}

#[test]
fn retention_eviction_drops_oldest_first() {
    let tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(tmp.path()));
    let retention = Arc::new(Retention::new(tmp.path(), Arc::clone(&logs)));
    let rate = Arc::new(WriteRateLimiter::new(1_000_000));

    let root = [9u8; 32];
    let topic = [5u8; 32];
    // Budget: ~3 messages worth.
    let probe = mk_msg(topic, 7, 0, 1024);
    let probe_bytes = serde_json::to_vec(&probe).unwrap().len() as u64;
    let budget = probe_bytes * 3;
    registry.insert_if_absent(&root, TenantRecord {
        registered_at: 0,
        status: TenantStatus::Active,
        retention_budget_bytes: budget,
    }).unwrap();
    registry.register_topic(&root, &topic).unwrap();
    let router = Router::new(registry, Arc::clone(&logs), Arc::clone(&retention), rate);

    for seq in 0..6 {
        router.route(&mk_msg(topic, 7, seq, 1024)).unwrap();
    }

    // After 6 writes with budget = 3, retention bytes ≤ budget.
    assert!(retention.bytes_stored(&[9u8; 32]).unwrap() <= budget);
    let log = logs.get_or_open(&root, &topic).unwrap();
    let got = log.read_after(&[7u8; 32], None, 100).unwrap();
    assert!(got.len() <= 3, "expected at most 3 messages surviving, got {}", got.len());
    // The surviving messages should be the most recent ones.
    let highest_seq = got.iter().map(|m| m.seq).max().unwrap();
    assert_eq!(highest_seq, 5);
}
```

- [ ] **Step 2: Run**

Run: `cargo test -p wires-host --test retention_eviction`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-host/tests/retention_eviction.rs
git commit -m "wires-host: integration test for rolling-retention eviction"
```

---

### Task 27: Integration test — bad signature / replayed nonce / unknown topic

**Files:**
- Create: `crates/wires-host/tests/rate_limit.rs`

- [ ] **Step 1: Write the test (covers signature/nonce/unknown-topic)**

Create `crates/wires-host/tests/rate_limit.rs`:

```rust
//! Negative paths through the tenant control protocol and inbound router.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use tempfile::TempDir;
use wires_core::{MessageKind, WireMessage};
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::retention::Retention;
use wires_host::routing::{Router, RouteOutcome, WriteRateLimiter};
use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
use wires_net::tenant::{
    register_signing_bytes, TenantErrorCode, TenantHandler, TenantRegisterRequest, TenantResponse,
};

#[test]
fn handle_register_rejects_bad_signature() {
    let tmp = TempDir::new().unwrap();
    let reg = Arc::new(TenantRegistry::open(tmp.path()).unwrap());
    let host_endpoint_id = [42u8; 32];
    let handler = TenantHandlerImpl {
        registry: Arc::clone(&reg),
        host_endpoint_id,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(|| 1_000_000),
        on_topic_registered: Arc::new(|_, _| {}),
        on_topic_unregistered: Arc::new(|_, _| {}),
    };
    let signing_key = SigningKey::generate(&mut OsRng);
    let root_pubkey = signing_key.verifying_key().to_bytes();
    let req = TenantRegisterRequest {
        version: 1,
        root_pubkey,
        timestamp: 1_000_000,
        nonce: [0u8; 16],
        signature: [0u8; 64], // garbage
    };
    match handler.handle_register(req) {
        TenantResponse::Error(e) => assert_eq!(e.code, TenantErrorCode::BadSignature),
        _ => panic!("expected BadSignature"),
    }
}

#[test]
fn handle_register_rejects_replayed_nonce() {
    let tmp = TempDir::new().unwrap();
    let reg = Arc::new(TenantRegistry::open(tmp.path()).unwrap());
    let host_endpoint_id = [42u8; 32];
    let handler = TenantHandlerImpl {
        registry: Arc::clone(&reg),
        host_endpoint_id,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(|| 1_000_000),
        on_topic_registered: Arc::new(|_, _| {}),
        on_topic_unregistered: Arc::new(|_, _| {}),
    };
    let signing_key = SigningKey::generate(&mut OsRng);
    let root_pubkey = signing_key.verifying_key().to_bytes();
    let nonce = [0xCDu8; 16];
    let bytes = register_signing_bytes(&root_pubkey, 1_000_000, &nonce, &host_endpoint_id);
    let sig = signing_key.sign(&bytes).to_bytes();
    let req = TenantRegisterRequest {
        version: 1,
        root_pubkey,
        timestamp: 1_000_000,
        nonce,
        signature: sig,
    };
    // First call succeeds.
    match handler.handle_register(req.clone()) {
        TenantResponse::Register(r) => assert!(r.ok),
        _ => panic!("expected Register OK"),
    }
    // Second call with same nonce → replayed.
    match handler.handle_register(req) {
        TenantResponse::Error(e) => assert_eq!(e.code, TenantErrorCode::ReplayedNonce),
        _ => panic!("expected ReplayedNonce"),
    }
}

#[test]
fn router_drops_envelope_for_unregistered_topic() {
    let tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(tmp.path()));
    let retention = Arc::new(Retention::new(tmp.path(), Arc::clone(&logs)));
    let rate = Arc::new(WriteRateLimiter::new(1_000));
    let router = Router::new(registry, logs, retention, rate);
    let msg = WireMessage {
        topic_id: [9u8; 32],
        epoch: 0, kind: MessageKind::Standard,
        sender: [3u8; 32], cap_id: [0u8; 16], seq: 0, prev_hash: [0u8; 32],
        timestamp: 0, payload_len: 1, signature: [0u8; 64], ciphertext: vec![0],
    };
    let outcome = router.route(&msg).unwrap();
    assert!(matches!(outcome, RouteOutcome::DroppedUnknownTopic));
}
```

- [ ] **Step 2: Run**

Run: `cargo test -p wires-host --test rate_limit`
Expected: PASS (three tests).

- [ ] **Step 3: Commit**

```bash
git add crates/wires-host/tests/rate_limit.rs
git commit -m "wires-host: integration tests for bad-sig, replay, unknown-topic"
```

---

### Task 28: Acceptance test — full HTTP discovery + tenant register

**Files:**
- Create: `crates/wires-host/tests/acceptance.rs`

- [ ] **Step 1: Write the test**

Create `crates/wires-host/tests/acceptance.rs`:

```rust
//! Acceptance: start the discovery HTTP service and a live iroh host with the
//! tenant protocol; a client fetches `/v1/bootstrap` via reqwest, parses the
//! endpoint list, dials the listed EndpointId, and registers.

use std::net::SocketAddr;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use iroh::{endpoint::presets, Endpoint, SecretKey};
use rand_core::OsRng;
use tempfile::TempDir;
use wires_host::http_discovery::{self, DiscoveryEndpoint, DiscoveryResponse, DiscoveryState};
use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
use wires_net::tenant::{
    register_signing_bytes, TenantClient, TenantProtocol, TenantRegisterRequest, TenantRequest,
    TenantResponse, ALPN as TENANT_ALPN,
};

#[tokio::test]
#[ignore]
async fn end_to_end_register_via_http_discovery() {
    let tmp = TempDir::new().unwrap();
    let registry = Arc::new(TenantRegistry::open(tmp.path()).unwrap());

    let host_secret = SecretKey::generate(&mut OsRng);
    let host_ep = Endpoint::builder(presets::N0)
        .secret_key(host_secret)
        .alpns(vec![TENANT_ALPN.to_vec()])
        .bind()
        .await.unwrap();
    let host_eid_bytes: [u8; 32] = host_ep.id().as_bytes().to_owned();

    let handler = Arc::new(TenantHandlerImpl {
        registry: Arc::clone(&registry),
        host_endpoint_id: host_eid_bytes,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(|| 1_000_000),
        on_topic_registered: Arc::new(|_, _| {}),
        on_topic_unregistered: Arc::new(|_, _| {}),
    });
    let _router = iroh::protocol::Router::builder(host_ep.clone())
        .accept(TENANT_ALPN, TenantProtocol::new(handler))
        .spawn();

    // Spin up discovery HTTP service on an ephemeral port.
    let discovery_state = Arc::new(DiscoveryState {
        response: DiscoveryResponse {
            version: 1,
            endpoints: vec![DiscoveryEndpoint {
                endpoint_id: hex::encode(host_eid_bytes),
                relay: None,
                addrs: vec![],
            }],
            ttl_seconds: 300,
        },
    });
    let app = http_discovery::router(discovery_state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok(); });

    // Client: fetch discovery, then register.
    let resp = reqwest::get(format!("http://{addr}/v1/bootstrap")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let payload: DiscoveryResponse = resp.json().await.unwrap();
    assert_eq!(payload.endpoints.len(), 1);
    let target_endpoint_id_hex = payload.endpoints[0].endpoint_id.clone();
    assert_eq!(target_endpoint_id_hex, hex::encode(host_eid_bytes));

    let client_secret = SecretKey::generate(&mut OsRng);
    let client_ep = Endpoint::builder(presets::N0).secret_key(client_secret).bind().await.unwrap();
    let client = TenantClient::new(client_ep);

    let signing_key = SigningKey::generate(&mut OsRng);
    let root_pubkey = signing_key.verifying_key().to_bytes();
    let nonce = [11u8; 16];
    let bytes = register_signing_bytes(&root_pubkey, 1_000_000, &nonce, &host_eid_bytes);
    let sig = signing_key.sign(&bytes).to_bytes();
    let req = TenantRequest::Register(TenantRegisterRequest {
        version: 1,
        root_pubkey,
        timestamp: 1_000_000,
        nonce,
        signature: sig,
    });
    let resp = client.send(host_ep.id(), &req).await.unwrap();
    match resp {
        TenantResponse::Register(r) => assert!(r.ok),
        other => panic!("expected Register OK, got {:?}", other),
    }
    assert!(registry.get(&root_pubkey).unwrap().is_some());
}
```

Add `reqwest` as a dev-dependency in `crates/wires-host/Cargo.toml`:

```toml
[dev-dependencies]
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json"] }
```

- [ ] **Step 2: Run with `--ignored`**

Run: `cargo test -p wires-host --test acceptance -- --ignored --nocapture`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-host/tests/acceptance.rs crates/wires-host/Cargo.toml
git commit -m "wires-host: acceptance test for HTTPS-discovery + tenant register"
```

---

## Phase 5: Final verification

### Task 29: Workspace-wide build + clippy + fmt

- [ ] **Step 1: Full workspace build**

Run: `cargo build --workspace`
Expected: success.

- [ ] **Step 2: Full workspace test (non-ignored)**

Run: `cargo test --workspace`
Expected: all tests pass.

- [ ] **Step 3: Ignored acceptance tests**

Run: `cargo test --workspace -- --ignored`
Expected: all ignored tests pass.

- [ ] **Step 4: Clippy with `-D warnings`**

Run: `cargo clippy --workspace -- -D warnings`
Expected: no warnings. Fix any that appear (commit each fix as its own small commit).

- [ ] **Step 5: Format**

Run: `cargo fmt --all`
Then: `git diff --exit-code` — if there are changes, commit them as `chore: cargo fmt`.

- [ ] **Step 6: Final commit if needed**

```bash
git add -A
git commit -m "chore: clippy + fmt"
```

(Skip if no diff.)

---

## Self-review against the spec

After implementation, walk through the spec sections and confirm:

- §2 Tenant lifecycle — covered by tasks 13–18.
- §3 Components — every entry in the table maps to one or more tasks.
- §4.2–4.6 Request/response types and behaviour — types in task 8, behaviour in task 18.
- §4.7 Anti-abuse on registration — covered by `TenantRegistry::nonce_seen` (task 15).
  Per-EndpointId-of-source registration rate-limit is **deferred** to a follow-up.
  Note this gap explicitly before merging.
- §5 Storage layout — tasks 16, 17, 19, 23.
- §5 Retention — tasks 4–5, 17.
- §5 Write-rate ceiling — `WriteRateLimiter` in task 19.
- §5 Replay protocol — task 23.
- §6 Invite token — task 6.
- §7 Service discovery — tasks 20, 21, 28.
- §10 Error handling — task 12.
- §11 Testing — tasks 24–28.
- §12 Acceptance criteria — task 28 (end-to-end), the rest via integration tests.

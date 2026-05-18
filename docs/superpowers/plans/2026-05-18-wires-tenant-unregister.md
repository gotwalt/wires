# Tenant Unregister Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fifth tenant control-plane RPC, `TenantUnregister`, that lets a tenant (signed by its root key) tear down its registration on a host — drops the tenant row, every topic_index entry that maps to it, and the on-disk `tenants/<root_hex>/` tree. Add a matching `wires host tenant-unregister` operator command that also clears the local `config.toml` host block. This is the host-side primitive a future iOS "Reset household" feature will call.

**Architecture:** Mirror the four existing tenant RPCs (`Register`, `TopicRegister`, `TopicUnregister`, `Status`). The wire types live in `wires-net::tenant`; the registry + filesystem deletion live in `wires-host`; the operator surface lives in `wires-cli`. No spec changes, no new ALPN, no new dependency. The host treats unregister as idempotent: re-running against an already-gone tenant returns `ok: false, topics_removed: 0` rather than an error, so a client retrying after a transient failure does the right thing. On-disk cleanup is best-effort and logged on failure; the control-plane response reflects logical success once the registry rows are gone.

**Tech Stack:** Rust edition 2024 / stable 1.95, snafu, serde+serde_json, ed25519-dalek 2, redb 4. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-05-14-wires-hosted-service-design.md` §4 (tenant control protocol). This plan extends it; no spec update is forced because the existing §4 framing covers a new request type by addition.

---

## File Map

| File | Action | Owner task |
|---|---|---|
| `crates/wires-net/src/tenant.rs` | Modify: new variant + request/response + handler trait method + client helper + tests | Tasks 1–3 |
| `crates/wires-host/src/tenant_registry.rs` | Modify: `TenantRegistry::delete_tenant`, `TenantHandlerImpl::on_tenant_unregistered` field, `handle_unregister`, tests | Tasks 4, 6 |
| `crates/wires-host/src/per_tenant_logs.rs` | Modify: `clear_tenant` (drop cache entries) + test | Task 5 |
| `crates/wires-host/src/retention.rs` | Modify: `clear_tenant` (drop cache entries) + test | Task 5 |
| `crates/wires-host/src/main.rs` | Modify: wire `on_tenant_unregistered` to call `clear_tenant` + remove the tenant dir | Task 7 |
| `crates/wires-cli/src/main.rs` | Modify: add `HostCmd::TenantUnregister` | Task 8 |
| `crates/wires-cli/src/cmd/host.rs` | Modify: `tenant_unregister` fn that calls the new client helper and clears `config.toml`'s host block | Task 8 |
| `crates/wires-host/tests/tenant_unregister.rs` | Create: end-to-end integration test | Task 9 |

No layering inversions: `wires-net` stays I/O-light, `wires-host` consumes `wires-net`'s new types, `wires-cli` consumes `wires-net`'s client helper.

---

## Phase A — Wire types in `wires-net`

### Task 1: Add `TenantOp::Unregister` and its signing domain

**Files:**
- Modify: `crates/wires-net/src/tenant.rs`

- [ ] **Step 1: Add the failing test**

Inside the existing `#[cfg(test)] mod tests` block in `crates/wires-net/src/tenant.rs`, append this test alongside `signing_bytes_distinguishes_topic_ops` (around line 471):

```rust
#[test]
fn signing_bytes_distinguishes_tenant_unregister_from_other_no_topic_ops() {
    let r = signing_bytes(TenantOp::Register, &[1u8; 32], 1, &[2u8; 16], &[3u8; 32]);
    let s = signing_bytes(TenantOp::Status, &[1u8; 32], 1, &[2u8; 16], &[3u8; 32]);
    let u = signing_bytes(TenantOp::Unregister, &[1u8; 32], 1, &[2u8; 16], &[3u8; 32]);
    assert_ne!(u, r);
    assert_ne!(u, s);
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p wires-net --lib signing_bytes_distinguishes_tenant_unregister`
Expected: FAIL with "no variant or associated item named `Unregister` found".

- [ ] **Step 3: Add the variant + domain**

In `crates/wires-net/src/tenant.rs`, edit the `TenantOp` enum (around line 150). The new variant goes between `Register` and `TopicRegister`:

```rust
#[derive(Debug, Clone, Copy)]
pub enum TenantOp<'a> {
    Register,
    Unregister,
    TopicRegister(&'a [u8; 32]),
    TopicUnregister(&'a [u8; 32]),
    Status,
}
```

Update `TenantOp::domain` to cover the new variant:

```rust
impl TenantOp<'_> {
    fn domain(&self) -> &'static [u8] {
        match self {
            TenantOp::Register => b"wires-tenant-register-v1\0",
            TenantOp::Unregister => b"wires-tenant-unregister-v1\0",
            TenantOp::TopicRegister(_) => b"wires-topic-register-v1\0",
            TenantOp::TopicUnregister(_) => b"wires-topic-unregister-v1\0",
            TenantOp::Status => b"wires-tenant-status-v1\0",
        }
    }

    fn topic_id(&self) -> Option<&[u8; 32]> {
        match self {
            TenantOp::TopicRegister(t) | TenantOp::TopicUnregister(t) => Some(t),
            TenantOp::Register | TenantOp::Unregister | TenantOp::Status => None,
        }
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p wires-net --lib signing_bytes_distinguishes_tenant_unregister`
Expected: PASS.

- [ ] **Step 5: Run the surrounding tests to confirm nothing else broke**

Run: `cargo test -p wires-net --lib tenant::`
Expected: All tenant tests pass (the existing `signing_bytes_distinguishes_topic_ops` will still pass; only the new test exercises the new variant).

- [ ] **Step 6: Commit**

```bash
git add crates/wires-net/src/tenant.rs
git commit -m "wires-net: TenantOp::Unregister + signing domain"
```

---

### Task 2: Add `TenantUnregister` request/response + handler trait method + protocol dispatch

**Files:**
- Modify: `crates/wires-net/src/tenant.rs`

- [ ] **Step 1: Add a failing test that proves the new request round-trips through serde**

Inside `mod tests`, append after the existing `request_serde_roundtrip` test (around line 438):

```rust
#[test]
fn tenant_unregister_request_serde_roundtrip() {
    let req = TenantRequest::Unregister(TenantUnregisterRequest {
        version: 1,
        root_pubkey: [1u8; 32],
        timestamp: 99,
        nonce: [9u8; 16],
        signature: [3u8; 64],
    });
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("\"type\":\"unregister\""), "tag missing: {json}");
    let back: TenantRequest = serde_json::from_str(&json).unwrap();
    match back {
        TenantRequest::Unregister(r) => {
            assert_eq!(r.timestamp, 99);
            assert_eq!(r.root_pubkey, [1u8; 32]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn tenant_unregister_response_serde_roundtrip() {
    let resp = TenantResponse::Unregister(TenantUnregisterResponse {
        ok: true,
        topics_removed: 3,
    });
    let json = serde_json::to_string(&resp).unwrap();
    let back: TenantResponse = serde_json::from_str(&json).unwrap();
    match back {
        TenantResponse::Unregister(r) => {
            assert!(r.ok);
            assert_eq!(r.topics_removed, 3);
        }
        _ => panic!("wrong variant"),
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p wires-net --lib tenant_unregister`
Expected: FAIL with "no variant or associated item named `Unregister`" on `TenantRequest` / `TenantResponse`.

- [ ] **Step 3: Add the new variants to `TenantRequest` and `TenantResponse`**

In `crates/wires-net/src/tenant.rs`, edit the two enums near the top of the file (lines 15–32). Add `Unregister` between `Register` and `TopicRegister` in both:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TenantRequest {
    Register(TenantRegisterRequest),
    Unregister(TenantUnregisterRequest),
    TopicRegister(TopicRegisterRequest),
    TopicUnregister(TopicUnregisterRequest),
    Status(TenantStatusRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TenantResponse {
    Register(TenantRegisterResponse),
    Unregister(TenantUnregisterResponse),
    TopicRegister(TopicRegisterResponse),
    TopicUnregister(TopicUnregisterResponse),
    Status(TenantStatusResponse),
    Error(TenantErrorResponse),
}
```

Then add the new request/response structs. Place them after `TenantRegisterResponse` (around line 53) and before `TopicRegisterRequest`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantUnregisterRequest {
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
pub struct TenantUnregisterResponse {
    pub ok: bool,
    /// Number of topics that were removed from the topic_index as part of this
    /// unregister. Zero when the tenant didn't exist or had no registered topics.
    pub topics_removed: u32,
}
```

- [ ] **Step 4: Add the `handle_unregister` method to `TenantHandler`**

In `crates/wires-net/src/tenant.rs`, edit the `TenantHandler` trait (around line 212):

```rust
pub trait TenantHandler: Send + Sync + 'static {
    fn handle_register(&self, req: TenantRegisterRequest) -> TenantResponse;
    fn handle_unregister(&self, req: TenantUnregisterRequest) -> TenantResponse;
    fn handle_topic_register(&self, req: TopicRegisterRequest) -> TenantResponse;
    fn handle_topic_unregister(&self, req: TopicUnregisterRequest) -> TenantResponse;
    fn handle_status(&self, req: TenantStatusRequest) -> TenantResponse;
}
```

- [ ] **Step 5: Wire the new branch into `TenantProtocol::handle_stream`**

Same file, around line 240 — extend the `match req` arm:

```rust
let resp = match req {
    TenantRequest::Register(r) => self.handler.handle_register(r),
    TenantRequest::Unregister(r) => self.handler.handle_unregister(r),
    TenantRequest::TopicRegister(r) => self.handler.handle_topic_register(r),
    TenantRequest::TopicUnregister(r) => self.handler.handle_topic_unregister(r),
    TenantRequest::Status(r) => self.handler.handle_status(r),
};
```

- [ ] **Step 6: Update the existing test stubs that implement `TenantHandler`**

The two existing in-test handlers (`Acc` in `register_tenant_helper_round_trips` around line 503, and `Acc` in `topic_register_status_unregister_helpers_round_trip` around line 576) will fail to compile because they don't implement `handle_unregister`. Add a stub to each:

In the first `Acc` (around line 503), insert after `handle_register`:

```rust
fn handle_unregister(&self, _r: TenantUnregisterRequest) -> TenantResponse {
    unreachable!()
}
```

In the second `Acc` (around line 576), insert after `handle_register`:

```rust
fn handle_unregister(&self, _r: TenantUnregisterRequest) -> TenantResponse {
    unreachable!()
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p wires-net --lib tenant::`
Expected: All tenant tests pass, including the two new serde round-trip tests.

- [ ] **Step 8: Commit**

```bash
git add crates/wires-net/src/tenant.rs
git commit -m "wires-net: TenantUnregister request/response + protocol dispatch"
```

---

### Task 3: Add `TenantClient::unregister_tenant` + extend the end-to-end client test

**Files:**
- Modify: `crates/wires-net/src/tenant.rs`

- [ ] **Step 1: Add a failing test that drives the new client helper**

In `crates/wires-net/src/tenant.rs`, extend the existing `register_tenant_helper_round_trips` test. After the existing register-then-decode block (around line 564), append (still inside the same `#[tokio::test]` function):

```rust
    // Now unregister: the handler returns a fixed response, we verify the
    // signature was domain-separated for Unregister.
    let resp = client
        .unregister_tenant(host_ep.id(), &root, &host_id, 1234)
        .await
        .unwrap();
    match resp {
        TenantResponse::Unregister(r) => {
            assert!(r.ok);
            assert_eq!(r.topics_removed, 7);
        }
        other => panic!("unexpected response: {other:?}"),
    }
```

And replace the `handle_unregister` stub in the same test's `Acc` (added in Task 2 step 6) with a real implementation:

```rust
fn handle_unregister(&self, req: TenantUnregisterRequest) -> TenantResponse {
    use ed25519_dalek::{Verifier, VerifyingKey};
    let bytes = signing_bytes(
        TenantOp::Unregister,
        &req.root_pubkey,
        req.timestamp,
        &req.nonce,
        &self.host_id,
    );
    let vk = VerifyingKey::from_bytes(&req.root_pubkey).unwrap();
    vk.verify(&bytes, &req.signature.into()).unwrap();
    TenantResponse::Unregister(TenantUnregisterResponse {
        ok: true,
        topics_removed: 7,
    })
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p wires-net --lib register_tenant_helper_round_trips`
Expected: FAIL with "no method named `unregister_tenant`".

- [ ] **Step 3: Wire `TenantOp::Unregister` into `signed_send`'s match**

In `crates/wires-net/src/tenant.rs`, edit the `match op` arm inside `signed_send` (around line 326–359). Add an `Unregister` arm between `Register` and `TopicRegister`:

```rust
let req = match op {
    TenantOp::Register => TenantRequest::Register(TenantRegisterRequest {
        version: 1,
        root_pubkey,
        timestamp: timestamp_ms,
        nonce,
        signature,
    }),
    TenantOp::Unregister => TenantRequest::Unregister(TenantUnregisterRequest {
        version: 1,
        root_pubkey,
        timestamp: timestamp_ms,
        nonce,
        signature,
    }),
    TenantOp::TopicRegister(topic) => TenantRequest::TopicRegister(TopicRegisterRequest {
        version: 1,
        root_pubkey,
        topic_id: *topic,
        timestamp: timestamp_ms,
        nonce,
        signature,
    }),
    TenantOp::TopicUnregister(topic) => {
        TenantRequest::TopicUnregister(TopicUnregisterRequest {
            version: 1,
            root_pubkey,
            topic_id: *topic,
            timestamp: timestamp_ms,
            nonce,
            signature,
        })
    }
    TenantOp::Status => TenantRequest::Status(TenantStatusRequest {
        version: 1,
        root_pubkey,
        timestamp: timestamp_ms,
        nonce,
        signature,
    }),
};
```

- [ ] **Step 4: Add the `unregister_tenant` client helper**

Same file, after the existing `register_tenant` helper (around line 378):

```rust
pub async fn unregister_tenant(
    &self,
    peer: EndpointId,
    root_signer: &dyn RootSigner,
    host_endpoint_id: &[u8; 32],
    timestamp_ms: i64,
) -> Result<TenantResponse> {
    self.signed_send(
        peer,
        TenantOp::Unregister,
        root_signer,
        host_endpoint_id,
        timestamp_ms,
    )
    .await
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p wires-net --lib register_tenant_helper_round_trips`
Expected: PASS. (One iroh cold-start cost; documented in CLAUDE.md.)

- [ ] **Step 6: Run the full tenant test set**

Run: `cargo test -p wires-net --lib tenant::`
Expected: All pass.

- [ ] **Step 7: Commit**

```bash
git add crates/wires-net/src/tenant.rs
git commit -m "wires-net: TenantClient::unregister_tenant helper"
```

---

## Phase B — Registry-level deletion in `wires-host`

### Task 4: `TenantRegistry::delete_tenant`

**Files:**
- Modify: `crates/wires-host/src/tenant_registry.rs`

- [ ] **Step 1: Add the failing test**

In `crates/wires-host/src/tenant_registry.rs`, append at the bottom of the existing `#[cfg(test)] mod tests` block (just before its closing `}`):

```rust
#[test]
fn delete_tenant_drops_record_and_indexed_topics() {
    let tmp = TempDir::new().unwrap();
    let reg = TenantRegistry::open(tmp.path()).unwrap();
    let root_a = [0xAAu8; 32];
    let root_b = [0xBBu8; 32];
    let topic1 = [0x11u8; 32];
    let topic2 = [0x22u8; 32];
    let topic3 = [0x33u8; 32];

    reg.insert_if_absent(
        &root_a,
        TenantRecord {
            registered_at: 1,
            status: TenantStatus::Active,
            retention_budget_bytes: 100,
        },
    )
    .unwrap();
    reg.insert_if_absent(
        &root_b,
        TenantRecord {
            registered_at: 1,
            status: TenantStatus::Active,
            retention_budget_bytes: 100,
        },
    )
    .unwrap();
    reg.register_topic(&root_a, &topic1).unwrap();
    reg.register_topic(&root_a, &topic2).unwrap();
    reg.register_topic(&root_b, &topic3).unwrap();

    let dropped = reg.delete_tenant(&root_a).unwrap();
    assert_eq!(dropped.existed, true);
    let mut topics = dropped.topics_removed;
    topics.sort();
    assert_eq!(topics, vec![topic1, topic2]);

    // Tenant A is gone; tenant B is intact.
    assert!(reg.get(&root_a).unwrap().is_none());
    assert!(reg.get(&root_b).unwrap().is_some());
    assert!(reg.lookup_topic_tenant(&topic1).unwrap().is_none());
    assert!(reg.lookup_topic_tenant(&topic2).unwrap().is_none());
    assert_eq!(reg.lookup_topic_tenant(&topic3).unwrap(), Some(root_b));
}

#[test]
fn delete_tenant_unknown_returns_not_existed() {
    let tmp = TempDir::new().unwrap();
    let reg = TenantRegistry::open(tmp.path()).unwrap();
    let dropped = reg.delete_tenant(&[7u8; 32]).unwrap();
    assert_eq!(dropped.existed, false);
    assert!(dropped.topics_removed.is_empty());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p wires-host --lib delete_tenant`
Expected: FAIL with "no method named `delete_tenant`".

- [ ] **Step 3: Add the result struct and method**

In `crates/wires-host/src/tenant_registry.rs`, add this struct after the existing `TopicRegisterOutcome` enum (around line 44):

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantDeleteOutcome {
    /// Whether a tenant row was found before deletion.
    pub existed: bool,
    /// Every topic_id that was removed from the topic_index as part of this delete.
    pub topics_removed: Vec<[u8; 32]>,
}
```

Add the `delete_tenant` method inside `impl TenantRegistry`, after `unregister_topic` (around line 242):

```rust
/// Remove the tenant row and every topic_index entry that maps to this
/// `root_pubkey`. The two writes happen in separate transactions: topic
/// index first (so routing stops immediately), then the tenant row. Each
/// step is idempotent; calling on an unknown tenant returns
/// `existed: false, topics_removed: vec![]`.
pub fn delete_tenant(&self, root_pubkey: &[u8; 32]) -> Result<TenantDeleteOutcome> {
    // 1. Collect every topic_id owned by this tenant.
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

    // 3. Delete the tenant row.
    let existed: bool = {
        let write = self.tenants_db.begin_write().context(TxnSnafu)?;
        let was_present = {
            match write.open_table(TENANTS) {
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

    Ok(TenantDeleteOutcome {
        existed,
        topics_removed,
    })
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p wires-host --lib delete_tenant`
Expected: PASS (2 new tests).

- [ ] **Step 5: Run the wider `tenant_registry` test set to confirm nothing else broke**

Run: `cargo test -p wires-host --lib tenant_registry`
Expected: All existing tests still pass.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-host/src/tenant_registry.rs
git commit -m "wires-host: TenantRegistry::delete_tenant"
```

---

### Task 5: `clear_tenant` on `PerTenantLogs` and `Retention`

**Files:**
- Modify: `crates/wires-host/src/per_tenant_logs.rs`
- Modify: `crates/wires-host/src/retention.rs`

These are in-memory caches that hold open `redb::Database` handles. Before we delete the tenant directory on disk we need to drop those handles, otherwise the open file descriptors keep the redb files alive (best case) or trigger a write to a now-missing path (worst case). Each `clear_tenant` is just a write-locked HashMap retain.

- [ ] **Step 1: Add the failing test on `PerTenantLogs`**

Append at the bottom of `crates/wires-host/src/per_tenant_logs.rs`'s `#[cfg(test)] mod tests`:

```rust
#[test]
fn clear_tenant_drops_cached_handles() {
    let tmp = TempDir::new().unwrap();
    let logs = PerTenantLogs::new(tmp.path());
    let root_a = [1u8; 32];
    let root_b = [2u8; 32];
    let topic1 = [9u8; 32];
    let topic2 = [10u8; 32];
    let _ = logs.get_or_open(&root_a, &topic1).unwrap();
    let _ = logs.get_or_open(&root_a, &topic2).unwrap();
    let _ = logs.get_or_open(&root_b, &topic1).unwrap();
    assert_eq!(logs.cache_len(), 3);
    logs.clear_tenant(&root_a);
    assert_eq!(logs.cache_len(), 1);
}
```

The test calls a `cache_len` accessor we also need to add (test-only).

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p wires-host --lib per_tenant_logs::tests::clear_tenant_drops_cached_handles`
Expected: FAIL with "no method named `clear_tenant`".

- [ ] **Step 3: Add `clear_tenant` and the test helper**

In `crates/wires-host/src/per_tenant_logs.rs`, add the methods inside `impl PerTenantLogs` (after `get_or_open`):

```rust
/// Drop every cached `TopicLog` handle for this tenant. The caller is
/// responsible for then deleting the on-disk `tenant_dir(root_pubkey)`.
pub fn clear_tenant(&self, root_pubkey: &[u8; 32]) {
    let mut map = self.cache.write().unwrap();
    map.retain(|(root, _topic), _| root != root_pubkey);
}

#[cfg(test)]
pub fn cache_len(&self) -> usize {
    self.cache.read().unwrap().len()
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p wires-host --lib per_tenant_logs::tests::clear_tenant_drops_cached_handles`
Expected: PASS.

- [ ] **Step 5: Add the failing test on `Retention`**

Append at the bottom of `crates/wires-host/src/retention.rs`'s `#[cfg(test)] mod tests`:

```rust
#[test]
fn clear_tenant_drops_cached_index() {
    let tmp = TempDir::new().unwrap();
    let logs = Arc::new(PerTenantLogs::new(tmp.path()));
    let retention = Retention::new(tmp.path(), Arc::clone(&logs));
    let root_a = [1u8; 32];
    let root_b = [2u8; 32];
    let topic = [9u8; 32];

    // Force index creation for both tenants.
    retention
        .on_append(&root_a, &topic, &[7u8; 32], 0, 100, u64::MAX)
        .unwrap();
    retention
        .on_append(&root_b, &topic, &[7u8; 32], 0, 100, u64::MAX)
        .unwrap();
    assert_eq!(retention.cache_len(), 2);
    retention.clear_tenant(&root_a);
    assert_eq!(retention.cache_len(), 1);
}
```

- [ ] **Step 6: Run the test to verify it fails**

Run: `cargo test -p wires-host --lib retention::tests::clear_tenant_drops_cached_index`
Expected: FAIL with "no method named `clear_tenant`".

- [ ] **Step 7: Add `clear_tenant` and the test helper on `Retention`**

In `crates/wires-host/src/retention.rs`, add inside `impl Retention` (after `oldest_retained_at`):

```rust
/// Drop the cached `IngestIndex` for this tenant. The caller is responsible
/// for then deleting `tenants/<root_pubkey_hex>/` on disk.
pub fn clear_tenant(&self, root_pubkey: &[u8; 32]) {
    let mut map = self.indices.write().unwrap();
    map.remove(root_pubkey);
}

#[cfg(test)]
pub fn cache_len(&self) -> usize {
    self.indices.read().unwrap().len()
}
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cargo test -p wires-host --lib retention::tests::clear_tenant_drops_cached_index`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/wires-host/src/per_tenant_logs.rs crates/wires-host/src/retention.rs
git commit -m "wires-host: clear_tenant on PerTenantLogs + Retention"
```

---

### Task 6: `TenantHandlerImpl::handle_unregister`

**Files:**
- Modify: `crates/wires-host/src/tenant_registry.rs`

- [ ] **Step 1: Add the failing test**

Append at the bottom of `crates/wires-host/src/tenant_registry.rs`'s `#[cfg(test)] mod tests`:

```rust
#[test]
fn handle_unregister_drops_tenant_and_fires_hook() {
    use crate::per_tenant_logs::PerTenantLogs;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use std::sync::Arc;
    use std::sync::Mutex;
    use wires_net::tenant::{
        TenantHandler, TenantRegisterRequest, TenantResponse, TenantUnregisterRequest,
    };

    let tmp = TempDir::new().unwrap();
    let reg = Arc::new(TenantRegistry::open(tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(tmp.path()));
    let retention = Arc::new(crate::retention::Retention::new(tmp.path(), logs));

    let signing_key = SigningKey::generate(&mut OsRng);
    let root_pubkey = signing_key.verifying_key().to_bytes();
    let host_endpoint_id = [42u8; 32];
    let now_ms = 1_000_000i64;

    let observed: Arc<Mutex<Vec<([u8; 32], Vec<[u8; 32]>)>>> = Arc::new(Mutex::new(Vec::new()));
    let observed_for_cb = Arc::clone(&observed);

    let handler = TenantHandlerImpl {
        registry: Arc::clone(&reg),
        retention,
        host_endpoint_id,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(move || now_ms),
        on_topic_registered: Arc::new(|_root, _topic| {}),
        on_topic_unregistered: Arc::new(|_root, _topic| {}),
        on_tenant_unregistered: Arc::new(move |root, topics| {
            observed_for_cb.lock().unwrap().push((root, topics));
        }),
    };

    // Register first so we have something to unregister.
    let nonce_reg = [1u8; 16];
    let bytes_reg = wires_net::tenant::signing_bytes(
        TenantOp::Register,
        &root_pubkey,
        now_ms,
        &nonce_reg,
        &host_endpoint_id,
    );
    let sig_reg = signing_key.sign(&bytes_reg).to_bytes();
    let _ = handler.handle_register(TenantRegisterRequest {
        version: 1,
        root_pubkey,
        timestamp: now_ms,
        nonce: nonce_reg,
        signature: sig_reg,
    });
    assert!(reg.get(&root_pubkey).unwrap().is_some());

    // Unregister.
    let nonce_un = [2u8; 16];
    let bytes_un = wires_net::tenant::signing_bytes(
        TenantOp::Unregister,
        &root_pubkey,
        now_ms,
        &nonce_un,
        &host_endpoint_id,
    );
    let sig_un = signing_key.sign(&bytes_un).to_bytes();
    let resp = handler.handle_unregister(TenantUnregisterRequest {
        version: 1,
        root_pubkey,
        timestamp: now_ms,
        nonce: nonce_un,
        signature: sig_un,
    });
    match resp {
        TenantResponse::Unregister(r) => {
            assert!(r.ok);
            // handle_register inserted the caps_topic_id for this tenant
            // (see TenantHandlerImpl::handle_register), so topics_removed
            // must reflect that.
            assert_eq!(r.topics_removed, 1);
        }
        other => panic!("expected Unregister, got {:?}", other),
    }
    // Tenant gone, hook fired with one topic.
    assert!(reg.get(&root_pubkey).unwrap().is_none());
    let obs = observed.lock().unwrap();
    assert_eq!(obs.len(), 1);
    assert_eq!(obs[0].0, root_pubkey);
    assert_eq!(obs[0].1.len(), 1);
}

#[test]
fn handle_unregister_unknown_tenant_returns_ok_false() {
    use crate::per_tenant_logs::PerTenantLogs;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use std::sync::Arc;
    use wires_net::tenant::{TenantHandler, TenantResponse, TenantUnregisterRequest};

    let tmp = TempDir::new().unwrap();
    let reg = Arc::new(TenantRegistry::open(tmp.path()).unwrap());
    let logs = Arc::new(PerTenantLogs::new(tmp.path()));
    let retention = Arc::new(crate::retention::Retention::new(tmp.path(), logs));

    let signing_key = SigningKey::generate(&mut OsRng);
    let root_pubkey = signing_key.verifying_key().to_bytes();
    let host_endpoint_id = [42u8; 32];
    let now_ms = 1_000_000i64;

    let handler = TenantHandlerImpl {
        registry: Arc::clone(&reg),
        retention,
        host_endpoint_id,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(move || now_ms),
        on_topic_registered: Arc::new(|_, _| {}),
        on_topic_unregistered: Arc::new(|_, _| {}),
        on_tenant_unregistered: Arc::new(|_, _| {}),
    };

    let nonce = [9u8; 16];
    let bytes = wires_net::tenant::signing_bytes(
        TenantOp::Unregister,
        &root_pubkey,
        now_ms,
        &nonce,
        &host_endpoint_id,
    );
    let sig = signing_key.sign(&bytes).to_bytes();
    let resp = handler.handle_unregister(TenantUnregisterRequest {
        version: 1,
        root_pubkey,
        timestamp: now_ms,
        nonce,
        signature: sig,
    });
    match resp {
        TenantResponse::Unregister(r) => {
            assert!(!r.ok);
            assert_eq!(r.topics_removed, 0);
        }
        other => panic!("expected Unregister, got {:?}", other),
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p wires-host --lib handle_unregister`
Expected: FAIL with missing field `on_tenant_unregistered` and missing method `handle_unregister`.

- [ ] **Step 3: Add the new field to `TenantHandlerImpl`**

In `crates/wires-host/src/tenant_registry.rs`, edit the `TenantHandlerImpl` struct (around line 309). Add the new field after `on_topic_unregistered`:

```rust
pub struct TenantHandlerImpl {
    pub registry: Arc<TenantRegistry>,
    pub retention: Arc<crate::retention::Retention>,
    pub host_endpoint_id: [u8; 32],
    pub config: TenantHandlerConfig,
    pub now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
    pub on_topic_registered: Arc<dyn Fn([u8; 32], [u8; 32]) + Send + Sync>,
    pub on_topic_unregistered: Arc<dyn Fn([u8; 32], [u8; 32]) + Send + Sync>,
    /// Fires after a successful `handle_unregister` removes the tenant's row
    /// and topic_index entries. `Vec<[u8; 32]>` is the list of topic_ids that
    /// were dropped from the index. The host wires this to clear filesystem
    /// state for the tenant.
    pub on_tenant_unregistered: Arc<dyn Fn([u8; 32], Vec<[u8; 32]>) + Send + Sync>,
}
```

- [ ] **Step 4: Add `handle_unregister` import and method**

In the existing `use wires_net::tenant::{ ... };` block (around line 283), add `TenantUnregisterRequest` and `TenantUnregisterResponse`:

```rust
use wires_net::tenant::{
    TenantErrorCode, TenantErrorResponse, TenantOp, TenantRegisterRequest, TenantRegisterResponse,
    TenantResponse, TenantStatusKind, TenantStatusRequest, TenantStatusResponse,
    TenantUnregisterRequest, TenantUnregisterResponse, TopicRegisterRequest, TopicRegisterResponse,
    TopicUnregisterRequest, TopicUnregisterResponse, signing_bytes,
};
```

Then add the new handler method inside `impl wires_net::tenant::TenantHandler for TenantHandlerImpl`, between `handle_register` and `handle_topic_register` (around line 422):

```rust
fn handle_unregister(&self, req: TenantUnregisterRequest) -> TenantResponse {
    let sig_bytes = signing_bytes(
        TenantOp::Unregister,
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

    match self.registry.delete_tenant(&req.root_pubkey) {
        Ok(outcome) => {
            if outcome.existed {
                (self.on_tenant_unregistered)(req.root_pubkey, outcome.topics_removed.clone());
            }
            TenantResponse::Unregister(TenantUnregisterResponse {
                ok: outcome.existed,
                topics_removed: outcome.topics_removed.len() as u32,
            })
        }
        Err(_) => Self::err(TenantErrorCode::Internal, "tenant delete failed"),
    }
}
```

- [ ] **Step 5: Update existing `handle_register` test stub**

The existing `handle_register_signs_and_records_tenant` test (around line 720) constructs a `TenantHandlerImpl` literal that's now missing the `on_tenant_unregistered` field. Add it:

```rust
let handler = TenantHandlerImpl {
    registry: Arc::clone(&reg),
    retention,
    host_endpoint_id,
    config: TenantHandlerConfig::default(),
    now_ms: Arc::new(move || now_ms),
    on_topic_registered: Arc::new(|_root, _topic| {}),
    on_topic_unregistered: Arc::new(|_root, _topic| {}),
    on_tenant_unregistered: Arc::new(|_root, _topics| {}),
};
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p wires-host --lib handle_unregister`
Expected: PASS (both new tests).

- [ ] **Step 7: Run the full `wires-host` lib test set**

Run: `cargo test -p wires-host --lib`
Expected: All pass.

- [ ] **Step 8: Commit**

```bash
git add crates/wires-host/src/tenant_registry.rs
git commit -m "wires-host: handle_unregister + on_tenant_unregistered hook"
```

---

## Phase C — Host binary wiring

### Task 7: Wire `on_tenant_unregistered` in `main.rs`

**Files:**
- Modify: `crates/wires-host/src/main.rs`

- [ ] **Step 1: Pass cache-clearing + filesystem-cleanup into the handler**

Open `crates/wires-host/src/main.rs`. The `TenantHandlerImpl` literal lives around lines 182–194. Replace the whole block with:

```rust
let subscribe_tx_clone = subscribe_tx.clone();
let logs_for_cb = Arc::clone(&logs);
let retention_for_cb = Arc::clone(&retention);
let data_dir_for_cb = args.data_dir.clone();
let handler = Arc::new(TenantHandlerImpl {
    registry: Arc::clone(&registry),
    retention: Arc::clone(&retention),
    host_endpoint_id: endpoint_id_bytes,
    config: TenantHandlerConfig::default(),
    now_ms: Arc::new(unix_now_ms),
    on_topic_registered: Arc::new(move |_root, topic| {
        let _ = subscribe_tx_clone.send(topic);
    }),
    on_topic_unregistered: Arc::new(|_root, _topic| {
        // v1: subscription stays live; future spec adds a teardown signal.
    }),
    on_tenant_unregistered: Arc::new(move |root, _topics| {
        // Drop in-memory caches first so the open redb handles get released,
        // then remove the on-disk tenant directory. Cache clearing is
        // synchronous; the rm is best-effort and logged on failure.
        logs_for_cb.clear_tenant(&root);
        retention_for_cb.clear_tenant(&root);
        let tenant_dir = data_dir_for_cb.join("tenants").join(hex::encode(root));
        if tenant_dir.exists() {
            if let Err(e) = std::fs::remove_dir_all(&tenant_dir) {
                tracing::warn!(
                    error = %e,
                    dir = %tenant_dir.display(),
                    "failed to remove tenant directory on unregister",
                );
            } else {
                tracing::info!(
                    dir = %tenant_dir.display(),
                    "removed tenant directory on unregister",
                );
            }
        }
    }),
});
```

This compiles only if `hex` is in scope. The crate already depends on `hex` (see `Cargo.toml`); confirm with `cargo build -p wires-host` after the edit.

- [ ] **Step 2: Verify the host still builds**

Run: `cargo build -p wires-host`
Expected: builds clean.

- [ ] **Step 3: Run the wires-host lib tests**

Run: `cargo test -p wires-host --lib`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add crates/wires-host/src/main.rs
git commit -m "wires-host: on_tenant_unregistered drops caches + tenants/<hex>/ dir"
```

---

## Phase D — CLI operator command

### Task 8: `wires host tenant-unregister`

**Files:**
- Modify: `crates/wires-cli/src/main.rs`
- Modify: `crates/wires-cli/src/cmd/host.rs`

- [ ] **Step 1: Add the subcommand to clap**

In `crates/wires-cli/src/main.rs`, edit `enum HostCmd` (around line 95). Add the new variant between `TopicUnregister` and `Status`:

```rust
#[derive(Subcommand)]
enum HostCmd {
    /// Pair with a host: decode a HostTicket, register this tenant (signed by
    /// your local root key), persist the host info.
    Pair {
        /// HostTicket string (base64), or `@<path>` to read from a file.
        #[arg(long)]
        ticket: String,
    },
    /// Register a topic with the paired host so it persists envelopes for it.
    TopicRegister { topic: String },
    /// Unregister a topic: the host stops persisting new envelopes (existing
    /// data is retained until eviction).
    TopicUnregister { topic: String },
    /// Unregister this tenant entirely: the host drops the tenant row, every
    /// topic_index entry for this root, and the on-disk tenant directory.
    /// Clears the local `config.toml` host block on success.
    TenantUnregister {
        /// Skip the interactive confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Print this tenant's status as the host reports it.
    Status,
}
```

And add the dispatch in the `match cli.command` block (around line 139):

```rust
Cmd::Host(HostCmd::TenantUnregister { yes }) => {
    cmd::host::tenant_unregister(&data_dir, yes).await
}
```

- [ ] **Step 2: Add the `tenant_unregister` fn in `cmd/host.rs`**

In `crates/wires-cli/src/cmd/host.rs`, append after `topic_unregister` (around line 169):

```rust
pub async fn tenant_unregister(data_dir: &Path, yes: bool) -> Result<()> {
    if !yes {
        use std::io::Write as _;
        eprint!(
            "This will tell the host to drop this tenant's record, every \
             topic_index entry, and the on-disk tenant directory.\n\
             It will also clear the local config.toml host block.\n\
             Continue? [y/N] "
        );
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).context(IoSnafu)?;
        let a = answer.trim().to_ascii_lowercase();
        if a != "y" && a != "yes" {
            eprintln!("aborted");
            return Ok(());
        }
    }
    let (client, host_eid, host_eid_bytes, root) = open_paired_client(data_dir).await?;
    let resp = client
        .unregister_tenant(host_eid, &root, &host_eid_bytes, unix_now_ms())
        .await
        .context(NetSnafu)?;
    match resp {
        TenantResponse::Unregister(r) => {
            if r.ok {
                println!(
                    "Unregistered tenant on host; host dropped {} topic(s)",
                    r.topics_removed
                );
            } else {
                println!("Host did not have a record for this tenant (already gone)");
            }
        }
        TenantResponse::Error(e) => return Err(host_rejected(e)),
        other => return unexpected(other),
    }

    // Clear the local host block in config.toml so subsequent `wires host *`
    // commands don't keep trying to use a host that just tore us down. Best
    // effort: if the file's gone or unparseable, log and move on — the host
    // side of the unregister already succeeded.
    let cfg_path = data_dir.join("config.toml");
    if let Ok(raw) = std::fs::read_to_string(&cfg_path) {
        if let Ok(mut cfg) = toml::from_str::<NodeConfig>(&raw) {
            cfg.host = None;
            match toml::to_string_pretty(&cfg) {
                Ok(serialized) => {
                    if let Err(e) = std::fs::write(&cfg_path, serialized) {
                        tracing::warn!(error = %e, "failed to rewrite config.toml after tenant-unregister");
                    } else {
                        println!("Cleared host block in {}", cfg_path.display());
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to serialize cleared config.toml after tenant-unregister");
                }
            }
        }
    }
    Ok(())
}
```

- [ ] **Step 3: Verify the CLI builds**

Run: `cargo build -p wires-cli`
Expected: builds clean.

- [ ] **Step 4: Smoke-test the help text**

Run: `cargo run -p wires-cli --quiet -- host tenant-unregister --help`
Expected: clap prints help including `--yes`.

- [ ] **Step 5: Commit**

```bash
git add crates/wires-cli/src/main.rs crates/wires-cli/src/cmd/host.rs
git commit -m "wires-cli: wires host tenant-unregister"
```

---

## Phase E — End-to-end integration test

### Task 9: Full-loop integration test

**Files:**
- Create: `crates/wires-host/tests/tenant_unregister.rs`

This test exercises the wire types, the registry, the filesystem cleanup, and a re-register sequence — proving that an iOS-style "reset → re-bootstrap" loop now works against a single host process.

- [ ] **Step 1: Add the test file**

Create `crates/wires-host/tests/tenant_unregister.rs` with this content:

```rust
//! End-to-end: register → register-topic → unregister → re-register.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use iroh::SecretKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_host::per_tenant_logs::PerTenantLogs;
use wires_host::retention::Retention;
use wires_host::tenant_registry::{TenantHandlerConfig, TenantHandlerImpl, TenantRegistry};
use wires_net::tenant::{ALPN as TENANT_ALPN, TenantClient, TenantProtocol, TenantResponse};
use wires_net::unix_now_ms;

#[tokio::test]
async fn full_tenant_lifecycle_register_unregister_reregister() {
    let _ = tracing_subscriber::fmt::try_init();

    // --- Set up an in-memory host: registry + handler + endpoint + router. ---
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_path_buf();
    let registry = Arc::new(TenantRegistry::open(&data_dir).unwrap());
    let logs = Arc::new(PerTenantLogs::new(&data_dir));
    let retention = Arc::new(Retention::new(&data_dir, Arc::clone(&logs)));

    let host_ep = wires_net::bind_lan(SecretKey::generate(), vec![TENANT_ALPN.to_vec()])
        .await
        .expect("bind_lan host");
    let host_id_bytes: [u8; 32] = host_ep.id().as_bytes().to_owned();

    let logs_cb = Arc::clone(&logs);
    let retention_cb = Arc::clone(&retention);
    let data_dir_cb = data_dir.clone();
    let handler = Arc::new(TenantHandlerImpl {
        registry: Arc::clone(&registry),
        retention: Arc::clone(&retention),
        host_endpoint_id: host_id_bytes,
        config: TenantHandlerConfig::default(),
        now_ms: Arc::new(unix_now_ms),
        on_topic_registered: Arc::new(|_root, _topic| {}),
        on_topic_unregistered: Arc::new(|_root, _topic| {}),
        on_tenant_unregistered: Arc::new(move |root, _topics| {
            logs_cb.clear_tenant(&root);
            retention_cb.clear_tenant(&root);
            let dir = data_dir_cb.join("tenants").join(hex::encode(root));
            let _ = std::fs::remove_dir_all(&dir);
        }),
    });

    let _router = iroh::protocol::Router::builder(host_ep.clone())
        .accept(TENANT_ALPN, TenantProtocol::new(Arc::clone(&handler)))
        .spawn();

    // --- Client side: a fresh signing key + endpoint + TenantClient. ---
    let caller_ep = wires_net::bind_lan(SecretKey::generate(), vec![])
        .await
        .expect("bind_lan caller");
    let client = TenantClient::new(caller_ep);
    let signing_key = SigningKey::generate(&mut OsRng);

    // 1. Register.
    let resp = client
        .register_tenant(host_ep.id(), &signing_key, &host_id_bytes, unix_now_ms())
        .await
        .unwrap();
    assert!(matches!(resp, TenantResponse::Register(ref r) if r.ok));

    // 2. Register a topic.
    let topic = [0x77u8; 32];
    let resp = client
        .register_topic(
            host_ep.id(),
            &signing_key,
            &topic,
            &host_id_bytes,
            unix_now_ms(),
        )
        .await
        .unwrap();
    assert!(matches!(resp, TenantResponse::TopicRegister(ref r) if r.ok));

    // Force the per-tenant log + retention to exist on disk by routing one
    // ingest through them (via direct API; no wire op needed for this test).
    let root_pubkey = signing_key.verifying_key().to_bytes();
    let _ = logs.get_or_open(&root_pubkey, &topic).unwrap();
    retention
        .on_append(&root_pubkey, &topic, &[0u8; 32], 0, 100, u64::MAX)
        .unwrap();
    let tenant_dir = data_dir.join("tenants").join(hex::encode(root_pubkey));
    assert!(tenant_dir.exists(), "tenant dir should exist after appends");

    // 3. Unregister.
    let resp = client
        .unregister_tenant(host_ep.id(), &signing_key, &host_id_bytes, unix_now_ms())
        .await
        .unwrap();
    match resp {
        TenantResponse::Unregister(r) => {
            assert!(r.ok);
            // 1 caps-topic (auto-registered by handle_register) + 1 explicit
            // = 2 topics dropped.
            assert_eq!(r.topics_removed, 2);
        }
        other => panic!("expected Unregister, got {other:?}"),
    }
    // Registry rows gone.
    assert!(registry.get(&root_pubkey).unwrap().is_none());
    assert!(registry.lookup_topic_tenant(&topic).unwrap().is_none());
    // Filesystem cleanup happened via the on_tenant_unregistered callback.
    assert!(!tenant_dir.exists(), "tenant dir should be removed");

    // 4. Re-register against the same host with the same root key.
    let resp = client
        .register_tenant(host_ep.id(), &signing_key, &host_id_bytes, unix_now_ms())
        .await
        .unwrap();
    assert!(matches!(resp, TenantResponse::Register(ref r) if r.ok));
    assert!(registry.get(&root_pubkey).unwrap().is_some());

    // 5. Idempotent unregister: second call after re-register succeeds; a
    // *third* call (with no tenant present) returns ok:false.
    let resp = client
        .unregister_tenant(host_ep.id(), &signing_key, &host_id_bytes, unix_now_ms())
        .await
        .unwrap();
    assert!(matches!(resp, TenantResponse::Unregister(ref r) if r.ok));
    let resp = client
        .unregister_tenant(host_ep.id(), &signing_key, &host_id_bytes, unix_now_ms())
        .await
        .unwrap();
    match resp {
        TenantResponse::Unregister(r) => {
            assert!(!r.ok, "third call should report tenant not present");
            assert_eq!(r.topics_removed, 0);
        }
        other => panic!("expected Unregister, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `cargo test -p wires-host --test tenant_unregister`
Expected: PASS. One iroh cold-start cost; retry once if it fails due to warm-up.

- [ ] **Step 3: Commit**

```bash
git add crates/wires-host/tests/tenant_unregister.rs
git commit -m "wires-host: end-to-end tenant unregister integration test"
```

---

## Phase F — Verification

### Task 10: Workspace-wide checks

**Files:** none (verification only).

- [ ] **Step 1: Workspace build**

Run: `cargo build --workspace`
Expected: builds clean.

- [ ] **Step 2: Workspace lib + integration tests**

Run: `cargo test --workspace`
Expected: all pass. (Retry once if the first run hits an iroh cold-start failure; CLAUDE.md documents this.)

- [ ] **Step 3: Clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: zero warnings. Likely tidy-ups: unused imports if `TenantUnregisterRequest`/`Response` ended up only used in tests of one module, `&Arc<X>` instead of `&X`, etc. Fix in-place.

- [ ] **Step 4: Rustfmt**

Run: `cargo fmt --all`
Expected: idempotent. If it produced a diff, commit it as a separate `chore: rustfmt` commit.

- [ ] **Step 5: Final commit (only if there's a fmt/clippy fix to land)**

```bash
git add -u
git commit -m "chore: clippy/fmt cleanup for tenant-unregister"
```

---

## Notes for the implementer

- This plan does NOT add an iOS surface for tenant-unregister. That belongs in a follow-up plan ("iOS Reset household debug button") that consumes `WiresClient.unregisterTenant` + a SwiftData + Keychain wipe. The host work landed here is the prerequisite.
- This plan does NOT touch the gossip subscription set. After an unregister, the host's `subscribe_tx`-driven gossip tasks are still subscribed to the now-defunct topics. Inbound envelopes get dropped at `routing.rs` because the topic_index lookup returns `None`. That's symmetric with the existing `topic_unregister` behavior ("v1: subscription stays live") and an acceptable v1 cost — the gossip task is cheap, and a host restart drops the stale subscription anyway.
- The handler returns `ok: false, topics_removed: 0` for a missing tenant rather than `TenantNotFound`. This is deliberate: a flaky network retry should still succeed if the first call already removed the tenant. Status RPC keeps `TenantNotFound` because there's no harm in a hard error there.
- The two writes (`topic_index` delete, then `tenants` delete) are NOT in a single redb transaction — they're separate databases. If the host crashes between them, the topic_index entries are gone but the tenant row remains, which is recoverable: the next `tenant-unregister` will idempotently clean up the tenant row and find no topics to remove.
- The local `config.toml` rewrite in the CLI is "best effort." If it fails, the host-side unregister has still succeeded; the user can manually `rm ~/.wires/config.toml` (or its host block) to fully reset.

# wires-mcp per-user retention — design

**Date:** 2026-05-18
**Status:** design, not yet implemented
**Scope:** bound the on-disk size of `wires-mcp`'s per-user message logs with a TTL-based eviction policy and an optional per-user byte budget. The gateway becomes a short-term cache for `wires_tail` rather than an unbounded mirror of every topic the gateway agent has been capped onto.

## Motivation

Today the per-user `NodeRuntime` rooted at `<data_dir>/users/<root>/` writes every inbound envelope on every joined topic to `log_<topic>.redb` via `wires-node::inbound::handle_inbound → wires-store::TopicLog::append`. There is no eviction. The only retention machinery in the workspace is `wires-host`'s `IngestIndex::evict_oldest_until` (per-tenant FIFO eviction by byte budget); it is not wired into agent-side runtimes. Result: a gateway running 24/7 grows monotonically. For an unattended dogfood deploy this is the difference between "fits on workbench" and "fills the disk in a month."

Live tailing for MCP clients is moving to SSE in a separate work stream. After that lands, the local log no longer has to support "client returned after a long disconnect" — its only jobs are:

1. Answer "what happened recently?" for a fresh `wires_tail` call.
2. Buffer live gossip during brief outages.
3. Maintain the runtime's view of reserved-type state (caps already live in `caps.db` separately; this is mainly relevant once `__cap.*` gossip lands).

A short fixed TTL plus a safety-valve byte budget covers all three.

## Goals

1. Per-user TTL on every persisted message in `users/<root>/log_*.redb`. Default 1 hour.
2. Optional per-user byte budget across all topics for that user. Default 50 MiB. Setting it to 0 disables the budget — TTL alone remains in force.
3. Reuse `wires-host`'s `IngestIndex` primitive rather than adding a parallel type. One column added (`ingested_at_ms`), one method added (`evict_older_than`).
4. Eviction runs on every inbound and every local publish, plus a per-runtime periodic sweep so quiet users don't carry stale entries forever.
5. Existing wires-mcp deploys (workbench has data already) survive a one-time backfill on first open with retention enabled. No data lost, no orphaned logs.
6. CLI agents (`wires`) and `wires-ha` keep today's behavior — retention is opt-in via `NodeConfig.retention`.

## Non-goals

- TTL or budget enforcement in `wires-host`. The host already has byte-budget eviction; adding TTL is a future option. This spec only writes the timestamp into the host's IngestIndex so the data is correct for when that future work happens.
- Per-user or per-topic policy overrides. One TTL + one byte budget for the whole gateway.
- Pinning reserved-type messages (`__cap.*`, `__topic.epoch_advance`) against eviction. Today their state effects are applied at inbound time and stored in `caps.db` / `epoch_keys` independently of the topic log, so log eviction doesn't lose state. The day `__cap.*` propagation lands, that design will revisit whether the log itself needs pinning.
- Gap signaling in `wires_tail` responses. The current cursor is per-sender (seq, hash); a tail spanning an evicted boundary silently returns fewer messages. This matches today's behavior under `wires-host` eviction. SSE replaces this path anyway.
- A migration tool. The first-open backfill handles existing on-disk data inline.

## Storage schema change: `IngestIndex` gains `ingested_at_ms`

Current `INGEST_INDEX` row value (76 bytes):

```
[0..32]  topic_id
[32..64] sender
[64..72] seq            (BE u64)
[72..76] bytes          (BE u32)
```

New layout (84 bytes):

```
[0..32]  topic_id
[32..64] sender
[64..72] seq            (BE u64)
[72..76] bytes          (BE u32)
[76..84] ingested_at_ms (BE i64)   ← new
```

`IngestEntry` (Rust struct) gains a matching field. `IngestIndex::record(...)` signature changes to take an explicit timestamp; all call sites pass `now_ms()` from a single helper (`crate::time::now_ms()` or similar — pick one home, don't sprinkle `SystemTime::now()`).

**Backward compat by length-tolerant read.** Decoding accepts both 76-byte legacy rows and 84-byte new rows. Legacy rows decode with `ingested_at_ms = 0`. No migration step needed for existing wires-host databases; the host writes new rows in the 84-byte format from the first record after upgrade. Legacy rows in a host DB age out naturally as `evict_oldest_until` (which doesn't read the timestamp) reclaims them under budget pressure.

**New method:**

```rust
impl IngestIndex {
    /// Remove every entry whose `ingested_at_ms < deadline_ms`. Returns the
    /// dropped entries in ingest order (oldest first). O(k) in the number
    /// of expired entries — stops at the first fresh row.
    pub fn evict_older_than(&self, deadline_ms: i64) -> Result<Vec<IngestEntry>>;
}
```

Same single-write-transaction pattern as `evict_oldest_until`. `INGEST_META.total_bytes` is decremented for each dropped row.

## `RetentionPolicy` and `NodeConfig` wiring

New type in `wires-node`:

```rust
pub struct RetentionPolicy {
    pub ttl: Duration,
    /// 0 = no budget cap (TTL alone enforces).
    pub max_bytes_per_user: u64,
}
```

`NodeConfig` (in wires-node) gains:

```rust
pub retention: Option<RetentionPolicy>,
```

`None` means "no retention enforcement, behave as today." CLI agents and `wires-ha` pass `None`. `wires-mcp`'s `TenantSupervisor` passes `Some(policy)` derived from gateway config when calling `NodeRuntime::open` per user.

When `retention.is_some()`, `NodeRuntime::open`:

1. Opens (or creates) `<data_dir>/ingest_<root>.redb` and wraps it in an `Arc<IngestIndex>`.
2. Runs the migration backfill (see §"Backfill") if the meta flag is unset.
3. Starts a 60-second tokio interval task that calls `sweep()`. Task handle stored on `NodeRuntime`; aborted on drop.

When `retention.is_none()`, none of the above happens — open is byte-identical to today.

## Eviction

A single `NodeRuntime::sweep(now_ms)` method, callable from all three triggers:

```rust
async fn sweep(&self, now_ms: i64) -> Result<()> {
    let Some(policy) = &self.retention else { return Ok(()); };
    let Some(ix) = &self.ingest_index else { return Ok(()); };

    let deadline = now_ms - (policy.ttl.as_millis() as i64);
    let dropped_ttl = ix.evict_older_than(deadline)?;
    for e in &dropped_ttl { self.delete_topic_log_entry(e).await?; }

    if policy.max_bytes_per_user > 0 {
        let dropped_budget = ix.evict_oldest_until(policy.max_bytes_per_user)?;
        for e in &dropped_budget { self.delete_topic_log_entry(e).await?; }
    }
    Ok(())
}
```

`delete_topic_log_entry` looks up the per-topic `TopicLog` for `e.topic_id` and calls `TopicLog::delete(&e.sender, e.seq)`. That method already exists, is idempotent, and returns `0` when the entry is absent — so a crash between IngestIndex-remove and TopicLog-delete recovers cleanly on the next sweep (the index entry is gone; the orphan TopicLog row is deleted by a startup reconciliation pass; see below).

### Triggers

1. **After every successful inbound** — in `wires-node::inbound::handle_inbound`, immediately after the existing `topic_log.append`, when `retention.is_some()`: `ingest_index.record(entry, now_ms())`, then `sweep(now_ms)`.
2. **After every local publish** — in `wires-node::publish` (the path that also calls `topic_log.append` locally), same hook.
3. **Periodic 60s sweep** — the timer task started in `NodeRuntime::open`. Idempotent; calls `sweep(now_ms)`.

### Ordering and crash safety

Within `evict_older_than` / `evict_oldest_until`, the IngestIndex row is removed in the same redb write transaction that returns the dropped entry. The matching `TopicLog::delete` happens after the commit. If the process crashes between the two:

- The IngestIndex entry is gone (no longer eligible for re-eviction).
- The TopicLog row is orphaned — present on disk, invisible to retention.

On next `NodeRuntime::open` with retention enabled, a **startup reconciliation sweep** iterates every per-topic `TopicLog::read_all` and ensures each entry has a matching `IngestIndex` row. Missing rows are inserted with `ingested_at_ms = now_ms()` (the orphan gets a fresh TTL window starting at startup; it will age out normally). The same pass doubles as the migration backfill (§next).

## Backfill for existing wires-mcp deploys

Workbench already has user data on disk in the wires-mcp-data volume. The startup reconciliation sweep handles migration inline:

1. Open `ingest_<root>.redb`. Read `INGEST_META.backfilled` flag.
2. If unset:
   a. Iterate every `log_<topic>.redb` under the user's data dir.
   b. For each entry, insert an `IngestIndex` row with `ingested_at_ms = now_ms()` and `bytes = serialized_message_len`.
   c. Set `backfilled = true` in `INGEST_META`. Commit.
3. If set: skip backfill, still run the orphan-reconciliation pass (cheap if there are no orphans).

Pre-existing messages get a fresh 1h TTL window starting at backfill time and then age out normally. No data loss. No separate migration tool. The flag prevents the O(N) scan from re-running on every restart.

## wires-mcp config

`docker/wires-mcp.toml.example` / operator's `wires-mcp.toml` / `/etc/wires-mcp/config.toml`:

```toml
public_url = "https://mcp.example.com"
bind = "127.0.0.1:10001"
data_dir = "/data"

[retention]
ttl_secs = 3600                  # default 1h; must be > 0 if section present
max_bytes_per_user = 52428800    # default 50 MiB; 0 disables budget
```

`[retention]` section is optional. If absent, defaults apply: `ttl_secs = 3600`, `max_bytes_per_user = 52_428_800`. If present, `ttl_secs` must be > 0 (rejected at config parse time); `max_bytes_per_user` may be 0.

The gateway always enforces retention — there is no "off" switch for the gateway specifically. The `Option<RetentionPolicy>` on `NodeConfig` is the seam that lets non-gateway runtimes opt out; gateway-internal callers always pass `Some(...)`.

## Affected crates

| Crate | Change |
|---|---|
| `wires-store` | `IngestIndex` schema: row size 76 → 84 bytes, length-tolerant read; `IngestEntry` field; `evict_older_than` method; tests. |
| `wires-host` | Call sites updated to pass `now_ms()` to `record`. No behavior change. |
| `wires-node` | `RetentionPolicy` type; `NodeConfig.retention`; per-user `IngestIndex` opened on `NodeRuntime::open` when `Some`; `sweep` method; startup reconciliation/backfill; 60s timer task; inbound + publish hooks. |
| `wires-mcp` | `GatewayConfig` gains a `[retention]` section with defaults; `TenantSupervisor` passes the policy when opening per-user runtimes. |
| `wires-cli`, `wires-ha` | No change (default `retention = None`). |

## Testing

**wires-store:**

- Roundtrip an 84-byte row with non-zero `ingested_at_ms`.
- Length-tolerant read decodes a 76-byte legacy row with `ingested_at_ms = 0`.
- `evict_older_than(deadline)` drops entries with `ingested_at_ms < deadline`, keeps fresh ones, stops at the first fresh row, returns dropped entries in ingest order.
- `evict_older_than` on an empty index returns `Vec::new()`.

**wires-node:**

- `NodeRuntime::open` with `retention = None` opens no IngestIndex and starts no timer (today's behavior).
- `NodeRuntime::open` with `retention = Some(_)` opens the IngestIndex and the timer.
- Inbound path records an IngestIndex entry then calls sweep; with a tight TTL (e.g. 100ms), an aged-out entry is evicted from both IngestIndex and TopicLog.
- Publish path triggers the same record + sweep.
- Budget eviction: append 100 messages of ~50 bytes each with a 1 KiB budget; assert roughly the last 20 remain.
- Startup reconciliation: write a TopicLog entry with no matching IngestIndex row, open the runtime, assert a row is inserted with `ingested_at_ms = now`.
- Backfill flag: on second open, the O(N) scan is skipped.

**wires-mcp:**

- `GatewayConfig` parses `[retention]` section with both keys present, both absent (defaults), and `ttl_secs = 0` (rejected).
- End-to-end: open a per-user runtime via `TenantSupervisor` with `ttl = 100ms`, publish a message, sleep 200ms, run sweep, assert the user's TopicLog is empty.

## Open questions

None that block implementation. Future work to track separately:

- `__cap.*` propagation, when it lands, may need to pin specific reserved-type messages against eviction.
- Host-side TTL eviction is now data-supported (timestamp is in the row) but unimplemented.
- SSE live-tail replaces the current `wires_tail` poll path; once shipped, the local log's role narrows further and these defaults may want to be revisited.

## Spec self-review notes

- The "0 disables budget" rule is mentioned in two places (§goal 2 and §config). Both say the same thing.
- "Startup reconciliation" and "backfill" share the same code path on the first open; spec calls this out in §Backfill step 3.
- Ordering invariant (IngestIndex remove before TopicLog delete) is the opposite of what the brainstorming considered first; the orphan-reconciliation pass is the reason it's safe. Called out in §"Ordering and crash safety."
- `now_ms()` source unspecified beyond "single helper." Plan should pick `std::time::SystemTime` (wall clock, matches all other timestamps in the workspace) and centralize it.

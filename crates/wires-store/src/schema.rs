use redb::TableDefinition;

/// Per-topic message log:
///   key   = (sender_pubkey [32B] || seq_be [8B])  — 40 byte composite
///   value = canonical JSON of WireMessage
pub const TOPIC_LOG: TableDefinition<&[u8], &[u8]> = TableDefinition::new("topic_log");

/// Per-topic high-water-mark index per sender:
///   key   = sender_pubkey [32B]
///   value = (seq_be [8B] || message_hash [32B])
pub const TOPIC_HWM: TableDefinition<&[u8], &[u8]> = TableDefinition::new("topic_hwm");

/// Cap-table keyed by cap_id:
///   key   = cap_id [16B]
///   value = serialized Capability JSON
pub const CAPS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("caps");

/// Revocations:
///   key   = cap_id [16B]
///   value = revoke_message_hash [32B]
pub const REVOKED: TableDefinition<&[u8], &[u8]> = TableDefinition::new("revoked");

/// Epoch keys per topic (one db per topic via `keys.db`):
///   key   = epoch (u32 BE)
///   value = epoch_key [32B]
pub const EPOCH_KEYS: TableDefinition<u32, &[u8]> = TableDefinition::new("epoch_keys");

/// Meta key/value (e.g. topic name).
pub const META: TableDefinition<&str, &str> = TableDefinition::new("meta");

/// Per-fabric FIFO index over ingested messages. Key = u64 BE ingest_seq.
/// Value layout (84 bytes):
///   [0..32]  topic_id
///   [32..64] sender
///   [64..72] seq            (BE u64)
///   [72..76] bytes          (BE u32)
///   [76..84] ingested_at_ms (BE i64)
/// Reads tolerate the legacy 76-byte layout (decoded with `ingested_at_ms = 0`).
pub const INGEST_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("ingest_index");

/// Single-entry table holding (next_ingest_seq u64 BE) || (total_bytes u64 BE) = 16 bytes.
/// Keyed by a fixed marker byte (b"m"). Stored separately to make total-bytes
/// reads/writes cheap.
pub const INGEST_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("ingest_meta");

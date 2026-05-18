//! UniFFI Records and Enums — the types that cross the Rust ↔ Swift boundary.

#[derive(Debug, Clone, uniffi::Record)]
pub struct HostInfo {
    pub endpoint_id_hex: String,
    pub addrs: Vec<String>,
    pub relay: Option<String>,
    pub hint_expires_at_ms: i64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct TenantRegistration {
    pub caps_topic_id_hex: String,
    pub host_endpoint_id_hex: String,
    pub server_time_ms: i64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct UnregisterResult {
    /// True iff the host had a tenant record to remove. False is a successful
    /// no-op (idempotent on retry).
    pub ok: bool,
    /// Number of topic_index entries the host dropped.
    pub topics_removed: u32,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PairRequestPreview {
    pub handle: PendingPairHandle,
    pub agent_pubkey_hex: String,
    pub role: String,
    pub description: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub requested_scopes: Vec<RequestedScopePreview>,
    pub dial_summary: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct RequestedScopePreview {
    pub topic_name: String,
    pub rights: Vec<Right>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct GrantedScope {
    pub topic_id_hex: String,
    pub topic_name: String,
    pub rights: Vec<Right>,
    pub epochs: Vec<EpochKey>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EpochKey {
    pub epoch: u32,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct NewTopic {
    pub topic_id_hex: String,
    pub epoch_0_key: Vec<u8>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PairAckRecord {
    pub installed_cap_id_hex: String,
    pub installed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, uniffi::Record)]
pub struct PendingPairHandle {
    pub id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Right {
    Read,
    Write,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structs_construct() {
        let _ = HostInfo {
            endpoint_id_hex: "00".repeat(32),
            addrs: vec!["1.2.3.4:5".into()],
            relay: None,
            hint_expires_at_ms: 1_700_000_000_000,
        };
        let _ = Right::Read;
        let _ = PairAckRecord {
            installed_cap_id_hex: String::new(),
            installed_at_ms: 0,
        };
    }
}

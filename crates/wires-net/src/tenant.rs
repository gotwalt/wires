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

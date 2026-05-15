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

use std::sync::Arc;

use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointId};
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
    pub fn new(handler: Arc<H>) -> Self {
        Self { handler }
    }

    async fn handle_stream(
        &self,
        mut send: iroh::endpoint::SendStream,
        mut recv: iroh::endpoint::RecvStream,
    ) -> Result<()> {
        let req: TenantRequest = read_frame(&mut recv, MAX_FRAME_LEN).await?;
        let resp = match req {
            TenantRequest::Register(r) => self.handler.handle_register(r),
            TenantRequest::TopicRegister(r) => self.handler.handle_topic_register(r),
            TenantRequest::TopicUnregister(r) => self.handler.handle_topic_unregister(r),
            TenantRequest::Status(r) => self.handler.handle_status(r),
        };
        write_frame(&mut send, &resp).await?;
        send.finish()
            .map_err(std::io::Error::other)
            .context(IoSnafu)?;
        Ok(())
    }
}

impl<H: TenantHandler> iroh::protocol::ProtocolHandler for TenantProtocol<H> {
    async fn accept(
        &self,
        connection: Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        loop {
            let (send, recv) = match connection.accept_bi().await {
                Ok(s) => s,
                Err(_) => return Ok(()),
            };
            if let Err(e) = self.handle_stream(send, recv).await {
                tracing::warn!(error = %e, "tenant handler stream failed");
            }
        }
    }
}

#[derive(Clone)]
pub struct TenantClient {
    endpoint: Endpoint,
}

impl TenantClient {
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    /// Open a bidi stream to `peer` and send a `TenantRequest`. Returns the
    /// response, or an error if the connection fails or the response is
    /// malformed.
    pub async fn send(&self, peer: EndpointId, req: &TenantRequest) -> Result<TenantResponse> {
        let conn = self
            .endpoint
            .connect(peer, ALPN)
            .await
            .map_err(std::io::Error::other)
            .context(IoSnafu)?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(std::io::Error::other)
            .context(IoSnafu)?;
        write_frame(&mut send, req).await?;
        send.finish()
            .map_err(std::io::Error::other)
            .context(IoSnafu)?;
        let resp: TenantResponse = read_frame(&mut recv, MAX_FRAME_LEN).await?;
        Ok(resp)
    }

    /// Sign a `TenantRegisterRequest` with `root_signer` and dial `peer` to
    /// send it. `host_endpoint_id` must be the 32-byte ID of the host at
    /// `peer` (included in the signed bytes per spec §4.2). `timestamp_ms`
    /// should be the caller's current UNIX millis (the host accepts ±60s).
    pub async fn register_tenant(
        &self,
        peer: EndpointId,
        root_signer: &ed25519_dalek::SigningKey,
        host_endpoint_id: &[u8; 32],
        timestamp_ms: i64,
    ) -> Result<TenantResponse> {
        use ed25519_dalek::Signer as _;
        use rand_core::RngCore as _;
        let root_pubkey = root_signer.verifying_key().to_bytes();
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let bytes =
            register_signing_bytes(&root_pubkey, timestamp_ms, &nonce, host_endpoint_id);
        let signature = root_signer.sign(&bytes).to_bytes();
        let req = TenantRequest::Register(TenantRegisterRequest {
            version: 1,
            root_pubkey,
            timestamp: timestamp_ms,
            nonce,
            signature,
        });
        self.send(peer, &req).await
    }

    pub async fn register_topic(
        &self,
        peer: EndpointId,
        root_signer: &ed25519_dalek::SigningKey,
        topic_id: &[u8; 32],
        host_endpoint_id: &[u8; 32],
        timestamp_ms: i64,
    ) -> Result<TenantResponse> {
        use ed25519_dalek::Signer as _;
        use rand_core::RngCore as _;
        let root_pubkey = root_signer.verifying_key().to_bytes();
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let bytes = topic_register_signing_bytes(
            &root_pubkey,
            topic_id,
            timestamp_ms,
            &nonce,
            host_endpoint_id,
        );
        let signature = root_signer.sign(&bytes).to_bytes();
        let req = TenantRequest::TopicRegister(TopicRegisterRequest {
            version: 1,
            root_pubkey,
            topic_id: *topic_id,
            timestamp: timestamp_ms,
            nonce,
            signature,
        });
        self.send(peer, &req).await
    }

    pub async fn unregister_topic(
        &self,
        peer: EndpointId,
        root_signer: &ed25519_dalek::SigningKey,
        topic_id: &[u8; 32],
        host_endpoint_id: &[u8; 32],
        timestamp_ms: i64,
    ) -> Result<TenantResponse> {
        use ed25519_dalek::Signer as _;
        use rand_core::RngCore as _;
        let root_pubkey = root_signer.verifying_key().to_bytes();
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let bytes = topic_unregister_signing_bytes(
            &root_pubkey,
            topic_id,
            timestamp_ms,
            &nonce,
            host_endpoint_id,
        );
        let signature = root_signer.sign(&bytes).to_bytes();
        let req = TenantRequest::TopicUnregister(TopicUnregisterRequest {
            version: 1,
            root_pubkey,
            topic_id: *topic_id,
            timestamp: timestamp_ms,
            nonce,
            signature,
        });
        self.send(peer, &req).await
    }

    pub async fn tenant_status(
        &self,
        peer: EndpointId,
        root_signer: &ed25519_dalek::SigningKey,
        host_endpoint_id: &[u8; 32],
        timestamp_ms: i64,
    ) -> Result<TenantResponse> {
        use ed25519_dalek::Signer as _;
        use rand_core::RngCore as _;
        let root_pubkey = root_signer.verifying_key().to_bytes();
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let bytes = status_signing_bytes(&root_pubkey, timestamp_ms, &nonce, host_endpoint_id);
        let signature = root_signer.sign(&bytes).to_bytes();
        let req = TenantRequest::Status(TenantStatusRequest {
            version: 1,
            root_pubkey,
            timestamp: timestamp_ms,
            nonce,
            signature,
        });
        self.send(peer, &req).await
    }
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

    #[tokio::test]
    async fn register_tenant_helper_round_trips() {
        // Build a tiny TenantHandler that approves any well-signed register.
        use std::sync::Arc;
        struct Acc {
            host_id: [u8; 32],
            now: i64,
        }
        impl TenantHandler for Acc {
            fn handle_register(&self, req: TenantRegisterRequest) -> TenantResponse {
                // Verify the signature so we exercise the convenience function's signing.
                use ed25519_dalek::{Verifier, VerifyingKey};
                let bytes = register_signing_bytes(
                    &req.root_pubkey,
                    req.timestamp,
                    &req.nonce,
                    &self.host_id,
                );
                let vk = VerifyingKey::from_bytes(&req.root_pubkey).unwrap();
                vk.verify(&bytes, &req.signature.into()).unwrap();
                TenantResponse::Register(TenantRegisterResponse {
                    ok: true,
                    host_endpoint_id: hex::encode(self.host_id),
                    server_time: self.now,
                    caps_topic_id: [9u8; 32],
                })
            }
            fn handle_topic_register(&self, _r: TopicRegisterRequest) -> TenantResponse {
                unreachable!()
            }
            fn handle_topic_unregister(&self, _r: TopicUnregisterRequest) -> TenantResponse {
                unreachable!()
            }
            fn handle_status(&self, _r: TenantStatusRequest) -> TenantResponse {
                unreachable!()
            }
        }
        let host_secret = iroh::SecretKey::generate();
        let host_ep = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(host_secret)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let host_id: [u8; 32] = host_ep.id().as_bytes().to_owned();
        let handler = Arc::new(Acc {
            host_id,
            now: 42,
        });
        let _router = iroh::protocol::Router::builder(host_ep.clone())
            .accept(ALPN, TenantProtocol::new(handler))
            .spawn();

        let caller_ep = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(iroh::SecretKey::generate())
            .bind()
            .await
            .unwrap();
        let client = TenantClient::new(caller_ep);
        let root = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let resp = client
            .register_tenant(host_ep.id(), &root, &host_id, 1234)
            .await
            .unwrap();
        match resp {
            TenantResponse::Register(r) => {
                assert!(r.ok);
                assert_eq!(r.server_time, 42);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn topic_register_status_unregister_helpers_round_trip() {
        use std::sync::{Arc, Mutex};
        let topic = [0xAAu8; 32];

        #[derive(Default)]
        struct Acc {
            host_id: [u8; 32],
            registered: Mutex<Vec<[u8; 32]>>,
        }
        impl TenantHandler for Acc {
            fn handle_register(&self, _r: TenantRegisterRequest) -> TenantResponse {
                unreachable!()
            }
            fn handle_topic_register(&self, req: TopicRegisterRequest) -> TenantResponse {
                use ed25519_dalek::{Verifier, VerifyingKey};
                let bytes = topic_register_signing_bytes(
                    &req.root_pubkey,
                    &req.topic_id,
                    req.timestamp,
                    &req.nonce,
                    &self.host_id,
                );
                let vk = VerifyingKey::from_bytes(&req.root_pubkey).unwrap();
                vk.verify(&bytes, &req.signature.into()).unwrap();
                self.registered.lock().unwrap().push(req.topic_id);
                TenantResponse::TopicRegister(TopicRegisterResponse {
                    ok: true,
                    topic_id: req.topic_id,
                })
            }
            fn handle_topic_unregister(&self, req: TopicUnregisterRequest) -> TenantResponse {
                use ed25519_dalek::{Verifier, VerifyingKey};
                let bytes = topic_unregister_signing_bytes(
                    &req.root_pubkey,
                    &req.topic_id,
                    req.timestamp,
                    &req.nonce,
                    &self.host_id,
                );
                let vk = VerifyingKey::from_bytes(&req.root_pubkey).unwrap();
                vk.verify(&bytes, &req.signature.into()).unwrap();
                self.registered.lock().unwrap().retain(|t| t != &req.topic_id);
                TenantResponse::TopicUnregister(TopicUnregisterResponse {
                    ok: true,
                    topic_id: req.topic_id,
                })
            }
            fn handle_status(&self, req: TenantStatusRequest) -> TenantResponse {
                use ed25519_dalek::{Verifier, VerifyingKey};
                let bytes = status_signing_bytes(
                    &req.root_pubkey,
                    req.timestamp,
                    &req.nonce,
                    &self.host_id,
                );
                let vk = VerifyingKey::from_bytes(&req.root_pubkey).unwrap();
                vk.verify(&bytes, &req.signature.into()).unwrap();
                TenantResponse::Status(TenantStatusResponse {
                    registered_at: 1,
                    topic_count: 1,
                    bytes_stored: 0,
                    retention_budget_bytes: 1 << 20,
                    oldest_retained_at: 0,
                    write_rate_limit_per_sec: 1000,
                    status: TenantStatusKind::Active,
                })
            }
        }

        let host_secret = iroh::SecretKey::generate();
        let host_ep = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(host_secret)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let host_id: [u8; 32] = host_ep.id().as_bytes().to_owned();
        let handler = Arc::new(Acc { host_id, registered: Default::default() });
        let _router = iroh::protocol::Router::builder(host_ep.clone())
            .accept(ALPN, TenantProtocol::new(Arc::clone(&handler)))
            .spawn();

        let caller_ep = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(iroh::SecretKey::generate())
            .bind()
            .await
            .unwrap();
        let client = TenantClient::new(caller_ep);
        let root = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

        // Register.
        let r = client
            .register_topic(host_ep.id(), &root, &topic, &host_id, 100)
            .await
            .unwrap();
        assert!(matches!(r, TenantResponse::TopicRegister(_)));
        assert_eq!(handler.registered.lock().unwrap().clone(), vec![topic]);

        // Status.
        let s = client
            .tenant_status(host_ep.id(), &root, &host_id, 101)
            .await
            .unwrap();
        match s {
            TenantResponse::Status(s) => assert_eq!(s.write_rate_limit_per_sec, 1000),
            other => panic!("unexpected response: {other:?}"),
        }

        // Unregister.
        let u = client
            .unregister_topic(host_ep.id(), &root, &topic, &host_id, 102)
            .await
            .unwrap();
        assert!(matches!(u, TenantResponse::TopicUnregister(_)));
        assert!(handler.registered.lock().unwrap().is_empty());
    }
}

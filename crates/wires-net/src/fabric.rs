//! Fabric control protocol — ALPN `/wires/fabric/0`.
//!
//! Synchronous request/response over a single QUIC bidi stream:
//!   client writes one length-prefixed JSON `FabricRequest`, closes send side;
//!   server writes one length-prefixed JSON `FabricResponse`, closes send side.

use serde::{Deserialize, Serialize};

pub const ALPN: &[u8] = b"/wires/fabric/0";

/// Max frame size — generous enough for any single request/response in this
/// protocol; tight enough to prevent abuse.
pub const MAX_FRAME_LEN: u32 = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FabricRequest {
    Register(FabricRegisterRequest),
    Unregister(FabricUnregisterRequest),
    TopicRegister(TopicRegisterRequest),
    TopicUnregister(TopicUnregisterRequest),
    Status(FabricStatusRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FabricResponse {
    Register(FabricRegisterResponse),
    Unregister(FabricUnregisterResponse),
    TopicRegister(TopicRegisterResponse),
    TopicUnregister(TopicUnregisterResponse),
    Status(FabricStatusResponse),
    Error(FabricErrorResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FabricRegisterRequest {
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
pub struct FabricRegisterResponse {
    pub ok: bool,
    pub host_endpoint_id: String,
    pub server_time: i64,
    #[serde(with = "hex::serde")]
    pub caps_topic_id: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FabricUnregisterRequest {
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
pub struct FabricUnregisterResponse {
    pub ok: bool,
    /// Number of topics that were removed from the topic_index as part of this
    /// unregister. Zero when the fabric didn't exist or had no registered topics.
    pub topics_removed: u32,
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
pub struct FabricStatusRequest {
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
pub struct FabricStatusResponse {
    pub registered_at: i64,
    pub topic_count: u32,
    pub bytes_stored: u64,
    pub retention_budget_bytes: u64,
    pub oldest_retained_at: i64,
    pub write_rate_limit_per_sec: u32,
    pub status: FabricStatusKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FabricStatusKind {
    Active,
    Suspended,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FabricErrorResponse {
    pub code: FabricErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FabricErrorCode {
    BadSignature,
    StaleTimestamp,
    ReplayedNonce,
    FabricNotFound,
    FabricSuspended,
    TopicAlreadyRegistered,
    RegistrationRateLimited,
    Internal,
}

/// The five control-plane operations. Each one's signed bytes are domain-
/// separated (spec §4.2) so signatures from one operation can never be
/// replayed as another.
#[derive(Debug, Clone, Copy)]
pub enum FabricOp<'a> {
    Register,
    Unregister,
    TopicRegister(&'a [u8; 32]),
    TopicUnregister(&'a [u8; 32]),
    Status,
}

impl FabricOp<'_> {
    fn domain(&self) -> &'static [u8] {
        match self {
            FabricOp::Register => b"wires-fabric-register-v1\0",
            FabricOp::Unregister => b"wires-fabric-unregister-v1\0",
            FabricOp::TopicRegister(_) => b"wires-topic-register-v1\0",
            FabricOp::TopicUnregister(_) => b"wires-topic-unregister-v1\0",
            FabricOp::Status => b"wires-fabric-status-v1\0",
        }
    }

    fn topic_id(&self) -> Option<&[u8; 32]> {
        match self {
            FabricOp::TopicRegister(t) | FabricOp::TopicUnregister(t) => Some(t),
            FabricOp::Register | FabricOp::Unregister | FabricOp::Status => None,
        }
    }
}

/// Canonical bytes to sign / verify for any fabric control-plane operation.
/// Layout: `domain || root_pubkey || [topic_id] || timestamp_le || nonce || host_endpoint_id`.
pub fn signing_bytes(
    op: FabricOp<'_>,
    root_pubkey: &[u8; 32],
    timestamp: i64,
    nonce: &[u8; 16],
    host_endpoint_id: &[u8; 32],
) -> Vec<u8> {
    let topic = op.topic_id();
    let domain = op.domain();
    let mut out = Vec::with_capacity(domain.len() + 32 + topic.map_or(0, |_| 32) + 8 + 16 + 32);
    out.extend_from_slice(domain);
    out.extend_from_slice(root_pubkey);
    if let Some(t) = topic {
        out.extend_from_slice(t);
    }
    out.extend_from_slice(&timestamp.to_le_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(host_endpoint_id);
    out
}

use std::sync::Arc;

use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointId};
use snafu::ResultExt as _;
use wires_core::RootSigner;

use crate::error::{FabricSignerRejectedSnafu, IoSnafu, Result};
use crate::framing::{read_frame, write_frame};

/// Business-logic hook the host wires in. All methods are synchronous and
/// pure-function from the protocol's perspective: validate, mutate state,
/// return the response. The protocol layer handles framing and stream
/// lifecycle.
pub trait FabricHandler: Send + Sync + 'static {
    fn handle_register(&self, req: FabricRegisterRequest) -> FabricResponse;
    fn handle_unregister(&self, req: FabricUnregisterRequest) -> FabricResponse;
    fn handle_topic_register(&self, req: TopicRegisterRequest) -> FabricResponse;
    fn handle_topic_unregister(&self, req: TopicUnregisterRequest) -> FabricResponse;
    fn handle_status(&self, req: FabricStatusRequest) -> FabricResponse;
}

#[derive(Clone)]
pub struct FabricProtocol<H: FabricHandler> {
    handler: Arc<H>,
}

impl<H: FabricHandler> std::fmt::Debug for FabricProtocol<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FabricProtocol").finish_non_exhaustive()
    }
}

impl<H: FabricHandler> FabricProtocol<H> {
    pub fn new(handler: Arc<H>) -> Self {
        Self { handler }
    }

    async fn handle_stream(
        &self,
        mut send: iroh::endpoint::SendStream,
        mut recv: iroh::endpoint::RecvStream,
    ) -> Result<()> {
        let req: FabricRequest = read_frame(&mut recv, MAX_FRAME_LEN).await?;
        let resp = match req {
            FabricRequest::Register(r) => self.handler.handle_register(r),
            FabricRequest::Unregister(r) => self.handler.handle_unregister(r),
            FabricRequest::TopicRegister(r) => self.handler.handle_topic_register(r),
            FabricRequest::TopicUnregister(r) => self.handler.handle_topic_unregister(r),
            FabricRequest::Status(r) => self.handler.handle_status(r),
        };
        write_frame(&mut send, &resp).await?;
        send.finish()
            .map_err(std::io::Error::other)
            .context(IoSnafu)?;
        Ok(())
    }
}

impl<H: FabricHandler> iroh::protocol::ProtocolHandler for FabricProtocol<H> {
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
                tracing::warn!(error = %e, "fabric handler stream failed");
            }
        }
    }
}

#[derive(Clone)]
pub struct FabricClient {
    endpoint: Endpoint,
}

impl FabricClient {
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    /// Open a bidi stream to `peer` and send a `FabricRequest`. Returns the
    /// response, or an error if the connection fails or the response is
    /// malformed.
    pub async fn send(&self, peer: EndpointId, req: &FabricRequest) -> Result<FabricResponse> {
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
        let resp: FabricResponse = read_frame(&mut recv, MAX_FRAME_LEN).await?;
        Ok(resp)
    }

    /// Sign `op` with `root_signer` and dial `peer` to deliver the matching
    /// `FabricRequest` variant. `host_endpoint_id` must be the 32-byte ID of
    /// the host at `peer` (included in the signed bytes per spec §4.2).
    /// `timestamp_ms` should be the caller's current UNIX millis (the host
    /// accepts ±60s).
    pub async fn signed_send(
        &self,
        peer: EndpointId,
        op: FabricOp<'_>,
        root_signer: &dyn RootSigner,
        host_endpoint_id: &[u8; 32],
        timestamp_ms: i64,
    ) -> Result<FabricResponse> {
        use rand_core::RngCore as _;
        let root_pubkey = root_signer.pubkey();
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let bytes = signing_bytes(op, &root_pubkey, timestamp_ms, &nonce, host_endpoint_id);
        let signature = root_signer
            .sign(&bytes)
            .context(FabricSignerRejectedSnafu)?;
        let req = match op {
            FabricOp::Register => FabricRequest::Register(FabricRegisterRequest {
                version: 1,
                root_pubkey,
                timestamp: timestamp_ms,
                nonce,
                signature,
            }),
            FabricOp::Unregister => FabricRequest::Unregister(FabricUnregisterRequest {
                version: 1,
                root_pubkey,
                timestamp: timestamp_ms,
                nonce,
                signature,
            }),
            FabricOp::TopicRegister(topic) => FabricRequest::TopicRegister(TopicRegisterRequest {
                version: 1,
                root_pubkey,
                topic_id: *topic,
                timestamp: timestamp_ms,
                nonce,
                signature,
            }),
            FabricOp::TopicUnregister(topic) => {
                FabricRequest::TopicUnregister(TopicUnregisterRequest {
                    version: 1,
                    root_pubkey,
                    topic_id: *topic,
                    timestamp: timestamp_ms,
                    nonce,
                    signature,
                })
            }
            FabricOp::Status => FabricRequest::Status(FabricStatusRequest {
                version: 1,
                root_pubkey,
                timestamp: timestamp_ms,
                nonce,
                signature,
            }),
        };
        self.send(peer, &req).await
    }

    pub async fn register_fabric(
        &self,
        peer: EndpointId,
        root_signer: &dyn RootSigner,
        host_endpoint_id: &[u8; 32],
        timestamp_ms: i64,
    ) -> Result<FabricResponse> {
        self.signed_send(
            peer,
            FabricOp::Register,
            root_signer,
            host_endpoint_id,
            timestamp_ms,
        )
        .await
    }

    pub async fn unregister_fabric(
        &self,
        peer: EndpointId,
        root_signer: &dyn RootSigner,
        host_endpoint_id: &[u8; 32],
        timestamp_ms: i64,
    ) -> Result<FabricResponse> {
        self.signed_send(
            peer,
            FabricOp::Unregister,
            root_signer,
            host_endpoint_id,
            timestamp_ms,
        )
        .await
    }

    pub async fn register_topic(
        &self,
        peer: EndpointId,
        root_signer: &dyn RootSigner,
        topic_id: &[u8; 32],
        host_endpoint_id: &[u8; 32],
        timestamp_ms: i64,
    ) -> Result<FabricResponse> {
        self.signed_send(
            peer,
            FabricOp::TopicRegister(topic_id),
            root_signer,
            host_endpoint_id,
            timestamp_ms,
        )
        .await
    }

    pub async fn unregister_topic(
        &self,
        peer: EndpointId,
        root_signer: &dyn RootSigner,
        topic_id: &[u8; 32],
        host_endpoint_id: &[u8; 32],
        timestamp_ms: i64,
    ) -> Result<FabricResponse> {
        self.signed_send(
            peer,
            FabricOp::TopicUnregister(topic_id),
            root_signer,
            host_endpoint_id,
            timestamp_ms,
        )
        .await
    }

    pub async fn fabric_status(
        &self,
        peer: EndpointId,
        root_signer: &dyn RootSigner,
        host_endpoint_id: &[u8; 32],
        timestamp_ms: i64,
    ) -> Result<FabricResponse> {
        self.signed_send(
            peer,
            FabricOp::Status,
            root_signer,
            host_endpoint_id,
            timestamp_ms,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_serde_roundtrip() {
        let req = FabricRequest::Register(FabricRegisterRequest {
            version: 1,
            root_pubkey: [1u8; 32],
            timestamp: 12345,
            nonce: [9u8; 16],
            signature: [3u8; 64],
        });
        let json = serde_json::to_string(&req).unwrap();
        let back: FabricRequest = serde_json::from_str(&json).unwrap();
        match back {
            FabricRequest::Register(r) => {
                assert_eq!(r.timestamp, 12345);
                assert_eq!(r.root_pubkey, [1u8; 32]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn signing_bytes_change_with_each_field() {
        let base = signing_bytes(FabricOp::Register, &[1u8; 32], 1, &[2u8; 16], &[3u8; 32]);
        let diff_root = signing_bytes(FabricOp::Register, &[9u8; 32], 1, &[2u8; 16], &[3u8; 32]);
        let diff_ts = signing_bytes(FabricOp::Register, &[1u8; 32], 2, &[2u8; 16], &[3u8; 32]);
        let diff_nonce = signing_bytes(FabricOp::Register, &[1u8; 32], 1, &[7u8; 16], &[3u8; 32]);
        let diff_host = signing_bytes(FabricOp::Register, &[1u8; 32], 1, &[2u8; 16], &[8u8; 32]);
        assert_ne!(base, diff_root);
        assert_ne!(base, diff_ts);
        assert_ne!(base, diff_nonce);
        assert_ne!(base, diff_host);
    }

    #[test]
    fn signing_bytes_distinguishes_topic_ops() {
        let topic = [4u8; 32];
        let r = signing_bytes(FabricOp::Register, &[1u8; 32], 1, &[2u8; 16], &[3u8; 32]);
        let s = signing_bytes(FabricOp::Status, &[1u8; 32], 1, &[2u8; 16], &[3u8; 32]);
        let tr = signing_bytes(
            FabricOp::TopicRegister(&topic),
            &[1u8; 32],
            1,
            &[2u8; 16],
            &[3u8; 32],
        );
        let tu = signing_bytes(
            FabricOp::TopicUnregister(&topic),
            &[1u8; 32],
            1,
            &[2u8; 16],
            &[3u8; 32],
        );
        assert_ne!(r, s);
        assert_ne!(tr, tu);
        assert_ne!(r, tr);
    }

    #[test]
    fn fabric_unregister_request_serde_roundtrip() {
        let req = FabricRequest::Unregister(FabricUnregisterRequest {
            version: 1,
            root_pubkey: [1u8; 32],
            timestamp: 99,
            nonce: [9u8; 16],
            signature: [3u8; 64],
        });
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            json.contains("\"type\":\"unregister\""),
            "tag missing: {json}"
        );
        let back: FabricRequest = serde_json::from_str(&json).unwrap();
        match back {
            FabricRequest::Unregister(r) => {
                assert_eq!(r.timestamp, 99);
                assert_eq!(r.root_pubkey, [1u8; 32]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn fabric_unregister_response_serde_roundtrip() {
        let resp = FabricResponse::Unregister(FabricUnregisterResponse {
            ok: true,
            topics_removed: 3,
        });
        let json = serde_json::to_string(&resp).unwrap();
        let back: FabricResponse = serde_json::from_str(&json).unwrap();
        match back {
            FabricResponse::Unregister(r) => {
                assert!(r.ok);
                assert_eq!(r.topics_removed, 3);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn signing_bytes_distinguishes_fabric_unregister_from_other_no_topic_ops() {
        let r = signing_bytes(FabricOp::Register, &[1u8; 32], 1, &[2u8; 16], &[3u8; 32]);
        let s = signing_bytes(FabricOp::Status, &[1u8; 32], 1, &[2u8; 16], &[3u8; 32]);
        let u = signing_bytes(FabricOp::Unregister, &[1u8; 32], 1, &[2u8; 16], &[3u8; 32]);
        assert_ne!(u, r);
        assert_ne!(u, s);
    }

    #[tokio::test]
    async fn register_fabric_helper_round_trips() {
        // Build a tiny FabricHandler that approves any well-signed register.
        use std::sync::Arc;
        struct Acc {
            host_id: [u8; 32],
            now: i64,
        }
        impl FabricHandler for Acc {
            fn handle_register(&self, req: FabricRegisterRequest) -> FabricResponse {
                // Verify the signature so we exercise the convenience function's signing.
                use ed25519_dalek::{Verifier, VerifyingKey};
                let bytes = signing_bytes(
                    FabricOp::Register,
                    &req.root_pubkey,
                    req.timestamp,
                    &req.nonce,
                    &self.host_id,
                );
                let vk = VerifyingKey::from_bytes(&req.root_pubkey).unwrap();
                vk.verify(&bytes, &req.signature.into()).unwrap();
                FabricResponse::Register(FabricRegisterResponse {
                    ok: true,
                    host_endpoint_id: hex::encode(self.host_id),
                    server_time: self.now,
                    caps_topic_id: [9u8; 32],
                })
            }
            fn handle_unregister(&self, req: FabricUnregisterRequest) -> FabricResponse {
                use ed25519_dalek::{Verifier, VerifyingKey};
                let bytes = signing_bytes(
                    FabricOp::Unregister,
                    &req.root_pubkey,
                    req.timestamp,
                    &req.nonce,
                    &self.host_id,
                );
                let vk = VerifyingKey::from_bytes(&req.root_pubkey).unwrap();
                vk.verify(&bytes, &req.signature.into()).unwrap();
                FabricResponse::Unregister(FabricUnregisterResponse {
                    ok: true,
                    topics_removed: 7,
                })
            }
            fn handle_topic_register(&self, _r: TopicRegisterRequest) -> FabricResponse {
                unreachable!()
            }
            fn handle_topic_unregister(&self, _r: TopicUnregisterRequest) -> FabricResponse {
                unreachable!()
            }
            fn handle_status(&self, _r: FabricStatusRequest) -> FabricResponse {
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
        let handler = Arc::new(Acc { host_id, now: 42 });
        let _router = iroh::protocol::Router::builder(host_ep.clone())
            .accept(ALPN, FabricProtocol::new(handler))
            .spawn();

        let caller_ep = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(iroh::SecretKey::generate())
            .bind()
            .await
            .unwrap();
        let client = FabricClient::new(caller_ep);
        let root = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let resp = client
            .register_fabric(host_ep.id(), &root, &host_id, 1234)
            .await
            .unwrap();
        match resp {
            FabricResponse::Register(r) => {
                assert!(r.ok);
                assert_eq!(r.server_time, 42);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        // Now unregister: the handler returns a fixed response, we verify the
        // signature was domain-separated for Unregister.
        let resp = client
            .unregister_fabric(host_ep.id(), &root, &host_id, 1234)
            .await
            .unwrap();
        match resp {
            FabricResponse::Unregister(r) => {
                assert!(r.ok);
                assert_eq!(r.topics_removed, 7);
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
        impl FabricHandler for Acc {
            fn handle_register(&self, _r: FabricRegisterRequest) -> FabricResponse {
                unreachable!()
            }
            fn handle_unregister(&self, _r: FabricUnregisterRequest) -> FabricResponse {
                unreachable!()
            }
            fn handle_topic_register(&self, req: TopicRegisterRequest) -> FabricResponse {
                use ed25519_dalek::{Verifier, VerifyingKey};
                let bytes = signing_bytes(
                    FabricOp::TopicRegister(&req.topic_id),
                    &req.root_pubkey,
                    req.timestamp,
                    &req.nonce,
                    &self.host_id,
                );
                let vk = VerifyingKey::from_bytes(&req.root_pubkey).unwrap();
                vk.verify(&bytes, &req.signature.into()).unwrap();
                self.registered.lock().unwrap().push(req.topic_id);
                FabricResponse::TopicRegister(TopicRegisterResponse {
                    ok: true,
                    topic_id: req.topic_id,
                })
            }
            fn handle_topic_unregister(&self, req: TopicUnregisterRequest) -> FabricResponse {
                use ed25519_dalek::{Verifier, VerifyingKey};
                let bytes = signing_bytes(
                    FabricOp::TopicUnregister(&req.topic_id),
                    &req.root_pubkey,
                    req.timestamp,
                    &req.nonce,
                    &self.host_id,
                );
                let vk = VerifyingKey::from_bytes(&req.root_pubkey).unwrap();
                vk.verify(&bytes, &req.signature.into()).unwrap();
                self.registered
                    .lock()
                    .unwrap()
                    .retain(|t| t != &req.topic_id);
                FabricResponse::TopicUnregister(TopicUnregisterResponse {
                    ok: true,
                    topic_id: req.topic_id,
                })
            }
            fn handle_status(&self, req: FabricStatusRequest) -> FabricResponse {
                use ed25519_dalek::{Verifier, VerifyingKey};
                let bytes = signing_bytes(
                    FabricOp::Status,
                    &req.root_pubkey,
                    req.timestamp,
                    &req.nonce,
                    &self.host_id,
                );
                let vk = VerifyingKey::from_bytes(&req.root_pubkey).unwrap();
                vk.verify(&bytes, &req.signature.into()).unwrap();
                FabricResponse::Status(FabricStatusResponse {
                    registered_at: 1,
                    topic_count: 1,
                    bytes_stored: 0,
                    retention_budget_bytes: 1 << 20,
                    oldest_retained_at: 0,
                    write_rate_limit_per_sec: 1000,
                    status: FabricStatusKind::Active,
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
        let handler = Arc::new(Acc {
            host_id,
            registered: Default::default(),
        });
        let _router = iroh::protocol::Router::builder(host_ep.clone())
            .accept(ALPN, FabricProtocol::new(Arc::clone(&handler)))
            .spawn();

        let caller_ep = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(iroh::SecretKey::generate())
            .bind()
            .await
            .unwrap();
        let client = FabricClient::new(caller_ep);
        let root = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

        // Register.
        let r = client
            .register_topic(host_ep.id(), &root, &topic, &host_id, 100)
            .await
            .unwrap();
        assert!(matches!(r, FabricResponse::TopicRegister(_)));
        assert_eq!(handler.registered.lock().unwrap().clone(), vec![topic]);

        // Status.
        let s = client
            .fabric_status(host_ep.id(), &root, &host_id, 101)
            .await
            .unwrap();
        match s {
            FabricResponse::Status(s) => assert_eq!(s.write_rate_limit_per_sec, 1000),
            other => panic!("unexpected response: {other:?}"),
        }

        // Unregister.
        let u = client
            .unregister_topic(host_ep.id(), &root, &topic, &host_id, 102)
            .await
            .unwrap();
        assert!(matches!(u, FabricResponse::TopicUnregister(_)));
        assert!(handler.registered.lock().unwrap().is_empty());
    }
}

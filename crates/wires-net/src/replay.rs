//! Custom QUIC-based replay protocol.
//!
//! Wire format (over a single bidi stream):
//! - Client opens a bidi stream, sends:
//!   [u32 BE length][JSON-serialized ReplayRequest bytes]
//!   then closes the send side.
//! - Server streams a series of frames:
//!   [u32 BE length][JSON-serialized ReplayResponseFrame bytes]
//!   ending with a frame where `msg = None` (end-of-stream sentinel).

use std::collections::HashMap;
use std::sync::Arc;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use wires_core::{MessageHash, WireMessage};

use crate::error::{IoSnafu, ReplayRpcSnafu, Result, SerdeSnafu};

/// ALPN advertised for the wires replay protocol.
pub const ALPN: &[u8] = b"/wires/replay/0";

pub type Pubkey = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayRequest {
    #[serde(with = "hex::serde")]
    pub topic_id: [u8; 32],
    /// Per-sender high-water-mark. Keyed by hex(sender_pubkey).
    pub hwm: HashMap<String, HwmEntry>,
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HwmEntry {
    pub seq: u64,
    #[serde(with = "hex::serde")]
    pub hash: MessageHash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResponseFrame {
    /// `None` signals end-of-stream.
    pub msg: Option<WireMessage>,
}

/// Storage trait the replay server reads from. Implemented by wires-node over
/// its TopicLog set.
pub trait ReplaySource: Send + Sync + 'static {
    fn read_after(
        &self,
        topic_id: &[u8; 32],
        sender: &Pubkey,
        after_seq: Option<u64>,
        limit: usize,
    ) -> std::result::Result<Vec<WireMessage>, Box<dyn std::error::Error + Send + Sync>>;

    fn all_senders_for(
        &self,
        topic_id: &[u8; 32],
    ) -> std::result::Result<Vec<Pubkey>, Box<dyn std::error::Error + Send + Sync>>;
}

/// Replay protocol handler — implements `iroh::protocol::ProtocolHandler`.
#[derive(Clone)]
pub struct ReplayProtocol<S: ReplaySource> {
    source: Arc<S>,
}

impl<S: ReplaySource> std::fmt::Debug for ReplayProtocol<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayProtocol").finish_non_exhaustive()
    }
}

impl<S: ReplaySource> ReplayProtocol<S> {
    pub fn new(source: Arc<S>) -> Self {
        Self { source }
    }

    async fn handle_stream(&self, mut send: SendStream, mut recv: RecvStream) -> Result<()> {
        // Read the request length-prefixed
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf)
            .await
            .map_err(std::io::Error::other)
            .context(IoSnafu)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut req_buf = vec![0u8; len];
        recv.read_exact(&mut req_buf)
            .await
            .map_err(std::io::Error::other)
            .context(IoSnafu)?;
        let req: ReplayRequest = serde_json::from_slice(&req_buf).context(SerdeSnafu)?;

        // Stream missing messages per sender
        let all_senders = self
            .source
            .all_senders_for(&req.topic_id)
            .map_err(|e| anyhow::anyhow!("{e}"))
            .context(ReplayRpcSnafu)?;
        let mut emitted: u32 = 0;
        for sender in all_senders {
            if emitted >= req.limit {
                break;
            }
            let after = req.hwm.get(&hex::encode(sender)).map(|h| h.seq);
            let remaining = (req.limit - emitted) as usize;
            let batch = self
                .source
                .read_after(&req.topic_id, &sender, after, remaining)
                .map_err(|e| anyhow::anyhow!("{e}"))
                .context(ReplayRpcSnafu)?;
            for msg in batch {
                let frame = ReplayResponseFrame { msg: Some(msg) };
                let bytes = serde_json::to_vec(&frame).context(SerdeSnafu)?;
                send.write_all(&(bytes.len() as u32).to_be_bytes())
                    .await
                    .map_err(std::io::Error::other)
                    .context(IoSnafu)?;
                send.write_all(&bytes)
                    .await
                    .map_err(std::io::Error::other)
                    .context(IoSnafu)?;
                emitted += 1;
                if emitted >= req.limit {
                    break;
                }
            }
        }
        // End-of-stream sentinel
        let end = ReplayResponseFrame { msg: None };
        let bytes = serde_json::to_vec(&end).context(SerdeSnafu)?;
        send.write_all(&(bytes.len() as u32).to_be_bytes())
            .await
            .map_err(std::io::Error::other)
            .context(IoSnafu)?;
        send.write_all(&bytes)
            .await
            .map_err(std::io::Error::other)
            .context(IoSnafu)?;
        send.finish()
            .map_err(std::io::Error::other)
            .context(IoSnafu)?;
        Ok(())
    }
}

impl<S: ReplaySource> iroh::protocol::ProtocolHandler for ReplayProtocol<S> {
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
                tracing::warn!(error = %e, "replay handler stream failed");
            }
        }
    }
}

use iroh::{Endpoint, EndpointId};
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct ReplayClient {
    endpoint: Endpoint,
}

impl ReplayClient {
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    /// Open a bidi stream to `peer` and send a `ReplayRequest`. Returns a
    /// channel that receives each `WireMessage` from the server's stream
    /// until the end-of-stream sentinel.
    pub async fn request(
        &self,
        peer: EndpointId,
        request: &ReplayRequest,
    ) -> Result<mpsc::Receiver<WireMessage>> {
        let conn = self
            .endpoint
            .connect(peer, ALPN)
            .await
            .map_err(|e| anyhow::Error::msg(format!("{e}")))
            .context(ReplayRpcSnafu)?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| anyhow::Error::msg(format!("{e}")))
            .context(ReplayRpcSnafu)?;

        let bytes = serde_json::to_vec(request).context(SerdeSnafu)?;
        send.write_all(&(bytes.len() as u32).to_be_bytes())
            .await
            .map_err(std::io::Error::other)
            .context(IoSnafu)?;
        send.write_all(&bytes)
            .await
            .map_err(std::io::Error::other)
            .context(IoSnafu)?;
        send.finish()
            .map_err(std::io::Error::other)
            .context(IoSnafu)?;

        let (tx, rx) = mpsc::channel::<WireMessage>(64);
        tokio::spawn(async move {
            loop {
                let mut len_buf = [0u8; 4];
                if recv.read_exact(&mut len_buf).await.is_err() {
                    break;
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut buf = vec![0u8; len];
                if recv.read_exact(&mut buf).await.is_err() {
                    break;
                }
                let frame: ReplayResponseFrame = match serde_json::from_slice(&buf) {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::warn!(error = %e, "bad replay frame");
                        break;
                    }
                };
                match frame.msg {
                    Some(m) => {
                        if tx.send(m).await.is_err() {
                            break;
                        }
                    }
                    None => break, // end-of-stream
                }
            }
        });
        Ok(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_request_serde_roundtrip() {
        let req = ReplayRequest {
            topic_id: [1u8; 32],
            hwm: {
                let mut m = HashMap::new();
                m.insert(
                    hex::encode([2u8; 32]),
                    HwmEntry {
                        seq: 7,
                        hash: [3u8; 32],
                    },
                );
                m
            },
            limit: 100,
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let back: ReplayRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.topic_id, req.topic_id);
        assert_eq!(back.limit, req.limit);
        assert_eq!(back.hwm.len(), 1);
    }

    #[test]
    fn end_of_stream_frame_serializes() {
        let f = ReplayResponseFrame { msg: None };
        let bytes = serde_json::to_vec(&f).unwrap();
        let back: ReplayResponseFrame = serde_json::from_slice(&bytes).unwrap();
        assert!(back.msg.is_none());
    }
}

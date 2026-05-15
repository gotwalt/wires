//! iroh `ProtocolHandler` for `/wires/pair/0`. One inbound connection per
//! grant attempt: one bidi stream in, one Grant frame in, one Ack-or-Reject
//! frame out, close.

use std::sync::Arc;

use async_trait::async_trait;
use snafu::ResultExt;
use tokio::sync::Mutex;

use super::MAX_FRAME_LEN;
use super::frames::{PairFrame, PairReject, PairRejectCode};
use super::grant::PairGrantEnvelope;

/// Business-logic hook the responder wires in. Called once per inbound Grant
/// frame; returns the frame to send back (Ack or Reject).
#[async_trait]
pub trait PairHandler: Send + Sync + 'static {
    async fn handle_grant(&self, envelope: PairGrantEnvelope) -> PairFrame;
}

/// A `tokio::Mutex` inside `PairProtocol` serializes concurrent dials so the
/// handler observes grants strictly one at a time — a single operator can't
/// race a second `wires pair-approve` against an in-flight install.
#[derive(Clone)]
pub struct PairProtocol<H: PairHandler> {
    handler: Arc<H>,
    serializer: Arc<Mutex<()>>,
}

impl<H: PairHandler> std::fmt::Debug for PairProtocol<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairProtocol").finish_non_exhaustive()
    }
}

impl<H: PairHandler> PairProtocol<H> {
    pub fn new(handler: Arc<H>) -> Self {
        Self {
            handler,
            serializer: Arc::new(Mutex::new(())),
        }
    }

    async fn handle_stream(
        &self,
        mut send: iroh::endpoint::SendStream,
        mut recv: iroh::endpoint::RecvStream,
    ) -> crate::error::Result<()> {
        let frame: PairFrame = crate::framing::read_frame(&mut recv, MAX_FRAME_LEN).await?;

        let response = match frame {
            PairFrame::Grant(envelope) => {
                let _guard = self.serializer.lock().await;
                self.handler.handle_grant(envelope).await
            }
            _ => PairFrame::Reject(PairReject {
                code: PairRejectCode::InternalError,
                message: "expected Grant frame".into(),
            }),
        };

        crate::framing::write_frame(&mut send, &response).await?;
        send.finish()
            .map_err(std::io::Error::other)
            .context(crate::error::IoSnafu)?;
        Ok(())
    }
}

impl<H: PairHandler> iroh::protocol::ProtocolHandler for PairProtocol<H> {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        loop {
            let (send, recv) = match connection.accept_bi().await {
                Ok(s) => s,
                Err(_) => return Ok(()),
            };
            if let Err(e) = self.handle_stream(send, recv).await {
                tracing::warn!(error = %e, "pair handler stream failed");
            }
        }
    }
}

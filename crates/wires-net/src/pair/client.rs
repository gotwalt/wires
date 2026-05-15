//! Dialer side of `/wires/pair/0`. Resolves a [`PairDial`] to an iroh
//! `EndpointAddr`, opens a bidi stream, writes one [`PairFrame::Grant`], and
//! awaits one [`PairFrame::Ack`] or [`PairFrame::Reject`].

use iroh::Endpoint;

use crate::endpoint_id_from_hex;
use crate::error::{NetError, Result};

use super::frames::{PairAck, PairFrame};
use super::grant::PairGrantEnvelope;
use super::request::PairDial;
use super::{ALPN, MAX_FRAME_LEN};

#[derive(Clone)]
pub struct PairClient {
    endpoint: Endpoint,
}

impl PairClient {
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    /// Dial `dial.node_id`, send a Grant frame, await one Ack or Reject frame,
    /// then close. Maps `Reject` into `NetError::PairRejected`.
    pub async fn deliver_grant(
        &self,
        dial: &PairDial,
        envelope: PairGrantEnvelope,
    ) -> Result<PairAck> {
        let node_id = endpoint_id_from_hex(&dial.node_id).ok_or_else(|| NetError::PairDial {
            message: format!("invalid endpoint_id hex: {}", dial.node_id),
            location: snafu::location!(),
        })?;

        let mut endpoint_addr = iroh::EndpointAddr::new(node_id);
        for a in &dial.addrs {
            if let Ok(sa) = a.parse::<std::net::SocketAddr>() {
                endpoint_addr = endpoint_addr.with_ip_addr(sa);
            }
        }
        if let Some(r) = &dial.relay
            && let Ok(url) = r.parse::<iroh::RelayUrl>()
        {
            endpoint_addr = endpoint_addr.with_relay_url(url);
        }

        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.endpoint.connect(endpoint_addr, ALPN),
        )
        .await
        .map_err(|_| NetError::PairDial {
            message: "dial timeout".into(),
            location: snafu::location!(),
        })?
        .map_err(|e| NetError::PairDial {
            message: format!("{e}"),
            location: snafu::location!(),
        })?;

        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| NetError::PairStream {
            message: format!("open_bi: {e}"),
            location: snafu::location!(),
        })?;
        crate::framing::write_frame(&mut send, &PairFrame::Grant(envelope)).await?;
        send.finish().ok();
        let frame: PairFrame = crate::framing::read_frame(&mut recv, MAX_FRAME_LEN).await?;
        match frame {
            PairFrame::Ack(a) => Ok(a),
            PairFrame::Reject(r) => Err(NetError::PairRejected {
                code: r.code,
                message: r.message,
                location: snafu::location!(),
            }),
            PairFrame::Grant(_) => Err(NetError::PairStream {
                message: "server returned Grant frame".into(),
                location: snafu::location!(),
            }),
        }
    }
}

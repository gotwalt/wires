//! Host discovery ticket — a self-contained, base64-encoded JSON artifact
//! distributed by the operator (QR scan, paste, AirDrop, etc.) that carries
//! everything a client needs to dial a `wires-host` over iroh.
//!
//! Replaces the v1 HTTPS `/v1/bootstrap` discovery flow. The ticket has no
//! signature — host trust in wires is availability-only (the receiver verifies
//! caps and decrypts on its end), and a hostile substituted ticket can only
//! DoS, not breach.
//!
//! See `docs/superpowers/specs/2026-05-15-wires-iroh-host-ticket-discovery-design.md`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, ensure};

use crate::error::{
    NetError, Result, TicketBoundsSnafu, TicketDecodeSnafu, TicketInvalidEndpointIdSnafu,
    TicketParseSnafu, TicketUnsupportedVersionSnafu,
};

pub const TICKET_VERSION: u8 = 1;
pub const MAX_TICKET_BYTES: usize = 1024;
pub const MAX_HINT_ADDRS: usize = 8;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostTicket {
    pub version: u8,
    /// Hex iroh EndpointId (matches `PairDial` / `PeerHint` convention).
    pub endpoint_id: String,
    pub addrs: Vec<String>,
    pub relay: Option<String>,
    /// Unix ms after which `addrs`/`relay` are treated as zero-weight hints by
    /// the consumer. `endpoint_id` itself never expires.
    pub hint_expires_at: i64,
}

impl HostTicket {
    /// URL-safe base64 of canonical JSON.
    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self).context(TicketParseSnafu)?;
        ensure!(
            json.len() <= MAX_TICKET_BYTES,
            TicketBoundsSnafu {
                what: "encoded ticket",
                limit: MAX_TICKET_BYTES,
            }
        );
        Ok(URL_SAFE_NO_PAD.encode(&json))
    }

    /// Decode a URL-safe base64 string. Validates `version`, size, the
    /// `endpoint_id` hex shape, and `addrs.len()`.
    pub fn decode(s: &str) -> Result<Self> {
        ensure!(
            s.len() <= MAX_TICKET_BYTES * 2,
            TicketBoundsSnafu {
                what: "encoded ticket",
                limit: MAX_TICKET_BYTES,
            }
        );
        let bytes = URL_SAFE_NO_PAD.decode(s).context(TicketDecodeSnafu)?;
        ensure!(
            bytes.len() <= MAX_TICKET_BYTES,
            TicketBoundsSnafu {
                what: "decoded ticket",
                limit: MAX_TICKET_BYTES,
            }
        );
        let t: HostTicket = serde_json::from_slice(&bytes).context(TicketParseSnafu)?;
        t.check_bounds()?;
        Ok(t)
    }

    fn check_bounds(&self) -> Result<()> {
        ensure!(
            self.version == TICKET_VERSION,
            TicketUnsupportedVersionSnafu {
                version: self.version,
            }
        );
        ensure!(
            self.addrs.len() <= MAX_HINT_ADDRS,
            TicketBoundsSnafu {
                what: "addrs",
                limit: MAX_HINT_ADDRS,
            }
        );
        ensure!(
            self.endpoint_id.len() == 64,
            TicketInvalidEndpointIdSnafu
        );
        let bytes = hex::decode(&self.endpoint_id)
            .ok()
            .ok_or_else(|| NetError::TicketInvalidEndpointId {
                location: snafu::location!(),
            })?;
        iroh::EndpointId::from_bytes(&bytes.as_slice().try_into().expect("len checked"))
            .ok()
            .ok_or_else(|| NetError::TicketInvalidEndpointId {
                location: snafu::location!(),
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a hex endpoint_id from a real iroh SecretKey so it passes
    /// `EndpointId::from_bytes` (which validates the Ed25519 compressed point).
    fn valid_endpoint_id_hex() -> String {
        let sk = iroh::SecretKey::generate();
        hex::encode(sk.public().as_bytes())
    }

    fn sample() -> HostTicket {
        HostTicket {
            version: TICKET_VERSION,
            endpoint_id: valid_endpoint_id_hex(),
            addrs: vec!["127.0.0.1:11204".into(), "192.0.2.5:11204".into()],
            relay: Some("https://relay.example/".into()),
            hint_expires_at: 1_700_000_000_000,
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let t = sample();
        let s = t.encode().unwrap();
        let back = HostTicket::decode(&s).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn rejects_version_other_than_one() {
        let mut t = sample();
        t.version = 2;
        let s = t.encode().unwrap();
        let err = HostTicket::decode(&s).unwrap_err();
        assert!(matches!(err, NetError::TicketUnsupportedVersion { .. }));
    }

    #[test]
    fn rejects_too_many_addrs() {
        let mut t = sample();
        t.addrs = (0..(MAX_HINT_ADDRS + 1))
            .map(|i| format!("127.0.0.{i}:11204"))
            .collect();
        let s = t.encode().unwrap();
        let err = HostTicket::decode(&s).unwrap_err();
        assert!(
            matches!(err, NetError::TicketBounds { what, .. } if what == "addrs"),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_non_hex_endpoint_id() {
        let mut t = sample();
        t.endpoint_id = "z".repeat(64);
        let s = t.encode().unwrap();
        let err = HostTicket::decode(&s).unwrap_err();
        assert!(matches!(err, NetError::TicketInvalidEndpointId { .. }));
    }

    #[test]
    fn rejects_wrong_endpoint_id_length() {
        let mut t = sample();
        t.endpoint_id = "ab".repeat(31); // 62 hex chars
        let s = t.encode().unwrap();
        let err = HostTicket::decode(&s).unwrap_err();
        assert!(matches!(err, NetError::TicketInvalidEndpointId { .. }));
    }

    #[test]
    fn rejects_oversize_token() {
        // Build base64 of a raw oversize buffer directly — the JSON encode
        // path is also guarded, but this exercises the decode-side check in
        // isolation.
        let big = vec![b'a'; MAX_TICKET_BYTES + 100];
        let s = URL_SAFE_NO_PAD.encode(&big);
        let err = HostTicket::decode(&s).unwrap_err();
        assert!(
            matches!(err, NetError::TicketBounds { what, .. } if what == "decoded ticket"),
            "got {err:?}"
        );
    }

    #[test]
    fn hint_expires_at_in_past_still_decodes() {
        let mut t = sample();
        t.hint_expires_at = 0;
        let s = t.encode().unwrap();
        let back = HostTicket::decode(&s).unwrap();
        assert_eq!(back.hint_expires_at, 0);
    }
}

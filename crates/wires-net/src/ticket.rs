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
    TicketParseSnafu, TicketQrRenderSnafu, TicketUnsupportedVersionSnafu,
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

    /// Build a ticket from a live iroh `Endpoint`. Pulls `EndpointId`, direct
    /// socket addrs, and the optional relay url off `endpoint.addr()`.
    pub fn from_endpoint(endpoint: &iroh::Endpoint, hint_ttl: std::time::Duration) -> Result<Self> {
        let endpoint_id = hex::encode(endpoint.id().as_bytes());
        let endpoint_addr = endpoint.addr();
        let mut addrs: Vec<String> = Vec::new();
        let mut relay: Option<String> = None;
        for t in &endpoint_addr.addrs {
            match t {
                iroh::TransportAddr::Ip(sa) => addrs.push(sa.to_string()),
                iroh::TransportAddr::Relay(url) => relay = Some(url.to_string()),
                _ => {}
            }
        }
        // Cap addrs so we never exceed the wire bound.
        if addrs.len() > MAX_HINT_ADDRS {
            addrs.truncate(MAX_HINT_ADDRS);
        }
        let now_ms = crate::unix_now_ms();
        Ok(HostTicket {
            version: TICKET_VERSION,
            endpoint_id,
            addrs,
            relay,
            hint_expires_at: now_ms + hint_ttl.as_millis() as i64,
        })
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
        ensure!(self.endpoint_id.len() == 64, TicketInvalidEndpointIdSnafu);
        let bytes = hex::decode(&self.endpoint_id).ok().ok_or_else(|| {
            NetError::TicketInvalidEndpointId {
                location: snafu::location!(),
            }
        })?;
        iroh::EndpointId::from_bytes(&bytes.as_slice().try_into().expect("len checked"))
            .ok()
            .ok_or_else(|| NetError::TicketInvalidEndpointId {
                location: snafu::location!(),
            })?;
        Ok(())
    }

    /// `HostTicket` → `PeerHint`. Used by the CLI when dispatching
    /// `wires host …` subcommands: the `--ticket` value is decoded into a
    /// `HostTicket`, converted to a `PeerHint`, and handed to
    /// `peer_hint::first_reachable`.
    pub fn to_peer_hint(&self) -> crate::peer_hint::PeerHint {
        crate::peer_hint::PeerHint {
            node_id: self.endpoint_id.clone(),
            addrs: self.addrs.clone(),
            relay: self.relay.clone(),
        }
    }

    /// Render the encoded ticket as an ANSI half-block QR string. Caller
    /// writes it wherever it likes (typically stderr).
    pub fn render_qr_ansi(&self) -> Result<String> {
        let payload = self.encode()?;
        let code = qrcode::QrCode::new(payload.as_bytes()).context(TicketQrRenderSnafu)?;
        let s = code
            .render::<qrcode::render::unicode::Dense1x2>()
            .dark_color(qrcode::render::unicode::Dense1x2::Light)
            .light_color(qrcode::render::unicode::Dense1x2::Dark)
            .build();
        Ok(s)
    }

    /// Render the encoded ticket as a standalone SVG QR. Dark modules are
    /// `#1c1c1c`; light modules are `#ffffff`. Callers that inline this SVG
    /// into HTML and want it to follow the page's text color should
    /// post-process: `str::replace("#1c1c1c", "currentColor")` and
    /// `str::replace("#ffffff", "transparent")`.
    pub fn render_qr_svg(&self) -> Result<String> {
        let payload = self.encode()?;
        let code = qrcode::QrCode::new(payload.as_bytes()).context(TicketQrRenderSnafu)?;
        let svg = code
            .render::<qrcode::render::svg::Color>()
            .quiet_zone(true)
            .dark_color(qrcode::render::svg::Color("#1c1c1c"))
            .light_color(qrcode::render::svg::Color("#ffffff"))
            .build();
        Ok(svg)
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

    #[tokio::test]
    async fn from_endpoint_roundtrips_endpoint_id() {
        use iroh::SecretKey;
        let ep = crate::bind_lan(SecretKey::generate(), vec![])
            .await
            .unwrap();
        let t = HostTicket::from_endpoint(&ep, std::time::Duration::from_secs(60)).unwrap();
        assert_eq!(t.endpoint_id, hex::encode(ep.id().as_bytes()));
        assert_eq!(t.version, TICKET_VERSION);
        assert!(t.hint_expires_at > 0, "hint_expires_at must be set");
        // Round-trip the encoded form.
        let s = t.encode().unwrap();
        let back = HostTicket::decode(&s).unwrap();
        assert_eq!(back.endpoint_id, t.endpoint_id);
    }

    #[test]
    fn to_peer_hint_carries_fields() {
        let t = sample();
        let h = t.to_peer_hint();
        assert_eq!(h.node_id, t.endpoint_id);
        assert_eq!(h.addrs, t.addrs);
        assert_eq!(h.relay, t.relay);
    }

    #[test]
    fn render_qr_ansi_produces_block_art() {
        let t = sample();
        let s = t.render_qr_ansi().unwrap();
        assert!(!s.is_empty(), "rendered QR must be non-empty");
        // Dense1x2 renderer uses half-block characters; sanity-check at least
        // one is present.
        assert!(
            s.chars()
                .any(|c| c == '\u{2580}' || c == '\u{2584}' || c == '\u{2588}'),
            "rendered string should contain block art chars"
        );
    }

    #[test]
    fn render_qr_svg_produces_svg() {
        let t = sample();
        let s = t.render_qr_svg().unwrap();
        assert!(!s.is_empty(), "rendered SVG must be non-empty");
        assert!(
            s.starts_with("<?xml") || s.starts_with("<svg"),
            "expected SVG to start with <?xml or <svg, got {:?}",
            &s[..s.len().min(40)]
        );
        assert!(
            s.contains("<rect") || s.contains("<path"),
            "SVG should contain at least one <rect> or <path>"
        );
        // Sanity-check that the dark/light colors land in the output so the
        // wires-host module's post-processing has something to str::replace on.
        assert!(s.contains("#1c1c1c"), "expected dark color to appear");
        assert!(s.contains("#ffffff"), "expected light color to appear");
    }
}

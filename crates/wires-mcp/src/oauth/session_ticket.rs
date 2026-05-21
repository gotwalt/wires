//! `SessionTicket` — compact QR payload the consent page renders.
//! iOS scans it, parses with `decode_url_safe_b64`, and POSTs to
//! `/oauth/session/probe` so the gateway can dispatch.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionTicket {
    #[serde(rename = "v")]
    pub version: u8,
    #[serde(rename = "k")]
    pub kind: String,
    pub gateway_url: String,
    pub session_id: String,
}

impl SessionTicket {
    pub const KIND: &'static str = "wires.oauth.v1";

    pub fn new(gateway_url: &str, session_id: &str) -> Self {
        Self {
            version: 1,
            kind: Self::KIND.into(),
            gateway_url: gateway_url.trim_end_matches('/').to_string(),
            session_id: session_id.to_string(),
        }
    }

    pub fn encode_url_safe_b64(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("SessionTicket always serializable");
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub fn decode_url_safe_b64(s: &str) -> Result<Self, serde_json::Error> {
        let bytes = URL_SAFE_NO_PAD.decode(s).map_err(|e| {
            use serde::de::Error;
            serde_json::Error::custom(format!("base64: {e}"))
        })?;
        let t: SessionTicket = serde_json::from_slice(&bytes)?;
        if t.kind != Self::KIND {
            use serde::de::Error;
            return Err(serde_json::Error::custom(format!(
                "unknown ticket kind: {}",
                t.kind
            )));
        }
        Ok(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let t = SessionTicket::new("https://mcp.example.com/", "sess-1");
        let s = t.encode_url_safe_b64();
        let back = SessionTicket::decode_url_safe_b64(&s).unwrap();
        // Trailing slash on gateway_url is stripped.
        assert_eq!(back.gateway_url, "https://mcp.example.com");
        assert_eq!(back.session_id, "sess-1");
        assert_eq!(back.kind, SessionTicket::KIND);
        assert_eq!(back.version, 1);
    }

    #[test]
    fn rejects_unknown_kind() {
        let bad = serde_json::json!({"v": 1, "k": "wires.other.v1", "gateway_url": "x", "session_id": "y"});
        let s = URL_SAFE_NO_PAD.encode(bad.to_string());
        let err = SessionTicket::decode_url_safe_b64(&s).unwrap_err();
        assert!(err.to_string().contains("unknown ticket kind"));
    }

    #[test]
    fn rejects_malformed_base64() {
        let err = SessionTicket::decode_url_safe_b64("not!base64!@@").unwrap_err();
        assert!(err.to_string().contains("base64"));
    }

    #[test]
    fn encoded_is_substantially_smaller_than_a_pair_token() {
        // Sanity check: ticket is in the 120-byte ballpark vs hundreds for a PairRequest.
        // Catches accidental schema bloat that would push QR error-correction off a cliff.
        let t = SessionTicket::new("https://mcp.example.com", &"a".repeat(36));
        assert!(t.encode_url_safe_b64().len() < 220);
    }
}

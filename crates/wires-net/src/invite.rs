use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use wires_core::Capability;

use crate::error::{Result, SerdeSnafu};

/// One-shot invite token bundling a signed capability and one-or-more peer
/// hints the recipient can dial to enter the gossip mesh.
///
/// Encoded as URL-safe base64 of canonical JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteToken {
    /// Schema version. Only `1` is currently valid; any other value is rejected
    /// at decode.
    pub version: u8,
    pub cap: Capability,
    /// Ordered list of peers to try. Receivers iterate in order.
    pub peer_hints: Vec<PeerHint>,
    /// Optional HTTPS service-discovery URL the receiver can fetch fresh hints
    /// from if every entry in `peer_hints` fails.
    pub service_discovery_url: Option<String>,
    pub expires: i64,
    /// Single-use token id — receivers SHOULD reject if seen before.
    pub token_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerHint {
    /// Hex of the iroh EndpointId.
    pub node_id: String,
    pub addrs: Vec<String>,
    pub relay: Option<String>,
}

impl InviteToken {
    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self).context(SerdeSnafu)?;
        Ok(base64url_encode(&json))
    }

    pub fn decode(token: &str) -> Result<Self> {
        let bytes = base64url_decode(token).map_err(|_| crate::error::NetError::Serde {
            source: serde_json::from_str::<()>("\"bad base64\"").unwrap_err(),
            location: snafu::location!(),
        })?;
        let tok: InviteToken = serde_json::from_slice(&bytes).context(SerdeSnafu)?;
        if tok.version != 1 {
            return Err(crate::error::NetError::Serde {
                source: serde_json::from_str::<()>("\"unsupported invite-token version\"")
                    .unwrap_err(),
                location: snafu::location!(),
            });
        }
        Ok(tok)
    }
}

// --- base64url (kept verbatim from the prior implementation) --------------

fn base64url_encode(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let chunks = bytes.chunks_exact(3);
    let rem = chunks.remainder().to_vec();
    for chunk in bytes.chunks_exact(3) {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        for i in (0..4).rev() {
            out.push(CHARS[((n >> (6 * i)) & 0x3F) as usize] as char);
        }
    }
    let _ = chunks;
    if !rem.is_empty() {
        let mut buf = [0u8; 3];
        for (i, b) in rem.iter().enumerate() {
            buf[i] = *b;
        }
        let n = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
        let chars_to_emit = match rem.len() {
            1 => 2,
            2 => 3,
            _ => unreachable!(),
        };
        for i in (4 - chars_to_emit..4).rev() {
            out.push(CHARS[((n >> (6 * i)) & 0x3F) as usize] as char);
        }
    }
    out
}

fn base64url_decode(s: &str) -> std::result::Result<Vec<u8>, ()> {
    fn val(c: u8) -> std::result::Result<u32, ()> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err(()),
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i < bytes.len() {
        let mut got = 0;
        let mut chunk = [0u32; 4];
        for j in 0..4 {
            if i + j >= bytes.len() {
                break;
            }
            chunk[j] = val(bytes[i + j])?;
            got += 1;
        }
        if got == 0 {
            break;
        }
        let n = (chunk[0] << 18) | (chunk[1] << 12) | (chunk[2] << 6) | chunk[3];
        if got >= 2 {
            out.push(((n >> 16) & 0xFF) as u8);
        }
        if got >= 3 {
            out.push(((n >> 8) & 0xFF) as u8);
        }
        if got == 4 {
            out.push((n & 0xFF) as u8);
        }
        i += 4;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use wires_core::cap::Right;

    fn signed_cap() -> Capability {
        let root = SigningKey::generate(&mut OsRng);
        let mut cap = Capability::new_unsigned(
            [5u8; 32],
            vec!["home.*".into()],
            vec![Right::Read],
            0,
            Some(1_000_000),
        );
        cap.sign(&root).unwrap();
        cap
    }

    #[test]
    fn base64url_roundtrip() {
        let cases: &[&[u8]] = &[
            b"",
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            b"abcde",
            b"abcdef",
            &[0u8, 255, 128, 1, 2, 3, 4, 5, 6, 7],
        ];
        for input in cases {
            let encoded = base64url_encode(input);
            let back = base64url_decode(&encoded).unwrap();
            assert_eq!(&back, input, "roundtrip failed for {input:?}");
        }
    }

    #[test]
    fn invite_token_roundtrip() {
        let tok = InviteToken {
            version: 1,
            cap: signed_cap(),
            peer_hints: vec![
                PeerHint {
                    node_id: "deadbeef".into(),
                    addrs: vec!["127.0.0.1:11204".into()],
                    relay: None,
                },
                PeerHint {
                    node_id: "feedface".into(),
                    addrs: vec![],
                    relay: Some("https://relay.example/".into()),
                },
            ],
            service_discovery_url: Some("https://discovery.example/v1/bootstrap".into()),
            expires: 1_000_000,
            token_id: "tk-1".into(),
        };
        let encoded = tok.encode().unwrap();
        let back = InviteToken::decode(&encoded).unwrap();
        assert_eq!(back.token_id, "tk-1");
        assert_eq!(back.peer_hints.len(), 2);
        assert_eq!(
            back.peer_hints[1].relay.as_deref(),
            Some("https://relay.example/")
        );
        assert_eq!(
            back.service_discovery_url.as_deref(),
            Some("https://discovery.example/v1/bootstrap")
        );
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let tok = InviteToken {
            version: 99,
            cap: signed_cap(),
            peer_hints: vec![],
            service_discovery_url: None,
            expires: 0,
            token_id: "x".into(),
        };
        let encoded = tok.encode().unwrap();
        assert!(InviteToken::decode(&encoded).is_err());
    }

    #[test]
    fn decode_rejects_invalid_base64() {
        assert!(InviteToken::decode("!!not-base64!!").is_err());
    }
}

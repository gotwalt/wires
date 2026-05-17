//! Pair-request decoding for the iOS app. Verifies the agent's ed25519
//! signature and converts the wire type into a Swift-friendly preview.

use uuid::Uuid;
use wires_net::pair::PairRequest;

use crate::error::{InvalidPairRequestSnafu, WiresError};
use crate::types::{PairRequestPreview, PendingPairHandle, RequestedScopePreview, Right};

/// Decoded request plus a fresh handle. Caller stores the raw `PairRequest`
/// (which carries the ephemeral X25519 pubkey, nonce, and dial info needed
/// later) keyed by `handle.id`.
pub struct ParsedRequest {
    pub handle: PendingPairHandle,
    pub request: PairRequest,
    pub preview: PairRequestPreview,
}

pub fn parse_pair_request(payload: &str) -> Result<ParsedRequest, WiresError> {
    let req: PairRequest = PairRequest::decode(payload).map_err(|e| {
        InvalidPairRequestSnafu {
            message: format!("{e}"),
        }
        .build()
    })?;
    req.verify().map_err(|e| {
        InvalidPairRequestSnafu {
            message: format!("{e}"),
        }
        .build()
    })?;

    let handle = PendingPairHandle {
        id: Uuid::new_v4().to_string(),
    };
    let preview = PairRequestPreview {
        handle: handle.clone(),
        agent_pubkey_hex: hex::encode(req.agent_pubkey),
        role: req.manifest.role.clone(),
        description: req.manifest.description.clone(),
        issued_at_ms: req.issued_at,
        expires_at_ms: req.expires,
        requested_scopes: req
            .manifest
            .requested_scopes
            .iter()
            .map(|s| RequestedScopePreview {
                topic_name: s.topic_name.clone(),
                rights: s
                    .rights
                    .iter()
                    .map(|r| match r {
                        wires_core::cap::Right::Read => Right::Read,
                        wires_core::cap::Right::Write => Right::Write,
                    })
                    .collect(),
            })
            .collect(),
        dial_summary: format!("{} ({} addrs)", req.dial.node_id, req.dial.addrs.len()),
    };
    Ok(ParsedRequest {
        handle,
        request: req,
        preview,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use wires_net::pair::{PairDial, PairManifest, PairRequest, RequestedScope};

    fn signed_request_payload() -> String {
        let sk = SigningKey::generate(&mut OsRng);
        let mut req = PairRequest {
            version: 1,
            agent_pubkey: sk.verifying_key().to_bytes(),
            agent_x25519: [9u8; 32],
            ephemeral_x25519: [7u8; 32],
            dial: PairDial {
                node_id: "00".repeat(32),
                addrs: vec!["127.0.0.1:1234".into()],
                relay: None,
            },
            manifest: PairManifest {
                role: "email".into(),
                description: "Gmail".into(),
                requested_scopes: vec![RequestedScope {
                    topic_name: "mail.inbox".into(),
                    rights: vec![wires_core::cap::Right::Read, wires_core::cap::Right::Write],
                }],
            },
            nonce: [3u8; 32],
            issued_at: 1_700_000_000_000,
            expires: 1_700_000_000_000 + 5 * 60 * 1000,
            signature: [0u8; 64],
        };
        req.sign(&sk).unwrap();
        req.encode().unwrap()
    }

    #[test]
    fn parses_and_verifies() {
        let s = signed_request_payload();
        let parsed = parse_pair_request(&s).unwrap();
        assert_eq!(parsed.preview.role, "email");
        assert_eq!(parsed.preview.requested_scopes.len(), 1);
        assert_eq!(parsed.preview.requested_scopes[0].topic_name, "mail.inbox");
        assert_eq!(parsed.preview.requested_scopes[0].rights.len(), 2);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_pair_request("nope").is_err());
    }

    #[test]
    fn rejects_tampered_signature() {
        // Decode → mutate one byte → re-encode → parse: the decode-side
        // bounds check passes but verify() rejects.
        let s = signed_request_payload();
        let mut req = PairRequest::decode(&s).unwrap();
        req.signature[0] ^= 0x01;
        let tampered = req.encode().unwrap();
        assert!(parse_pair_request(&tampered).is_err());
    }
}

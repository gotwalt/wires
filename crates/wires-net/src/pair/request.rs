//! `PairRequest` — the token Bob publishes for the operator to scan, and its
//! sign/verify/encode/decode round-trip.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, ensure};

use crate::error::{
    NetError, PairBoundsSnafu, PairInvalidCharsSnafu, PairSignatureSnafu, PairTokenDecodeSnafu,
    PairUnsupportedVersionSnafu, Result, SerdeSnafu,
};

pub const MAX_TOKEN_BYTES: usize = 4 * 1024;
pub const MAX_ROLE_LEN: usize = 32;
pub const MAX_DESCRIPTION_LEN: usize = 256;
pub const MAX_SCOPES: usize = 16;
pub const MAX_TOPIC_NAME_LEN: usize = 128;
pub const MIN_TTL_MS: i64 = 60_000;
pub const MAX_TTL_MS: i64 = 60 * 60 * 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRequest {
    pub version: u8,
    #[serde(with = "hex::serde")]
    pub agent_pubkey: [u8; 32],
    #[serde(with = "hex::serde")]
    pub agent_x25519: [u8; 32],
    #[serde(with = "hex::serde")]
    pub ephemeral_x25519: [u8; 32],
    pub dial: PairDial,
    pub manifest: PairManifest,
    #[serde(with = "hex::serde")]
    pub nonce: [u8; 32],
    pub issued_at: i64,
    pub expires: i64,
    #[serde(with = "hex::serde")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairDial {
    pub node_id: String,
    pub addrs: Vec<String>,
    pub relay: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairManifest {
    pub role: String,
    pub description: String,
    pub requested_scopes: Vec<RequestedScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestedScope {
    pub topic_name: String,
    pub rights: Vec<wires_core::cap::Right>,
}

impl PairRequest {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct View<'a> {
            version: u8,
            #[serde(with = "hex::serde")]
            agent_pubkey: &'a [u8; 32],
            #[serde(with = "hex::serde")]
            agent_x25519: &'a [u8; 32],
            #[serde(with = "hex::serde")]
            ephemeral_x25519: &'a [u8; 32],
            dial: &'a PairDial,
            manifest: &'a PairManifest,
            #[serde(with = "hex::serde")]
            nonce: &'a [u8; 32],
            issued_at: i64,
            expires: i64,
        }
        let v = View {
            version: self.version,
            agent_pubkey: &self.agent_pubkey,
            agent_x25519: &self.agent_x25519,
            ephemeral_x25519: &self.ephemeral_x25519,
            dial: &self.dial,
            manifest: &self.manifest,
            nonce: &self.nonce,
            issued_at: self.issued_at,
            expires: self.expires,
        };
        serde_json::to_vec(&v).context(SerdeSnafu)
    }

    pub fn sign(&mut self, agent_sk: &SigningKey) -> Result<()> {
        let bytes = self.signing_bytes()?;
        self.signature = agent_sk.sign(&bytes).to_bytes();
        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&self.agent_pubkey)
            .ok()
            .ok_or_else(|| NetError::PairSignature {
                location: snafu::location!(),
            })?;
        let sig = Signature::from_bytes(&self.signature);
        let bytes = self.signing_bytes()?;
        ensure!(vk.verify(&bytes, &sig).is_ok(), PairSignatureSnafu);
        Ok(())
    }

    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self).context(SerdeSnafu)?;
        ensure!(
            json.len() <= MAX_TOKEN_BYTES,
            PairBoundsSnafu {
                what: "encoded token",
                limit: MAX_TOKEN_BYTES
            }
        );
        Ok(URL_SAFE_NO_PAD.encode(&json))
    }

    pub fn decode(token: &str) -> Result<Self> {
        ensure!(
            token.len() <= MAX_TOKEN_BYTES * 2,
            PairBoundsSnafu {
                what: "encoded token",
                limit: MAX_TOKEN_BYTES
            }
        );
        let bytes = URL_SAFE_NO_PAD
            .decode(token)
            .context(PairTokenDecodeSnafu)?;
        let tok: PairRequest = serde_json::from_slice(&bytes).context(SerdeSnafu)?;
        tok.check_bounds()?;
        Ok(tok)
    }

    fn check_bounds(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            PairUnsupportedVersionSnafu {
                version: self.version
            }
        );
        ensure!(
            !self.manifest.role.is_empty() && self.manifest.role.len() <= MAX_ROLE_LEN,
            PairBoundsSnafu {
                what: "manifest.role",
                limit: MAX_ROLE_LEN
            }
        );
        ensure!(
            self.manifest
                .role
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            PairInvalidCharsSnafu {
                field: "manifest.role"
            }
        );
        ensure!(
            !self.manifest.description.is_empty()
                && self.manifest.description.len() <= MAX_DESCRIPTION_LEN,
            PairBoundsSnafu {
                what: "manifest.description",
                limit: MAX_DESCRIPTION_LEN
            }
        );
        ensure!(
            !self.manifest.requested_scopes.is_empty()
                && self.manifest.requested_scopes.len() <= MAX_SCOPES,
            PairBoundsSnafu {
                what: "manifest.requested_scopes",
                limit: MAX_SCOPES
            }
        );
        for scope in &self.manifest.requested_scopes {
            ensure!(
                !scope.topic_name.is_empty() && scope.topic_name.len() <= MAX_TOPIC_NAME_LEN,
                PairBoundsSnafu {
                    what: "scope.topic_name",
                    limit: MAX_TOPIC_NAME_LEN
                }
            );
        }
        let ttl = self.expires.saturating_sub(self.issued_at);
        ensure!(
            (MIN_TTL_MS..=MAX_TTL_MS).contains(&ttl),
            PairBoundsSnafu {
                what: "ttl",
                limit: MAX_TTL_MS as usize
            }
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn sample(now: i64) -> (PairRequest, SigningKey) {
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
                role: "chat-agent".into(),
                description: "Bob".into(),
                requested_scopes: vec![RequestedScope {
                    topic_name: "home.notes".into(),
                    rights: vec![wires_core::cap::Right::Read, wires_core::cap::Right::Write],
                }],
            },
            nonce: [3u8; 32],
            issued_at: now,
            expires: now + 5 * 60 * 1000,
            signature: [0u8; 64],
        };
        req.sign(&sk).unwrap();
        (req, sk)
    }

    #[test]
    fn encode_decode_roundtrip() {
        let (req, _) = sample(1_700_000_000_000);
        let s = req.encode().unwrap();
        let back = PairRequest::decode(&s).unwrap();
        assert_eq!(back.agent_pubkey, req.agent_pubkey);
        assert_eq!(back.manifest.role, "chat-agent");
        assert_eq!(back.signature, req.signature);
    }

    #[test]
    fn signature_verifies() {
        let (req, _) = sample(1_700_000_000_000);
        req.verify().unwrap();
    }

    #[test]
    fn tampered_role_invalidates() {
        let (mut req, _) = sample(1_700_000_000_000);
        req.manifest.role = "evil-agent".into();
        assert!(req.verify().is_err());
    }

    #[test]
    fn tampered_pubkey_invalidates() {
        let (mut req, _) = sample(1_700_000_000_000);
        req.agent_pubkey = [0xff; 32];
        assert!(req.verify().is_err());
    }

    #[test]
    fn rejects_version_other_than_one() {
        let (mut req, _) = sample(1_700_000_000_000);
        req.version = 2;
        let s = req.encode().unwrap();
        assert!(PairRequest::decode(&s).is_err());
    }

    #[test]
    fn rejects_oversize_description() {
        let (mut req, sk) = sample(1_700_000_000_000);
        req.manifest.description = "x".repeat(MAX_DESCRIPTION_LEN + 1);
        req.sign(&sk).unwrap();
        let s = req.encode().unwrap();
        assert!(PairRequest::decode(&s).is_err());
    }

    #[test]
    fn rejects_ttl_below_min() {
        let now = 1_700_000_000_000;
        let (mut req, sk) = sample(now);
        req.expires = now + 1000;
        req.sign(&sk).unwrap();
        let s = req.encode().unwrap();
        assert!(PairRequest::decode(&s).is_err());
    }

    #[test]
    fn rejects_role_with_disallowed_chars() {
        let (mut req, sk) = sample(1_700_000_000_000);
        req.manifest.role = "chat agent".into();
        req.sign(&sk).unwrap();
        let s = req.encode().unwrap();
        assert!(PairRequest::decode(&s).is_err());
    }

    #[test]
    fn signing_bytes_covers_every_non_signature_field() {
        let now = 1_700_000_000_000;
        let (req, _) = sample(now);
        let baseline = req.signing_bytes().unwrap();

        let mut m = req.clone();
        m.version = 2;
        assert_ne!(m.signing_bytes().unwrap(), baseline, "version not covered");

        let mut m = req.clone();
        m.agent_pubkey = [0xff; 32];
        assert_ne!(
            m.signing_bytes().unwrap(),
            baseline,
            "agent_pubkey not covered"
        );

        let mut m = req.clone();
        m.agent_x25519 = [0xff; 32];
        assert_ne!(
            m.signing_bytes().unwrap(),
            baseline,
            "agent_x25519 not covered"
        );

        let mut m = req.clone();
        m.ephemeral_x25519 = [0xff; 32];
        assert_ne!(
            m.signing_bytes().unwrap(),
            baseline,
            "ephemeral_x25519 not covered"
        );

        let mut m = req.clone();
        m.dial.node_id = "ff".repeat(32);
        assert_ne!(
            m.signing_bytes().unwrap(),
            baseline,
            "dial.node_id not covered"
        );

        let mut m = req.clone();
        m.dial.addrs = vec!["10.0.0.1:9999".into()];
        assert_ne!(
            m.signing_bytes().unwrap(),
            baseline,
            "dial.addrs not covered"
        );

        let mut m = req.clone();
        m.dial.relay = Some("https://relay.example".into());
        assert_ne!(
            m.signing_bytes().unwrap(),
            baseline,
            "dial.relay not covered"
        );

        let mut m = req.clone();
        m.manifest.role = "other-role".into();
        assert_ne!(
            m.signing_bytes().unwrap(),
            baseline,
            "manifest.role not covered"
        );

        let mut m = req.clone();
        m.manifest.description = "different".into();
        assert_ne!(
            m.signing_bytes().unwrap(),
            baseline,
            "manifest.description not covered"
        );

        let mut m = req.clone();
        m.manifest.requested_scopes[0].topic_name = "mail.inbox".into();
        assert_ne!(
            m.signing_bytes().unwrap(),
            baseline,
            "requested_scopes not covered"
        );

        let mut m = req.clone();
        m.nonce = [0xff; 32];
        assert_ne!(m.signing_bytes().unwrap(), baseline, "nonce not covered");

        let mut m = req.clone();
        m.issued_at = now + 1;
        assert_ne!(
            m.signing_bytes().unwrap(),
            baseline,
            "issued_at not covered"
        );

        let mut m = req.clone();
        m.expires = now + 6 * 60 * 1000;
        assert_ne!(m.signing_bytes().unwrap(), baseline, "expires not covered");

        // signature itself MUST NOT be covered (otherwise sign() is recursive)
        let mut m = req.clone();
        m.signature = [0xff; 64];
        assert_eq!(
            m.signing_bytes().unwrap(),
            baseline,
            "signature must be excluded"
        );
    }
}

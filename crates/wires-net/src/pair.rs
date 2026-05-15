//! Responder-driven pairing — ALPN `/wires/pair/0`.
//!
//! See `docs/superpowers/specs/2026-05-15-wires-responder-driven-pairing-design.md`.

use ed25519_dalek::{Signature, SigningKey, Signer, VerifyingKey, Verifier};
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, ensure};
use x25519_dalek::StaticSecret;
use wires_core::Capability;

use crate::error::{
    NetError, PairBoundsSnafu, PairCryptoSnafu, PairInvalidCharsSnafu, PairSignatureSnafu,
    PairUnsupportedVersionSnafu, Result, SerdeSnafu,
};
use crate::invite::PeerHint;

pub const ALPN: &[u8] = b"/wires/pair/0";

pub const MAX_FRAME_LEN: u32 = 64 * 1024;
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
            .ok_or_else(|| NetError::PairSignature { location: snafu::location!() })?;
        let sig = Signature::from_bytes(&self.signature);
        let bytes = self.signing_bytes()?;
        ensure!(vk.verify(&bytes, &sig).is_ok(), PairSignatureSnafu);
        Ok(())
    }

    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self).context(SerdeSnafu)?;
        ensure!(
            json.len() <= MAX_TOKEN_BYTES,
            PairBoundsSnafu { what: "encoded token", limit: MAX_TOKEN_BYTES }
        );
        Ok(crate::base64url::encode(&json))
    }

    pub fn decode(token: &str) -> Result<Self> {
        ensure!(
            token.len() <= MAX_TOKEN_BYTES * 2,
            PairBoundsSnafu { what: "encoded token", limit: MAX_TOKEN_BYTES }
        );
        let bytes = crate::base64url::decode(token).map_err(|_| NetError::Serde {
            source: serde_json::from_str::<()>("\"bad base64\"").unwrap_err(),
            location: snafu::location!(),
        })?;
        let tok: PairRequest = serde_json::from_slice(&bytes).context(SerdeSnafu)?;
        tok.check_bounds()?;
        Ok(tok)
    }

    fn check_bounds(&self) -> Result<()> {
        ensure!(self.version == 1, PairUnsupportedVersionSnafu { version: self.version });
        ensure!(
            !self.manifest.role.is_empty() && self.manifest.role.len() <= MAX_ROLE_LEN,
            PairBoundsSnafu { what: "manifest.role", limit: MAX_ROLE_LEN }
        );
        ensure!(
            self.manifest.role.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            PairInvalidCharsSnafu { field: "manifest.role" }
        );
        ensure!(
            !self.manifest.description.is_empty()
                && self.manifest.description.len() <= MAX_DESCRIPTION_LEN,
            PairBoundsSnafu { what: "manifest.description", limit: MAX_DESCRIPTION_LEN }
        );
        ensure!(
            !self.manifest.requested_scopes.is_empty()
                && self.manifest.requested_scopes.len() <= MAX_SCOPES,
            PairBoundsSnafu { what: "manifest.requested_scopes", limit: MAX_SCOPES }
        );
        for scope in &self.manifest.requested_scopes {
            ensure!(
                !scope.topic_name.is_empty() && scope.topic_name.len() <= MAX_TOPIC_NAME_LEN,
                PairBoundsSnafu { what: "scope.topic_name", limit: MAX_TOPIC_NAME_LEN }
            );
        }
        let ttl = self.expires.saturating_sub(self.issued_at);
        ensure!(
            ttl >= MIN_TTL_MS && ttl <= MAX_TTL_MS,
            PairBoundsSnafu { what: "ttl", limit: MAX_TTL_MS as usize }
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairGrant {
    pub version: u8,
    #[serde(with = "hex::serde")]
    pub root_pubkey: [u8; 32],
    pub cap: Capability,
    pub topic_keys: Vec<TopicEpochKey>,
    pub topic_names: Vec<TopicNameEntry>,
    pub host: Option<HostInfo>,
    #[serde(with = "hex::serde")]
    pub nonce: [u8; 32],
    pub issued_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicEpochKey {
    #[serde(with = "hex::serde")]
    pub topic_id: [u8; 32],
    pub epoch: u32,
    #[serde(with = "hex::serde")]
    pub key: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicNameEntry {
    #[serde(with = "hex::serde")]
    pub topic_id: [u8; 32],
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub peer_hints: Vec<PeerHint>,
    pub service_discovery_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairGrantEnvelope {
    #[serde(with = "hex::serde")]
    pub root_pubkey: [u8; 32],
    /// Sealed-box output: prepended-ephemeral-pubkey || ChaCha20-Poly1305(content).
    pub sealed_payload: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub signature: [u8; 64],
}

/// Domain separator for the pair-grant sealed-box AAD. Prevents cross-protocol
/// confusion if the same ephemeral key were ever reused elsewhere.
const PAIR_SEAL_AAD: &[u8] = b"wires.pair.v1";

impl PairGrantEnvelope {
    /// Build an envelope from `grant`: seal `grant` to Bob's `recipient_ephemeral_x25519`,
    /// then sign over (root_pubkey || sealed_payload) with `root_sk`.
    pub fn seal_and_sign(
        grant: &PairGrant,
        recipient_ephemeral_x25519: &[u8; 32],
        root_sk: &SigningKey,
    ) -> Result<Self> {
        let content = serde_json::to_vec(grant).context(SerdeSnafu)?;
        let sealed_payload = wires_crypto::sealed::seal_to(
            recipient_ephemeral_x25519,
            &grant.nonce,
            &grant.root_pubkey,
            0,
            &content,
            PAIR_SEAL_AAD,
        )
        .context(PairCryptoSnafu)?;

        let mut to_sign = Vec::with_capacity(32 + sealed_payload.len());
        to_sign.extend_from_slice(&grant.root_pubkey);
        to_sign.extend_from_slice(&sealed_payload);
        let signature = root_sk.sign(&to_sign).to_bytes();

        Ok(Self {
            root_pubkey: grant.root_pubkey,
            sealed_payload,
            signature,
        })
    }

    /// Verify the outer signature, then sealed-box-decrypt with `recipient_sk`.
    /// Caller verifies inner-payload invariants (`nonce`, `issued_at`, etc.)
    /// after parsing.
    pub fn open_and_verify(
        &self,
        recipient_sk: &StaticSecret,
        expected_nonce: &[u8; 32],
    ) -> Result<PairGrant> {
        let vk = VerifyingKey::from_bytes(&self.root_pubkey)
            .ok()
            .ok_or_else(|| NetError::PairSignature {
                location: snafu::location!(),
            })?;
        let mut to_verify = Vec::with_capacity(32 + self.sealed_payload.len());
        to_verify.extend_from_slice(&self.root_pubkey);
        to_verify.extend_from_slice(&self.sealed_payload);
        let sig = Signature::from_bytes(&self.signature);
        ensure!(vk.verify(&to_verify, &sig).is_ok(), PairSignatureSnafu);

        let content = wires_crypto::sealed::open_sealed(
            recipient_sk,
            expected_nonce,
            &self.root_pubkey,
            0,
            &self.sealed_payload,
            PAIR_SEAL_AAD,
        )
        .context(PairCryptoSnafu)?;
        let grant: PairGrant = serde_json::from_slice(&content).context(SerdeSnafu)?;
        Ok(grant)
    }
}

#[cfg(test)]
mod grant_tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use wires_core::cap::Right;
    use x25519_dalek::{PublicKey as XPub, StaticSecret as XSk};

    fn sample_grant(root_pk: [u8; 32], cap: Capability, nonce: [u8; 32]) -> PairGrant {
        PairGrant {
            version: 1,
            root_pubkey: root_pk,
            cap,
            topic_keys: vec![TopicEpochKey {
                topic_id: [4u8; 32],
                epoch: 0,
                key: [5u8; 32],
            }],
            topic_names: vec![TopicNameEntry {
                topic_id: [4u8; 32],
                name: "home.notes".into(),
            }],
            host: None,
            nonce,
            issued_at: 1_700_000_000_000,
        }
    }

    fn signed_cap(root_sk: &SigningKey, bob_pk: [u8; 32]) -> Capability {
        let mut cap = Capability::new_unsigned(
            bob_pk,
            vec!["home.notes".into()],
            vec![Right::Read, Right::Write],
            1_700_000_000_000,
            None,
        );
        cap.sign(root_sk).unwrap();
        cap
    }

    #[test]
    fn seal_and_open_roundtrip() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_pk = root_sk.verifying_key().to_bytes();
        let bob_ephemeral_sk = XSk::random_from_rng(OsRng);
        let bob_ephemeral_pk = XPub::from(&bob_ephemeral_sk).to_bytes();

        let nonce = [9u8; 32];
        let grant = sample_grant(root_pk, signed_cap(&root_sk, [7u8; 32]), nonce);

        let env = PairGrantEnvelope::seal_and_sign(&grant, &bob_ephemeral_pk, &root_sk).unwrap();
        let opened = env.open_and_verify(&bob_ephemeral_sk, &nonce).unwrap();
        assert_eq!(opened.nonce, nonce);
        assert_eq!(opened.cap.agent, [7u8; 32]);
    }

    #[test]
    fn tampered_signature_rejected() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_pk = root_sk.verifying_key().to_bytes();
        let bob_ephemeral_sk = XSk::random_from_rng(OsRng);
        let bob_ephemeral_pk = XPub::from(&bob_ephemeral_sk).to_bytes();

        let nonce = [9u8; 32];
        let grant = sample_grant(root_pk, signed_cap(&root_sk, [7u8; 32]), nonce);
        let mut env = PairGrantEnvelope::seal_and_sign(&grant, &bob_ephemeral_pk, &root_sk).unwrap();
        env.signature[0] ^= 0x01;
        assert!(env.open_and_verify(&bob_ephemeral_sk, &nonce).is_err());
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_pk = root_sk.verifying_key().to_bytes();
        let bob_sk = XSk::random_from_rng(OsRng);
        let bob_pk = XPub::from(&bob_sk).to_bytes();
        let mallory_sk = XSk::random_from_rng(OsRng);

        let nonce = [9u8; 32];
        let grant = sample_grant(root_pk, signed_cap(&root_sk, [7u8; 32]), nonce);
        let env = PairGrantEnvelope::seal_and_sign(&grant, &bob_pk, &root_sk).unwrap();
        assert!(env.open_and_verify(&mallory_sk, &nonce).is_err());
    }

    #[test]
    fn wrong_nonce_aad_fails() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_pk = root_sk.verifying_key().to_bytes();
        let bob_sk = XSk::random_from_rng(OsRng);
        let bob_pk = XPub::from(&bob_sk).to_bytes();
        let grant = sample_grant(root_pk, signed_cap(&root_sk, [7u8; 32]), [9u8; 32]);
        let env = PairGrantEnvelope::seal_and_sign(&grant, &bob_pk, &root_sk).unwrap();
        assert!(env.open_and_verify(&bob_sk, &[8u8; 32]).is_err());
    }
}

#[cfg(test)]
mod request_tests {
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

        // version
        let mut m = req.clone(); m.version = 2;
        assert_ne!(m.signing_bytes().unwrap(), baseline, "version not covered");
        // agent_pubkey
        let mut m = req.clone(); m.agent_pubkey = [0xff; 32];
        assert_ne!(m.signing_bytes().unwrap(), baseline, "agent_pubkey not covered");
        // agent_x25519
        let mut m = req.clone(); m.agent_x25519 = [0xff; 32];
        assert_ne!(m.signing_bytes().unwrap(), baseline, "agent_x25519 not covered");
        // ephemeral_x25519
        let mut m = req.clone(); m.ephemeral_x25519 = [0xff; 32];
        assert_ne!(m.signing_bytes().unwrap(), baseline, "ephemeral_x25519 not covered");
        // dial.node_id
        let mut m = req.clone(); m.dial.node_id = "ff".repeat(32);
        assert_ne!(m.signing_bytes().unwrap(), baseline, "dial.node_id not covered");
        // dial.addrs
        let mut m = req.clone(); m.dial.addrs = vec!["10.0.0.1:9999".into()];
        assert_ne!(m.signing_bytes().unwrap(), baseline, "dial.addrs not covered");
        // dial.relay
        let mut m = req.clone(); m.dial.relay = Some("https://relay.example".into());
        assert_ne!(m.signing_bytes().unwrap(), baseline, "dial.relay not covered");
        // manifest.role
        let mut m = req.clone(); m.manifest.role = "other-role".into();
        assert_ne!(m.signing_bytes().unwrap(), baseline, "manifest.role not covered");
        // manifest.description
        let mut m = req.clone(); m.manifest.description = "different".into();
        assert_ne!(m.signing_bytes().unwrap(), baseline, "manifest.description not covered");
        // manifest.requested_scopes
        let mut m = req.clone(); m.manifest.requested_scopes[0].topic_name = "mail.inbox".into();
        assert_ne!(m.signing_bytes().unwrap(), baseline, "requested_scopes not covered");
        // nonce
        let mut m = req.clone(); m.nonce = [0xff; 32];
        assert_ne!(m.signing_bytes().unwrap(), baseline, "nonce not covered");
        // issued_at
        let mut m = req.clone(); m.issued_at = now + 1;
        assert_ne!(m.signing_bytes().unwrap(), baseline, "issued_at not covered");
        // expires
        let mut m = req.clone(); m.expires = now + 6 * 60 * 1000;
        assert_ne!(m.signing_bytes().unwrap(), baseline, "expires not covered");

        // signature itself MUST NOT be covered (otherwise sign() is recursive)
        let mut m = req.clone(); m.signature = [0xff; 64];
        assert_eq!(m.signing_bytes().unwrap(), baseline, "signature must be excluded");
    }
}

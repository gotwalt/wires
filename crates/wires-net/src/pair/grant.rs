//! `PairGrant` — the operator's signed, sealed reply: cap, epoch keys, topic
//! names, optional host info. Travels inside `PairGrantEnvelope`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, ensure};
use wires_core::{Capability, RootSigner};
use x25519_dalek::StaticSecret;

use crate::error::{
    NetError, PairCryptoSnafu, PairSignatureSnafu, PairSignerRejectedSnafu, Result, SerdeSnafu,
};
use crate::peer_hint::PeerHint;

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
    /// then sign over (root_pubkey || sealed_payload) with `root`.
    pub fn seal_and_sign(
        grant: &PairGrant,
        recipient_ephemeral_x25519: &[u8; 32],
        root: &dyn RootSigner,
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
        let signature = root.sign(&to_sign).context(PairSignerRejectedSnafu)?;

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
mod tests {
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
        let mut env =
            PairGrantEnvelope::seal_and_sign(&grant, &bob_ephemeral_pk, &root_sk).unwrap();
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

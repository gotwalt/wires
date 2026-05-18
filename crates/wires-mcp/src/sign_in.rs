//! `SignInChallenge` — what the returning-user QR encodes. The iOS app
//! signs the canonical JSON (with `signature` zeroed) using the household
//! root ed25519 and POSTs the signature back to /oauth/signin/assertion.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignInChallenge {
    pub version: u8,
    pub kind: String,           // always "wires.signin.v1"
    pub gateway_url: String,
    pub session_id: String,
    pub nonce: String,          // hex of 32 bytes
    pub issued_at: i64,
    pub expires: i64,
}

impl SignInChallenge {
    pub const KIND: &'static str = "wires.signin.v1";

    pub fn new(gateway_url: &str, session_id: &str, nonce: [u8; 32], now_ms: i64, ttl_ms: i64) -> Self {
        Self {
            version: 1,
            kind: Self::KIND.into(),
            gateway_url: gateway_url.trim_end_matches('/').to_string(),
            session_id: session_id.to_string(),
            nonce: hex::encode(nonce),
            issued_at: now_ms,
            expires: now_ms + ttl_ms,
        }
    }

    /// Canonical JSON encoding suitable for signing. Stable ordering and no
    /// insignificant whitespace.
    pub fn signing_bytes(&self) -> Vec<u8> {
        // Same canonicalization as wires_core::content
        let v = serde_json::to_value(self).expect("SignInChallenge always serializable");
        let canonical = canonicalize(&v);
        serde_json::to_vec(&canonical).expect("canonical JSON")
    }

    pub fn encode_url_safe_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_bytes())
    }

    pub fn decode_url_safe_b64(s: &str) -> Result<Self, serde_json::Error> {
        let bytes = URL_SAFE_NO_PAD.decode(s).map_err(|e| {
            use serde::de::Error;
            serde_json::Error::custom(format!("base64: {e}"))
        })?;
        serde_json::from_slice(&bytes)
    }

    pub fn sign(&self, root: &SigningKey) -> Signature {
        root.sign(&self.signing_bytes())
    }

    pub fn verify(&self, root_pubkey: &VerifyingKey, sig: &Signature) -> bool {
        root_pubkey.verify(&self.signing_bytes(), sig).is_ok()
    }
}

fn canonicalize(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(m) => {
            let mut sorted = serde_json::Map::new();
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            for k in keys {
                sorted.insert(k.clone(), canonicalize(&m[k]));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(canonicalize).collect())
        }
        _ => v.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn sk(seed: u8) -> SigningKey { SigningKey::from_bytes(&[seed; 32]) }

    fn ch() -> SignInChallenge {
        SignInChallenge::new("https://mcp.example.com", "sess-1", [7u8; 32], 1_000, 60_000)
    }

    #[test]
    fn encode_decode_roundtrip() {
        let c = ch();
        let s = c.encode_url_safe_b64();
        let back = SignInChallenge::decode_url_safe_b64(&s).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn sign_and_verify_with_root_key() {
        let k = sk(1);
        let c = ch();
        let sig = c.sign(&k);
        assert!(c.verify(&k.verifying_key(), &sig));
    }

    #[test]
    fn wrong_root_does_not_verify() {
        let k1 = sk(1);
        let k2 = sk(2);
        let c = ch();
        let sig = c.sign(&k1);
        assert!(!c.verify(&k2.verifying_key(), &sig));
    }

    #[test]
    fn tampering_invalidates_signature() {
        let k = sk(1);
        let c = ch();
        let sig = c.sign(&k);
        let mut tampered = c.clone();
        tampered.nonce = hex::encode([8u8; 32]);
        assert!(!tampered.verify(&k.verifying_key(), &sig));
    }
}

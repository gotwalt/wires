//! JWT mint + verify. EdDSA-signed by the gateway's `token_signing.ed25519`.
//! Claims per spec §4.5. Verification is offline (signature + claims +
//! optional caller-supplied JTI revocation check).

use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use crate::error::{
    ExpiredTokenSnafu, GatewayError, MissingScopeSnafu, RevokedJtiSnafu, Result,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub scope: String,
    pub client_id: String,
}

#[derive(Debug, Clone)]
pub struct MintInput<'a> {
    pub iss: &'a str,
    pub sub: &'a str,
    pub aud: &'a str,
    pub now_s: i64,
    pub ttl_s: i64,
    pub client_id: &'a str,
}

pub const SCOPE_MCP_WIRES: &str = "mcp:wires";

pub fn mint(sk: &SigningKey, input: &MintInput<'_>) -> Result<String> {
    let kid = crate::keys::kid_for(&sk.verifying_key());
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid);
    header.typ = Some("JWT".into());
    let claims = Claims {
        iss: input.iss.to_string(),
        sub: input.sub.to_string(),
        aud: input.aud.to_string(),
        iat: input.now_s,
        exp: input.now_s + input.ttl_s,
        jti: uuid::Uuid::new_v4().to_string(),
        scope: SCOPE_MCP_WIRES.to_string(),
        client_id: input.client_id.to_string(),
    };
    let key = EncodingKey::from_ed_der(&ed_pkcs8_der(sk));
    jsonwebtoken::encode(&header, &claims, &key).map_err(|e| GatewayError::Json {
        source: serde_json::Error::custom(e.to_string()),
        location: snafu::location!(),
    })
}

pub fn verify(
    vk: &VerifyingKey,
    expected_iss: &str,
    expected_aud: &str,
    is_jti_revoked: impl Fn(&str) -> bool,
    token: &str,
    now_s: i64,
) -> Result<Claims> {
    let key = DecodingKey::from_ed_der(&ed_spki_der(vk));
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[expected_aud]);
    validation.set_issuer(&[expected_iss]);
    validation.validate_exp = false;
    validation.required_spec_claims = std::collections::HashSet::from([
        "iss".into(),
        "sub".into(),
        "aud".into(),
        "exp".into(),
        "iat".into(),
        "jti".into(),
    ]);
    let data = jsonwebtoken::decode::<Claims>(token, &key, &validation).map_err(|e| {
        use jsonwebtoken::errors::ErrorKind::*;
        match e.kind() {
            InvalidAudience => GatewayError::BadAudience {
                location: snafu::location!(),
            },
            _ => GatewayError::BadTokenSignature {
                location: snafu::location!(),
            },
        }
    })?;
    let c = data.claims;
    if c.exp <= now_s {
        return ExpiredTokenSnafu.fail();
    }
    if is_jti_revoked(&c.jti) {
        return RevokedJtiSnafu.fail();
    }
    if c.scope.split_whitespace().all(|s| s != SCOPE_MCP_WIRES) {
        return MissingScopeSnafu.fail();
    }
    Ok(c)
}

// jsonwebtoken expects PKCS#8/SPKI DER for Ed25519; build minimal encodings.
fn ed_pkcs8_der(sk: &SigningKey) -> Vec<u8> {
    // PKCS#8 v1 for Ed25519: SEQUENCE { INTEGER 0, AlgorithmIdentifier, OCTET STRING containing OCTET STRING(seed) }
    // We use the canonical 48-byte prefix + 32 seed bytes.
    let prefix = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(&prefix);
    out.extend_from_slice(sk.to_bytes().as_slice());
    out
}

fn ed_spki_der(vk: &VerifyingKey) -> Vec<u8> {
    // ring's ED25519 UnparsedPublicKey::verify expects raw 32-byte pubkey,
    // not a SPKI DER wrapper. DecodingKey::from_ed_der passes bytes straight
    // through to ring, so we return only the raw key bytes.
    vk.to_bytes().to_vec()
}

// `serde_json::Error::custom` is not pub; wrap via the public From<...> shim.
trait SerdeJsonErrorCustom: Sized {
    fn custom<T: std::fmt::Display>(msg: T) -> Self;
}
impl SerdeJsonErrorCustom for serde_json::Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        <serde_json::Error as serde::de::Error>::custom(msg.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn sk() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    #[test]
    fn mint_and_verify_roundtrip() {
        let sk = sk();
        let vk = sk.verifying_key();
        let now = 1_000_000;
        let token = mint(
            &sk,
            &MintInput {
                iss: "https://mcp.example",
                sub: "ab".repeat(32).as_str(),
                aud: "https://mcp.example",
                now_s: now,
                ttl_s: 900,
                client_id: "client-1",
            },
        )
        .unwrap();
        let c = verify(&vk, "https://mcp.example", "https://mcp.example", |_| false, &token, now + 5).unwrap();
        assert_eq!(c.sub.len(), 64);
        assert_eq!(c.scope, SCOPE_MCP_WIRES);
        assert_eq!(c.client_id, "client-1");
    }

    #[test]
    fn expired_token_rejected() {
        let sk = sk();
        let now = 1_000_000;
        let t = mint(
            &sk,
            &MintInput {
                iss: "i",
                sub: "s",
                aud: "i",
                now_s: now,
                ttl_s: 60,
                client_id: "c",
            },
        )
        .unwrap();
        let err = verify(&sk.verifying_key(), "i", "i", |_| false, &t, now + 999).unwrap_err();
        assert!(matches!(err, GatewayError::ExpiredToken { .. }));
    }

    #[test]
    fn revoked_jti_rejected() {
        let sk = sk();
        let now = 1_000_000;
        let t = mint(
            &sk,
            &MintInput {
                iss: "i",
                sub: "s",
                aud: "i",
                now_s: now,
                ttl_s: 900,
                client_id: "c",
            },
        )
        .unwrap();
        let err = verify(&sk.verifying_key(), "i", "i", |_| true, &t, now + 5).unwrap_err();
        assert!(matches!(err, GatewayError::RevokedJti { .. }));
    }

    #[test]
    fn audience_mismatch_rejected() {
        let sk = sk();
        let now = 1_000_000;
        let t = mint(
            &sk,
            &MintInput {
                iss: "i",
                sub: "s",
                aud: "i",
                now_s: now,
                ttl_s: 900,
                client_id: "c",
            },
        )
        .unwrap();
        let err = verify(&sk.verifying_key(), "i", "other", |_| false, &t, now + 5).unwrap_err();
        assert!(matches!(err, GatewayError::BadAudience { .. }));
    }

    #[test]
    fn tampered_signature_rejected() {
        let sk = sk();
        let now = 1_000_000;
        let t = mint(
            &sk,
            &MintInput {
                iss: "i",
                sub: "s",
                aud: "i",
                now_s: now,
                ttl_s: 900,
                client_id: "c",
            },
        )
        .unwrap();
        let mut bytes = t.into_bytes();
        let last = bytes.last_mut().unwrap();
        *last = if *last == b'a' { b'b' } else { b'a' };
        let t = String::from_utf8(bytes).unwrap();
        let err = verify(&sk.verifying_key(), "i", "i", |_| false, &t, now + 5).unwrap_err();
        assert!(matches!(err, GatewayError::BadTokenSignature { .. }));
    }
}

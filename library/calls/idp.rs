//! IdP identity bound to a wires node key, presented in the handshake.
//!
//! A node key says *which machine* is calling; an organization wants to know
//! *which person*. `wires login` closes that gap without a wires-run identity
//! service: it runs an ordinary OIDC authorization-code flow against the
//! user's IdP (Google, Okta, Entra…) with the request `nonce` set to
//! [`OidcNonce::for_node`] of the node's own key. The IdP signs an ID token
//! containing that nonce, so the token itself proves "the holder of node key
//! *K* authenticated as *alice@corp*".
//!
//! Nothing is published. The caller presents the raw ID token in the session
//! `Hello` of each call (and of each inbox fetch or record stream it opens);
//! the host pairs it with the key iroh authenticated to form an
//! [`IdentityClaim`], verifies the IdP's signature against the issuer's
//! published keys **itself** with [`verify_claim`], under the issuers its own
//! `host.json` trusts, and derives the [`Principal`]. No party has to trust a
//! wires attestor, and hosts can trust several IdPs at once; every role
//! matcher names the issuer it accepts.
//!
//! This module is pure: it verifies against a [`Jwks`] the caller already
//! holds. Fetching and caching the issuer's keys (OIDC discovery →
//! `jwks_uri`) is the binary's job.
//!
//! # Example
//!
//! ```
//! use library::{Audience, IdToken, IdTokenError, IdentityClaim, Issuer, Jwks, NodeIdentity,
//!     Error, verify_claim};
//!
//! let jwks = Jwks::from_json(r#"{"keys":[]}"#).unwrap();
//! let claim = IdentityClaim {
//!     node: NodeIdentity::generate().node_id(),
//!     id_token: IdToken::new("not.a.jws!"),
//! };
//! let err = verify_claim(
//!     &claim,
//!     &Issuer::new("https://accounts.google.com"),
//!     &jwks,
//!     &[Audience::new("my-client-id")],
//!     1_700_000_000,
//! )
//! .unwrap_err();
//! assert!(matches!(err, Error::IdToken(IdTokenError::Malformed(_))));
//! ```

use std::fmt;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{Error, IdTokenError, Result};
use crate::identity::NodeId;

/// Domain-separation context for [`OidcNonce::for_node`].
pub const OIDC_NONCE_CONTEXT: &str = "wires oidc-nonce v1";

/// How far `exp` / `iat` may be off from the verifier's clock, in seconds.
pub const CLOCK_SKEW_SECS: i64 = 60;

/// Google's issuer identifier: the one issuer whose `hd` (hosted domain)
/// claim becomes [`Principal::org`], and the issuer `wires role set` names
/// when none is given.
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// A raw OIDC ID token: a compact JWS (`header.payload.signature`), exactly as
/// the IdP issued it. Opaque until verified.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdToken(String);

impl IdToken {
    /// Wrap a compact-JWS string. No validation happens here — an `IdToken`
    /// is untrusted input until verified.
    pub fn new(jws: impl Into<String>) -> Self {
        Self(jws.into())
    }

    /// The compact JWS.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The **unverified** `iss` claim — only for choosing which issuer's keys
    /// to fetch before calling [`verify_claim`], never as an identity.
    ///
    /// ```
    /// use library::IdToken;
    /// // header {"alg":"RS256"}, payload {"iss":"https://idp.example"}, no signature
    /// let t = IdToken::new("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIn0.");
    /// assert_eq!(t.unverified_issuer().unwrap().as_str(), "https://idp.example");
    /// ```
    pub fn unverified_issuer(&self) -> Result<Issuer> {
        let jws = Jws::parse(self)?;
        let iss = jws
            .payload
            .get("iss")
            .and_then(Value::as_str)
            .ok_or(IdTokenError::MissingClaim("iss"))?;
        Ok(Issuer::new(iss))
    }

    /// The **unverified** header `kid`, if any — lets a key fetcher notice a
    /// rotated key and refetch the JWKS before verifying.
    pub fn unverified_kid(&self) -> Result<Option<String>> {
        Ok(Jws::parse(self)?.header.kid)
    }
}

/// An OIDC issuer identifier (the exact `iss` string, e.g.
/// `https://accounts.google.com`).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Issuer(String);

impl Issuer {
    /// Wrap an issuer identifier. Compared byte-for-byte against `iss`.
    pub fn new(iss: impl Into<String>) -> Self {
        Self(iss.into())
    }

    /// The issuer string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Issuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An accepted OIDC audience: the OAuth client id the token was issued to.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Audience(String);

impl Audience {
    /// Wrap a client id.
    pub fn new(aud: impl Into<String>) -> Self {
        Self(aud.into())
    }

    /// The client id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One JSON Web Key (RFC 7517) as an issuer publishes it. Only RSA and P-256
/// EC signing keys are usable; other entries are ignored, not errors.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type: `RSA` or `EC` for usable keys.
    pub kty: String,
    /// Key id, matched against the JWS header's `kid`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Intended algorithm; when present it must equal the header's `alg`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Intended use; when present it must be `sig`.
    #[serde(default, rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<String>,
    /// RSA modulus, base64url big-endian.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA public exponent, base64url big-endian.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    /// EC curve name (`P-256`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// EC x coordinate, base64url (32 bytes for P-256).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// EC y coordinate, base64url (32 bytes for P-256).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

/// An issuer's JSON Web Key Set — the document at its `jwks_uri`.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct Jwks {
    /// The published keys, in the issuer's order.
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Parse a JWKS document.
    ///
    /// ```
    /// use library::Jwks;
    /// let jwks = Jwks::from_json(r#"{"keys":[{"kty":"EC","kid":"k1","crv":"P-256",
    ///     "x":"AA","y":"AA"}]}"#).unwrap();
    /// assert!(jwks.has_kid("k1"));
    /// assert!(!jwks.has_kid("k2"));
    /// ```
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|_| IdTokenError::Malformed("jwks").into())
    }

    /// Whether any key carries this `kid`.
    pub fn has_kid(&self, kid: &str) -> bool {
        self.keys.iter().any(|k| k.kid.as_deref() == Some(kid))
    }
}

/// The OIDC `nonce` that binds an ID token to one node key.
///
/// Deterministic in the node id, so a verifier recomputes it from the claim's
/// `node` and compares it to the token's `nonce` claim — a token minted for
/// one key cannot be replayed as another's.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OidcNonce(String);

impl OidcNonce {
    /// The nonce for `node`: base64url (no padding) of
    /// `blake3::derive_key(OIDC_NONCE_CONTEXT, node bytes)`.
    ///
    /// ```
    /// use library::{NodeIdentity, OidcNonce};
    /// let node = NodeIdentity::from_seed([7; 32]).node_id();
    /// let nonce = OidcNonce::for_node(&node);
    /// assert_eq!(nonce, OidcNonce::for_node(&node));
    /// assert_eq!(nonce.as_str().len(), 43); // 32 bytes, base64url, no padding
    /// ```
    pub fn for_node(node: &NodeId) -> Self {
        Self(B64.encode(blake3::derive_key(OIDC_NONCE_CONTEXT, node.as_bytes())))
    }

    /// The nonce string as sent in the authorization request.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Who a verified ID token says the node's holder is.
///
/// Only ever produced by verification, never deserialized off the wire as a
/// trusted value — the wire carries the token, and each reader derives this.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Principal {
    /// The token's `iss` (e.g. `https://accounts.google.com`).
    pub issuer: String,
    /// The token's `sub`: the IdP's stable user id.
    pub subject: String,
    /// The `email` claim, when present and `email_verified` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// The Google Workspace hosted domain (`hd`), read only when the issuer
    /// is exactly [`GOOGLE_ISSUER`]; `None` for every other issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// Group memberships, when the IdP asserts them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// The token's `exp`, Unix seconds: the claim is stale after this.
    pub not_after: i64,
    /// The token's whole verified payload, every claim as the IdP signed it.
    ///
    /// The fields above are the ones wires reads today; this keeps the rest
    /// (Okta `groups`, Entra `roles`, custom claims) so a later host policy
    /// can match any claim without a wire change. Reader-local: it is derived
    /// by verification like everything else here and is never serialized, so
    /// a [`Principal`] read back from a call record has it empty.
    #[serde(skip)]
    pub claims: Map<String, Value>,
}

/// "Node *K* is held by the person this ID token names": the ID token a
/// caller presented, paired with the key the connection authenticated, for
/// the host to verify independently.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct IdentityClaim {
    /// The node key the token was minted for (its `nonce` must equal
    /// [`OidcNonce::for_node`] of this id).
    pub node: NodeId,
    /// The IdP-signed ID token.
    pub id_token: IdToken,
}

/// Verify `claim` against `issuer`'s published keys and derive its
/// [`Principal`].
///
/// Checks, in order (each failure is its own [`IdTokenError`]):
///
/// 1. the token is a compact JWS whose header `alg` is `RS256` or `ES256`;
/// 2. a key in `jwks` matching the header `kid` (and key type) verifies the
///    signature;
/// 3. `iss` equals `issuer` exactly;
/// 4. some `aud` value is in `audiences`;
/// 5. `exp` is not more than [`CLOCK_SKEW_SECS`] in the past and `iat` (if
///    present) not more than that in the future, relative to `now` (unix
///    seconds);
/// 6. `nonce` equals [`OidcNonce::for_node`] of `claim.node`.
///
/// `email` is surfaced only when `email_verified` is true; `hd` becomes
/// [`Principal::org`] only when the issuer is exactly [`GOOGLE_ISSUER`]
/// (another IdP's `hd` is just a claim, never an org); a string-array `groups` claim becomes
/// [`Principal::groups`].
pub fn verify_claim(
    claim: &IdentityClaim,
    issuer: &Issuer,
    jwks: &Jwks,
    audiences: &[Audience],
    now: i64,
) -> Result<Principal> {
    let jws = Jws::parse(&claim.id_token)?;
    jws.verify_signature(jwks)?;
    let p = &jws.payload;

    let iss = str_claim(p, "iss")?;
    if iss != issuer.as_str() {
        return Err(IdTokenError::WrongIssuer {
            expected: issuer.as_str().to_string(),
            got: iss.to_string(),
        }
        .into());
    }

    let aud: Vec<String> = match p.get("aud") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| v.as_str().map(str::to_string))
            .collect::<Option<_>>()
            .ok_or(IdTokenError::MissingClaim("aud"))?,
        _ => return Err(IdTokenError::MissingClaim("aud").into()),
    };
    if !aud
        .iter()
        .any(|a| audiences.iter().any(|ok| ok.as_str() == a))
    {
        return Err(IdTokenError::WrongAudience { got: aud }.into());
    }

    let exp = int_claim(p, "exp")?.ok_or(IdTokenError::MissingClaim("exp"))?;
    if now > exp.saturating_add(CLOCK_SKEW_SECS) {
        return Err(IdTokenError::Expired { exp }.into());
    }
    if let Some(iat) = int_claim(p, "iat")?
        && iat > now.saturating_add(CLOCK_SKEW_SECS)
    {
        return Err(IdTokenError::NotYetValid { iat }.into());
    }

    let nonce = str_claim(p, "nonce")?;
    if nonce != OidcNonce::for_node(&claim.node).as_str() {
        return Err(IdTokenError::WrongNonce {
            node: claim.node.hex(),
        }
        .into());
    }

    let subject = str_claim(p, "sub")?.to_string();
    let verified = match p.get("email_verified") {
        Some(Value::Bool(b)) => *b,
        // Some IdPs historically sent the string form.
        Some(Value::String(s)) => s == "true",
        _ => false,
    };
    let email = verified
        .then(|| p.get("email").and_then(Value::as_str).map(str::to_string))
        .flatten();
    let org = (iss == GOOGLE_ISSUER)
        .then(|| p.get("hd").and_then(Value::as_str).map(str::to_string))
        .flatten();
    let groups = match p.get("groups") {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    };
    Ok(Principal {
        issuer: iss.to_string(),
        subject,
        email,
        org,
        groups,
        not_after: exp,
        claims: p.clone(),
    })
}

/// A required string claim.
fn str_claim<'a>(p: &'a Map<String, Value>, name: &'static str) -> Result<&'a str> {
    p.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| IdTokenError::MissingClaim(name).into())
}

/// An optional integer claim; present-but-not-an-integer is an error.
fn int_claim(p: &Map<String, Value>, name: &'static str) -> Result<Option<i64>> {
    match p.get(name) {
        None => Ok(None),
        Some(v) => v
            .as_i64()
            // Some IdPs emit NumericDate as a float.
            .or_else(|| v.as_f64().map(|f| f as i64))
            .map(Some)
            .ok_or_else(|| IdTokenError::MissingClaim(name).into()),
    }
}

/// The JWS header fields the verifier reads.
#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    crit: Option<Value>,
}

/// The two signature algorithms accepted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Alg {
    Rs256,
    Es256,
}

impl Alg {
    fn name(self) -> &'static str {
        match self {
            Alg::Rs256 => "RS256",
            Alg::Es256 => "ES256",
        }
    }

    /// Whether `jwk` is a key this algorithm can use.
    fn fits(self, jwk: &Jwk) -> bool {
        let kty_ok = match self {
            Alg::Rs256 => jwk.kty == "RSA",
            Alg::Es256 => jwk.kty == "EC" && jwk.crv.as_deref() == Some("P-256"),
        };
        kty_ok
            && jwk.alg.as_deref().is_none_or(|a| a == self.name())
            && jwk.key_use.as_deref().is_none_or(|u| u == "sig")
    }
}

/// A parsed (not yet verified) compact JWS.
struct Jws<'a> {
    header: Header,
    alg: Alg,
    payload: Map<String, Value>,
    /// `base64url(header) "." base64url(payload)` — the signed bytes.
    signing_input: &'a str,
    signature: Vec<u8>,
}

impl<'a> Jws<'a> {
    /// Split and decode; rejects any algorithm but RS256/ES256.
    fn parse(token: &'a IdToken) -> Result<Self> {
        let s = token.as_str();
        let mut parts = s.split('.');
        let (Some(h), Some(p), Some(sig), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(IdTokenError::Malformed("not a three-part compact JWS").into());
        };
        let header: Header = decode_json(h, "header")?;
        if header.crit.is_some() {
            return Err(IdTokenError::Malformed("critical header extensions").into());
        }
        let alg = match header.alg.as_str() {
            "RS256" => Alg::Rs256,
            "ES256" => Alg::Es256,
            other => return Err(IdTokenError::UnsupportedAlgorithm(other.to_string()).into()),
        };
        let payload: Map<String, Value> = decode_json(p, "payload")?;
        let signature = B64
            .decode(sig)
            .map_err(|_| IdTokenError::Malformed("signature is not base64url"))?;
        Ok(Self {
            header,
            alg,
            payload,
            signing_input: &s[..h.len() + 1 + p.len()],
            signature,
        })
    }

    /// Check the signature against the JWKS key(s) the header selects.
    fn verify_signature(&self, jwks: &Jwks) -> Result<()> {
        let candidates: Vec<&Jwk> = jwks
            .keys
            .iter()
            .filter(|k| match &self.header.kid {
                Some(kid) => k.kid.as_deref() == Some(kid.as_str()),
                None => true,
            })
            .filter(|k| self.alg.fits(k))
            .collect();
        if candidates.is_empty() {
            return Err(IdTokenError::UnknownKey {
                kid: self.header.kid.clone(),
            }
            .into());
        }
        let msg = self.signing_input.as_bytes();
        let ok = candidates
            .into_iter()
            .any(|k| verify_with(self.alg, k, msg, &self.signature).unwrap_or(false));
        if ok {
            Ok(())
        } else {
            Err(IdTokenError::BadSignature.into())
        }
    }
}

/// Verify `sig` over `msg` with one key. `Err` means the key itself is
/// unusable (bad encoding); `Ok(false)` means it did not verify.
fn verify_with(alg: Alg, jwk: &Jwk, msg: &[u8], sig: &[u8]) -> Result<bool> {
    use ring::signature;
    let field = |v: &Option<String>| -> Result<Vec<u8>> {
        let text = v.as_deref().ok_or(IdTokenError::Malformed("jwk field"))?;
        B64.decode(text)
            .map_err(|_| IdTokenError::Malformed("jwk field").into())
    };
    match alg {
        Alg::Rs256 => {
            let n = field(&jwk.n)?;
            let e = field(&jwk.e)?;
            let key = signature::RsaPublicKeyComponents {
                n: strip_leading_zeros(&n),
                e: strip_leading_zeros(&e),
            };
            Ok(key
                .verify(&signature::RSA_PKCS1_2048_8192_SHA256, msg, sig)
                .is_ok())
        }
        Alg::Es256 => {
            let x = field(&jwk.x)?;
            let y = field(&jwk.y)?;
            if x.len() != 32 || y.len() != 32 {
                return Err(IdTokenError::Malformed("P-256 coordinate length").into());
            }
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            Ok(
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                    .verify(msg, sig)
                    .is_ok(),
            )
        }
    }
}

/// Big-endian integers in a JWK are minimal, but tolerate a stray leading
/// zero (ring rejects non-minimal encodings).
fn strip_leading_zeros(b: &[u8]) -> &[u8] {
    let first = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[first..]
}

/// base64url-decode one JWS segment and parse it as JSON.
fn decode_json<T: serde::de::DeserializeOwned>(seg: &str, what: &'static str) -> Result<T> {
    let bytes = B64.decode(seg).map_err(|_| {
        Error::from(IdTokenError::Malformed(match what {
            "header" => "header is not base64url",
            _ => "payload is not base64url",
        }))
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        IdTokenError::Malformed(match what {
            "header" => "header is not a JSON object",
            _ => "payload is not a JSON object",
        })
        .into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use crate::idp_vectors as v;
    use proptest::prelude::*;
    use ring::rand::SystemRandom;
    use ring::signature::{self as sig, KeyPair as _};

    const NOW: i64 = 1_800_000_000;
    const ISS: &str = "https://issuer.example";
    const AUD: &str = "client-123";

    fn rsa_jwk(kid: &str) -> Jwk {
        Jwk {
            kty: "RSA".into(),
            kid: Some(kid.into()),
            alg: Some("RS256".into()),
            key_use: Some("sig".into()),
            n: Some(v::RSA_N.into()),
            e: Some(v::RSA_E.into()),
            crv: None,
            x: None,
            y: None,
        }
    }

    fn ec_jwk(kid: &str) -> Jwk {
        Jwk {
            kty: "EC".into(),
            kid: Some(kid.into()),
            alg: None,
            key_use: None,
            n: None,
            e: None,
            crv: Some("P-256".into()),
            x: Some(v::EC_X.into()),
            y: Some(v::EC_Y.into()),
        }
    }

    fn jwks() -> Jwks {
        Jwks {
            keys: vec![rsa_jwk("rsa-1"), ec_jwk("ec-1")],
        }
    }

    /// Sign `claims` as a compact JWS with the fixture key for `alg`.
    fn sign(alg: Alg, kid: &str, claims: &Value) -> IdToken {
        let header = serde_json::json!({"alg": alg.name(), "kid": kid, "typ": "JWT"});
        let input = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(claims.to_string())
        );
        let rng = SystemRandom::new();
        let signature = match alg {
            Alg::Rs256 => {
                let kp = sig::RsaKeyPair::from_pkcs8(&B64.decode(v::RSA_PKCS8).unwrap()).unwrap();
                let mut out = vec![0; kp.public().modulus_len()];
                kp.sign(&sig::RSA_PKCS1_SHA256, &rng, input.as_bytes(), &mut out)
                    .unwrap();
                out
            }
            Alg::Es256 => {
                let kp = sig::EcdsaKeyPair::from_pkcs8(
                    &sig::ECDSA_P256_SHA256_FIXED_SIGNING,
                    &B64.decode(v::EC_PKCS8).unwrap(),
                    &rng,
                )
                .unwrap();
                assert_eq!(kp.public_key().as_ref().len(), 65);
                kp.sign(&rng, input.as_bytes()).unwrap().as_ref().to_vec()
            }
        };
        IdToken::new(format!("{input}.{}", B64.encode(signature)))
    }

    fn good_claims(node: &NodeId) -> Value {
        serde_json::json!({
            "iss": ISS,
            "sub": "1234567890",
            "aud": AUD,
            "exp": NOW + 3600,
            "iat": NOW,
            "nonce": OidcNonce::for_node(node).as_str(),
            "email": "alice@example.com",
            "email_verified": true,
            "hd": "example.com",
        })
    }

    fn node() -> NodeId {
        NodeIdentity::from_seed([9; 32]).node_id()
    }

    fn check(claim: &IdentityClaim) -> Result<Principal> {
        verify_claim(
            claim,
            &Issuer::new(ISS),
            &jwks(),
            &[Audience::new("other"), Audience::new(AUD)],
            NOW,
        )
    }

    fn token_err(r: Result<Principal>) -> IdTokenError {
        match r {
            Err(Error::IdToken(e)) => e,
            other => panic!("expected an IdToken error, got {other:?}"),
        }
    }

    fn with(node: NodeId, alg: Alg, f: impl FnOnce(&mut Map<String, Value>)) -> IdentityClaim {
        let mut claims = good_claims(&node);
        f(claims.as_object_mut().unwrap());
        let kid = if alg == Alg::Rs256 { "rsa-1" } else { "ec-1" };
        IdentityClaim {
            node,
            id_token: sign(alg, kid, &claims),
        }
    }

    // --- known-answer vectors (produced by Python `cryptography`/OpenSSL, not ring)

    #[test]
    fn rs256_known_answer_vector_verifies() {
        let token = IdToken::new(v::RSA_JWS);
        let jws = Jws::parse(&token).unwrap();
        assert_eq!(jws.alg, Alg::Rs256);
        let keys = Jwks {
            keys: vec![rsa_jwk("rsa-kat")],
        };
        jws.verify_signature(&keys).unwrap();
        assert_eq!(
            token.unverified_issuer().unwrap().as_str(),
            "https://kat.example"
        );
    }

    #[test]
    fn es256_known_answer_vector_verifies() {
        let token = IdToken::new(v::EC_JWS);
        let jws = Jws::parse(&token).unwrap();
        assert_eq!(jws.alg, Alg::Es256);
        let keys = Jwks {
            keys: vec![ec_jwk("ec-kat")],
        };
        jws.verify_signature(&keys).unwrap();
    }

    #[test]
    fn known_answer_vectors_fail_under_the_other_key() {
        // Swap the kid so the RSA vector selects nothing it can use.
        let token = IdToken::new(v::RSA_JWS);
        let keys = Jwks {
            keys: vec![ec_jwk("rsa-kat")],
        };
        let err = Jws::parse(&token).unwrap().verify_signature(&keys);
        assert!(matches!(
            err,
            Err(Error::IdToken(IdTokenError::UnknownKey { kid: Some(ref k) })) if k == "rsa-kat"
        ));
        // The right key type, the wrong key material: a signature failure.
        let mut other = ec_jwk("ec-kat");
        other.y = Some(v::EC_X.into());
        let err = Jws::parse(&IdToken::new(v::EC_JWS))
            .unwrap()
            .verify_signature(&Jwks { keys: vec![other] });
        assert!(matches!(
            err,
            Err(Error::IdToken(IdTokenError::BadSignature))
        ));
    }

    // --- full claim verification

    #[test]
    fn a_good_claim_yields_the_principal_under_both_algorithms() {
        for alg in [Alg::Rs256, Alg::Es256] {
            let p = check(&with(node(), alg, |_| {})).unwrap();
            assert_eq!(
                p,
                Principal {
                    issuer: ISS.into(),
                    subject: "1234567890".into(),
                    email: Some("alice@example.com".into()),
                    org: None,
                    groups: vec![],
                    not_after: NOW + 3600,
                    claims: p.claims.clone(),
                }
            );
            assert_eq!(p.claims["nonce"], OidcNonce::for_node(&node()).as_str());
            assert_eq!(p.claims["hd"], "example.com", "kept as a claim, not an org");
        }
    }

    #[test]
    fn hd_is_an_org_only_from_google() {
        let google = |iss: &str| {
            let claim = with(node(), Alg::Es256, |c| {
                c.insert("iss".into(), iss.into());
            });
            verify_claim(
                &claim,
                &Issuer::new(iss),
                &jwks(),
                &[Audience::new(AUD)],
                NOW,
            )
            .unwrap()
        };
        assert_eq!(google(GOOGLE_ISSUER).org.as_deref(), Some("example.com"));
        assert_eq!(
            google("accounts.google.com").org,
            None,
            "not exactly Google"
        );
        assert_eq!(google("https://okta.example").org, None);
    }

    #[test]
    fn each_failed_check_has_its_own_error() {
        let n = node();
        let cases: Vec<(IdentityClaim, IdTokenError)> = vec![
            (
                with(n, Alg::Es256, |c| {
                    c.insert(
                        "nonce".into(),
                        OidcNonce::for_node(&NodeIdentity::from_seed([1; 32]).node_id())
                            .as_str()
                            .into(),
                    );
                }),
                IdTokenError::WrongNonce { node: n.hex() },
            ),
            (
                with(n, Alg::Es256, |c| {
                    c.insert("aud".into(), "someone-else".into());
                }),
                IdTokenError::WrongAudience {
                    got: vec!["someone-else".into()],
                },
            ),
            (
                with(n, Alg::Rs256, |c| {
                    c.insert("iss".into(), "https://evil.example".into());
                }),
                IdTokenError::WrongIssuer {
                    expected: ISS.into(),
                    got: "https://evil.example".into(),
                },
            ),
            (
                with(n, Alg::Rs256, |c| {
                    c.insert("exp".into(), (NOW - CLOCK_SKEW_SECS - 1).into());
                }),
                IdTokenError::Expired {
                    exp: NOW - CLOCK_SKEW_SECS - 1,
                },
            ),
            (
                with(n, Alg::Rs256, |c| {
                    c.insert("iat".into(), (NOW + CLOCK_SKEW_SECS + 1).into());
                }),
                IdTokenError::NotYetValid {
                    iat: NOW + CLOCK_SKEW_SECS + 1,
                },
            ),
            (
                with(n, Alg::Es256, |c| {
                    c.remove("nonce");
                }),
                IdTokenError::MissingClaim("nonce"),
            ),
            (
                with(n, Alg::Es256, |c| {
                    c.remove("sub");
                }),
                IdTokenError::MissingClaim("sub"),
            ),
        ];
        let mut seen = Vec::new();
        for (claim, want) in cases {
            let got = token_err(check(&claim));
            assert_eq!(got, want);
            assert!(!seen.contains(&got.to_string()), "duplicate message {got}");
            seen.push(got.to_string());
        }
    }

    #[test]
    fn a_claim_for_another_node_is_a_nonce_failure() {
        let mut claim = with(node(), Alg::Es256, |_| {});
        let other = NodeIdentity::from_seed([3; 32]).node_id();
        claim.node = other;
        assert_eq!(
            token_err(check(&claim)),
            IdTokenError::WrongNonce { node: other.hex() }
        );
    }

    #[test]
    fn skew_is_tolerated_at_the_boundary() {
        let claim = with(node(), Alg::Es256, |c| {
            c.insert("exp".into(), (NOW - CLOCK_SKEW_SECS).into());
            c.insert("iat".into(), (NOW + CLOCK_SKEW_SECS).into());
        });
        assert!(check(&claim).is_ok());
    }

    #[test]
    fn email_only_when_verified_and_groups_and_array_aud() {
        let claim = with(node(), Alg::Es256, |c| {
            c.insert("email_verified".into(), false.into());
            c.remove("hd");
            c.insert("aud".into(), serde_json::json!(["x", AUD]));
            c.insert("groups".into(), serde_json::json!(["eng", "ops"]));
        });
        let p = check(&claim).unwrap();
        assert_eq!(p.email, None);
        assert_eq!(p.org, None);
        assert_eq!(p.groups, vec!["eng".to_string(), "ops".to_string()]);
        let claim = with(node(), Alg::Es256, |c| {
            c.insert("email_verified".into(), "true".into());
        });
        assert_eq!(
            check(&claim).unwrap().email.as_deref(),
            Some("alice@example.com")
        );
    }

    #[test]
    fn unsupported_algorithms_are_refused_before_any_key_lookup() {
        for alg in ["none", "HS256", "RS512", "PS256"] {
            let h = B64.encode(format!(r#"{{"alg":"{alg}"}}"#));
            let p = B64.encode(good_claims(&node()).to_string());
            let claim = IdentityClaim {
                node: node(),
                id_token: IdToken::new(format!("{h}.{p}.")),
            };
            assert_eq!(
                token_err(check(&claim)),
                IdTokenError::UnsupportedAlgorithm(alg.into())
            );
        }
    }

    #[test]
    fn an_unknown_kid_is_reported_as_such() {
        let claim = IdentityClaim {
            node: node(),
            id_token: sign(Alg::Es256, "rotated", &good_claims(&node())),
        };
        assert_eq!(
            token_err(check(&claim)),
            IdTokenError::UnknownKey {
                kid: Some("rotated".into())
            }
        );
        assert_eq!(
            claim.id_token.unverified_kid().unwrap().as_deref(),
            Some("rotated")
        );
    }

    #[test]
    fn a_key_of_the_wrong_type_under_the_right_kid_is_not_used() {
        // An RS256 token whose kid names the EC key.
        let claim = IdentityClaim {
            node: node(),
            id_token: sign(Alg::Rs256, "ec-1", &good_claims(&node())),
        };
        assert!(matches!(
            token_err(check(&claim)),
            IdTokenError::UnknownKey { .. }
        ));
    }

    #[test]
    fn malformed_tokens_are_malformed() {
        for t in ["", "a.b", "a.b.c.d", "!!.e30.", "e30.!!.", "e30.e30.!!"] {
            let claim = IdentityClaim {
                node: node(),
                id_token: IdToken::new(t),
            };
            let e = token_err(check(&claim));
            assert!(
                matches!(
                    e,
                    IdTokenError::Malformed(_) | IdTokenError::UnsupportedAlgorithm(_)
                ),
                "{t:?} → {e:?}"
            );
        }
    }

    // --- properties

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Changing any single byte of a valid token makes it fail.
        #[test]
        fn any_single_byte_tamper_fails(rsa in any::<bool>(), idx in any::<prop::sample::Index>(), b in any::<u8>()) {
            let alg = if rsa { Alg::Rs256 } else { Alg::Es256 };
            let claim = with(node(), alg, |_| {});
            let mut bytes = claim.id_token.as_str().as_bytes().to_vec();
            let i = idx.index(bytes.len());
            prop_assume!(bytes[i] != b);
            bytes[i] = b;
            let tampered = IdentityClaim {
                node: claim.node,
                id_token: IdToken::new(String::from_utf8_lossy(&bytes).into_owned()),
            };
            prop_assert!(check(&tampered).is_err());
        }

        /// The nonce is deterministic per node and distinct across nodes.
        #[test]
        fn for_node_is_deterministic_and_distinct(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
            let (na, nb) = (NodeId::from_bytes(a), NodeId::from_bytes(b));
            prop_assert_eq!(OidcNonce::for_node(&na), OidcNonce::for_node(&na));
            if a != b {
                prop_assert_ne!(OidcNonce::for_node(&na), OidcNonce::for_node(&nb));
            }
            let s = OidcNonce::for_node(&na);
            prop_assert!(s.as_str().bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
        }
    }
}

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use snafu::{ensure, OptionExt, ResultExt};
use uuid::Uuid;

use crate::error::{
    BadCapSignatureSnafu, BadGlobSnafu, CapDeniedSnafu, CapExpiredSnafu, Result, SerializeEnvelopeSnafu,
};
use crate::wire::{CapId, Pubkey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Right {
    Read,
    Write,
}

impl std::fmt::Display for Right {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Right::Read => f.write_str("read"),
            Right::Write => f.write_str("write"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    #[serde(with = "hex::serde")]
    pub agent: Pubkey,
    pub topics: Vec<String>,    // glob patterns
    pub rights: Vec<Right>,
    pub issued: i64,            // unix ms
    pub expires: Option<i64>,   // unix ms, None = no expiry
    pub cap_id: CapIdRepr,
    #[serde(with = "hex::serde")]
    pub sig: [u8; 64],
}

/// Cap IDs are 16 bytes; hex string in JSON for human readability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapIdRepr(pub CapId);

impl Serialize for CapIdRepr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        hex::encode(self.0).serialize(s)
    }
}

impl<'de> Deserialize<'de> for CapIdRepr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: CapId = bytes.try_into().map_err(|_| serde::de::Error::custom("cap_id must be 16 bytes"))?;
        Ok(CapIdRepr(arr))
    }
}

impl Capability {
    pub fn new_unsigned(
        agent: Pubkey,
        topics: Vec<String>,
        rights: Vec<Right>,
        issued: i64,
        expires: Option<i64>,
    ) -> Self {
        let cap_id = CapIdRepr(*Uuid::new_v4().as_bytes());
        Self {
            agent,
            topics,
            rights,
            issued,
            expires,
            cap_id,
            sig: [0u8; 64],
        }
    }

    /// Bytes signed by the root: everything except `sig`.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct View<'a> {
            #[serde(with = "hex::serde")]
            agent: &'a Pubkey,
            topics: &'a [String],
            rights: &'a [Right],
            issued: i64,
            expires: Option<i64>,
            cap_id: &'a CapIdRepr,
        }
        let v = View {
            agent: &self.agent,
            topics: &self.topics,
            rights: &self.rights,
            issued: self.issued,
            expires: self.expires,
            cap_id: &self.cap_id,
        };
        serde_json::to_vec(&v).context(SerializeEnvelopeSnafu)
    }

    pub fn sign(&mut self, root_sk: &SigningKey) -> Result<()> {
        let bytes = self.signing_bytes()?;
        self.sig = root_sk.sign(&bytes).to_bytes();
        Ok(())
    }

    pub fn verify(&self, root_pk: &Pubkey) -> Result<()> {
        let vk = VerifyingKey::from_bytes(root_pk).ok().context(BadCapSignatureSnafu)?;
        let sig = ed25519_dalek::Signature::from_bytes(&self.sig);
        let bytes = self.signing_bytes()?;
        ensure!(vk.verify(&bytes, &sig).is_ok(), BadCapSignatureSnafu);
        Ok(())
    }

    pub fn check_not_expired(&self, now: i64) -> Result<()> {
        if let Some(exp) = self.expires {
            ensure!(
                now < exp,
                CapExpiredSnafu { issued: self.issued, expires: self.expires, now }
            );
        }
        Ok(())
    }

    pub fn allows(&self, topic_name: &str, right: Right) -> Result<()> {
        ensure!(
            self.rights.contains(&right),
            CapDeniedSnafu { right: right.to_string(), topic: topic_name.to_string() }
        );
        let any_match = self.topics.iter().any(|p| glob_matches(p, topic_name).unwrap_or(false));
        ensure!(
            any_match,
            CapDeniedSnafu { right: right.to_string(), topic: topic_name.to_string() }
        );
        Ok(())
    }
}

/// Dotted-namespace glob.
/// - `*` matches exactly one segment
/// - `**` matches zero or more segments
/// - anything else is a literal segment
pub fn glob_matches(pattern: &str, name: &str) -> Result<bool> {
    ensure!(!pattern.is_empty(), BadGlobSnafu { pattern: pattern.to_string() });
    let p: Vec<&str> = pattern.split('.').collect();
    let n: Vec<&str> = name.split('.').collect();
    Ok(matches_segments(&p, &n))
}

fn matches_segments(pattern: &[&str], name: &[&str]) -> bool {
    match (pattern.first(), name.first()) {
        (None, None) => true,
        (None, Some(_)) => false,
        (Some(&"**"), _) => {
            if matches_segments(&pattern[1..], name) { return true; }
            if name.is_empty() { return false; }
            matches_segments(pattern, &name[1..])
        }
        (Some(_), None) => false,
        (Some(&"*"), Some(_)) => matches_segments(&pattern[1..], &name[1..]),
        (Some(p), Some(n)) if p == n => matches_segments(&pattern[1..], &name[1..]),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    #[test]
    fn glob_literal_matches_exactly() {
        assert!(glob_matches("home.fridge", "home.fridge").unwrap());
        assert!(!glob_matches("home.fridge", "home.fridge.temp").unwrap());
        assert!(!glob_matches("home.fridge", "home").unwrap());
    }

    #[test]
    fn glob_star_matches_one_segment() {
        assert!(glob_matches("home.*", "home.fridge").unwrap());
        assert!(!glob_matches("home.*", "home.fridge.temp").unwrap());
        assert!(!glob_matches("home.*", "home").unwrap());
    }

    #[test]
    fn glob_doublestar_matches_zero_or_more() {
        assert!(glob_matches("home.**", "home").unwrap());
        assert!(glob_matches("home.**", "home.fridge").unwrap());
        assert!(glob_matches("home.**", "home.fridge.temp").unwrap());
        assert!(!glob_matches("home.**", "office.lamp").unwrap());
    }

    #[test]
    fn empty_pattern_rejected() {
        assert!(glob_matches("", "anything").is_err());
    }

    #[test]
    fn cap_sign_and_verify_roundtrip() {
        let root = SigningKey::generate(&mut OsRng);
        let root_pk = root.verifying_key().to_bytes();
        let mut cap = Capability::new_unsigned(
            [9u8; 32],
            vec!["home.*".to_string()],
            vec![Right::Read, Right::Write],
            1000,
            None,
        );
        cap.sign(&root).unwrap();
        cap.verify(&root_pk).unwrap();
    }

    #[test]
    fn cap_verify_fails_with_wrong_root() {
        let root_a = SigningKey::generate(&mut OsRng);
        let root_b = SigningKey::generate(&mut OsRng);
        let mut cap = Capability::new_unsigned([9u8; 32], vec![], vec![], 0, None);
        cap.sign(&root_a).unwrap();
        assert!(cap.verify(&root_b.verifying_key().to_bytes()).is_err());
    }

    #[test]
    fn cap_allows_check() {
        let cap = Capability::new_unsigned(
            [0u8; 32],
            vec!["home.*".to_string(), "mail.inbox".to_string()],
            vec![Right::Read],
            0,
            None,
        );
        cap.allows("home.fridge", Right::Read).unwrap();
        cap.allows("mail.inbox", Right::Read).unwrap();
        assert!(cap.allows("home.fridge", Right::Write).is_err());
        assert!(cap.allows("office.lamp", Right::Read).is_err());
    }

    #[test]
    fn cap_expired_check() {
        let mut cap = Capability::new_unsigned([0u8; 32], vec![], vec![], 100, Some(200));
        cap.check_not_expired(150).unwrap();
        assert!(cap.check_not_expired(250).is_err());
        cap.expires = None;
        cap.check_not_expired(i64::MAX).unwrap();
    }
}

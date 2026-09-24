//! Role definitions: named OR-of-matchers over a caller's verified IdP
//! [`Principal`] (card 27; the shape moved here from card 13's `host.json`).
//!
//! A **role** is an OR of [`Matcher`]s; a matcher is an AND of its keys
//! (`issuer`, `email`, `org`, `group`). Every matcher names its issuer, so a
//! role only ever admits a caller with a verified principal from that IdP:
//! there is no built-in role, and no role admits a caller without an
//! identity. "Anyone signed in with this IdP" is a matcher with only
//! `issuer`. Role definitions live in the admin-signed
//! [`State`](crate::State), so every host and every caller evaluates the same
//! table.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::idp::Principal;

/// The longest role name accepted.
pub const MAX_ROLE_NAME: usize = 64;

/// A role's name: 1–64 of `[A-Za-z0-9_.-]`.
///
/// ```
/// use library::RoleName;
/// assert!(RoleName::new("analyst").is_ok());
/// assert!(RoleName::new("has space").is_err());
/// // `member` is an ordinary name: nothing is built in.
/// assert!(RoleName::new("member").is_ok());
/// ```
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RoleName(String);

impl RoleName {
    /// Validate and wrap a role name; [`Error::InvalidRoleName`] if it breaks
    /// the rules in the type docs.
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        if name.is_empty()
            || name.len() > MAX_ROLE_NAME
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        {
            return Err(Error::InvalidRoleName);
        }
        Ok(Self(name))
    }

    /// The name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RoleName {
    type Error = Error;

    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}

impl From<RoleName> for String {
    fn from(r: RoleName) -> String {
        r.0
    }
}

impl fmt::Display for RoleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How an `email` key matches the verified email.
///
/// Emails and domains compare ASCII case-insensitively. `*@example.com`
/// matches `alice@example.com` but neither `alice@sub.example.com` nor
/// `alice@example.com.evil.net`.
///
/// ```
/// use library::EmailPattern;
/// let p: EmailPattern = "*@example.com".parse().unwrap();
/// assert!(p.matches("Alice@Example.com"));
/// assert!(!p.matches("alice@example.com.evil.net"));
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum EmailPattern {
    /// One address (stored lowercased).
    Exact(String),
    /// `*@domain`: any address at exactly this domain (stored lowercased).
    Domain(String),
}

impl EmailPattern {
    /// Whether `email` matches.
    pub fn matches(&self, email: &str) -> bool {
        match self {
            EmailPattern::Exact(want) => email.eq_ignore_ascii_case(want),
            EmailPattern::Domain(domain) => email
                .rsplit_once('@')
                .is_some_and(|(local, d)| !local.is_empty() && d.eq_ignore_ascii_case(domain)),
        }
    }
}

impl FromStr for EmailPattern {
    type Err = Error;

    /// An address, or `*@domain` (the only glob); else
    /// [`Error::InvalidEmailPattern`].
    fn from_str(s: &str) -> Result<Self> {
        if let Some(domain) = s.strip_prefix("*@") {
            if domain.is_empty() || domain.contains(['*', '@']) {
                return Err(Error::InvalidEmailPattern);
            }
            return Ok(EmailPattern::Domain(domain.to_ascii_lowercase()));
        }
        if s.contains('*') {
            return Err(Error::InvalidEmailPattern);
        }
        match s.split_once('@') {
            Some((local, domain))
                if !local.is_empty() && !domain.is_empty() && !domain.contains('@') =>
            {
                Ok(EmailPattern::Exact(s.to_ascii_lowercase()))
            }
            _ => Err(Error::InvalidEmailPattern),
        }
    }
}

impl TryFrom<String> for EmailPattern {
    type Error = Error;

    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl From<EmailPattern> for String {
    fn from(p: EmailPattern) -> String {
        p.to_string()
    }
}

impl fmt::Display for EmailPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmailPattern::Exact(e) => f.write_str(e),
            EmailPattern::Domain(d) => write!(f, "*@{d}"),
        }
    }
}

/// One entry of a role: `issuer` and every other key present must hold (AND).
///
/// | key      | matches                                                   |
/// |----------|-----------------------------------------------------------|
/// | `issuer` | [`Principal::issuer`], exactly; **always required**       |
/// | `email`  | the verified email: exact, or `*@domain` (the only glob)  |
/// | `org`    | [`Principal::org`] (Google's `hd`), ASCII case-insensitive|
/// | `group`  | one of [`Principal::groups`], exactly                     |
///
/// Every matcher names the IdP it trusts, so `*@acme.com` from one issuer is
/// never satisfied by a token another trusted issuer minted for
/// `alice@acme.com`. A matcher with only `issuer` admits anyone that IdP
/// verified. A matcher never matches a caller without a verified principal,
/// and a matcher whose `issuer` is empty is refused by
/// [`State::validate`](crate::State::validate).
///
/// Inside the signed state, absent optional keys are omitted from the
/// canonical JSON; that is sound because the matcher is signed as part of the
/// whole state body, and "absent" vs "present" can't be confused (there is no
/// default value that means "any").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matcher {
    /// `issuer`: the IdP, exactly (e.g. `https://accounts.google.com`).
    pub issuer: String,
    /// `email`: the verified email.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<EmailPattern>,
    /// `org`: the org / hosted domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// `group`: a group the IdP says the principal is in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

impl Matcher {
    /// A matcher on `issuer` alone (anyone that IdP verified); set the other
    /// keys with struct-update syntax.
    ///
    /// ```
    /// use library::Matcher;
    /// let m = Matcher {
    ///     email: Some("*@example.com".parse().unwrap()),
    ///     ..Matcher::new("https://accounts.google.com")
    /// };
    /// assert_eq!(m.to_string(), "issuer=https://accounts.google.com,email=*@example.com");
    /// ```
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            email: None,
            org: None,
            group: None,
        }
    }

    /// Whether `p` satisfies every key: its issuer is exactly `issuer`, and
    /// each other key present holds.
    ///
    /// ```
    /// use library::{Matcher, Principal};
    /// let m = Matcher {
    ///     email: Some("*@example.com".parse().unwrap()),
    ///     ..Matcher::new("https://idp")
    /// };
    /// let mut p = Principal {
    ///     issuer: "https://idp".into(), subject: "1".into(),
    ///     email: Some("alice@example.com".into()), org: None, groups: vec![],
    ///     not_after: 0, claims: Default::default(),
    /// };
    /// assert!(m.matches(&p));
    /// p.issuer = "https://other-idp".into();
    /// assert!(!m.matches(&p), "same email, different IdP");
    /// ```
    pub fn matches(&self, p: &Principal) -> bool {
        p.issuer == self.issuer
            && self
                .email
                .as_ref()
                .is_none_or(|pat| p.email.as_deref().is_some_and(|e| pat.matches(e)))
            && self.org.as_ref().is_none_or(|org| {
                p.org
                    .as_deref()
                    .is_some_and(|have| have.eq_ignore_ascii_case(org))
            })
            && self
                .group
                .as_ref()
                .is_none_or(|g| p.groups.iter().any(|have| have == g))
    }
}

impl fmt::Display for Matcher {
    /// `issuer=…,email=…,org=…,group=…` (`issuer`, then the keys present, in
    /// that order).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = vec![format!("issuer={}", self.issuer)];
        if let Some(v) = &self.email {
            parts.push(format!("email={v}"));
        }
        if let Some(v) = &self.org {
            parts.push(format!("org={v}"));
        }
        if let Some(v) = &self.group {
            parts.push(format!("group={v}"));
        }
        f.write_str(&parts.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const ISS: &str = "https://idp.example";

    fn principal(email: &str) -> Principal {
        Principal {
            issuer: ISS.into(),
            subject: "s".into(),
            email: Some(email.into()),
            org: None,
            groups: vec!["sre".into()],
            not_after: 0,
            claims: Default::default(),
        }
    }

    #[test]
    fn role_names() {
        assert!(RoleName::new("a.b-c_1").is_ok());
        assert!(RoleName::new("").is_err());
        assert!(RoleName::new("x".repeat(65)).is_err());
        assert!(serde_json::from_str::<RoleName>("\"bad name\"").is_err());
    }

    #[test]
    fn matcher_is_an_and() {
        let m = Matcher {
            email: Some("*@example.com".parse().unwrap()),
            group: Some("sre".into()),
            ..Matcher::new(ISS)
        };
        assert!(m.matches(&principal("a@example.com")));
        assert!(!m.matches(&principal("a@other.com")));
        let m = Matcher {
            group: Some("dba".into()),
            ..m
        };
        assert!(!m.matches(&principal("a@example.com")));
    }

    #[test]
    fn an_issuer_only_matcher_admits_anyone_that_idp_verified() {
        let m = Matcher::new(ISS);
        assert!(m.matches(&principal("anyone@anywhere.net")));
        let mut p = principal("anyone@anywhere.net");
        p.issuer = "https://elsewhere".into();
        assert!(!m.matches(&p));
    }

    #[test]
    fn email_patterns() {
        assert!("*@*".parse::<EmailPattern>().is_err());
        assert!("a*b@x".parse::<EmailPattern>().is_err());
        assert!("nope".parse::<EmailPattern>().is_err());
        let p: EmailPattern = "Bob@X.com".parse().unwrap();
        assert!(p.matches("bob@x.com"));
        assert_eq!(p.to_string(), "bob@x.com");
    }

    #[test]
    fn matcher_rejects_unknown_keys() {
        assert!(
            serde_json::from_str::<Matcher>(r#"{"issuer":"https://i","emial":"a@b.c"}"#).is_err()
        );
    }

    #[test]
    fn matcher_requires_an_issuer_on_the_wire() {
        assert!(serde_json::from_str::<Matcher>(r#"{"email":"a@b.c"}"#).is_err());
        let m: Matcher = serde_json::from_str(r#"{"issuer":"https://i","email":"a@b.c"}"#).unwrap();
        assert_eq!(m.issuer, "https://i");
    }

    proptest! {
        /// A matcher never matches a principal from another issuer, whatever
        /// the other keys and claims say.
        #[test]
        fn a_matcher_never_crosses_issuers(
            matcher_iss in "https://[a-c]\\.example",
            token_iss in "https://[a-c]\\.example",
            email in prop::option::of(prop::sample::select(vec!["*@acme.com", "alice@acme.com"])),
            org in prop::option::of(Just("acme.com".to_string())),
            group in prop::option::of(Just("sre".to_string())),
        ) {
            let m = Matcher {
                email: email.map(|e| e.parse().unwrap()),
                org,
                group,
                ..Matcher::new(matcher_iss.clone())
            };
            let p = Principal {
                issuer: token_iss.clone(),
                subject: "s".into(),
                email: Some("alice@acme.com".into()),
                org: Some("acme.com".into()),
                groups: vec!["sre".into()],
                not_after: 0,
                claims: Default::default(),
            };
            prop_assert_eq!(m.matches(&p), matcher_iss == token_iss);
        }
    }
}

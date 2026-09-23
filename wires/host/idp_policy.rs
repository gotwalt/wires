//! `serve --require-idp`: which verified identities may call (board card 05).
//!
//! A policy is a list of [`IdpRule`]s, one per `--require-idp` flag, and a
//! principal is allowed when **any** rule matches (OR). Within one rule every
//! condition must hold (AND):
//!
//! ```text
//! --require-idp 'iss=https://accounts.google.com,email=*@example.com'
//! --require-idp 'iss=https://login.partner.example,group=oncall'
//! ```
//!
//! | key     | matches                                                       |
//! |---------|---------------------------------------------------------------|
//! | `iss`   | [`Principal::issuer`], exactly                                |
//! | `email` | the verified email: exact, or `*@domain` (the only glob)      |
//! | `org`   | [`Principal::org`] (Google's `hd`), ASCII case-insensitively  |
//! | `group` | one of [`Principal::groups`], exactly (repeatable: all needed)|
//!
//! Emails and domains compare ASCII case-insensitively. `*@example.com`
//! matches `alice@example.com` but neither `alice@sub.example.com` nor
//! `alice@example.com.evil.net`. A rule with no `iss` accepts every issuer the
//! responder trusts (`WIRES_OIDC_ISSUER`, plus the `iss` of every rule).
//!
//! Matching only ever sees a [`Principal`] that [`crate::jwks`] verified; the
//! email is present only when the IdP marked it verified.

use std::fmt;
use std::str::FromStr;

use anyhow::{Result, anyhow, bail};
use library::{Issuer, Principal};

/// How an `email=` condition matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EmailPattern {
    /// One address (stored lowercased).
    Exact(String),
    /// `*@domain`: any address at exactly this domain (stored lowercased).
    Domain(String),
}

impl EmailPattern {
    /// Whether `email` matches.
    fn matches(&self, email: &str) -> bool {
        match self {
            EmailPattern::Exact(want) => email.eq_ignore_ascii_case(want),
            EmailPattern::Domain(domain) => email
                .rsplit_once('@')
                .is_some_and(|(local, d)| !local.is_empty() && d.eq_ignore_ascii_case(domain)),
        }
    }
}

impl FromStr for EmailPattern {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if let Some(domain) = s.strip_prefix("*@") {
            if domain.is_empty() || domain.contains(['*', '@']) {
                bail!("email pattern {s:?}: the only glob is `*@domain`");
            }
            return Ok(EmailPattern::Domain(domain.to_ascii_lowercase()));
        }
        if s.contains('*') {
            bail!("email pattern {s:?}: the only glob is `*@domain`");
        }
        match s.split_once('@') {
            Some((local, domain))
                if !local.is_empty() && !domain.is_empty() && !domain.contains('@') =>
            {
                Ok(EmailPattern::Exact(s.to_ascii_lowercase()))
            }
            _ => bail!("email pattern {s:?} is neither an address nor `*@domain`"),
        }
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

/// One `key=value` condition of a rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Condition {
    /// `iss=`: the issuer, exactly.
    Issuer(String),
    /// `email=`: the verified email.
    Email(EmailPattern),
    /// `org=`: the org / hosted domain.
    Org(String),
    /// `group=`: a group membership.
    Group(String),
}

impl Condition {
    /// Whether `p` satisfies this condition.
    fn matches(&self, p: &Principal) -> bool {
        match self {
            Condition::Issuer(iss) => p.issuer == *iss,
            Condition::Email(pattern) => p.email.as_deref().is_some_and(|e| pattern.matches(e)),
            Condition::Org(org) => p
                .org
                .as_deref()
                .is_some_and(|o| o.eq_ignore_ascii_case(org)),
            Condition::Group(g) => p.groups.iter().any(|have| have == g),
        }
    }

    /// The flag key this condition is written under.
    fn key(&self) -> &'static str {
        match self {
            Condition::Issuer(_) => "iss",
            Condition::Email(_) => "email",
            Condition::Org(_) => "org",
            Condition::Group(_) => "group",
        }
    }
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Condition::Issuer(v) | Condition::Org(v) | Condition::Group(v) => {
                write!(f, "{}={v}", self.key())
            }
            Condition::Email(p) => write!(f, "email={p}"),
        }
    }
}

/// One `--require-idp` flag: every condition must hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IdpRule {
    /// The conditions, in flag order (never empty).
    conditions: Vec<Condition>,
}

impl IdpRule {
    /// Whether `p` satisfies every condition.
    pub(crate) fn matches(&self, p: &Principal) -> bool {
        self.conditions.iter().all(|c| c.matches(p))
    }

    /// The issuer this rule pins, if any.
    pub(crate) fn issuer(&self) -> Option<&str> {
        self.conditions.iter().find_map(|c| match c {
            Condition::Issuer(iss) => Some(iss.as_str()),
            _ => None,
        })
    }
}

impl FromStr for IdpRule {
    type Err = anyhow::Error;

    /// Parse `key=value[,key=value…]`. Keys: `iss`, `email`, `org` (each at
    /// most once) and `group` (repeatable). Values are trimmed and non-empty.
    fn from_str(s: &str) -> Result<Self> {
        let mut conditions = Vec::new();
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (key, value) = part
                .split_once('=')
                .ok_or_else(|| anyhow!("--require-idp {s:?}: {part:?} is not key=value"))?;
            let (key, value) = (key.trim(), value.trim());
            if value.is_empty() {
                bail!("--require-idp {s:?}: {key} has an empty value");
            }
            let condition = match key {
                "iss" => Condition::Issuer(value.to_string()),
                "email" => Condition::Email(value.parse()?),
                "org" => Condition::Org(value.to_string()),
                "group" => Condition::Group(value.to_string()),
                other => bail!(
                    "--require-idp {s:?}: unknown key {other:?} (expected iss, email, org, group)"
                ),
            };
            if key != "group" && conditions.iter().any(|c: &Condition| c.key() == key) {
                bail!("--require-idp {s:?}: {key} given twice");
            }
            conditions.push(condition);
        }
        if conditions.is_empty() {
            bail!("--require-idp {s:?} has no conditions");
        }
        Ok(Self { conditions })
    }
}

impl fmt::Display for IdpRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, c) in self.conditions.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{c}")?;
        }
        Ok(())
    }
}

/// Every `--require-idp` flag: a principal passes when any rule matches. An
/// empty policy requires nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct IdpPolicy {
    /// The rules, OR'd.
    rules: Vec<IdpRule>,
}

impl IdpPolicy {
    /// Parse every `--require-idp` value.
    pub(crate) fn parse(flags: &[String]) -> Result<Self> {
        Ok(Self {
            rules: flags.iter().map(|f| f.parse()).collect::<Result<_>>()?,
        })
    }

    /// Whether no identity is required at all.
    pub(crate) fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Whether some rule admits `p`.
    pub(crate) fn allows(&self, p: &Principal) -> bool {
        self.rules.iter().any(|r| r.matches(p))
    }

    /// The issuers the rules pin (to add to the responder's trusted set).
    pub(crate) fn issuers(&self) -> Vec<Issuer> {
        let mut out: Vec<Issuer> = Vec::new();
        for iss in self.rules.iter().filter_map(IdpRule::issuer) {
            let iss = Issuer::new(iss);
            if !out.contains(&iss) {
                out.push(iss);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const GOOGLE: &str = "https://accounts.google.com";

    fn principal(issuer: &str, email: Option<&str>) -> Principal {
        Principal {
            issuer: issuer.into(),
            subject: "1".into(),
            email: email.map(str::to_string),
            org: None,
            groups: vec![],
            not_after: 0,
        }
    }

    #[test]
    fn parses_the_card_example() {
        let rule: IdpRule = "iss=https://accounts.google.com,email=*@example.com"
            .parse()
            .unwrap();
        assert_eq!(rule.issuer(), Some(GOOGLE));
        assert!(rule.matches(&principal(GOOGLE, Some("alice@example.com"))));
        assert!(rule.matches(&principal(GOOGLE, Some("Alice@EXAMPLE.com"))));
        assert!(!rule.matches(&principal(GOOGLE, Some("alice@other.com"))));
        assert!(!rule.matches(&principal("https://other", Some("alice@example.com"))));
        assert!(!rule.matches(&principal(GOOGLE, None)), "no verified email");
    }

    #[test]
    fn parse_errors_name_the_problem() {
        for (bad, why) in [
            ("", "no conditions"),
            (" , ", "no conditions"),
            ("iss", "not key=value"),
            ("iss=", "empty value"),
            ("foo=bar", "unknown key"),
            ("iss=a,iss=b", "given twice"),
            ("email=a@b,email=c@d", "given twice"),
            ("email=*", "only glob"),
            ("email=a*@example.com", "only glob"),
            ("email=*@", "only glob"),
            ("email=*@*.example.com", "only glob"),
            ("email=nobody", "neither an address"),
            ("email=@example.com", "neither an address"),
        ] {
            let e = bad.parse::<IdpRule>().unwrap_err().to_string();
            assert!(e.contains(why), "{bad:?}: {e}");
        }
    }

    #[test]
    fn org_and_groups() {
        let rule: IdpRule = "org=Example.com,group=oncall,group=db".parse().unwrap();
        let mut p = principal(GOOGLE, Some("a@example.com"));
        assert!(!rule.matches(&p), "no org");
        p.org = Some("example.com".into());
        p.groups = vec!["oncall".into()];
        assert!(!rule.matches(&p), "every group is required");
        p.groups.push("db".into());
        assert!(rule.matches(&p));
    }

    #[test]
    fn a_policy_is_an_or_of_rules() {
        let policy = IdpPolicy::parse(&[
            format!("iss={GOOGLE},email=*@example.com"),
            "iss=https://partner,email=*@partner.org".into(),
        ])
        .unwrap();
        assert!(!policy.is_empty());
        assert!(policy.allows(&principal(GOOGLE, Some("a@example.com"))));
        assert!(policy.allows(&principal("https://partner", Some("b@partner.org"))));
        assert!(!policy.allows(&principal(GOOGLE, Some("b@partner.org"))));
        assert!(!policy.allows(&principal("https://third", Some("e@evil.net"))));
        assert_eq!(
            policy.issuers(),
            vec![Issuer::new(GOOGLE), Issuer::new("https://partner")]
        );
        let empty = IdpPolicy::parse(&[]).unwrap();
        assert!(empty.is_empty());
        assert!(!empty.allows(&principal(GOOGLE, Some("a@example.com"))));
    }

    fn label() -> impl Strategy<Value = String> {
        "[a-z0-9]([a-z0-9-]{0,8}[a-z0-9])?"
    }

    fn domain() -> impl Strategy<Value = String> {
        proptest::collection::vec(label(), 1..4).prop_map(|l| l.join("."))
    }

    fn local() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9._+-]{1,12}"
    }

    fn condition() -> impl Strategy<Value = Condition> {
        prop_oneof![
            "https://[a-z]{1,8}\\.example".prop_map(Condition::Issuer),
            (local(), domain()).prop_map(|(l, d)| Condition::Email(EmailPattern::Exact(
                format!("{l}@{d}").to_ascii_lowercase()
            ))),
            domain().prop_map(|d| Condition::Email(EmailPattern::Domain(d))),
            domain().prop_map(Condition::Org),
            "[a-z][a-z0-9_-]{0,8}".prop_map(Condition::Group),
        ]
    }

    proptest! {
        /// `*@domain` matches every address at exactly that domain, in any
        /// ASCII case, and nothing at a sub-, super- or look-alike domain.
        #[test]
        fn domain_glob_matches_exactly_that_domain(
            l in local(), d in domain(), other in domain(), upper in any::<bool>()
        ) {
            let pattern: EmailPattern = format!("*@{d}").parse().unwrap();
            let email = format!("{l}@{d}");
            let email = if upper { email.to_ascii_uppercase() } else { email };
            let (sub, lookalike, no_local) =
                (format!("{l}@sub.{d}"), format!("{l}@{d}.evil.net"), format!("@{d}"));
            prop_assert!(pattern.matches(&email));
            prop_assert!(!pattern.matches(&sub));
            prop_assert!(!pattern.matches(&lookalike));
            prop_assert!(!pattern.matches(&no_local));
            let elsewhere = format!("{l}@{other}");
            if !other.eq_ignore_ascii_case(&d) {
                prop_assert!(!pattern.matches(&elsewhere));
            }
        }

        /// An exact address matches itself (any case) and no other address.
        #[test]
        fn exact_email_matches_only_itself(
            l in local(), d in domain(), l2 in local(), d2 in domain()
        ) {
            let email = format!("{l}@{d}");
            let pattern: EmailPattern = email.parse().unwrap();
            prop_assert!(pattern.matches(&email.to_ascii_uppercase()));
            let other = format!("{l2}@{d2}");
            prop_assert_eq!(pattern.matches(&other), other.eq_ignore_ascii_case(&email));
        }

        /// A rule pinned to one issuer never admits a principal from another,
        /// whatever else matches.
        #[test]
        fn a_pinned_issuer_is_never_bypassed(l in local(), d in domain(), iss in "[a-z]{1,8}") {
            let rule: IdpRule = format!("iss=https://{iss}.example,email=*@{d}").parse().unwrap();
            let email = format!("{l}@{d}");
            let (pinned, other) =
                (format!("https://{iss}.example"), format!("https://{iss}.example.evil"));
            prop_assert!(rule.matches(&principal(&pinned, Some(&email))));
            prop_assert!(!rule.matches(&principal(&other, Some(&email))));
        }

        /// Display and parse round-trip.
        #[test]
        fn rules_round_trip(conditions in proptest::collection::vec(condition(), 1..5)) {
            // One of each single-valued key, as the parser requires.
            let mut seen = Vec::new();
            let conditions: Vec<Condition> = conditions
                .into_iter()
                .filter(|c| c.key() == "group" || {
                    let fresh = !seen.contains(&c.key());
                    seen.push(c.key());
                    fresh
                })
                .collect();
            let rule = IdpRule { conditions };
            prop_assert_eq!(rule.to_string().parse::<IdpRule>().unwrap(), rule);
        }
    }
}

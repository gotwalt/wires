//! How a reader shows an [`IdentityClaim`] it saw on a channel (card 04).
//!
//! Every reader verifies the claim **itself** (see [`crate::jwks`]); this
//! module turns the verdict into the one line a `wires tail` prints, and holds
//! the reader's trust settings ([`IdpTrust`]).
//!
//! The integrator hooks [`describe_identity`] into `render.rs` (lane B) for
//! `ChannelRecord::Identity`, in place of the "unverified" placeholder there;
//! [`render_identity`] is the async wrapper that fetches keys first.

// Unused by the shipped binary until the integrator wires it into render.rs;
// remove this once `wires tail` calls `render_identity`.
#![cfg_attr(not(test), allow(dead_code))]

use library::{Audience, IdentityClaim, Issuer, Principal};

use crate::jwks::{KeyFetcher, VerifyError};

/// The default issuer: Google, the demo IdP.
pub(crate) const DEFAULT_ISSUER: &str = "https://accounts.google.com";

/// Which issuers and audiences a reader accepts identity claims from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IdpTrust {
    /// Issuers whose keys this reader will fetch and trust.
    pub issuers: Vec<Issuer>,
    /// Accepted `aud` values (OAuth client ids).
    pub audiences: Vec<Audience>,
}

impl IdpTrust {
    /// From the environment:
    ///
    /// - `WIRES_OIDC_ISSUER` — comma-separated issuers (default
    ///   [`DEFAULT_ISSUER`]);
    /// - `WIRES_OIDC_AUDIENCE` — comma-separated accepted client ids, falling
    ///   back to `WIRES_OIDC_CLIENT_ID`.
    pub(crate) fn from_env() -> Self {
        Self::from_vars(
            std::env::var("WIRES_OIDC_ISSUER").ok().as_deref(),
            std::env::var("WIRES_OIDC_AUDIENCE")
                .ok()
                .or_else(|| std::env::var("WIRES_OIDC_CLIENT_ID").ok())
                .as_deref(),
        )
    }

    /// The testable half of [`from_env`](Self::from_env).
    pub(crate) fn from_vars(issuers: Option<&str>, audiences: Option<&str>) -> Self {
        let split = |s: &str| -> Vec<String> {
            s.split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_string)
                .collect()
        };
        let mut iss: Vec<Issuer> = split(issuers.unwrap_or(""))
            .into_iter()
            .map(Issuer::new)
            .collect();
        if iss.is_empty() {
            iss.push(Issuer::new(DEFAULT_ISSUER));
        }
        Self {
            issuers: iss,
            audiences: split(audiences.unwrap_or(""))
                .into_iter()
                .map(Audience::new)
                .collect(),
        }
    }
}

/// Verify `claim` with `fetcher` and render the line (the async wrapper).
pub(crate) async fn render_identity(
    fetcher: &KeyFetcher,
    trust: &IdpTrust,
    claim: &IdentityClaim,
    now: i64,
) -> String {
    let verdict = fetcher
        .verify(claim, &trust.issuers, &trust.audiences, now)
        .await;
    describe_identity(claim, &verdict)
}

/// The one line a reader prints for an identity claim, given its verdict.
///
/// - verified: `identity 3f2a1b9c is alice@example.com (verified by https://accounts.google.com)`
/// - stale:    `identity 3f2a1b9c is alice@example.com (expired)`
/// - failed:   `identity 3f2a1b9c UNVERIFIED: nonce does not bind this token to node …`
///
/// Pure, so it is what the renderer and its tests call.
pub(crate) fn describe_identity(
    claim: &IdentityClaim,
    verdict: &Result<Principal, VerifyError>,
) -> String {
    let who = short(claim);
    match verdict {
        Ok(p) => {
            let org = p
                .org
                .as_deref()
                .map(|o| format!(", org {o}"))
                .unwrap_or_default();
            format!(
                "identity {who} is {} (verified by {}{org})",
                name(p),
                p.issuer
            )
        }
        Err(VerifyError::Expired(p)) => format!("identity {who} is {} (expired)", name(p)),
        Err(e) => format!("identity {who} UNVERIFIED: {e}"),
    }
}

/// The human name for a principal: the verified email, else `sub` at the
/// issuer.
fn name(p: &Principal) -> String {
    match &p.email {
        Some(email) => email.clone(),
        None => format!("{} at {}", p.subject, p.issuer),
    }
}

/// The node's first 8 hex characters, like the tail's sender column.
fn short(claim: &IdentityClaim) -> String {
    let hex = claim.node.hex();
    hex[..8.min(hex.len())].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{IdToken, IdTokenError, NodeIdentity};

    fn claim() -> IdentityClaim {
        IdentityClaim {
            node: NodeIdentity::from_seed([5; 32]).node_id(),
            id_token: IdToken::new("x.y.z"),
        }
    }

    fn alice() -> Principal {
        Principal {
            issuer: "https://accounts.google.com".into(),
            subject: "42".into(),
            email: Some("alice@example.com".into()),
            org: None,
            groups: vec![],
            not_after: 0,
        }
    }

    #[test]
    fn each_verdict_renders_its_own_line() {
        let c = claim();
        let short = &c.node.hex()[..8];
        assert_eq!(
            describe_identity(&c, &Ok(alice())),
            format!(
                "identity {short} is alice@example.com (verified by https://accounts.google.com)"
            )
        );
        let mut corp = alice();
        corp.org = Some("example.com".into());
        assert!(describe_identity(&c, &Ok(corp)).ends_with(", org example.com)"));
        let mut anon = alice();
        anon.email = None;
        assert!(describe_identity(&c, &Ok(anon)).contains("is 42 at https://accounts.google.com"));
        assert_eq!(
            describe_identity(&c, &Err(VerifyError::Expired(alice()))),
            format!("identity {short} is alice@example.com (expired)")
        );
        let bad = describe_identity(
            &c,
            &Err(VerifyError::Rejected(IdTokenError::WrongNonce {
                node: c.node.hex(),
            })),
        );
        assert!(bad.starts_with(&format!("identity {short} UNVERIFIED: nonce")));
        let untrusted =
            describe_identity(&c, &Err(VerifyError::Untrusted(Issuer::new("https://x"))));
        assert!(untrusted.contains("not trusted"));
    }

    #[test]
    fn trust_defaults_to_google_and_splits_lists() {
        let t = IdpTrust::from_vars(None, Some("a, b,,"));
        assert_eq!(t.issuers, vec![Issuer::new(DEFAULT_ISSUER)]);
        assert_eq!(t.audiences, vec![Audience::new("a"), Audience::new("b")]);
        let t = IdpTrust::from_vars(Some("https://one, https://two"), None);
        assert_eq!(t.issuers.len(), 2);
        assert!(t.audiences.is_empty());
        // Whatever the test environment holds, there is always an issuer.
        assert!(!IdpTrust::from_env().issuers.is_empty());
    }
}

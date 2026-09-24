//! The gateway's OAuth bookkeeping: authorizations in flight, one-time
//! authorization codes, and the access tokens it issued.
//!
//! An access token is 32 random bytes the client presents as a bearer token;
//! behind it is a [`Session`]: the web user's verified [`Principal`] and the
//! Google ID token that proves it, nonce-bound to the gateway's node key.
//! The token lives exactly as long as that ID token (a host drops the
//! principal at its `exp` too), and there is no refresh: Google omits the
//! `nonce` when it refreshes, so a renewed token could not be bound to this
//! node. The client signs in again instead.
//!
//! Sessions are kept in memory and written through to a `0600` file keyed by
//! the SHA-256 of the access token, so a restart doesn't sign everyone out.
//! The file holds no access token, but it does hold each session's live ID
//! token: with the gateway's `node.seed` (in the same keystore) those are
//! usable until they expire, so the keystore is as sensitive as the node key.
//! Authorizations and codes are memory only: they live for minutes, and each
//! map is capped ([`MAX_PENDING`], [`MAX_CODES`]), oldest evicted first, so
//! unauthenticated traffic can't grow memory without bound.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Context, Result};
use base64::Engine as _;
use library::{IdToken, Principal};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::caller::login::{random_token, save_secret};

/// How long an authorization may sit between `/authorize` and Google's
/// redirect back (the consent page, then the Google sign-in).
pub(crate) const PENDING_TTL_SECS: i64 = 600;
/// How long an authorization code is redeemable (OAuth 2.1 recommends short).
pub(crate) const CODE_TTL_SECS: i64 = 60;
/// Most authorizations in flight at once; the oldest is evicted past this.
pub(crate) const MAX_PENDING: usize = 1024;
/// Most unredeemed codes at once; the oldest is evicted past this.
pub(crate) const MAX_CODES: usize = 1024;

/// Who a token speaks for, and the proof the hosts will check.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Session {
    /// The web user, as the gateway verified their ID token.
    pub(crate) principal: Principal,
    /// That ID token: presented, unchanged, in every call's handshake.
    pub(crate) id_token: IdToken,
    /// The OAuth client the token was issued to.
    pub(crate) client_id: String,
    /// The resource (RFC 8707) the token is bound to: this gateway's `/mcp`.
    pub(crate) resource: String,
}

impl Session {
    /// Unix seconds after which the session is over: the ID token's `exp`.
    pub(crate) fn not_after(&self) -> i64 {
        self.principal.not_after
    }
}

/// An authorization in flight: what the client asked for, and the PKCE
/// verifier of the gateway's own sign-in with Google.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Authorization {
    /// The client's id (a DCR id or a metadata document URL).
    pub(crate) client_id: String,
    /// The client's display name, for the consent page.
    pub(crate) client_name: String,
    /// Where the code goes (validated against the client's registration).
    pub(crate) redirect_uri: Url,
    /// The client's `state`, echoed back.
    pub(crate) state: Option<String>,
    /// The client's S256 PKCE challenge.
    pub(crate) code_challenge: String,
    /// The resource the token will be bound to.
    pub(crate) resource: String,
    /// The PKCE verifier for the upstream (Google) leg.
    pub(crate) upstream_verifier: String,
    /// The client's OIDC `login_hint`, passed on to the IdP.
    pub(crate) login_hint: Option<String>,
    /// When `/authorize` saw it, Unix seconds.
    pub(crate) created: i64,
}

/// An issued, unredeemed authorization code.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CodeGrant {
    /// The client it was issued to.
    pub(crate) client_id: String,
    /// The redirect URI it was sent to (must be repeated at `/token`).
    pub(crate) redirect_uri: Url,
    /// The client's S256 PKCE challenge.
    pub(crate) code_challenge: String,
    /// What the access token will carry.
    pub(crate) session: Session,
    /// Unix seconds after which the code is void.
    pub(crate) expires: i64,
}

#[derive(Default)]
struct Inner {
    pending: HashMap<String, Authorization>,
    codes: HashMap<String, CodeGrant>,
    /// Token hash (hex) → session.
    tokens: HashMap<String, Session>,
}

/// The gateway's OAuth state. Every method takes `now` (Unix seconds), so
/// expiry is testable without a clock.
pub(crate) struct Store {
    inner: Mutex<Inner>,
    file: Option<PathBuf>,
}

impl Store {
    /// A store persisting sessions to `file` (loaded now, expired ones
    /// dropped), or memory-only when `None`.
    pub(crate) fn open(file: Option<PathBuf>, now: i64) -> Result<Self> {
        let mut tokens: HashMap<String, Session> = match &file {
            Some(path) => match std::fs::read_to_string(path) {
                Ok(text) => serde_json::from_str(&text)
                    .with_context(|| format!("reading sessions from {}", path.display()))?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
                Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
            },
            None => HashMap::new(),
        };
        tokens.retain(|_, s| s.not_after() > now);
        Ok(Self {
            inner: Mutex::new(Inner {
                tokens,
                ..Inner::default()
            }),
            file,
        })
    }

    /// Record an authorization; returns its id (sent to Google as `state`).
    pub(crate) fn begin(&self, a: Authorization) -> Result<String> {
        let id = random_token(24)?;
        let mut inner = self.lock();
        let now = a.created;
        inner
            .pending
            .retain(|_, p| p.created + PENDING_TTL_SECS > now);
        while inner.pending.len() >= MAX_PENDING {
            let oldest = inner
                .pending
                .iter()
                .min_by_key(|(_, p)| p.created)
                .map(|(k, _)| k.clone())
                .expect("non-empty");
            inner.pending.remove(&oldest);
        }
        inner.pending.insert(id.clone(), a);
        Ok(id)
    }

    /// The authorization `id`, if it is still live (it stays pending).
    pub(crate) fn pending(&self, id: &str, now: i64) -> Option<Authorization> {
        let inner = self.lock();
        inner
            .pending
            .get(id)
            .filter(|p| p.created + PENDING_TTL_SECS > now)
            .cloned()
    }

    /// Remove and return the authorization `id`, if it is still live.
    pub(crate) fn finish(&self, id: &str, now: i64) -> Option<Authorization> {
        self.lock()
            .pending
            .remove(id)
            .filter(|p| p.created + PENDING_TTL_SECS > now)
    }

    /// Mint a one-time authorization code for `grant`.
    pub(crate) fn issue_code(&self, grant: CodeGrant) -> Result<String> {
        let code = random_token(32)?;
        let mut inner = self.lock();
        let now = grant.expires - CODE_TTL_SECS;
        inner.codes.retain(|_, c| c.expires > now);
        while inner.codes.len() >= MAX_CODES {
            let oldest = inner
                .codes
                .iter()
                .min_by_key(|(_, c)| c.expires)
                .map(|(k, _)| k.clone())
                .expect("non-empty");
            inner.codes.remove(&oldest);
        }
        inner.codes.insert(code.clone(), grant);
        Ok(code)
    }

    /// Redeem `code`: it is gone afterwards whatever the outcome, so a
    /// replayed code never works twice (OAuth 2.1 §4.1.3).
    pub(crate) fn redeem_code(&self, code: &str, now: i64) -> Option<CodeGrant> {
        self.lock().codes.remove(code).filter(|c| c.expires > now)
    }

    /// Mint an access token for `session`; persisted if the store has a file.
    pub(crate) fn issue_token(&self, session: Session, now: i64) -> Result<String> {
        let token = random_token(32)?;
        let mut inner = self.lock();
        inner.tokens.retain(|_, s| s.not_after() > now);
        inner.tokens.insert(token_hash(&token), session);
        self.persist(&inner)?;
        Ok(token)
    }

    /// The live session behind `token`, if any.
    pub(crate) fn session(&self, token: &str, now: i64) -> Option<Session> {
        self.lock()
            .tokens
            .get(&token_hash(token))
            .filter(|s| s.not_after() > now)
            .cloned()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn persist(&self, inner: &Inner) -> Result<()> {
        let Some(path) = &self.file else {
            return Ok(());
        };
        save_secret(path, &serde_json::to_string(&inner.tokens)?)
    }
}

/// SHA-256 of an access token, base64url: how the store keys it.
fn token_hash(token: &str) -> String {
    library::B64.encode(ring::digest::digest(
        &ring::digest::SHA256,
        token.as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const NOW: i64 = 1_800_000_000;

    fn session(not_after: i64) -> Session {
        Session {
            principal: Principal {
                issuer: "https://accounts.google.com".into(),
                subject: "1".into(),
                email: Some("alice@example.com".into()),
                org: None,
                groups: vec![],
                not_after,
                claims: Default::default(),
            },
            id_token: IdToken::new("h.p.s"),
            client_id: "c".into(),
            resource: "https://wires.example/mcp".into(),
        }
    }

    fn authorization(created: i64) -> Authorization {
        Authorization {
            client_id: "c".into(),
            client_name: "Claude".into(),
            redirect_uri: Url::parse("https://claude.ai/api/mcp/auth_callback").unwrap(),
            state: Some("s".into()),
            code_challenge: "x".into(),
            resource: "https://wires.example/mcp".into(),
            upstream_verifier: "v".into(),
            login_hint: None,
            created,
        }
    }

    fn grant(expires: i64) -> CodeGrant {
        CodeGrant {
            client_id: "c".into(),
            redirect_uri: Url::parse("https://claude.ai/api/mcp/auth_callback").unwrap(),
            code_challenge: "x".into(),
            session: session(NOW + 3600),
            expires,
        }
    }

    #[test]
    fn a_pending_authorization_is_readable_until_finished_or_stale() {
        let store = Store::open(None, NOW).unwrap();
        let id = store.begin(authorization(NOW)).unwrap();
        assert!(store.pending(&id, NOW + 10).is_some());
        assert!(
            store.pending(&id, NOW + PENDING_TTL_SECS).is_none(),
            "stale"
        );
        assert_eq!(store.finish(&id, NOW + 10), Some(authorization(NOW)));
        assert!(store.finish(&id, NOW + 10).is_none(), "single use");
        assert!(store.pending("nope", NOW).is_none());
    }

    #[test]
    fn pending_authorizations_are_capped_oldest_first() {
        let store = Store::open(None, NOW).unwrap();
        let first = store.begin(authorization(NOW)).unwrap();
        let mut last = String::new();
        for i in 1..=MAX_PENDING as i64 {
            last = store.begin(authorization(NOW + i.min(10))).unwrap();
        }
        assert!(store.pending(&first, NOW + 10).is_none(), "oldest evicted");
        assert!(store.pending(&last, NOW + 10).is_some());
        assert_eq!(store.lock().pending.len(), MAX_PENDING);
    }

    #[test]
    fn a_code_redeems_once_and_not_after_it_expires() {
        let store = Store::open(None, NOW).unwrap();
        let code = store.issue_code(grant(NOW + CODE_TTL_SECS)).unwrap();
        assert!(store.redeem_code(&code, NOW + 1).is_some());
        assert!(store.redeem_code(&code, NOW + 1).is_none(), "replay");
        let late = store.issue_code(grant(NOW + CODE_TTL_SECS)).unwrap();
        assert!(store.redeem_code(&late, NOW + CODE_TTL_SECS).is_none());
    }

    #[test]
    fn a_token_lives_as_long_as_its_id_token() {
        let store = Store::open(None, NOW).unwrap();
        let token = store.issue_token(session(NOW + 100), NOW).unwrap();
        assert_eq!(store.session(&token, NOW + 99), Some(session(NOW + 100)));
        assert_eq!(store.session(&token, NOW + 100), None);
        assert_eq!(store.session("forged", NOW), None);
    }

    #[test]
    fn sessions_survive_a_restart_but_the_file_holds_no_token() {
        let dir = crate::testutil::ScratchDir::new("gw-sessions");
        let file = dir.path().join("sessions.json");
        let token = {
            let store = Store::open(Some(file.clone()), NOW).unwrap();
            store.issue_token(session(NOW + 100), NOW).unwrap()
        };
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(!text.contains(&token));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let reopened = Store::open(Some(file.clone()), NOW + 1).unwrap();
        assert_eq!(reopened.session(&token, NOW + 1), Some(session(NOW + 100)));
        let later = Store::open(Some(file), NOW + 200).unwrap();
        assert_eq!(later.session(&token, NOW + 200), None, "expired on load");
    }

    proptest! {
        #[test]
        fn tokens_and_codes_are_distinct_and_unguessable(n in 2usize..20) {
            let store = Store::open(None, NOW).unwrap();
            let mut seen = std::collections::HashSet::new();
            for _ in 0..n {
                let t = store.issue_token(session(NOW + 10), NOW).unwrap();
                prop_assert!(t.len() >= 43);
                prop_assert!(seen.insert(t));
            }
        }
    }
}

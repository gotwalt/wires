//! Who is behind each node key that has presented an ID token to this host
//! (board cards 05 and 27).
//!
//! [`Identities`] is the in-memory index `NodeId → latest verified
//! Principal`. It is fed every ID token a caller presents in person: in the
//! session [`Hello`](library::Hello) of a call, and in the inbox
//! [`Hello`](library::InboxFrame::Hello) of a fetch. Each one is verified
//! here with card 04's [`KeyFetcher`](crate::caller::jwks::KeyFetcher) under
//! the host's own trusted issuers ([`IdpTrust`], from `host.json`). The iroh
//! connection authenticated the presenting key, and the token's OIDC nonce
//! binds it to that key, so a token for someone else's key never verifies.
//! A token that fails is logged and never displaces a principal that
//! verified.
//!
//! Nothing is broadcast: a host knows the identities of the callers that
//! have spoken to it, and no others. That is what push authorization reads
//! ([`ServicesHost::decide_push`](crate::host::gate::ServicesHost::decide_push)).

use std::collections::HashMap;
use std::sync::Mutex;

use library::{Audience, CLOCK_SKEW_SECS, IdentityClaim, Issuer, NodeId, Principal};

use crate::caller::jwks::{KeyFetcher, VerifyError};

/// What verifying one token concluded.
pub(crate) type Verdict = Result<Principal, VerifyError>;

/// Which issuers a host accepts ID tokens from, each with its own accepted
/// audiences (`host.json` `identity.issuers`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IdpTrust {
    /// Issuers whose keys this host will fetch and trust.
    pub issuers: Vec<Issuer>,
    /// Accepted `aud` values per issuer. An audience accepted from one issuer
    /// is not accepted from another.
    pub by_issuer: Vec<(Issuer, Vec<Audience>)>,
}

impl IdpTrust {
    /// Exactly these issuers, each with its own accepted audiences.
    pub(crate) fn per_issuer(issuers: Vec<(Issuer, Vec<Audience>)>) -> Self {
        Self {
            issuers: issuers.iter().map(|(iss, _)| iss.clone()).collect(),
            by_issuer: issuers,
        }
    }

    /// The audiences accepted from `issuer` (none from an untrusted one).
    pub(crate) fn audiences_for(&self, issuer: &Issuer) -> &[Audience] {
        self.by_issuer
            .iter()
            .find(|(iss, _)| iss == issuer)
            .map_or(&[], |(_, auds)| auds)
    }

    /// The audiences to verify `claim` against: those of the issuer it
    /// names (unverified — verification then checks that very issuer).
    pub(crate) fn audiences_for_claim(&self, claim: &IdentityClaim) -> &[Audience] {
        match claim.id_token.unverified_issuer() {
            Ok(iss) => self.audiences_for(&iss),
            Err(_) => &[],
        }
    }
}

/// The human name for a principal: the verified email, else `sub` at the
/// issuer.
pub(crate) fn principal_name(p: &Principal) -> String {
    match &p.email {
        Some(email) => email.clone(),
        None => format!("{} at {}", p.subject, p.issuer),
    }
}

/// What the index holds for one node.
#[derive(Clone, Debug, Default)]
struct Known {
    /// The verified principal with the latest `exp` (possibly stale by now).
    principal: Option<Principal>,
    /// Why the most recent failing token failed.
    failure: Option<String>,
}

/// What the index says about a node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Lookup {
    /// No token from it has been seen.
    Unknown,
    /// Tokens were seen, none verified; the latest failure's reason.
    Unverified(String),
    /// A verified principal (check [`is_fresh`] before trusting it now).
    Known(Principal),
}

/// Whether `p` is still within its token's lifetime at `now` (with the same
/// skew allowance [`library::verify_claim`] uses).
pub(crate) fn is_fresh(p: &Principal, now: i64) -> bool {
    now <= p.not_after.saturating_add(CLOCK_SKEW_SECS)
}

/// The index `NodeId → latest verified Principal`. See the module docs.
pub(crate) struct Identities {
    /// Fetches and caches issuers' keys.
    fetcher: KeyFetcher,
    /// Which issuers and audiences this host accepts.
    trust: IdpTrust,
    /// What is known per node.
    known: Mutex<HashMap<NodeId, Known>>,
}

impl std::fmt::Debug for Identities {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identities")
            .field("trust", &self.trust)
            .finish_non_exhaustive()
    }
}

impl Identities {
    /// An empty index verifying with `fetcher` under `trust`.
    pub(crate) fn new(fetcher: KeyFetcher, trust: IdpTrust) -> Self {
        Self {
            fetcher,
            trust,
            known: Mutex::new(HashMap::new()),
        }
    }

    /// Verify the ID token `node` presented (in a session or inbox `Hello`)
    /// and record the verdict. The iroh-authenticated key presented it
    /// itself, so the nonce binding to `node` is the whole proof.
    pub(crate) async fn verify_token(
        &self,
        node: NodeId,
        id_token: &library::IdToken,
        now: i64,
    ) -> Verdict {
        let claim = IdentityClaim {
            node,
            id_token: id_token.clone(),
        };
        let verdict = self
            .fetcher
            .verify(
                &claim,
                &self.trust.issuers,
                self.trust.audiences_for_claim(&claim),
                now,
            )
            .await;
        self.record(node, &verdict);
        verdict
    }

    /// Fold one verdict about `node` into the index.
    ///
    /// A verified principal (fresh or expired) replaces the held one when its
    /// `exp` is at least as late — re-logins win, and replaying an old token
    /// cannot roll a node back to an older identity. A failure is remembered
    /// only as the reason to give while nothing has verified.
    pub(crate) fn record(&self, node: NodeId, verdict: &Verdict) {
        let mut known = self.known.lock().expect("identity index poisoned");
        let entry = known.entry(node).or_default();
        match verdict {
            Ok(p) | Err(VerifyError::Expired(p)) => {
                if entry
                    .principal
                    .as_ref()
                    .is_none_or(|held| p.not_after >= held.not_after)
                {
                    tracing::info!(node = %node.hex(), who = %principal_name(p), "identity verified");
                    entry.principal = Some(p.clone());
                }
            }
            Err(e) => {
                tracing::warn!(node = %node.hex(), "ID token did not verify: {e}");
                entry.failure = Some(e.to_string());
            }
        }
    }

    /// Every node a token has been seen from, verified or not.
    pub(crate) fn nodes(&self) -> Vec<NodeId> {
        let known = self.known.lock().expect("identity index poisoned");
        known.keys().copied().collect()
    }

    /// What is known about `node`.
    pub(crate) fn lookup(&self, node: NodeId) -> Lookup {
        let known = self.known.lock().expect("identity index poisoned");
        match known.get(&node) {
            None => Lookup::Unknown,
            Some(Known {
                principal: Some(p), ..
            }) => Lookup::Known(p.clone()),
            Some(Known {
                failure: Some(why), ..
            }) => Lookup::Unverified(why.clone()),
            Some(_) => Lookup::Unknown,
        }
    }

    /// `node`'s principal if one verified and is still fresh at `now`.
    pub(crate) fn current(&self, node: NodeId, now: i64) -> Option<Principal> {
        match self.lookup(node) {
            Lookup::Known(p) if is_fresh(&p, now) => Some(p),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use library::{IdTokenError, NodeIdentity};

    const ISS: &str = "https://idp.example";

    fn node(seed: u8) -> NodeId {
        NodeIdentity::from_seed([seed; 32]).node_id()
    }

    fn who(email: &str, not_after: i64) -> Principal {
        Principal {
            issuer: ISS.into(),
            subject: format!("sub-{email}"),
            email: Some(email.into()),
            org: None,
            groups: vec![],
            not_after,
            claims: Default::default(),
        }
    }

    fn index() -> Arc<Identities> {
        Arc::new(Identities::new(
            KeyFetcher::new(None).unwrap(),
            IdpTrust::per_issuer(vec![(Issuer::new(ISS), vec![Audience::new("aud")])]),
        ))
    }

    #[test]
    fn each_state_of_a_node() {
        let ids = index();
        let n = node(1);
        assert_eq!(ids.lookup(n), Lookup::Unknown);
        ids.record(
            n,
            &Err(VerifyError::Rejected(IdTokenError::WrongNonce {
                node: n.hex(),
            })),
        );
        assert!(matches!(ids.lookup(n), Lookup::Unverified(why) if why.contains("nonce")));
        ids.record(n, &Ok(who("alice@example.com", 1_000)));
        assert_eq!(ids.current(n, 100), Some(who("alice@example.com", 1_000)));
        assert_eq!(ids.current(n, 1_000 + CLOCK_SKEW_SECS + 1), None);
        assert_eq!(ids.nodes(), vec![n]);
    }

    #[test]
    fn failures_and_older_tokens_never_displace_a_verified_principal() {
        let ids = index();
        let n = node(5);
        ids.record(n, &Ok(who("new@example.com", 200)));
        ids.record(n, &Ok(who("old@example.com", 100)));
        ids.record(n, &Err(VerifyError::Unavailable("down".into())));
        assert_eq!(ids.lookup(n), Lookup::Known(who("new@example.com", 200)));
        // An expired verdict still names who the node was.
        ids.record(n, &Err(VerifyError::Expired(who("later@example.com", 300))));
        assert_eq!(ids.lookup(n), Lookup::Known(who("later@example.com", 300)));
        assert_eq!(ids.lookup(node(6)), Lookup::Unknown);
    }

    #[test]
    fn per_issuer_audiences_do_not_leak_across_issuers() {
        let t = IdpTrust::per_issuer(vec![
            (Issuer::new("https://a"), vec![Audience::new("x")]),
            (Issuer::new("https://b"), vec![Audience::new("y")]),
        ]);
        assert_eq!(
            t.issuers,
            ["https://a", "https://b"].map(Issuer::new).to_vec()
        );
        assert_eq!(
            t.audiences_for(&Issuer::new("https://a")),
            [Audience::new("x")]
        );
        assert_eq!(
            t.audiences_for(&Issuer::new("https://b")),
            [Audience::new("y")]
        );
        assert!(t.audiences_for(&Issuer::new("https://c")).is_empty());
        // A token that doesn't even parse gets no audience at all.
        let garbage = IdentityClaim {
            node: node(5),
            id_token: library::IdToken::new("x.y.z"),
        };
        assert!(t.audiences_for_claim(&garbage).is_empty());
    }

    #[test]
    fn a_principal_is_named_by_email_else_subject_at_issuer() {
        assert_eq!(principal_name(&who("a@example.com", 0)), "a@example.com");
        let mut anon = who("a@example.com", 0);
        anon.email = None;
        assert_eq!(principal_name(&anon), format!("sub-a@example.com at {ISS}"));
    }
}

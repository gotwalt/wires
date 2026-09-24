//! Who is behind each node key that has presented an ID token to this host
//! (board cards 05 and 27).
//!
//! [`Identities`] is the in-memory index `NodeId → latest verified
//! Principal`. It is fed every ID token a caller presents in person: in the
//! session [`Hello`](library::Hello) of a call, and in the inbox
//! [`Hello`](library::InboxFrame::Hello) of a fetch. Each one is verified
//! here with card 04's [`KeyFetcher`] under
//! the host's trusted issuers ([`IdpTrust`]: the signed policy's `issuer`
//! items, narrowed by `host.json`; card 36), which follow the policy the
//! host decides under ([`Identities::set_trust`]). The iroh
//! connection authenticated the presenting key, and the token's OIDC nonce
//! binds it to that key, so a token for someone else's key never verifies.
//! A token that fails is traced and never displaces a principal that
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
/// audiences (the policy's `issuer` items, narrowed by `host.json`'s
/// `identity.issuers`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IdpTrust {
    /// The issuers whose keys this host will fetch and trust, each with the
    /// `aud` values it accepts from that issuer. An audience accepted from
    /// one issuer is not accepted from another.
    by_issuer: Vec<(Issuer, Vec<Audience>)>,
}

impl IdpTrust {
    /// Exactly these issuers, each with its own accepted audiences.
    pub(crate) fn per_issuer(issuers: Vec<(Issuer, Vec<Audience>)>) -> Self {
        Self { by_issuer: issuers }
    }

    /// The trusted issuers, in order.
    pub(crate) fn issuers(&self) -> Vec<Issuer> {
        self.by_issuer.iter().map(|(iss, _)| iss.clone()).collect()
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

/// Whether `p` is still within its token's lifetime at `now` (with the same
/// skew allowance [`library::verify_claim`] uses).
pub(crate) fn is_fresh(p: &Principal, now: i64) -> bool {
    now <= p.not_after.saturating_add(CLOCK_SKEW_SECS)
}

/// The index `NodeId → latest verified Principal`. See the module docs.
pub(crate) struct Identities {
    /// Fetches and caches issuers' keys.
    fetcher: KeyFetcher,
    /// Which issuers and audiences this host accepts now.
    trust: std::sync::RwLock<IdpTrust>,
    /// Every node a token has been seen from, with the verified principal
    /// of the latest `exp` (possibly stale by now), if any verified.
    known: Mutex<HashMap<NodeId, Option<Principal>>>,
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
            trust: std::sync::RwLock::new(trust),
            known: Mutex::new(HashMap::new()),
        }
    }

    /// Verify under `trust` from now on (the host adopted a policy whose
    /// `issuer` items changed). Principals already verified stay.
    pub(crate) fn set_trust(&self, trust: IdpTrust) {
        let mut held = self.trust.write().expect("identity trust poisoned");
        if *held != trust {
            tracing::info!(issuers = ?trust.issuers(), "trusted issuers changed");
            *held = trust;
        }
    }

    /// The trust tokens are verified under now.
    pub(crate) fn trust(&self) -> IdpTrust {
        self.trust.read().expect("identity trust poisoned").clone()
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
        let trust = self.trust();
        let verdict = self
            .fetcher
            .verify(
                &claim,
                &trust.issuers(),
                trust.audiences_for_claim(&claim),
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
    /// cannot roll a node back to an older identity. A failure is traced,
    /// and only notes that the node presented a token.
    pub(crate) fn record(&self, node: NodeId, verdict: &Verdict) {
        let mut known = self.known.lock().expect("identity index poisoned");
        let held = known.entry(node).or_default();
        match verdict {
            Ok(p) | Err(VerifyError::Expired(p)) => {
                if held.as_ref().is_none_or(|h| p.not_after >= h.not_after) {
                    tracing::info!(node = %node.hex(), who = %p.name(), "identity verified");
                    *held = Some(p.clone());
                }
            }
            Err(e) => tracing::warn!(node = %node.hex(), "ID token did not verify: {e}"),
        }
    }

    /// Every node a token has been seen from, verified or not.
    pub(crate) fn nodes(&self) -> Vec<NodeId> {
        let known = self.known.lock().expect("identity index poisoned");
        known.keys().copied().collect()
    }

    /// The principal `node` last verified as, fresh or not.
    fn latest(&self, node: NodeId) -> Option<Principal> {
        let known = self.known.lock().expect("identity index poisoned");
        known.get(&node).cloned().flatten()
    }

    /// `node`'s principal if one verified and is still fresh at `now`.
    pub(crate) fn current(&self, node: NodeId, now: i64) -> Option<Principal> {
        self.latest(node).filter(|p| is_fresh(p, now))
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
        assert_eq!(ids.latest(n), None);
        assert!(ids.nodes().is_empty());
        ids.record(
            n,
            &Err(VerifyError::Rejected(IdTokenError::WrongNonce {
                node: n.hex(),
            })),
        );
        // Seen, but nobody verified.
        assert_eq!(ids.latest(n), None);
        assert_eq!(ids.nodes(), vec![n]);
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
        assert_eq!(ids.latest(n), Some(who("new@example.com", 200)));
        // An expired verdict still names who the node was.
        ids.record(n, &Err(VerifyError::Expired(who("later@example.com", 300))));
        assert_eq!(ids.latest(n), Some(who("later@example.com", 300)));
        assert_eq!(ids.latest(node(6)), None);
    }

    #[test]
    fn per_issuer_audiences_do_not_leak_across_issuers() {
        let t = IdpTrust::per_issuer(vec![
            (Issuer::new("https://a"), vec![Audience::new("x")]),
            (Issuer::new("https://b"), vec![Audience::new("y")]),
        ]);
        assert_eq!(
            t.issuers(),
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
}

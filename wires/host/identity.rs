//! Who is behind each node key on a channel, as this reader verified it
//! (board card 05).
//!
//! [`Identities`] is the in-memory index `NodeId → latest verified
//! Principal`. It is fed every [`IdentityClaim`] the resident tail loop
//! decrypts — live, replayed, or (for a responder) already in the log at
//! startup — and verifies each one itself with card 04's
//! [`KeyFetcher`](crate::caller::jwks::KeyFetcher). A claim that fails verification is
//! logged and never displaces a principal that verified.
//!
//! A claim only counts when the envelope carrying it was **signed by the node
//! it names**. The OIDC nonce binds the token to a node id, but that id is
//! public, so anyone could obtain a token bound to someone else's key; only
//! the key holder can publish it on its own chain.
//!
//! [`IdentityGate`] is the responder's use of the index: the principal to
//! stamp into [`AuditRecord::Started`](library::AuditRecord::Started) and hand
//! to the host's [`Policy`](crate::host::policy::Policy), or why there is
//! none. The lookup happens per call, so a claim that lands after a refusal
//! admits the very next call, with no restart.

use std::collections::HashMap;
use std::sync::Mutex;

use library::{CLOCK_SKEW_SECS, ChannelRecord, IdentityClaim, NodeId, Principal};

use crate::caller::jwks::{KeyFetcher, VerifyError};
use crate::channel::idp_view::{IdpTrust, principal_name};
use crate::channel::store::TopicStore;

/// What verifying one claim concluded.
pub(crate) type Verdict = Result<Principal, VerifyError>;

/// What the index holds for one node.
#[derive(Clone, Debug, Default)]
struct Known {
    /// The verified principal with the latest `exp` (possibly stale by now).
    principal: Option<Principal>,
    /// Why the most recent failing claim failed.
    failure: Option<String>,
}

/// What the index says about a node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Lookup {
    /// No claim for it has been seen.
    Unknown,
    /// Claims were seen, none verified; the latest failure's reason.
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
    /// Which issuers and audiences this reader accepts.
    trust: IdpTrust,
    /// What is known per node.
    known: Mutex<HashMap<NodeId, Known>>,
    /// Signalled whenever a node's held principal changes — what a host's
    /// announcer waits on to re-announce (card 15).
    changed: tokio::sync::Notify,
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
            changed: tokio::sync::Notify::new(),
        }
    }

    /// Verify `claim`, which arrived in an envelope signed by `sender`, and
    /// record the verdict. Returns the verdict for display.
    pub(crate) async fn observe(&self, sender: NodeId, claim: &IdentityClaim, now: i64) -> Verdict {
        let verdict = if sender != claim.node {
            Err(VerifyError::WrongSender(sender))
        } else {
            self.fetcher
                .verify(
                    claim,
                    &self.trust.issuers,
                    self.trust.audiences_for_claim(claim),
                    now,
                )
                .await
        };
        self.record(claim.node, &verdict);
        verdict
    }

    /// Verify the ID token `node` presented in its session `Hello` (card
    /// 27) and record the verdict. The iroh-authenticated key presented it
    /// itself, so the nonce binding to `node` is the whole proof; there is no
    /// envelope sender to compare.
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

    /// The synchronous half of [`observe`](Self::observe): fold one verdict
    /// about `node` into the index.
    ///
    /// A verified principal (fresh or expired) replaces the held one when its
    /// `exp` is at least as late — re-logins win, and replaying an old claim
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
                    // One stored permit: a change while nobody waits is
                    // still seen by the next `changed().await`.
                    self.changed.notify_one();
                }
            }
            Err(e) => {
                tracing::warn!(node = %node.hex(), "identity claim did not verify: {e}");
                entry.failure = Some(e.to_string());
            }
        }
    }

    /// Resolves after the next change to any node's held principal (or at
    /// once, if one happened since the last call returned). One waiter.
    pub(crate) async fn changed(&self) {
        self.changed.notified().await;
    }

    /// Every node a claim has been seen for, verified or not.
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
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn current(&self, node: NodeId, now: i64) -> Option<Principal> {
        match self.lookup(node) {
            Lookup::Known(p) if is_fresh(&p, now) => Some(p),
            _ => None,
        }
    }

    /// Index every identity claim already in `store` that `keyring` opens —
    /// what a responder does at startup, since it prints no backfill but must
    /// know callers who logged in before it started.
    pub(crate) async fn prime(
        &self,
        store: &TopicStore,
        keyring: &mut crate::channel::printer::Keyring,
        now: i64,
    ) {
        let envelopes = match store.read_backfill(usize::MAX) {
            Ok(all) => all,
            Err(e) => {
                tracing::warn!("reading the log for identity claims: {e:#}");
                return;
            }
        };
        for envelope in envelopes {
            let Some(plaintext) = keyring.open(&envelope) else {
                continue;
            };
            if let Some(ChannelRecord::Identity(claim)) =
                ChannelRecord::parse(&String::from_utf8_lossy(&plaintext))
            {
                // The verdict is indexed (and logged) by `observe` itself.
                let _ = self.observe(envelope.sender, &claim, now).await;
            }
        }
    }
}

/// The host's view of who each caller is: the index plus the channel name
/// callers log in on. Lives in
/// [`ServeConfig::identity`](crate::host::transport::ServeConfig::identity);
/// what an identity *may do* is the [`Policy`](crate::host::policy::Policy)'s
/// call, not this gate's.
pub(crate) struct IdentityGate {
    /// Who is who on the channel.
    identities: std::sync::Arc<Identities>,
    /// The channel's name, for the `wires login --topic` remedy.
    topic: String,
}

impl IdentityGate {
    /// A gate over `identities`; `topic` names where callers publish their
    /// claims.
    pub(crate) fn new(identities: std::sync::Arc<Identities>, topic: impl Into<String>) -> Self {
        Self {
            identities,
            topic: topic.into(),
        }
    }

    /// `caller`'s fresh verified principal at `now`, or why there is none —
    /// with the `wires login` remedy — for a refusal to quote.
    pub(crate) fn resolve(&self, caller: NodeId, now: i64) -> Result<Principal, String> {
        let node = short(caller);
        let remedy = format!("run `wires login --topic {}`", self.topic);
        match self.identities.lookup(caller) {
            Lookup::Unknown => Err(format!("no identity claim for {node}; {remedy}")),
            Lookup::Unverified(why) => Err(format!(
                "no verified identity claim for {node} ({why}); {remedy}"
            )),
            Lookup::Known(p) if !is_fresh(&p, now) => Err(format!(
                "identity claim expired for {} (at {}); {remedy}",
                principal_name(&p),
                p.not_after
            )),
            Lookup::Known(p) => Ok(p),
        }
    }
}

/// A node's first 8 hex characters, like the tail's sender column.
fn short(node: NodeId) -> String {
    let hex = node.hex();
    hex[..8.min(hex.len())].to_string()
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
            IdpTrust::from_vars(Some(ISS), Some("aud")),
        ))
    }

    fn gate(ids: &Arc<Identities>) -> IdentityGate {
        IdentityGate::new(Arc::clone(ids), "ops")
    }

    #[test]
    fn each_reason_for_no_principal() {
        let ids = index();
        let g = gate(&ids);
        let n = node(1);

        let e = g.resolve(n, 100).unwrap_err();
        assert!(e.starts_with("no identity claim for "), "{e}");
        assert!(e.ends_with("run `wires login --topic ops`"), "{e}");

        ids.record(
            n,
            &Err(VerifyError::Rejected(IdTokenError::WrongNonce {
                node: n.hex(),
            })),
        );
        let e = g.resolve(n, 100).unwrap_err();
        assert!(e.starts_with("no verified identity claim for "), "{e}");
        assert!(e.contains("nonce"), "{e}");

        ids.record(n, &Ok(who("alice@example.com", 1_000)));
        assert_eq!(g.resolve(n, 100), Ok(who("alice@example.com", 1_000)));
        let e = g.resolve(n, 1_000 + CLOCK_SKEW_SECS + 1).unwrap_err();
        assert!(
            e.starts_with("identity claim expired for alice@example.com"),
            "{e}"
        );
    }

    #[test]
    fn a_later_claim_resolves_the_next_call() {
        let ids = index();
        let g = gate(&ids);
        let n = node(3);
        assert!(g.resolve(n, 0).is_err());
        ids.record(n, &Ok(who("carol@example.com", 50)));
        assert_eq!(g.resolve(n, 0), Ok(who("carol@example.com", 50)));
    }

    #[test]
    fn failures_and_older_claims_never_displace_a_verified_principal() {
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

    /// A claim for node A arriving on B's chain is refused before any key is
    /// fetched: only A can publish A's identity.
    #[tokio::test]
    async fn a_claim_must_be_published_by_the_node_it_names() {
        let ids = index();
        let claim = IdentityClaim {
            node: node(7),
            id_token: library::IdToken::new("x.y.z"),
        };
        let verdict = ids.observe(node(8), &claim, 0).await;
        assert_eq!(verdict, Err(VerifyError::WrongSender(node(8))));
        assert!(matches!(ids.lookup(node(7)), Lookup::Unverified(_)));
    }
}

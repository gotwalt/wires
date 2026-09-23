//! The host announces what it serves on its channel (board card 15), and each
//! member sees only the tools it may use.
//!
//! An [`Announcer`] runs beside the host's resident tail loop and publishes a
//! [`ChannelRecord::Host`] through the same publish queue as the call records
//! (so the tail loop stays the one sequence allocator):
//!
//! - **at startup**, so a caller that has only joined the channel finds the
//!   host;
//! - **when the audience changes** — a verified identity claim lands (or a
//!   newer one replaces it) and the host's [`Policy`] now gives that member a
//!   different set of tools. That is how a member who just ran `wires login`
//!   sees its tools within a moment;
//! - **on a heartbeat** ([`HEARTBEAT`], default 10 minutes), which is also
//!   when a member whose claim expired drops out, and how callers tell a live
//!   host from a stale one (three heartbeats without an announcement).
//!
//! # Who sees what
//!
//! [`Audience`] is the policy's answer, per member: the tools every member may
//! run ([`Policy::member_tools`]) go in the announcement's open listing,
//! readable by the whole channel; for each member with a fresh verified
//! principal, the *further* tools [`Policy::allowed_tools`] grants it are
//! sealed to that member's node key alone (see [`library::announce`]). Members
//! with nothing further get no entry. Every listing carries the host's dial
//! hints, so a caller needs nothing but the announcement to reach it.
//!
//! This is privacy, not access control: the host's [`Policy`] still decides
//! every call, and a call to a tool the caller cannot see is refused with the
//! same reason as any other.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use library::{
    ChannelRecord, HostAnnouncement, HostListing, ListedTool, NodeId, SealedListing, ToolName,
    TopicPeer,
};
use tokio::sync::{mpsc, oneshot};

use super::identity::{Identities, IdentityGate};
use super::policy::Policy;
use crate::channel::ipc::PublishRequest;
use crate::now_unix;

/// The default heartbeat: re-announce every 10 minutes even if nothing
/// changed.
pub(crate) const HEARTBEAT: Duration = Duration::from_secs(600);

/// Overrides [`HEARTBEAT`], in seconds (demos and tests; not a documented
/// flag).
pub(crate) const HEARTBEAT_ENV: &str = "WIRES_ANNOUNCE_HEARTBEAT_SECS";

/// How long to let a burst of identity changes settle before re-announcing.
const DEBOUNCE: Duration = Duration::from_millis(150);

/// The heartbeat to use: `$WIRES_ANNOUNCE_HEARTBEAT_SECS` if it is a positive
/// integer, else [`HEARTBEAT`].
pub(crate) fn heartbeat() -> Duration {
    heartbeat_from(std::env::var(HEARTBEAT_ENV).ok().as_deref())
}

/// [`heartbeat`] over an explicit value (the testable half).
fn heartbeat_from(var: Option<&str>) -> Duration {
    var.and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&secs| secs > 0)
        .map_or(HEARTBEAT, Duration::from_secs)
}

/// Who may see which tools, as the host's policy says right now.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Audience {
    /// Tools every member may run: announced in the open.
    pub(crate) open: Vec<ToolName>,
    /// Per member with a fresh verified principal: the tools it may run
    /// beyond [`open`](Self::open). Members with none are absent.
    pub(crate) members: BTreeMap<NodeId, Vec<ToolName>>,
}

/// Announces one host's tools on its channel. See the module docs.
pub(crate) struct Announcer {
    /// The host's node id (the announcement's `node`, never sealed to).
    node: NodeId,
    /// What each member may run.
    policy: Arc<dyn Policy>,
    /// Who each member is (fresh, verified), as the host's calls see it.
    gate: Arc<IdentityGate>,
    /// The index the gate reads; its change signal triggers re-announcement.
    identities: Arc<Identities>,
    /// Each tool's `host.json` description.
    descriptions: BTreeMap<ToolName, String>,
    /// Re-announce at least this often.
    heartbeat: Duration,
}

impl std::fmt::Debug for Announcer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Announcer")
            .field("node", &self.node.hex())
            .field("tools", &self.descriptions.len())
            .field("heartbeat", &self.heartbeat)
            .finish_non_exhaustive()
    }
}

impl Announcer {
    /// An announcer for the host `node`.
    pub(crate) fn new(
        node: NodeId,
        policy: Arc<dyn Policy>,
        gate: Arc<IdentityGate>,
        identities: Arc<Identities>,
        descriptions: BTreeMap<ToolName, String>,
        heartbeat: Duration,
    ) -> Self {
        Self {
            node,
            policy,
            gate,
            identities,
            descriptions,
            heartbeat,
        }
    }

    /// The audience at unix time `now`: every node the identity index holds
    /// a fresh verified principal for, asked of the policy.
    pub(crate) fn audience(&self, now: i64) -> Audience {
        let open = self.policy.member_tools();
        let everyone: BTreeSet<&ToolName> = open.iter().collect();
        let mut members = BTreeMap::new();
        for member in self.identities.nodes() {
            if member == self.node {
                continue;
            }
            let Ok(principal) = self.gate.resolve(member, now) else {
                continue;
            };
            let extra: Vec<ToolName> = self
                .policy
                .allowed_tools(Some(&principal), member)
                .into_iter()
                .filter(|t| !everyone.contains(t))
                .collect();
            if !extra.is_empty() {
                members.insert(member, extra);
            }
        }
        Audience { open, members }
    }

    /// The listing for `tools`, with this host's dial hints.
    fn listing(&self, tools: &[ToolName], reach: &TopicPeer) -> HostListing {
        HostListing {
            tools: tools
                .iter()
                .map(|name| ListedTool {
                    name: name.clone(),
                    description: self.descriptions.get(name).cloned().unwrap_or_default(),
                })
                .collect(),
            addrs: reach.addrs.clone(),
            relay_url: reach.relay_url.clone(),
        }
    }

    /// The announcement for `audience` at `at_ms`: the open listing, and one
    /// sealed entry per member. A member whose key cannot be sealed to (not
    /// a usable Ed25519 point) is logged and left out.
    pub(crate) fn announcement(
        &self,
        audience: &Audience,
        reach: &TopicPeer,
        at_ms: i64,
    ) -> HostAnnouncement {
        let open = (!audience.open.is_empty()).then(|| self.listing(&audience.open, reach));
        let sealed = audience
            .members
            .iter()
            .filter_map(|(member, tools)| {
                SealedListing::seal(self.node, at_ms, member, &self.listing(tools, reach))
                    .inspect_err(|e| {
                        tracing::warn!(member = %member.hex(), "not announcing to member: {e}");
                    })
                    .ok()
            })
            .collect();
        HostAnnouncement::new(
            self.node,
            at_ms,
            self.heartbeat.as_millis() as u64,
            open,
            sealed,
        )
    }

    /// Announce now, then whenever the audience changes, and at least every
    /// heartbeat, until the publish queue closes. `reach` is this host's own
    /// topic peer entry (its addresses and relay).
    pub(crate) async fn run(self, tx: mpsc::Sender<PublishRequest>, reach: TopicPeer) {
        let mut last: Option<Audience> = None;
        let mut beat = tokio::time::Instant::now();
        loop {
            let audience = self.audience(now_unix());
            if tokio::time::Instant::now() >= beat || last.as_ref() != Some(&audience) {
                let ann = self.announcement(&audience, &reach, now_ms());
                if !publish(&tx, ChannelRecord::Host(ann)).await {
                    return;
                }
                tracing::info!(
                    open = audience.open.len(),
                    sealed = audience.members.len(),
                    "announced this host's tools"
                );
                last = Some(audience);
                beat = tokio::time::Instant::now() + self.heartbeat;
            }
            tokio::select! {
                _ = tokio::time::sleep_until(beat) => {}
                _ = self.identities.changed() => tokio::time::sleep(DEBOUNCE).await,
            }
        }
    }
}

/// Unix milliseconds now.
fn now_ms() -> i64 {
    crate::host::audit::now_ms()
}

/// Queue one record on the tail loop and wait for its answer. `false` when
/// the loop is gone (nothing more will ever publish).
async fn publish(tx: &mpsc::Sender<PublishRequest>, record: ChannelRecord) -> bool {
    let text = match record.to_text() {
        Ok(text) => text,
        Err(e) => {
            tracing::warn!("host announcement not encodable: {e}");
            return true;
        }
    };
    let (reply, answer) = oneshot::channel();
    if tx.send(PublishRequest { text, reply }).await.is_err() {
        tracing::warn!("the tail loop is gone; this host will not be announced");
        return false;
    }
    match answer.await {
        Ok(Ok(seq)) => tracing::debug!(seq, "host announcement published"),
        Ok(Err(e)) => tracing::warn!("host announcement not published: {e}"),
        Err(_) => tracing::warn!("host announcement publish went unanswered"),
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caller::jwks::{KeyFetcher, VerifyError};
    use crate::channel::idp_view::IdpTrust;
    use crate::host::config::HostConfig;
    use library::{NodeIdentity, Principal};

    const ISS: &str = "https://idp.example";

    fn id(seed: u8) -> NodeIdentity {
        NodeIdentity::from_seed([seed; 32])
    }

    fn who(email: &str) -> Principal {
        Principal {
            issuer: ISS.into(),
            subject: format!("sub-{email}"),
            email: Some(email.into()),
            org: None,
            groups: vec![],
            not_after: 1_000,
            claims: Default::default(),
        }
    }

    fn tool(name: &str) -> ToolName {
        ToolName::new(name).unwrap()
    }

    /// A host.json with `db_query` for analysts (`*@example.com`) and
    /// `status` for every member; an index holding `claims`.
    fn announcer(claims: &[(u8, Result<Principal, VerifyError>)]) -> Announcer {
        let host = HostConfig::parse(&format!(
            r#"{{"version":1,"channel":"ops",
                "identity":{{"issuers":[{{"issuer":"{ISS}","audiences":["aud"]}}]}},
                "roles":{{"analyst":[{{"email":"*@example.com"}}]}},
                "tools":{{
                  "db_query":{{"description":"SQL","command":["sqlite3"],"allow":["analyst"]}},
                  "status":{{"command":["true"],"allow":["member"]}},
                  "nobody":{{"command":["true"],"allow":[]}}
                }}}}"#
        ))
        .unwrap();
        let identities = Arc::new(Identities::new(
            KeyFetcher::new(None).unwrap(),
            IdpTrust::from_vars(Some(ISS), Some("aud")),
        ));
        for (seed, verdict) in claims {
            identities.record(id(*seed).node_id(), verdict);
        }
        let gate = Arc::new(IdentityGate::new(Arc::clone(&identities), "ops"));
        Announcer::new(
            id(1).node_id(),
            Arc::new(host.policy()),
            gate,
            identities,
            host.descriptions(),
            Duration::from_secs(60),
        )
    }

    fn reach() -> TopicPeer {
        TopicPeer::new(id(1).node_id()).with_addrs(vec!["127.0.0.1:9".parse().unwrap()])
    }

    fn names(listing: Option<HostListing>) -> Vec<String> {
        listing
            .map(|l| l.tools.into_iter().map(|t| t.name.to_string()).collect())
            .unwrap_or_default()
    }

    /// The analyst gets `db_query` sealed to it; a verified non-analyst, an
    /// unverified claim, and an expired one get nothing beyond the open
    /// `status`; the `allow: []` tool reaches nobody.
    #[test]
    fn the_audience_is_the_policy_per_member() {
        let a = announcer(&[
            (2, Ok(who("alice@example.com"))),
            (3, Ok(who("bob@other.org"))),
            (4, Err(VerifyError::Unavailable("down".into()))),
        ]);
        let audience = a.audience(500);
        assert_eq!(audience.open, vec![tool("status")]);
        assert_eq!(
            audience.members,
            BTreeMap::from([(id(2).node_id(), vec![tool("db_query")])])
        );
        // Past alice's `exp` (plus skew), she drops out.
        assert!(a.audience(1_000_000).members.is_empty());
    }

    /// End to end over the record: each member opens exactly its own view,
    /// with the host's descriptions and dial hints.
    #[test]
    fn each_member_opens_its_own_view() {
        let a = announcer(&[
            (2, Ok(who("alice@example.com"))),
            (3, Ok(who("bob@other.org"))),
        ]);
        let ann = a.announcement(&a.audience(500), &reach(), 42);
        assert_eq!(ann.node, id(1).node_id());
        assert_eq!(ann.heartbeat_ms, 60_000);
        assert_eq!(ann.sealed.len(), 1, "one entry: the analyst");
        let alice = ann.listing_for(&id(2)).unwrap();
        assert_eq!(names(Some(alice.clone())), ["db_query", "status"]);
        assert_eq!(alice.tools[0].description, "SQL");
        assert_eq!(alice.addrs, reach().addrs);
        assert_eq!(names(ann.listing_for(&id(3))), ["status"]);
        assert_eq!(names(ann.listing_for(&id(9))), ["status"]);
    }

    /// A new verified claim changes the audience (what triggers a
    /// re-announcement), and wakes the announcer.
    #[tokio::test]
    async fn a_new_claim_changes_the_audience_and_wakes_the_announcer() {
        let a = announcer(&[]);
        let before = a.audience(500);
        a.identities
            .record(id(5).node_id(), &Ok(who("carol@example.com")));
        tokio::time::timeout(Duration::from_secs(1), a.identities.changed())
            .await
            .expect("the change is signalled");
        assert_ne!(a.audience(500), before);
    }

    /// The loop announces once at start, and again when a claim lands.
    #[tokio::test]
    async fn run_announces_at_start_and_on_change() {
        let a = announcer(&[]);
        let identities = Arc::clone(&a.identities);
        let (tx, mut rx) = mpsc::channel(4);
        let task = tokio::spawn(a.run(tx, reach()));
        let first = rx.recv().await.unwrap();
        let Some(ChannelRecord::Host(ann)) = ChannelRecord::parse(&first.text) else {
            panic!("a host record: {}", first.text);
        };
        assert!(ann.sealed.is_empty());
        let _ = first.reply.send(Ok(0));
        // Fresh against the real clock the loop reads.
        let dave = Principal {
            not_after: i64::MAX / 2,
            ..who("dave@example.com")
        };
        identities.record(id(6).node_id(), &Ok(dave));
        let second = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("re-announced")
            .unwrap();
        let Some(ChannelRecord::Host(ann)) = ChannelRecord::parse(&second.text) else {
            panic!("a host record");
        };
        assert_eq!(names(ann.listing_for(&id(6))), ["db_query", "status"]);
        task.abort();
    }

    #[test]
    fn the_heartbeat_env_override() {
        assert_eq!(heartbeat_from(None), HEARTBEAT);
        assert_eq!(heartbeat_from(Some("2")), Duration::from_secs(2));
        assert_eq!(heartbeat_from(Some("0")), HEARTBEAT);
        assert_eq!(heartbeat_from(Some("x")), HEARTBEAT);
    }
}

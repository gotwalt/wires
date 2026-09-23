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
//! - **when the channel re-keys** — every `wires invite` / `wires remove` is a
//!   commit with a fresh fabric key, and a member who joined after the last
//!   announcement holds no key for it (late joiners never read pre-join
//!   history). The announcer re-announces under the new key, so the newcomer
//!   can read it;
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
//! with nothing further get no entry — and neither does a node the channel's
//! current roster no longer holds ([`CurrentRoster`]): the identity index
//! keeps a removed member's verified claim until it expires, so the audience
//! is (current roster members) ∩ (policy-allowed verified principals). Every
//! listing carries the host's dial hints, so a caller needs nothing but the
//! announcement to reach it; the open listing is always present for that
//! reason, even with no tools in it (the hints are no secret from a member:
//! the host is its channel's bootstrap peer).
//!
//! This is privacy, not access control: the host's [`Policy`] still decides
//! every call, and a call to a tool the caller cannot see is refused with the
//! same reason as any other.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use library::{
    ChannelRecord, HostAnnouncement, HostListing, InclusionProof, ListedTool, NodeId,
    ProofDirectory, RosterHead, SealedListing, ToolName, TopicPeer,
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

/// How often the announcer looks for a new fabric key (a re-key it must
/// re-announce under).
const KEY_POLL: Duration = Duration::from_secs(1);

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

/// Which nodes the channel's current roster holds, as far as this host can
/// tell — the other half of the audience (see the module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CurrentRoster {
    /// No roster head is enforced (plumbing with no roster): every member
    /// with a verified claim counts.
    Unenforced,
    /// This host joined at the current head and has seen no commit since, so
    /// every claim it could read was sealed under the head's key by one of
    /// the head's members: all of them count. (A removal is a commit, and its
    /// re-key leaves a directory — [`Members`](Self::Members).)
    JoinedAtHead,
    /// Exactly these nodes: the proof directory for the current head, each
    /// proof re-verified against it.
    Members(BTreeSet<NodeId>),
    /// A head is enforced but this host holds no directory for it (it
    /// adopted the head without its re-key): seal to nobody until it does.
    Unknown,
}

impl CurrentRoster {
    /// What the host knows at `now`, from its enforced `head`, the proof
    /// `directory` beside it, and its `own` inclusion proof, under `fabric`.
    pub(crate) fn from_parts(
        head: Option<&RosterHead>,
        directory: Option<&ProofDirectory>,
        own: Option<&InclusionProof>,
        fabric: NodeId,
        now: i64,
    ) -> Self {
        let Some(head) = head else {
            return Self::Unenforced;
        };
        if let Some(dir) = directory.filter(|d| &d.head == head) {
            return Self::Members(
                dir.proofs
                    .iter()
                    .filter(|p| {
                        library::check_roster_inclusion(head, p, fabric, p.member, now).is_ok()
                    })
                    .map(|p| p.member)
                    .collect(),
            );
        }
        match own {
            Some(p) if library::check_roster_inclusion(head, p, fabric, p.member, now).is_ok() => {
                Self::JoinedAtHead
            }
            _ => Self::Unknown,
        }
    }

    /// Whether `node` may be sealed to.
    pub(crate) fn admits(&self, node: NodeId) -> bool {
        match self {
            Self::Unenforced | Self::JoinedAtHead => true,
            Self::Members(members) => members.contains(&node),
            Self::Unknown => false,
        }
    }
}

/// Reads the host's [`CurrentRoster`] at a unix time.
pub(crate) type RosterView = Arc<dyn Fn(i64) -> CurrentRoster + Send + Sync>;

/// The [`RosterView`] of a host serving `config`, whose own credentials are
/// in `keystore`: the head the session gate enforces, the directory beside
/// it, and the host's own proof — re-read each time, like the gate does.
pub(crate) fn roster_view(
    config: Arc<crate::host::transport::ServeConfig>,
    keystore: Arc<crate::admin::keystore::Keystore>,
) -> RosterView {
    Arc::new(move |now| {
        let head = match config.head.load() {
            Ok(head) => head,
            Err(e) => {
                tracing::debug!("no roster head for the announcement: {e:#}");
                return CurrentRoster::Unknown;
            }
        };
        let directory = crate::channel::rekey::directory_for(&config.head);
        let own = keystore.read_inclusion_proof().ok().flatten();
        CurrentRoster::from_parts(
            head.as_ref(),
            directory.as_ref(),
            own.as_ref(),
            config.trust_root,
            now,
        )
    })
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
    /// Where the channel's fabric keys are; a new one means re-announce.
    /// `None`: never checked (unit tests).
    keystore: Option<Arc<crate::admin::keystore::Keystore>>,
    /// Who the channel's current roster holds. `None`: not checked (unit
    /// tests of the policy half).
    roster: Option<RosterView>,
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
            keystore: None,
            roster: None,
        }
    }

    /// Seal only to nodes `roster` says the current roster holds.
    pub(crate) fn within(mut self, roster: RosterView) -> Self {
        self.roster = Some(roster);
        self
    }

    /// Also re-announce whenever `keystore` gains a newer fabric key.
    pub(crate) fn watching_keys(mut self, keystore: Arc<crate::admin::keystore::Keystore>) -> Self {
        self.keystore = Some(keystore);
        self
    }

    /// The newest fabric key version held (what the next announcement is
    /// sealed under), when keys are watched.
    fn key_version(&self) -> Option<u64> {
        let ks = self.keystore.as_ref()?;
        ks.latest_fabric_key().ok().flatten().map(|(v, _)| v.0)
    }

    /// The audience at unix time `now`: every node the identity index holds
    /// a fresh verified principal for *and* the current roster holds, asked
    /// of the policy.
    pub(crate) fn audience(&self, now: i64) -> Audience {
        let open = self.policy.member_tools();
        let everyone: BTreeSet<&ToolName> = open.iter().collect();
        let roster = self
            .roster
            .as_ref()
            .map_or(CurrentRoster::Unenforced, |view| view(now));
        let mut members = BTreeMap::new();
        for member in self.identities.nodes() {
            if member == self.node || !roster.admits(member) {
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
        // Always present: it carries the dial hints, so a member shown no
        // tool can still reach the host and hear why (the hints are no
        // secret from a member — the host is its channel's bootstrap peer).
        let open = Some(self.listing(&audience.open, reach));
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
        let mut last: Option<(Audience, Option<u64>)> = None;
        let mut beat = tokio::time::Instant::now();
        loop {
            let now = (self.audience(now_unix()), self.key_version());
            if tokio::time::Instant::now() >= beat || last.as_ref() != Some(&now) {
                let audience = &now.0;
                let ann = self.announcement(audience, &reach, now_ms());
                if !publish(&tx, ChannelRecord::Host(ann)).await {
                    return;
                }
                tracing::info!(
                    open = audience.open.len(),
                    sealed = audience.members.len(),
                    key = ?now.1,
                    "announced this host's tools"
                );
                last = Some(now);
                beat = tokio::time::Instant::now() + self.heartbeat;
            }
            let poll = tokio::time::Instant::now() + KEY_POLL;
            tokio::select! {
                _ = tokio::time::sleep_until(beat) => {}
                _ = tokio::time::sleep_until(poll), if self.keystore.is_some() => {}
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

    /// A two-commit roster: nodes 2..=4 at v1, node 2 removed at v2. Returns
    /// the fabric, both heads, the v2 directory, and each version's proofs.
    #[allow(clippy::type_complexity)]
    fn commits() -> (
        NodeId,
        RosterHead,
        RosterHead,
        ProofDirectory,
        BTreeMap<NodeId, InclusionProof>,
        BTreeMap<NodeId, InclusionProof>,
    ) {
        let root = id(1);
        let mut roster = library::Roster::new(root.node_id());
        for seed in 2..=4 {
            roster.insert(id(seed).node_id());
        }
        let (v1, p1) = roster.commit(&root, 0, i64::MAX).unwrap();
        roster.remove(&id(2).node_id());
        let (v2, p2) = roster.commit(&root, 0, i64::MAX).unwrap();
        let dir = ProofDirectory {
            head: v2.clone(),
            proofs: p2.iter().map(|(_, p)| p.clone()).collect(),
        };
        (
            root.node_id(),
            v1,
            v2,
            dir,
            p1.into_iter().collect(),
            p2.into_iter().collect(),
        )
    }

    #[test]
    fn the_current_roster_is_the_directory_for_exactly_the_head() {
        let (fabric, v1, v2, dir, p1, p2) = commits();
        let me = id(3).node_id();
        // No head enforced: no filter.
        assert_eq!(
            CurrentRoster::from_parts(None, Some(&dir), None, fabric, 0),
            CurrentRoster::Unenforced
        );
        // The directory for the head: its members, and nobody it left out.
        let r = CurrentRoster::from_parts(Some(&v2), Some(&dir), p2.get(&me), fabric, 0);
        assert!(r.admits(id(3).node_id()) && r.admits(id(4).node_id()));
        assert!(!r.admits(id(2).node_id()), "the removed node");
        // Joined at the head (own proof current), no directory yet: everyone
        // it could have heard from is a member.
        assert_eq!(
            CurrentRoster::from_parts(Some(&v1), None, p1.get(&me), fabric, 0),
            CurrentRoster::JoinedAtHead
        );
        // Head advanced with neither its directory nor a current own proof
        // (a stale directory for v1 is no help): nobody.
        let old = ProofDirectory {
            head: v1.clone(),
            proofs: p1.values().cloned().collect(),
        };
        let r = CurrentRoster::from_parts(Some(&v2), Some(&old), p1.get(&me), fabric, 0);
        assert_eq!(r, CurrentRoster::Unknown);
        assert!(!r.admits(id(3).node_id()));
        // A directory proof that does not verify against the head is dropped.
        let forged = ProofDirectory {
            head: v2.clone(),
            proofs: vec![p1[&id(2).node_id()].clone()],
        };
        let r = CurrentRoster::from_parts(Some(&v2), Some(&forged), None, fabric, 0);
        assert!(!r.admits(id(2).node_id()));
    }

    /// Card 21, item 4: a removed member's verified claim is still in the
    /// identity index, but the audience leaves it out.
    #[test]
    fn a_removed_member_with_a_fresh_claim_gets_no_entry() {
        let (fabric, _, v2, dir, _, p2) = commits();
        let a = announcer(&[
            (2, Ok(who("alice@example.com"))),
            (3, Ok(who("carol@example.com"))),
        ]);
        let before = a.audience(500);
        assert_eq!(before.members.len(), 2, "no roster view: both");
        let own = p2[&id(3).node_id()].clone();
        let a = a.within(Arc::new(move |now| {
            CurrentRoster::from_parts(Some(&v2), Some(&dir), Some(&own), fabric, now)
        }));
        let after = a.audience(500);
        assert_eq!(
            after.members,
            BTreeMap::from([(id(3).node_id(), vec![tool("db_query")])])
        );
        let ann = a.announcement(&after, &reach(), 42);
        assert_eq!(ann.sealed.len(), 1);
        assert_eq!(names(ann.listing_for(&id(2))), ["status"]);
    }

    #[test]
    fn the_heartbeat_env_override() {
        assert_eq!(heartbeat_from(None), HEARTBEAT);
        assert_eq!(heartbeat_from(Some("2")), Duration::from_secs(2));
        assert_eq!(heartbeat_from(Some("0")), HEARTBEAT);
        assert_eq!(heartbeat_from(Some("x")), HEARTBEAT);
    }
}

//! The host pushes to callers (board card 23): `wires push --to <node|role>
//! --subject S -- body`, queued per recipient, delivered by key, recorded.
//!
//! # Sending
//!
//! `wires push` is host-local: it hands a [`PushSpec`] to the resident
//! `wires serve` over its control socket (the same single-allocator path the
//! call records take), and prints the [`PushReport`]. A tool can address its
//! own caller: the host puts the verified caller's id in each tool's
//! environment as `WIRES_CALLER_NODE`, so a tool that starts background work
//! can later run `wires push --to "$WIRES_CALLER_NODE" …`.
//!
//! # Who may receive
//!
//! `host.json`'s `push.allow` (default deny), asked of the host's
//! [`Policy`](crate::host::policy::Policy) **at send, at delivery and at
//! fetch** — each time with the recipient's verified identity as it stands
//! then — and only for nodes the channel's **current roster** holds (the
//! same [`CurrentRoster`](crate::host::announce::CurrentRoster) the
//! announcer seals to; a fetch additionally passes the session's own
//! membership and roster gate). A removed member gets nothing: its queue is
//! dropped (recorded `denied`), and its fetch is refused on the channel.
//!
//! A `host.json` v2 host (card 27) asks its **signed state** instead
//! ([`ServicesHost::decide_push`]): the recipient must be a member of it, in
//! a registry role that v2's `push.allow` names, with the identity it last
//! verified as in a `Hello` to this host. Its `wires push` socket is
//! [`host_socket`] (there is no channel).
//!
//! # Delivery
//!
//! Each message joins its recipient's queue ([`Queue`]: at most
//! [`QUEUE_PER_RECIPIENT`], oldest dropped first; TTL [`DEFAULT_TTL`], at most
//! [`MAX_TTL`]), and the host dials the recipient's resident receiver by key
//! at once (relay allowed; [`DIRECT_BUDGET`]). If that fails, the message
//! waits for the recipient's next `wires inbox` fetch, which this host
//! serves on the inbox ALPN ([`PushFetch`]), holding the stream open up to
//! [`FETCH_WAIT_MAX`] for a long poll. Each attempt is at least once; the
//! recipient de-duplicates by id, and only an acknowledged message leaves
//! the queue. The queue is kept in `$WIRES_HOME/push-queue.json` (`0600`), so
//! a host restart loses nothing.
//!
//! # Records
//!
//! Every milestone is an [`AuditRecord::Push`] on the host's channel —
//! `queued`, `delivered`, `fetched`, `expired`, `dropped`, `denied` — with
//! the subject, and the body only under `"push": {"log_body": true}`.

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use std::io::IsTerminal;

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use iroh::Endpoint;
use library::{
    AuditRecord, INBOX_ALPN, InboxFrame, MAX_BATCH, NodeId, Principal, PushBody, PushId,
    PushMessage, PushOutcome, Subject,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, mpsc, oneshot};

use super::announce::RosterView;
use super::gate::ServicesHost;
use super::identity::{Identities, IdentityGate};
use super::policy::RoleName;
use super::transport::{self, AuditSink, ServeConfig};
use crate::admin::commit::Ttl;
use crate::admin::keystore::Keystore;
use crate::caller::inbox::{deny, read_frame, write_frame};

/// How long a push waits for its recipient when `--ttl` isn't given.
pub(crate) const DEFAULT_TTL: Duration = Duration::from_secs(24 * 3600);

/// The longest `--ttl` a host accepts.
pub(crate) const MAX_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

/// Most messages queued for one recipient; a newer one drops the oldest
/// (recorded `dropped`).
pub(crate) const QUEUE_PER_RECIPIENT: usize = 64;

/// How long `wires push` spends dialing the recipient before leaving the
/// message queued.
pub(crate) const DIRECT_BUDGET: Duration = Duration::from_secs(3);

/// The longest a fetch may be held open waiting for a message.
pub(crate) const FETCH_WAIT_MAX: Duration = Duration::from_secs(25);

/// How often queued messages are checked for expiry.
const SWEEP: Duration = Duration::from_secs(1);

/// How long to wait for a peer's next frame.
const FRAME_TIMEOUT: Duration = Duration::from_secs(10);

/// The queue file under `$WIRES_HOME`.
pub(crate) const QUEUE_FILE: &str = "push-queue.json";

// ---------------------------------------------------------------------------
// The request and its answer (the control socket's `push` operation)
// ---------------------------------------------------------------------------

/// What `wires push` asks the resident host to send.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PushSpec {
    /// A node id (64 hex) or a role name (`host.json`'s roles, or `member`).
    pub(crate) to: String,
    /// One line.
    pub(crate) subject: Subject,
    /// The text.
    pub(crate) body: PushBody,
    /// Time to live in seconds; `None` is [`DEFAULT_TTL`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ttl_secs: Option<u64>,
}

/// What happened for one recipient.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PushResult {
    /// The recipient.
    pub(crate) to: NodeId,
    /// Its verified identity (email), when the host knows one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) who: Option<String>,
    /// The message id (also on a refusal: it names the `denied` record).
    pub(crate) id: PushId,
    /// `delivered`, `queued` or `denied`.
    pub(crate) outcome: PushOutcome,
    /// Why, when denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
}

/// The answer to a [`PushSpec`]: one result per recipient.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PushReport {
    /// In recipient order.
    pub(crate) results: Vec<PushResult>,
}

impl PushReport {
    /// One line per recipient, for `wires push`'s stdout:
    /// `delivered  alice@example.com (a1b2c3d4)  <id>`.
    pub(crate) fn render(&self) -> String {
        self.results
            .iter()
            .map(|r| {
                let who = match &r.who {
                    Some(w) => format!("{w} ({})", &r.to.hex()[..8]),
                    None => r.to.hex()[..8].to_string(),
                };
                let mut line = format!("{:<9}  {who}  {}", r.outcome.as_str(), r.id);
                if let Some(reason) = &r.reason {
                    line.push_str(&format!("  {reason}"));
                }
                line
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Whether any recipient got (or will get) the message.
    pub(crate) fn any_accepted(&self) -> bool {
        self.results
            .iter()
            .any(|r| r.outcome != PushOutcome::Denied)
    }
}

/// A [`PushSpec`] handed from the control socket to the [`PushHost`], with
/// where its answer goes.
#[derive(Debug)]
pub(crate) struct PushCommand {
    /// The request.
    pub(crate) spec: PushSpec,
    /// The report, or why the request itself was refused.
    pub(crate) reply: oneshot::Sender<std::result::Result<PushReport, String>>,
}

// ---------------------------------------------------------------------------
// The queue (pure)
// ---------------------------------------------------------------------------

/// One queued message, with who it was admitted as (for later records).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Entry {
    /// The message.
    pub(crate) message: PushMessage,
    /// The recipient's verified identity at send time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) principal: Option<Principal>,
    /// The `push.allow` role that admitted it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) role: Option<String>,
}

/// Per-recipient FIFO queues, bounded by `cap` each. See the module docs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Queue {
    /// Oldest first.
    by_recipient: BTreeMap<NodeId, VecDeque<Entry>>,
}

impl Queue {
    /// Add `entry` behind its recipient's queue; returns the entry dropped to
    /// keep it within `cap` (the oldest), if any. An id already queued is
    /// not added twice.
    pub(crate) fn insert(&mut self, entry: Entry, cap: usize) -> Option<Entry> {
        let q = self.by_recipient.entry(entry.message.to).or_default();
        if q.iter().any(|e| e.message.id == entry.message.id) {
            return None;
        }
        q.push_back(entry);
        (q.len() > cap.max(1)).then(|| q.pop_front()).flatten()
    }

    /// Up to `max` messages for `to` not expired at `now_ms`, oldest first.
    pub(crate) fn pending(&self, to: NodeId, now_ms: i64, max: usize) -> Vec<PushMessage> {
        self.by_recipient
            .get(&to)
            .into_iter()
            .flatten()
            .filter(|e| !e.message.is_expired(now_ms))
            .take(max)
            .map(|e| e.message.clone())
            .collect()
    }

    /// Remove the entries of `to` whose ids are in `ids`; returns them.
    pub(crate) fn remove(&mut self, to: NodeId, ids: &[PushId]) -> Vec<Entry> {
        let Some(q) = self.by_recipient.get_mut(&to) else {
            return Vec::new();
        };
        let (gone, kept): (Vec<Entry>, Vec<Entry>) =
            q.drain(..).partition(|e| ids.contains(&e.message.id));
        *q = kept.into();
        if q.is_empty() {
            self.by_recipient.remove(&to);
        }
        gone
    }

    /// Remove and return every entry expired at `now_ms`.
    pub(crate) fn expire(&mut self, now_ms: i64) -> Vec<Entry> {
        let mut gone = Vec::new();
        self.by_recipient.retain(|_, q| {
            let (expired, kept): (Vec<Entry>, Vec<Entry>) =
                q.drain(..).partition(|e| e.message.is_expired(now_ms));
            gone.extend(expired);
            *q = kept.into();
            !q.is_empty()
        });
        gone
    }

    /// Remove and return everything queued for `to`.
    pub(crate) fn purge(&mut self, to: NodeId) -> Vec<Entry> {
        self.by_recipient
            .remove(&to)
            .map(Vec::from)
            .unwrap_or_default()
    }

    /// Whether message `id` is still queued for `to`.
    pub(crate) fn holds(&self, to: NodeId, id: PushId) -> bool {
        self.by_recipient
            .get(&to)
            .is_some_and(|q| q.iter().any(|e| e.message.id == id))
    }

    /// How many messages are queued for `to`.
    #[cfg(test)]
    pub(crate) fn len_for(&self, to: NodeId) -> usize {
        self.by_recipient.get(&to).map_or(0, VecDeque::len)
    }

    /// Every recipient with something queued.
    #[cfg(test)]
    pub(crate) fn recipients(&self) -> Vec<NodeId> {
        self.by_recipient.keys().copied().collect()
    }
}

// ---------------------------------------------------------------------------
// The service
// ---------------------------------------------------------------------------

/// A host's push service: the queue, the policy checks, direct delivery, and
/// the fetch side of the inbox ALPN. Shared (`Arc`) by the control socket's
/// commands, the fetch handler and the expiry sweep.
pub(crate) struct PushHost {
    /// This host.
    me: NodeId,
    /// Who decides who may receive.
    authority: Authority,
    /// The verified identities (for `--to <role>`).
    identities: Arc<Identities>,
    /// Where the host's own proof is re-read from (for its `Hello`).
    keystore: Option<Arc<Keystore>>,
    /// `push.log_body`.
    log_body: bool,
    /// The queues.
    queue: Mutex<Queue>,
    /// Where the queue persists (`None`: memory only, in tests).
    path: Option<PathBuf>,
    /// Signalled whenever a message is queued (wakes long polls).
    arrived: Notify,
    /// The host node's endpoint, set once it is bound.
    endpoint: OnceLock<Endpoint>,
}

/// Who decides who may receive: a v1 host asks its channel's roster and
/// `host.json` roles; a v2 host (card 27) asks its signed state and the
/// registry roles in `push.allow`.
enum Authority {
    /// v1 (`host.json` version 1, with a channel).
    Roster {
        /// The host's session config: trust root, head source, policy,
        /// identity gate, audit sink, own membership.
        serve: Arc<ServeConfig>,
        /// Who the channel's current roster holds.
        roster: RosterView,
        /// The per-call identity lookup.
        gate: Option<Arc<IdentityGate>>,
    },
    /// v2 (`host.json` version 2): the signed state decides.
    State(Arc<ServicesHost>),
}

impl std::fmt::Debug for PushHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushHost")
            .field("me", &self.me.hex())
            .field("log_body", &self.log_body)
            .finish_non_exhaustive()
    }
}

impl PushHost {
    /// A push service for the host `me` serving `serve`.
    pub(crate) fn new(
        me: NodeId,
        serve: Arc<ServeConfig>,
        roster: RosterView,
        identities: Arc<Identities>,
        log_body: bool,
    ) -> Self {
        let gate = serve.identity.clone();
        Self::with_authority(
            me,
            Authority::Roster {
                serve,
                roster,
                gate,
            },
            identities,
            log_body,
        )
    }

    /// A push service for the v2 host `host` (card 27): recipients are
    /// members of its signed state in a registry role `push.allow` names.
    pub(crate) fn from_state(host: Arc<ServicesHost>) -> Self {
        let identities = Arc::clone(&host.identities);
        let log_body = host.config.push.as_ref().is_some_and(|p| p.log_body);
        Self::with_authority(host.me, Authority::State(host), identities, log_body)
    }

    fn with_authority(
        me: NodeId,
        authority: Authority,
        identities: Arc<Identities>,
        log_body: bool,
    ) -> Self {
        Self {
            me,
            authority,
            identities,
            keystore: None,
            log_body,
            queue: Mutex::new(Queue::default()),
            path: None,
            arrived: Notify::new(),
            endpoint: OnceLock::new(),
        }
    }

    /// Persist the queue at `path` (loading what is there), and present the
    /// proof in `keystore` when dialing receivers.
    pub(crate) fn persisted(self, path: PathBuf, keystore: Arc<Keystore>) -> Self {
        let mut me = self.persisted_queue(path);
        me.keystore = Some(keystore);
        me
    }

    /// Persist the queue at `path` (loading what is there); a v2 host has
    /// no proof to present.
    pub(crate) fn persisted_queue(mut self, path: PathBuf) -> Self {
        match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<Queue>(&text) {
                Ok(q) => self.queue = Mutex::new(q),
                Err(e) => {
                    tracing::warn!(path = %path.display(), "ignoring an unreadable push queue: {e}")
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(path = %path.display(), "reading the push queue: {e}"),
        }
        self.path = Some(path);
        self
    }

    /// Use `endpoint` (the host node's) for direct deliveries.
    pub(crate) fn attach(&self, endpoint: Endpoint) {
        let _ = self.endpoint.set(endpoint);
    }

    /// Where records go.
    fn audit(&self) -> Option<&AuditSink> {
        match &self.authority {
            Authority::Roster { serve, .. } => serve.audit.as_ref(),
            Authority::State(host) => host.audit.as_ref(),
        }
    }

    /// Record one milestone of `entry` in the call log.
    fn record(&self, entry: &Entry, outcome: PushOutcome, reason: Option<String>) {
        if let Some(sink) = self.audit() {
            sink.record(AuditRecord::Push {
                id: entry.message.id,
                to: entry.message.to,
                principal: entry.principal.clone(),
                role: entry.role.clone(),
                subject: entry.message.subject.clone(),
                outcome,
                reason: reason.map(transport::truncate_reason),
                body: self.log_body.then(|| entry.message.body.clone()),
                at_ms: now_ms(),
            });
        }
    }

    /// Save the queue (best effort; a host that can't write it still
    /// delivers).
    fn save(&self, q: &Queue) {
        let Some(path) = &self.path else { return };
        let write = || -> Result<()> {
            let tmp = path.with_extension("json.tmp");
            std::fs::write(&tmp, serde_json::to_vec(q)?)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
            }
            std::fs::rename(&tmp, path)?;
            Ok(())
        };
        if let Err(e) = write() {
            tracing::warn!(path = %path.display(), "saving the push queue: {e:#}");
        }
    }

    /// Change the queue under its lock, then save it.
    fn with_queue<T>(&self, f: impl FnOnce(&mut Queue) -> T) -> T {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        let out = f(&mut q);
        self.save(&q);
        out
    }

    /// Whether `node` may receive from this host at `now`: in the current
    /// roster (v2: the signed state), and admitted by `push.allow` with its
    /// identity as it stands. `Ok` names the principal and role; `Err` the
    /// reason, and whether it is membership (not the push rule) that refused.
    pub(crate) fn authorize(
        &self,
        node: NodeId,
        now: i64,
    ) -> std::result::Result<(Option<Principal>, Option<String>), (String, bool)> {
        let (serve, roster, gate) = match &self.authority {
            Authority::State(host) => {
                return host
                    .decide_push(node, now)
                    .map(|(p, role)| (p, Some(role.as_str().to_string())));
            }
            Authority::Roster {
                serve,
                roster,
                gate,
            } => (serve, roster, gate),
        };
        if !roster(now).admits(node) {
            return Err((
                format!(
                    "{} is not in the channel's current roster",
                    &node.hex()[..8]
                ),
                true,
            ));
        }
        let (principal, missing) = match gate.as_deref().map(|g| g.resolve(node, now)) {
            Some(Ok(p)) => (Some(p), None),
            Some(Err(why)) => (None, Some(why)),
            None => (None, None),
        };
        let d = serve.policy.decide_push(principal.as_ref(), node);
        if d.allow {
            return Ok((principal, d.role.map(|r| r.as_str().to_string())));
        }
        Err((
            match missing {
                Some(why) => format!("{why}; {}", d.reason),
                None => d.reason,
            },
            false,
        ))
    }

    /// The recipients `to` names at `now`: a node id, or every node with a
    /// verified identity in that role (plus, for `member`, every node the
    /// current roster's directory lists).
    fn recipients(&self, to: &str, now: i64) -> Result<Vec<NodeId>> {
        if to.len() == 64
            && let Ok(node) = NodeId::from_hex(to)
        {
            return Ok(vec![node]);
        }
        let role = RoleName::new(to)
            .map_err(|_| anyhow!("--to {to:?} is neither a node id (64 hex) nor a role name"))?;
        let (serve, roster, gate) = match &self.authority {
            Authority::State(host) => {
                let role = library::RoleName::new(to).map_err(|_| anyhow!("bad role {to:?}"))?;
                let nodes = host.push_recipients(&role, now);
                if nodes.is_empty() {
                    bail!("no member with a verified identity is in role {role} right now");
                }
                return Ok(nodes);
            }
            Authority::Roster {
                serve,
                roster,
                gate,
            } => (serve, roster, gate),
        };
        let mut nodes: Vec<NodeId> = self
            .identities
            .nodes()
            .into_iter()
            .filter(|n| *n != self.me)
            .filter(|n| {
                let p = gate.as_deref().and_then(|g| g.resolve(*n, now).ok());
                serve.policy.in_role(&role, p.as_ref())
            })
            .collect();
        if role.is_member()
            && let super::announce::CurrentRoster::Members(members) = roster(now)
        {
            nodes.extend(members.into_iter().filter(|n| *n != self.me));
        }
        nodes.sort();
        nodes.dedup();
        if nodes.is_empty() {
            bail!("no member with a verified identity is in role {role} right now");
        }
        Ok(nodes)
    }

    /// Send `spec`: authorize each recipient, queue, try a direct delivery,
    /// record every outcome.
    pub(crate) async fn send(&self, spec: PushSpec) -> Result<PushReport> {
        let ttl = spec
            .ttl_secs
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_TTL);
        if ttl.is_zero() || ttl > MAX_TTL {
            bail!("--ttl must be between 1s and 7d");
        }
        let now = crate::now_unix();
        let at_ms = now_ms();
        let mut report = PushReport::default();
        for to in self.recipients(&spec.to, now)? {
            let message = PushMessage {
                id: PushId::generate(),
                from: self.me,
                to,
                subject: spec.subject.clone(),
                body: spec.body.clone(),
                at_ms,
                expires_ms: at_ms.saturating_add(ttl.as_millis() as i64),
            };
            let (principal, role) = match self.authorize(to, now) {
                Ok(admitted) => admitted,
                Err((reason, _)) => {
                    let entry = Entry {
                        message,
                        principal: None,
                        role: None,
                    };
                    self.record(&entry, PushOutcome::Denied, Some(reason.clone()));
                    report.results.push(PushResult {
                        to,
                        who: None,
                        id: entry.message.id,
                        outcome: PushOutcome::Denied,
                        reason: Some(reason),
                    });
                    continue;
                }
            };
            let entry = Entry {
                message,
                principal,
                role,
            };
            let id = entry.message.id;
            let who = entry.principal.as_ref().and_then(|p| p.email.clone());
            if let Some(dropped) = self.with_queue(|q| q.insert(entry.clone(), QUEUE_PER_RECIPIENT))
            {
                self.record(
                    &dropped,
                    PushOutcome::Dropped,
                    Some(format!(
                        "the queue for this recipient holds at most {QUEUE_PER_RECIPIENT}"
                    )),
                );
            }
            self.arrived.notify_waiters();
            let delivered = match tokio::time::timeout(DIRECT_BUDGET, self.deliver_direct(to)).await
            {
                Ok(Ok(ids)) => ids.contains(&id),
                Ok(Err(e)) => {
                    tracing::debug!(to = %to.hex(), "direct push not delivered: {e:#}");
                    false
                }
                Err(_) => {
                    tracing::debug!(to = %to.hex(), "direct push timed out");
                    false
                }
            };
            let outcome = if delivered {
                PushOutcome::Delivered
            } else {
                // Still queued unless a fetch took it meanwhile (its own
                // record says so).
                if self
                    .queue
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .holds(to, id)
                {
                    self.record(&entry, PushOutcome::Queued, None);
                }
                PushOutcome::Queued
            };
            report.results.push(PushResult {
                to,
                who,
                id,
                outcome,
                reason: None,
            });
        }
        Ok(report)
    }

    /// Dial `to`'s resident receiver and hand it what is queued for it (one
    /// batch). Returns the ids it acknowledged, which leave the queue and are
    /// recorded `delivered`. Re-checks authorization first: a recipient the
    /// roster no longer holds loses its queue (recorded `denied`).
    pub(crate) async fn deliver_direct(&self, to: NodeId) -> Result<Vec<PushId>> {
        let now = crate::now_unix();
        if let Err((reason, roster)) = self.authorize(to, now) {
            if roster {
                for e in self.with_queue(|q| q.purge(to)) {
                    self.record(&e, PushOutcome::Denied, Some(reason.clone()));
                }
            }
            bail!("not delivering: {reason}");
        }
        let batch = self
            .queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending(to, now_ms(), MAX_BATCH);
        if batch.is_empty() {
            return Ok(Vec::new());
        }
        let endpoint = self
            .endpoint
            .get()
            .ok_or_else(|| anyhow!("the host's endpoint is not up yet"))?;
        let addr = transport::endpoint_addr(&to, &[], None)?;
        let conn = endpoint
            .connect(addr, INBOX_ALPN)
            .await
            .map_err(|e| anyhow!("dialing {}: {e}", &to.hex()[..8]))?;
        let (mut send, mut recv) = conn.open_bi().await.context("opening a stream")?;
        write_frame(&mut send, &self.hello()).await?;
        write_frame(&mut send, &InboxFrame::Deliver { messages: batch }).await?;
        let acked = match read_frame(&mut recv, FRAME_TIMEOUT).await? {
            Some(InboxFrame::Ack { ids }) => ids,
            Some(InboxFrame::Denied { reason }) => {
                conn.close(0u32.into(), b"refused");
                bail!("the receiver refused: {reason}");
            }
            _ => bail!("the receiver answered out of turn"),
        };
        send.finish().ok();
        conn.close(0u32.into(), b"done");
        let gone = self.with_queue(|q| q.remove(to, &acked));
        for e in &gone {
            self.record(e, PushOutcome::Delivered, None);
        }
        Ok(gone.into_iter().map(|e| e.message.id).collect())
    }

    /// This host's `Hello`: its membership and current proof.
    fn hello(&self) -> InboxFrame {
        match &self.authority {
            Authority::Roster { serve, .. } => InboxFrame::Hello {
                membership: serve.membership.clone(),
                proof: self
                    .keystore
                    .as_ref()
                    .and_then(|ks| ks.read_inclusion_proof().ok().flatten())
                    .or_else(|| serve.proof.clone()),
            },
            Authority::State(host) => InboxFrame::Hello {
                membership: host.membership.clone(),
                proof: None,
            },
        }
    }

    /// The credential check a fetch passes before the push rule: v1, the
    /// session's membership and roster gate; v2, the membership credential
    /// (membership of the signed state is in [`authorize`](Self::authorize)).
    fn check_fetcher(
        &self,
        membership: &library::Membership,
        proof: Option<&library::InclusionProof>,
        caller: NodeId,
        now: i64,
    ) -> Result<()> {
        match &self.authority {
            Authority::Roster { serve, .. } => {
                transport::check_member(serve, membership, proof, caller, now).map(|_| ())
            }
            Authority::State(host) => {
                library::check_inclusion(membership, host.trust_root, caller, now)
                    .map_err(|e| anyhow!("membership rejected: {e}"))
            }
        }
    }

    /// Serve one fetch from `caller` over an accepted stream. See the module
    /// docs; refusals are sent and recorded.
    pub(crate) async fn serve_fetch<S, R>(
        &self,
        mut send: S,
        mut recv: R,
        caller: NodeId,
    ) -> Result<()>
    where
        S: AsyncWrite + Unpin,
        R: AsyncRead + Unpin,
    {
        let (membership, proof) = match read_frame(&mut recv, FRAME_TIMEOUT).await? {
            Some(InboxFrame::Hello { membership, proof }) => (membership, proof),
            _ => {
                deny(&mut send, "expected hello").await;
                bail!("a fetcher spoke out of turn");
            }
        };
        let wait_ms = match read_frame(&mut recv, FRAME_TIMEOUT).await? {
            Some(InboxFrame::Fetch { wait_ms }) => wait_ms,
            _ => {
                deny(&mut send, "expected fetch").await;
                bail!("a fetcher spoke out of turn");
            }
        };
        let now = crate::now_unix();
        let refusal = match self.check_fetcher(&membership, proof.as_ref(), caller, now) {
            Err(e) => Some((format!("{e:#}"), true)),
            Ok(_) => self.authorize(caller, now).err(),
        };
        if let Some((reason, roster)) = refusal {
            let reason = format!("inbox fetch refused: {reason}");
            // A credential refusal (not a member, removed) is recorded like a
            // refused call. A policy one is only answered: a member's resident
            // receiver asks every host now and then, and a host it may not
            // hear from would otherwise log it every time.
            if roster {
                crate::host::audit::denied(self.audit(), caller, None, &reason);
                for e in self.with_queue(|q| q.purge(caller)) {
                    self.record(&e, PushOutcome::Denied, Some(reason.clone()));
                }
            }
            deny(&mut send, &reason).await;
            return Ok(());
        }
        // Long poll: until something is queued for the caller, or the wait
        // (capped) runs out. The notification is armed before each look, so
        // a message queued in between is never missed.
        let until =
            tokio::time::Instant::now() + Duration::from_millis(wait_ms).min(FETCH_WAIT_MAX);
        let batch = loop {
            let arrived = self.arrived.notified();
            tokio::pin!(arrived);
            arrived.as_mut().enable();
            let batch = self
                .queue
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pending(caller, now_ms(), MAX_BATCH);
            if !batch.is_empty() || tokio::time::Instant::now() >= until {
                break batch;
            }
            if tokio::time::timeout_at(until, arrived).await.is_err() {
                continue;
            }
        };
        write_frame(&mut send, &InboxFrame::Deliver { messages: batch }).await?;
        let acked = match read_frame(&mut recv, FRAME_TIMEOUT).await? {
            Some(InboxFrame::Ack { ids }) => ids,
            _ => bail!("the fetcher did not acknowledge"),
        };
        let gone = self.with_queue(|q| q.remove(caller, &acked));
        for e in &gone {
            self.record(e, PushOutcome::Fetched, None);
        }
        send.shutdown().await.ok();
        Ok(())
    }

    /// Record and drop what expired at `now_ms`.
    pub(crate) fn sweep(&self, now_ms: i64) {
        let expired = {
            let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
            let gone = q.expire(now_ms);
            if !gone.is_empty() {
                self.save(&q);
            }
            gone
        };
        for e in &expired {
            self.record(e, PushOutcome::Expired, None);
        }
    }

    /// Serve `commands` from the control socket and sweep expiries, until
    /// the command channel closes.
    pub(crate) async fn run(self: Arc<Self>, mut commands: mpsc::Receiver<PushCommand>) {
        let mut tick = tokio::time::interval(SWEEP);
        loop {
            tokio::select! {
                command = commands.recv() => {
                    let Some(PushCommand { spec, reply }) = command else { return };
                    let me = Arc::clone(&self);
                    tokio::spawn(async move {
                        let _ = reply.send(me.send(spec).await.map_err(|e| format!("{e:#}")));
                    });
                }
                _ = tick.tick() => self.sweep(now_ms()),
            }
        }
    }
}

/// The inbox ALPN on a host: serves fetches ([`PushHost::serve_fetch`]).
#[derive(Clone, Debug)]
pub(crate) struct PushFetch(pub(crate) Arc<PushHost>);

impl iroh::protocol::ProtocolHandler for PushFetch {
    async fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        let caller = transport::to_node_id(&conn.remote_id());
        let result = async {
            let (send, recv) = conn.accept_bi().await.context("accepting a stream")?;
            self.0.serve_fetch(send, recv, caller).await
        }
        .await;
        let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
        result.map_err(|e| {
            tracing::warn!(caller = %caller.hex(), "inbox fetch failed: {e:#}");
            iroh::protocol::AcceptError::from_boxed(e.into())
        })
    }
}

/// Unix milliseconds now.
fn now_ms() -> i64 {
    crate::host::audit::now_ms()
}

// ---------------------------------------------------------------------------
// `wires push`
// ---------------------------------------------------------------------------

/// `wires push --to <node|role> --subject S [--ttl D] [-- body…]`.
#[derive(Args, Clone, Debug)]
pub(crate) struct PushArgs {
    /// Who receives it: a node id (a tool's `$WIRES_CALLER_NODE` is its
    /// caller's), or a role from host.json (every member with a verified
    /// identity in it right now; `member` for every member).
    #[arg(long)]
    pub(crate) to: String,
    /// One line, recorded on the channel (the body is not, unless host.json
    /// says `"push": {"log_body": true}`).
    #[arg(long)]
    pub(crate) subject: String,
    /// How long the host keeps it for a recipient that isn't listening
    /// (e.g. `90m`, `2d`; default 24h, at most 7d).
    #[arg(long)]
    pub(crate) ttl: Option<Ttl>,
    /// The channel of the host that sends it (default: the joined channel).
    #[arg(long)]
    pub(crate) channel: Option<String>,
    /// The body. Read from stdin when none is given (and stdin isn't a
    /// terminal).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) body: Vec<String>,
}

/// `wires push`: hand the push to this machine's running `wires serve` and
/// print what happened per recipient. Exit 0 when anyone got (or will get)
/// it, 77 when every recipient was refused.
pub(crate) async fn push_cmd(a: PushArgs) -> Result<i32> {
    let subject = Subject::new(a.subject).context("--subject")?;
    let body = if a.body.is_empty() && !std::io::stdin().is_terminal() {
        let mut text = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut tokio::io::stdin(), &mut text)
            .await
            .context("reading the body from stdin")?;
        text
    } else {
        a.body.join(" ")
    };
    let body = PushBody::new(body).context("the body")?;
    let spec = PushSpec {
        to: a.to,
        subject,
        body,
        ttl_secs: a.ttl.map(|t| t.duration().as_secs()),
    };
    // A v2 host (card 27) has no channel: its `serve` listens on the host
    // socket.
    if a.channel.is_none()
        && let Some(mut client) = crate::channel::ipc::ControlClient::connect(&host_socket(
            &crate::admin::keystore::home()?,
        ))
        .await?
    {
        return report(client.push(spec).await?);
    }
    let args = crate::channel::context::TopicArgs {
        topic: a.channel.unwrap_or_default(),
        ..Default::default()
    };
    let ctx = crate::channel::context::TopicContext::resolve(
        Arc::new(Keystore::resolve()?),
        crate::admin::keystore::home()?,
        &args,
    )?;
    let Some(mut client) = crate::channel::ipc::ControlClient::connect(&ctx.socket_path()).await?
    else {
        bail!(
            "no `wires serve` is running for channel {:?} on this machine (`wires push` hands \
             the message to it)",
            ctx.name
        );
    };
    report(client.push(spec).await?)
}

/// Print `report`; exit 0 when anyone got (or will get) it, else 77.
fn report(report: PushReport) -> Result<i32> {
    println!("{}", report.render());
    Ok(if report.any_accepted() {
        0
    } else {
        crate::EXIT_DENIED
    })
}

/// The control socket a v2 host's `serve` answers `wires push` on:
/// `$WIRES_HOME/run/serve.sock`, or a short stand-in when that path is too
/// long to bind.
pub(crate) fn host_socket(home: &std::path::Path) -> PathBuf {
    use crate::channel::ipc::{fits_sockaddr, run_dir, short_socket_path};
    let full = run_dir(home).join("serve.sock");
    if fits_sockaddr(&full) {
        return full;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(home) {
            let bases = [std::env::temp_dir(), PathBuf::from("/tmp")];
            if let Some(short) = short_socket_path(&full, meta.uid(), &bases) {
                return short;
            }
        }
    }
    full
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::NodeIdentity;
    use proptest::prelude::*;

    fn node(seed: u8) -> NodeId {
        NodeIdentity::from_seed([seed; 32]).node_id()
    }

    fn entry(to: NodeId, at_ms: i64, expires_ms: i64) -> Entry {
        Entry {
            message: PushMessage {
                id: PushId::generate(),
                from: node(1),
                to,
                subject: Subject::new("s").unwrap(),
                body: PushBody::new("b").unwrap(),
                at_ms,
                expires_ms,
            },
            principal: None,
            role: None,
        }
    }

    #[test]
    fn a_full_queue_drops_its_oldest() {
        let mut q = Queue::default();
        let (a, b, c) = (
            entry(node(2), 1, 99),
            entry(node(2), 2, 99),
            entry(node(2), 3, 99),
        );
        assert_eq!(q.insert(a.clone(), 2), None);
        assert_eq!(q.insert(b.clone(), 2), None);
        assert_eq!(q.insert(c.clone(), 2), Some(a));
        assert_eq!(q.pending(node(2), 0, 10), [b.message, c.message]);
        // Another recipient's queue is its own.
        assert_eq!(q.insert(entry(node(3), 1, 99), 2), None);
        let mut want = vec![node(2), node(3)];
        want.sort();
        assert_eq!(q.recipients(), want);
    }

    #[test]
    fn remove_expire_and_purge_take_exactly_theirs() {
        let mut q = Queue::default();
        let live = entry(node(2), 1, 100);
        let old = entry(node(2), 1, 10);
        let other = entry(node(3), 1, 100);
        for e in [&live, &old, &other] {
            q.insert(e.clone(), 8);
        }
        // Expired messages are never handed out.
        assert_eq!(
            q.pending(node(2), 50, 8),
            std::slice::from_ref(&live.message)
        );
        assert_eq!(q.expire(50), std::slice::from_ref(&old));
        assert_eq!(q.remove(node(2), &[other.message.id]), []);
        assert_eq!(q.remove(node(2), &[live.message.id]), [live]);
        assert_eq!(q.len_for(node(2)), 0);
        assert_eq!(q.purge(node(3)), [other]);
        assert_eq!(q, Queue::default());
    }

    #[test]
    fn the_queue_survives_a_round_trip_through_its_file() {
        let mut q = Queue::default();
        q.insert(entry(node(2), 1, 100), 8);
        let back: Queue = serde_json::from_str(&serde_json::to_string(&q).unwrap()).unwrap();
        assert_eq!(back, q);
    }

    #[test]
    fn a_report_says_what_happened_per_recipient() {
        let id = PushId::from_hex("0123456789abcdef0123456789abcdef").unwrap();
        let report = PushReport {
            results: vec![
                PushResult {
                    to: node(2),
                    who: Some("alice@example.com".into()),
                    id,
                    outcome: PushOutcome::Delivered,
                    reason: None,
                },
                PushResult {
                    to: node(3),
                    who: None,
                    id,
                    outcome: PushOutcome::Denied,
                    reason: Some("no role".into()),
                },
            ],
        };
        let text = report.render();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            format!(
                "delivered  alice@example.com ({})  {id}",
                &node(2).hex()[..8]
            )
        );
        assert_eq!(
            lines[1],
            format!("denied     {}  {id}  no role", &node(3).hex()[..8])
        );
        assert!(report.any_accepted());
    }

    proptest! {
        /// Whatever arrives, a queue never holds more than `cap` per
        /// recipient, what it drops is the oldest, and nothing is lost:
        /// held + dropped = inserted.
        #[test]
        fn queues_stay_bounded_and_drop_oldest_first(
            to in proptest::collection::vec(0u8..3, 1..60),
            cap in 1usize..8,
        ) {
            let mut q = Queue::default();
            let mut dropped = Vec::new();
            let mut inserted = Vec::new();
            for (i, t) in to.iter().enumerate() {
                let e = entry(node(10 + t), i as i64, i64::MAX);
                inserted.push(e.message.id);
                if let Some(d) = q.insert(e, cap) {
                    // The oldest for that recipient: no held one is older.
                    let held = q.pending(d.message.to, 0, usize::MAX);
                    prop_assert!(held.iter().all(|m| m.at_ms > d.message.at_ms));
                    dropped.push(d.message.id);
                }
            }
            let mut held: Vec<PushId> = Vec::new();
            for r in q.recipients() {
                prop_assert!(q.len_for(r) <= cap);
                held.extend(q.pending(r, 0, usize::MAX).iter().map(|m| m.id));
            }
            held.extend(dropped);
            held.sort();
            inserted.sort();
            prop_assert_eq!(held, inserted);
        }
    }
}

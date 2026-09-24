//! `wires watch [<service>…] [--mine] [--json]` (card 26b): stream call
//! records from the hosts that hold them.
//!
//! The service's hosts come from its entry in the reader's view (card 37: the
//! services it may read, or call for its own records); it never names a
//! host. Each host is dialed by key on the record-stream ALPN
//! ([`record_stream`]) with the same credentials
//! a call presents, and answers with what this reader may see: every record
//! of a service whose `readers` roles it is in, otherwise only its own calls
//! (`--mine` asks for only those everywhere). With no service named, every
//! service in the view is asked for.
//!
//! Every entry is checked as it arrives ([`Chain`]): the host's signature,
//! and the hash link to the entry before it, across the runs of entries the
//! reader may not see. A tampered, missing or forked entry stops that host's
//! stream with a loud alarm on stderr (exit 1), and the reader's mark for it
//! is left at the last good entry.
//!
//! The reader keeps, in [`MARKS_FILE`], **one chain anchor per host** (the
//! furthest entry of that host's log it has verified, under any view) and a
//! **resume point per view** (the services asked of that host, `--mine`).
//! A view resumes from its own point, and wherever its stream passes the
//! anchor the entry must be the one verified before, so `watch x` after
//! `watch` (or after a service moves) still catches a rewrite. Each host
//! also says where its log stands ([`RecordFrame::Granted`]): a tip below
//! the anchor is a rollback (an alarm, exit 1); a first held entry past the
//! anchor is retention, reported as a notice, and checking starts over from
//! what the host still holds.
//!
//! The service a line names is derived here, from signed records: a
//! `Started`'s service, and for a `Finished` or a service's push the service of the
//! `Started` with the same call id ([`Labels`]). An operator push, or a line
//! whose call this reader never saw start, shows `-`.
//!
//! The backlog from every host is merged by time and printed first; then,
//! unless `--once`, new records as they are logged. A host that re-decides a
//! following reader's access (a new signed policy, an expired token) may end
//! the stream with a refusal, which is printed like any other.
//!
//! ```text
//! 14:02:07 orders-db ▶ 3fa2 alice@example.com (a1b2…) [analyst] orders-db "select 1"
//! 14:02:07 orders-db ■ 3fa2 exit 0 · 41 ms · 12 B out · blake3 9c1e…
//! 14:02:09 orders-db ✗ 7c3d… orders-db denied: bob@example.com is in no role allowed to call orders-db (analyst)
//! 14:03:00 -         ⇢ 9c1e → alice@example.com (a1b2…) [analyst] "build-41" delivered
//! ```

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Args;
use iroh::{Endpoint, EndpointAddr};
use library::{
    AuditRecord, CallId, ChainBreak, ChainPoint, LogEntry, LogSeq, NodeId, Principal, ServiceName,
    verify_chain,
};
use serde::Serialize;
use tokio::sync::mpsc;

use crate::admin::keystore::{self, Keystore};
use crate::caller::one_line;
use crate::caller::pick::{self, Hints};
use crate::host::record_stream::{self, Link, RecordFrame, StreamItem};
use crate::host::transport;

/// The keystore file holding the reader's marks: per host, its chain anchor,
/// a resume point per view, and recent calls' labels ([`Marks`]).
pub(crate) const MARKS_FILE: &str = "record-marks.json";

/// How long a host gets to answer the dial.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// `wires watch [<service>…] [--mine] [--json] [--once]`.
#[derive(Args, Clone, Debug, Default)]
pub(crate) struct WatchArgs {
    /// The services to watch (default: every service you may call or read).
    #[arg(value_name = "SERVICE")]
    pub(crate) services: Vec<String>,
    /// Only your own calls, even where you may read everyone's.
    #[arg(long)]
    pub(crate) mine: bool,
    /// One JSON object per record: `{service, host, seq, entry}`.
    // The entry is the host-signed log entry, verifiable on its own;
    // `service` is derived by this reader from signed records, not supplied
    // by the host.
    #[arg(long)]
    pub(crate) json: bool,
    /// Print what is there (after your last mark) and exit; don't follow.
    #[arg(long)]
    pub(crate) once: bool,
    /// Dial through this relay instead of the n0 default.
    #[arg(long, hide = true)]
    pub(crate) relay_url: Option<String>,
}

/// What a watch asks for.
#[derive(Clone, Debug, Default)]
pub(crate) struct WatchOpts {
    /// The services (empty: every service in the view).
    pub(crate) services: Vec<ServiceName>,
    /// Only the reader's own calls.
    pub(crate) mine: bool,
    /// Keep streaming after the backlog.
    pub(crate) follow: bool,
}

/// One verified record, ready to show.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Shown {
    /// The service it is about, as this reader derived it from signed
    /// records ([`Labels`]; `None`: none known, e.g. an operator push).
    pub(crate) service: Option<ServiceName>,
    /// The host that logged it.
    pub(crate) host: NodeId,
    /// Its place in that host's log.
    pub(crate) seq: LogSeq,
    /// The signed entry.
    pub(crate) entry: LogEntry,
}

/// What a watch emits, in order.
#[derive(Clone, Debug)]
pub(crate) enum Output {
    /// A verified record.
    Record(Box<Shown>),
    /// Something the reader must be told on stderr (a refusal, an
    /// unreachable host, a log that does not verify).
    Alarm(String),
    /// Something the reader should know that is not a fault (a host pruned
    /// entries past its retention).
    Notice(String),
}

/// How a watch ended (`--once`, or every host gone).
#[derive(Clone, Debug, Default)]
pub(crate) struct Report {
    /// Records shown.
    pub(crate) shown: usize,
    /// Hosts whose log did not verify, and why.
    pub(crate) broken: Vec<(NodeId, ChainBreak)>,
    /// Hosts that refused the reader, and why.
    pub(crate) refused: Vec<(NodeId, String)>,
    /// Hosts that could not be read (dial or stream failure).
    pub(crate) failed: Vec<(NodeId, String)>,
    /// Hosts that pruned entries past the reader's anchor (retention), and
    /// the first seq each still holds.
    pub(crate) pruned: Vec<(NodeId, LogSeq)>,
    /// Hosts asked.
    pub(crate) hosts: usize,
}

// ---------------------------------------------------------------------------
// Verifying a host's stream
// ---------------------------------------------------------------------------

/// A reader's running check of one host's log.
///
/// It continues from the view's resume point (`tip`), and also holds the
/// host's **anchor**: the furthest point of this host's chain the reader has
/// verified under any view. Wherever the stream passes the anchor, the entry
/// there must be the one verified before (and the next must link to it), so
/// a rewrite is caught even when this view has never seen that stretch.
#[derive(Clone, Debug)]
pub(crate) struct Chain {
    /// The host whose log it is.
    host: NodeId,
    /// The last verified point of this stream (`None`: nothing yet).
    tip: Option<ChainPoint>,
    /// The host's anchor (`None`: none, or dropped by retention).
    anchor: Option<ChainPoint>,
}

/// What a host's [`RecordFrame::Granted`] told the reader, once checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Standing {
    /// The log reaches everything the reader verified.
    Continuous,
    /// The host pruned entries before this seq (retention): what the reader
    /// verified before it can no longer be checked, and checking starts
    /// over from there. Not tampering.
    Pruned(LogSeq),
}

/// The later of two points (by seq).
fn later(a: Option<ChainPoint>, b: Option<ChainPoint>) -> Option<ChainPoint> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if y.seq > x.seq { y } else { x }),
        (x, y) => x.or(y),
    }
}

impl Chain {
    /// Continue checking `host`'s log from `tip` (the view's resume point),
    /// holding it to `anchor` (the host's).
    pub(crate) fn new(host: NodeId, tip: Option<ChainPoint>, anchor: Option<ChainPoint>) -> Self {
        Self { host, tip, anchor }
    }

    /// The last verified point of this stream.
    pub(crate) fn tip(&self) -> Option<ChainPoint> {
        self.tip
    }

    /// The host's anchor after this stream: the furthest verified point.
    pub(crate) fn anchor(&self) -> Option<ChainPoint> {
        later(self.anchor, self.tip)
    }

    /// Check the host's tip and first held seq (from a
    /// [`RecordFrame::Granted`]) against what the reader verified.
    ///
    /// A tip below the furthest verified point is a rollback, and a
    /// different entry at that point a fork: both are [`ChainBreak`]s. A
    /// first held seq past the point after the anchor (or the resume point)
    /// is retention: that point is dropped, and [`Standing::Pruned`] says
    /// so.
    pub(crate) fn granted(
        &mut self,
        tip: Option<ChainPoint>,
        first: Option<LogSeq>,
    ) -> std::result::Result<Standing, ChainBreak> {
        if let Some(known) = self.anchor() {
            match tip {
                None => return Err(ChainBreak::RolledBack { seq: known.seq }),
                Some(t) if t.seq < known.seq => {
                    return Err(ChainBreak::RolledBack { seq: known.seq });
                }
                Some(t) if t.seq == known.seq && t.hash != known.hash => {
                    return Err(ChainBreak::Fork { seq: t.seq });
                }
                Some(_) => {}
            }
        }
        let Some(first) = first else {
            return Ok(Standing::Continuous);
        };
        let gone = |p: Option<ChainPoint>| p.is_some_and(|p| p.seq.next() < first);
        let mut standing = Standing::Continuous;
        if gone(self.anchor) {
            self.anchor = None;
            standing = Standing::Pruned(first);
        }
        if gone(self.tip) {
            self.tip = None;
            standing = Standing::Pruned(first);
        }
        Ok(standing)
    }

    /// Check the next streamed item. A shown entry must be signed by the host
    /// and link to the point before it; a hidden run must start right after
    /// it and link to it; and either must agree with the anchor where they
    /// meet it. Returns the entry when it is new and shown.
    pub(crate) fn accept(
        &mut self,
        item: StreamItem,
    ) -> std::result::Result<Option<LogEntry>, ChainBreak> {
        match item {
            StreamItem::Entry { entry } => {
                let before = self.tip.map(|t| t.seq);
                let tip = verify_chain(self.host, self.tip, std::slice::from_ref(&entry))?;
                let hash = entry
                    .hash()
                    .map_err(|_| ChainBreak::Malformed { seq: entry.seq })?;
                self.against_anchor(entry.seq, entry.prev, hash)?;
                self.tip = tip;
                // An exact repeat of the tip verifies but is not news.
                Ok((before < Some(entry.seq)).then_some(entry))
            }
            StreamItem::Hidden { from, links } => {
                let mut seq = from;
                for link in links {
                    self.link(seq, link)?;
                    seq = seq.next();
                }
                Ok(None)
            }
        }
    }

    /// The entry at `seq` (linking to `prev`, hashing to `hash`) against the
    /// anchor: at the anchor's seq it must be the anchored entry, and right
    /// after it, it must link to it.
    fn against_anchor(
        &self,
        seq: LogSeq,
        prev: library::EntryHash,
        hash: library::EntryHash,
    ) -> std::result::Result<(), ChainBreak> {
        match self.anchor {
            Some(a) if seq == a.seq && hash != a.hash => Err(ChainBreak::Fork { seq }),
            Some(a) if seq == a.seq.next() && prev != a.hash => Err(ChainBreak::BrokenLink { seq }),
            _ => Ok(()),
        }
    }

    /// Check one hidden entry at `seq`: it must follow the tip and link to
    /// it (a repeat of the tip must be the tip), and agree with the anchor.
    fn link(&mut self, seq: LogSeq, link: Link) -> std::result::Result<(), ChainBreak> {
        match self.tip {
            Some(t) if seq == t.seq && link.hash != t.hash => {
                return Err(ChainBreak::Fork { seq });
            }
            Some(t) if seq == t.seq => return Ok(()),
            Some(t) if seq < t.seq => return Err(ChainBreak::OutOfOrder { seq }),
            Some(t) if seq != t.seq.next() => {
                return Err(ChainBreak::Gap { after: t.seq, seq });
            }
            Some(t) if link.prev != t.hash => return Err(ChainBreak::BrokenLink { seq }),
            None if seq == LogSeq::GENESIS && !link.prev.is_zero() => {
                return Err(ChainBreak::BadGenesis { seq });
            }
            _ => {}
        }
        self.against_anchor(seq, link.prev, link.hash)?;
        self.tip = Some(ChainPoint {
            seq,
            hash: link.hash,
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

/// How many recent calls per host [`Labels`] remembers.
const LABELS_KEPT: usize = 1024;

/// The service each record is about, derived by the reader from signed
/// records (never from anything the host adds): a `Started`'s service, and for
/// a `Finished` or a service's `Push` the service of the `Started` with the
/// same call id this reader saw. Kept per host across runs (in
/// [`MARKS_FILE`]), for the most recent [`LABELS_KEPT`] calls.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, Serialize)]
pub(crate) struct Labels(VecDeque<(CallId, ServiceName)>);

impl Labels {
    /// The label for `record`, learning from it when it starts a call.
    pub(crate) fn label(&mut self, record: &AuditRecord) -> Option<ServiceName> {
        let of = |labels: &Self, call: &CallId| {
            labels
                .0
                .iter()
                .rev()
                .find(|(c, _)| c == call)
                .map(|(_, s)| s.clone())
        };
        match record {
            AuditRecord::Started { call, service, .. } => {
                self.0.push_back((*call, service.clone()));
                while self.0.len() > LABELS_KEPT {
                    self.0.pop_front();
                }
                Some(service.clone())
            }
            AuditRecord::Finished { call, .. } => of(self, call),
            AuditRecord::Push { call, .. } => call.as_ref().and_then(|c| of(self, c)),
            AuditRecord::Denied { service, .. } => service.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Marks
// ---------------------------------------------------------------------------

/// What the reader keeps about one host, in [`MARKS_FILE`].
#[derive(Clone, Debug, Default, serde::Deserialize, Serialize)]
pub(crate) struct HostMarks {
    /// The furthest point of this host's chain the reader verified, under
    /// any view: every later stream is held to it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) anchor: Option<ChainPoint>,
    /// Where each view (the services asked of this host, `--mine`) resumes.
    pub(crate) views: BTreeMap<String, ChainPoint>,
    /// The recent calls' services, for labels.
    pub(crate) labels: Labels,
}

/// The reader's marks per host (keyed by the host's hex id), in
/// [`MARKS_FILE`]: one chain anchor per host, and a resume point per view.
#[derive(Clone, Debug, Default, serde::Deserialize, Serialize)]
pub(crate) struct Marks(BTreeMap<String, HostMarks>);

impl Marks {
    /// The view key for the services asked of a host and `mine`.
    fn view(services: &[ServiceName], mine: bool) -> String {
        let names: Vec<&str> = services.iter().map(ServiceName::as_str).collect();
        format!("{}{}", names.join(","), if mine { " mine" } else { "" })
    }

    /// The marks for `host` (default when none).
    pub(crate) fn host(&self, host: NodeId) -> HostMarks {
        self.0.get(&host.hex()).cloned().unwrap_or_default()
    }

    /// Load the marks (none when the file is missing or unreadable).
    pub(crate) fn load(ks: &Keystore) -> Self {
        std::fs::read_to_string(ks.path(MARKS_FILE))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    /// Save the marks (`0600`); a failure is only logged.
    fn save(&self, ks: &Keystore) {
        let saved = serde_json::to_string_pretty(self)
            .map_err(anyhow::Error::from)
            .and_then(|json| {
                keystore::write_text_mode(&ks.path(MARKS_FILE), &format!("{json}\n"), Some(0o600))
            });
        if let Err(e) = saved {
            tracing::warn!("saving the watch marks: {e:#}");
        }
    }
}

// ---------------------------------------------------------------------------
// Streaming
// ---------------------------------------------------------------------------

/// Where one host's check stands: the stream's tip (the view's resume
/// point) and the host's anchor.
#[derive(Clone, Copy, Debug, Default)]
struct Progress {
    tip: Option<ChainPoint>,
    anchor: Option<ChainPoint>,
}

/// What one host's stream reports to the watch.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // transient, one per streamed item
enum Event {
    /// A verified item: where the check stands, and the entry when shown.
    Item {
        host: NodeId,
        progress: Progress,
        shown: Option<LogEntry>,
    },
    /// The host pruned entries before this seq (retention).
    Pruned(NodeId, LogSeq, Progress),
    /// The backlog is in.
    CaughtUp(NodeId),
    /// The log did not verify; the stream was dropped.
    Broken(NodeId, ChainBreak),
    /// The host refused the reader.
    Refused(NodeId, String),
    /// The dial or the stream failed.
    Failed(NodeId, String),
    /// The stream is over.
    Ended(NodeId),
}

impl Event {
    fn host(&self) -> NodeId {
        match self {
            Event::Item { host, .. }
            | Event::Pruned(host, ..)
            | Event::CaughtUp(host)
            | Event::Broken(host, _)
            | Event::Refused(host, _)
            | Event::Failed(host, _)
            | Event::Ended(host) => *host,
        }
    }
}

impl Chain {
    /// Whether this stream has yet to reach the host's anchor.
    fn short_of_anchor(&self) -> bool {
        self.anchor
            .is_some_and(|a| self.tip.is_none_or(|t| t.seq < a.seq))
    }

    /// Where this check stands.
    fn progress(&self) -> Progress {
        Progress {
            tip: self.tip(),
            anchor: self.anchor(),
        }
    }
}

/// Stream one host: send `open`, check every item with `chain`, report.
async fn stream_host(
    endpoint: Endpoint,
    target: EndpointAddr,
    open: RecordFrame,
    mut chain: Chain,
    tx: mpsc::UnboundedSender<Event>,
) {
    let host = chain.host;
    let result: Result<()> = async {
        let conn =
            tokio::time::timeout(DIAL_TIMEOUT, endpoint.connect(target, record_stream::ALPN))
                .await
                .context("the host did not answer in time")?
                .context("dialing the host")?;
        let (mut send, mut recv) = conn.open_bi().await.context("opening a stream")?;
        record_stream::write_frame(&mut send, &open).await?;
        // Entries before the anchor wait until the stream reaches it: they
        // are not known good until the anchor confirms the chain they're on
        // (a stream that breaks, or ends, first never shows them).
        let mut held: Vec<Event> = Vec::new();
        loop {
            match record_stream::read_frame(&mut recv).await? {
                None => break,
                Some(RecordFrame::Denied { reason }) => {
                    let _ = tx.send(Event::Refused(host, reason));
                    break;
                }
                Some(RecordFrame::Granted { scopes, tip, first }) => {
                    tracing::debug!(host = %host.hex(), ?scopes, ?tip, ?first, "record stream granted");
                    match chain.granted(tip, first) {
                        Ok(Standing::Continuous) => {}
                        Ok(Standing::Pruned(first)) => {
                            let _ = tx.send(Event::Pruned(host, first, chain.progress()));
                        }
                        Err(why) => {
                            let _ = tx.send(Event::Broken(host, why));
                            conn.close(1u32.into(), b"log does not verify");
                            return Ok(());
                        }
                    }
                }
                Some(RecordFrame::Batch { items }) => {
                    for item in items {
                        match chain.accept(item) {
                            Ok(shown) => {
                                held.push(Event::Item {
                                    host,
                                    progress: chain.progress(),
                                    shown,
                                });
                                if !chain.short_of_anchor() {
                                    for event in held.drain(..) {
                                        let _ = tx.send(event);
                                    }
                                }
                            }
                            Err(why) => {
                                let _ = tx.send(Event::Broken(host, why));
                                conn.close(1u32.into(), b"log does not verify");
                                return Ok(());
                            }
                        }
                    }
                }
                Some(RecordFrame::CaughtUp) => {
                    let _ = tx.send(Event::CaughtUp(host));
                }
                Some(RecordFrame::Open { .. }) => bail!("the host sent an open"),
            }
        }
        conn.close(0u32.into(), b"done");
        Ok(())
    }
    .await;
    if let Err(e) = result {
        let _ = tx.send(Event::Failed(host, format!("{e:#}")));
    }
    let _ = tx.send(Event::Ended(host));
}

/// Watch as the node in `ks`: dial the hosts of the services asked for
/// through `endpoint` (addresses from `hints`), verify, and hand each record,
/// notice and alarm to `out` — the merged backlog first, then (with
/// `follow`) live records. Returns when every host's stream has ended.
pub(crate) async fn watch_with(
    ks: &Keystore,
    endpoint: &Endpoint,
    hints: &Hints,
    relay: Option<&str>,
    opts: &WatchOpts,
    out: &mut (dyn FnMut(Output) + Send),
) -> Result<Report> {
    // Card 37: the services come from this node's view: those it may read
    // (every record) or call (its own records).
    let membership = ks.read_membership()?.context(crate::help::NOT_JOINED)?;
    let held = crate::caller::services::current_view(ks).await?;
    let view = &held.view;
    let services: Vec<ServiceName> = if opts.services.is_empty() {
        view.entries.iter().map(|e| e.entry.name.clone()).collect()
    } else {
        for s in &opts.services {
            if view.entry(s).is_none() {
                bail!("no service named `{s}` in your view (see `wires services`)");
            }
        }
        opts.services.clone()
    };
    let hello = crate::caller::hello::with_membership(ks, membership);
    let mut marks = Marks::load(ks);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let hosts = pick::hosts_of(view, services.iter());
    let mut report = Report {
        hosts: hosts.len(),
        ..Report::default()
    };
    // Per host: its view key, and the reader-side labels.
    let mut views: BTreeMap<NodeId, String> = BTreeMap::new();
    let mut labels: BTreeMap<NodeId, Labels> = BTreeMap::new();
    for host in &hosts {
        let here: Vec<ServiceName> = services
            .iter()
            .filter(|s| {
                view.entry(s)
                    .is_some_and(|e| e.entry.service.hosts.contains(host))
            })
            .cloned()
            .collect();
        let view = Marks::view(&here, opts.mine);
        let held = marks.host(*host);
        let resume = held.views.get(&view).copied();
        views.insert(*host, view);
        labels.insert(*host, held.labels.clone());
        let open = RecordFrame::Open {
            hello: hello.clone(),
            services: here,
            since: resume.map(|m| m.seq),
            mine: opts.mine,
            follow: opts.follow,
        };
        let Some(target) = hints.targets(&[*host], relay).into_iter().next() else {
            report
                .failed
                .push((*host, "no address for this host".to_string()));
            continue;
        };
        tokio::spawn(stream_host(
            endpoint.clone(),
            target,
            open,
            Chain::new(*host, resume, held.anchor),
            tx.clone(),
        ));
    }
    drop(tx);

    // The backlog: held until every host has caught up (or gone), then
    // merged by log time.
    let mut pending: BTreeSet<NodeId> = hosts.iter().copied().collect();
    for (h, _) in &report.failed {
        pending.remove(h);
    }
    let mut live: BTreeSet<NodeId> = pending.clone();
    let mut backlog: Vec<Shown> = Vec::new();
    let mut progress: BTreeMap<NodeId, Progress> = BTreeMap::new();
    let flush = |backlog: &mut Vec<Shown>,
                 progress: &mut BTreeMap<NodeId, Progress>,
                 labels: &BTreeMap<NodeId, Labels>,
                 marks: &mut Marks,
                 report: &mut Report,
                 out: &mut (dyn FnMut(Output) + Send)| {
        backlog.sort_by_key(|s| (s.entry.at_ms, s.host, s.seq));
        for s in backlog.drain(..) {
            report.shown += 1;
            out(Output::Record(Box::new(s)));
        }
        let changed = !progress.is_empty();
        for (h, p) in std::mem::take(progress) {
            let held = marks.0.entry(h.hex()).or_default();
            held.anchor = p.anchor;
            match p.tip {
                Some(tip) => held.views.insert(views[&h].clone(), tip),
                None => held.views.remove(&views[&h]),
            };
            held.labels = labels[&h].clone();
        }
        if changed {
            marks.save(ks);
        }
    };
    while let Some(event) = rx.recv().await {
        let host = event.host();
        let short = host.short();
        match event {
            Event::Item {
                progress: p, shown, ..
            } => {
                progress.insert(host, p);
                if let Some(entry) = shown {
                    let service = labels.get_mut(&host).and_then(|l| l.label(&entry.record));
                    backlog.push(Shown {
                        service,
                        host,
                        seq: entry.seq,
                        entry,
                    });
                }
            }
            Event::Pruned(_, first, p) => {
                progress.insert(host, p);
                out(Output::Notice(format!(
                    "host {short} pruned entries before seq {first} (retention); what this reader \
                     verified before that can no longer be checked, so checking starts over there"
                )));
                report.pruned.push((host, first));
            }
            Event::CaughtUp(_) => {
                pending.remove(&host);
            }
            Event::Broken(_, why) => {
                out(Output::Alarm(format!(
                    "ALERT: host {short}'s call log does not verify: {why}; stopped reading it \
                     (the mark stays at the last good entry)"
                )));
                report.broken.push((host, why));
            }
            Event::Refused(_, reason) => {
                out(Output::Alarm(format!("host {short}: {reason}")));
                report.refused.push((host, reason));
            }
            Event::Failed(_, e) => {
                out(Output::Alarm(format!(
                    "host {short} could not be read: {e}"
                )));
                report.failed.push((host, e));
            }
            Event::Ended(_) => {
                pending.remove(&host);
                live.remove(&host);
            }
        }
        if pending.is_empty() {
            flush(
                &mut backlog,
                &mut progress,
                &labels,
                &mut marks,
                &mut report,
                out,
            );
        }
        if live.is_empty() {
            break;
        }
    }
    flush(
        &mut backlog,
        &mut progress,
        &labels,
        &mut marks,
        &mut report,
        out,
    );
    Ok(report)
}

/// `wires watch`: returns the exit code (1 when a log did not verify, 77
/// when every host refused).
pub(crate) async fn watch_cmd(a: WatchArgs) -> Result<i32> {
    let ks = Keystore::resolve()?;
    let node = keystore::node_identity_in(&ks)?;
    let services = a
        .services
        .iter()
        .map(|s| ServiceName::new(s).with_context(|| format!("{s:?} is not a service name")))
        .collect::<Result<Vec<_>>>()?;
    let opts = WatchOpts {
        services,
        mine: a.mine,
        follow: !a.once,
    };
    let hints = Hints::load(&ks);
    let endpoint = transport::bind(&node, a.relay_url.as_deref()).await?;
    let json = a.json;
    let mut out = |o: Output| match o {
        Output::Record(s) => println!("{}", if json { json_line(&s) } else { text_line(&s) }),
        Output::Alarm(msg) => eprintln!("wires: {msg}"),
        Output::Notice(msg) => eprintln!("wires: note: {msg}"),
    };
    let report = tokio::select! {
        r = watch_with(&ks, &endpoint, &hints, a.relay_url.as_deref(), &opts, &mut out) => r?,
        r = tokio::signal::ctrl_c() => { r.context("waiting for ctrl-c")?; return Ok(0) }
    };
    endpoint.close().await;
    Ok(if !report.broken.is_empty() {
        1
    } else if report.hosts > 0 && report.refused.len() == report.hosts {
        crate::EXIT_DENIED
    } else {
        0
    })
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// How many hex characters of a node id or digest a record line shows.
const SHORT_HEX: usize = 4;

/// How many characters of a call's stdin a `■` line quotes.
const STDIN_PREVIEW_CHARS: usize = 80;

/// The `--json` line for a record.
pub(crate) fn json_line(s: &Shown) -> String {
    serde_json::json!({
        "service": s.service,
        "host": s.host.hex(),
        "seq": s.seq,
        "entry": s.entry,
    })
    .to_string()
}

/// The human line for a record: `HH:MM:SS <service> <record line>`.
pub(crate) fn text_line(s: &Shown) -> String {
    let service = s.service.as_ref().map_or("-", ServiceName::as_str);
    format!(
        "{} {service:<9} {}",
        format_clock(s.entry.at_ms / 1000),
        audit_line(&s.entry.record)
    )
}

/// `HH:MM:SS` (UTC) of a Unix-seconds timestamp.
fn format_clock(ts: i64) -> String {
    let secs = ts.rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// One human line for a call-log record (`▶ ■ ⇢ ✗`).
pub(crate) fn audit_line(record: &AuditRecord) -> String {
    match record {
        AuditRecord::Started {
            call,
            caller,
            principal,
            service,
            argv,
            role,
            ..
        } => {
            let mut line = format!(
                "▶ {} {} [{}] {service}",
                short_hex(&call.hex()),
                caller_label(*caller, principal.as_ref()),
                one_line(role.as_str())
            );
            for arg in argv.as_slice() {
                line.push(' ');
                line.push_str(&quote_arg(arg));
            }
            line
        }
        AuditRecord::Finished {
            call,
            exit,
            duration_ms,
            stdout_bytes,
            stdout_digest,
            stdin_bytes,
            stdin_head,
            ..
        } => {
            let stdin = stdin_head
                .as_deref()
                .map(|head| format!("stdin {} · ", stdin_preview(head, *stdin_bytes)))
                .unwrap_or_default();
            format!(
                "■ {} exit {exit} · {duration_ms} ms · {stdin}{} out · blake3 {}…",
                short_hex(&call.hex()),
                human_bytes(*stdout_bytes),
                short_hex(&stdout_digest.hex())
            )
        }
        AuditRecord::Push {
            id,
            to,
            principal,
            role,
            subject,
            outcome,
            reason,
            body,
            ..
        } => {
            let role = role
                .as_deref()
                .map(|r| format!(" [{}]", one_line(r)))
                .unwrap_or_default();
            let mut line = format!(
                "⇢ {} → {}{role} {:?} {}",
                short_hex(&id.hex()),
                caller_label(*to, principal.as_ref()),
                subject.as_str(),
                outcome.as_str()
            );
            if let Some(reason) = reason {
                line.push_str(&format!(": {}", one_line(reason)));
            }
            if let Some(body) = body {
                line.push_str(&format!(" · body {}", stdin_preview(body.as_str(), 0)));
            }
            line
        }
        AuditRecord::Denied {
            caller,
            service,
            reason,
            ..
        } => match service {
            Some(service) => format!(
                "✗ {} {service} denied: {}",
                short_node(*caller),
                one_line(reason)
            ),
            None => format!("✗ {} denied: {}", short_node(*caller), one_line(reason)),
        },
    }
}

/// `alice@corp (a1b2…)` when the host verified an email, else `a1b2…`.
fn caller_label(caller: NodeId, principal: Option<&Principal>) -> String {
    match principal.and_then(|p| p.email.as_deref()) {
        Some(email) => format!("{} ({})", one_line(email), short_node(caller)),
        None => short_node(caller),
    }
}

/// The first [`SHORT_HEX`] hex characters of a node id, with an ellipsis.
fn short_node(node: NodeId) -> String {
    format!("{}…", short_hex(&node.hex()))
}

/// A byte count for humans: `512 B`, `3.1 KiB`, `2.0 MiB`.
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Stdin as a `■` line quotes it: whitespace collapsed, at most
/// [`STDIN_PREVIEW_CHARS`] characters, ` …` when cut, quoted.
fn stdin_preview(head: &str, stdin_bytes: u64) -> String {
    let collapsed = head.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut preview: String = collapsed.chars().take(STDIN_PREVIEW_CHARS).collect();
    if preview.len() < collapsed.len() || stdin_bytes > head.len() as u64 {
        preview.truncate(preview.trim_end().len());
        preview.push_str(" …");
    }
    format!("{preview:?}")
}

/// The leading [`SHORT_HEX`] characters of a hex string.
fn short_hex(hex: &str) -> &str {
    &hex[..SHORT_HEX.min(hex.len())]
}

/// An argument bare when it is a plain word, else quoted with escapes.
fn quote_arg(arg: &str) -> String {
    let plain = !arg.is_empty()
        && arg.chars().all(|c| {
            c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':' | '=' | ',' | '+' | '@')
        });
    if plain {
        arg.to_string()
    } else {
        format!("{arg:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{Argv, CallId, NodeIdentity, ServiceName};

    fn host() -> NodeIdentity {
        NodeIdentity::from_seed([9; 32])
    }

    fn entries(n: usize) -> Vec<LogEntry> {
        let h = host();
        let mut out: Vec<LogEntry> = Vec::new();
        for i in 0..n {
            let tip = out.last().map(|e| e.point().unwrap());
            let r = AuditRecord::Denied {
                caller: h.node_id(),
                principal: None,
                service: None,
                reason: format!("r{i}"),
                at_ms: 0,
            };
            out.push(LogEntry::next(&h, tip, 0, r).unwrap());
        }
        out
    }

    fn hidden(es: &[LogEntry]) -> StreamItem {
        StreamItem::Hidden {
            from: es[0].seq,
            links: es
                .iter()
                .map(|e| Link {
                    prev: e.prev,
                    hash: e.hash().unwrap(),
                })
                .collect(),
        }
    }

    fn shown(e: &LogEntry) -> StreamItem {
        StreamItem::Entry { entry: e.clone() }
    }

    #[test]
    fn a_chain_links_across_hidden_runs() {
        let es = entries(5);
        let mut c = Chain::new(host().node_id(), None, None);
        assert!(c.accept(shown(&es[0])).unwrap().is_some());
        assert!(c.accept(hidden(&es[1..4])).unwrap().is_none());
        assert!(c.accept(shown(&es[4])).unwrap().is_some());
        assert_eq!(c.tip(), Some(es[4].point().unwrap()));
        // A repeat of the tip is not news.
        assert!(c.accept(shown(&es[4])).unwrap().is_none());
    }

    #[test]
    fn a_chain_catches_tamper_gap_and_a_forged_hidden_run() {
        let es = entries(4);
        let id = host().node_id();
        // A flipped byte in a shown entry.
        let mut bad = es[1].clone();
        if let AuditRecord::Denied { reason, .. } = &mut bad.record {
            *reason = "rX".into();
        }
        let mut c = Chain::new(id, Some(es[0].point().unwrap()), None);
        assert_eq!(
            c.accept(shown(&bad)),
            Err(ChainBreak::BadSignature { seq: LogSeq(1) })
        );
        // A missing entry.
        let mut c = Chain::new(id, Some(es[0].point().unwrap()), None);
        assert_eq!(
            c.accept(shown(&es[2])),
            Err(ChainBreak::Gap {
                after: LogSeq(0),
                seq: LogSeq(2)
            })
        );
        // A hidden run whose hash doesn't match what the next entry links to
        // (a tampered entry the reader can't see).
        let mut c = Chain::new(id, Some(es[0].point().unwrap()), None);
        let mut run = hidden(&es[1..3]);
        if let StreamItem::Hidden { links, .. } = &mut run {
            links[0].hash = bad.hash().unwrap();
        }
        assert_eq!(
            c.accept(run),
            Err(ChainBreak::BrokenLink { seq: LogSeq(2) })
        );
        // A hidden run that doesn't link to the tip.
        let mut c = Chain::new(id, Some(es[1].point().unwrap()), None);
        let mut run = hidden(&es[2..3]);
        if let StreamItem::Hidden { links, .. } = &mut run {
            links[0].prev = es[0].hash().unwrap();
        }
        assert_eq!(
            c.accept(run),
            Err(ChainBreak::BrokenLink { seq: LogSeq(2) })
        );
    }

    /// `entries(n)`, but entry `at` (and so every later one) rewritten and
    /// re-signed by the host key: a consistent chain of its own.
    fn rewritten(n: usize, at: usize) -> Vec<LogEntry> {
        let h = host();
        let mut out: Vec<LogEntry> = Vec::new();
        for (i, e) in entries(n).into_iter().enumerate() {
            let tip = out.last().map(|e| e.point().unwrap());
            let mut r = e.record;
            if i == at
                && let AuditRecord::Denied { reason, .. } = &mut r
            {
                *reason = "rewritten".into();
            }
            out.push(LogEntry::next(&h, tip, 0, r).unwrap());
        }
        out
    }

    /// A view with no resume point of its own is still held to the host's
    /// anchor: a rewritten log that is consistent in itself is a fork where
    /// it passes the anchor, whether it passes it shown or hidden.
    #[test]
    fn a_new_view_is_held_to_the_hosts_anchor() {
        let es = entries(5);
        let anchor = Some(es[3].point().unwrap());
        let forged = rewritten(5, 2);
        let mut c = Chain::new(host().node_id(), None, anchor);
        for e in &forged[..3] {
            c.accept(shown(e)).unwrap();
        }
        assert_eq!(
            c.accept(shown(&forged[3])),
            Err(ChainBreak::Fork { seq: LogSeq(3) })
        );
        let mut c = Chain::new(host().node_id(), None, anchor);
        assert_eq!(
            c.accept(hidden(&forged[..5])),
            Err(ChainBreak::Fork { seq: LogSeq(3) })
        );
        // The honest log passes, and the anchor moves on with it.
        let mut c = Chain::new(host().node_id(), None, anchor);
        c.accept(hidden(&es[..4])).unwrap();
        c.accept(shown(&es[4])).unwrap();
        assert_eq!(c.anchor(), Some(es[4].point().unwrap()));
        // Starting right after the anchor (it was pruned), the first entry
        // must still link to it.
        let mut c = Chain::new(host().node_id(), None, anchor);
        assert_eq!(
            c.accept(shown(&forged[4])),
            Err(ChainBreak::BrokenLink { seq: LogSeq(4) })
        );
    }

    /// A host whose tip is below the anchor rolled its log back; one with a
    /// different entry at the anchor forked it.
    #[test]
    fn a_tip_below_the_anchor_is_a_rollback() {
        let es = entries(5);
        let id = host().node_id();
        let anchor = Some(es[3].point().unwrap());
        let mut c = Chain::new(id, Some(es[1].point().unwrap()), anchor);
        assert_eq!(
            c.granted(Some(es[2].point().unwrap()), Some(LogSeq(0))),
            Err(ChainBreak::RolledBack { seq: LogSeq(3) })
        );
        assert_eq!(
            Chain::new(id, None, anchor).granted(None, None),
            Err(ChainBreak::RolledBack { seq: LogSeq(3) })
        );
        let forged = rewritten(4, 2);
        assert_eq!(
            Chain::new(id, None, anchor).granted(Some(forged[3].point().unwrap()), Some(LogSeq(0))),
            Err(ChainBreak::Fork { seq: LogSeq(3) })
        );
        let mut c = Chain::new(id, None, anchor);
        assert_eq!(
            c.granted(Some(es[4].point().unwrap()), Some(LogSeq(0))),
            Ok(Standing::Continuous)
        );
    }

    /// Entries pruned from the front past the anchor are retention, not
    /// tampering: the anchor (and a resume point the host can't continue)
    /// is dropped, and the stream from the first held entry verifies.
    #[test]
    fn pruning_past_the_anchor_is_retention() {
        let es = entries(8);
        let id = host().node_id();
        let mut c = Chain::new(
            id,
            Some(es[1].point().unwrap()),
            Some(es[2].point().unwrap()),
        );
        assert_eq!(
            c.granted(Some(es[7].point().unwrap()), Some(LogSeq(5))),
            Ok(Standing::Pruned(LogSeq(5)))
        );
        assert_eq!((c.tip(), c.anchor()), (None, None));
        c.accept(shown(&es[5])).unwrap();
        c.accept(hidden(&es[6..8])).unwrap();
        assert_eq!(c.anchor(), Some(es[7].point().unwrap()));
        // Pruned up to right after the anchor: it can still be checked.
        let mut c = Chain::new(
            id,
            Some(es[2].point().unwrap()),
            Some(es[2].point().unwrap()),
        );
        assert_eq!(
            c.granted(Some(es[7].point().unwrap()), Some(LogSeq(3))),
            Ok(Standing::Continuous)
        );
    }

    /// The label is derived from signed records by the reader: a Started's
    /// service, and the same call's Finished and pushes; an operator push and
    /// a call never seen start have none.
    #[test]
    fn labels_come_from_the_signed_started() {
        let caller = NodeIdentity::from_seed([2; 32]).node_id();
        let call = CallId::from_hex(&"3fa2".repeat(8)).unwrap();
        let other = CallId::from_hex(&"9999".repeat(8)).unwrap();
        let started = AuditRecord::Started {
            call,
            caller,
            principal: None,
            service: ServiceName::new("orders-db").unwrap(),
            argv: Argv::new(vec![]).unwrap(),
            state_version: library::StateVersion(1),
            role: library::RoleName::new("analyst").unwrap(),
            at_ms: 0,
        };
        let finished = |call| AuditRecord::Finished {
            call,
            exit: 0,
            duration_ms: 1,
            stdout_bytes: 0,
            stderr_bytes: 0,
            stdout_digest: library::OutputDigest::empty(),
            stdin_bytes: 0,
            stdin_digest: library::OutputDigest::empty(),
            stdin_head: None,
        };
        let push = |call| AuditRecord::Push {
            id: library::PushId::from_hex(&"ab".repeat(16)).unwrap(),
            to: caller,
            principal: None,
            role: None,
            subject: library::Subject::new("s").unwrap(),
            outcome: library::PushOutcome::Queued,
            reason: None,
            body: None,
            call,
            at_ms: 0,
        };
        let orders = Some(ServiceName::new("orders-db").unwrap());
        let mut labels = Labels::default();
        assert_eq!(labels.label(&finished(call)), None);
        assert_eq!(labels.label(&started), orders);
        assert_eq!(labels.label(&push(Some(call))), orders);
        assert_eq!(labels.label(&finished(call)), orders);
        assert_eq!(labels.label(&push(None)), None);
        assert_eq!(labels.label(&push(Some(other))), None);
        // Kept across runs in the marks file.
        let json = serde_json::to_string(&labels).unwrap();
        let mut back: Labels = serde_json::from_str(&json).unwrap();
        assert_eq!(back.label(&finished(call)), orders);
    }

    #[test]
    fn record_line_formats() {
        let caller = NodeIdentity::from_seed([2; 32]).node_id();
        let started = AuditRecord::Started {
            call: CallId::from_hex(&"3fa2".repeat(8)).unwrap(),
            caller,
            principal: None,
            service: ServiceName::new("orders-db").unwrap(),
            argv: Argv::new(vec!["select 1".into(), "x".into()]).unwrap(),
            state_version: library::StateVersion(1),
            role: library::RoleName::new("analyst").unwrap(),
            at_ms: 0,
        };
        assert_eq!(
            audit_line(&started),
            format!(
                "▶ 3fa2 {} [analyst] orders-db \"select 1\" x",
                short_node(caller)
            )
        );
        let denied = AuditRecord::Denied {
            caller,
            principal: None,
            service: None,
            reason: "no\nforged".into(),
            at_ms: 0,
        };
        assert!(!audit_line(&denied).contains('\n'));
        assert_eq!(format_clock(86_400 + 61), "00:01:01");
        assert_eq!(human_bytes(3200), "3.1 KiB");
    }
}

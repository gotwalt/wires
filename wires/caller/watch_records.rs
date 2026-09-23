//! `wires watch [<service>…] [--mine] [--json]` (card 26b): stream call
//! records from the hosts that hold them.
//!
//! The service's hosts come from the signed state; the reader never names a
//! host. Each host is dialed by key on the record-stream ALPN
//! ([`record_stream`](crate::host::record_stream)) with the same credentials
//! a call presents, and answers with what this reader may see: every record
//! of a service whose `readers` roles it is in, otherwise only its own calls
//! (`--mine` asks for only those everywhere). With no service named, every
//! service in the signed state is asked for.
//!
//! Every entry is checked as it arrives ([`Chain`]): the host's signature,
//! and the hash link to the entry before it, across the runs of entries the
//! reader may not see. A tampered, missing or forked entry stops that host's
//! stream with a loud alarm on stderr (exit 1), and the reader's mark for it
//! is left at the last good entry.
//!
//! The backlog from every host is merged by time and printed first; then,
//! unless `--once`, new records as they are logged. The verified tip per
//! host (and per view: the services asked for and `--mine`) is kept in
//! [`MARKS_FILE`] in the keystore, so a restart resumes where it stopped.
//!
//! ```text
//! 14:02:07 orders-db ▶ 3fa2 alice@example.com (a1b2…) [analyst] orders-db "select 1"
//! 14:02:07 orders-db ■ 3fa2 exit 0 · 41 ms · 12 B out · blake3 9c1e…
//! 14:02:09 orders-db ✗ 7c3d… orders-db denied: bob@example.com is in no role allowed to call orders-db (analyst)
//! 14:03:00 -         ⇢ 9c1e → alice@example.com (a1b2…) [analyst] "build-41" delivered
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Args;
use iroh::{Endpoint, EndpointAddr};
use library::{
    AuditRecord, ChainBreak, ChainPoint, LogEntry, LogSeq, NodeId, Principal, ServiceName,
    verify_chain,
};
use serde::Serialize;
use tokio::sync::mpsc;

use crate::admin::keystore::{self, Keystore};
use crate::caller::pick::{self, Hints};
use crate::host::record_stream::{self, Link, RecordFrame, StreamItem};
use crate::host::transport;
use crate::state::store;

/// The keystore file holding the reader's verified tip per host and view.
pub(crate) const MARKS_FILE: &str = "record-marks.json";

/// How long a host gets to answer the dial.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// `wires watch [<service>…] [--mine] [--json] [--once]`.
#[derive(Args, Clone, Debug, Default)]
pub(crate) struct WatchArgs {
    /// The services to watch (default: every service in the signed state).
    #[arg(value_name = "SERVICE")]
    pub(crate) services: Vec<String>,
    /// Only your own calls, even for services whose records you may read.
    #[arg(long)]
    pub(crate) mine: bool,
    /// One JSON object per record: `{service, host, seq, entry}` (the entry
    /// is the host-signed log entry, verifiable on its own).
    #[arg(long)]
    pub(crate) json: bool,
    /// Print what is there (after your last mark) and exit, instead of
    /// following.
    #[arg(long)]
    pub(crate) once: bool,
    /// Dial through this relay instead of the n0 default.
    #[arg(long)]
    pub(crate) relay_url: Option<String>,
}

/// What a watch asks for.
#[derive(Clone, Debug, Default)]
pub(crate) struct WatchOpts {
    /// The services (empty: every service in the signed state).
    pub(crate) services: Vec<ServiceName>,
    /// Only the reader's own calls.
    pub(crate) mine: bool,
    /// Keep streaming after the backlog.
    pub(crate) follow: bool,
}

/// One verified record, ready to show.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Shown {
    /// The service it is about (`None`: none, e.g. a push).
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
    /// Hosts asked.
    pub(crate) hosts: usize,
}

// ---------------------------------------------------------------------------
// Verifying a host's stream
// ---------------------------------------------------------------------------

/// A reader's running check of one host's log.
#[derive(Clone, Debug)]
pub(crate) struct Chain {
    /// The host whose log it is.
    host: NodeId,
    /// The last verified point (`None`: nothing yet).
    tip: Option<ChainPoint>,
}

impl Chain {
    /// Continue checking `host`'s log from `tip` (the reader's mark).
    pub(crate) fn new(host: NodeId, tip: Option<ChainPoint>) -> Self {
        Self { host, tip }
    }

    /// The last verified point.
    pub(crate) fn tip(&self) -> Option<ChainPoint> {
        self.tip
    }

    /// Check the next streamed item. A shown entry must be signed by the host
    /// and link to the point before it; a hidden run must start right after
    /// it and link to it. Returns the entry when it is new and shown.
    pub(crate) fn accept(
        &mut self,
        item: StreamItem,
    ) -> std::result::Result<Option<(Option<ServiceName>, LogEntry)>, ChainBreak> {
        match item {
            StreamItem::Entry { service, entry } => {
                let before = self.tip.map(|t| t.seq);
                self.tip = verify_chain(self.host, self.tip, std::slice::from_ref(&entry))?;
                // An exact repeat of the tip verifies but is not news.
                Ok((before < Some(entry.seq)).then_some((service, entry)))
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

    /// Check one hidden entry at `seq`: it must follow the tip and link to
    /// it (a repeat of the tip must be the tip).
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
        self.tip = Some(ChainPoint {
            seq,
            hash: link.hash,
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Marks
// ---------------------------------------------------------------------------

/// The reader's verified tip per host and view, in [`MARKS_FILE`].
#[derive(Clone, Debug, Default, serde::Deserialize, Serialize)]
pub(crate) struct Marks(BTreeMap<String, ChainPoint>);

impl Marks {
    /// The key for `host` under a view (the services asked of it, `mine`).
    fn key(host: NodeId, services: &[ServiceName], mine: bool) -> String {
        let names: Vec<&str> = services.iter().map(ServiceName::as_str).collect();
        format!(
            "{} {}{}",
            host.hex(),
            names.join(","),
            if mine { " mine" } else { "" }
        )
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

/// What one host's stream reports to the watch.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // transient, one per streamed item
enum Event {
    /// A verified item; the new tip, and the entry when it is shown.
    Item {
        host: NodeId,
        tip: Option<ChainPoint>,
        shown: Option<(Option<ServiceName>, LogEntry)>,
    },
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
            | Event::CaughtUp(host)
            | Event::Broken(host, _)
            | Event::Refused(host, _)
            | Event::Failed(host, _)
            | Event::Ended(host) => *host,
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
        loop {
            match record_stream::read_frame(&mut recv).await? {
                None => break,
                Some(RecordFrame::Denied { reason }) => {
                    let _ = tx.send(Event::Refused(host, reason));
                    break;
                }
                Some(RecordFrame::Granted { scopes }) => {
                    tracing::debug!(host = %host.hex(), ?scopes, "record stream granted");
                }
                Some(RecordFrame::Batch { items }) => {
                    for item in items {
                        match chain.accept(item) {
                            Ok(shown) => {
                                let _ = tx.send(Event::Item {
                                    host,
                                    tip: chain.tip(),
                                    shown,
                                });
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
/// through `endpoint` (addresses from `hints`), verify, and hand each record
/// and alarm to `out` — the merged backlog first, then (with `follow`) live
/// records. Returns when every host's stream has ended.
pub(crate) async fn watch_with(
    ks: &Keystore,
    endpoint: &Endpoint,
    hints: &Hints,
    relay: Option<&str>,
    opts: &WatchOpts,
    out: &mut (dyn FnMut(Output) + Send),
) -> Result<Report> {
    let membership = ks
        .read_membership()?
        .context("this node has no membership: run `wires join <token>` first")?;
    let state = store::read(ks, membership.fabric)?.context(
        "this node holds no signed state yet: `wires join` delivers it (or ask the admin to \
         push it)",
    )?;
    let state = &state.state;
    let services: Vec<ServiceName> = if opts.services.is_empty() {
        state.services.keys().cloned().collect()
    } else {
        for s in &opts.services {
            if state.service(s).is_none() {
                bail!("no service named `{s}` (see `wires services`)");
            }
        }
        opts.services.clone()
    };
    let hello = crate::caller::hello::with_membership(ks, membership)?;
    let mut marks = Marks::load(ks);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let hosts = pick::hosts_of(state, services.iter());
    let mut report = Report {
        hosts: hosts.len(),
        ..Report::default()
    };
    let mut keys: BTreeMap<NodeId, String> = BTreeMap::new();
    for host in &hosts {
        let here: Vec<ServiceName> = services
            .iter()
            .filter(|s| state.assigns(s, *host))
            .cloned()
            .collect();
        let key = Marks::key(*host, &here, opts.mine);
        let mark = marks.0.get(&key).copied();
        keys.insert(*host, key);
        let open = RecordFrame::Open {
            hello: hello.clone(),
            services: here,
            since: mark.map(|m| m.seq),
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
            Chain::new(*host, mark),
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
    let mut tips: BTreeMap<NodeId, ChainPoint> = BTreeMap::new();
    let flush = |backlog: &mut Vec<Shown>,
                 tips: &mut BTreeMap<NodeId, ChainPoint>,
                 marks: &mut Marks,
                 report: &mut Report,
                 out: &mut (dyn FnMut(Output) + Send)| {
        backlog.sort_by_key(|s| (s.entry.at_ms, s.host, s.seq));
        for s in backlog.drain(..) {
            report.shown += 1;
            out(Output::Record(Box::new(s)));
        }
        let changed = !tips.is_empty();
        for (h, tip) in std::mem::take(tips) {
            marks.0.insert(keys[&h].clone(), tip);
        }
        if changed {
            marks.save(ks);
        }
    };
    while let Some(event) = rx.recv().await {
        let host = event.host();
        let short = pick::short(&host);
        match event {
            Event::Item { tip, shown, .. } => {
                if let Some(tip) = tip {
                    tips.insert(host, tip);
                }
                if let Some((service, entry)) = shown {
                    backlog.push(Shown {
                        service,
                        host,
                        seq: entry.seq,
                        entry,
                    });
                }
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
            flush(&mut backlog, &mut tips, &mut marks, &mut report, out);
        }
        if live.is_empty() {
            break;
        }
    }
    flush(&mut backlog, &mut tips, &mut marks, &mut report, out);
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
    let fabric = ks
        .read_membership()?
        .context("this node has no membership: run `wires join <token>` first")?
        .fabric;
    let hints = Hints::load(&ks, fabric);
    let endpoint = transport::bind(&node, a.relay_url.as_deref()).await?;
    let json = a.json;
    let mut out = |o: Output| match o {
        Output::Record(s) => println!("{}", if json { json_line(&s) } else { text_line(&s) }),
        Output::Alarm(msg) => eprintln!("wires: {msg}"),
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
// Rendering (copied from the channel-era `wires watch`, which is going away)
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
            tool,
            argv,
            role,
            ..
        } => {
            let role = role
                .as_deref()
                .map(|r| format!(" [{}]", escape(r)))
                .unwrap_or_default();
            let mut line = format!(
                "▶ {} {}{role} {tool}",
                short_hex(&call.hex()),
                caller_label(*caller, principal.as_ref())
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
                .map(|r| format!(" [{}]", escape(r)))
                .unwrap_or_default();
            let mut line = format!(
                "⇢ {} → {}{role} {:?} {}",
                short_hex(&id.hex()),
                caller_label(*to, principal.as_ref()),
                subject.as_str(),
                outcome.as_str()
            );
            if let Some(reason) = reason {
                line.push_str(&format!(": {}", escape(reason)));
            }
            if let Some(body) = body {
                line.push_str(&format!(" · body {}", stdin_preview(body.as_str(), 0)));
            }
            line
        }
        AuditRecord::Denied {
            caller,
            tool,
            reason,
            ..
        } => match tool {
            Some(tool) => format!(
                "✗ {} {tool} denied: {}",
                short_node(*caller),
                escape(reason)
            ),
            None => format!("✗ {} denied: {}", short_node(*caller), escape(reason)),
        },
    }
}

/// `alice@corp (a1b2…)` when the host verified an email, else `a1b2…`.
fn caller_label(caller: NodeId, principal: Option<&Principal>) -> String {
    match principal.and_then(|p| p.email.as_deref()) {
        Some(email) => format!("{} ({})", escape(email), short_node(caller)),
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

/// `s` with every control character escaped (a record must not be able to
/// forge a second line or drive the terminal).
fn escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            let escaped: Vec<char> = if c.is_control() {
                c.escape_default().collect()
            } else {
                vec![c]
            };
            escaped
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{Argv, CallId, NodeIdentity, ToolName};

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
                tool: None,
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
        StreamItem::Entry {
            service: None,
            entry: e.clone(),
        }
    }

    #[test]
    fn a_chain_links_across_hidden_runs() {
        let es = entries(5);
        let mut c = Chain::new(host().node_id(), None);
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
        let mut c = Chain::new(id, Some(es[0].point().unwrap()));
        assert_eq!(
            c.accept(shown(&bad)),
            Err(ChainBreak::BadSignature { seq: LogSeq(1) })
        );
        // A missing entry.
        let mut c = Chain::new(id, Some(es[0].point().unwrap()));
        assert_eq!(
            c.accept(shown(&es[2])),
            Err(ChainBreak::Gap {
                after: LogSeq(0),
                seq: LogSeq(2)
            })
        );
        // A hidden run whose hash doesn't match what the next entry links to
        // (a tampered entry the reader can't see).
        let mut c = Chain::new(id, Some(es[0].point().unwrap()));
        let mut run = hidden(&es[1..3]);
        if let StreamItem::Hidden { links, .. } = &mut run {
            links[0].hash = bad.hash().unwrap();
        }
        assert_eq!(
            c.accept(run),
            Err(ChainBreak::BrokenLink { seq: LogSeq(2) })
        );
        // A hidden run that doesn't link to the tip.
        let mut c = Chain::new(id, Some(es[1].point().unwrap()));
        let mut run = hidden(&es[2..3]);
        if let StreamItem::Hidden { links, .. } = &mut run {
            links[0].prev = es[0].hash().unwrap();
        }
        assert_eq!(
            c.accept(run),
            Err(ChainBreak::BrokenLink { seq: LogSeq(2) })
        );
    }

    #[test]
    fn the_record_line_formats_are_the_channel_eras() {
        let caller = NodeIdentity::from_seed([2; 32]).node_id();
        let started = AuditRecord::Started {
            call: CallId::from_hex(&"3fa2".repeat(8)).unwrap(),
            caller,
            principal: None,
            tool: ToolName::new("orders-db").unwrap(),
            argv: Argv::new(vec!["select 1".into(), "x".into()]).unwrap(),
            roster_version: None,
            role: Some("analyst".into()),
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
            tool: None,
            reason: "no\nforged".into(),
            at_ms: 0,
        };
        assert!(!audit_line(&denied).contains('\n'));
        assert_eq!(format_clock(86_400 + 61), "00:01:01");
        assert_eq!(human_bytes(3200), "3.1 KiB");
    }
}

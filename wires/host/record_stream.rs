//! The record stream (card 26b): a host serves its own signed call log
//! ([`call_log`](super::call_log)) to authorized readers, by key, on
//! [`ALPN`]. Nothing is broadcast: a record leaves the host only when a
//! reader asks for it and may see it.
//!
//! # Protocol
//!
//! One bi-stream of length-prefixed JSON [`RecordFrame`]s:
//!
//! 1. reader → [`RecordFrame::Open`]: its [`Hello`] (membership, state
//!    version, ID token: the same credentials a call presents), the services
//!    it wants, `since` (its high-water mark on this host), `mine`, `follow`;
//! 2. host → [`RecordFrame::Denied`] (not a member; nothing else is sent), or
//!    [`RecordFrame::Granted`]: per requested service assigned to this host,
//!    [`Scope::All`] (the caller is in one of the service's `readers` roles,
//!    and didn't ask for `mine`) or [`Scope::Mine`] (every other member);
//! 3. host → [`RecordFrame::Batch`]es of [`StreamItem`]s after `since`, then
//!    [`RecordFrame::CaughtUp`]; with `follow`, further batches as the log
//!    grows, until the reader hangs up.
//!
//! # What a reader sees
//!
//! Every entry of the log is sent either **in full** (signed, exactly as
//! stored) or in a [`StreamItem::Hidden`] run: only each entry's [`Link`]
//! (its `prev` and its hash as stored). No content, caller, service or time.
//! The links let the reader keep checking the chain across entries it may
//! not see, so a flipped byte in *any* stored entry (seen or not) breaks its
//! chain, and so does a gap or a fork. (A link costs about 140 bytes; a
//! reader of little is still sent one per entry. Fine for the alpha.)
//!
//! An entry is shown in full when its service was granted [`Scope::All`], or
//! when the reader is its subject (the caller of a call or refusal, the
//! recipient of a push) and its service was requested (entries with no
//! service, like a refusal before naming one or a push, count as requested).
//! Service-less entries are also shown to a reader holding [`Scope::All`]
//! for any service here. `Finished` records carry no caller or service; they
//! inherit their `Started`'s.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use library::{
    AuditRecord, CallId, EntryHash, Hello, LogEntry, LogSeq, NodeId, ServiceName, check_inclusion,
    role_admits,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::call_log;
use super::gate::ServicesHost;
use super::transport;

/// The record-stream ALPN.
pub(crate) const ALPN: &[u8] = b"wires/records/1";

/// The largest frame either side accepts.
const MAX_FRAME: usize = 16 * 1024 * 1024;

/// How long the host waits for the reader's [`RecordFrame::Open`].
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Most items per [`RecordFrame::Batch`].
const BATCH: usize = 256;

/// How often a following stream looks for new entries.
const POLL: Duration = Duration::from_millis(200);

/// What a reader may see of one service's records on a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Scope {
    /// Every record: the reader is in one of the service's `readers` roles.
    All,
    /// Only the reader's own calls.
    Mine,
}

/// One log entry as streamed: shown, or hidden in a run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)] // transient, one per entry on the wire
pub(crate) enum StreamItem {
    /// An entry the reader may see, exactly as stored, with the service it
    /// belongs to (`None`: no service, e.g. a push).
    Entry {
        /// The service the record is about.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        service: Option<ServiceName>,
        /// The signed entry.
        entry: LogEntry,
    },
    /// Consecutive entries the reader may not see, from `from` on: only each
    /// entry's link (its `prev` and its own hash), so the reader can keep
    /// checking the chain across them.
    Hidden {
        /// The first hidden entry's seq.
        from: LogSeq,
        /// One link per hidden entry, in order.
        links: Vec<Link>,
    },
}

/// A hidden entry's place in the chain: what it links to, and its hash as
/// stored (so a stored entry that was altered no longer matches the `prev`
/// of the entry after it).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Link {
    /// The entry's `prev`.
    pub(crate) prev: EntryHash,
    /// The entry's hash.
    pub(crate) hash: EntryHash,
}

impl StreamItem {
    /// The last seq this item covers.
    pub(crate) fn last_seq(&self) -> LogSeq {
        match self {
            StreamItem::Entry { entry, .. } => entry.seq,
            StreamItem::Hidden { from, links } => LogSeq(from.0 + links.len().max(1) as u64 - 1),
        }
    }
}

/// A frame on the record stream. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)] // transient, one per frame
pub(crate) enum RecordFrame {
    /// Reader → host: who it is and what it wants.
    Open {
        /// The reader's credentials (as a call presents them).
        hello: Hello,
        /// The services it wants records of.
        services: Vec<ServiceName>,
        /// Only entries after this seq (its high-water mark here).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        since: Option<LogSeq>,
        /// Only its own calls, even where it may read all.
        mine: bool,
        /// Keep the stream open for new entries after the backlog.
        follow: bool,
    },
    /// Host → reader: what it may see, per requested service hosted here.
    Granted {
        /// Service → scope (services not assigned here are left out).
        scopes: BTreeMap<ServiceName, Scope>,
    },
    /// Host → reader: the next items, in log order.
    Batch {
        /// The items.
        items: Vec<StreamItem>,
    },
    /// Host → reader: the backlog has been sent.
    CaughtUp,
    /// Host → reader: refused, and why.
    Denied {
        /// The reason.
        reason: String,
    },
}

/// Write one frame: a 4-byte big-endian length, then JSON.
pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, f: &RecordFrame) -> Result<()> {
    let body = serde_json::to_vec(f).context("encoding a record frame")?;
    if body.len() > MAX_FRAME {
        bail!("record frame too large: {} bytes", body.len());
    }
    let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(&body);
    w.write_all(&bytes)
        .await
        .context("writing a record frame")?;
    Ok(())
}

/// Read one frame; `None` at a clean end of stream. The length is checked
/// before the body is allocated.
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<RecordFrame>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("reading a record frame"),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        bail!("record frame too large: {len} bytes (max {MAX_FRAME})");
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)
        .await
        .context("reading a record frame body")?;
    Ok(Some(
        serde_json::from_slice(&body).context("decoding a record frame")?,
    ))
}

/// Who a reader is and what it was granted: decides each entry.
#[derive(Clone, Debug)]
pub(crate) struct View {
    /// The reader.
    pub(crate) reader: NodeId,
    /// What it was granted, per service.
    pub(crate) scopes: BTreeMap<ServiceName, Scope>,
}

impl View {
    /// Whether the reader may see a record about `service` whose subject is
    /// `subject`. See the module docs.
    fn shows(&self, service: Option<&ServiceName>, subject: Option<NodeId>) -> bool {
        let mine = subject == Some(self.reader);
        match service {
            Some(s) => match self.scopes.get(s) {
                Some(Scope::All) => true,
                Some(Scope::Mine) => mine,
                None => false,
            },
            None => mine || self.scopes.values().any(|s| *s == Scope::All),
        }
    }

    /// Turn a whole log (`entries`, oldest first) into what this reader is
    /// sent of the entries after `since`: shown entries in full, the rest in
    /// [`StreamItem::Hidden`] runs. The whole log is walked so a `Finished`
    /// finds its `Started` even when that came before `since`.
    pub(crate) fn items(&self, entries: &[LogEntry], since: Option<LogSeq>) -> Vec<StreamItem> {
        let mut calls: HashMap<CallId, (ServiceName, NodeId)> = HashMap::new();
        let mut out: Vec<StreamItem> = Vec::new();
        for entry in entries {
            let (service, subject) = match &entry.record {
                AuditRecord::Started {
                    call, caller, tool, ..
                } => {
                    let service = ServiceName::from(tool.clone());
                    calls.insert(*call, (service.clone(), *caller));
                    (Some(service), Some(*caller))
                }
                AuditRecord::Finished { call, .. } => match calls.get(call) {
                    Some((s, c)) => (Some(s.clone()), Some(*c)),
                    // Its start was pruned: nobody can tell whose it was.
                    None => (None, None),
                },
                AuditRecord::Denied { caller, tool, .. } => {
                    (tool.clone().map(ServiceName::from), Some(*caller))
                }
                AuditRecord::Push { to, .. } => (None, Some(*to)),
            };
            if since.is_some_and(|s| entry.seq <= s) {
                continue;
            }
            if self.shows(service.as_ref(), subject) {
                out.push(StreamItem::Entry {
                    service,
                    entry: entry.clone(),
                });
                continue;
            }
            // Hash what is stored: a tampered entry breaks the reader's chain
            // even when the reader can't see it.
            let Ok(hash) = entry.hash() else { continue };
            let link = Link {
                prev: entry.prev,
                hash,
            };
            match out.last_mut() {
                Some(StreamItem::Hidden { from, links })
                    if LogSeq(from.0 + links.len() as u64) == entry.seq =>
                {
                    links.push(link)
                }
                _ => out.push(StreamItem::Hidden {
                    from: entry.seq,
                    links: vec![link],
                }),
            }
        }
        out
    }
}

/// Decide what `caller` (with `hello`) may read of `wanted` on `host` at
/// `now`: `Err` is the refusal sent to it.
pub(crate) async fn authorize(
    host: &ServicesHost,
    caller: NodeId,
    hello: &Hello,
    wanted: &[ServiceName],
    mine: bool,
    now: i64,
) -> std::result::Result<View, String> {
    let state = host.state().map_err(|e| {
        tracing::warn!("signed state unusable: {e:#}");
        "responder configuration error".to_string()
    })?;
    check_inclusion(&hello.membership, host.trust_root, caller, now)
        .map_err(|e| format!("membership rejected: {e}"))?;
    state.check_fresh(now).map_err(|e| {
        format!(
            "this host's signed state (version {}) is not fresh ({e})",
            state.state.version.0
        )
    })?;
    let s = &state.state;
    if !s.is_member(caller) {
        return Err(format!(
            "not a member of the current signed state (version {})",
            s.version.0
        ));
    }
    let (principal, _) = host.principal(caller, hello.id_token.as_ref(), now).await;
    let mut scopes = BTreeMap::new();
    for name in wanted {
        let Some(svc) = s.service(name) else { continue };
        if !s.assigns(name, host.me) {
            continue;
        }
        let reader = svc
            .readers
            .iter()
            .any(|r| role_admits(s, r, principal.as_ref()));
        scopes.insert(
            name.clone(),
            if reader && !mine {
                Scope::All
            } else {
                Scope::Mine
            },
        );
    }
    Ok(View {
        reader: caller,
        scopes,
    })
}

/// The record-stream ALPN on a v2 host.
#[derive(Clone, Debug)]
pub(crate) struct RecordStream {
    /// The host (its signed state, identity verifier, trust root).
    host: Arc<ServicesHost>,
    /// The call log file.
    log: PathBuf,
}

impl RecordStream {
    /// Serve `host`'s call log (`$WIRES_HOME/call-log.jsonl`).
    pub(crate) fn new(host: Arc<ServicesHost>) -> Self {
        let log = host.keystore.path(call_log::LOG_FILE);
        Self { host, log }
    }
}

impl iroh::protocol::ProtocolHandler for RecordStream {
    async fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        let caller = transport::to_node_id(&conn.remote_id());
        let result = async {
            let (send, recv) = conn.accept_bi().await.context("accepting a stream")?;
            let closed = conn.clone();
            serve(send, recv, caller, &self.host, &self.log, async move {
                closed.closed().await;
            })
            .await
        }
        .await;
        let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
        result.map_err(|e| {
            tracing::warn!(reader = %caller.hex(), "record stream failed: {e:#}");
            iroh::protocol::AcceptError::from_boxed(e.into())
        })
    }
}

/// Serve one reader over a bi-stream: read its `Open`, authorize it, send the
/// backlog after `since`, then (with `follow`) new entries until `gone`
/// resolves or a write fails.
pub(crate) async fn serve<S, R>(
    mut send: S,
    mut recv: R,
    caller: NodeId,
    host: &ServicesHost,
    log: &Path,
    gone: impl std::future::Future<Output = ()>,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let open = tokio::time::timeout(OPEN_TIMEOUT, read_frame(&mut recv))
        .await
        .map_err(|_| anyhow!("no open within {OPEN_TIMEOUT:?}"))??;
    let Some(RecordFrame::Open {
        hello,
        services,
        since,
        mine,
        follow,
    }) = open
    else {
        let reason = "expected open".to_string();
        let _ = write_frame(&mut send, &RecordFrame::Denied { reason }).await;
        bail!("a reader spoke out of turn");
    };
    let view = match authorize(host, caller, &hello, &services, mine, crate::now_unix()).await {
        Ok(view) => view,
        Err(reason) => {
            let reason = transport::truncate_reason(format!("record stream refused: {reason}"));
            tracing::info!(reader = %caller.hex(), "{reason}");
            let _ = write_frame(&mut send, &RecordFrame::Denied { reason }).await;
            let _ = send.shutdown().await;
            return Ok(());
        }
    };
    tracing::info!(reader = %caller.hex(), scopes = ?view.scopes, since = ?since, "record stream opened");
    write_frame(
        &mut send,
        &RecordFrame::Granted {
            scopes: view.scopes.clone(),
        },
    )
    .await?;
    let mut sent = since;
    let mut seen = file_mark(log);
    sent = send_new(&mut send, &view, log, sent).await?;
    write_frame(&mut send, &RecordFrame::CaughtUp).await?;
    if !follow {
        send.shutdown().await.ok();
        return Ok(());
    }
    tokio::pin!(gone);
    loop {
        tokio::select! {
            () = &mut gone => return Ok(()),
            () = tokio::time::sleep(POLL) => {}
        }
        let now = file_mark(log);
        if now != seen {
            seen = now;
            sent = send_new(&mut send, &view, log, sent).await?;
        }
    }
}

/// The log file's size and modification time: what changes when it grows
/// (or is pruned).
fn file_mark(log: &Path) -> Option<(u64, std::time::SystemTime)> {
    let m = std::fs::metadata(log).ok()?;
    Some((m.len(), m.modified().ok()?))
}

/// Send what `view` gets of the entries after `sent`; returns the new mark.
async fn send_new<S: AsyncWrite + Unpin>(
    send: &mut S,
    view: &View,
    log: &Path,
    sent: Option<LogSeq>,
) -> Result<Option<LogSeq>> {
    let entries = call_log::read(log)?;
    let items = view.items(&entries, sent);
    let mark = items.last().map(StreamItem::last_seq).or(sent);
    for chunk in items.chunks(BATCH) {
        write_frame(
            send,
            &RecordFrame::Batch {
                items: chunk.to_vec(),
            },
        )
        .await?;
    }
    Ok(mark)
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{Argv, NodeIdentity, OutputDigest, ToolName};

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    fn svc(s: &str) -> ServiceName {
        ServiceName::new(s).unwrap()
    }

    /// A log: alice starts+finishes orders-db, bob is denied orders-db, bob
    /// runs status, a push to alice.
    fn log() -> Vec<LogEntry> {
        let host = NodeIdentity::from_seed([9; 32]);
        let call = |b: u8| CallId::from_hex(&format!("{b:02x}").repeat(16)).unwrap();
        let started = |c: u8, caller: NodeId, tool: &str| AuditRecord::Started {
            call: call(c),
            caller,
            principal: None,
            tool: ToolName::new(tool).unwrap(),
            argv: Argv::new(vec![]).unwrap(),
            roster_version: None,
            role: None,
            at_ms: 0,
        };
        let finished = |c: u8| AuditRecord::Finished {
            call: call(c),
            exit: 0,
            duration_ms: 1,
            stdout_bytes: 0,
            stderr_bytes: 0,
            stdout_digest: OutputDigest::empty(),
            stdin_bytes: 0,
            stdin_digest: OutputDigest::empty(),
            stdin_head: None,
        };
        let records = vec![
            started(1, node(2), "orders-db"),
            finished(1),
            AuditRecord::Denied {
                caller: node(3),
                tool: Some(ToolName::new("orders-db").unwrap()),
                reason: "no".into(),
                at_ms: 0,
            },
            started(2, node(3), "status"),
            finished(2),
        ];
        let mut out: Vec<LogEntry> = Vec::new();
        for r in records {
            let tip = out.last().map(|e| e.point().unwrap());
            out.push(LogEntry::next(&host, tip, 0, r).unwrap());
        }
        out
    }

    fn shown(items: &[StreamItem]) -> Vec<u64> {
        items
            .iter()
            .filter_map(|i| match i {
                StreamItem::Entry { entry, .. } => Some(entry.seq.0),
                StreamItem::Hidden { .. } => None,
            })
            .collect()
    }

    fn view(reader: u8, scopes: &[(&str, Scope)]) -> View {
        View {
            reader: node(reader),
            scopes: scopes.iter().map(|(s, sc)| (svc(s), *sc)).collect(),
        }
    }

    #[test]
    fn a_reader_sees_all_of_its_service_and_nothing_else() {
        let items = view(4, &[("orders-db", Scope::All)]).items(&log(), None);
        assert_eq!(shown(&items), vec![0, 1, 2]);
        let l = log();
        assert_eq!(
            items[3],
            StreamItem::Hidden {
                from: LogSeq(3),
                links: l[3..]
                    .iter()
                    .map(|e| Link {
                        prev: e.prev,
                        hash: e.hash().unwrap(),
                    })
                    .collect(),
            }
        );
        assert_eq!(items[3].last_seq(), LogSeq(4));
    }

    #[test]
    fn mine_is_the_readers_own_calls_including_finished() {
        let bob = view(3, &[("orders-db", Scope::Mine), ("status", Scope::Mine)]);
        assert_eq!(shown(&bob.items(&log(), None)), vec![2, 3, 4]);
        let alice = view(2, &[("orders-db", Scope::Mine)]);
        assert_eq!(shown(&alice.items(&log(), None)), vec![0, 1]);
        // `since` skips, but a Finished still finds its earlier Started.
        assert_eq!(shown(&alice.items(&log(), Some(LogSeq(0)))), vec![1]);
    }

    #[test]
    fn a_stranger_view_gets_only_hidden_runs() {
        let items = view(7, &[("orders-db", Scope::Mine)]).items(&log(), None);
        assert_eq!(items.len(), 1);
        assert!(matches!(
            items[0],
            StreamItem::Hidden { from: LogSeq(0), ref links } if links.len() == 5
        ));
    }

    #[tokio::test]
    async fn frames_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        let f = RecordFrame::Batch {
            items: vec![StreamItem::Entry {
                service: Some(svc("orders-db")),
                entry: log()[0].clone(),
            }],
        };
        write_frame(&mut a, &f).await.unwrap();
        write_frame(&mut a, &RecordFrame::CaughtUp).await.unwrap();
        drop(a);
        assert_eq!(read_frame(&mut b).await.unwrap(), Some(f));
        assert_eq!(
            read_frame(&mut b).await.unwrap(),
            Some(RecordFrame::CaughtUp)
        );
        assert_eq!(read_frame(&mut b).await.unwrap(), None);
    }
}

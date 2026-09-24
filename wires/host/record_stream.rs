//! The record stream (card 26b): a host serves its own signed call log
//! ([`call_log`]) to authorized readers, by key, on
//! [`ALPN`]. Nothing is broadcast: a record's content leaves the host only
//! when a reader asks for it and may see it (any other member asking gets
//! its hash link).
//!
//! # Protocol
//!
//! One bi-stream of length-prefixed JSON [`RecordFrame`]s:
//!
//! 1. reader → [`RecordFrame::Open`]: its [`Hello`] (membership, state
//!    version, ID token: the same credentials a call presents), the services
//!    it wants, `since` (its resume point for this view on this host),
//!    `mine`, `follow`;
//! 2. host → [`RecordFrame::Denied`] (a non-member gets only
//!    [`NOT_ADMITTED`]; nothing else is sent), or [`RecordFrame::Granted`]:
//!    per requested service assigned to this host, [`Scope::All`] (the
//!    reader's verified principal is in one of the service's `readers` roles,
//!    and it didn't ask for `mine`) or [`Scope::Mine`]; plus the log's
//!    current tip and first held seq, so the reader can tell a rollback from
//!    retention;
//! 3. host → [`RecordFrame::Batch`]es of [`StreamItem`]s after `since`, then
//!    [`RecordFrame::CaughtUp`]; with `follow`, further batches as the log
//!    grows, until the reader hangs up.
//!
//! A following stream is **re-authorized** whenever the host's signed state
//! changes and when the reader's ID token, the state or the membership
//! expires: the same checks as at open. Access gone → [`RecordFrame::Denied`]
//! and the stream ends; access changed (e.g. dropped from `readers`) → a new
//! [`RecordFrame::Granted`], and the entries after it are decided by the new
//! view. A reader whose ID token expires mid-stream is closed (a stream that
//! silently turned to hidden links would look like a quiet log).
//!
//! # What a reader sees
//!
//! Every entry of the log is sent either **in full** (signed, exactly as
//! stored) or in a [`StreamItem::Hidden`] run: only each entry's [`Link`]
//! (its `prev` and its hash as stored). No content, caller, service or time;
//! but a non-reader still learns how many entries the log holds and, under
//! `follow`, when each was written. The links let the reader keep checking
//! the chain across entries it may not see, so a flipped byte in *any*
//! stored entry (seen or not) breaks its chain, and so does a gap or a fork.
//!
//! An entry is shown in full when:
//! - its service was requested and granted [`Scope::All`]; or
//! - its service was requested (either scope) and its subject is the
//!   reader's **person**: the same verified principal (issuer and subject)
//!   the host verified for the reader now. Not the node: two nodes of one
//!   person see each other's entries, and one node never sees another
//!   person's. A reader with no verified principal sees nothing in full.
//!
//! What a record is about ([`about`]):
//! - `Started`: its service; its `principal`.
//! - `Finished`: its `Started`'s service and subject. When that `Started`
//!   was pruned, neither is known, and the entry is only a hidden link.
//! - `Denied`: its service, if it named one; its `principal`. With no
//!   service, it is shown only to its subject.
//! - `Push`: the service of the call that sent it (`call` → that call's
//!   `Started`); its subject is the principal it was admitted for (none
//!   recorded: shown to nobody but that service's readers). An operator
//!   push (no `call`), or one whose call's `Started` was pruned, has no
//!   service and is shown only to its recipient.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use library::{
    AuditRecord, CLOCK_SKEW_SECS, CallId, ChainPoint, EntryHash, Hello, LogEntry, LogSeq, NodeId,
    Principal, ServiceName, StateVersion, role_admits,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::call_log;
use super::gate::{HOST_MISCONFIGURED, NOT_ADMITTED, ServicesHost};
use super::transport;

/// The record-stream ALPN.
pub(crate) const ALPN: &[u8] = b"wires/records/1";

/// The refusal a following reader gets when its ID token expires.
pub(crate) const TOKEN_EXPIRED: &str =
    "the ID token this stream was opened with expired; run `wires login` and watch again";

/// The largest frame either side accepts.
const MAX_FRAME: usize = 16 * 1024 * 1024;

/// The largest [`RecordFrame::Open`] the host reads, before it knows who is
/// asking: a [`Hello`] (a membership and an ID token, a few KiB) plus the
/// names of the services wanted here (at most 64 bytes each).
pub(crate) const MAX_OPEN_FRAME: usize = 64 * 1024;

/// How many readers may be undecided at once (connected, `Open` not yet
/// read and authorized). Any key can connect; one more is closed
/// unanswered. A decided stream no longer counts.
pub(crate) const MAX_PREAUTH_READERS: usize = 16;

/// Refusals of readers not known to be members (see [`transport::Throttle`]).
static STRANGERS: transport::Throttle = transport::Throttle::new();

/// How long the host waits for the reader's [`RecordFrame::Open`].
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Most items per [`RecordFrame::Batch`].
const BATCH: usize = 256;

/// How often a following stream looks for new entries (and a new state).
const POLL: Duration = Duration::from_millis(200);

/// What a reader may see of one service's records on a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Scope {
    /// Every record: the reader is in one of the service's `readers` roles.
    All,
    /// Only the reader's own (its person's) records.
    Mine,
}

/// A verified person: an IdP principal's issuer and subject. What "mine"
/// compares, so the boundary is the person, not the node.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Person {
    /// The token's `iss`.
    issuer: String,
    /// The token's `sub`.
    subject: String,
}

impl Person {
    /// The person `p` names.
    pub(crate) fn of(p: &Principal) -> Self {
        Self {
            issuer: p.issuer.clone(),
            subject: p.subject.clone(),
        }
    }
}

/// One log entry as streamed: shown, or hidden in a run.
///
/// A shown entry carries nothing but the signed entry: the reader derives
/// what it is about (its service label) from signed records itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)] // transient, one per entry on the wire
pub(crate) enum StreamItem {
    /// An entry the reader may see, exactly as stored.
    Entry {
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
            StreamItem::Entry { entry } => entry.seq,
            // A run is never empty: it starts with the entry that opened it.
            StreamItem::Hidden { from, links } => LogSeq(from.0 + links.len() as u64 - 1),
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
        /// Only entries after this seq (its resume point for this view).
        #[serde(skip_serializing_if = "Option::is_none")]
        since: Option<LogSeq>,
        /// Only its own records, even where it may read all.
        mine: bool,
        /// Keep the stream open for new entries after the backlog.
        follow: bool,
    },
    /// Host → reader: what it may see, per requested service hosted here,
    /// and where the log stands. Sent again mid-stream when a
    /// re-authorization changes the view.
    Granted {
        /// Service → scope (services not assigned here are left out).
        scopes: BTreeMap<ServiceName, Scope>,
        /// The log's newest entry (`None`: the log is empty). Below the
        /// reader's anchor means the log was rolled back.
        #[serde(skip_serializing_if = "Option::is_none")]
        tip: Option<ChainPoint>,
        /// The oldest entry the host still holds (`None`: empty). Above the
        /// reader's anchor means entries were pruned (retention), not
        /// tampered with.
        #[serde(skip_serializing_if = "Option::is_none")]
        first: Option<LogSeq>,
    },
    /// Host → reader: the next items, in log order.
    Batch {
        /// The items.
        items: Vec<StreamItem>,
    },
    /// Host → reader: the backlog has been sent.
    CaughtUp,
    /// Host → reader: refused (at open, or when a re-authorization fails),
    /// and why.
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

/// Read one frame of at most [`MAX_FRAME`]; `None` at a clean end of
/// stream. See [`read_frame_within`].
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<RecordFrame>> {
    read_frame_within(r, MAX_FRAME).await
}

/// [`read_frame`], refusing a frame whose length prefix is over `max`. The
/// prefix is the peer's claim, so nothing is sized from it: the buffer grows
/// only as bytes arrive.
pub(crate) async fn read_frame_within<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> Result<Option<RecordFrame>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("reading a record frame"),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        bail!("record frame too large: {len} bytes (max {max})");
    }
    let mut body = Vec::with_capacity(len.min(MAX_OPEN_FRAME));
    (&mut *r)
        .take(len as u64)
        .read_to_end(&mut body)
        .await
        .context("reading a record frame body")?;
    if body.len() != len {
        bail!("truncated record frame");
    }
    Ok(Some(
        serde_json::from_slice(&body).context("decoding a record frame")?,
    ))
}

/// Who a reader is and what it was granted: decides each entry, and when it
/// must be decided again.
#[derive(Clone, Debug)]
pub(crate) struct View {
    /// The reader's verified person (`None`: no verified principal, so
    /// nothing is its own).
    pub(crate) reader: Option<Person>,
    /// What it was granted, per service.
    pub(crate) scopes: BTreeMap<ServiceName, Scope>,
    /// The signed-state version it was decided under: a newer one means
    /// deciding again.
    pub(crate) version: StateVersion,
    /// Unix seconds from which it must be decided again: the earliest expiry
    /// of the reader's ID token, the state and the membership (see
    /// [`deadline`]).
    pub(crate) until: i64,
}

/// When a view decided at the given expiries must be decided again: the
/// first second at which the state (`state_not_after`, inclusive), the
/// membership (`membership_not_after`, inclusive) or the reader's verified
/// ID token (its `exp` plus the host's [`CLOCK_SKEW_SECS`]) no longer holds.
pub(crate) fn deadline(
    state_not_after: i64,
    membership_not_after: i64,
    principal: Option<&Principal>,
) -> i64 {
    let token = principal.map_or(i64::MAX, |p| {
        p.not_after
            .saturating_add(CLOCK_SKEW_SECS)
            .saturating_add(1)
    });
    state_not_after
        .saturating_add(1)
        .min(membership_not_after.saturating_add(1))
        .min(token)
}

/// What a record is about: the service it belongs to and whose it is.
/// `calls` holds, per call already seen, its `Started`'s service and
/// subject (so a `Finished` or a service's `Push` inherits them). See the
/// module docs.
pub(crate) fn about(
    record: &AuditRecord,
    calls: &HashMap<CallId, (ServiceName, Option<Person>)>,
) -> (Option<ServiceName>, Option<Person>) {
    match record {
        AuditRecord::Started {
            service, principal, ..
        } => (Some(service.clone()), principal.as_ref().map(Person::of)),
        AuditRecord::Finished { call, .. } => match calls.get(call) {
            Some((s, who)) => (Some(s.clone()), who.clone()),
            // Its start was pruned: nobody can tell whose it was.
            None => (None, None),
        },
        AuditRecord::Denied {
            service, principal, ..
        } => (service.clone(), principal.as_ref().map(Person::of)),
        AuditRecord::Push {
            call, principal, ..
        } => (
            call.and_then(|c| calls.get(&c)).map(|(s, _)| s.clone()),
            principal.as_ref().map(Person::of),
        ),
    }
}

impl View {
    /// Whether the reader may see a record about `service` whose subject is
    /// `subject`. See the module docs.
    fn shows(&self, service: Option<&ServiceName>, subject: Option<&Person>) -> bool {
        let mine = self.reader.is_some() && subject == self.reader.as_ref();
        match service {
            Some(s) => match self.scopes.get(s) {
                Some(Scope::All) => true,
                Some(Scope::Mine) => mine,
                None => false,
            },
            None => mine,
        }
    }

    /// Whether this view must be decided again: the host's state is now
    /// `version` (`None`: unreadable), and it is `now`.
    pub(crate) fn due(&self, version: Option<StateVersion>, now: i64) -> bool {
        version != Some(self.version) || now >= self.until
    }

    /// Whether `other` grants what this view grants (same person, same
    /// scopes): no new [`RecordFrame::Granted`] needed.
    fn same_grant(&self, other: &View) -> bool {
        self.reader == other.reader && self.scopes == other.scopes
    }

    /// Turn a whole log (`entries`, oldest first) into what this reader is
    /// sent of the entries after `since`: shown entries in full, the rest in
    /// [`StreamItem::Hidden`] runs. The whole log is walked so a `Finished`
    /// (or a service's `Push`) finds its `Started` even when that came
    /// before `since`. Fails when a hidden entry can't be hashed: skipping
    /// it would leave a gap the reader can't explain.
    pub(crate) fn items(
        &self,
        entries: &[LogEntry],
        since: Option<LogSeq>,
    ) -> Result<Vec<StreamItem>> {
        let mut calls: HashMap<CallId, (ServiceName, Option<Person>)> = HashMap::new();
        let mut out: Vec<StreamItem> = Vec::new();
        for entry in entries {
            let (service, subject) = about(&entry.record, &calls);
            if let AuditRecord::Started { call, .. } = &entry.record
                && let Some(s) = &service
            {
                calls.insert(*call, (s.clone(), subject.clone()));
            }
            if since.is_some_and(|s| entry.seq <= s) {
                continue;
            }
            if self.shows(service.as_ref(), subject.as_ref()) {
                out.push(StreamItem::Entry {
                    entry: entry.clone(),
                });
                continue;
            }
            // Hash what is stored: a tampered entry breaks the reader's chain
            // even when the reader can't see it.
            let hash = entry
                .hash()
                .with_context(|| format!("hashing call-log entry {}", entry.seq.0))?;
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
        Ok(out)
    }
}

/// Decide what `caller` (with `hello`) may read of `wanted` on `host` at
/// `now`: `Err` is the refusal sent to it. A non-member gets only
/// [`NOT_ADMITTED`]. Membership is checked before anything else.
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
        HOST_MISCONFIGURED.to_string()
    })?;
    let s = &state.state;
    if let Err(detail) = host.check_member(&state, &hello.membership, caller, now) {
        STRANGERS.refused("record stream", caller, &detail);
        return Err(NOT_ADMITTED.to_string());
    }
    if let Err(e) = state.check_fresh(now) {
        tracing::warn!(
            version = s.version.0,
            "record stream: signed state not fresh: {e}"
        );
        return Err("this host's signed state is not fresh; try again later".to_string());
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
        reader: principal.as_ref().map(Person::of),
        scopes,
        version: s.version,
        until: deadline(s.not_after, hello.membership.not_after, principal.as_ref()),
    })
}

/// The record-stream ALPN on a host. At most [`MAX_PREAUTH_READERS`]
/// readers wait for a decision at once.
#[derive(Clone, Debug)]
pub(crate) struct RecordStream {
    /// The host (its signed state, identity verifier, trust root).
    host: Arc<ServicesHost>,
    /// The call log file.
    log: PathBuf,
    /// Permits for readers not yet decided.
    preauth: Arc<tokio::sync::Semaphore>,
}

impl RecordStream {
    /// Serve `host`'s call log (`$WIRES_HOME/call-log.jsonl`).
    pub(crate) fn new(host: Arc<ServicesHost>) -> Self {
        let log = host.keystore.path(call_log::LOG_FILE);
        Self {
            host,
            log,
            preauth: Arc::new(tokio::sync::Semaphore::new(MAX_PREAUTH_READERS)),
        }
    }
}

impl iroh::protocol::ProtocolHandler for RecordStream {
    async fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        let caller = transport::to_node_id(&conn.remote_id());
        let Ok(permit) = Arc::clone(&self.preauth).try_acquire_owned() else {
            STRANGERS.refused(
                "record stream",
                caller,
                &format!("{MAX_PREAUTH_READERS} readers already await a decision"),
            );
            conn.close(1u32.into(), b"busy");
            return Ok(());
        };
        let result = async {
            let (send, recv) = conn.accept_bi().await.context("accepting a stream")?;
            let closed = conn.clone();
            serve(
                send,
                recv,
                caller,
                &self.host,
                &self.log,
                permit,
                async move {
                    closed.closed().await;
                },
            )
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

/// Send `reason` as a [`RecordFrame::Denied`] and end the stream. A
/// member's refusal is traced here; a stranger's ([`NOT_ADMITTED`]) was
/// already traced, throttled, by [`authorize`].
async fn deny<S: AsyncWrite + Unpin>(send: &mut S, caller: NodeId, reason: &str) {
    let reason = transport::truncate_reason(reason.to_string());
    if reason != NOT_ADMITTED {
        tracing::info!(reader = %caller.hex(), "record stream refused: {reason}");
    }
    let _ = write_frame(send, &RecordFrame::Denied { reason }).await;
    let _ = send.shutdown().await;
}

/// The [`RecordFrame::Granted`] for `view` over the log `entries`.
fn granted(view: &View, entries: &[LogEntry]) -> RecordFrame {
    RecordFrame::Granted {
        scopes: view.scopes.clone(),
        tip: entries.last().and_then(|e| e.point().ok()),
        first: entries.first().map(|e| e.seq),
    }
}

/// Serve one reader over a bi-stream: read its `Open` (at most
/// [`MAX_OPEN_FRAME`]), authorize it, send the backlog after `since`, then
/// (with `follow`) new entries until `gone` resolves or a write fails,
/// re-authorizing it as the module docs say. `preauth` (the reader's place
/// among the undecided) is released once it is decided. A reader that
/// fails before that is traced as a stranger, throttled.
pub(crate) async fn serve<S, R>(
    mut send: S,
    mut recv: R,
    caller: NodeId,
    host: &ServicesHost,
    log: &Path,
    preauth: tokio::sync::OwnedSemaphorePermit,
    gone: impl std::future::Future<Output = ()>,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let open = match tokio::time::timeout(
        OPEN_TIMEOUT,
        read_frame_within(&mut recv, MAX_OPEN_FRAME),
    )
    .await
    {
        Ok(Ok(open)) => open,
        Ok(Err(e)) => {
            STRANGERS.refused("record stream", caller, &format!("{e:#}"));
            return Ok(());
        }
        Err(_) => {
            STRANGERS.refused(
                "record stream",
                caller,
                &format!("no open within {OPEN_TIMEOUT:?}"),
            );
            return Ok(());
        }
    };
    let Some(RecordFrame::Open {
        hello,
        services,
        since,
        mine,
        follow,
    }) = open
    else {
        STRANGERS.refused("record stream", caller, "its first frame wasn't an open");
        let reason = "expected open".to_string();
        let _ = write_frame(&mut send, &RecordFrame::Denied { reason }).await;
        return Ok(());
    };
    let decide = |now| authorize(host, caller, &hello, &services, mine, now);
    let decided = decide(crate::clock::now_unix()).await;
    drop(preauth);
    let mut view = match decided {
        Ok(view) => view,
        Err(reason) => {
            deny(&mut send, caller, &reason).await;
            return Ok(());
        }
    };
    tracing::info!(reader = %caller.hex(), scopes = ?view.scopes, since = ?since, "record stream opened");
    let mut seen = file_mark(log);
    let entries = call_log::read(log)?;
    write_frame(&mut send, &granted(&view, &entries)).await?;
    let mut sent = send_items(&mut send, &view, &entries, since).await?;
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
        // Decide again before sending anything new: a reader removed (or
        // dropped from `readers`) gets nothing logged after that.
        let now = crate::clock::now_unix();
        let version = host.state().ok().map(|s| s.state.version);
        let regrant = if view.due(version, now) {
            let next = match decide(now).await {
                Ok(next) => next,
                Err(reason) => {
                    deny(&mut send, caller, &reason).await;
                    return Ok(());
                }
            };
            if view.reader.is_some() && next.reader.is_none() {
                deny(&mut send, caller, TOKEN_EXPIRED).await;
                return Ok(());
            }
            let changed = !view.same_grant(&next);
            if changed {
                tracing::info!(reader = %caller.hex(), scopes = ?next.scopes, "record stream re-granted");
            }
            view = next;
            changed
        } else {
            false
        };
        let mark = file_mark(log);
        if mark != seen || regrant {
            seen = mark;
            let entries = call_log::read(log)?;
            if regrant {
                write_frame(&mut send, &granted(&view, &entries)).await?;
            }
            sent = send_items(&mut send, &view, &entries, sent).await?;
        }
    }
}

/// The log file's size and modification time: what changes when it grows
/// (or is pruned).
fn file_mark(log: &Path) -> Option<(u64, std::time::SystemTime)> {
    let m = std::fs::metadata(log).ok()?;
    Some((m.len(), m.modified().ok()?))
}

/// Send what `view` gets of `entries` after `sent`; returns the new mark.
async fn send_items<S: AsyncWrite + Unpin>(
    send: &mut S,
    view: &View,
    entries: &[LogEntry],
    sent: Option<LogSeq>,
) -> Result<Option<LogSeq>> {
    let items = view.items(entries, sent)?;
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
    use library::{Argv, NodeIdentity, OutputDigest, PushId, PushOutcome, ServiceName, Subject};

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    fn svc(s: &str) -> ServiceName {
        ServiceName::new(s).unwrap()
    }

    /// A verified principal at `issuer` with subject `sub`.
    fn who(issuer: &str, sub: &str) -> Principal {
        Principal {
            issuer: issuer.into(),
            subject: sub.into(),
            email: Some(format!("{sub}@example.com")),
            org: None,
            groups: vec![],
            not_after: 1_000,
            claims: Default::default(),
        }
    }

    fn alice() -> Principal {
        who("https://idp.example", "alice")
    }

    fn bob() -> Principal {
        who("https://idp.example", "bob")
    }

    fn call(b: u8) -> CallId {
        CallId::from_hex(&format!("{b:02x}").repeat(16)).unwrap()
    }

    fn started(c: u8, caller: NodeId, principal: Option<Principal>, service: &str) -> AuditRecord {
        AuditRecord::Started {
            call: call(c),
            caller,
            principal,
            service: ServiceName::new(service).unwrap(),
            argv: Argv::new(vec![]).unwrap(),
            state_version: library::StateVersion(1),
            role: library::RoleName::new("analyst").unwrap(),
            at_ms: 0,
        }
    }

    fn finished(c: u8) -> AuditRecord {
        AuditRecord::Finished {
            call: call(c),
            exit: 0,
            duration_ms: 1,
            stdout_bytes: 0,
            stderr_bytes: 0,
            stdout_digest: OutputDigest::empty(),
            stdin_bytes: 0,
            stdin_digest: OutputDigest::empty(),
            stdin_head: None,
        }
    }

    fn denied(caller: NodeId, principal: Option<Principal>, service: Option<&str>) -> AuditRecord {
        AuditRecord::Denied {
            caller,
            principal,
            service: service.map(|s| ServiceName::new(s).unwrap()),
            reason: "no".into(),
            at_ms: 0,
        }
    }

    fn push(to: NodeId, principal: Option<Principal>, via: Option<u8>) -> AuditRecord {
        AuditRecord::Push {
            id: PushId::from_hex(&"ab".repeat(16)).unwrap(),
            to,
            principal,
            role: None,
            subject: Subject::new("build-41").unwrap(),
            outcome: PushOutcome::Queued,
            reason: None,
            body: None,
            call: via.map(call),
            at_ms: 0,
        }
    }

    /// Sign `records` into a log, oldest first.
    fn signed(records: Vec<AuditRecord>) -> Vec<LogEntry> {
        let host = NodeIdentity::from_seed([9; 32]);
        let mut out: Vec<LogEntry> = Vec::new();
        for r in records {
            let tip = out.last().map(|e| e.point().unwrap());
            out.push(LogEntry::next(&host, tip, 0, r).unwrap());
        }
        out
    }

    /// A log: alice (node 2) starts+finishes orders-db, bob (node 3) is
    /// denied orders-db, bob runs status.
    fn log() -> Vec<LogEntry> {
        signed(vec![
            started(1, node(2), Some(alice()), "orders-db"),
            finished(1),
            denied(node(3), Some(bob()), Some("orders-db")),
            started(2, node(3), Some(bob()), "status"),
            finished(2),
        ])
    }

    fn shown(items: &[StreamItem]) -> Vec<u64> {
        items
            .iter()
            .filter_map(|i| match i {
                StreamItem::Entry { entry } => Some(entry.seq.0),
                StreamItem::Hidden { .. } => None,
            })
            .collect()
    }

    fn view(reader: Option<Principal>, scopes: &[(&str, Scope)]) -> View {
        View {
            reader: reader.as_ref().map(Person::of),
            scopes: scopes.iter().map(|(s, sc)| (svc(s), *sc)).collect(),
            version: StateVersion(1),
            until: i64::MAX,
        }
    }

    #[test]
    fn a_reader_sees_all_of_its_service_and_nothing_else() {
        let items = view(None, &[("orders-db", Scope::All)])
            .items(&log(), None)
            .unwrap();
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
    fn mine_is_the_readers_person_including_finished() {
        let bob_view = view(
            Some(bob()),
            &[("orders-db", Scope::Mine), ("status", Scope::Mine)],
        );
        assert_eq!(shown(&bob_view.items(&log(), None).unwrap()), vec![2, 3, 4]);
        let alice_view = view(Some(alice()), &[("orders-db", Scope::Mine)]);
        assert_eq!(shown(&alice_view.items(&log(), None).unwrap()), vec![0, 1]);
        // `since` skips, but a Finished still finds its earlier Started.
        assert_eq!(
            shown(&alice_view.items(&log(), Some(LogSeq(0))).unwrap()),
            vec![1]
        );
    }

    /// The boundary is the person: alice's second node sees her first
    /// node's calls; a node of another person never does, even one that
    /// made calls with alice's node id (the node is not compared).
    #[test]
    fn mine_matches_issuer_and_subject_not_the_node() {
        let records = signed(vec![
            started(1, node(2), Some(alice()), "orders-db"),
            finished(1),
            // The same node id, but another person holds it now.
            started(2, node(2), Some(bob()), "orders-db"),
        ]);
        let mine = [("orders-db", Scope::Mine)];
        assert_eq!(
            shown(&view(Some(alice()), &mine).items(&records, None).unwrap()),
            [0, 1]
        );
        assert_eq!(
            shown(&view(Some(bob()), &mine).items(&records, None).unwrap()),
            [2]
        );
        // Same subject at another issuer: another person.
        let impostor = who("https://other.example", "alice");
        assert!(shown(&view(Some(impostor), &mine).items(&records, None).unwrap()).is_empty());
    }

    /// A reader with no verified principal sees nothing in full, not even
    /// entries its own node caused (with or without an identity).
    #[test]
    fn a_reader_with_no_principal_sees_nothing_in_full() {
        let records = signed(vec![
            denied(node(2), None, None),
            denied(node(2), None, Some("orders-db")),
            started(1, node(2), Some(alice()), "orders-db"),
        ]);
        let items = view(None, &[("orders-db", Scope::Mine)])
            .items(&records, None)
            .unwrap();
        assert!(shown(&items).is_empty(), "{items:?}");
    }

    /// A service's push is scoped by the service whose call sent it; an
    /// operator push, only to its recipient; neither to readers of another
    /// service.
    #[test]
    fn a_push_is_scoped_by_its_calls_service_and_its_recipient() {
        let records = signed(vec![
            started(1, node(2), Some(alice()), "orders-db"),
            push(node(2), Some(alice()), Some(1)),
            finished(1),
            // The operator's push to bob.
            push(node(3), Some(bob()), None),
            // A push naming a call whose start this log no longer holds.
            push(node(3), Some(bob()), Some(7)),
            // A push admitted for no verified principal.
            push(node(3), None, None),
        ]);
        let orders_reader = view(None, &[("orders-db", Scope::All)]);
        assert_eq!(
            shown(&orders_reader.items(&records, None).unwrap()),
            [0, 1, 2]
        );
        let status_reader = view(None, &[("status", Scope::All), ("orders-db", Scope::Mine)]);
        assert!(shown(&status_reader.items(&records, None).unwrap()).is_empty());
        let alice_view = view(Some(alice()), &[("orders-db", Scope::Mine)]);
        assert_eq!(shown(&alice_view.items(&records, None).unwrap()), [0, 1, 2]);
        // bob, reading nothing: only the pushes admitted for him.
        let bob_view = view(Some(bob()), &[("orders-db", Scope::Mine)]);
        assert_eq!(shown(&bob_view.items(&records, None).unwrap()), [3, 4]);
        // An all-reader of every service here still doesn't see bob's.
        let everything = view(
            Some(alice()),
            &[("orders-db", Scope::All), ("status", Scope::All)],
        );
        assert_eq!(shown(&everything.items(&records, None).unwrap()), [0, 1, 2]);
    }

    /// A Finished whose Started was pruned is a hidden link to everyone; a
    /// Denied with no tool is shown only to its subject.
    #[test]
    fn serviceless_records_are_shown_to_their_subject_only() {
        let records = signed(vec![finished(1), denied(node(3), Some(bob()), None)]);
        let all = view(Some(alice()), &[("orders-db", Scope::All)]);
        assert!(shown(&all.items(&records, None).unwrap()).is_empty());
        let bob_view = view(Some(bob()), &[("orders-db", Scope::Mine)]);
        assert_eq!(shown(&bob_view.items(&records, None).unwrap()), [1]);
    }

    #[test]
    fn a_stranger_view_gets_only_hidden_runs() {
        let stranger = who("https://idp.example", "carol");
        let items = view(Some(stranger), &[("orders-db", Scope::Mine)])
            .items(&log(), None)
            .unwrap();
        assert_eq!(items.len(), 1);
        assert!(matches!(
            items[0],
            StreamItem::Hidden { from: LogSeq(0), ref links } if links.len() == 5
        ));
    }

    /// A view is decided again on a new state, an unreadable one, and at the
    /// earliest of the token's, the state's and the membership's expiry.
    #[test]
    fn a_view_is_due_on_a_new_state_and_at_its_deadline() {
        let token = alice(); // exp 1_000
        let until = deadline(5_000, 9_000, Some(&token));
        assert_eq!(until, 1_000 + CLOCK_SKEW_SECS + 1);
        assert_eq!(deadline(5_000, 9_000, None), 5_001);
        assert_eq!(deadline(5_000, 4_000, None), 4_001);
        let v = View {
            until,
            ..view(Some(token), &[])
        };
        assert!(!v.due(Some(StateVersion(1)), until - 1));
        assert!(v.due(Some(StateVersion(1)), until));
        assert!(v.due(Some(StateVersion(2)), 0));
        assert!(v.due(None, 0));
    }

    #[tokio::test]
    async fn frames_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        let f = RecordFrame::Batch {
            items: vec![StreamItem::Entry {
                entry: log()[0].clone(),
            }],
        };
        let g = RecordFrame::Granted {
            scopes: [(svc("orders-db"), Scope::All)].into(),
            tip: Some(log()[4].point().unwrap()),
            first: Some(LogSeq(0)),
        };
        write_frame(&mut a, &g).await.unwrap();
        write_frame(&mut a, &f).await.unwrap();
        write_frame(&mut a, &RecordFrame::CaughtUp).await.unwrap();
        drop(a);
        assert_eq!(read_frame(&mut b).await.unwrap(), Some(g));
        assert_eq!(read_frame(&mut b).await.unwrap(), Some(f));
        assert_eq!(
            read_frame(&mut b).await.unwrap(),
            Some(RecordFrame::CaughtUp)
        );
        assert_eq!(read_frame(&mut b).await.unwrap(), None);
    }
}

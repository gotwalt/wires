//! `wires inbox`: messages hosts push to this caller (board card 23).
//!
//! A host reaches a caller by **key**: it needs no address, and the caller
//! exposes nothing it doesn't choose to. Messages land in the local mailbox
//! (`$WIRES_HOME/inbox/`, `0700`) one of two ways:
//!
//! - **fetched** by `wires inbox`: a bounded catch-up from every host of the
//!   services this node may call (from its signed state), after which the
//!   host forgets what was acknowledged. The fetch presents this node's ID
//!   token (`wires login`), which is how a host learns who it is for pushes
//!   addressed to a role;
//! - **pushed** while `wires inbox --wait` runs: it serves the inbox ALPN
//!   ([`INBOX_ALPN`]) and accepts deliveries ([`InboxReceiver`]) from members
//!   the signed state names as hosts, besides long-polling each host.
//!
//! `wires inbox` then prints what is unread — one line per message, or
//! `--json` — and marks it read. `--wait` blocks until a message arrives
//! (exit [`EXIT_TIMEOUT`] on `--timeout`), which a harness with background
//! tasks turns into a wake-up that costs no turns.
//!
//! # Pushed content is untrusted
//!
//! A line always starts with who sent it, as this caller verified it — the
//! host's key, authenticated by the connection it arrived on:
//!
//! ```text
//! 2026-09-23 16:04:05Z  from host 51442ef9 (verified)  build-41  failed: test_orders_total …
//! ```
//!
//! The body is the host's words (escaped onto one line), never instructions
//! from the person running the agent.
//!
//! # The mailbox
//!
//! `new/<id>.json` holds unread messages, `read/<id>.json` the last
//! [`MAX_READ`] read ones (so a re-delivery of one already read is dropped —
//! delivery is at least once, and this is the de-duplication), and `notes/`
//! what `wires inbox` should tell its reader (messages evicted because more
//! than [`MAX_UNREAD`] piled up unread; the oldest go first). Every write is
//! a rename, so a receiver and a concurrent `wires inbox` never see half a
//! message, and marking read is a rename too: two readers never both print
//! one.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use iroh::{Endpoint, EndpointAddr};
use library::{
    INBOX_ALPN, InboxFrame, MAX_BATCH, Membership, NodeId, NodeIdentity, PushId, PushMessage,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::admin::keystore::{self, Keystore};
use crate::admin::ttl::Ttl;
use crate::caller::call::CredArgs;
use crate::caller::lock::{EXIT_LOCKED, Lock};
use crate::clock::now_ms;
use crate::host::transport::{self, Denied};

/// The mailbox directory under `$WIRES_HOME`.
pub(crate) const INBOX_DIR: &str = "inbox";

/// Most unread messages the mailbox keeps; a newer one evicts the oldest,
/// with a note.
pub(crate) const MAX_UNREAD: usize = 256;

/// How many read messages are remembered, for de-duplication.
pub(crate) const MAX_READ: usize = 1024;

/// Exit code of `wires inbox --wait --timeout D` when nothing arrived (as
/// `timeout(1)` uses): distinct from 0 (messages printed), 1 (failure) and
/// 77 (refused).
pub(crate) const EXIT_TIMEOUT: i32 = 124;

/// How long a cold `wires inbox` spends fetching from the hosts.
const FETCH_BUDGET: Duration = Duration::from_secs(3);

/// How long one fetch asks a host to hold the stream open for a message
/// (`--wait`). The host caps it too.
pub(crate) const LONG_POLL: Duration = Duration::from_secs(25);

/// How long to wait for a peer's frame (beyond any long poll).
const FRAME_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a fetch waits for a host to answer the dial.
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Frame I/O (shared with the host's side, `host::push`)
// ---------------------------------------------------------------------------

/// Write one [`InboxFrame`].
pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    frame: &InboxFrame,
) -> Result<()> {
    let bytes = frame.encode().context("encoding an inbox frame")?;
    w.write_all(&bytes)
        .await
        .context("writing an inbox frame")?;
    Ok(())
}

/// Read one [`InboxFrame`] within `within`; `None` at a clean end of stream.
/// The length prefix is checked before the body is allocated.
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    within: Duration,
) -> Result<Option<InboxFrame>> {
    read_frame_within(r, within, library::MAX_INBOX_FRAME).await
}

/// [`read_frame`], refusing a frame whose length prefix is over `max` (use
/// [`MAX_INBOX_HELLO`](library::MAX_INBOX_HELLO) before the peer is known).
/// Nothing is sized from the prefix: the buffer grows as bytes arrive.
pub(crate) async fn read_frame_within<R: AsyncRead + Unpin>(
    r: &mut R,
    within: Duration,
    max: usize,
) -> Result<Option<InboxFrame>> {
    let read = async {
        let mut prefix = [0u8; 4];
        match r.read_exact(&mut prefix).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e).context("reading an inbox frame"),
        }
        let len = InboxFrame::length(&prefix)?.unwrap_or(0);
        if len > max {
            bail!("inbox frame too large: {len} bytes (max {max})");
        }
        let mut buf = Vec::with_capacity(4 + len.min(library::MAX_INBOX_HELLO));
        buf.extend_from_slice(&prefix);
        (&mut *r)
            .take(len as u64)
            .read_to_end(&mut buf)
            .await
            .context("reading an inbox frame body")?;
        match InboxFrame::decode(&buf)? {
            Some((frame, _)) => Ok(Some(frame)),
            None => bail!("truncated inbox frame"),
        }
    };
    tokio::time::timeout(within, read)
        .await
        .map_err(|_| anyhow!("no inbox frame within {within:?}"))?
}

/// Answer with a refusal and close our side (best effort).
pub(crate) async fn deny<W: AsyncWrite + Unpin>(w: &mut W, reason: &str) {
    let reason = transport::truncate_reason(reason.to_string());
    let _ = write_frame(w, &InboxFrame::Denied { reason }).await;
    let _ = w.shutdown().await;
}

// ---------------------------------------------------------------------------
// The mailbox
// ---------------------------------------------------------------------------

/// What [`Mailbox::store`] did with a batch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Stored {
    /// Every id now held (new or already there): what to acknowledge.
    pub(crate) ids: Vec<PushId>,
    /// How many were new.
    pub(crate) fresh: usize,
    /// How many older unread messages were evicted to make room.
    pub(crate) evicted: usize,
}

/// The local mailbox. See the module docs.
#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    /// `$WIRES_HOME/inbox`.
    dir: PathBuf,
}

impl Mailbox {
    /// The mailbox under `home`, created (`0700`) if missing.
    pub(crate) fn open(home: &Path) -> Result<Self> {
        let dir = home.join(INBOX_DIR);
        for sub in ["", "new", "read", "notes"] {
            let d = dir.join(sub);
            std::fs::create_dir_all(&d).with_context(|| format!("creating {}", d.display()))?;
        }
        private(&dir);
        Ok(Self { dir })
    }

    fn new_dir(&self) -> PathBuf {
        self.dir.join("new")
    }

    fn read_dir(&self) -> PathBuf {
        self.dir.join("read")
    }

    fn file(dir: &Path, id: &PushId) -> PathBuf {
        dir.join(format!("{}.json", id.hex()))
    }

    /// Store `messages` (already checked: from the authenticated host, to
    /// this node). One already held, unread or read, is not stored again
    /// but is still acknowledged. Evicts the oldest unread past
    /// [`MAX_UNREAD`], leaving a note.
    pub(crate) fn store(&self, messages: &[PushMessage]) -> Result<Stored> {
        let mut out = Stored::default();
        for m in messages {
            out.ids.push(m.id);
            if self.holds(&m.id) {
                continue;
            }
            let path = Self::file(&self.new_dir(), &m.id);
            write_atomic(&path, &serde_json::to_vec(m)?)?;
            out.fresh += 1;
        }
        if out.fresh > 0 {
            let unread = self.unread_index();
            let evict = evictions(&unread, 0, MAX_UNREAD);
            for id in &evict {
                if std::fs::rename(
                    Self::file(&self.new_dir(), id),
                    Self::file(&self.read_dir(), id),
                )
                .is_ok()
                {
                    out.evicted += 1;
                }
            }
            if out.evicted > 0 {
                let note = format!(
                    "{} unread message(s) evicted: the mailbox keeps at most {MAX_UNREAD} unread \
                     (oldest first)",
                    out.evicted
                );
                let path = self.dir.join("notes").join(format!(
                    "{}-{}.txt",
                    now_ms(),
                    PushId::generate().hex()
                ));
                write_atomic(&path, note.as_bytes())?;
            }
        }
        Ok(out)
    }

    /// Whether `id` is already held (unread or read).
    fn holds(&self, id: &PushId) -> bool {
        Self::file(&self.new_dir(), id).exists() || Self::file(&self.read_dir(), id).exists()
    }

    /// `(at_ms, id)` of every unread message.
    fn unread_index(&self) -> Vec<(i64, PushId)> {
        self.load_dir(&self.new_dir())
            .into_iter()
            .map(|m| (m.at_ms, m.id))
            .collect()
    }

    /// Every message in `dir`, in `(at_ms, id)` order; unreadable files are
    /// skipped.
    fn load_dir(&self, dir: &Path) -> Vec<PushMessage> {
        let mut out: Vec<PushMessage> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .filter_map(|e| std::fs::read(e.path()).ok())
            .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
            .collect();
        out.sort_by_key(|m| (m.at_ms, m.id));
        out
    }

    /// Whether anything is unread.
    pub(crate) fn has_unread(&self) -> bool {
        std::fs::read_dir(self.new_dir())
            .into_iter()
            .flatten()
            .flatten()
            .any(|e| e.path().extension().is_some_and(|x| x == "json"))
    }

    /// Take every unread message, oldest first, marking each read (a rename:
    /// a message another reader took first is skipped). Keeps the newest
    /// [`MAX_READ`] read ones.
    pub(crate) fn take_unread(&self) -> Result<Vec<PushMessage>> {
        let mut taken = Vec::new();
        for m in self.load_dir(&self.new_dir()) {
            let from = Self::file(&self.new_dir(), &m.id);
            if std::fs::rename(&from, Self::file(&self.read_dir(), &m.id)).is_ok() {
                taken.push(m);
            }
        }
        let read = self.load_dir(&self.read_dir());
        if read.len() > MAX_READ {
            for m in &read[..read.len() - MAX_READ] {
                let _ = std::fs::remove_file(Self::file(&self.read_dir(), &m.id));
            }
        }
        Ok(taken)
    }

    /// Take the notes left for the reader (evictions), oldest first.
    pub(crate) fn take_notes(&self) -> Vec<String> {
        let dir = self.dir.join("notes");
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "txt"))
            .collect();
        paths.sort();
        paths
            .into_iter()
            .filter_map(|p| {
                let text = std::fs::read_to_string(&p).ok()?;
                std::fs::remove_file(&p).ok()?;
                Some(text)
            })
            .collect()
    }
}

/// Which unread messages to evict so that `unread` plus `incoming` new ones
/// fit in `cap`: the oldest (by `(at_ms, id)`), as few as possible.
pub(crate) fn evictions(unread: &[(i64, PushId)], incoming: usize, cap: usize) -> Vec<PushId> {
    let over = (unread.len() + incoming).saturating_sub(cap);
    let mut sorted = unread.to_vec();
    sorted.sort();
    sorted
        .into_iter()
        .take(over.min(unread.len()))
        .map(|(_, id)| id)
        .collect()
}

/// Write `bytes` to `path` via a temp file and a rename.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

/// Best-effort `0700`.
fn private(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Keep only messages a peer may hand this node: from `peer` (the key the
/// connection authenticated), to `me`, and not expired at `now_ms`.
pub(crate) fn acceptable(
    messages: Vec<PushMessage>,
    peer: NodeId,
    me: NodeId,
    now_ms: i64,
) -> Vec<PushMessage> {
    messages
        .into_iter()
        .filter(|m| m.from == peer && m.to == me && !m.is_expired(now_ms))
        .collect()
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// One line for a message: when (the host's clock, UTC), who sent it as
/// this caller verified it, the subject, and the body on one line.
pub(crate) fn line(m: &PushMessage) -> String {
    format!(
        "{}  from host {} (verified)  {}  {}",
        utc(m.at_ms),
        m.from.short(),
        one_line(m.subject.as_str()),
        one_line(m.body.as_str())
    )
    .trim_end()
    .to_string()
}

/// The `--json` object for a message (one per line).
#[derive(Serialize, Deserialize)]
pub(crate) struct JsonLine {
    /// The message id.
    pub(crate) id: PushId,
    /// The sending host's node id, as the connection authenticated it.
    pub(crate) from: NodeId,
    /// Always `true`: a message whose sender did not verify is never stored.
    pub(crate) from_verified: bool,
    /// The subject.
    pub(crate) subject: String,
    /// The body, verbatim (untrusted).
    pub(crate) body: String,
    /// The host's clock when it accepted the push (unix ms).
    pub(crate) at_ms: i64,
}

impl JsonLine {
    fn of(m: &PushMessage) -> Self {
        Self {
            id: m.id,
            from: m.from,
            from_verified: true,
            subject: m.subject.as_str().to_string(),
            body: m.body.as_str().to_string(),
            at_ms: m.at_ms,
        }
    }
}

/// `s` on one line: newlines and other control characters escaped.
fn one_line(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            let v: Vec<char> = if c.is_control() {
                c.escape_default().collect()
            } else {
                vec![c]
            };
            v
        })
        .collect()
}

/// `2026-09-23 16:04:05Z` for unix milliseconds.
pub(crate) fn utc(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 → (year, month, day) (Howard Hinnant's
/// `civil_from_days`).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ---------------------------------------------------------------------------
// The receiver (inside `wires inbox --wait`)
// ---------------------------------------------------------------------------

/// Refusals of peers that may not deliver here (see [`transport::Throttle`]).
static STRANGERS: transport::Throttle = transport::Throttle::new();

/// The inbox ALPN on a waiting caller: accepts deliveries from hosts.
///
/// A delivery is accepted only from a peer that proves fabric membership
/// and that this node's **signed state names as a host** (re-read per
/// delivery). Each message must be from that peer and to this node.
#[derive(Clone)]
pub(crate) struct InboxReceiver {
    /// This node.
    pub(crate) me: NodeId,
    /// The fabric root memberships and the state must chain to.
    pub(crate) fabric: NodeId,
    /// Where this node's signed state is.
    pub(crate) keystore: Arc<Keystore>,
    /// Where messages go.
    pub(crate) mailbox: Mailbox,
}

impl std::fmt::Debug for InboxReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboxReceiver")
            .field("me", &self.me.hex())
            .finish_non_exhaustive()
    }
}

impl InboxReceiver {
    /// Whether `peer` may deliver here: a member, and a host in this node's
    /// signed state. `Err` is why not, for this node's trace only: the peer
    /// hears just [`NOT_ADMITTED`](crate::host::gate::NOT_ADMITTED).
    pub(crate) fn admit(
        &self,
        peer: NodeId,
        membership: &Membership,
        now: i64,
    ) -> std::result::Result<(), String> {
        library::check_inclusion(membership, self.fabric, peer, now)
            .map_err(|e| format!("membership rejected: {e}"))?;
        let state = crate::state::store::read(&self.keystore, self.fabric)
            .map_err(|e| format!("{e:#}"))?
            .ok_or("this node holds no signed state")?;
        if !state.state.is_host(peer) {
            return Err(format!(
                "not a host in the signed state (version {}); this inbox takes pushes from \
                 hosts only",
                state.state.version.0
            ));
        }
        Ok(())
    }

    /// Serve one delivery over an accepted connection from `peer`.
    async fn serve<S, R>(&self, mut send: S, mut recv: R, peer: NodeId) -> Result<()>
    where
        S: AsyncWrite + Unpin,
        R: AsyncRead + Unpin,
    {
        let membership =
            match read_frame_within(&mut recv, FRAME_TIMEOUT, library::MAX_INBOX_HELLO).await? {
                Some(InboxFrame::Hello { membership, .. }) => membership,
                _ => {
                    deny(&mut send, "expected hello").await;
                    bail!("a peer spoke out of turn");
                }
            };
        if let Err(detail) = self.admit(peer, &membership, crate::clock::now_unix()) {
            STRANGERS.refused("inbox delivery", peer, &detail);
            deny(&mut send, crate::host::gate::NOT_ADMITTED).await;
            return Ok(());
        }
        let messages = match read_frame(&mut recv, FRAME_TIMEOUT).await? {
            Some(InboxFrame::Deliver { messages }) => messages,
            _ => {
                deny(&mut send, "expected deliver").await;
                bail!("a host spoke out of turn");
            }
        };
        let ok = acceptable(messages, peer, self.me, now_ms());
        let stored = self.mailbox.store(&ok)?;
        tracing::info!(
            host = %peer.hex(),
            fresh = stored.fresh,
            "push delivered to the inbox"
        );
        write_frame(&mut send, &InboxFrame::Ack { ids: stored.ids }).await?;
        send.shutdown().await.ok();
        Ok(())
    }
}

impl iroh::protocol::ProtocolHandler for InboxReceiver {
    async fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        let peer = transport::to_node_id(&conn.remote_id());
        let result = async {
            let (send, recv) = conn.accept_bi().await.context("accepting a stream")?;
            self.serve(send, recv, peer).await
        }
        .await;
        let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
        result.map_err(|e| {
            tracing::warn!(peer = %peer.hex(), "inbox delivery failed: {e:#}");
            iroh::protocol::AcceptError::from_boxed(e.into())
        })
    }
}

// ---------------------------------------------------------------------------
// Fetching from hosts
// ---------------------------------------------------------------------------

/// What one host answered a fetch with.
#[derive(Debug)]
pub(crate) enum Fetched {
    /// How many new messages it handed over (after de-duplication).
    Messages(usize),
    /// It refused, and why.
    Refused(String),
}

/// Fetch from `host` over `endpoint`: say `hello`, ask for what is queued
/// (holding up to `wait` for something to arrive), store and acknowledge
/// it. Keeps fetching while the host hands over full batches.
pub(crate) async fn fetch_from(
    endpoint: &Endpoint,
    host: EndpointAddr,
    hello: &InboxFrame,
    wait: Duration,
    mailbox: &Mailbox,
) -> Result<Fetched> {
    let me = transport::to_node_id(&endpoint.id());
    let mut total = 0;
    let mut wait = wait;
    loop {
        let conn = tokio::time::timeout(DIAL_TIMEOUT, endpoint.connect(host.clone(), INBOX_ALPN))
            .await
            .map_err(|_| anyhow!("no answer within {DIAL_TIMEOUT:?}"))?
            .map_err(|e| anyhow!("dialing: {e}"))?;
        let peer = transport::to_node_id(&conn.remote_id());
        let (mut send, mut recv) = conn.open_bi().await.context("opening a stream")?;
        write_frame(&mut send, hello).await?;
        write_frame(
            &mut send,
            &InboxFrame::Fetch {
                wait_ms: wait.as_millis() as u64,
            },
        )
        .await?;
        let answer = read_frame(&mut recv, wait + FRAME_TIMEOUT).await?;
        let messages = match answer {
            Some(InboxFrame::Deliver { messages }) => messages,
            Some(InboxFrame::Denied { reason }) => {
                conn.close(0u32.into(), b"refused");
                return Ok(Fetched::Refused(reason));
            }
            _ => bail!("the host answered a fetch out of turn"),
        };
        let full = messages.len() >= MAX_BATCH;
        let stored = mailbox.store(&acceptable(messages, peer, me, now_ms()))?;
        total += stored.fresh;
        write_frame(&mut send, &InboxFrame::Ack { ids: stored.ids }).await?;
        send.finish().ok();
        // Let the host read the ack before the connection goes.
        let _ = tokio::time::timeout(FRAME_TIMEOUT, recv.read_to_end(0)).await;
        conn.close(0u32.into(), b"done");
        if !full {
            return Ok(Fetched::Messages(total));
        }
        wait = Duration::ZERO;
    }
}

/// The `Hello` this node presents: its membership and the ID token `wires
/// login` stored (so the host learns who it is, for pushes by role).
pub(crate) fn hello(ks: &Keystore, membership: &Membership) -> InboxFrame {
    InboxFrame::Hello {
        membership: membership.clone(),
        id_token: crate::caller::hello::stored_token(ks),
    }
}

/// Fetch from every host in `targets` at once, each bounded by `budget`
/// (plus `wait` for a long poll). Returns what each answered (a failure to
/// reach one is logged and left out).
pub(crate) async fn fetch_all(
    endpoint: &Endpoint,
    targets: &[(NodeId, EndpointAddr)],
    hello: &InboxFrame,
    wait: Duration,
    budget: Duration,
    mailbox: &Mailbox,
) -> Vec<(NodeId, Fetched)> {
    let mut set = tokio::task::JoinSet::new();
    for (node, addr) in targets.iter().cloned() {
        let endpoint = endpoint.clone();
        let hello = hello.clone();
        let mailbox = mailbox.clone();
        set.spawn(async move {
            let r = tokio::time::timeout(
                budget + wait,
                fetch_from(&endpoint, addr, &hello, wait, &mailbox),
            )
            .await;
            (node, r)
        });
    }
    let mut out = Vec::new();
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((node, Ok(Ok(fetched)))) => out.push((node, fetched)),
            Ok((node, Ok(Err(e)))) => {
                tracing::debug!(host = %node.hex(), "fetching the inbox: {e:#}")
            }
            Ok((node, Err(_))) => {
                tracing::debug!(host = %node.hex(), "fetching the inbox timed out")
            }
            Err(e) => tracing::debug!("a fetch task ended abnormally: {e}"),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// `wires inbox`
// ---------------------------------------------------------------------------

/// `wires inbox [--wait [--timeout D]] [--json]`.
#[derive(Args, Clone, Debug, Default)]
pub(crate) struct InboxArgs {
    /// Block until at least one message is here, print it, and exit. For a
    /// harness that runs commands in the background and wakes the agent when
    /// one exits.
    #[arg(long)]
    pub(crate) wait: bool,
    /// With `--wait`: give up after this long (e.g. `90s`, `10m`) and exit
    /// 124.
    #[arg(long, requires = "wait")]
    pub(crate) timeout: Option<Ttl>,
    /// Print one JSON object per message instead of a line.
    #[arg(long)]
    pub(crate) json: bool,
    /// Hex 32-byte seed of this node's key (refused in locked mode). Falls
    /// back to `$WIRES_NODE_SEED`, then the keystore.
    #[arg(long)]
    pub(crate) node_seed: Option<String>,
    /// Read the node key seed from this file (refused in locked mode).
    #[arg(long)]
    pub(crate) node_seed_file: Option<PathBuf>,
    /// The membership token to present (refused in locked mode).
    #[arg(long)]
    pub(crate) membership: Option<String>,
    /// Read the membership token from this file (refused in locked mode).
    #[arg(long)]
    pub(crate) membership_file: Option<PathBuf>,
    /// Dial hosts through this relay (refused in locked mode).
    #[arg(long)]
    pub(crate) relay_url: Option<String>,
}

impl InboxArgs {
    /// The credential flags, as `call` / `mcp` take them (what locked mode
    /// checks).
    pub(crate) fn creds(&self) -> CredArgs {
        CredArgs {
            tools_file: None,
            node_seed: self.node_seed.clone(),
            node_seed_file: self.node_seed_file.clone(),
            membership: self.membership.clone(),
            membership_file: self.membership_file.clone(),
            relay_url: self.relay_url.clone(),
        }
    }
}

/// `wires inbox`: fetch from the hosts of this node's services (and, with
/// `--wait`, accept direct deliveries meanwhile), print what is unread, mark
/// it read; returns the exit code.
pub(crate) async fn inbox_cmd(a: InboxArgs) -> Result<i32> {
    let lock = Lock::detect()?;
    let creds = a.creds();
    if let Err(e) = lock.check(&creds) {
        eprintln!("wires: {e}");
        return Ok(EXIT_LOCKED);
    }
    let node = keystore::node_identity(a.node_seed.as_deref(), a.node_seed_file.as_deref())?;
    let membership = keystore::membership(a.membership.as_deref(), a.membership_file.as_deref())?;
    keystore::preflight(node.node_id(), &membership).map_err(anyhow::Error::msg)?;
    let ks = Arc::new(Keystore::resolve()?);
    let mailbox = Mailbox::open(&keystore::home()?)?;
    let deadline = a
        .timeout
        .map(|t| tokio::time::Instant::now() + t.duration());
    let fetcher = cold_fetcher(&ks, &node, &membership, a.relay_url.as_deref()).await?;
    // While waiting, a host's direct delivery lands here too.
    let _receiver = a.wait.then(|| {
        iroh::protocol::Router::builder(fetcher.0.clone())
            .accept(
                INBOX_ALPN,
                InboxReceiver {
                    me: node.node_id(),
                    fabric: membership.fabric,
                    keystore: Arc::clone(&ks),
                    mailbox: mailbox.clone(),
                },
            )
            .spawn()
    });
    let code = read_loop(&a, &mailbox, &fetcher, deadline).await;
    fetcher.0.close().await;
    code
}

/// `wires inbox`'s way to the hosts: its endpoint, their dial targets, and
/// the `Hello` it presents.
type Fetcher = (Endpoint, Vec<(NodeId, EndpointAddr)>, InboxFrame);

/// Fetch, print what is unread, and — with `--wait` — repeat until
/// something is printed or `deadline` passes.
async fn read_loop(
    a: &InboxArgs,
    mailbox: &Mailbox,
    fetcher: &Fetcher,
    deadline: Option<tokio::time::Instant>,
) -> Result<i32> {
    let mut out = tokio::io::stdout();
    loop {
        let round = tokio::time::Instant::now();
        // Every host refused this node: an answer, not "nothing yet" (77).
        let mut refused_by_all: Option<String> = None;
        {
            let (endpoint, targets, hello) = fetcher;
            let wait = if a.wait && !mailbox.has_unread() {
                deadline
                    .map_or(LONG_POLL, |d| d.saturating_duration_since(round))
                    .min(LONG_POLL)
            } else {
                Duration::ZERO
            };
            let mut refusals = Vec::new();
            for (host, fetched) in
                fetch_all(endpoint, targets, hello, wait, FETCH_BUDGET, mailbox).await
            {
                match fetched {
                    Fetched::Refused(reason) => {
                        eprintln!("wires inbox: host {} refused: {reason}", host.short());
                        refusals.push(reason);
                    }
                    Fetched::Messages(n) => {
                        tracing::debug!(host = %host.hex(), fetched = n, "inbox fetch")
                    }
                }
            }
            if !targets.is_empty() && refusals.len() == targets.len() {
                refused_by_all = refusals.into_iter().next();
            }
        }
        for note in mailbox.take_notes() {
            eprintln!("wires inbox: {note}");
        }
        let messages = mailbox.take_unread()?;
        for m in &messages {
            let text = if a.json {
                serde_json::to_string(&JsonLine::of(m))?
            } else {
                line(m)
            };
            out.write_all(format!("{text}\n").as_bytes()).await?;
        }
        out.flush().await?;
        if messages.is_empty()
            && let Some(reason) = refused_by_all
        {
            return Err(Denied::new(reason).into());
        }
        if !messages.is_empty() || !a.wait {
            return Ok(0);
        }
        if deadline.is_some_and(|d| tokio::time::Instant::now() >= d) {
            eprintln!("wires inbox: nothing arrived before the timeout");
            return Ok(EXIT_TIMEOUT);
        }
        // A fetch long-polls, so a round that came back early (a host that
        // could not be reached) waits out a second before the next.
        tokio::time::sleep_until(round + Duration::from_secs(1)).await;
    }
}

/// A fetcher: this node's endpoint, the hosts of every service it may call
/// (from its signed state; no network read), and its `Hello`.
async fn cold_fetcher(
    ks: &Keystore,
    node: &NodeIdentity,
    membership: &Membership,
    relay_url: Option<&str>,
) -> Result<Fetcher> {
    let allowed = crate::caller::services::allowed(ks).await?;
    let hosts: Vec<NodeId> = crate::caller::pick::hosts_of(
        &allowed.state.state,
        allowed.grants.iter().map(|g| &g.service),
    )
    .into_iter()
    .filter(|h| *h != node.node_id())
    .collect();
    let hints = crate::caller::pick::Hints::load(ks);
    let targets = hosts
        .iter()
        .copied()
        .zip(hints.targets(&hosts, relay_url))
        .collect();
    let endpoint = transport::bind(node, relay_url).await?;
    Ok((endpoint, targets, hello(ks, membership)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{NodeIdentity, PushBody, Subject};
    use proptest::prelude::*;

    fn node(seed: u8) -> NodeId {
        NodeIdentity::from_seed([seed; 32]).node_id()
    }

    fn msg(at_ms: i64, subject: &str, body: &str) -> PushMessage {
        PushMessage {
            id: PushId::generate(),
            from: node(1),
            to: node(2),
            subject: Subject::new(subject).unwrap(),
            body: PushBody::new(body).unwrap(),
            at_ms,
            expires_ms: i64::MAX,
        }
    }

    fn mailbox() -> Mailbox {
        Mailbox::open(&crate::testutil::temp_dir()).unwrap()
    }

    /// Card 28 §9: a dialer that may not deliver here (a member that isn't
    /// a host, or no member at all) hears only the fixed "not admitted", no
    /// reason and no state version.
    #[tokio::test]
    async fn a_refused_deliverer_hears_only_not_admitted() {
        let root = NodeIdentity::from_seed([1; 32]);
        let (me, member, stranger) = (node(2), NodeIdentity::from_seed([3; 32]), node(4));
        let home = crate::testutil::temp_dir();
        let ks = Arc::new(Keystore::at(&home));
        let mut s = library::State::new(root.node_id());
        s.version = library::StateVersion(9);
        s.not_after = i64::MAX;
        s.members.extend([me, member.node_id()]);
        let signed = s.sign(&root).unwrap();
        crate::state::store::adopt_if_newer(&ks, &signed, root.node_id(), 10).unwrap();
        let receiver = InboxReceiver {
            me,
            fabric: root.node_id(),
            keystore: ks,
            mailbox: Mailbox::open(&home).unwrap(),
        };
        let other_root = NodeIdentity::from_seed([5; 32]);
        for (peer, membership) in [
            (
                member.node_id(),
                Membership::mint(&root, member.node_id(), 0, i64::MAX).unwrap(),
            ),
            (
                stranger,
                Membership::mint(&other_root, stranger, 0, i64::MAX).unwrap(),
            ),
        ] {
            let (mut dialer, host_side) = tokio::io::duplex(64 * 1024);
            let (recv, send) = tokio::io::split(host_side);
            write_frame(
                &mut dialer,
                &InboxFrame::Hello {
                    membership,
                    id_token: None,
                },
            )
            .await
            .unwrap();
            receiver.serve(send, recv, peer).await.unwrap();
            match read_frame(&mut dialer, Duration::from_secs(1))
                .await
                .unwrap()
            {
                Some(InboxFrame::Denied { reason }) => {
                    assert_eq!(reason, crate::host::gate::NOT_ADMITTED)
                }
                other => panic!("expected a denial, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_line_names_the_verified_host_first_and_stays_on_one_line() {
        let mut m = msg(
            1_790_150_645_000,
            "build-41",
            "failed: test_orders_total\nline 2\u{1b}[31m",
        );
        m.from = node(1);
        let l = line(&m);
        assert_eq!(
            l,
            format!(
                "2026-09-23 08:04:05Z  from host {} (verified)  build-41  failed: test_orders_total\\nline 2\\u{{1b}}[31m",
                node(1).short()
            )
        );
        assert!(!l.contains('\n'));
    }

    #[test]
    fn utc_dates_are_civil() {
        assert_eq!(utc(0), "1970-01-01 00:00:00Z");
        assert_eq!(utc(951_782_400_000), "2000-02-29 00:00:00Z");
        assert_eq!(utc(1_790_150_645_000), "2026-09-23 08:04:05Z");
        assert_eq!(utc(-1_000), "1969-12-31 23:59:59Z");
    }

    #[test]
    fn store_dedupes_by_id_across_unread_and_read() {
        let mb = mailbox();
        let a = msg(1, "a", "");
        let b = msg(2, "b", "");
        let s = mb.store(&[a.clone(), b.clone()]).unwrap();
        assert_eq!(s.fresh, 2);
        assert_eq!(s.ids, [a.id, b.id]);
        // A re-delivery (lost ack) is acknowledged but not stored twice.
        let s = mb.store(std::slice::from_ref(&a)).unwrap();
        assert_eq!((s.fresh, s.ids.clone()), (0, vec![a.id]));
        let taken = mb.take_unread().unwrap();
        assert_eq!(taken, [a.clone(), b.clone()]);
        assert!(!mb.has_unread());
        // Read, and delivered again: still a duplicate.
        assert_eq!(mb.store(std::slice::from_ref(&b)).unwrap().fresh, 0);
        assert!(mb.take_unread().unwrap().is_empty());
    }

    #[test]
    fn a_full_mailbox_evicts_the_oldest_with_a_note() {
        let mb = mailbox();
        let batch: Vec<PushMessage> = (0..MAX_UNREAD as i64 + 3)
            .map(|i| msg(i, &format!("s{i}"), ""))
            .collect();
        let s = mb.store(&batch).unwrap();
        assert_eq!(s.evicted, 3);
        let notes = mb.take_notes();
        assert_eq!(notes.len(), 1);
        assert!(
            notes[0].starts_with("3 unread message(s) evicted"),
            "{notes:?}"
        );
        assert!(mb.take_notes().is_empty(), "a note is shown once");
        let taken = mb.take_unread().unwrap();
        assert_eq!(taken.len(), MAX_UNREAD);
        assert_eq!(taken[0].at_ms, 3, "the three oldest went");
    }

    #[test]
    fn only_messages_from_the_peer_to_me_and_unexpired_are_acceptable() {
        let good = msg(1, "ok", "");
        let mut forged = msg(1, "forged", "");
        forged.from = node(9);
        let mut elsewhere = msg(1, "elsewhere", "");
        elsewhere.to = node(9);
        let mut stale = msg(1, "stale", "");
        stale.expires_ms = 5;
        let ok = acceptable(
            vec![good.clone(), forged, elsewhere, stale],
            node(1),
            node(2),
            10,
        );
        assert_eq!(ok, [good]);
    }

    #[test]
    fn inbox_parses_its_flags_and_timeout_needs_wait() {
        use crate::{Cli, Command};
        use clap::Parser;
        let parse = |args: &[&str]| Cli::try_parse_from(["wires", "inbox"].iter().chain(args));
        let Command::Inbox(a) = parse(&["--wait", "--timeout", "90s", "--json"])
            .unwrap()
            .command
        else {
            panic!("expected inbox");
        };
        assert!(a.wait && a.json);
        assert_eq!(a.timeout.unwrap().duration(), Duration::from_secs(90));
        assert!(
            parse(&["--timeout", "5s"]).is_err(),
            "--timeout needs --wait"
        );
        assert!(parse(&[]).is_ok());
    }

    /// Locked mode refuses inbox's credential flags like `call`'s.
    #[test]
    fn locked_mode_refuses_inbox_overrides() {
        let lock = Lock::from_sources(Some("1"), None, false);
        let a = InboxArgs {
            relay_url: Some("https://r".into()),
            ..Default::default()
        };
        assert!(lock.check(&a.creds()).is_err());
        assert!(lock.check(&InboxArgs::default().creds()).is_ok());
    }

    proptest! {
        /// Eviction makes exactly enough room, and takes the oldest.
        #[test]
        fn evictions_make_room_oldest_first(
            ats in proptest::collection::vec(any::<i64>(), 0..40),
            incoming in 0usize..10,
            cap in 1usize..30,
        ) {
            let unread: Vec<(i64, PushId)> = ats.iter().map(|&a| (a, PushId::generate())).collect();
            let evict = evictions(&unread, incoming, cap);
            let want = (unread.len() + incoming).saturating_sub(cap).min(unread.len());
            prop_assert_eq!(evict.len(), want);
            let mut sorted = unread.clone();
            sorted.sort();
            let oldest: Vec<PushId> = sorted.iter().take(want).map(|(_, id)| *id).collect();
            prop_assert_eq!(evict, oldest);
        }

        /// However messages arrive and repeat, each is read exactly once.
        #[test]
        fn every_message_is_read_exactly_once(
            n in 1usize..12,
            repeats in proptest::collection::vec(0usize..12, 0..24),
        ) {
            let mb = mailbox();
            let msgs: Vec<PushMessage> = (0..n).map(|i| msg(i as i64, "s", "b")).collect();
            mb.store(&msgs).unwrap();
            let mut seen: Vec<PushId> = mb.take_unread().unwrap().iter().map(|m| m.id).collect();
            let again: Vec<PushMessage> = repeats.iter().map(|&i| msgs[i % n].clone()).collect();
            mb.store(&again).unwrap();
            seen.extend(mb.take_unread().unwrap().iter().map(|m| m.id));
            seen.sort();
            let mut want: Vec<PushId> = msgs.iter().map(|m| m.id).collect();
            want.sort();
            prop_assert_eq!(seen, want);
        }
    }
}

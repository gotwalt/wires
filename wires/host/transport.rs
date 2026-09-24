//! The iroh session transport: bind/dial, the `Hello`, and the stdio bridge.
//!
//! `library` stays pure (no iroh/tokio); this module is where the
//! key-addressed session meets the iroh QUIC endpoint. The session ALPN is
//! [`ALPN`]. A caller opens a bi-stream and sends a
//! [`Frame::Hello`](library::Frame::Hello) — its root-signed membership, the
//! signed-state version it holds, and its IdP ID token — followed at once by
//! a [`Frame::Invoke`] naming a service plus per-call arguments. The host
//! ([`serve_session_permitted`]) decides by the signed state it holds, re-read
//! per connection (see [`gate`](crate::host::gate)), then execs the
//! service's fixed argv with the caller's arguments appended — never through
//! a shell — with the verified caller identity injected into its
//! environment, and bridges its stdio over tagged frames.
//!
//! Two properties this module exists to preserve:
//!
//! - **Refusals are legible.** A host that turns a caller away sends a
//!   [`Frame::Denied`] carrying the reason before closing, which the dialer
//!   surfaces as a [`Denied`] error (`wires call` exits 77). Nothing the
//!   dialer sends or receives on a refused session ever reaches its stdout.
//! - **Refusals are current.** The signed state is re-read on every
//!   connection, so a `wires remove` takes effect on the next dial rather
//!   than the next restart.
//! - **Strangers are cheap.** Anyone can open a connection, so until the
//!   host knows the peer is a member it reads small frames only
//!   ([`MAX_HELLO_FRAME`], [`MAX_INVOKE_FRAME`]), holds at most
//!   [`MAX_PREAUTH_SESSIONS`] such sessions, verifies no token, says only
//!   [`NOT_ADMITTED`](crate::host::gate::NOT_ADMITTED), and writes nothing to
//!   the call log.
//! - **No call runs unlogged.** An admitted call's `Started` is in the call
//!   log, `fsync`ed, before its child is spawned ([`AuditSink`]).

use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::presets::N0;
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};

use library::{
    Chunk, Frame, Hello, Invocation, NodeId, NodeIdentity, SignedState, ToolName, check_inclusion,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::mpsc;

/// The custom ALPN identifying a wires session.
///
/// `/3`: the session opens with a [`Hello`] (card 27); a peer still speaking
/// the channel-era `/2` handshake fails cleanly at connect time rather than
/// mid-handshake.
pub const ALPN: &[u8] = b"wires/session/3";

/// Read buffer size for pumping child / local stdio into frames.
const PUMP_BUF: usize = 64 * 1024;

/// Largest frame body accepted off the wire once a session is admitted.
/// Bounds what a member can make the host buffer; generous versus the 64 KiB
/// stdio chunk size, but far below "exhaust memory".
const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Largest [`Frame::Hello`] a host reads, before it knows who is asking: a
/// membership, a state version and an ID token fit in a few KiB.
pub(crate) const MAX_HELLO_FRAME: usize = 64 * 1024;

/// Largest [`Frame::Invoke`] a host reads before admitting the caller. An
/// [`Argv`](library::Argv) holds at most [`MAX_ARGV_BYTES`](library::MAX_ARGV_BYTES),
/// but canonical JSON may escape a control character as six bytes (`\u001f`)
/// and adds quotes and commas per argument, so the cap is eight times that
/// (512 KiB) — the most a valid invocation can take, and no more.
pub(crate) const MAX_INVOKE_FRAME: usize = 8 * library::MAX_ARGV_BYTES;

/// How many sessions a host holds open at once *before* deciding who they are
/// (reading `Hello`/`Invoke`, checking membership, verifying the ID token).
/// One more is closed at once, without a reply. Admitted sessions don't
/// count: the permit is returned as soon as the gate decides.
pub(crate) const MAX_PREAUTH_SESSIONS: usize = 64;

/// How long a responder waits for the opening handshake before giving up, so a
/// peer that connects but never speaks can't hold a session task open.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a session waits for the call log to take one record — its turn
/// in the queue plus the append and `fsync` — before treating the log as
/// unavailable. See [`AuditSink::append`].
pub(crate) const LOG_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Denial reason: the responder got something other than an
/// [`Frame::Invoke`] after the handshake.
pub const DENY_INVOKE_REQUIRED: &str = "invoke required";

/// Denial reason: the host could not record the call's `Started` entry, so
/// the call did not run. The cause is in the host's own trace.
pub const DENY_LOG_UNAVAILABLE: &str = "this host can't record calls right now, so it runs none; \
                                        try again later";

/// The call log could not take a record (see [`AuditSink::append`]). The
/// text is for the host's trace, never for a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogUnavailable(String);

impl std::fmt::Display for LogUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the call log did not take the record: {}", self.0)
    }
}

impl std::error::Error for LogUnavailable {}

/// One record on its way to the call log, with where to say whether it was
/// logged. Built by [`AuditSink::append`]; drained by the log's writer
/// ([`call_log::tee`](crate::host::call_log::tee)).
#[derive(Debug)]
pub struct Pending {
    /// The record to append.
    pub record: library::AuditRecord,
    /// Answered once the record is durably logged (or failed to be).
    done: tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
}

impl Pending {
    /// Tell the waiting session how the append went: `Ok` only once the
    /// entry is written and `fsync`ed.
    pub fn answer(self, outcome: std::result::Result<(), String>) {
        let _ = self.done.send(outcome);
    }
}

/// The host's handle on its call log: where sessions and pushes send
/// [`AuditRecord`](library::AuditRecord)s.
///
/// **Fail closed.** [`append`](Self::append) waits (at most [`LOG_WAIT`])
/// until the record is written and `fsync`ed, and says whether it was. A
/// full queue is waited on, never skipped, so no record is silently dropped.
/// A call's `Started` must be logged before its child is spawned, or the call
/// is refused; what a failure of any later record means is decided by the
/// caller of `append` (see [`audit`](crate::host::audit)).
#[derive(Clone, Debug)]
pub struct AuditSink(tokio::sync::mpsc::Sender<Pending>);

impl AuditSink {
    /// A sink and the queue the log's writer drains (at most `cap` records
    /// waiting; a session beyond that waits its turn).
    pub fn log_queue(cap: usize) -> (Self, tokio::sync::mpsc::Receiver<Pending>) {
        let (tx, rx) = tokio::sync::mpsc::channel(cap);
        (Self(tx), rx)
    }

    /// An in-memory sink (tests): every record is answered as logged once it
    /// is in the returned receiver, which holds at most `cap`. Must be called
    /// inside a Tokio runtime.
    #[cfg(test)]
    pub fn channel(cap: usize) -> (Self, tokio::sync::mpsc::Receiver<library::AuditRecord>) {
        let (sink, mut queue) = Self::log_queue(cap);
        let (tx, rx) = tokio::sync::mpsc::channel(cap);
        tokio::spawn(async move {
            while let Some(pending) = queue.recv().await {
                let kept = tx.send(pending.record.clone()).await;
                pending.answer(kept.map_err(|_| "the receiver is gone".to_string()));
            }
        });
        (sink, rx)
    }

    /// Append `record` to the call log, waiting until it is durably written.
    /// `Err` when the log refused it, is gone, or took longer than
    /// [`LOG_WAIT`] (the record may still be written later).
    pub async fn append(&self, record: library::AuditRecord) -> Result<(), LogUnavailable> {
        let (done, answer) = tokio::sync::oneshot::channel();
        let wait = async {
            self.0
                .send(Pending { record, done })
                .await
                .map_err(|_| LogUnavailable("the log writer is gone".into()))?;
            answer
                .await
                .map_err(|_| LogUnavailable("the log writer is gone".into()))?
                .map_err(LogUnavailable)
        };
        tokio::time::timeout(LOG_WAIT, wait)
            .await
            .map_err(|_| LogUnavailable(format!("no answer within {LOG_WAIT:?}")))?
    }
}

/// Keeps a trace of refusals a stranger can cause from becoming a flood:
/// each one is traced at `debug`, and at most one `info` line per
/// [`Throttle::EVERY_MS`] says how many there were. Anyone can open a
/// connection, so the rate is the stranger's to choose; `info` stays
/// readable and `debug` has the detail when an operator wants it.
#[derive(Debug)]
pub(crate) struct Throttle {
    /// When the last `info` line was written (unix ms).
    last_ms: std::sync::atomic::AtomicI64,
    /// Refusals since then.
    since: std::sync::atomic::AtomicU64,
}

impl Throttle {
    /// The least time between two `info` lines.
    pub(crate) const EVERY_MS: i64 = 10_000;

    /// A throttle that lets its first event through.
    pub(crate) const fn new() -> Self {
        Self {
            last_ms: std::sync::atomic::AtomicI64::new(i64::MIN),
            since: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Count one event at `now_ms`: `Some(n)` — the events since the last
    /// `info` line, this one included — when it is time for another.
    pub(crate) fn tick(&self, now_ms: i64) -> Option<u64> {
        use std::sync::atomic::Ordering::SeqCst;
        self.since.fetch_add(1, SeqCst);
        let last = self.last_ms.load(SeqCst);
        if now_ms.saturating_sub(last) < Self::EVERY_MS {
            return None;
        }
        if self
            .last_ms
            .compare_exchange(last, now_ms, SeqCst, SeqCst)
            .is_err()
        {
            return None;
        }
        Some(self.since.swap(0, SeqCst))
    }

    /// Trace one refusal of a stranger: `what` names the protocol, `detail`
    /// is why (never sent to the peer).
    pub(crate) fn refused(&self, what: &str, peer: NodeId, detail: &str) {
        tracing::debug!(peer = %peer.hex(), "{what} refused: {detail}");
        if let Some(n) = self.tick(crate::host::audit::now_ms()) {
            tracing::info!(
                refused = n,
                last_peer = %peer.hex(),
                "{what}: refused {n} unadmitted peer(s) since the last report (latest: {detail}); \
                 not written to the call log"
            );
        }
    }
}

/// The refusal a session sends and returns: already traced (and, for a
/// member, logged), so the accept loop need not warn about it again.
#[derive(Debug)]
pub(crate) struct Refused(pub(crate) String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "refused: {}", self.0)
    }
}

impl std::error::Error for Refused {}

// ---------------------------------------------------------------------------
// Key bridge: our `library` identities <-> iroh's
// ---------------------------------------------------------------------------

/// Map a `library` node identity to the iroh `SecretKey` of the same Ed25519
/// key, so the iroh node id equals our [`NodeId`].
pub fn secret_key(identity: &NodeIdentity) -> SecretKey {
    SecretKey::from_bytes(&identity.seed_bytes())
}

/// Map our [`NodeId`] to the iroh `EndpointId` (public key) it names.
pub fn endpoint_id(node: &NodeId) -> Result<EndpointId> {
    iroh::PublicKey::from_bytes(node.as_bytes()).context("node id is not a valid Ed25519 key")
}

/// Map an iroh `EndpointId` back to our [`NodeId`].
pub fn to_node_id(id: &EndpointId) -> NodeId {
    NodeId::from_bytes(*id.as_bytes())
}

/// Build the [`EndpointAddr`] to dial `node`, attaching any direct socket
/// addresses and relay URL from the target. With no hints this is a bare addr
/// resolved via discovery at dial time; with hints the dialer needs no
/// discovery service. The address is only a hint — iroh still authenticates the
/// peer to `node`'s key.
pub fn endpoint_addr(
    node: &NodeId,
    addrs: &[std::net::SocketAddr],
    relay_url: Option<&str>,
) -> Result<EndpointAddr> {
    let mut addr = EndpointAddr::new(endpoint_id(node)?);
    for sock in addrs {
        addr = addr.with_ip_addr(*sock);
    }
    if let Some(url) = relay_url {
        let relay: iroh::RelayUrl = url.parse().with_context(|| format!("relay url {url}"))?;
        addr = addr.with_relay_url(relay);
    }
    Ok(addr)
}

/// Bind an iroh endpoint for `identity` on the session [`ALPN`] (see
/// [`bind_with_alpn`]).
pub async fn bind(identity: &NodeIdentity, relay_url: Option<&str>) -> Result<Endpoint> {
    bind_with_alpn(identity, relay_url, ALPN).await
}

/// Bind an iroh endpoint for `identity` advertising `alpn`, using the n0 preset
/// for discovery + relays. If `relay_url` is given, that relay is used instead
/// of the n0 default (for a self-hosted `//relay`).
pub async fn bind_with_alpn(
    identity: &NodeIdentity,
    relay_url: Option<&str>,
    alpn: &[u8],
) -> Result<Endpoint> {
    // The local, unsigned hints file (`$WIRES_HOME/hints`, usually absent):
    // extra places to try a key, beside n0 discovery.
    let hints = iroh::address_lookup::memory::MemoryLookup::new();
    if let Ok(ks) = crate::admin::keystore::Keystore::resolve() {
        for addr in crate::caller::pick::Hints::load(&ks).endpoint_addrs() {
            hints.add_endpoint_info(addr);
        }
    }
    let mut builder = Endpoint::builder(N0)
        .secret_key(secret_key(identity))
        .address_lookup(hints)
        .alpns(vec![alpn.to_vec()]);
    if let Some(url) = relay_url {
        let map = iroh::RelayMap::try_from_iter([url])
            .with_context(|| format!("parsing relay url {url}"))?;
        builder = builder.relay_mode(iroh::endpoint::RelayMode::Custom(map));
    }
    builder
        .bind()
        .await
        .map_err(|e| anyhow!("binding iroh endpoint: {e}"))
}

// ---------------------------------------------------------------------------
// Frame I/O over an iroh bi-stream (length-prefixed via `library::Frame`)
// ---------------------------------------------------------------------------

/// Write one length-prefixed frame.
pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> Result<()> {
    let bytes = frame.encode().context("encoding frame")?;
    w.write_all(&bytes).await.context("writing frame")?;
    Ok(())
}

/// Read one length-prefixed frame (at most [`MAX_FRAME`]), or `None` at a
/// clean end of stream.
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Frame>> {
    read_frame_within(r, MAX_FRAME).await
}

/// [`read_frame`], refusing a frame whose length prefix is over `max`.
///
/// The prefix is the peer's claim, so nothing is sized from it: the body
/// buffer grows only as bytes actually arrive, and a prefix over `max` is
/// refused before a byte of body is read.
pub(crate) async fn read_frame_within<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> Result<Option<Frame>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("reading frame length"),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max {
        bail!("frame too large: {len} bytes (max {max})");
    }
    let mut full = Vec::with_capacity(4 + len.min(PUMP_BUF));
    full.extend_from_slice(&len_buf);
    (&mut *r)
        .take(len as u64)
        .read_to_end(&mut full)
        .await
        .context("reading frame body")?;
    if full.len() != 4 + len {
        bail!("truncated frame");
    }
    match Frame::decode(&full)? {
        Some((frame, _)) => Ok(Some(frame)),
        None => bail!("truncated frame"),
    }
}

/// The largest denial reason put on the wire. A refusal is a short sentence;
/// the cap keeps a pathological `{e:#}` chain from becoming a frame.
const MAX_REASON: usize = 512;

/// Clamp a denial reason to [`MAX_REASON`] bytes, cutting on a char boundary so
/// the frame body stays valid UTF-8.
pub(crate) fn truncate_reason(mut s: String) -> String {
    if s.len() > MAX_REASON {
        let mut end = MAX_REASON;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

/// Tell the dialer *why* it was refused, then close our side.
///
/// Best-effort: a peer that already vanished simply never reads it, and the
/// caller still returns the original error for logging.
async fn deny<W: AsyncWrite + Unpin>(send: &mut W, reason: String) {
    let reason = truncate_reason(reason);
    let _ = write_frame(send, &Frame::Denied { reason }).await;
    send.shutdown().await.ok();
}

/// Pump a child output stream into `tx` as frames built by `make`
/// ([`Frame::Stdout`] / [`Frame::Stderr`]).
async fn pump_reader<R: AsyncRead + Unpin>(
    mut r: R,
    make: fn(Chunk) -> Frame,
    tx: mpsc::Sender<Frame>,
) -> Result<()> {
    let mut buf = vec![0u8; PUMP_BUF];
    loop {
        let n = r.read(&mut buf).await.context("reading child output")?;
        if n == 0 {
            break;
        }
        if tx
            .send(make(Chunk::from_bytes(buf[..n].to_vec())))
            .await
            .is_err()
        {
            break;
        }
    }
    Ok(())
}

/// Read the [`Frame::Invoke`] a dialer sends right after its
/// handshake (bounded by [`HANDSHAKE_TIMEOUT`]).
async fn read_invocation<R: AsyncRead + Unpin>(recv: &mut R) -> Result<Invocation> {
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_frame_within(recv, MAX_INVOKE_FRAME))
        .await
        .context("timed out waiting for invoke")??
    {
        Some(Frame::Invoke(invocation)) => Ok(invocation),
        Some(_) => bail!("second frame was not an invoke"),
        None => bail!("connection closed before invoke"),
    }
}

/// Spawn `cmd` (`program` names it in errors) with piped stdio and bridge
/// the child's stdio over the session until it exits (or kill it when
/// `shutdown` says the dialer is gone), then log the call's `Finished` via
/// `audit` and send its [`Frame::Exit`]. The call's `Started` is already
/// logged and the ack already written; a child that fails to spawn is
/// logged as finished with exit -1.
async fn bridge_child<S, R>(
    send: S,
    mut recv: R,
    mut cmd: Command,
    program: &str,
    shutdown: impl std::future::Future<Output = ()> + Send,
    audit: Option<crate::host::audit::CallAudit>,
) -> Result<()>
where
    S: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    let spawned = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => {
            if let Some(audit) = audit {
                audit.finish(-1).await; // audit: finished (never ran)
            }
            return Err(e).with_context(|| format!("spawning {program}"));
        }
    };
    let mut child_stdin = child.stdin.take().context("child stdin")?;
    let stdin_tap = crate::host::audit::tap_stdin(audit.as_ref());
    let child_stdout = crate::host::audit::tap_stdout(
        audit.as_ref(),
        child.stdout.take().context("child stdout")?,
    );
    let child_stderr = crate::host::audit::tap_stderr(
        audit.as_ref(),
        child.stderr.take().context("child stderr")?,
    );

    // A single writer task serializes all server->client frames.
    let (tx, mut rx) = mpsc::channel::<Frame>(64);
    let writer = tokio::spawn(async move {
        let mut send = send;
        while let Some(frame) = rx.recv().await {
            write_frame(&mut send, &frame).await?;
        }
        send.shutdown().await.ok();
        Ok::<(), anyhow::Error>(())
    });

    // client stdin frames -> child stdin (closes child stdin at end of stream).
    let stdin_task = tokio::spawn(async move {
        loop {
            match read_frame(&mut recv).await? {
                Some(Frame::Stdin(chunk)) => {
                    stdin_tap.feed(chunk.as_bytes()); // audit: stdin
                    child_stdin.write_all(chunk.as_bytes()).await?;
                }
                Some(_) => {} // ignore unexpected frames from the dialer
                None => break,
            }
        }
        child_stdin.shutdown().await.ok();
        Ok::<(), anyhow::Error>(())
    });

    let out_task = tokio::spawn(pump_reader(child_stdout, Frame::Stdout, tx.clone()));
    let err_task = tokio::spawn(pump_reader(child_stderr, Frame::Stderr, tx.clone()));

    // Wait for the child, unless the dialer vanishes first — in which case kill
    // it and reap, rather than leaving an orphan behind. (The `child.wait()`
    // future is dropped when the select ends, releasing its borrow of `child`.)
    let status = tokio::select! {
        status = child.wait() => status.context("waiting for child")?,
        _ = shutdown => {
            tracing::warn!("dialer disconnected; killing child");
            child.start_kill().ok();
            child.wait().await.context("reaping killed child")?
        }
    };
    out_task.await.context("stdout pump")??;
    err_task.await.context("stderr pump")??;
    // The child is gone, so there is nobody left to feed. Don't wait for the
    // dialer's stdin to reach EOF: from a terminal it never does, and a
    // `wires call tool -- ARGS` whose child ignores stdin would hang until
    // Ctrl-D. Whatever stdin already arrived is in the audit tap.
    stdin_task.abort();
    let _ = stdin_task.await;

    let code = status.code().unwrap_or(-1);
    tracing::info!(code, "child exited; closing session");
    if let Some(audit) = audit {
        audit.finish(code).await; // audit: finished, before the caller hears the exit
    }
    tx.send(Frame::Exit(code)).await.ok();
    drop(tx);
    writer.await.context("writer task")??;
    Ok(())
}

// ---------------------------------------------------------------------------
// Responder (`wires serve`)
// ---------------------------------------------------------------------------

/// The session ALPN for a host, as a router protocol (see
/// [`serve_session_permitted`]). At most [`MAX_PREAUTH_SESSIONS`] sessions
/// wait for a decision at once; one more is closed unanswered and traced.
#[derive(Clone, Debug)]
pub(crate) struct ServicesProtocol {
    /// Who decides.
    host: Arc<crate::host::gate::ServicesHost>,
    /// Permits for sessions not yet decided.
    preauth: Arc<tokio::sync::Semaphore>,
}

impl ServicesProtocol {
    /// Serve sessions for `host`.
    pub(crate) fn new(host: Arc<crate::host::gate::ServicesHost>) -> Self {
        Self {
            host,
            preauth: Arc::new(tokio::sync::Semaphore::new(MAX_PREAUTH_SESSIONS)),
        }
    }

    /// A permit for one more undecided session, if there is room.
    fn enter(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.preauth).try_acquire_owned().ok()
    }
}

/// Refusals of peers not known to be members (see [`Throttle`]).
static STRANGERS: Throttle = Throttle::new();

impl iroh::protocol::ProtocolHandler for ServicesProtocol {
    async fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        let caller = to_node_id(&conn.remote_id());
        let Some(permit) = self.enter() else {
            STRANGERS.refused(
                "session",
                caller,
                &format!("{MAX_PREAUTH_SESSIONS} sessions already await a decision"),
            );
            conn.close(1u32.into(), b"busy");
            return Ok(());
        };
        tracing::debug!(caller = %caller.hex(), "connection accepted (iroh-authenticated)");
        let result = async {
            let (send, recv) = conn.accept_bi().await.context("accepting bi-stream")?;
            // The transport's own liveness signal: when the dialer goes away,
            // the child dies with it instead of being stranded on this host.
            let closed = conn.clone();
            serve_session_permitted(send, recv, caller, &self.host, Some(permit), async move {
                closed.closed().await;
            })
            .await
        }
        .await;
        // Let the dialer read a `Denied` (or the final frames) before the
        // connection is torn down; bounded so a vanished dialer can't pin us.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), conn.closed()).await;
        result.map_err(|e| {
            if e.downcast_ref::<Refused>().is_some() {
                tracing::debug!(caller = %caller.hex(), "{e:#}");
            } else {
                tracing::warn!(caller = %caller.hex(), "session failed: {e:#}");
            }
            iroh::protocol::AcceptError::from_boxed(e.into())
        })
    }
}

/// Refuse a **member**: log the refusal in the call log (awaited; a log that
/// can't take it is traced as an error) and send the reason.
async fn refuse_member<W: AsyncWrite + Unpin>(
    send: &mut W,
    audit: Option<&AuditSink>,
    caller: NodeId,
    tool: Option<ToolName>,
    reason: String,
) -> anyhow::Error {
    crate::host::audit::denied(audit, caller, tool, &reason).await; // audit: denied
    deny(send, reason.clone()).await;
    Refused(reason).into()
}

/// Refuse a peer not known to be a member: send `reason`, trace `detail`
/// (throttled), and write nothing to the call log — anyone can connect, so a
/// stranger must not be able to fill the log or crowd out real calls.
async fn refuse_stranger<W: AsyncWrite + Unpin>(
    send: &mut W,
    caller: NodeId,
    reason: &str,
    detail: &str,
) -> anyhow::Error {
    STRANGERS.refused("session", caller, detail);
    deny(send, reason.to_string()).await;
    Refused(reason.to_string()).into()
}

/// The v2 responder over an authenticated bi-stream (see
/// [`serve_session_permitted`], here with no pre-auth permit to return).
#[cfg(test)]
pub(crate) async fn serve_services_session<S, R>(
    send: S,
    recv: R,
    caller: NodeId,
    host: &crate::host::gate::ServicesHost,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<()>
where
    S: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    serve_session_permitted(send, recv, caller, host, None, shutdown).await
}

/// The v2 responder over an authenticated bi-stream: read the
/// [`Frame::Hello`] (at most [`MAX_HELLO_FRAME`]) and the [`Frame::Invoke`]
/// (at most [`MAX_INVOKE_FRAME`]), then decide by **this host's** signed
/// state (re-read now, so a removal applies on the next dial):
///
/// 1. the caller's membership credential, and that the state lists it
///    ([`ServicesHost::check_member`](crate::host::gate::ServicesHost::check_member)).
///    Anyone else hears only [`NOT_ADMITTED`](crate::host::gate::NOT_ADMITTED),
///    costs no token verification, and is traced, not logged;
/// 2. its ID token (verified under `identity.issuers`, bound to `caller`);
/// 3. [`gate::admit`](crate::host::gate::admit): fresh → registered and
///    assigned here → registry role → `also_require`;
/// 4. whether `host.json` implements the service.
///
/// A member's refusal is a [`Frame::Denied`] plus a call-log record.
/// `preauth` is returned once this is decided.
///
/// Admitted: the call's `Started` is appended to the call log and `fsync`ed
/// **before** anything else — if it can't be, the call is refused with
/// [`DENY_LOG_UNAVAILABLE`] and nothing runs. Then a [`Frame::HelloAck`]
/// carrying this host's membership and state version, plus the state itself
/// when the caller's copy is older (the cheapest pull), then the service's
/// command with the caller's argv appended (never a shell), in its `cwd`
/// with its `env`, and the server-derived `WIRES_*` variables.
pub(crate) async fn serve_session_permitted<S, R>(
    mut send: S,
    mut recv: R,
    caller: NodeId,
    host: &crate::host::gate::ServicesHost,
    preauth: Option<tokio::sync::OwnedSemaphorePermit>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<()>
where
    S: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    let audit = host.audit.as_ref();
    let first = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        read_frame_within(&mut recv, MAX_HELLO_FRAME),
    )
    .await;
    let hello = match first {
        Ok(Ok(Some(Frame::Hello(hello)))) => hello,
        Ok(Ok(Some(_))) => {
            let reason = "first frame was not a hello";
            return Err(refuse_stranger(&mut send, caller, reason, reason).await);
        }
        Ok(Ok(None)) => {
            let reason = "connection closed before hello";
            return Err(refuse_stranger(&mut send, caller, reason, reason).await);
        }
        Ok(Err(e)) => {
            let detail = format!("unreadable hello: {e:#}");
            return Err(refuse_stranger(&mut send, caller, "unreadable hello", &detail).await);
        }
        Err(_) => {
            let reason = "timed out waiting for hello";
            return Err(refuse_stranger(&mut send, caller, reason, reason).await);
        }
    };
    let invocation = match read_invocation(&mut recv).await {
        Ok(invocation) => invocation,
        Err(e) => {
            let detail = format!("{e:#}");
            return Err(refuse_stranger(&mut send, caller, DENY_INVOKE_REQUIRED, &detail).await);
        }
    };
    let tool = invocation.tool.clone();
    let service = library::ServiceName::from(tool.clone());
    let now = crate::now_unix();

    let state = match host.state() {
        Ok(state) => state,
        Err(e) => {
            // The host's own fault, not the caller's: an operator error.
            tracing::warn!("signed state unusable: {e:#}");
            let reason = "responder configuration error";
            deny(&mut send, reason.to_string()).await;
            return Err(Refused(reason.to_string()).into());
        }
    };
    // Membership first: a stranger costs no token verification (no JWKS
    // fetch, no identity-index entry) and no call-log entry.
    if let Err(detail) = host.check_member(&state, &hello.membership, caller, now) {
        let reason = crate::host::gate::NOT_ADMITTED;
        return Err(refuse_stranger(&mut send, caller, reason, &detail).await);
    }
    // A member from here on: every refusal is logged.
    let (principal, missing) = host.principal(caller, hello.id_token.as_ref(), now).await;
    let admitted = match host.decide(
        &state,
        caller,
        principal.as_ref(),
        missing.as_deref(),
        &service,
        now,
    ) {
        Ok(admitted) => admitted,
        Err(reason) => {
            return Err(refuse_member(&mut send, audit, caller, Some(tool), reason).await);
        }
    };
    // Only an admitted caller learns whether this host implements it.
    let Some(svc) = host.config.services.get(&service) else {
        let reason = format!("service {service} is not implemented on this host");
        return Err(refuse_member(&mut send, audit, caller, Some(tool), reason).await);
    };
    drop(preauth);
    let version = admitted.state_version;
    if hello.state_version > version {
        // The caller saw a newer state than ours; we still decide by ours
        // (its state pull catches this host up).
        tracing::info!(
            caller = %caller.hex(),
            theirs = hello.state_version.0,
            ours = version.0,
            "caller holds a newer signed state"
        );
    }
    tracing::info!(
        caller = %caller.hex(),
        service = %service,
        role = %admitted.role,
        state_version = version.0,
        "session accepted"
    );
    // The call is logged before it can run; a call the log can't take
    // doesn't run.
    let call_audit = match crate::host::audit::CallAudit::start(
        audit,
        caller,
        principal.clone(),
        tool.clone(),
        invocation.argv.as_slice(),
        Some(version.0),
        Some(admitted.role.as_str().to_string()),
    )
    .await
    {
        Ok(call_audit) => call_audit,
        Err(e) => {
            tracing::error!(
                caller = %caller.hex(),
                service = %service,
                "call refused: its start could not be logged: {e}"
            );
            deny(&mut send, DENY_LOG_UNAVAILABLE.to_string()).await;
            return Err(Refused(DENY_LOG_UNAVAILABLE.to_string()).into());
        }
    };
    let ack = Frame::HelloAck(library::HelloAck {
        membership: host.membership.clone(),
        state_version: version,
        newer_state: (hello.state_version < version).then(|| state.clone()),
    });
    if let Err(e) = write_frame(&mut send, &ack).await {
        // The caller is gone before anything ran: close the logged call.
        if let Some(call_audit) = call_audit {
            call_audit.finish(-1).await;
        }
        return Err(e);
    }

    let (program, fixed) = svc
        .command
        .split_first()
        .ok_or_else(|| anyhow!("empty service command"))?;
    let mut cmd = Command::new(program);
    cmd.args(fixed).args(invocation.argv.as_slice());
    if let Some(cwd) = &svc.cwd {
        cmd.current_dir(cwd);
    }
    // Scrub every inherited `WIRES_*`, then the service's own env, then the
    // server-derived values (which always win; `host.json` can't set them).
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("WIRES_") {
            cmd.env_remove(key);
        }
    }
    cmd.envs(&svc.env)
        .env("WIRES_CALLER_NODE", caller.hex())
        .env("WIRES_FABRIC_ROOT", host.trust_root.hex())
        .env(
            "WIRES_MEMBERSHIP_NOT_AFTER",
            hello.membership.not_after.to_string(),
        )
        .env("WIRES_STATE_VERSION", version.0.to_string())
        .env("WIRES_SERVICE", service.as_str())
        .env("WIRES_TOOL", tool.as_str())
        .env("WIRES_ROLE", admitted.role.as_str())
        // The host's own home, so a service can `wires push` back to its
        // caller through this `serve` (card 23).
        .env("WIRES_HOME", host.keystore.path(""));
    if let Some(email) = principal.as_ref().and_then(|p| p.email.as_deref()) {
        cmd.env("WIRES_CALLER_EMAIL", email);
    }
    bridge_child(send, recv, cmd, program, shutdown, call_audit).await
}

// ---------------------------------------------------------------------------
// Dialer (`wires call`, `wires mcp`)
// ---------------------------------------------------------------------------

/// The responder refused the handshake and said why.
///
/// Distinguishes an *authorization* failure (the credential this dialer
/// presented was not acceptable — removed, expired, not in a role) from every
/// local or transport failure, so `wires call` can exit with a dedicated
/// code and print the responder's own words. Hand-rolled rather than derived:
/// `//wires` deliberately carries no `thiserror` dependency.
#[derive(Debug)]
pub struct Denied {
    reason: String,
}

impl Denied {
    /// Wrap the responder's stated reason.
    pub(crate) fn new(reason: String) -> Self {
        Self { reason }
    }

    /// The responder's stated reason, verbatim (e.g. `membership rejected:
    /// revoked`).
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "denied by responder: {}", self.reason)
    }
}

impl std::error::Error for Denied {}

/// What a service call came to: [`Dialed`] plus the host that answered.
#[derive(Debug)]
pub(crate) struct ServiceDialed {
    /// The host that ran the call.
    pub(crate) host: NodeId,
    /// The remote exit code and any newer state.
    pub(crate) dialed: Dialed,
}

/// Card 27's dial: try each of `targets` (a service's hosts, in the caller's
/// preferred order) until one connects within `dial_timeout`, then open with
/// `hello`, send `invocation` and bridge stdio on that one.
///
/// Fails over **only on a dial failure**: once a host has answered, its
/// refusal ([`Denied`]) or a mid-session error is final (it decided, and
/// stdin may already be spent). Errors if no target connects, naming each
/// failure. Does not close `endpoint`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn call_service_on<R, W, E>(
    endpoint: &Endpoint,
    targets: &[EndpointAddr],
    dial_timeout: std::time::Duration,
    hello: Hello,
    invocation: Invocation,
    stdin: R,
    stdout: W,
    stderr: E,
) -> Result<ServiceDialed>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let mut failures = Vec::new();
    for target in targets {
        let host = to_node_id(&target.id);
        let conn = match tokio::time::timeout(dial_timeout, endpoint.connect(target.clone(), ALPN))
            .await
        {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                tracing::debug!(host = %host.hex(), "dial failed: {e}");
                failures.push(format!("{}: {e}", &host.hex()[..8]));
                continue;
            }
            Err(_) => {
                tracing::debug!(host = %host.hex(), "dial timed out");
                failures.push(format!(
                    "{}: no answer within {}s",
                    &host.hex()[..8],
                    dial_timeout.as_secs_f32()
                ));
                continue;
            }
        };
        let host = to_node_id(&conn.remote_id());
        let (send, recv) = conn.open_bi().await.context("opening bi-stream")?;
        let dialed = dial_opened(
            send,
            recv,
            hello,
            invocation,
            Some(host),
            stdin,
            stdout,
            stderr,
        )
        .await;
        conn.close(0u32.into(), b"done");
        return dialed.map(|dialed| ServiceDialed { host, dialed });
    }
    if failures.is_empty() {
        bail!("no host to dial");
    }
    bail!("no host answered ({})", failures.join("; "))
}

/// What a finished dial came to: the remote exit code and, when the host's
/// `HelloAck` carried one, the newer signed state it handed back.
#[derive(Debug)]
pub(crate) struct Dialed {
    /// The remote child's exit code.
    pub(crate) exit: i32,
    /// The host's newer state (card 27), for the caller to adopt.
    pub(crate) newer_state: Option<SignedState>,
}

/// The dialer half of a session over an established bi-stream. Presents the
/// `hello`, then reads the host's [`HelloAck`](library::HelloAck); when
/// `verify_target` is `Some` (always, from [`call_service_on`]), verifies the responder's membership against the dialer's own
/// fabric root and the authenticated target id **before** any stdin is
/// forwarded. On failure, aborts with no stdin sent.
///
/// The [`Frame::Invoke`] carrying `invocation` follows the opening
/// immediately, without waiting for the ack.
///
/// Errors if the session ends **without** an [`Frame::Exit`] — a responder that
/// closes mid-session is a failure, not a silent success.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dial_opened<S, R, I, W, E>(
    mut send: S,
    mut recv: R,
    hello: Hello,
    invocation: Invocation,
    verify_target: Option<NodeId>,
    stdin: I,
    mut stdout: W,
    mut stderr: E,
) -> Result<Dialed>
where
    S: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin,
    I: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    // The dialer's own fabric root is the authority for verifying the responder.
    let fabric_root = hello.membership.fabric;
    write_frame(&mut send, &Frame::Hello(hello)).await?;
    write_frame(&mut send, &Frame::Invoke(invocation)).await?;

    // Read the responder's ack first (it is always the responder's first frame).
    let (ack_membership, newer_state) = match read_frame(&mut recv).await? {
        Some(Frame::HelloAck(ack)) => (ack.membership, ack.newer_state),
        // Refused: surface the responder's reason. No stdin task has been
        // spawned yet, so nothing was forwarded and nothing hit local stdout.
        Some(Frame::Denied { reason }) => return Err(Denied::new(reason).into()),
        Some(_) => bail!("the host's first frame was not a hello ack"),
        None => bail!("the host closed before sending a hello ack"),
    };
    // Verify the service is a fabric member before streaming stdin.
    // Credential-only (root-vouched + TTL); reverse roster-freshness is deferred.
    if let Some(target_id) = verify_target {
        check_inclusion(&ack_membership, fabric_root, target_id, crate::now_unix())
            .map_err(|e| anyhow!("responder membership rejected (no stdin sent): {e}"))?;
    }

    // Local stdin -> Stdin frames, then shut down the send direction (EOF).
    let stdin_task = tokio::spawn(async move {
        let mut stdin = stdin;
        let mut buf = vec![0u8; PUMP_BUF];
        loop {
            let n = stdin.read(&mut buf).await.context("reading local stdin")?;
            if n == 0 {
                break;
            }
            write_frame(
                &mut send,
                &Frame::Stdin(Chunk::from_bytes(buf[..n].to_vec())),
            )
            .await?;
        }
        send.shutdown().await.ok();
        Ok::<(), anyhow::Error>(())
    });

    // Server frames -> local stdout/stderr; Exit ends the session.
    let mut code = 0;
    let mut saw_exit = false;
    loop {
        match read_frame(&mut recv).await? {
            Some(Frame::Stdout(chunk)) => stdout.write_all(chunk.as_bytes()).await?,
            Some(Frame::Stderr(chunk)) => stderr.write_all(chunk.as_bytes()).await?,
            Some(Frame::Exit(c)) => {
                code = c;
                saw_exit = true;
                tracing::info!(code, "remote child exited");
                break;
            }
            // A responder may also refuse mid-stream (e.g. a future re-check);
            // treat it exactly like a refusal at the ack.
            Some(Frame::Denied { reason }) => {
                stdin_task.abort();
                return Err(Denied::new(reason).into());
            }
            Some(_) => {} // ignore unexpected frames from the responder
            None => break,
        }
    }
    stdout.flush().await.ok();
    stderr.flush().await.ok();
    stdin_task.abort();
    if !saw_exit {
        bail!("session ended without an exit code (responder closed early?)");
    }
    Ok(Dialed {
        exit: code,
        newer_state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::keystore::Keystore;
    use crate::host::config_v2::HostConfigV2;
    use crate::host::gate::ServicesHost;
    use library::{Argv, Membership, RoleName, Service, ServiceName, State, StateVersion};

    /// A shutdown signal that never fires: the dialer stays present for the
    /// whole session.
    fn never() -> std::future::Pending<()> {
        std::future::pending::<()>()
    }

    /// The fabric root, the host and the caller every session test uses.
    fn root() -> NodeIdentity {
        NodeIdentity::from_seed([1u8; 32])
    }
    fn host_id() -> NodeIdentity {
        NodeIdentity::from_seed([4u8; 32])
    }
    fn caller_id() -> NodeIdentity {
        NodeIdentity::from_seed([2u8; 32])
    }

    /// A host implementing service `t` as `command`, allowed to every
    /// `member`; the caller and the host are the members of its signed state.
    fn host_running(command: &[&str]) -> Arc<ServicesHost> {
        Arc::new(host_unshared(command))
    }

    /// [`host_running`], logging to `audit`.
    fn host_logging(command: &[&str], audit: AuditSink) -> Arc<ServicesHost> {
        let mut host = host_unshared(command);
        host.audit = Some(audit);
        Arc::new(host)
    }

    /// [`host_running`], before it is shared.
    fn host_unshared(command: &[&str]) -> ServicesHost {
        let (root, host, caller) = (root(), host_id(), caller_id());
        let home = crate::testutil::temp_dir();
        let ks = Keystore::at(&home);
        let mut s = State::new(root.node_id());
        s.version = StateVersion(1);
        s.issued = crate::now_unix();
        s.not_after = i64::MAX;
        s.members.extend([host.node_id(), caller.node_id()]);
        s.hosts.insert(host.node_id());
        s.services.insert(
            ServiceName::new("t").unwrap(),
            Service {
                description: String::new(),
                allow: vec![RoleName::member()],
                hosts: vec![host.node_id()],
                readers: vec![],
            },
        );
        let signed = s.sign(&root).unwrap();
        crate::state::store::adopt_if_newer(&ks, &signed, root.node_id(), crate::now_unix())
            .unwrap();
        let config = HostConfigV2::parse(&format!(
            r#"{{"version":2,"services":{{"t":{{"command":{}}}}}}}"#,
            serde_json::to_string(command).unwrap()
        ))
        .unwrap();
        crate::host::serve::services_host(
            host.node_id(),
            Membership::mint(&root, host.node_id(), 0, i64::MAX).unwrap(),
            Arc::new(ks),
            &home,
            config,
        )
        .unwrap()
    }

    /// The caller's `Hello` (membership under the root, state version 1, no
    /// ID token: service `t` is open to every member).
    fn hello() -> Hello {
        Hello {
            membership: Membership::mint(&root(), caller_id().node_id(), 0, i64::MAX).unwrap(),
            state_version: StateVersion(1),
            id_token: None,
        }
    }

    /// An invocation of `t` with `args`.
    fn invoke(args: &[&str]) -> Invocation {
        Invocation {
            tool: ToolName::new("t").unwrap(),
            argv: Argv::new(args.iter().map(|a| a.to_string()).collect()).unwrap(),
        }
    }

    /// Run a whole session over in-memory duplex pipes (no iroh): the
    /// dialer's result plus captured stdout/stderr.
    async fn run_session(
        command: &[&str],
        args: &[&str],
        input: &[u8],
    ) -> (Result<i32>, Vec<u8>, Vec<u8>) {
        let host = host_running(command);
        let (c2s_w, c2s_r) = tokio::io::duplex(64 * 1024);
        let (s2c_w, s2c_r) = tokio::io::duplex(64 * 1024);
        let caller = caller_id().node_id();
        let srv = tokio::spawn(async move {
            serve_services_session(s2c_w, c2s_r, caller, &host, never()).await
        });
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = dial_opened(
            c2s_w,
            s2c_r,
            hello(),
            invoke(args),
            Some(host_id().node_id()),
            std::io::Cursor::new(input.to_vec()),
            &mut out,
            &mut err,
        )
        .await
        .map(|d| d.exit);
        let _ = srv.await;
        (code, out, err)
    }

    #[test]
    fn key_bridge_is_consistent() {
        let id = NodeIdentity::from_seed([42u8; 32]);
        let iroh_pub = secret_key(&id).public();
        assert_eq!(iroh_pub.as_bytes(), id.node_id().as_bytes());
        assert_eq!(to_node_id(&iroh_pub), id.node_id());
    }

    #[tokio::test]
    async fn frames_round_trip_over_a_pipe() {
        let frames = vec![
            Frame::Hello(hello()),
            Frame::Invoke(invoke(&["x"])),
            Frame::Stdin(Chunk::from_bytes(b"hi".to_vec())),
            Frame::Stdout(Chunk::from_bytes(Vec::new())),
            Frame::Exit(7),
        ];
        let (mut w, mut r) = tokio::io::duplex(64 * 1024);
        for f in &frames {
            write_frame(&mut w, f).await.unwrap();
        }
        drop(w);
        let mut got = Vec::new();
        while let Some(f) = read_frame(&mut r).await.unwrap() {
            got.push(f);
        }
        assert_eq!(got, frames);
    }

    #[tokio::test]
    async fn read_frame_rejects_oversized_length() {
        // A length prefix claiming ~4 GiB must be refused without allocating it.
        let mut cur = std::io::Cursor::new(vec![0xff, 0xff, 0xff, 0xff]);
        assert!(read_frame(&mut cur).await.is_err());
    }

    #[test]
    fn truncate_reason_cuts_on_a_char_boundary() {
        let short = "membership rejected: revoked".to_string();
        assert_eq!(truncate_reason(short.clone()), short);
        let long = "é拒".repeat(400);
        let cut = truncate_reason(long);
        assert!(cut.len() <= MAX_REASON);
        assert!(cut.len() > MAX_REASON - 4);
    }

    #[tokio::test]
    async fn session_echoes_stdin() {
        let (code, out, err) = run_session(&["cat"], &[], b"hello over wires").await;
        assert_eq!(code.unwrap(), 0);
        assert_eq!(out, b"hello over wires");
        assert!(err.is_empty());
    }

    #[tokio::test]
    async fn session_propagates_nonzero_exit_and_routes_stderr() {
        let (code, out, err) =
            run_session(&["sh", "-c", "printf oops 1>&2; exit 3"], &[], b"").await;
        assert_eq!(code.unwrap(), 3);
        assert!(out.is_empty());
        assert_eq!(err, b"oops");
    }

    /// `wires call orders-db -- "select 1"` from a terminal: the child exits
    /// without reading stdin while the dialer's stdin never reaches EOF. The
    /// session must still end with the child's exit code.
    #[tokio::test]
    async fn session_ends_when_the_child_exits_with_dialer_stdin_still_open() {
        let host = host_running(&["sh", "-c", "printf done"]);
        let (c2s_w, c2s_r) = tokio::io::duplex(64 * 1024);
        let (s2c_w, s2c_r) = tokio::io::duplex(64 * 1024);
        let caller = caller_id().node_id();
        let srv = tokio::spawn(async move {
            serve_services_session(s2c_w, c2s_r, caller, &host, never()).await
        });
        let (_stdin_held_open, stdin) = tokio::io::duplex(64);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dialed = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            dial_opened(
                c2s_w,
                s2c_r,
                hello(),
                invoke(&[]),
                None,
                stdin,
                &mut out,
                &mut err,
            ),
        )
        .await
        .expect("the session hung waiting for the dialer's stdin to close");
        assert_eq!(dialed.unwrap().exit, 0);
        assert_eq!(out, b"done");
        tokio::time::timeout(std::time::Duration::from_secs(10), srv)
            .await
            .expect("the host hung after the child exited")
            .unwrap()
            .unwrap();
    }

    /// A dialer that vanishes mid-session takes the remote child with it.
    #[tokio::test]
    async fn child_is_killed_when_the_dialer_vanishes() {
        let host = host_running(&["sh", "-c", "sleep 30"]);
        let mut opening = Frame::Hello(hello()).encode().unwrap();
        opening.extend(Frame::Invoke(invoke(&[])).encode().unwrap());
        let recv = std::io::Cursor::new(opening);
        let send: Vec<u8> = Vec::new();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let caller = caller_id().node_id();
        let srv = tokio::spawn(async move {
            serve_services_session(send, recv, caller, &host, async move {
                let _ = rx.await;
            })
            .await
        });
        tx.send(()).ok();
        let finished = tokio::time::timeout(std::time::Duration::from_secs(5), srv).await;
        assert!(
            finished.is_ok(),
            "the session must return once the dialer is gone, not outlive the child"
        );
    }

    /// What `host` answers to the raw `bytes` from `caller`: the denial
    /// reason.
    async fn refusal_by(host: &ServicesHost, bytes: Vec<u8>, caller: NodeId) -> String {
        let (send, mut answer) = tokio::io::duplex(64 * 1024);
        let r =
            serve_services_session(send, std::io::Cursor::new(bytes), caller, host, never()).await;
        assert!(r.is_err());
        match read_frame(&mut answer).await.unwrap() {
            Some(Frame::Denied { reason }) => reason,
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    /// `frames`, encoded back to back.
    fn encoded(frames: &[Frame]) -> Vec<u8> {
        frames.iter().flat_map(|f| f.encode().unwrap()).collect()
    }

    /// What the host answers to `frames` from `caller`: the denial reason.
    async fn refusal(frames: &[Frame], caller: NodeId) -> String {
        refusal_by(&host_running(&["cat"]), encoded(frames), caller).await
    }

    /// A key that is not in the state, with a membership the root really
    /// minted for it (so only the state's member list keeps it out).
    fn stranger(seed: u8) -> (NodeId, Hello) {
        let id = NodeIdentity::from_seed([seed; 32]).node_id();
        let hello = Hello {
            membership: Membership::mint(&root(), id, 0, i64::MAX).unwrap(),
            state_version: StateVersion(1),
            id_token: None,
        };
        (id, hello)
    }

    #[tokio::test]
    async fn the_host_refuses_out_of_turn_frames() {
        let caller = caller_id().node_id();
        let r = refusal(&[Frame::Invoke(invoke(&[]))], caller).await;
        assert!(r.contains("not a hello"), "{r}");
        let r = refusal(&[Frame::Hello(hello()), Frame::Exit(0)], caller).await;
        assert_eq!(r, DENY_INVOKE_REQUIRED);
    }

    /// Whatever keeps a peer out — someone else's credential, a credential
    /// from another fabric, or a genuine one the state doesn't list — it
    /// hears the one fixed sentence: no reason, no state version.
    #[tokio::test]
    async fn a_non_member_hears_only_the_fixed_refusal() {
        let open = [Frame::Hello(hello()), Frame::Invoke(invoke(&[]))];
        let theirs = refusal(&open, NodeIdentity::from_seed([9u8; 32]).node_id()).await;
        let other_root = NodeIdentity::from_seed([8u8; 32]);
        let (id, _) = stranger(7);
        let foreign = Hello {
            membership: Membership::mint(&other_root, id, 0, i64::MAX).unwrap(),
            ..hello()
        };
        let foreign = refusal(&[Frame::Hello(foreign), Frame::Invoke(invoke(&[]))], id).await;
        let (id, genuine) = stranger(7);
        let unlisted = refusal(&[Frame::Hello(genuine), Frame::Invoke(invoke(&[]))], id).await;
        for r in [theirs, foreign, unlisted] {
            assert_eq!(r, crate::host::gate::NOT_ADMITTED);
        }
    }

    /// A non-member's ID token is never looked at: no verification, so no
    /// JWKS fetch and no identity-index entry. (A member's is.)
    #[tokio::test]
    async fn a_non_member_never_has_its_token_verified() {
        let host = host_running(&["true"]);
        let token =
            library::IdToken::new("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIn0.");
        let (id, mut hello_s) = stranger(7);
        hello_s.id_token = Some(token.clone());
        let r = refusal_by(
            &host,
            encoded(&[Frame::Hello(hello_s), Frame::Invoke(invoke(&[]))]),
            id,
        )
        .await;
        assert_eq!(r, crate::host::gate::NOT_ADMITTED);
        assert!(
            host.identities.nodes().is_empty(),
            "a stranger's token was verified"
        );
        // The member's token is verified (and fails: its issuer isn't trusted).
        let member = Hello {
            id_token: Some(token),
            ..hello()
        };
        let (send, _answer) = tokio::io::duplex(64 * 1024);
        let bytes = encoded(&[Frame::Hello(member), Frame::Invoke(invoke(&[]))]);
        let caller = caller_id().node_id();
        let _ =
            serve_services_session(send, std::io::Cursor::new(bytes), caller, &host, never()).await;
        assert_eq!(host.identities.nodes(), [caller]);
    }

    /// The card's flood: a thousand connections from keys that aren't
    /// members — junk, silence, out-of-turn frames, someone else's
    /// credential, a genuine but unlisted one — write nothing to the call
    /// log. A member's refusal is still logged.
    #[tokio::test]
    async fn strangers_leave_nothing_in_the_log_and_members_do() {
        let (sink, mut records) = AuditSink::channel(2048);
        let host = host_logging(&["true"], sink);
        for n in 0..1000u32 {
            let key = NodeIdentity::from_seed({
                let mut s = [0x55u8; 32];
                s[..4].copy_from_slice(&n.to_be_bytes());
                s
            });
            let genuine = Hello {
                membership: Membership::mint(&root(), key.node_id(), 0, i64::MAX).unwrap(),
                ..hello()
            };
            let bytes = match n % 5 {
                0 => vec![0xde, 0xad, 0xbe, 0xef, 1, 2, 3],
                1 => Vec::new(),
                2 => encoded(&[Frame::Invoke(invoke(&[]))]),
                3 => encoded(&[Frame::Hello(hello()), Frame::Invoke(invoke(&[]))]),
                _ => encoded(&[Frame::Hello(genuine), Frame::Invoke(invoke(&[]))]),
            };
            let (send, _answer) = tokio::io::duplex(64 * 1024);
            let r = serve_services_session(
                send,
                std::io::Cursor::new(bytes),
                key.node_id(),
                &host,
                never(),
            )
            .await;
            assert!(r.is_err());
        }
        assert!(
            records.try_recv().is_err(),
            "a stranger's refusal reached the call log"
        );
        let unknown = Invocation {
            tool: ToolName::new("nope").unwrap(),
            argv: Argv::default(),
        };
        let r = refusal_by(
            &host,
            encoded(&[Frame::Hello(hello()), Frame::Invoke(unknown)]),
            caller_id().node_id(),
        )
        .await;
        match records.recv().await {
            Some(library::AuditRecord::Denied { caller, reason, .. }) => {
                assert_eq!(caller, caller_id().node_id());
                assert_eq!(reason, r);
            }
            other => panic!("expected the member's refusal, got {other:?}"),
        }
    }

    /// The card's acceptance: a call whose `Started` can't be logged is
    /// refused, and its command never runs.
    #[tokio::test]
    async fn a_call_whose_start_cannot_be_logged_never_runs() {
        let dir = crate::testutil::temp_dir();
        let marker = dir.join("ran");
        let (sink, mut queue) = AuditSink::log_queue(4);
        tokio::spawn(async move {
            while let Some(p) = queue.recv().await {
                p.answer(Err("disk full".into()));
            }
        });
        let touch = format!("touch {}", marker.display());
        let host = host_logging(&["sh", "-c", &touch], sink);
        let r = refusal_by(
            &host,
            encoded(&[Frame::Hello(hello()), Frame::Invoke(invoke(&[]))]),
            caller_id().node_id(),
        )
        .await;
        assert_eq!(r, DENY_LOG_UNAVAILABLE);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!marker.exists(), "the command ran without a logged start");
    }

    /// A logged call: `Started` then `Finished`, and the child ran after
    /// `Started` was in the log.
    #[tokio::test]
    async fn a_call_is_logged_started_then_finished() {
        let (sink, mut records) = AuditSink::channel(8);
        let host = host_logging(&["printf", "ok"], sink);
        let (c2s_w, c2s_r) = tokio::io::duplex(64 * 1024);
        let (s2c_w, s2c_r) = tokio::io::duplex(64 * 1024);
        let caller = caller_id().node_id();
        let srv = tokio::spawn(async move {
            serve_services_session(s2c_w, c2s_r, caller, &host, never()).await
        });
        let mut out = Vec::new();
        let dialed = dial_opened(
            c2s_w,
            s2c_r,
            hello(),
            invoke(&[]),
            None,
            std::io::Cursor::new(Vec::new()),
            &mut out,
            &mut Vec::new(),
        )
        .await
        .unwrap();
        srv.await.unwrap().unwrap();
        assert_eq!((dialed.exit, out.as_slice()), (0, &b"ok"[..]));
        let Some(library::AuditRecord::Started { call, .. }) = records.recv().await else {
            panic!("expected Started first");
        };
        let Some(library::AuditRecord::Finished {
            call: done, exit, ..
        }) = records.recv().await
        else {
            panic!("expected Finished second");
        };
        assert_eq!((done, exit), (call, 0));
    }

    /// A `Hello` whose prefix claims 16 MiB is refused at the prefix: the
    /// host neither waits for nor allocates the body. So is an oversized
    /// `Invoke`.
    #[tokio::test]
    async fn oversized_opening_frames_are_refused_at_the_prefix() {
        for (prefix, before) in [
            (16u32 * 1024 * 1024, Vec::new()),
            (
                (MAX_INVOKE_FRAME + 1) as u32,
                Frame::Hello(hello()).encode().unwrap(),
            ),
        ] {
            let host = host_running(&["true"]);
            let (mut to_host, from_caller) = tokio::io::duplex(64 * 1024);
            let (send, mut answer) = tokio::io::duplex(64 * 1024);
            to_host.write_all(&before).await.unwrap();
            to_host.write_all(&prefix.to_be_bytes()).await.unwrap();
            to_host.write_all(&[8u8; 16]).await.unwrap();
            // `to_host` stays open: a host that waited for the body would hang.
            let caller = caller_id().node_id();
            let r = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                serve_services_session(send, from_caller, caller, &host, never()),
            )
            .await
            .expect("the host waited for an oversized body");
            assert!(r.is_err());
            let Some(Frame::Denied { .. }) = read_frame(&mut answer).await.unwrap() else {
                panic!("expected a denial");
            };
            drop(to_host);
        }
        let mut cur = std::io::Cursor::new([0u8, 1, 0, 1].to_vec());
        let e = read_frame_within(&mut cur, MAX_HELLO_FRAME)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("too large"), "{e}");
    }

    /// A body shorter than its prefix claims is an error, not a zero-filled
    /// frame.
    #[tokio::test]
    async fn a_short_body_is_truncated() {
        let mut bytes = Frame::Exit(1).encode().unwrap();
        bytes.pop();
        let e = read_frame(&mut std::io::Cursor::new(bytes))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("truncated"), "{e}");
    }

    /// At most `MAX_PREAUTH_SESSIONS` sessions wait for a decision; a
    /// finished one makes room.
    #[test]
    fn pre_auth_sessions_are_capped() {
        let protocol = ServicesProtocol::new(host_running(&["true"]));
        let held: Vec<_> = (0..MAX_PREAUTH_SESSIONS)
            .map(|_| protocol.enter().expect("room"))
            .collect();
        assert!(protocol.enter().is_none());
        drop(held);
        assert!(protocol.enter().is_some());
    }

    /// The refusal trace: the first event reports, the rest within
    /// `EVERY_MS` are only counted, and the next report says how many.
    #[test]
    fn the_throttle_reports_at_most_once_per_interval() {
        let t = Throttle::new();
        assert_eq!(t.tick(1_000), Some(1));
        for _ in 0..99 {
            assert_eq!(t.tick(1_001), None);
        }
        assert_eq!(t.tick(1_000 + Throttle::EVERY_MS), Some(100));
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(16))]

        /// Whatever valid `Argv` a caller sends reaches the child's argv
        /// byte-for-byte: `printf '%s\0'` echoes each argument NUL-terminated,
        /// after a marker that separates the service's own argv from the
        /// caller's.
        #[test]
        fn any_argv_reaches_the_child_verbatim(
            args in proptest::collection::vec("[^\u{0}]{0,16}", 0..8),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let (res, out, _) = rt.block_on(run_session(&["printf", "%s\\0", "MARK"], &refs, b""));
            proptest::prop_assert_eq!(res.unwrap(), 0);
            let mut expected = b"MARK\0".to_vec();
            for a in &args {
                expected.extend_from_slice(a.as_bytes());
                expected.push(0);
            }
            proptest::prop_assert_eq!(out, expected);
        }
    }
}

//! The iroh session transport: bind/dial, the `Hello`, and the stdio bridge.
//!
//! `library` stays pure (no iroh/tokio); this module is where the
//! key-addressed session meets the iroh QUIC endpoint. The session ALPN is
//! [`ALPN`]. A caller opens a bi-stream and sends a
//! [`Frame::Hello`] — the policy version it holds and its IdP ID token,
//! which is what admits it — followed at once by
//! a [`Frame::Invoke`] naming a service plus per-call arguments. The host
//! ([`serve_session_permitted`]) decides by the signed policy it holds, re-read
//! per connection (see [`gate`](crate::host::gate)), then execs the
//! service's fixed argv with the caller's arguments appended — never through
//! a shell — with the verified caller identity injected into its
//! environment, and bridges its stdio over tagged frames.
//!
//! The properties this module exists to preserve:
//!
//! - **Refusals are legible.** A host that turns a caller away sends a
//!   [`Frame::Denied`] carrying the reason before closing, which the dialer
//!   surfaces as a [`Denied`] error (`wires call` exits 77). Nothing the
//!   dialer sends or receives on a refused session ever reaches its stdout.
//! - **Refusals are current.** The signed policy is re-read on every
//!   connection, so a `wires remove` takes effect on the next dial rather
//!   than the next restart.
//! - **Strangers are cheap.** Anyone can open a connection, so until the
//!   host has admitted the peer it reads small frames only
//!   ([`MAX_HELLO_FRAME`], [`MAX_INVOKE_FRAME`]), holds at most
//!   [`MAX_PREAUTH_SESSIONS`] such sessions, spends one token check on it
//!   (keys fetched only for a trusted issuer, an unknown `kid` refetched at
//!   most once per window), says only
//!   [`NOT_ADMITTED`](crate::host::gate::NOT_ADMITTED) (or that its sign-in
//!   expired, or the IdP is unreachable), and traces the refusal throttled
//!   ([`Throttle`]), so strangers can't flood the log.
//! - **One log line per call.** An admitted call's end, and an identified
//!   caller's refusal, is one `info` line
//!   ([`call_trace`](crate::host::call_trace)); nothing else is kept.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::presets::N0;
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};

use library::{Chunk, Frame, Hello, HelloAck, Invocation, NodeId, NodeIdentity, ServiceName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;

use crate::host::call_trace::CallTrace;
use crate::host::gate::Implementation;
use crate::host::service::Running;
use tokio::sync::mpsc;

/// The custom ALPN identifying a wires session, which opens with a
/// [`Hello`].
pub const ALPN: &[u8] = b"wires/session/1";

/// Read buffer size for pumping child / local stdio into frames.
const PUMP_BUF: usize = 64 * 1024;

/// Largest frame body accepted off the wire once a session is admitted.
/// Bounds what an admitted caller can make the host buffer; generous versus the 64 KiB
/// stdio chunk size, but far below "exhaust memory".
const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Largest [`Frame::Hello`] a host reads, before it knows who is asking: a
/// policy version and an ID token fit in a few KiB.
pub(crate) const MAX_HELLO_FRAME: usize = 64 * 1024;

/// Largest [`Frame::Invoke`] a host reads before admitting the caller. An
/// [`Argv`](library::Argv) holds at most [`MAX_ARGV_BYTES`](library::MAX_ARGV_BYTES),
/// but canonical JSON may escape a control character as six bytes (`\u001f`)
/// and adds quotes and commas per argument, so the cap is eight times that
/// (512 KiB) — the most a valid invocation can take, and no more.
pub(crate) const MAX_INVOKE_FRAME: usize = 8 * library::MAX_ARGV_BYTES;

/// How many sessions a host holds open at once *before* deciding who they are
/// (reading `Hello`/`Invoke`, verifying the ID token, checking the bans).
/// One more is closed at once, without a reply. Admitted sessions don't
/// count: the permit is returned as soon as the gate decides.
pub(crate) const MAX_PREAUTH_SESSIONS: usize = 64;

/// How long a host waits for the opening handshake before giving up, so a
/// peer that connects but never speaks can't hold a session task open.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Denial reason: the host got something other than an
/// [`Frame::Invoke`] after the handshake.
pub const DENY_INVOKE_REQUIRED: &str = "invoke required";

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
        if let Some(n) = self.tick(crate::clock::now_ms()) {
            tracing::info!(
                refused = n,
                last_peer = %peer.hex(),
                "{what}: refused {n} unadmitted peer(s) since the last report (latest: {detail})"
            );
        }
    }
}

/// The refusal a session sends and returns: already traced, so the accept
/// loop need not warn about it again.
#[derive(Debug)]
pub(crate) struct Refused(pub(crate) String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "refused: {}", self.0)
    }
}

impl std::error::Error for Refused {}

/// Map a `library` node identity to the iroh `SecretKey` of the same Ed25519
/// key, so the iroh node id equals our [`NodeId`].
pub fn secret_key(identity: &NodeIdentity) -> SecretKey {
    SecretKey::from_bytes(&identity.expose_seed())
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
/// of the n0 default (for a self-hosted iroh relay). Address hints come from
/// $WIRES_HOME's hints file.
pub async fn bind_with_alpn(
    identity: &NodeIdentity,
    relay_url: Option<&str>,
    alpn: &[u8],
) -> Result<Endpoint> {
    let ks = crate::admin::keystore::Keystore::resolve().ok();
    bind_with(identity, relay_url, alpn, false, ks.as_ref()).await
}

/// [`bind_with_alpn`], with direct (IP) connections only on loopback
/// (`127.0.0.1` and `::1`) when `loopback_only`: peers on this machine
/// connect directly, others through the relay. A host bound so opens no
/// socket on the network and does no gateway (UPnP/PCP/NAT-PMP) probing,
/// so the macOS firewall doesn't ask to approve it (useful for an
/// interpreter running a local demo, which can't be signed). Address hints
/// come from `hints_from`'s hints file (an embedded host passes its own keystore,
/// never `$WIRES_HOME`).
pub async fn bind_with(
    identity: &NodeIdentity,
    relay_url: Option<&str>,
    alpn: &[u8],
    loopback_only: bool,
    hints_from: Option<&crate::admin::keystore::Keystore>,
) -> Result<Endpoint> {
    // The local, unsigned hints file (usually absent): extra places to try
    // a key, beside n0 discovery.
    let hints = iroh::address_lookup::memory::MemoryLookup::new();
    if let Some(ks) = hints_from {
        for addr in crate::caller::pick::Hints::load(ks).endpoint_addrs() {
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
    if loopback_only {
        // No gateway probing either: port mapping is pointless without a
        // network socket, and its multicast discovery is what raises the
        // macOS firewall dialog (iroh's `PortmapperConfig` docs).
        builder = builder
            .portmapper_config(iroh::endpoint::PortmapperConfig::Disabled)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .and_then(|b| b.bind_addr("[::1]:0"))
            .map_err(|e| anyhow!("binding to loopback: {e}"))?;
    }
    builder
        .bind()
        .await
        .map_err(|e| anyhow!("binding iroh endpoint: {e}"))
}

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
/// ([`Frame::Stdout`] / [`Frame::Stderr`]); returns how many bytes it sent.
async fn pump_reader<R: AsyncRead + Unpin>(
    mut r: R,
    make: fn(Chunk) -> Frame,
    tx: mpsc::Sender<Frame>,
) -> Result<u64> {
    let mut buf = vec![0u8; PUMP_BUF];
    let mut sent = 0u64;
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
        sent += n as u64;
    }
    Ok(sent)
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

/// Bridge a running service's stdio over the session until it exits (or
/// stop it when `shutdown` says the dialer is gone), then write the call's
/// log line via `trace` and send its [`Frame::Exit`]. The ack is already
/// written.
async fn bridge<S, R>(
    send: S,
    mut recv: R,
    running: Running,
    shutdown: impl std::future::Future<Output = ()> + Send,
    trace: CallTrace,
) -> Result<()>
where
    S: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    let Running {
        stdin: mut child_stdin,
        stdout,
        stderr,
        mut process,
    } = running;

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
                    child_stdin.write_all(chunk.as_bytes()).await?;
                }
                Some(_) => {} // ignore unexpected frames from the dialer
                None => break,
            }
        }
        child_stdin.shutdown().await.ok();
        Ok::<(), anyhow::Error>(())
    });

    let out_task = tokio::spawn(pump_reader(stdout, Frame::Stdout, tx.clone()));
    let err_task = tokio::spawn(pump_reader(stderr, Frame::Stderr, tx.clone()));

    // Wait for the service, unless the dialer vanishes first — in which case
    // stop it and reap, rather than leaving an orphan behind. (The `wait()`
    // future is dropped when the select ends, releasing its borrow of
    // `process`.)
    let code = tokio::select! {
        code = process.wait() => code?,
        _ = shutdown => {
            tracing::warn!("dialer disconnected; stopping the service");
            process.kill();
            process.wait().await.context("reaping the stopped service")?
        }
    };
    let out_bytes = out_task.await.context("stdout pump")??;
    let err_bytes = err_task.await.context("stderr pump")??;
    // The child is gone, so there is nobody left to feed. Don't wait for the
    // dialer's stdin to reach EOF: from a terminal it never does, and a
    // `wires call <service> -- ARGS` whose child ignores stdin would hang until
    // Ctrl-D.
    stdin_task.abort();
    let _ = stdin_task.await;

    trace.finish(code, out_bytes + err_bytes);
    tx.send(Frame::Exit(code)).await.ok();
    drop(tx);
    writer.await.context("writer task")??;
    Ok(())
}

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

/// Refusals of peers not known to be admitted (see [`Throttle`]).
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

/// Refuse an **admitted** caller: write its log line
/// ([`call_trace::refused`](crate::host::call_trace::refused)) and send the
/// reason, cut as the frame carries it.
async fn refuse_member<W: AsyncWrite + Unpin>(
    send: &mut W,
    caller: NodeId,
    principal: Option<&library::Principal>,
    service: &ServiceName,
    reason: String,
) -> anyhow::Error {
    let reason = truncate_reason(reason);
    crate::host::call_trace::refused(caller, principal, Some(service), &reason);
    deny(send, reason.clone()).await;
    Refused(reason).into()
}

/// Refuse a peer not admitted: send `reason` and trace `detail`
/// (throttled) — anyone can connect, so a stranger must not be able to
/// flood the host's log.
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

/// The host side of a session, over an authenticated bi-stream (see
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

/// The host side of a session, over an authenticated bi-stream: read the
/// [`Frame::Hello`] (at most [`MAX_HELLO_FRAME`]) and the [`Frame::Invoke`]
/// (at most [`MAX_INVOKE_FRAME`]), then decide by **this host's** signed
/// policy (re-read now, so a removal applies on the next dial):
///
/// 1. admission: its ID token (verified under the policy's issuers as
///    `identity.issuers` narrows them, unexpired, bound to `caller`), and
///    [`library::check_admitted`]: a verified email, neither the node nor
///    the person banned, a role that matches
///    ([`ServicesHost::admit_caller`](crate::host::gate::ServicesHost::admit_caller)).
///    Anyone else hears only [`NOT_ADMITTED`](crate::host::gate::NOT_ADMITTED)
///    (or that its sign-in expired, or the IdP is unreachable), writes no
///    log line, and is traced, throttled;
/// 2. [`gate::admit`](crate::host::gate::admit): fresh → the policy lets
///    the caller call it (else one fixed sentence) → assigned here →
///    `also_require`;
/// 3. whether `host.json` implements the service.
///
/// An admitted caller's refusal is a [`Frame::Denied`] plus its log line
/// ([`call_trace`](crate::host::call_trace)).
/// `preauth` is returned once this is decided.
///
/// Admitted: a [`Frame::HelloAck`]
/// carrying this host's policy version, plus the policy head and
/// the called service's signed entry when the caller's view is older (so it
/// checks this host is still assigned before stdin, then refreshes), then the service's
/// command with the caller's argv appended (never a shell), in its `cwd`
/// with its `env`, and the server-derived `WIRES_*` variables. Its end is
/// the call's log line.
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
    let service = invocation.service.clone();
    let now = crate::clock::now_unix();

    let state = match host.policy() {
        Ok(state) => state,
        Err(e) => {
            // The host's own fault, not the caller's: an operator error.
            tracing::warn!("signed policy unusable: {e:#}");
            let reason = crate::host::gate::HOST_MISCONFIGURED;
            deny(&mut send, reason.to_string()).await;
            return Err(Refused(reason.to_string()).into());
        }
    };
    // Admission first: the token, a verified email, the bans and a role. A
    // stranger costs one token check and no log line of its own.
    let verified = match host
        .admit_caller(&state, caller, &hello.id_token, now)
        .await
    {
        Ok(verified) => verified,
        Err(refused) => {
            return Err(refuse_stranger(&mut send, caller, refused.said, &refused.why).await);
        }
    };
    let principal = Some(verified.principal.clone());
    // Admitted from here on: every refusal is the caller's log line.
    let admitted = match host.decide(&state, caller, &verified, &service, now) {
        Ok(admitted) => admitted,
        Err(reason) => {
            let who = principal.as_ref();
            return Err(refuse_member(&mut send, caller, who, &service, reason).await);
        }
    };
    // Only an admitted caller learns whether this host implements it.
    let Some(implementation) = host.implementation(&service) else {
        let reason = format!("service {service} is not implemented on this host");
        let who = principal.as_ref();
        return Err(refuse_member(&mut send, caller, who, &service, reason).await);
    };
    drop(preauth);
    let version = admitted.state_version;
    if hello.state_version > version {
        // The caller saw a newer policy than ours; we still decide by ours
        // (our directory subscription catches this host up).
        tracing::info!(
            caller = %caller.hex(),
            theirs = hello.state_version.0,
            ours = version.0,
            "caller holds a newer signed policy"
        );
    }
    // At `debug`: the call's one `info` line is written when it ends.
    tracing::debug!(
        caller = %caller.hex(),
        service = %service,
        role = %admitted.role,
        state_version = version.0,
        "session accepted"
    );
    // Times the call for its log line, written when it ends.
    let trace = CallTrace::start(
        caller,
        principal.clone(),
        service.clone(),
        admitted.role.clone(),
    );
    // Card 37: a caller whose view is older gets this host's head and the
    // service's entry, to check the host is still assigned before stdin.
    let news = hello.state_version < version;
    let ack = Frame::HelloAck(HelloAck {
        state_version: version,
        head: news.then(|| state.signed.head.clone()),
        entry: news
            .then(|| state.signed.entries().find(|e| e.name == service).cloned())
            .flatten(),
    });
    if let Err(e) = write_frame(&mut send, &ack).await {
        // The caller is gone before anything ran.
        trace.finish(-1, 0);
        return Err(e);
    }

    let svc = match implementation {
        Implementation::Command(svc) => svc,
        // An app's in-process handler (card 33): the same gate, log line,
        // ack and bridge as a child, with the verified caller as a type
        // rather than `WIRES_*` variables.
        Implementation::Native(native) => {
            // The call's push capability, as a CLI child gets it (card 28
            // §1), held in-process rather than in the environment.
            let capability = match (&host.push_grants, &host.push_commands) {
                (Some(grants), Some(commands)) => {
                    let cap = grants.caps.mint(caller);
                    let push = crate::host::native::CallerPush {
                        caps: Arc::clone(&grants.caps),
                        token: cap.token().clone(),
                        commands: commands.clone(),
                    };
                    Some((cap, push))
                }
                _ => None,
            };
            let call = crate::host::native::Call {
                caller,
                id_token: admitted.caller.token.clone(),
                principal: admitted.caller.principal.clone(),
                role: admitted.role.clone(),
                service: service.clone(),
                args: invocation.argv.clone(),
                push: capability.as_ref().map(|(_, push)| push.clone()),
            };
            let running = crate::host::native::start(native, call);
            let result = bridge(send, recv, running, shutdown, trace).await;
            // Dropping the capability starts its grace period.
            drop(capability);
            return result;
        }
    };
    let Some((program, args)) = svc.argv(invocation.argv.as_slice()) else {
        // Nothing can run.
        trace.finish(-1, 0);
        return Err(anyhow!("empty service command"));
    };
    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some(cwd) = &svc.cwd {
        cmd.current_dir(cwd);
    }
    // A minimal environment: `PATH` and the locale inherited, then the
    // service's own `env`, then the server-derived values (which always win;
    // `host.json` can't set them). Nothing of the host's own: no
    // `WIRES_HOME`, `HOME`, agent sockets or cloud credentials.
    // The caller's identity is the token it presented and the claims the
    // host verified from it, as one JSON value (protocol §5–6).
    let who = &admitted.caller;
    let mut server: Vec<(&str, std::ffi::OsString)> = vec![
        ("WIRES_CALLER_NODE", caller.hex().into()),
        ("WIRES_ID_TOKEN", who.token.as_str().into()),
        ("WIRES_CALLER", caller_json(&who.principal).into()),
        ("WIRES_SERVICE", service.as_str().into()),
        ("WIRES_ROLE", admitted.role.as_str().into()),
    ];
    if let Some(email) = who.principal.email.as_deref() {
        server.push(("WIRES_CALLER_EMAIL", email.into()));
    }
    // The call's push capability: this child may push to its caller, and
    // no one else, until shortly after the call ends (card 28 §1).
    let capability = host
        .push_grants
        .as_ref()
        .map(|g| (g.caps.mint(caller), g.socket.clone()));
    if let Some((cap, socket)) = &capability {
        use crate::host::capability::{ENV_SOCKET, ENV_TOKEN};
        server.push((ENV_SOCKET, socket.clone().into_os_string()));
        server.push((ENV_TOKEN, cap.token().hex().into()));
    }
    cmd.env_clear()
        .envs(child_env(std::env::vars_os(), &svc.env, server));
    let running = match Running::spawn(cmd) {
        Ok(running) => running,
        Err(e) => {
            trace.finish(-1, 0); // never ran
            return Err(e).with_context(|| format!("spawning {program}"));
        }
    };
    let result = bridge(send, recv, running, shutdown, trace).await;
    // Dropping the capability starts its grace period.
    drop(capability);
    result
}

/// `WIRES_CALLER`: the verified principal as one JSON object, the fields of
/// [`Principal`](library::Principal) (`issuer`, `subject`, `not_after`, and
/// `email`, `org`, `groups` when present), so a script reads `jq -r .email`.
pub(crate) fn caller_json(principal: &library::Principal) -> String {
    serde_json::to_string(principal).expect("a principal serializes")
}

/// Inherited variables a service child keeps, besides every `LC_*`: the
/// search path, and the locale (so tools print the text their operator
/// expects; locale variables carry no credentials).
const CHILD_INHERITS: &[&str] = &["PATH", "LANG"];

/// The whole environment of a service child: from `inherited` (the host's
/// own) only [`CHILD_INHERITS`] and `LC_*`; then `service` (`host.json`
/// `env`); then `server` (the `WIRES_*` values), each layer overriding the
/// one before.
pub(crate) fn child_env(
    inherited: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    service: &std::collections::BTreeMap<String, String>,
    server: Vec<(&str, std::ffi::OsString)>,
) -> std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> {
    let mut env: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> = inherited
        .into_iter()
        .filter(|(k, _)| {
            k.to_str()
                .is_some_and(|k| CHILD_INHERITS.contains(&k) || k.starts_with("LC_"))
        })
        .collect();
    env.extend(service.iter().map(|(k, v)| (k.into(), v.into())));
    env.extend(server.into_iter().map(|(k, v)| (k.into(), v)));
    env
}

/// The host refused the call and said why.
///
/// Distinguishes an *authorization* failure (the credential this dialer
/// presented was not acceptable — removed, expired, not in a role) from every
/// local or transport failure, so `wires call` can exit with a dedicated
/// code and print the host's own words.
#[derive(Debug, thiserror::Error)]
#[error("denied by host: {reason}")]
pub struct Denied {
    /// The host's stated reason.
    reason: String,
}

impl Denied {
    /// Wrap the host's stated reason.
    pub(crate) fn new(reason: String) -> Self {
        Self { reason }
    }

    /// The host's stated reason, verbatim (e.g. `not admitted to this
    /// network: sign in with \`wires login\`, or ask your admin for a role`).
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// What a service call came to: [`Dialed`] plus the host that answered.
#[derive(Debug)]
pub(crate) struct ServiceDialed {
    /// The host that ran the call.
    pub(crate) host: NodeId,
    /// The remote exit code.
    pub(crate) dialed: Dialed,
}

/// Card 27's dial: try each of `targets` (a service's hosts, in the caller's
/// preferred order) until one connects within `dial_timeout`, then open with
/// `hello`, send `invocation` and bridge stdio on that one.
///
/// `on_ack` runs once the host's `HelloAck` has arrived and **before** any
/// stdin is forwarded, with the host's id (the key iroh authenticated, one
/// of `targets`) and the ack (its head version, and the head and service
/// entry when newer than the caller's view): the caller checks the host is
/// still assigned there and may abort the call.
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
    on_ack: impl FnOnce(NodeId, &HelloAck) -> Result<()>,
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
                failures.push(format!("{}: {e}", host.short()));
                continue;
            }
            Err(_) => {
                tracing::debug!(host = %host.hex(), "dial timed out");
                failures.push(format!(
                    "{}: no answer within {}s",
                    host.short(),
                    dial_timeout.as_secs_f32()
                ));
                continue;
            }
        };
        let host = to_node_id(&conn.remote_id());
        let (send, recv) = conn.open_bi().await.context("opening bi-stream")?;
        let dialed = dial_opened_with(
            send,
            recv,
            hello,
            invocation,
            |ack| on_ack(host, ack),
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
    bail!(
        "no host answered ({}); try again later, or ask your admin whether its hosts are up",
        failures.join("; ")
    )
}

/// What a finished dial came to: the remote exit code.
#[derive(Debug)]
pub(crate) struct Dialed {
    /// The remote child's exit code.
    pub(crate) exit: i32,
}

/// [`dial_opened_with`] with nothing to do at the ack (a newer head the
/// host hands back is ignored): the session tests' form.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dial_opened<S, R, I, W, E>(
    send: S,
    recv: R,
    hello: Hello,
    invocation: Invocation,
    stdin: I,
    stdout: W,
    stderr: E,
) -> Result<Dialed>
where
    S: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin,
    I: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    dial_opened_with(
        send,
        recv,
        hello,
        invocation,
        |_| Ok(()),
        stdin,
        stdout,
        stderr,
    )
    .await
}

/// The dialer half of a session over an established bi-stream to an
/// iroh-authenticated host (one the service's root-signed entry names; the
/// caller chose it). Presents the `hello`, then reads the host's
/// [`HelloAck`](library::HelloAck) and runs `on_ack` with it, **before**
/// any stdin is forwarded. On any failure, aborts with no stdin sent.
///
/// The [`Frame::Invoke`] carrying `invocation` follows the opening
/// immediately, without waiting for the ack.
///
/// Errors if the session ends **without** an [`Frame::Exit`] — a host that
/// closes mid-session is a failure, not a silent success.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dial_opened_with<S, R, I, W, E>(
    mut send: S,
    mut recv: R,
    hello: Hello,
    invocation: Invocation,
    on_ack: impl FnOnce(&HelloAck) -> Result<()>,
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
    write_frame(&mut send, &Frame::Hello(hello)).await?;
    write_frame(&mut send, &Frame::Invoke(invocation)).await?;

    // Read the host's ack first (it is always the host's first frame).
    let ack = match read_frame(&mut recv).await? {
        Some(Frame::HelloAck(ack)) => ack,
        // Refused: surface the host's reason. No stdin task has been
        // spawned yet, so nothing was forwarded and nothing hit local stdout.
        Some(Frame::Denied { reason }) => return Err(Denied::new(reason).into()),
        Some(_) => bail!("the host's first frame was not a hello ack"),
        None => bail!("the host closed before sending a hello ack"),
    };
    // Before any stdin: whether the host is still assigned the service is
    // `on_ack`'s to check, against the ack's head and entry.
    on_ack(&ack)?;

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
            Some(_) => {} // ignore unexpected frames from the host
            None => break,
        }
    }
    stdout.flush().await.ok();
    stderr.flush().await.ok();
    stdin_task.abort();
    if !saw_exit {
        bail!("session ended without an exit code (the host closed early?)");
    }
    Ok(Dialed { exit: code })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::keystore::Keystore;
    use crate::host::config::HostConfig;
    use crate::host::gate::ServicesHost;
    use library::{Argv, Policy, Service, StateVersion};

    #[test]
    fn a_service_child_gets_a_minimal_environment() {
        let os = |k: &str, v: &str| (std::ffi::OsString::from(k), std::ffi::OsString::from(v));
        let inherited = vec![
            os("PATH", "/usr/bin"),
            os("LANG", "en_US.UTF-8"),
            os("LC_ALL", "C.UTF-8"),
            os("HOME", "/home/host"),
            os("SSH_AUTH_SOCK", "/tmp/agent"),
            os("AWS_SECRET_ACCESS_KEY", "s3cr3t"),
            os("GH_TOKEN", "ghp_x"),
            os("WIRES_HOME", "/home/host/.config/wires"),
            os("WIRES_NODE_SEED", "00"),
            os("WIRES_CALLER_NODE", "spoofed"),
        ];
        let service: std::collections::BTreeMap<String, String> = [
            ("LC_ALL".to_string(), "C".to_string()),
            ("CI_JOBS".to_string(), "/srv/jobs".to_string()),
        ]
        .into();
        let env = child_env(
            inherited,
            &service,
            vec![("WIRES_CALLER_NODE", "abc".into())],
        );
        let got: Vec<(String, String)> = env
            .into_iter()
            .map(|(k, v)| (k.into_string().unwrap(), v.into_string().unwrap()))
            .collect();
        let want: Vec<(String, String)> = [
            ("CI_JOBS", "/srv/jobs"),
            ("LANG", "en_US.UTF-8"),
            ("LC_ALL", "C"),
            ("PATH", "/usr/bin"),
            ("WIRES_CALLER_NODE", "abc"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        assert_eq!(got, want);
    }

    /// A shutdown signal that never fires: the dialer stays present for the
    /// whole session.
    fn never() -> std::future::Pending<()> {
        std::future::pending::<()>()
    }

    /// The network root, the host and the caller every session test uses.
    fn root() -> NodeIdentity {
        NodeIdentity::from_seed([1u8; 32])
    }
    fn host_id() -> NodeIdentity {
        NodeIdentity::from_seed([4u8; 32])
    }
    fn caller_id() -> NodeIdentity {
        NodeIdentity::from_seed([2u8; 32])
    }

    /// A host implementing service `t` as `command`, allowed to role `staff`
    /// (anyone the shared test IdP verified with an email); its signed policy bans
    /// [`stranger`]`(7)`.
    fn host_running(command: &[&str]) -> Arc<ServicesHost> {
        Arc::new(host_unshared(command))
    }

    /// [`host_running`], before it is shared.
    fn host_unshared(command: &[&str]) -> ServicesHost {
        host_with(command, |_| {})
    }

    /// [`host_unshared`], its policy changed by `edit` first.
    fn host_with(command: &[&str], edit: impl FnOnce(&mut Policy)) -> ServicesHost {
        let (root, host) = (root(), host_id());
        let home = crate::testutil::temp_dir();
        let ks = Keystore::at(&home);
        let mut s = Policy::new(root.node_id());
        s.version = StateVersion(1);
        s.issued = crate::clock::now_unix();
        s.not_after = i64::MAX;
        s.ban(stranger(7).0);
        let (staff, matchers) = crate::testutil::staff_role();
        s.roles.insert(staff.clone(), matchers);
        s.services.insert(
            ServiceName::new("t").unwrap(),
            Service {
                description: String::new(),
                allow: vec![staff],
                hosts: vec![host.node_id()],
            },
        );
        edit(&mut s);
        let signed = crate::testutil::signed_policy(&root, s);
        crate::policy::store::adopt_if_newer(
            &ks,
            &signed,
            root.node_id(),
            crate::clock::now_unix(),
        )
        .unwrap();
        let config = HostConfig::parse(&format!(
            r#"{{"version":2,"identity":{},"services":{{"t":{{"command":{}}}}}}}"#,
            crate::testutil::test_identity_json(),
            serde_json::to_string(command).unwrap()
        ))
        .unwrap();
        crate::host::serve::services_host(host.node_id(), root.node_id(), Arc::new(ks), config)
            .unwrap()
    }

    /// The caller's `Hello` (policy version 1, and an ID token from the
    /// shared test IdP bound to the caller's key: service `t` needs `staff`).
    fn hello() -> Hello {
        Hello {
            state_version: StateVersion(1),
            id_token: crate::testutil::test_id_token(&caller_id().node_id()),
        }
    }

    /// An invocation of `t` with `args`.
    fn invoke(args: &[&str]) -> Invocation {
        Invocation {
            service: ServiceName::new("t").unwrap(),
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
        run_session_on(host_running(command), args, input).await
    }

    /// [`run_session`] against `host`.
    async fn run_session_on(
        host: Arc<ServicesHost>,
        args: &[&str],
        input: &[u8],
    ) -> (Result<i32>, Vec<u8>, Vec<u8>) {
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
        let short = crate::host::gate::NOT_ADMITTED.to_string();
        assert_eq!(truncate_reason(short.clone()), short);
        let long = "é拒".repeat(400);
        let cut = truncate_reason(long);
        assert!(cut.len() <= MAX_REASON);
        assert!(cut.len() > MAX_REASON - 4);
    }

    /// Card 28 §10: with `end_of_options`, the child sees `--` between its
    /// fixed arguments and the caller's; without, the caller's follow
    /// directly.
    #[tokio::test]
    async fn end_of_options_puts_a_double_dash_before_the_callers_args() {
        let script = ["sh", "-c", r#"printf '%s|' "$@""#, "sh", "fixed"];
        let (code, out, _) = run_session(&script, &["-X", "DELETE"], b"").await;
        assert_eq!(code.unwrap(), 0);
        assert_eq!(String::from_utf8(out).unwrap(), "fixed|-X|DELETE|");
        let mut host = host_unshared(&script);
        host.config
            .services
            .get_mut(&ServiceName::new("t").unwrap())
            .unwrap()
            .end_of_options = true;
        let (code, out, _) = run_session_on(Arc::new(host), &["-X", "DELETE"], b"").await;
        assert_eq!(code.unwrap(), 0);
        assert_eq!(String::from_utf8(out).unwrap(), "fixed|--|-X|DELETE|");
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

    /// A dialer that vanishes mid-session takes the remote child with it:
    /// the child was running, and once the session returns it is gone.
    #[tokio::test]
    async fn child_is_killed_when_the_dialer_vanishes() {
        let pid_file = crate::testutil::temp_dir().join("pid");
        let script = format!("echo $$ > {}; exec sleep 30", pid_file.display());
        let host = host_running(&["sh", "-c", &script]);
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
        // The child is spawned (and has written its pid) before the dialer
        // goes.
        let pid = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(pid) = std::fs::read_to_string(&pid_file)
                    .ok()
                    .and_then(|s| s.trim().parse::<i32>().ok())
                {
                    return pid;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the child never started");
        let alive = |pid: i32| {
            // SAFETY: kill(2) with signal 0 only checks that `pid` exists.
            unsafe { libc::kill(pid, 0) == 0 }
        };
        assert!(alive(pid));
        tx.send(()).ok();
        tokio::time::timeout(std::time::Duration::from_secs(5), srv)
            .await
            .expect("the session must return once the dialer is gone")
            .unwrap()
            .unwrap();
        assert!(!alive(pid), "the child {pid} outlived its dialer");
    }

    /// Upper-cases its stdin to stdout, writes `note` to stderr, exits 3.
    struct Upper;

    impl crate::host::native::Service for Upper {
        async fn call(&self, _call: crate::Call, mut io: crate::CallIo) -> i32 {
            let mut input = Vec::new();
            io.stdin.read_to_end(&mut input).await.unwrap();
            io.stdout
                .write_all(&input.to_ascii_uppercase())
                .await
                .unwrap();
            io.stderr.write_all(b"note").await.unwrap();
            3
        }
    }

    /// Never returns.
    struct Forever;

    impl crate::host::native::Service for Forever {
        async fn call(&self, _call: crate::Call, _io: crate::CallIo) -> i32 {
            std::future::pending::<()>().await;
            0
        }
    }

    /// `service` started on a test call, as the session starts a native
    /// service.
    fn native(service: impl crate::host::native::Service) -> crate::host::service::Running {
        crate::host::native::start(Arc::new(service), crate::host::native::test_call())
    }

    /// A call's log line, timed from now.
    fn trace() -> CallTrace {
        CallTrace::start(
            caller_id().node_id(),
            None,
            ServiceName::new("t").unwrap(),
            library::RoleName::new("staff").unwrap(),
        )
    }

    /// Every frame the bridge sent, in order, through the last.
    async fn frames_from(mut answer: tokio::io::DuplexStream) -> Vec<Frame> {
        let mut frames = Vec::new();
        while let Some(frame) = read_frame(&mut answer).await.unwrap() {
            frames.push(frame);
        }
        frames
    }

    #[tokio::test]
    async fn a_native_service_is_bridged_and_traced_like_a_child() {
        let (lines, _guard) = crate::host::call_trace::capture::lines();
        let recv = std::io::Cursor::new(encoded(&[
            Frame::Stdin(Chunk::from_bytes(b"abc".to_vec())),
            Frame::Stdin(Chunk::from_bytes(b"def".to_vec())),
        ]));
        let (send, answer) = tokio::io::duplex(64 * 1024);
        bridge(send, recv, native(Upper), never(), trace())
            .await
            .unwrap();

        let (mut out, mut err, mut exit) = (Vec::new(), Vec::new(), None);
        for frame in frames_from(answer).await {
            match frame {
                Frame::Stdout(c) => out.extend_from_slice(c.as_bytes()),
                Frame::Stderr(c) => err.extend_from_slice(c.as_bytes()),
                Frame::Exit(code) => exit = Some(code),
                other => panic!("unexpected frame {other:?}"),
            }
        }
        assert_eq!(
            (out.as_slice(), err.as_slice(), exit),
            (&b"ABCDEF"[..], &b"note"[..], Some(3))
        );
        let finished = lines.matching("call finished");
        assert_eq!(finished.len(), 1, "{}", lines.text());
        assert!(
            finished[0].contains("exit=3") && finished[0].contains("bytes_out=10"),
            "{}",
            finished[0]
        );
    }

    /// The caller disconnects mid-call: the handler is stopped, the caller
    /// is sent exit -1, and the call still gets its log line (exit -1).
    #[tokio::test]
    async fn a_native_service_is_stopped_and_finished_when_the_dialer_vanishes() {
        let (lines, _guard) = crate::host::call_trace::capture::lines();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let (send, answer) = tokio::io::duplex(64 * 1024);
        let (_hold_stdin_open, recv) = tokio::io::duplex(64);
        let bridged = tokio::spawn(bridge(
            send,
            recv,
            native(Forever),
            async move {
                let _ = rx.await;
            },
            trace(),
        ));
        tx.send(()).ok();
        let done = tokio::time::timeout(std::time::Duration::from_secs(5), bridged).await;
        done.expect("the bridge must stop the service once the dialer is gone")
            .unwrap()
            .unwrap();
        assert!(matches!(
            frames_from(answer).await.last(),
            Some(Frame::Exit(-1))
        ));
        let finished = lines.matching("call finished");
        assert_eq!(finished.len(), 1, "{}", lines.text());
        assert!(finished[0].contains("exit=-1"), "{}", finished[0]);
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

    /// A key, with a genuine ID token bound to it (seed 7's node is the one
    /// the policy bans, so only the ban keeps it out).
    fn stranger(seed: u8) -> (NodeId, Hello) {
        let id = NodeIdentity::from_seed([seed; 32]).node_id();
        let hello = Hello {
            state_version: StateVersion(1),
            id_token: crate::testutil::test_id_token(&id),
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

    /// A `Hello` without an ID token is refused at that first message:
    /// it doesn't decode, and nothing runs.
    #[tokio::test]
    async fn a_hello_without_a_token_is_refused_at_the_first_message() {
        let body = br#"{"state_version":1}"#;
        let mut bytes = ((body.len() + 1) as u32).to_be_bytes().to_vec();
        bytes.push(10); // the `Hello` tag
        bytes.extend_from_slice(body);
        bytes.extend(Frame::Invoke(invoke(&[])).encode().unwrap());
        let r = refusal_by(&host_running(&["cat"]), bytes, caller_id().node_id()).await;
        assert_eq!(r, "unreadable hello");
    }

    /// Whatever keeps a caller out — a token bound to another key, a forged
    /// one, one from an issuer the policy doesn't trust, a banned node or a
    /// banned person — it hears the one fixed sentence: no reason, no policy
    /// version. An expired token says so (it is who it says).
    #[tokio::test]
    async fn a_caller_without_a_valid_sign_in_hears_only_the_fixed_refusal() {
        let open = |hello: Hello| encoded(&[Frame::Hello(hello), Frame::Invoke(invoke(&[]))]);
        let host = host_running(&["cat"]);
        // The caller's own token, presented by another key.
        let theirs = refusal_by(&host, open(hello()), stranger(9).0).await;
        // A forged token.
        let forged = Hello {
            id_token: library::IdToken::new("eyJhbGciOiJSUzI1NiJ9.e30.c2ln"),
            ..hello()
        };
        let forged = refusal_by(&host, open(forged), caller_id().node_id()).await;
        // A banned node, with a genuine token bound to it.
        let (id, genuine) = stranger(7);
        let banned = refusal_by(&host, open(genuine), id).await;
        // A banned person, from a node nobody banned.
        let removed = host_with(&["cat"], |p| {
            p.ban_person(library::Person::new(
                crate::testutil::test_idp().issuer.clone(),
                "caller@example.com",
            ));
        });
        let person = refusal_by(&removed, open(hello()), caller_id().node_id()).await;
        // An issuer the policy no longer trusts: no role names it, so the
        // only issuer goes and nothing verifies.
        let untrusting = host_with(&["cat"], |p| {
            p.roles.clear();
            p.services.values_mut().for_each(|s| s.allow.clear());
            p.issuers.clear();
            p.issuers.insert(
                library::Issuer::new("https://other-idp.example"),
                library::IssuerConfig {
                    client_id: library::Audience::new("x"),
                    audiences: vec![library::Audience::new("x")],
                },
            );
        });
        let untrusted = refusal_by(&untrusting, open(hello()), caller_id().node_id()).await;
        for r in [theirs, forged, banned, person, untrusted] {
            assert_eq!(r, crate::host::gate::NOT_ADMITTED);
        }
        let expired = Hello {
            id_token: crate::testutil::test_idp().mint(
                &library::OidcNonce::for_node(&caller_id().node_id()),
                crate::clock::now_unix() - 3600,
            ),
            ..hello()
        };
        let expired = refusal_by(&host, open(expired), caller_id().node_id()).await;
        assert_eq!(expired, crate::host::gate::SIGN_IN_EXPIRED);
    }

    /// A token that verifies is not enough: a person no role matches, and a
    /// sign-in with no verified email (even under `staff`, a role that names
    /// only the issuer), hear the same bytes as a stranger, at the first
    /// message, and leave no identity behind.
    #[tokio::test]
    async fn a_verified_token_no_role_matches_or_without_an_email_is_not_admitted() {
        let me = caller_id().node_id();
        let nonce = library::OidcNonce::for_node(&me);
        let idp = crate::testutil::test_idp();
        let exp = crate::clock::now_unix() + 3600;
        let open = |hello: Hello| encoded(&[Frame::Hello(hello), Frame::Invoke(invoke(&[]))]);
        // `t` allows only an analyst: someone else.
        let narrow = host_with(&["true"], |p| {
            p.roles.insert(
                library::RoleName::new("analyst").unwrap(),
                vec![library::Matcher {
                    email: Some("analyst@example.com".parse().unwrap()),
                    ..library::Matcher::new(idp.issuer.as_str())
                }],
            );
            p.roles.remove(&library::RoleName::new("staff").unwrap());
            p.services.values_mut().for_each(|s| {
                s.allow = vec![library::RoleName::new("analyst").unwrap()];
            });
        });
        let outsider = refusal_by(&narrow, open(hello()), me).await;
        let no_email = Hello {
            id_token: idp.mint_for("caller@example.com", false, &nonce, exp),
            ..hello()
        };
        let host = host_unshared(&["true"]);
        let emailless = refusal_by(&host, open(no_email), me).await;
        for r in [outsider, emailless] {
            assert_eq!(r, crate::host::gate::NOT_ADMITTED);
        }
        assert!(narrow.identities.nodes().is_empty());
        assert!(host.identities.nodes().is_empty());
    }

    /// A token that fails leaves nothing behind: no identity-index entry
    /// (any key can present one). A caller's that verifies is indexed.
    #[tokio::test]
    async fn a_failed_token_leaves_no_identity() {
        let host = host_running(&["true"]);
        let token =
            library::IdToken::new("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIn0.");
        let forged = Hello {
            id_token: token,
            ..hello()
        };
        let (id, _) = stranger(9);
        let r = refusal_by(
            &host,
            encoded(&[Frame::Hello(forged), Frame::Invoke(invoke(&[]))]),
            id,
        )
        .await;
        assert_eq!(r, crate::host::gate::NOT_ADMITTED);
        assert!(host.identities.nodes().is_empty(), "a failure was indexed");
        let (send, _answer) = tokio::io::duplex(64 * 1024);
        let bytes = encoded(&[Frame::Hello(hello()), Frame::Invoke(invoke(&[]))]);
        let caller = caller_id().node_id();
        let _ =
            serve_services_session(send, std::io::Cursor::new(bytes), caller, &host, never()).await;
        assert_eq!(host.identities.nodes(), [caller]);
    }

    /// A flood: a thousand connections from keys that aren't
    /// admitted — junk, silence, out-of-turn frames, someone else's token,
    /// a genuine token on a banned node — leave no `call refused` line, and
    /// at most one throttled `info` report. An admitted caller's refusal is
    /// its own line.
    #[tokio::test]
    async fn strangers_leave_no_call_lines_and_admitted_callers_do() {
        let (lines, _guard) = crate::host::call_trace::capture::lines();
        let host = host_running(&["true"]);
        for n in 0..1000u32 {
            let key = NodeIdentity::from_seed({
                let mut s = [0x55u8; 32];
                s[..4].copy_from_slice(&n.to_be_bytes());
                s
            });
            let (banned, genuine) = stranger(7);
            let (caller, bytes) = match n % 5 {
                0 => (key.node_id(), vec![0xde, 0xad, 0xbe, 0xef, 1, 2, 3]),
                1 => (key.node_id(), Vec::new()),
                2 => (key.node_id(), encoded(&[Frame::Invoke(invoke(&[]))])),
                3 => (
                    key.node_id(),
                    encoded(&[Frame::Hello(hello()), Frame::Invoke(invoke(&[]))]),
                ),
                _ => (
                    banned,
                    encoded(&[Frame::Hello(genuine), Frame::Invoke(invoke(&[]))]),
                ),
            };
            let (send, _answer) = tokio::io::duplex(64 * 1024);
            let r =
                serve_services_session(send, std::io::Cursor::new(bytes), caller, &host, never())
                    .await;
            assert!(r.is_err());
        }
        assert!(
            lines.matching("call refused").is_empty(),
            "a stranger's refusal was traced as a call"
        );
        // The session's own `info`: only the throttled count (at most one
        // per 10 s).
        let info: Vec<String> = lines
            .matching(" INFO ")
            .into_iter()
            .filter(|l| l.contains("wires::host::transport") || l.contains("call_trace"))
            .filter(|l| !l.contains("unadmitted peer(s) since the last report"))
            .collect();
        assert!(info.is_empty(), "{info:?}");
        let unknown = Invocation {
            service: ServiceName::new("nope").unwrap(),
            argv: Argv::default(),
        };
        let r = refusal_by(
            &host,
            encoded(&[Frame::Hello(hello()), Frame::Invoke(unknown)]),
            caller_id().node_id(),
        )
        .await;
        let refused = lines.matching("call refused");
        assert_eq!(refused.len(), 1, "{}", lines.text());
        let line = &refused[0];
        assert!(line.contains(" INFO "), "{line}");
        assert!(line.contains("service=nope"), "{line}");
        assert!(
            line.contains(&format!("caller={}", caller_id().node_id().hex())),
            "{line}"
        );
        assert!(line.contains("subject="), "{line}");
        assert!(line.contains(&format!("reason={r:?}")), "{line}");
    }

    /// A call is one `call finished` line naming the service, the caller,
    /// the person, the role, the exit code, the duration and the bytes it
    /// sent; and no argv.
    #[tokio::test]
    async fn a_call_is_one_log_line() {
        let (lines, _guard) = crate::host::call_trace::capture::lines();
        // The caller's arguments land in `$@`, which the script ignores.
        let host = host_running(&["sh", "-c", "printf ok", "sh"]);
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
            invoke(&["secret-arg"]),
            std::io::Cursor::new(Vec::new()),
            &mut out,
            &mut Vec::new(),
        )
        .await
        .unwrap();
        srv.await.unwrap().unwrap();
        assert_eq!((dialed.exit, out.as_slice()), (0, &b"ok"[..]));
        let finished = lines.matching("call finished");
        assert_eq!(finished.len(), 1, "{}", lines.text());
        let line = &finished[0];
        for field in [
            " INFO ",
            "service=t",
            &format!("caller={}", caller_id().node_id().hex()),
            "issuer=",
            "subject=",
            "role=staff",
            "exit=0",
            "duration_ms=",
            "bytes_out=2",
        ] {
            assert!(line.contains(field), "{field} missing from {line}");
        }
        assert!(
            !lines.text().contains("secret-arg"),
            "the argv reached the log"
        );
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

        /// `WIRES_CALLER` is the verified principal itself: it parses back
        /// to the same value, and every claim is a field a script can read.
        #[test]
        fn caller_json_is_the_principal(
            issuer in "[ -~]{1,24}",
            subject in "[ -~]{1,24}",
            email in proptest::option::of("[a-z]{1,8}@[a-z]{1,8}\\.com"),
            org in proptest::option::of("[a-z.]{1,12}"),
            groups in proptest::collection::vec("[ -~]{0,12}", 0..4),
            not_after in proptest::prelude::any::<i64>(),
        ) {
            let p = library::Principal { issuer, subject, email, org, groups, not_after };
            let json = caller_json(&p);
            let back: library::Principal = serde_json::from_str(&json).unwrap();
            proptest::prop_assert_eq!(&back, &p);
            let v: serde_json::Value = serde_json::from_str(&json).unwrap();
            proptest::prop_assert_eq!(v["issuer"].as_str(), Some(p.issuer.as_str()));
            proptest::prop_assert_eq!(v["subject"].as_str(), Some(p.subject.as_str()));
            proptest::prop_assert_eq!(v["email"].as_str(), p.email.as_deref());
            proptest::prop_assert_eq!(v["not_after"].as_i64(), Some(p.not_after));
        }
    }

    #[test]
    fn caller_json_known_answer() {
        let p = library::Principal {
            issuer: "https://idp.example".into(),
            subject: "u-1".into(),
            email: Some("a@example.com".into()),
            org: None,
            groups: vec!["eng".into()],
            not_after: 1_700_000_000,
        };
        assert_eq!(
            caller_json(&p),
            r#"{"issuer":"https://idp.example","subject":"u-1","email":"a@example.com","groups":["eng"],"not_after":1700000000}"#
        );
    }
}

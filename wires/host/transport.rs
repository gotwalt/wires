//! The iroh session transport: bind/dial, the `Hello`, and the stdio bridge.
//!
//! `library` stays pure (no iroh/tokio); this module is where the
//! key-addressed session meets the iroh QUIC endpoint. The session ALPN is
//! [`ALPN`]. A caller opens a bi-stream and sends a
//! [`Frame::Hello`](library::Frame::Hello) — its root-signed membership, the
//! signed-state version it holds, and its IdP ID token — followed at once by
//! a [`Frame::Invoke`] naming a service plus per-call arguments. The host
//! ([`serve_services_session`]) decides by the signed state it holds, re-read
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

/// Largest frame body accepted off the wire. Bounds the allocation a peer can
/// induce from the (untrusted) length prefix; generous versus the 64 KiB stdio
/// chunk size, but far below "exhaust memory".
const MAX_FRAME: usize = 16 * 1024 * 1024;

/// How long a responder waits for the opening handshake before giving up, so a
/// peer that connects but never speaks can't hold a session task open.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Denial reason: the responder got something other than an
/// [`Frame::Invoke`] after the handshake.
pub const DENY_INVOKE_REQUIRED: &str = "invoke required";

/// The responder's handle for publishing [`AuditRecord`](library::AuditRecord)s.
///
/// Cloneable and non-blocking: a session never waits on the audit channel. A
/// full or closed sink is logged and the record dropped — the call itself is
/// not failed. (Whether a *missing* audit path should fail closed is the
/// audit lane's decision; see `docs/board`.)
#[derive(Clone, Debug)]
pub struct AuditSink(tokio::sync::mpsc::Sender<library::AuditRecord>);

impl AuditSink {
    /// A sink and the receiver the audit publisher drains.
    pub fn channel(cap: usize) -> (Self, tokio::sync::mpsc::Receiver<library::AuditRecord>) {
        let (tx, rx) = tokio::sync::mpsc::channel(cap);
        (Self(tx), rx)
    }

    /// Queue `record` for publishing without waiting.
    pub fn record(&self, record: library::AuditRecord) {
        if let Err(e) = self.0.try_send(record) {
            tracing::warn!("audit record dropped: {e}");
        }
    }
}

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

/// Read one length-prefixed frame, or `None` at a clean end of stream.
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Frame>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("reading frame length"),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        // Refuse before allocating: the length prefix is attacker-controlled
        // (this runs even for the pre-auth handshake frame).
        bail!("frame too large: {len} bytes (max {MAX_FRAME})");
    }
    let mut full = Vec::with_capacity(4 + len);
    full.extend_from_slice(&len_buf);
    full.resize(4 + len, 0);
    r.read_exact(&mut full[4..])
        .await
        .context("reading frame body")?;
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
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_frame(recv))
        .await
        .context("timed out waiting for invoke")??
    {
        Some(Frame::Invoke(invocation)) => Ok(invocation),
        Some(_) => bail!("second frame was not an invoke"),
        None => bail!("connection closed before invoke"),
    }
}

/// Spawn `cmd` (`program` names it in errors) with piped stdio, emit the
/// call's `Started` record via `start_audit`, and bridge the child's stdio
/// over the session until it exits (or kill it when `shutdown` says the
/// dialer is gone), then send its [`Frame::Exit`]. The ack has already been
/// written.
async fn bridge_child<S, R>(
    send: S,
    mut recv: R,
    mut cmd: Command,
    program: &str,
    shutdown: impl std::future::Future<Output = ()> + Send,
    start_audit: impl FnOnce() -> Option<crate::host::audit::CallAudit>,
) -> Result<()>
where
    S: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {program}"))?;
    let audit = start_audit();
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
        audit.finish(code); // audit: finished
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
/// [`serve_services_session`]).
#[derive(Clone, Debug)]
pub(crate) struct ServicesProtocol(pub(crate) Arc<crate::host::gate::ServicesHost>);

impl iroh::protocol::ProtocolHandler for ServicesProtocol {
    async fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        let caller = to_node_id(&conn.remote_id());
        tracing::info!(caller = %caller.hex(), "connection accepted (iroh-authenticated)");
        let result = async {
            let (send, recv) = conn.accept_bi().await.context("accepting bi-stream")?;
            // The transport's own liveness signal: when the dialer goes away,
            // the child dies with it instead of being stranded on this host.
            let closed = conn.clone();
            serve_services_session(send, recv, caller, &self.0, async move {
                closed.closed().await;
            })
            .await
        }
        .await;
        // Let the dialer read a `Denied` (or the final frames) before the
        // connection is torn down; bounded so a vanished dialer can't pin us.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), conn.closed()).await;
        result.map_err(|e| {
            tracing::warn!("connection rejected or failed: {e:#}");
            iroh::protocol::AcceptError::from_boxed(e.into())
        })
    }
}

/// Refuse `caller`: record it in the call log and send the reason.
async fn refuse<W: AsyncWrite + Unpin>(
    send: &mut W,
    audit: Option<&AuditSink>,
    caller: NodeId,
    tool: Option<ToolName>,
    reason: String,
) -> anyhow::Error {
    crate::host::audit::denied(audit, caller, tool, &reason); // audit: denied
    deny(send, reason.clone()).await;
    anyhow!(reason)
}

/// The v2 responder over an authenticated bi-stream: read the
/// [`Frame::Hello`] and the [`Frame::Invoke`], then decide by **this host's**
/// signed state (re-read now, so a removal applies on the next dial): the
/// caller's membership credential, its ID token (verified under
/// `identity.issuers`, bound to `caller`), then
/// [`gate::admit`](crate::host::gate::admit) — member → registered and
/// assigned here → registry role → `also_require`. Only then is the service
/// looked up in `host.json`. A refusal is a [`Frame::Denied`] plus a call-log
/// record.
///
/// Admitted: a [`Frame::HelloAck`] carrying this host's membership and state
/// version, plus the state itself when the caller's copy is older (the
/// cheapest pull), then the service's command with the caller's argv
/// appended (never a shell), in its `cwd` with its `env`, and the
/// server-derived `WIRES_*` variables.
pub(crate) async fn serve_services_session<S, R>(
    mut send: S,
    mut recv: R,
    caller: NodeId,
    host: &crate::host::gate::ServicesHost,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<()>
where
    S: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    let audit = host.audit.as_ref();
    let first = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_frame(&mut recv))
        .await
        .context("timed out waiting for hello")??;
    let hello = match first {
        Some(Frame::Hello(hello)) => hello,
        Some(_) => {
            let reason = "first frame was not a hello".to_string();
            return Err(refuse(&mut send, audit, caller, None, reason).await);
        }
        None => {
            let reason = "connection closed before hello".to_string();
            return Err(refuse(&mut send, audit, caller, None, reason).await);
        }
    };
    let invocation = match read_invocation(&mut recv).await {
        Ok(invocation) => invocation,
        Err(e) => {
            let _ = refuse(&mut send, audit, caller, None, DENY_INVOKE_REQUIRED.into()).await;
            return Err(e.context(DENY_INVOKE_REQUIRED));
        }
    };
    let tool = invocation.tool.clone();
    let service = library::ServiceName::from(tool.clone());
    let now = crate::now_unix();

    let state = match host.state() {
        Ok(state) => state,
        Err(e) => {
            tracing::warn!("signed state unusable: {e:#}");
            let reason = "responder configuration error".to_string();
            return Err(refuse(&mut send, audit, caller, Some(tool), reason).await);
        }
    };
    if let Err(e) = check_inclusion(&hello.membership, host.trust_root, caller, now) {
        let reason = format!("membership rejected: {e}");
        return Err(refuse(&mut send, audit, caller, Some(tool), reason).await);
    }
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
        Err(reason) => return Err(refuse(&mut send, audit, caller, Some(tool), reason).await),
    };
    // Only an admitted caller learns whether this host implements it.
    let Some(svc) = host.config.services.get(&service) else {
        let reason = format!("service {service} is not implemented on this host");
        return Err(refuse(&mut send, audit, caller, Some(tool), reason).await);
    };
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
    write_frame(
        &mut send,
        &Frame::HelloAck(library::HelloAck {
            membership: host.membership.clone(),
            state_version: version,
            newer_state: (hello.state_version < version).then(|| state.clone()),
        }),
    )
    .await?;

    let (program, fixed) = svc
        .command
        .split_first()
        .ok_or_else(|| anyhow!("empty service command"))?;
    let mut cmd = Command::new(program);
    cmd.args(fixed).args(invocation.argv.as_slice());
    if let Some(cwd) = &svc.cwd {
        cmd.current_dir(cwd);
    }
    // A minimal environment: `PATH` and the locale inherited, then the
    // service's own `env`, then the server-derived values (which always win;
    // `host.json` can't set them). Nothing of the host's own: no
    // `WIRES_HOME`, `HOME`, agent sockets or cloud credentials.
    let mut server: Vec<(&str, std::ffi::OsString)> = vec![
        ("WIRES_CALLER_NODE", caller.hex().into()),
        ("WIRES_FABRIC_ROOT", host.trust_root.hex().into()),
        (
            "WIRES_MEMBERSHIP_NOT_AFTER",
            hello.membership.not_after.to_string().into(),
        ),
        ("WIRES_STATE_VERSION", version.0.to_string().into()),
        ("WIRES_SERVICE", service.as_str().into()),
        ("WIRES_TOOL", tool.as_str().into()),
        ("WIRES_ROLE", admitted.role.as_str().into()),
    ];
    if let Some(email) = principal.as_ref().and_then(|p| p.email.as_deref()) {
        server.push(("WIRES_CALLER_EMAIL", email.into()));
    }
    // The call's push capability: this child may push to its caller, and
    // no one else, until shortly after the call ends (card 28 §1).
    let capability = host
        .push_grants
        .as_ref()
        .map(|g| (g.caps.mint(caller, service.clone()), g.socket.clone()));
    if let Some((cap, socket)) = &capability {
        use crate::host::capability::{ENV_SOCKET, ENV_TOKEN};
        server.push((ENV_SOCKET, socket.clone().into_os_string()));
        server.push((ENV_TOKEN, cap.token().hex().into()));
    }
    cmd.env_clear()
        .envs(child_env(std::env::vars_os(), &svc.env, server));
    let role = admitted.role;
    let result = bridge_child(send, recv, cmd, program, shutdown, || {
        let audit = crate::host::audit::CallAudit::start(
            audit,
            caller,
            principal,
            tool,
            invocation.argv.as_slice(),
            Some(version.0),
            Some(role.as_str().to_string()),
        );
        if let (Some((cap, _)), Some(audit)) = (&capability, &audit) {
            cap.bind_call(audit.call());
        }
        audit
    })
    .await;
    // Dropping the capability starts its grace period.
    drop(capability);
    result
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
    use crate::admin::keystore::Keystore;
    use crate::host::config_v2::HostConfigV2;
    use crate::host::gate::ServicesHost;
    use library::{Argv, Membership, Service, ServiceName, State, StateVersion};

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

    /// A host implementing service `t` as `command`, allowed to role `staff`
    /// (anyone the shared test IdP verified); the caller and the host are the
    /// members of its signed state.
    fn host_running(command: &[&str]) -> Arc<ServicesHost> {
        let (root, host, caller) = (root(), host_id(), caller_id());
        let home = crate::testutil::temp_dir();
        let ks = Keystore::at(&home);
        let mut s = State::new(root.node_id());
        s.version = StateVersion(1);
        s.issued = crate::now_unix();
        s.not_after = i64::MAX;
        s.members.extend([host.node_id(), caller.node_id()]);
        s.hosts.insert(host.node_id());
        let (staff, matchers) = crate::testutil::staff_role();
        s.roles.insert(staff.clone(), matchers);
        s.services.insert(
            ServiceName::new("t").unwrap(),
            Service {
                description: String::new(),
                allow: vec![staff],
                hosts: vec![host.node_id()],
                readers: vec![],
            },
        );
        let signed = s.sign(&root).unwrap();
        crate::state::store::adopt_if_newer(&ks, &signed, root.node_id(), crate::now_unix())
            .unwrap();
        let config = HostConfigV2::parse(&format!(
            r#"{{"version":2,"identity":{},"services":{{"t":{{"command":{}}}}}}}"#,
            crate::testutil::test_identity_json(),
            serde_json::to_string(command).unwrap()
        ))
        .unwrap();
        Arc::new(
            crate::host::serve::services_host(
                host.node_id(),
                Membership::mint(&root, host.node_id(), 0, i64::MAX).unwrap(),
                Arc::new(ks),
                &home,
                config,
            )
            .unwrap(),
        )
    }

    /// The caller's `Hello` (membership under the root, state version 1, and
    /// an ID token from the shared test IdP: service `t` needs `staff`).
    fn hello() -> Hello {
        Hello {
            membership: Membership::mint(&root(), caller_id().node_id(), 0, i64::MAX).unwrap(),
            state_version: StateVersion(1),
            id_token: Some(crate::testutil::test_id_token(&caller_id().node_id())),
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

    /// What the host answers to `frames` from `caller`: the denial reason.
    async fn refusal(frames: &[Frame], caller: NodeId) -> String {
        let host = host_running(&["cat"]);
        let mut bytes = Vec::new();
        for f in frames {
            bytes.extend(f.encode().unwrap());
        }
        let (send, mut answer) = tokio::io::duplex(64 * 1024);
        let r =
            serve_services_session(send, std::io::Cursor::new(bytes), caller, &host, never()).await;
        assert!(r.is_err());
        match read_frame(&mut answer).await.unwrap() {
            Some(Frame::Denied { reason }) => reason,
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_host_refuses_out_of_turn_frames_and_foreign_credentials() {
        let caller = caller_id().node_id();
        let r = refusal(&[Frame::Invoke(invoke(&[]))], caller).await;
        assert!(r.contains("not a hello"), "{r}");
        let r = refusal(&[Frame::Hello(hello()), Frame::Exit(0)], caller).await;
        assert_eq!(r, DENY_INVOKE_REQUIRED);
        // Someone else's membership, presented by this caller.
        let r = refusal(
            &[Frame::Hello(hello()), Frame::Invoke(invoke(&[]))],
            NodeIdentity::from_seed([9u8; 32]).node_id(),
        )
        .await;
        assert!(r.contains("membership rejected"), "{r}");
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

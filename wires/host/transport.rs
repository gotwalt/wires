//! The iroh session transport: bind/dial, the membership handshake, and the
//! stdio bridge.
//!
//! `library` stays pure (no iroh/tokio); this module is where the
//! key-addressed session meets the iroh QUIC endpoint. The session ALPN
//! is [`ALPN`]. A dialer opens a bi-stream and sends a
//! [`Frame::Handshake`](library::Frame::Handshake) bearing its fabric
//! [`Membership`](library::Membership) (and roster inclusion proof), followed
//! at once by a [`Frame::Invoke`] naming one of the responder's tools plus
//! per-call arguments ([`call_on`]). The responder verifies inclusion with
//! [`library::check_inclusion`] and the roster head against the
//! iroh-authenticated caller, asks the host's policy whether it may run *that
//! tool*, then execs the tool's fixed argv with the caller's arguments appended — never through a shell — with the verified
//! caller identity injected into its environment, and bridges its stdio over
//! tagged frames.
//!
//! Two properties this module exists to preserve:
//!
//! - **Refusals are legible.** A responder that turns a caller away sends a
//!   [`Frame::Denied`] carrying the reason before closing, which the dialer
//!   surfaces as a [`Denied`] error (`wires call` exits 77). Nothing the
//!   dialer sends or receives on a refused session ever reaches its stdout.
//! - **Refusals are current.** The enforced roster head is a *source*
//!   ([`HeadSource`]), re-read on every connection, so a `wires remove` (a new
//!   roster commit) takes effect on the next dial rather than the next restart.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::presets::N0;
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use std::collections::BTreeMap;

use library::{
    Chunk, Frame, InclusionProof, Invocation, Membership, NodeId, NodeIdentity, RosterHead,
    ToolName, check_inclusion,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::mpsc;

/// The custom ALPN identifying a wires session.
///
/// Bumped to `/2` for the mutual-inclusion handshake (a proof in the dialer's
/// handshake and a `HandshakeAck` carrying the responder's own membership): a
/// peer speaking `/1` fails cleanly at connect time rather than mid-handshake.
pub const ALPN: &[u8] = b"wires/session/2";

/// Read buffer size for pumping child / local stdio into frames.
const PUMP_BUF: usize = 64 * 1024;

/// Largest frame body accepted off the wire. Bounds the allocation a peer can
/// induce from the (untrusted) length prefix; generous versus the 64 KiB stdio
/// chunk size, but far below "exhaust memory".
const MAX_FRAME: usize = 16 * 1024 * 1024;

/// How long a responder waits for the opening handshake before giving up, so a
/// peer that connects but never speaks can't hold a session task open.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a dialer (`wires call`, `wires mcp`) waits for the target to answer before giving up; an
/// unreachable responder must fail fast rather than look like a hung MCP server
/// to the client.
const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Denial reason: the responder got something other than an
/// [`Frame::Invoke`] after the handshake.
pub const DENY_INVOKE_REQUIRED: &str = "invoke required";

/// Denial reason for an [`Invocation`] naming a tool this responder does not
/// expose.
fn deny_unknown_tool(tool: &ToolName) -> String {
    format!("unknown tool: {tool}")
}

/// The responder's static configuration: what it trusts, which tools it
/// exposes, the optional roster head it enforces, and the identity it presents
/// in the ack. Built once per `serve` and shared across connections.
pub struct ServeConfig {
    /// The trusted fabric root whose memberships and head are honored.
    pub trust_root: NodeId,
    /// Where the enforced roster head comes from (or that none is enforced).
    pub head: HeadSource,
    /// The responder's own membership, presented in the `HandshakeAck`.
    pub membership: Membership,
    /// The responder's own inclusion proof, presented if set (unused by the
    /// dialer in this slice; reverse roster-freshness is deferred).
    pub proof: Option<InclusionProof>,
    /// The exposed tools (`host.json`'s `tools`): each tool's fixed argv. The
    /// dialer sends a [`Frame::Invoke`] naming one of these; its `argv` is
    /// appended to the tool's fixed argv (never through a shell).
    pub tools: BTreeMap<ToolName, Vec<String>>,
    /// Where call records go (`host.json`'s `channel`), if anywhere.
    pub audit: Option<AuditSink>,
    /// Who callers are, per the IdP claims on the channel. `None` without a
    /// channel: every caller is then unverified.
    pub identity: Option<Arc<crate::host::identity::IdentityGate>>,
    /// Who may run which tool (`host.json`'s roles and `allow`): asked last,
    /// once every credential check has passed. Default deny.
    pub policy: Arc<dyn crate::host::policy::Policy>,
}

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

/// Where the responder reads the enforced roster head from.
///
/// `None` disables head enforcement (membership + TTL only); `File` and
/// `Keystore` are re-read per connection, so `wires advanced roster commit` takes effect
/// on the next dial without a restart.
#[derive(Debug)]
pub enum HeadSource {
    /// No head enforcement. Built only by tests: the CLI's "no head yet" case
    /// is an unarmed [`Keystore`](Self::Keystore) source.
    #[cfg_attr(not(test), allow(dead_code))]
    None,
    /// A head fixed at startup (an inline token or environment variable).
    Fixed(RosterHead),
    /// An explicitly configured path (`--roster-head-file`), re-read per
    /// connection. Enforcing from the start: a missing file is an error.
    File(PathBuf),
    /// The keystore default (`roster-head.json`), whose *existence* is
    /// re-checked per connection.
    ///
    /// Enforcement arms itself the first time the file is seen: before that a
    /// missing file means "this responder has no head" (the pre-roster
    /// membership + TTL behavior); after that it means the head was
    /// deleted, and every dial is refused. That is what makes `wires advanced import
    /// --roster-head…` land on a responder that started with no head at all —
    /// without it, a later-installed head would never be consulted and the
    /// omitted member would stay admitted.
    Keystore {
        /// The keystore's `roster-head.json`.
        path: PathBuf,
        /// Set once a head has been read from `path`; from then on the source
        /// fails closed.
        armed: std::sync::atomic::AtomicBool,
    },
}

impl HeadSource {
    /// Resolve the head to enforce right now.
    ///
    /// **Fails closed.** A `File` source that is missing or malformed is an
    /// error, not "no enforcement": head enforcement was deliberately
    /// configured, so losing the file must refuse callers rather than silently
    /// re-admit the whole fabric. A responder that wants no enforcement says so
    /// with [`HeadSource::None`].
    ///
    /// A `Keystore` source is the one case that can *become* enforcing: while
    /// `roster-head.json` has never been seen it resolves to `None`, and from
    /// the first read onward it behaves exactly like `File`.
    pub fn load(&self) -> Result<Option<RosterHead>> {
        match self {
            HeadSource::None => Ok(None),
            HeadSource::Fixed(head) => Ok(Some(head.clone())),
            HeadSource::File(path) => Ok(Some(read_head(path)?)),
            HeadSource::Keystore { path, armed } => {
                use std::sync::atomic::Ordering;
                match std::fs::read_to_string(path) {
                    Ok(text) => {
                        let head = RosterHead::decode(text.trim())
                            .with_context(|| format!("parsing roster head {}", path.display()))?;
                        if !armed.swap(true, Ordering::SeqCst) {
                            tracing::info!(
                                path = %path.display(),
                                version = ?head.version,
                                "roster head installed; enforcing inclusion from this dial on"
                            );
                        }
                        Ok(Some(head))
                    }
                    // Never seen a head: pre-roster behavior (membership +
                    // TTL only). Seen one before: it was deleted — refuse.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        if armed.load(Ordering::SeqCst) {
                            Err(anyhow!(
                                "roster head {} has gone missing after being enforced; \
                                 restore it or restart `wires serve`",
                                path.display()
                            ))
                        } else {
                            Ok(None)
                        }
                    }
                    Err(e) => {
                        Err(e).with_context(|| format!("reading roster head {}", path.display()))
                    }
                }
            }
        }
    }

    /// How this source reports at startup: `"yes"`, `"no"`, or `"when-present"`
    /// for the keystore default, which arms itself the first time a head
    /// appears.
    pub fn enforcement(&self) -> &'static str {
        match self {
            HeadSource::None => "no",
            HeadSource::Fixed(_) | HeadSource::File(_) => "yes",
            HeadSource::Keystore { .. } => "when-present",
        }
    }
}

/// Read and decode a roster head from `path`; missing or malformed is an error.
fn read_head(path: &Path) -> Result<RosterHead> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading roster head {}", path.display()))?;
    RosterHead::decode(text.trim())
        .with_context(|| format!("parsing roster head {}", path.display()))
}

/// The roster head as loaded for **one** connection.
///
/// Loaded fresh in [`serve_session`] rather than frozen in [`ServeConfig`], so a
/// removal lands on the next dial instead of the next restart.
struct LoadedPolicy {
    head: Option<RosterHead>,
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
    let mut builder = Endpoint::builder(N0)
        .secret_key(secret_key(identity))
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
async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> Result<()> {
    let bytes = frame.encode().context("encoding frame")?;
    w.write_all(&bytes).await.context("writing frame")?;
    Ok(())
}

/// Read one length-prefixed frame, or `None` at a clean end of stream.
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Frame>> {
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

/// The argv to exec for this session: the invoked tool's fixed argv with the
/// caller's [`Argv`](library::Argv) appended element by element.
///
/// `Err` carries the denial reason for an invocation naming a tool this
/// responder does not expose.
fn resolve_command(
    config: &ServeConfig,
    invocation: &Invocation,
) -> std::result::Result<Vec<String>, String> {
    let base = config
        .tools
        .get(&invocation.tool)
        .ok_or_else(|| deny_unknown_tool(&invocation.tool))?;
    Ok(base
        .iter()
        .chain(invocation.argv.as_slice())
        .cloned()
        .collect())
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

// ---------------------------------------------------------------------------
// Responder (`wires serve`)
// ---------------------------------------------------------------------------

/// Bind for `node` and serve the session ALPN (see [`serve_on`]).
pub async fn serve(node: NodeIdentity, config: ServeConfig, relay_url: Option<&str>) -> Result<()> {
    let endpoint = bind(&node, relay_url).await?;
    serve_on(endpoint, config).await
}

/// Accept connections on `endpoint`, verifying each caller against `config`, then
/// exec the invoked tool and bridge its stdio. One task per connection; a
/// rejected or failed connection is logged at `warn` and does not stop the
/// listener.
pub async fn serve_on(endpoint: Endpoint, config: ServeConfig) -> Result<()> {
    tracing::info!(
        node = %to_node_id(&endpoint.id()).hex(),
        enforcing_head = config.head.enforcement(),
        sockets = ?endpoint.bound_sockets(),
        "serving session ALPN (egress-only)"
    );
    tracing::info!(
        head = ?config.head,
        "credential source (re-read per connection)"
    );
    let config = Arc::new(config);
    while let Some(incoming) = endpoint.accept().await {
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, &config).await {
                tracing::warn!("connection rejected or failed: {e:#}");
            }
        });
    }
    Ok(())
}

/// Accept one inbound iroh connection, then run the session over its bi-stream.
async fn handle_connection(incoming: iroh::endpoint::Incoming, config: &ServeConfig) -> Result<()> {
    let conn = incoming.await.context("accepting connection")?;
    serve_connection(conn, config).await
}

/// The session ALPN as a router protocol, for a responder whose endpoint is
/// owned by a [`TopicNode`](crate::channel::topics::TopicNode) (`serve host.json`):
/// one endpoint per node key, so the session rides the topic node's router
/// instead of a second bind.
#[derive(Clone)]
pub struct SessionProtocol(pub Arc<ServeConfig>);

impl std::fmt::Debug for SessionProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionProtocol")
            .field("trust_root", &self.0.trust_root.hex())
            .finish_non_exhaustive()
    }
}

impl iroh::protocol::ProtocolHandler for SessionProtocol {
    /// Serve one session exactly as [`serve_on`]'s accept loop does.
    async fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        serve_connection(conn, &self.0).await.map_err(|e| {
            tracing::warn!("connection rejected or failed: {e:#}");
            iroh::protocol::AcceptError::from_boxed(e.into())
        })
    }
}

/// Run the session over an accepted connection's bi-stream.
async fn serve_connection(conn: iroh::endpoint::Connection, config: &ServeConfig) -> Result<()> {
    let caller = to_node_id(&conn.remote_id());
    tracing::info!(caller = %caller.hex(), "connection accepted (iroh-authenticated)");
    let (send, recv) = conn.accept_bi().await.context("accepting bi-stream")?;

    // The transport's own liveness signal: when the dialer goes away (clean
    // close, SIGKILL, network loss), the child dies with it instead of being
    // stranded on this host. `Connection` is cheap to clone.
    let closed = conn.clone();
    let result = serve_session(send, recv, caller, config, async move {
        closed.closed().await;
    })
    .await;

    // Wait for the dialer to read the final frames and close, so we don't tear
    // the connection down mid-flush. Bounded so a vanished dialer can't pin us.
    // This runs on the **refusal** path too: dropping `conn` here would discard
    // the buffered `Frame::Denied` and the dialer would see nothing but a lost
    // connection — which is exactly the error this frame exists to replace.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), conn.closed()).await;
    result
}

/// The responder half of a session over an established, already-authenticated
/// bi-stream: read and verify the handshake against `caller` and `config`, send a
/// `HandshakeAck`, then exec the invoked tool and bridge its stdio. `caller`
/// must already be authenticated by whoever supplies the streams.
///
/// The handshake must be followed by a [`Frame::Invoke`]; the caller is
/// authorized for the named tool and the tool's argv plus the invocation's
/// arguments are exec'd (with `WIRES_TOOL` set).
///
/// A refused handshake is answered with a [`Frame::Denied`] carrying the reason
/// before the connection drops, and no child is spawned. (A peer that connects
/// and then says nothing at all hits the handshake *timeout* instead and is
/// dropped in silence — there is nobody listening to tell.)
///
/// `shutdown` resolves when the transport says the dialer is gone; the child is
/// then killed rather than left running. MCP clients restart their stdio
/// servers routinely, so without this every restart would strand a process on
/// the tool host.
async fn serve_session<S, R>(
    mut send: S,
    mut recv: R,
    caller: NodeId,
    config: &ServeConfig,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<()>
where
    S: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    // The first frame must be the credential-bearing handshake (bounded by a
    // timeout so a silent peer can't hold the task open).
    let first = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_frame(&mut recv))
        .await
        .context("timed out waiting for handshake")??;
    let (membership, proof) = match first {
        Some(Frame::Handshake { membership, proof }) => (membership, proof),
        // A peer is on the other end and spoke out of turn (or hung up): say so
        // on the wire before failing, so it need not guess.
        Some(_) => {
            let e = anyhow!("first frame was not a handshake");
            crate::host::audit::denied(config.audit.as_ref(), caller, None, &format!("{e:#}")); // audit: denied
            deny(&mut send, format!("{e:#}")).await;
            return Err(e);
        }
        None => {
            let e = anyhow!("connection closed before handshake");
            crate::host::audit::denied(config.audit.as_ref(), caller, None, &format!("{e:#}")); // audit: denied
            deny(&mut send, format!("{e:#}")).await;
            return Err(e);
        }
    };

    // The dialer sends its `Invoke` right behind the handshake without waiting
    // for the ack, so it is read here, before authorization (which is per
    // tool).
    let invocation = match read_invocation(&mut recv).await {
        Ok(invocation) => invocation,
        Err(e) => {
            crate::host::audit::denied(config.audit.as_ref(), caller, None, DENY_INVOKE_REQUIRED); // audit: denied
            deny(&mut send, DENY_INVOKE_REQUIRED.to_string()).await;
            return Err(e.context(DENY_INVOKE_REQUIRED));
        }
    };
    let tool = &invocation.tool;
    let now = crate::now_unix();

    // Re-read the enforced head for *this* connection, so a fresh roster head
    // (a removal) applies to the very next dial. A source
    // we cannot read is fatal for this session, but the dialer is told only that
    // the responder is misconfigured — never the path.
    let policy = match load_policy(config) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("credential sources unusable: {e:#}");
            let reason = "responder configuration error".to_string();
            crate::host::audit::denied(config.audit.as_ref(), caller, Some(tool.clone()), &reason); // audit: denied
            deny(&mut send, reason).await;
            return Err(e.context("loading credential sources"));
        }
    };

    let Admitted {
        roster_version,
        principal,
        role,
    } = match authorize(
        config,
        &policy,
        &membership,
        proof.as_ref(),
        caller,
        now,
        &invocation,
    ) {
        Ok(v) => v,
        Err(e) => {
            crate::host::audit::denied(
                config.audit.as_ref(),
                caller,
                Some(tool.clone()),
                &format!("{e:#}"),
            ); // audit: denied
            deny(&mut send, format!("{e:#}")).await;
            return Err(e);
        }
    };

    // Only an authorized caller learns whether the tool it named exists.
    let argv = match resolve_command(config, &invocation) {
        Ok(argv) => argv,
        Err(reason) => {
            crate::host::audit::denied(config.audit.as_ref(), caller, Some(tool.clone()), &reason); // audit: denied
            deny(&mut send, reason.clone()).await;
            return Err(anyhow!(reason));
        }
    };

    tracing::info!(
        caller = %caller.hex(),
        tool = %tool,
        roster_version = ?roster_version,
        "session accepted"
    );

    // Mutual inclusion: present our own membership (+ optional proof) so a
    // dialer can verify us before streaming stdin. Written directly
    // on `send` so it is the first frame back, before any child output.
    write_frame(
        &mut send,
        &Frame::HandshakeAck {
            membership: config.membership.clone(),
            proof: config.proof.clone(),
        },
    )
    .await?;

    // Spawn the child with piped stdio, injecting the verified caller identity
    // (and the admitting roster version, if any, and the invoked tool). Scrub
    // any inherited `WIRES_*` first so a malicious parent environment cannot
    // smuggle a stale identity to a child that trusts it. These are
    // *server-derived, post-verification* values — `caller` is the
    // iroh-authenticated peer, never a handshake claim — and are public ids,
    // not secrets.
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| anyhow!("empty tool command"))?;
    tracing::info!(program = %program, "spawning child and bridging stdio");
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_remove("WIRES_CALLER_NODE")
        .env_remove("WIRES_FABRIC_ROOT")
        .env_remove("WIRES_MEMBERSHIP_NOT_AFTER")
        .env_remove("WIRES_ROSTER_VERSION")
        .env_remove("WIRES_TOOL")
        .env("WIRES_CALLER_NODE", caller.hex())
        .env("WIRES_FABRIC_ROOT", config.trust_root.hex())
        .env(
            "WIRES_MEMBERSHIP_NOT_AFTER",
            membership.not_after.to_string(),
        );
    if let Some(v) = roster_version {
        cmd.env("WIRES_ROSTER_VERSION", v.to_string());
    }
    cmd.env("WIRES_TOOL", tool.as_str());
    bridge_child(send, recv, cmd, program, shutdown, || {
        // audit: started — the tool and the *caller's* arguments (not the
        // tool's fixed argv).
        crate::host::audit::CallAudit::start(
            config.audit.as_ref(),
            caller,
            principal,
            tool.clone(),
            invocation.argv.as_slice(),
            roster_version,
            role.map(String::from),
        )
    })
    .await
}

/// Spawn `cmd` (`program` names it in errors) with piped stdio, emit the
/// call's `Started` record via `start_audit`, and bridge the child's stdio
/// over the session until it exits (or kill it when `shutdown` says the
/// dialer is gone), then send its [`Frame::Exit`]. The ack has already been
/// written. Shared by the v1 and the services (v2) sessions.
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

/// Load this connection's view of the responder's credential sources.
fn load_policy(config: &ServeConfig) -> Result<LoadedPolicy> {
    Ok(LoadedPolicy {
        head: config.head.load()?,
    })
}

/// What [`authorize`] admitted a caller with.
#[derive(Debug)]
struct Admitted {
    /// The roster version that admitted the caller, or `None` when no head is
    /// enforced.
    roster_version: Option<u64>,
    /// The caller's fresh verified IdP principal, when the responder knows one
    /// (see [`ServeConfig::identity`]).
    principal: Option<library::Principal>,
    /// The policy role that admitted the caller.
    role: Option<crate::host::policy::RoleName>,
}

/// Every credential check a caller must pass, in one place.
///
/// Runs, in order: fabric inclusion (always), the roster head gate, and last
/// the host's [`Policy`](crate::host::policy::Policy)
/// (`host.json`), which only ever sees a caller whose key already passed
/// everything else, with its verified principal if it has one. Returns the
/// admitting roster version, the caller's principal, and the admitting role.
///
/// The error messages are user-facing: they are what the responder logs *and*
/// what it sends back in a [`Frame::Denied`], so each keeps a prefix naming the
/// credential at fault (`membership rejected: …`,
/// `roster inclusion rejected: …`).
///
/// `invocation` names the tool the policy is asked about. A policy refusal of
/// a caller with no verified identity leads with why there is none (and the
/// `wires login` remedy), then the rule that needed one.
fn authorize(
    config: &ServeConfig,
    policy: &LoadedPolicy,
    membership: &Membership,
    proof: Option<&InclusionProof>,
    caller: NodeId,
    now: i64,
    invocation: &Invocation,
) -> Result<Admitted> {
    let tool = &invocation.tool;
    // Inclusion is always required: the caller must prove fabric membership,
    // bound to its iroh-authenticated key.
    check_inclusion(membership, config.trust_root, caller, now)
        .map_err(|e| anyhow!("membership rejected: {e}"))?;

    // Roster head gate: when a head is enforced, require a proof and check the
    // caller's *current* membership; remember the admitting version.
    let roster_version = roster_gate(config, policy.head.as_ref(), proof, caller, now)?;

    // Identity: looked up per call, so a claim that lands after a refusal
    // admits the next call.
    let (principal, missing) = match config.identity.as_deref().map(|g| g.resolve(caller, now)) {
        Some(Ok(p)) => (Some(p), None),
        Some(Err(why)) => (None, Some(why)),
        None => (None, None),
    };
    let decision = config.policy.decide(&crate::host::policy::CallContext {
        principal: principal.as_ref(),
        caller,
        roster_version,
        tool,
        argv: &invocation.argv,
    });
    if !decision.allow {
        match missing {
            Some(why) if principal.is_none() => bail!("{why}; {}", decision.reason),
            _ => bail!("{}", decision.reason),
        }
    }
    Ok(Admitted {
        roster_version,
        principal,
        role: decision.role,
    })
}

/// The credential half of [`authorize`] for a peer that runs no tool: fabric
/// inclusion, then this connection's roster head gate. What
/// the inbox protocol (card 23) asks of a caller fetching its pushes before
/// the host's push policy is consulted. Returns the admitting roster version;
/// the error carries the same prefixes a call's refusal does.
pub(crate) fn check_member(
    config: &ServeConfig,
    membership: &Membership,
    proof: Option<&InclusionProof>,
    caller: NodeId,
    now: i64,
) -> Result<Option<u64>> {
    let loaded = load_policy(config).map_err(|e| {
        tracing::warn!("credential sources unusable: {e:#}");
        anyhow!("responder configuration error")
    })?;
    check_inclusion(membership, config.trust_root, caller, now)
        .map_err(|e| anyhow!("membership rejected: {e}"))?;
    roster_gate(config, loaded.head.as_ref(), proof, caller, now)
}

/// The roster head gate. With no enforced `head`, returns `Ok(None)` (slice-1
/// behavior). With one, requires `proof` and checks the caller's *current*
/// membership against that head, returning the admitting version for
/// `WIRES_ROSTER_VERSION`. `head` is the freshly loaded head for this
/// connection, not a value frozen at startup.
fn roster_gate(
    config: &ServeConfig,
    head: Option<&RosterHead>,
    proof: Option<&InclusionProof>,
    caller: NodeId,
    now: i64,
) -> Result<Option<u64>> {
    let Some(head) = head else {
        return Ok(None);
    };
    // Card 14: a caller that missed the admin's re-key still presents last
    // commit's proof; the directory that re-key left beside the head has its
    // current one (and nobody the commit removed).
    let directory = crate::channel::rekey::directory_for(&config.head);
    library::check_roster_inclusion_via(
        head,
        proof,
        directory.as_ref(),
        config.trust_root,
        caller,
        now,
    )
    .map_err(|e| anyhow!("roster inclusion rejected: {e}"))?;
    Ok(Some(head.version.0))
}

// ---------------------------------------------------------------------------
// Responder, services era (card 27: `host.json` v2, `Hello`)
// ---------------------------------------------------------------------------

/// Denial reason for a v1 [`Frame::Handshake`] sent to a v2 host.
pub const DENY_HELLO_REQUIRED: &str =
    "this host serves services (host.json v2): the caller must open with Hello (upgrade wires)";

/// The session ALPN for a v2 host, as a router protocol (see
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
            let closed = conn.clone();
            serve_services_session(send, recv, caller, &self.0, async move {
                closed.closed().await;
            })
            .await
        }
        .await;
        // As in `serve_connection`: let the dialer read a `Denied` before the
        // connection is torn down.
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
        Some(Frame::Handshake { .. }) => {
            return Err(refuse(&mut send, audit, caller, None, DENY_HELLO_REQUIRED.into()).await);
        }
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
        // (lane 27a's pull catches this host up).
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
        .env("WIRES_ROLE", admitted.role.as_str());
    if let Some(email) = principal.as_ref().and_then(|p| p.email.as_deref()) {
        cmd.env("WIRES_CALLER_EMAIL", email);
    }
    let role = admitted.role;
    bridge_child(send, recv, cmd, program, shutdown, || {
        crate::host::audit::CallAudit::start(
            audit,
            caller,
            principal,
            tool,
            invocation.argv.as_slice(),
            Some(version.0),
            Some(role.as_str().to_string()),
        )
    })
    .await
}

// ---------------------------------------------------------------------------
// Dialer (`wires call`, `wires mcp`)
// ---------------------------------------------------------------------------

/// The responder refused the handshake and said why.
///
/// Distinguishes an *authorization* failure (the credential this dialer
/// presented was not acceptable — revoked, expired, off the roster) from every
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

/// Dial `target` on `endpoint`, present `membership` (+ `proof` if any), send
/// [`Frame::Invoke`] with `invocation` right after the handshake (before the
/// ack arrives), verify the responder's `HandshakeAck` membership before
/// forwarding any stdin, then bridge local stdio. The entry point for
/// `wires call` and `wires mcp`.
///
/// Returns the remote child's exit code. A refusal — including
/// [`DENY_INVOKE_REQUIRED`]-style protocol refusals and `unknown tool: <name>`
/// — is an `Err` that downcasts to [`Denied`]; nothing reaches `stdout` on the
/// refusal paths that happen before the ack. Consumes `endpoint` and closes it
/// on return.
#[allow(clippy::too_many_arguments)]
pub async fn call_on<R, W, E>(
    endpoint: Endpoint,
    target: EndpointAddr,
    membership: Membership,
    proof: Option<InclusionProof>,
    invocation: Invocation,
    stdin: R,
    stdout: W,
    stderr: E,
) -> Result<i32>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    tracing::info!("dialing the responder over wires");
    let conn = match tokio::time::timeout(DIAL_TIMEOUT, endpoint.connect(target, ALPN)).await {
        Ok(Ok(conn)) => conn,
        // Close on the failure paths too: an endpoint dropped without
        // `close()` makes iroh log an alarming abort line over the actual
        // error the user needs to read.
        Ok(Err(e)) => {
            endpoint.close().await;
            return Err(anyhow!("dialing target: {e}"));
        }
        Err(_) => {
            endpoint.close().await;
            return Err(anyhow!(
                "dialing target: no answer within {}s — is `wires serve` running on the target, \
                 and are its --addr hints still current?",
                DIAL_TIMEOUT.as_secs()
            ));
        }
    };
    let target_id = to_node_id(&conn.remote_id());
    let (send, recv) = conn.open_bi().await.context("opening bi-stream")?;
    tracing::info!("session open; presenting membership and bridging stdio");

    let verify_target = Some(target_id);
    let result = dial_session(
        send,
        recv,
        membership,
        proof,
        invocation,
        verify_target,
        stdin,
        stdout,
        stderr,
    )
    .await;

    // Close gracefully so our CONNECTION_CLOSE flushes (lets the responder's
    // teardown return promptly, and avoids iroh's "dropped without close" warn),
    // whether the session succeeded or failed.
    endpoint.close().await;
    result
}

/// The dialer half of a session over an established bi-stream. Presents the
/// handshake, then reads the responder's `HandshakeAck`; when `verify_target` is
/// `Some` (always, from [`call_on`]), verifies the responder's membership against the
/// dialer's own fabric root and the authenticated target id **before** any stdin
/// is forwarded. On failure, aborts with no stdin sent.
///
/// The [`Frame::Invoke`] carrying `invocation` follows the handshake
/// immediately, without waiting for the ack.
///
/// Errors if the session ends **without** an [`Frame::Exit`] — a responder that
/// closes mid-session is a failure, not a silent success.
#[allow(clippy::too_many_arguments)]
async fn dial_session<S, R, I, W, E>(
    mut send: S,
    mut recv: R,
    membership: Membership,
    proof: Option<InclusionProof>,
    invocation: Invocation,
    verify_target: Option<NodeId>,
    stdin: I,
    mut stdout: W,
    mut stderr: E,
) -> Result<i32>
where
    S: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin,
    I: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    // The dialer's own fabric root is the authority for verifying the responder.
    let fabric_root = membership.fabric;
    write_frame(&mut send, &Frame::Handshake { membership, proof }).await?;
    write_frame(&mut send, &Frame::Invoke(invocation)).await?;

    // Read the responder's ack first (it is always the responder's first frame).
    let ack_membership = match read_frame(&mut recv).await? {
        Some(Frame::HandshakeAck { membership, .. }) => membership,
        // Refused: surface the responder's reason. No stdin task has been
        // spawned yet, so nothing was forwarded and nothing hit local stdout.
        Some(Frame::Denied { reason }) => return Err(Denied::new(reason).into()),
        Some(_) => bail!("responder's first frame was not a handshake ack"),
        None => bail!("responder closed before sending a handshake ack"),
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
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A shutdown signal that never fires: the dialer stays present for the
    /// whole session, which is what every test but
    /// [`child_is_killed_when_the_dialer_vanishes`] wants.
    fn never() -> std::future::Pending<()> {
        std::future::pending::<()>()
    }

    /// Build an endpoint with no discovery/relay (hermetic) for loopback tests.
    async fn test_endpoint(identity: &NodeIdentity) -> Endpoint {
        Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(secret_key(identity))
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap()
    }

    /// The endpoint's bound sockets with wildcard binds rewritten to localhost,
    /// for use as a target's direct `addrs` (so a dialer reaches it without
    /// discovery).
    fn localhost_socks(endpoint: &Endpoint) -> Vec<std::net::SocketAddr> {
        endpoint
            .bound_sockets()
            .into_iter()
            .map(|sock| match sock {
                std::net::SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
                    std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                        std::net::Ipv4Addr::LOCALHOST,
                        v4.port(),
                    ))
                }
                std::net::SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
                    std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                        std::net::Ipv6Addr::LOCALHOST,
                        v6.port(),
                        v6.flowinfo(),
                        v6.scope_id(),
                    ))
                }
                other => other,
            })
            .collect()
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
        let root = NodeIdentity::from_seed([1u8; 32]);
        let subject = NodeIdentity::from_seed([2u8; 32]).node_id();
        let membership = Membership::mint(&root, subject, 0, i64::MAX).unwrap();
        let frames = vec![
            Frame::Handshake {
                membership: membership.clone(),
                proof: None,
            },
            Frame::HandshakeAck {
                membership,
                proof: None,
            },
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

    /// The one tool most tests expose: [`test_config`] maps it to the test's
    /// command, and every dial invokes it.
    const TEST_TOOL: &str = "t";

    /// A tools map exposing `command` as [`TEST_TOOL`].
    fn tool_map(command: Vec<String>) -> BTreeMap<ToolName, Vec<String>> {
        BTreeMap::from([(ToolName::new(TEST_TOOL).unwrap(), command)])
    }

    /// An invocation of [`TEST_TOOL`] with no arguments.
    fn invoke_test_tool() -> Invocation {
        invoke(TEST_TOOL, &[])
    }

    /// A responder config for tests: server is a fabric member under `root`,
    /// exposing `command` as [`TEST_TOOL`].
    fn test_config(root: &NodeIdentity, server: NodeId, command: Vec<String>) -> ServeConfig {
        ServeConfig {
            tools: tool_map(command),
            audit: None,
            identity: None,
            policy: Arc::new(crate::host::policy::AnyMember),
            trust_root: root.node_id(),
            head: HeadSource::None,
            membership: Membership::mint(root, server, 0, i64::MAX).unwrap(),
            proof: None,
        }
    }

    /// The bytes a dialer sends before any stdin: `handshake`, then an
    /// invocation of [`TEST_TOOL`].
    fn opening(handshake: Frame) -> Vec<u8> {
        let mut bytes = handshake.encode().unwrap();
        bytes.extend(Frame::Invoke(invoke_test_tool()).encode().unwrap());
        bytes
    }

    /// Run a full session over two in-memory duplex pipes (no iroh): returns the
    /// dialer's exit result plus captured stdout/stderr (the ack is not
    /// verified: no iroh, so there is no authenticated target id).
    async fn run_session(command: Vec<String>, input: &[u8]) -> (Result<i32>, Vec<u8>, Vec<u8>) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let server = NodeIdentity::from_seed([4u8; 32]).node_id();
        let membership = Membership::mint(&root, caller, 0, i64::MAX).unwrap();

        let (c2s_w, c2s_r) = tokio::io::duplex(64 * 1024); // dialer -> responder
        let (s2c_w, s2c_r) = tokio::io::duplex(64 * 1024); // responder -> dialer

        let config = test_config(&root, server, command);
        let srv =
            tokio::spawn(
                async move { serve_session(s2c_w, c2s_r, caller, &config, never()).await },
            );

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = dial_session(
            c2s_w,
            s2c_r,
            membership,
            None, // dialer proof
            invoke_test_tool(),
            None, // verify_target: no iroh here → ignore the ack
            std::io::Cursor::new(input.to_vec()),
            &mut out,
            &mut err,
        )
        .await;
        let _ = srv.await;
        (code, out, err)
    }

    /// Whether the responder rejects a handshake bearing `membership` (then an
    /// invocation of [`TEST_TOOL`]).
    async fn serve_rejects(membership: Membership, trust_root: NodeId, caller: NodeId) -> bool {
        let recv = std::io::Cursor::new(opening(Frame::Handshake {
            membership,
            proof: None,
        }));
        let send: Vec<u8> = Vec::new();
        // The server's own membership is signed under seed [1]; rejection happens
        // during dialer verification, before the (unreached) ack, so the signer is
        // irrelevant to these negative tests.
        let server = NodeIdentity::from_seed([44u8; 32]);
        let server_membership = Membership::mint(
            &NodeIdentity::from_seed([1u8; 32]),
            server.node_id(),
            0,
            i64::MAX,
        )
        .unwrap();
        let config = ServeConfig {
            tools: tool_map(vec!["cat".to_string()]),
            audit: None,
            identity: None,
            policy: Arc::new(crate::host::policy::AnyMember),
            trust_root,
            head: HeadSource::None,
            membership: server_membership,
            proof: None,
        };
        serve_session(send, recv, caller, &config, never())
            .await
            .is_err()
    }

    /// Drive one dial/serve pair over duplex pipes with an explicit responder
    /// config and dialer credentials; returns the dialer's result plus whatever
    /// reached its stdout (which must stay empty on every refusal path).
    async fn run_with_config(
        config: ServeConfig,
        caller: NodeId,
        membership: Membership,
        proof: Option<InclusionProof>,
    ) -> (Result<i32>, Vec<u8>) {
        let (c2s_w, c2s_r) = tokio::io::duplex(64 * 1024);
        let (s2c_w, s2c_r) = tokio::io::duplex(64 * 1024);
        let srv =
            tokio::spawn(
                async move { serve_session(s2c_w, c2s_r, caller, &config, never()).await },
            );

        let mut out = Vec::new();
        let mut err = Vec::new();
        let res = dial_session(
            c2s_w,
            s2c_r,
            membership,
            proof,
            invoke_test_tool(),
            None, // no iroh here → ignore the ack
            std::io::Cursor::new(Vec::new()),
            &mut out,
            &mut err,
        )
        .await;
        let _ = srv.await;
        (res, out)
    }

    #[tokio::test]
    async fn denied_session_reports_reason_and_writes_no_stdout() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let server = NodeIdentity::from_seed([4u8; 32]).node_id();
        // A membership signed by another fabric's root.
        let membership = valid_membership(&NodeIdentity::from_seed([9u8; 32]), caller);

        let config = test_config(&root, server, vec!["cat".to_string()]);
        let (res, out) = run_with_config(config, caller, membership, None).await;

        let e = res.expect_err("a foreign membership must be refused");
        let denied = e
            .downcast_ref::<Denied>()
            .unwrap_or_else(|| panic!("expected a Denied error, got: {e:#}"));
        assert!(
            denied.reason().contains("membership rejected"),
            "reason should name the membership, got: {}",
            denied.reason()
        );
        assert!(
            out.is_empty(),
            "a refused dial must write nothing to stdout"
        );
    }

    #[tokio::test]
    async fn denied_roster_removal_reports_the_roster_reason() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let server = NodeIdentity::from_seed([3u8; 32]).node_id();
        // A v1 proof against a head that has since advanced to v2 — what a
        // removed member holds.
        let (mut config, v1_proof) = head_enforcing(&root, server, caller, vec!["cat".to_string()]);
        let mut roster = Roster::new(root.node_id());
        roster.insert(caller);
        roster.insert(server);
        let _ = roster.commit(&root, 0, i64::MAX).unwrap(); // v1
        let (v2_head, _) = roster.commit(&root, 0, i64::MAX).unwrap(); // v2
        config.head = HeadSource::Fixed(v2_head);

        let membership = valid_membership(&root, caller);
        let (res, out) = run_with_config(config, caller, membership, Some(v1_proof)).await;

        let e = res.expect_err("a stale proof must be refused");
        let denied = e
            .downcast_ref::<Denied>()
            .unwrap_or_else(|| panic!("expected a Denied error, got: {e:#}"));
        assert!(
            denied.reason().contains("roster inclusion rejected"),
            "reason should name the roster gate, got: {}",
            denied.reason()
        );
        assert!(out.is_empty());
    }

    /// A fresh, unique directory for tests that need real files (mirrors the
    /// `TEST_TMPDIR`-aware helper in `keystore`'s tests).
    fn temp_dir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let base = std::env::var_os("TEST_TMPDIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join(format!(
            "wires-transport-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn head_source_fails_closed_on_a_missing_or_malformed_file() {
        let dir = temp_dir();
        assert!(HeadSource::None.load().unwrap().is_none());
        // Enforcement was configured, so a vanished head refuses rather than
        // re-admitting the whole fabric.
        assert!(HeadSource::File(dir.join("absent.json")).load().is_err());
        let bad = dir.join("bad-head.json");
        std::fs::write(&bad, "not-a-token").unwrap();
        assert!(HeadSource::File(bad).load().is_err());
    }

    /// The keystore default re-checks *existence* per connection: a responder
    /// that started with no `roster-head.json` must still enforce the head an
    /// operator imports later. Once it has seen one, it fails closed like
    /// [`HeadSource::File`].
    #[test]
    fn head_source_keystore_arms_when_a_head_appears() {
        let path = temp_dir().join("roster-head.json");
        let source = HeadSource::Keystore {
            path: path.clone(),
            armed: std::sync::atomic::AtomicBool::new(false),
        };
        // Never had a head: pre-roster behavior, no enforcement.
        assert!(source.load().unwrap().is_none());
        assert_eq!(source.enforcement(), "when-present");

        // `wires advanced import --roster-head …` lands while `serve` is running.
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut roster = Roster::new(root.node_id());
        roster.insert(NodeIdentity::from_seed([2u8; 32]).node_id());
        let (head, _) = roster.commit(&root, 0, i64::MAX).unwrap();
        std::fs::write(&path, head.encode().unwrap()).unwrap();
        // Same source object, no restart.
        assert_eq!(source.load().unwrap().unwrap(), head);

        // Now armed: deleting the head refuses callers instead of re-admitting
        // the whole fabric.
        std::fs::remove_file(&path).unwrap();
        assert!(source.load().is_err());
    }

    /// The other money shot: a responder that came up with *no* head enforces
    /// the one imported between two connections. Without the per-connection
    /// existence check this fails **open** — the omitted member stays admitted.
    #[tokio::test]
    async fn roster_head_installed_between_connections_takes_effect() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let server = NodeIdentity::from_seed([4u8; 32]).node_id();
        let head_path = temp_dir().join("roster-head.json");
        let config = ServeConfig {
            audit: None,
            identity: None,
            policy: Arc::new(crate::host::policy::AnyMember),
            trust_root: root.node_id(),
            head: HeadSource::Keystore {
                path: head_path.clone(),
                armed: std::sync::atomic::AtomicBool::new(false),
            },
            membership: Membership::mint(&root, server, 0, i64::MAX).unwrap(),
            proof: None,
            tools: tool_map(vec!["cat".to_string()]),
        };
        // The caller holds a perfectly good proof from roster v1.
        let mut roster = Roster::new(root.node_id());
        roster.insert(caller);
        roster.insert(server);
        let (_v1, v1_proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let v1_proof = v1_proofs.into_iter().find(|(m, _)| *m == caller).unwrap().1;
        let handshake = || Frame::Handshake {
            membership: Membership::mint(&root, caller, 0, i64::MAX).unwrap(),
            proof: Some(v1_proof.clone()),
        };

        // No roster-head.json yet → admitted on membership alone.
        serve_once_with(&config, caller, handshake())
            .await
            .expect("no head installed yet: membership + TTL only");

        // The operator re-commits a roster that omits the caller and imports
        // the new head into the running responder's keystore.
        roster.remove(&caller);
        let (v2, _) = roster.commit(&root, 0, i64::MAX).unwrap();
        std::fs::write(&head_path, v2.encode().unwrap()).unwrap();

        // Same config object, next dial → denied by the roster gate.
        let e = serve_once_with(&config, caller, handshake())
            .await
            .expect_err("the omitted caller must now be refused");
        assert!(
            format!("{e:#}").contains("roster inclusion"),
            "expected a roster-gate denial, got: {e:#}"
        );
    }

    /// A dialer that vanishes mid-session takes the remote child with it: the
    /// session returns promptly instead of waiting out a `sleep 30`.
    #[tokio::test]
    async fn child_is_killed_when_the_dialer_vanishes() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let server = NodeIdentity::from_seed([4u8; 32]).node_id();
        let config = test_config(
            &root,
            server,
            vec!["sh".to_string(), "-c".to_string(), "sleep 30".to_string()],
        );
        let handshake = Frame::Handshake {
            membership: valid_membership(&root, caller),
            proof: None,
        };
        let recv = std::io::Cursor::new(opening(handshake));
        let send: Vec<u8> = Vec::new();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let srv = tokio::spawn(async move {
            serve_session(send, recv, caller, &config, async move {
                let _ = rx.await;
            })
            .await
        });

        // The dialer disappears.
        tx.send(()).ok();
        let finished = tokio::time::timeout(std::time::Duration::from_secs(5), srv).await;
        assert!(
            finished.is_ok(),
            "serve_session must return once the dialer is gone, not outlive the child"
        );
    }

    #[test]
    fn truncate_reason_cuts_on_a_char_boundary() {
        let short = "membership rejected: revoked".to_string();
        assert_eq!(truncate_reason(short.clone()), short);
        // 400 multi-byte chars (1200 bytes) must clamp to <= 512 bytes and stay
        // valid UTF-8 (the type guarantees it; the boundary walk is what's tested).
        let long = "é拒".repeat(400);
        let cut = truncate_reason(long);
        assert!(cut.len() <= MAX_REASON);
        assert!(cut.len() > MAX_REASON - 4);
    }

    #[tokio::test]
    async fn session_echoes_stdin() {
        let (code, out, err) = run_session(vec!["cat".to_string()], b"hello over wires").await;
        assert_eq!(code.unwrap(), 0);
        assert_eq!(out, b"hello over wires");
        assert!(err.is_empty());
    }

    #[tokio::test]
    async fn session_propagates_nonzero_exit() {
        let (code, _out, _err) =
            run_session(vec!["sh".into(), "-c".into(), "exit 3".into()], b"").await;
        assert_eq!(code.unwrap(), 3);
    }

    #[tokio::test]
    async fn session_routes_stderr_separately() {
        let (code, out, err) = run_session(
            vec!["sh".into(), "-c".into(), "printf oops 1>&2".into()],
            b"",
        )
        .await;
        assert_eq!(code.unwrap(), 0);
        assert!(out.is_empty());
        assert_eq!(err, b"oops");
    }

    /// `wires call db_query -- "select 1"` from a terminal: the child takes its
    /// input from argv and exits without reading stdin, while the dialer's
    /// stdin (the tty) never reaches EOF. The session must still end with the
    /// child's exit code instead of waiting for the caller to press Ctrl-D.
    #[tokio::test]
    async fn session_ends_when_the_child_exits_with_dialer_stdin_still_open() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let server = NodeIdentity::from_seed([4u8; 32]).node_id();
        let membership = Membership::mint(&root, caller, 0, i64::MAX).unwrap();
        let (c2s_w, c2s_r) = tokio::io::duplex(64 * 1024);
        let (s2c_w, s2c_r) = tokio::io::duplex(64 * 1024);
        let command = vec!["sh".into(), "-c".into(), "printf done".into()];
        let config = test_config(&root, server, command);
        let srv =
            tokio::spawn(
                async move { serve_session(s2c_w, c2s_r, caller, &config, never()).await },
            );
        // A stdin that stays open for the whole test: its writer is held below.
        let (_stdin_held_open, stdin) = tokio::io::duplex(64);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            dial_session(
                c2s_w,
                s2c_r,
                membership,
                None,
                invoke_test_tool(),
                None,
                stdin,
                &mut out,
                &mut err,
            ),
        )
        .await
        .expect("the session hung waiting for the dialer's stdin to close");
        assert_eq!(code.unwrap(), 0);
        assert_eq!(out, b"done");
        tokio::time::timeout(std::time::Duration::from_secs(10), srv)
            .await
            .expect("the responder hung after the child exited")
            .unwrap()
            .unwrap();
    }

    /// Mint a valid membership for `caller` under `root`.
    fn valid_membership(root: &NodeIdentity, caller: NodeId) -> Membership {
        Membership::mint(root, caller, 0, i64::MAX).unwrap()
    }

    #[tokio::test]
    async fn inclusion_only_session_echoes() {
        // No scope: any fabric member may connect; `cat` echoes stdin.
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let server = NodeIdentity::from_seed([4u8; 32]).node_id();
        let membership = valid_membership(&root, caller);

        let (c2s_w, c2s_r) = tokio::io::duplex(64 * 1024);
        let (s2c_w, s2c_r) = tokio::io::duplex(64 * 1024);
        let config = test_config(&root, server, vec!["cat".to_string()]);
        let srv =
            tokio::spawn(
                async move { serve_session(s2c_w, c2s_r, caller, &config, never()).await },
            );

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = dial_session(
            c2s_w,
            s2c_r,
            membership,
            None,
            invoke_test_tool(),
            None,
            std::io::Cursor::new(b"hi inclusion".to_vec()),
            &mut out,
            &mut err,
        )
        .await;
        let _ = srv.await;
        assert_eq!(code.unwrap(), 0);
        assert_eq!(out, b"hi inclusion");
    }

    #[tokio::test]
    async fn session_rejects_wrong_fabric_membership() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let other_root = NodeIdentity::from_seed([9u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        // Signed by other_root; the responder trusts root.
        let m = Membership::mint(&other_root, caller, 0, i64::MAX).unwrap();
        assert!(serve_rejects(m, root.node_id(), caller).await);
    }

    #[tokio::test]
    async fn session_rejects_expired_membership() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let m = Membership::mint(&root, caller, 0, 0).unwrap(); // not_after 1970
        assert!(serve_rejects(m, root.node_id(), caller).await);
    }

    #[tokio::test]
    async fn session_rejects_member_not_caller() {
        // The credential is for `member`, but a different peer authenticated.
        let root = NodeIdentity::from_seed([1u8; 32]);
        let member = NodeIdentity::from_seed([2u8; 32]).node_id();
        let caller = NodeIdentity::from_seed([3u8; 32]).node_id();
        let m = valid_membership(&root, member);
        assert!(serve_rejects(m, root.node_id(), caller).await);
    }

    /// Full flow over a real (loopback) iroh connection: dial → handshake
    /// (membership) → `serve` execs `cat` → stdin echoes back
    /// on stdout → exit 0.
    #[tokio::test]
    async fn loopback_echo_round_trip() {
        let root = NodeIdentity::from_seed([10u8; 32]);
        let server = NodeIdentity::from_seed([11u8; 32]);
        let client = NodeIdentity::from_seed([12u8; 32]);
        let membership = Membership::mint(&root, client.node_id(), 0, i64::MAX).unwrap();

        let server_ep = test_endpoint(&server).await;
        // Dial via the production `endpoint_addr` using direct socket hints —
        // the same path a tools.json target's `addrs` take, no discovery involved.
        let addr = endpoint_addr(&server.node_id(), &localhost_socks(&server_ep), None).unwrap();
        let srv = tokio::spawn(serve_on(
            server_ep,
            test_config(&root, server.node_id(), vec!["cat".to_string()]),
        ));

        let client_ep = test_endpoint(&client).await;
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let code = call_on(
            client_ep,
            addr,
            membership,
            None, // no roster proof
            invoke_test_tool(),
            std::io::Cursor::new(b"hello world".to_vec()),
            &mut out,
            &mut err,
        )
        .await
        .unwrap();

        assert_eq!(code, 0);
        assert_eq!(out, b"hello world");
        srv.abort();
    }

    /// Inclusion-only over a real loopback connection: a member presents only
    /// its membership; the responder verifies it and injects the verified
    /// identity into the child's environment — no extra round-trip.
    #[tokio::test]
    async fn loopback_inclusion_only_injects_identity() {
        let root = NodeIdentity::from_seed([30u8; 32]);
        let server = NodeIdentity::from_seed([31u8; 32]);
        let client = NodeIdentity::from_seed([32u8; 32]);
        let not_after = i64::MAX;
        let membership = Membership::mint(&root, client.node_id(), 0, not_after).unwrap();

        let server_ep = test_endpoint(&server).await;
        let addr = endpoint_addr(&server.node_id(), &localhost_socks(&server_ep), None).unwrap();
        let srv = tokio::spawn(serve_on(
            server_ep,
            test_config(
                &root,
                server.node_id(),
                vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    r#"printf "%s,%s,%s" "$WIRES_CALLER_NODE" "$WIRES_FABRIC_ROOT" "$WIRES_MEMBERSHIP_NOT_AFTER""#
                        .to_string(),
                ],
            ),
        ));

        let client_ep = test_endpoint(&client).await;
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let code = call_on(
            client_ep,
            addr,
            membership,
            None,
            invoke_test_tool(),
            std::io::Cursor::new(Vec::new()),
            &mut out,
            &mut err,
        )
        .await
        .unwrap();

        assert_eq!(code, 0);
        let expected = format!(
            "{},{},{}",
            client.node_id().hex(),
            root.node_id().hex(),
            not_after
        );
        assert_eq!(String::from_utf8(out).unwrap(), expected);
        srv.abort();
    }

    /// A membership minted by the wrong root is refused, and the child never
    /// runs (nothing on stdout).
    #[tokio::test]
    async fn loopback_rejects_untrusted_membership() {
        let trusted_root = NodeIdentity::from_seed([40u8; 32]);
        let evil_root = NodeIdentity::from_seed([41u8; 32]);
        let server = NodeIdentity::from_seed([42u8; 32]);
        let client = NodeIdentity::from_seed([43u8; 32]);
        let membership = Membership::mint(&evil_root, client.node_id(), 0, i64::MAX).unwrap();

        let server_ep = test_endpoint(&server).await;
        let addr = endpoint_addr(&server.node_id(), &localhost_socks(&server_ep), None).unwrap();
        let srv = tokio::spawn(serve_on(
            server_ep,
            test_config(
                &trusted_root,
                server.node_id(),
                vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    "echo SHOULD_NOT_RUN".to_string(),
                ],
            ),
        ));

        let client_ep = test_endpoint(&client).await;
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let result = call_on(
            client_ep,
            addr,
            membership,
            None,
            invoke_test_tool(),
            std::io::Cursor::new(Vec::new()),
            &mut out,
            &mut err,
        )
        .await;
        assert!(result.is_err());
        assert!(out.is_empty());
        srv.abort();
    }

    use library::Roster;

    /// Build a head-enforcing config for `member` plus the member's proof.
    fn head_enforcing(
        root: &NodeIdentity,
        server: NodeId,
        member: NodeId,
        command: Vec<String>,
    ) -> (ServeConfig, InclusionProof) {
        let mut roster = Roster::new(root.node_id());
        roster.insert(member);
        roster.insert(server);
        let (head, proofs) = roster.commit(root, 0, i64::MAX).unwrap();
        let proof = proofs.into_iter().find(|(m, _)| *m == member).unwrap().1;
        let config = ServeConfig {
            audit: None,
            identity: None,
            policy: Arc::new(crate::host::policy::AnyMember),
            trust_root: root.node_id(),
            head: HeadSource::Fixed(head),
            membership: Membership::mint(root, server, 0, i64::MAX).unwrap(),
            proof: None,
            tools: tool_map(command),
        };
        (config, proof)
    }

    /// Drive `serve_session` against a one-shot handshake (and an invocation of
    /// [`TEST_TOOL`]); returns the result.
    async fn serve_once(config: ServeConfig, caller: NodeId, handshake: Frame) -> Result<()> {
        serve_once_with(&config, caller, handshake).await
    }

    /// [`serve_once`] against a *borrowed* config, for tests that dial the same
    /// long-lived `ServeConfig` more than once.
    async fn serve_once_with(config: &ServeConfig, caller: NodeId, handshake: Frame) -> Result<()> {
        let recv = std::io::Cursor::new(opening(handshake));
        let send: Vec<u8> = Vec::new();
        serve_session(send, recv, caller, config, never()).await
    }

    #[tokio::test]
    async fn head_enforcing_accepts_member_with_matching_proof() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let server = NodeIdentity::from_seed([3u8; 32]).node_id();
        let (config, proof) = head_enforcing(&root, server, caller, vec!["cat".to_string()]);
        let membership = Membership::mint(&root, caller, 0, i64::MAX).unwrap();
        let ok = serve_once(
            config,
            caller,
            Frame::Handshake {
                membership,
                proof: Some(proof),
            },
        )
        .await;
        assert!(ok.is_ok());
    }

    #[tokio::test]
    async fn head_enforcing_rejects_missing_proof() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let server = NodeIdentity::from_seed([3u8; 32]).node_id();
        let (config, _proof) = head_enforcing(&root, server, caller, vec!["cat".to_string()]);
        let membership = Membership::mint(&root, caller, 0, i64::MAX).unwrap();
        let res = serve_once(
            config,
            caller,
            Frame::Handshake {
                membership,
                proof: None,
            },
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn head_enforcing_rejects_proof_for_other_member() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let other = NodeIdentity::from_seed([8u8; 32]).node_id();
        let server = NodeIdentity::from_seed([3u8; 32]).node_id();
        // Head/proof are built for `other`; `caller` presents other's proof.
        let (config, other_proof) = head_enforcing(&root, server, other, vec!["cat".to_string()]);
        let membership = Membership::mint(&root, caller, 0, i64::MAX).unwrap();
        let res = serve_once(
            config,
            caller,
            Frame::Handshake {
                membership,
                proof: Some(other_proof),
            },
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn head_enforcing_rejects_stale_proof_after_recommit() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let server = NodeIdentity::from_seed([3u8; 32]).node_id();
        // Build a v1 proof, then advance the enforced head to v2.
        let (mut config, v1_proof) = head_enforcing(&root, server, caller, vec!["cat".to_string()]);
        let mut roster = Roster::new(root.node_id());
        roster.insert(caller);
        roster.insert(server);
        let _ = roster.commit(&root, 0, i64::MAX).unwrap(); // v1
        let (v2_head, _) = roster.commit(&root, 0, i64::MAX).unwrap(); // v2
        config.head = HeadSource::Fixed(v2_head);
        let membership = Membership::mint(&root, caller, 0, i64::MAX).unwrap();
        let res = serve_once(
            config,
            caller,
            Frame::Handshake {
                membership,
                proof: Some(v1_proof),
            },
        )
        .await;
        assert!(res.is_err());
    }

    /// A root commits a roster of {client, server}; an inclusion-only,
    /// head-enforcing responder admits the client over a real loopback
    /// connection; the child prints WIRES_CALLER_NODE / WIRES_ROSTER_VERSION.
    #[tokio::test]
    async fn loopback_head_enforcing_admits_member() {
        let root = NodeIdentity::from_seed([50u8; 32]);
        let server = NodeIdentity::from_seed([51u8; 32]);
        let client = NodeIdentity::from_seed([52u8; 32]);

        let mut roster = Roster::new(root.node_id());
        roster.insert(client.node_id());
        roster.insert(server.node_id());
        let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let head_version = head.version.0;
        let client_proof = proofs
            .into_iter()
            .find(|(m, _)| *m == client.node_id())
            .unwrap()
            .1;

        let server_ep = test_endpoint(&server).await;
        let addr = endpoint_addr(&server.node_id(), &localhost_socks(&server_ep), None).unwrap();
        let config = ServeConfig {
            audit: None,
            identity: None,
            policy: Arc::new(crate::host::policy::AnyMember),
            trust_root: root.node_id(),
            head: HeadSource::Fixed(head),
            membership: Membership::mint(&root, server.node_id(), 0, i64::MAX).unwrap(),
            proof: None,
            tools: tool_map(vec![
                "sh".to_string(),
                "-c".to_string(),
                r#"printf "%s,%s" "$WIRES_CALLER_NODE" "$WIRES_ROSTER_VERSION""#.to_string(),
            ]),
        };
        let srv = tokio::spawn(serve_on(server_ep, config));

        let client_ep = test_endpoint(&client).await;
        let membership = Membership::mint(&root, client.node_id(), 0, i64::MAX).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = call_on(
            client_ep,
            addr,
            membership,
            Some(client_proof),
            invoke_test_tool(),
            std::io::Cursor::new(Vec::new()),
            &mut out,
            &mut err,
        )
        .await
        .unwrap();

        assert_eq!(code, 0);
        let expected = format!("{},{}", client.node_id().hex(), head_version);
        assert_eq!(String::from_utf8(out).unwrap(), expected);
        srv.abort();
    }

    /// After the client is removed and the roster re-committed, the client's old
    /// proof is rejected and the child never runs.
    #[tokio::test]
    async fn loopback_head_enforcing_rejects_removed_member() {
        let root = NodeIdentity::from_seed([60u8; 32]);
        let server = NodeIdentity::from_seed([61u8; 32]);
        let client = NodeIdentity::from_seed([62u8; 32]);

        let mut roster = Roster::new(root.node_id());
        roster.insert(client.node_id());
        roster.insert(server.node_id());
        let (_v1, v1_proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let client_proof = v1_proofs
            .into_iter()
            .find(|(m, _)| *m == client.node_id())
            .unwrap()
            .1;
        // Remove the client and re-commit; the enforced head is now v2.
        roster.remove(&client.node_id());
        let (v2, _) = roster.commit(&root, 0, i64::MAX).unwrap();

        let server_ep = test_endpoint(&server).await;
        let addr = endpoint_addr(&server.node_id(), &localhost_socks(&server_ep), None).unwrap();
        let config = ServeConfig {
            audit: None,
            identity: None,
            policy: Arc::new(crate::host::policy::AnyMember),
            trust_root: root.node_id(),
            head: HeadSource::Fixed(v2),
            membership: Membership::mint(&root, server.node_id(), 0, i64::MAX).unwrap(),
            proof: None,
            tools: tool_map(vec![
                "sh".to_string(),
                "-c".to_string(),
                "echo SHOULD_NOT_RUN".to_string(),
            ]),
        };
        let srv = tokio::spawn(serve_on(server_ep, config));

        let client_ep = test_endpoint(&client).await;
        let membership = Membership::mint(&root, client.node_id(), 0, i64::MAX).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = call_on(
            client_ep,
            addr,
            membership,
            Some(client_proof),
            invoke_test_tool(),
            std::io::Cursor::new(Vec::new()),
            &mut out,
            &mut err,
        )
        .await;
        assert!(result.is_err());
        assert!(out.is_empty());
        srv.abort();
    }

    /// Mutual inclusion: a dialer aborts (no stdin echoed) when the
    /// responder's ack membership is signed by a different root; succeeds when it
    /// is signed by the trusted root.
    #[tokio::test]
    async fn loopback_mutual_inclusion_checks_the_responder() {
        let root = NodeIdentity::from_seed([70u8; 32]);
        let evil = NodeIdentity::from_seed([71u8; 32]);
        let client = NodeIdentity::from_seed([73u8; 32]);
        let membership = Membership::mint(&root, client.node_id(), 0, i64::MAX).unwrap();

        // Serve with the server's own membership signed by `signer`.
        async fn run(
            signer: &NodeIdentity,
            client_membership: Membership,
            client: &NodeIdentity,
        ) -> Result<i32> {
            let server = NodeIdentity::from_seed([72u8; 32]);
            let trust_root = NodeIdentity::from_seed([70u8; 32]).node_id();
            let server_ep = test_endpoint(&server).await;
            let addr =
                endpoint_addr(&server.node_id(), &localhost_socks(&server_ep), None).unwrap();
            let config = ServeConfig {
                audit: None,
                identity: None,
                policy: Arc::new(crate::host::policy::AnyMember),
                trust_root,
                head: HeadSource::None,
                membership: Membership::mint(signer, server.node_id(), 0, i64::MAX).unwrap(),
                proof: None,
                tools: tool_map(vec!["cat".to_string()]),
            };
            let srv = tokio::spawn(serve_on(server_ep, config));
            let client_ep = test_endpoint(client).await;
            let mut out = Vec::new();
            let mut err = Vec::new();
            let code = call_on(
                client_ep,
                addr,
                client_membership,
                None,
                invoke_test_tool(),
                std::io::Cursor::new(b"ping".to_vec()),
                &mut out,
                &mut err,
            )
            .await;
            srv.abort();
            code
        }

        // Server membership signed by the trusted root → success.
        assert!(run(&root, membership.clone(), &client).await.is_ok());
        // Server membership signed by a different root → dialer aborts.
        assert!(run(&evil, membership, &client).await.is_err());
    }

    // -----------------------------------------------------------------------
    // Tools (`serve --expose`, `call_on`)
    // -----------------------------------------------------------------------

    use library::Argv;

    /// A multi-tool responder config: `server` is a member under `root`, and
    /// the tools are `(name, argv)` pairs, open to any member.
    fn tools_config(root: &NodeIdentity, server: NodeId, tools: &[(&str, &[&str])]) -> ServeConfig {
        let mut config = test_config(root, server, Vec::new());
        config.tools = tools
            .iter()
            .map(|(name, argv)| {
                (
                    ToolName::new(*name).unwrap(),
                    argv.iter().map(|a| a.to_string()).collect(),
                )
            })
            .collect();
        config
    }

    /// An invocation of `tool` with `args`.
    fn invoke(tool: &str, args: &[&str]) -> Invocation {
        Invocation {
            tool: ToolName::new(tool).unwrap(),
            argv: Argv::new(args.iter().map(|a| a.to_string()).collect()).unwrap(),
        }
    }

    /// One dial/serve pair over duplex pipes carrying `invocation`; the caller
    /// (seed 2) holds a membership under `root`. Returns the dialer's result,
    /// stdout, stderr.
    async fn run_call(
        config: impl Into<Arc<ServeConfig>>,
        root: &NodeIdentity,
        invocation: Invocation,
        input: &[u8],
    ) -> (Result<i32>, Vec<u8>, Vec<u8>) {
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let membership = valid_membership(root, caller);
        let config: Arc<ServeConfig> = config.into();
        let (c2s_w, c2s_r) = tokio::io::duplex(64 * 1024);
        let (s2c_w, s2c_r) = tokio::io::duplex(64 * 1024);
        let srv =
            tokio::spawn(
                async move { serve_session(s2c_w, c2s_r, caller, &config, never()).await },
            );
        let mut out = Vec::new();
        let mut err = Vec::new();
        let res = dial_session(
            c2s_w,
            s2c_r,
            membership,
            None,
            invocation,
            None,
            std::io::Cursor::new(input.to_vec()),
            &mut out,
            &mut err,
        )
        .await;
        let _ = srv.await;
        (res, out, err)
    }

    /// Feed `serve_session` exactly `frames` (then EOF) and return its result
    /// plus every frame it wrote back — for protocol violations a well-behaved
    /// dialer cannot produce.
    async fn serve_raw(
        config: ServeConfig,
        caller: NodeId,
        frames: &[Frame],
    ) -> (Result<()>, Vec<Frame>) {
        let mut input = Vec::new();
        for f in frames {
            input.extend(f.encode().unwrap());
        }
        let (s2c_w, mut s2c_r) = tokio::io::duplex(64 * 1024);
        let res = serve_session(s2c_w, std::io::Cursor::new(input), caller, &config, never()).await;
        let mut back = Vec::new();
        while let Some(f) = read_frame(&mut s2c_r).await.unwrap() {
            back.push(f);
        }
        (res, back)
    }

    /// The reason carried by a dialer-side [`Denied`], or a panic naming what
    /// came back instead.
    fn denied_reason(res: Result<i32>) -> String {
        let e = res.expect_err("expected a refusal");
        e.downcast_ref::<Denied>()
            .unwrap_or_else(|| panic!("expected a Denied error, got: {e:#}"))
            .reason()
            .to_string()
    }

    #[tokio::test]
    async fn invoke_execs_the_tool_argv_plus_args_literally() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let server = NodeIdentity::from_seed([4u8; 32]).node_id();
        let config = tools_config(&root, server, &[("lines", &["printf", "%s\\n"])]);
        let args = [
            "two words",
            "'single'",
            "\"double\"",
            "a; rm -rf /",
            "$(whoami)",
            "`id`",
            "*",
            "$HOME",
            "",
        ];
        let (res, out, err) = run_call(config, &root, invoke("lines", &args), b"").await;
        assert_eq!(res.unwrap(), 0, "stderr: {}", String::from_utf8_lossy(&err));
        let expected: String = args.iter().map(|a| format!("{a}\n")).collect();
        assert_eq!(String::from_utf8(out).unwrap(), expected);
    }

    #[tokio::test]
    async fn invoke_injects_the_tool_name_and_bridges_stdin() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let server = NodeIdentity::from_seed([4u8; 32]).node_id();
        let config = tools_config(
            &root,
            server,
            &[("who", &["sh", "-c", "printf '%s:' \"$WIRES_TOOL\"; cat"])],
        );
        let (res, out, _) = run_call(config, &root, invoke("who", &[]), b"piped").await;
        assert_eq!(res.unwrap(), 0);
        assert_eq!(out, b"who:piped");
    }

    #[tokio::test]
    async fn a_responder_requires_an_invoke() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let server = NodeIdentity::from_seed([4u8; 32]).node_id();
        let handshake = Frame::Handshake {
            membership: valid_membership(&root, caller),
            proof: None,
        };
        // Handshake then EOF, and handshake then a stdin frame: both refused.
        for frames in [
            vec![handshake.clone()],
            vec![handshake, Frame::Stdin(Chunk::from_bytes(b"x".to_vec()))],
        ] {
            let config = tools_config(&root, server, &[("a", &["cat"])]);
            let (res, back) = serve_raw(config, caller, &frames).await;
            assert!(res.is_err());
            assert_eq!(
                back,
                vec![Frame::Denied {
                    reason: DENY_INVOKE_REQUIRED.to_string()
                }]
            );
        }
    }

    /// Multi-tool calls are audited with the invoked tool and the *caller's*
    /// arguments (not the tool's fixed argv); a refusal after the invoke names
    /// the tool it asked for.
    #[tokio::test]
    async fn multi_tool_calls_are_audited_with_tool_and_caller_args() {
        use library::AuditRecord;
        let root = NodeIdentity::from_seed([1u8; 32]);
        let server = NodeIdentity::from_seed([4u8; 32]).node_id();
        let (sink, mut records) = AuditSink::channel(16);

        let mut config = tools_config(&root, server, &[("say", &["printf", "%s"])]);
        config.audit = Some(sink.clone());
        let (res, out, _) = run_call(config, &root, invoke("say", &["hi"]), b"").await;
        assert_eq!(res.unwrap(), 0);
        assert_eq!(out, b"hi");
        match records.recv().await.unwrap() {
            AuditRecord::Started { tool, argv, .. } => {
                assert_eq!(tool.as_str(), "say");
                assert_eq!(argv.as_slice(), ["hi"]);
            }
            other => panic!("expected Started, got {other:?}"),
        }
        match records.recv().await.unwrap() {
            AuditRecord::Finished {
                exit,
                stdout_bytes,
                stdin_bytes,
                stdin_head,
                ..
            } => {
                assert_eq!((exit, stdout_bytes), (0, 2));
                assert_eq!((stdin_bytes, stdin_head), (0, None));
            }
            other => panic!("expected Finished, got {other:?}"),
        }

        let mut config = tools_config(&root, server, &[("say", &["printf", "%s"])]);
        config.audit = Some(sink);
        let (res, _, _) = run_call(config, &root, invoke("nope", &[]), b"").await;
        let reason = denied_reason(res);
        match records.recv().await.unwrap() {
            AuditRecord::Denied {
                tool, reason: r, ..
            } => {
                assert_eq!(tool.unwrap().as_str(), "nope");
                assert_eq!(r, reason);
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_tool_is_refused_by_name() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let server = NodeIdentity::from_seed([4u8; 32]).node_id();
        let config = tools_config(&root, server, &[("a", &["cat"])]);
        let (res, out, _) = run_call(config, &root, invoke("nope", &[]), b"").await;
        assert_eq!(denied_reason(res), "unknown tool: nope");
        assert!(out.is_empty());
    }

    /// The host policy is asked last: a caller that passed every credential
    /// check is still refused a tool no role of it may run — with the rule,
    /// on the channel — and admitted to one open to `member`, whose
    /// `Started` names the role.
    #[tokio::test]
    async fn the_policy_decides_last_and_names_the_role() {
        use crate::host::config::HostConfig;
        let root = NodeIdentity::from_seed([1u8; 32]);
        let server = NodeIdentity::from_seed([4u8; 32]).node_id();
        let host = HostConfig::parse(
            r#"{"version":1,"channel":"ops",
                "identity":{"issuers":[{"issuer":"https://idp.example","audiences":["a"]}]},
                "roles":{"analyst":[{"email":"*@example.com"}]},
                "tools":{"open":{"command":["printf","ran"],"allow":["member"]},
                         "db":{"command":["printf","secret"],"allow":["analyst"]},
                         "shut":{"command":["printf","never"]}}}"#,
        )
        .unwrap();
        let mut config = test_config(&root, server, Vec::new());
        config.tools = host.commands();
        config.policy = Arc::new(host.policy());
        let (sink, mut records) = AuditSink::channel(16);
        config.audit = Some(sink);
        let config = Arc::new(config);

        let (res, out, _) = run_call(Arc::clone(&config), &root, invoke("db", &[]), b"").await;
        let reason = denied_reason(res);
        assert!(out.is_empty());
        assert!(
            reason
                .starts_with("db needs a verified identity in role analyst (email=*@example.com)"),
            "{reason}"
        );
        let Ok(library::AuditRecord::Denied { reason: logged, .. }) = records.try_recv() else {
            panic!("the refusal is recorded");
        };
        assert_eq!(logged, reason);

        let (res, _, _) = run_call(Arc::clone(&config), &root, invoke("shut", &[]), b"").await;
        assert!(denied_reason(res).contains("shut allows no role"));
        records.try_recv().unwrap();

        let (res, out, _) = run_call(Arc::clone(&config), &root, invoke("open", &[]), b"").await;
        assert_eq!(res.unwrap(), 0);
        assert_eq!(out, b"ran");
        let Ok(library::AuditRecord::Started {
            role, principal, ..
        }) = records.try_recv()
        else {
            panic!("expected Started");
        };
        assert_eq!(role.as_deref(), Some("member"));
        assert_eq!(principal, None);
    }

    #[tokio::test]
    async fn membership_is_checked_before_the_tool_is_resolved() {
        // A caller from another fabric naming an unknown tool learns its
        // membership was rejected, not which tools exist.
        let root = NodeIdentity::from_seed([1u8; 32]);
        let server = NodeIdentity::from_seed([4u8; 32]).node_id();
        let mut config = tools_config(&root, server, &[("a", &["cat"])]);
        config.trust_root = NodeIdentity::from_seed([9u8; 32]).node_id();
        let (res, _, _) = run_call(config, &root, invoke("nope", &[]), b"").await;
        let reason = denied_reason(res);
        assert!(reason.contains("membership rejected"), "{reason}");
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(24))]

        /// Whatever valid `Argv` a caller sends reaches the child's argv
        /// byte-for-byte: `printf '%s\0'` echoes each argument NUL-terminated
        /// (a NUL can't occur inside an `Argv`), after a fixed marker that
        /// separates the tool's own argv from the caller's.
        #[test]
        fn any_argv_reaches_the_child_verbatim(
            args in proptest::collection::vec("[^\u{0}]{0,16}", 0..8),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let (res, out, _) = rt.block_on(async {
                let root = NodeIdentity::from_seed([1u8; 32]);
                let server = NodeIdentity::from_seed([4u8; 32]).node_id();
                let config = tools_config(&root, server, &[("echo", &["printf", "%s\\0", "MARK"])]);
                let invocation = Invocation {
                    tool: ToolName::new("echo").unwrap(),
                    argv: Argv::new(args.clone()).unwrap(),
                };
                run_call(config, &root, invocation, b"").await
            });
            proptest::prop_assert_eq!(res.unwrap(), 0);
            let mut expected = b"MARK\0".to_vec();
            for a in &args {
                expected.extend_from_slice(a.as_bytes());
                expected.push(0);
            }
            proptest::prop_assert_eq!(out, expected);
        }
    }

    /// Two exposed tools + `wires call` over a real loopback endpoint:
    /// `call_on` carries the invocation, and each call runs its own tool.
    #[tokio::test]
    async fn loopback_expose_and_call() {
        let root = NodeIdentity::from_seed([80u8; 32]);
        let server = NodeIdentity::from_seed([81u8; 32]);
        let client = NodeIdentity::from_seed([82u8; 32]);
        let membership = Membership::mint(&root, client.node_id(), 0, i64::MAX).unwrap();

        let server_ep = test_endpoint(&server).await;
        let addr = endpoint_addr(&server.node_id(), &localhost_socks(&server_ep), None).unwrap();
        let mut config = test_config(&root, server.node_id(), Vec::new());
        config.tools = BTreeMap::from([
            (
                ToolName::new("shout").unwrap(),
                ["tr", "a-z", "A-Z"].map(String::from).to_vec(),
            ),
            (
                ToolName::new("echo").unwrap(),
                ["printf", "%s|"].map(String::from).to_vec(),
            ),
        ]);
        let srv = tokio::spawn(serve_on(server_ep, config));

        let client_ep = test_endpoint(&client).await;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = call_on(
            client_ep,
            addr.clone(),
            membership.clone(),
            None,
            invoke("shout", &[]),
            std::io::Cursor::new(b"hello over wires".to_vec()),
            &mut out,
            &mut err,
        )
        .await
        .unwrap();
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        assert_eq!(out, b"HELLO OVER WIRES");

        // The other tool, with arguments.
        let client_ep = test_endpoint(&client).await;
        let mut out = Vec::new();
        let res = call_on(
            client_ep,
            addr,
            membership,
            None,
            invoke("echo", &["a b"]),
            std::io::Cursor::new(Vec::new()),
            &mut out,
            &mut Vec::new(),
        )
        .await;
        assert_eq!(res.unwrap(), 0);
        assert_eq!(out, b"a b|");
        srv.abort();
    }
}

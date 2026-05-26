//! The iroh session transport: bind/dial, the grant handshake, and the stdio
//! bridge.
//!
//! `library` stays pure (no iroh/tokio); this module is where the
//! capability-addressed session meets the iroh QUIC endpoint. The session ALPN
//! is [`ALPN`]. A dialer opens a bi-stream and sends a
//! [`Frame::Handshake`](library::Frame::Handshake) bearing its fabric
//! [`Membership`](library::Membership) and (for a scoped session) a
//! [`Grant`](library::Grant); the responder verifies inclusion with
//! [`library::check_inclusion`] (and, when scoped, the grant with
//! [`library::check_accept`]) against the iroh-authenticated caller, then execs
//! the configured child — with the verified caller identity injected into its
//! environment — and bridges its stdio over tagged frames.

use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::presets::N0;
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use library::{
    Chunk, Crl, Frame, Grant, InclusionProof, Membership, NodeId, NodeIdentity, RosterHead, Scope,
    check_accept, check_inclusion, check_roster_inclusion,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::mpsc;

/// The custom ALPN identifying a wires capability session.
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

/// The responder's static configuration: what it trusts, what it serves, the
/// optional roster head it enforces, the identity it presents in the ack, and
/// the child to exec. Built once per `serve` and shared across connections.
pub struct ServeConfig {
    /// The trusted fabric root whose memberships, grants, and head are honored.
    pub trust_root: NodeId,
    /// The scope this responder serves; `None` is inclusion-only.
    pub scope: Option<Scope>,
    /// The revocation list applied to the slice-1 credential checks.
    pub crl: Crl,
    /// When `Some`, the head a caller's inclusion proof is checked against.
    pub roster_head: Option<RosterHead>,
    /// The responder's own membership, presented in the `HandshakeAck`.
    pub membership: Membership,
    /// The responder's own inclusion proof, presented if set (unused by the
    /// dialer in this slice; reverse roster-freshness is deferred).
    pub proof: Option<InclusionProof>,
    /// The command (program + args) to exec per session.
    pub command: Vec<String>,
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
/// addresses and relay URL from the ticket. With no hints this is a bare addr
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

// ---------------------------------------------------------------------------
// Responder (`wires serve`)
// ---------------------------------------------------------------------------

/// Bind for `node` and serve the session ALPN (see [`serve_on`]).
pub async fn serve(node: NodeIdentity, config: ServeConfig, relay_url: Option<&str>) -> Result<()> {
    let endpoint = bind(&node, relay_url).await?;
    serve_on(endpoint, config).await
}

/// Accept connections on `endpoint`, verifying each caller against `config`, then
/// exec `config.command` and bridge its stdio. One task per connection; a
/// rejected or failed connection is logged at `warn` and does not stop the
/// listener.
pub async fn serve_on(endpoint: Endpoint, config: ServeConfig) -> Result<()> {
    tracing::info!(
        node = %to_node_id(&endpoint.id()).hex(),
        scope = ?config.scope.as_ref().map(Scope::as_str),
        enforcing_head = config.roster_head.is_some(),
        sockets = ?endpoint.bound_sockets(),
        "serving session ALPN (egress-only)"
    );
    if config.scope.is_none() {
        tracing::warn!("inclusion-only: any fabric member may connect");
    }
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
    let caller = to_node_id(&conn.remote_id());
    tracing::info!(caller = %caller.hex(), "connection accepted (iroh-authenticated)");
    let (send, recv) = conn.accept_bi().await.context("accepting bi-stream")?;

    serve_session(send, recv, caller, config).await?;

    // Wait for the dialer to read the final frames and close, so we don't tear
    // the connection down mid-flush. Bounded so a vanished dialer can't pin us.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), conn.closed()).await;
    Ok(())
}

/// The responder half of a session over an established, already-authenticated
/// bi-stream: read and verify the handshake against `caller` and `config`, send a
/// `HandshakeAck`, then exec `config.command` and bridge its stdio. `caller` must
/// already be authenticated by whoever supplies the streams.
async fn serve_session<S, R>(
    mut send: S,
    mut recv: R,
    caller: NodeId,
    config: &ServeConfig,
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
    let (membership, grant, proof) = match first {
        Some(Frame::Handshake {
            membership,
            grant,
            proof,
        }) => (membership, grant, proof),
        Some(_) => bail!("first frame was not a handshake"),
        None => bail!("connection closed before handshake"),
    };
    let now = crate::now_unix();

    // Inclusion is always required: the caller must prove fabric membership,
    // bound to its iroh-authenticated key.
    check_inclusion(&membership, config.trust_root, caller, now, &config.crl)
        .map_err(|e| anyhow!("membership rejected: {e}"))?;

    // A scoped responder additionally requires a matching, accepted grant.
    if let Some(scope) = config.scope.as_ref() {
        let grant = grant
            .as_ref()
            .ok_or_else(|| anyhow!("scoped session requires a grant; none presented"))?;
        check_accept(grant, config.trust_root, caller, now, &config.crl)
            .map_err(|e| anyhow!("grant rejected: {e}"))?;
        if grant.scope.as_str() != scope.as_str() {
            bail!(
                "grant scope {:?} does not match served scope {:?}",
                grant.scope.as_str(),
                scope.as_str()
            );
        }
    }

    // Defense-in-depth: if a grant rode along, it must name the same node as the
    // membership. Redundant (both are pinned to `caller`) but cheap, and it
    // guards against a future refactor that loosens one path.
    if let Some(grant) = grant.as_ref()
        && grant.subject != membership.member
    {
        bail!("grant subject does not match membership member");
    }

    // Roster head gate: when a head is configured, require a proof and check the
    // caller's *current* membership; remember the admitting version.
    let roster_version = roster_gate(config, proof.as_ref(), caller, now)?;

    tracing::info!(
        caller = %caller.hex(),
        scope = ?config.scope.as_ref().map(Scope::as_str),
        roster_version = ?roster_version,
        "session accepted"
    );

    // Mutual inclusion: present our own membership (+ optional proof) so a
    // ticket-less dialer can verify us before streaming stdin. Written directly
    // on `send` so it is the first frame back, before any child output.
    write_frame(
        &mut send,
        &Frame::HandshakeAck {
            membership: config.membership.clone(),
            proof: config.proof.clone(),
        },
    )
    .await?;

    // Spawn the configured child with piped stdio, injecting the verified caller
    // identity (and the admitting roster version, if any). Scrub any inherited
    // `WIRES_*` first so a malicious parent environment cannot smuggle a stale
    // identity to a child that trusts it. These are *server-derived,
    // post-verification* values — `caller` is the iroh-authenticated peer, never a
    // handshake claim — and are public ids, not secrets.
    let (program, args) = config
        .command
        .split_first()
        .ok_or_else(|| anyhow!("empty serve command"))?;
    tracing::info!(program = %program, "spawning child and bridging stdio");
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_remove("WIRES_CALLER_NODE")
        .env_remove("WIRES_FABRIC_ROOT")
        .env_remove("WIRES_MEMBERSHIP_NOT_AFTER")
        .env_remove("WIRES_ROSTER_VERSION")
        .env("WIRES_CALLER_NODE", caller.hex())
        .env("WIRES_FABRIC_ROOT", config.trust_root.hex())
        .env("WIRES_MEMBERSHIP_NOT_AFTER", membership.not_after.to_string());
    if let Some(v) = roster_version {
        cmd.env("WIRES_ROSTER_VERSION", v.to_string());
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {program}"))?;
    let mut child_stdin = child.stdin.take().context("child stdin")?;
    let child_stdout = child.stdout.take().context("child stdout")?;
    let child_stderr = child.stderr.take().context("child stderr")?;

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

    let out_task = tokio::spawn(pump_reader(child_stdout, Frame::Stdout, tx.clone()));
    let err_task = tokio::spawn(pump_reader(child_stderr, Frame::Stderr, tx.clone()));

    let status = child.wait().await.context("waiting for child")?;
    out_task.await.context("stdout pump")??;
    err_task.await.context("stderr pump")??;
    let _ = stdin_task.await;

    let code = status.code().unwrap_or(-1);
    tracing::info!(code, "child exited; closing session");
    tx.send(Frame::Exit(code)).await.ok();
    drop(tx);
    writer.await.context("writer task")??;
    Ok(())
}

/// The roster head gate. When `config.roster_head` is `None`, returns `Ok(None)`
/// (slice-1 behavior). When `Some`, requires `proof` and checks the caller's
/// *current* membership against the head, returning the admitting version for
/// `WIRES_ROSTER_VERSION`.
fn roster_gate(
    config: &ServeConfig,
    proof: Option<&InclusionProof>,
    caller: NodeId,
    now: i64,
) -> Result<Option<u64>> {
    let Some(head) = config.roster_head.as_ref() else {
        return Ok(None);
    };
    let proof = proof.ok_or(library::Error::InclusionProofRequired)?;
    check_roster_inclusion(head, proof, config.trust_root, caller, now)
        .map_err(|e| anyhow!("roster inclusion rejected: {e}"))?;
    Ok(Some(head.version.0))
}

// ---------------------------------------------------------------------------
// Dialer (`wires connect`)
// ---------------------------------------------------------------------------

/// Bind for `node` and dial `target` (see [`connect_on`]).
#[allow(clippy::too_many_arguments)]
pub async fn connect_io<R, W, E>(
    node: NodeIdentity,
    target: EndpointAddr,
    membership: Membership,
    grant: Option<Grant>,
    proof: Option<InclusionProof>,
    ticketless: bool,
    relay_url: Option<&str>,
    stdin: R,
    stdout: W,
    stderr: E,
) -> Result<i32>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let endpoint = bind(&node, relay_url).await?;
    connect_on(
        endpoint, target, membership, grant, proof, ticketless, stdin, stdout, stderr,
    )
    .await
}

/// Dial `target` on `endpoint`, present `membership` (+ `grant`/`proof` if any),
/// then bridge local stdio and return the child's exit code. When `ticketless`,
/// verify the responder's `HandshakeAck` membership before forwarding any stdin.
#[allow(clippy::too_many_arguments)]
pub async fn connect_on<R, W, E>(
    endpoint: Endpoint,
    target: EndpointAddr,
    membership: Membership,
    grant: Option<Grant>,
    proof: Option<InclusionProof>,
    ticketless: bool,
    stdin: R,
    stdout: W,
    stderr: E,
) -> Result<i32>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    tracing::info!("dialing the capability over wires");
    let conn = endpoint
        .connect(target, ALPN)
        .await
        .map_err(|e| anyhow!("dialing target: {e}"))?;
    let target_id = to_node_id(&conn.remote_id());
    let (send, recv) = conn.open_bi().await.context("opening bi-stream")?;
    tracing::info!("session open; presenting membership and bridging stdio");

    let verify_target = ticketless.then_some(target_id);
    let result = dial_session(
        send,
        recv,
        membership,
        grant,
        proof,
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
/// `Some` (ticket-less mode), verifies the responder's membership against the
/// dialer's own fabric root and the authenticated target id **before** any stdin
/// is forwarded. On failure, aborts with no stdin sent.
///
/// Errors if the session ends **without** an [`Frame::Exit`] — a responder that
/// closes mid-session is a failure, not a silent success.
#[allow(clippy::too_many_arguments)]
async fn dial_session<S, R, I, W, E>(
    mut send: S,
    mut recv: R,
    membership: Membership,
    grant: Option<Grant>,
    proof: Option<InclusionProof>,
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
    write_frame(
        &mut send,
        &Frame::Handshake {
            membership,
            grant,
            proof,
        },
    )
    .await?;

    // Read the responder's ack first (it is always the responder's first frame).
    let ack_membership = match read_frame(&mut recv).await? {
        Some(Frame::HandshakeAck { membership, .. }) => membership,
        Some(_) => bail!("responder's first frame was not a handshake ack"),
        None => bail!("responder closed before sending a handshake ack"),
    };
    // Ticket-less: verify the service is a fabric member before streaming stdin.
    // Credential-only (root-vouched + TTL); reverse roster-freshness is deferred.
    if let Some(target_id) = verify_target {
        check_inclusion(
            &ack_membership,
            fabric_root,
            target_id,
            crate::now_unix(),
            &Crl::new(),
        )
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
    /// for use as a ticket's direct `addrs` (so a dialer reaches it without
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
        let grant = Grant::mint(&root, subject, Scope::new("tools.rg"), i64::MAX).unwrap();
        let frames = vec![
            Frame::Handshake {
                membership: membership.clone(),
                grant: Some(grant),
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

    /// A responder config for tests: server is a fabric member under `root`.
    fn test_config(
        root: &NodeIdentity,
        server: NodeId,
        scope: Option<&str>,
        crl: Crl,
        command: Vec<String>,
    ) -> ServeConfig {
        ServeConfig {
            trust_root: root.node_id(),
            scope: scope.map(Scope::new),
            crl,
            roster_head: None,
            membership: Membership::mint(root, server, 0, i64::MAX).unwrap(),
            proof: None,
            command,
        }
    }

    /// Run a full session over two in-memory duplex pipes (no iroh): returns the
    /// dialer's exit result plus captured stdout/stderr. Ticketed (grant present,
    /// ack ignored).
    async fn run_session(
        command: Vec<String>,
        input: &[u8],
        served_scope: &str,
    ) -> (Result<i32>, Vec<u8>, Vec<u8>) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let server = NodeIdentity::from_seed([4u8; 32]).node_id();
        let membership = Membership::mint(&root, caller, 0, i64::MAX).unwrap();
        let grant = Grant::mint(&root, caller, Scope::new(served_scope), i64::MAX).unwrap();

        let (c2s_w, c2s_r) = tokio::io::duplex(64 * 1024); // dialer -> responder
        let (s2c_w, s2c_r) = tokio::io::duplex(64 * 1024); // responder -> dialer

        let config = test_config(&root, server, Some(served_scope), Crl::new(), command);
        let srv = tokio::spawn(async move { serve_session(s2c_w, c2s_r, caller, &config).await });

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = dial_session(
            c2s_w,
            s2c_r,
            membership,
            Some(grant),
            None, // dialer proof
            None, // verify_target: ticketed → ignore ack
            std::io::Cursor::new(input.to_vec()),
            &mut out,
            &mut err,
        )
        .await;
        let _ = srv.await;
        (code, out, err)
    }

    /// Whether the responder rejects a handshake bearing `membership` / `grant`
    /// for a session serving `served_scope` (`None` = inclusion-only).
    async fn serve_rejects(
        membership: Membership,
        grant: Option<Grant>,
        trust_root: NodeId,
        served_scope: Option<&str>,
        crl: Crl,
        caller: NodeId,
    ) -> bool {
        let recv = std::io::Cursor::new(
            Frame::Handshake {
                membership,
                grant,
                proof: None,
            }
            .encode()
            .unwrap(),
        );
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
            trust_root,
            scope: served_scope.map(Scope::new),
            crl,
            roster_head: None,
            membership: server_membership,
            proof: None,
            command: vec!["cat".to_string()],
        };
        serve_session(send, recv, caller, &config).await.is_err()
    }

    #[tokio::test]
    async fn session_echoes_stdin() {
        let (code, out, err) =
            run_session(vec!["cat".to_string()], b"hello over wires", "tools.cat").await;
        assert_eq!(code.unwrap(), 0);
        assert_eq!(out, b"hello over wires");
        assert!(err.is_empty());
    }

    #[tokio::test]
    async fn session_propagates_nonzero_exit() {
        let (code, _out, _err) = run_session(
            vec!["sh".into(), "-c".into(), "exit 3".into()],
            b"",
            "tools.sh",
        )
        .await;
        assert_eq!(code.unwrap(), 3);
    }

    #[tokio::test]
    async fn session_routes_stderr_separately() {
        let (code, out, err) = run_session(
            vec!["sh".into(), "-c".into(), "printf oops 1>&2".into()],
            b"",
            "tools.sh",
        )
        .await;
        assert_eq!(code.unwrap(), 0);
        assert!(out.is_empty());
        assert_eq!(err, b"oops");
    }

    /// Mint a valid membership for `caller` under `root` (used to isolate
    /// grant-side rejections, which run only after inclusion succeeds).
    fn valid_membership(root: &NodeIdentity, caller: NodeId) -> Membership {
        Membership::mint(root, caller, 0, i64::MAX).unwrap()
    }

    #[tokio::test]
    async fn session_rejects_scope_mismatch() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let m = valid_membership(&root, caller);
        let grant = Grant::mint(&root, caller, Scope::new("tools.b"), i64::MAX).unwrap();
        assert!(
            serve_rejects(
                m,
                Some(grant),
                root.node_id(),
                Some("tools.a"),
                Crl::new(),
                caller
            )
            .await
        );
    }

    #[tokio::test]
    async fn session_rejects_expired_grant() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let m = valid_membership(&root, caller);
        // not_after = 0 (1970) is always in the past.
        let grant = Grant::mint(&root, caller, Scope::new("s"), 0).unwrap();
        assert!(
            serve_rejects(
                m,
                Some(grant),
                root.node_id(),
                Some("s"),
                Crl::new(),
                caller
            )
            .await
        );
    }

    #[tokio::test]
    async fn session_rejects_revoked_subject() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let m = valid_membership(&root, caller);
        let grant = Grant::mint(&root, caller, Scope::new("s"), i64::MAX).unwrap();
        let mut crl = Crl::new();
        crl.insert(caller);
        assert!(serve_rejects(m, Some(grant), root.node_id(), Some("s"), crl, caller).await);
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
        let config = test_config(&root, server, None, Crl::new(), vec!["cat".to_string()]);
        let srv = tokio::spawn(async move { serve_session(s2c_w, c2s_r, caller, &config).await });

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = dial_session(
            c2s_w,
            s2c_r,
            membership,
            None,
            None,
            None, // ticketed-style call: do not verify ack
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
        assert!(serve_rejects(m, None, root.node_id(), None, Crl::new(), caller).await);
    }

    #[tokio::test]
    async fn session_rejects_expired_membership() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let m = Membership::mint(&root, caller, 0, 0).unwrap(); // not_after 1970
        assert!(serve_rejects(m, None, root.node_id(), None, Crl::new(), caller).await);
    }

    #[tokio::test]
    async fn session_rejects_revoked_member() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let m = valid_membership(&root, caller);
        let mut crl = Crl::new();
        crl.insert(caller);
        assert!(serve_rejects(m, None, root.node_id(), None, crl, caller).await);
    }

    #[tokio::test]
    async fn session_rejects_member_not_caller() {
        // The credential is for `member`, but a different peer authenticated.
        let root = NodeIdentity::from_seed([1u8; 32]);
        let member = NodeIdentity::from_seed([2u8; 32]).node_id();
        let caller = NodeIdentity::from_seed([3u8; 32]).node_id();
        let m = valid_membership(&root, member);
        assert!(serve_rejects(m, None, root.node_id(), None, Crl::new(), caller).await);
    }

    #[tokio::test]
    async fn scoped_session_requires_a_grant() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let m = valid_membership(&root, caller);
        // A scope is served but no grant is presented.
        assert!(
            serve_rejects(
                m,
                None,
                root.node_id(),
                Some("tools.cat"),
                Crl::new(),
                caller
            )
            .await
        );
    }

    #[tokio::test]
    async fn scoped_session_rejects_grant_for_other_subject() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let caller = NodeIdentity::from_seed([2u8; 32]).node_id();
        let other = NodeIdentity::from_seed([7u8; 32]).node_id();
        let m = valid_membership(&root, caller);
        let grant = Grant::mint(&root, other, Scope::new("tools.cat"), i64::MAX).unwrap();
        assert!(
            serve_rejects(
                m,
                Some(grant),
                root.node_id(),
                Some("tools.cat"),
                Crl::new(),
                caller
            )
            .await
        );
    }

    /// Full scoped flow over a real (loopback) iroh connection: dial →
    /// handshake (membership + grant) → `serve` execs `cat` → stdin echoes back
    /// on stdout → exit 0.
    #[tokio::test]
    async fn loopback_echo_round_trip() {
        let root = NodeIdentity::from_seed([10u8; 32]);
        let server = NodeIdentity::from_seed([11u8; 32]);
        let client = NodeIdentity::from_seed([12u8; 32]);
        let scope = Scope::new("tools.cat");
        let membership = Membership::mint(&root, client.node_id(), 0, i64::MAX).unwrap();
        let grant = Grant::mint(&root, client.node_id(), scope.clone(), i64::MAX).unwrap();

        let server_ep = test_endpoint(&server).await;
        // Dial via the production `endpoint_addr` using direct socket hints —
        // the same path a ticket's `addrs` take, no discovery involved.
        let addr = endpoint_addr(&server.node_id(), &localhost_socks(&server_ep), None).unwrap();
        let srv = tokio::spawn(serve_on(
            server_ep,
            test_config(
                &root,
                server.node_id(),
                Some("tools.cat"),
                Crl::new(),
                vec!["cat".to_string()],
            ),
        ));

        let client_ep = test_endpoint(&client).await;
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let code = connect_on(
            client_ep,
            addr,
            membership,
            Some(grant),
            None,  // proof
            false, // ticketed
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
                None,
                Crl::new(),
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
        let code = connect_on(
            client_ep,
            addr,
            membership,
            None,
            None, // proof
            true, // ticket-less → verify the responder's ack
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

    /// A grant minted by the wrong root is refused (membership is valid, so the
    /// grant is what's rejected).
    #[tokio::test]
    async fn loopback_rejects_untrusted_grant() {
        let trusted_root = NodeIdentity::from_seed([20u8; 32]);
        let evil_root = NodeIdentity::from_seed([21u8; 32]);
        let server = NodeIdentity::from_seed([22u8; 32]);
        let client = NodeIdentity::from_seed([23u8; 32]);
        let scope = Scope::new("tools.cat");
        let membership = Membership::mint(&trusted_root, client.node_id(), 0, i64::MAX).unwrap();
        // Signed by evil_root, but the server only trusts trusted_root.
        let grant = Grant::mint(&evil_root, client.node_id(), scope.clone(), i64::MAX).unwrap();

        let server_ep = test_endpoint(&server).await;
        let addr = endpoint_addr(&server.node_id(), &localhost_socks(&server_ep), None).unwrap();
        let srv = tokio::spawn(serve_on(
            server_ep,
            test_config(
                &trusted_root,
                server.node_id(),
                Some("tools.cat"),
                Crl::new(),
                vec!["cat".to_string()],
            ),
        ));

        let client_ep = test_endpoint(&client).await;
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        // The responder refuses the handshake and drops the connection, so the
        // dialer's session fails (no child ran, nothing on stdout).
        let result = connect_on(
            client_ep,
            addr,
            membership,
            Some(grant),
            None,  // proof
            false, // ticketed
            std::io::Cursor::new(Vec::new()),
            &mut out,
            &mut err,
        )
        .await;
        assert!(
            result.is_err(),
            "dialer should fail when the responder refuses the grant"
        );
        assert!(out.is_empty());
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
                None,
                Crl::new(),
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
        let result = connect_on(
            client_ep,
            addr,
            membership,
            None,
            None, // proof
            true, // ticket-less
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
            trust_root: root.node_id(),
            scope: None,
            crl: Crl::new(),
            roster_head: Some(head),
            membership: Membership::mint(root, server, 0, i64::MAX).unwrap(),
            proof: None,
            command,
        };
        (config, proof)
    }

    /// Drive `serve_session` against a one-shot handshake; returns the result.
    async fn serve_once(config: ServeConfig, caller: NodeId, handshake: Frame) -> Result<()> {
        let recv = std::io::Cursor::new(handshake.encode().unwrap());
        let send: Vec<u8> = Vec::new();
        serve_session(send, recv, caller, &config).await
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
                grant: None,
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
                grant: None,
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
                grant: None,
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
        config.roster_head = Some(v2_head);
        let membership = Membership::mint(&root, caller, 0, i64::MAX).unwrap();
        let res = serve_once(
            config,
            caller,
            Frame::Handshake {
                membership,
                grant: None,
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
            trust_root: root.node_id(),
            scope: None,
            crl: Crl::new(),
            roster_head: Some(head),
            membership: Membership::mint(&root, server.node_id(), 0, i64::MAX).unwrap(),
            proof: None,
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                r#"printf "%s,%s" "$WIRES_CALLER_NODE" "$WIRES_ROSTER_VERSION""#.to_string(),
            ],
        };
        let srv = tokio::spawn(serve_on(server_ep, config));

        let client_ep = test_endpoint(&client).await;
        let membership = Membership::mint(&root, client.node_id(), 0, i64::MAX).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = connect_on(
            client_ep,
            addr,
            membership,
            None,
            Some(client_proof),
            true, // ticket-less
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
            trust_root: root.node_id(),
            scope: None,
            crl: Crl::new(),
            roster_head: Some(v2),
            membership: Membership::mint(&root, server.node_id(), 0, i64::MAX).unwrap(),
            proof: None,
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                "echo SHOULD_NOT_RUN".to_string(),
            ],
        };
        let srv = tokio::spawn(serve_on(server_ep, config));

        let client_ep = test_endpoint(&client).await;
        let membership = Membership::mint(&root, client.node_id(), 0, i64::MAX).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = connect_on(
            client_ep,
            addr,
            membership,
            None,
            Some(client_proof),
            true,
            std::io::Cursor::new(Vec::new()),
            &mut out,
            &mut err,
        )
        .await;
        assert!(result.is_err());
        assert!(out.is_empty());
        srv.abort();
    }

    /// Mutual inclusion: a ticket-less dialer aborts (no stdin echoed) when the
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
                trust_root,
                scope: None,
                crl: Crl::new(),
                roster_head: None,
                membership: Membership::mint(signer, server.node_id(), 0, i64::MAX).unwrap(),
                proof: None,
                command: vec!["cat".to_string()],
            };
            let srv = tokio::spawn(serve_on(server_ep, config));
            let client_ep = test_endpoint(client).await;
            let mut out = Vec::new();
            let mut err = Vec::new();
            let code = connect_on(
                client_ep,
                addr,
                client_membership,
                None,
                None,
                true, // ticket-less → verify the responder
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
}

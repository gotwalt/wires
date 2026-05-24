//! The iroh session transport: bind/dial, the grant handshake, and the stdio
//! bridge.
//!
//! `library` stays pure (no iroh/tokio); this module is where the
//! capability-addressed session meets the iroh QUIC endpoint. The session ALPN
//! is [`ALPN`]. A dialer opens a bi-stream and sends a
//! [`Frame::Handshake`](library::Frame::Handshake); the responder verifies it
//! with [`library::check_accept`] against the iroh-authenticated caller, then
//! execs the configured child and bridges its stdio over tagged frames.

use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::presets::N0;
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use library::{Chunk, Crl, Frame, Grant, NodeId, NodeIdentity, Scope, check_accept};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::mpsc;

/// The custom ALPN identifying a wires capability session.
pub const ALPN: &[u8] = b"wires/session/0";

/// Read buffer size for pumping child / local stdio into frames.
const PUMP_BUF: usize = 64 * 1024;

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

/// The bare [`EndpointAddr`] for a node id (no direct IP; resolved via
/// discovery / relays at dial time).
pub fn endpoint_addr(node: &NodeId) -> Result<EndpointAddr> {
    Ok(EndpointAddr::from(endpoint_id(node)?))
}

/// Bind an iroh endpoint for `identity` on the session ALPN, using the n0
/// preset for discovery + relays.
pub async fn bind(identity: &NodeIdentity) -> Result<Endpoint> {
    Endpoint::builder(N0)
        .secret_key(secret_key(identity))
        .alpns(vec![ALPN.to_vec()])
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
pub async fn serve(
    node: NodeIdentity,
    trust_root: NodeId,
    scope: Scope,
    crl: Crl,
    command: Vec<String>,
) -> Result<()> {
    let endpoint = bind(&node).await?;
    serve_on(endpoint, trust_root, scope, crl, command).await
}

/// Accept connections on `endpoint`, verifying each caller's grant against
/// `trust_root` / `scope` / `crl`, then exec `command` and bridge its stdio.
///
/// One spawned task per connection; a rejected or failed connection logs to
/// stderr and does not bring down the listener.
pub async fn serve_on(
    endpoint: Endpoint,
    trust_root: NodeId,
    scope: Scope,
    crl: Crl,
    command: Vec<String>,
) -> Result<()> {
    let scope = Arc::new(scope);
    let crl = Arc::new(crl);
    let command = Arc::new(command);
    while let Some(incoming) = endpoint.accept().await {
        let scope = Arc::clone(&scope);
        let crl = Arc::clone(&crl);
        let command = Arc::clone(&command);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, trust_root, &scope, &crl, &command).await {
                eprintln!("wires serve: connection error: {e:#}");
            }
        });
    }
    Ok(())
}

/// Verify one inbound connection's handshake, then exec + bridge.
async fn handle_connection(
    incoming: iroh::endpoint::Incoming,
    trust_root: NodeId,
    scope: &Scope,
    crl: &Crl,
    command: &[String],
) -> Result<()> {
    let conn = incoming.await.context("accepting connection")?;
    let caller = to_node_id(&conn.remote_id());
    let (mut send, mut recv) = conn.accept_bi().await.context("accepting bi-stream")?;

    // The first frame must be the grant-bearing handshake.
    let grant = match read_frame(&mut recv).await? {
        Some(Frame::Handshake { grant }) => grant,
        Some(_) => bail!("first frame was not a handshake"),
        None => bail!("connection closed before handshake"),
    };
    check_accept(&grant, trust_root, caller, crate::now_unix(), crl)
        .map_err(|e| anyhow!("grant rejected: {e}"))?;
    if grant.scope.as_str() != scope.as_str() {
        bail!(
            "grant scope {:?} does not match served scope {:?}",
            grant.scope.as_str(),
            scope.as_str()
        );
    }

    // Spawn the configured child with piped stdio.
    let (program, args) = command
        .split_first()
        .ok_or_else(|| anyhow!("empty serve command"))?;
    let mut child = Command::new(program)
        .args(args)
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
        while let Some(frame) = rx.recv().await {
            write_frame(&mut send, &frame).await?;
        }
        let _ = send.finish();
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
    let _ = out_task.await.context("stdout pump")?;
    let _ = err_task.await.context("stderr pump")?;
    let _ = stdin_task.await;

    let code = status.code().unwrap_or(-1);
    tx.send(Frame::Exit(code)).await.ok();
    drop(tx);
    writer.await.context("writer task")??;
    Ok(())
}

// ---------------------------------------------------------------------------
// Dialer (`wires connect`)
// ---------------------------------------------------------------------------

/// Bind for `node` and dial `target` (see [`connect_on`]).
pub async fn connect_io<R, W, E>(
    node: NodeIdentity,
    target: EndpointAddr,
    grant: Grant,
    stdin: R,
    stdout: W,
    stderr: E,
) -> Result<i32>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let endpoint = bind(&node).await?;
    connect_on(endpoint, target, grant, stdin, stdout, stderr).await
}

/// Dial `target` on `endpoint`, present `grant`, then bridge local stdio over
/// the session and return the child's exit code.
pub async fn connect_on<R, W, E>(
    endpoint: Endpoint,
    target: EndpointAddr,
    grant: Grant,
    stdin: R,
    mut stdout: W,
    mut stderr: E,
) -> Result<i32>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let conn = endpoint
        .connect(target, ALPN)
        .await
        .map_err(|e| anyhow!("dialing target: {e}"))?;
    let (mut send, mut recv) = conn.open_bi().await.context("opening bi-stream")?;

    write_frame(&mut send, &Frame::Handshake { grant }).await?;

    // Local stdin -> Stdin frames, then finish the send direction (signals EOF).
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
        let _ = send.finish();
        Ok::<(), anyhow::Error>(())
    });

    // Server frames -> local stdout/stderr; Exit ends the session.
    let mut code = 0;
    loop {
        match read_frame(&mut recv).await? {
            Some(Frame::Stdout(chunk)) => stdout.write_all(chunk.as_bytes()).await?,
            Some(Frame::Stderr(chunk)) => stderr.write_all(chunk.as_bytes()).await?,
            Some(Frame::Exit(c)) => {
                code = c;
                break;
            }
            Some(_) => {} // ignore unexpected frames from the responder
            None => break,
        }
    }
    stdout.flush().await.ok();
    stderr.flush().await.ok();
    stdin_task.abort();
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an endpoint with no discovery/relay (hermetic) for loopback tests.
    async fn test_endpoint(identity: &NodeIdentity) -> Endpoint {
        Endpoint::empty_builder()
            .secret_key(secret_key(identity))
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap()
    }

    /// The endpoint's address with wildcard binds rewritten to localhost, so a
    /// dialer can reach it directly without discovery.
    fn local_endpoint_addr(endpoint: &Endpoint) -> EndpointAddr {
        let mut addr = EndpointAddr::new(endpoint.id());
        for sock in endpoint.bound_sockets() {
            let local = match sock {
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
            };
            addr = addr.with_ip_addr(local);
        }
        addr
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
        let grant = Grant::mint(&root, subject, Scope::new("tools.rg"), i64::MAX).unwrap();
        let frames = vec![
            Frame::Handshake { grant },
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

    /// Full Flow A over a real (loopback) iroh connection: dial → handshake →
    /// `serve` execs `cat` → stdin echoes back on stdout → exit 0.
    #[tokio::test]
    async fn loopback_echo_round_trip() {
        let root = NodeIdentity::from_seed([10u8; 32]);
        let server = NodeIdentity::from_seed([11u8; 32]);
        let client = NodeIdentity::from_seed([12u8; 32]);
        let scope = Scope::new("tools.cat");
        let grant = Grant::mint(&root, client.node_id(), scope.clone(), i64::MAX).unwrap();

        let server_ep = test_endpoint(&server).await;
        let addr = local_endpoint_addr(&server_ep);
        let srv = tokio::spawn(serve_on(
            server_ep,
            root.node_id(),
            scope,
            Crl::new(),
            vec!["cat".to_string()],
        ));

        let client_ep = test_endpoint(&client).await;
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let code = connect_on(
            client_ep,
            addr,
            grant,
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

    /// A grant minted by the wrong root is refused by the responder.
    #[tokio::test]
    async fn loopback_rejects_untrusted_grant() {
        let trusted_root = NodeIdentity::from_seed([20u8; 32]);
        let evil_root = NodeIdentity::from_seed([21u8; 32]);
        let server = NodeIdentity::from_seed([22u8; 32]);
        let client = NodeIdentity::from_seed([23u8; 32]);
        let scope = Scope::new("tools.cat");
        // Signed by evil_root, but the server only trusts trusted_root.
        let grant = Grant::mint(&evil_root, client.node_id(), scope.clone(), i64::MAX).unwrap();

        let server_ep = test_endpoint(&server).await;
        let addr = local_endpoint_addr(&server_ep);
        let srv = tokio::spawn(serve_on(
            server_ep,
            trusted_root.node_id(),
            scope,
            Crl::new(),
            vec!["cat".to_string()],
        ));

        let client_ep = test_endpoint(&client).await;
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        // The responder refuses the handshake and drops the connection, so the
        // dialer's session fails (no child ran, nothing on stdout).
        let result = connect_on(
            client_ep,
            addr,
            grant,
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
}

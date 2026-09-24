//! The host's control sockets: how `wires push` reaches the running `wires
//! serve` on the same machine (card 23).
//!
//! The push queue, the host's endpoint and its call log belong to the one
//! `serve` process, so `wires push` is a *request to it*, over a unix socket.
//! There are two, each with its own [`Authority`]:
//!
//! - the **operator** socket, `$WIRES_HOME/run/serve.sock`
//!   ([`host_socket`](crate::host::push::host_socket)): `{"push":…}` to any
//!   node or role;
//! - the **child** socket, `push.sock` in a private directory made for each
//!   `serve` outside the keystore
//!   ([`ChildDir`](crate::host::capability::ChildDir)): only
//!   `{"caller_push":{"token":…,"push":…}}`, which reaches only the caller of
//!   the call that token was minted for
//!   ([`capability`](crate::host::capability)).
//!
//! A home too deep for a unix socket path puts the operator socket at
//! `$TMPDIR/wires-<uid>/<hash>.sock`, or the same under `/tmp`.
//!
//! ```text
//! push  → {"push":{"to":"…","subject":"build-41","body":"…"}}
//! serve ← {"pushed":{"results":[…]}}          (or {"err":"…"})
//! ```
//!
//! NDJSON, one request per line, replies in order on the same connection.
//!
//! # Who may connect
//!
//! The directory is `0700` and **owned by this user** (checked against
//! `geteuid()` by the server before it binds and by the operator's client
//! before it connects), and the socket is `0600`: on unix, connecting to a
//! socket requires write permission on the node, so the mode *is* the access
//! control, and it admits only this user — a socket reachable by another
//! local user would be a push-as-this-host capability. The directory mode is
//! the load-bearing half (it is set before the socket exists); the socket's
//! own mode is set immediately after `bind`. A service child running as the
//! same user isn't told where the operator socket is, but could still find it
//! (under the keystore's default path) and open it; only running services as
//! another Unix user (or, later, in a microVM) closes that.
//!
//! # Stale sockets
//!
//! A `serve` killed with `SIGKILL` leaves the socket file behind, and `bind`
//! on an existing path fails with `EADDRINUSE` whether or not anyone is
//! listening. The answer is a **connect probe**, not a blind unlink: if
//! something answers, another `serve` owns this home and this one must not
//! steal it; if the connect is refused, the file is a corpse and is removed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::host::capability::{Capabilities, PushToken};
use crate::host::push::{PushCommand, PushReport, PushSpec};
use crate::host::transport::truncate_reason;

/// The directory under the wires home that holds control sockets.
const RUN_DIR: &str = "run";

/// The most bytes one NDJSON request line may occupy (a line is read into
/// memory before it can be parsed, so an unbounded reader is a local memory
/// bomb).
pub const MAX_REQUEST_LINE: usize = 1024 * 1024;

/// How long `wires push` waits for the host's report (a push dials its
/// recipients, each bounded by [`DIRECT_BUDGET`](crate::host::push::DIRECT_BUDGET)).
pub const REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// How many hex characters of a hash name a short socket.
const SOCKET_NAME_HEX: usize = 16;

/// The run directory for control sockets under the wires home `home`.
pub fn run_dir(home: &Path) -> PathBuf {
    home.join(RUN_DIR)
}

/// The size of `sockaddr_un::sun_path`, NUL terminator included: 104 bytes on
/// macOS (and the BSDs), 108 on Linux.
const SUN_PATH_BYTES: usize = if cfg!(target_os = "linux") { 108 } else { 104 };

/// Whether `path` can be bound as a unix socket (it leaves room for the NUL).
pub fn fits_sockaddr(path: &Path) -> bool {
    path.as_os_str().as_encoded_bytes().len() < SUN_PATH_BYTES
}

/// A short stand-in for a control socket path too long to bind:
/// `<base>/wires-<uid>/<16 hex of BLAKE3(full path)>.sock`, under the first
/// of `bases` that yields a path which fits; `None` if none does.
///
/// Hashing the *full* path keeps the property the long path had — one socket
/// per home and socket name — and lets every process that can compute the
/// long path find the short one. The `wires-<uid>` directory is created `0700` by
/// [`ControlSocket::bind`] (which refuses one it cannot make private), so a
/// shared `/tmp` does not open the socket to other users.
pub fn short_socket_path(full: &Path, uid: u32, bases: &[PathBuf]) -> Option<PathBuf> {
    let mut hasher = library::OutputHasher::new();
    hasher.update(full.as_os_str().as_encoded_bytes());
    let digest = hasher.finish().hex();
    let name = format!("{}.sock", &digest[..SOCKET_NAME_HEX]);
    bases
        .iter()
        .map(|base| base.join(format!("wires-{uid}")).join(&name))
        .find(|path| fits_sockaddr(path))
}

/// One request from `wires push` to the running `serve`: externally tagged,
/// `{"push":{…}}`, which leaves room for later operations.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    /// Push a message to callers (`wires push`, card 23). Operator socket
    /// only.
    Push(PushSpec),
    /// Push to a call's caller under that call's push capability (`wires
    /// push` inside a service). Child socket only.
    CallerPush(CallerPush),
}

/// A push under a call's capability: the token `serve` gave the child, and
/// the push (whose `to` must be that call's caller).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerPush {
    /// `WIRES_PUSH_TOKEN`, as given.
    pub token: String,
    /// The push.
    pub push: PushSpec,
}

/// What a control socket lets its clients do.
#[derive(Clone, Debug)]
pub(crate) enum Authority {
    /// The operator's socket: any push.
    Operator,
    /// The child socket: only [`Request::CallerPush`] with a live token, to
    /// that token's caller.
    Calls(std::sync::Arc<Capabilities>),
}

/// One reply: `{"pushed":{…}}` or `{"err":"…"}`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    /// A push was handled: what happened per recipient.
    Pushed(PushReport),
    /// Refused, with the host's own words. Never fatal to the connection: the
    /// next line is still read.
    Err(String),
}

/// A bound control socket, unlinked when dropped.
#[derive(Debug)]
pub struct ControlSocket {
    /// The listening socket.
    listener: UnixListener,
    /// Its path, kept for the unlink and for error messages.
    path: PathBuf,
}

impl ControlSocket {
    /// Bind the control socket at `path`, creating its directory at `0700` and
    /// the socket at `0600`. An existing path is probed first: a socket
    /// somebody answers on means another `serve` owns it and this call fails;
    /// a socket nobody answers on is removed and rebound.
    pub async fn bind(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            ensure_private_dir(dir)?;
        }
        if path.exists() {
            if is_live(path).await {
                bail!(
                    "another `wires serve` is already running in this home (its control socket \
                     at {} answered); stop it before starting a second one",
                    path.display()
                );
            }
            tracing::warn!(socket = %path.display(), "removing a stale control socket");
            std::fs::remove_file(path)
                .with_context(|| format!("removing the stale control socket {}", path.display()))?;
        }
        let listener = UnixListener::bind(path)
            .with_context(|| format!("binding the control socket {}", path.display()))?;
        set_mode(path, 0o600);
        tracing::info!(socket = %path.display(), "control socket listening");
        Ok(Self {
            listener,
            path: path.to_path_buf(),
        })
    }

    /// Accept connections forever, handing every push `authority` allows to
    /// `push`. One task per connection, so a client that says nothing cannot
    /// wedge the others.
    async fn serve(self, push: mpsc::Sender<PushCommand>, authority: Authority) {
        loop {
            match self.listener.accept().await {
                Ok((stream, _)) => {
                    let push = push.clone();
                    let authority = authority.clone();
                    tokio::spawn(async move {
                        let (recv, send) = stream.into_split();
                        if let Err(e) = serve_conn(recv, send, push, &authority).await {
                            tracing::warn!("control connection ended: {e:#}");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(socket = %self.path.display(), "control accept failed: {e}");
                    // Usually transient (EMFILE); a tight spin would be worse.
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Spawn [`serve`](Self::serve) as a task (aborting it drops the socket
    /// and unlinks the file).
    pub fn spawn(self, push: mpsc::Sender<PushCommand>, authority: Authority) -> JoinHandle<()> {
        tokio::spawn(self.serve(push, authority))
    }
}

impl Drop for ControlSocket {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(socket = %self.path.display(), "could not unlink the control socket: {e}");
        }
    }
}

/// The NDJSON server loop over one duplex pair (generic, so it is testable
/// without a socket). Every line gets exactly one reply line, in order; a
/// malformed line, or one `authority` does not allow, is answered with
/// `{"err":…}`, not by hanging up.
pub(crate) async fn serve_conn<R, W>(
    recv: R,
    mut send: W,
    push: mpsc::Sender<PushCommand>,
    authority: &Authority,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(recv);
    let mut line = Vec::new();
    while read_capped_line(&mut reader, &mut line, MAX_REQUEST_LINE).await? {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let response = match (serde_json::from_slice::<Request>(&line), authority) {
            (Ok(Request::Push(spec)), Authority::Operator) => {
                dispatch_push(&push, spec, None).await
            }
            (Ok(Request::CallerPush(req)), Authority::Calls(caps)) => {
                let token = PushToken::from_hex(&req.token);
                let checked = match &token {
                    Some(token) => caps.check(token, &req.push.to, std::time::Instant::now()),
                    None => Err(crate::host::capability::CapabilityRefusal::Unknown),
                };
                match checked {
                    Ok(grant) => dispatch_push(&push, req.push, grant.call).await,
                    Err(refusal) => {
                        tracing::warn!(to = %req.push.to, "capability push refused: {refusal}");
                        Response::Err(truncate_reason(refusal.to_string()))
                    }
                }
            }
            (Ok(Request::Push(_)), Authority::Calls(_)) => Response::Err(
                "this socket takes only a call's push (`caller_push` with its WIRES_PUSH_TOKEN)"
                    .into(),
            ),
            (Ok(Request::CallerPush(_)), Authority::Operator) => {
                Response::Err("a call's push goes to the child socket (WIRES_PUSH_SOCKET)".into())
            }
            (Err(e), _) => Response::Err(truncate_reason(format!("malformed request: {e}"))),
        };
        write_response(&mut send, &response).await?;
    }
    Ok(())
}

/// Hand one push (sent under `call`'s capability, if any) to the host's push
/// service and wait for its report.
async fn dispatch_push(
    push: &mpsc::Sender<PushCommand>,
    spec: PushSpec,
    call: Option<library::CallId>,
) -> Response {
    let (reply, answer) = oneshot::channel();
    if push.send(PushCommand { spec, call, reply }).await.is_err() {
        return Response::Err("the host is shutting down".into());
    }
    match answer.await {
        Ok(Ok(report)) => Response::Pushed(report),
        Ok(Err(reason)) => Response::Err(truncate_reason(reason)),
        Err(_) => Response::Err("the host dropped the push without answering".into()),
    }
}

/// Write one NDJSON reply and flush it (the client is waiting on this line).
async fn write_response<W: AsyncWrite + Unpin>(send: &mut W, response: &Response) -> Result<()> {
    let mut bytes = serde_json::to_vec(response).context("encoding a control reply")?;
    bytes.push(b'\n');
    send.write_all(&bytes)
        .await
        .context("writing a control reply")?;
    send.flush().await.context("flushing a control reply")?;
    Ok(())
}

/// Read one `\n`-terminated line into `line` (cleared first), refusing one
/// longer than `cap` bytes. `Ok(false)` at a clean end of stream.
///
/// Hand-rolled rather than `AsyncBufReadExt::lines()` because that one grows its
/// buffer without limit; see [`MAX_REQUEST_LINE`].
async fn read_capped_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
    cap: usize,
) -> Result<bool> {
    line.clear();
    loop {
        let available = reader
            .fill_buf()
            .await
            .context("reading a control request")?;
        if available.is_empty() {
            // EOF: a trailing unterminated line is still a request.
            return Ok(!line.is_empty());
        }
        match available.iter().position(|b| *b == b'\n') {
            Some(at) => {
                line.extend_from_slice(&available[..at]);
                reader.consume(at + 1);
                return Ok(true);
            }
            None => {
                let taken = available.len();
                line.extend_from_slice(available);
                reader.consume(taken);
                if line.len() > cap {
                    bail!("control request line exceeds {cap} bytes; refusing to buffer it");
                }
            }
        }
    }
}

/// A connection to a running `serve`'s control socket.
#[derive(Debug)]
pub struct ControlClient {
    /// The buffered read half, for reply lines.
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    /// The write half, for request lines.
    writer: tokio::net::unix::OwnedWriteHalf,
    /// The socket path, for error messages.
    path: PathBuf,
}

impl ControlClient {
    /// Connect to the operator socket at `path` of the `serve` owning it, or
    /// `Ok(None)` when none is running (no socket, or a leftover one that
    /// refuses the connection). Refuses a socket whose directory this user
    /// does not own: another user's socket there could be collecting pushes.
    pub async fn connect(path: &Path) -> Result<Option<Self>> {
        if let Some(dir) = path.parent()
            && dir.exists()
        {
            check_owner(dir, effective_uid())?;
        }
        Self::connect_child(path).await
    }

    /// Connect to the child socket at `path` (`WIRES_PUSH_SOCKET`, handed to
    /// this process by the `serve` that spawned it, so its directory's owner
    /// is not second-guessed: a service may run as another user). `Ok(None)`
    /// as for [`connect`](Self::connect).
    pub async fn connect_child(path: &Path) -> Result<Option<Self>> {
        match UnixStream::connect(path).await {
            Ok(stream) => {
                let (recv, writer) = stream.into_split();
                Ok(Some(Self {
                    reader: BufReader::new(recv),
                    writer,
                    path: path.to_path_buf(),
                }))
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                tracing::debug!(socket = %path.display(), "no running serve ({e})");
                Ok(None)
            }
            Err(e) => Err(e)
                .with_context(|| format!("connecting to the control socket {}", path.display())),
        }
    }

    /// Ask the running host to push `spec`; its per-recipient report.
    pub async fn push(&mut self, spec: PushSpec) -> Result<PushReport> {
        self.answer(Request::Push(spec)).await
    }

    /// Ask the running host to push `spec` under the call capability
    /// `token` (only to that call's caller); its per-recipient report.
    pub async fn caller_push(&mut self, token: String, spec: PushSpec) -> Result<PushReport> {
        self.answer(Request::CallerPush(CallerPush { token, push: spec }))
            .await
    }

    /// Send `request` and turn the reply into a report or the host's refusal.
    async fn answer(&mut self, request: Request) -> Result<PushReport> {
        match self.request(&request, REPLY_TIMEOUT).await? {
            Response::Pushed(report) => Ok(report),
            Response::Err(reason) => Err(anyhow!("the host refused the push: {reason}")),
        }
    }

    /// Send one request line and read its reply line within `budget`.
    async fn request(
        &mut self,
        request: &Request,
        budget: std::time::Duration,
    ) -> Result<Response> {
        let mut bytes = serde_json::to_vec(request).context("encoding a control request")?;
        bytes.push(b'\n');
        self.writer
            .write_all(&bytes)
            .await
            .with_context(|| format!("writing to the control socket {}", self.path.display()))?;
        self.writer.flush().await.context("flushing a request")?;
        let mut line = Vec::new();
        let answered = tokio::time::timeout(
            budget,
            read_capped_line(&mut self.reader, &mut line, MAX_REQUEST_LINE),
        )
        .await
        .map_err(|_| {
            anyhow!(
                "the host on {} did not answer within {:?}",
                self.path.display(),
                budget
            )
        })??;
        if !answered {
            bail!(
                "the host closed the control socket {} without answering",
                self.path.display()
            );
        }
        serde_json::from_slice::<Response>(&line).with_context(|| {
            format!(
                "parsing the host's reply from {} ({:?})",
                self.path.display(),
                String::from_utf8_lossy(&line)
            )
        })
    }
}

/// Is something listening on the socket at `path`?
///
/// The stale-socket probe. A successful connect means yes; `ECONNREFUSED` (and
/// `ENOENT`, racing with a removal) means no. Any other error is treated as
/// "yes" — refusing to start is the safe answer when the answer is unknown,
/// because guessing wrong puts two `serve`s on one keystore, both appending
/// to its call log and push queue.
async fn is_live(path: &Path) -> bool {
    match UnixStream::connect(path).await {
        Ok(_) => true,
        Err(e) => !matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
        ),
    }
}

/// Create `dir` (and parents), set it to `0700`, and check that it took and
/// that this user (`geteuid()`) owns it.
///
/// The check matters for the short fallback directory under a shared `/tmp`
/// ([`short_socket_path`]): another user could have made `wires-<uid>` first.
/// We cannot chmod a directory we do not own, so one that is a symlink,
/// someone else's, or still open to group/other after the chmod, is refused
/// rather than used.
fn ensure_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    set_mode(dir, 0o700);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::symlink_metadata(dir)
            .with_context(|| format!("inspecting {}", dir.display()))?;
        if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
            bail!(
                "the control socket directory {} is not a private (0700) directory this user \
                 owns; remove it or set WIRES_HOME to a shorter path",
                dir.display()
            );
        }
    }
    check_owner(dir, effective_uid())
}

/// This process's effective uid (`geteuid()`); `0` off unix, where no
/// directory has an owner to check.
fn effective_uid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: geteuid(2) has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    0
}

/// Refuse `dir` unless it is a real directory (not a symlink) owned by `uid`.
fn check_owner(dir: &Path, uid: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(dir)
            .with_context(|| format!("inspecting {}", dir.display()))?;
        if !meta.is_dir() || meta.uid() != uid {
            bail!(
                "the control socket directory {} is not a directory owned by this user (uid \
                 {uid}; it is uid {}); refusing to use it",
                dir.display(),
                meta.uid()
            );
        }
    }
    #[cfg(not(unix))]
    let _ = (dir, uid);
    Ok(())
}

/// Set a path's unix mode (best-effort; a no-op off unix).
fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).ok();
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    const PATIENCE: Duration = Duration::from_secs(10);

    #[test]
    fn a_short_socket_path_is_stable_distinct_and_fits() {
        let long = PathBuf::from("/x".repeat(80)).join("run/serve.sock");
        assert!(!fits_sockaddr(&long));
        let bases = [PathBuf::from("/tmp")];
        let a = short_socket_path(&long, 501, &bases).unwrap();
        assert_eq!(a, short_socket_path(&long, 501, &bases).unwrap());
        assert!(fits_sockaddr(&a));
        let other = PathBuf::from("/y".repeat(80)).join("run/serve.sock");
        assert_ne!(a, short_socket_path(&other, 501, &bases).unwrap());
        assert!(a.starts_with("/tmp/wires-501"));
    }

    #[test]
    fn the_wire_forms_are_the_documented_ones() {
        let err = serde_json::to_string(&Response::Err("no".into())).unwrap();
        assert_eq!(err, r#"{"err":"no"}"#);
        let req: Request =
            serde_json::from_str(r#"{"push":{"to":"analyst","subject":"s","body":"b"}}"#).unwrap();
        assert!(matches!(req, Request::Push(spec) if spec.to == "analyst"));
    }

    #[tokio::test]
    async fn a_malformed_line_is_answered_and_a_push_reaches_the_host() {
        let (tx, mut rx) = mpsc::channel::<PushCommand>(8);
        let host = tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                let _ = cmd.reply.send(Err(format!("no one is {}", cmd.spec.to)));
            }
        });
        let (client, server) = tokio::io::duplex(4096);
        let (srecv, ssend) = tokio::io::split(server);
        let loop_task =
            tokio::spawn(async move { serve_conn(srecv, ssend, tx, &Authority::Operator).await });
        let (crecv, mut csend) = tokio::io::split(client);
        let mut creader = BufReader::new(crecv);
        csend
            .write_all(
                b"{\"push\":\n\n{\"push\":{\"to\":\"x\",\"subject\":\"s\",\"body\":\"b\"}}\n",
            )
            .await
            .unwrap();
        let mut line = Vec::new();
        read_capped_line(&mut creader, &mut line, MAX_REQUEST_LINE)
            .await
            .unwrap();
        let first: Response = serde_json::from_slice(&line).unwrap();
        assert!(
            matches!(&first, Response::Err(r) if r.contains("malformed request")),
            "{first:?}"
        );
        read_capped_line(&mut creader, &mut line, MAX_REQUEST_LINE)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Response>(&line).unwrap(),
            Response::Err("no one is x".into())
        );
        drop(csend);
        drop(creader);
        timeout(PATIENCE, loop_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        host.abort();
    }

    /// One request line through `serve_conn` under `authority`; the reply,
    /// and the command the host received (if any).
    async fn one(
        authority: Authority,
        request: &str,
    ) -> (Response, Option<(PushSpec, Option<library::CallId>)>) {
        let (tx, mut rx) = mpsc::channel::<PushCommand>(8);
        let host = tokio::spawn(async move {
            let cmd = rx.recv().await?;
            let _ = cmd.reply.send(Ok(PushReport::default()));
            Some((cmd.spec, cmd.call))
        });
        let (client, server) = tokio::io::duplex(4096);
        let (srecv, ssend) = tokio::io::split(server);
        let loop_task = tokio::spawn(async move { serve_conn(srecv, ssend, tx, &authority).await });
        let (crecv, mut csend) = tokio::io::split(client);
        csend.write_all(request.as_bytes()).await.unwrap();
        csend.write_all(b"\n").await.unwrap();
        let mut line = Vec::new();
        read_capped_line(&mut BufReader::new(crecv), &mut line, MAX_REQUEST_LINE)
            .await
            .unwrap();
        drop(csend);
        timeout(PATIENCE, loop_task).await.unwrap().unwrap().ok();
        let got = timeout(PATIENCE, host).await.unwrap().unwrap();
        (serde_json::from_slice(&line).unwrap(), got)
    }

    #[tokio::test]
    async fn the_child_socket_takes_only_a_live_token_to_its_caller() {
        use library::NodeIdentity;
        let caps = std::sync::Arc::new(Capabilities::default());
        let alice = NodeIdentity::from_seed([2; 32]).node_id();
        let bob = NodeIdentity::from_seed([3; 32]).node_id();
        let cap = caps.mint(alice);
        let call = library::CallId::generate();
        cap.bind_call(call);
        let token = cap.token().hex();
        let child = || Authority::Calls(std::sync::Arc::clone(&caps));
        let req = |token: &str, to: &str| {
            format!(
                r#"{{"caller_push":{{"token":"{token}","push":{{"to":"{to}","subject":"s","body":"b"}}}}}}"#
            )
        };

        // Its caller: handed to the host, naming the call.
        let (resp, got) = one(child(), &req(&token, &alice.hex())).await;
        assert_eq!(resp, Response::Pushed(PushReport::default()));
        let (spec, via) = got.unwrap();
        assert_eq!((spec.to.as_str(), via), (alice.hex().as_str(), Some(call)));

        // Anyone else, a role, a forged token, the operator's form: refused
        // before the host hears of it.
        for (request, why) in [
            (req(&token, &bob.hex()), "reaches only its caller"),
            (req(&token, "analyst"), "reaches only its caller"),
            (req(&"0".repeat(64), &alice.hex()), "unknown or expired"),
            (req("nope", &alice.hex()), "unknown or expired"),
            (
                format!(
                    r#"{{"push":{{"to":"{}","subject":"s","body":"b"}}}}"#,
                    alice.hex()
                ),
                "takes only a call's push",
            ),
        ] {
            let (resp, got) = one(child(), &request).await;
            assert!(
                matches!(&resp, Response::Err(r) if r.contains(why)),
                "{request}: {resp:?}"
            );
            assert!(got.is_none(), "{request} reached the host");
        }

        // The operator socket refuses the call form (it has its own).
        let (resp, got) = one(Authority::Operator, &req(&token, &alice.hex())).await;
        assert!(
            matches!(&resp, Response::Err(r) if r.contains("child socket")),
            "{resp:?}"
        );
        assert!(got.is_none());
    }

    #[test]
    fn a_socket_directory_owned_by_someone_else_is_refused() {
        let dir = crate::testutil::ScratchDir::new("own");
        let me = effective_uid();
        check_owner(dir.path(), me).unwrap();
        ensure_private_dir(&dir.path().join("run")).unwrap();
        let e = format!(
            "{:#}",
            check_owner(dir.path(), me.wrapping_add(1)).unwrap_err()
        );
        assert!(e.contains("not a directory owned by this user"), "{e}");
        // A symlink to our own directory is not the directory.
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path().join("run"), &link).unwrap();
        assert!(check_owner(&link, me).is_err());
    }

    #[tokio::test]
    async fn an_over_long_line_is_refused_rather_than_buffered() {
        let (tx, _rx) = mpsc::channel::<PushCommand>(1);
        let (client, server) = tokio::io::duplex(4096);
        let (srecv, ssend) = tokio::io::split(server);
        let loop_task =
            tokio::spawn(async move { serve_conn(srecv, ssend, tx, &Authority::Operator).await });
        let (_crecv, mut csend) = tokio::io::split(client);
        let chunk = vec![b'x'; 64 * 1024];
        let mut written = 0usize;
        while written <= MAX_REQUEST_LINE {
            if csend.write_all(&chunk).await.is_err() {
                break;
            }
            written += chunk.len();
        }
        let err = timeout(PATIENCE, loop_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(format!("{err:#}").contains("exceeds"), "{err:#}");
    }

    #[tokio::test]
    async fn bind_reclaims_a_stale_socket_refuses_a_live_one_and_unlinks_on_drop() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::testutil::ScratchDir::new("ctl");
        let path = run_dir(dir.path()).join("serve.sock");
        std::fs::create_dir_all(run_dir(dir.path())).unwrap();
        // Nothing there: no running serve.
        assert!(ControlClient::connect(&path).await.unwrap().is_none());
        // Stale: a bound-then-dropped listener leaves the file behind.
        drop(UnixListener::bind(&path).unwrap());
        assert!(path.exists());
        assert!(ControlClient::connect(&path).await.unwrap().is_none());
        let socket = ControlSocket::bind(&path).await.unwrap();
        #[cfg(unix)]
        {
            let dir_mode = std::fs::metadata(run_dir(dir.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(dir_mode & 0o777, 0o700);
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Live: a second serve must not steal it.
        let (tx, _rx) = mpsc::channel(1);
        let server = socket.spawn(tx, Authority::Operator);
        let msg = format!("{:#}", ControlSocket::bind(&path).await.unwrap_err());
        assert!(msg.contains("already running"), "{msg}");
        server.abort();
        let _ = server.await;
        assert!(!path.exists(), "dropping the socket must unlink it");
    }
}

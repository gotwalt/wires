//! The control socket: how `wires advanced publish` reaches the resident `wires watch`
//! (spec §7.1).
//!
//! redb locks a topic's log to one process and one endpoint identity must not
//! run twice, so `wires watch` is the resident node — it owns the store, the
//! endpoint, and, decisively, the **sequence allocator**. A second process that
//! wanted to publish by opening the same log would either fail on the lock or,
//! worse, hand out a sequence number the tail has already used, which is a
//! repeated `(key_version, seq)` slot and exactly the hazard the envelope's
//! synthetic IV exists to survive rather than to invite (spec §4.1).
//!
//! So publishing is a *request to the tail*, over a unix socket at
//! `$WIRES_HOME/run/<topic-hex-prefix>.sock` (see [`socket_path`]; a home too
//! deep for a unix socket path falls back to
//! `$TMPDIR/wires-<uid>/<hash>.sock`, or the same under `/tmp`):
//!
//! ```text
//! publish → {"publish":{"text":"ship it"}}
//! tail    ← {"ok":{"seq":7}}                  (or {"err":"…"})
//! ```
//!
//! NDJSON, one request per line, replies in order on the same connection — so a
//! `wires advanced publish` fed a hundred lines of stdin sends a hundred requests over
//! one connection and the tail allocates a hundred consecutive sequences.
//!
//! # Who may connect
//!
//! The directory is `0700` and the socket is `0600`: on unix, connecting to a
//! socket requires write permission on the node, so the mode *is* the access
//! control, and it admits only this user. That matters because the tail seals
//! whatever it is handed with the fabric key — a control socket reachable by
//! another local user would be a publish-as-me capability. The directory mode is
//! the load-bearing half (it is set before the socket exists); the socket's own
//! mode is set immediately after `bind` and closes the same door twice.
//!
//! # Stale sockets
//!
//! A tail killed with `SIGKILL` leaves the socket file behind, and `bind` on an
//! existing path fails with `EADDRINUSE` whether or not anyone is listening. The
//! answer is a **connect probe**, not a blind unlink: if something answers, the
//! topic really is owned and this process must not steal it (that is the
//! two-allocators failure again); if the connect is refused, the file is a
//! corpse and is removed. Unlink-on-exit ([`ControlSocket`]'s `Drop`) keeps the
//! usual case tidy; the probe is what makes the unusual one safe.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use library::TopicId;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::host::transport::truncate_reason;

/// The directory under the wires home that holds control sockets.
pub const RUN_DIR: &str = "run";

/// The most bytes one NDJSON request line may occupy.
///
/// A line is read into memory before it can be parsed, so an unbounded reader
/// is a local memory bomb — the same argument the frame codecs make about
/// peer-chosen lengths (spec §2.1), one trust level closer in. A megabyte is
/// far past any message a human types and far short of anything that hurts.
pub const MAX_REQUEST_LINE: usize = 1024 * 1024;

/// How long `wires advanced publish` waits for the tail's reply to one line.
///
/// The tail answers from its select loop, which also serves the mesh, so a reply
/// can be delayed by a catch-up pass or a slow peer — every one of those is now
/// itself bounded, and this is the outer bound behind them. A publisher that
/// waits forever turns a wedged tail into a wedged pipeline with nothing in the
/// log to say so.
/// Two minutes rather than one: a tail that is still starting has bound this
/// socket but not yet entered its loop (it binds before joining the mesh, so a
/// publish racing a start queues instead of colliding on the redb lock), and its
/// bootstrap plus first catch-up are each allowed thirty seconds.
pub const PUBLISH_REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// The run directory for control sockets under the wires home `home`.
pub fn run_dir(home: &Path) -> PathBuf {
    home.join(RUN_DIR)
}

/// How many hex characters of the topic id name a control socket.
///
/// **Not all 64, and that is not an aesthetic choice.** A unix socket path is
/// not a path like any other: the whole absolute path has to fit in
/// `sockaddr_un::sun_path`, which is 104 bytes on macOS and 108 on Linux, and
/// overflowing it is not a truncation but a hard `bind`/`connect` failure
/// (`path must be shorter than SUN_LEN`). `<home>/run/<64 hex>.sock` spends 74
/// of those bytes before the home is counted, which leaves under 30 for the
/// home on macOS: `/Users/<name>/.config/wires` just fits, and nothing deeper
/// does. Every test harness and demo script on this platform puts its home
/// under `/var/folders/…/T/tmp.XXXXXXXX`, and those could not publish at all.
///
/// Sixteen hex characters is 64 bits of a `blake3::derive_key` output. The
/// collision it risks is two topics *inside one keystore* sharing one socket —
/// not something reachable from outside the home, which is 0700 — at 2^-64 per
/// pair, against a certainty of unusable paths at 64 characters.
const SOCKET_NAME_HEX: usize = 16;

/// The control socket path for `topic` under the wires home `home`:
/// `<home>/run/<topic-hex-prefix>.sock`, where the prefix is the first
/// [`SOCKET_NAME_HEX`] characters of the topic id.
///
/// Named by topic id rather than by name, so two fabrics' `ops` topics do not
/// collide and the path is derivable by any process that can derive the id.
///
/// ```text
/// ~/.config/wires/run/1f0c9ab3a1b2c3d4.sock
/// ```
///
/// When that path would not fit in a `sockaddr_un` (a deep `$WIRES_HOME`), it
/// is swapped for a short one under the system temp directory — see
/// [`short_socket_path`]. Binding (`tail`, `serve host.json`) and
/// connecting (`publish`) both come through here, so they always agree.
pub fn socket_path(home: &Path, topic: TopicId) -> PathBuf {
    let hex = topic.hex();
    let name = &hex[..SOCKET_NAME_HEX.min(hex.len())];
    let full = run_dir(home).join(format!("{name}.sock"));
    if fits_sockaddr(&full) {
        return full;
    }
    let Some(uid) = owner_uid(home) else {
        // No home to take an owner from: keep the long path, whose bind fails
        // with the kernel's own "shorter than SUN_LEN" message.
        return full;
    };
    let bases = [std::env::temp_dir(), PathBuf::from("/tmp")];
    short_socket_path(&full, uid, &bases).unwrap_or(full)
}

/// The size of `sockaddr_un::sun_path`, NUL terminator included: 104 bytes on
/// macOS (and the BSDs), 108 on Linux.
pub const SUN_PATH_BYTES: usize = if cfg!(target_os = "linux") { 108 } else { 104 };

/// Whether `path` can be bound as a unix socket (it leaves room for the NUL).
pub fn fits_sockaddr(path: &Path) -> bool {
    path.as_os_str().as_encoded_bytes().len() < SUN_PATH_BYTES
}

/// A short stand-in for a control socket path too long to bind:
/// `<base>/wires-<uid>/<16 hex of BLAKE3(full path)>.sock`, under the first
/// of `bases` that yields a path which fits; `None` if none does.
///
/// Hashing the *full* path keeps the property the long path had — one socket
/// per (home, topic) — and lets every process that can compute the long path
/// find the short one. The `wires-<uid>` directory is created `0700` by
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

/// The uid that owns `path` (the wires home), naming the fallback directory.
#[cfg(unix)]
fn owner_uid(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| m.uid())
}

/// Off unix there are no unix sockets to shorten.
#[cfg(not(unix))]
fn owner_uid(_path: &Path) -> Option<u32> {
    None
}

// ---------------------------------------------------------------------------
// The wire protocol
// ---------------------------------------------------------------------------

/// One request from `wires advanced publish` to the resident tail.
///
/// Externally tagged, so the JSON is `{"publish":{"text":"…"}}` — an object with
/// one key naming the operation, which leaves room for later operations without
/// a version field.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    /// Publish `text` as this node's next message on the topic.
    Publish(Publish),
}

/// The body of a [`Request::Publish`].
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Publish {
    /// The message text (UTF-8; the CLI's payload convention, spec §4.1).
    pub text: String,
}

/// One reply from the tail: `{"ok":{"seq":N}}` or `{"err":"…"}`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    /// Sealed, appended, and broadcast; `seq` is the sequence it was allocated.
    Ok(Published),
    /// Refused, with the tail's own words. Never fatal to the connection: the
    /// next line is still read.
    Err(String),
}

/// The body of a [`Response::Ok`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Published {
    /// The sequence number the tail allocated for the message.
    pub seq: u64,
}

// ---------------------------------------------------------------------------
// Server side (owned by `wires watch`)
// ---------------------------------------------------------------------------

/// A publish handed to the tail loop, with the channel its answer goes back on.
///
/// The tail loop is the single sequence allocator, so it — not a socket task —
/// does the seal/append/broadcast. Requests reach it as values on an [`mpsc`]
/// channel it `select!`s over, which is what keeps the allocator single-threaded
/// without a lock around it.
#[derive(Debug)]
pub struct PublishRequest {
    /// The text to publish.
    pub text: String,
    /// Where the outcome goes: the allocated sequence, or a reason.
    pub reply: oneshot::Sender<std::result::Result<u64, String>>,
}

/// A bound control socket, unlinked when dropped.
///
/// Dropping it removes the socket file, which is what makes the common exit
/// path leave nothing behind for the next tail to probe. A `SIGKILL`ed tail
/// leaves the file, and [`bind`](Self::bind)'s connect probe reclaims it.
#[derive(Debug)]
pub struct ControlSocket {
    /// The listening socket.
    listener: UnixListener,
    /// Its path, kept for the unlink and for error messages.
    path: PathBuf,
}

impl ControlSocket {
    /// Bind the control socket at `path`, creating its directory at `0700` and
    /// the socket at `0600`.
    ///
    /// An existing path is probed first: a socket somebody answers on means
    /// another tail owns this topic and this call fails (naming it, because the
    /// remedy is to stop that tail, never to steal the topic); a socket nobody
    /// answers on is removed and rebound.
    pub async fn bind(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            ensure_private_dir(dir)?;
        }
        if path.exists() {
            if is_live(path).await {
                bail!(
                    "another `wires watch` is already serving this topic (its control socket at \
                     {} answered); stop it before starting a second one — a topic's log and \
                     sequence allocator belong to exactly one process",
                    path.display()
                );
            }
            tracing::warn!(
                socket = %path.display(),
                "removing a stale control socket left by a previous tail"
            );
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

    /// Where this socket lives.
    ///
    /// `#[cfg(test)]`: the field drives the unlink on drop and the error
    /// messages; the accessor exists so the suite can assert the socket bound
    /// where it was asked to.
    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accept connections forever, forwarding every request to `tx`.
    ///
    /// One task per connection, so a client that opens a connection and says
    /// nothing cannot wedge the others. Ends only when accepting fails
    /// unrecoverably; the caller runs it as a task and drops it at shutdown
    /// (which unlinks the socket, this value being moved in).
    pub async fn serve(self, tx: mpsc::Sender<PublishRequest>) {
        loop {
            match self.listener.accept().await {
                Ok((stream, _)) => {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve_stream(stream, tx).await {
                            tracing::warn!("control connection ended: {e:#}");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(socket = %self.path.display(), "control accept failed: {e}");
                    // A failed accept is usually transient (EMFILE); a tight
                    // spin on it would be worse than the failure.
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Spawn [`serve`](Self::serve) as a task.
    ///
    /// The socket moves into the task, so aborting the handle (or dropping the
    /// runtime) drops the socket and unlinks the file.
    pub fn spawn(self, tx: mpsc::Sender<PublishRequest>) -> JoinHandle<()> {
        tokio::spawn(self.serve(tx))
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

/// Serve one accepted connection.
async fn serve_stream(stream: UnixStream, tx: mpsc::Sender<PublishRequest>) -> Result<()> {
    let (recv, send) = stream.into_split();
    serve_conn(recv, send, tx).await
}

/// The NDJSON server loop over one duplex pair — the testable half of
/// [`ControlSocket::serve`], generic so it runs over anything, not just a unix
/// stream (the `serve_session` pattern).
///
/// Every line gets exactly one reply line, in order. A line that is not a valid
/// request is answered with `{"err":…}` rather than by hanging up: a client that
/// sent one bad line usually has good ones behind it, and a silent close would
/// look like a dead tail.
pub(crate) async fn serve_conn<R, W>(
    recv: R,
    mut send: W,
    tx: mpsc::Sender<PublishRequest>,
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
        let response = match serde_json::from_slice::<Request>(&line) {
            Ok(Request::Publish(publish)) => dispatch(&tx, publish.text).await,
            Err(e) => Response::Err(truncate_reason(format!("malformed request: {e}"))),
        };
        write_response(&mut send, &response).await?;
    }
    Ok(())
}

/// Hand one publish to the tail loop and wait for its verdict.
async fn dispatch(tx: &mpsc::Sender<PublishRequest>, text: String) -> Response {
    let (reply, answer) = oneshot::channel();
    if tx.send(PublishRequest { text, reply }).await.is_err() {
        return Response::Err("the tail is shutting down".into());
    }
    match answer.await {
        Ok(Ok(seq)) => Response::Ok(Published { seq }),
        Ok(Err(reason)) => Response::Err(truncate_reason(reason)),
        Err(_) => Response::Err("the tail dropped the request without answering".into()),
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

// ---------------------------------------------------------------------------
// Client side (owned by `wires advanced publish`)
// ---------------------------------------------------------------------------

/// A connection to a resident tail's control socket.
///
/// Holds the connection open across many publishes, so a `wires advanced publish` reading
/// stdin sends every line down one connection and the tail allocates one
/// contiguous run of sequences.
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
    /// Connect to the tail owning `path`, or `Ok(None)` when there is no tail.
    ///
    /// "No tail" is two cases and both are ordinary: the socket does not exist
    /// (nobody ever tailed this topic here), or it exists and refuses the
    /// connection (a tail died without unlinking). Either way the caller falls
    /// back to the one-shot publish path, which is why this returns `None`
    /// rather than an error — the absence of a tail is not a failure.
    pub async fn connect(path: &Path) -> Result<Option<Self>> {
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
                tracing::debug!(socket = %path.display(), "no resident tail ({e}); publishing one-shot");
                Ok(None)
            }
            Err(e) => Err(e)
                .with_context(|| format!("connecting to the control socket {}", path.display())),
        }
    }

    /// Publish `text` through the tail, returning the sequence it allocated.
    ///
    /// A `{"err":…}` reply becomes an error carrying the tail's own words, the
    /// same shape an admission refusal takes.
    pub async fn publish(&mut self, text: &str) -> Result<u64> {
        self.publish_within(text, PUBLISH_REPLY_TIMEOUT).await
    }

    /// [`publish`](Self::publish) with an explicit reply deadline.
    ///
    /// The deadline is a parameter so the "the tail never answered" path is
    /// asserted in milliseconds rather than by waiting out
    /// [`PUBLISH_REPLY_TIMEOUT`].
    pub async fn publish_within(&mut self, text: &str, budget: std::time::Duration) -> Result<u64> {
        let request = Request::Publish(Publish {
            text: text.to_string(),
        });
        let mut bytes = serde_json::to_vec(&request).context("encoding a publish request")?;
        bytes.push(b'\n');
        self.writer
            .write_all(&bytes)
            .await
            .with_context(|| format!("writing to the control socket {}", self.path.display()))?;
        self.writer.flush().await.context("flushing a publish")?;

        let mut line = Vec::new();
        // Bounded, because the tail is a program too: it can be wedged on a slow
        // peer or a long catch-up, and a publisher that waits forever is a
        // pipeline that has silently stopped rather than one that reported a
        // problem. Generous enough that an ordinary busy tail always answers.
        let answered = tokio::time::timeout(
            budget,
            read_capped_line(&mut self.reader, &mut line, MAX_REQUEST_LINE),
        )
        .await
        .map_err(|_| {
            anyhow!(
                "the tail on {} did not answer within {:?}",
                self.path.display(),
                budget
            )
        })??;
        if !answered {
            bail!(
                "the tail closed the control socket {} without answering",
                self.path.display()
            );
        }
        match serde_json::from_slice::<Response>(&line).with_context(|| {
            format!(
                "parsing the tail's reply from {} ({:?})",
                self.path.display(),
                String::from_utf8_lossy(&line)
            )
        })? {
            Response::Ok(Published { seq }) => Ok(seq),
            Response::Err(reason) => Err(anyhow!("the tail refused the publish: {reason}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Small unix helpers
// ---------------------------------------------------------------------------

/// Is something listening on the socket at `path`?
///
/// The stale-socket probe. A successful connect means yes; `ECONNREFUSED` (and
/// `ENOENT`, racing with a removal) means no. Any other error is treated as
/// "yes" — refusing to start is the safe answer when the answer is unknown,
/// because the failure mode of guessing wrong is two sequence allocators.
async fn is_live(path: &Path) -> bool {
    match UnixStream::connect(path).await {
        Ok(_) => true,
        Err(e) => !matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
        ),
    }
}

/// Create `dir` (and parents), set it to `0700`, and check that it took.
///
/// The check matters for the short fallback directory under a shared `/tmp`
/// ([`short_socket_path`]): another user could have made `wires-<uid>` first.
/// We cannot chmod a directory we do not own, so one that is a symlink, or
/// still open to group/other after the chmod, is refused rather than used.
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

/// A scratch directory for tests that bind real unix sockets, removed on drop.
///
/// A `sockaddr_un` path is capped at ~104 bytes on macOS, and Bazel's sandboxed
/// `$TEST_TMPDIR` is longer than that *by itself* — so a socket test that used
/// the usual temp root would fail everywhere with `path must be shorter than
/// SUN_LEN` and teach nothing. This picks the shortest writable base available
/// and keeps its own names to a few characters.
#[cfg(test)]
pub(crate) struct ScratchDir {
    /// The created directory.
    path: PathBuf,
}

#[cfg(test)]
impl ScratchDir {
    /// Create a short-named scratch directory (`/tmp` when writable, else the
    /// test temp root).
    pub(crate) fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("w{tag}{}-{n}", std::process::id());
        let short = PathBuf::from("/tmp").join(&name);
        let path = if std::fs::create_dir_all(&short).is_ok() {
            short
        } else {
            let base = std::env::var_os("TEST_TMPDIR")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            let fallback = base.join(name);
            std::fs::create_dir_all(&fallback).unwrap();
            fallback
        };
        Self { path }
    }

    /// The directory itself.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// A socket path inside it.
    pub(crate) fn socket(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

#[cfg(test)]
impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use tokio::time::timeout;

    /// The outer bound on any wait here: everything is local, so this is only
    /// ever reached by a bug.
    const PATIENCE: Duration = Duration::from_secs(10);

    /// Answer every request by echoing a sequence that counts up from `first`,
    /// or by refusing the text `"no"`. Stands in for the tail loop.
    fn fake_tail(mut rx: mpsc::Receiver<PublishRequest>, first: u64) -> JoinHandle<Vec<String>> {
        tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut seq = first;
            while let Some(request) = rx.recv().await {
                let answer = if request.text == "no" {
                    Err("refused on purpose".to_string())
                } else {
                    seq += 1;
                    Ok(seq - 1)
                };
                seen.push(request.text);
                let _ = request.reply.send(answer);
            }
            seen
        })
    }

    #[test]
    fn socket_path_lives_under_the_run_directory() {
        let fabric = library::NodeIdentity::from_seed([1u8; 32]).node_id();
        let topic = TopicId::derive(fabric, "ops");
        let path = socket_path(Path::new("/wires-home"), topic);
        assert_eq!(
            path,
            PathBuf::from("/wires-home")
                .join(RUN_DIR)
                .join(format!("{}.sock", &topic.hex()[..SOCKET_NAME_HEX]))
        );
    }

    /// The regression behind [`SOCKET_NAME_HEX`]: a home under the platform
    /// temp directory — which is where every harness and demo script puts one —
    /// must still produce a bindable path. macOS caps `sun_path` at 104 bytes,
    /// so this is the assertion that the name is short enough to leave room for
    /// a real home.
    #[test]
    fn socket_path_fits_in_a_unix_sockaddr() {
        /// The smaller of the two platform limits (macOS 104, Linux 108), minus
        /// the NUL terminator.
        const SUN_LEN: usize = 103;
        let fabric = library::NodeIdentity::from_seed([7u8; 32]).node_id();
        let topic = TopicId::derive(fabric, "ops");
        // A macOS `mktemp -d` home, plus a per-node subdirectory: the exact
        // shape `.scripts/demo-topic.sh` provisions.
        let home = Path::new("/var/folders/zb/x2_9m2_n3759fz_fy3b5w4yr0000gn/T/tmp.gAtytESDox")
            .join("agent-b");
        let path = socket_path(&home, topic);
        let len = path.as_os_str().as_encoded_bytes().len();
        assert!(len <= SUN_LEN, "{} is {len} bytes", path.display());
        // And binding it really works, which is the property the length is a
        // proxy for.
        let scratch = ScratchDir::new("sockaddr");
        let real = socket_path(scratch.path(), topic);
        std::fs::create_dir_all(real.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&real).unwrap();
        drop(listener);
    }

    #[test]
    fn a_short_socket_path_is_stable_distinct_and_fits() {
        let long = PathBuf::from(format!("/{}", "d".repeat(120))).join("run/abcd.sock");
        let other = PathBuf::from(format!("/{}", "e".repeat(120))).join("run/abcd.sock");
        let bases = [PathBuf::from("/tmp")];
        let a = short_socket_path(&long, 501, &bases).unwrap();
        assert_eq!(a, short_socket_path(&long, 501, &bases).unwrap());
        assert_ne!(a, short_socket_path(&other, 501, &bases).unwrap());
        assert!(a.starts_with("/tmp/wires-501"), "{}", a.display());
        assert!(fits_sockaddr(&a));
        let name = a.file_name().unwrap().to_string_lossy();
        assert_eq!(name.len(), SOCKET_NAME_HEX + ".sock".len(), "{name}");
        // A base that is itself too deep is skipped for the next one.
        let deep = PathBuf::from(format!("/{}", "t".repeat(100)));
        let b = short_socket_path(&long, 501, &[deep.clone(), PathBuf::from("/tmp")]).unwrap();
        assert_eq!(b, a);
        assert_eq!(short_socket_path(&long, 501, &[deep]), None);
    }

    #[test]
    fn a_short_home_keeps_its_socket_under_the_home() {
        let home = ScratchDir::new("keep");
        let topic = TopicId::derive(library::NodeIdentity::from_seed([3u8; 32]).node_id(), "ops");
        assert!(socket_path(home.path(), topic).starts_with(home.path()));
    }

    /// **Card 10.** A home deep enough that `<home>/run/<name>.sock` overflows
    /// `sun_path` (the first live run died on this with `path must be shorter
    /// than SUN_LEN`) still gets a control socket: a tail binds the fallback
    /// path, and a publisher — resolving the path the same way — reaches it.
    #[tokio::test]
    async fn a_deep_home_falls_back_to_a_short_socket_that_publish_reaches() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let scratch = ScratchDir::new("deep");
        let mut home = scratch.path().to_path_buf();
        while home.as_os_str().len() < 120 {
            home.push("nested-wires-home");
        }
        std::fs::create_dir_all(&home).unwrap();
        let topic = TopicId::derive(library::NodeIdentity::from_seed([9u8; 32]).node_id(), "ops");
        assert!(
            !fits_sockaddr(&run_dir(&home).join("0123456789abcdef.sock")),
            "the home must be deep enough to need the fallback"
        );

        let path = socket_path(&home, topic);
        assert!(!path.starts_with(&home), "{}", path.display());
        assert!(fits_sockaddr(&path), "{}", path.display());
        assert_eq!(path, socket_path(&home, topic), "deterministic");

        let socket = ControlSocket::bind(&path).await.unwrap();
        #[cfg(unix)]
        {
            let dir = path.parent().unwrap();
            let mode = std::fs::metadata(dir).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o700,
                "the fallback directory must be private"
            );
        }
        let (tx, rx) = mpsc::channel(8);
        let tail = fake_tail(rx, 1);
        let server = socket.spawn(tx);

        let mut client = ControlClient::connect(&socket_path(&home, topic))
            .await
            .unwrap()
            .expect("publish finds the tail at the fallback path");
        assert_eq!(
            timeout(PATIENCE, client.publish("deep"))
                .await
                .unwrap()
                .unwrap(),
            1
        );
        drop(client);
        server.abort();
        let seen = timeout(PATIENCE, tail).await.unwrap().unwrap();
        assert_eq!(seen, ["deep"]);
    }

    /// A socket directory that is not a private directory of ours — here a
    /// symlink, as another user could plant under a shared `/tmp` — is refused.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlinked_socket_directory_is_refused() {
        let scratch = ScratchDir::new("link");
        let real = scratch.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = scratch.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = ControlSocket::bind(&link.join("t.sock"))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(format!("{err:#}").contains("not a private"), "{err:#}");
    }

    #[test]
    fn the_wire_forms_are_the_documented_ones() {
        // The protocol is the contract with `wires advanced publish`, including anything
        // an operator debugs with `socat`; pin the exact JSON.
        let request = Request::Publish(Publish {
            text: "ship it".into(),
        });
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"publish":{"text":"ship it"}}"#
        );
        assert_eq!(
            serde_json::from_str::<Request>(r#"{"publish":{"text":"ship it"}}"#).unwrap(),
            request
        );
        assert_eq!(
            serde_json::to_string(&Response::Ok(Published { seq: 7 })).unwrap(),
            r#"{"ok":{"seq":7}}"#
        );
        assert_eq!(
            serde_json::to_string(&Response::Err("nope".into())).unwrap(),
            r#"{"err":"nope"}"#
        );
    }

    #[tokio::test]
    async fn publish_round_trips_over_a_real_socket() {
        let dir = ScratchDir::new("ipc");
        let path = dir.socket("t.sock");
        let socket = ControlSocket::bind(&path).await.unwrap();
        let (tx, rx) = mpsc::channel(8);
        let tail = fake_tail(rx, 3);
        let server = socket.spawn(tx);

        let mut client = ControlClient::connect(&path).await.unwrap().unwrap();
        // Many publishes down one connection get one contiguous run of seqs.
        assert_eq!(
            timeout(PATIENCE, client.publish("one"))
                .await
                .unwrap()
                .unwrap(),
            3
        );
        assert_eq!(
            timeout(PATIENCE, client.publish("two"))
                .await
                .unwrap()
                .unwrap(),
            4
        );

        // A refusal is an error carrying the tail's own words, and the
        // connection survives it.
        let err = client.publish("no").await.unwrap_err();
        assert!(format!("{err:#}").contains("refused on purpose"), "{err:#}");
        assert_eq!(client.publish("three").await.unwrap(), 5);

        drop(client);
        server.abort();
        drop(server);
        // The tail saw every text, in order.
        // (Dropping the sender ends `fake_tail`; the abort above drops it.)
        let seen = timeout(PATIENCE, tail).await.unwrap().unwrap();
        assert_eq!(seen, vec!["one", "two", "no", "three"]);
    }

    #[tokio::test]
    async fn a_malformed_line_is_answered_not_hung_up_on() {
        let (tx, rx) = mpsc::channel(8);
        let tail = fake_tail(rx, 0);
        // Duplex halves stand in for the socket: the loop is stream-agnostic.
        let (client, server) = tokio::io::duplex(4096);
        let (srecv, ssend) = tokio::io::split(server);
        let loop_task = tokio::spawn(async move { serve_conn(srecv, ssend, tx).await });

        let (crecv, mut csend) = tokio::io::split(client);
        let mut creader = BufReader::new(crecv);
        csend
            .write_all(b"{\"publish\":\n\n{\"publish\":{\"text\":\"after\"}}\n")
            .await
            .unwrap();
        csend.flush().await.unwrap();

        let mut line = Vec::new();
        read_capped_line(&mut creader, &mut line, MAX_REQUEST_LINE)
            .await
            .unwrap();
        let first: Response = serde_json::from_slice(&line).unwrap();
        assert!(
            matches!(&first, Response::Err(reason) if reason.contains("malformed request")),
            "{first:?}"
        );

        // Blank lines are skipped, and the good request behind the bad one is
        // still served — the whole point of not hanging up.
        read_capped_line(&mut creader, &mut line, MAX_REQUEST_LINE)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Response>(&line).unwrap(),
            Response::Ok(Published { seq: 0 })
        );

        drop(csend);
        drop(creader);
        timeout(PATIENCE, loop_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let seen = timeout(PATIENCE, tail).await.unwrap().unwrap();
        assert_eq!(seen, vec!["after"]);
    }

    #[tokio::test]
    async fn an_over_long_line_is_refused_rather_than_buffered() {
        let (tx, _rx) = mpsc::channel::<PublishRequest>(1);
        let (client, server) = tokio::io::duplex(4096);
        let (srecv, ssend) = tokio::io::split(server);
        let loop_task = tokio::spawn(async move { serve_conn(srecv, ssend, tx).await });

        let (_crecv, mut csend) = tokio::io::split(client);
        // Never a newline: the reader must give up on the cap, not on memory.
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
    async fn connect_is_none_when_no_tail_is_listening() {
        let dir = ScratchDir::new("ipc");
        let path = dir.socket("t.sock");
        // Nothing there at all.
        assert!(ControlClient::connect(&path).await.unwrap().is_none());

        // A leftover socket file nobody answers on: also "no tail", not an error.
        let listener = UnixListener::bind(&path).unwrap();
        drop(listener); // std/tokio do not unlink on drop
        assert!(path.exists());
        assert!(ControlClient::connect(&path).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn bind_reclaims_a_stale_socket_but_refuses_a_live_one() {
        let dir = ScratchDir::new("ipc");
        let path = dir.socket("t.sock");

        // Stale: a bound-then-dropped listener leaves the file behind.
        let listener = UnixListener::bind(&path).unwrap();
        drop(listener);
        assert!(path.exists());
        let socket = ControlSocket::bind(&path).await.unwrap();

        // Live: a second tail on the same topic must not steal the allocator.
        let (tx, rx) = mpsc::channel(1);
        let _tail = fake_tail(rx, 0);
        let server = socket.spawn(tx);
        let err = ControlSocket::bind(&path).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("already serving"), "{msg}");
        assert!(msg.contains(&path.display().to_string()), "{msg}");

        server.abort();
    }

    #[tokio::test]
    async fn the_socket_and_its_directory_are_private_and_unlinked_on_drop() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let home = ScratchDir::new("ipc");
        let home = home.path();
        let fabric = library::NodeIdentity::from_seed([1u8; 32]).node_id();
        let path = socket_path(home, TopicId::derive(fabric, "ops"));
        let socket = ControlSocket::bind(&path).await.unwrap();
        assert_eq!(socket.path(), path);

        #[cfg(unix)]
        {
            let dir_mode = std::fs::metadata(run_dir(home))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(dir_mode & 0o777, 0o700, "the run directory must be private");
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the socket must be private");
        }

        drop(socket);
        assert!(!path.exists(), "dropping the socket must unlink it");
    }

    #[tokio::test]
    async fn a_client_whose_tail_vanished_reports_it() {
        let dir = ScratchDir::new("ipc");
        let path = dir.socket("t.sock");
        let socket = ControlSocket::bind(&path).await.unwrap();
        let (tx, rx) = mpsc::channel(1);
        // The tail loop is gone: the request channel is closed.
        drop(rx);
        let server = socket.spawn(tx);

        let mut client = ControlClient::connect(&path).await.unwrap().unwrap();
        let err = client.publish("hello").await.unwrap_err();
        assert!(format!("{err:#}").contains("shutting down"), "{err:#}");
        server.abort();
    }
}

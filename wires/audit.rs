//! `wires serve --audit-topic <name>`: every call the responder handles lands
//! on an E2EE topic as a signed record.
//!
//! # Shape
//!
//! A responder with an audit topic is **one process, one endpoint, one
//! allocator**. It stands up the [`TopicNode`](crate::topics::TopicNode) for
//! the topic itself and registers the session ALPN ([`transport::ALPN`]) on
//! that node's router (see [`TopicNodeConfig::protocols`]), rather than binding
//! a second endpoint for the same node key. It then runs the ordinary resident
//! tail loop, which owns the topic log and is the only thing that allocates
//! sequences on it.
//!
//! Sessions report through an [`AuditSink`] in the [`ServeConfig`]. [`forward`]
//! drains the sink's receiver and turns each [`AuditRecord`] into exactly one
//! [`PublishRequest`] on the same channel the control socket feeds — so a call
//! record is sealed, appended and broadcast by the very code path `wires
//! publish` uses, never by a second allocator.
//!
//! # Where the records come from
//!
//! [`CallAudit`] is the per-call handle `serve_session` holds: `start` emits
//! [`Started`](AuditRecord::Started) once the child is spawned, the [`Tap`]s
//! it hands out count (and, for stdout, BLAKE3-hash) what the child writes,
//! the [`StdinTap`] hashes, counts and quotes the head of what the caller
//! sent on stdin, and `finish` emits [`Finished`](AuditRecord::Finished). A refusal emits a
//! lone [`Denied`](AuditRecord::Denied) via [`denied`] carrying the exact
//! reason the caller was sent. The caller is always the iroh-authenticated
//! peer, never a handshake claim.
//!
//! Publishing is best-effort by design: a full or closed sink, or a publish
//! the tail loop refuses, is logged at `warn` and the call proceeds. The
//! fail-closed part is *startup*: `--audit-topic` refuses to start unless this
//! node is a provisioned member of the channel (membership, inclusion proof,
//! roster head and fabric key), with an error naming the `wires import` flag.
//!
//! # Observer setup
//!
//! An observer is any roster member holding the current fabric key: `wires
//! import` its membership, proof, head and key, then `wires tail <topic>
//! --peer <responder's topic ticket>`. It holds no grant for any exposed tool
//! and no credential of the caller, and it sees every call live.
//!
//! [`TopicNodeConfig::protocols`]: crate::topics::TopicNodeConfig::protocols
//! [`ServeConfig`]: crate::transport::ServeConfig

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;

use library::{
    Argv, AuditRecord, CallId, ChannelRecord, NodeId, OutputHasher, Principal, StdinCapture,
    ToolName,
};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use crate::ipc::PublishRequest;
use crate::transport::{self, AuditSink};

/// How many records may queue between the sessions and the tail loop before
/// the sink starts dropping (and logging) them.
pub const AUDIT_QUEUE: usize = 256;

/// The tool name a single-command responder (`wires serve -- <cmd>`) reports:
/// it exposes exactly one CLI, bridged over stdio, under no name of its own.
pub const STDIO_TOOL: &str = "stdio";

/// Unix milliseconds now (the `at_ms` of a record).
pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The [`ToolName`] for [`STDIO_TOOL`].
pub fn stdio_tool() -> ToolName {
    ToolName::new(STDIO_TOOL).expect("\"stdio\" is a valid tool name")
}

/// Record a refusal of `caller` (asking for `tool`, if it named one) with the
/// reason it was sent. A no-op when the responder has no audit sink.
///
/// The reason is cut exactly as [`transport`] cuts the one it sends, so the
/// record and the caller's `Denied` frame say the same thing.
pub fn denied(sink: Option<&AuditSink>, caller: NodeId, tool: Option<ToolName>, reason: &str) {
    if let Some(sink) = sink {
        sink.record(AuditRecord::Denied {
            caller,
            tool,
            reason: transport::truncate_reason(reason.to_string()),
            at_ms: now_ms(),
        });
    }
}

/// What a [`Tap`] has seen: a byte count, and for stdout the running hash.
type Tally = Arc<Mutex<OutputHasher>>;

/// One authorized call, from spawn to exit. See the module docs.
#[derive(Debug)]
pub struct CallAudit {
    /// Where the records go.
    sink: AuditSink,
    /// Pairs `Started` with `Finished`.
    call: CallId,
    /// When the child was spawned.
    spawned: Instant,
    /// Everything the child wrote to stdout.
    stdout: Tally,
    /// Everything the child wrote to stderr (only the count is reported).
    stderr: Tally,
    /// Everything the caller sent on stdin.
    stdin: Arc<Mutex<StdinCapture>>,
}

impl CallAudit {
    /// Emit [`Started`](AuditRecord::Started) for a call `caller` was admitted
    /// to (under `roster_version`, if a head is enforced) and return the
    /// handle that will emit its `Finished`. `None` — and nothing emitted —
    /// when the responder has no audit sink.
    ///
    /// `principal` is the caller's fresh verified IdP identity, when the
    /// responder's identity index holds one (see [`crate::identity`]) — so
    /// the record names the person, not only the key.
    ///
    /// `args` are the call's arguments as the record should show them; an
    /// argument list too large for an [`Argv`] is logged and recorded empty
    /// rather than failing a call that is already running.
    pub fn start(
        sink: Option<&AuditSink>,
        caller: NodeId,
        principal: Option<Principal>,
        tool: ToolName,
        args: &[String],
        roster_version: Option<u64>,
    ) -> Option<Self> {
        let sink = sink?.clone();
        let argv = Argv::new(args.to_vec()).unwrap_or_else(|e| {
            tracing::warn!("audit: recording an empty argv ({e})");
            Argv::default()
        });
        let call = CallId::generate();
        sink.record(AuditRecord::Started {
            call,
            caller,
            principal,
            tool,
            argv,
            roster_version,
            at_ms: now_ms(),
        });
        Some(Self {
            sink,
            call,
            spawned: Instant::now(),
            stdout: Tally::default(),
            stderr: Tally::default(),
            stdin: Arc::default(),
        })
    }

    /// Emit [`Finished`](AuditRecord::Finished) with the child's exit code and
    /// what the taps counted.
    pub fn finish(self, exit: i32) {
        let (stdout_bytes, stdout_digest) = {
            let h = self.stdout.lock().expect("stdout tally poisoned");
            (h.bytes(), h.finish())
        };
        let stderr_bytes = self.stderr.lock().expect("stderr tally poisoned").bytes();
        let (stdin_bytes, stdin_digest, stdin_head) = {
            let c = self.stdin.lock().expect("stdin capture poisoned");
            (c.bytes(), c.digest(), c.head())
        };
        self.sink.record(AuditRecord::Finished {
            call: self.call,
            exit,
            duration_ms: self.spawned.elapsed().as_millis() as u64,
            stdout_bytes,
            stderr_bytes,
            stdout_digest,
            stdin_bytes,
            stdin_digest,
            stdin_head,
        });
    }
}

/// Wrap the child's stdout so `audit` (if any) sees every byte.
pub fn tap_stdout<R>(audit: Option<&CallAudit>, inner: R) -> Tap<R> {
    Tap {
        inner,
        tally: audit.map(|a| Arc::clone(&a.stdout)),
    }
}

/// Wrap the child's stderr so `audit` (if any) counts every byte.
pub fn tap_stderr<R>(audit: Option<&CallAudit>, inner: R) -> Tap<R> {
    Tap {
        inner,
        tally: audit.map(|a| Arc::clone(&a.stderr)),
    }
}

/// A handle for recording the caller's stdin as the session pump forwards it
/// to the child. Stdin arrives as frames rather than through a reader, so
/// this is fed explicitly ([`StdinTap::feed`]) instead of wrapping a stream.
pub fn tap_stdin(audit: Option<&CallAudit>) -> StdinTap {
    StdinTap(audit.map(|a| Arc::clone(&a.stdin)))
}

/// See [`tap_stdin`]. With no audit it records nothing.
#[derive(Debug)]
pub struct StdinTap(Option<Arc<Mutex<StdinCapture>>>);

impl StdinTap {
    /// Record one chunk of stdin, in the order the caller sent it.
    pub fn feed(&self, chunk: &[u8]) {
        if let Some(capture) = &self.0 {
            capture
                .lock()
                .expect("stdin capture poisoned")
                .update(chunk);
        }
    }
}

/// An [`AsyncRead`] pass-through that feeds every byte read into a tally.
/// With no tally it is a plain pass-through.
#[derive(Debug)]
pub struct Tap<R> {
    /// The stream being read.
    inner: R,
    /// Where the bytes are counted, if anywhere.
    tally: Option<Tally>,
}

impl<R: AsyncRead + Unpin> AsyncRead for Tap<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let (Poll::Ready(Ok(())), Some(tally)) = (&polled, &self.tally) {
            tally
                .lock()
                .expect("tally poisoned")
                .update(&buf.filled()[before..]);
        }
        polled
    }
}

/// Drain `records` into the tail loop's publish queue, one
/// [`PublishRequest`] per record, in order. Returns when either side closes.
///
/// Each request's reply is awaited before the next is sent, so the records a
/// call produces reach the log in the order the call produced them. A refused
/// publish is logged, never retried: the call it describes has already run.
pub async fn forward(mut records: mpsc::Receiver<AuditRecord>, tx: mpsc::Sender<PublishRequest>) {
    while let Some(record) = records.recv().await {
        let text = match ChannelRecord::Audit(record).to_text() {
            Ok(text) => text,
            Err(e) => {
                tracing::warn!("audit record not encodable; dropped: {e}");
                continue;
            }
        };
        let (reply, answer) = oneshot::channel();
        if tx.send(PublishRequest { text, reply }).await.is_err() {
            tracing::warn!("the tail loop is gone; audit records will not be published");
            return;
        }
        match answer.await {
            Ok(Ok(seq)) => tracing::debug!(seq, "audit record published"),
            Ok(Err(e)) => tracing::warn!("audit record not published: {e}"),
            Err(_) => tracing::warn!("audit record publish went unanswered"),
        }
    }
}

/// What a `serve --audit-topic` responder adds to the resident tail loop:
/// the session protocol for the node's router, and the records to publish.
#[derive(Debug)]
pub struct Hosted {
    /// The session ALPN handler, registered on the topic node's router.
    pub session: transport::SessionProtocol,
    /// The receiving end of the [`ServeConfig::audit`](crate::transport::ServeConfig::audit) sink.
    pub records: mpsc::Receiver<AuditRecord>,
    /// The identity index the session protocol's gate reads; the tail loop
    /// feeds it every identity claim on the topic.
    pub identities: Arc<crate::identity::Identities>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::NodeIdentity;
    use tokio::io::AsyncReadExt;

    fn caller() -> NodeId {
        NodeIdentity::from_seed([5u8; 32]).node_id()
    }

    fn alice() -> Principal {
        Principal {
            issuer: "https://idp.example".into(),
            subject: "1".into(),
            email: Some("alice@example.com".into()),
            org: None,
            groups: vec![],
            not_after: 0,
        }
    }

    fn samples() -> Vec<AuditRecord> {
        let call = CallId::from_hex("0123456789abcdef0123456789abcdef").unwrap();
        vec![
            AuditRecord::Started {
                call,
                caller: caller(),
                principal: None,
                tool: stdio_tool(),
                argv: Argv::new(vec!["-n".into()]).unwrap(),
                roster_version: Some(1),
                at_ms: 1,
            },
            AuditRecord::Finished {
                call,
                exit: 0,
                duration_ms: 3,
                stdout_bytes: 0,
                stderr_bytes: 0,
                stdout_digest: OutputHasher::new().finish(),
                stdin_bytes: 0,
                stdin_digest: OutputHasher::new().finish(),
                stdin_head: None,
            },
            AuditRecord::Denied {
                caller: caller(),
                tool: None,
                reason: "no".into(),
                at_ms: 2,
            },
        ]
    }

    /// The sink → publish loop turns each record into exactly one publish
    /// request, in order, whose text parses back to that record.
    #[tokio::test]
    async fn each_record_becomes_exactly_one_publish() {
        let (sink, rx) = AuditSink::channel(AUDIT_QUEUE);
        let (tx, mut requests) = mpsc::channel(4);
        let forwarder = tokio::spawn(forward(rx, tx));
        for record in samples() {
            sink.record(record);
        }
        drop(sink);

        let mut seen = Vec::new();
        while let Some(request) = requests.recv().await {
            seen.push(ChannelRecord::parse(&request.text).expect("a record"));
            let _ = request.reply.send(Ok(seen.len() as u64));
        }
        forwarder.await.unwrap();
        assert_eq!(
            seen,
            samples()
                .into_iter()
                .map(ChannelRecord::Audit)
                .collect::<Vec<_>>(),
            "one message per record, in order, no more and no fewer"
        );
    }

    /// A refused publish is logged and the forwarder keeps going.
    #[tokio::test]
    async fn a_refused_publish_does_not_stop_the_forwarder() {
        let (sink, rx) = AuditSink::channel(AUDIT_QUEUE);
        let (tx, mut requests) = mpsc::channel(4);
        let forwarder = tokio::spawn(forward(rx, tx));
        for record in samples().into_iter().take(2) {
            sink.record(record);
        }
        drop(sink);
        let first = requests.recv().await.unwrap();
        let _ = first.reply.send(Err("no fabric key".into()));
        let second = requests.recv().await.unwrap();
        let _ = second.reply.send(Ok(0));
        assert!(requests.recv().await.is_none());
        forwarder.await.unwrap();
    }

    #[test]
    fn no_sink_means_no_records_and_no_handle() {
        assert!(CallAudit::start(None, caller(), None, stdio_tool(), &[], None).is_none());
        denied(None, caller(), None, "whatever"); // must not panic
    }

    #[test]
    fn denied_records_the_reason_the_caller_gets() {
        let (sink, mut rx) = AuditSink::channel(4);
        let long = "x".repeat(10_000);
        denied(Some(&sink), caller(), None, &long);
        let Ok(AuditRecord::Denied {
            reason, caller: c, ..
        }) = rx.try_recv()
        else {
            panic!("expected a Denied record");
        };
        assert_eq!(c, caller());
        assert_eq!(reason, transport::truncate_reason(long));
    }

    #[tokio::test]
    async fn start_tap_finish_reports_bytes_and_digest() {
        let (sink, mut rx) = AuditSink::channel(4);
        let audit = CallAudit::start(
            Some(&sink),
            caller(),
            Some(alice()),
            stdio_tool(),
            &["a b".to_string()],
            Some(7),
        )
        .unwrap();
        let mut out = tap_stdout(Some(&audit), &b"hello world"[..]);
        let mut err = tap_stderr(Some(&audit), &b"warn"[..]);
        let stdin = tap_stdin(Some(&audit));
        stdin.feed(b"select ");
        stdin.feed(b"1");
        let mut sink_buf = Vec::new();
        out.read_to_end(&mut sink_buf).await.unwrap();
        err.read_to_end(&mut sink_buf).await.unwrap();
        audit.finish(3);

        let Ok(AuditRecord::Started {
            call: started,
            caller: c,
            principal,
            tool,
            argv,
            roster_version,
            ..
        }) = rx.try_recv()
        else {
            panic!("expected Started first");
        };
        assert_eq!(c, caller());
        assert_eq!(principal, Some(alice()), "the record names the person");
        assert_eq!(tool.as_str(), "stdio");
        assert_eq!(argv.as_slice(), ["a b"]);
        assert_eq!(roster_version, Some(7));
        let Ok(AuditRecord::Finished {
            call,
            exit,
            stdout_bytes,
            stderr_bytes,
            stdout_digest,
            stdin_bytes,
            stdin_digest,
            stdin_head,
            ..
        }) = rx.try_recv()
        else {
            panic!("expected Finished second");
        };
        assert_eq!(stdin_bytes, 8);
        assert_eq!(stdin_head.as_deref(), Some("select 1"));
        let mut expect_in = OutputHasher::new();
        expect_in.update(b"select 1");
        assert_eq!(stdin_digest, expect_in.finish());
        assert_eq!(call, started);
        assert_eq!(exit, 3);
        assert_eq!(stdout_bytes, 11);
        assert_eq!(stderr_bytes, 4);
        let mut expect = OutputHasher::new();
        expect.update(b"hello world");
        assert_eq!(stdout_digest, expect.finish());
    }

    #[test]
    fn an_untallied_stdin_tap_records_nothing() {
        tap_stdin(None).feed(b"ignored"); // must not panic
    }

    #[tokio::test]
    async fn an_untallied_tap_is_a_pass_through() {
        let mut tap = tap_stdout(None, &b"abc"[..]);
        let mut buf = Vec::new();
        tap.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"abc");
    }
}

//! The records a host keeps about every call it handles (card 26a): each one
//! lands in the host's own signed, hash-linked call log
//! ([`call_log`](crate::host::call_log)), and is exported over OTLP when
//! `audit.otlp` is set. Nothing is broadcast.
//!
//! # Where the records come from
//!
//! [`CallAudit`] is the per-call handle the session holds: `start` logs
//! [`Started`](AuditRecord::Started) **before** the child is spawned, the
//! [`Tap`]s it hands out count (and, for stdout, BLAKE3-hash) what the child
//! writes, the [`StdinTap`] hashes, counts and quotes the head of what the
//! caller sent on stdin, and `finish` logs [`Finished`](AuditRecord::Finished)
//! before the caller hears the exit code. A member's refusal logs a lone
//! [`Denied`](AuditRecord::Denied) via [`denied`] carrying the exact reason
//! the caller was sent. The caller is always the iroh-authenticated peer,
//! never a handshake claim. A peer that is not a member is traced, never
//! logged (see [`transport`]).
//!
//! # When the log can't take a record
//!
//! Every record is awaited until it is written and `fsync`ed
//! ([`AuditSink::append`]); none is dropped to keep a session moving.
//!
//! - **`Started` fails:** the call is refused
//!   ([`DENY_LOG_UNAVAILABLE`](transport::DENY_LOG_UNAVAILABLE)) and its
//!   child never runs. A call that can't be logged doesn't run.
//! - **`Finished`, `Denied` or a push record fails:** what it records has
//!   already happened, so it is traced at `error` and the session goes on.
//!   The host does not keep a separate "log is broken" switch: every later
//!   call must log its own `Started` first, so while the log stays
//!   unwritable the host runs nothing, and it serves again as soon as the
//!   log takes an entry. A `Started` with no `Finished` in the log therefore
//!   means the call's end was not recorded, not that it never ran.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;

use library::{Argv, AuditRecord, CallId, NodeId, OutputHasher, Principal, StdinCapture, ToolName};
use tokio::io::{AsyncRead, ReadBuf};

use crate::host::transport::{self, AuditSink, LogUnavailable};

/// How many records may wait for the log's writer. A session beyond that
/// waits its turn (within [`LOG_WAIT`](transport::LOG_WAIT)); nothing is
/// dropped.
pub const AUDIT_QUEUE: usize = 256;

/// Unix milliseconds now (the `at_ms` of a record).
pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Log a refusal of `caller` — a member; see the module docs — (asking for
/// `tool`, if it named one) with the reason it was sent. A no-op when the
/// responder has no audit sink. A log that can't take it is traced at
/// `error`: the refusal stands either way.
///
/// The reason is cut exactly as [`transport`] cuts the one it sends, so the
/// record and the caller's `Denied` frame say the same thing.
pub async fn denied(
    sink: Option<&AuditSink>,
    caller: NodeId,
    tool: Option<ToolName>,
    reason: &str,
) {
    let Some(sink) = sink else { return };
    let record = AuditRecord::Denied {
        caller,
        tool,
        reason: transport::truncate_reason(reason.to_string()),
        at_ms: now_ms(),
    };
    if let Err(e) = sink.append(record).await {
        tracing::error!(caller = %caller.hex(), "a refusal was not logged: {e}");
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
    /// Log [`Started`](AuditRecord::Started) for a call `caller` was
    /// admitted to (under `roster_version`, the state version) and return
    /// the handle that will log its `Finished`. `Ok(None)` — and nothing
    /// logged — when the responder has no audit sink.
    ///
    /// Waits until the entry is durably written. `Err` means it wasn't, and
    /// the call must not run (see the module docs).
    ///
    /// `principal` is the caller's verified IdP identity, when it presented
    /// one, so the record names the person, not only the key. `role` is the
    /// registry role that admitted the caller.
    ///
    /// `args` are the call's arguments as the record should show them; an
    /// argument list too large for an [`Argv`] is logged and recorded empty.
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        sink: Option<&AuditSink>,
        caller: NodeId,
        principal: Option<Principal>,
        tool: ToolName,
        args: &[String],
        roster_version: Option<u64>,
        role: Option<String>,
    ) -> Result<Option<Self>, LogUnavailable> {
        let Some(sink) = sink.cloned() else {
            return Ok(None);
        };
        let argv = Argv::new(args.to_vec()).unwrap_or_else(|e| {
            tracing::warn!("audit: recording an empty argv ({e})");
            Argv::default()
        });
        let call = CallId::generate();
        sink.append(AuditRecord::Started {
            call,
            caller,
            principal,
            tool,
            argv,
            roster_version,
            role,
            at_ms: now_ms(),
        })
        .await?;
        Ok(Some(Self {
            sink,
            call,
            spawned: Instant::now(),
            stdout: Tally::default(),
            stderr: Tally::default(),
            stdin: Arc::default(),
        }))
    }

    /// Log [`Finished`](AuditRecord::Finished) with the child's exit code
    /// and what the taps counted, waiting until it is written. The call has
    /// already run, so a log that can't take it is traced at `error` (see
    /// the module docs).
    pub async fn finish(self, exit: i32) {
        let (stdout_bytes, stdout_digest) = {
            let h = self.stdout.lock().expect("stdout tally poisoned");
            (h.bytes(), h.finish())
        };
        let stderr_bytes = self.stderr.lock().expect("stderr tally poisoned").bytes();
        let (stdin_bytes, stdin_digest, stdin_head) = {
            let c = self.stdin.lock().expect("stdin capture poisoned");
            (c.bytes(), c.digest(), c.head())
        };
        let record = AuditRecord::Finished {
            call: self.call,
            exit,
            duration_ms: self.spawned.elapsed().as_millis() as u64,
            stdout_bytes,
            stderr_bytes,
            stdout_digest,
            stdin_bytes,
            stdin_digest,
            stdin_head,
        };
        if let Err(e) = self.sink.append(record).await {
            tracing::error!(
                call = %self.call.hex(),
                exit,
                "a call ran but its end was not logged: {e}"
            );
        }
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
            claims: Default::default(),
        }
    }

    /// The tool the sample calls invoke.
    fn db_query() -> ToolName {
        ToolName::new("db_query").unwrap()
    }

    #[tokio::test]
    async fn no_sink_means_no_records_and_no_handle() {
        let started = CallAudit::start(None, caller(), None, db_query(), &[], None, None).await;
        assert!(started.unwrap().is_none());
        denied(None, caller(), None, "whatever").await; // must not panic
    }

    #[tokio::test]
    async fn denied_records_the_reason_the_caller_gets() {
        let (sink, mut rx) = AuditSink::channel(4);
        let long = "x".repeat(10_000);
        denied(Some(&sink), caller(), None, &long).await;
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
            db_query(),
            &["a b".to_string()],
            Some(7),
            Some("analyst".into()),
        )
        .await
        .unwrap()
        .unwrap();
        let mut out = tap_stdout(Some(&audit), &b"hello world"[..]);
        let mut err = tap_stderr(Some(&audit), &b"warn"[..]);
        let stdin = tap_stdin(Some(&audit));
        stdin.feed(b"select ");
        stdin.feed(b"1");
        let mut sink_buf = Vec::new();
        out.read_to_end(&mut sink_buf).await.unwrap();
        err.read_to_end(&mut sink_buf).await.unwrap();
        audit.finish(3).await;

        let Ok(AuditRecord::Started {
            call: started,
            caller: c,
            principal,
            tool,
            argv,
            roster_version,
            role,
            ..
        }) = rx.try_recv()
        else {
            panic!("expected Started first");
        };
        assert_eq!(role.as_deref(), Some("analyst"));
        assert_eq!(c, caller());
        assert_eq!(principal, Some(alice()), "the record names the person");
        assert_eq!(tool.as_str(), "db_query");
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

    /// A log that can't take `Started` refuses the call's start: no handle,
    /// so no child.
    #[tokio::test]
    async fn a_start_the_log_refuses_is_an_error() {
        let (sink, mut queue) = AuditSink::log_queue(4);
        tokio::spawn(async move {
            while let Some(p) = queue.recv().await {
                p.answer(Err("disk full".into()));
            }
        });
        let e = CallAudit::start(Some(&sink), caller(), None, db_query(), &[], None, None)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("disk full"), "{e}");
    }

    /// A log that never answers is unavailable after `LOG_WAIT`, not a
    /// session stuck forever.
    #[tokio::test(start_paused = true)]
    async fn a_log_that_never_answers_times_out() {
        let (sink, _queue) = AuditSink::log_queue(4);
        let e = CallAudit::start(Some(&sink), caller(), None, db_query(), &[], None, None)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("no answer"), "{e}");
    }

    /// A full queue is waited on, never skipped: every record of a burst far
    /// larger than the queue arrives.
    #[tokio::test]
    async fn a_full_queue_waits_and_drops_nothing() {
        let (sink, mut rx) = AuditSink::channel(2);
        let burst = tokio::spawn(async move {
            for n in 0..50 {
                denied(Some(&sink), caller(), None, &format!("no {n}")).await;
            }
        });
        let mut reasons = Vec::new();
        while reasons.len() < 50 {
            match rx.recv().await {
                Some(AuditRecord::Denied { reason, .. }) => reasons.push(reason),
                other => panic!("unexpected {other:?}"),
            }
        }
        burst.await.unwrap();
        let want: Vec<String> = (0..50).map(|n| format!("no {n}")).collect();
        assert_eq!(reasons, want);
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

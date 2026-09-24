//! Native services: an app's own code serving wires calls in-process, in
//! place of a CLI child.
//!
//! An app implements [`Service`] and registers it on a
//! [`Host`](crate::Host). To callers it is a CLI like any other: it is invoked
//! with arguments, reads stdin, writes stdout and stderr, and returns an exit
//! code. `wires call`, `wires mcp`, the gateway and `wires watch` can't tell
//! the two apart. The host runs a handler only for a call the signed state
//! admitted and whose `Started` record is already in the call log, and
//! records what it read and wrote the way it records a child's stdio. What a
//! handler gets beyond a CLI is a warm process (whatever state the app
//! keeps between calls) and the verified caller as a type ([`Call`]) rather
//! than `WIRES_*` environment variables.
//!
//! A handler runs as a tokio task. When the caller disconnects, or the
//! session is dropped, the task is aborted at its next `.await` (clean up in
//! `Drop`). If it panics, the call exits -1 and still gets its `Finished`
//! record.
//!
//! With `push` configured, a handler can message its caller
//! ([`Call::push_to_caller`]) under the same per-call capability a CLI child
//! gets as `WIRES_PUSH_TOKEN` (card 28 §1): only to this call's caller, only
//! until shortly after the call ends, and only if `push.allow` admits them.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use library::{
    Argv, CallId, NodeId, Principal, PushBody, PushOutcome, RoleName, ServiceName, StateVersion,
    Subject,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use crate::host::capability::{Capabilities, PushToken};
use crate::host::push::{PushCommand, PushSpec};
use crate::host::service::{BoxFuture, Process, Running};

/// A wires service implemented in-process: the handler for every call the
/// host admits to it.
///
/// ```no_run
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
///
/// /// Echoes its stdin back, upper-cased, and greets the verified caller.
/// struct Shout;
///
/// impl wires::Service for Shout {
///     async fn call(&self, call: wires::Call, mut io: wires::CallIo) -> i32 {
///         let who = call.principal().name();
///         let mut input = Vec::new();
///         if io.stdin.read_to_end(&mut input).await.is_err() {
///             return 1;
///         }
///         let reply = format!("hi {who}: {}", String::from_utf8_lossy(&input).to_uppercase());
///         match io.stdout.write_all(reply.as_bytes()).await {
///             Ok(()) => 0,
///             Err(_) => 1,
///         }
///     }
/// }
/// ```
pub trait Service: Send + Sync + 'static {
    /// Handle one admitted call and return its exit code. `call` says who
    /// is calling and with what arguments; `io` is the call's stdin, stdout
    /// and stderr. Returning closes stdout and stderr. The exit code goes
    /// into the call record and back to the caller.
    fn call(&self, call: Call, io: CallIo) -> impl Future<Output = i32> + Send;
}

/// One admitted call, as its handler sees it: the caller the host verified,
/// and what the caller asked for.
///
/// Not `Clone`: it holds the call's push capability, which should have one
/// owner. Share it behind an `Arc` if more than one task needs it.
#[derive(Debug)]
pub struct Call {
    /// The caller's node key.
    pub(crate) caller: NodeId,
    /// The person the caller's ID token verified as (the gate admits no
    /// one without one).
    pub(crate) principal: Principal,
    /// The registry role that admitted the caller.
    pub(crate) role: RoleName,
    /// The signed-state version the call was decided under.
    pub(crate) state_version: StateVersion,
    /// The service called.
    pub(crate) service: ServiceName,
    /// The caller's arguments.
    pub(crate) args: Argv,
    /// This call's id in the host's call log.
    pub(crate) id: CallId,
    /// Its way back to the caller, when the host pushes.
    pub(crate) push: Option<CallerPush>,
}

/// A call's push capability, held in-process: the token the host minted for
/// this call, the registry that decides whether it is still live, and the
/// host's push service.
#[derive(Clone)]
pub(crate) struct CallerPush {
    /// The live tokens (the same registry the child socket checks).
    pub(crate) caps: Arc<Capabilities>,
    /// This call's token.
    pub(crate) token: PushToken,
    /// The host's push service.
    pub(crate) commands: mpsc::Sender<PushCommand>,
}

impl std::fmt::Debug for CallerPush {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The token is a bearer credential: never printed.
        f.write_str("CallerPush { .. }")
    }
}

impl Call {
    /// The caller's node key (the machine that dialed).
    pub fn caller(&self) -> NodeId {
        self.caller
    }

    /// The person the caller verified as with their IdP. Every registry
    /// role names an issuer and no role admits a caller without a verified
    /// ID token, so every admitted call has one.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// The registry role that admitted the caller.
    pub fn role(&self) -> &RoleName {
        &self.role
    }

    /// The signed-state version the call was decided under.
    pub fn state_version(&self) -> StateVersion {
        self.state_version
    }

    /// The service called (the name this handler was registered under).
    pub fn service(&self) -> &ServiceName {
        &self.service
    }

    /// The caller's arguments, as a CLI would get them after its own name.
    pub fn args(&self) -> &[String] {
        self.args.as_slice()
    }

    /// This call's id in the host's call log (the id `wires watch` shows).
    pub fn id(&self) -> CallId {
        self.id
    }

    /// Send the caller a message (their `wires inbox`), as a CLI service
    /// does with `wires push` and its `WIRES_PUSH_TOKEN`. It reaches only
    /// this call's caller, only while the call runs and for a short grace
    /// period after (so a job the call started can still report), and only
    /// if the host's `push.allow` admits them. The push is in the host's
    /// call log, naming this call. Returns whether it was delivered or
    /// queued; errors if the host doesn't push, the capability has expired,
    /// the subject or body is invalid, or `push.allow` refused the caller.
    pub async fn push_to_caller(
        &self,
        subject: impl Into<String>,
        body: impl Into<String>,
    ) -> Result<PushOutcome> {
        let push = self
            .push
            .as_ref()
            .ok_or_else(|| anyhow!("this host doesn't push (it has no `push` configured)"))?;
        let to = self.caller.hex();
        let grant = push
            .caps
            .check(&push.token, &to, std::time::Instant::now())
            .map_err(|refusal| anyhow!("{refusal}"))?;
        let spec = PushSpec {
            to,
            subject: Subject::new(subject)?,
            body: PushBody::new(body)?,
            ttl_secs: None,
        };
        let (reply, answer) = oneshot::channel();
        push.commands
            .send(PushCommand {
                spec,
                call: grant.call,
                reply,
            })
            .await
            .map_err(|_| anyhow!("the host is shutting down"))?;
        let report = answer
            .await
            .map_err(|_| anyhow!("the host dropped the push without answering"))?
            .map_err(anyhow::Error::msg)?;
        let Some(result) = report.results.into_iter().next() else {
            bail!("the host reported no recipient");
        };
        if result.outcome == PushOutcome::Denied {
            bail!(
                "push refused: {}",
                result.reason.as_deref().unwrap_or("denied")
            );
        }
        Ok(result.outcome)
    }
}

/// One call's stdio: what the caller sends on stdin, and where the handler
/// writes stdout and stderr. The host records all three the way it records
/// a CLI child's.
pub struct CallIo {
    /// The caller's stdin, until they send EOF.
    pub stdin: Box<dyn AsyncRead + Send + Unpin>,
    /// Goes to the caller's stdout.
    pub stdout: Box<dyn AsyncWrite + Send + Unpin>,
    /// Goes to the caller's stderr.
    pub stderr: Box<dyn AsyncWrite + Send + Unpin>,
}

/// One of a call's streams, until the call finishes.
type Slot<T> = tokio::sync::Mutex<Option<Box<T>>>;

/// A call's stdio behind locks, for a handler that can't hold [`CallIo`] by
/// value: a foreign-language runtime (the Python and Node bindings) whose
/// call object is shared between threads or Promises and may outlive the
/// call. Every method fails with "the call has finished" once
/// [`close`](Self::close) has run.
pub struct SharedIo {
    stdin: Slot<dyn AsyncRead + Send + Unpin>,
    stdout: Slot<dyn AsyncWrite + Send + Unpin>,
    stderr: Slot<dyn AsyncWrite + Send + Unpin>,
}

impl SharedIo {
    /// The most bytes [`read_to_end`](Self::read_to_end) gathers before it
    /// fails, so a caller can't make a handler buffer without bound. Stream
    /// larger input with [`read`](Self::read).
    pub const READ_ALL_MAX: u64 = 64 * 1024 * 1024;

    /// Share `io`.
    pub fn new(io: CallIo) -> Self {
        Self {
            stdin: tokio::sync::Mutex::new(Some(io.stdin)),
            stdout: tokio::sync::Mutex::new(Some(io.stdout)),
            stderr: tokio::sync::Mutex::new(Some(io.stderr)),
        }
    }

    /// Read some of the caller's stdin into `buf`: how many bytes, 0 at EOF.
    /// Waits until some arrive.
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut stdin = self.stdin.lock().await;
        let stdin = stdin.as_mut().ok_or_else(finished)?;
        Ok(stdin.read(buf).await?)
    }

    /// Append the rest of the caller's stdin, to EOF, to `buf`. Fails past
    /// [`READ_ALL_MAX`](Self::READ_ALL_MAX) bytes.
    pub async fn read_to_end(&self, buf: &mut Vec<u8>) -> Result<()> {
        let mut stdin = self.stdin.lock().await;
        let stdin = stdin.as_mut().ok_or_else(finished)?;
        let n = (&mut **stdin)
            .take(Self::READ_ALL_MAX + 1)
            .read_to_end(buf)
            .await?;
        if n as u64 > Self::READ_ALL_MAX {
            bail!("stdin is over 64 MiB; read it in chunks");
        }
        Ok(())
    }

    /// Write all of `data` to the caller's stdout (waits while the caller
    /// is behind).
    pub async fn write_stdout(&self, data: &[u8]) -> Result<()> {
        write_all(&self.stdout, data).await
    }

    /// Write all of `data` to the caller's stderr.
    pub async fn write_stderr(&self, data: &[u8]) -> Result<()> {
        write_all(&self.stderr, data).await
    }

    /// The handler is done: close stdout and stderr (EOF to the caller) and
    /// drop stdin, even while the foreign side still holds the call.
    pub async fn close(&self) {
        for out in [&self.stdout, &self.stderr] {
            if let Some(mut w) = out.lock().await.take() {
                let _ = w.shutdown().await;
            }
        }
        self.stdin.lock().await.take();
    }
}

/// Write and flush all of `data` to `out`, unless the call has finished.
async fn write_all(out: &Slot<dyn AsyncWrite + Send + Unpin>, data: &[u8]) -> Result<()> {
    let mut out = out.lock().await;
    let out = out.as_mut().ok_or_else(finished)?;
    out.write_all(data).await?;
    Ok(out.flush().await?)
}

/// The error for stdio used after the call finished.
fn finished() -> anyhow::Error {
    anyhow!("the call has finished")
}

/// [`Service`] with its future boxed, so a host can hold services of
/// different types in one map.
pub(crate) trait DynService: Send + Sync + 'static {
    /// [`Service::call`], boxed.
    fn call_boxed(&self, call: Call, io: CallIo) -> BoxFuture<'_, i32>;
}

impl<S: Service> DynService for S {
    fn call_boxed(&self, call: Call, io: CallIo) -> BoxFuture<'_, i32> {
        Box::pin(self.call(call, io))
    }
}

/// The native services a host implements, by name.
pub(crate) type NativeServices = BTreeMap<ServiceName, Arc<dyn DynService>>;

/// How much of a stream sits in memory between the handler and the session
/// before a write waits: the session's stdio chunk size.
const PIPE_BUF: usize = 64 * 1024;

/// Start `service` on `call` as a task, and hand the bridge its stdio.
pub(crate) fn start(service: Arc<dyn DynService>, call: Call) -> Running {
    let (stdin_w, stdin_r) = tokio::io::duplex(PIPE_BUF);
    let (stdout_w, stdout_r) = tokio::io::duplex(PIPE_BUF);
    let (stderr_w, stderr_r) = tokio::io::duplex(PIPE_BUF);
    let io = CallIo {
        stdin: Box::new(stdin_r),
        stdout: Box::new(stdout_w),
        stderr: Box::new(stderr_w),
    };
    // `io` moves into the task, so stdout and stderr close (EOF to the
    // bridge) when the handler returns.
    let task = tokio::spawn(async move { service.call_boxed(call, io).await });
    Running {
        stdin: Box::new(stdin_w),
        stdout: Box::new(stdout_r),
        stderr: Box::new(stderr_r),
        process: Box::new(Task {
            handle: task,
            code: None,
        }),
    }
}

/// A native service's task as a [`Process`]: stopping it aborts the task;
/// a task that was aborted or panicked exits -1. The handle stays here while
/// a [`wait`](Process::wait) is pending, so a `kill` after a dropped `wait`
/// still reaches the task, and dropping the `Task` aborts it too: a handler
/// never outlives its session (a dropped `JoinHandle` would detach it).
struct Task {
    /// The handler's task.
    handle: tokio::task::JoinHandle<i32>,
    /// Its exit code, once it has ended.
    code: Option<i32>,
}

impl Drop for Task {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl Process for Task {
    fn wait(&mut self) -> BoxFuture<'_, Result<i32>> {
        Box::pin(async move {
            if let Some(code) = self.code {
                return Ok(code);
            }
            let code = match (&mut self.handle).await {
                Ok(code) => code,
                Err(e) if e.is_panic() => {
                    tracing::warn!("a native service's handler panicked; the call exits -1");
                    -1
                }
                Err(_) => -1,
            };
            self.code = Some(code);
            Ok(code)
        })
    }

    fn kill(&mut self) {
        self.handle.abort();
    }
}

/// A call to service `t` with arguments `a b`, from node 2 verified as
/// `alice@example.com`, admitted as `staff`: for unit tests.
#[cfg(test)]
pub(crate) fn test_call() -> Call {
    Call {
        caller: library::NodeIdentity::from_seed([2u8; 32]).node_id(),
        principal: Principal {
            issuer: "https://idp.example".into(),
            subject: "alice".into(),
            email: Some("alice@example.com".into()),
            org: None,
            groups: Vec::new(),
            not_after: i64::MAX,
            claims: Default::default(),
        },
        role: RoleName::new("staff").unwrap(),
        state_version: StateVersion(1),
        service: ServiceName::new("t").unwrap(),
        args: Argv::new(vec!["a".into(), "b".into()]).unwrap(),
        id: CallId::generate(),
        push: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call() -> Call {
        test_call()
    }

    /// Writes its arguments to stdout, its stdin to stderr, exits 7.
    struct Echo;

    impl Service for Echo {
        async fn call(&self, call: Call, mut io: CallIo) -> i32 {
            let mut input = Vec::new();
            io.stdin.read_to_end(&mut input).await.unwrap();
            io.stdout
                .write_all(call.args().join(" ").as_bytes())
                .await
                .unwrap();
            io.stderr.write_all(&input).await.unwrap();
            7
        }
    }

    struct Panics;

    impl Service for Panics {
        async fn call(&self, _call: Call, _io: CallIo) -> i32 {
            panic!("boom")
        }
    }

    #[tokio::test]
    async fn a_handler_gets_its_call_and_stdio_and_its_exit_code_is_the_calls() {
        let mut running = start(Arc::new(Echo), call());
        running.stdin.write_all(b"in").await.unwrap();
        running.stdin.shutdown().await.unwrap();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        running.stdout.read_to_end(&mut out).await.unwrap();
        running.stderr.read_to_end(&mut err).await.unwrap();
        assert_eq!((out.as_slice(), err.as_slice()), (&b"a b"[..], &b"in"[..]));
        assert_eq!(running.process.wait().await.unwrap(), 7);
    }

    #[tokio::test]
    async fn a_panicking_handler_exits_minus_one_and_closes_its_output() {
        let mut running = start(Arc::new(Panics), call());
        let mut out = Vec::new();
        running.stdout.read_to_end(&mut out).await.unwrap();
        assert!(out.is_empty());
        assert_eq!(running.process.wait().await.unwrap(), -1);
    }

    /// The bridge's shape: a `wait` raced against the caller leaving and
    /// dropped, then `kill` and `wait` again. The kill must still reach the
    /// task.
    #[tokio::test]
    async fn a_kill_after_a_dropped_wait_still_stops_the_handler() {
        struct Forever;
        impl Service for Forever {
            async fn call(&self, _call: Call, _io: CallIo) -> i32 {
                std::future::pending::<()>().await;
                0
            }
        }
        let mut running = start(Arc::new(Forever), call());
        tokio::select! {
            _ = running.process.wait() => panic!("Forever doesn't end"),
            () = tokio::task::yield_now() => {}
        }
        running.process.kill();
        let code = tokio::time::timeout(std::time::Duration::from_secs(5), running.process.wait())
            .await
            .expect("the kill should end the handler");
        assert_eq!(code.unwrap(), -1);
        // Its stdio closes with it.
        let mut out = Vec::new();
        running.stdout.read_to_end(&mut out).await.unwrap();
    }

    #[tokio::test]
    async fn a_stopped_handler_exits_minus_one() {
        struct Forever;
        impl Service for Forever {
            async fn call(&self, _call: Call, _io: CallIo) -> i32 {
                std::future::pending::<()>().await;
                0
            }
        }
        let mut running = start(Arc::new(Forever), call());
        running.process.kill();
        assert_eq!(running.process.wait().await.unwrap(), -1);
    }

    /// Dropping a call's `Running` (its session future was dropped) aborts
    /// the handler rather than leaving it running detached.
    #[tokio::test]
    async fn dropping_the_running_service_aborts_its_handler() {
        /// Holds `alive` for as long as its task runs; never returns.
        struct Forever(std::sync::Mutex<Option<oneshot::Sender<()>>>);
        impl Service for Forever {
            async fn call(&self, _call: Call, _io: CallIo) -> i32 {
                let _alive = self.0.lock().unwrap().take();
                std::future::pending::<()>().await;
                0
            }
        }
        let (alive, ended) = oneshot::channel();
        let running = start(
            Arc::new(Forever(std::sync::Mutex::new(Some(alive)))),
            call(),
        );
        tokio::task::yield_now().await;
        drop(running);
        let ended = tokio::time::timeout(std::time::Duration::from_secs(5), ended).await;
        assert!(
            ended.expect("the handler should be aborted").is_err(),
            "the handler's task ended without sending: it was dropped"
        );
    }

    #[tokio::test]
    async fn shared_io_reads_writes_and_refuses_after_close() {
        let (mut in_w, in_r) = tokio::io::duplex(64);
        let (out_w, mut out_r) = tokio::io::duplex(64);
        let (err_w, mut err_r) = tokio::io::duplex(64);
        let io = SharedIo::new(CallIo {
            stdin: Box::new(in_r),
            stdout: Box::new(out_w),
            stderr: Box::new(err_w),
        });
        in_w.write_all(b"abc").await.unwrap();
        drop(in_w);
        let mut all = Vec::new();
        io.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, b"abc");
        io.write_stdout(b"out").await.unwrap();
        io.write_stderr(b"err").await.unwrap();
        io.close().await;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        out_r.read_to_end(&mut out).await.unwrap();
        err_r.read_to_end(&mut err).await.unwrap();
        assert_eq!((out.as_slice(), err.as_slice()), (&b"out"[..], &b"err"[..]));
        let late = [
            io.read(&mut [0u8; 4]).await.unwrap_err(),
            io.read_to_end(&mut Vec::new()).await.unwrap_err(),
            io.write_stdout(b"late").await.unwrap_err(),
            io.write_stderr(b"late").await.unwrap_err(),
        ];
        for e in late {
            assert_eq!(e.to_string(), "the call has finished");
        }
    }
}

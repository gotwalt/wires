//! Native services: an app's own code serving wires calls in-process
//! (card 33), in place of a CLI child.
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
//! A handler runs as a tokio task. When the caller disconnects, the task is
//! aborted at its next `.await` (clean up in `Drop`). If it panics, the call
//! exits -1 and still gets its `Finished` record.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;

use anyhow::Result;
use library::{Argv, CallId, NodeId, Principal, RoleName, ServiceName, StateVersion};
use tokio::io::{AsyncRead, AsyncWrite};

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
///         let who = call.principal().and_then(|p| p.email.clone()).unwrap_or_default();
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
#[derive(Clone, Debug)]
pub struct Call {
    /// The caller's node key.
    pub(crate) caller: NodeId,
    /// The person the caller's ID token verified as, when it presented one.
    pub(crate) principal: Option<Principal>,
    /// The registry role that admitted the caller.
    pub(crate) role: RoleName,
    /// The signed-state version the call was decided under.
    pub(crate) state_version: StateVersion,
    /// The service called.
    pub(crate) service: ServiceName,
    /// The caller's arguments.
    pub(crate) args: Argv,
    /// This call's id in the host's call log, when the host keeps one.
    pub(crate) id: Option<CallId>,
}

impl Call {
    /// The caller's node key (the machine that dialed).
    pub fn caller(&self) -> NodeId {
        self.caller
    }

    /// The person the caller verified as with their IdP. Every registry
    /// role names an issuer, so an admitted call has one; `None` only if
    /// that ever changes.
    pub fn principal(&self) -> Option<&Principal> {
        self.principal.as_ref()
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
    pub fn id(&self) -> Option<CallId> {
        self.id
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
        process: Box::new(Task(Some(task))),
    }
}

/// A native service's task as a [`Process`]: stopping it aborts the task;
/// a task that was aborted or panicked exits -1.
struct Task(Option<tokio::task::JoinHandle<i32>>);

impl Process for Task {
    fn wait(&mut self) -> BoxFuture<'_, Result<i32>> {
        Box::pin(async move {
            let Some(task) = self.0.take() else {
                return Ok(-1);
            };
            Ok(match task.await {
                Ok(code) => code,
                Err(e) if e.is_panic() => {
                    tracing::warn!("a native service's handler panicked; the call exits -1");
                    -1
                }
                Err(_) => -1,
            })
        })
    }

    fn kill(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn call() -> Call {
        Call {
            caller: library::NodeIdentity::from_seed([2u8; 32]).node_id(),
            principal: None,
            role: RoleName::new("staff").unwrap(),
            state_version: StateVersion(1),
            service: ServiceName::new("t").unwrap(),
            args: Argv::new(vec!["a".into(), "b".into()]).unwrap(),
            id: None,
        }
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
}

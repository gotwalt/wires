//! What a service is while one call runs, as the session bridge sees it
//! (card 33).
//!
//! The bridge ([`transport`](crate::host::transport)) doesn't care what
//! implements a service. It needs the call's stdin to write to, its stdout
//! and stderr to read from, and a [`Process`] to wait on or stop: a
//! [`Running`]. A CLI child ([`Running::spawn`]) is one way to get one; an
//! in-process handler is another. The audit taps, the kill when the caller
//! disconnects, and the rule that stdin stops once the service ends all live
//! in the bridge, so every kind of service gets them.

use std::future::Future;
use std::pin::Pin;
use std::process::Stdio;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::process::{Child, Command};

/// A boxed, sendable future: what [`Process`]'s methods return, so the trait
/// works as `dyn Process`.
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How the bridge learns that a running service has ended, or stops it.
pub(crate) trait Process: Send {
    /// Wait for the service to end. Its exit code, or -1 when it had none
    /// (a child killed by a signal).
    fn wait(&mut self) -> BoxFuture<'_, Result<i32>>;

    /// Ask the service to stop because its caller is gone; a later
    /// [`wait`](Self::wait) reaps it.
    fn kill(&mut self);
}

/// One call's running service: its stdio and its [`Process`].
pub(crate) struct Running {
    /// Where the caller's stdin goes. The bridge shuts it down at the
    /// caller's EOF.
    pub(crate) stdin: Box<dyn AsyncWrite + Send + Unpin>,
    /// The service's stdout, read until EOF.
    pub(crate) stdout: Box<dyn AsyncRead + Send + Unpin>,
    /// The service's stderr, read until EOF.
    pub(crate) stderr: Box<dyn AsyncRead + Send + Unpin>,
    /// How it ends.
    pub(crate) process: Box<dyn Process>,
}

impl Running {
    /// Spawn `cmd` with piped stdio. Errors if it can't be spawned.
    pub(crate) fn spawn(mut cmd: Command) -> std::io::Result<Running> {
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let piped = || std::io::Error::other("child stdio was not piped");
        Ok(Running {
            stdin: Box::new(child.stdin.take().ok_or_else(piped)?),
            stdout: Box::new(child.stdout.take().ok_or_else(piped)?),
            stderr: Box::new(child.stderr.take().ok_or_else(piped)?),
            process: Box::new(ChildProcess(child)),
        })
    }
}

/// A spawned CLI child as a [`Process`].
struct ChildProcess(Child);

impl Process for ChildProcess {
    fn wait(&mut self) -> BoxFuture<'_, Result<i32>> {
        Box::pin(async move {
            let status = self.0.wait().await.context("waiting for child")?;
            Ok(status.code().unwrap_or(-1))
        })
    }

    fn kill(&mut self) {
        self.0.start_kill().ok();
    }
}

//! `wires-ffi`: wires-native services from other languages (card 33,
//! phase 2), through [UniFFI](https://mozilla.github.io/uniffi-rs/). The
//! foreign module is named `wires`.
//!
//! The surface is the Rust embedding API ([`wires::Host`],
//! [`wires::Service`]) reshaped for a foreign runtime: nothing generic, no
//! Rust futures, and stdio as chunks of bytes.
//!
//! - [`Service`]: what a foreign class implements. `call(call) -> int` is
//!   **synchronous** and runs on a blocking thread of its own, so any code
//!   works in it (Python's included, which takes the GIL there).
//! - [`Call`]: one admitted call. It holds the verified caller, the
//!   arguments, blocking stdio (`read_stdin`, `write_stdout`,
//!   `write_stderr`) and `push_to_caller`.
//! - [`HostBuilder`] → [`Host`]: build from a joined node's keystore, then
//!   `serve()`, which blocks until `stop()` or Ctrl-C.
//!
//! ```python
//! import wires
//!
//! class Shout(wires.Service):
//!     def call(self, call):
//!         call.write_stdout(call.read_all_stdin().upper())
//!         return 0
//!
//! host = (wires.HostBuilder("/var/lib/shout/wires")
//!         .trust_issuer("https://accounts.google.com", ["…apps.googleusercontent.com"])
//!         .service("shout", Shout())
//!         .build())
//! host.serve()
//! ```
//!
//! What a foreign handler differs in from a Rust one: it runs on a thread,
//! so when the caller disconnects it isn't stopped; its next read or write
//! fails instead. An exception it raises ends the call with exit 1 and the
//! exception's text on the caller's stderr, as an uncaught exception in a
//! CLI would. The host's node key stays in Rust memory; nothing here hands
//! it to the foreign side.

use std::sync::{Arc, Mutex, OnceLock};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

uniffi::setup_scaffolding!("wires");

/// Every failure the bindings report: a message saying what went wrong.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum WiresError {
    /// The operation failed.
    #[error("{message}")]
    Failed {
        /// Why.
        message: String,
    },
}

impl WiresError {
    fn from_anyhow(e: impl std::fmt::Display) -> Self {
        Self::Failed {
            message: e.to_string(),
        }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for WiresError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Failed { message: e.reason }
    }
}

/// A wires service implemented in a foreign language: the handler for every
/// call the host admits to it.
#[uniffi::export(with_foreign)]
pub trait Service: Send + Sync {
    /// Handle one admitted call and return its exit code. Runs on a thread
    /// of its own; block freely. Raising (returning an error) ends the call
    /// with exit 1.
    fn call(&self, call: Arc<Call>) -> Result<i32, WiresError>;
}

/// The person a caller verified as with their IdP.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Principal {
    /// The ID token's `iss`.
    pub issuer: String,
    /// The ID token's `sub`: the IdP's stable id for them.
    pub subject: String,
    /// Their verified email, when the IdP asserted one.
    pub email: Option<String>,
}

/// One admitted call: who is calling, with what, and its stdio. Readable and
/// writable only while the call runs; after the handler returns, the stdio
/// methods fail.
#[derive(uniffi::Object)]
pub struct Call {
    call: wires::Call,
    stdin: tokio::sync::Mutex<Option<Box<dyn AsyncRead + Send + Unpin>>>,
    stdout: tokio::sync::Mutex<Option<Box<dyn AsyncWrite + Send + Unpin>>>,
    stderr: tokio::sync::Mutex<Option<Box<dyn AsyncWrite + Send + Unpin>>>,
}

/// The most bytes [`Call::read_all_stdin`] gathers before it fails, so a
/// caller can't make a handler buffer without bound. Stream larger input
/// with [`Call::read_stdin`].
const READ_ALL_MAX: u64 = 64 * 1024 * 1024;

/// The error for stdio used after the call finished.
fn finished() -> WiresError {
    WiresError::Failed {
        message: "the call has finished".into(),
    }
}

#[uniffi::export]
impl Call {
    /// The caller's node id (64 hex).
    pub fn caller(&self) -> String {
        self.call.caller().hex()
    }

    /// The person the caller verified as. Every registry role names an
    /// issuer, so an admitted call has one.
    pub fn principal(&self) -> Option<Principal> {
        self.call.principal().map(|p| Principal {
            issuer: p.issuer.clone(),
            subject: p.subject.clone(),
            email: p.email.clone(),
        })
    }

    /// The registry role that admitted the caller.
    pub fn role(&self) -> String {
        self.call.role().as_str().to_string()
    }

    /// The signed-state version the call was decided under.
    pub fn state_version(&self) -> u64 {
        self.call.state_version().0
    }

    /// The service called.
    pub fn service(&self) -> String {
        self.call.service().as_str().to_string()
    }

    /// The caller's arguments.
    pub fn args(&self) -> Vec<String> {
        self.call.args().to_vec()
    }

    /// This call's id in the host's call log (what `wires watch` shows).
    pub fn id(&self) -> Option<String> {
        self.call.id().map(|id| id.hex())
    }

    /// Up to `max` bytes of the caller's stdin; empty at EOF. Blocks until
    /// some arrive.
    pub fn read_stdin(&self, max: u32) -> Result<Vec<u8>, WiresError> {
        runtime().block_on(async {
            let mut stdin = self.stdin.lock().await;
            let stdin = stdin.as_mut().ok_or_else(finished)?;
            let mut buf = vec![0u8; max.max(1) as usize];
            let n = stdin
                .read(&mut buf)
                .await
                .map_err(WiresError::from_anyhow)?;
            buf.truncate(n);
            Ok(buf)
        })
    }

    /// The rest of the caller's stdin, to EOF (at most 64 MiB; stream more
    /// with `read_stdin`).
    pub fn read_all_stdin(&self) -> Result<Vec<u8>, WiresError> {
        runtime().block_on(async {
            let mut stdin = self.stdin.lock().await;
            let stdin = stdin.as_mut().ok_or_else(finished)?;
            let mut all = Vec::new();
            (&mut *stdin)
                .take(READ_ALL_MAX + 1)
                .read_to_end(&mut all)
                .await
                .map_err(WiresError::from_anyhow)?;
            if all.len() as u64 > READ_ALL_MAX {
                return Err(WiresError::Failed {
                    message: "stdin is over 64 MiB; read it with read_stdin".into(),
                });
            }
            Ok(all)
        })
    }

    /// Write `data` to the caller's stdout. Blocks while the caller is
    /// behind.
    pub fn write_stdout(&self, data: Vec<u8>) -> Result<(), WiresError> {
        write(&self.stdout, &data)
    }

    /// Write `data` to the caller's stderr.
    pub fn write_stderr(&self, data: Vec<u8>) -> Result<(), WiresError> {
        write(&self.stderr, &data)
    }

    /// Send the caller a message (their `wires inbox`), under this call's
    /// push capability: only to this caller, until shortly after the call
    /// ends, and only if the host's push allow-list admits them. Returns
    /// `delivered` or `queued`.
    pub fn push_to_caller(&self, subject: String, body: String) -> Result<String, WiresError> {
        runtime()
            .block_on(self.call.push_to_caller(subject, body))
            .map(|outcome| outcome.as_str().to_string())
            .map_err(|e| WiresError::from_anyhow(format!("{e:#}")))
    }
}

impl Call {
    /// A call wrapping `call` and its stdio.
    fn new(call: wires::Call, io: wires::CallIo) -> Self {
        Self {
            call,
            stdin: tokio::sync::Mutex::new(Some(io.stdin)),
            stdout: tokio::sync::Mutex::new(Some(io.stdout)),
            stderr: tokio::sync::Mutex::new(Some(io.stderr)),
        }
    }

    /// The handler returned: close stdout and stderr (EOF to the caller),
    /// even if the foreign side still holds this object.
    async fn close(&self) {
        for out in [&self.stdout, &self.stderr] {
            if let Some(mut w) = out.lock().await.take() {
                let _ = w.shutdown().await;
            }
        }
        self.stdin.lock().await.take();
    }
}

/// Write all of `data` to `out`, blocking the calling (foreign) thread.
fn write(
    out: &tokio::sync::Mutex<Option<Box<dyn AsyncWrite + Send + Unpin>>>,
    data: &[u8],
) -> Result<(), WiresError> {
    runtime().block_on(async {
        let mut out = out.lock().await;
        let out = out.as_mut().ok_or_else(finished)?;
        out.write_all(data).await.map_err(WiresError::from_anyhow)?;
        out.flush().await.map_err(WiresError::from_anyhow)
    })
}

/// A foreign [`Service`] as a Rust [`wires::Service`]: its `call` runs on a
/// blocking thread.
struct Foreign(Arc<dyn Service>);

impl wires::Service for Foreign {
    async fn call(&self, call: wires::Call, io: wires::CallIo) -> i32 {
        let ffi = Arc::new(Call::new(call, io));
        let service = Arc::clone(&self.0);
        let handed = Arc::clone(&ffi);
        let code = match tokio::task::spawn_blocking(move || service.call(handed)).await {
            Ok(Ok(code)) => code,
            Ok(Err(e)) => {
                // What an uncaught exception in a CLI does: its text on
                // stderr, exit 1.
                let text = format!("{e}\n");
                if let Some(err) = ffi.stderr.lock().await.as_mut() {
                    let _ = err.write_all(text.as_bytes()).await;
                }
                1
            }
            Err(e) => {
                tracing::warn!("a foreign service's handler failed: {e}");
                -1
            }
        };
        ffi.close().await;
        code
    }
}

/// The runtime every host and every blocking stdio call runs on: made on
/// first use, and never shut down.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("wires")
            .build()
            .expect("starting the wires runtime")
    })
}

/// Collects what a [`Host`] implements and trusts; each method returns the
/// builder, for chaining. [`build`](Self::build) checks it and reads the
/// keystore.
#[derive(uniffi::Object)]
pub struct HostBuilder {
    inner: Mutex<Option<wires::HostBuilder>>,
}

impl HostBuilder {
    /// Apply `f` to the builder, unless it was already built.
    fn with(
        self: Arc<Self>,
        f: impl FnOnce(wires::HostBuilder) -> wires::HostBuilder,
    ) -> Arc<Self> {
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            *inner = inner.take().map(f);
        }
        self
    }
}

#[uniffi::export]
impl HostBuilder {
    /// Start building a host whose keystore is `home` (a node joined with
    /// `WIRES_HOME=<home> wires id` and `wires join`).
    #[uniffi::constructor]
    pub fn new(home: String) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Some(wires::Host::builder(home))),
        })
    }

    /// Trust ID tokens from `issuer` for the OAuth client ids `audiences`.
    pub fn trust_issuer(self: Arc<Self>, issuer: String, audiences: Vec<String>) -> Arc<Self> {
        self.with(|b| b.trust_issuer(issuer, audiences))
    }

    /// Let the host push to members of `roles` (what `push_to_caller`
    /// needs).
    pub fn push_allow(self: Arc<Self>, roles: Vec<String>) -> Arc<Self> {
        self.with(|b| b.push_allow(roles))
    }

    /// Also read `path` as `host.json` v2 (CLI services beside the foreign
    /// ones, trusted IdPs, push, audit export).
    pub fn host_json(self: Arc<Self>, path: String) -> Arc<Self> {
        self.with(|b| b.host_json(path))
    }

    /// Accept direct connections only on this machine's loopback; callers
    /// elsewhere still reach the host through its relay. For local demos:
    /// the macOS firewall doesn't prompt for a loopback-only host.
    pub fn bind_loopback(self: Arc<Self>) -> Arc<Self> {
        self.with(|b| b.bind_loopback())
    }

    /// Use a self-hosted relay at `url`.
    pub fn relay_url(self: Arc<Self>, url: String) -> Arc<Self> {
        self.with(|b| b.relay_url(url))
    }

    /// Implement service `name` with `service`.
    pub fn service(self: Arc<Self>, name: String, service: Arc<dyn Service>) -> Arc<Self> {
        self.with(|b| b.service(name, Foreign(service)))
    }

    /// Check the configuration and load the keystore. A builder builds once.
    pub fn build(&self) -> Result<Arc<Host>, WiresError> {
        let builder = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| WiresError::Failed {
                message: "this builder was already built".into(),
            })?;
        let host = builder
            .build()
            .map_err(|e| WiresError::from_anyhow(format!("{e:#}")))?;
        Ok(Arc::new(Host {
            node_id: host.node_id().hex(),
            host: Mutex::new(Some(host)),
            stop: Mutex::new(None),
        }))
    }
}

/// A wires host in this process, ready to serve.
#[derive(uniffi::Object)]
pub struct Host {
    node_id: String,
    host: Mutex<Option<wires::Host>>,
    stop: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

#[uniffi::export]
impl Host {
    /// This host's node id: what the admin names in `wires service add
    /// --host`.
    pub fn node_id(&self) -> String {
        self.node_id.clone()
    }

    /// Serve, blocking, until [`stop`](Self::stop) or Ctrl-C. Errors
    /// before serving if the signed state doesn't assign every service to
    /// this host. A host serves once.
    pub fn serve(&self) -> Result<(), WiresError> {
        let host = self
            .host
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| WiresError::Failed {
                message: "this host has already served".into(),
            })?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        *self.stop.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        runtime()
            .block_on(host.serve_until(async {
                tokio::select! {
                    _ = rx => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }))
            .map_err(|e| WiresError::from_anyhow(format!("{e:#}")))
    }

    /// Make a running [`serve`](Self::serve) return. Safe from any thread;
    /// does nothing if the host isn't serving.
    pub fn stop(&self) {
        if let Some(tx) = self.stop.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = tx.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Nop;

    impl Service for Nop {
        fn call(&self, _call: Arc<Call>) -> Result<i32, WiresError> {
            Ok(0)
        }
    }

    #[test]
    fn a_builder_builds_once_and_an_unjoined_keystore_says_what_to_run() {
        let home = std::env::temp_dir().join(format!("wires-ffi-{}", std::process::id()));
        let b = HostBuilder::new(home.display().to_string()).service("t".into(), Arc::new(Nop));
        let e = b
            .build()
            .err()
            .expect("an empty keystore can't build")
            .to_string();
        assert!(e.contains("wires id"), "{e}");
        let again = b.build().err().expect("a builder builds once").to_string();
        assert_eq!(again, "this builder was already built");
    }
}

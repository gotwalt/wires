//! `wires-ffi`: wires-native services from other languages, through
//! [UniFFI](https://mozilla.github.io/uniffi-rs/). The foreign module is
//! named `wires`.
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
//!   `serve()`, which blocks until `stop()` (or Ctrl-C, when asked with
//!   `serve(handle_ctrl_c=True)`).
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

use wires::SharedIo;

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
    /// `e`, with its whole chain of causes.
    fn failed(e: &anyhow::Error) -> Self {
        Self::Failed {
            message: format!("{e:#}"),
        }
    }

    /// An error saying `message`.
    fn msg(message: impl Into<String>) -> Self {
        Self::Failed {
            message: message.into(),
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

impl From<&wires::Principal> for Principal {
    fn from(p: &wires::Principal) -> Self {
        Self {
            issuer: p.issuer.clone(),
            subject: p.subject.clone(),
            email: p.email.clone(),
        }
    }
}

/// One admitted call: who is calling, with what, and its stdio. Readable and
/// writable only while the call runs; after the handler returns, the stdio
/// methods fail.
#[derive(uniffi::Object)]
pub struct Call {
    call: wires::Call,
    io: Arc<SharedIo>,
}

#[uniffi::export]
impl Call {
    /// The caller's node id (64 hex).
    pub fn caller(&self) -> String {
        self.call.caller().hex()
    }

    /// The person the caller verified as (every admitted call has one).
    pub fn principal(&self) -> Principal {
        self.call.principal().into()
    }

    /// The registry role that admitted the caller.
    pub fn role(&self) -> String {
        self.call.role().as_str().to_string()
    }

    /// The policy version the call was decided under.
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
    pub fn id(&self) -> String {
        self.call.id().hex()
    }

    /// Up to `max` bytes of the caller's stdin; empty at EOF. Blocks until
    /// some arrive.
    pub fn read_stdin(&self, max: u32) -> Result<Vec<u8>, WiresError> {
        let mut buf = vec![0u8; max.max(1) as usize];
        let n = runtime()
            .block_on(self.io.read(&mut buf))
            .map_err(|e| WiresError::failed(&e))?;
        buf.truncate(n);
        Ok(buf)
    }

    /// The rest of the caller's stdin, to EOF (at most 64 MiB; stream more
    /// with `read_stdin`).
    pub fn read_all_stdin(&self) -> Result<Vec<u8>, WiresError> {
        let mut all = Vec::new();
        runtime()
            .block_on(self.io.read_to_end(&mut all))
            .map_err(|e| WiresError::failed(&e))?;
        Ok(all)
    }

    /// Write `data` to the caller's stdout. Blocks while the caller is
    /// behind.
    pub fn write_stdout(&self, data: Vec<u8>) -> Result<(), WiresError> {
        runtime()
            .block_on(self.io.write_stdout(&data))
            .map_err(|e| WiresError::failed(&e))
    }

    /// Write `data` to the caller's stderr.
    pub fn write_stderr(&self, data: Vec<u8>) -> Result<(), WiresError> {
        runtime()
            .block_on(self.io.write_stderr(&data))
            .map_err(|e| WiresError::failed(&e))
    }

    /// Send the caller a message (their `wires inbox`), under this call's
    /// push capability: only to this caller, until shortly after the call
    /// ends, and only if the host's push allow-list admits them. Returns
    /// `delivered` or `queued`.
    pub fn push_to_caller(&self, subject: String, body: String) -> Result<String, WiresError> {
        runtime()
            .block_on(self.call.push_to_caller(subject, body))
            .map(|outcome| outcome.as_str().to_string())
            .map_err(|e| WiresError::failed(&e))
    }
}

/// A foreign [`Service`] as a Rust [`wires::Service`]: its `call` runs on a
/// blocking thread.
struct Foreign(Arc<dyn Service>);

impl wires::Service for Foreign {
    async fn call(&self, call: wires::Call, io: wires::CallIo) -> i32 {
        let io = Arc::new(SharedIo::new(io));
        let ffi = Arc::new(Call {
            call,
            io: Arc::clone(&io),
        });
        let service = Arc::clone(&self.0);
        run_foreign(io, move || service.call(ffi)).await
    }
}

/// Run a foreign handler on a blocking thread and end its call as a CLI
/// would: an error (a raised exception) becomes exit 1 with its text on
/// stderr, and stdout and stderr are closed once it returns, even if the
/// foreign side keeps the call.
async fn run_foreign(
    io: Arc<SharedIo>,
    handler: impl FnOnce() -> Result<i32, WiresError> + Send + 'static,
) -> i32 {
    let code = match tokio::task::spawn_blocking(handler).await {
        Ok(Ok(code)) => code,
        Ok(Err(e)) => {
            let _ = io.write_stderr(format!("{e}\n").as_bytes()).await;
            1
        }
        Err(e) => {
            tracing::warn!("a foreign service's handler failed: {e}");
            -1
        }
    };
    io.close().await;
    code
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

    /// Also read `path` as `host.json` (CLI services beside the foreign
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
            .ok_or_else(|| WiresError::msg("this builder was already built"))?;
        let host = builder.build().map_err(|e| WiresError::failed(&e))?;
        let (stop, stopped) = tokio::sync::oneshot::channel();
        Ok(Arc::new(Host {
            node_id: host.node_id().hex(),
            host: Mutex::new(Some((host, stopped))),
            stop: Mutex::new(Some(stop)),
        }))
    }
}

/// A wires host in this process, ready to serve.
#[derive(uniffi::Object)]
pub struct Host {
    node_id: String,
    /// The host and its stop signal, until it serves.
    host: Mutex<Option<(wires::Host, tokio::sync::oneshot::Receiver<()>)>>,
    /// Sends the stop signal, once.
    stop: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

#[uniffi::export]
impl Host {
    /// This host's node id: what the admin names in `wires service add
    /// --host`.
    pub fn node_id(&self) -> String {
        self.node_id.clone()
    }

    /// Serve, blocking, until [`stop`](Self::stop) is called (from another
    /// thread, or a signal handler), then close the host's endpoint and
    /// return. With `handle_ctrl_c`, Ctrl-C (SIGINT) stops it too; that
    /// claims the signal for the whole process, so it is off unless asked.
    /// Errors before serving if the signed policy doesn't assign every
    /// service to this host. A host serves once.
    #[uniffi::method(default(handle_ctrl_c = false))]
    pub fn serve(&self, handle_ctrl_c: bool) -> Result<(), WiresError> {
        let (host, stopped) = self
            .host
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| WiresError::msg("this host has already served"))?;
        runtime()
            .block_on(host.serve_until(async move {
                if handle_ctrl_c {
                    tokio::select! {
                        _ = stopped => {}
                        _ = tokio::signal::ctrl_c() => {}
                    }
                } else {
                    let _ = stopped.await;
                }
            }))
            .map_err(|e| WiresError::failed(&e))
    }

    /// Make [`serve`](Self::serve) return (at once, if it hasn't started).
    /// Safe from any thread; does nothing the second time.
    pub fn stop(&self) {
        if let Some(tx) = self.stop.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = tx.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// Shared stdio whose stdin holds `input`, and the caller's ends of its
    /// stdout and stderr.
    fn stdio(
        input: &[u8],
    ) -> (
        Arc<SharedIo>,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    ) {
        let (mut in_w, in_r) = tokio::io::duplex(64 * 1024);
        let (out_w, out_r) = tokio::io::duplex(64 * 1024);
        let (err_w, err_r) = tokio::io::duplex(64 * 1024);
        let input = input.to_vec();
        tokio::spawn(async move { in_w.write_all(&input).await });
        let io = SharedIo::new(wires::CallIo {
            stdin: Box::new(in_r),
            stdout: Box::new(out_w),
            stderr: Box::new(err_w),
        });
        (Arc::new(io), out_r, err_r)
    }

    /// Everything left on `r`.
    async fn drain(mut r: tokio::io::DuplexStream) -> String {
        let mut all = String::new();
        r.read_to_string(&mut all).await.unwrap();
        all
    }

    /// A raised exception is a CLI's uncaught exception: exit 1, its text
    /// on the caller's stderr.
    #[tokio::test]
    async fn a_raising_handler_exits_1_with_its_message_on_stderr() {
        let (io, out, err) = stdio(b"");
        let code = run_foreign(Arc::clone(&io), || Err(WiresError::msg("KeyError: 'x'"))).await;
        assert_eq!(code, 1);
        assert_eq!(drain(out).await, "");
        assert_eq!(drain(err).await, "KeyError: 'x'\n");
    }

    /// The handler's stdio works on its thread, and is closed once it
    /// returns even though the foreign side kept a reference.
    #[tokio::test]
    async fn stdio_is_closed_after_the_handler_returns() {
        let (io, out, err) = stdio(b"in");
        let kept = Arc::new(Mutex::new(None));
        let (handed, keep) = (Arc::clone(&io), Arc::clone(&kept));
        let code = run_foreign(Arc::clone(&io), move || {
            let rt = tokio::runtime::Handle::current();
            let mut input = Vec::new();
            rt.block_on(handed.read_to_end(&mut input)).unwrap();
            rt.block_on(handed.write_stdout(&input.to_ascii_uppercase()))
                .unwrap();
            *keep.lock().unwrap() = Some(handed);
            Ok(0)
        })
        .await;
        assert_eq!(code, 0);
        assert_eq!(
            (drain(out).await, drain(err).await),
            ("IN".into(), "".into())
        );
        let late = kept.lock().unwrap().take().unwrap();
        let e = late.write_stdout(b"late").await.unwrap_err();
        assert_eq!(e.to_string(), "the call has finished");
    }

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

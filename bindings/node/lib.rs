//! `wires-node`: wires-native services from Node.js and TypeScript, through
//! [napi-rs](https://napi.rs). The package is `wires`;
//! its `index.d.ts` is generated from this file.
//!
//! The surface is the Rust embedding API ([`wires::Host`],
//! [`wires::Service`]) in JavaScript's idiom: a service is an `async`
//! function of a [`Call`] that returns the exit code, it runs on Node's own
//! event loop, and every stdio method returns a Promise.
//!
//! ```ts
//! import { HostBuilder, type Call } from "wires";
//!
//! const host = new HostBuilder("/var/lib/shout/wires")
//!   .trustIssuer("https://accounts.google.com", ["…apps.googleusercontent.com"])
//!   .service("shout", async (call: Call) => {
//!     await call.writeStdout(Buffer.from((await call.readAllStdin()).toString().toUpperCase()));
//!     return 0;
//!   })
//!   .build();
//! process.on("SIGTERM", () => host.stop());
//! await host.serve(); // until stop(); serve(true) also stops on Ctrl-C
//! ```
//!
//! What a JavaScript handler differs in from a Rust one: when the caller
//! disconnects, its Promise isn't cancelled; its next read or write rejects
//! instead. A handler that throws (or rejects) ends the call with exit 1 and
//! the error's message on the caller's stderr, as an uncaught exception in a
//! CLI would. The host's node key stays in Rust memory; nothing here hands
//! it to JavaScript.

use std::sync::{Arc, Mutex};

use napi::bindgen_prelude::{Buffer, Either, Promise, This};
use napi::threadsafe_function::ThreadsafeFunction;
use napi::{Error, Result, Status};
use napi_derive::napi;
use wires::SharedIo;

/// A JavaScript service: `(call) => exitCode`, or a Promise of one.
type Handler = ThreadsafeFunction<Call, Either<i32, Promise<i32>>, Call, Status, false>;

/// How much [`Call::read_stdin`] reads at most when not told.
const READ_DEFAULT: u32 = 64 * 1024;

/// A failure, as a JavaScript `Error` with `message`.
fn failed(message: impl std::fmt::Display) -> Error {
    Error::new(Status::GenericFailure, message.to_string())
}

/// The person a caller verified as with their IdP.
#[napi(object)]
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

/// A failure of the embedding API, with its chain of causes.
fn failed_by(e: &anyhow::Error) -> Error {
    failed(format!("{e:#}"))
}

/// One admitted call: who is calling, with what, and its stdio. The stdio
/// methods reject once the handler has returned.
#[napi]
pub struct Call {
    call: wires::Call,
    io: Arc<SharedIo>,
}

#[napi]
impl Call {
    /// The caller's node id (64 hex).
    #[napi]
    pub fn caller(&self) -> String {
        self.call.caller().hex()
    }

    /// The person the caller verified as (every admitted call has one).
    #[napi]
    pub fn principal(&self) -> Principal {
        self.call.principal().into()
    }

    /// The registry role that admitted the caller.
    #[napi]
    pub fn role(&self) -> String {
        self.call.role().as_str().to_string()
    }

    /// The signed-state version the call was decided under.
    #[napi]
    pub fn state_version(&self) -> i64 {
        i64::try_from(self.call.state_version().0).unwrap_or(i64::MAX)
    }

    /// The service called.
    #[napi]
    pub fn service(&self) -> String {
        self.call.service().as_str().to_string()
    }

    /// The caller's arguments.
    #[napi]
    pub fn args(&self) -> Vec<String> {
        self.call.args().to_vec()
    }

    /// This call's id in the host's call log (what `wires watch` shows).
    #[napi]
    pub fn id(&self) -> String {
        self.call.id().hex()
    }

    /// Up to `max` bytes (default 64 KiB) of the caller's stdin; empty at
    /// EOF.
    #[napi]
    pub async fn read_stdin(&self, max: Option<u32>) -> Result<Buffer> {
        let mut buf = vec![0u8; max.unwrap_or(READ_DEFAULT).max(1) as usize];
        let n = self.io.read(&mut buf).await.map_err(|e| failed_by(&e))?;
        buf.truncate(n);
        Ok(buf.into())
    }

    /// The rest of the caller's stdin, to EOF (at most 64 MiB; stream more
    /// with `readStdin`).
    #[napi]
    pub async fn read_all_stdin(&self) -> Result<Buffer> {
        let mut all = Vec::new();
        self.io
            .read_to_end(&mut all)
            .await
            .map_err(|e| failed_by(&e))?;
        Ok(all.into())
    }

    /// Write `data` to the caller's stdout. Resolves once it's taken
    /// (waits while the caller is behind).
    #[napi]
    pub async fn write_stdout(&self, data: Buffer) -> Result<()> {
        self.io.write_stdout(&data).await.map_err(|e| failed_by(&e))
    }

    /// Write `data` to the caller's stderr.
    #[napi]
    pub async fn write_stderr(&self, data: Buffer) -> Result<()> {
        self.io.write_stderr(&data).await.map_err(|e| failed_by(&e))
    }

    /// Send the caller a message (their `wires inbox`), under this call's
    /// push capability: only to this caller, until shortly after the call
    /// ends, and only if the host's push allow-list admits them. Resolves to
    /// `delivered` or `queued`.
    #[napi]
    pub async fn push_to_caller(&self, subject: String, body: String) -> Result<String> {
        self.call
            .push_to_caller(subject, body)
            .await
            .map(|outcome| outcome.as_str().to_string())
            .map_err(|e| failed_by(&e))
    }
}

/// A JavaScript service as a Rust [`wires::Service`].
struct Node(Arc<Handler>);

impl wires::Service for Node {
    async fn call(&self, call: wires::Call, io: wires::CallIo) -> i32 {
        let stdio = Arc::new(SharedIo::new(io));
        let js = Call {
            call,
            io: Arc::clone(&stdio),
        };
        let returned = match self.0.call_async_catch(js).await {
            Ok(Either::A(code)) => Ok(code),
            Ok(Either::B(promise)) => promise.await,
            Err(e) => Err(e),
        };
        let code = match returned {
            Ok(code) => code,
            Err(e) => {
                // What an uncaught exception in a CLI does: its message on
                // stderr, exit 1.
                let _ = stdio
                    .write_stderr(format!("{}\n", e.reason).as_bytes())
                    .await;
                1
            }
        };
        stdio.close().await;
        code
    }
}

/// Collects what a `Host` implements and trusts; each method returns the
/// builder, for chaining. `build()` checks it and reads the keystore.
#[napi]
pub struct HostBuilder {
    inner: Option<wires::HostBuilder>,
}

impl HostBuilder {
    /// Apply `f` to the builder, unless it was already built.
    fn with(&mut self, f: impl FnOnce(wires::HostBuilder) -> wires::HostBuilder) {
        self.inner = self.inner.take().map(f);
    }
}

#[napi]
impl HostBuilder {
    /// Start building a host whose keystore is `home` (a node joined with
    /// `WIRES_HOME=<home> wires id` and `wires join`).
    #[napi(constructor)]
    pub fn new(home: String) -> Self {
        Self {
            inner: Some(wires::Host::builder(home)),
        }
    }

    /// Trust ID tokens from `issuer` for the OAuth client ids `audiences`.
    #[napi]
    pub fn trust_issuer<'a>(
        &mut self,
        this: This<'a>,
        issuer: String,
        audiences: Vec<String>,
    ) -> This<'a> {
        self.with(|b| b.trust_issuer(issuer, audiences));
        this
    }

    /// Let the host push to members of `roles` (what `pushToCaller` needs).
    #[napi]
    pub fn push_allow<'a>(&mut self, this: This<'a>, roles: Vec<String>) -> This<'a> {
        self.with(|b| b.push_allow(roles));
        this
    }

    /// Also read `path` as `host.json` (CLI services beside the
    /// JavaScript ones, trusted IdPs, push, audit export).
    #[napi]
    pub fn host_json<'a>(&mut self, this: This<'a>, path: String) -> This<'a> {
        self.with(|b| b.host_json(path));
        this
    }

    /// Accept direct connections only on this machine's loopback; callers
    /// elsewhere still reach the host through its relay. For local demos:
    /// the macOS firewall doesn't prompt for a loopback-only host.
    #[napi]
    pub fn bind_loopback<'a>(&mut self, this: This<'a>) -> This<'a> {
        self.with(|b| b.bind_loopback());
        this
    }

    /// Use a self-hosted relay at `url`.
    #[napi]
    pub fn relay_url<'a>(&mut self, this: This<'a>, url: String) -> This<'a> {
        self.with(|b| b.relay_url(url));
        this
    }

    /// Implement service `name` with `handler`: `(call) => exitCode`, or a
    /// Promise of one (an `async` function).
    #[napi(ts_args_type = "name: string, handler: (call: Call) => number | Promise<number>")]
    pub fn service<'a>(&mut self, this: This<'a>, name: String, handler: Handler) -> This<'a> {
        self.with(|b| b.service(name, Node(Arc::new(handler))));
        this
    }

    /// Check the configuration and load the keystore. A builder builds once.
    #[napi]
    pub fn build(&mut self) -> Result<Host> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| failed("this builder was already built"))?;
        let host = builder.build().map_err(|e| failed_by(&e))?;
        let (stop, stopped) = tokio::sync::oneshot::channel();
        Ok(Host {
            node_id: host.node_id().hex(),
            host: Mutex::new(Some((host, stopped))),
            stop: Mutex::new(Some(stop)),
        })
    }
}

/// A wires host in this process, ready to serve.
#[napi]
pub struct Host {
    node_id: String,
    /// The host and its stop signal, until it serves.
    host: Mutex<Option<(wires::Host, tokio::sync::oneshot::Receiver<()>)>>,
    /// Sends the stop signal, once.
    stop: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

#[napi]
impl Host {
    /// This host's node id: what the admin names in `wires service add
    /// --host`.
    #[napi]
    pub fn node_id(&self) -> String {
        self.node_id.clone()
    }

    /// Serve until `stop()`, then close the host's endpoint and resolve.
    /// With `handleCtrlC`, Ctrl-C (SIGINT) stops it too; that claims the
    /// signal for the whole process, so it is off unless asked (an app with
    /// its own handling calls `stop()` from `process.on("SIGINT", …)`).
    /// Rejects before serving if the signed state doesn't assign every
    /// service to this host. A host serves once.
    #[napi]
    pub async fn serve(&self, handle_ctrl_c: Option<bool>) -> Result<()> {
        let (host, stopped) = self
            .host
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| failed("this host has already served"))?;
        host.serve_until(async move {
            if handle_ctrl_c.unwrap_or(false) {
                tokio::select! {
                    _ = stopped => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            } else {
                let _ = stopped.await;
            }
        })
        .await
        .map_err(|e| failed_by(&e))
    }

    /// Make `serve()` resolve (at once, if it hasn't started). Does nothing
    /// the second time.
    #[napi]
    pub fn stop(&self) {
        if let Some(tx) = self.stop.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = tx.send(());
        }
    }
}

//! `wires-node`: wires-native services from Node.js and TypeScript (card 33,
//! phase 2), through [napi-rs](https://napi.rs). The package is `wires`;
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
//! await host.serve();
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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A JavaScript service: `(call) => exitCode`, or a Promise of one.
type Handler = ThreadsafeFunction<Call, Either<i32, Promise<i32>>, Call, Status, false>;

/// The most bytes [`Call::read_all_stdin`] gathers before it rejects, so a
/// caller can't make a handler buffer without bound. Stream larger input
/// with [`Call::read_stdin`].
const READ_ALL_MAX: u64 = 64 * 1024 * 1024;

/// How much [`Call::read_stdin`] reads at most when not told.
const READ_DEFAULT: u32 = 64 * 1024;

/// A failure, as a JavaScript `Error` with `message`.
fn failed(message: impl std::fmt::Display) -> Error {
    Error::new(Status::GenericFailure, message.to_string())
}

/// The error for stdio used after the call finished.
fn finished() -> Error {
    failed("the call has finished")
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

/// One call's stdio, shared between the handler's `Call` and the host.
struct Stdio {
    stdin: tokio::sync::Mutex<Option<Box<dyn AsyncRead + Send + Unpin>>>,
    stdout: tokio::sync::Mutex<Option<Box<dyn AsyncWrite + Send + Unpin>>>,
    stderr: tokio::sync::Mutex<Option<Box<dyn AsyncWrite + Send + Unpin>>>,
}

impl Stdio {
    /// The handler is done: close stdout and stderr (EOF to the caller),
    /// even if JavaScript still holds the `Call`.
    async fn close(&self) {
        for out in [&self.stdout, &self.stderr] {
            if let Some(mut w) = out.lock().await.take() {
                let _ = w.shutdown().await;
            }
        }
        self.stdin.lock().await.take();
    }
}

/// Write all of `data` to `out`.
async fn write(
    out: &tokio::sync::Mutex<Option<Box<dyn AsyncWrite + Send + Unpin>>>,
    data: &[u8],
) -> Result<()> {
    let mut out = out.lock().await;
    let out = out.as_mut().ok_or_else(finished)?;
    out.write_all(data).await.map_err(failed)?;
    out.flush().await.map_err(failed)
}

/// One admitted call: who is calling, with what, and its stdio. The stdio
/// methods reject once the handler has returned.
#[napi]
pub struct Call {
    call: wires::Call,
    io: Arc<Stdio>,
}

#[napi]
impl Call {
    /// The caller's node id (64 hex).
    #[napi]
    pub fn caller(&self) -> String {
        self.call.caller().hex()
    }

    /// The person the caller verified as. Every registry role names an
    /// issuer, so an admitted call has one.
    #[napi]
    pub fn principal(&self) -> Option<Principal> {
        self.call.principal().map(|p| Principal {
            issuer: p.issuer.clone(),
            subject: p.subject.clone(),
            email: p.email.clone(),
        })
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
    pub fn id(&self) -> Option<String> {
        self.call.id().map(|id| id.hex())
    }

    /// Up to `max` bytes (default 64 KiB) of the caller's stdin; empty at
    /// EOF.
    #[napi]
    pub async fn read_stdin(&self, max: Option<u32>) -> Result<Buffer> {
        let mut stdin = self.io.stdin.lock().await;
        let stdin = stdin.as_mut().ok_or_else(finished)?;
        let mut buf = vec![0u8; max.unwrap_or(READ_DEFAULT).max(1) as usize];
        let n = stdin.read(&mut buf).await.map_err(failed)?;
        buf.truncate(n);
        Ok(buf.into())
    }

    /// The rest of the caller's stdin, to EOF (at most 64 MiB; stream more
    /// with `readStdin`).
    #[napi]
    pub async fn read_all_stdin(&self) -> Result<Buffer> {
        let mut stdin = self.io.stdin.lock().await;
        let stdin = stdin.as_mut().ok_or_else(finished)?;
        let mut all = Vec::new();
        (&mut *stdin)
            .take(READ_ALL_MAX + 1)
            .read_to_end(&mut all)
            .await
            .map_err(failed)?;
        if all.len() as u64 > READ_ALL_MAX {
            return Err(failed("stdin is over 64 MiB; read it with readStdin"));
        }
        Ok(all.into())
    }

    /// Write `data` to the caller's stdout. Resolves once it's taken
    /// (waits while the caller is behind).
    #[napi]
    pub async fn write_stdout(&self, data: Buffer) -> Result<()> {
        write(&self.io.stdout, &data).await
    }

    /// Write `data` to the caller's stderr.
    #[napi]
    pub async fn write_stderr(&self, data: Buffer) -> Result<()> {
        write(&self.io.stderr, &data).await
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
            .map_err(|e| failed(format!("{e:#}")))
    }
}

/// A JavaScript service as a Rust [`wires::Service`].
struct Node(Arc<Handler>);

impl wires::Service for Node {
    async fn call(&self, call: wires::Call, io: wires::CallIo) -> i32 {
        let stdio = Arc::new(Stdio {
            stdin: tokio::sync::Mutex::new(Some(io.stdin)),
            stdout: tokio::sync::Mutex::new(Some(io.stdout)),
            stderr: tokio::sync::Mutex::new(Some(io.stderr)),
        });
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
                let text = format!("{}\n", e.reason);
                if let Some(err) = stdio.stderr.lock().await.as_mut() {
                    let _ = err.write_all(text.as_bytes()).await;
                }
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
        let host = builder.build().map_err(|e| failed(format!("{e:#}")))?;
        Ok(Host {
            node_id: host.node_id().hex(),
            host: Mutex::new(Some(host)),
            stop: Mutex::new(None),
        })
    }
}

/// A wires host in this process, ready to serve.
#[napi]
pub struct Host {
    node_id: String,
    host: Mutex<Option<wires::Host>>,
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

    /// Serve until `stop()` or Ctrl-C; resolves then. Rejects before
    /// serving if the signed state doesn't assign every service to this
    /// host. A host serves once.
    #[napi]
    pub async fn serve(&self) -> Result<()> {
        let host = self
            .host
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| failed("this host has already served"))?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        *self.stop.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        host.serve_until(async {
            tokio::select! {
                _ = rx => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        })
        .await
        .map_err(|e| failed(format!("{e:#}")))
    }

    /// Make a running `serve()` resolve. Does nothing if the host isn't
    /// serving.
    #[napi]
    pub fn stop(&self) {
        if let Some(tx) = self.stop.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = tx.send(());
        }
    }
}

//! `wires call`: run one remote CLI by name, as if it were local.
//!
//! The name is a **service** (card 27): its hosts come from the service's
//! root-signed entry in this node's view (card 37), tried in a random order
//! per call, moving on only on a dial failure ([`crate::caller::pick`]), and the
//! session opens with the [`Hello`] (the view's head version, and the ID
//! token `wires login` stored: no token, no call). A name the view doesn't
//! hold is asked of a directory (`resolve`) before the call fails; nothing
//! is dialed from an expired view, and a view older than a day is refreshed
//! first when a directory answers (with none answering, the call goes ahead
//! from the view as it is). When a host's `HelloAck` reports a newer head, it carries the
//! head and the service's entry, and the call stops there, **before** any
//! stdin is sent, unless that entry still lists the host; the caller then
//! refreshes its view after the call. On an unchanged policy, within a day
//! of the last refresh, the call is the only connection. Locked mode
//! ([`crate::caller::lock`]) refuses a call whose stdin holds data.
//!
//! The CLI-native front door. An agent runs `wires call <service> [-- args…]`
//! from its shell: stdin, stdout and stderr pass straight through, the remote
//! exit code becomes ours, and a refusal by the host exits
//! [`EXIT_DENIED`](crate::EXIT_DENIED) (77) with the reason on stderr. A
//! remote command that itself exits 77 is reported as 1, with a note
//! ([`own_exit`]), so 77 always means "refused".
//!
//! The same dialing sits behind the [`Caller`] trait, which buffers a call's
//! output into a [`CallOutcome`] for `wires mcp` — and lets the MCP server be
//! tested against a fake while the live path stays one function
//! ([`dial`]).

use std::future::Future;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use library::{
    Argv, Hello, HelloAck, IdToken, Invocation, NodeId, NodeIdentity, ServiceName, SignedEntry,
    StateVersion,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::admin::keystore::{self, Keystore};
use crate::caller::lock::{self, EXIT_LOCKED, check_process_stdin};
use crate::caller::pick::{self, Hints, Unanswered};
use crate::caller::shape::{EXIT_SHAPE, Shape, ShapeArgs, exit_code};
use crate::caller::view::{self, HeldView};
use crate::host::transport;

/// How long one host of a service gets to answer a dial before the next is
/// tried.
pub(crate) const SERVICE_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// What one remote call came to, fully buffered.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CallOutcome {
    /// The remote command ran and exited.
    Exited {
        /// The remote process's exit code.
        exit: i32,
        /// Everything it wrote to stdout.
        stdout: Vec<u8>,
        /// Everything it wrote to stderr.
        stderr: Vec<u8>,
    },
    /// The host refused the call; its stated reason, verbatim.
    Denied(String),
}

/// Something that can call a service by name and hand back its
/// [`CallOutcome`].
///
/// `Err` is reserved for local or transport failures (no keystore, dial
/// timeout, session dropped); a refusal by the host is an `Ok`
/// [`CallOutcome::Denied`], because to the caller it is an answer.
pub trait Caller {
    /// Call `service` (one in the caller's view; its host is picked at call
    /// time) with the extra `argv`, feeding it `stdin` (then EOF).
    fn call(
        &self,
        service: &ServiceName,
        argv: Argv,
        stdin: Vec<u8>,
    ) -> impl Future<Output = Result<CallOutcome>> + Send;
}

/// This node's credentials for dialing: the node key and the network's
/// root key, plus the ID token to present when it isn't the one `wires
/// login` stored (and, for `wires gateway`, a self-hosted relay). The ID
/// token is the only credential: there is nothing the admin minted for this
/// node.
#[derive(Clone)]
pub struct Credentials {
    node: Arc<NodeIdentity>,
    root: NodeId,
    relay_override: Option<String>,
    id_token: Option<IdToken>,
}

impl Credentials {
    /// The node key and the network, both from the keystore (`$WIRES_HOME`:
    /// the one way to point a caller at another key).
    pub fn resolve() -> Result<Self> {
        let ks = Keystore::resolve()?;
        let root = ks.network_root()?.context(crate::help::NOT_JOINED)?;
        Ok(Self {
            node: Arc::new(keystore::node_identity_in(&ks)?),
            root,
            relay_override: None,
            id_token: None,
        })
    }

    /// Dial through the self-hosted relay at `url` instead of n0's (`wires
    /// gateway --relay-url`; a caller's own commands take no relay).
    pub fn through_relay(mut self, url: Option<String>) -> Self {
        self.relay_override = url;
        self
    }

    /// Credentials for `node` in the network rooted at `root`, from no flags
    /// and no keystore (the tests' form).
    #[cfg(test)]
    pub(crate) fn of(node: NodeIdentity, root: NodeId) -> Self {
        Self {
            node: Arc::new(node),
            root,
            relay_override: None,
            id_token: None,
        }
    }

    /// Present `token` in the session `Hello` instead of the stored one.
    ///
    /// `wires gateway` dials for many web users from one node: each call
    /// carries the caller's own ID token, nonce-bound to this node's key, so
    /// the host verifies the IdP's signature for that user itself.
    pub fn presenting(mut self, token: IdToken) -> Self {
        self.id_token = Some(token);
        self
    }

    /// This node's id.
    pub(crate) fn node_id(&self) -> NodeId {
        self.node.node_id()
    }

    /// The [`through_relay`](Self::through_relay) relay, if any.
    pub(crate) fn relay(&self) -> Option<&str> {
        self.relay_override.as_deref()
    }

    /// The network's root key.
    pub(crate) fn root(&self) -> NodeId {
        self.root
    }

    /// The ID token to present: [`presenting`](Self::presenting)'s, else
    /// the one `wires login` stored in `ks`.
    pub(crate) fn id_token(&self, ks: &Keystore) -> Option<IdToken> {
        self.id_token
            .clone()
            .or_else(|| crate::caller::hello::stored_token(ks))
    }

    /// Bind this node's endpoint (through the
    /// [`through_relay`](Self::through_relay) relay, if any), for dialing
    /// services.
    pub(crate) async fn bind(&self) -> Result<iroh::Endpoint> {
        transport::bind(&self.node, self.relay_override.as_deref()).await
    }

    /// The ID token to present, or the error saying to sign in: with none,
    /// nothing is dialed (every host would refuse the call).
    pub(crate) fn require_token(&self, ks: &Keystore) -> Result<IdToken> {
        self.id_token(ks)
            .ok_or_else(|| anyhow!(crate::help::NOT_SIGNED_IN))
    }

    /// The session [`Hello`] to open with: `version` (the head version of
    /// the view the call is made from), and the ID token
    /// ([`require_token`](Self::require_token)).
    fn hello(&self, ks: &Keystore, version: StateVersion) -> Result<Hello> {
        Ok(Hello {
            state_version: version,
            id_token: self.require_token(ks)?,
        })
    }
}

/// The live [`Caller`]: dials over wires with this node's [`Credentials`],
/// from the view in its keystore (which `wires mcp`'s subscription keeps
/// current, so a call needs no refresh after it).
pub struct WiresCaller {
    creds: Credentials,
}

impl WiresCaller {
    /// A caller that dials with `creds`.
    pub fn new(creds: Credentials) -> Self {
        Self { creds }
    }
}

impl Caller for WiresCaller {
    /// A host's `NOT_ADMITTED` comes back as what this caller's person can
    /// act on ([`explain_not_admitted`](crate::caller::hello::explain_not_admitted)).
    async fn call(&self, service: &ServiceName, argv: Argv, stdin: Vec<u8>) -> Result<CallOutcome> {
        let outcome = self.call_as_is(service, argv, stdin).await?;
        Ok(match outcome {
            CallOutcome::Denied(reason) => CallOutcome::Denied(match Keystore::resolve() {
                Ok(ks) => crate::caller::hello::say_refusal(&ks, &reason),
                Err(_) => reason,
            }),
            other => other,
        })
    }
}

impl WiresCaller {
    /// [`Caller::call`], with the host's refusal as it said it.
    async fn call_as_is(
        &self,
        service: &ServiceName,
        argv: Argv,
        stdin: Vec<u8>,
    ) -> Result<CallOutcome> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let result = async {
            let ks = Keystore::resolve()?;
            let held = usable_view(&ks, &self.creds).await?;
            call_service(
                &self.creds,
                &ks,
                &held,
                service,
                argv,
                std::io::Cursor::new(stdin),
                &mut stdout,
                &mut stderr,
                CallOpts::default(),
            )
            .await
        }
        .await;
        outcome(result, stdout, stderr)
    }
}

/// Fold a dial result and its buffered output into a [`CallOutcome`]: a
/// [`transport::Denied`] anywhere in the error chain is an answer, not a
/// failure.
pub(crate) fn outcome(
    result: Result<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
) -> Result<CallOutcome> {
    match result {
        Ok(exit) => Ok(CallOutcome::Exited {
            exit,
            stdout,
            stderr,
        }),
        Err(e) => match e.downcast_ref::<transport::Denied>() {
            Some(d) => Ok(CallOutcome::Denied(d.reason().to_string())),
            None => Err(e),
        },
    }
}

/// This node's view to dial from ([`view::usable`]): never an expired one
/// (it would name hosts the admin may have since removed); a missing or
/// stale one ([`HeldView::is_stale`]) is refreshed from a directory first,
/// and a stale one still unexpired is used when no directory answers. So a
/// day bounds how long a host the admin removed can still be dialed only
/// while a directory answers truthfully; the hard bound is the view's
/// head's `not_after` (protocol §5).
///
/// With no ID token it fails at once and asks no directory: nothing is sent
/// for a call every host would refuse.
pub(crate) async fn usable_view(ks: &Keystore, creds: &Credentials) -> Result<HeldView> {
    creds.require_token(ks)?;
    view::usable(ks, &creds.node, creds.root, creds.relay()).await
}

/// What the caller does at a host's `HelloAck`, before any stdin: when the
/// host's head is newer than the view (`held`), require its head and the
/// service's entry to verify under `root` and the entry to still list
/// `host` ([`HelloAck::assigns`]). An error aborts the call (exit 1): the
/// host keeps the `Invoke` it already has, but gets no stdin.
fn accept_ack(
    root: NodeId,
    held: StateVersion,
    service: &ServiceName,
    host: NodeId,
    ack: &HelloAck,
) -> Result<()> {
    match ack.assigns(root, held, service, host) {
        Ok(true) => Ok(()),
        Ok(false) => bail!(
            "signed policy version {} no longer assigns `{service}` to host {}, so the call was \
             stopped before any input was sent (see `wires services`)",
            ack.state_version.0,
            host.short()
        ),
        Err(e) => Err(anyhow!(e).context(
            "the host's newer policy head or service entry does not verify; no input was sent",
        )),
    }
}

/// The exit code `wires call` reports for a remote exit code, and a note for
/// stderr when it differs: 77 is reserved for a refusal by the host, so a
/// remote command's own 77 becomes 1.
pub(crate) fn own_exit(remote: i32) -> (i32, Option<String>) {
    if remote == crate::EXIT_DENIED {
        return (
            1,
            Some(format!(
                "wires: the remote command exited {remote}; reported as 1 (exit {remote} means \
                 the host refused the call)"
            )),
        );
    }
    (remote, None)
}

/// How [`call_service`] behaves around the call itself.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CallOpts {
    /// Name the host that answered on stderr.
    pub(crate) verbose: bool,
    /// After a host reported a newer head, refresh the view from a
    /// directory (a one-shot `wires call`; a subscriber doesn't need to).
    pub(crate) refresh_after: bool,
}

/// Call `service` (card 27) from the view `held` (which must be fresh):
/// the service's entry (asked of a directory with `resolve` when the view
/// doesn't hold it), its hosts in a random order per call, moving on only on
/// a dial failure, the [`Hello`], the ack check ([`accept_ack`]), stdio, and
/// the hosts that didn't answer remembered. With [`CallOpts::refresh_after`], a newer
/// head a host reported is followed by a view refresh. A refusal is a
/// [`transport::Denied`] error.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn call_service<R, W, E>(
    creds: &Credentials,
    ks: &Keystore,
    held: &HeldView,
    service: &ServiceName,
    argv: Argv,
    stdin: R,
    stdout: W,
    stderr: E,
    opts: CallOpts,
) -> Result<i32>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let endpoint = creds.bind().await?;
    let dial = ServiceDial {
        endpoint: &endpoint,
        hints: Hints::load(ks),
        timeout: SERVICE_DIAL_TIMEOUT,
    };
    let result = call_service_with(
        creds, ks, held, service, &dial, argv, stdin, stdout, stderr, opts,
    )
    .await;
    endpoint.close().await;
    result
}

/// [`call_service`] over a given endpoint and hints.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn call_service_with<R, W, E>(
    creds: &Credentials,
    ks: &Keystore,
    held: &HeldView,
    service: &ServiceName,
    dial: &ServiceDial<'_>,
    argv: Argv,
    stdin: R,
    stdout: W,
    stderr: E,
    opts: CallOpts,
) -> Result<i32>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    creds.require_token(ks)?;
    let entry = match held.entry(service) {
        Some(e) => e.clone(),
        None => resolve_entry(creds, ks, dial.endpoint, service).await?,
    };
    let called = call_entry(
        creds,
        ks,
        held.version(),
        &entry,
        dial,
        argv,
        stdin,
        stdout,
        stderr,
        opts.verbose,
    )
    .await;
    // A refusal can mean the view is behind the host's policy (the person
    // was removed, or lost the service): have the next command refresh.
    if let Err(e) = &called
        && e.downcast_ref::<transport::Denied>().is_some()
    {
        view::note_refused(ks, creds.root);
    }
    let called = called?;
    if let Some(newer) = called.newer {
        view::note_seen(ks, creds.root(), newer);
        if opts.refresh_after {
            let asker = view::Asker {
                endpoint: dial.endpoint,
                root: creds.root,
                id_token: creds.id_token(ks),
            };
            let refreshed =
                tokio::time::timeout(view::REFRESH_BUDGET, view::refresh(ks, &asker, false)).await;
            match refreshed {
                Ok(Ok(v)) => tracing::info!(version = v.version().0, "refreshed the view"),
                Ok(Err(e)) => tracing::debug!("refreshing the view after the call: {e:#}"),
                Err(_) => tracing::debug!("refreshing the view after the call timed out"),
            }
        }
    }
    Ok(called.exit)
}

/// `service`'s entry from a directory (`resolve`), for a name the view
/// doesn't hold; an error naming what to do when there is none.
async fn resolve_entry(
    creds: &Credentials,
    ks: &Keystore,
    endpoint: &iroh::Endpoint,
    service: &ServiceName,
) -> Result<SignedEntry> {
    let asker = view::Asker {
        endpoint,
        root: creds.root,
        id_token: Some(creds.require_token(ks)?),
    };
    let found = tokio::time::timeout(view::REFRESH_BUDGET, view::resolve(ks, &asker, service))
        .await
        .unwrap_or_else(|_| Err(anyhow!("no directory answered")));
    match found {
        Ok(found) => found.ok_or_else(|| not_callable(service)),
        Err(e) => Err(e.context(format!(
            "`{service}` is not in this node's view, and no directory could be asked"
        ))),
    }
}

/// Why `wires call <service>` has nothing to dial: no service by that name
/// that this caller may call (a directory said so), and the next step.
pub(crate) fn not_callable(service: &ServiceName) -> anyhow::Error {
    anyhow!("no service named `{service}` that you may call; see `wires services`")
}

/// How [`call_entry`] reaches hosts.
pub(crate) struct ServiceDial<'a> {
    /// This node's bound endpoint (not closed here).
    pub(crate) endpoint: &'a iroh::Endpoint,
    /// Address hints for the hosts.
    pub(crate) hints: Hints,
    /// How long each host gets to answer a dial.
    pub(crate) timeout: std::time::Duration,
}

/// What [`call_entry`] came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Called {
    /// The remote exit code.
    pub(crate) exit: i32,
    /// The host's head version, when it was newer than the view's.
    pub(crate) newer: Option<StateVersion>,
}

/// One call of the service `entry` names on the hosts it lists, from a view
/// at `version`, over `dial`'s endpoint and hints: a random order per call
/// ([`pick::candidates`]), moving on only on a dial failure, the [`Hello`],
/// the ack check ([`accept_ack`]), stdio, and the hosts that didn't answer
/// remembered.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn call_entry<R, W, E>(
    creds: &Credentials,
    ks: &Keystore,
    version: StateVersion,
    entry: &SignedEntry,
    dial: &ServiceDial<'_>,
    argv: Argv,
    stdin: R,
    stdout: W,
    stderr: E,
    verbose: bool,
) -> Result<Called>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let service = &entry.name;
    let hello = creds.hello(ks, version)?;
    let unanswered = Unanswered::path(ks);
    let now = crate::clock::now_unix();
    let hosts = pick::candidates(
        &entry.service,
        &Unanswered::load(&unanswered),
        now,
        &mut rand::rng(),
    );
    if hosts.is_empty() {
        bail!("no service named `{service}` with a host; see `wires services`");
    }
    let targets = dial.hints.targets(&hosts, creds.relay_override.as_deref());
    let fabric = creds.root;
    let mut reported = StateVersion(0);
    let done = transport::call_service_on(
        dial.endpoint,
        &targets,
        dial.timeout,
        hello,
        Invocation {
            service: service.clone(),
            argv,
        },
        |host, ack| {
            reported = ack.state_version;
            accept_ack(fabric, version, service, host, ack)
        },
        stdin,
        stdout,
        stderr,
    )
    .await
    .with_context(|| format!("calling {service}"))?;
    if verbose {
        eprintln!("wires: {service} answered by host {}", done.host.short());
    }
    Unanswered::record(&unanswered, &hosts, done.host, now);
    Ok(Called {
        exit: done.dialed.exit,
        newer: (reported > version).then_some(reported),
    })
}

/// `wires call <service> [--jq F] [--head N] [--max-bytes N] [-- args…]`.
#[derive(Args)]
pub struct CallArgs {
    // Local output shaping (no shell needed). Goes before `--`, after the
    // service name (so a permission rule scoped to the service, e.g.
    // `Bash(wires call gh:*)`, still matches) or before it.
    #[command(flatten)]
    pub shape: ShapeArgs,
    /// Name the host that answered, and print every cause of an error.
    #[arg(long)]
    pub verbose: bool,
    /// The service's name, as `wires services` lists it.
    #[arg(value_name = "SERVICE")]
    pub service: String,
    /// Its arguments, after `--`; there is no shell (no pipes or globs).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

/// `wires call`: stream local stdio to the remote service; returns its exit
/// code.
///
/// With a shaping flag (`--jq`/`--head`/`--max-bytes`), the remote stdout is
/// buffered and shaped in-process before it is written; stderr still
/// streams. A filter that doesn't compile fails with [`EXIT_SHAPE`] before
/// anything is dialed.
///
/// The shaping flags are local: they are not part of the [`Invocation`], so
/// the host never sees them: it gets only `(service, argv)`.
///
/// In locked mode ([`crate::caller::lock`]), data on stdin fails with
/// [`EXIT_LOCKED`] before anything is dialed.
pub async fn call_cmd(a: CallArgs) -> Result<i32> {
    let shape = match Shape::new(&a.shape) {
        Ok(shape) => shape,
        Err(e) => {
            eprintln!("wires: {e}");
            return Ok(EXIT_SHAPE);
        }
    };
    let stdin: Box<dyn AsyncRead + Unpin + Send> = if lock::detect() {
        if let Err(e) = check_process_stdin().await {
            eprintln!("wires: {e}");
            return Ok(EXIT_LOCKED);
        }
        Box::new(tokio::io::empty())
    } else {
        Box::new(tokio::io::stdin())
    };
    let service = ServiceName::new(&a.service).map_err(|e| anyhow!("`{}`: {e}", a.service))?;
    let argv = Argv::new(a.args).context("arguments")?;
    let creds = Credentials::resolve()?;
    let ks = Keystore::resolve()?;
    let held = usable_view(&ks, &creds).await?;
    let run = async |stdout: &mut (dyn AsyncWrite + Unpin + Send)| {
        call_service(
            &creds,
            &ks,
            &held,
            &service,
            argv,
            stdin,
            stdout,
            tokio::io::stderr(),
            CallOpts {
                verbose: a.verbose,
                refresh_after: true,
            },
        )
        .await
    };
    let report = |remote: i32| {
        let (code, note) = own_exit(remote);
        if let Some(note) = note {
            eprintln!("{note}");
        }
        code
    };
    if shape.is_identity() {
        return Ok(report(run(&mut tokio::io::stdout()).await?));
    }
    let mut stdout = Vec::new();
    let remote = report(run(&mut stdout).await?);
    write_shaped(
        &shape,
        remote,
        &stdout,
        tokio::io::stdout(),
        tokio::io::stderr(),
    )
    .await
}

/// Shape a finished call's `stdout`, write it to `out` and any notes to
/// `err`, and return the exit code: the remote one, unless that was 0 and
/// shaping failed ([`EXIT_SHAPE`]).
pub async fn write_shaped<W, E>(
    shape: &Shape,
    remote: i32,
    stdout: &[u8],
    mut out: W,
    mut err: E,
) -> Result<i32>
where
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let shaped = shape.apply(stdout);
    out.write_all(&shaped.stdout).await?;
    out.flush().await?;
    for note in shaped.stderr_lines() {
        err.write_all(format!("{note}\n").as_bytes()).await?;
    }
    err.flush().await?;
    Ok(exit_code(remote, &shaped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use library::SignedPolicy;
    use std::net::SocketAddr;

    #[test]
    fn denied_is_an_outcome_and_other_errors_stay_errors() {
        let denied =
            anyhow::Error::new(transport::Denied::new("not admitted".into())).context("dialing");
        assert_eq!(
            outcome(Err(denied), vec![], vec![]).unwrap(),
            CallOutcome::Denied("not admitted".into())
        );
        assert!(outcome(Err(anyhow!("timeout")), vec![], vec![]).is_err());
        assert_eq!(
            outcome(Ok(3), b"o".to_vec(), b"e".to_vec()).unwrap(),
            CallOutcome::Exited {
                exit: 3,
                stdout: b"o".to_vec(),
                stderr: b"e".to_vec()
            }
        );
    }

    /// A stand-in CLI so `CallArgs` parsing can be tested on its own.
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        call: CallArgs,
    }

    fn parse(argv: &[&str]) -> CallArgs {
        Cli::try_parse_from(std::iter::once("call").chain(argv.iter().copied()))
            .unwrap()
            .call
    }

    #[test]
    fn shaping_flags_go_before_the_service_and_after_it_belong_to_it() {
        let a = parse(&[
            "--jq",
            ".[].name",
            "--head",
            "3",
            "--max-bytes",
            "100",
            "gh",
            "--",
            "api",
            "x",
        ]);
        assert_eq!(a.shape.jq.as_deref(), Some(".[].name"));
        assert_eq!((a.shape.head, a.shape.max_bytes), (Some(3), Some(100)));
        assert_eq!(a.args, ["api", "x"]);
        // Right after the service name, before `--`, they are still ours — so
        // a permission rule scoped to one service (`Bash(wires call gh:*)`) still
        // matches a shaped call.
        let a = parse(&["gh", "--jq", ".[].name", "--head", "3", "--", "api", "x"]);
        assert_eq!(a.service, "gh");
        assert_eq!(a.shape.jq.as_deref(), Some(".[].name"));
        assert_eq!(a.shape.head, Some(3));
        assert_eq!(a.args, ["api", "x"]);
        // After `--`, or once the service's own arguments have begun, `--jq` is
        // the remote command's flag (gh's).
        let a = parse(&["gh", "--", "api", "x", "--jq", ".name"]);
        assert_eq!(a.shape, ShapeArgs::default());
        assert_eq!(a.args, ["api", "x", "--jq", ".name"]);
        let a = parse(&["gh", "api", "x", "--jq", ".name"]);
        assert_eq!(a.shape, ShapeArgs::default());
        assert_eq!(a.args, ["api", "x", "--jq", ".name"]);
    }

    fn shape(jq: Option<&str>, head: Option<usize>, max_bytes: Option<usize>) -> Shape {
        Shape::new(&ShapeArgs {
            jq: jq.map(str::to_owned),
            head,
            max_bytes,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn write_shaped_filters_stdout_and_notes_on_stderr() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = write_shaped(
            &shape(Some(".[].n"), None, Some(3)),
            0,
            br#"[{"n":"abc"},{"n":"def"}]"#,
            &mut out,
            &mut err,
        )
        .await
        .unwrap();
        assert_eq!(code, 0);
        assert_eq!(out, b"abc");
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "wires: stdout truncated to 3 of 8 bytes (--max-bytes 3)\n"
        );
    }

    #[tokio::test]
    async fn write_shaped_never_masks_a_remote_failure() {
        let jq = shape(Some(".a"), None, None);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = write_shaped(&jq, 4, b"gh: Not Found", &mut out, &mut err)
            .await
            .unwrap();
        assert_eq!(code, 4, "the remote exit code wins");
        assert!(String::from_utf8(err).unwrap().contains("not JSON"));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = write_shaped(&jq, 0, b"not json", &mut out, &mut err)
            .await
            .unwrap();
        assert_eq!(code, EXIT_SHAPE);
    }

    /// End to end over a real loopback host: the remote stdout is shaped
    /// after it arrives, and the remote exit code passes through.
    #[tokio::test]
    async fn shaping_over_a_loopback_host() {
        use crate::host::config::HostConfig;
        use crate::host::transport::endpoint_addr;
        use library::{Policy, Service};

        let root = NodeIdentity::from_seed([70; 32]);
        let server = NodeIdentity::from_seed([71; 32]);
        let client = NodeIdentity::from_seed([72; 32]);
        let mut s = Policy::new(root.node_id());
        s.version = StateVersion(1);
        s.issued = 1;
        s.not_after = i64::MAX;
        let (staff, matchers) = crate::testutil::staff_role();
        s.roles.insert(staff.clone(), matchers);
        for name in ["json", "fail"] {
            s.services.insert(
                ServiceName::new(name).unwrap(),
                Service {
                    description: String::new(),
                    allow: vec![staff.clone()],
                    hosts: vec![server.node_id()],
                },
            );
        }
        let home = crate::testutil::temp_dir();
        let ks = Keystore::at(&home);
        crate::policy::store::adopt_if_newer(
            &ks,
            &crate::testutil::signed_policy(&root, s),
            root.node_id(),
            10,
        )
        .unwrap();
        let config = HostConfig::parse(&format!(
            r#"{{"version":2,"identity":{},"services":{{
                "json":{{"command":["sh","-c","printf '{{\"items\":[{{\"name\":\"é-one\"}},{{\"name\":\"two\"}},{{\"name\":\"three\"}}]}}'"]}},
                "fail":{{"command":["sh","-c","echo 'HTTP 404'; exit 3"]}}}}}}"#,
            crate::testutil::test_identity_json()
        ))
        .unwrap();
        let host = crate::host::serve::services_host(
            server.node_id(),
            root.node_id(),
            std::sync::Arc::new(ks),
            config,
        )
        .unwrap();
        let server_ep = test_endpoint(&server).await;
        let target = endpoint_addr(&server.node_id(), &[loopback(&server_ep)], None).unwrap();
        let _router =
            crate::host::serve::services_router(server_ep, std::sync::Arc::new(host), None, None);
        let client_ep = test_endpoint(&client).await;

        let run = async |name: &str, shape: Shape| {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let remote = transport::call_service_on(
                &client_ep,
                std::slice::from_ref(&target),
                SERVICE_DIAL_TIMEOUT,
                Hello {
                    state_version: StateVersion(1),
                    id_token: crate::testutil::test_id_token(&client.node_id()),
                },
                Invocation {
                    service: ServiceName::new(name).unwrap(),
                    argv: Argv::default(),
                },
                |_, _| Ok(()),
                std::io::Cursor::new(Vec::new()),
                &mut stdout,
                &mut stderr,
            )
            .await
            .unwrap()
            .dialed
            .exit;
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let code = write_shaped(&shape, remote, &stdout, &mut out, &mut err)
                .await
                .unwrap();
            (
                code,
                String::from_utf8(out).unwrap(),
                String::from_utf8(err).unwrap(),
            )
        };

        let (code, out, err) = run("json", shape(Some(".items[].name"), Some(2), None)).await;
        assert_eq!((code, out.as_str(), err.as_str()), (0, "é-one\ntwo\n", ""));
        // `é` is 2 bytes: a 1-byte cap backs off to 0 rather than emit half
        // a character.
        let (code, out, err) = run("json", shape(Some(".items[0].name"), None, Some(1))).await;
        assert_eq!((code, out.as_str()), (0, ""));
        assert!(err.contains("truncated to 0 of"), "{err}");
        let (code, out, err) = run("fail", shape(Some(".x"), None, None)).await;
        assert_eq!(code, 3, "remote exit code passes through: {err}");
        assert_eq!(out, "");
        assert!(err.contains("HTTP 404"), "{err}");
    }

    #[test]
    fn args_pass_through_with_or_without_a_separator() {
        let a = parse(&["rg", "foo", "bar"]);
        assert_eq!(
            (a.service.as_str(), a.args),
            ("rg", vec!["foo".into(), "bar".into()])
        );
        let a = parse(&["rg", "--", "-n", "--x", "foo"]);
        assert_eq!(a.args, ["-n", "--x", "foo"]);
        // A flag `wires call` doesn't take, after the service name, is the
        // service's own argument.
        let a = parse(&["rg", "--relay-url", "x"]);
        assert_eq!(a.args, ["--relay-url", "x"]);
        assert!(parse(&["rg"]).args.is_empty());
    }

    /// The dial side against a minimal in-test acceptor (the host's accept
    /// side has its own tests): what a host answers a `Hello` with.
    #[derive(Clone)]
    #[allow(clippy::large_enum_variant)]
    enum Answer {
        /// `HelloAck` at `policy`'s version (with its head and the service's
        /// entry when the caller's view is older), then `out` on stdout and
        /// exit 0. `None`: the caller's own version, nothing new.
        Run {
            out: &'static str,
            policy: Option<SignedPolicy>,
        },
        /// `Denied`.
        Deny(&'static str),
        /// `HelloAck` (as `Run`), then every `Stdin` byte into `got` until
        /// EOF, then exit 0.
        Echo {
            policy: SignedPolicy,
            got: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        },
    }

    type Seen = std::sync::Arc<std::sync::Mutex<Vec<library::Hello>>>;

    /// The ack a host holding `policy` gives a caller at `caller_version`.
    fn ack_for(policy: Option<&SignedPolicy>, caller_version: StateVersion) -> library::HelloAck {
        let Some(policy) = policy else {
            return library::HelloAck {
                state_version: caller_version,
                head: None,
                entry: None,
            };
        };
        let news = policy.version() > caller_version;
        library::HelloAck {
            state_version: policy.version(),
            head: news.then(|| policy.head.clone()),
            entry: news
                .then(|| {
                    policy
                        .entries()
                        .find(|e| e.name.as_str() == "orders-db")
                        .cloned()
                })
                .flatten(),
        }
    }

    /// A loopback host speaking just enough of the session protocol: it
    /// records each `Hello` it receives and answers per `answer`.
    async fn fake_host(me: &NodeIdentity, answer: Answer) -> (NodeId, SocketAddr, Seen) {
        use library::{Chunk, Frame};
        let seen: Seen = Default::default();
        let ep = test_endpoint(me).await;
        let addr = loopback(&ep);
        let log = seen.clone();
        tokio::spawn(async move {
            while let Some(incoming) = ep.accept().await {
                let Ok(conn) = incoming.await else { continue };
                let Ok((mut send, mut recv)) = conn.accept_bi().await else {
                    continue;
                };
                let Ok(Some(Frame::Hello(hello))) = transport::read_frame(&mut recv).await else {
                    continue;
                };
                let _invoke = transport::read_frame(&mut recv).await;
                let caller_version = hello.state_version;
                log.lock().unwrap().push(hello);
                match &answer {
                    Answer::Deny(reason) => {
                        let denied = Frame::Denied {
                            reason: reason.to_string(),
                        };
                        let _ = transport::write_frame(&mut send, &denied).await;
                    }
                    Answer::Run { out, policy } => {
                        let ack = ack_for(policy.as_ref(), caller_version);
                        let _ = transport::write_frame(&mut send, &Frame::HelloAck(ack)).await;
                        let chunk = Chunk::from_bytes(out.as_bytes().to_vec());
                        let _ = transport::write_frame(&mut send, &Frame::Stdout(chunk)).await;
                        let _ = transport::write_frame(&mut send, &Frame::Exit(0)).await;
                    }
                    Answer::Echo { policy, got } => {
                        let ack = ack_for(Some(policy), caller_version);
                        let _ = transport::write_frame(&mut send, &Frame::HelloAck(ack)).await;
                        while let Ok(Some(Frame::Stdin(chunk))) =
                            transport::read_frame(&mut recv).await
                        {
                            got.lock().unwrap().extend_from_slice(chunk.as_bytes());
                        }
                        let _ = transport::write_frame(&mut send, &Frame::Exit(0)).await;
                    }
                }
                let _ = send.finish();
                let _ =
                    tokio::time::timeout(std::time::Duration::from_secs(2), conn.closed()).await;
            }
        });
        (me.node_id(), addr, seen)
    }

    async fn test_endpoint(id: &NodeIdentity) -> iroh::Endpoint {
        iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(transport::secret_key(id))
            .alpns(vec![transport::ALPN.to_vec()])
            .bind()
            .await
            .unwrap()
    }

    fn loopback(ep: &iroh::Endpoint) -> SocketAddr {
        ep.bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv4)
            .map(|s| SocketAddr::from(([127, 0, 0, 1], s.port())))
            .unwrap()
    }

    /// The fake IdP's issuer the test policies trust.
    const IDP: &str = "https://idp.example";

    /// Whom the stored token ("h.p.s") stands for, as a directory would
    /// verify it: anyone at [`IDP`].
    fn me() -> library::Principal {
        library::Principal {
            issuer: IDP.into(),
            subject: "1".into(),
            email: Some("me@example.com".into()),
            org: None,
            groups: vec![],
            not_after: i64::MAX,
        }
    }

    /// A signed policy at `version` in which `hosts` implement `orders-db`,
    /// listing `directories`.
    fn signed_listing(
        root: &NodeIdentity,
        version: u64,
        hosts: &[NodeId],
        directories: &[NodeId],
    ) -> SignedPolicy {
        use library::{Matcher, Policy, RoleName, Service};
        let mut s = Policy::new(root.node_id());
        s.version = StateVersion(version);
        s.issued = 1;
        s.not_after = i64::MAX;
        s.directories = directories.to_vec();
        let staff = RoleName::new("staff").unwrap();
        s.roles.insert(staff.clone(), vec![Matcher::new(IDP)]);
        s.services.insert(
            ServiceName::new("orders-db").unwrap(),
            Service {
                description: "Read-only SQL".into(),
                allow: vec![staff],
                hosts: hosts.to_vec(),
            },
        );
        crate::testutil::signed_policy(root, s)
    }

    /// [`signed_listing`] with no directory.
    fn signed_at(root: &NodeIdentity, version: u64, hosts: &[NodeId]) -> SignedPolicy {
        signed_listing(root, version, hosts, &[])
    }

    /// `signed`'s view for [`me`], as this node holds it (and stored).
    fn held(f: &Fixture, signed: &SignedPolicy) -> HeldView {
        let held = HeldView::fetched(
            signed.view_for(crate::testutil::any_node(), Some(&me()), None),
            None,
            10,
        );
        view::write(&f.ks, f.root.node_id(), &held).unwrap();
        held
    }

    struct Fixture {
        root: NodeIdentity,
        creds: Credentials,
        ks: Keystore,
    }

    fn fixture() -> Fixture {
        let root = NodeIdentity::from_seed([80; 32]);
        let me = NodeIdentity::from_seed([81; 32]);
        let ks = Keystore::at(crate::testutil::temp_dir());
        std::fs::write(ks.path(crate::caller::login::ID_TOKEN_FILE), "h.p.s\n").unwrap();
        Fixture {
            creds: Credentials {
                node: Arc::new(me),
                root: root.node_id(),
                relay_override: None,
                id_token: None,
            },
            root,
            ks,
        }
    }

    /// With no ID token, a call asks no directory for a view (protocol.md
    /// §5: nothing is sent): it says to sign in first.
    #[tokio::test]
    async fn a_call_without_a_sign_in_asks_no_directory() {
        let root = NodeIdentity::from_seed([82; 32]);
        let ks = Keystore::at(crate::testutil::temp_dir());
        let directory = NodeIdentity::from_seed([83; 32]).node_id();
        crate::testutil::join(&ks, &root, &[directory]);
        let creds = Credentials::of(NodeIdentity::from_seed([84; 32]), root.node_id());
        let e = tokio::time::timeout(std::time::Duration::from_secs(2), usable_view(&ks, &creds))
            .await
            .expect("it dialed nothing, so it answers at once")
            .unwrap_err();
        assert_eq!(e.to_string(), crate::help::NOT_SIGNED_IN);
    }

    async fn run_service(f: &Fixture, held: &HeldView, hints: Hints) -> (Result<i32>, String) {
        run_service_with_stdin(f, held, hints, Vec::new()).await
    }

    async fn run_service_with_stdin(
        f: &Fixture,
        held: &HeldView,
        hints: Hints,
        stdin: Vec<u8>,
    ) -> (Result<i32>, String) {
        let endpoint = test_endpoint(&f.creds.node).await;
        let dial = ServiceDial {
            endpoint: &endpoint,
            hints,
            timeout: std::time::Duration::from_millis(700),
        };
        let mut stdout = Vec::new();
        let r = call_service_with(
            &f.creds,
            &f.ks,
            held,
            &ServiceName::new("orders-db").unwrap(),
            &dial,
            Argv::default(),
            std::io::Cursor::new(stdin),
            &mut stdout,
            Vec::new(),
            CallOpts::default(),
        )
        .await;
        endpoint.close().await;
        (r, String::from_utf8(stdout).unwrap())
    }

    /// Host A is down, host B answers: whichever the random order tries
    /// first, the call reaches B, presents a `Hello` with this node's view
    /// version and stored token, and notes the newer head B reports (the next
    /// `wires services` refreshes); once A has been tried it is remembered as
    /// unanswered (so it goes last for a while) and B is not.
    #[tokio::test]
    async fn a_service_call_fails_over_and_notes_the_hosts_newer_head() {
        let f = fixture();
        let down = NodeIdentity::from_seed([82; 32]).node_id();
        let b = NodeIdentity::from_seed([83; 32]);
        let v1 = signed_at(&f.root, 1, &[down, b.node_id()]);
        let v2 = signed_at(&f.root, 2, &[down, b.node_id()]);
        let held_v1 = held(&f, &v1);
        let answer = Answer::Run {
            out: "42\n",
            policy: Some(v2),
        };
        let (b_id, b_addr, seen) = fake_host(&b, answer).await;
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let hints = Hints::from_pairs([(down, vec![dead]), (b_id, vec![b_addr])]);

        let (r, out) = run_service(&f, &held_v1, hints.clone()).await;
        assert_eq!(r.unwrap(), 0);
        assert_eq!(out, "42\n");
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].state_version, StateVersion(1));
            assert_eq!(seen[0].id_token, library::IdToken::new("h.p.s"));
        }
        let stored = view::read(&f.ks, f.root.node_id()).unwrap().unwrap();
        assert_eq!(stored.version(), StateVersion(1), "a view isn't a policy");
        assert_eq!(stored.seen, StateVersion(2));
        assert!(stored.is_stale(10), "the next `wires services` refreshes");
        // Call until the random order has tried A first (one in two).
        let path = Unanswered::path(&f.ks);
        let tried_a = || {
            Unanswered::load(&path)
                .failed_recently(down, crate::clock::now_unix())
                .is_some()
        };
        let mut calls = 1;
        while !tried_a() {
            assert!(calls < 40, "the order never put A first");
            let (r, _) = run_service(&f, &stored, hints.clone()).await;
            assert_eq!(r.unwrap(), 0);
            calls += 1;
        }
        assert_eq!(seen.lock().unwrap().len(), calls, "B answered every call");
        let now = crate::clock::now_unix();
        assert_eq!(Unanswered::load(&path).failed_recently(b_id, now), None);
    }

    /// A refusal is final: no failover to the next host, and it surfaces as
    /// `Denied` (exit 77 in `wires call`). Both hosts refuse, each in its
    /// own words: whichever the random order tried first is the only one
    /// asked, and its reason is the one surfaced.
    #[tokio::test]
    async fn a_refusal_does_not_fail_over() {
        let f = fixture();
        let a = NodeIdentity::from_seed([84; 32]);
        let b = NodeIdentity::from_seed([85; 32]);
        let state = held(&f, &signed_at(&f.root, 1, &[a.node_id(), b.node_id()]));
        let (a_id, a_addr, a_seen) = fake_host(&a, Answer::Deny("a: not in role analyst")).await;
        let (b_id, b_addr, b_seen) = fake_host(&b, Answer::Deny("b: not in role analyst")).await;
        let hints = Hints::from_pairs([(a_id, vec![a_addr]), (b_id, vec![b_addr])]);
        let (r, out) = run_service(&f, &state, hints).await;
        let err = r.unwrap_err();
        let denied = err.downcast_ref::<transport::Denied>().expect("a Denied");
        assert_eq!(out, "");
        let (a_n, b_n) = (a_seen.lock().unwrap().len(), b_seen.lock().unwrap().len());
        assert_eq!(a_n + b_n, 1, "no failover after a refusal");
        let asked = if a_n == 1 { "a" } else { "b" };
        assert_eq!(denied.reason(), format!("{asked}: not in role analyst"));
        // The view may be behind the host's policy (a removal, a lost
        // grant): the next `wires services` or `wires call` refreshes it.
        let after = view::read(&f.ks, f.root.node_id()).unwrap().unwrap();
        assert!(after.is_stale(crate::clock::now_unix()));
    }

    /// Every host down: one error naming each.
    #[tokio::test]
    async fn no_host_answering_is_an_error_naming_them() {
        let f = fixture();
        let a = NodeIdentity::from_seed([86; 32]).node_id();
        let state = held(&f, &signed_at(&f.root, 1, &[a]));
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let (r, _) = run_service(&f, &state, Hints::from_pairs([(a, vec![dead])])).await;
        let err = format!("{:#}", r.unwrap_err());
        assert!(err.contains("no host answered"), "{err}");
        assert!(err.contains(&a.short()), "{err}");
    }

    /// Card 28 §8: an expired view is never dialed from.
    #[test]
    fn an_expired_view_refuses_to_dial() {
        let f = fixture();
        let mut p = signed_at(&f.root, 1, &[NodeIdentity::from_seed([87; 32]).node_id()])
            .to_policy()
            .unwrap();
        p.not_after = 1;
        let expired = crate::testutil::signed_policy(&f.root, p);
        let held = HeldView::fetched(
            expired.view_for(crate::testutil::any_node(), Some(&me()), None),
            None,
            0,
        );
        let err = format!("{:#}", view::check_fresh(&held, 10).unwrap_err());
        assert!(
            err.contains("expired") && err.contains("wires policy push"),
            "{err}"
        );
        assert!(view::check_fresh(&held, 1).is_ok());
    }

    /// Card 37 (was card 28 §8): the host's newer head and entry are checked
    /// at the ack, and when the entry no longer lists that host the call
    /// stops there, before any stdin, as a failure (not a refusal).
    #[tokio::test]
    async fn a_newer_head_dropping_the_host_aborts_before_stdin() {
        let f = fixture();
        let h = NodeIdentity::from_seed([88; 32]);
        let other = NodeIdentity::from_seed([89; 32]).node_id();
        let v1 = signed_at(&f.root, 1, &[h.node_id()]);
        let v2 = signed_at(&f.root, 2, &[other]);
        let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let answer = Answer::Echo {
            policy: v2,
            got: got.clone(),
        };
        let (h_id, h_addr, _) = fake_host(&h, answer).await;
        let hints = Hints::from_pairs([(h_id, vec![h_addr])]);
        let (r, out) = run_service_with_stdin(&f, &held(&f, &v1), hints, b"secret".to_vec()).await;
        let err = r.unwrap_err();
        assert!(
            err.downcast_ref::<transport::Denied>().is_none(),
            "exit 1, not 77"
        );
        let err = format!("{err:#}");
        assert!(err.contains("no longer assigns"), "{err}");
        assert_eq!(out, "");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(got.lock().unwrap().is_empty(), "no stdin reached the host");

        // A forged entry that lists the host: refused the same way.
        let f = fixture();
        let mut forged = signed_at(&f.root, 2, &[other]);
        if let Some(library::Item::Service(e)) = forged
            .items
            .iter_mut()
            .find(|i| matches!(i, library::Item::Service(_)))
        {
            e.service.hosts = vec![h.node_id()];
        }
        let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let answer = Answer::Echo {
            policy: forged,
            got: got.clone(),
        };
        let (h_id, h_addr, _) = fake_host(&h, answer).await;
        let hints = Hints::from_pairs([(h_id, vec![h_addr])]);
        let (r, _) = run_service_with_stdin(&f, &held(&f, &v1), hints, b"secret".to_vec()).await;
        let err = format!("{:#}", r.unwrap_err());
        assert!(err.contains("does not verify"), "{err}");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(got.lock().unwrap().is_empty(), "no stdin reached the host");

        // Control: a newer head that still assigns the host lets stdin through.
        let f = fixture();
        let v2 = signed_at(&f.root, 2, &[h.node_id()]);
        let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let answer = Answer::Echo {
            policy: v2,
            got: got.clone(),
        };
        let (h_id, h_addr, _) = fake_host(&h, answer).await;
        let hints = Hints::from_pairs([(h_id, vec![h_addr])]);
        let (r, _) = run_service_with_stdin(&f, &held(&f, &v1), hints, b"secret".to_vec()).await;
        assert_eq!(r.unwrap(), 0);
        assert_eq!(got.lock().unwrap().as_slice(), b"secret");
    }

    /// Counts every connection on the directory ALPN, and closes it.
    #[derive(Debug, Clone, Default)]
    struct Counter(Arc<std::sync::atomic::AtomicUsize>);

    impl iroh::protocol::ProtocolHandler for Counter {
        async fn accept(
            &self,
            conn: iroh::endpoint::Connection,
        ) -> Result<(), iroh::protocol::AcceptError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            conn.close(0u32.into(), b"counted");
            Ok(())
        }
    }

    /// Card 37: `wires call` on an unchanged policy makes no connection but
    /// the call itself: the directory its view lists hears nothing. When
    /// the host reports a newer head, the caller asks a directory after the
    /// call (and only then).
    #[tokio::test]
    async fn a_call_on_an_unchanged_policy_dials_only_the_host() {
        use std::sync::atomic::Ordering;
        let f = fixture();
        // A directory that counts every request.
        let dir_node = NodeIdentity::from_seed([94; 32]);
        let dir_ep = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(transport::secret_key(&dir_node))
            .bind()
            .await
            .unwrap();
        let asked = Counter::default();
        let _dir_router = iroh::protocol::Router::builder(dir_ep.clone())
            .accept(library::DIRECTORY_ALPN, asked.clone())
            .spawn();
        let h = NodeIdentity::from_seed([95; 32]);
        let v1 = signed_listing(&f.root, 1, &[h.node_id()], &[dir_node.node_id()]);
        let v2 = signed_listing(&f.root, 2, &[h.node_id()], &[dir_node.node_id()]);
        let held_v1 = held(&f, &v1);
        // The caller finds the directory by its key (the hints file does
        // this in production).
        let book = iroh::address_lookup::memory::MemoryLookup::new();
        book.add_endpoint_info(
            transport::endpoint_addr(&dir_node.node_id(), &[loopback(&dir_ep)], None).unwrap(),
        );
        // A fresh endpoint per call, so no path to the last fake host lingers.
        let call = async |answer: Answer| {
            let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .secret_key(transport::secret_key(&f.creds.node))
                .address_lookup(book.clone())
                .bind()
                .await
                .unwrap();
            let (h_id, h_addr, _) = fake_host(&h, answer).await;
            let dial = ServiceDial {
                endpoint: &endpoint,
                hints: Hints::from_pairs([(h_id, vec![h_addr])]),
                timeout: std::time::Duration::from_secs(2),
            };
            let code = call_service_with(
                &f.creds,
                &f.ks,
                &held_v1,
                &ServiceName::new("orders-db").unwrap(),
                &dial,
                Argv::default(),
                std::io::Cursor::new(Vec::new()),
                Vec::new(),
                Vec::new(),
                CallOpts {
                    verbose: false,
                    refresh_after: true,
                },
            )
            .await
            .unwrap();
            endpoint.close().await;
            code
        };
        let unchanged = Answer::Run {
            out: "ok\n",
            policy: Some(v1.clone()),
        };
        assert_eq!(call(unchanged).await, 0);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(asked.0.load(Ordering::SeqCst), 0, "no directory was asked");

        let changed = Answer::Run {
            out: "ok\n",
            policy: Some(v2),
        };
        assert_eq!(call(changed).await, 0);
        assert!(
            asked.0.load(Ordering::SeqCst) >= 1,
            "a newer head: the view is refreshed after the call"
        );
    }

    /// Card 28 §10: a remote exit 77 is not a refusal.
    #[test]
    fn a_remote_77_is_reported_as_1() {
        assert_eq!(own_exit(0), (0, None));
        assert_eq!(own_exit(3), (3, None));
        let (code, note) = own_exit(crate::EXIT_DENIED);
        assert_eq!(code, 1);
        assert!(note.unwrap().contains("exited 77"));
    }
}

//! `wires call`: run one remote CLI by name, as if it were local.
//!
//! The name is a **service** (card 27): its hosts come from this node's
//! admin-signed policy, tried last-good first with failover on a dial failure
//! ([`crate::caller::pick`]), and the session opens with the card-27
//! [`Hello`] (membership, state version, ID token). Nothing
//! is dialed from an expired state. A newer state a host hands back in its
//! `HelloAck` is adopted **before** any stdin is sent, and the call stops
//! there if that state no longer assigns the service to that host. A
//! registered service wins over a `tools.json` alias of the same name; an
//! alias pins a name to one host (and address hints), which the current
//! state must assign the alias's service, and that host still decides by
//! its signed policy.
//! Locked mode ([`crate::caller::lock`]) refuses the override flags a
//! sandboxed agent could steer this with.
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
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use library::{
    Argv, Hello, IdToken, Invocation, Membership, NodeId, NodeIdentity, ServiceName, SignedPolicy,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::admin::keystore::{self, Keystore};
use crate::caller::lock::{EXIT_LOCKED, Lock, check_process_stdin};
use crate::caller::pick::{self, Hints, LastGood};
use crate::caller::shape::{EXIT_SHAPE, Shape, ShapeArgs, exit_code};
use crate::caller::tools::{RemoteTool, ToolTarget, ToolsConfig};
use crate::host::transport;
use crate::policy::store::{self, Held};

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

/// Something that can run a [`RemoteTool`] and hand back its [`CallOutcome`].
///
/// `Err` is reserved for local or transport failures (no keystore, dial
/// timeout, session dropped); a refusal by the host is an `Ok`
/// [`CallOutcome::Denied`], because to the caller it is an answer.
pub trait Caller {
    /// Call `tool` (a service, or an alias) with the extra `argv`, feeding
    /// it `stdin` (then EOF).
    fn call(
        &self,
        tool: &RemoteTool,
        argv: Argv,
        stdin: Vec<u8>,
    ) -> impl Future<Output = Result<CallOutcome>> + Send;
}

/// Everything needed to dial one call, resolved from a [`RemoteTool`] entry.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Dial {
    /// The pinned host's node id.
    pub target: NodeId,
    /// Direct address hints for the host.
    pub addrs: Vec<SocketAddr>,
    /// The relay to dial through, if any.
    pub relay_url: Option<String>,
    /// The service to ask for plus the per-call argv.
    pub invocation: Invocation,
}

impl Dial {
    /// Resolve the alias `tool` into a dial plan carrying `argv`. The service
    /// asked for is the entry's explicit `remote_tool`, else the local name.
    pub fn resolve(tool: &RemoteTool, argv: Argv) -> Result<Self> {
        let ToolTarget::Node {
            node,
            relay_url,
            addrs,
        } = &tool.target
        else {
            bail!(
                "`{}` is a service: it resolves to a host at call time",
                tool.name
            );
        };
        let remote = tool
            .remote_tool
            .clone()
            .unwrap_or_else(|| tool.name.clone());
        Ok(Self {
            target: *node,
            addrs: addrs.clone(),
            relay_url: relay_url.clone(),
            invocation: Invocation {
                service: remote,
                argv,
            },
        })
    }
}

/// This node's credentials for dialing: the node key and its membership,
/// plus the ID token to present when it isn't the one `wires login` stored.
#[derive(Clone)]
pub struct Credentials {
    node: Arc<NodeIdentity>,
    membership: Membership,
    relay_override: Option<String>,
    id_token: Option<IdToken>,
}

impl Credentials {
    /// Resolve credentials the way `wires serve` does (flag, env, file,
    /// keystore).
    pub fn resolve(a: &CredArgs) -> Result<Self> {
        Ok(Self {
            node: Arc::new(keystore::node_identity(
                a.node_seed.as_deref(),
                a.node_seed_file.as_deref(),
            )?),
            membership: keystore::membership(
                a.membership.as_deref(),
                a.membership_file.as_deref(),
            )?,
            relay_override: a.relay_url.clone(),
            id_token: None,
        })
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

    /// The network root this node's membership names.
    pub(crate) fn fabric(&self) -> NodeId {
        self.membership.fabric
    }

    /// Bind this node's endpoint (through the `--relay-url` override, if
    /// any), for dialing services.
    pub(crate) async fn bind(&self) -> Result<iroh::Endpoint> {
        transport::bind(&self.node, self.relay_override.as_deref()).await
    }

    /// The session [`Hello`] to open with, after a local preflight (so a
    /// membership issued to another node fails here, not at the host): the
    /// membership, the version of the state in `ks`, and the ID token
    /// ([`presenting`](Self::presenting)'s, else the stored one).
    fn hello(&self, ks: &Keystore) -> Result<Hello> {
        keystore::preflight(self.node.node_id(), &self.membership).map_err(anyhow::Error::msg)?;
        let mut hello = crate::caller::hello::with_membership(ks, self.membership.clone());
        if let Some(token) = &self.id_token {
            hello.id_token = Some(token.clone());
        }
        Ok(hello)
    }
}

/// Dial `plan` (an alias: one pinned host) with `creds` and bridge the given
/// stdio; returns the remote exit code. The session opens with the same
/// [`Hello`] a service call does, so the host still decides
/// by its signed policy. A refusal surfaces as a [`transport::Denied`] error.
///
/// Runs a local preflight first, so a membership issued to another node
/// fails here, not at the host; and refuses, before dialing, an expired
/// state or a pinned host the state doesn't assign the alias's service.
pub async fn dial<R, W, E>(
    creds: &Credentials,
    plan: Dial,
    stdin: R,
    stdout: W,
    stderr: E,
) -> Result<i32>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let ks = Keystore::resolve()?;
    let hello = creds.hello(&ks)?;
    let state = fresh_state(&ks, creds)?;
    check_alias(&state, &plan)?;
    let service = plan.invocation.service.clone();
    let relay = creds.relay_override.clone().or(plan.relay_url);
    let target = transport::endpoint_addr(&plan.target, &plan.addrs, relay.as_deref())?;
    let endpoint = transport::bind(&creds.node, relay.as_deref()).await?;
    let fabric = creds.membership.fabric;
    let done = transport::call_service_on(
        &endpoint,
        &[target],
        SERVICE_DIAL_TIMEOUT,
        hello,
        plan.invocation,
        |host, newer| accept_ack(&ks, fabric, &service, host, newer),
        stdin,
        stdout,
        stderr,
    )
    .await;
    endpoint.close().await;
    Ok(done?.dialed.exit)
}

/// The live [`Caller`]: dials over wires with this node's [`Credentials`].
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
    async fn call(&self, tool: &RemoteTool, argv: Argv, stdin: Vec<u8>) -> Result<CallOutcome> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        if tool.target == ToolTarget::Service {
            let result = async {
                let ks = Keystore::resolve()?;
                let state = fresh_state(&ks, &self.creds)?;
                call_service(
                    &self.creds,
                    &ks,
                    &state,
                    &tool.name,
                    argv,
                    std::io::Cursor::new(stdin),
                    &mut stdout,
                    &mut stderr,
                    false,
                )
                .await
            }
            .await;
            return outcome(result, stdout, stderr);
        }
        let plan = Dial::resolve(tool, argv)?;
        let result = dial(
            &self.creds,
            plan,
            std::io::Cursor::new(stdin),
            &mut stdout,
            &mut stderr,
        )
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

/// This node's verified signed policy, under the network root its
/// membership names, required to exist and to be fresh: a caller never dials
/// from an expired policy (it would present an old version, and name hosts
/// the admin may have since removed).
pub(crate) fn fresh_state(ks: &Keystore, creds: &Credentials) -> Result<Held> {
    let state = store::require_policy(ks, creds.membership.fabric)?;
    check_fresh(&state, crate::clock::now_unix())?;
    Ok(state)
}

/// Refuse an expired `state`, saying what to do about it.
fn check_fresh(state: &Held, now: i64) -> Result<()> {
    if state.check_fresh(now).is_err() {
        bail!(
            "this node's signed policy (version {}) has expired and no newer one could be \
             fetched, so nothing was dialed; ask the admin to run `wires state push` (or for a \
             fresh invite)",
            state.version().0
        );
    }
    Ok(())
}

/// An alias may only pin a host that the current `state` assigns the alias's
/// service (its `remote_tool`, else its name).
fn check_alias(state: &Held, plan: &Dial) -> Result<()> {
    let service = plan.invocation.service.clone();
    if !state.policy.assigns(&service, plan.target) {
        bail!(
            "the alias's host {} is not assigned `{service}` in signed policy version {}; \
             nothing was dialed",
            plan.target.short(),
            state.version().0
        );
    }
    Ok(())
}

/// What the caller does at a host's `HelloAck`, before any stdin: adopt the
/// newer policy it handed back (if any), then require the policy now held to
/// still assign `service` to `host`. An error aborts the call (exit 1): the
/// host keeps the `Invoke` it already has, but gets no stdin.
fn accept_ack(
    ks: &Keystore,
    fabric: NodeId,
    service: &ServiceName,
    host: NodeId,
    newer: Option<&SignedPolicy>,
) -> Result<()> {
    let Some(newer) = newer else {
        return Ok(());
    };
    if store::adopt_if_newer(ks, newer, fabric, crate::clock::now_unix())
        .context("the host handed back a signed policy that does not verify; no input was sent")?
    {
        tracing::info!(
            version = newer.version().0,
            "adopted the host's newer signed policy"
        );
    }
    let held = store::read(ks, fabric)?.context("no signed policy after adopting one")?;
    if !held.policy.assigns(service, host) {
        bail!(
            "signed policy version {} no longer assigns `{service}` to host {}, so the call was \
             stopped before any input was sent (see `wires services`)",
            held.version().0,
            host.short()
        );
    }
    Ok(())
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

/// Call `service` (card 27): its hosts from `state` (which must be fresh),
/// last-good first, failing over on a dial failure; open with the
/// [`Hello`]; at the host's ack, adopt any newer state it
/// hands back and stop unless that state still assigns `service` to it; then
/// bridge stdio and remember the host that answered. `verbose` names that
/// host on stderr. A refusal is a [`transport::Denied`] error, as in
/// [`dial`].
#[allow(clippy::too_many_arguments)]
pub(crate) async fn call_service<R, W, E>(
    creds: &Credentials,
    ks: &Keystore,
    state: &Held,
    service: &ServiceName,
    argv: Argv,
    stdin: R,
    stdout: W,
    stderr: E,
    verbose: bool,
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
        creds, ks, state, service, &dial, argv, stdin, stdout, stderr, verbose,
    )
    .await;
    endpoint.close().await;
    result
}

/// How [`call_service_with`] reaches hosts.
pub(crate) struct ServiceDial<'a> {
    /// This node's bound endpoint (not closed here).
    pub(crate) endpoint: &'a iroh::Endpoint,
    /// Address hints for the hosts.
    pub(crate) hints: Hints,
    /// How long each host gets to answer a dial.
    pub(crate) timeout: std::time::Duration,
}

/// [`call_service`] over a given endpoint and hints.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn call_service_with<R, W, E>(
    creds: &Credentials,
    ks: &Keystore,
    state: &Held,
    service: &ServiceName,
    dial: &ServiceDial<'_>,
    argv: Argv,
    stdin: R,
    stdout: W,
    stderr: E,
    verbose: bool,
) -> Result<i32>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let hello = creds.hello(ks)?;
    check_fresh(state, crate::clock::now_unix())?;
    let last_good = LastGood::path(ks);
    let hosts = pick::candidates(
        &state.policy,
        service,
        LastGood::load(&last_good).get(service),
    );
    if hosts.is_empty() {
        bail!("no service named `{service}` with a host (see `wires services`)");
    }
    let targets = dial.hints.targets(&hosts, creds.relay_override.as_deref());
    let fabric = creds.membership.fabric;
    let done = transport::call_service_on(
        dial.endpoint,
        &targets,
        dial.timeout,
        hello,
        Invocation {
            service: service.clone(),
            argv,
        },
        |host, newer| accept_ack(ks, fabric, service, host, newer),
        stdin,
        stdout,
        stderr,
    )
    .await
    .with_context(|| format!("calling {service}"))?;
    if verbose {
        eprintln!("wires: {service} answered by host {}", done.host.short());
    }
    LastGood::record(&last_good, service, done.host);
    Ok(done.dialed.exit)
}

/// Credential flags shared by `wires call`, `wires mcp` and `wires inbox`.
///
/// Every one of them is refused in locked mode (`WIRES_LOCKED=1`, see
/// [`crate::caller::lock`]), as is `--tools-file`: they are how a caller is
/// steered off the operator's configuration.
#[derive(Args, Clone, Debug, Default)]
pub struct CredArgs {
    /// Hex 32-byte seed of this node's key. Falls back to `$WIRES_NODE_SEED`,
    /// then `--node-seed-file`, then the keystore (`node.seed`).
    #[arg(long)]
    pub node_seed: Option<String>,
    /// Read the node key seed (hex) from this file instead of the keystore.
    #[arg(long)]
    pub node_seed_file: Option<PathBuf>,
    /// The base64 membership token to present. Falls back to
    /// `$WIRES_MEMBERSHIP`, then `--membership-file`, then the keystore.
    #[arg(long)]
    pub membership: Option<String>,
    /// Read the membership token from this file instead of the keystore.
    #[arg(long)]
    pub membership_file: Option<PathBuf>,
    /// Dial through this relay, overriding an alias's own.
    #[arg(long)]
    pub relay_url: Option<String>,
}

/// `wires call <service> [--jq F] [--head N] [--max-bytes N] [-- args…]`.
#[derive(Args)]
pub struct CallArgs {
    #[command(flatten)]
    pub creds: CredArgs,
    /// Read aliases from this file instead of `$WIRES_HOME/tools.json`.
    #[arg(long)]
    pub tools_file: Option<PathBuf>,
    /// Local output shaping (no shell needed). Goes before `--`, after the
    /// service name (so a permission rule scoped to the service, e.g.
    /// `Bash(wires call gh:*)`, still matches) or before it.
    #[command(flatten)]
    pub shape: ShapeArgs,
    /// Say on stderr which host answered (callers don't normally care).
    #[arg(long)]
    pub verbose: bool,
    /// The service's name (`wires services`).
    #[arg(value_name = "SERVICE")]
    pub service: String,
    /// Extra arguments appended to the remote command. Use `--` before any
    /// that start with `-`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

/// Look the alias `name` up in `config`, with an error that lists what *is*
/// there.
pub fn lookup<'a>(config: &'a ToolsConfig, name: &str) -> Result<&'a RemoteTool> {
    let found = ServiceName::new(name).ok().and_then(|n| config.get(&n));
    found.ok_or_else(|| {
        let known: Vec<&str> = config.tools.iter().map(|t| t.name.as_str()).collect();
        if known.is_empty() {
            anyhow!("no alias named `{name}`: tools.json is empty (add one with `wires tools add`)")
        } else {
            anyhow!("no alias named `{name}` (known: {})", known.join(", "))
        }
    })
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
/// the host never sees them and its call record holds only `(service, argv)`.
///
/// In locked mode ([`Lock`]), an override flag, or data on stdin the operator
/// didn't allow, fails with [`EXIT_LOCKED`] before anything is dialed.
pub async fn call_cmd(a: CallArgs) -> Result<i32> {
    let lock = Lock::detect()?;
    if let Err(e) = lock.check(&a.creds, a.tools_file.as_deref()) {
        eprintln!("wires: {e}");
        return Ok(EXIT_LOCKED);
    }
    let shape = match Shape::new(&a.shape) {
        Ok(shape) => shape,
        Err(e) => {
            eprintln!("wires: {e}");
            return Ok(EXIT_SHAPE);
        }
    };
    let stdin: Box<dyn AsyncRead + Unpin + Send> = if lock.refuses_stdin() {
        if let Err(e) = check_process_stdin().await {
            eprintln!("wires: {e}");
            return Ok(EXIT_LOCKED);
        }
        Box::new(tokio::io::empty())
    } else {
        Box::new(tokio::io::stdin())
    };
    let config = ToolsConfig::load(&crate::caller::tools::resolve_path(
        a.tools_file.as_deref(),
    )?)?;
    let argv = Argv::new(a.args).context("arguments")?;
    let creds = Credentials::resolve(&a.creds)?;
    let route = route(&config, &a.service, argv, &creds)?;
    let run = async |stdout: &mut (dyn AsyncWrite + Unpin + Send)| match route {
        Route::Service {
            ks,
            state,
            service,
            argv,
        } => {
            call_service(
                &creds,
                &ks,
                &state,
                &service,
                argv,
                stdin,
                stdout,
                tokio::io::stderr(),
                a.verbose,
            )
            .await
        }
        Route::Alias(plan) => dial(&creds, plan, stdin, stdout, tokio::io::stderr()).await,
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

/// Where `wires call <name>` goes.
#[allow(clippy::large_enum_variant)]
enum Route {
    /// A service in this node's signed policy.
    Service {
        /// This node's keystore.
        ks: Keystore,
        /// The verified policy it holds.
        state: Held,
        /// The service.
        service: ServiceName,
        /// The per-call arguments.
        argv: Argv,
    },
    /// An alias in `tools.json`, resolved to its pinned host.
    Alias(Dial),
}

/// A service registered in the stored state wins; else an alias (whose host
/// [`dial`] checks against the state). A name that is neither is an error
/// that points at `wires services`.
fn route(config: &ToolsConfig, name: &str, argv: Argv, creds: &Credentials) -> Result<Route> {
    let ks = Keystore::resolve()?;
    let state = store::require_policy(&ks, creds.membership.fabric)?;
    route_in(config, name, argv, ks, state)
}

/// [`route`] against a given keystore and state.
fn route_in(
    config: &ToolsConfig,
    name: &str,
    argv: Argv,
    ks: Keystore,
    state: Held,
) -> Result<Route> {
    let service = ServiceName::new(name).ok();
    if let Some(service) = service
        && state.policy.service(&service).is_some()
    {
        return Ok(Route::Service {
            ks,
            state,
            service,
            argv,
        });
    }
    if let Ok(alias) = lookup(config, name) {
        return Ok(Route::Alias(Dial::resolve(alias, argv)?));
    }
    ServiceName::new(name).map_err(|e| anyhow!("`{name}`: {e}"))?;
    bail!("no service named `{name}` (see `wires services`)")
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

    fn tool(target: ToolTarget, remote: Option<&str>) -> RemoteTool {
        RemoteTool {
            name: ServiceName::new("local").unwrap(),
            description: String::new(),
            target,
            remote_tool: remote.map(|r| ServiceName::new(r).unwrap()),
        }
    }

    fn node() -> NodeId {
        NodeIdentity::from_seed([9; 32]).node_id()
    }

    #[test]
    fn node_target_keeps_the_local_name() {
        let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let t = tool(
            ToolTarget::Node {
                node: node(),
                relay_url: Some("https://relay.example".into()),
                addrs: vec![addr],
            },
            None,
        );
        let d = Dial::resolve(&t, Argv::new(vec!["x".into()]).unwrap()).unwrap();
        assert_eq!(d.target, node());
        assert_eq!(d.addrs, vec![addr]);
        assert_eq!(d.relay_url.as_deref(), Some("https://relay.example"));
        assert_eq!(d.invocation.service.as_str(), "local");
        assert_eq!(d.invocation.argv.as_slice(), ["x"]);
    }

    #[test]
    fn explicit_remote_name_wins_over_the_local_name() {
        let t = tool(
            ToolTarget::Node {
                node: node(),
                relay_url: None,
                addrs: vec![],
            },
            Some("psql"),
        );
        let d = Dial::resolve(&t, Argv::default()).unwrap();
        assert_eq!(d.invocation.service.as_str(), "psql");
    }

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

    #[test]
    fn lookup_lists_known_aliases_on_a_miss() {
        let config = ToolsConfig {
            tools: vec![tool(
                ToolTarget::Node {
                    node: node(),
                    relay_url: None,
                    addrs: vec![],
                },
                None,
            )],
            locked: false,
        };
        assert!(lookup(&config, "local").is_ok());
        let err = lookup(&config, "nope").unwrap_err().to_string();
        assert!(err.contains("known: local"), "{err}");
        let err = lookup(&ToolsConfig::default(), "nope")
            .unwrap_err()
            .to_string();
        assert!(err.contains("tools.json is empty"), "{err}");
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
        use library::{Hello, Membership, Policy, Service, StateVersion};

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
                    readers: vec![],
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
            Membership::mint(&root, server.node_id(), 0, i64::MAX).unwrap(),
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
                    membership: Membership::mint(&root, client.node_id(), 0, i64::MAX).unwrap(),
                    state_version: StateVersion(1),
                    id_token: Some(crate::testutil::test_id_token(&client.node_id())),
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
        let a = parse(&["--tools-file", "/t.json", "rg", "-n"]);
        assert_eq!(a.tools_file, Some(PathBuf::from("/t.json")));
        assert_eq!(a.args, ["-n"]);
        assert!(parse(&["rg"]).args.is_empty());
    }

    /// The dial side against a minimal in-test acceptor (the host's accept
    /// side has its own tests): what a host answers a `Hello` with.
    #[derive(Clone)]
    #[allow(clippy::large_enum_variant)]
    enum Answer {
        /// `HelloAck` (with `newer` when the caller's state is older), then
        /// `out` on stdout and exit 0.
        Run {
            out: &'static str,
            newer: Option<SignedPolicy>,
        },
        /// `Denied`.
        Deny(&'static str),
        /// `HelloAck` (with `newer`), then every `Stdin` byte into `got`
        /// until EOF, then exit 0.
        Echo {
            newer: Option<SignedPolicy>,
            got: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        },
    }

    type Seen = std::sync::Arc<std::sync::Mutex<Vec<library::Hello>>>;

    /// A loopback host speaking just enough of the session protocol: it
    /// records each `Hello` it receives and answers per `answer`.
    async fn fake_host(
        root: &NodeIdentity,
        me: &NodeIdentity,
        answer: Answer,
    ) -> (NodeId, SocketAddr, Seen) {
        use library::{Chunk, Frame, HelloAck};
        let seen: Seen = Default::default();
        let ep = test_endpoint(me).await;
        let addr = loopback(&ep);
        let membership = Membership::mint(root, me.node_id(), 0, i64::MAX).unwrap();
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
                    Answer::Run { out, newer } => {
                        let ack = Frame::HelloAck(HelloAck {
                            membership: membership.clone(),
                            state_version: newer
                                .as_ref()
                                .map_or(caller_version, SignedPolicy::version),
                            newer_policy: newer.clone().filter(|n| n.version() > caller_version),
                        });
                        let _ = transport::write_frame(&mut send, &ack).await;
                        let chunk = Chunk::from_bytes(out.as_bytes().to_vec());
                        let _ = transport::write_frame(&mut send, &Frame::Stdout(chunk)).await;
                        let _ = transport::write_frame(&mut send, &Frame::Exit(0)).await;
                    }
                    Answer::Echo { newer, got } => {
                        let ack = Frame::HelloAck(HelloAck {
                            membership: membership.clone(),
                            state_version: caller_version,
                            newer_policy: newer.clone(),
                        });
                        let _ = transport::write_frame(&mut send, &ack).await;
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

    /// A signed policy at `version` in which `hosts` implement `orders-db`.
    fn signed_state(root: &NodeIdentity, version: u64, hosts: &[NodeId]) -> SignedPolicy {
        use library::{Matcher, Policy, RoleName, Service, StateVersion};
        let mut s = Policy::new(root.node_id());
        s.version = StateVersion(version);
        s.issued = 1;
        s.not_after = i64::MAX;
        let staff = RoleName::new("staff").unwrap();
        s.roles
            .insert(staff.clone(), vec![Matcher::new("https://idp.example")]);
        s.services.insert(
            ServiceName::new("orders-db").unwrap(),
            Service {
                description: "Read-only SQL".into(),
                allow: vec![staff],
                hosts: hosts.to_vec(),
                readers: vec![],
            },
        );
        crate::testutil::signed_policy(root, s)
    }

    /// `signed` as this node holds it.
    fn held(f: &Fixture, signed: &SignedPolicy) -> Held {
        Held::verify(signed.clone(), f.root.node_id()).unwrap()
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
        let membership = Membership::mint(&root, me.node_id(), 0, i64::MAX).unwrap();
        Fixture {
            creds: Credentials {
                node: Arc::new(me),
                membership,
                relay_override: None,
                id_token: None,
            },
            root,
            ks,
        }
    }

    async fn run_service(f: &Fixture, state: &Held, hints: Hints) -> (Result<i32>, String) {
        run_service_with_stdin(f, state, hints, Vec::new()).await
    }

    async fn run_service_with_stdin(
        f: &Fixture,
        state: &Held,
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
            state,
            &ServiceName::new("orders-db").unwrap(),
            &dial,
            Argv::default(),
            std::io::Cursor::new(stdin),
            &mut stdout,
            Vec::new(),
            false,
        )
        .await;
        endpoint.close().await;
        (r, String::from_utf8(stdout).unwrap())
    }

    /// Host A is down, host B answers: the call fails over to B, presents a
    /// `Hello` with this node's membership, state version and stored token,
    /// adopts the newer state B hands back, and remembers B as last-good.
    #[tokio::test]
    async fn a_service_call_fails_over_and_adopts_the_hosts_newer_state() {
        let f = fixture();
        let down = NodeIdentity::from_seed([82; 32]).node_id();
        let b = NodeIdentity::from_seed([83; 32]);
        let v1 = signed_state(&f.root, 1, &[down, b.node_id()]);
        let v2 = signed_state(&f.root, 2, &[down, b.node_id()]);
        store::adopt_if_newer(&f.ks, &v1, f.root.node_id(), 10).unwrap();
        let answer = Answer::Run {
            out: "42\n",
            newer: Some(v2),
        };
        let (b_id, b_addr, seen) = fake_host(&f.root, &b, answer).await;
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let hints = Hints::from_pairs([(down, vec![dead]), (b_id, vec![b_addr])]);

        let (r, out) = run_service(&f, &held(&f, &v1), hints.clone()).await;
        assert_eq!(r.unwrap(), 0);
        assert_eq!(out, "42\n");
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].membership, f.creds.membership);
            assert_eq!(seen[0].state_version, library::StateVersion(1));
            assert_eq!(seen[0].id_token, Some(library::IdToken::new("h.p.s")));
        }
        let stored = store::read(&f.ks, f.root.node_id()).unwrap().unwrap();
        assert_eq!(stored.version(), library::StateVersion(2));
        let name = ServiceName::new("orders-db").unwrap();
        let last = LastGood::load(&LastGood::path(&f.ks));
        assert_eq!(last.get(&name), Some(b_id));

        // Next call: B is tried first, and presents the adopted version.
        let (r, _) = run_service(&f, &stored, hints).await;
        assert_eq!(r.unwrap(), 0);
        let seen = seen.lock().unwrap();
        assert_eq!(seen[1].state_version, library::StateVersion(2));
    }

    /// A refusal is final: no failover to the next host, and it surfaces as
    /// `Denied` (exit 77 in `wires call`).
    #[tokio::test]
    async fn a_refusal_does_not_fail_over() {
        let f = fixture();
        let a = NodeIdentity::from_seed([84; 32]);
        let b = NodeIdentity::from_seed([85; 32]);
        let state = held(&f, &signed_state(&f.root, 1, &[a.node_id(), b.node_id()]));
        let (a_id, a_addr, _) = fake_host(&f.root, &a, Answer::Deny("not in role analyst")).await;
        let answer = Answer::Run {
            out: "",
            newer: None,
        };
        let (b_id, b_addr, b_seen) = fake_host(&f.root, &b, answer).await;
        let hints = Hints::from_pairs([(a_id, vec![a_addr]), (b_id, vec![b_addr])]);
        let (r, out) = run_service(&f, &state, hints).await;
        let err = r.unwrap_err();
        let denied = err.downcast_ref::<transport::Denied>().expect("a Denied");
        assert_eq!(denied.reason(), "not in role analyst");
        assert_eq!(out, "");
        assert!(
            b_seen.lock().unwrap().is_empty(),
            "no failover after a refusal"
        );
    }

    /// Card 35: with its state current, a caller never sends `Hello` (so
    /// never `Invoke`) to a host that state bans, even one still listed for
    /// the service (a validated state can't list one; this is the caller's
    /// own guard) and remembered as the last that answered.
    #[tokio::test]
    async fn a_banned_host_is_never_dialed() {
        let f = fixture();
        let banned = NodeIdentity::from_seed([92; 32]);
        let fine = NodeIdentity::from_seed([93; 32]);
        let mut state = held(
            &f,
            &signed_state(&f.root, 1, &[banned.node_id(), fine.node_id()]),
        );
        // As if the ban were signed in: `call` checks freshness, not the
        // signature (the store verified it on the way in).
        let forever = library::Ban { until: i64::MAX };
        state.policy.bans.insert(banned.node_id(), forever);
        let run = || Answer::Run {
            out: "ok\n",
            newer: None,
        };
        let (b_id, b_addr, b_seen) = fake_host(&f.root, &banned, run()).await;
        let (f_id, f_addr, f_seen) = fake_host(&f.root, &fine, run()).await;
        let name = ServiceName::new("orders-db").unwrap();
        LastGood::record(&LastGood::path(&f.ks), &name, b_id);
        let hints = Hints::from_pairs([(b_id, vec![b_addr]), (f_id, vec![f_addr])]);
        let (r, out) = run_service(&f, &state, hints.clone()).await;
        assert_eq!(r.unwrap(), 0);
        assert_eq!(out, "ok\n");
        assert_eq!(f_seen.lock().unwrap().len(), 1);
        assert!(
            b_seen.lock().unwrap().is_empty(),
            "the banned host was dialed"
        );

        // Its only host banned: nothing is dialed at all.
        state.policy.bans.insert(fine.node_id(), forever);
        let (r, _) = run_service(&f, &state, hints).await;
        assert!(format!("{:#}", r.unwrap_err()).contains("with a host"));
        assert!(b_seen.lock().unwrap().is_empty());
        assert_eq!(f_seen.lock().unwrap().len(), 1);
    }

    /// Every host down: one error naming each.
    #[tokio::test]
    async fn no_host_answering_is_an_error_naming_them() {
        let f = fixture();
        let a = NodeIdentity::from_seed([86; 32]).node_id();
        let state = held(&f, &signed_state(&f.root, 1, &[a]));
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let (r, _) = run_service(&f, &state, Hints::from_pairs([(a, vec![dead])])).await;
        let err = format!("{:#}", r.unwrap_err());
        assert!(err.contains("no host answered"), "{err}");
        assert!(err.contains(&a.short()), "{err}");
    }
    /// Card 28 §8: an expired state is never dialed from.
    #[tokio::test]
    async fn an_expired_state_refuses_to_dial() {
        let f = fixture();
        let h = NodeIdentity::from_seed([87; 32]);
        let answer = Answer::Run {
            out: "",
            newer: None,
        };
        let (h_id, h_addr, seen) = fake_host(&f.root, &h, answer).await;
        let mut expired = signed_state(&f.root, 1, &[h_id]).to_policy().unwrap();
        expired.not_after = 1;
        let expired = crate::testutil::held(&f.root, expired);
        let (r, _) = run_service(&f, &expired, Hints::from_pairs([(h_id, vec![h_addr])])).await;
        let err = format!("{:#}", r.unwrap_err());
        assert!(
            err.contains("expired") && err.contains("wires state push"),
            "{err}"
        );
        assert!(seen.lock().unwrap().is_empty(), "nothing was dialed");
    }

    /// Card 28 §8: the host's newer state is adopted at the ack, and when it
    /// no longer assigns the service to that host the call stops there,
    /// before any stdin, as a failure (not a refusal).
    #[tokio::test]
    async fn a_newer_state_dropping_the_host_aborts_before_stdin() {
        let f = fixture();
        let h = NodeIdentity::from_seed([88; 32]);
        let other = NodeIdentity::from_seed([89; 32]).node_id();
        let v1 = signed_state(&f.root, 1, &[h.node_id()]);
        let v2 = signed_state(&f.root, 2, &[other]);
        store::adopt_if_newer(&f.ks, &v1, f.root.node_id(), 10).unwrap();
        let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let answer = Answer::Echo {
            newer: Some(v2.clone()),
            got: got.clone(),
        };
        let (h_id, h_addr, _) = fake_host(&f.root, &h, answer).await;
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
        assert_eq!(
            store::read(&f.ks, f.root.node_id())
                .unwrap()
                .unwrap()
                .signed,
            v2
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(got.lock().unwrap().is_empty(), "no stdin reached the host");

        // Control: a newer state that still assigns the host lets stdin through.
        let f = fixture();
        let v2 = signed_state(&f.root, 2, &[h.node_id()]);
        store::adopt_if_newer(&f.ks, &v1, f.root.node_id(), 10).unwrap();
        let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let answer = Answer::Echo {
            newer: Some(v2),
            got: got.clone(),
        };
        let (h_id, h_addr, _) = fake_host(&f.root, &h, answer).await;
        let hints = Hints::from_pairs([(h_id, vec![h_addr])]);
        let (r, _) = run_service_with_stdin(&f, &held(&f, &v1), hints, b"secret".to_vec()).await;
        assert_eq!(r.unwrap(), 0);
        assert_eq!(got.lock().unwrap().as_slice(), b"secret");
    }

    /// Card 28 §8: a registered service beats an alias of the same name, and
    /// an alias may only pin a host the state assigns its service.
    #[test]
    fn a_service_beats_an_alias_and_an_alias_needs_an_assigned_host() {
        let f = fixture();
        let host = NodeIdentity::from_seed([90; 32]).node_id();
        let stranger = NodeIdentity::from_seed([91; 32]).node_id();
        let state = held(&f, &signed_state(&f.root, 1, &[host]));
        let alias = |name: &str, node: NodeId| RemoteTool {
            name: ServiceName::new(name).unwrap(),
            description: String::new(),
            target: ToolTarget::Node {
                node,
                relay_url: None,
                addrs: vec![],
            },
            remote_tool: Some(ServiceName::new("orders-db").unwrap()),
        };
        let config = ToolsConfig {
            tools: vec![alias("orders-db", stranger), alias("orders", stranger)],
            locked: false,
        };
        let ks = || Keystore::at(crate::testutil::temp_dir());
        let route = |name| route_in(&config, name, Argv::default(), ks(), state.clone());
        let routed = route("orders-db").unwrap();
        assert!(matches!(routed, Route::Service { .. }), "the service wins");
        let Route::Alias(plan) = route("orders").unwrap() else {
            panic!("an alias")
        };
        assert_eq!(plan.target, stranger);
        assert!(route("nope").is_err());

        let plan = |node| Dial::resolve(&alias("orders", node), Argv::default()).unwrap();
        let err = check_alias(&state, &plan(stranger))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not assigned `orders-db`"), "{err}");
        check_alias(&state, &plan(host)).unwrap();
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

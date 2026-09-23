//! `wires call`: run one remote CLI by name, as if it were local.
//!
//! The name is a **service** (card 27): its hosts come from this node's
//! admin-signed state, tried last-good first with failover on a dial failure
//! ([`crate::caller::pick`]), and the session opens with the card-27
//! [`Hello`](library::Hello) (membership, state version, ID token). A newer
//! state a host hands back is adopted. An alias in `tools.json` wins over a
//! service: it pins a name to one host (and address hints), and that host
//! still decides by its signed state.
//! Locked mode ([`crate::caller::lock`]) refuses the override flags a
//! sandboxed agent could steer this with.
//!
//! The CLI-native front door. An agent runs `wires call <tool> [-- args…]`
//! from its shell: stdin, stdout and stderr pass straight through, the remote
//! exit code becomes ours, and a refusal by the responder exits
//! [`EXIT_DENIED`](crate::EXIT_DENIED) (77) with the reason on stderr.
//!
//! The same dialing sits behind the [`Caller`] trait, which buffers a call's
//! output into a [`CallOutcome`] for `wires mcp` — and lets the MCP server be
//! tested against a fake while the live path stays one function
//! ([`dial`]).

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use library::{
    Argv, Invocation, Membership, NodeId, NodeIdentity, ServiceName, SignedState, ToolName,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::admin::keystore::{self, Keystore};
use crate::caller::lock::{EXIT_LOCKED, Lock, check_process_stdin};
use crate::caller::pick::{self, Hints, LastGood};
use crate::caller::shape::{EXIT_SHAPE, Shape, ShapeArgs, exit_code};
use crate::caller::tools::{RemoteTool, ToolTarget, ToolsConfig};
use crate::host::transport;
use crate::state::store;

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
    /// The responder refused the call; its stated reason, verbatim.
    Denied(String),
}

/// Something that can run a [`RemoteTool`] and hand back its [`CallOutcome`].
///
/// `Err` is reserved for local or transport failures (no keystore, dial
/// timeout, session dropped); a refusal by the responder is an `Ok`
/// [`CallOutcome::Denied`], because to the caller it is an answer.
pub trait Caller {
    /// Run `tool` with the extra `argv`, feeding it `stdin` (then EOF).
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
    /// The responder's node id.
    pub target: NodeId,
    /// Direct address hints for the responder.
    pub addrs: Vec<SocketAddr>,
    /// The relay to dial through, if any.
    pub relay_url: Option<String>,
    /// The remote tool name plus the per-call argv.
    pub invocation: Invocation,
}

impl Dial {
    /// Resolve `tool` into a dial plan carrying `argv`. The remote tool name
    /// is the entry's explicit `remote_tool`, else the local name.
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
            invocation: Invocation { tool: remote, argv },
        })
    }
}

/// This node's credentials for dialing: the node key and its membership.
pub struct Credentials {
    node: NodeIdentity,
    membership: Membership,
    relay_override: Option<String>,
}

impl Credentials {
    /// Resolve credentials the way `wires serve` does (flag, env, file,
    /// keystore).
    pub fn resolve(a: &CredArgs) -> Result<Self> {
        Ok(Self {
            node: keystore::node_identity(a.node_seed.as_deref(), a.node_seed_file.as_deref())?,
            membership: keystore::membership(
                a.membership.as_deref(),
                a.membership_file.as_deref(),
            )?,
            relay_override: a.relay_url.clone(),
        })
    }
}

/// Dial `plan` (an alias: one pinned host) with `creds` and bridge the given
/// stdio; returns the remote exit code. The session opens with the same
/// [`Hello`](library::Hello) a service call does, so the host still decides
/// by its signed state. A refusal surfaces as a [`transport::Denied`] error.
///
/// Runs a local preflight first, so a membership issued to another node
/// fails here, not at the host.
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
    crate::admin::keystore::preflight(creds.node.node_id(), &creds.membership)
        .map_err(anyhow::Error::msg)?;
    let relay = creds.relay_override.clone().or(plan.relay_url);
    let target = transport::endpoint_addr(&plan.target, &plan.addrs, relay.as_deref())?;
    let ks = Keystore::resolve()?;
    let hello = crate::caller::hello::with_membership(&ks, creds.membership.clone())?;
    let endpoint = transport::bind(&creds.node, relay.as_deref()).await?;
    let done = transport::call_service_on(
        &endpoint,
        &[target],
        SERVICE_DIAL_TIMEOUT,
        hello,
        plan.invocation,
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
                let state = stored_state(&ks, &self.creds)?
                    .ok_or_else(|| anyhow!("this node holds no signed state"))?;
                call_service(
                    &self.creds,
                    &ks,
                    &state,
                    &ServiceName::from(tool.name.clone()),
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
fn outcome(result: Result<i32>, stdout: Vec<u8>, stderr: Vec<u8>) -> Result<CallOutcome> {
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

/// This node's verified signed state, under the fabric root its membership
/// names; `None` if it holds none yet.
pub(crate) fn stored_state(ks: &Keystore, creds: &Credentials) -> Result<Option<SignedState>> {
    store::read(ks, creds.membership.fabric)
}

/// Call `service` (card 27): its hosts from `state`, last-good first, failing
/// over on a dial failure; open with the [`Hello`](library::Hello), bridge
/// stdio, adopt any newer state the host hands back, remember the host that
/// answered. `verbose` names that host on stderr. A refusal is a
/// [`transport::Denied`] error, as in [`dial`].
#[allow(clippy::too_many_arguments)]
pub(crate) async fn call_service<R, W, E>(
    creds: &Credentials,
    ks: &Keystore,
    state: &SignedState,
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
    crate::admin::keystore::preflight(creds.node.node_id(), &creds.membership)
        .map_err(anyhow::Error::msg)?;
    let relay = creds.relay_override.as_deref();
    let endpoint = transport::bind(&creds.node, relay).await?;
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
    state: &SignedState,
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
    let last_good = LastGood::path(ks);
    let hosts = pick::candidates(
        &state.state,
        service,
        LastGood::load(&last_good).get(service),
    );
    if hosts.is_empty() {
        bail!("no service named `{service}` with a host (see `wires services`)");
    }
    let hello = crate::caller::hello::with_membership(ks, creds.membership.clone())?;
    let targets = dial.hints.targets(&hosts, creds.relay_override.as_deref());
    let done = transport::call_service_on(
        dial.endpoint,
        &targets,
        dial.timeout,
        hello,
        Invocation {
            tool: service.clone().into(),
            argv,
        },
        stdin,
        stdout,
        stderr,
    )
    .await
    .with_context(|| format!("calling {service}"))?;
    if verbose {
        eprintln!(
            "wires: {service} answered by host {}",
            pick::short(&done.host)
        );
    }
    LastGood::record(&last_good, service, done.host);
    if let Some(newer) = &done.dialed.newer_state {
        match store::adopt_if_newer(ks, newer, creds.membership.fabric, crate::now_unix()) {
            Ok(true) => tracing::info!(
                version = newer.state.version.0,
                "adopted the host's newer signed state"
            ),
            Ok(false) => {}
            Err(e) => tracing::warn!("the host's newer state was not adopted: {e:#}"),
        }
    }
    Ok(done.dialed.exit)
}

/// Credential and config flags shared by `wires call` and `wires mcp`.
///
/// Every one of them is refused in locked mode (`WIRES_LOCKED=1`, see
/// [`crate::caller::lock`]): they are how a caller is steered off the
/// operator's configuration.
#[derive(Args, Clone, Debug, Default)]
pub struct CredArgs {
    /// Read aliases from this file instead of `$WIRES_HOME/tools.json`.
    #[arg(long)]
    pub tools_file: Option<PathBuf>,
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
    /// Dial through this relay, overriding the tool entry's own.
    #[arg(long)]
    pub relay_url: Option<String>,
}

/// `wires call <tool> [--jq F] [--head N] [--max-bytes N] [-- args…]`.
#[derive(Args)]
pub struct CallArgs {
    #[command(flatten)]
    pub creds: CredArgs,
    /// Local output shaping (no shell needed). Goes before `--`, after the
    /// tool name (so a permission rule scoped to the tool, e.g.
    /// `Bash(wires call gh:*)`, still matches) or before it.
    #[command(flatten)]
    pub shape: ShapeArgs,
    /// Say on stderr which host answered (callers don't normally care).
    #[arg(long)]
    pub verbose: bool,
    /// The service's name (`wires services`), or an alias from `tools.json`.
    pub tool: String,
    /// Extra arguments appended to the remote command. Use `--` before any
    /// that start with `-`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

/// Look `name` up in `config`, with an error that lists what *is* there.
pub fn lookup<'a>(config: &'a ToolsConfig, name: &str) -> Result<&'a RemoteTool> {
    let found = ToolName::new(name).ok().and_then(|n| config.get(&n));
    found.ok_or_else(|| {
        let known: Vec<&str> = config.tools.iter().map(|t| t.name.as_str()).collect();
        if known.is_empty() {
            anyhow!("no tool named `{name}`: tools.json is empty (add one with `wires tools add`)")
        } else {
            anyhow!("no tool named `{name}` (known: {})", known.join(", "))
        }
    })
}

/// `wires call`: stream local stdio to the remote tool; returns its exit code.
///
/// With a shaping flag (`--jq`/`--head`/`--max-bytes`), the remote stdout is
/// buffered and shaped in-process before it is written; stderr still
/// streams. A filter that doesn't compile fails with [`EXIT_SHAPE`] before
/// anything is dialed.
///
/// The shaping flags are local: they are not part of the [`Invocation`], so
/// the host never sees them and its call record holds only `(tool, argv)`.
///
/// In locked mode ([`Lock`]), an override flag, or data on stdin the operator
/// didn't allow, fails with [`EXIT_LOCKED`] before anything is dialed.
pub async fn call_cmd(a: CallArgs) -> Result<i32> {
    let lock = Lock::detect()?;
    if let Err(e) = lock.check(&a.creds) {
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
        a.creds.tools_file.as_deref(),
    )?)?;
    let argv = Argv::new(a.args).context("arguments")?;
    let creds = Credentials::resolve(&a.creds)?;
    let route = route(&config, &a.tool, &creds)?;
    let plan = match &route {
        Route::Service { .. } => None,
        Route::Alias => Some(Dial::resolve(lookup(&config, &a.tool)?, argv.clone())?),
    };
    let run = async |stdout: &mut (dyn AsyncWrite + Unpin + Send)| match (&route, plan) {
        (Route::Service { ks, state, service }, _) => {
            call_service(
                &creds,
                ks,
                state,
                service,
                argv,
                stdin,
                stdout,
                tokio::io::stderr(),
                a.verbose,
            )
            .await
        }
        (Route::Alias, Some(plan)) => dial(&creds, plan, stdin, stdout, tokio::io::stderr()).await,
        (Route::Alias, None) => unreachable!("an alias route always has a plan"),
    };
    if shape.is_identity() {
        return run(&mut tokio::io::stdout()).await;
    }
    let mut stdout = Vec::new();
    let remote = run(&mut stdout).await?;
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
    /// A service in this node's signed state.
    Service {
        /// This node's keystore.
        ks: Keystore,
        /// The verified state it holds.
        state: SignedState,
        /// The service.
        service: ServiceName,
    },
    /// An alias in `tools.json`.
    Alias,
}

/// An alias wins; else a service registered in the stored state. A name the
/// state doesn't register is an error that points at `wires services`.
fn route(config: &ToolsConfig, name: &str, creds: &Credentials) -> Result<Route> {
    if lookup(config, name).is_ok() {
        return Ok(Route::Alias);
    }
    let ks = Keystore::resolve()?;
    let Some(state) = stored_state(&ks, creds)? else {
        bail!("this node holds no signed state yet: run `wires join <token>` first");
    };
    let service = ServiceName::new(name).map_err(|e| anyhow!("`{name}`: {e}"))?;
    if state.state.service(&service).is_none() {
        bail!("no service named `{name}` (see `wires services`)");
    }
    Ok(Route::Service { ks, state, service })
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
            name: ToolName::new("local").unwrap(),
            description: String::new(),
            target,
            remote_tool: remote.map(|r| ToolName::new(r).unwrap()),
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
        assert_eq!(d.invocation.tool.as_str(), "local");
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
        assert_eq!(d.invocation.tool.as_str(), "psql");
    }

    #[test]
    fn denied_is_an_outcome_and_other_errors_stay_errors() {
        let denied =
            anyhow::Error::new(transport::Denied::new("revoked".into())).context("dialing");
        assert_eq!(
            outcome(Err(denied), vec![], vec![]).unwrap(),
            CallOutcome::Denied("revoked".into())
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
    fn lookup_lists_known_tools_on_a_miss() {
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
    fn shaping_flags_go_before_the_tool_and_after_it_belong_to_the_tool() {
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
        // Right after the tool name, before `--`, they are still ours — so a
        // permission rule scoped to one tool (`Bash(wires call gh:*)`) still
        // matches a shaped call.
        let a = parse(&["gh", "--jq", ".[].name", "--head", "3", "--", "api", "x"]);
        assert_eq!(a.tool, "gh");
        assert_eq!(a.shape.jq.as_deref(), Some(".[].name"));
        assert_eq!(a.shape.head, Some(3));
        assert_eq!(a.args, ["api", "x"]);
        // After `--`, or once the tool's own arguments have begun, `--jq` is
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
        use crate::host::config_v2::HostConfigV2;
        use crate::host::transport::{ALPN, endpoint_addr, secret_key};
        use library::{Hello, Membership, RoleName, Service, State, StateVersion};

        let root = NodeIdentity::from_seed([70; 32]);
        let server = NodeIdentity::from_seed([71; 32]);
        let client = NodeIdentity::from_seed([72; 32]);
        let mut s = State::new(root.node_id());
        s.version = StateVersion(1);
        s.issued = 1;
        s.not_after = i64::MAX;
        s.members.extend([server.node_id(), client.node_id()]);
        s.hosts.insert(server.node_id());
        for name in ["json", "fail"] {
            s.services.insert(
                ServiceName::new(name).unwrap(),
                Service {
                    description: String::new(),
                    allow: vec![RoleName::member()],
                    hosts: vec![server.node_id()],
                    readers: vec![],
                },
            );
        }
        let home = crate::testutil::temp_dir();
        let ks = Keystore::at(&home);
        crate::state::store::adopt_if_newer(&ks, &s.sign(&root).unwrap(), root.node_id(), 10)
            .unwrap();
        let config = HostConfigV2::parse(
            r#"{"version":2,"services":{
                "json":{"command":["sh","-c","printf '{\"items\":[{\"name\":\"é-one\"},{\"name\":\"two\"},{\"name\":\"three\"}]}'"]},
                "fail":{"command":["sh","-c","echo 'HTTP 404'; exit 3"]}}}"#,
        )
        .unwrap();
        let host = crate::host::serve::services_host(
            server.node_id(),
            Membership::mint(&root, server.node_id(), 0, i64::MAX).unwrap(),
            std::sync::Arc::new(ks),
            &home,
            config,
        )
        .unwrap();
        let endpoint = |id: &NodeIdentity| {
            iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .secret_key(secret_key(id))
                .alpns(vec![ALPN.to_vec()])
                .bind()
        };
        let server_ep = endpoint(&server).await.unwrap();
        let addrs: Vec<SocketAddr> = server_ep
            .bound_sockets()
            .into_iter()
            .filter(SocketAddr::is_ipv4)
            .map(|s| SocketAddr::from(([127, 0, 0, 1], s.port())))
            .collect();
        let target = endpoint_addr(&server.node_id(), &addrs, None).unwrap();
        let _router =
            crate::host::serve::services_router(server_ep, std::sync::Arc::new(host), None);
        let client_ep = endpoint(&client).await.unwrap();

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
                    id_token: None,
                },
                Invocation {
                    tool: ToolName::new(name).unwrap(),
                    argv: Argv::default(),
                },
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
            (a.tool.as_str(), a.args),
            ("rg", vec!["foo".into(), "bar".into()])
        );
        let a = parse(&["rg", "--", "-n", "--x", "foo"]);
        assert_eq!(a.args, ["-n", "--x", "foo"]);
        let a = parse(&["--tools-file", "/t.json", "rg", "-n"]);
        assert_eq!(a.creds.tools_file, Some(PathBuf::from("/t.json")));
        assert_eq!(a.args, ["-n"]);
        assert!(parse(&["rg"]).args.is_empty());
    }

    /// Card 27, the dial side against a minimal in-test acceptor (the host's
    /// accept side is lane 27c): what a host answers a `Hello` with.
    #[derive(Clone)]
    #[allow(clippy::large_enum_variant)]
    enum Answer {
        /// `HelloAck` (with `newer` when the caller's state is older), then
        /// `out` on stdout and exit 0.
        Run {
            out: &'static str,
            newer: Option<SignedState>,
        },
        /// `Denied`.
        Deny(&'static str),
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
                                .map_or(caller_version, |n| n.state.version),
                            newer_state: newer.clone().filter(|n| n.state.version > caller_version),
                        });
                        let _ = transport::write_frame(&mut send, &ack).await;
                        let chunk = Chunk::from_bytes(out.as_bytes().to_vec());
                        let _ = transport::write_frame(&mut send, &Frame::Stdout(chunk)).await;
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

    /// A signed state at `version` in which `hosts` implement `orders-db`.
    fn signed_state(
        root: &NodeIdentity,
        version: u64,
        caller: NodeId,
        hosts: &[NodeId],
    ) -> SignedState {
        use library::{RoleName, Service, State, StateVersion};
        let mut s = State::new(root.node_id());
        s.version = StateVersion(version);
        s.issued = 1;
        s.not_after = i64::MAX;
        s.members.insert(caller);
        s.members.extend(hosts.iter().copied());
        s.hosts.extend(hosts.iter().copied());
        s.services.insert(
            ServiceName::new("orders-db").unwrap(),
            Service {
                description: "Read-only SQL".into(),
                allow: vec![RoleName::member()],
                hosts: hosts.to_vec(),
                readers: vec![],
            },
        );
        s.sign(root).unwrap()
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
                node: me,
                membership,
                relay_override: None,
            },
            root,
            ks,
        }
    }

    async fn run_service(f: &Fixture, state: &SignedState, hints: Hints) -> (Result<i32>, String) {
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
            std::io::Cursor::new(Vec::new()),
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
        let me = f.creds.node.node_id();
        let v1 = signed_state(&f.root, 1, me, &[down, b.node_id()]);
        let v2 = signed_state(&f.root, 2, me, &[down, b.node_id()]);
        store::adopt_if_newer(&f.ks, &v1, f.root.node_id(), 10).unwrap();
        let answer = Answer::Run {
            out: "42\n",
            newer: Some(v2),
        };
        let (b_id, b_addr, seen) = fake_host(&f.root, &b, answer).await;
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let hints = Hints::from_pairs([(down, vec![dead]), (b_id, vec![b_addr])]);

        let (r, out) = run_service(&f, &v1, hints.clone()).await;
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
        assert_eq!(stored.state.version, library::StateVersion(2));
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
        let me = f.creds.node.node_id();
        let state = signed_state(&f.root, 1, me, &[a.node_id(), b.node_id()]);
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

    /// Every host down: one error naming each.
    #[tokio::test]
    async fn no_host_answering_is_an_error_naming_them() {
        let f = fixture();
        let a = NodeIdentity::from_seed([86; 32]).node_id();
        let me = f.creds.node.node_id();
        let state = signed_state(&f.root, 1, me, &[a]);
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let (r, _) = run_service(&f, &state, Hints::from_pairs([(a, vec![dead])])).await;
        let err = format!("{:#}", r.unwrap_err());
        assert!(err.contains("no host answered"), "{err}");
        assert!(err.contains(&a.hex()[..8]), "{err}");
    }
}

//! `wires call`: run one remote CLI by name, as if it were local.
//!
//! The name resolves through the channel's host announcements (the
//! `directory.json` cache, refreshed from the channel when needed); an alias
//! in `tools.json` wins over it. Locked mode ([`crate::caller::lock`]) refuses
//! the override flags a sandboxed agent could steer this with.
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

use anyhow::{Context, Result, anyhow};
use clap::Args;
use library::{Argv, InclusionProof, Invocation, Membership, NodeId, NodeIdentity, ToolName};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::admin::keystore;
use crate::caller::lock::{EXIT_LOCKED, Lock, check_process_stdin};
use crate::caller::shape::{EXIT_SHAPE, Shape, ShapeArgs, exit_code};
use crate::caller::tools::{RemoteTool, ToolTarget, ToolsConfig};
use crate::host::transport;

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
        } = &tool.target;
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

/// This node's credentials for dialing: the node key, its membership, and
/// (for a head-enforcing responder) its inclusion proof.
pub struct Credentials {
    node: NodeIdentity,
    membership: Membership,
    proof: Option<InclusionProof>,
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
            proof: keystore::inclusion_proof(
                a.inclusion_proof.as_deref(),
                a.inclusion_proof_file.as_deref(),
            )?,
            relay_override: a.relay_url.clone(),
        })
    }
}

/// Dial `plan` with `creds` and bridge the given stdio; returns the remote
/// exit code. A refusal surfaces as a [`transport::Denied`] error.
///
/// Runs the same local preflight as the topic commands first, so a
/// membership issued to another node fails here, not at the responder.
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
    let endpoint = transport::bind(&creds.node, relay.as_deref()).await?;
    transport::call_on(
        endpoint,
        target,
        creds.membership.clone(),
        creds.proof.clone(),
        plan.invocation,
        stdin,
        stdout,
        stderr,
    )
    .await
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
        let plan = Dial::resolve(tool, argv)?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
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
    /// The inclusion proof token to present. Falls back to
    /// `$WIRES_INCLUSION_PROOF`, then `--inclusion-proof-file`, then the keystore.
    #[arg(long)]
    pub inclusion_proof: Option<String>,
    /// Read the inclusion proof token from this file.
    #[arg(long)]
    pub inclusion_proof_file: Option<PathBuf>,
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
    /// The tool's name as your channel's hosts announce it (`wires tools`),
    /// `<host8>/<name>` to pick one host, or an alias from `tools.json`.
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
    // An alias in tools.json, else the channel's host announcements (card 15).
    let tool = crate::caller::resolve::resolve_tool(&config, &a.tool, &a.creds).await?;
    let argv = Argv::new(a.args).context("arguments")?;
    let plan = Dial::resolve(&tool, argv)?;
    let creds = Credentials::resolve(&a.creds)?;
    if shape.is_identity() {
        return dial(
            &creds,
            plan,
            stdin,
            tokio::io::stdout(),
            tokio::io::stderr(),
        )
        .await;
    }
    let mut stdout = Vec::new();
    let remote = dial(&creds, plan, stdin, &mut stdout, tokio::io::stderr()).await?;
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
            audit_topic: None,
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

    /// End to end over a loopback responder: the remote stdout is shaped
    /// after it arrives, and the remote exit code passes through.
    #[tokio::test]
    async fn shaping_over_a_loopback_host() {
        use crate::host::transport::{
            ALPN, HeadSource, ServeConfig, call_on, endpoint_addr, secret_key, serve_on,
        };
        use library::Membership;
        use std::collections::BTreeMap;

        let root = NodeIdentity::from_seed([70; 32]);
        let server = NodeIdentity::from_seed([71; 32]);
        let client = NodeIdentity::from_seed([72; 32]);
        let tool = |name: &str, script: &str| {
            (
                ToolName::new(name).unwrap(),
                vec!["sh".into(), "-c".into(), script.into()],
            )
        };
        let config = ServeConfig {
            tools: BTreeMap::from([
                tool(
                    "json",
                    r#"printf '{"items":[{"name":"é-one"},{"name":"two"},{"name":"three"}]}'"#,
                ),
                tool("fail", "echo 'HTTP 404'; exit 3"),
            ]),
            audit: None,
            identity: None,
            trust_root: root.node_id(),
            head: HeadSource::None,
            membership: Membership::mint(&root, server.node_id(), 0, i64::MAX).unwrap(),
            proof: None,
            policy: std::sync::Arc::new(crate::host::policy::AnyMember),
        };
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
        let srv = tokio::spawn(serve_on(server_ep, config));

        let run = async |name: &str, shape: Shape| {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let remote = call_on(
                endpoint(&client).await.unwrap(),
                target.clone(),
                Membership::mint(&root, client.node_id(), 0, i64::MAX).unwrap(),
                None,
                Invocation {
                    tool: ToolName::new(name).unwrap(),
                    argv: Argv::default(),
                },
                std::io::Cursor::new(Vec::new()),
                &mut stdout,
                &mut stderr,
            )
            .await
            .unwrap();
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
        srv.abort();
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
}

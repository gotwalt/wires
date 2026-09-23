//! `wires call`: run one remote CLI from `tools.json`, as if it were local.
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
use library::{
    Argv, CapabilityTicket, Grant, InclusionProof, Invocation, Membership, NodeId, NodeIdentity,
    ToolName,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::admin::keystore;
use crate::caller::tools::{RemoteTool, ToolTarget, ToolsConfig, tool_from_scope};
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
    /// The ticket's grant, for a scoped session; `None` when inclusion-only.
    pub grant: Option<Grant>,
    /// Inclusion-only session: verify the responder's ack before sending stdin.
    pub ticketless: bool,
    /// The remote tool name plus the per-call argv.
    pub invocation: Invocation,
}

impl Dial {
    /// Resolve `tool` into a dial plan carrying `argv`.
    ///
    /// The remote tool name is the entry's explicit `remote_tool`; else, for a
    /// ticket scoped `tool:<x>`, `x`; else the local name.
    pub fn resolve(tool: &RemoteTool, argv: Argv) -> Result<Self> {
        let (target, addrs, relay_url, grant, scoped) = match &tool.target {
            ToolTarget::Ticket(text) => {
                let t = CapabilityTicket::decode(text).with_context(|| {
                    format!(
                        "tool `{}`: its ticket in tools.json does not decode",
                        tool.name
                    )
                })?;
                let scoped = tool_from_scope(&t.scope);
                (t.target, t.addrs, t.relay_url, Some(t.grant), scoped)
            }
            ToolTarget::Node {
                node,
                relay_url,
                addrs,
            } => (*node, addrs.clone(), relay_url.clone(), None, None),
        };
        let remote: ToolName = tool
            .remote_tool
            .clone()
            .or(scoped)
            .unwrap_or_else(|| tool.name.clone());
        Ok(Self {
            target,
            addrs,
            relay_url,
            ticketless: grant.is_none(),
            grant,
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
/// Runs the same local preflight as the topic commands first, so a ticket or
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
    crate::admin::keystore::preflight(creds.node.node_id(), &creds.membership, plan.grant.as_ref())
        .map_err(anyhow::Error::msg)?;
    let relay = creds.relay_override.clone().or(plan.relay_url);
    let target = transport::endpoint_addr(&plan.target, &plan.addrs, relay.as_deref())?;
    let endpoint = transport::bind(&creds.node, relay.as_deref()).await?;
    transport::call_on(
        endpoint,
        target,
        creds.membership.clone(),
        plan.grant,
        creds.proof.clone(),
        plan.ticketless,
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
#[derive(Args, Clone, Debug, Default)]
pub struct CredArgs {
    /// Use this file instead of `$WIRES_HOME/tools.json`.
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

/// `wires call <tool> [-- args…]`.
#[derive(Args)]
pub struct CallArgs {
    #[command(flatten)]
    pub creds: CredArgs,
    /// The tool's local name in `tools.json`.
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
pub async fn call_cmd(a: CallArgs) -> Result<i32> {
    let config = ToolsConfig::load(&crate::caller::tools::resolve_path(
        a.creds.tools_file.as_deref(),
    )?)?;
    let tool = lookup(&config, &a.tool)?;
    let argv = Argv::new(a.args).context("arguments")?;
    let plan = Dial::resolve(tool, argv)?;
    let creds = Credentials::resolve(&a.creds)?;
    dial(
        &creds,
        plan,
        tokio::io::stdin(),
        tokio::io::stdout(),
        tokio::io::stderr(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caller::tools::tests::ticket;
    use clap::Parser;
    use library::Scope;

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
    fn node_target_is_ticketless_and_keeps_the_local_name() {
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
        assert!(d.ticketless);
        assert!(d.grant.is_none());
        assert_eq!(d.target, node());
        assert_eq!(d.addrs, vec![addr]);
        assert_eq!(d.relay_url.as_deref(), Some("https://relay.example"));
        assert_eq!(d.invocation.tool.as_str(), "local");
        assert_eq!(d.invocation.argv.as_slice(), ["x"]);
    }

    #[test]
    fn tool_scoped_ticket_defaults_the_remote_name() {
        let t = tool(ToolTarget::Ticket(ticket("tool:db_query")), None);
        let d = Dial::resolve(&t, Argv::default()).unwrap();
        assert!(!d.ticketless);
        assert_eq!(d.grant.as_ref().unwrap().scope, Scope::new("tool:db_query"));
        assert_eq!(d.invocation.tool.as_str(), "db_query");
    }

    #[test]
    fn explicit_remote_name_wins_over_the_scope() {
        let t = tool(ToolTarget::Ticket(ticket("tool:db_query")), Some("psql"));
        let d = Dial::resolve(&t, Argv::default()).unwrap();
        assert_eq!(d.invocation.tool.as_str(), "psql");
    }

    #[test]
    fn other_scopes_fall_back_to_the_local_name() {
        let t = tool(ToolTarget::Ticket(ticket("tools.rg")), None);
        let d = Dial::resolve(&t, Argv::default()).unwrap();
        assert_eq!(d.invocation.tool.as_str(), "local");
    }

    #[test]
    fn undecodable_ticket_names_the_tool() {
        let t = tool(ToolTarget::Ticket("garbage".into()), None);
        let err = Dial::resolve(&t, Argv::default()).unwrap_err();
        assert!(format!("{err:#}").contains("tool `local`"), "{err:#}");
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
            tools: vec![tool(ToolTarget::Ticket(ticket("tools.rg")), None)],
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

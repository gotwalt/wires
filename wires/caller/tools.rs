//! The caller's local map of remote CLIs: `$WIRES_HOME/tools.json`.
//!
//! Shared by `wires call <tool> [args…]` (the CLI-native path an agent drives
//! from its shell) and `wires mcp` (the stdio MCP server that exposes the same
//! entries as MCP tools). Each entry names a tool, says what it does, and says
//! where it lives — a capability ticket, or a bare responder node id plus
//! optional relay — so the caller dials by public key and never by host.
//!
//! ```json
//! {
//!   "audit_topic": "ops",
//!   "tools": [
//!     {
//!       "name": "db_query",
//!       "description": "Read-only SQL against the orders database",
//!       "target": { "ticket": "…" },
//!       "remote_tool": "db_query"
//!     }
//!   ]
//! }
//! ```
//!
//! `wires tools add|list|rm` edit the file; hand edits are fine too, since
//! [`ToolsConfig::load`] re-validates everything it reads.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{ArgGroup, Args, Subcommand};
use library::{CapabilityTicket, NodeId, Scope, ToolName, TopicTicket};
use serde::{Deserialize, Serialize};

/// The file name under `$WIRES_HOME`.
pub const TOOLS_FILE: &str = "tools.json";

/// The scope prefix that names a single exposed tool (`tool:<name>`). A ticket
/// scoped this way defaults its entry's [`RemoteTool::remote_tool`] to `<name>`.
pub const TOOL_SCOPE_PREFIX: &str = "tool:";

/// Where a remote tool's responder is reached.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolTarget {
    /// A capability ticket (target, scope, grant, address hints).
    Ticket(String),
    /// A bare responder node id; inclusion-only session, optional relay.
    Node {
        /// The responder's node id.
        node: NodeId,
        /// A self-hosted relay to dial through instead of the n0 default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay_url: Option<String>,
        /// Direct socket addresses where the responder is reachable, so the
        /// dialer needs no discovery (the node-target analogue of a ticket's
        /// address hints).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        addrs: Vec<SocketAddr>,
    },
}

/// One remote CLI the caller can invoke.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RemoteTool {
    /// The local name (`wires call <name>`, and the MCP tool name).
    pub name: ToolName,
    /// One line for humans and for the MCP `description`.
    pub description: String,
    /// Where the responder lives.
    pub target: ToolTarget,
    /// The name the responder exposes it under, when different from `name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_tool: Option<ToolName>,
}

impl RemoteTool {
    /// One short line saying where this tool lives, for `wires tools list`.
    pub fn target_summary(&self) -> String {
        match &self.target {
            ToolTarget::Ticket(text) => match CapabilityTicket::decode(text) {
                Ok(t) => format!(
                    "ticket → {} (scope {})",
                    short(&t.target.hex()),
                    t.scope.as_str()
                ),
                Err(_) => "ticket (undecodable)".to_string(),
            },
            ToolTarget::Node { node, .. } => format!("node → {}", short(&node.hex())),
        }
    }
}

/// The first 16 hex chars of a node id: enough to tell nodes apart in a list.
fn short(hex: &str) -> &str {
    &hex[..hex.len().min(16)]
}

/// The tool a `tool:<x>` scope names, if `scope` has that shape and `x` is a
/// valid [`ToolName`].
pub fn tool_from_scope(scope: &Scope) -> Option<ToolName> {
    scope
        .as_str()
        .strip_prefix(TOOL_SCOPE_PREFIX)
        .and_then(|x| ToolName::new(x).ok())
}

/// The whole `tools.json`.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ToolsConfig {
    /// The channel responders log these calls to, surfaced by `wires mcp`'s
    /// observation tool. Informational: the responder, not the caller,
    /// decides where its log goes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_topic: Option<String>,
    /// The tools, in display order.
    #[serde(default)]
    pub tools: Vec<RemoteTool>,
}

impl ToolsConfig {
    /// `$WIRES_HOME/tools.json`.
    pub fn path(home: &Path) -> PathBuf {
        home.join(TOOLS_FILE)
    }

    /// Load from `path`; a missing file is an empty config. Duplicate names
    /// are an error.
    pub fn load(path: &Path) -> Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let config: Self =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        config
            .validate()
            .with_context(|| format!("validating {}", path.display()))?;
        Ok(config)
    }

    /// Check the invariants [`load`](Self::load) enforces: every name unique.
    /// (Names and remote names are already valid [`ToolName`]s by type.)
    pub fn validate(&self) -> Result<()> {
        let mut seen = BTreeSet::new();
        for tool in &self.tools {
            if !seen.insert(&tool.name) {
                bail!("duplicate tool name `{}`", tool.name);
            }
        }
        Ok(())
    }

    /// Validate, then write to `path` as pretty JSON (via a temp file and a
    /// rename, so a crash never leaves a half-written config). Creates the
    /// parent directory if needed.
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let mut json = serde_json::to_string_pretty(self)?;
        json.push('\n');
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    }

    /// Append `tool`; an error if its name is already taken.
    pub fn add(&mut self, tool: RemoteTool) -> Result<()> {
        if self.get(&tool.name).is_some() {
            bail!(
                "a tool named `{}` already exists (remove it first with `wires tools rm {}`)",
                tool.name,
                tool.name
            );
        }
        self.tools.push(tool);
        Ok(())
    }

    /// Remove and return the entry named `name`, if any.
    pub fn remove(&mut self, name: &ToolName) -> Option<RemoteTool> {
        let at = self.tools.iter().position(|t| &t.name == name)?;
        Some(self.tools.remove(at))
    }

    /// The entry named `name`, if any.
    pub fn get(&self, name: &ToolName) -> Option<&RemoteTool> {
        self.tools.iter().find(|t| &t.name == name)
    }
}

/// Resolve the tools file: an explicit `--tools-file`, else
/// `$WIRES_HOME/tools.json`.
pub fn resolve_path(explicit: Option<&Path>) -> Result<PathBuf> {
    match explicit {
        Some(p) => Ok(p.to_path_buf()),
        None => Ok(ToolsConfig::path(&crate::admin::keystore::home()?)),
    }
}

/// `wires tools`: list the tools the hosts on your channel let you run, or
/// edit the local aliases in `tools.json`.
#[derive(Args)]
pub struct ToolsArgs {
    /// Use this file instead of `$WIRES_HOME/tools.json`.
    #[arg(long, global = true)]
    pub tools_file: Option<PathBuf>,
    /// None: list what the channel's hosts announce to you (card 15), then
    /// your aliases.
    #[command(subcommand)]
    pub cmd: Option<ToolsCmd>,
}

/// The `wires tools` alias operations (optional: the channel's host
/// announcements are the directory; an alias pins a name by hand).
#[derive(Subcommand)]
pub enum ToolsCmd {
    /// Add an alias: a remote tool reached by ticket, by responder node id, or
    /// by the responder's audit-topic ticket.
    Add(ToolsAddArgs),
    /// List the aliases in `tools.json`, one per line.
    List,
    /// Remove a tool by name.
    Rm {
        /// The local tool name to remove.
        name: String,
    },
}

/// `wires tools add`: a name, a description, and where the responder lives.
#[derive(Args)]
#[command(group(ArgGroup::new("where").required(true).args(["ticket", "node", "topic_ticket"])))]
pub struct ToolsAddArgs {
    /// The local tool name (`wires call <name>`, and the MCP tool name).
    pub name: String,
    /// A base64 capability ticket for the responder (scoped session).
    #[arg(long)]
    pub ticket: Option<String>,
    /// The responder's hex node id (inclusion-only session, no grant).
    #[arg(long)]
    pub node: Option<String>,
    /// The topic ticket a `serve --audit-topic` responder prints at startup
    /// (`share to bootstrap: …`). Its one peer entry *is* the responder, so
    /// this fills `--node`, its addresses, and its relay — and names the
    /// audit topic in `tools.json` if none is set yet.
    #[arg(long)]
    pub topic_ticket: Option<String>,
    /// Relay to reach a `--node` responder through.
    #[arg(long, requires = "node")]
    pub relay_url: Option<String>,
    /// Direct socket address of a `--node` responder. Repeatable.
    #[arg(long = "addr", requires = "node")]
    pub addr: Vec<SocketAddr>,
    /// One line saying what the tool does (shown to agents).
    #[arg(long)]
    pub description: String,
    /// The name the responder exposes it under, when different from `name`.
    #[arg(long)]
    pub remote_tool: Option<String>,
}

/// `wires tools`: with no subcommand, the channel directory (see
/// [`crate::caller::resolve`]); else [`run_tools_cmd`].
pub async fn tools_cmd(a: ToolsArgs) -> Result<String> {
    if a.cmd.is_some() {
        return run_tools_cmd(a);
    }
    let path = resolve_path(a.tools_file.as_deref())?;
    let config = ToolsConfig::load(&path)?;
    crate::caller::resolve::list_cmd(&config).await
}

/// Run a `wires tools` alias subcommand against the tools file; returns what
/// to print on stdout (possibly empty).
pub fn run_tools_cmd(a: ToolsArgs) -> Result<String> {
    let path = resolve_path(a.tools_file.as_deref())?;
    let mut config = ToolsConfig::load(&path)?;
    let Some(cmd) = a.cmd else {
        bail!("`wires tools` with no subcommand reads the channel (tools_cmd)");
    };
    match cmd {
        ToolsCmd::List => Ok(render_list(&config)),
        ToolsCmd::Rm { name } => {
            let name = ToolName::new(name)?;
            if config.remove(&name).is_none() {
                bail!("no tool named `{name}` in {}", path.display());
            }
            config.save(&path)?;
            Ok(format!("removed {name}"))
        }
        ToolsCmd::Add(add) => {
            let (tool, audit_topic) = remote_tool_from_args(add)?;
            let line = format!("added {} ({})", tool.name, tool.target_summary());
            config.add(tool)?;
            if config.audit_topic.is_none() {
                config.audit_topic = audit_topic;
            }
            config.save(&path)?;
            Ok(line)
        }
    }
}

/// Build (and validate) the entry `wires tools add` describes, plus the audit
/// topic a `--topic-ticket` names. A ticket must decode; a node id must be
/// valid hex.
fn remote_tool_from_args(a: ToolsAddArgs) -> Result<(RemoteTool, Option<String>)> {
    let mut audit_topic = None;
    let target = match (a.ticket, a.node, a.topic_ticket) {
        (Some(ticket), None, None) => {
            CapabilityTicket::decode(&ticket)
                .context("--ticket (is the pasted base64 ticket complete?)")?;
            ToolTarget::Ticket(ticket)
        }
        (None, Some(node), None) => ToolTarget::Node {
            node: NodeId::from_hex(&node).context("--node")?,
            relay_url: a.relay_url,
            addrs: a.addr,
        },
        (None, None, Some(text)) => {
            let (target, topic) = target_from_topic_ticket(&text)?;
            audit_topic = Some(topic);
            target
        }
        _ => bail!("pass exactly one of --ticket, --node, or --topic-ticket"),
    };
    let tool = RemoteTool {
        name: ToolName::new(a.name).context("tool name")?,
        description: a.description,
        target,
        remote_tool: a
            .remote_tool
            .map(ToolName::new)
            .transpose()
            .context("--remote-tool")?,
    };
    Ok((tool, audit_topic))
}

/// The node target a responder's audit-topic ticket describes, and the
/// topic's name.
///
/// A responder's ticket (`share to bootstrap: …`) carries exactly one peer —
/// the responder itself, with the addresses and relay it is reachable at. A
/// ticket with several peers (hand-built, or a future multi-peer share) does
/// not say which of them runs the tool, so it is refused rather than guessed
/// at; pass `--node` for one of them instead.
pub fn target_from_topic_ticket(text: &str) -> Result<(ToolTarget, String)> {
    let ticket = TopicTicket::decode(text.trim())
        .context("--topic-ticket (is the pasted base64 ticket complete?)")?;
    let peer = match ticket.peers.as_slice() {
        [peer] => peer.clone(),
        [] => bail!(
            "--topic-ticket for {:?} names no peer; use the ticket the responder printed",
            ticket.name
        ),
        many => bail!(
            "--topic-ticket for {:?} names {} peers, so it does not say which one is the \
             responder; pass `--node <id>` for it instead ({})",
            ticket.name,
            many.len(),
            many.iter()
                .map(|p| p.node.hex())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    Ok((
        ToolTarget::Node {
            node: peer.node,
            relay_url: peer.relay_url,
            addrs: peer.addrs,
        },
        ticket.name,
    ))
}

/// `wires tools list` output: `name<TAB>target<TAB>description`, config order.
/// The aliases, for the end of `wires tools`: `name  alias: …  description`.
pub(crate) fn render_aliases(config: &ToolsConfig) -> String {
    config
        .tools
        .iter()
        .map(|t| {
            format!(
                "{}  alias: {}  {}",
                t.name,
                t.target_summary(),
                t.description
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_list(config: &ToolsConfig) -> String {
    config
        .tools
        .iter()
        .map(|t| format!("{}\t{}\t{}", t.name, t.target_summary(), t.description))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use library::{Grant, NodeIdentity};
    use proptest::prelude::*;

    /// A decodable ticket for `scope`, issued to a throwaway subject.
    pub(crate) fn ticket(scope: &str) -> String {
        let root = NodeIdentity::from_seed([1; 32]);
        let subject = NodeIdentity::from_seed([2; 32]).node_id();
        let target = NodeIdentity::from_seed([3; 32]).node_id();
        let grant = Grant::mint(&root, subject, Scope::new(scope), i64::MAX).unwrap();
        CapabilityTicket::new(target, Scope::new(scope), grant)
            .encode()
            .unwrap()
    }

    fn node_tool(name: &str) -> RemoteTool {
        RemoteTool {
            name: ToolName::new(name).unwrap(),
            description: format!("{name} does things"),
            target: ToolTarget::Node {
                node: NodeIdentity::from_seed([4; 32]).node_id(),
                relay_url: None,
                addrs: vec![],
            },
            remote_tool: None,
        }
    }

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wires-tools-{tag}-{}-{}",
            std::process::id(),
            crate::now_unix()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join(TOOLS_FILE)
    }

    #[test]
    fn missing_file_is_empty() {
        let path = tmp("missing");
        assert_eq!(ToolsConfig::load(&path).unwrap(), ToolsConfig::default());
    }

    #[test]
    fn parses_the_documented_example() {
        let json = format!(
            r#"{{"audit_topic":"ops","tools":[{{"name":"db_query","description":"SQL",
                "target":{{"ticket":"{}"}},"remote_tool":"db_query"}}]}}"#,
            ticket("tool:db_query")
        );
        let c: ToolsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c.audit_topic.as_deref(), Some("ops"));
        assert_eq!(c.tools[0].name.as_str(), "db_query");
        assert!(matches!(c.tools[0].target, ToolTarget::Ticket(_)));
    }

    #[test]
    fn node_target_json_shape() {
        let t = node_tool("rg");
        let v = serde_json::to_value(&t.target).unwrap();
        assert!(v["node"]["node"].is_string(), "{v}");
        assert!(v["node"].get("relay_url").is_none(), "omits empty relay");
        assert!(v["node"].get("addrs").is_none(), "omits empty addrs");
    }

    #[test]
    fn duplicate_names_are_rejected_on_load() {
        let path = tmp("dup");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let c = ToolsConfig {
            audit_topic: None,
            tools: vec![node_tool("rg"), node_tool("rg")],
        };
        std::fs::write(&path, serde_json::to_string(&c).unwrap()).unwrap();
        let err = ToolsConfig::load(&path).unwrap_err();
        assert!(
            format!("{err:#}").contains("duplicate tool name `rg`"),
            "{err:#}"
        );
    }

    #[test]
    fn invalid_names_are_rejected_on_load() {
        let path = tmp("badname");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut v = serde_json::to_value(ToolsConfig {
            audit_topic: None,
            tools: vec![node_tool("rg")],
        })
        .unwrap();
        v["tools"][0]["name"] = "Not Valid".into();
        std::fs::write(&path, v.to_string()).unwrap();
        assert!(ToolsConfig::load(&path).is_err());
    }

    #[test]
    fn add_refuses_a_taken_name_and_remove_returns_it() {
        let mut c = ToolsConfig::default();
        c.add(node_tool("rg")).unwrap();
        assert!(c.add(node_tool("rg")).is_err());
        let rg = ToolName::new("rg").unwrap();
        assert_eq!(c.remove(&rg).unwrap().name, rg);
        assert!(c.remove(&rg).is_none());
    }

    #[test]
    fn save_then_load_round_trips() {
        let path = tmp("save");
        let c = ToolsConfig {
            audit_topic: Some("ops".into()),
            tools: vec![
                node_tool("rg"),
                RemoteTool {
                    remote_tool: Some(ToolName::new("psql").unwrap()),
                    target: ToolTarget::Ticket(ticket("tool:psql")),
                    ..node_tool("db_query")
                },
            ],
        };
        c.save(&path).unwrap();
        assert_eq!(ToolsConfig::load(&path).unwrap(), c);
    }

    #[test]
    fn tool_scope_names_a_tool() {
        assert_eq!(
            tool_from_scope(&Scope::new("tool:db_query")),
            Some(ToolName::new("db_query").unwrap())
        );
        assert_eq!(tool_from_scope(&Scope::new("tools.rg")), None);
        assert_eq!(tool_from_scope(&Scope::new("tool:Bad Name")), None);
    }

    #[test]
    fn cli_add_list_rm() {
        let path = tmp("cli");
        let run = |cmd: ToolsCmd| {
            run_tools_cmd(ToolsArgs {
                tools_file: Some(path.clone()),
                cmd: Some(cmd),
            })
        };
        let add = |name: &str| ToolsAddArgs {
            name: name.into(),
            ticket: Some(ticket("tool:rg")),
            node: None,
            topic_ticket: None,
            relay_url: None,
            addr: vec![],
            description: "search".into(),
            remote_tool: None,
        };
        assert!(
            run(ToolsCmd::Add(add("rg")))
                .unwrap()
                .starts_with("added rg")
        );
        assert!(run(ToolsCmd::Add(add("rg"))).is_err(), "duplicate add");
        assert!(run(ToolsCmd::Add(add("Bad"))).is_err(), "invalid name");
        let bad_ticket = ToolsAddArgs {
            ticket: Some("not-a-ticket".into()),
            ..add("other")
        };
        assert!(run(ToolsCmd::Add(bad_ticket)).is_err());
        let list = run(ToolsCmd::List).unwrap();
        assert!(list.starts_with("rg\tticket → "), "{list}");
        assert!(list.ends_with("\tsearch"), "{list}");
        assert_eq!(
            run(ToolsCmd::Rm { name: "rg".into() }).unwrap(),
            "removed rg"
        );
        assert_eq!(run(ToolsCmd::List).unwrap(), "");
        assert!(run(ToolsCmd::Rm { name: "rg".into() }).is_err());
    }

    /// A responder's audit-topic ticket, as `serve --audit-topic` prints it.
    fn topic_ticket(peers: Vec<library::TopicPeer>) -> String {
        TopicTicket::new(NodeIdentity::from_seed([1; 32]).node_id(), "ops", peers)
            .encode()
            .unwrap()
    }

    /// Card 11: `tools add --topic-ticket` fills the node target from the
    /// ticket's one peer, and names the audit topic.
    #[test]
    fn add_from_a_topic_ticket_fills_node_addrs_and_relay() {
        let path = tmp("topicticket");
        let responder = NodeIdentity::from_seed([9; 32]).node_id();
        let addr: SocketAddr = "127.0.0.1:4242".parse().unwrap();
        let text = topic_ticket(vec![
            library::TopicPeer::new(responder)
                .with_addrs(vec![addr])
                .with_relay_url(Some("https://relay.example".into())),
        ]);
        let out = run_tools_cmd(ToolsArgs {
            tools_file: Some(path.clone()),
            cmd: Some(ToolsCmd::Add(ToolsAddArgs {
                name: "db_query".into(),
                ticket: None,
                node: None,
                topic_ticket: Some(format!("{text}\n")),
                relay_url: None,
                addr: vec![],
                description: "SQL".into(),
                remote_tool: None,
            })),
        })
        .unwrap();
        assert!(out.starts_with("added db_query (node → "), "{out}");
        let config = ToolsConfig::load(&path).unwrap();
        assert_eq!(
            config.tools[0].target,
            ToolTarget::Node {
                node: responder,
                relay_url: Some("https://relay.example".into()),
                addrs: vec![addr],
            }
        );
        assert_eq!(config.audit_topic.as_deref(), Some("ops"));
    }

    #[test]
    fn a_topic_ticket_must_name_exactly_one_peer() {
        let one = NodeIdentity::from_seed([9; 32]).node_id();
        let two = NodeIdentity::from_seed([10; 32]).node_id();
        let err = target_from_topic_ticket(&topic_ticket(vec![])).unwrap_err();
        assert!(format!("{err:#}").contains("names no peer"), "{err:#}");
        let err = target_from_topic_ticket(&topic_ticket(vec![
            library::TopicPeer::new(one),
            library::TopicPeer::new(two),
        ]))
        .unwrap_err();
        assert!(format!("{err:#}").contains("--node"), "{err:#}");
        assert!(target_from_topic_ticket("not-a-ticket").is_err());
    }

    /// The flag parses, and is exclusive with the other two ways to name the
    /// responder.
    #[test]
    fn topic_ticket_is_one_of_the_three_targets() {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            add: ToolsAddArgs,
        }
        let text = topic_ticket(vec![library::TopicPeer::new(
            NodeIdentity::from_seed([9; 32]).node_id(),
        )]);
        let ok = Cli::try_parse_from([
            "t",
            "db_query",
            "--topic-ticket",
            &text,
            "--description",
            "SQL",
        ])
        .unwrap();
        assert_eq!(ok.add.topic_ticket.as_deref(), Some(text.as_str()));
        let hex = NodeIdentity::from_seed([9; 32]).node_id().hex();
        assert!(
            Cli::try_parse_from([
                "t",
                "db_query",
                "--topic-ticket",
                &text,
                "--node",
                &hex,
                "--description",
                "SQL",
            ])
            .is_err(),
            "--topic-ticket and --node conflict"
        );
    }

    fn arb_tool() -> impl Strategy<Value = RemoteTool> {
        (
            "[a-z][a-z0-9_-]{0,12}",
            ".{0,40}",
            proptest::option::of("[a-z][a-z0-9_]{0,8}"),
            any::<[u8; 32]>(),
            proptest::option::of("https://[a-z]{1,8}\\.example"),
        )
            .prop_map(|(name, description, remote, seed, relay_url)| RemoteTool {
                name: ToolName::new(name).unwrap(),
                description,
                target: ToolTarget::Node {
                    node: NodeIdentity::from_seed(seed).node_id(),
                    relay_url,
                    addrs: vec![],
                },
                remote_tool: remote.map(|r| ToolName::new(r).unwrap()),
            })
    }

    proptest! {
        #[test]
        fn config_json_round_trips(
            audit_topic in proptest::option::of("[a-z]{1,8}"),
            tools in proptest::collection::vec(arb_tool(), 0..6),
        ) {
            let c = ToolsConfig { audit_topic, tools };
            let back: ToolsConfig = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
            prop_assert_eq!(back, c);
        }
    }
}

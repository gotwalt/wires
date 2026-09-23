//! The caller's local map of remote CLIs: `$WIRES_HOME/tools.json`.
//!
//! Shared by `wires call <tool> [args…]` (the CLI-native path an agent drives
//! from its shell) and `wires mcp` (the stdio MCP server that exposes the same
//! entries as MCP tools). Each entry names a tool, says what it does, and says
//! where it lives — the responder's node id plus optional address hints and
//! relay — so the caller dials by public key and never by host. The channel's
//! host announcements are the usual directory; an entry here pins a name by
//! hand.
//!
//! ```json
//! {
//!   "audit_topic": "ops",
//!   "tools": [
//!     {
//!       "name": "db_query",
//!       "description": "Read-only SQL against the orders database",
//!       "target": { "node": { "node": "<64 hex chars>" } },
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
use clap::{Args, Subcommand};
use library::{NodeId, ToolName};
use serde::{Deserialize, Serialize};

/// The file name under `$WIRES_HOME`.
pub const TOOLS_FILE: &str = "tools.json";

/// Where a remote tool's responder is reached.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolTarget {
    /// The responder's node id, with optional relay and address hints.
    Node {
        /// The responder's node id.
        node: NodeId,
        /// A self-hosted relay to dial through instead of the n0 default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay_url: Option<String>,
        /// Direct socket addresses where the responder is reachable, so the
        /// dialer needs no discovery.
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
        let ToolTarget::Node { node, .. } = &self.target;
        format!("node → {}", short(&node.hex()))
    }
}

/// The first 16 hex chars of a node id: enough to tell nodes apart in a list.
fn short(hex: &str) -> &str {
    &hex[..hex.len().min(16)]
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
    /// Locked caller mode (card 20): when `true` in `$WIRES_HOME/tools.json`,
    /// `wires call` and `wires mcp` refuse every flag that would steer them
    /// off this configuration. Only the default file is consulted (see
    /// [`crate::caller::lock`]); the operator sets it, and makes the file
    /// read-only to the agent.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub locked: bool,
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
    /// Add an alias: a remote tool reached by its responder's node id.
    Add(ToolsAddArgs),
    /// List the aliases in `tools.json`, one per line, then a `#` line on
    /// how to call and filter them.
    List,
    /// Remove a tool by name.
    Rm {
        /// The local tool name to remove.
        name: String,
    },
}

/// `wires tools add`: a name, a description, and where the responder lives.
#[derive(Args)]
pub struct ToolsAddArgs {
    /// The local tool name (`wires call <name>`, and the MCP tool name).
    pub name: String,
    /// The responder's hex node id.
    #[arg(long)]
    pub node: String,
    /// Relay to reach the responder through.
    #[arg(long)]
    pub relay_url: Option<String>,
    /// Direct socket address of the responder. Repeatable.
    #[arg(long = "addr")]
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
            let tool = remote_tool_from_args(add)?;
            let line = format!("added {} ({})", tool.name, tool.target_summary());
            config.add(tool)?;
            config.save(&path)?;
            Ok(line)
        }
    }
}

/// Build (and validate) the entry `wires tools add` describes: the node id
/// must be valid hex, the names valid [`ToolName`]s.
fn remote_tool_from_args(a: ToolsAddArgs) -> Result<RemoteTool> {
    Ok(RemoteTool {
        name: ToolName::new(a.name).context("tool name")?,
        description: a.description,
        target: ToolTarget::Node {
            node: NodeId::from_hex(&a.node).context("--node")?,
            relay_url: a.relay_url,
            addrs: a.addr,
        },
        remote_tool: a
            .remote_tool
            .map(ToolName::new)
            .transpose()
            .context("--remote-tool")?,
    })
}

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

/// `wires tools list` output: `name<TAB>target<TAB>description`, config
/// order, then (if there are any) [`CALL_HINT`](crate::caller::shape::CALL_HINT)
/// as a `#` line, so an agent without a shell learns how to filter.
fn render_list(config: &ToolsConfig) -> String {
    let mut lines: Vec<String> = config
        .tools
        .iter()
        .map(|t| format!("{}\t{}\t{}", t.name, t.target_summary(), t.description))
        .collect();
    if !lines.is_empty() {
        lines.push(format!("# {}", crate::caller::shape::CALL_HINT));
    }
    lines.join("\n")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use library::NodeIdentity;
    use proptest::prelude::*;

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
                "target":{{"node":{{"node":"{}"}}}},"remote_tool":"db_query"}}]}}"#,
            "ab".repeat(32)
        );
        let c: ToolsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c.audit_topic.as_deref(), Some("ops"));
        assert_eq!(c.tools[0].name.as_str(), "db_query");
        assert!(matches!(c.tools[0].target, ToolTarget::Node { .. }));
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
            locked: false,
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
            locked: false,
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
                    ..node_tool("db_query")
                },
            ],
            locked: true,
        };
        c.save(&path).unwrap();
        assert_eq!(ToolsConfig::load(&path).unwrap(), c);
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
            node: NodeIdentity::from_seed([3; 32]).node_id().hex(),
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
        let bad_node = ToolsAddArgs {
            node: "not-hex".into(),
            ..add("other")
        };
        assert!(run(ToolsCmd::Add(bad_node)).is_err());
        let list = run(ToolsCmd::List).unwrap();
        assert!(list.starts_with("rg\tnode → "), "{list}");
        assert!(list.lines().next().unwrap().ends_with("\tsearch"), "{list}");
        assert!(list.ends_with(&format!("\n# {}", crate::caller::shape::CALL_HINT)));
        assert_eq!(
            run(ToolsCmd::Rm { name: "rg".into() }).unwrap(),
            "removed rg"
        );
        assert_eq!(run(ToolsCmd::List).unwrap(), "");
        assert!(run(ToolsCmd::Rm { name: "rg".into() }).is_err());
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
            locked in any::<bool>(),
        ) {
            let c = ToolsConfig { audit_topic, tools, locked };
            let back: ToolsConfig = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
            prop_assert_eq!(back, c);
        }
    }
}

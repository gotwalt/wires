//! The caller's local config: `$WIRES_HOME/tools.json`.
//!
//! It holds the operator's locked-mode switch ([`crate::caller::lock`]) and,
//! optionally, **aliases**: a local name pinned to one host, by node id plus
//! optional address hints and relay. Services from the signed state are the
//! usual way to call (`wires services`); an alias is for pinning a service to
//! one host by hand. Either way the session opens with the same `Hello`, and
//! the host decides by its signed state (the alias's `remote_tool` is the
//! service name it asks for). Shared by `wires call` and `wires mcp`.
//!
//! ```json
//! {
//!   "tools": [
//!     {
//!       "name": "orders",
//!       "description": "Read-only SQL against the orders database",
//!       "target": { "node": { "node": "<64 hex chars>", "addrs": ["10.0.0.5:4433"] } },
//!       "remote_tool": "orders-db"
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
use library::{NodeId, ServiceName};
use serde::{Deserialize, Serialize};

/// The file name under `$WIRES_HOME`.
pub const TOOLS_FILE: &str = "tools.json";

/// Where a [`RemoteTool`]'s host is reached.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolTarget {
    /// One host, pinned by node id, with optional relay and address hints.
    Node {
        /// The host's node id.
        node: NodeId,
        /// A self-hosted relay to dial through instead of the n0 default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay_url: Option<String>,
        /// Direct socket addresses where the host is reachable, so the
        /// dialer needs no discovery.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        addrs: Vec<SocketAddr>,
    },
    /// A service in this node's signed state (card 27): the host is picked
    /// at call time, never pinned. Built by `wires mcp`, not written to
    /// `tools.json` by any command.
    Service,
}

/// One name the caller can call: a `tools.json` alias, or (built by `wires
/// mcp`) a service from the signed state.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RemoteTool {
    /// The local name (`wires call <name>`, and the MCP tool name).
    pub name: ServiceName,
    /// One line for humans and for the MCP `description`.
    pub description: String,
    /// Where the host is.
    pub target: ToolTarget,
    /// The service to ask the host for, when different from `name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_tool: Option<ServiceName>,
}

impl RemoteTool {
    /// One short line saying where this entry goes, for `wires tools list`.
    pub fn target_summary(&self) -> String {
        match &self.target {
            ToolTarget::Node { node, .. } => format!("node → {}", node.short()),
            ToolTarget::Service => "service".to_string(),
        }
    }
}

/// The whole `tools.json`.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ToolsConfig {
    /// The aliases, in display order.
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
    /// (Names and remote names are already valid [`ServiceName`]s by type.)
    pub fn validate(&self) -> Result<()> {
        let mut seen = BTreeSet::new();
        for tool in &self.tools {
            if !seen.insert(&tool.name) {
                bail!("duplicate alias `{}`", tool.name);
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
                "an alias named `{}` already exists (remove it first with `wires tools rm {}`)",
                tool.name,
                tool.name
            );
        }
        self.tools.push(tool);
        Ok(())
    }

    /// Remove and return the entry named `name`, if any.
    pub fn remove(&mut self, name: &ServiceName) -> Option<RemoteTool> {
        let at = self.tools.iter().position(|t| &t.name == name)?;
        Some(self.tools.remove(at))
    }

    /// The entry named `name`, if any.
    pub fn get(&self, name: &ServiceName) -> Option<&RemoteTool> {
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

/// `wires tools` (hidden): edit the local aliases in `tools.json`.
#[derive(Args)]
pub struct ToolsArgs {
    /// Use this file instead of `$WIRES_HOME/tools.json`.
    #[arg(long, global = true)]
    pub tools_file: Option<PathBuf>,
    /// What to do with the aliases.
    #[command(subcommand)]
    pub cmd: ToolsCmd,
}

/// The `wires tools` alias operations (optional: the signed state's services
/// are the directory; an alias pins a name to one host by hand).
#[derive(Subcommand)]
pub enum ToolsCmd {
    /// Add an alias: a service pinned to one host by its node id.
    Add(ToolsAddArgs),
    /// List the aliases in `tools.json`, one per line, then a `#` line on
    /// how to call and filter them.
    List,
    /// Remove an alias by name.
    Rm {
        /// The alias to remove.
        name: String,
    },
}

/// `wires tools add`: a name, a description, and the host it pins.
#[derive(Args)]
pub struct ToolsAddArgs {
    /// The alias (`wires call <name>`, and the MCP tool name).
    pub name: String,
    /// The host's hex node id.
    #[arg(long)]
    pub node: String,
    /// Relay to reach the host through.
    #[arg(long)]
    pub relay_url: Option<String>,
    /// Direct socket address of the host. Repeatable.
    #[arg(long = "addr")]
    pub addr: Vec<SocketAddr>,
    /// One line saying what it does (shown to agents).
    #[arg(long)]
    pub description: String,
    /// The service to ask the host for, when different from `name`.
    #[arg(long)]
    pub remote_tool: Option<String>,
}

/// Run a `wires tools` alias subcommand against the tools file; returns what
/// to print on stdout (possibly empty).
pub fn run_tools_cmd(a: ToolsArgs) -> Result<String> {
    let path = resolve_path(a.tools_file.as_deref())?;
    let mut config = ToolsConfig::load(&path)?;
    match a.cmd {
        ToolsCmd::List => Ok(render_list(&config)),
        ToolsCmd::Rm { name } => {
            let name = ServiceName::new(name)?;
            if config.remove(&name).is_none() {
                bail!("no alias named `{name}` in {}", path.display());
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
/// must be valid hex, the names valid [`ServiceName`]s.
fn remote_tool_from_args(a: ToolsAddArgs) -> Result<RemoteTool> {
    Ok(RemoteTool {
        name: ServiceName::new(a.name).context("alias name")?,
        description: a.description,
        target: ToolTarget::Node {
            node: NodeId::from_hex(&a.node).context("--node")?,
            relay_url: a.relay_url,
            addrs: a.addr,
        },
        remote_tool: a
            .remote_tool
            .map(ServiceName::new)
            .transpose()
            .context("--remote-tool")?,
    })
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
mod tests {
    use super::*;
    use library::NodeIdentity;
    use proptest::prelude::*;

    fn node_tool(name: &str) -> RemoteTool {
        RemoteTool {
            name: ServiceName::new(name).unwrap(),
            description: format!("{name} does things"),
            target: ToolTarget::Node {
                node: NodeIdentity::from_seed([4; 32]).node_id(),
                relay_url: None,
                addrs: vec![],
            },
            remote_tool: None,
        }
    }

    /// A `tools.json` path in a fresh empty directory.
    fn tmp() -> PathBuf {
        crate::testutil::temp_dir().join(TOOLS_FILE)
    }

    #[test]
    fn missing_file_is_empty() {
        let path = tmp();
        assert_eq!(ToolsConfig::load(&path).unwrap(), ToolsConfig::default());
    }

    #[test]
    fn parses_the_documented_example() {
        let json = format!(
            r#"{{"tools":[{{"name":"db_query","description":"SQL",
                "target":{{"node":{{"node":"{}"}}}},"remote_tool":"db_query"}}]}}"#,
            "ab".repeat(32)
        );
        let c: ToolsConfig = serde_json::from_str(&json).unwrap();
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
        let path = tmp();
        let c = ToolsConfig {
            tools: vec![node_tool("rg"), node_tool("rg")],
            locked: false,
        };
        std::fs::write(&path, serde_json::to_string(&c).unwrap()).unwrap();
        let err = ToolsConfig::load(&path).unwrap_err();
        assert!(
            format!("{err:#}").contains("duplicate alias `rg`"),
            "{err:#}"
        );
    }

    #[test]
    fn invalid_names_are_rejected_on_load() {
        let path = tmp();
        let mut v = serde_json::to_value(ToolsConfig {
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
        let rg = ServiceName::new("rg").unwrap();
        assert_eq!(c.remove(&rg).unwrap().name, rg);
        assert!(c.remove(&rg).is_none());
    }

    #[test]
    fn save_then_load_round_trips() {
        let path = tmp();
        let c = ToolsConfig {
            tools: vec![
                node_tool("rg"),
                RemoteTool {
                    remote_tool: Some(ServiceName::new("psql").unwrap()),
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
        let path = tmp();
        let run = |cmd: ToolsCmd| {
            run_tools_cmd(ToolsArgs {
                tools_file: Some(path.clone()),
                cmd,
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
                name: ServiceName::new(name).unwrap(),
                description,
                target: ToolTarget::Node {
                    node: NodeIdentity::from_seed(seed).node_id(),
                    relay_url,
                    addrs: vec![],
                },
                remote_tool: remote.map(|r| ServiceName::new(r).unwrap()),
            })
    }

    proptest! {
        #[test]
        fn config_json_round_trips(
            tools in proptest::collection::vec(arb_tool(), 0..6),
            locked in any::<bool>(),
        ) {
            let c = ToolsConfig { tools, locked };
            let back: ToolsConfig = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
            prop_assert_eq!(back, c);
        }
    }
}

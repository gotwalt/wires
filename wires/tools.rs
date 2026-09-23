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

use std::path::{Path, PathBuf};

use anyhow::Result;
use library::{NodeId, ToolName};
use serde::{Deserialize, Serialize};

/// The file name under `$WIRES_HOME`.
pub const TOOLS_FILE: &str = "tools.json";

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
        let _ = path;
        todo!("client lane: load and validate tools.json")
    }

    /// The entry named `name`, if any.
    pub fn get(&self, name: &ToolName) -> Option<&RemoteTool> {
        self.tools.iter().find(|t| &t.name == name)
    }
}

//! `wires mcp`: a stdio MCP server whose tools are the services you may call
//! (the entries of your view marked `call`, as `wires services` lists
//! them), plus `tools.json` aliases.
//!
//! The view is followed, not read once (card 37): `wires mcp` holds a
//! `view` subscription with a directory ([`crate::caller::view::follow`]),
//! so a grant or a revocation changes the tool list within seconds, and the
//! client hears `notifications/tools/list_changed` (the server declares
//! `tools.listChanged`). When the view holds more than
//! [`SEARCH_THRESHOLD`] services, `tools/list` offers `search_services` and
//! `call_service` instead of one tool per service, so a large catalog
//! doesn't fill the model's context.
//!
//! wires in the stdio MCP clients people already use (Claude Desktop, IDEs).
//! Each service (or alias) becomes one MCP tool taking `{ args?: string[],
//! stdin?: string, jq?: string, head?: integer, max_bytes?: integer }`; the
//! last three shape the remote stdout in-process
//! ([`shape`](crate::caller::shape)), as `wires call --jq/--head/--max-bytes`
//! do. Calling a tool dials the service's host over wires (through a
//! [`Caller`]) and returns the remote output as one text block. There is no
//! HTTP and no OAuth here: the caller is this node's key and the ID token
//! `wires login` stored, presented in each call's `Hello` as `wires call`
//! does, so the host verifies the same person and keeps the same record.
//!
//! Wire format: newline-delimited JSON-RPC 2.0 on stdin/stdout. **stdout is
//! protocol-only** — every diagnostic goes to stderr. Both eras are served
//! ("dual-era" in the 2026-07-28 versioning page): the legacy handshake
//! (`initialize` → `notifications/initialized`, e.g. `2025-06-18`), and the
//! modern stateless form (no `initialize`; each request names its version in
//! `_meta["io.modelcontextprotocol/protocolVersion"]`, `server/discover`
//! answers up front, an unknown version is an `UnsupportedProtocolVersion`
//! error listing ours).
//!
//! [`McpServer`] is transport-free: `wires gateway` drives the same core
//! over Streamable HTTP, one request at a time
//! ([`crate::gateway::mcp_http`]).

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use library::Argv;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

use crate::caller::call::{CallOutcome, Caller, CredArgs, Credentials, WiresCaller};
use crate::caller::shape::{Shape, ShapeArgs, exit_code};
use crate::caller::tools::{RemoteTool, ToolTarget, ToolsConfig};

/// The newest MCP revision this server speaks (the stateless one).
pub const LATEST_PROTOCOL_VERSION: &str = "2026-07-28";

/// Every revision served, newest first. The surface used here (tools, text
/// content, `isError`) is the same in all of them.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[
    "2026-07-28",
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
];

/// The revisions `initialize` negotiates (the legacy era), newest first.
pub const LEGACY_PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// The first modern revision: no `initialize`, the version in every
/// request's `_meta`, `resultType` on every result.
pub const FIRST_MODERN_VERSION: &str = "2026-07-28";

/// How long a client may cache `tools/list` and `server/discover` results
/// (the 2026-07-28 `ttlMs`). The tool list only changes with the signed
/// state, which a client picks up within this.
pub const LIST_TTL_MS: u64 = 60_000;

/// The server's `instructions`: how to use these tools well.
pub const INSTRUCTIONS: &str = "Each tool runs one command-line program on another machine, by service name, as you: the machine checks your identity against an admin-signed list of who may call it, and logs the call. Pass the program's arguments as `args` (one string per argument, no shell quoting). There is no shell: filter output with the program's own flags or the `jq`/`head`/`max_bytes` fields.";

/// The per-request protocol-version key of the 2026-07-28 revision.
pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";

/// The reserved result `_meta` key identifying the server (2026-07-28).
pub const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

/// Most bytes of remote stdout (and, separately, stderr) placed in a result.
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// Appended to every tool's description: how to cut output down without a
/// shell (board card 19).
pub const FILTER_HINT: &str = "Filter output with the command's own flags (e.g. `gh … --json f --jq …`) or the `jq`/`head`/`max_bytes` fields; there is no shell, so pipes are not available.";

/// The name this server reports in `serverInfo`.
pub const SERVER_NAME: &str = "wires";

/// Past this many services, `tools/list` offers [`SEARCH_TOOL`] and
/// [`CALL_TOOL`] instead of one tool per service (card 37; a guess, to be
/// measured with the token benchmark, card 16).
pub const SEARCH_THRESHOLD: usize = 40;

/// The tool that finds services by name or description, for a view too
/// large to list.
pub const SEARCH_TOOL: &str = "search_services";

/// The tool that calls a service found with [`SEARCH_TOOL`], by name.
pub const CALL_TOOL: &str = "call_service";

/// Most services one [`SEARCH_TOOL`] answer names.
pub const MAX_SEARCH_RESULTS: usize = 20;

/// The notification a server sends when its tool list changed.
pub const LIST_CHANGED: &str = "notifications/tools/list_changed";

/// JSON-RPC: the line was not valid JSON.
pub(crate) const PARSE_ERROR: i64 = -32700;
/// JSON-RPC: valid JSON, but not a request object.
pub(crate) const INVALID_REQUEST: i64 = -32600;
/// JSON-RPC: no such method.
pub(crate) const METHOD_NOT_FOUND: i64 = -32601;
/// JSON-RPC: bad params (including MCP's "unknown tool").
pub(crate) const INVALID_PARAMS: i64 = -32602;
/// MCP `HeaderMismatch` (2026-07-28): HTTP headers disagree with the body.
pub(crate) const HEADER_MISMATCH: i64 = -32020;
/// MCP `UnsupportedProtocolVersion` (2026-07-28).
pub(crate) const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// A JSON-RPC error: code, message, and optional `data`.
#[derive(Debug, PartialEq)]
pub(crate) struct RpcError {
    pub(crate) code: i64,
    pub(crate) message: String,
    pub(crate) data: Option<Value>,
}

impl RpcError {
    pub(crate) fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// `UnsupportedProtocolVersion` for `requested`, listing what is served.
    pub(crate) fn unsupported_version(requested: &str) -> Self {
        Self {
            code: UNSUPPORTED_PROTOCOL_VERSION,
            message: "Unsupported protocol version".into(),
            data: Some(json!({
                "supported": SUPPORTED_PROTOCOL_VERSIONS,
                "requested": requested,
            })),
        }
    }
}

/// Whether `version` is of the modern (stateless) era.
pub(crate) fn is_modern(version: &str) -> bool {
    version >= FIRST_MODERN_VERSION
}

/// The MCP server state: the tool map, the caller that runs tools, and the
/// protocol version agreed by `initialize` (if the client did one).
pub struct McpServer<C> {
    config: ToolsConfig,
    caller: C,
    negotiated: Option<String>,
    redact_failures: bool,
    list_changed: bool,
}

impl<C: Caller> McpServer<C> {
    /// A server exposing `config`'s tools, running them through `caller`.
    pub fn new(config: ToolsConfig, caller: C) -> Self {
        Self {
            config,
            caller,
            negotiated: None,
            redact_failures: false,
            list_changed: false,
        }
    }

    /// Declare `tools.listChanged`: this server tells the client when its
    /// tool list changes ([`serve`] with a view to follow).
    pub fn with_list_changed(mut self) -> Self {
        self.list_changed = true;
        self
    }

    /// Serve `config`'s tools from now on; whether the tool list a client
    /// sees changed.
    pub fn set_tools(&mut self, config: ToolsConfig) -> bool {
        let changed = self.config != config;
        self.config = config;
        changed
    }

    /// Report a failed dial as `call failed` without its details (host ids,
    /// addresses, relay errors), which go to the log instead: for callers
    /// who are not the operator (`wires gateway`'s web users).
    pub fn with_redacted_failures(mut self) -> Self {
        self.redact_failures = true;
        self
    }

    /// Serve as if `initialize` had agreed `version` (a legacy HTTP client
    /// names it in its `MCP-Protocol-Version` header on every request after
    /// the handshake; there is no session to remember it in).
    pub fn with_negotiated(mut self, version: Option<String>) -> Self {
        self.negotiated = version;
        self
    }

    /// Handle one line of input; returns the response line to write, or
    /// `None` for a notification (or a blank line).
    pub async fn handle_line(&mut self, line: &str) -> Option<String> {
        if line.trim().is_empty() {
            return None;
        }
        let response = match serde_json::from_str::<Value>(line) {
            Ok(msg) => self.handle(msg).await?,
            Err(e) => error_response(
                Value::Null,
                RpcError::new(PARSE_ERROR, format!("parse error: {e}")),
            ),
        };
        Some(response.to_string())
    }

    /// Handle one parsed JSON-RPC message; `None` when no reply is due.
    pub async fn handle(&mut self, msg: Value) -> Option<Value> {
        let Value::Object(msg) = msg else {
            return Some(error_response(
                Value::Null,
                RpcError::new(INVALID_REQUEST, "expected a single JSON-RPC request object"),
            ));
        };
        let method = msg.get("method").and_then(Value::as_str);
        let Some(id) = msg.get("id").cloned() else {
            // A notification: never answered, whatever it is.
            if let Some(m) = method {
                tracing::debug!("mcp notification: {m}");
            }
            return None;
        };
        let Some(method) = method else {
            return Some(error_response(
                id,
                RpcError::new(INVALID_REQUEST, "missing method"),
            ));
        };
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        let version = self.version_for(&params);
        if let Some(v) = version.as_deref()
            && !SUPPORTED_PROTOCOL_VERSIONS.contains(&v)
            && method != "initialize"
        {
            return Some(error_response(id, RpcError::unsupported_version(v)));
        }
        let modern = version.as_deref().is_some_and(is_modern);
        let result = match method {
            "server/discover" => Ok(discover()),
            "initialize" => Ok(self.initialize(&params)),
            // Removed in 2026-07-28; still part of every legacy revision.
            "ping" if !modern => Ok(json!({})),
            "tools/list" => Ok(self.tools_list(modern)),
            "tools/call" => self.tools_call(&params).await,
            other => Err(RpcError::new(
                METHOD_NOT_FOUND,
                format!("method not found: {other}"),
            )),
        };
        Some(match result {
            Ok(result) => {
                let version = match method {
                    // `initialize` fixes the version for the session.
                    "initialize" => self.negotiated.clone(),
                    // A discover probe without `_meta` still gets a modern
                    // reply: it is a modern method.
                    "server/discover" => {
                        version.or_else(|| Some(LATEST_PROTOCOL_VERSION.to_owned()))
                    }
                    _ => version,
                };
                json!({"jsonrpc": "2.0", "id": id, "result": stamp(result, version.as_deref())})
            }
            Err(e) => error_response(id, e),
        })
    }

    /// The version a request speaks: its own `_meta` key (stateless form),
    /// else whatever `initialize` agreed, else unknown.
    fn version_for(&self, params: &Value) -> Option<String> {
        params
            .get("_meta")
            .and_then(|m| m.get(META_PROTOCOL_VERSION))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| self.negotiated.clone())
    }

    /// `initialize` (legacy era only): agree the client's version if it is a
    /// legacy one we speak, else offer the newest legacy one. A modern
    /// version can't be agreed here: modern clients don't handshake.
    fn initialize(&mut self, params: &Value) -> Value {
        let requested = params.get("protocolVersion").and_then(Value::as_str);
        let agreed = match requested {
            Some(v) if LEGACY_PROTOCOL_VERSIONS.contains(&v) => v,
            _ => LEGACY_PROTOCOL_VERSIONS[0],
        };
        self.negotiated = Some(agreed.to_owned());
        json!({
            "protocolVersion": agreed,
            "capabilities": {"tools": {"listChanged": self.list_changed}},
            "serverInfo": server_info(),
            "instructions": INSTRUCTIONS,
        })
    }

    /// Whether the services are too many to list one tool each (card 37):
    /// `tools/list` then offers [`SEARCH_TOOL`] and [`CALL_TOOL`].
    fn searching(&self) -> bool {
        self.services().count() > SEARCH_THRESHOLD
    }

    /// The service tools (not the aliases), in order.
    fn services(&self) -> impl Iterator<Item = &RemoteTool> {
        self.config
            .tools
            .iter()
            .filter(|t| t.target == ToolTarget::Service)
    }

    /// `tools/list`: every alias, then every service, in order (stable, so
    /// clients and prompt caches can rely on it); past [`SEARCH_THRESHOLD`]
    /// services, the aliases then [`SEARCH_TOOL`] and [`CALL_TOOL`]. A
    /// modern reply carries the 2026-07-28 cache hints: `private`, since
    /// the list is per caller.
    fn tools_list(&self, modern: bool) -> Value {
        let searching = self.searching();
        let mut tools: Vec<Value> = self
            .config
            .tools
            .iter()
            .filter(|t| !searching || t.target != ToolTarget::Service)
            .map(|t| {
                json!({
                    "name": t.name.as_str(),
                    "description": describe(t),
                    "inputSchema": input_schema(),
                })
            })
            .collect();
        if searching {
            tools.push(search_tool(self.services().count()));
            tools.push(call_tool());
        }
        if modern {
            json!({ "tools": tools, "ttlMs": LIST_TTL_MS, "cacheScope": "private" })
        } else {
            json!({ "tools": tools })
        }
    }

    /// `tools/call`: look the tool up, validate its arguments, run it.
    async fn tools_call(&self, params: &Value) -> Result<Value, RpcError> {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::new(INVALID_PARAMS, "tools/call: missing tool name"))?;
        let mut arguments = params.get("arguments").cloned();
        let listed = |n: &str| self.config.tools.iter().find(|t| t.name.as_str() == n);
        let tool = match (name, listed(name)) {
            (_, Some(tool)) => tool,
            (SEARCH_TOOL, None) if self.searching() => {
                return self.search(arguments.as_ref());
            }
            (CALL_TOOL, None) if self.searching() => {
                let service = take_service(&mut arguments)?;
                self.services()
                    .find(|t| t.name.as_str() == service)
                    .ok_or_else(|| {
                        RpcError::new(
                            INVALID_PARAMS,
                            format!(
                                "no service named `{service}` that you may call \
                                 (find one with `{SEARCH_TOOL}`)"
                            ),
                        )
                    })?
            }
            _ => {
                return Err(RpcError::new(
                    INVALID_PARAMS,
                    format!("unknown tool: {name}"),
                ));
            }
        };
        let (argv, stdin, shape) =
            parse_arguments(arguments.as_ref()).map_err(|m| RpcError::new(INVALID_PARAMS, m))?;
        // A bad jq filter is the model's mistake to fix: a tool error it can
        // read, and nothing is dialed.
        let shape = match Shape::new(&shape) {
            Ok(shape) => shape,
            Err(e) => {
                return Ok(json!({
                    "content": [{"type": "text", "text": format!("wires: {}", e.message())}],
                    "isError": true,
                }));
            }
        };
        let (text, is_error) = match self.caller.call(tool, argv, stdin).await {
            Ok(outcome) => render_outcome(&shaped(&shape, outcome)),
            Err(e) => {
                tracing::warn!("wires mcp: call to `{name}` failed: {e:#}");
                if self.redact_failures {
                    (
                        "wires: call failed: no host of this service could be reached; try again, or ask the operator".to_owned(),
                        true,
                    )
                } else {
                    (format!("wires: call failed: {e:#}"), true)
                }
            }
        };
        Ok(json!({
            "content": [{"type": "text", "text": text}],
            "isError": is_error,
        }))
    }

    /// [`SEARCH_TOOL`]: the services whose name or description contains
    /// `query` (ignoring case), one per line (`name: description`), at most
    /// [`MAX_SEARCH_RESULTS`]. Dials nothing.
    fn search(&self, arguments: Option<&Value>) -> Result<Value, RpcError> {
        let query = arguments
            .and_then(|a| a.get("query"))
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::new(INVALID_PARAMS, "`query` must be a string"))?;
        let needle = query.to_ascii_lowercase();
        let found: Vec<&RemoteTool> = self
            .services()
            .filter(|t| {
                t.name.as_str().to_ascii_lowercase().contains(&needle)
                    || t.description.to_ascii_lowercase().contains(&needle)
            })
            .collect();
        let mut text = found
            .iter()
            .take(MAX_SEARCH_RESULTS)
            .map(|t| {
                format!(
                    "{}: {}",
                    t.name,
                    t.description
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        if found.is_empty() {
            text = format!("no service you may call matches {query:?}");
        } else if found.len() > MAX_SEARCH_RESULTS {
            text.push_str(&format!(
                "\n[{} more; narrow the query]",
                found.len() - MAX_SEARCH_RESULTS
            ));
        }
        Ok(json!({
            "content": [{"type": "text", "text": text}],
            "isError": false,
        }))
    }
}

/// Take `service` out of a [`CALL_TOOL`] call's arguments, leaving the rest
/// for [`parse_arguments`].
fn take_service(arguments: &mut Option<Value>) -> Result<String, RpcError> {
    let missing = || RpcError::new(INVALID_PARAMS, format!("`{CALL_TOOL}` needs `service`"));
    let Some(Value::Object(map)) = arguments else {
        return Err(missing());
    };
    match map.remove("service") {
        Some(Value::String(s)) => Ok(s),
        _ => Err(missing()),
    }
}

/// The [`SEARCH_TOOL`] definition, for a view of `count` services.
fn search_tool(count: usize) -> Value {
    json!({
        "name": SEARCH_TOOL,
        "description": format!(
            "Find services you may call, among {count}, by a word in their name or description; \
             then run one with `{CALL_TOOL}`."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "A word to look for, e.g. `orders`."}
            },
            "required": ["query"],
            "additionalProperties": false
        }
    })
}

/// The [`CALL_TOOL`] definition: a service's name plus the fields every
/// service tool takes.
fn call_tool() -> Value {
    let mut schema = input_schema();
    schema["properties"]["service"] = json!({
        "type": "string",
        "description": format!("The service's name, as `{SEARCH_TOOL}` lists it.")
    });
    schema["required"] = json!(["service"]);
    json!({
        "name": CALL_TOOL,
        "description": format!(
            "Run a service found with `{SEARCH_TOOL}`, by name, as you. {FILTER_HINT}"
        ),
        "inputSchema": schema,
    })
}

/// `server/discover`: every version served, the capabilities, and how to
/// use the tools. The same for every caller, so `public` to caches.
fn discover() -> Value {
    json!({
        "supportedVersions": SUPPORTED_PROTOCOL_VERSIONS,
        "capabilities": {"tools": {}},
        "instructions": INSTRUCTIONS,
        "ttlMs": LIST_TTL_MS,
        "cacheScope": "public",
    })
}

/// `serverInfo`: this binary's name and version.
fn server_info() -> Value {
    json!({"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")})
}

/// For a modern request, stamp `resultType` and the reserved `_meta` keys on
/// the result; legacy revisions get the result untouched.
fn stamp(mut result: Value, version: Option<&str>) -> Value {
    let Some(version) = version.filter(|v| is_modern(v)) else {
        return result;
    };
    if let Value::Object(map) = &mut result {
        map.insert("resultType".into(), "complete".into());
        let mut meta = Map::new();
        meta.insert(META_PROTOCOL_VERSION.into(), version.into());
        meta.insert(META_SERVER_INFO.into(), server_info());
        map.insert("_meta".into(), Value::Object(meta));
    }
    result
}

/// A JSON-RPC error response (`id` is `null` when the request's is unknown).
pub(crate) fn error_response(id: Value, e: RpcError) -> Value {
    let mut error = json!({"code": e.code, "message": e.message});
    if let Some(data) = e.data {
        error["data"] = data;
    }
    json!({"jsonrpc": "2.0", "id": id, "error": error})
}

/// The one input schema every tool shares.
fn input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "The primary way to pass input: arguments appended to the remote command, e.g. the SQL statement. Each element is one argument; no shell quoting is needed."
            },
            "stdin": {
                "type": "string",
                "description": "Secondary: text fed to the remote command's stdin, for input too large or too structured to pass as arguments. Prefer `args` when the command accepts its input that way."
            },
            "jq": {
                "type": "string",
                "description": "Optional jq filter applied to stdout before it is returned (strings print raw, other values as compact JSON). Prefer the command's own filter flags when it has them."
            },
            "head": {
                "type": "integer",
                "minimum": 0,
                "description": "Optional: keep only the first N lines of stdout (after `jq`)."
            },
            "max_bytes": {
                "type": "integer",
                "minimum": 0,
                "description": "Optional: keep at most N bytes of stdout (after `jq` and `head`)."
            }
        },
        "additionalProperties": false
    })
}

/// The MCP description for `tool`: its own line, then [`FILTER_HINT`].
fn describe(tool: &RemoteTool) -> String {
    if tool.description.is_empty() {
        FILTER_HINT.to_owned()
    } else {
        format!("{} {FILTER_HINT}", tool.description)
    }
}

/// Apply `shape` to an exited call: stdout shaped, notes and any jq error
/// appended to stderr, exit code per [`exit_code`]. Denials pass through.
fn shaped(shape: &Shape, outcome: CallOutcome) -> CallOutcome {
    match outcome {
        CallOutcome::Exited {
            exit,
            stdout,
            mut stderr,
        } if !shape.is_identity() => {
            let shaped = shape.apply(&stdout);
            for line in shaped.stderr_lines() {
                if !stderr.is_empty() && !stderr.ends_with(b"\n") {
                    stderr.push(b'\n');
                }
                stderr.extend_from_slice(line.as_bytes());
                stderr.push(b'\n');
            }
            CallOutcome::Exited {
                exit: exit_code(exit, &shaped),
                stdout: shaped.stdout,
                stderr,
            }
        }
        other => other,
    }
}

/// The `tools/call` argument names [`parse_arguments`] accepts.
const ARGUMENTS: &[&str] = &["args", "stdin", "jq", "head", "max_bytes"];

/// Validate `tools/call` arguments into an [`Argv`], stdin bytes and the
/// shaping fields. All are optional; anything else is an error message for
/// the client.
fn parse_arguments(arguments: Option<&Value>) -> Result<(Argv, Vec<u8>, ShapeArgs), String> {
    let map = match arguments {
        None | Some(Value::Null) => {
            return Ok((Argv::default(), Vec::new(), ShapeArgs::default()));
        }
        Some(Value::Object(map)) => map,
        Some(_) => return Err("arguments must be an object".into()),
    };
    if let Some(extra) = map.keys().find(|k| !ARGUMENTS.contains(&k.as_str())) {
        return Err(format!(
            "unexpected argument `{extra}` (expected one of `{}`)",
            ARGUMENTS.join("`, `")
        ));
    }
    let args = match map.get("args") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or("`args` must be an array of strings")?,
        Some(_) => return Err("`args` must be an array of strings".into()),
    };
    let argv = Argv::new(args).map_err(|e| format!("`args`: {e}"))?;
    let stdin = match map.get("stdin") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(s)) => s.clone().into_bytes(),
        Some(_) => return Err("`stdin` must be a string".into()),
    };
    let jq = match map.get("jq") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err("`jq` must be a string".into()),
    };
    let count = |key: &str| match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .map(Some)
            .ok_or(format!("`{key}` must be a non-negative integer")),
    };
    let shape = ShapeArgs {
        jq,
        head: count("head")?,
        max_bytes: count("max_bytes")?,
    };
    Ok((argv, stdin, shape))
}

/// Render an outcome as the result's text, plus whether it is an error:
/// stdout, then a `stderr:` block if any, then `exit: N`. A denial reads
/// `denied by host: <reason>`.
fn render_outcome(outcome: &CallOutcome) -> (String, bool) {
    match outcome {
        CallOutcome::Denied(reason) => (format!("denied by host: {reason}"), true),
        CallOutcome::Exited {
            exit,
            stdout,
            stderr,
        } => {
            let mut text = capped(stdout, "stdout");
            if !stderr.is_empty() {
                end_line(&mut text);
                text.push_str("stderr:\n");
                text.push_str(&capped(stderr, "stderr"));
            }
            end_line(&mut text);
            text.push_str(&format!("exit: {exit}"));
            (text, *exit != 0)
        }
    }
}

/// Lossy UTF-8 of `bytes`, cut to at most [`MAX_OUTPUT_BYTES`] on a char
/// boundary, with a note saying how much was dropped.
fn capped(bytes: &[u8], stream: &str) -> String {
    let mut text = String::from_utf8_lossy(bytes).into_owned();
    if text.len() > MAX_OUTPUT_BYTES {
        let mut cut = MAX_OUTPUT_BYTES;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        end_line(&mut text);
        text.push_str(&format!(
            "[wires: {stream} truncated to {cut} of {} bytes]",
            bytes.len()
        ));
    }
    text
}

/// Terminate a non-empty `text` with a newline if it lacks one.
fn end_line(text: &mut String) {
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
}

/// Serve MCP over `input`/`output` until `input` hits EOF, requests one at
/// a time, in order; and follow `tools`, if given: each new tool list
/// replaces the server's, and when it differs from what the client saw,
/// the client hears [`LIST_CHANGED`] (between replies, never inside one).
pub async fn serve_following<C, R, W>(
    server: &mut McpServer<C>,
    input: R,
    mut output: W,
    mut tools: Option<tokio::sync::watch::Receiver<ToolsConfig>>,
) -> Result<()>
where
    C: Caller,
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut lines = input.lines();
    loop {
        let changed = async {
            match tools.as_mut() {
                Some(rx) => rx.changed().await.is_ok(),
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line? else { return Ok(()) };
                if let Some(mut reply) = server.handle_line(&line).await {
                    reply.push('\n');
                    output.write_all(reply.as_bytes()).await?;
                    output.flush().await?;
                }
            }
            alive = changed => {
                if !alive {
                    tools = None;
                    continue;
                }
                let next = tools.as_mut().map(|rx| rx.borrow_and_update().clone());
                if let Some(next) = next
                    && server.set_tools(next)
                {
                    let note = json!({"jsonrpc": "2.0", "method": LIST_CHANGED});
                    output.write_all(format!("{note}\n").as_bytes()).await?;
                    output.flush().await?;
                }
            }
        }
    }
}

/// `wires mcp`: the credential and config flags `wires call` takes.
#[derive(Args)]
pub struct McpArgs {
    #[command(flatten)]
    pub creds: CredArgs,
    /// Read aliases from this file instead of `$WIRES_HOME/tools.json`.
    #[arg(long)]
    pub tools_file: Option<PathBuf>,
}

/// `config`'s aliases, then one [`ToolTarget::Service`] tool per view entry
/// marked `call` (its registry description). A service in the view wins: an
/// alias with the name of any service the view holds is dropped (with a
/// warning), callable or not.
pub(crate) fn with_services(mut config: ToolsConfig, view: &library::View) -> ToolsConfig {
    config.tools.retain(|t| {
        let registered =
            library::ServiceName::new(t.name.as_str()).is_ok_and(|n| view.entry(&n).is_some());
        if registered {
            tracing::warn!(
                "tools.json alias `{}` is shadowed by the registered service of that name",
                t.name
            );
        }
        !registered
    });
    for e in view.entries.iter().filter(|e| e.call) {
        config.tools.push(RemoteTool {
            name: e.entry.name.clone(),
            description: e.entry.service.description.clone(),
            target: ToolTarget::Service,
            remote_tool: None,
        });
    }
    config
}

/// `wires mcp`: load this node's view (refreshing it if needed),
/// `tools.json` aliases and credentials, subscribe to the view, then serve
/// MCP on stdio, telling the client whenever the tool list changes.
///
/// In locked mode ([`Lock`](crate::caller::lock::Lock)) an override flag is
/// refused before anything loads. A tool's `stdin` field is still accepted:
/// it is text in the client's request, never a file this process reads.
pub async fn mcp_cmd(a: McpArgs) -> Result<()> {
    use std::sync::Arc;
    crate::caller::lock::Lock::detect()?.check(&a.creds, a.tools_file.as_deref())?;
    let path = crate::caller::tools::resolve_path(a.tools_file.as_deref())?;
    let aliases = ToolsConfig::load(&path)?;
    let creds = Credentials::resolve(&a.creds)?;
    let ks = Arc::new(crate::admin::keystore::Keystore::resolve()?);
    let held = match crate::caller::call::usable_view(&ks, &creds).await {
        Ok(held) => Some(held),
        Err(e) => {
            tracing::warn!("no view of your services yet ({e:#}): aliases only, until one arrives");
            None
        }
    };
    let config = match &held {
        Some(h) => with_services(aliases.clone(), &h.view),
        None => aliases.clone(),
    };
    tracing::info!(
        "wires mcp: serving {} tool(s) from {}",
        config.tools.len(),
        path.display()
    );
    // Follow the view: a grant or a revocation becomes `list_changed`.
    let endpoint = creds.bind().await?;
    let token_ks = Arc::clone(&ks);
    let (mut views, follower) = crate::caller::view::follow(crate::caller::view::Follow {
        endpoint: endpoint.clone(),
        badge: creds.membership().clone(),
        id_token: Arc::new(move || crate::caller::hello::stored_token(&token_ks)),
        initial: held,
        fallback: crate::caller::view::joined_directories(&ks),
        persist: Some(Arc::clone(&ks)),
    });
    let (tools_tx, tools_rx) = tokio::sync::watch::channel(config.clone());
    let mapper = tokio::spawn(async move {
        while views.changed().await.is_ok() {
            let next = views.borrow_and_update().clone();
            if let Some(held) = next {
                tools_tx.send_replace(with_services(aliases.clone(), &held.view));
            }
        }
    });
    let mut server = McpServer::new(config, WiresCaller::new(creds)).with_list_changed();
    let served = serve_following(
        &mut server,
        tokio::io::BufReader::new(tokio::io::stdin()),
        tokio::io::stdout(),
        Some(tools_rx),
    )
    .await;
    follower.abort();
    mapper.abort();
    endpoint.close().await;
    served
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{NodeIdentity, ServiceName};
    use proptest::prelude::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// One recorded call: tool name, argv, stdin.
    type RecordedCall = (String, Vec<String>, Vec<u8>);

    /// A scripted [`Caller`]: answers per tool name and records every call.
    #[derive(Default)]
    struct FakeCaller {
        answers: BTreeMap<String, std::result::Result<CallOutcome, String>>,
        calls: Mutex<Vec<RecordedCall>>,
    }

    impl FakeCaller {
        fn answer(mut self, tool: &str, a: std::result::Result<CallOutcome, String>) -> Self {
            self.answers.insert(tool.into(), a);
            self
        }
    }

    impl Caller for FakeCaller {
        async fn call(
            &self,
            tool: &RemoteTool,
            argv: Argv,
            stdin: Vec<u8>,
        ) -> anyhow::Result<CallOutcome> {
            let name = tool.name.as_str().to_owned();
            self.calls
                .lock()
                .unwrap()
                .push((name.clone(), argv.into(), stdin));
            match self.answers.get(&name) {
                Some(Ok(o)) => Ok(o.clone()),
                Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
                None => Ok(CallOutcome::Exited {
                    exit: 0,
                    stdout: vec![],
                    stderr: vec![],
                }),
            }
        }
    }

    fn entry(name: &str, description: &str) -> RemoteTool {
        RemoteTool {
            name: ServiceName::new(name).unwrap(),
            description: description.into(),
            target: ToolTarget::Node {
                node: NodeIdentity::from_seed([5; 32]).node_id(),
                relay_url: None,
                addrs: vec![],
            },
            remote_tool: None,
        }
    }

    fn exited(exit: i32, stdout: &str, stderr: &str) -> CallOutcome {
        CallOutcome::Exited {
            exit,
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    fn server() -> McpServer<FakeCaller> {
        let config = ToolsConfig {
            tools: vec![
                entry("db_query", "Read-only SQL"),
                entry("fails", "Always exits 2"),
                entry("locked", "Refused"),
                entry("offline", "Unreachable"),
            ],
            locked: false,
        };
        let caller = FakeCaller::default()
            .answer("db_query", Ok(exited(0, "id\n1\n", "")))
            .answer("fails", Ok(exited(2, "partial", "boom\n")))
            .answer(
                "locked",
                Ok(CallOutcome::Denied("not a member of this network".into())),
            )
            .answer(
                "offline",
                Err("dialing target: no answer within 10s".into()),
            );
        McpServer::new(config, caller)
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// Drive `requests` (one JSON value per line) through [`serve`] and return
    /// every stdout line, each parsed — which also proves stdout is JSON only.
    fn transcript(server: &mut McpServer<FakeCaller>, requests: &[Value]) -> Vec<Value> {
        let input: String = requests.iter().map(|r| format!("{r}\n")).collect();
        let mut out = Vec::new();
        rt().block_on(serve_following(server, input.as_bytes(), &mut out, None))
            .unwrap();
        String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).expect("stdout line is JSON-RPC"))
            .collect()
    }

    fn call(id: i64, name: &str, arguments: Value) -> Value {
        json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
               "params":{"name":name,"arguments":arguments}})
    }

    fn text_result(id: i64, text: &str, is_error: bool) -> Value {
        json!({"jsonrpc":"2.0","id":id,"result":{
            "content":[{"type":"text","text":text}],"isError":is_error}})
    }

    #[test]
    fn golden_classic_session() {
        let mut s = server();
        let out = transcript(
            &mut s,
            &[
                json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                    "protocolVersion":"2025-06-18","capabilities":{},
                    "clientInfo":{"name":"test","version":"0"}}}),
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
                call(3, "db_query", json!({"args":["select 1"],"stdin":"hi"})),
                call(4, "fails", json!({})),
                call(5, "locked", json!({"args":[]})),
                call(6, "nope", json!({})),
                call(7, "offline", json!({})),
                json!({"jsonrpc":"2.0","id":8,"method":"ping"}),
                json!({"jsonrpc":"2.0","id":9,"method":"resources/list"}),
            ],
        );
        let suffix = format!(" {FILTER_HINT}");
        let expected = vec![
            json!({"jsonrpc":"2.0","id":1,"result":{
                "protocolVersion":"2025-06-18",
                "capabilities":{"tools":{"listChanged":false}},
                "serverInfo":{"name":"wires","version":env!("CARGO_PKG_VERSION")},
                "instructions":INSTRUCTIONS}}),
            json!({"jsonrpc":"2.0","id":2,"result":{"tools":[
                {"name":"db_query","description":format!("Read-only SQL{suffix}"),"inputSchema":input_schema()},
                {"name":"fails","description":format!("Always exits 2{suffix}"),"inputSchema":input_schema()},
                {"name":"locked","description":format!("Refused{suffix}"),"inputSchema":input_schema()},
                {"name":"offline","description":format!("Unreachable{suffix}"),"inputSchema":input_schema()},
            ]}}),
            text_result(3, "id\n1\nexit: 0", false),
            text_result(4, "partial\nstderr:\nboom\nexit: 2", true),
            text_result(5, "denied by host: not a member of this network", true),
            json!({"jsonrpc":"2.0","id":6,"error":{"code":-32602,"message":"unknown tool: nope"}}),
            text_result(
                7,
                "wires: call failed: dialing target: no answer within 10s",
                true,
            ),
            json!({"jsonrpc":"2.0","id":8,"result":{}}),
            json!({"jsonrpc":"2.0","id":9,"error":{"code":-32601,
                "message":"method not found: resources/list"}}),
        ];
        assert_eq!(out.len(), expected.len(), "{out:#?}");
        for (got, want) in out.iter().zip(&expected) {
            assert_eq!(got, want);
        }
        let calls = s.caller.calls.lock().unwrap();
        assert_eq!(
            calls[0],
            ("db_query".into(), vec!["select 1".into()], b"hi".to_vec())
        );
        assert_eq!(calls.len(), 4, "unknown tool never reaches the caller");
    }

    #[test]
    fn golden_stateless_session() {
        let mut s = server();
        let meta = json!({META_PROTOCOL_VERSION: "2026-07-28"});
        let out = transcript(
            &mut s,
            &[
                json!({"jsonrpc":"2.0","id":"a","method":"tools/list","params":{"_meta":meta}}),
                json!({"jsonrpc":"2.0","id":"b","method":"tools/call","params":{
                    "_meta":meta,"name":"db_query","arguments":{"args":["x"]}}}),
            ],
        );
        let stamped_meta = json!({
            META_PROTOCOL_VERSION: "2026-07-28",
            META_SERVER_INFO: {"name":"wires","version":env!("CARGO_PKG_VERSION")},
        });
        assert_eq!(
            out[0],
            json!({"jsonrpc":"2.0","id":"a","result":{
                "tools":[
                    {"name":"db_query","description":format!("Read-only SQL {FILTER_HINT}"),"inputSchema":input_schema()},
                    {"name":"fails","description":format!("Always exits 2 {FILTER_HINT}"),"inputSchema":input_schema()},
                    {"name":"locked","description":format!("Refused {FILTER_HINT}"),"inputSchema":input_schema()},
                    {"name":"offline","description":format!("Unreachable {FILTER_HINT}"),"inputSchema":input_schema()},
                ],
                "ttlMs":LIST_TTL_MS,"cacheScope":"private",
                "resultType":"complete","_meta":stamped_meta}})
        );
        assert_eq!(
            out[1],
            json!({"jsonrpc":"2.0","id":"b","result":{
                "content":[{"type":"text","text":"id\n1\nexit: 0"}],"isError":false,
                "resultType":"complete","_meta":stamped_meta}})
        );
    }

    #[test]
    fn initialize_offers_the_newest_legacy_version_for_an_unknown_or_modern_one() {
        for asked in ["1999-01-01", "2026-07-28"] {
            let mut s = server();
            let out = transcript(
                &mut s,
                &[
                    json!({"jsonrpc":"2.0","id":1,"method":"initialize",
                           "params":{"protocolVersion":asked}}),
                    json!({"jsonrpc":"2.0","id":2,"method":"ping"}),
                ],
            );
            assert_eq!(
                out[0]["result"]["protocolVersion"], LEGACY_PROTOCOL_VERSIONS[0],
                "{asked}"
            );
            assert_eq!(
                out[0]["result"].get("resultType"),
                None,
                "legacy: unstamped"
            );
            assert_eq!(
                out[1],
                json!({"jsonrpc":"2.0","id":2,"result":{}}),
                "ping is legacy"
            );
        }
    }

    #[test]
    fn discover_answers_with_or_without_meta() {
        let mut s = server();
        let meta = json!({META_PROTOCOL_VERSION: "2026-07-28"});
        let out = transcript(
            &mut s,
            &[
                json!({"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":meta}}),
                json!({"jsonrpc":"2.0","id":2,"method":"server/discover"}),
            ],
        );
        for reply in &out {
            let r = &reply["result"];
            assert_eq!(r["supportedVersions"], json!(SUPPORTED_PROTOCOL_VERSIONS));
            assert_eq!(r["capabilities"], json!({"tools":{}}));
            assert_eq!(r["resultType"], "complete");
            assert_eq!(r["cacheScope"], "public");
            assert_eq!(r["ttlMs"], json!(LIST_TTL_MS));
            assert_eq!(r["instructions"], INSTRUCTIONS);
            assert_eq!(r["_meta"][META_SERVER_INFO]["name"], "wires");
        }
    }

    #[test]
    fn an_unsupported_version_lists_what_is_served_and_dials_nothing() {
        let mut s = server();
        let meta = json!({META_PROTOCOL_VERSION: "2099-01-01"});
        let out = transcript(
            &mut s,
            &[
                json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{
                "_meta":meta,"name":"db_query","arguments":{}}}),
            ],
        );
        assert_eq!(
            out[0],
            json!({"jsonrpc":"2.0","id":7,"error":{
                "code":UNSUPPORTED_PROTOCOL_VERSION,
                "message":"Unsupported protocol version",
                "data":{"supported":SUPPORTED_PROTOCOL_VERSIONS,"requested":"2099-01-01"}}})
        );
        assert!(s.caller.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn redacted_failures_hide_the_details() {
        let mut s = server().with_redacted_failures();
        let out = transcript(&mut s, &[call(1, "offline", json!({}))]);
        let text = out[0]["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("wires: call failed"), "{text}");
        assert!(!text.contains("10s"), "{text}");
        let out = transcript(&mut s, &[call(2, "locked", json!({}))]);
        assert_eq!(
            out[0],
            text_result(2, "denied by host: not a member of this network", true),
            "a refusal is an answer, still shown"
        );
    }

    #[test]
    fn ping_is_gone_in_the_modern_era() {
        let mut s = server();
        let meta = json!({META_PROTOCOL_VERSION: "2026-07-28"});
        let out = transcript(
            &mut s,
            &[json!({"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":meta}})],
        );
        assert_eq!(out[0]["error"]["code"], METHOD_NOT_FOUND);
    }

    #[test]
    fn a_negotiated_version_can_be_given_up_front() {
        let mut s = server().with_negotiated(Some("2025-06-18".into()));
        let out = transcript(
            &mut s,
            &[json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})],
        );
        assert_eq!(out[0]["result"].get("resultType"), None);
        assert_eq!(out[0]["result"].get("ttlMs"), None);
    }

    #[test]
    fn malformed_input_gets_json_rpc_errors() {
        let mut s = server();
        let rt = rt();
        let reply = |s: &mut McpServer<FakeCaller>, line: &str| -> Option<Value> {
            rt.block_on(s.handle_line(line))
                .map(|r| serde_json::from_str(&r).unwrap())
        };
        assert_eq!(
            reply(&mut s, "{not json").unwrap()["error"]["code"],
            PARSE_ERROR
        );
        assert_eq!(
            reply(&mut s, "[1,2]").unwrap()["error"]["code"],
            INVALID_REQUEST
        );
        assert_eq!(
            reply(&mut s, r#"{"jsonrpc":"2.0","id":1}"#).unwrap()["error"]["code"],
            INVALID_REQUEST
        );
        assert_eq!(reply(&mut s, "   "), None);
        assert_eq!(
            reply(&mut s, r#"{"jsonrpc":"2.0","method":"whatever"}"#),
            None
        );
        for bad in [
            json!("x"),
            json!({"args":"not-an-array"}),
            json!({"args":[1]}),
            json!({"stdin":5}),
            json!({"extra":true}),
            json!({"args":["a\u{0}b"]}),
        ] {
            let r = reply(&mut s, &call(1, "db_query", bad.clone()).to_string()).unwrap();
            assert_eq!(r["error"]["code"], INVALID_PARAMS, "{bad}");
        }
        let r = reply(
            &mut s,
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}).to_string(),
        )
        .unwrap();
        assert_eq!(r["error"]["code"], INVALID_PARAMS);
        assert!(s.caller.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn output_is_capped_with_a_note() {
        let big = "x".repeat(MAX_OUTPUT_BYTES + 10);
        let (text, is_error) = render_outcome(&exited(0, &big, ""));
        assert!(!is_error);
        assert!(text.starts_with(&"x".repeat(MAX_OUTPUT_BYTES)));
        assert!(text.contains(&format!(
            "[wires: stdout truncated to {MAX_OUTPUT_BYTES} of {} bytes]",
            MAX_OUTPUT_BYTES + 10
        )));
        assert!(text.ends_with("exit: 0"));
        // A multi-byte char straddling the cap is dropped whole, not split.
        let straddle = format!("{}é", "x".repeat(MAX_OUTPUT_BYTES - 1));
        let (text, _) = render_outcome(&exited(0, &straddle, ""));
        assert!(
            text.contains("truncated to 65535 of"),
            "{}",
            &text[text.len() - 80..]
        );
    }

    #[test]
    fn descriptions_say_how_to_filter_without_a_shell() {
        let d = describe(&entry("gh", "The GitHub CLI"));
        assert!(d.starts_with("The GitHub CLI "), "{d}");
        assert!(d.contains("--jq"), "{d}");
        assert!(d.contains("pipes are not available"), "{d}");
    }

    #[test]
    fn shaping_fields_filter_the_result() {
        let mut s = server();
        s.caller = FakeCaller::default().answer(
            "db_query",
            Ok(exited(0, r#"[{"n":"a"},{"n":"b"},{"n":"c"}]"#, "")),
        );
        let out = transcript(
            &mut s,
            &[
                call(1, "db_query", json!({"jq": ".[].n", "head": 2})),
                call(2, "db_query", json!({"jq": ".[0]", "max_bytes": 3})),
                call(3, "db_query", json!({"jq": ".foo"})),
            ],
        );
        assert_eq!(out[0], text_result(1, "a\nb\nexit: 0", false));
        assert_eq!(
            out[1],
            text_result(
                2,
                "{\"n\nstderr:\nwires: stdout truncated to 3 of 10 bytes (--max-bytes 3)\nexit: 0",
                false
            )
        );
        // `.foo` on an array is a jq error: exit 2, since the remote exit was 0.
        let text = out[2]["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("wires: --jq:"), "{text}");
        assert!(text.ends_with("exit: 2"), "{text}");
        assert_eq!(out[2]["result"]["isError"], json!(true));
    }

    #[test]
    fn a_bad_filter_is_a_tool_error_and_nothing_is_dialed() {
        let mut s = server();
        let out = transcript(&mut s, &[call(1, "db_query", json!({"jq": ".["}))]);
        assert_eq!(out[0]["result"]["isError"], json!(true));
        let text = out[0]["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("wires: --jq: invalid filter"), "{text}");
        assert!(s.caller.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn shaping_fields_are_type_checked() {
        let mut s = server();
        let out = transcript(
            &mut s,
            &[
                call(1, "db_query", json!({"head": -1})),
                call(2, "db_query", json!({"max_bytes": "10"})),
                call(3, "db_query", json!({"jq": 5})),
            ],
        );
        for (i, field) in ["head", "max_bytes", "jq"].iter().enumerate() {
            assert_eq!(out[i]["error"]["code"], INVALID_PARAMS);
            let msg = out[i]["error"]["message"].as_str().unwrap();
            assert!(msg.contains(field), "{msg}");
        }
        assert!(s.caller.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_denial_is_not_shaped() {
        let out = shaped(
            &Shape::new(&ShapeArgs {
                jq: Some(".".into()),
                ..Default::default()
            })
            .unwrap(),
            CallOutcome::Denied("not admitted".into()),
        );
        assert_eq!(out, CallOutcome::Denied("not admitted".into()));
    }

    #[test]
    fn render_shapes() {
        assert_eq!(
            render_outcome(&exited(0, "", "")),
            ("exit: 0".into(), false)
        );
        assert_eq!(
            render_outcome(&exited(1, "", "e")),
            ("stderr:\ne\nexit: 1".into(), true)
        );
        assert_eq!(
            render_outcome(&exited(0, "a\n", "")),
            ("a\nexit: 0".into(), false)
        );
    }

    /// A view for anyone the mock IdP signed in: `services` callable,
    /// `readable` only readable (role `auditor`).
    fn view_of(services: &[(&str, &str)], readable: &[&str]) -> library::View {
        use library::{Policy, RoleName, Service, ServiceName, StateVersion};
        let node = |b: u8| NodeIdentity::from_seed([b; 32]).node_id();
        let root = NodeIdentity::from_seed([1; 32]);
        let mut state = Policy::new(root.node_id());
        state.version = StateVersion(1);
        state.not_after = i64::MAX;
        let (staff, anyone) = crate::testutil::staff_role();
        let auditor = RoleName::new("auditor").unwrap();
        let nobody = RoleName::new("nobody").unwrap();
        state.roles.insert(staff.clone(), anyone.clone());
        state.roles.insert(auditor.clone(), anyone);
        state.roles.insert(
            nobody.clone(),
            vec![library::Matcher {
                email: Some("nobody@example.com".parse().unwrap()),
                ..library::Matcher::new(crate::testutil::test_idp().issuer.as_str())
            }],
        );
        let svc = |desc: &str, allow: &RoleName, readers: Vec<RoleName>| Service {
            description: desc.into(),
            allow: vec![allow.clone()],
            hosts: vec![node(4)],
            readers,
        };
        for (name, desc) in services {
            state
                .services
                .insert(ServiceName::new(*name).unwrap(), svc(desc, &staff, vec![]));
        }
        for name in readable {
            state.services.insert(
                ServiceName::new(*name).unwrap(),
                svc("read only", &nobody, vec![auditor.clone()]),
            );
        }
        let anyone = library::Principal {
            issuer: crate::testutil::test_idp().issuer.as_str().into(),
            subject: "1".into(),
            email: Some("a@example.com".into()),
            org: None,
            groups: vec![],
            not_after: i64::MAX,
        };
        crate::testutil::signed_policy(&root, state).view_for(Some(&anyone), None)
    }

    /// Card 28 §8: a service in the view beats an alias of the same name,
    /// and only services marked `call` become tools.
    #[test]
    fn services_become_tools_after_the_aliases_and_shadow_them() {
        let view = view_of(
            &[("orders-db", "Read-only SQL"), ("db_query", "shadowed")],
            &["audit-log"],
        );
        let aliases = ToolsConfig {
            tools: vec![
                entry("db_query", "an alias"),
                entry("audit-log", "an alias too"),
                entry("mine", "kept"),
            ],
            ..ToolsConfig::default()
        };
        let config = with_services(aliases, &view);
        let names: Vec<_> = config.tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["mine", "db_query", "orders-db"]);
        assert_eq!(config.tools[0].description, "kept");
        assert_eq!(config.tools[1].target, ToolTarget::Service);
        assert_eq!(config.tools[1].description, "shadowed");
        assert_eq!(config.tools[2].description, "Read-only SQL");
    }

    /// Card 37: past [`SEARCH_THRESHOLD`] services, `tools/list` offers
    /// `search_services` and `call_service`; the search finds a service by
    /// name or description, and `call_service` runs it by name.
    #[test]
    fn a_large_view_is_searched_not_listed() {
        let many: Vec<(String, String)> = (0..SEARCH_THRESHOLD + 5)
            .map(|i| (format!("svc-{i:02}"), format!("service number {i}")))
            .chain([("orders-db".into(), "Read-only SQL over the orders".into())])
            .collect();
        let pairs: Vec<(&str, &str)> = many.iter().map(|(n, d)| (n.as_str(), d.as_str())).collect();
        let config = with_services(
            ToolsConfig {
                tools: vec![entry("mine", "an alias")],
                ..ToolsConfig::default()
            },
            &view_of(&pairs, &[]),
        );
        let mut s = McpServer::new(config, FakeCaller::default());
        let out = transcript(
            &mut s,
            &[
                json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
                call(2, SEARCH_TOOL, json!({"query": "ORDERS"})),
                call(3, SEARCH_TOOL, json!({"query": "nothing like this"})),
                call(
                    4,
                    CALL_TOOL,
                    json!({"service": "orders-db", "args": ["select 1"]}),
                ),
                call(5, CALL_TOOL, json!({"service": "payroll"})),
                call(6, "orders-db", json!({})),
            ],
        );
        let listed: Vec<&str> = out[0]["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(listed, ["mine", SEARCH_TOOL, CALL_TOOL]);
        let found = out[1]["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(found, "orders-db: Read-only SQL over the orders");
        let none = out[2]["result"]["content"][0]["text"].as_str().unwrap();
        assert!(none.contains("no service"), "{none}");
        assert_eq!(out[3]["result"]["isError"], json!(false));
        assert!(
            out[4]["error"]["message"]
                .as_str()
                .unwrap()
                .contains("payroll")
        );
        assert_eq!(
            out[5]["result"]["isError"],
            json!(false),
            "still callable by name"
        );
        let calls = s.caller.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "orders-db");
        assert_eq!(calls[0].1, vec!["select 1".to_string()]);

        // At the threshold, every service is listed.
        let few: Vec<(String, String)> = (0..SEARCH_THRESHOLD)
            .map(|i| (format!("svc-{i:02}"), "d".to_string()))
            .collect();
        let pairs: Vec<(&str, &str)> = few.iter().map(|(n, d)| (n.as_str(), d.as_str())).collect();
        let s = McpServer::new(
            with_services(ToolsConfig::default(), &view_of(&pairs, &[])),
            FakeCaller::default(),
        );
        let list = s.tools_list(false);
        assert_eq!(list["tools"].as_array().unwrap().len(), SEARCH_THRESHOLD);
    }

    /// Card 37: a new tool list reaches the client as `list_changed`, and
    /// only when it differs; `initialize` declares `listChanged`.
    #[tokio::test]
    async fn a_changed_view_is_announced_between_replies() {
        let one = with_services(ToolsConfig::default(), &view_of(&[("a", "one")], &[]));
        let two = with_services(
            ToolsConfig::default(),
            &view_of(&[("a", "one"), ("b", "two")], &[]),
        );
        let (tx, rx) = tokio::sync::watch::channel(one.clone());
        let mut s = McpServer::new(one.clone(), FakeCaller::default()).with_list_changed();
        let (client, server_side) = tokio::io::duplex(4096);
        let (client_read, mut client_write) = tokio::io::split(client);
        let (server_read, server_write) = tokio::io::split(server_side);
        let served = tokio::spawn(async move {
            let r = serve_following(
                &mut s,
                tokio::io::BufReader::new(server_read),
                server_write,
                Some(rx),
            )
            .await;
            (s, r)
        });
        let mut lines = tokio::io::BufReader::new(client_read).lines();
        let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}});
        client_write
            .write_all(format!("{init}\n").as_bytes())
            .await
            .unwrap();
        let reply: Value =
            serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(
            reply["result"]["capabilities"]["tools"]["listChanged"],
            json!(true)
        );
        // The same list again: nothing to announce.
        tx.send_replace(one);
        // A grant: announced.
        tx.send_replace(two);
        let note: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(note["method"], LIST_CHANGED);
        assert!(note.get("id").is_none());
        let list = json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
        client_write
            .write_all(format!("{list}\n").as_bytes())
            .await
            .unwrap();
        let reply: Value =
            serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(reply["id"], json!(2));
        assert_eq!(reply["result"]["tools"].as_array().unwrap().len(), 2);
        drop(client_write);
        drop(lines);
        drop(tx);
        let (_, r) = served.await.unwrap();
        r.unwrap();
    }

    proptest! {
        #[test]
        fn args_survive_mcp_to_argv_to_caller(
            args in proptest::collection::vec("[^\u{0}]{0,24}", 0..12),
            stdin in ".{0,64}",
        ) {
            let mut s = server();
            let out = transcript(
                &mut s,
                &[call(1, "db_query", json!({"args": args, "stdin": stdin}))],
            );
            prop_assert_eq!(&out[0]["result"]["isError"], &json!(false));
            let calls = s.caller.calls.lock().unwrap();
            prop_assert_eq!(calls.len(), 1);
            prop_assert_eq!(&calls[0].1, &args);
            prop_assert_eq!(&calls[0].2, stdin.as_bytes());
        }
    }
}

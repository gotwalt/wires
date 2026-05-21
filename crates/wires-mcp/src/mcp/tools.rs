use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::http::ServiceState;
use crate::mcp::router::JsonRpcError;
use crate::token::Claims;

pub fn list_descriptors() -> Value {
    serde_json::json!({"tools": [
        {"name": "wires_list_topics",       "description": "List topics this agent can access",                  "inputSchema": {"type":"object","properties":{}}},
        {"name": "wires_publish",           "description": "Publish a message to a topic",                       "inputSchema": {"type":"object","properties":{"topic":{"type":"string"},"text":{"type":"string"},"data":{"type":"object"}},"required":["topic","text"]}},
        {"name": "wires_tail",              "description": "Read recent messages from a topic",                  "inputSchema": {"type":"object","properties":{"topic":{"type":"string"},"since":{"type":"string"},"limit":{"type":"integer"}},"required":["topic"]}},
        {"name": "wires_list_channels",     "description": "List channels (named + DMs) this agent is in",       "inputSchema": {"type":"object","properties":{}}},
        {"name": "wires_create_channel",    "description": "Create a named channel",                             "inputSchema": {"type":"object","properties":{"name":{"type":"string"},"description":{"type":"string"}},"required":["name"]}},
        {"name": "wires_channel_members",   "description": "Return the roster (members + pending) of a channel", "inputSchema": {"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}},
        {"name": "wires_invite_to_channel", "description": "Invite an agent to a named channel",                 "inputSchema": {"type":"object","properties":{"name":{"type":"string"},"agent_pubkey":{"type":"string"}},"required":["name","agent_pubkey"]}}
    ]})
}

#[derive(Debug, Clone, Deserialize)]
pub struct CallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

// ── list_topics ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct TopicListing {
    pub topics: Vec<TopicEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopicEntry {
    pub topic_id: String,
    pub name: Option<String>,
    pub rights: Vec<String>,
    pub cap_id: String,
}

async fn list_topics(state: &ServiceState, claims: &Claims) -> Result<Value, JsonRpcError> {
    let runtime = state
        .supervisor
        .get_or_open(&claims.sub)
        .await
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("unknown_user: {e}"),
        })?;
    let caps = runtime.node.caps.all().map_err(|e| JsonRpcError {
        code: -32000,
        message: format!("caps: {e}"),
    })?;
    let names = wires_node::load_topic_names(&runtime.node.config.data_dir).unwrap_or_default();
    let mut topics = Vec::new();
    for (cap_id, entry) in caps {
        if entry.revoked {
            continue;
        }
        let cap = &entry.cap;
        let rights: Vec<String> = cap
            .rights
            .iter()
            .map(|r| match r {
                wires_core::Right::Read => "read".to_string(),
                wires_core::Right::Write => "write".to_string(),
            })
            .collect();
        for pattern in &cap.topics {
            for (name, topic_id) in &names {
                if let Ok(true) = wires_core::glob_matches(pattern, name) {
                    topics.push(TopicEntry {
                        topic_id: hex::encode(topic_id),
                        name: Some(name.clone()),
                        rights: rights.clone(),
                        cap_id: hex::encode(cap_id),
                    });
                }
            }
        }
    }
    let body = TopicListing { topics };
    let text = serde_json::to_string(&body).map_err(|e| JsonRpcError {
        code: -32000,
        message: e.to_string(),
    })?;
    Ok(serde_json::json!({"content": [{"type": "text", "text": text}], "isError": false}))
}

// ── publish ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct PublishArgs {
    topic: String,
    text: String,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
struct PublishOutput {
    topic_id: String,
    sender: String,
    seq: u64,
    prev_hash: String,
    timestamp: i64,
    message_hash: String,
}

const DEFAULT_TYPE: &str = "message";

fn resolve_topic_id(
    runtime: &wires_node::runtime::NodeRuntime,
    topic: &str,
) -> Result<[u8; 32], String> {
    // 64-char lowercase hex → topic_id literal; else look up in topic_names.json.
    if topic.len() == 64
        && topic
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        let bytes = hex::decode(topic).map_err(|e| format!("topic_not_found: bad hex: {e}"))?;
        return bytes.try_into().map_err(|_| "topic_not_found".to_string());
    }
    let names = wires_node::load_topic_names(&runtime.node.config.data_dir).unwrap_or_default();
    names
        .iter()
        .find_map(|(n, id)| (n == topic).then_some(*id))
        .ok_or_else(|| format!("topic_not_found: {topic}"))
}

fn topic_name_for_id(runtime: &wires_node::runtime::NodeRuntime, id: &[u8; 32]) -> Option<String> {
    let names = wires_node::load_topic_names(&runtime.node.config.data_dir).ok()?;
    names.into_iter().find_map(|(n, t)| (t == *id).then_some(n))
}

fn pick_cap_for(
    runtime: &wires_node::runtime::NodeRuntime,
    name_or_id: &str,
    topic_id: &[u8; 32],
    right: wires_core::Right,
) -> Result<wires_core::CapId, String> {
    let name = topic_name_for_id(runtime, topic_id).unwrap_or_else(|| name_or_id.to_string());
    let caps = runtime.node.caps.all().map_err(|e| format!("caps: {e}"))?;
    for (cid, entry) in caps {
        if entry.revoked {
            continue;
        }
        if entry.cap.allows(&name, right).is_ok() {
            return Ok(cid);
        }
    }
    Err(format!(
        "permission_denied: no cap for {} with {:?}",
        hex::encode(topic_id),
        right
    ))
}

fn error_result(msg: &str) -> Value {
    serde_json::json!({"content": [{"type": "text", "text": msg}], "isError": true})
}

/// Load member identity from `me.json` in the user's data dir, falling back to
/// `(MemberKind::Api, "wires-mcp", None)` if absent or malformed.
fn load_me_meta(
    data_dir: &std::path::Path,
) -> (
    wires_core::channel::types::MemberKind,
    String,
    Option<String>,
) {
    use wires_core::channel::types::MemberKind;
    let p = data_dir.join("me.json");
    let default = (MemberKind::Api, "wires-mcp".to_string(), None);
    let raw = match std::fs::read_to_string(&p) {
        Ok(s) => s,
        Err(_) => return default,
    };
    let v: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return default,
    };
    let kind = v
        .get("kind")
        .and_then(|x| x.as_str())
        .and_then(|s| serde_json::from_str(&format!("\"{s}\"")).ok())
        .unwrap_or(MemberKind::Api);
    let display_name = v
        .get("display_name")
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| "wires-mcp".to_string());
    let description = v
        .get("description")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    (kind, display_name, description)
}

async fn publish_tool(
    state: &ServiceState,
    claims: &Claims,
    args: PublishArgs,
) -> Result<Value, JsonRpcError> {
    let runtime = state
        .supervisor
        .get_or_open(&claims.sub)
        .await
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("unknown_user: {e}"),
        })?;
    let topic_id = match resolve_topic_id(&runtime, &args.topic) {
        Ok(t) => t,
        Err(msg) => return Ok(error_result(&msg)),
    };
    // Defense: refuse the __caps topic.
    let caps_topic = runtime.node.config.caps_topic_id();
    if topic_id == caps_topic {
        return Ok(error_result(&format!(
            "reserved_topic: {}",
            hex::encode(topic_id)
        )));
    }
    let cap_id = match pick_cap_for(&runtime, &args.topic, &topic_id, wires_core::Right::Write) {
        Ok(c) => c,
        Err(msg) => return Ok(error_result(&msg)),
    };
    // Join + publish.
    if let Err(e) = runtime.join_topic(topic_id, vec![]).await {
        return Ok(error_result(&format!("join_topic: {e}")));
    }
    let content = wires_core::CanonicalContent {
        type_: DEFAULT_TYPE.into(),
        text: args.text,
        data: args.data,
    };
    let msg = runtime
        .publish_and_broadcast(topic_id, cap_id, content)
        .await
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("publish: {e}"),
        })?;
    let message_hash = hex::encode(msg.message_hash().unwrap_or_default());
    let out = PublishOutput {
        topic_id: hex::encode(topic_id),
        sender: hex::encode(msg.sender),
        seq: msg.seq,
        prev_hash: hex::encode(msg.prev_hash),
        timestamp: msg.timestamp,
        message_hash,
    };
    let text = serde_json::to_string(&out).map_err(|e| JsonRpcError {
        code: -32000,
        message: e.to_string(),
    })?;
    Ok(serde_json::json!({"content": [{"type": "text", "text": text}], "isError": false}))
}

// ── tail ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct TailArgs {
    topic: String,
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

/// Cursor: per-sender (hex) → (last_seq, hash_hex).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TailCursor {
    hwm: HashMap<String, (u64, String)>,
}

const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 500;

async fn tail_tool(
    state: &ServiceState,
    claims: &Claims,
    args: TailArgs,
) -> Result<Value, JsonRpcError> {
    let runtime = state
        .supervisor
        .get_or_open(&claims.sub)
        .await
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("unknown_user: {e}"),
        })?;
    let topic_id = match resolve_topic_id(&runtime, &args.topic) {
        Ok(t) => t,
        Err(msg) => return Ok(error_result(&msg)),
    };
    if pick_cap_for(&runtime, &args.topic, &topic_id, wires_core::Right::Read).is_err() {
        return Ok(error_result(&format!(
            "permission_denied: read on {}",
            hex::encode(topic_id)
        )));
    }
    // Parse optional cursor.
    let cursor: TailCursor = match &args.since {
        None => TailCursor::default(),
        Some(s) => {
            match URL_SAFE_NO_PAD
                .decode(s)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
            {
                Some(c) => c,
                None => return Ok(error_result("invalid_cursor")),
            }
        }
    };
    // Best-effort replay on first tail (no cursor).
    if args.since.is_none() {
        let _ = runtime.replay_from_host(topic_id).await;
    }
    // Idempotent join.
    let _ = runtime.join_topic(topic_id, vec![]).await;
    // Read decrypted history using the node's read_decrypted_since method.
    let limit = args.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let msgs = runtime
        .node
        .read_decrypted_since(&topic_id, &cursor.hwm, limit)
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("tail: {e}"),
        })?;
    let next_cursor = encode_cursor(&cursor, &msgs);
    let body = serde_json::json!({
        "messages": msgs.iter().map(|m| serde_json::json!({
            "topic_id":  hex::encode(m.envelope.topic_id),
            "sender":    hex::encode(m.envelope.sender),
            "seq":       m.envelope.seq,
            "prev_hash": hex::encode(m.envelope.prev_hash),
            "timestamp": m.envelope.timestamp,
            "kind":      format!("{:?}", m.envelope.kind),
            "content":   m.content,
        })).collect::<Vec<_>>(),
        "next_cursor": next_cursor,
        "exhausted":   msgs.len() < limit,
    });
    let text = serde_json::to_string(&body).map_err(|e| JsonRpcError {
        code: -32000,
        message: e.to_string(),
    })?;
    Ok(serde_json::json!({"content": [{"type": "text", "text": text}], "isError": false}))
}

// ── list_channels ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
struct ChannelListing {
    channels: Vec<ChannelEntry>,
}

#[derive(Debug, Clone, Serialize)]
struct ChannelEntry {
    topic_id: String,
    name: String,
    kind: String, // "named" | "dm"
    member_count: usize,
    pending_count: usize,
}

async fn list_channels(state: &ServiceState, claims: &Claims) -> Result<Value, JsonRpcError> {
    let runtime = state
        .supervisor
        .get_or_open(&claims.sub)
        .await
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("unknown_user: {e}"),
        })?;
    let data_dir = &runtime.node.config.data_dir;
    let names = wires_node::load_topic_names(data_dir).unwrap_or_default();
    let self_pk = runtime.node.ed_sk.verifying_key().to_bytes();

    let mut channels: Vec<ChannelEntry> = Vec::new();
    for (name, topic_id) in &names {
        if !name.starts_with("channels.") {
            continue;
        }
        let log = match runtime.node.open_topic_log(topic_id) {
            Ok(l) => l,
            Err(_) => continue,
        };
        let keys = match runtime.node.epoch_keys_for(topic_id) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let (_epoch, key) = match keys.latest() {
            Ok(Some(pair)) => pair,
            _ => continue,
        };
        let is_dm = name.starts_with("channels.dm.");
        if is_dm {
            // For DMs, we don't have on-hand the sorted participants; ChannelView::empty_dm
            // requires them. The participant list is implicit in the topic_id; we re-fold
            // members from log entries (member_meta) regardless of variant for counts.
            let view = match wires_node::channel::open_dm(*topic_id, vec![], &log, &key) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if view.members.contains_key(&self_pk) {
                channels.push(ChannelEntry {
                    topic_id: hex::encode(topic_id),
                    name: name.clone(),
                    kind: "dm".to_string(),
                    member_count: view.members.len(),
                    pending_count: view.pending.len(),
                });
            }
        } else {
            let view = match wires_node::channel::open_named(*topic_id, &log, &key) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if view.members.contains_key(&self_pk) {
                channels.push(ChannelEntry {
                    topic_id: hex::encode(topic_id),
                    name: name.clone(),
                    kind: "named".to_string(),
                    member_count: view.members.len(),
                    pending_count: view.pending.len(),
                });
            }
        }
    }
    let body = ChannelListing { channels };
    let text = serde_json::to_string(&body).map_err(|e| JsonRpcError {
        code: -32000,
        message: e.to_string(),
    })?;
    Ok(serde_json::json!({"content": [{"type": "text", "text": text}], "isError": false}))
}

// ── create_channel ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct CreateChannelArgs {
    name: String,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct CreateChannelOutput {
    topic_id: String,
    name: String,
}

async fn create_channel_tool(
    state: &ServiceState,
    claims: &Claims,
    args: CreateChannelArgs,
) -> Result<Value, JsonRpcError> {
    let runtime = state
        .supervisor
        .get_or_open(&claims.sub)
        .await
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("unknown_user: {e}"),
        })?;
    let topic_name = if args.name.starts_with("channels.") {
        args.name.clone()
    } else {
        format!("channels.{}", args.name)
    };

    let (topic_id, _epoch_key) = match wires_node::channel::allocate_named(&runtime.node) {
        Ok(pair) => pair,
        Err(e) => return Ok(error_result(&format!("allocate_named: {e}"))),
    };

    if let Err(e) = wires_node::upsert_topic_names(
        &runtime.node.config.data_dir,
        [(topic_name.clone(), topic_id)],
    ) {
        return Ok(error_result(&format!("upsert_topic_names: {e}")));
    }

    // MCP cannot auto-mint a self-cap (no root key in the gateway). The user
    // must already hold a write-covering cap for `topic_name`.
    let cap_id = match wires_node::channel::find_cap_for(
        &runtime.node,
        &topic_name,
        wires_core::Right::Write,
    ) {
        Some(id) => id,
        None => {
            return Ok(error_result(&format!(
                "permission_denied: no cap covers '{topic_name}' for Write"
            )));
        }
    };

    let now = wires_net::unix_now_ms();
    let (kind, display_name, _description) = load_me_meta(&runtime.node.config.data_dir);

    if let Err(e) = wires_node::channel::publish_create_and_meta(
        &runtime.node,
        topic_id,
        &topic_name,
        cap_id,
        args.description.as_deref(),
        &display_name,
        kind,
        now,
    ) {
        return Ok(error_result(&format!("publish_create_and_meta: {e}")));
    }

    let out = CreateChannelOutput {
        topic_id: hex::encode(topic_id),
        name: topic_name,
    };
    let text = serde_json::to_string(&out).map_err(|e| JsonRpcError {
        code: -32000,
        message: e.to_string(),
    })?;
    Ok(serde_json::json!({"content": [{"type": "text", "text": text}], "isError": false}))
}

// ── channel_members ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct ChannelMembersArgs {
    name: String,
}

#[derive(Debug, Clone, Serialize)]
struct ChannelMembersOutput {
    topic_id: String,
    name: String,
    members: Vec<MemberEntry>,
    pending: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct MemberEntry {
    pubkey: String,
    kind: String,
    display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

async fn channel_members_tool(
    state: &ServiceState,
    claims: &Claims,
    args: ChannelMembersArgs,
) -> Result<Value, JsonRpcError> {
    let runtime = state
        .supervisor
        .get_or_open(&claims.sub)
        .await
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("unknown_user: {e}"),
        })?;
    let topic_name = if args.name.starts_with("channels.") {
        args.name.clone()
    } else {
        format!("channels.{}", args.name)
    };
    let topic_id = match wires_node::resolve_topic(&runtime.node.config.data_dir, &topic_name) {
        Ok(t) => t,
        Err(e) => return Ok(error_result(&format!("topic_not_found: {e}"))),
    };
    let log = match runtime.node.open_topic_log(&topic_id) {
        Ok(l) => l,
        Err(e) => return Ok(error_result(&format!("open_topic_log: {e}"))),
    };
    let keys = match runtime.node.epoch_keys_for(&topic_id) {
        Ok(k) => k,
        Err(e) => return Ok(error_result(&format!("epoch_keys: {e}"))),
    };
    let (_epoch, key) = match keys.latest() {
        Ok(Some(pair)) => pair,
        Ok(None) => return Ok(error_result(&format!("no epoch key for {topic_name}"))),
        Err(e) => return Ok(error_result(&format!("epoch_keys.latest: {e}"))),
    };
    let is_dm = topic_name.starts_with("channels.dm.");
    let view = if is_dm {
        match wires_node::channel::open_dm(topic_id, vec![], &log, &key) {
            Ok(v) => v,
            Err(e) => return Ok(error_result(&format!("open_dm: {e}"))),
        }
    } else {
        match wires_node::channel::open_named(topic_id, &log, &key) {
            Ok(v) => v,
            Err(e) => return Ok(error_result(&format!("open_named: {e}"))),
        }
    };
    let members: Vec<MemberEntry> = view
        .members
        .iter()
        .map(|(pk, meta)| MemberEntry {
            pubkey: hex::encode(pk),
            kind: serde_json::to_value(meta.kind)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "unknown".to_string()),
            display_name: meta.display_name.clone(),
            description: meta.description.clone(),
        })
        .collect();
    let pending: Vec<String> = view.pending.iter().map(hex::encode).collect();
    let out = ChannelMembersOutput {
        topic_id: hex::encode(topic_id),
        name: topic_name,
        members,
        pending,
    };
    let text = serde_json::to_string(&out).map_err(|e| JsonRpcError {
        code: -32000,
        message: e.to_string(),
    })?;
    Ok(serde_json::json!({"content": [{"type": "text", "text": text}], "isError": false}))
}

// ── invite_to_channel ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct InviteToChannelArgs {
    name: String,
    agent_pubkey: String,
}

async fn invite_to_channel_tool(
    state: &ServiceState,
    claims: &Claims,
    args: InviteToChannelArgs,
) -> Result<Value, JsonRpcError> {
    let runtime = state
        .supervisor
        .get_or_open(&claims.sub)
        .await
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("unknown_user: {e}"),
        })?;
    let topic_name = if args.name.starts_with("channels.") {
        args.name.clone()
    } else {
        format!("channels.{}", args.name)
    };
    let agent_bytes = match hex::decode(&args.agent_pubkey) {
        Ok(b) => b,
        Err(e) => return Ok(error_result(&format!("agent_pubkey not hex: {e}"))),
    };
    let agent: [u8; 32] = match agent_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return Ok(error_result("agent_pubkey must be 32 bytes")),
    };
    let topic_id = match wires_node::resolve_topic(&runtime.node.config.data_dir, &topic_name) {
        Ok(t) => t,
        Err(e) => return Ok(error_result(&format!("topic_not_found: {e}"))),
    };
    let cap_id = match wires_node::channel::find_cap_for(
        &runtime.node,
        &topic_name,
        wires_core::Right::Write,
    ) {
        Some(id) => id,
        None => {
            return Ok(error_result(&format!(
                "permission_denied: no cap covers '{topic_name}'"
            )));
        }
    };
    let keys = match runtime.node.epoch_keys_for(&topic_id) {
        Ok(k) => k,
        Err(e) => return Ok(error_result(&format!("epoch_keys: {e}"))),
    };
    let (_epoch, key) = match keys.latest() {
        Ok(Some(pair)) => pair,
        Ok(None) => return Ok(error_result(&format!("no epoch key for {topic_name}"))),
        Err(e) => return Ok(error_result(&format!("epoch_keys.latest: {e}"))),
    };
    let now = wires_net::unix_now_ms();
    if let Err(e) =
        wires_node::channel::invite_member(&runtime.node, topic_id, cap_id, agent, &key, now)
    {
        return Ok(error_result(&format!("invite_member: {e}")));
    }
    let out =
        serde_json::json!({"ok": true, "topic_id": hex::encode(topic_id), "name": topic_name});
    let text = serde_json::to_string(&out).map_err(|e| JsonRpcError {
        code: -32000,
        message: e.to_string(),
    })?;
    Ok(serde_json::json!({"content": [{"type": "text", "text": text}], "isError": false}))
}

fn encode_cursor(prev: &TailCursor, msgs: &[wires_node::DecryptedMessage]) -> String {
    let mut cur = prev.clone();
    for m in msgs {
        let sender = hex::encode(m.envelope.sender);
        let hash = hex::encode(m.envelope.message_hash().unwrap_or_default());
        cur.hwm.insert(sender, (m.envelope.seq, hash));
    }
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&cur).unwrap())
}

// ── dispatch ──────────────────────────────────────────────────────────────────

pub async fn call(
    state: ServiceState,
    claims: &Claims,
    params: &Value,
) -> Result<Value, JsonRpcError> {
    let p: CallParams = serde_json::from_value(params.clone()).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("invalid params: {e}"),
    })?;
    match p.name.as_str() {
        "wires_list_topics" => list_topics(&state, claims).await,
        "wires_publish" => {
            let args: PublishArgs =
                serde_json::from_value(p.arguments).map_err(|e| JsonRpcError {
                    code: -32602,
                    message: format!("invalid arguments: {e}"),
                })?;
            publish_tool(&state, claims, args).await
        }
        "wires_tail" => {
            let args: TailArgs = serde_json::from_value(p.arguments).map_err(|e| JsonRpcError {
                code: -32602,
                message: format!("invalid arguments: {e}"),
            })?;
            tail_tool(&state, claims, args).await
        }
        "wires_list_channels" => list_channels(&state, claims).await,
        "wires_create_channel" => {
            let args: CreateChannelArgs =
                serde_json::from_value(p.arguments).map_err(|e| JsonRpcError {
                    code: -32602,
                    message: format!("invalid arguments: {e}"),
                })?;
            create_channel_tool(&state, claims, args).await
        }
        "wires_channel_members" => {
            let args: ChannelMembersArgs =
                serde_json::from_value(p.arguments).map_err(|e| JsonRpcError {
                    code: -32602,
                    message: format!("invalid arguments: {e}"),
                })?;
            channel_members_tool(&state, claims, args).await
        }
        "wires_invite_to_channel" => {
            let args: InviteToChannelArgs =
                serde_json::from_value(p.arguments).map_err(|e| JsonRpcError {
                    code: -32602,
                    message: format!("invalid arguments: {e}"),
                })?;
            invite_to_channel_tool(&state, claims, args).await
        }
        other => Err(JsonRpcError {
            code: -32601,
            message: format!("unknown tool: {other}"),
        }),
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::test_state;
    use crate::store::UserRecord;
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;
    use wires_core::Capability;
    use wires_core::cap::Right;
    use wires_node::NodeConfig;
    use wires_node::runtime::NodeRuntime;

    /// Seed a user: write identity + config, insert one cap, one topic_name entry,
    /// register with the supervisor's store. Returns (ServiceState, root_pubkey_hex).
    async fn seed_user(tmp: &TempDir) -> (ServiceState, String) {
        let st = test_state(tmp.path());
        let sub_seed = [42u8; 32];
        let agent = SigningKey::from_bytes(&sub_seed);
        let root_seed = [99u8; 32];
        let root = SigningKey::from_bytes(&root_seed);
        let root_hex = hex::encode(root.verifying_key().to_bytes());

        let users_dir = st.config.users_dir();
        std::fs::create_dir_all(&users_dir).unwrap();
        let user_dir = users_dir.join(&root_hex);
        std::fs::create_dir_all(&user_dir).unwrap();

        let cfg = NodeConfig {
            data_dir: user_dir.clone(),
            root_pubkey_hex: root_hex.clone(),
            host: None,
            retention: None,
        };
        std::fs::write(
            user_dir.join("config.toml"),
            toml::to_string_pretty(&cfg).unwrap(),
        )
        .unwrap();
        std::fs::write(user_dir.join("identity.ed25519"), agent.to_bytes()).unwrap();
        std::fs::write(user_dir.join("identity.x25519"), [1u8; 32]).unwrap();
        std::fs::write(user_dir.join("iroh.secret"), [2u8; 32]).unwrap();

        // Seed one cap and one topic name.
        let topic_id = [7u8; 32];
        let runtime = NodeRuntime::open(cfg.clone()).await.unwrap();

        // new_unsigned takes 5 args: agent, topics, rights, issued, expires
        let mut cap = Capability::new_unsigned(
            agent.verifying_key().to_bytes(),
            vec!["home.notes".into()],
            vec![Right::Read, Right::Write],
            0,
            None,
        );
        // SigningKey implements RootSigner; sign directly.
        cap.sign(&root).unwrap();
        runtime.node.caps.upsert_grant(&cap).unwrap();

        // Install an epoch key so publish works.
        runtime
            .node
            .install_epoch_key(topic_id, 0, [9u8; 32])
            .unwrap();

        wires_node::upsert_topic_names(
            &user_dir,
            std::iter::once(("home.notes".to_string(), topic_id)),
        )
        .unwrap();

        st.store
            .put_user(&UserRecord {
                root_pubkey_hex: root_hex.clone(),
                data_dir: user_dir.to_string_lossy().into_owned(),
                created_at_ms: 0,
                last_seen_ms: 0,
            })
            .unwrap();

        // Pre-open the runtime in the supervisor so tests don't need to lazy-open.
        // get_or_open reads from users_dir/<root_hex>, which is already user_dir.
        let _ = st.supervisor.get_or_open(&root_hex).await;

        drop(runtime);
        (st, root_hex)
    }

    fn make_claims(st: &ServiceState, sub: String) -> Claims {
        Claims {
            iss: st.config.public_url.clone(),
            sub,
            aud: st.config.public_url.clone(),
            iat: 0,
            exp: i64::MAX,
            jti: "j".into(),
            scope: crate::token::SCOPE_MCP_WIRES.into(),
            client_id: "c1".into(),
        }
    }

    #[tokio::test]
    async fn list_topics_returns_caps_and_names() {
        let tmp = TempDir::new().unwrap();
        let (st, root_hex) = seed_user(&tmp).await;
        let claims = make_claims(&st, root_hex);
        let params = serde_json::json!({"name": "wires_list_topics", "arguments": {}});
        let v = call(st, &claims, &params).await.unwrap();
        let arr = v["content"][0]["text"].as_str().unwrap();
        let body: serde_json::Value = serde_json::from_str(arr).unwrap();
        let topics = body["topics"].as_array().unwrap();
        assert!(topics.iter().any(|t| t["name"] == "home.notes"));
    }

    #[tokio::test]
    async fn publish_rejects_unknown_topic() {
        let tmp = TempDir::new().unwrap();
        let (st, root_hex) = seed_user(&tmp).await;
        let claims = make_claims(&st, root_hex);
        let params = serde_json::json!({
            "name": "wires_publish",
            "arguments": {"topic": "no.such.topic", "text": "hi"}
        });
        let v = call(st, &claims, &params).await.unwrap();
        assert_eq!(v["isError"], true);
        let text = v["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("topic_not_found"), "got: {text}");
    }

    #[tokio::test]
    async fn publish_refuses_caps_topic() {
        let tmp = TempDir::new().unwrap();
        let (st, root_hex) = seed_user(&tmp).await;
        let caps_topic = NodeConfig {
            data_dir: st.config.users_dir().join(&root_hex),
            root_pubkey_hex: root_hex.clone(),
            host: None,
            retention: None,
        }
        .caps_topic_id();
        let claims = make_claims(&st, root_hex);
        let params = serde_json::json!({
            "name": "wires_publish",
            "arguments": {"topic": hex::encode(caps_topic), "text": "x"}
        });
        let v = call(st, &claims, &params).await.unwrap();
        assert_eq!(v["isError"], true);
        let text = v["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("reserved_topic"), "got: {text}");
    }

    #[tokio::test]
    async fn tail_round_trips_a_published_message() {
        let tmp = TempDir::new().unwrap();
        let (st, root_hex) = seed_user(&tmp).await;
        let claims = make_claims(&st, root_hex);
        // Publish via the tool.
        let pub_params = serde_json::json!({
            "name": "wires_publish",
            "arguments": {"topic": "home.notes", "text": "hello"}
        });
        let _ = call(st.clone(), &claims, &pub_params).await.unwrap();
        // Tail.
        let tail_params = serde_json::json!({
            "name": "wires_tail",
            "arguments": {"topic": "home.notes"}
        });
        let v = call(st, &claims, &tail_params).await.unwrap();
        assert_eq!(v["isError"], false);
        let text = v["content"][0]["text"].as_str().unwrap();
        let body: serde_json::Value = serde_json::from_str(text).unwrap();
        let msgs = body["messages"].as_array().unwrap();
        assert!(msgs.iter().any(|m| m["content"]["text"] == "hello"));
        assert!(body.get("next_cursor").is_some());
    }
}

//! wires channel ... subcommands. Spec §10 of wires-channels-design.

use std::path::Path;

use snafu::ResultExt;
use wires_core::Capability;
use wires_core::cap::Right;
use wires_core::channel::types::MemberKind;
use wires_net::unix_now_ms;
use wires_node::{Node, NodeConfig, load_root_signing_key, upsert_topic_names};

use crate::cmd::publish_helpers::find_write_cap_for;
use crate::error::{CoreSnafu, IoSnafu, NodeSnafu, Result, StoreSnafu, TomlParseSnafu};
use crate::invalid;

pub async fn create(data_dir: &Path, name: &str, description: Option<&str>) -> Result<()> {
    let topic_name = if name.starts_with("channels.") {
        name.to_string()
    } else {
        format!("channels.{name}")
    };

    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let node = Node::open(cfg).context(NodeSnafu)?;

    let (topic_id, _epoch_key) = wires_node::channel::allocate_named(&node).context(NodeSnafu)?;
    upsert_topic_names(data_dir, [(topic_name.clone(), topic_id)]).context(NodeSnafu)?;

    // Auto-mint self-cap if this dir holds a root key and no covering cap exists.
    // Mirrors cmd::topic::create.
    if data_dir.join("root.ed25519").exists() {
        let root_sk = load_root_signing_key(data_dir).context(IoSnafu)?;
        let agent_pk = node.ed_sk.verifying_key().to_bytes();
        let has_existing = node.caps.all().context(StoreSnafu)?.values().any(|entry| {
            !entry.revoked
                && entry.cap.agent == agent_pk
                && entry.cap.allows(&topic_name, Right::Write).is_ok()
        });
        if !has_existing {
            let now = unix_now_ms();
            let mut cap = Capability::new_unsigned(
                agent_pk,
                vec![topic_name.clone()],
                vec![Right::Read, Right::Write],
                now,
                None,
            );
            cap.sign(&root_sk).context(CoreSnafu)?;
            node.caps.upsert_grant(&cap).context(StoreSnafu)?;
        }
    }

    let cap_id = find_write_cap_for(&node, &topic_name)
        .ok_or_else(|| invalid!("no cap covers '{topic_name}' for Write"))?;

    let now = unix_now_ms();
    let display_name = load_display_name(data_dir).unwrap_or_else(|| "wires-cli".to_string());

    wires_node::channel::publish_create_and_meta(
        &node,
        topic_id,
        &topic_name,
        cap_id,
        description,
        &display_name,
        MemberKind::Cli,
        now,
    )
    .context(NodeSnafu)?;

    println!(
        "Created channel '{topic_name}' with id {}",
        hex::encode(topic_id)
    );
    Ok(())
}

/// Publish a `MessageKind::Public` envelope containing `content` to `topic_id`.
/// Thin wrapper around `wires_node::channel::publish_public`. Used by
/// `cmd::channel::invite`, `cmd::dm::open`, and `cmd::me::set` until Tasks
/// 24/25 lift those flows into `wires-node` too.
pub(super) fn publish_public(
    node: &Node,
    topic_id: [u8; 32],
    cap_id: wires_core::CapId,
    content_type: &str,
    text: &str,
    content: serde_json::Value,
    timestamp: i64,
) -> Result<()> {
    wires_node::channel::publish_public(
        node,
        topic_id,
        cap_id,
        content_type,
        text,
        content,
        timestamp,
    )
    .context(NodeSnafu)
}

fn load_display_name(data_dir: &Path) -> Option<String> {
    let p = data_dir.join("me.json");
    if !p.exists() {
        return None;
    }
    let raw = std::fs::read_to_string(&p).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    v.get("display_name")
        .and_then(|x| x.as_str())
        .map(str::to_string)
}

pub async fn list(data_dir: &Path) -> Result<()> {
    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let node = Node::open(cfg).context(NodeSnafu)?;
    let names = wires_node::load_topic_names(data_dir).context(IoSnafu)?;
    let self_pk = node.ed_sk.verifying_key().to_bytes();

    let mut shown = 0;
    for (name, topic_id) in &names {
        if !name.starts_with("channels.") || name.starts_with("channels.dm.") {
            continue;
        }
        let log = node.open_topic_log(topic_id).context(NodeSnafu)?;
        let keys = node.epoch_keys_for(topic_id).context(NodeSnafu)?;
        let (_epoch, key) = match keys.latest().context(StoreSnafu)? {
            Some(pair) => pair,
            None => continue,
        };
        let view = wires_node::channel::open_named(*topic_id, &log, &key).context(NodeSnafu)?;
        if view.members.contains_key(&self_pk) {
            if let wires_core::channel::ChannelVariant::Named { name: n, .. } = &view.variant {
                println!(
                    "{}  {}  members={}  pending={}",
                    n,
                    hex::encode(topic_id),
                    view.members.len(),
                    view.pending.len()
                );
            }
            shown += 1;
        }
    }
    if shown == 0 {
        println!("(no channels)");
    }
    Ok(())
}

pub async fn members(data_dir: &Path, name: &str) -> Result<()> {
    let topic_name = if name.starts_with("channels.") {
        name.to_string()
    } else {
        format!("channels.{name}")
    };
    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let node = Node::open(cfg).context(NodeSnafu)?;
    let topic_id = wires_node::resolve_topic(data_dir, &topic_name).context(IoSnafu)?;
    let log = node.open_topic_log(&topic_id).context(NodeSnafu)?;
    let keys = node.epoch_keys_for(&topic_id).context(NodeSnafu)?;
    let (_epoch, key) = keys
        .latest()
        .context(StoreSnafu)?
        .ok_or_else(|| invalid!("no epoch key for {topic_name}",))?;
    let view = wires_node::channel::open_named(topic_id, &log, &key).context(NodeSnafu)?;
    for (pk, meta) in &view.members {
        println!(
            "{}  {:?}  {}  {}",
            hex::encode(pk),
            meta.kind,
            meta.display_name,
            meta.description.as_deref().unwrap_or("")
        );
    }
    if !view.pending.is_empty() {
        println!("--- pending ---");
        for pk in &view.pending {
            println!("{}  (no meta yet)", hex::encode(pk));
        }
    }
    Ok(())
}

pub async fn invite(data_dir: &Path, name: &str, agent_pubkey_hex: &str) -> Result<()> {
    let topic_name = if name.starts_with("channels.") {
        name.to_string()
    } else {
        format!("channels.{name}")
    };
    let agent_bytes =
        hex::decode(agent_pubkey_hex).map_err(|e| invalid!("agent pubkey not hex: {e}", e = e))?;
    let agent: [u8; 32] = agent_bytes
        .try_into()
        .map_err(|_| invalid!("agent pubkey must be 32 bytes",))?;

    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let node = Node::open(cfg).context(NodeSnafu)?;
    let topic_id = wires_node::resolve_topic(data_dir, &topic_name).context(IoSnafu)?;
    let cap_id = find_write_cap_for(&node, &topic_name)
        .ok_or_else(|| invalid!("no cap covers '{topic_name}'",))?;
    let keys = node.epoch_keys_for(&topic_id).context(NodeSnafu)?;
    let (_epoch, key) = keys
        .latest()
        .context(StoreSnafu)?
        .ok_or_else(|| invalid!("no epoch key for {topic_name}",))?;
    let now = unix_now_ms();

    wires_node::channel::invite_member(&node, topic_id, cap_id, agent, &key, now)
        .context(NodeSnafu)?;

    println!("Invited {agent_pubkey_hex} to {topic_name}");
    Ok(())
}

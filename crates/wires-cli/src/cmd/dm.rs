//! wires dm ... subcommands. Spec §10.

use std::path::Path;

use snafu::ResultExt;
use wires_core::CanonicalContent;
use wires_core::channel::types::MemberKind;
use wires_core::wire::MessageKind;
use wires_net::unix_now_ms;
use wires_node::{KeyingMaterial, Node, NodeConfig, PublishParams, build_message, load_dm_roster};

use crate::cmd::publish_helpers::find_write_cap_for;
use crate::error::{IoSnafu, NodeSnafu, Result, TomlParseSnafu};
use crate::invalid;

pub async fn open(data_dir: &Path, other_pubkey_hex: &str, message: Option<&str>) -> Result<()> {
    let other_bytes =
        hex::decode(other_pubkey_hex).map_err(|e| invalid!("agent pubkey not hex: {e}", e = e))?;
    let other: [u8; 32] = other_bytes
        .try_into()
        .map_err(|_| invalid!("agent pubkey must be 32 bytes",))?;

    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let cfg_root_bytes = hex::decode(&cfg.root_pubkey_hex)
        .map_err(|e| invalid!("root pubkey in config not hex: {e}", e = e))?;
    let cfg_root: [u8; 32] = cfg_root_bytes
        .try_into()
        .map_err(|_| invalid!("root pubkey must be 32 bytes",))?;
    let node = Node::open(cfg).context(NodeSnafu)?;

    let other_x_pk = lookup_x25519_pubkey(data_dir, &other).ok_or_else(|| {
        invalid!("no x25519 pubkey on file for {other_pubkey_hex} — pair with them first",)
    })?;

    let now = unix_now_ms();
    let display_name = load_display_name(data_dir).unwrap_or_else(|| "wires-cli".to_string());
    let opened = wires_node::channel::dm_open(
        &node,
        data_dir,
        &cfg_root,
        other,
        other_x_pk,
        &display_name,
        MemberKind::Cli,
        now,
    )
    .context(NodeSnafu)?;

    if let Some(msg_text) = message {
        // Standard-encrypted note. Requires a write cap; dm_open does not
        // demand one (it best-effort skips member_meta publish if absent),
        // so re-check here.
        let cap_id = find_write_cap_for(&node, &opened.topic_name)
            .ok_or_else(|| invalid!("no cap covers '{name}'", name = opened.topic_name))?;
        let canonical = CanonicalContent::new("agent.note", msg_text);
        let (seq, prev_hash) = node
            .next_seq_and_prev_hash(&opened.topic_id)
            .context(NodeSnafu)?;
        let params = PublishParams {
            topic_id: opened.topic_id,
            sender_sk: &node.ed_sk,
            cap_id,
            kind: MessageKind::Standard,
            content: canonical,
            epoch: 0,
            seq,
            prev_hash,
            timestamp: unix_now_ms(),
            keying: KeyingMaterial::StandardEpochKey(&opened.epoch_key),
        };
        let msg = build_message(&params).context(NodeSnafu)?;
        node.append_local(&msg).context(NodeSnafu)?;
    }

    println!("DM topic {}", opened.topic_name);
    Ok(())
}

fn lookup_x25519_pubkey(data_dir: &Path, agent: &[u8; 32]) -> Option<[u8; 32]> {
    let map = load_dm_roster(data_dir).ok()?;
    let hex_key = map.get(&hex::encode(agent))?;
    let bytes = hex::decode(hex_key).ok()?;
    bytes.try_into().ok()
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
    let names = wires_node::load_topic_names(data_dir).context(IoSnafu)?;
    let mut found = 0;
    for (name, topic_id) in names {
        if name.starts_with("channels.dm.") {
            println!("{name}  {}", hex::encode(topic_id));
            found += 1;
        }
    }
    if found == 0 {
        println!("(no DMs)");
    }
    Ok(())
}

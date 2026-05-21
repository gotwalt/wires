//! wires dm ... subcommands. Spec §10.

use std::path::Path;

use snafu::ResultExt;
use wires_core::CanonicalContent;
use wires_core::channel::derive::{dm_epoch_key, dm_topic_id, dm_topic_name, sort_participants};
use wires_core::channel::schemas::{ChannelMemberMeta, TYPE_MEMBER_META};
use wires_core::channel::types::MemberKind;
use wires_core::wire::MessageKind;
use wires_net::unix_now_ms;
use wires_node::{
    KeyingMaterial, Node, NodeConfig, PublishParams, build_message, load_dm_roster,
    upsert_topic_names,
};

use crate::cmd::channel::publish_public;
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
    let self_pk = node.ed_sk.verifying_key().to_bytes();

    let participants = sort_participants(vec![self_pk, other]);
    let topic_id = dm_topic_id(&cfg_root, &participants);

    let other_x_pk = lookup_x25519_pubkey(data_dir, &other).ok_or_else(|| {
        invalid!("no x25519 pubkey on file for {other_pubkey_hex} — pair with them first",)
    })?;
    let self_x_sk_bytes = node.x_sk.to_bytes();
    let epoch_key = dm_epoch_key(&self_x_sk_bytes, &other_x_pk, &cfg_root, &participants);

    node.install_epoch_key(topic_id, 0, epoch_key)
        .context(NodeSnafu)?;
    let topic_name = dm_topic_name(&topic_id);
    upsert_topic_names(data_dir, [(topic_name.clone(), topic_id)]).context(NodeSnafu)?;

    let cap_id = find_write_cap_for(&node, &topic_name)
        .ok_or_else(|| invalid!("no cap covers '{topic_name}'",))?;

    let now = unix_now_ms();

    // Publish member_meta if we haven't already.
    let log = node.open_topic_log(&topic_id).context(NodeSnafu)?;
    let view = wires_node::channel::open_dm(topic_id, participants.clone(), &log, &epoch_key)
        .context(NodeSnafu)?;
    if !view.members.contains_key(&self_pk) {
        let display_name = load_display_name(data_dir).unwrap_or_else(|| "wires-cli".to_string());
        let meta_value = serde_json::to_value(&ChannelMemberMeta {
            kind: MemberKind::Cli,
            display_name: display_name.clone(),
            description: None,
            asserted_at: now,
        })
        .map_err(|e| invalid!("serialize meta: {e}", e = e))?;
        publish_public(
            &node,
            topic_id,
            cap_id,
            TYPE_MEMBER_META,
            &format!("member {display_name}"),
            meta_value,
            now,
        )?;
    }

    if let Some(msg_text) = message {
        // Standard-encrypted note.
        let canonical = CanonicalContent::new("agent.note", msg_text);
        let (seq, prev_hash) = node.next_seq_and_prev_hash(&topic_id).context(NodeSnafu)?;
        let params = PublishParams {
            topic_id,
            sender_sk: &node.ed_sk,
            cap_id,
            kind: MessageKind::Standard,
            content: canonical,
            epoch: 0,
            seq,
            prev_hash,
            timestamp: unix_now_ms(),
            keying: KeyingMaterial::StandardEpochKey(&epoch_key),
        };
        let msg = build_message(&params).context(NodeSnafu)?;
        node.append_local(&msg).context(NodeSnafu)?;
    }

    println!("DM topic {topic_name}");
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

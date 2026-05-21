//! wires channel ... subcommands. Spec §10 of wires-channels-design.

use std::path::Path;

use rand_core::{OsRng, RngCore};
use snafu::ResultExt;
use wires_core::CanonicalContent;
use wires_core::Capability;
use wires_core::cap::Right;
use wires_core::channel::schemas::{
    ChannelCreate, ChannelMemberMeta, TYPE_CREATE, TYPE_MEMBER_META,
};
use wires_core::channel::types::MemberKind;
use wires_core::wire::MessageKind;
use wires_net::unix_now_ms;
use wires_node::{
    KeyingMaterial, Node, NodeConfig, PublishParams, build_message, load_root_signing_key,
    upsert_topic_names,
};

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

    let mut topic_id = [0u8; 32];
    OsRng.fill_bytes(&mut topic_id);
    let mut epoch_key = [0u8; 32];
    OsRng.fill_bytes(&mut epoch_key);
    node.install_epoch_key(topic_id, 0, epoch_key)
        .context(NodeSnafu)?;
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

    let create_value = serde_json::to_value(&ChannelCreate {
        name: topic_name.clone(),
        description: description.map(str::to_string),
        created_at: now,
    })
    .map_err(|e| invalid!("serialize __channel.create: {e}", e = e))?;
    publish_public(
        &node,
        topic_id,
        cap_id,
        TYPE_CREATE,
        &format!("created channel {topic_name}"),
        create_value,
        now,
    )?;

    let display_name = load_display_name(data_dir).unwrap_or_else(|| "wires-cli".to_string());
    let meta_value = serde_json::to_value(&ChannelMemberMeta {
        kind: MemberKind::Cli,
        display_name: display_name.clone(),
        description: None,
        asserted_at: now,
    })
    .map_err(|e| invalid!("serialize __channel.member_meta: {e}", e = e))?;
    publish_public(
        &node,
        topic_id,
        cap_id,
        TYPE_MEMBER_META,
        &format!("member {display_name}"),
        meta_value,
        now,
    )?;

    println!(
        "Created channel '{topic_name}' with id {}",
        hex::encode(topic_id)
    );
    Ok(())
}

/// Publish a `MessageKind::Public` envelope containing `content` to `topic_id`.
/// Reused by Tasks 17, 18, 20.
pub(super) fn publish_public(
    node: &Node,
    topic_id: [u8; 32],
    cap_id: wires_core::CapId,
    content_type: &str,
    text: &str,
    content: serde_json::Value,
    timestamp: i64,
) -> Result<()> {
    let canonical = CanonicalContent::new(content_type, text).with_data(content);
    let (seq, prev_hash) = node.next_seq_and_prev_hash(&topic_id).context(NodeSnafu)?;
    let params = PublishParams {
        topic_id,
        sender_sk: &node.ed_sk,
        cap_id,
        kind: MessageKind::Public,
        content: canonical,
        epoch: 0,
        seq,
        prev_hash,
        timestamp,
        keying: KeyingMaterial::Public,
    };
    let msg = build_message(&params).context(NodeSnafu)?;
    node.append_local(&msg).context(NodeSnafu)?;
    Ok(())
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

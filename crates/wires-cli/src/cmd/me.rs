//! wires me set — update local member meta and republish into every joined
//! channels.* topic.

use std::path::Path;

use snafu::ResultExt;
use wires_core::channel::schemas::{ChannelMemberMeta, TYPE_MEMBER_META};
use wires_core::channel::types::MemberKind;
use wires_net::unix_now_ms;
use wires_node::{Node, NodeConfig};

use crate::cmd::channel::publish_public;
use crate::cmd::publish_helpers::find_write_cap_for;
use crate::error::{IoSnafu, NodeSnafu, Result, TomlParseSnafu};
use crate::invalid;

pub async fn set(
    data_dir: &Path,
    kind: &str,
    display_name: &str,
    description: Option<&str>,
) -> Result<()> {
    // Validate kind by attempting to parse it as MemberKind.
    let parsed_kind: MemberKind = serde_json::from_str(&format!("\"{kind}\""))
        .map_err(|_| invalid!("kind must be one of: agent, api, cli, human, unknown"))?;

    // Write me.json with the provided metadata.
    let me = serde_json::json!({
        "kind": kind,
        "display_name": display_name,
        "description": description,
    });
    std::fs::write(
        data_dir.join("me.json"),
        serde_json::to_vec_pretty(&me).expect("JSON serializes"),
    )
    .context(IoSnafu)?;

    // Load node and topic names to find channels.* topics with write caps.
    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let node = Node::open(cfg).context(NodeSnafu)?;
    let names = wires_node::load_topic_names(data_dir).context(IoSnafu)?;

    let now = unix_now_ms();
    let mut count = 0;

    // Republish __channel.member_meta into every channels.* topic with a write cap.
    for (name, topic_id) in names {
        if !name.starts_with("channels.") {
            continue;
        }
        let cap_id = match find_write_cap_for(&node, &name) {
            Some(id) => id,
            None => continue,
        };

        let meta = ChannelMemberMeta {
            kind: parsed_kind,
            display_name: display_name.to_string(),
            description: description.map(str::to_string),
            asserted_at: now,
        };

        let value =
            serde_json::to_value(&meta).map_err(|e| invalid!("serialize meta: {e}", e = e))?;

        publish_public(
            &node,
            topic_id,
            cap_id,
            TYPE_MEMBER_META,
            &format!("member {display_name}"),
            value,
            now,
        )?;

        count += 1;
    }

    println!("Updated member_meta and republished into {count} channel(s).");
    Ok(())
}

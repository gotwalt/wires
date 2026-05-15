use std::path::Path;

use chrono::TimeZone;
use snafu::ResultExt;
use wires_node::{DecryptedEvent, Inbound, NodeConfig, NodeRuntime, resolve_topic};

use crate::cmd::publish_helpers::{bootstrap_endpoints, register_peer_addresses};
use crate::error::{IoSnafu, NodeSnafu, Result, StoreSnafu, TomlParseSnafu};

pub async fn run(data_dir: &Path, topic: &str, tail: bool) -> Result<()> {
    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let topic_id = resolve_topic(data_dir, topic).context(IoSnafu)?;
    let bootstrap = bootstrap_endpoints(&cfg);
    let host_configured = cfg.host.is_some();

    let runtime = NodeRuntime::open(cfg).await.context(NodeSnafu)?;
    register_peer_addresses(&runtime)?;
    runtime
        .join_topic(topic_id, bootstrap)
        .await
        .context(NodeSnafu)?;
    if host_configured {
        match runtime.replay_from_host(topic_id).await {
            Ok(n) => eprintln!("(replay catch-up: {n} envelopes from host)"),
            Err(e) => eprintln!("(replay catch-up skipped: {e})"),
        }
    }

    let log = runtime
        .node
        .logs
        .get_or_open(&topic_id)
        .context(NodeSnafu)?;
    for msg in log.read_all().context(StoreSnafu)? {
        let outcome = runtime
            .node
            .handle_inbound(msg.clone())
            .context(NodeSnafu)?;
        let content = match outcome {
            Inbound::Accepted { content, .. } => content,
            _ => None,
        };
        print_event(&DecryptedEvent {
            topic_id,
            msg,
            content,
        });
    }

    if !tail {
        return Ok(());
    }

    let mut sub = runtime.node.subscribe();
    while let Ok(ev) = sub.recv().await {
        if ev.topic_id == topic_id {
            print_event(&ev);
        }
    }
    Ok(())
}

fn print_event(ev: &DecryptedEvent) {
    let ts = chrono::Utc
        .timestamp_millis_opt(ev.msg.timestamp)
        .single()
        .unwrap_or_default();
    let sender_short = &hex::encode(ev.msg.sender)[..8];
    match &ev.content {
        Some(c) => println!(
            "{} {} {} | {} :: {}",
            ts.format("%Y-%m-%d %H:%M:%S%.3f"),
            sender_short,
            ev.msg.seq,
            c.type_,
            c.text
        ),
        None => println!(
            "{} {} {} | <opaque>",
            ts.format("%Y-%m-%d %H:%M:%S%.3f"),
            sender_short,
            ev.msg.seq
        ),
    }
}

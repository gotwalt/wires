use std::path::Path;

use chrono::TimeZone;
use wires_node::{DecryptedEvent, Inbound, Node, NodeConfig};

use crate::cmd::publish::resolve_topic;

pub async fn run(
    data_dir: &Path,
    topic: &str,
    tail: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
    let node = Node::open(cfg)?;
    let topic_id = resolve_topic(data_dir, topic)?;
    let log = node.logs.get_or_open(&topic_id)?;
    for msg in log.read_all()? {
        let outcome = node.handle_inbound(msg.clone())?;
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

    let mut sub = node.subscribe();
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

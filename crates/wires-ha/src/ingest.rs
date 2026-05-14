//! HA event → wires message translation and the publish loop.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value};
use tokio::time::sleep;
use wires_core::CanonicalContent;
use wires_net::GossipHandle;
use wires_node::Node;

use crate::ha::{self, HaEvent};

/// `type` value used for every published message.
pub const CONTENT_TYPE: &str = "home.ha.state_changed";

/// Translate one `HaEvent` into the `CanonicalContent` body that gets encrypted
/// and signed. Always sets `type` and `text`; `data` carries the structured
/// payload with `null`s elided.
pub fn translate(event: &HaEvent) -> CanonicalContent {
    let old = event.old_state.as_deref().unwrap_or("?");
    let new = event.new_state.as_deref().unwrap_or("?");
    let text = format!("{}: {} → {}", event.entity_id, old, new);

    let mut data = Map::new();
    data.insert("entity_id".into(), Value::String(event.entity_id.clone()));
    if let Some(ns) = &event.new_state {
        data.insert("new_state".into(), Value::String(ns.clone()));
    }
    if let Some(os) = &event.old_state {
        data.insert("old_state".into(), Value::String(os.clone()));
    }
    if let Some(attrs) = &event.attributes {
        data.insert("attributes".into(), attrs.clone());
    }
    if let Some(tf) = &event.time_fired {
        data.insert("time_fired".into(), Value::String(tf.clone()));
    }
    if let Some(cid) = &event.context_id {
        data.insert("context_id".into(), Value::String(cid.clone()));
    }

    CanonicalContent::new(CONTENT_TYPE, text).with_data(Value::Object(data))
}

/// Run the ingest loop until cancelled. Reconnects with exponential backoff
/// on any error from the WebSocket session.
pub async fn run(
    node: Arc<Node>,
    gossip: GossipHandle,
    topic_id: [u8; 32],
    cap_id: [u8; 16],
    ha_url: String,
    access_token: String,
    max_backoff: Duration,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        match run_session(&node, &gossip, topic_id, cap_id, &ha_url, &access_token).await {
            Ok(()) => {
                tracing::warn!("HA WebSocket closed cleanly; reconnecting in {:?}", backoff);
            }
            Err(e) => {
                tracing::warn!(error = %e, "HA session ended; reconnecting in {:?}", backoff);
            }
        }
        sleep(backoff).await;
        backoff = (backoff * 2).min(max_backoff);
    }
}

async fn run_session(
    node: &Arc<Node>,
    gossip: &GossipHandle,
    topic_id: [u8; 32],
    cap_id: [u8; 16],
    ha_url: &str,
    access_token: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut ws = ha::connect(ha_url, access_token).await?;
    tracing::info!("subscribed to HA state_changed events");
    while let Some(value) = ha::next_frame(&mut ws).await? {
        let Some(event) = ha::parse_event(&value) else {
            continue;
        };
        if let Err(e) = publish_event(node, gossip, topic_id, cap_id, &event).await {
            tracing::warn!(error = %e, entity = %event.entity_id, "failed to publish event");
        }
    }
    Ok(())
}

async fn publish_event(
    node: &Arc<Node>,
    gossip: &GossipHandle,
    topic_id: [u8; 32],
    cap_id: [u8; 16],
    event: &HaEvent,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let content = translate(event);
    let msg = node.publish_standard(topic_id, cap_id, content)?;
    let bytes = serde_json::to_vec(&msg)?;
    gossip.broadcast(bytes).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(entity: &str, old: Option<&str>, new: Option<&str>) -> HaEvent {
        HaEvent {
            entity_id: entity.into(),
            new_state: new.map(str::to_string),
            old_state: old.map(str::to_string),
            attributes: Some(json!({"friendly_name": "X"})),
            time_fired: Some("2026-05-14T12:00:00Z".into()),
            context_id: Some("ctx-1".into()),
        }
    }

    #[test]
    fn translate_sets_type_and_text() {
        let c = translate(&event("light.kitchen", Some("off"), Some("on")));
        assert_eq!(c.type_, CONTENT_TYPE);
        assert_eq!(c.text, "light.kitchen: off → on");
        let data = c.data.unwrap();
        assert_eq!(data["entity_id"], "light.kitchen");
        assert_eq!(data["new_state"], "on");
        assert_eq!(data["old_state"], "off");
        assert_eq!(data["time_fired"], "2026-05-14T12:00:00Z");
        assert_eq!(data["context_id"], "ctx-1");
        assert_eq!(data["attributes"]["friendly_name"], "X");
    }

    #[test]
    fn translate_handles_missing_states() {
        let c = translate(&event("sensor.new", None, Some("21.5")));
        assert_eq!(c.text, "sensor.new: ? → 21.5");
        let data = c.data.unwrap();
        assert!(data.get("old_state").is_none());
        assert_eq!(data["new_state"], "21.5");
    }

    #[test]
    fn translate_elides_null_optional_fields() {
        let ev = HaEvent {
            entity_id: "sensor.bare".into(),
            new_state: Some("ok".into()),
            old_state: None,
            attributes: None,
            time_fired: None,
            context_id: None,
        };
        let c = translate(&ev);
        let data = c.data.unwrap();
        assert!(data.get("attributes").is_none());
        assert!(data.get("time_fired").is_none());
        assert!(data.get("context_id").is_none());
        assert!(data.get("old_state").is_none());
    }
}

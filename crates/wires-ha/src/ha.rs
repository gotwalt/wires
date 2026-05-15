//! Home Assistant WebSocket client.
//!
//! Handles the auth handshake and the `subscribe_events` subscription, then
//! returns the underlying WebSocket stream so the caller can pump frames.
//! Event parsing is split into [`parse_event`] so it can be unit-tested
//! against recorded HA frames without any network.

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use snafu::{OptionExt, ResultExt, Snafu};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

pub type HaWs = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Debug, Snafu)]
pub enum HaError {
    #[snafu(display("Invalid Home Assistant URL '{url}', at {location}"))]
    Url {
        url: String,
        #[snafu(implicit)]
        location: snafu::Location,
    },
    #[snafu(display("WebSocket connect/IO error, at {location}"))]
    Ws {
        #[snafu(source)]
        source: tokio_tungstenite::tungstenite::Error,
        #[snafu(implicit)]
        location: snafu::Location,
    },
    #[snafu(display("WebSocket closed before handshake completed, at {location}"))]
    ClosedEarly {
        #[snafu(implicit)]
        location: snafu::Location,
    },
    #[snafu(display("Non-text frame during handshake, at {location}"))]
    UnexpectedFrame {
        #[snafu(implicit)]
        location: snafu::Location,
    },
    #[snafu(display("Bad JSON from Home Assistant, at {location}"))]
    Json {
        #[snafu(source)]
        source: serde_json::Error,
        #[snafu(implicit)]
        location: snafu::Location,
    },
    #[snafu(display("Unexpected handshake frame: expected {expected}, got {got}, at {location}"))]
    HandshakeProtocol {
        expected: String,
        got: String,
        #[snafu(implicit)]
        location: snafu::Location,
    },
    #[snafu(display("Home Assistant rejected access token: {message}, at {location}"))]
    AuthInvalid {
        message: String,
        #[snafu(implicit)]
        location: snafu::Location,
    },
    #[snafu(display("subscribe_events failed: {message}, at {location}"))]
    SubscribeFailed {
        message: String,
        #[snafu(implicit)]
        location: snafu::Location,
    },
}

/// One Home Assistant `state_changed` event after light parsing. Untyped
/// `Value`s preserve whatever HA sends (attributes vary wildly by domain).
#[derive(Debug, Clone, PartialEq)]
pub struct HaEvent {
    pub entity_id: String,
    pub new_state: Option<String>,
    pub old_state: Option<String>,
    pub attributes: Option<Value>,
    pub time_fired: Option<String>,
    pub context_id: Option<String>,
}

/// Connect, auth, and subscribe to `state_changed`. Returns the live stream
/// positioned right after the `subscribe_events` `result` frame; the caller
/// drives it from there.
pub async fn connect(url: &str, access_token: &str) -> Result<HaWs, HaError> {
    if url::Url::parse(url).is_err() {
        return UrlSnafu {
            url: url.to_string(),
        }
        .fail();
    }
    let (mut ws, _resp) = connect_async(url).await.context(WsSnafu)?;

    // 1. auth_required
    let first = recv_json(&mut ws).await?;
    expect_type(&first, "auth_required").map_err(|e| *e)?;

    // 2. send auth
    let auth = json!({ "type": "auth", "access_token": access_token });
    ws.send(Message::Text(auth.to_string()))
        .await
        .context(WsSnafu)?;

    // 3. auth_ok or auth_invalid
    let reply = recv_json(&mut ws).await?;
    match reply.get("type").and_then(Value::as_str) {
        Some("auth_ok") => {}
        Some("auth_invalid") => {
            let message = reply
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            return AuthInvalidSnafu { message }.fail();
        }
        other => {
            return HandshakeProtocolSnafu {
                expected: "auth_ok|auth_invalid".to_string(),
                got: other.unwrap_or("(missing)").to_string(),
            }
            .fail();
        }
    }

    // 4. subscribe_events
    let sub = json!({ "id": 1, "type": "subscribe_events", "event_type": "state_changed" });
    ws.send(Message::Text(sub.to_string()))
        .await
        .context(WsSnafu)?;

    // 5. expect a result frame
    let result = recv_json(&mut ws).await?;
    let success = result
        .get("type")
        .and_then(Value::as_str)
        .map(|t| t == "result")
        .unwrap_or(false)
        && result
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    if !success {
        let message = result
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("subscribe_events not acknowledged")
            .to_string();
        return SubscribeFailedSnafu { message }.fail();
    }

    Ok(ws)
}

async fn recv_json(ws: &mut HaWs) -> Result<Value, HaError> {
    loop {
        let next = ws.next().await.context(ClosedEarlySnafu)?;
        let frame = next.context(WsSnafu)?;
        match frame {
            Message::Text(t) => return serde_json::from_str(&t).context(JsonSnafu),
            Message::Binary(b) => return serde_json::from_slice(&b).context(JsonSnafu),
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => return ClosedEarlySnafu.fail(),
            Message::Frame(_) => return UnexpectedFrameSnafu.fail(),
        }
    }
}

fn expect_type(v: &Value, expected: &str) -> std::result::Result<(), Box<HaError>> {
    let got = v.get("type").and_then(Value::as_str).unwrap_or("(missing)");
    if got == expected {
        Ok(())
    } else {
        Err(Box::new(
            HandshakeProtocolSnafu {
                expected: expected.to_string(),
                got: got.to_string(),
            }
            .build(),
        ))
    }
}

/// Try to extract an `HaEvent` from one decoded WebSocket frame. Returns
/// `None` for any frame that isn't a `state_changed` event (other event
/// types, `pong`s, `result` frames, etc.) so the caller can drop them.
pub fn parse_event(value: &Value) -> Option<HaEvent> {
    if value.get("type").and_then(Value::as_str)? != "event" {
        return None;
    }
    let event = value.get("event")?;
    if event.get("event_type").and_then(Value::as_str)? != "state_changed" {
        return None;
    }
    let data = event.get("data")?;
    let entity_id = data.get("entity_id").and_then(Value::as_str)?.to_string();

    let new_state_obj = data.get("new_state");
    let old_state_obj = data.get("old_state");

    Some(HaEvent {
        entity_id,
        new_state: state_string(new_state_obj),
        old_state: state_string(old_state_obj),
        attributes: new_state_obj.and_then(|s| s.get("attributes")).cloned(),
        time_fired: event
            .get("time_fired")
            .and_then(Value::as_str)
            .map(str::to_string),
        context_id: event
            .get("context")
            .and_then(|c| c.get("id"))
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

fn state_string(state: Option<&Value>) -> Option<String> {
    state?
        .get("state")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Read the next frame from `ws` and decode it as a JSON value, looping past
/// ping/pong frames. Returns `Ok(None)` if the stream cleanly closes.
pub async fn next_frame(ws: &mut HaWs) -> Result<Option<Value>, HaError> {
    loop {
        let Some(next) = ws.next().await else {
            return Ok(None);
        };
        let frame = next.context(WsSnafu)?;
        match frame {
            Message::Text(t) => return Ok(Some(serde_json::from_str(&t).context(JsonSnafu)?)),
            Message::Binary(b) => return Ok(Some(serde_json::from_slice(&b).context(JsonSnafu)?)),
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => return Ok(None),
            Message::Frame(_) => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_state_changed_event() {
        let frame = json!({
            "id": 1,
            "type": "event",
            "event": {
                "event_type": "state_changed",
                "data": {
                    "entity_id": "light.kitchen",
                    "old_state": {
                        "entity_id": "light.kitchen",
                        "state": "off",
                        "attributes": {"friendly_name": "Kitchen"}
                    },
                    "new_state": {
                        "entity_id": "light.kitchen",
                        "state": "on",
                        "attributes": {"friendly_name": "Kitchen", "brightness": 254}
                    }
                },
                "origin": "LOCAL",
                "time_fired": "2026-05-14T12:00:00.000000+00:00",
                "context": {"id": "abc123", "parent_id": null, "user_id": null}
            }
        });
        let ev = parse_event(&frame).unwrap();
        assert_eq!(ev.entity_id, "light.kitchen");
        assert_eq!(ev.new_state.as_deref(), Some("on"));
        assert_eq!(ev.old_state.as_deref(), Some("off"));
        assert_eq!(
            ev.time_fired.as_deref(),
            Some("2026-05-14T12:00:00.000000+00:00")
        );
        assert_eq!(ev.context_id.as_deref(), Some("abc123"));
        let attrs = ev.attributes.unwrap();
        assert_eq!(attrs["brightness"], 254);
    }

    #[test]
    fn handles_missing_old_state() {
        let frame = json!({
            "id": 1,
            "type": "event",
            "event": {
                "event_type": "state_changed",
                "data": {
                    "entity_id": "sensor.new",
                    "old_state": null,
                    "new_state": {"state": "21.5", "attributes": {"unit": "°C"}}
                },
                "time_fired": "2026-05-14T12:00:00Z",
                "context": {"id": "x"}
            }
        });
        let ev = parse_event(&frame).unwrap();
        assert_eq!(ev.entity_id, "sensor.new");
        assert_eq!(ev.new_state.as_deref(), Some("21.5"));
        assert!(ev.old_state.is_none());
    }

    #[test]
    fn ignores_non_state_changed_events() {
        let other_event = json!({
            "type": "event",
            "event": {
                "event_type": "call_service",
                "data": {"domain": "light", "service": "turn_on"}
            }
        });
        assert!(parse_event(&other_event).is_none());

        let result_frame = json!({"id": 1, "type": "result", "success": true, "result": null});
        assert!(parse_event(&result_frame).is_none());

        let pong = json!({"id": 2, "type": "pong"});
        assert!(parse_event(&pong).is_none());
    }
}

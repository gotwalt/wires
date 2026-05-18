use serde_json::Value;

use crate::http::ServiceState;
use crate::mcp::router::JsonRpcError;
use crate::token::Claims;

pub fn list_descriptors() -> Value {
    serde_json::json!({"tools": [
        {"name": "wires.list_topics", "description": "List topics this agent can access", "inputSchema": {"type":"object","properties":{}}},
        {"name": "wires.publish",     "description": "Publish a message to a topic",       "inputSchema": {"type":"object","properties":{"topic":{"type":"string"},"text":{"type":"string"},"data":{"type":"object"}},"required":["topic","text"]}},
        {"name": "wires.tail",        "description": "Read recent messages from a topic",  "inputSchema": {"type":"object","properties":{"topic":{"type":"string"},"since":{"type":"string"},"limit":{"type":"integer"}},"required":["topic"]}}
    ]})
}

pub async fn call(
    _state: ServiceState,
    _claims: &Claims,
    _params: &Value,
) -> Result<Value, JsonRpcError> {
    Err(JsonRpcError { code: -32601, message: "tools/call not yet wired (see Tasks 26–28)".into() })
}

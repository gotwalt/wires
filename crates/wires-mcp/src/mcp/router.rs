//! Minimal MCP streamable-HTTP route. Accepts JSON-RPC 2.0 envelopes on
//! POST /mcp, dispatches `initialize`, `tools/list`, `tools/call` to the
//! handlers in `crate::mcp::tools`. Pulls the bound user's `NodeRuntime`
//! from the supervisor by the JWT's `sub`.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::http::ServiceState;
use crate::mcp::tools;
use crate::token::Claims;

#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

pub async fn handler(
    State(state): State<ServiceState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Json(req): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let id = req.id.unwrap_or(serde_json::Value::Null);
    let result = match req.method.as_str() {
        "initialize" => Ok(serde_json::json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "wires-mcp", "version": env!("CARGO_PKG_VERSION") }
        })),
        "tools/list" => Ok(tools::list_descriptors()),
        "tools/call" => tools::call(state, &claims, &req.params).await,
        _ => Err(JsonRpcError {
            code: -32601,
            message: format!("method not found: {}", req.method),
        }),
    };
    let resp = match result {
        Ok(v) => JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(v),
            error: None,
        },
        Err(e) => JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(e),
        },
    };
    (StatusCode::OK, Json(resp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{ServiceState, test_state};
    use crate::store::{OauthClientRecord, UserRecord};
    use crate::token::{MintInput, mint};
    use axum::body::Body;
    use axum::http::Request;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn bearer(state: &ServiceState, sub: &str, client_id: &str) -> String {
        mint(
            &state.signing_key,
            &MintInput {
                iss: &state.config.public_url,
                sub,
                aud: &state.config.public_url,
                now_s: chrono::Utc::now().timestamp(),
                ttl_s: 60,
                client_id,
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn initialize_returns_protocol_version() {
        let tmp = TempDir::new().unwrap();
        let st = test_state(tmp.path());
        let sub = "ab".repeat(32);
        st.store
            .put_user(&UserRecord {
                root_pubkey_hex: sub.clone(),
                data_dir: "x".into(),
                created_at_ms: 0,
                last_seen_ms: 0,
            })
            .unwrap();
        st.store
            .put_oauth_client(&OauthClientRecord {
                client_id: "c1".into(),
                client_name: "C".into(),
                redirect_uris: vec!["http://x".into()],
                grant_types: vec!["authorization_code".into()],
                created_at_ms: 0,
                revoked: false,
            })
            .unwrap();
        let token = bearer(&st, &sub, "c1");
        let body =
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
        let resp = crate::http::app(st)
            .oneshot(
                Request::post("/mcp")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 1);
        assert_eq!(v["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn mcp_route_requires_bearer() {
        let tmp = TempDir::new().unwrap();
        let st = test_state(tmp.path());
        let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"});
        let resp = crate::http::app(st)
            .oneshot(
                Request::post("/mcp")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

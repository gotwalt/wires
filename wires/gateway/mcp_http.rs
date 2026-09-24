//! `POST /mcp`: the Streamable HTTP binding of MCP, over the same core as
//! `wires mcp` ([`McpServer`]).
//!
//! Dual-era, as the 2026-07-28 versioning page allows:
//!
//! - **Modern** (2026-07-28): every request carries its version in `_meta`,
//!   mirrored in `MCP-Protocol-Version`, plus `Mcp-Method` (and `Mcp-Name`
//!   for `tools/call`). Headers that disagree with the body, or are missing,
//!   are `400` + `HeaderMismatch`; an unknown version is `400` +
//!   `UnsupportedProtocolVersion`; an unknown method is `404` + `-32601`.
//! - **Legacy** (2025-11-25 and earlier): `initialize` first, then the agreed
//!   version in `MCP-Protocol-Version` (or none, read as 2025-03-26). No
//!   `Mcp-Session-Id` is minted: nothing here is per-session.
//!
//! Every response is one `application/json` body (no SSE: nothing here
//! streams, and there are no server-initiated messages). A notification is
//! `202`. `GET` and `DELETE` are `405`. An `Origin` that isn't allowed is
//! `403` (DNS-rebinding protection). No valid bearer token is `401` with the
//! [`challenge`].
//!
//! The tool list is computed per request from the signed state the gateway
//! holds and the caller's verified principal, so an admin's change applies
//! to the next request.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use serde_json::Value;
#[cfg(test)]
use serde_json::json;

use super::oauth::challenge;
use super::{Backend, Gateway};
use crate::caller::mcp::{
    HEADER_MISMATCH, INVALID_REQUEST, META_PROTOCOL_VERSION, METHOD_NOT_FOUND, McpServer,
    PARSE_ERROR, RpcError, SUPPORTED_PROTOCOL_VERSIONS, UNSUPPORTED_PROTOCOL_VERSION,
    error_response, is_modern,
};

/// The version a legacy request with no `MCP-Protocol-Version` speaks.
pub(crate) const HEADERLESS_VERSION: &str = "2025-03-26";

/// Decode an `Mcp-Name` / `Mcp-Param-*` value: plain ASCII as is, or the
/// `=?base64?…?=` sentinel form. `None` if the sentinel doesn't decode.
pub(crate) fn decode_header_value(v: &str) -> Option<String> {
    match v
        .strip_prefix("=?base64?")
        .and_then(|rest| rest.strip_suffix("?="))
    {
        Some(b64) => base64::engine::general_purpose::STANDARD
            .decode(b64)
            .ok()
            .and_then(|b| String::from_utf8(b).ok()),
        None => Some(v.to_owned()),
    }
}

/// The era and version of one request, or the error to answer with.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Era {
    /// Modern: the version is in the body's `_meta` (and the header agrees).
    Modern,
    /// Legacy: `initialize`, or the version a prior `initialize` agreed.
    Legacy(Option<String>),
}

/// Classify a request and check its mirrored headers (2026-07-28
/// "Server Validation"). `Err` carries the JSON-RPC error for a `400`.
pub(crate) fn check_headers(headers: &HeaderMap, msg: &Value) -> Result<Era, RpcError> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let mismatch =
        |what: String| RpcError::new(HEADER_MISMATCH, format!("Header mismatch: {what}"));
    let method = msg
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let params = msg.get("params");
    let body_version = params
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get(META_PROTOCOL_VERSION))
        .and_then(Value::as_str);
    let header_version = header("mcp-protocol-version");
    let modern = body_version.is_some() || header_version.is_some_and(is_modern);
    if !modern {
        if method == "initialize" {
            return Ok(Era::Legacy(None));
        }
        let v = header_version.unwrap_or(HEADERLESS_VERSION);
        if !SUPPORTED_PROTOCOL_VERSIONS.contains(&v) {
            return Err(RpcError::unsupported_version(v));
        }
        return Ok(Era::Legacy(Some(v.to_owned())));
    }
    match (header_version, body_version) {
        (Some(h), Some(b)) if h == b => {}
        (None, _) => return Err(mismatch("MCP-Protocol-Version header is required".into())),
        (Some(h), b) => {
            return Err(mismatch(format!(
                "MCP-Protocol-Version header '{h}' does not match body value '{}'",
                b.unwrap_or("(none)")
            )));
        }
    }
    let v = body_version.unwrap_or_default();
    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&v) {
        return Err(RpcError::unsupported_version(v));
    }
    match header("mcp-method") {
        Some(m) if m == method => {}
        Some(m) => {
            return Err(mismatch(format!(
                "Mcp-Method header '{m}' does not match body value '{method}'"
            )));
        }
        None => return Err(mismatch("Mcp-Method header is required".into())),
    }
    let name_field = match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        _ => None,
    };
    if let Some(field) = name_field {
        let body = params
            .and_then(|p| p.get(field))
            .and_then(Value::as_str)
            .unwrap_or_default();
        match header("mcp-name").map(decode_header_value) {
            Some(Some(n)) if n == body => {}
            Some(Some(n)) => {
                return Err(mismatch(format!(
                    "Mcp-Name header value '{n}' does not match body value '{body}'"
                )));
            }
            Some(None) => return Err(mismatch("Mcp-Name header is not valid base64".into())),
            None => return Err(mismatch("Mcp-Name header is required".into())),
        }
    }
    Ok(Era::Modern)
}

/// The HTTP status a JSON-RPC reply goes out with.
pub(crate) fn status_for(reply: &Value, modern: bool) -> StatusCode {
    match reply
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_i64)
    {
        Some(HEADER_MISMATCH | UNSUPPORTED_PROTOCOL_VERSION | PARSE_ERROR | INVALID_REQUEST) => {
            StatusCode::BAD_REQUEST
        }
        Some(METHOD_NOT_FOUND) if modern => StatusCode::NOT_FOUND,
        _ => StatusCode::OK,
    }
}

/// `GET` / `DELETE /mcp`: no standalone stream, no sessions.
pub(crate) async fn not_allowed() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, "POST")],
        "wires gateway: POST JSON-RPC to this endpoint",
    )
        .into_response()
}

fn json_reply(status: StatusCode, body: &Value) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        body.to_string(),
    )
        .into_response()
}

/// `POST /mcp`.
pub(crate) async fn post<B: Backend>(
    State(gw): State<Arc<Gateway<B>>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Some(origin) = headers.get(header::ORIGIN) {
        let ok = origin
            .to_str()
            .is_ok_and(|o| gw.origins.iter().any(|a| a.eq_ignore_ascii_case(o)));
        if !ok {
            return json_reply(
                StatusCode::FORBIDDEN,
                &error_response(
                    Value::Null,
                    RpcError::new(INVALID_REQUEST, "origin not allowed"),
                ),
            );
        }
    }
    let now = crate::clock::now_unix();
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        });
    let session = match bearer {
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, challenge(&gw.urls, None))],
            )
                .into_response();
        }
        Some(token) => match gw.store.session(token.trim(), now) {
            Some(s) if s.resource == gw.urls.resource() => s,
            _ => {
                return (
                    StatusCode::UNAUTHORIZED,
                    [(
                        header::WWW_AUTHENTICATE,
                        challenge(&gw.urls, Some("invalid_token")),
                    )],
                )
                    .into_response();
            }
        },
    };
    let msg: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            let reply = error_response(
                Value::Null,
                RpcError::new(PARSE_ERROR, format!("parse error: {e}")),
            );
            return json_reply(StatusCode::BAD_REQUEST, &reply);
        }
    };
    if !msg.is_object() {
        let reply = error_response(
            Value::Null,
            RpcError::new(
                INVALID_REQUEST,
                "expected a single JSON-RPC request or notification",
            ),
        );
        return json_reply(StatusCode::BAD_REQUEST, &reply);
    }
    let id = msg.get("id").cloned();
    let era = match check_headers(&headers, &msg) {
        Ok(era) => era,
        Err(e) => {
            return json_reply(
                StatusCode::BAD_REQUEST,
                &error_response(id.unwrap_or(Value::Null), e),
            );
        }
    };
    if id.is_none() {
        return StatusCode::ACCEPTED.into_response();
    }
    let tools = match gw.tools_for(&session.principal) {
        Ok((_, tools)) => tools,
        Err(e) => {
            tracing::warn!("gateway: no usable signed state: {e:#}");
            let reply = error_response(
                id.unwrap_or(Value::Null),
                RpcError::new(-32000, "the gateway holds no usable signed state"),
            );
            return json_reply(StatusCode::SERVICE_UNAVAILABLE, &reply);
        }
    };
    let (modern, negotiated) = match era {
        Era::Modern => (true, None),
        Era::Legacy(v) => (false, v),
    };
    let mut server = McpServer::new(tools, gw.backend.caller(session.id_token.clone()))
        .with_negotiated(negotiated)
        .with_redacted_failures();
    let Some(reply) = server.handle(msg).await else {
        return StatusCode::ACCEPTED.into_response();
    };
    json_reply(status_for(&reply, modern), &reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    fn modern_call(name: &str) -> Value {
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":name,"arguments":{},"_meta":{META_PROTOCOL_VERSION:"2026-07-28"}}})
    }

    #[test]
    fn a_modern_request_must_mirror_its_body() {
        let good = headers(&[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tools/call"),
            ("mcp-name", "orders-db"),
        ]);
        assert_eq!(
            check_headers(&good, &modern_call("orders-db")),
            Ok(Era::Modern)
        );
        let encoded = headers(&[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tools/call"),
            ("mcp-name", "=?base64?b3JkZXJzLWRi?="),
        ]);
        assert_eq!(
            check_headers(&encoded, &modern_call("orders-db")),
            Ok(Era::Modern)
        );
        for (bad, why) in [
            (
                vec![("mcp-method", "tools/call"), ("mcp-name", "orders-db")],
                "no version header",
            ),
            (
                vec![
                    ("mcp-protocol-version", "2025-11-25"),
                    ("mcp-method", "tools/call"),
                    ("mcp-name", "orders-db"),
                ],
                "version differs",
            ),
            (
                vec![
                    ("mcp-protocol-version", "2026-07-28"),
                    ("mcp-name", "orders-db"),
                ],
                "no method",
            ),
            (
                vec![
                    ("mcp-protocol-version", "2026-07-28"),
                    ("mcp-method", "tools/list"),
                    ("mcp-name", "orders-db"),
                ],
                "method differs",
            ),
            (
                vec![
                    ("mcp-protocol-version", "2026-07-28"),
                    ("mcp-method", "tools/call"),
                ],
                "no name",
            ),
            (
                vec![
                    ("mcp-protocol-version", "2026-07-28"),
                    ("mcp-method", "tools/call"),
                    ("mcp-name", "status"),
                ],
                "name differs",
            ),
        ] {
            let e = check_headers(&headers(&bad), &modern_call("orders-db")).unwrap_err();
            assert_eq!(e.code, HEADER_MISMATCH, "{why}");
        }
    }

    #[test]
    fn a_modern_header_without_body_meta_is_a_mismatch() {
        let msg = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
        let h = headers(&[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tools/list"),
        ]);
        assert_eq!(check_headers(&h, &msg).unwrap_err().code, HEADER_MISMATCH);
    }

    #[test]
    fn an_unknown_version_is_unsupported() {
        let mut msg = modern_call("x");
        msg["params"]["_meta"][META_PROTOCOL_VERSION] = json!("2099-01-01");
        let h = headers(&[
            ("mcp-protocol-version", "2099-01-01"),
            ("mcp-method", "tools/call"),
            ("mcp-name", "x"),
        ]);
        let e = check_headers(&h, &msg).unwrap_err();
        assert_eq!(e.code, UNSUPPORTED_PROTOCOL_VERSION);
        let legacy = headers(&[("mcp-protocol-version", "2020-01-01")]);
        let list = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
        assert_eq!(
            check_headers(&legacy, &list).unwrap_err().code,
            UNSUPPORTED_PROTOCOL_VERSION
        );
    }

    #[test]
    fn legacy_requests_need_no_mirrored_headers() {
        let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}});
        assert_eq!(
            check_headers(&HeaderMap::new(), &init),
            Ok(Era::Legacy(None))
        );
        let list = json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
        assert_eq!(
            check_headers(&headers(&[("mcp-protocol-version", "2025-06-18")]), &list),
            Ok(Era::Legacy(Some("2025-06-18".into())))
        );
        assert_eq!(
            check_headers(&HeaderMap::new(), &list),
            Ok(Era::Legacy(Some(HEADERLESS_VERSION.into())))
        );
    }

    #[test]
    fn statuses_follow_the_transport_spec() {
        let err = |code: i64| json!({"jsonrpc":"2.0","id":1,"error":{"code":code,"message":"m"}});
        assert_eq!(
            status_for(&err(METHOD_NOT_FOUND), true),
            StatusCode::NOT_FOUND
        );
        assert_eq!(status_for(&err(METHOD_NOT_FOUND), false), StatusCode::OK);
        assert_eq!(
            status_for(&err(UNSUPPORTED_PROTOCOL_VERSION), true),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_for(&err(crate::caller::mcp::INVALID_PARAMS), true),
            StatusCode::OK
        );
        assert_eq!(status_for(&json!({"result":{}}), true), StatusCode::OK);
    }

    #[test]
    fn a_bad_sentinel_does_not_decode() {
        assert_eq!(decode_header_value("=?base64?***?="), None);
        assert_eq!(decode_header_value("plain"), Some("plain".into()));
        assert_eq!(
            decode_header_value("=?base64?SGVsbG8sIOS4lueVjA==?="),
            Some("Hello, 世界".into())
        );
    }

    proptest! {
        #[test]
        fn any_name_survives_the_sentinel(name in "\\PC{0,40}") {
            let enc = format!("=?base64?{}?=", base64::engine::general_purpose::STANDARD.encode(&name));
            prop_assert_eq!(decode_header_value(&enc), Some(name));
        }
    }
}

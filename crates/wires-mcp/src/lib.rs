//! `wires-mcp` — an authenticated MCP gateway that exposes a small tool
//! surface for AI agents to act on a wires household's behalf. See the
//! design doc at `docs/superpowers/specs/2026-05-18-wires-mcp-gateway-design.md`.

pub mod config;
pub mod error;
pub mod keys;
pub mod store;
pub mod token;
pub mod http;

#[cfg(test)]
mod lib_tests {
    use crate::error::{GatewayError, UnknownUserSnafu};
    use snafu::ResultExt;

    #[test]
    fn error_messages_end_with_location() {
        let err: Result<(), _> = Err::<(), _>(std::io::Error::other("boom"))
            .context(crate::error::IoSnafu);
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains(", at "), "no location: {msg}");
    }

    #[test]
    fn unknown_user_renders_sub_prefix() {
        let err: GatewayError = UnknownUserSnafu {
            sub: "deadbeef".to_string(),
        }
        .build();
        let msg = err.to_string();
        assert!(msg.contains("deadbeef"));
    }
}

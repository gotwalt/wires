//! The **caller** role: an agent or a person running remote CLIs.
//!
//! The caller binds its node key to an IdP identity (`wires login`), keeps a
//! local map of remote CLIs (`wires tools`), and runs them (`wires call`, the
//! CLI-native path; `wires mcp`, the stdio MCP adapter kept for clients that
//! only speak MCP).
//!
//! - [`call`] — dial a tool and bridge stdio; the exit code is the remote one.
//! - [`shape`] — `--jq` / `--head` / `--max-bytes`: output shaping, in-process.
//! - [`mcp`] — the same calls as MCP tools over stdio (backward compatibility).
//! - [`tools`] — `tools.json`: the local name → responder map.
//! - [`login`] — OIDC sign-in, nonce-bound to this node's key.
//! - [`jwks`] — issuer discovery and key fetching for ID-token verification.
//! - `mock_idp` — a hermetic OIDC issuer (tests and the dev build only).
//! - [`join`] — `wires id` and `wires join <token>` (card 14; every role
//!   joins this way, the host and the observer included).
//!
//! Where what comes next lands: resolving a tool by name from the hosts'
//! announcements on the channel in `resolve.rs` (card 15).

pub mod call;
pub mod join;
pub mod jwks;
pub mod login;
pub mod mcp;
/// A hermetic OIDC issuer for the `wires login` tests (card 04), also served
/// by the dev-only `//wires:wires_dev` build (`wires dev-mock-idp`) for
/// `.scripts/demo-remote-cli.sh`. Never compiled into the shipped `//wires`.
#[cfg(any(test, feature = "dev-mock-idp"))]
#[cfg_attr(not(test), allow(dead_code))]
pub mod mock_idp;
pub mod shape;
pub mod tools;

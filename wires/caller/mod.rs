//! The **caller** role: an agent or a person running remote CLIs.
//!
//! The caller binds its node key to an IdP identity (`wires login`), finds
//! remote CLIs by name on its channel (`wires tools`), and runs them (`wires
//! call`, the CLI-native path; `wires mcp`, the stdio MCP adapter kept for clients that
//! only speak MCP).
//!
//! - [`call`] — dial a tool and bridge stdio; the exit code is the remote one.
//! - [`shape`] — `--jq` / `--head` / `--max-bytes`: output shaping, in-process.
//! - [`lock`] — locked mode: `WIRES_LOCKED=1` refuses the override flags so a
//!   sandboxed agent can't steer `call`/`mcp` off the operator's config.
//! - [`mcp`] — the same calls as MCP tools over stdio (backward compatibility).
//! - [`resolve`] — the channel is the directory: hosts' announcements, cached
//!   in `directory.json`, resolve a name to a host (card 15).
//! - [`tools`] — `wires tools`, and `tools.json`: local aliases (name → host).
//! - [`login`] — OIDC sign-in, nonce-bound to this node's key.
//! - [`jwks`] — issuer discovery and key fetching for ID-token verification.
//! - `mock_idp` — a hermetic OIDC issuer (tests and the dev build only).
//! - [`join`] — `wires id` and `wires join <token>` (card 14; every role
//!   joins this way, the host and the observer included).

pub mod call;
pub mod join;
pub mod jwks;
pub mod lock;
pub mod login;
pub mod mcp;
/// A hermetic OIDC issuer for the `wires login` tests (card 04), also served
/// by the dev-only `//wires:wires_dev` build (`wires dev-mock-idp`) for
/// `.scripts/demo-remote-cli.sh`. Never compiled into the shipped `//wires`.
#[cfg(any(test, feature = "dev-mock-idp"))]
#[cfg_attr(not(test), allow(dead_code))]
pub mod mock_idp;
pub mod resolve;
pub mod shape;
pub mod tools;

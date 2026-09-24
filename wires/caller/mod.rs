//! The **caller** role: an agent or a person running remote CLIs.
//!
//! The caller binds its node key to an IdP identity (`wires login`), lists
//! the services the signed policy lets it call (`wires services`), and runs
//! them by name (`wires call`, the CLI-native path and the source of the
//! token savings; `wires mcp`, the same services as MCP tools over stdio, so
//! wires works in the MCP clients people already use).
//!
//! - [`call`] — dial a service's host and bridge stdio; the exit code is the
//!   remote one.
//! - [`shape`] — `--jq` / `--head` / `--max-bytes`: output shaping, in-process.
//! - [`inbox`] — `wires inbox`: what hosts pushed to this caller (card 23),
//!   fetched from the hosts of its services, or received while `--wait`s.
//! - [`watch_records`] — `wires watch`: stream call records from the hosts
//!   that hold them, checking each host's hash chain.
//! - [`lock`] — locked mode: `WIRES_LOCKED=1` refuses the override flags so a
//!   sandboxed agent can't steer `call`/`mcp`/`inbox` off the operator's
//!   config.
//! - [`mcp`] — the same calls as MCP tools over stdio (`wires gateway`
//!   serves them over HTTP).
//! - [`tools`] — `tools.json`: locked mode, and local aliases (name → one
//!   host, with address hints).
//! - [`login`] — OIDC sign-in, nonce-bound to this node's key.
//! - [`jwks`] — issuer discovery and key fetching for ID-token verification.
//! - `mock_idp` — a hermetic OIDC issuer (tests and the dev build only).
//! - [`services`] — `wires services`: what this caller may call, evaluated
//!   locally.
//! - [`pick`] — service name → host, with failover; the local dial hints.
//! - [`hello`] — the caller's session `Hello`.
//! - [`join`] — `wires id` and `wires join <token>` (card 14; every node
//!   joins this way, hosts included).

pub mod call;
pub mod hello;
pub mod inbox;
pub mod join;
pub mod jwks;
pub mod lock;
pub mod login;
pub mod mcp;
/// A hermetic OIDC issuer for the `wires login` tests (card 04), also served
/// by the `dev-mock-idp` feature build (`wires dev-mock-idp`) for
/// `.scripts/demo-remote-cli.sh`. Never compiled into a release.
#[cfg(any(test, feature = "dev-mock-idp"))]
pub mod mock_idp;
pub mod pick;
pub mod services;
pub mod shape;
pub mod tools;
pub mod watch_records;

/// `s` on one line: newlines and every other control character escaped, so
/// text from elsewhere (a pushed message, a call record) can't forge a
/// second line or drive the terminal.
pub(crate) fn one_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::one_line;

    #[test]
    fn one_line_escapes_only_control_characters() {
        assert_eq!(one_line("a\nb\r\t\u{1b}[31m"), "a\\nb\\r\\t\\u{1b}[31m");
        assert_eq!(one_line("é \"q\" \\ ok"), "é \"q\" \\ ok");
        assert_eq!(one_line("\u{85}"), "\\u{85}");
    }
}

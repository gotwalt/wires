//! The **admin** role: holds the root key and signs the state.
//!
//! The admin-signed state (card 27) is one versioned document: who is in,
//! which members host, the role definitions, and the service registry. Every
//! command here edits it, signs the next version, and pushes it to the
//! hosts — there is nothing else to distribute.
//!
//! - [`init`] — `wires init`: root key, node key, the first signed state.
//! - [`invite`] — `wires invite` (one token per joiner) and `wires remove`.
//! - [`service`] — `wires service add | set | rm` and `wires role set | rm`.
//! - [`propagate`] — pushing each edit to the hosts (an edit that reaches
//!   none fails), and `wires state push`.
//! - [`keystore`] — the on-disk home: keys, the membership, and the
//!   flag → env → file → keystore resolution every command uses.
//! - [`ttl`] — the `--ttl` / `--state-ttl` / `--timeout` lifetimes.

pub mod init;
pub mod invite;
pub mod keystore;
pub mod propagate;
pub mod service;
pub mod ttl;

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

use keystore::Keystore;

/// What an admin command prints: `stdout` is the result (the token, for
/// `invite`), `notes` then `hint` go to stderr, and a `failure` (the new
/// state reached no host) goes last on stderr and makes the command exit 1.
#[derive(Debug, Default)]
pub(crate) struct Report {
    /// The command's result, for stdout (nothing when empty).
    pub(crate) stdout: String,
    /// Progress, for stderr.
    pub(crate) notes: Vec<String>,
    /// What to do next, for stderr after the notes.
    pub(crate) hint: Option<String>,
    /// Why the command failed after doing its work, if it did.
    pub(crate) failure: Option<String>,
}

/// An admin command: `edit` against the resolved keystore (it signs and
/// stores the next state), then that state pushed to its hosts and to the
/// hosts of the state before the edit ([`propagate`]).
pub(crate) async fn run_edit(
    edit: impl FnOnce(&Keystore) -> anyhow::Result<Report>,
) -> anyhow::Result<Report> {
    let ks = Keystore::resolve()?;
    let earlier = crate::state::sync::held_hosts(&ks)?;
    let report = edit(&ks)?;
    Ok(propagate::fold(
        report,
        propagate::propagate(&ks, &earlier).await,
    ))
}

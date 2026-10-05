//! The **admin** role: holds the root key and signs the policy.
//!
//! The admin-signed policy (cards 27, 36) is a root-signed head over items:
//! the trusted IdPs, the role definitions, the services (who may call each,
//! which hosts run it), the node and person bans, the settings, and (in the
//! head) the directories. The admin mints nothing for any node: a caller is
//! admitted by its IdP sign-in when a role matches it, and a host or
//! directory by the policy naming its key. `init` signs the first version
//! and stores it; every edit after it signs the next version and publishes
//! it to the directories (never to a host: hosts follow it from a directory,
//! and callers ask one for their views).
//!
//! - [`init`] — `wires init`: root key, node key, the first signed policy.
//! - [`network`] — `wires network`: the string every node joins with.
//! - [`remove`] — `wires remove` and `wires restore`: person and node bans.
//! - [`labels`] — `labels.json`: the admin's names for nodes
//!   (`label=<node id>` the first time, the label afterwards).
//! - [`login_client`] — `login-client.json`: which trusted IdP the network
//!   string tells `wires login` to use, and its public client secret.
//! - [`service`] — `wires service add | set | rm`, `wires role set | rm`,
//!   `wires issuer set | rm`, and the edits behind `wires directory add |
//!   rm`.
//! - [`propagate`] — publishing each edit to the directories (an edit that
//!   reaches none fails, after the first run), and `wires policy push`.
//! - [`settings`] — `wires policy settings`: the freshness rule and the
//!   directories' beat, in the signed policy.
//! - [`keystore`] — the on-disk home: keys, the network string, and the
//!   flag → env → file → keystore resolution every command uses.
//! - [`ttl`] — the `--policy-ttl` / `--timeout` lifetimes.

pub mod init;
pub mod keystore;
pub mod labels;
pub mod login_client;
pub mod network;
pub mod propagate;
pub mod remove;
pub mod service;
pub mod settings;
pub mod ttl;

use keystore::Keystore;

/// What an admin command prints: `stdout` is the result (the network
/// string, for `network`), `notes` then `hint` go to stderr, and a `failure` (the new
/// policy reached no directory) goes last on stderr and makes the command
/// exit 1.
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
/// stores the next policy), then that policy published to its directories
/// and to those of the policy before the edit ([`propagate`]).
pub(crate) async fn run_edit(
    edit: impl FnOnce(&Keystore) -> anyhow::Result<Report>,
) -> anyhow::Result<Report> {
    run_edit_with(crate::policy::fetch::Retry::Reached, edit).await
}

/// [`run_edit`], trying the directories `retry` names again for a while
/// when the publish's first try misses them.
pub(crate) async fn run_edit_with(
    retry: crate::policy::fetch::Retry,
    edit: impl FnOnce(&Keystore) -> anyhow::Result<Report>,
) -> anyhow::Result<Report> {
    let ks = Keystore::resolve()?;
    let earlier = crate::policy::fetch::held_directories(&ks)?;
    let report = edit(&ks)?;
    Ok(propagate::fold(
        report,
        propagate::propagate(&ks, &earlier, retry).await,
    ))
}

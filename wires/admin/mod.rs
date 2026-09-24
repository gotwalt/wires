//! The **admin** role: holds the root key, mints badges and signs the
//! policy.
//!
//! The admin-signed policy (cards 27, 36) is a root-signed head over items:
//! the trusted IdPs, the role definitions, the service registry (which hosts
//! run each service), the bans, the settings, and (in the head) the
//! directories. It lists no members (card 35): a node is admitted by the
//! root-signed badge the admin mints for it, so inviting one is no edit.
//! Every other command here edits the policy, signs the next version, and
//! publishes it to the directories (never to a host: hosts and callers
//! fetch it from a directory).
//!
//! - [`init`] — `wires init`: root key, node key, the admin's own badge, the
//!   first signed policy.
//! - [`invite`] — `wires invite` (one token per joiner: a badge, no edit)
//!   and `wires remove` (a ban).
//! - [`login_client`] — `login-client.json`: which trusted IdP invites tell
//!   `wires login` to use, and its public client secret (card 37).
//! - [`ledger`] — `issued.json`: the badges this admin minted, with their
//!   labels and expiries (how long a ban must last).
//! - [`service`] — `wires service add | set | rm`, `wires role set | rm`,
//!   `wires issuer set | rm`, and the edits behind `wires directory add |
//!   rm`.
//! - [`propagate`] — publishing each edit to the directories (an edit that
//!   reaches none fails), and `wires state push`.
//! - [`settings`] — `wires state settings`: the freshness rule and the
//!   directories' beat, in the signed policy.
//! - [`keystore`] — the on-disk home: keys, the membership, and the
//!   flag → env → file → keystore resolution every command uses.
//! - [`ttl`] — the `--ttl` / `--state-ttl` / `--timeout` lifetimes.

pub mod init;
pub mod invite;
pub mod keystore;
pub mod ledger;
pub mod login_client;
pub mod propagate;
pub mod service;
pub mod settings;
pub mod ttl;

use std::collections::BTreeSet;

use keystore::Keystore;
use library::{NodeId, StateVersion};

/// What an admin command prints: `stdout` is the result (the token, for
/// `invite`), `notes` then `hint` go to stderr, and a `failure` (the new
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
    let ks = Keystore::resolve()?;
    let earlier = crate::policy::fetch::held_directories(&ks)?;
    let report = edit(&ks)?;
    Ok(propagate::fold(
        report,
        propagate::propagate(&ks, &earlier).await,
    ))
}

/// An admin command that usually doesn't edit the policy (`invite`): `cmd`
/// against the resolved keystore, then a publish **only if** the stored
/// policy's version moved ([`run_if_edited_in`]).
pub(crate) async fn run_if_edited(
    cmd: impl FnOnce(&Keystore) -> anyhow::Result<Report>,
) -> anyhow::Result<Report> {
    let ks = Keystore::resolve()?;
    run_if_edited_in(&ks, cmd, async |ks, earlier| {
        propagate::propagate(ks, earlier).await
    })
    .await
}

/// [`run_if_edited`] against `ks`, with the publish as a parameter (the
/// testable form): `push` runs, and its outcome is folded into the report,
/// only when `cmd` left a newer policy stored than it found.
pub(crate) async fn run_if_edited_in(
    ks: &Keystore,
    cmd: impl FnOnce(&Keystore) -> anyhow::Result<Report>,
    push: impl AsyncFnOnce(&Keystore, &BTreeSet<NodeId>) -> propagate::Propagation,
) -> anyhow::Result<Report> {
    let before = held_version(ks)?;
    let earlier = crate::policy::fetch::held_directories(ks)?;
    let report = cmd(ks)?;
    if held_version(ks)? == before {
        return Ok(report);
    }
    Ok(propagate::fold(report, push(ks, &earlier).await))
}

/// The version of the policy `ks` holds (`None`: it holds none).
fn held_version(ks: &Keystore) -> anyhow::Result<Option<StateVersion>> {
    let Some(root) = crate::policy::store::fabric(ks)? else {
        return Ok(None);
    };
    Ok(crate::policy::store::read(ks, root)?.map(|h| h.version()))
}

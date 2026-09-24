//! The **directory** role (card 36): where the fabric's policy lives.
//!
//! A directory is a node the root-signed head lists in `directories`. It
//! holds the newest policy (`directory.redb`), signs a freshness timestamp
//! for it every `settings.beat_secs`, takes a newer policy from anyone
//! admitted (the admin publishes each edit to every directory), follows the
//! other directories as a replica, and answers hosts and callers. **It never
//! decides a call:** hosts decide from their own copy, so calls keep working
//! with every directory down. It is trusted for availability and freshness
//! only: everything it serves is root-signed.
//!
//! It is a mode on its own ALPNs (`wires/directory/1`,
//! `wires/directory-sub/1`), not a native service: hosts aren't people, and
//! a host's checks aren't calls to log. `wires serve` runs it when the policy
//! lists its node; `wires directory serve` runs it alone.
//!
//! - [`db`] — `directory.redb`: heads, items, the current index, freshness.
//! - [`node`] — the [`Directory`](node::Directory): accept, beat, answer.
//! - [`serve`] — both ALPNs, the beat and replica loops,
//!   `wires directory serve`.
//! - [`sub_policy`] — a host's `policy` subscription: the whole policy
//!   once, then a delta per new head, and a `fresh` beat (card 36c).
//! - [`sub_view`] — a caller's `view` subscription (card 37).
//! - [`wire`] — frame I/O, and [`ask`](wire::ask): one request to a
//!   directory, for every other role.
//!
//! ```text
//! wires directory add workbench     # admin: list a node as a directory
//! wires directory rm workbench      # admin: stop listing it
//! wires directory serve             # on that node, when it hosts nothing
//! ```

pub mod db;
pub mod node;
pub mod serve;
pub mod sub_policy;
pub mod sub_view;
pub mod wire;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::admin::invite::resolve_member;
use crate::admin::keystore::Keystore;
use crate::admin::ledger::Ledger;
use crate::admin::service::{directory_add, directory_rm};
use crate::admin::ttl::Ttl;
use crate::admin::{Report, run_edit};

/// `directory` arguments.
#[derive(Args)]
pub(crate) struct DirectoryArgs {
    #[command(subcommand)]
    pub(crate) cmd: DirectoryCmd,
}

/// The `directory` subcommands.
#[derive(Subcommand)]
pub(crate) enum DirectoryCmd {
    /// Run this node's directory alone (no host.json) until Ctrl-C
    // The policy it holds must list this node.
    #[command(after_help = "Example:\n  wires directory serve")]
    Serve(serve::DirectoryServeArgs),
    /// Admin: list a node as one of the network's directories, and publish
    #[command(after_help = "Example:\n  wires directory add workbench")]
    Add(DirectoryEditArgs),
    /// Admin: stop listing a node as a directory, and publish
    #[command(after_help = "Example:\n  wires directory rm workbench")]
    Rm(DirectoryEditArgs),
}

/// `directory add | rm` arguments.
#[derive(Args)]
pub(crate) struct DirectoryEditArgs {
    /// The node: an `invite --name` label or a hex node id.
    pub(crate) node: String,
    /// Lifetime of the new policy, from now; never shortens the current one.
    #[arg(long = "state-ttl", default_value = Ttl::POLICY_DEFAULT, hide = true)]
    pub(crate) ttl: Ttl,
}

/// Is this `directory` command the admin's edit (vs `serve`)?
pub(crate) fn is_edit(a: &DirectoryArgs) -> bool {
    !matches!(a.cmd, DirectoryCmd::Serve(_))
}

/// Run a `directory add | rm` against `ks` (no publish): what changed.
pub(crate) fn edit_in(ks: &Keystore, cmd: DirectoryCmd) -> Result<String> {
    let ledger = Ledger::load(ks)?;
    let (verb, edit) = match cmd {
        DirectoryCmd::Add(e) => ("added", e),
        DirectoryCmd::Rm(e) => ("removed", e),
        DirectoryCmd::Serve(_) => anyhow::bail!("`directory serve` is not an edit"),
    };
    let (node, label) = resolve_member(&ledger, &edit.node)?;
    let held = if verb == "added" {
        directory_add(ks, node, edit.ttl)?
    } else {
        directory_rm(ks, node, edit.ttl)?
    };
    Ok(format!(
        "directory {}{} {verb} (policy version {}; {} directory(ies))",
        node.hex(),
        label.map(|n| format!(" ({n})")).unwrap_or_default(),
        held.version().0,
        held.directories().len()
    ))
}

/// `wires directory add | rm`: the edit, then the publish.
pub(crate) async fn edit_cmd(a: DirectoryArgs) -> Result<Report> {
    run_edit(|ks| {
        Ok(Report {
            stdout: edit_in(ks, a.cmd)?,
            ..Report::default()
        })
    })
    .await
}

#[cfg(test)]
mod tests;

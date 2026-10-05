//! The **directory** role (card 36): where the network's policy lives.
//!
//! A directory is a node the root-signed head lists in `directories`. It
//! holds the newest policy (`directory.redb`), signs a freshness timestamp
//! for it every `settings.beat_secs`, takes a newer policy from anyone whose
//! head the root signed (the admin publishes each edit to every directory;
//! the first directory starts empty and takes the first), follows the
//! other directories as a replica, and answers hosts and callers. **It never
//! decides a call:** hosts decide from their own copy. But a caller tells a
//! host nothing without a directory's current `Fresh` for the head that host
//! holds (card 49), so with every directory down calls stop within
//! `fresh_secs`. It is trusted for availability and freshness only:
//! everything it serves is root-signed.
//!
//! It is a mode on its own ALPNs (`wires/directory/2`,
//! `wires/directory-sub/2`), not a native service: hosts aren't people, and
//! a host's checks aren't calls to log. `wires serve` runs it when the policy
//! it holds lists its node (or, holding none yet, its network string does);
//! `wires directory serve` runs it alone.
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
//! wires directory add workbench=3ef7…   # admin: list a node as a directory
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

use crate::admin::keystore::Keystore;
use crate::admin::labels::resolve_all;
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
    // The policy it holds must list this node, or, holding none, its network
    // string; it then waits for the admin's first publish.
    #[command(after_help = "Example:\n  wires directory serve")]
    Serve(serve::DirectoryServeArgs),
    /// Admin: list a node as one of the network's directories, and publish
    #[command(
        after_help = "Examples:\n  wires directory add workbench=<node id>\n  wires directory add workbench"
    )]
    Add(DirectoryEditArgs),
    /// Admin: stop listing a node as a directory, and publish
    #[command(after_help = "Example:\n  wires directory rm workbench")]
    Rm(DirectoryEditArgs),
}

/// `directory add | rm` arguments.
#[derive(Args)]
pub(crate) struct DirectoryEditArgs {
    /// The node: `label=<node id>` the first time, then the label (or its id).
    pub(crate) node: String,
    /// Lifetime of the new policy, from now; never shortens the current one.
    #[arg(long = "policy-ttl", default_value = Ttl::POLICY_DEFAULT, hide = true)]
    pub(crate) ttl: Ttl,
}

/// Is this `directory` command the admin's edit (vs `serve`)?
pub(crate) fn is_edit(a: &DirectoryArgs) -> bool {
    !matches!(a.cmd, DirectoryCmd::Serve(_))
}

/// Run a `directory add | rm` against `ks` (no publish): what changed.
pub(crate) fn edit_in(ks: &Keystore, cmd: DirectoryCmd) -> Result<String> {
    let (verb, edit) = match cmd {
        DirectoryCmd::Add(e) => ("added", e),
        DirectoryCmd::Rm(e) => ("removed", e),
        DirectoryCmd::Serve(_) => anyhow::bail!("`directory serve` is not an edit"),
    };
    let named = resolve_all(ks, std::slice::from_ref(&edit.node))?.remove(0);
    let held = if verb == "added" {
        directory_add(ks, named.node, edit.ttl)?
    } else {
        directory_rm(ks, named.node, edit.ttl)?
    };
    Ok(format!(
        "directory {}{} {verb} (policy version {}; {} directory(ies))",
        named.node.hex(),
        named.label.map(|n| format!(" ({n})")).unwrap_or_default(),
        held.version().0,
        held.directories().len()
    ))
}

/// `wires directory add | rm`: the edit, then the publish; after an `add`,
/// that node's next step ([`next_step`]).
pub(crate) async fn edit_cmd(a: DirectoryArgs) -> Result<Report> {
    run_edit(|ks| {
        let add = match &a.cmd {
            DirectoryCmd::Add(e) => Some(e.node.clone()),
            _ => None,
        };
        let stdout = edit_in(ks, a.cmd)?;
        let hint = match add {
            Some(node) => Some(next_step(ks, &node)?),
            None => None,
        };
        Ok(Report {
            stdout,
            hint,
            ..Report::default()
        })
    })
    .await
}

/// What the node `text` (a label or node id, already listed) does next: a
/// running host follows the policy and runs the directory at its next
/// `wires serve`; any other node joins with the network string and serves,
/// and takes the policy from the admin's next publish.
pub(crate) fn next_step(ks: &Keystore, text: &str) -> Result<String> {
    let named = resolve_all(ks, &[text.to_string()])?.remove(0);
    let held = ks
        .network_root()?
        .and_then(|root| crate::policy::store::read(ks, root).ok().flatten());
    let hosts = held.as_ref().is_some_and(|h| h.policy.is_host(named.node));
    let in_string = held.as_ref().is_some_and(|h| {
        h.directories()
            .iter()
            .take(library::NETWORK_MAX_DIRECTORIES)
            .any(|d| *d == named.node)
    });
    let who = named.label.clone().unwrap_or_else(|| named.node.hex());
    let string = if in_string {
        " (the network string now names it: `wires network` prints it)"
    } else {
        ""
    };
    Ok(if hosts {
        format!("next: restart `wires serve` on {who} to run the directory{string}")
    } else {
        format!(
            "next: on {who}, `wires join <network>`{string}, then `wires serve host.json` or \
             `wires directory serve`; it starts empty and takes this policy from `wires policy \
             push`"
        )
    })
}

#[cfg(test)]
mod tests;

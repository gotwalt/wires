//! Getting an admin edit to the directories, and `wires state push`.
//!
//! Every admin edit (`remove`, `service`, `role`, `issuer`, `directory add |
//! rm`, and the rare `invite` that edits) is signed and stored here first,
//! then published to every directory the new head lists (and those the head
//! before the edit listed) by key ([`fetch::publish_current`]). The admin
//! dials no host: hosts and callers fetch from a directory. If the policy
//! names directories and **none** took it, the command fails: the policy is
//! in force nowhere but here. The new one stays stored here, and `wires
//! state push` re-publishes it once a directory is up.
//!
//! ```text
//! wires state push     # re-publish the stored policy to every directory
//! ```

use std::collections::BTreeSet;

use anyhow::Result;
use clap::{Args, Subcommand};
use library::NodeId;

use super::keystore::Keystore;
use super::{Report, run_edit};
use crate::policy::fetch;

/// `state` arguments.
#[derive(Args)]
pub(crate) struct StateArgs {
    #[command(subcommand)]
    pub(crate) cmd: StateCmd,
}

/// The `state` subcommands.
#[derive(Subcommand)]
pub(crate) enum StateCmd {
    /// Re-publish the stored signed policy to every directory (after an
    /// edit that reached none, or a directory that was down).
    Push,
}

/// How a publish went, for an admin command's [`Report`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Propagation {
    /// The line for stderr (`policy version N: published to K of D
    /// directory(ies)…`).
    pub(crate) note: String,
    /// Set when the policy names directories and none took it: the command
    /// fails.
    pub(crate) failure: Option<String>,
}

impl Propagation {
    /// The outcome of publishing `version`, given the publish's `report` (or
    /// the error that stopped it).
    pub(crate) fn from_publish(
        result: Result<(library::StateVersion, fetch::PublishReport)>,
    ) -> Propagation {
        match result {
            Ok((version, report)) => Propagation {
                note: report.line(version),
                failure: report.reached_none().then(|| {
                    format!(
                        "policy version {} is signed and stored here, but reached none of its \
                         {} directory(ies), so no host or caller can fetch it yet; run `wires \
                         state push` once a directory is up",
                        version.0,
                        report.missed.len()
                    )
                }),
            },
            Err(e) => Propagation {
                note: format!("the new policy is stored here but was not published: {e:#}"),
                failure: Some(
                    "no directory has the new policy yet; run `wires state push` to re-publish it"
                        .into(),
                ),
            },
        }
    }
}

/// Publish the policy stored in `ks` to its directories and those in
/// `earlier` (the policy's before the edit).
pub(crate) async fn propagate(ks: &Keystore, earlier: &BTreeSet<NodeId>) -> Propagation {
    Propagation::from_publish(fetch::publish_current(ks, earlier).await)
}

/// Fold a publish into an admin command's report: its line is the last
/// note, and a publish that reached no directory fails the command.
pub(crate) fn fold(mut report: Report, pushed: Propagation) -> Report {
    report.notes.push(pushed.note);
    report.failure = pushed.failure;
    report
}

/// `wires state push`: re-publish the stored policy to every directory.
pub(crate) async fn state_cmd(a: StateArgs) -> Result<Report> {
    match a.cmd {
        StateCmd::Push => {
            run_edit(|ks| {
                if ks.read_root_identity()?.is_none() {
                    anyhow::bail!("no root key here: `wires state push` runs on the admin");
                }
                Ok(Report::default())
            })
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::fetch::PublishReport;
    use library::{NodeIdentity, StateVersion};

    #[test]
    fn an_edit_that_reaches_no_directory_fails_and_says_it_is_stored() {
        let host = NodeIdentity::from_seed([3; 32]).node_id();
        let missed = Propagation::from_publish(Ok((
            StateVersion(7),
            PublishReport {
                delivered: vec![],
                missed: vec![host],
            },
        )));
        let failure = missed.failure.expect("fails");
        assert!(failure.contains("stored here"), "{failure}");
        assert!(failure.contains("wires state push"), "{failure}");
        // No directories at all: nothing to reach, nothing failed.
        let none = Propagation::from_publish(Ok((StateVersion(7), PublishReport::default())));
        assert_eq!(none.failure, None);
        // One directory took it: fine.
        let one = Propagation::from_publish(Ok((
            StateVersion(7),
            PublishReport {
                delivered: vec![host],
                missed: vec![],
            },
        )));
        assert_eq!(one.failure, None);
        // The publish itself failed: the command fails.
        let broke = Propagation::from_publish(Err(anyhow::anyhow!("no network")));
        assert!(broke.failure.is_some());
        assert!(broke.note.contains("stored here"), "{}", broke.note);
    }
}

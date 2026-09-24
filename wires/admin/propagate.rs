//! Getting an admin edit to the hosts, and `wires state push`.
//!
//! Every admin edit (`invite`, `remove`, `service`, `role`) is signed and
//! stored here first, then offered to the hosts by key
//! ([`sync::push_current`]). The hosts are the members that listen (only
//! `wires serve` answers the state protocol) and the ones that enforce it.
//! If the state names hosts and **none** took it, the command fails:
//! the fabric is still enforcing the older state. The new one stays stored
//! here, and `wires state push` re-sends it once a host is up.
//!
//! ```text
//! wires state push     # re-send the stored state to every host
//! ```

use std::collections::BTreeSet;

use anyhow::Result;
use clap::{Args, Subcommand};
use library::NodeId;

use super::invite::Report;
use super::keystore::Keystore;
use crate::state::sync;

/// `state` arguments.
#[derive(Args)]
pub(crate) struct StateArgs {
    #[command(subcommand)]
    pub(crate) cmd: StateCmd,
}

/// The `state` subcommands.
#[derive(Subcommand)]
pub(crate) enum StateCmd {
    /// Re-send the stored signed state to every host (after an edit that
    /// reached none, or a host that was down).
    Push,
}

/// How a push went, for an admin command's [`Report`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Propagation {
    /// The line for stderr (`state version N: pushed to K of H host(s)…`).
    pub(crate) note: String,
    /// Set when the state names hosts and none took it: the command fails.
    pub(crate) failure: Option<String>,
}

impl Propagation {
    /// The outcome of pushing `version`, given the push's `report` (or the
    /// error that stopped it).
    pub(crate) fn from_push(
        result: Result<(library::StateVersion, sync::PushReport)>,
    ) -> Propagation {
        match result {
            Ok((version, report)) => Propagation {
                note: report.line(version),
                failure: report.reached_no_host().then(|| {
                    format!(
                        "state version {} is signed and stored here, but reached none of its \
                         {} host(s), so they still enforce the older state; run `wires state \
                         push` once a host is up",
                        version.0,
                        report.missed.len()
                    )
                }),
            },
            Err(e) => Propagation {
                note: format!("the new state is stored here but was not pushed: {e:#}"),
                failure: Some(
                    "no host has the new state yet; run `wires state push` to re-send it".into(),
                ),
            },
        }
    }
}

/// Push the state stored in `ks` to its hosts and the hosts in `earlier`
/// (those of the state before the edit).
pub(crate) async fn propagate(ks: &Keystore, earlier: &BTreeSet<NodeId>) -> Propagation {
    Propagation::from_push(sync::push_current(ks, earlier).await)
}

/// Fold a push into an admin command's report: its line is the last note,
/// and a push that reached no host fails the command.
pub(crate) fn fold(mut report: Report, pushed: Propagation) -> Report {
    report.notes.push(pushed.note);
    report.failure = pushed.failure;
    report
}

/// `wires state push`: re-send the stored state to every host.
pub(crate) async fn state_cmd(a: StateArgs) -> Result<Report> {
    match a.cmd {
        StateCmd::Push => {
            let ks = Keystore::resolve()?;
            if ks.read_root_identity()?.is_none() {
                anyhow::bail!("no root key here: `wires state push` runs on the admin");
            }
            let report = Report {
                stdout: String::new(),
                notes: Vec::new(),
                failure: None,
            };
            Ok(fold(report, propagate(&ks, &BTreeSet::new()).await))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::sync::PushReport;
    use library::{NodeIdentity, StateVersion};

    #[test]
    fn an_edit_that_reaches_no_host_fails_and_says_it_is_stored() {
        let host = NodeIdentity::from_seed([3; 32]).node_id();
        let missed = Propagation::from_push(Ok((
            StateVersion(7),
            PushReport {
                delivered: vec![],
                missed: vec![host],
            },
        )));
        let failure = missed.failure.expect("fails");
        assert!(failure.contains("stored here"), "{failure}");
        assert!(failure.contains("wires state push"), "{failure}");
        // No hosts at all: nothing to reach, nothing failed.
        let none = Propagation::from_push(Ok((StateVersion(7), PushReport::default())));
        assert_eq!(none.failure, None);
        // One host took it: fine.
        let one = Propagation::from_push(Ok((
            StateVersion(7),
            PushReport {
                delivered: vec![host],
                missed: vec![],
            },
        )));
        assert_eq!(one.failure, None);
        // The push itself failed: the command fails.
        let broke = Propagation::from_push(Err(anyhow::anyhow!("no network")));
        assert!(broke.failure.is_some());
        assert!(broke.note.contains("stored here"), "{}", broke.note);
    }

    #[test]
    fn state_push_parses() {
        use crate::{Cli, Command};
        use clap::Parser;
        let Command::State(a) = Cli::try_parse_from(["wires", "state", "push"])
            .unwrap()
            .command
        else {
            panic!("expected state");
        };
        assert!(matches!(a.cmd, StateCmd::Push));
        assert!(Cli::try_parse_from(["wires", "state"]).is_err());
    }
}

//! Getting an admin edit to the directories, and `wires policy push`.
//!
//! Every admin edit (`remove`, `service`, `role`, `issuer`, `directory add |
//! rm`, and the rare `invite` that edits) is signed and stored here first,
//! then published to every directory the new head lists (and those the head
//! before the edit listed) by key ([`fetch::publish_current`]). The admin
//! dials no host: hosts and callers fetch from a directory. If the policy
//! names directories and **none** took it, the command fails: the policy is
//! in force nowhere but here. The new one stays stored here, and `wires
//! policy push` re-publishes it once a directory is up.
//!
//! Two exceptions, both about where the network is:
//!
//! - **The first run.** Until some directory the publish aims at has ever
//!   taken a publish from this admin ([`REACHED_FILE`]), reaching none is a
//!   one-line note, not a failure: no directory is running yet, and the
//!   one the admin starts gets the policy in its invite.
//! - **A stale copy.** A directory holding a newer policy than the one
//!   published (or another at its version) fails the command, whatever the
//!   others did: this admin's `policy.json` is behind, so its edit changed
//!   nothing there. Restore `policy.json` from any host or directory, then
//!   edit again.
//!
//! ```text
//! wires policy push                          # re-publish the stored policy to every directory
//! wires policy settings --freshness strict    # the signed freshness rule (card 36c)
//! ```

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use library::{NodeId, StateVersion};

use super::keystore::{Keystore, write_text_mode};
use super::{Report, run_edit};
use crate::policy::fetch;

/// The admin keystore's record of the directories that have taken a publish
/// from this admin (a JSON list of node ids): until one of those a publish
/// aims at has, reaching none is the network's first run, not a failure.
pub(crate) const REACHED_FILE: &str = "reached.json";

/// `policy` arguments.
#[derive(Args)]
pub(crate) struct PolicyArgs {
    #[command(subcommand)]
    pub(crate) cmd: PolicyCmd,
}

/// The `policy` subcommands.
#[derive(Subcommand)]
pub(crate) enum PolicyCmd {
    /// Re-publish the stored signed policy to every directory
    // After an edit that reached none, or a directory that was down.
    #[command(after_help = "Example:\n  wires policy push")]
    Push,
    /// Print the network's settings, or change them and publish
    // The freshness rule (`--freshness lenient|strict`) and how often
    // directories vouch for the policy.
    #[command(
        after_help = "Examples:\n  wires policy settings\n  wires policy settings --freshness strict --beat-secs 60"
    )]
    Settings(super::settings::SettingsArgs),
}

/// How a publish went, for an admin command's [`Report`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Propagation {
    /// The line for stderr (`policy version N: published to K of D
    /// directory(ies)…`).
    pub(crate) note: String,
    /// Set when the policy names directories and none took it (after the
    /// first run), or one holds a newer policy: the command fails.
    pub(crate) failure: Option<String>,
}

impl Propagation {
    /// The outcome of publishing `version`, given the publish's `report` (or
    /// the error that stopped it). `first_run`: no directory the publish
    /// missed has ever taken one from this admin ([`settle`]).
    pub(crate) fn from_publish(
        result: Result<(StateVersion, fetch::PublishReport)>,
        first_run: bool,
    ) -> Propagation {
        match result {
            Ok((version, report)) if !report.newer.is_empty() => {
                let (dir, theirs) = report.newer[0];
                let what = if theirs == version {
                    format!("another policy at version {}", theirs.0)
                } else {
                    format!("policy version {}, newer than this one", theirs.0)
                };
                Propagation {
                    note: report.line(version),
                    failure: Some(format!(
                        "directory {}… holds {what}: this admin's policy.json is stale, so the \
                         edit changed nothing there; copy policy.json from any host or \
                         directory into this admin's keystore, then make the edit again",
                        dir.short()
                    )),
                }
            }
            Ok((version, report)) if report.reached_none() && first_run => Propagation {
                note: format!(
                    "policy version {}: no directory is running yet (none has taken a publish \
                     from this admin); start one with `wires directory serve` on its node: an \
                     invite minted from now on carries this policy",
                    version.0
                ),
                failure: None,
            },
            Ok((version, report)) => Propagation {
                note: report.line(version),
                failure: report.reached_none().then(|| {
                    format!(
                        "policy version {} is signed and stored here, but reached none of its \
                         {} directory(ies), so no host or caller can fetch it yet; run `wires \
                         policy push` once a directory is up",
                        version.0,
                        report.missed.len()
                    )
                }),
            },
            Err(e) => Propagation {
                note: format!("the new policy is stored here but was not published: {e:#}"),
                failure: Some(
                    "no directory has the new policy yet; run `wires policy push` to re-publish it"
                        .into(),
                ),
            },
        }
    }
}

/// Publish the policy stored in `ks` to its directories and those in
/// `earlier` (the policy's before the edit).
pub(crate) async fn propagate(ks: &Keystore, earlier: &BTreeSet<NodeId>) -> Propagation {
    settle(ks, fetch::publish_current(ks, earlier).await)
}

/// What a publish from `ks` came to: whether it is the first run (no
/// directory it missed is in [`REACHED_FILE`]), and the directories that
/// took it recorded there.
pub(crate) fn settle(
    ks: &Keystore,
    result: Result<(StateVersion, fetch::PublishReport)>,
) -> Propagation {
    let first_run = match &result {
        Ok((_, report)) => {
            let reached = reached(ks);
            report.missed.iter().all(|d| !reached.contains(d))
        }
        Err(_) => false,
    };
    if let Ok((_, report)) = &result
        && let Err(e) = note_reached(ks, &report.delivered)
    {
        tracing::warn!("could not record the directories reached: {e:#}");
    }
    Propagation::from_publish(result, first_run)
}

/// The directories that have taken a publish from this admin (none when
/// [`REACHED_FILE`] is missing or unreadable).
pub(crate) fn reached(ks: &Keystore) -> BTreeSet<NodeId> {
    std::fs::read_to_string(ks.path(REACHED_FILE))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// Add `delivered` to [`REACHED_FILE`].
fn note_reached(ks: &Keystore, delivered: &[NodeId]) -> Result<()> {
    let mut all = reached(ks);
    if delivered.iter().all(|d| all.contains(d)) {
        return Ok(());
    }
    all.extend(delivered.iter().copied());
    let text = serde_json::to_string(&all).context("encoding the directories reached")?;
    write_text_mode(&ks.path(REACHED_FILE), &format!("{text}\n"), Some(0o600))
}

/// Fold a publish into an admin command's report: its line is the last
/// note, and a publish that reached no directory fails the command.
pub(crate) fn fold(mut report: Report, pushed: Propagation) -> Report {
    report.notes.push(pushed.note);
    report.failure = pushed.failure;
    report
}

/// `wires policy push` (re-publish the stored policy to every directory) and
/// `wires policy settings`.
pub(crate) async fn policy_cmd(a: PolicyArgs) -> Result<Report> {
    match a.cmd {
        PolicyCmd::Settings(s) if !s.is_edit() => Ok(Report {
            stdout: super::settings::settings_in(&Keystore::resolve()?, &s)?,
            ..Report::default()
        }),
        PolicyCmd::Settings(s) => {
            run_edit(|ks| {
                Ok(Report {
                    stdout: super::settings::settings_in(ks, &s)?,
                    ..Report::default()
                })
            })
            .await
        }
        PolicyCmd::Push => {
            run_edit(|ks| {
                if ks.read_root_identity()?.is_none() {
                    anyhow::bail!("no root key here: `wires policy push` runs on the admin");
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
    use library::NodeIdentity;

    fn node(seed: u8) -> NodeId {
        NodeIdentity::from_seed([seed; 32]).node_id()
    }

    fn missed(dirs: &[NodeId]) -> PublishReport {
        PublishReport {
            missed: dirs.to_vec(),
            ..PublishReport::default()
        }
    }

    #[test]
    fn an_edit_that_reaches_no_directory_fails_and_says_it_is_stored() {
        let dir = node(3);
        let missed = Propagation::from_publish(Ok((StateVersion(7), missed(&[dir]))), false);
        let failure = missed.failure.expect("fails");
        assert!(failure.contains("stored here"), "{failure}");
        assert!(failure.contains("wires policy push"), "{failure}");
        // No directories at all: nothing to reach, nothing failed.
        let none =
            Propagation::from_publish(Ok((StateVersion(7), PublishReport::default())), false);
        assert_eq!(none.failure, None);
        // One directory took it: fine.
        let one = Propagation::from_publish(
            Ok((
                StateVersion(7),
                PublishReport {
                    delivered: vec![dir],
                    ..PublishReport::default()
                },
            )),
            false,
        );
        assert_eq!(one.failure, None);
        // The publish itself failed: the command fails.
        let broke = Propagation::from_publish(Err(anyhow::anyhow!("no network")), true);
        assert!(broke.failure.is_some());
        assert!(broke.note.contains("stored here"), "{}", broke.note);
    }

    /// Until a directory has taken a publish from this admin, reaching none
    /// is the network's first run: a note naming the next step, exit 0.
    /// Once one has, missing it fails as ever.
    #[test]
    fn reaching_no_directory_before_any_ever_took_a_publish_is_a_note() {
        let ks = Keystore::at(crate::testutil::temp_dir());
        let (dir, other) = (node(3), node(4));
        let first = settle(&ks, Ok((StateVersion(2), missed(&[dir]))));
        assert_eq!(first.failure, None);
        assert!(
            first.note.contains("no directory is running yet"),
            "{}",
            first.note
        );
        assert!(
            first.note.contains("wires directory serve"),
            "{}",
            first.note
        );
        // It runs, and takes the next edit.
        let took = PublishReport {
            delivered: vec![dir],
            missed: vec![other],
            ..PublishReport::default()
        };
        assert_eq!(settle(&ks, Ok((StateVersion(3), took))).failure, None);
        assert_eq!(reached(&ks), BTreeSet::from([dir]));
        // Now missing it is a failure; missing only one never reached
        // still isn't.
        assert!(
            settle(&ks, Ok((StateVersion(4), missed(&[dir]))))
                .failure
                .is_some()
        );
        assert!(
            settle(&ks, Ok((StateVersion(5), missed(&[dir, other]))))
                .failure
                .is_some()
        );
        assert_eq!(
            settle(&ks, Ok((StateVersion(6), missed(&[other])))).failure,
            None
        );
    }

    /// A directory holding a newer policy (or another at this version)
    /// fails the command even when others took it: this admin's copy is
    /// stale, and says how to restore it.
    #[test]
    fn a_directory_holding_a_newer_policy_fails_the_edit() {
        let (dir, other) = (node(3), node(4));
        for theirs in [StateVersion(9), StateVersion(7)] {
            let report = PublishReport {
                delivered: vec![other],
                newer: vec![(dir, theirs)],
                ..PublishReport::default()
            };
            let p = Propagation::from_publish(Ok((StateVersion(7), report)), true);
            let failure = p.failure.expect("fails");
            assert!(failure.contains("policy.json is stale"), "{failure}");
            assert!(failure.contains("copy policy.json"), "{failure}");
            assert!(
                failure.contains(&format!("version {}", theirs.0)),
                "{failure}"
            );
            assert!(p.note.contains("holding a newer policy"), "{}", p.note);
        }
    }
}

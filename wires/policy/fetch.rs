//! Moving the signed policy by key, through the directories
//! (`wires/directory/2`; the frames are [`library::directory`]'s).
//!
//! - [`publish_all`]: after every admin edit (and `wires policy push`), the
//!   admin publishes the whole new policy to every directory the new head
//!   lists, plus those the head before the edit listed (so a directory the
//!   edit drops learns it). It dials no host. A directory it can't reach is
//!   tried again within [`PUBLISH_BUDGET`] when it has taken a publish from
//!   this admin before ([`Retry`]: a directory just restarted is not
//!   findable by its key for a few seconds), then reported, not queued; the
//!   command fails when it reached none ([`PublishReport::reached_none`]).
//! - [`fetch`]: one `policy {have}` to each directory the held head lists
//!   in turn, stopping at the first adopted policy (whole, or the held one
//!   with a `policy_update` applied) or the first "you are current" vouched
//!   for by a `Fresh` from a listed directory. A host uses it once, at a
//!   start whose preflight fails ([`fetch_now`]: its first policy, or a
//!   service assigned while it was down), asking the directories its network
//!   string names while it holds no policy. Only nodes the policy names as
//!   hosts and directories may fetch the whole policy
//!   (card 37): a caller, the gateway included, holds its view
//!   ([`crate::caller::view`]).
//!
//! A running host follows its directories by subscription instead
//! ([`crate::host::follow`], card 36c).
//!
//! Nothing is ever adopted except through [`store::adopt_if_newer`]
//! (verified under the root, fresh, strictly newer), so a lying directory
//! can only fail to help.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use iroh::Endpoint;
use library::{
    DIRECTORY_ALPN, DirectoryAnswer, DirectoryRequest, NodeId, NodeIdentity, SignedPolicy,
    StateVersion,
};

use super::store::{self, Held};
use crate::admin::keystore::{self, Keystore};
use crate::clock::now_unix;
use crate::directory::wire::{ask, publish};
use crate::host::transport;

/// How long a host's start-up fetch ([`fetch_now`]) spends, all directories together.
const COLD_FETCH_BUDGET: Duration = Duration::from_secs(8);

/// How long a publish keeps trying a directory it could not reach
/// ([`publish_retrying`]), from its first try. A directory that has just
/// restarted can't be found by its key until its new address is known: n0
/// discovery has no record for it for about 3 s after it starts, and a
/// stale address hint costs a whole [`DIAL_TIMEOUT`](crate::directory::wire::DIAL_TIMEOUT)
/// before the next try looks it up again (card 48).
pub(crate) const PUBLISH_BUDGET: Duration = Duration::from_secs(15);

/// The pause between two tries at the directories a publish missed.
const RETRY_PAUSE: Duration = Duration::from_secs(1);

/// Which directories a publish tries again, within [`PUBLISH_BUDGET`], when
/// its first try misses them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Retry {
    /// Those that have taken a publish from this admin before
    /// ([`REACHED_FILE`](crate::admin::propagate::REACHED_FILE)): an edit's.
    /// One never reached may not run yet (the network's first run), and
    /// isn't waited for.
    Reached,
    /// Every one: `wires policy push`, which the admin runs once the
    /// directories are up.
    Every,
}

/// Which directories took a published policy and which didn't.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PublishReport {
    /// Directories now holding the published policy.
    pub(crate) delivered: Vec<NodeId>,
    /// Directories that couldn't be reached or refused it.
    pub(crate) missed: Vec<NodeId>,
    /// Of [`missed`](Self::missed), those that answered with a refusal: a
    /// decision, not tried again.
    pub(crate) refused: Vec<NodeId>,
    /// Directories holding a policy newer than the published one, or
    /// another at its version, with that version: the publisher's copy is
    /// stale, and its edit was not taken.
    pub(crate) newer: Vec<(NodeId, StateVersion)>,
}

impl PublishReport {
    /// One human line for the admin's stderr.
    pub(crate) fn line(&self, version: StateVersion) -> String {
        let total = self.delivered.len() + self.missed.len() + self.newer.len();
        if total == 0 {
            return format!(
                "policy version {} is stored here: no directory to publish to yet (name one with \
                 `wires directory add <label>=<node id>`)",
                version.0
            );
        }
        let mut out = format!(
            "policy version {}: published to {} of {total} directory(ies)",
            version.0,
            self.delivered.len()
        );
        if !self.missed.is_empty() {
            let short = |n: &NodeId| format!("{}…", n.short());
            let unreachable: Vec<String> = self
                .missed
                .iter()
                .filter(|n| !self.refused.contains(n))
                .map(short)
                .collect();
            let refused: Vec<String> = self.refused.iter().map(short).collect();
            if !unreachable.is_empty() {
                out.push_str(&format!("; not reached: {}", unreachable.join(", ")));
            }
            if !refused.is_empty() {
                out.push_str(&format!("; refused by: {}", refused.join(", ")));
            }
            // A directory that took it hands it on: every directory follows
            // the others (a replica subscription).
            if !self.delivered.is_empty() {
                out.push_str(&format!(
                    "; until it has version {}, hosts that follow it decide under the policy \
                     before it. It takes this one from a directory that did as soon as it \
                     reaches one; `wires policy push` re-publishes it",
                    version.0
                ));
            } else {
                out.push_str(" (`wires policy push` re-publishes it)");
            }
        }
        if !self.newer.is_empty() {
            out.push_str(&format!(
                "; holding a newer policy: {}",
                self.newer
                    .iter()
                    .map(|(n, v)| format!("{}… (version {})", n.short(), v.0))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        out
    }

    /// Whether there were directories to reach and not one took the
    /// policy: it is in force nowhere but here.
    pub(crate) fn reached_none(&self) -> bool {
        self.delivered.is_empty() && !self.missed.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Publish (admin)
// ---------------------------------------------------------------------------

/// What one directory made of a publish.
enum Took {
    /// It holds the published policy.
    Delivered,
    /// Unreachable.
    Missed,
    /// It answered, refusing it.
    Refused,
    /// It holds a newer policy, or another at this version (that version).
    Newer(StateVersion),
}

/// Publish `policy` to each of `targets`, concurrently ([`publish`]: no
/// credential, the root's signature is the whole check). A target counts as
/// delivered when it answers holding `policy`'s version and its very head
/// (by [`HeadHash`](library::HeadHash)). One answering a newer version, or
/// another head at this version, is [`newer`](PublishReport::newer): the
/// publisher's copy was stale, and the directory kept its own.
pub(crate) async fn publish_all(
    endpoint: &Endpoint,
    policy: &SignedPolicy,
    targets: &[NodeId],
) -> Result<PublishReport> {
    let mut report = PublishReport::default();
    let mut set = tokio::task::JoinSet::new();
    let policy = Arc::new(policy.clone());
    let want_head = policy.head.hash()?;
    for &target in targets {
        let endpoint = endpoint.clone();
        let policy = Arc::clone(&policy);
        set.spawn(async move {
            let want = policy.version();
            let took = match publish(&endpoint, target, &policy).await {
                Ok(DirectoryAnswer::Published { version, .. }) if version > want => {
                    Took::Newer(version)
                }
                // The same version may be another policy (an admin whose
                // copy was one edit behind): its head says.
                Ok(DirectoryAnswer::Published { version, head }) if version == want => {
                    if head == want_head {
                        Took::Delivered
                    } else {
                        Took::Newer(version)
                    }
                }
                Ok(DirectoryAnswer::Denied { reason }) => {
                    tracing::warn!(directory = %target.hex(), "publish refused: {reason}");
                    Took::Refused
                }
                Ok(_) => {
                    tracing::warn!(directory = %target.hex(), "publish answered out of turn");
                    Took::Refused
                }
                Err(e) => {
                    tracing::debug!(directory = %target.hex(), "publish failed: {e:#}");
                    Took::Missed
                }
            };
            (target, took)
        });
    }
    while let Some(joined) = set.join_next().await {
        match joined.context("a publish task panicked")? {
            (target, Took::Delivered) => report.delivered.push(target),
            (target, Took::Missed) => report.missed.push(target),
            (target, Took::Refused) => {
                report.missed.push(target);
                report.refused.push(target);
            }
            (target, Took::Newer(v)) => report.newer.push((target, v)),
        }
    }
    report.delivered.sort();
    report.missed.sort();
    report.refused.sort();
    report.newer.sort();
    Ok(report)
}

/// [`publish_all`], then the directories it missed for want of a dial
/// (not those that refused) and `patient` names, again and again, a
/// [`RETRY_PAUSE`] apart, until each took it or `budget` (from the first
/// try) is spent: a directory just restarted is not findable by its key for
/// a few seconds, and every new dial looks its key up again. The report
/// holds each directory's last outcome.
pub(crate) async fn publish_retrying(
    endpoint: &Endpoint,
    policy: &SignedPolicy,
    targets: &[NodeId],
    patient: &BTreeSet<NodeId>,
    budget: Duration,
) -> Result<PublishReport> {
    let deadline = tokio::time::Instant::now() + budget;
    let mut report = publish_all(endpoint, policy, targets).await?;
    loop {
        let again: Vec<NodeId> = report
            .missed
            .iter()
            .filter(|d| patient.contains(d) && !report.refused.contains(d))
            .copied()
            .collect();
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if again.is_empty() || left <= RETRY_PAUSE {
            return Ok(report);
        }
        tracing::debug!(
            directories = again.len(),
            "publish: trying the directories not reached again"
        );
        tokio::time::sleep(RETRY_PAUSE).await;
        // A try cut off by the deadline leaves them missed.
        let Ok(round) =
            tokio::time::timeout(left - RETRY_PAUSE, publish_all(endpoint, policy, &again)).await
        else {
            return Ok(report);
        };
        let round = round?;
        report.missed.retain(|d| !again.contains(d));
        report.delivered.extend(round.delivered);
        report.missed.extend(round.missed);
        report.refused.extend(round.refused);
        report.newer.extend(round.newer);
        report.delivered.sort();
        report.missed.sort();
        report.refused.sort();
        report.newer.sort();
    }
}

/// Who the admin publishes `held` to: its directories, plus `earlier` (the
/// directories of the policy before this edit), never `me`.
pub(crate) fn publish_targets(held: &Held, earlier: &BTreeSet<NodeId>, me: NodeId) -> Vec<NodeId> {
    held.directories()
        .iter()
        .copied()
        .chain(earlier.iter().copied())
        .filter(|d| *d != me)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The admin's publish of the stored policy from `ks` over `endpoint`, to
/// [`publish_targets`], trying those `retry` names again within
/// [`PUBLISH_BUDGET`] ([`publish_retrying`]).
pub(crate) async fn publish_current_on(
    endpoint: &Endpoint,
    ks: &Keystore,
    earlier: &BTreeSet<NodeId>,
    retry: Retry,
) -> Result<PublishReport> {
    let held = stored(ks)?;
    let me = transport::to_node_id(&endpoint.id());
    let targets = publish_targets(&held, earlier, me);
    let patient = match retry {
        Retry::Reached => crate::admin::propagate::reached(ks),
        Retry::Every => targets.iter().copied().collect(),
    };
    publish_retrying(endpoint, &held.signed, &targets, &patient, PUBLISH_BUDGET).await
}

/// [`publish_current_on`] over a freshly bound endpoint for this keystore's
/// node (the admin CLI's form): the version published and the report. Binds
/// nothing when there is no directory to publish to.
pub(crate) async fn publish_current(
    ks: &Keystore,
    earlier: &BTreeSet<NodeId>,
    retry: Retry,
) -> Result<(StateVersion, PublishReport)> {
    let held = stored(ks)?;
    let node = keystore::node_identity_in(ks)?;
    let version = held.version();
    if publish_targets(&held, earlier, node.node_id()).is_empty() {
        return Ok((version, PublishReport::default()));
    }
    let endpoint = transport::bind_with_alpn(&node, None, DIRECTORY_ALPN).await?;
    let report = publish_current_on(&endpoint, ks, earlier, retry).await;
    endpoint.close().await;
    Ok((version, report?))
}

/// The directories of the policy `ks` holds now (empty when it holds none):
/// what an admin command records before its edit, for [`publish_targets`].
pub(crate) fn held_directories(ks: &Keystore) -> Result<BTreeSet<NodeId>> {
    let Some(root) = ks.network_root()? else {
        return Ok(BTreeSet::new());
    };
    Ok(store::read(ks, root)?
        .map_or_else(BTreeSet::new, |h| h.directories().iter().copied().collect()))
}

/// The policy `ks` holds, or an error saying there is none.
fn stored(ks: &Keystore) -> Result<Held> {
    let root = ks
        .network_root()?
        .ok_or_else(|| anyhow!("this keystore is in no network"))?;
    store::read(ks, root)?.ok_or_else(|| anyhow!("no signed policy here"))
}

// ---------------------------------------------------------------------------
// Fetch (hosts)
// ---------------------------------------------------------------------------

/// Ask `directories` in turn for a policy newer than the one `ks` holds,
/// stopping at the first answer that settles it:
///
/// - a `policy` whose `Fresh` vouches for its head, and which verifies, is
///   fresh and is newer, is adopted and returned; so is the held policy with
///   a `policy_update` applied ([`SignedPolicy::apply`]);
/// - `current`, with a `Fresh` for the held head from a directory that head
///   lists, current at `now`: this node is up to date (`Ok(None)`).
///
/// A refusal, a lapsed or foreign `Fresh`, or an older policy settles
/// nothing: the next directory is asked.
pub(crate) async fn fetch(
    endpoint: &Endpoint,
    ks: &Keystore,
    directories: &[NodeId],
) -> Result<Option<SignedPolicy>> {
    let root = ks
        .network_root()?
        .ok_or_else(|| anyhow!("this keystore is in no network"))?;
    for dir in directories {
        let held = store::read(ks, root)?;
        let have = held.as_ref().map_or(StateVersion(0), Held::version);
        let request = DirectoryRequest::Policy { have };
        match ask(endpoint, *dir, None, &request).await {
            Ok(DirectoryAnswer::Policy { policy, fresh }) => {
                let vouched = policy
                    .head
                    .verify(root)
                    .map_err(anyhow::Error::from)
                    .and_then(|()| Ok(fresh.verify(&policy.head)?));
                if let Err(e) = vouched {
                    tracing::warn!(directory = %dir.hex(), "refused a fetched policy: {e:#}");
                    continue;
                }
                match store::adopt_if_newer(ks, &policy, root, now_unix()) {
                    Ok(true) => {
                        return Ok(Some(policy));
                    }
                    Ok(false) => {}
                    Err(e) => {
                        tracing::warn!(directory = %dir.hex(), "refused a fetched policy: {e:#}")
                    }
                }
            }
            // The delta from the version held (card 36c): applied to the
            // held copy, which must then verify as a whole.
            Ok(DirectoryAnswer::PolicyUpdate { update, fresh }) => {
                let Some(held) = held else { continue };
                let applied = held
                    .signed
                    .apply(&update, root)
                    .map_err(anyhow::Error::from)
                    .and_then(|next| {
                        fresh.verify(&next.head)?;
                        Ok(next)
                    });
                let next = match applied {
                    Ok(next) => next,
                    Err(e) => {
                        tracing::warn!(directory = %dir.hex(), "refused a policy update: {e:#}");
                        continue;
                    }
                };
                match store::adopt_if_newer(ks, &next, root, now_unix()) {
                    Ok(true) => {
                        return Ok(Some(next));
                    }
                    Ok(false) => {}
                    Err(e) => {
                        tracing::warn!(directory = %dir.hex(), "refused a policy update: {e:#}")
                    }
                }
            }
            Ok(DirectoryAnswer::Current { fresh }) => {
                let Some(held) = held else { continue };
                match fresh.verify(&held.signed.head) {
                    Ok(()) if fresh.is_current(now_unix()) => {
                        return Ok(None);
                    }
                    Ok(()) => tracing::debug!(directory = %dir.hex(), "a lapsed freshness"),
                    Err(e) => {
                        tracing::warn!(directory = %dir.hex(), "refused a freshness: {e:#}")
                    }
                }
            }
            Ok(DirectoryAnswer::Denied { reason }) => {
                tracing::debug!(directory = %dir.hex(), "policy fetch refused: {reason}")
            }
            Ok(other) => {
                tracing::debug!(directory = %dir.hex(), "an unexpected answer: {other:?}")
            }
            Err(e) => tracing::debug!(directory = %dir.hex(), "policy fetch failed: {e:#}"),
        }
    }
    Ok(None)
}

/// The directories this node asks, never itself: those its held policy
/// lists, in the admin's order, or, holding none yet, those its network
/// string names.
pub(crate) fn directories_of(ks: &Keystore, me: NodeId) -> Result<Vec<NodeId>> {
    let Some(root) = ks.network_root()? else {
        return Ok(Vec::new());
    };
    let listed = match store::read(ks, root)? {
        Some(h) => h.directories().to_vec(),
        None => ks.read_network()?.map_or_else(Vec::new, |n| n.directories),
    };
    Ok(listed.into_iter().filter(|d| *d != me).collect())
}

/// [`fetch`] over `endpoint` from [`directories_of`], whether or not the
/// copy is stale. Returns the newly adopted policy, if any.
pub(crate) async fn catch_up(endpoint: &Endpoint, ks: &Keystore) -> Result<Option<SignedPolicy>> {
    let me = transport::to_node_id(&endpoint.id());
    let dirs = directories_of(ks, me)?;
    if dirs.is_empty() {
        return Ok(None);
    }
    fetch(endpoint, ks, &dirs).await
}

/// `wires serve`'s fetch at start (its first policy, or a service assigned
/// while it was offline): bind as `node` briefly and [`catch_up`], within
/// the start-up fetch budget.
pub(crate) async fn fetch_now(
    ks: &Keystore,
    node: &NodeIdentity,
    relay_url: Option<&str>,
) -> Result<Option<SignedPolicy>> {
    let endpoint = transport::bind_with(node, relay_url, DIRECTORY_ALPN, false, Some(ks)).await?;
    let fetched = tokio::time::timeout(COLD_FETCH_BUDGET, catch_up(&endpoint, ks))
        .await
        .unwrap_or(Ok(None));
    endpoint.close().await;
    fetched
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_publish_line_says_which_directories_it_missed() {
        let a = NodeIdentity::from_seed([3; 32]).node_id();
        let b = NodeIdentity::from_seed([4; 32]).node_id();
        let none = PublishReport::default();
        assert!(none.line(StateVersion(2)).contains("no directory"));
        assert!(!none.reached_none());
        let missed = PublishReport {
            delivered: vec![a],
            missed: vec![b],
            ..PublishReport::default()
        };
        let line = missed.line(StateVersion(2));
        assert!(line.contains("published to 1 of 2"), "{line}");
        assert!(
            line.contains(&format!("not reached: {}…", b.short())),
            "{line}"
        );
        // What a miss means, when another directory took it.
        assert!(
            line.contains(
                "until it has version 2, hosts that follow it decide under the policy before it"
            ),
            "{line}"
        );
        assert!(line.contains("wires policy push"), "{line}");
        assert!(!missed.reached_none());
        // A refusal is named as one.
        let refused = PublishReport {
            delivered: vec![a],
            missed: vec![b],
            refused: vec![b],
            ..PublishReport::default()
        };
        let line = refused.line(StateVersion(2));
        assert!(
            line.contains(&format!("refused by: {}…", b.short())),
            "{line}"
        );
        assert!(!line.contains("not reached"), "{line}");
        let all_missed = PublishReport {
            delivered: vec![],
            missed: vec![a, b],
            ..PublishReport::default()
        };
        assert!(all_missed.reached_none());
        let line = all_missed.line(StateVersion(2));
        assert!(!line.contains("hosts that follow it"), "{line}");
        assert!(
            line.contains("`wires policy push` re-publishes it"),
            "{line}"
        );
    }
}

//! Moving the signed policy by key, through the directories
//! (`wires/directory/1`; the frames are [`library::directory`]'s).
//!
//! - [`publish_all`]: after every admin edit (and `wires state push`), the
//!   admin publishes the whole new policy to every directory the new head
//!   lists, plus those the head before the edit listed (so a directory the
//!   edit drops learns it). It dials no host. A directory it can't reach is
//!   reported, not queued; the command fails when it reached none
//!   ([`PublishReport::reached_none`]).
//! - [`fetch`]: one `policy {have}` to each directory the held head lists
//!   in turn, stopping at the first adopted policy (whole, or the held one
//!   with a `policy_update` applied) or the first "you are current" vouched
//!   for by a `Fresh` from a listed directory. A host uses it once, at a
//!   start whose preflight fails ([`fetch_now`]: a service assigned while it
//!   was down). Only hosts and directories may fetch the whole policy
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
    DIRECTORY_ALPN, DirectoryAnswer, DirectoryRequest, Membership, NodeId, NodeIdentity,
    SignedPolicy, StateVersion,
};

use super::store::{self, Held};
use crate::admin::keystore::{self, Keystore};
use crate::clock::now_unix;
use crate::directory::wire::ask;
use crate::host::transport;

/// How long a cold command spends fetching, all directories together.
const COLD_FETCH_BUDGET: Duration = Duration::from_secs(8);

/// Which directories took a published policy and which didn't.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PublishReport {
    /// Directories now holding at least the published version.
    pub(crate) delivered: Vec<NodeId>,
    /// Directories that couldn't be reached or refused it.
    pub(crate) missed: Vec<NodeId>,
}

impl PublishReport {
    /// One human line for the admin's stderr.
    pub(crate) fn line(&self, version: StateVersion) -> String {
        let total = self.delivered.len() + self.missed.len();
        if total == 0 {
            return format!(
                "policy version {}: no directory to publish to yet (name one with `wires \
                 directory add <node>`; a new node gets the policy in its invite token)",
                version.0
            );
        }
        let mut out = format!(
            "policy version {}: published to {} of {total} directory(ies)",
            version.0,
            self.delivered.len()
        );
        if !self.missed.is_empty() {
            out.push_str(&format!(
                "; not reached: {} (`wires state push` re-publishes it)",
                self.missed
                    .iter()
                    .map(|n| format!("{}…", n.short()))
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

/// Publish `policy` to each of `targets`, concurrently, presenting `badge`
/// (the admin's own). A target counts as delivered once it answers holding
/// at least `policy`'s version.
pub(crate) async fn publish_all(
    endpoint: &Endpoint,
    badge: &Membership,
    policy: &SignedPolicy,
    targets: &[NodeId],
) -> Result<PublishReport> {
    let mut report = PublishReport::default();
    let mut set = tokio::task::JoinSet::new();
    let request = Arc::new(DirectoryRequest::Publish {
        head: policy.head.clone(),
        items: policy.items.clone(),
    });
    for &target in targets {
        let endpoint = endpoint.clone();
        let badge = badge.clone();
        let request = Arc::clone(&request);
        let want = policy.version();
        set.spawn(async move {
            let ok = match ask(&endpoint, target, &badge, None, &request).await {
                Ok(DirectoryAnswer::Published { version }) => version >= want,
                Ok(DirectoryAnswer::Denied { reason }) => {
                    tracing::warn!(directory = %target.hex(), "publish refused: {reason}");
                    false
                }
                Ok(_) => false,
                Err(e) => {
                    tracing::debug!(directory = %target.hex(), "publish failed: {e:#}");
                    false
                }
            };
            (target, ok)
        });
    }
    while let Some(joined) = set.join_next().await {
        let (target, ok) = joined.context("a publish task panicked")?;
        if ok {
            report.delivered.push(target);
        } else {
            report.missed.push(target);
        }
    }
    report.delivered.sort();
    report.missed.sort();
    Ok(report)
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
/// [`publish_targets`].
pub(crate) async fn publish_current_on(
    endpoint: &Endpoint,
    ks: &Keystore,
    earlier: &BTreeSet<NodeId>,
) -> Result<PublishReport> {
    let held = stored(ks)?;
    let me = transport::to_node_id(&endpoint.id());
    publish_all(
        endpoint,
        &badge(ks)?,
        &held.signed,
        &publish_targets(&held, earlier, me),
    )
    .await
}

/// [`publish_current_on`] over a freshly bound endpoint for this keystore's
/// node (the admin CLI's form): the version published and the report. Binds
/// nothing when there is no directory to publish to.
pub(crate) async fn publish_current(
    ks: &Keystore,
    earlier: &BTreeSet<NodeId>,
) -> Result<(StateVersion, PublishReport)> {
    let held = stored(ks)?;
    let node = keystore::node_identity_in(ks)?;
    let version = held.version();
    if publish_targets(&held, earlier, node.node_id()).is_empty() {
        return Ok((version, PublishReport::default()));
    }
    let endpoint = transport::bind_with_alpn(&node, None, DIRECTORY_ALPN).await?;
    let report = publish_current_on(&endpoint, ks, earlier).await;
    endpoint.close().await;
    Ok((version, report?))
}

/// The directories of the policy `ks` holds now (empty when it holds none):
/// what an admin command records before its edit, for [`publish_targets`].
pub(crate) fn held_directories(ks: &Keystore) -> Result<BTreeSet<NodeId>> {
    let Some(root) = store::fabric(ks)? else {
        return Ok(BTreeSet::new());
    };
    Ok(store::read(ks, root)?
        .map_or_else(BTreeSet::new, |h| h.directories().iter().copied().collect()))
}

/// This node's own badge, which every request opens with.
fn badge(ks: &Keystore) -> Result<Membership> {
    ks.read_membership()?
        .ok_or_else(|| anyhow!("this keystore holds no badge (membership.json)"))
}

/// The policy `ks` holds, or an error saying there is none.
fn stored(ks: &Keystore) -> Result<Held> {
    let root = store::fabric(ks)?.ok_or_else(|| anyhow!("this keystore is in no network"))?;
    store::read(ks, root)?.ok_or_else(|| anyhow!("no signed policy here"))
}

// ---------------------------------------------------------------------------
// Fetch (hosts and callers)
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
/// Only those two mark the copy checked; a refusal, a lapsed or foreign
/// `Fresh`, or an older policy does not (so the next check asks again).
pub(crate) async fn fetch(
    endpoint: &Endpoint,
    ks: &Keystore,
    directories: &[NodeId],
) -> Result<Option<SignedPolicy>> {
    let root = store::fabric(ks)?.ok_or_else(|| anyhow!("this keystore is in no network"))?;
    let badge = badge(ks)?;
    for dir in directories {
        let held = store::read(ks, root)?;
        let have = held.as_ref().map_or(StateVersion(0), Held::version);
        let request = DirectoryRequest::Policy { have };
        match ask(endpoint, *dir, &badge, None, &request).await {
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
                        store::mark_checked(ks, now_unix())?;
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
                        store::mark_checked(ks, now_unix())?;
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
                        store::mark_checked(ks, now_unix())?;
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
/// lists, in the admin's order.
pub(crate) fn directories_of(ks: &Keystore, me: NodeId) -> Result<Vec<NodeId>> {
    let Some(root) = store::fabric(ks)? else {
        return Ok(Vec::new());
    };
    Ok(store::read(ks, root)?.map_or_else(Vec::new, |h| {
        h.directories()
            .iter()
            .copied()
            .filter(|d| *d != me)
            .collect()
    }))
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

/// `wires serve`'s fetch at start (a host assigned a service while it was
/// offline): bind as `node` briefly and [`catch_up`], within the cold-fetch
/// budget.
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
        };
        let line = missed.line(StateVersion(2));
        assert!(line.contains("published to 1 of 2"), "{line}");
        assert!(line.contains(&b.short()), "{line}");
        assert!(!missed.reached_none());
        let all_missed = PublishReport {
            delivered: vec![],
            missed: vec![a, b],
        };
        assert!(all_missed.reached_none());
    }
}

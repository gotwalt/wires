//! The host's `policy` subscription (card 36c): how a running host keeps
//! its whole signed policy current, and learns that it is.
//!
//! A [`Follower`] subscribes (`wires/directory-sub/1`, `subscribe {kind:
//! policy, have}`) to the first directory its held head lists that answers,
//! never itself, and takes every frame the directory streams
//! ([`Follower::take`]):
//!
//! - `policy {policy, fresh}`: the whole policy (first sync, or after a
//!   failed update): verified under the root and adopted if newer;
//! - `policy_update {update, fresh}`: applied to the held copy
//!   ([`SignedPolicy::apply`](library::SignedPolicy::apply): the items'
//!   hash and the root's one signature on the new head), then adopted;
//! - `fresh {fresh}`: a beat for the held head.
//!
//! Every policy goes through [`store::adopt_if_newer`], so a directory can
//! only fail to help; every `Fresh` must vouch for the head then held
//! ([`Freshness::offer`]). A frame that can't be taken (an update that
//! doesn't apply, a policy that doesn't verify) makes the follower subscribe
//! again at once with `have: 0`, for the whole policy. When the stream ends
//! (the directory stopped, went silent for two beats, or is no longer
//! listed) it reconnects, trying the directory it last followed first and
//! then the others in the head's order, backing off from 1 s to the beat
//! (at most 30 s) while none answers. The list is re-read from the held
//! policy each time, so a directory the admin adds is followed without a
//! restart.
//!
//! A host that is itself a directory also vouches for its own head
//! ([`vouch_from_local`]); its directory's replica loop keeps its copy in
//! step with the other directories.
//!
//! The follower never blocks serving: a host restarted with its policy on
//! disk decides from it before any directory answers.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use iroh::Endpoint;
use library::{
    DIRECTORY_SUB_ALPN, Fresh, Membership, NodeId, SignedPolicy, StateVersion, SubFrame,
    SubRequest, SubscriptionKind,
};

use super::freshness::Freshness;
use super::transport;
use crate::admin::keystore::Keystore;
use crate::clock::now_unix;
use crate::directory::node::Directory;
use crate::directory::wire;
use crate::policy::fetch::directories_of;
use crate::policy::store;

/// The longest pause between two rounds of dialing the directories.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// What a follower received, for its trace and the tests: frames and their
/// bytes, by kind.
#[derive(Debug, Default)]
pub(crate) struct FollowStats {
    /// Every frame.
    pub(crate) frames: AtomicU64,
    /// Their encoded bytes, length prefixes included.
    pub(crate) bytes: AtomicU64,
    /// Whole `policy` frames.
    pub(crate) wholes: AtomicU64,
    /// `policy_update` frames.
    pub(crate) updates: AtomicU64,
    /// `fresh` beats.
    pub(crate) beats: AtomicU64,
    /// Subscriptions started over with `have: 0` after a frame that
    /// couldn't be taken.
    pub(crate) resyncs: AtomicU64,
}

/// A running host's subscription to its directories. See the module docs.
pub(crate) struct Follower {
    /// The host's endpoint: the subscription dials from it.
    pub(crate) endpoint: Endpoint,
    /// Where the policy (`policy.json`) is kept.
    pub(crate) ks: Arc<Keystore>,
    /// The network root everything verifies under.
    pub(crate) root: NodeId,
    /// The host's badge, which each subscription opens with.
    pub(crate) badge: Membership,
    /// Where each `Fresh` goes.
    pub(crate) freshness: Arc<Freshness>,
    /// Whether this host runs the directory mode (decided at start): if not,
    /// a policy that newly lists it says a restart is needed.
    pub(crate) runs_directory: bool,
    /// What it received.
    pub(crate) stats: Arc<FollowStats>,
}

/// How one subscription ended, after the directory answered.
#[derive(Debug)]
enum Ended {
    /// The stream closed or went silent: reconnect.
    Closed,
    /// A frame couldn't be taken: subscribe again with `have: 0`.
    Resync(anyhow::Error),
}

impl Follower {
    /// This host's node id.
    fn me(&self) -> NodeId {
        transport::to_node_id(&self.endpoint.id())
    }

    /// The version held now (0: none).
    fn held_version(&self) -> StateVersion {
        store::read(&self.ks, self.root)
            .ok()
            .flatten()
            .map_or(StateVersion(0), |h| h.version())
    }

    /// The pause cap: the held policy's beat, at most [`MAX_BACKOFF`].
    fn max_backoff(&self) -> Duration {
        let beat = store::read(&self.ks, self.root)
            .ok()
            .flatten()
            .map_or(library::DEFAULT_BEAT_SECS, |h| h.policy.settings.beat_secs);
        Duration::from_secs(u64::from(beat.max(1))).min(MAX_BACKOFF)
    }

    /// How long a subscription may stay silent before it is taken for dead:
    /// two beats and some slack.
    fn silence(&self) -> Duration {
        let beat = store::read(&self.ks, self.root)
            .ok()
            .flatten()
            .map_or(library::DEFAULT_BEAT_SECS, |h| h.policy.settings.beat_secs);
        Duration::from_secs(2 * u64::from(beat.max(1)) + 10)
    }

    /// Follow the directories until the task is dropped. See the module
    /// docs.
    pub(crate) async fn run(self) {
        let mut backoff = Duration::from_secs(1);
        let mut whole = false;
        let mut last: Option<NodeId> = None;
        loop {
            if self.endpoint.is_closed() {
                return;
            }
            let mut dirs = directories_of(&self.ks, self.me()).unwrap_or_default();
            if let Some(i) = last.and_then(|l| dirs.iter().position(|d| *d == l)) {
                dirs.rotate_left(i);
            }
            let mut answered = false;
            for dir in dirs {
                let have = if whole {
                    StateVersion(0)
                } else {
                    self.held_version()
                };
                match self.subscribe_once(dir, have).await {
                    Ok(Ended::Closed) => {
                        whole = false;
                        answered = true;
                    }
                    Ok(Ended::Resync(e)) => {
                        self.stats.resyncs.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            directory = %dir.hex(),
                            "policy subscription: {e:#}; asking for the whole policy"
                        );
                        // Twice in a row from the whole policy: try the next
                        // directory, after a pause.
                        answered = !whole;
                        whole = true;
                    }
                    Err(e) => {
                        tracing::debug!(directory = %dir.hex(), "policy subscription: {e:#}");
                        continue;
                    }
                }
                last = Some(dir);
                break;
            }
            if answered {
                backoff = Duration::from_secs(1);
                if whole {
                    continue;
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(self.max_backoff());
        }
    }

    /// One subscription to `dir` from `have`, until it ends. `Err`: the
    /// directory never answered (unreachable, refused, or closed at once).
    async fn subscribe_once(&self, dir: NodeId, have: StateVersion) -> Result<Ended> {
        let addr = transport::endpoint_addr(&dir, &[], None)?;
        let conn = tokio::time::timeout(
            wire::DIAL_TIMEOUT,
            self.endpoint.connect(addr, DIRECTORY_SUB_ALPN),
        )
        .await
        .map_err(|_| anyhow!("no answer within {:?}", wire::DIAL_TIMEOUT))?
        .map_err(|e| anyhow!("dialing directory {}…: {e}", dir.short()))?;
        let ended = self.stream(&conn, dir, have).await;
        conn.close(0u32.into(), b"done");
        ended
    }

    /// Subscribe on `conn` and take its frames until it ends.
    async fn stream(
        &self,
        conn: &iroh::endpoint::Connection,
        dir: NodeId,
        have: StateVersion,
    ) -> Result<Ended> {
        let (mut send, mut recv) = conn.open_bi().await.context("opening a stream")?;
        let hello = SubRequest::Hello {
            badge: self.badge.clone(),
            id_token: None,
        };
        let subscribe = SubRequest::Subscribe {
            kind: SubscriptionKind::Policy,
            have,
        };
        wire::write(&mut send, &hello.encode()?).await?;
        wire::write(&mut send, &subscribe.encode()?).await?;
        let mut answered = false;
        loop {
            let read = tokio::time::timeout(self.silence(), wire::read_sub_frame(&mut recv)).await;
            let frame = match read {
                Ok(Ok(Some(frame))) => frame,
                Ok(Ok(None)) if !answered => bail!("the directory closed without answering"),
                Ok(Err(e)) if !answered => return Err(e),
                Err(_) if !answered => bail!("no answer within {:?}", self.silence()),
                Ok(Ok(None)) | Ok(Err(_)) | Err(_) => return Ok(Ended::Closed),
            };
            self.count(&frame);
            if let SubFrame::Denied { reason } = frame {
                if answered {
                    tracing::info!(directory = %dir.hex(), "policy subscription ended: {reason}");
                    return Ok(Ended::Closed);
                }
                bail!("refused: {reason}");
            }
            if !answered {
                tracing::info!(directory = %dir.hex(), have = have.0, "following the policy");
            }
            answered = true;
            if let Err(e) = self.take(frame, now_unix()) {
                return Ok(Ended::Resync(e));
            }
            let listed = store::read(&self.ks, self.root)
                .ok()
                .flatten()
                .is_some_and(|h| h.directories().contains(&dir));
            if !listed {
                tracing::info!(directory = %dir.hex(), "no longer a directory; following another");
                return Ok(Ended::Closed);
            }
        }
    }

    /// Count `frame` in [`stats`](Self::stats).
    fn count(&self, frame: &SubFrame) {
        let s = &self.stats;
        s.frames.fetch_add(1, Ordering::Relaxed);
        let bytes = frame.encode().map_or(0, |b| b.len() as u64);
        s.bytes.fetch_add(bytes, Ordering::Relaxed);
        match frame {
            SubFrame::Policy { .. } => s.wholes.fetch_add(1, Ordering::Relaxed),
            SubFrame::PolicyUpdate { .. } => s.updates.fetch_add(1, Ordering::Relaxed),
            SubFrame::Fresh { .. } => s.beats.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    /// Take one frame at `now`: adopt the policy it brings (whole, or the
    /// held copy with the update applied) if newer, and keep its `Fresh`.
    /// `Err`: it can't be taken, and the follower asks for the whole policy.
    pub(crate) fn take(&self, frame: SubFrame, now: i64) -> Result<()> {
        match frame {
            SubFrame::Policy { policy, fresh } => {
                policy
                    .head
                    .verify(self.root)
                    .context("the policy's head doesn't verify")?;
                fresh
                    .verify(&policy.head)
                    .context("the freshness doesn't vouch for the policy's head")?;
                self.adopt(&policy, "whole", now)?;
                self.vouch(&fresh)
            }
            SubFrame::PolicyUpdate { update, fresh } => {
                let held = store::read(&self.ks, self.root)?
                    .context("this host holds no policy to apply an update to")?;
                let next = held
                    .signed
                    .apply(&update, self.root)
                    .context("the update doesn't apply to the held policy")?;
                fresh
                    .verify(&next.head)
                    .context("the freshness doesn't vouch for the update's head")?;
                self.adopt(&next, "update", now)?;
                self.vouch(&fresh)
            }
            SubFrame::Fresh { fresh } => self.vouch(&fresh),
            SubFrame::Denied { reason } => bail!("refused: {reason}"),
            SubFrame::View { .. } | SubFrame::ViewUpdate { .. } => {
                bail!("a view frame on a policy subscription")
            }
        }
    }

    /// Adopt `policy` if newer (`how` it came, for the trace).
    fn adopt(&self, policy: &SignedPolicy, how: &str, now: i64) -> Result<()> {
        if store::adopt_if_newer(&self.ks, policy, self.root, now)? {
            tracing::info!(version = policy.version().0, how, "followed a newer policy");
            let me = self.me();
            if !self.runs_directory && policy.head.head.directories.contains(&me) {
                static SAID: AtomicBool = AtomicBool::new(false);
                if !SAID.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        "the policy now lists this host as a directory; restart `wires serve` \
                         to run it"
                    );
                }
            }
        }
        Ok(())
    }

    /// Keep `fresh` if it vouches for the head held now. One for another
    /// head (a directory behind this host, say) is skipped, not an error.
    fn vouch(&self, fresh: &Fresh) -> Result<()> {
        let Some(held) = store::read(&self.ks, self.root)? else {
            return Ok(());
        };
        if fresh.version != held.version() {
            tracing::debug!(
                theirs = fresh.version.0,
                ours = held.version().0,
                "a freshness for another version"
            );
            return Ok(());
        }
        self.freshness.offer(fresh, &held.signed.head)?;
        Ok(())
    }
}

/// A host that is also a directory: keep every `Fresh` its own directory
/// signs, for the head held then, until the task is dropped.
pub(crate) async fn vouch_from_local(
    dir: Arc<Directory>,
    ks: Arc<Keystore>,
    root: NodeId,
    freshness: Arc<Freshness>,
) {
    let mut changes = dir.watch();
    loop {
        let fresh = changes
            .borrow_and_update()
            .as_ref()
            .and_then(|c| c.fresh.clone());
        if let Some(fresh) = fresh
            && let Ok(Some(held)) = store::read(&ks, root)
            && held.version() == fresh.version
            && let Err(e) = freshness.offer(&fresh, &held.signed.head)
        {
            tracing::debug!("this directory's own freshness: {e:#}");
        }
        if changes.changed().await.is_err() {
            return;
        }
    }
}

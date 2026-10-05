//! The host's subscription to the policy: how a running host keeps its
//! whole signed policy current, and learns that it is.
//!
//! A [`Follower`] subscribes (`wires/directory-sub/3`, a `hello` with no
//! token, then `subscribe {have}`) to the first directory its held head
//! lists that answers, never itself, and takes every frame the directory
//! streams ([`Follower::take`]):
//!
//! - `policy {policy, fresh}`: the whole policy (there are no deltas, card
//!   45): verified under the root and adopted if newer;
//! - `fresh {fresh}`: a beat, kept when it vouches for the held head.
//!
//! Every policy goes through [`store::adopt_if_newer`] (on a host that is
//! also a directory, through its directory's [`Directory::accept`], which
//! adopts it: the node has one copy), so a directory can only fail to help;
//! every `Fresh` must vouch for the head then held ([`Freshness::offer`]).
//!
//! A directory is **passed over** for the next one, at once, when it is
//! behind this host (a frame for an older head than the one held: it missed
//! a publish, and can't vouch for this host's head), when it sends a policy
//! this host can't take (it doesn't verify, or has expired), and when it
//! answers `denied`, at once or ending the stream (this host is not
//! admitted, or may no longer hold the whole policy; the directory is no
//! longer one, or busy). The next round starts at the directory after it; a
//! round in which no directory served waits a pause growing from 1 s to the
//! beat (at most 30 s). When the stream ends (the directory stopped, went
//! silent for two beats, or is no longer listed) it reconnects, trying the
//! directory it last followed first and then the others in the head's order.
//! The list is re-read from the held policy each time, so a directory the
//! admin adds is followed without a restart.
//!
//! A host that is itself a directory also vouches for its own head
//! ([`vouch_from_local`]).
//!
//! The follower never blocks serving: a host restarted with its policy on
//! disk decides from it before any directory answers.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use iroh::Endpoint;
use library::{
    DIRECTORY_SUB_ALPN, Fresh, NodeId, SignedPolicy, StateVersion, SubFrame, SubRequest,
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
    /// `fresh` beats.
    pub(crate) beats: AtomicU64,
    /// `denied` answers, at once or ending a stream.
    pub(crate) denials: AtomicU64,
    /// Directories passed over because they were behind this host.
    pub(crate) behind: AtomicU64,
}

/// A running host's subscription to its directories. See the module docs.
pub(crate) struct Follower {
    /// The host's endpoint: the subscription dials from it.
    pub(crate) endpoint: Endpoint,
    /// Where the policy (`policy.json`) is kept.
    pub(crate) ks: Arc<Keystore>,
    /// The network root everything verifies under.
    pub(crate) root: NodeId,
    /// Where each `Fresh` goes.
    pub(crate) freshness: Arc<Freshness>,
    /// This host's own directory, when it runs one (decided at start): a
    /// newer policy goes through it, so it serves what the host decides
    /// under. Without one, a policy that newly lists this host says a
    /// restart is needed.
    pub(crate) directory: Option<Arc<Directory>>,
    /// What it received.
    pub(crate) stats: Arc<FollowStats>,
}

/// How one subscription ended.
#[derive(Debug)]
enum Ended {
    /// The stream closed or went silent, after the directory answered:
    /// reconnect.
    Closed,
    /// The directory refused, is behind this host, or sent a policy this
    /// host can't take: pass it over.
    PassOver(String),
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

    /// The held policy's beat.
    fn beat(&self) -> Duration {
        let beat = store::read(&self.ks, self.root)
            .ok()
            .flatten()
            .map_or(library::DEFAULT_BEAT_SECS, |h| h.policy.settings.beat_secs);
        Duration::from_secs(u64::from(beat.max(1)))
    }

    /// How long a subscription may stay silent before it is taken for dead:
    /// two beats and some slack.
    fn silence(&self) -> Duration {
        2 * self.beat() + Duration::from_secs(10)
    }

    /// Follow the directories until the task is dropped. See the module
    /// docs.
    pub(crate) async fn run(self) {
        let mut backoff = Duration::from_secs(1);
        let mut last: Option<NodeId> = None;
        loop {
            if self.endpoint.is_closed() {
                return;
            }
            let mut dirs = directories_of(&self.ks, self.me()).unwrap_or_default();
            if let Some(i) = last.and_then(|l| dirs.iter().position(|d| *d == l)) {
                dirs.rotate_left(i);
            }
            let order = dirs.clone();
            let mut answered = false;
            for dir in dirs {
                match self.subscribe_once(dir, self.held_version()).await {
                    Ok(Ended::Closed) => {
                        answered = true;
                        last = Some(dir);
                        break;
                    }
                    Ok(Ended::PassOver(reason)) => {
                        tracing::info!(
                            directory = %dir.hex(),
                            "policy subscription: {reason}; trying the next directory"
                        );
                        // Not asked first again: the next round starts
                        // after it, and this one goes on at once.
                        last = next_after(&order, dir);
                    }
                    Err(e) => {
                        tracing::debug!(directory = %dir.hex(), "policy subscription: {e:#}");
                    }
                }
            }
            if answered {
                backoff = Duration::from_secs(1);
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(self.beat().min(MAX_BACKOFF));
        }
    }

    /// One subscription to `dir` from `have`, until it ends. `Err`: the
    /// directory never answered (unreachable, or closed at once).
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
        // A host presents no token: the directory admits it because the
        // policy names its key.
        let hello = SubRequest::Hello { id_token: None };
        let subscribe = SubRequest::Subscribe { have };
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
                return Ok(Ended::PassOver(format!("refused: {reason}")));
            }
            if !answered {
                tracing::info!(directory = %dir.hex(), have = have.0, "following the policy");
            }
            answered = true;
            if let Err(e) = self.take(dir, frame, now_unix()) {
                if e.downcast_ref::<Behind>().is_some() {
                    self.stats.behind.fetch_add(1, Ordering::Relaxed);
                }
                return Ok(Ended::PassOver(format!("{e:#}")));
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
            SubFrame::Fresh { .. } => s.beats.fetch_add(1, Ordering::Relaxed),
            SubFrame::Denied { .. } => s.denials.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// Take one frame at `now`: adopt the policy it brings if newer, and
    /// keep its `Fresh`. `Err`: it can't be taken ([`Behind`] when it is for
    /// a head older than the one held), and the follower passes the
    /// directory over.
    pub(crate) fn take(&self, dir: NodeId, frame: SubFrame, now: i64) -> Result<()> {
        let (fresh, policy) = match frame {
            SubFrame::Policy { policy, fresh } => (fresh, Some(policy)),
            SubFrame::Fresh { fresh } => (fresh, None),
            SubFrame::Denied { reason } => bail!("refused: {reason}"),
        };
        // Verified before anything is concluded from it (second review): a
        // whole policy's word against that policy's root-verified head; a
        // beat's, which may be for a head this host doesn't hold, by its
        // signature, and only as the word of the directory followed.
        if let Some(policy) = &policy {
            policy
                .head
                .verify(self.root)
                .context("the policy's head doesn't verify")?;
            fresh
                .verify(&policy.head)
                .context("the freshness doesn't vouch for the policy's head")?;
        } else {
            fresh
                .verify_signature()
                .context("the beat's signature doesn't verify")?;
            if fresh.directory != dir || fresh.fabric != self.root {
                bail!("a beat that isn't the followed directory's own");
            }
        }
        let held = self.held_version();
        if fresh.version < held {
            return Err(Behind {
                theirs: fresh.version,
                ours: held,
            }
            .into());
        }
        if let Some(policy) = policy {
            self.adopt(&policy, now)?;
        }
        self.vouch(&fresh, now)
    }

    /// Adopt `policy` if newer: through this host's own directory when it
    /// runs one, else into `policy.json`.
    fn adopt(&self, policy: &SignedPolicy, now: i64) -> Result<()> {
        let adopted = match &self.directory {
            Some(dir) => dir.accept(policy, now)?,
            None => store::adopt_if_newer(&self.ks, policy, self.root, now)?,
        };
        if adopted {
            tracing::info!(version = policy.version().0, "followed a newer policy");
            let me = self.me();
            if self.directory.is_none() && policy.head.head.directories.contains(&me) {
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

    /// Keep `fresh` if it vouches for the head held now.
    fn vouch(&self, fresh: &Fresh, now: i64) -> Result<()> {
        let Some(held) = store::read(&self.ks, self.root)? else {
            return Ok(());
        };
        if fresh.version != held.version() {
            return Ok(());
        }
        self.freshness.offer(fresh, &held.signed.head, now)?;
        Ok(())
    }
}

/// A directory is behind this host: what it sent is for an older head than
/// the one held, so it can't vouch for this host's (it missed a publish).
#[derive(Debug, thiserror::Error)]
#[error("the directory is behind this host (its policy version {}, ours {})", theirs.0, ours.0)]
pub(crate) struct Behind {
    /// The directory's version.
    theirs: StateVersion,
    /// This host's.
    ours: StateVersion,
}

/// The directory after `dir` in `order` (wrapping), where the next round
/// starts once `dir` was passed over.
fn next_after(order: &[NodeId], dir: NodeId) -> Option<NodeId> {
    let i = order.iter().position(|d| *d == dir)?;
    order.get((i + 1) % order.len()).copied()
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
            && let Err(e) = freshness.offer(&fresh, &held.signed.head, now_unix())
        {
            tracing::debug!("this directory's own freshness: {e:#}");
        }
        if changes.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_next_round_starts_after_the_directory_passed_over() {
        let n = |b: u8| library::NodeIdentity::from_seed([b; 32]).node_id();
        let order = [n(1), n(2), n(3)];
        assert_eq!(next_after(&order, n(1)), Some(n(2)));
        assert_eq!(next_after(&order, n(3)), Some(n(1)));
        assert_eq!(next_after(&order, n(9)), None);
    }
}

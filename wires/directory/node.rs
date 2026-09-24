//! The directory itself: its copy of the policy, its freshness, and the
//! answer to each request, without the network.
//!
//! [`Directory`] holds the newest signed policy (in `directory.redb`, with
//! the typed copy in memory), signs a [`Fresh`] for its head
//! ([`Directory::beat`]), takes a newer policy from anyone admitted
//! ([`Directory::accept`]: verified under the root, fresh, strictly newer,
//! items hashing to the head's root) and answers `wires/directory/1`
//! requests ([`Directory::answer`]). **It never decides a call.**
//!
//! Every change of head or freshness is published on a watch channel
//! ([`Directory::watch`]), which the subscriptions follow.

use std::sync::{Arc, RwLock};

use anyhow::{Context, Result, anyhow};
use library::{
    DirectoryAnswer, DirectoryRequest, Fresh, Membership, NodeId, NodeIdentity, SignedPolicy,
    StateVersion, check_admitted, check_inclusion,
};

use super::db::{DB_FILE, DirectoryDb};
use crate::admin::keystore::Keystore;
use crate::policy::store::{self, Held};

/// What a directory holds now: the newest verified policy and its `Fresh`
/// (none when this node can't sign one: the head doesn't list it).
#[derive(Clone, Debug)]
pub(crate) struct Current {
    /// The newest policy.
    pub(crate) held: Held,
    /// This directory's `Fresh` for it.
    pub(crate) fresh: Option<Fresh>,
}

/// What [`Directory::watch`] carries: the current state, or nothing yet.
pub(crate) type Snapshot = Option<Arc<Current>>;

/// A directory. See the module docs.
pub(crate) struct Directory {
    /// This node: its key signs `Fresh`.
    me: NodeIdentity,
    /// The fabric root everything verifies under.
    root: NodeId,
    /// Its keystore: `directory.redb`, and `policy.json`, which it keeps in
    /// step (so a host that is also the directory decides under what it
    /// serves).
    ks: Arc<Keystore>,
    /// The store.
    db: DirectoryDb,
    /// The newest policy and `Fresh`, and the channel subscribers follow.
    current: tokio::sync::watch::Sender<Snapshot>,
    /// Serializes accepts (the store has one writer).
    write: std::sync::Mutex<()>,
    /// The subscriber cap (local config).
    pub(crate) max_subscribers: usize,
    /// The subscribers following now.
    pub(crate) subscribers: Arc<tokio::sync::Semaphore>,
    /// Streams not yet admitted (bounded: any key can dial).
    pub(crate) undecided: Arc<tokio::sync::Semaphore>,
    /// For tests: count every accept.
    accepts: RwLock<u64>,
}

/// How many streams, on both ALPNs together, may be open before their
/// `hello` is checked. One more is closed unanswered.
pub(crate) const MAX_UNDECIDED: usize = 16;

/// The default subscriber cap.
pub(crate) const DEFAULT_MAX_SUBSCRIBERS: usize = 4096;

/// What a node not admitted hears on either ALPN, whatever the reason.
pub(crate) use crate::host::gate::NOT_ADMITTED;

/// What a request this directory doesn't serve yet hears.
const NOT_YET: &str = "this directory does not serve slices, views or resolve yet (cards 36c, 37); \
                       ask for `policy`";

impl std::fmt::Debug for Directory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Directory")
            .field("me", &self.me.node_id().hex())
            .finish_non_exhaustive()
    }
}

impl Directory {
    /// Open `me`'s directory in `ks` (its `directory.redb`) for `root`'s
    /// fabric: load the newest head, or seed the store from the keystore's
    /// own `policy.json` when that is newer (a node that joined by invite
    /// holds one), then sign a `Fresh` for it.
    pub(crate) fn open(
        me: NodeIdentity,
        root: NodeId,
        ks: Arc<Keystore>,
        max_subscribers: usize,
        now: i64,
    ) -> Result<Arc<Directory>> {
        let db = DirectoryDb::open(&ks.path(DB_FILE))?;
        if let Some(own) = store::read(&ks, root)?
            && own.version() > db.version()?
            && own.check_fresh(now).is_ok()
        {
            db.store(&own.signed)?;
        }
        let held = match db.current()? {
            Some(signed) => Some(
                Held::verify(signed, root).context("directory.redb holds a policy that fails")?,
            ),
            None => None,
        };
        let (current, _) =
            tokio::sync::watch::channel(held.map(|held| Arc::new(Current { held, fresh: None })));
        let dir = Arc::new(Directory {
            me,
            root,
            ks,
            db,
            current,
            write: std::sync::Mutex::new(()),
            max_subscribers,
            subscribers: Arc::new(tokio::sync::Semaphore::new(max_subscribers)),
            undecided: Arc::new(tokio::sync::Semaphore::new(MAX_UNDECIDED)),
            accepts: RwLock::new(0),
        });
        dir.beat(now)?;
        Ok(dir)
    }

    /// This directory's node id.
    pub(crate) fn id(&self) -> NodeId {
        self.me.node_id()
    }

    /// The fabric root.
    pub(crate) fn root(&self) -> NodeId {
        self.root
    }

    /// What it holds now.
    pub(crate) fn snapshot(&self) -> Snapshot {
        self.current.borrow().clone()
    }

    /// The version it holds (0: none).
    pub(crate) fn version(&self) -> StateVersion {
        self.snapshot()
            .map_or(StateVersion(0), |c| c.held.version())
    }

    /// Follow every change of head or freshness.
    pub(crate) fn watch(&self) -> tokio::sync::watch::Receiver<Snapshot> {
        self.current.subscribe()
    }

    /// How many publishes it has accepted since it opened (tests).
    #[cfg(test)]
    pub(crate) fn accepted(&self) -> u64 {
        *self.accepts.read().unwrap()
    }

    /// Sign a new `Fresh` for the held head, valid for the head's
    /// `settings.fresh_secs` from `now`, store it and announce it. A head
    /// that doesn't list this node gets none (traced): it holds the policy
    /// but vouches for nothing.
    pub(crate) fn beat(&self, now: i64) -> Result<()> {
        let Some(current) = self.snapshot() else {
            return Ok(());
        };
        let fresh = self.sign_fresh(&current.held, now);
        if let Some(f) = &fresh {
            self.db.set_fresh(f)?;
        }
        self.current.send_replace(Some(Arc::new(Current {
            held: current.held.clone(),
            fresh,
        })));
        Ok(())
    }

    /// A `Fresh` for `held`'s head from `now`, or `None` (traced) when the
    /// head doesn't list this node.
    fn sign_fresh(&self, held: &Held, now: i64) -> Option<Fresh> {
        let secs = i64::from(held.policy.settings.fresh_secs);
        match Fresh::sign(&self.me, &held.signed.head, now, now.saturating_add(secs)) {
            Ok(f) => Some(f),
            Err(e) => {
                tracing::warn!(
                    version = held.version().0,
                    "this node signs no freshness for the policy it holds: {e}"
                );
                None
            }
        }
    }

    /// Take `candidate` if it verifies under the root (head, items hashing
    /// to its root, validation), is fresh at `now`, and is strictly newer
    /// than the held head: store it, mirror it into `policy.json`, sign a
    /// `Fresh` for it and announce it. `Ok(false)`: not newer (nothing
    /// changes). `Err`: refused, and why.
    pub(crate) fn accept(&self, candidate: &SignedPolicy, now: i64) -> Result<bool> {
        let held = Held::verify(candidate.clone(), self.root)?;
        held.check_fresh(now)
            .context("the published policy has expired")?;
        let _one_writer = self.write.lock().map_err(|_| anyhow!("a poisoned lock"))?;
        if !self.db.store(candidate)? {
            return Ok(false);
        }
        *self.accepts.write().unwrap() += 1;
        if let Err(e) = store::adopt_if_newer(&self.ks, candidate, self.root, now) {
            tracing::warn!("could not keep policy.json in step with the directory: {e:#}");
        }
        let fresh = self.sign_fresh(&held, now);
        if let Some(f) = &fresh {
            self.db.set_fresh(f)?;
        }
        tracing::info!(version = held.version().0, "directory: took a newer policy");
        self.current
            .send_replace(Some(Arc::new(Current { held, fresh })));
        Ok(true)
    }

    /// Whether `caller`, presenting `badge`, is admitted: the badge verifies
    /// under the root and names it, and the held policy (if any) doesn't ban
    /// it. `Err` is the detail, for this node's trace only.
    pub(crate) fn admit(&self, caller: NodeId, badge: &Membership, now: i64) -> Result<(), String> {
        let result = match self.snapshot() {
            Some(c) => check_admitted(badge, self.root, &c.held.policy, caller, now),
            None => check_inclusion(badge, self.root, caller, now),
        };
        result.map_err(|e| format!("{}… is not admitted: {e}", caller.short()))
    }

    /// The answer to one request from an admitted `caller`.
    pub(crate) fn answer(
        &self,
        caller: NodeId,
        request: DirectoryRequest,
        now: i64,
    ) -> DirectoryAnswer {
        let denied = |reason: String| DirectoryAnswer::Denied {
            reason: crate::host::transport::truncate_reason(reason),
        };
        match request {
            DirectoryRequest::Publish { head, items } => {
                let candidate = SignedPolicy { head, items };
                match self.accept(&candidate, now) {
                    Ok(_) => DirectoryAnswer::Published {
                        version: self.version(),
                    },
                    Err(e) => {
                        tracing::info!(peer = %caller.hex(), "publish refused: {e:#}");
                        denied(format!("the published policy was refused: {e:#}"))
                    }
                }
            }
            DirectoryRequest::Head {} => match self.current_with_fresh() {
                Ok((c, fresh)) => DirectoryAnswer::Head {
                    head: c.held.signed.head.clone(),
                    fresh,
                },
                Err(reason) => denied(reason),
            },
            // Temporary (card 36b): the whole policy, for the hosts and
            // callers that still hold all of it.
            DirectoryRequest::Policy { have } => match self.current_with_fresh() {
                Ok((c, fresh)) if have >= c.held.version() => DirectoryAnswer::Current { fresh },
                Ok((c, fresh)) => DirectoryAnswer::Policy {
                    policy: c.held.signed.clone(),
                    fresh,
                },
                Err(reason) => denied(reason),
            },
            DirectoryRequest::Slice { .. }
            | DirectoryRequest::View { .. }
            | DirectoryRequest::Resolve { .. } => denied(NOT_YET.into()),
            DirectoryRequest::Hello { .. } => denied("a second hello".into()),
        }
    }

    /// The held policy and its `Fresh`, or why there is none to serve.
    fn current_with_fresh(&self) -> Result<(Arc<Current>, Fresh), String> {
        let c = self
            .snapshot()
            .ok_or_else(|| "this directory holds no policy yet".to_string())?;
        let fresh = c.fresh.clone().ok_or_else(|| {
            format!(
                "this node is not a directory of the policy it holds (version {})",
                c.held.version().0
            )
        })?;
        Ok((c, fresh))
    }
}

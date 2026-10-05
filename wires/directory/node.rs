//! The directory itself: its copy of the policy, its freshness, and the
//! answer to each request, without the network.
//!
//! [`Directory`] holds the newest signed policy (the node's own
//! `policy.json`, and nothing else: no history, card 45; the typed copy in
//! memory), signs a [`Fresh`] for its head
//! ([`Directory::beat`]), takes a newer policy from any publisher
//! ([`Directory::check_head`] then [`Directory::accept`]: verified under the
//! root, fresh, strictly newer, items matching the head's `items_hash`) and
//! answers `wires/directory/2` requests ([`Directory::answer`]). **It never
//! decides a call.** It may start empty, holding no policy, and take the
//! admin's first publish.
//!
//! Who is asking is decided at the `hello` ([`Directory::admit`]): a node
//! the held policy names as a host or directory ([`Peer::named`], by its
//! key), and a caller whose ID token verifies and whom the policy admits
//! ([`Peer::principal`]: [`library::check_admitted`], a verified email, no
//! ban, a role that matches) are admitted; anyone else may only publish,
//! and hears [`NOT_ADMITTED`] for anything more. The directory verifies the
//! token itself, as a host does (the policy's signed `issuer` items, the
//! IdP's keys held in memory, the nonce bound to the iroh-authenticated
//! key), and cuts the caller's **view** (card 37) from the policy it holds
//! ([`SignedPolicy::view_for`]): the root-signed entries its principal may
//! call. Nothing per user is stored, and a request is traced, not logged: a
//! view grants nothing (the host decides every call).
//!
//! Before a caller presents its token it reads the directory's
//! [`proof`](Directory::proof): its head and the current `Fresh`es it holds
//! (its own, and on a node that is also a host, the host's), as a host shows
//! one (card 49). Only hosts and directories subscribe
//! ([`Directory::subscribers`]); callers ask.
//!
//! Every change of head or freshness is published on a watch channel
//! ([`Directory::watch`]), which the subscriptions follow.

use std::sync::{Arc, OnceLock, RwLock};

use anyhow::{Context, Result, anyhow};
use library::{
    DirectoryAnswer, DirectoryRequest, Fresh, FreshSet, HostProof, IdToken, IdentityClaim, Item,
    NodeId, NodeIdentity, Policy, Principal, SignedPolicy, SignedPolicyHead, StateVersion,
};

use crate::admin::keystore::Keystore;
use crate::caller::jwks::KeyFetcher;
use crate::host::freshness::Freshness;
use crate::host::identity::IdpTrust;
use crate::policy::store::{self, Held};

/// What a directory holds now: the newest verified policy and its `Fresh`
/// (none when this node can't sign one: the head doesn't list it).
#[derive(Clone, Debug)]
pub(crate) struct Current {
    /// The newest policy.
    pub(crate) held: Held,
    /// This directory's `Fresh` for it.
    pub(crate) fresh: Option<Fresh>,
    /// The whole-policy subscription frame, encoded once and shared by
    /// every subscriber ([`Current::frame`]).
    policy_frame: OnceLock<Arc<Vec<u8>>>,
    /// The beat frame, likewise.
    fresh_frame: OnceLock<Arc<Vec<u8>>>,
}

impl Current {
    /// What a directory holds: `held`, vouched for by `fresh`.
    pub(crate) fn new(held: Held, fresh: Option<Fresh>) -> Current {
        Current {
            held,
            fresh,
            policy_frame: OnceLock::new(),
            fresh_frame: OnceLock::new(),
        }
    }

    /// The encoded subscription frame: the whole `policy` (`whole`) or the
    /// `fresh` beat, each encoded once for every subscriber. `None` when it
    /// holds no `Fresh` (the head doesn't list this node).
    pub(crate) fn frame(&self, whole: bool) -> Result<Option<Arc<Vec<u8>>>> {
        let Some(fresh) = self.fresh.clone() else {
            return Ok(None);
        };
        let (cell, frame) = if whole {
            (
                &self.policy_frame,
                library::SubFrame::Policy {
                    policy: self.held.signed.clone(),
                    fresh,
                },
            )
        } else {
            (&self.fresh_frame, library::SubFrame::Fresh { fresh })
        };
        if let Some(bytes) = cell.get() {
            return Ok(Some(Arc::clone(bytes)));
        }
        let bytes = Arc::new(frame.encode()?);
        Ok(Some(Arc::clone(cell.get_or_init(|| bytes))))
    }
}

/// What [`Directory::watch`] carries: what it holds now, or nothing yet.
pub(crate) type Snapshot = Option<Arc<Current>>;

/// A directory. See the module docs.
pub(crate) struct Directory {
    /// This node: its key signs `Fresh`.
    me: NodeIdentity,
    /// The network's root key, which everything verifies under.
    root: NodeId,
    /// Its keystore: `policy.json` is its store (so a host that is also the
    /// directory decides under what it serves).
    ks: Arc<Keystore>,
    /// On a node that is also a host, the `Fresh`es that host holds (another
    /// directory's among them): shown beside its own in its proof.
    pub(crate) host_freshness: OnceLock<Arc<Freshness>>,
    /// The newest policy and `Fresh`, and the channel subscribers follow.
    current: tokio::sync::watch::Sender<Snapshot>,
    /// Serializes accepts and beats (the store has one writer, and the
    /// head announced is always the newest held).
    write: std::sync::Mutex<()>,
    /// The subscriber cap (local config).
    pub(crate) max_subscribers: usize,
    /// The subscribers following now: hosts and directories the policy
    /// names. Callers never take one.
    pub(crate) subscribers: Arc<tokio::sync::Semaphore>,
    /// Connections not yet admitted (bounded: any key can dial). A permit
    /// is held from the connection until its `hello` is decided, never
    /// longer.
    pub(crate) undecided: Arc<tokio::sync::Semaphore>,
    /// Admitted work not yet answered or subscribed: a one-shot request
    /// being read and answered (a view may wait on an IdP's keys), or a
    /// `subscribe` being read.
    pub(crate) admitted: Arc<tokio::sync::Semaphore>,
    /// How long a new connection may take to open its stream, and a `hello`
    /// to arrive ([`wire::FRAME_TIMEOUT`](super::wire::FRAME_TIMEOUT);
    /// shorter in tests).
    pub(crate) stream_deadline: std::time::Duration,
    /// For tests: count every accept.
    accepts: RwLock<u64>,
    /// Verifies callers' ID tokens (the IdPs' keys, in memory only).
    fetcher: KeyFetcher,
    /// For tests: run once by the next [`beat`](Directory::beat), after it
    /// signs and before it announces.
    #[cfg(test)]
    pub(crate) beat_hook: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

/// How many connections, on both ALPNs together, may be undecided (from the
/// connection until its `hello` is decided, at most
/// [`stream_deadline`](Directory::stream_deadline) to open a stream and as
/// long again for the `hello`). One more is closed unanswered.
pub(crate) const MAX_UNDECIDED: usize = 16;

/// How many admitted requests (and `subscribe`s being read) a directory
/// works on at once, apart from the undecided ones. One more hears
/// [`BUSY`].
pub(crate) const MAX_ADMITTED: usize = 64;

/// What an admitted node hears when [`MAX_ADMITTED`] are in hand.
pub(crate) const BUSY: &str = "this directory is busy; try again or ask another";

/// The default subscriber cap: the hosts and directories following the
/// policy here at once.
pub(crate) const DEFAULT_MAX_SUBSCRIBERS: usize = 4096;

/// What a node not admitted hears on either ALPN, whatever the reason.
pub(crate) use crate::host::gate::NOT_ADMITTED;

/// What a directory holding no policy answers every request but a publish.
pub(crate) const EMPTY: &str = "this directory holds no policy yet: it is waiting for the \
                                admin's first publish (`wires policy push`)";

/// Who a directory peer is, as its `hello` decided ([`Directory::admit`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Peer {
    /// The iroh-authenticated key.
    pub(crate) node: NodeId,
    /// The held policy names it as a host or a directory (and doesn't ban
    /// it): it may hold the whole policy.
    pub(crate) named: bool,
    /// Who its ID token verified as, under the held policy's issuers, when
    /// the held policy admits that person ([`library::check_admitted`]);
    /// `None` otherwise.
    pub(crate) principal: Option<Principal>,
}

impl Peer {
    /// Whether it may ask more than a publish: named, or an admitted
    /// caller.
    pub(crate) fn admitted(&self) -> bool {
        self.named || self.principal.is_some()
    }
}

/// What [`Directory::check_head`] makes of a publish's head.
#[derive(Debug)]
pub(crate) enum HeadCheck {
    /// Root-signed, fresh and newer than the held head: read its items.
    Wanted,
    /// Not newer: what the directory holds (its version and head hash),
    /// which is the answer.
    Held {
        /// The held version.
        version: StateVersion,
        /// The held head's hash.
        head: library::HeadHash,
    },
    /// Refused, and why.
    Refused(String),
}

/// What a node that is neither a host nor a directory hears when it asks
/// for (or subscribes to) the whole policy (card 37).
pub(crate) const VIEW_NOT_POLICY: &str = "the whole policy is for the network's hosts and \
                                          directories; a caller asks for its view";

impl std::fmt::Debug for Directory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Directory")
            .field("me", &self.me.node_id().hex())
            .finish_non_exhaustive()
    }
}

impl Directory {
    /// Open `me`'s directory in `ks` for `root`'s network: read the
    /// keystore's `policy.json` (its store, card 45) and sign a `Fresh` for
    /// it. Holding none, it opens empty, and takes the admin's first
    /// publish.
    pub(crate) fn open(
        me: NodeIdentity,
        root: NodeId,
        ks: Arc<Keystore>,
        max_subscribers: usize,
        now: i64,
    ) -> Result<Arc<Directory>> {
        let held = store::read(&ks, root).context("reading this directory's policy")?;
        let (current, _) =
            tokio::sync::watch::channel(held.map(|held| Arc::new(Current::new(held, None))));
        let dir = Arc::new(Directory {
            me,
            root,
            ks,
            host_freshness: OnceLock::new(),
            current,
            write: std::sync::Mutex::new(()),
            max_subscribers,
            subscribers: Arc::new(tokio::sync::Semaphore::new(max_subscribers)),
            undecided: Arc::new(tokio::sync::Semaphore::new(MAX_UNDECIDED)),
            admitted: Arc::new(tokio::sync::Semaphore::new(MAX_ADMITTED)),
            stream_deadline: super::wire::FRAME_TIMEOUT,
            accepts: RwLock::new(0),
            fetcher: KeyFetcher::new(None)?,
            #[cfg(test)]
            beat_hook: std::sync::Mutex::new(None),
        });
        dir.beat(now)?;
        Ok(dir)
    }

    /// This directory's node id.
    pub(crate) fn id(&self) -> NodeId {
        self.me.node_id()
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
    /// but vouches for nothing. It holds the writer lock [`accept`](Self::accept)
    /// holds, and reads the head under it, so it never announces (or stores
    /// a `Fresh` for) a head older than one accepted meanwhile.
    pub(crate) fn beat(&self, now: i64) -> Result<()> {
        let _one_writer = self.write.lock().map_err(|_| anyhow!("a poisoned lock"))?;
        let Some(current) = self.snapshot() else {
            return Ok(());
        };
        let fresh = self.sign_fresh(&current.held, now);
        #[cfg(test)]
        if let Some(hook) = self.beat_hook.lock().unwrap().take() {
            hook();
        }
        self.current
            .send_replace(Some(Arc::new(Current::new(current.held.clone(), fresh))));
        Ok(())
    }

    /// A `Fresh` for `held`'s head from `now`, or `None` (traced) when the
    /// head doesn't list this node or has expired (an expired policy is
    /// served by no directory).
    fn sign_fresh(&self, held: &Held, now: i64) -> Option<Fresh> {
        if let Err(e) = held.check_fresh(now) {
            tracing::warn!(
                version = held.version().0,
                "this directory vouches for nothing: the policy it holds {e}; publish a newer one"
            );
            return None;
        }
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
    /// than the held head: adopt it into `policy.json` (the store), sign a
    /// `Fresh` for it and announce it. `Ok(false)`: not newer (nothing
    /// changes). `Err`: refused, and why. A publish brings it, or, on a
    /// node that is also a host, that host's following of another
    /// directory ([`crate::host::follow`]).
    pub(crate) fn accept(&self, candidate: &SignedPolicy, now: i64) -> Result<bool> {
        let held = Held::verify(candidate.clone(), self.root)?;
        held.check_fresh(now)
            .context("the published policy has expired")?;
        let _one_writer = self.write.lock().map_err(|_| anyhow!("a poisoned lock"))?;
        if held.version() <= self.version() {
            return Ok(false);
        }
        // `policy.json` may hold it already, or a newer one; what it holds
        // after this is what the directory serves.
        store::adopt_if_newer(&self.ks, candidate, self.root, now)?;
        let Some(held) = store::read(&self.ks, self.root)?.filter(|h| h.version() > self.version())
        else {
            return Ok(false);
        };
        *self.accepts.write().unwrap() += 1;
        let fresh = self.sign_fresh(&held, now);
        tracing::info!(version = held.version().0, "directory: took a newer policy");
        self.current
            .send_replace(Some(Arc::new(Current::new(held, fresh))));
        Ok(true)
    }

    /// Who `caller` is, from its `hello`'s `id_token` (see [`Peer`]): named
    /// when the held policy names it as a host or directory (by its key), an
    /// admitted caller when the token verifies under the held policy and
    /// [`library::check_admitted`] passes (the reason it doesn't is traced).
    /// Holding no policy, it admits nobody (anyone may still publish).
    pub(crate) async fn admit(&self, caller: NodeId, id_token: Option<&IdToken>, now: i64) -> Peer {
        // An expired policy admits nobody.
        let held = self.snapshot().filter(|c| c.held.check_fresh(now).is_ok());
        let named = self.holds_whole(caller);
        let principal = match (held, id_token) {
            (Some(c), Some(token)) => self
                .principal(caller, token, &c.held.policy, now)
                .await
                .filter(
                    |p| match library::check_admitted(&c.held.policy, caller, p) {
                        Ok(()) => true,
                        Err(e) => {
                            tracing::debug!(
                                peer = %caller.hex(),
                                who = %p.name(),
                                "directory: not admitted: {e}"
                            );
                            false
                        }
                    },
                ),
            _ => None,
        };
        Peer {
            node: caller,
            named,
            principal,
        }
    }

    /// The first half of a publish: whether `head` is one to read the items
    /// of. Root-signed and fresh, and newer than the held head:
    /// [`HeadCheck::Wanted`]. Root-signed but not newer: the held version
    /// and head hash, read no further ([`HeadCheck::Held`]). Anything else is
    /// refused. Nobody but the root can make a directory read a publish's
    /// items.
    pub(crate) fn check_head(&self, head: &SignedPolicyHead, now: i64) -> HeadCheck {
        if let Err(e) = head.verify(self.root) {
            return HeadCheck::Refused(format!("the published head does not verify: {e}"));
        }
        if let Err(e) = head.check_fresh(now) {
            return HeadCheck::Refused(format!("the published policy has expired: {e}"));
        }
        match self.snapshot() {
            Some(c) if head.head.version <= c.held.version() => match c.held.signed.head.hash() {
                Ok(hash) => HeadCheck::Held {
                    version: c.held.version(),
                    head: hash,
                },
                Err(e) => HeadCheck::Refused(format!("hashing the held head: {e}")),
            },
            _ => HeadCheck::Wanted,
        }
    }

    /// The second half of a publish from `peer`: `head` with `items`,
    /// [`accept`](Self::accept)ed, answered with the version and head hash
    /// the directory then holds.
    pub(crate) fn publish(
        &self,
        peer: NodeId,
        head: SignedPolicyHead,
        items: Vec<Item>,
        now: i64,
    ) -> DirectoryAnswer {
        let candidate = SignedPolicy { head, items };
        if let Err(e) = self.accept(&candidate, now) {
            tracing::info!(peer = %peer.hex(), "publish refused: {e:#}");
            return DirectoryAnswer::Denied {
                reason: crate::host::transport::truncate_reason(format!(
                    "the published policy was refused: {e:#}"
                )),
            };
        }
        match self.snapshot() {
            Some(c) => match c.held.signed.head.hash() {
                Ok(head) => DirectoryAnswer::Published {
                    version: c.held.version(),
                    head,
                },
                Err(e) => DirectoryAnswer::Denied {
                    reason: format!("hashing the held head: {e}"),
                },
            },
            None => DirectoryAnswer::Denied {
                reason: EMPTY.into(),
            },
        }
    }

    /// What this directory shows a dialer before it presents a token
    /// (card 45): its head and every current `Fresh` it holds for it, its
    /// own and, on a node that is also a host, the ones that host holds (at
    /// most [`library::MAX_FRESH_SET`]); the caller checks it as it does a
    /// host's ([`HostProof::check`]). `Err`: why there is none to show (it
    /// holds no policy, an expired one, or one that doesn't list it).
    pub(crate) fn proof(&self, now: i64) -> Result<HostProof, String> {
        let (c, own) = self.current_with_fresh(now)?;
        let head = &c.held.signed.head;
        let mut set = FreshSet::default();
        set.insert(own, now);
        if let Some(host) = self.host_freshness.get() {
            for f in host.proof(head, self.id(), now).fresh {
                set.insert(f, now);
            }
        }
        Ok(HostProof {
            head: head.clone(),
            fresh: set.current_for(head, now),
        })
    }

    /// The answer to one request (not a publish: see
    /// [`check_head`](Self::check_head)) from `peer`, which
    /// [`admit`](Self::admit) admitted:
    ///
    /// - `policy {have}`, for a named node only (card 37: a caller holds
    ///   its view): `current {fresh}` when `have` is the newest, else the
    ///   whole policy;
    /// - `view {query}`: the caller's whole view, or the entries matching
    ///   `query`;
    /// - `resolve {service}`: a view holding just that service, or no entry.
    ///
    /// Every view is cut for `peer`'s node and admitted principal (a named
    /// node with none gets the empty one). Traced, not logged (see the
    /// module docs).
    pub(crate) fn answer(
        &self,
        peer: &Peer,
        request: DirectoryRequest,
        now: i64,
    ) -> DirectoryAnswer {
        let denied = |reason: String| DirectoryAnswer::Denied {
            reason: crate::host::transport::truncate_reason(reason),
        };
        if !peer.admitted() {
            return denied(NOT_ADMITTED.into());
        }
        let (c, fresh) = match self.current_with_fresh(now) {
            Ok(held) => held,
            Err(reason) => return denied(reason),
        };
        let principal = peer.principal.as_ref();
        let answer = match request {
            DirectoryRequest::Policy { .. } if !peer.named => {
                return denied(VIEW_NOT_POLICY.into());
            }
            DirectoryRequest::Policy { have } if have >= c.held.version() => {
                return DirectoryAnswer::Current { fresh };
            }
            DirectoryRequest::Policy { .. } => {
                return DirectoryAnswer::Policy {
                    policy: c.held.signed.clone(),
                    fresh,
                };
            }
            DirectoryRequest::View { query } => DirectoryAnswer::View {
                view: c
                    .held
                    .signed
                    .view_for(peer.node, principal, query.as_deref()),
                fresh,
            },
            DirectoryRequest::Resolve { service } => {
                let mut view = c.held.signed.view_for(peer.node, principal, None);
                view.entries.retain(|e| e.name == service);
                DirectoryAnswer::View { view, fresh }
            }
            DirectoryRequest::Hello { .. } | DirectoryRequest::Open {} => {
                return denied("a second hello".into());
            }
            DirectoryRequest::Publish { .. } | DirectoryRequest::Items { .. } => {
                return denied("a publish is a head and then its items".into());
            }
        };
        let entries = match &answer {
            DirectoryAnswer::View { view, .. } => view.entries.len(),
            _ => 0,
        };
        tracing::debug!(
            peer = %peer.node.hex(),
            who = principal.map(Principal::name).as_deref().unwrap_or("-"),
            entries,
            version = c.held.version().0,
            "directory: answered a view"
        );
        answer
    }

    /// Whether `node` may hold the whole policy (card 37): a host of one of
    /// its services, or one of its directories, in the policy held now (a
    /// banned node is neither). A caller holds its view instead.
    pub(crate) fn holds_whole(&self, node: NodeId) -> bool {
        self.snapshot().is_some_and(|c| {
            !c.held.policy.bans_node(node)
                && (c.held.policy.is_host(node) || c.held.directories().contains(&node))
        })
    }

    /// Who `caller` is: its `id_token` verified under `policy`'s trusted
    /// issuers (each with its accepted audiences) and bound to `caller`'s
    /// key, unexpired, or `None` (one that doesn't verify, traced).
    async fn principal(
        &self,
        caller: NodeId,
        id_token: &IdToken,
        policy: &Policy,
        now: i64,
    ) -> Option<Principal> {
        let trust = IdpTrust::per_issuer(
            policy
                .issuers
                .iter()
                .map(|(iss, config)| (iss.clone(), config.audiences.clone()))
                .collect(),
        );
        let claim = IdentityClaim {
            node: caller,
            id_token: id_token.clone(),
        };
        match self
            .fetcher
            .verify(
                &claim,
                &trust.issuers(),
                trust.audiences_for_claim(&claim),
                now,
            )
            .await
        {
            Ok(p) => Some(p),
            Err(e) => {
                tracing::debug!(peer = %caller.hex(), "directory: an ID token did not verify: {e}");
                None
            }
        }
    }

    /// The held policy and its `Fresh`, or why there is none to serve (an
    /// expired policy is served to nobody).
    fn current_with_fresh(&self, now: i64) -> Result<(Arc<Current>, Fresh), String> {
        let c = self.snapshot().ok_or_else(|| EMPTY.to_string())?;
        if c.held.check_fresh(now).is_err() {
            return Err(format!(
                "this directory holds only an expired policy (version {}); try again later",
                c.held.version().0
            ));
        }
        let fresh = c.fresh.clone().ok_or_else(|| {
            format!(
                "this node is not a directory of the policy it holds (version {})",
                c.held.version().0
            )
        })?;
        Ok((c, fresh))
    }
}

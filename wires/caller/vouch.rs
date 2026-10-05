//! The caller's check of a host before it tells the host anything (card 49).
//!
//! Every session and inbox fetch opens with the host's
//! [`HostProof`]: its root-signed head and the current `Fresh`es it holds.
//! The caller presents its ID token and the call's arguments only once a
//! current `Fresh` from a directory **other than that host** vouches for the
//! head the host holds, and its view says the host serves what it wants
//! ([`Vouching::check`]). A host the admin removed has nothing to show
//! within `fresh_secs` of the edit reaching the directories, because an
//! honest directory signs only for its newest head; and a removed host that
//! is itself a directory can't vouch for its own old head. A head that lists
//! exactly one directory, the host itself, is the exception: a one-machine
//! network, where the host's own word is all there is.
//!
//! **The cached path costs no flight.** A caller that already holds such a
//! `Fresh` for its view's head (from its own refresh, or an earlier host's
//! or directory's proof: a `Fresh` vouches for a head, not for a host) sends `Hello` and `Invoke` at once ([`Vouching::ready`]), and still
//! checks the host's proof before it sends a byte of stdin. Whatever a
//! proof carries that vouches for the view is kept ([`Sink`]), so only the
//! first call in each `fresh_secs` window, to a host no `Fresh` held covers,
//! pays the extra flight.
//!
//! **Fail closed.** A proof that doesn't check out is a dial failure: the
//! next host is tried, and this one was sent nothing ([`Unvouched`]). With
//! every directory down, no host can show a current `Fresh`, and the call
//! fails saying so ([`all_unvouched`]).

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use library::{Fresh, FreshSet, HostProof, IdToken, NodeId, ServiceName, Standing, StateVersion};

use crate::admin::keystore::Keystore;
use crate::caller::view::{self, HeldView};

/// What the caller checks a host against: what it wants from the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    /// A call of this service: the view's entry for it must list the host.
    Service(ServiceName),
    /// An inbox fetch: the host must host some service in the view.
    AnyService,
}

/// A view being asked for again.
pub(crate) type Refreshing =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<HeldView>> + Send>>;

/// How the caller brings its view up to date when a host shows a newer
/// head: a way to ask the directories for it again (from a keystore's
/// view, [`Refresher::keystore`], or the gateway's for one web user).
#[derive(Clone)]
pub(crate) struct Refresher(pub(crate) Arc<dyn Fn() -> Refreshing + Send + Sync>);

impl Refresher {
    /// The view in `ks`, asked of the directories ([`view::refresh`]) over
    /// `endpoint` (any; it dials the directory ALPN) for `root`'s network,
    /// presenting `id_token`.
    pub(crate) fn keystore(
        ks: Keystore,
        endpoint: iroh::Endpoint,
        root: NodeId,
        id_token: Option<IdToken>,
    ) -> Refresher {
        Refresher(Arc::new(move || {
            let (ks, endpoint, id_token) = (ks.clone(), endpoint.clone(), id_token.clone());
            Box::pin(async move {
                let asker = view::Asker {
                    endpoint: &endpoint,
                    root,
                    id_token,
                };
                view::refresh(&ks, &asker, false).await
            })
        }))
    }
}

/// Where a `Fresh` a host's proof carried goes, so the next call speaks at
/// once.
#[derive(Clone)]
pub(crate) enum Sink {
    /// The view in this keystore (`view.json`).
    Keystore(Keystore),
    /// A set shared in memory (the gateway's, across its users: a `Fresh`
    /// vouches for a head, not for a person).
    Shared(Arc<Mutex<FreshSet>>),
    /// Nowhere.
    Nowhere,
}

/// A host could not show that its policy is current, so it was sent
/// nothing: a dial failure (the next host is tried).
#[derive(Debug, thiserror::Error)]
#[error("host {host} could not show a current policy ({why}); nothing was sent to it")]
pub(crate) struct Unvouched {
    /// The host, short.
    pub(crate) host: String,
    /// Why its proof didn't check out.
    pub(crate) why: String,
    /// Whether no directory had vouched for it (as opposed to, say, a head
    /// older than this caller's view).
    pub(crate) lapsed: bool,
}

/// The error when every host of a call failed its proof: no directory has
/// vouched for any of them recently, so nothing was sent anywhere (exit 1).
pub(crate) fn all_unvouched(what: &str, failures: &[String]) -> anyhow::Error {
    anyhow!(
        "no directory has vouched for {what} recently, so nothing was sent ({}); the network's \
         directories may be down or out of reach: try again later, or ask your admin",
        failures.join("; ")
    )
}

/// A caller's view, and what it checks each host's proof against. See the
/// module docs.
#[derive(Clone)]
pub(crate) struct Vouching {
    /// The network root everything verifies under.
    root: NodeId,
    /// The view dialed from (replaced when a refresh brings a newer one).
    held: HeldView,
    /// What the caller wants from the host.
    scope: Scope,
    /// How to refresh the view on a newer head; none: a newer head is a
    /// dial failure.
    refresher: Option<Refresher>,
    /// Where a `Fresh` learned from a host goes.
    sink: Sink,
    /// Directories this caller knows of besides its view's head's (the
    /// network string's): a head listing only the dialed host is taken as
    /// a one-machine network only when none of these is another node (an
    /// old one-directory head must not make a later network look like one;
    /// card 49 review).
    known: Vec<NodeId>,
}

impl Vouching {
    /// Check hosts against `held` (verified under `root`) for `scope`.
    pub(crate) fn new(root: NodeId, held: HeldView, scope: Scope) -> Self {
        Self {
            root,
            held,
            scope,
            refresher: None,
            sink: Sink::Nowhere,
            known: Vec::new(),
        }
    }

    /// Also know of `directories` (the network string's).
    pub(crate) fn knowing(mut self, directories: Vec<NodeId>) -> Self {
        self.known = directories;
        self
    }

    /// Whether `fresh`, which vouches by [`Fresh::vouches`]'s rule, may be
    /// taken: one the host signed itself only while no other directory is
    /// known (the head's one directory, and the network string's).
    fn takes(&self, fresh: &Fresh, host: NodeId) -> bool {
        fresh.directory != host || self.known.iter().all(|d| *d == host)
    }

    /// Refresh the view with `refresher` when a host shows a newer head.
    pub(crate) fn refreshing(mut self, refresher: Refresher) -> Self {
        self.refresher = Some(refresher);
        self
    }

    /// Keep what hosts show in `sink`; a [`Sink::Shared`] set also counts
    /// toward [`ready`](Self::ready) now.
    pub(crate) fn keeping_in(mut self, sink: Sink) -> Self {
        if let Sink::Shared(shared) = &sink {
            let now = crate::clock::now_unix();
            for f in shared.lock().unwrap_or_else(|e| e.into_inner()).iter() {
                self.held.fresh.insert(f.clone(), now);
            }
        }
        self.sink = sink;
        self
    }

    /// The head version of the view, for the `Hello`.
    pub(crate) fn version(&self) -> StateVersion {
        self.held.version()
    }

    /// Whether the view says `host` serves what the caller wants.
    pub(crate) fn serves(&self, host: NodeId) -> bool {
        match &self.scope {
            Scope::Service(name) => self
                .held
                .entry(name)
                .is_some_and(|e| e.service.hosts.contains(&host)),
            Scope::AnyService => self
                .held
                .view
                .entries
                .iter()
                .any(|e| e.service.hosts.contains(&host)),
        }
    }

    /// Whether the caller may speak to `host` at once (the cached path): a
    /// current `Fresh` it holds from a directory other than `host` vouches
    /// for its view's head, and the view says `host` serves.
    pub(crate) fn ready(&self, host: NodeId, now: i64) -> bool {
        self.serves(host)
            && self
                .held
                .fresh
                .vouching(&self.held.view.head, host, now)
                .is_some_and(|f| self.takes(f, host))
    }

    /// Check `host`'s `proof` at `now`. `before_speaking`: nothing was sent
    /// yet (a failure is then an [`Unvouched`] dial failure, and a newer
    /// head is refreshed to before deciding); else the caller spoke on a
    /// cached `Fresh`, which still counts beside the host's own (the host's
    /// may have lapsed a moment after the caller's was checked), and a
    /// failure stops the call before stdin: a head older than the view, or
    /// another head at its version. A newer root-signed head, once spoken,
    /// needs no directory's word (the host already has what the caller
    /// sent, and an honest host refuses what its newer policy no longer
    /// allows): it is the ack's to check, and is noted for a refresh after.
    pub(crate) async fn check(
        &mut self,
        host: NodeId,
        proof: &HostProof,
        now: i64,
        before_speaking: bool,
    ) -> Result<()> {
        if !before_speaking && proof.head.head.version > self.version() {
            proof
                .head
                .verify(self.root)
                .with_context(|| format!("host {}'s newer policy head", host.short()))?;
            self.note_newer(proof.head.head.version);
            return Ok(());
        }
        let unvouched = |e: library::Error| -> anyhow::Error {
            let lapsed = matches!(
                e,
                library::Error::Unvouched
                    | library::Error::FreshLapsed
                    | library::Error::SelfVouched
            );
            Unvouched {
                host: host.short(),
                why: e.to_string(),
                lapsed,
            }
            .into()
        };
        let combined;
        let proof = if before_speaking {
            proof
        } else {
            let mut fresh = proof.fresh.clone();
            fresh.extend(self.held.fresh.current_for(&proof.head, now));
            fresh.truncate(library::MAX_FRESH_SET);
            combined = HostProof {
                head: proof.head.clone(),
                fresh,
            };
            &combined
        };
        let standing = proof.check(self.root, &self.held.view.head, host, now);
        let standing = match (standing, before_speaking) {
            (Ok(s), _) => s,
            (Err(e), true) => return Err(unvouched(e)),
            (Err(e), false) => {
                return Err(anyhow!(e).context(format!(
                    "host {} could not show a current policy, so the call was stopped before \
                     any input was sent",
                    host.short()
                )));
            }
        };
        match standing {
            Standing::Same => {}
            Standing::Newer(v) if !before_speaking => {
                self.note_newer(v);
                return Ok(());
            }
            Standing::Newer(v) => {
                // Any failure here is a dial failure too: nothing was sent.
                let dial_failure = |why: String| -> anyhow::Error {
                    Unvouched {
                        host: host.short(),
                        why,
                        lapsed: false,
                    }
                    .into()
                };
                self.refresh_to(v)
                    .await
                    .map_err(|e| dial_failure(format!("{e:#}")))?;
                // The refresh must have reached the host's head: a lagging
                // directory, or a removed one answering `current` for the
                // old head it still vouches for, leaves the view where it
                // was, and the old view must not decide (card 49 review).
                if self.version() < v {
                    return Err(dial_failure(format!(
                        "it holds policy version {}, and no directory gave a view that new (got \
                         {})",
                        v.0,
                        self.version().0
                    )));
                }
                match proof.check(self.root, &self.held.view.head, host, now) {
                    Ok(Standing::Same) => {}
                    Ok(Standing::Newer(_)) => {
                        return Err(dial_failure("the refreshed view is still older".into()));
                    }
                    Err(e) => return Err(unvouched(e)),
                }
            }
        }
        if before_speaking
            && let Ok(f) = proof.vouching(host, now)
            && !self.takes(f, host)
        {
            return Err(Unvouched {
                host: host.short(),
                why: "it vouched for its own policy, which lists it as the one directory, but \
                      the network names others"
                    .into(),
                lapsed: true,
            }
            .into());
        }
        if before_speaking && !self.serves(host) {
            return Err(Unvouched {
                host: host.short(),
                why: format!(
                    "your view (policy version {}) no longer lists it here",
                    self.version().0
                ),
                lapsed: false,
            }
            .into());
        }
        if let Ok(f) = proof.vouching(host, now) {
            self.learn(f, now);
        }
        Ok(())
    }

    /// The view is behind the host's head `v`: bring it up to `v` from a
    /// directory (with a [`Refresher`]), else fail as a dial failure.
    async fn refresh_to(&mut self, v: StateVersion) -> Result<()> {
        self.note_newer(v);
        let Some(r) = &self.refresher else {
            bail!(
                "this host holds policy version {}, newer than your view's {}; try again shortly",
                v.0,
                self.version().0
            );
        };
        let refreshed = tokio::time::timeout(view::REFRESH_BUDGET, (r.0)())
            .await
            .map_err(|_| anyhow!("no directory answered within {:?}", view::REFRESH_BUDGET))
            .and_then(|r| r)
            .with_context(|| {
                format!("refreshing your view to the host's policy version {}", v.0)
            })?;
        self.held = refreshed;
        Ok(())
    }

    /// Keep `fresh` (it vouched for a proof that checked out): in memory,
    /// and in the sink.
    fn learn(&mut self, fresh: &Fresh, now: i64) {
        if fresh.verify(&self.held.view.head).is_ok() {
            self.held.fresh.insert(fresh.clone(), now);
        }
        match &self.sink {
            Sink::Keystore(ks) => view::note_fresh(ks, self.root, fresh),
            Sink::Shared(set) => {
                set.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(fresh.clone(), now);
            }
            Sink::Nowhere => {}
        }
    }

    /// A host showed head `v`: have the next command refresh first.
    fn note_newer(&self, v: StateVersion) {
        if let Sink::Keystore(ks) = &self.sink {
            view::note_seen(ks, self.root, v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{NodeIdentity, Policy, Service, SignedPolicy};

    fn root() -> NodeIdentity {
        NodeIdentity::from_seed([120; 32])
    }
    fn dir() -> NodeIdentity {
        NodeIdentity::from_seed([121; 32])
    }
    fn host() -> NodeIdentity {
        NodeIdentity::from_seed([122; 32])
    }
    fn orders() -> ServiceName {
        ServiceName::new("orders-db").unwrap()
    }

    /// A policy at `version` with `orders-db` on `hosts`, listing
    /// `directories`.
    fn signed(version: u64, hosts: &[NodeId], directories: &[NodeId]) -> SignedPolicy {
        let mut p = Policy::new(root().node_id());
        p.version = StateVersion(version);
        p.not_after = i64::MAX;
        p.directories = directories.to_vec();
        let (staff, matchers) = crate::testutil::staff_role();
        p.roles.insert(staff.clone(), matchers);
        p.services.insert(
            orders(),
            Service {
                description: String::new(),
                allow: vec![staff],
                hosts: hosts.to_vec(),
            },
        );
        crate::testutil::signed_policy(&root(), p)
    }

    /// A view holding every entry of `p` (whose it is doesn't matter here).
    fn held(p: &SignedPolicy, fresh: Option<Fresh>) -> HeldView {
        let view = library::View {
            head: p.head.clone(),
            entries: p.entries().cloned().collect(),
        };
        HeldView::fetched(view, fresh, 0)
    }

    fn proof(p: &SignedPolicy, by: &NodeIdentity, now: i64) -> HostProof {
        HostProof {
            head: p.head.clone(),
            fresh: vec![Fresh::sign(by, &p.head, now, now + 900).unwrap()],
        }
    }

    fn now() -> i64 {
        crate::clock::now_unix()
    }

    /// The cached path: a `Fresh` from another directory for the view's
    /// head, and a view that lists the host. Without one, the caller waits
    /// for the proof.
    #[test]
    fn a_caller_speaks_at_once_only_on_another_directorys_current_word() {
        let both = [dir().node_id(), host().node_id()];
        let p = signed(3, &[host().node_id()], &both);
        let t = now();
        let by_dir = Fresh::sign(&dir(), &p.head, t, t + 900).unwrap();
        let by_host = Fresh::sign(&host(), &p.head, t, t + 900).unwrap();
        let scope = Scope::Service(orders());
        let v = |f| Vouching::new(root().node_id(), held(&p, f), scope.clone());
        assert!(v(Some(by_dir.clone())).ready(host().node_id(), t));
        assert!(!v(Some(by_dir.clone())).ready(host().node_id(), t + 901));
        assert!(!v(Some(by_host)).ready(host().node_id(), t), "its own word");
        assert!(!v(None).ready(host().node_id(), t));
        // A host the view doesn't list for the service: never at once.
        let other = NodeIdentity::from_seed([123; 32]).node_id();
        assert!(!v(Some(by_dir)).ready(other, t));
    }

    /// The attack: the admin dropped the host from the service (v4), the
    /// caller's view is still v3, and the host still holds v3. Its own
    /// `Fresh` (it is also a directory) doesn't do; no other directory signs
    /// for v3 any more, so it can't show one: a dial failure, nothing sent.
    #[tokio::test]
    async fn a_removed_host_with_the_old_head_is_sent_nothing() {
        let both = [dir().node_id(), host().node_id()];
        let v3 = signed(3, &[host().node_id()], &both);
        let t = now();
        let mut v = Vouching::new(root().node_id(), held(&v3, None), Scope::Service(orders()));
        for shown in [proof(&v3, &host(), t), proof(&v3, &dir(), t - 1_000)] {
            let e = v
                .check(host().node_id(), &shown, t, true)
                .await
                .unwrap_err();
            let u = e.downcast_ref::<Unvouched>().expect("a dial failure");
            assert!(u.lapsed, "{u}");
        }
        // The control: another directory's current word, for that head.
        v.check(host().node_id(), &proof(&v3, &dir(), t), t, true)
            .await
            .unwrap();
    }

    /// A one-machine network: the host is the only directory, and its own
    /// word is enough.
    #[tokio::test]
    async fn a_one_machine_network_takes_the_hosts_word() {
        let p = signed(3, &[host().node_id()], &[host().node_id()]);
        let t = now();
        let mut v = Vouching::new(root().node_id(), held(&p, None), Scope::Service(orders()));
        v.check(host().node_id(), &proof(&p, &host(), t), t, true)
            .await
            .unwrap();
        assert!(
            v.ready(host().node_id(), t),
            "and it is kept for the next call"
        );
    }

    /// A newer head, vouched for: with no way to refresh, a dial failure;
    /// on the cached path, noted and left to the ack.
    #[tokio::test]
    async fn a_newer_head_needs_a_refresh_first() {
        let ds = [dir().node_id()];
        let v3 = signed(3, &[host().node_id()], &ds);
        let v4 = signed(4, &[host().node_id()], &ds);
        let t = now();
        let mut v = Vouching::new(root().node_id(), held(&v3, None), Scope::Service(orders()));
        let e = v
            .check(host().node_id(), &proof(&v4, &dir(), t), t, true)
            .await
            .unwrap_err();
        assert!(
            e.downcast_ref::<Unvouched>().is_some(),
            "a dial failure: {e:#}"
        );
        assert!(format!("{e:#}").contains("newer than your view"), "{e:#}");
        v.check(host().node_id(), &proof(&v4, &dir(), t), t, false)
            .await
            .unwrap();
        // Once spoken, a newer root-signed head needs no directory's word:
        // the ack decides (an honest host refuses what it no longer allows).
        let bare = HostProof {
            head: v4.head.clone(),
            fresh: vec![],
        };
        v.check(host().node_id(), &bare, t, false).await.unwrap();
        let rogue = NodeIdentity::from_seed([125; 32]);
        let mut forged = Policy::new(rogue.node_id());
        forged.version = StateVersion(9);
        forged.not_after = i64::MAX;
        let forged = HostProof {
            head: forged.sign(&rogue).unwrap().head,
            fresh: vec![],
        };
        assert!(
            v.check(host().node_id(), &forged, t, false).await.is_err(),
            "but it must be the root's"
        );
        // An older head than the view, after speaking: the call stops.
        let mut v = Vouching::new(root().node_id(), held(&v4, None), Scope::Service(orders()));
        assert!(
            v.check(host().node_id(), &proof(&v3, &dir(), t), t, false)
                .await
                .is_err()
        );
    }

    /// Card 49 review, finding 4: a view from the one-machine days (its head
    /// lists only X) doesn't make X's own word enough once the network
    /// string names another directory: X is sent nothing.
    #[tokio::test]
    async fn an_old_one_directory_head_is_not_a_one_machine_network() {
        let p = signed(3, &[host().node_id()], &[host().node_id()]);
        let t = now();
        let own = proof(&p, &host(), t);
        let held_own = held(&p, Some(own.fresh[0].clone()));
        let later = vec![host().node_id(), dir().node_id()];
        let mut v = Vouching::new(root().node_id(), held_own.clone(), Scope::Service(orders()))
            .knowing(later.clone());
        assert!(!v.ready(host().node_id(), t), "not at once");
        let e = v.check(host().node_id(), &own, t, true).await.unwrap_err();
        assert!(e.downcast_ref::<Unvouched>().is_some(), "{e:#}");
        // With no other directory known, it is the one-machine network.
        let mut v = Vouching::new(root().node_id(), held_own, Scope::Service(orders()))
            .knowing(vec![host().node_id()]);
        assert!(v.ready(host().node_id(), t));
        v.check(host().node_id(), &own, t, true).await.unwrap();
    }

    /// An inbox fetch asks any host of a service in the view; a host the
    /// view doesn't name is refused even with a good proof.
    #[tokio::test]
    async fn an_inbox_fetch_needs_a_host_of_some_service() {
        let p = signed(3, &[host().node_id()], &[dir().node_id()]);
        let t = now();
        let mut v = Vouching::new(root().node_id(), held(&p, None), Scope::AnyService);
        v.check(host().node_id(), &proof(&p, &dir(), t), t, true)
            .await
            .unwrap();
        let stranger = NodeIdentity::from_seed([124; 32]).node_id();
        let e = v
            .check(stranger, &proof(&p, &dir(), t), t, true)
            .await
            .unwrap_err();
        assert!(e.downcast_ref::<Unvouched>().is_some(), "{e:#}");
    }

    /// What a proof carries is kept: in the keystore's view, and in a shared
    /// set, so the next call speaks at once.
    #[tokio::test]
    async fn a_good_proof_is_kept_for_the_next_call() {
        let ks = Keystore::at(crate::testutil::temp_dir());
        let p = signed(3, &[host().node_id()], &[dir().node_id()]);
        let t = now();
        view::write(&ks, root().node_id(), &held(&p, None)).unwrap();
        let mut v = Vouching::new(root().node_id(), held(&p, None), Scope::Service(orders()))
            .keeping_in(Sink::Keystore(ks.clone()));
        v.check(host().node_id(), &proof(&p, &dir(), t), t, true)
            .await
            .unwrap();
        let stored = view::read(&ks, root().node_id()).unwrap().unwrap();
        let next = Vouching::new(root().node_id(), stored, Scope::Service(orders()));
        assert!(next.ready(host().node_id(), t));

        let shared = Arc::new(Mutex::new(FreshSet::default()));
        let mut v = Vouching::new(root().node_id(), held(&p, None), Scope::Service(orders()))
            .keeping_in(Sink::Shared(Arc::clone(&shared)));
        v.check(host().node_id(), &proof(&p, &dir(), t), t, true)
            .await
            .unwrap();
        let next = Vouching::new(root().node_id(), held(&p, None), Scope::Service(orders()))
            .keeping_in(Sink::Shared(shared));
        assert!(next.ready(host().node_id(), t));
    }
}

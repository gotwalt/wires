//! Card 36c's acceptance: **hosts follow the directory by subscription, and
//! the signed freshness rule decides what a host does when no directory
//! vouches for its policy.**
//!
//! Policies here are signed by the root directly and handed to a directory
//! by the admin's publish ([`publish_all`]) or [`Directory::accept`]; hosts
//! are [`Follower`]s, or whole hosts ([`serve_until`]) on hermetic loopback.
//!
//! - [`an_edit_reaches_every_subscribed_host_within_2s_as_one_update`]: and
//!   what it costs each host, in frames and bytes.
//! - [`a_host_that_missed_edits_catches_up_by_one_update_on_reconnect`]
//! - [`an_update_that_does_not_apply_makes_the_host_take_the_whole_policy`]
//! - [`with_every_directory_down_lenient_keeps_serving`]
//! - [`with_every_directory_down_strict_refuses_until_one_is_back`]
//! - [`a_host_restarted_from_disk_serves_before_any_directory_answers`]
//! - [`a_directory_serving_an_unadoptable_policy_is_passed_over`]
//! - [`a_publish_from_a_stale_copy_is_not_delivered`]

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use iroh::Endpoint;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::protocol::Router;
use library::{
    FreshnessMode, Matcher, Membership, NodeIdentity, Policy, Service, Settings, SignedPolicy,
    StateVersion,
};

use super::{PATIENCE, bind_in, call, hello, host_config, localhost_socks, role, service};
use crate::admin::keystore::Keystore;
use crate::caller::mock_idp::MockIdp;
use crate::clock::now_unix;
use crate::directory::node::Directory;
use crate::directory::serve::Running;
use crate::host::follow::{FollowStats, Follower};
use crate::host::freshness::{Freshness, STALE, Vouched};
use crate::host::native::NativeServices;
use crate::host::serve::{Binding, Serving, serve_until};
use crate::host::transport::endpoint_addr;
use crate::policy::fetch::publish_all;
use crate::policy::store;

/// Root 1; the admin 2; directories 40, 41; hosts 50, 51; alice 60.
struct World {
    root: NodeIdentity,
    admin: NodeIdentity,
    dirs: Vec<NodeIdentity>,
    hosts: Vec<NodeIdentity>,
    alice: NodeIdentity,
    book: MemoryLookup,
    idp: MockIdp,
    /// The newest policy signed, which the next is signed after.
    last: std::sync::Mutex<Option<SignedPolicy>>,
}

impl World {
    async fn new() -> World {
        World {
            root: NodeIdentity::from_seed([1u8; 32]),
            admin: NodeIdentity::from_seed([2u8; 32]),
            dirs: (40..42u8)
                .map(|b| NodeIdentity::from_seed([b; 32]))
                .collect(),
            hosts: (50..52u8)
                .map(|b| NodeIdentity::from_seed([b; 32]))
                .collect(),
            alice: NodeIdentity::from_seed([60u8; 32]),
            book: MemoryLookup::new(),
            idp: MockIdp::start("alice@example.com").await,
            last: Default::default(),
        }
    }

    fn badge(&self, who: &NodeIdentity) -> Membership {
        Membership::mint(&self.root, who.node_id(), 0, i64::MAX).unwrap()
    }

    /// The policy at `version`: `echo` on every host for `analyst` (alice),
    /// both directories listed, `settings`, and `bans` banned nodes; signed
    /// after the previous one, so unchanged entries keep their signature.
    fn policy(&self, version: u64, settings: Settings, bans: u8) -> SignedPolicy {
        self.policy_until(version, settings, bans, i64::MAX)
    }

    /// [`policy`](Self::policy), good until `not_after`.
    fn policy_until(
        &self,
        version: u64,
        settings: Settings,
        bans: u8,
        not_after: i64,
    ) -> SignedPolicy {
        let mut p = Policy::new(self.root.node_id());
        p.version = StateVersion(version);
        p.issued = now_unix();
        p.not_after = not_after;
        p.directories = self.dirs.iter().map(|d| d.node_id()).collect();
        p.settings = settings;
        p.roles.insert(
            role("analyst"),
            vec![Matcher {
                email: Some("alice@example.com".parse().unwrap()),
                ..Matcher::new(self.idp.issuer.as_str())
            }],
        );
        p.services.insert(
            service("echo"),
            Service {
                description: String::new(),
                allow: vec![role("analyst")],
                hosts: self.hosts.iter().map(|h| h.node_id()).collect(),
                readers: vec![],
            },
        );
        for b in 0..bans {
            p.ban(NodeIdentity::from_seed([100 + b; 32]).node_id(), i64::MAX);
        }
        crate::testutil::trust_role_issuers(&mut p);
        let mut last = self.last.lock().unwrap();
        let signed = match last.as_ref() {
            Some(prev) => p.sign_after(&self.root, prev).unwrap(),
            None => p.sign(&self.root).unwrap(),
        };
        *last = Some(signed.clone());
        signed
    }

    /// A keystore for `who`, joined, holding `policy`.
    fn keystore(&self, who: &NodeIdentity, policy: &SignedPolicy) -> Arc<Keystore> {
        let ks = Arc::new(Keystore::at(crate::testutil::temp_dir()));
        ks.save_node(who).unwrap();
        ks.save_membership(&self.badge(who)).unwrap();
        store::adopt_if_newer(&ks, policy, self.root.node_id(), now_unix()).unwrap();
        ks
    }

    /// A hermetic endpoint for `who`, findable through the book.
    async fn bind(&self, who: &NodeIdentity) -> Endpoint {
        let endpoint = bind_in(who, &self.book).await;
        self.book.add_endpoint_info(
            endpoint_addr(&who.node_id(), &localhost_socks(&endpoint), None).unwrap(),
        );
        endpoint
    }

    /// Directory `i`, open from `ks` and serving (beats included).
    async fn directory(&self, i: usize, ks: &Arc<Keystore>) -> Dir {
        let node = &self.dirs[i];
        let dir = Directory::open(
            node.duplicate(),
            self.root.node_id(),
            Arc::clone(ks),
            64,
            now_unix(),
        )
        .unwrap();
        let endpoint = self.bind(node).await;
        let router = Running::mount(Router::builder(endpoint.clone()), &dir).spawn();
        let running = Running::start(Arc::clone(&dir), endpoint.clone(), self.badge(node));
        Dir {
            dir,
            endpoint,
            router,
            running,
        }
    }

    /// Host `i`'s follower on its own endpoint, from `ks`, until the task is
    /// aborted.
    async fn follower(&self, i: usize, ks: &Arc<Keystore>) -> Following {
        let node = &self.hosts[i];
        let endpoint = self.bind(node).await;
        let root = self.root.node_id();
        let head = store::read(ks, root).unwrap().map(|h| h.signed.head);
        let freshness = Arc::new(Freshness::load(Arc::clone(ks), head.as_ref()));
        let stats = Arc::new(FollowStats::default());
        let task = tokio::spawn(
            Follower {
                endpoint: endpoint.clone(),
                ks: Arc::clone(ks),
                root,
                badge: self.badge(node),
                freshness: Arc::clone(&freshness),
                runs_directory: false,
                stats: Arc::clone(&stats),
            }
            .run(),
        );
        Following {
            ks: Arc::clone(ks),
            root,
            freshness,
            stats,
            task,
            _endpoint: endpoint,
        }
    }

    /// Host `i` serving `echo` from `ks` (a whole host: gate, log,
    /// follower), until the returned sender is dropped.
    async fn host(
        &self,
        i: usize,
        ks: &Arc<Keystore>,
    ) -> (iroh::EndpointAddr, tokio::sync::oneshot::Sender<()>) {
        let node = &self.hosts[i];
        let endpoint = self.bind(node).await;
        let addr = endpoint_addr(&node.node_id(), &localhost_socks(&endpoint), None).unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let serving = Serving {
            node: node.duplicate(),
            membership: self.badge(node),
            keystore: Arc::clone(ks),
            config: host_config(&[&self.idp], r#"{"echo":{"command":["echo","hi"]}}"#, ""),
            native: NativeServices::new(),
            binding: Binding::Endpoint(endpoint),
        };
        tokio::spawn(async move {
            serve_until(serving, async {
                let _ = stopped.await;
                Ok(())
            })
            .await
            .unwrap();
        });
        (addr, stop)
    }

    /// Alice calls `echo` on the host at `addr`: its stdout, or the
    /// refusal.
    async fn call(&self, addr: &iroh::EndpointAddr) -> Result<String, String> {
        let hello = hello(&self.root, &self.alice, 0, Some(&self.idp));
        match call(&self.alice, addr, hello, "echo", &[]).await {
            super::Outcome::Ran {
                code: 0, stdout, ..
            } => Ok(stdout),
            super::Outcome::Denied(reason) => Err(reason),
            other => panic!("unexpected: {other:?}"),
        }
    }
}

/// A directory on the network.
struct Dir {
    dir: Arc<Directory>,
    endpoint: Endpoint,
    router: Router,
    running: Running,
}

impl Dir {
    /// Stop it: loops, protocols, endpoint.
    async fn stop(self) {
        self.running.stop().await;
        self.router.shutdown().await.unwrap();
        self.endpoint.close().await;
    }
}

/// A running follower.
struct Following {
    ks: Arc<Keystore>,
    root: library::NodeId,
    freshness: Arc<Freshness>,
    stats: Arc<FollowStats>,
    task: tokio::task::JoinHandle<()>,
    _endpoint: Endpoint,
}

impl Following {
    /// Wait until it holds `version`, vouched for by a current `Fresh`.
    async fn until(&self, version: StateVersion) {
        tokio::time::timeout(PATIENCE, async {
            loop {
                if let Some(h) = store::read(&self.ks, self.root).unwrap()
                    && h.version() == version
                    && self.freshness.vouched(&h.signed.head, now_unix()) == Vouched::Current
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("never reached version {}", version.0));
    }

    fn frames(&self) -> (u64, u64, u64, u64) {
        let s = &self.stats;
        (
            s.wholes.load(Ordering::SeqCst),
            s.updates.load(Ordering::SeqCst),
            s.bytes.load(Ordering::SeqCst),
            s.resyncs.load(Ordering::SeqCst),
        )
    }
}

/// Retry `f` until it gives `Some`, within [`PATIENCE`].
async fn eventually<T, F: std::future::Future<Output = Option<T>>>(
    what: &str,
    mut f: impl FnMut() -> F,
) -> T {
    tokio::time::timeout(PATIENCE, async {
        loop {
            if let Some(t) = f().await {
                return t;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("never: {what}"))
}

/// The admin's edit reaches both subscribed hosts within 2 s, each as one
/// `policy_update` carrying only what changed, measured in frames and bytes.
#[tokio::test]
async fn an_edit_reaches_every_subscribed_host_within_2s_as_one_update() {
    let w = World::new().await;
    let v1 = w.policy(1, Settings::default(), 20);
    let d = w.directory(0, &w.keystore(&w.dirs[0], &v1)).await;
    // The second directory is down: hosts follow the first that answers.
    let hosts = [
        w.follower(0, &w.keystore(&w.hosts[0], &v1)).await,
        w.follower(1, &w.keystore(&w.hosts[1], &v1)).await,
    ];
    for h in &hosts {
        h.until(StateVersion(1)).await;
    }
    let before: Vec<_> = hosts.iter().map(Following::frames).collect();

    // One edit: a new ban. Published by the admin, as every edit is.
    let admin = w.bind(&w.admin).await;
    let v2 = w.policy(2, Settings::default(), 21);
    let started = Instant::now();
    let report = publish_all(&admin, &w.badge(&w.admin), &v2, &[w.dirs[0].node_id()])
        .await
        .unwrap();
    assert_eq!(report.delivered, vec![w.dirs[0].node_id()]);
    for h in &hosts {
        h.until(StateVersion(2)).await;
    }
    let took = started.elapsed();
    assert!(took < Duration::from_secs(2), "the edit took {took:?}");
    for (h, before) in hosts.iter().zip(&before) {
        let after = h.frames();
        assert_eq!(after.0, before.0, "no whole policy was sent");
        assert_eq!(after.1, before.1 + 1, "one policy_update");
        let bytes = after.2 - before.2;
        eprintln!("an edit (one ban) cost this host {bytes} bytes in one frame ({took:?})");
        assert!(bytes < 3_000, "{bytes} bytes for one ban");
    }
    // The update is a delta: much smaller than the whole policy.
    let whole = library::SubFrame::Policy {
        policy: v2.clone(),
        fresh: d.dir.snapshot().unwrap().fresh.clone().unwrap(),
    }
    .encode()
    .unwrap()
    .len();
    eprintln!("the whole policy is {whole} bytes as a frame");
    assert!(hosts[0].frames().2 - before[0].2 < whole as u64 / 2);
    for h in hosts {
        h.task.abort();
    }
    admin.close().await;
    d.stop().await;
}

/// A host whose subscription was down while two edits were made gets both
/// in one `policy_update` when it subscribes again.
#[tokio::test]
async fn a_host_that_missed_edits_catches_up_by_one_update_on_reconnect() {
    let w = World::new().await;
    let v1 = w.policy(1, Settings::default(), 1);
    let d = w.directory(0, &w.keystore(&w.dirs[0], &v1)).await;
    let ks = w.keystore(&w.hosts[0], &v1);
    let first = w.follower(0, &ks).await;
    first.until(StateVersion(1)).await;
    first.task.abort();

    let now = now_unix();
    d.dir
        .accept(&w.policy(2, Settings::default(), 2), now)
        .unwrap();
    d.dir
        .accept(&w.policy(3, Settings::default(), 3), now)
        .unwrap();
    let again = w.follower(0, &ks).await;
    again.until(StateVersion(3)).await;
    let (wholes, updates, _, resyncs) = again.frames();
    assert_eq!((wholes, updates, resyncs), (0, 1, 0));
    again.task.abort();
    d.stop().await;
}

/// A host holding a copy the directory's delta doesn't apply to (here, a
/// root-signed policy at the same version but other items) fails the
/// update's hash check, and takes the whole policy instead.
#[tokio::test]
async fn an_update_that_does_not_apply_makes_the_host_take_the_whole_policy() {
    let w = World::new().await;
    let v1 = w.policy(1, Settings::default(), 1);
    let d = w.directory(0, &w.keystore(&w.dirs[0], &v1)).await;
    d.dir
        .accept(&w.policy(2, Settings::default(), 2), now_unix())
        .unwrap();
    // Another version 1: the delta from the directory's version 1 won't
    // hash to version 2's head when applied to it.
    let mut forked = Policy::new(w.root.node_id());
    forked.version = StateVersion(1);
    forked.not_after = i64::MAX;
    forked.directories = w.dirs.iter().map(|d| d.node_id()).collect();
    forked.ban(NodeIdentity::from_seed([7u8; 32]).node_id(), i64::MAX);
    let forked = crate::testutil::signed_policy(&w.root, forked);
    let h = w.follower(0, &w.keystore(&w.hosts[0], &forked)).await;
    h.until(StateVersion(2)).await;
    let (wholes, updates, _, resyncs) = h.frames();
    assert_eq!((wholes, updates, resyncs), (1, 1, 1));
    let held = store::read(&h.ks, h.root).unwrap().unwrap();
    assert_eq!(held.signed, w.last.lock().unwrap().clone().unwrap());
    h.task.abort();
    d.stop().await;
}

/// Short intervals: a `Fresh` every second, good for three.
fn quick(freshness: FreshnessMode) -> Settings {
    Settings {
        freshness,
        beat_secs: 1,
        fresh_secs: 3,
    }
}

/// With every directory stopped, a `lenient` host keeps serving under its
/// held policy.
#[tokio::test]
async fn with_every_directory_down_lenient_keeps_serving() {
    let w = World::new().await;
    let v1 = w.policy(1, quick(FreshnessMode::Lenient), 0);
    let d = w.directory(0, &w.keystore(&w.dirs[0], &v1)).await;
    let ks = w.keystore(&w.hosts[0], &v1);
    let (addr, _stop) = w.host(0, &ks).await;
    assert_eq!(w.call(&addr).await.unwrap(), "hi\n");
    d.stop().await;
    // Past the last `Fresh`'s `until`.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(w.call(&addr).await.unwrap(), "hi\n");
}

/// With every directory stopped, a `strict` host refuses calls once its
/// `Fresh` lapses, and serves again once a directory is back.
#[tokio::test]
async fn with_every_directory_down_strict_refuses_until_one_is_back() {
    let w = World::new().await;
    let v1 = w.policy(1, quick(FreshnessMode::Strict), 0);
    let dir_ks = w.keystore(&w.dirs[0], &v1);
    let d = w.directory(0, &dir_ks).await;
    let ks = w.keystore(&w.hosts[0], &v1);
    let (addr, _stop) = w.host(0, &ks).await;
    // Served once a directory has vouched for its policy.
    eventually("a vouched call", || async { w.call(&addr).await.ok() }).await;
    d.stop().await;
    let refused = eventually("a refusal", || async { w.call(&addr).await.err() }).await;
    assert_eq!(refused, STALE);
    // The directory comes back (from directory.redb): calls are served again.
    let d = w.directory(0, &dir_ks).await;
    let out = eventually("a call after", || async { w.call(&addr).await.ok() }).await;
    assert_eq!(out, "hi\n");
    d.stop().await;
}

/// A directory that serves a policy the host can't adopt (here, one that
/// expired after the directory took it) is passed over: the host asks it
/// for the whole policy once, then fails over to the next directory, which
/// serves a good one, instead of asking the first again forever.
#[tokio::test]
async fn a_directory_serving_an_unadoptable_policy_is_passed_over() {
    let w = World::new().await;
    let v1 = w.policy(1, Settings::default(), 0);
    let first_ks = w.keystore(&w.dirs[0], &v1);
    let second_ks = w.keystore(&w.dirs[1], &v1);
    // Two version 2s, so neither directory takes the other's (not newer).
    // The first directory's expires a moment after it takes it.
    let expiring = w.policy_until(2, Settings::default(), 1, now_unix() + 1);
    let good = w.policy(2, Settings::default(), 2);
    let first = w.directory(0, &first_ks).await;
    assert!(first.dir.accept(&expiring, now_unix()).unwrap());
    let second = w.directory(1, &second_ks).await;
    assert!(second.dir.accept(&good, now_unix()).unwrap());
    tokio::time::sleep(Duration::from_millis(2_500)).await;

    // The host's policy lists the first directory first.
    let h = w.follower(0, &w.keystore(&w.hosts[0], &v1)).await;
    h.until(StateVersion(2)).await;
    assert_eq!(store::read(&h.ks, h.root).unwrap().unwrap().signed, good);
    let (_, _, _, resyncs) = h.frames();
    assert_eq!(
        resyncs, 2,
        "the update, then the whole policy, from the first"
    );
    h.task.abort();
    first.stop().await;
    second.stop().await;
}

/// An admin publishing from a stale copy: a directory holding a newer
/// version, or another policy at the version offered, answers with what it
/// holds and keeps it. The publish reports it as `newer`, never delivered,
/// and the admin command fails naming the way back.
#[tokio::test]
async fn a_publish_from_a_stale_copy_is_not_delivered() {
    let w = World::new().await;
    let v1 = w.policy(1, Settings::default(), 0);
    let d = w.directory(0, &w.keystore(&w.dirs[0], &v1)).await;
    let (v2, v3) = (
        w.policy(2, Settings::default(), 1),
        w.policy(3, Settings::default(), 2),
    );
    let now = now_unix();
    assert!(d.dir.accept(&v2, now).unwrap());
    assert!(d.dir.accept(&v3, now).unwrap());
    let admin = w.bind(&w.admin).await;
    let badge = w.badge(&w.admin);
    let only = [w.dirs[0].node_id()];

    // Two versions behind: its version 2 is older than the directory's 3.
    let report = publish_all(&admin, &badge, &v2, &only).await.unwrap();
    assert_eq!(report.newer, vec![(only[0], StateVersion(3))], "{report:?}");
    assert!(report.delivered.is_empty(), "{report:?}");
    // One behind: another version 3, signed from its copy of version 2.
    let other_v3 = w.policy(3, Settings::default(), 5);
    assert_ne!(other_v3.head, v3.head);
    let report = publish_all(&admin, &badge, &other_v3, &only).await.unwrap();
    assert_eq!(report.newer, vec![(only[0], StateVersion(3))], "{report:?}");
    let failure =
        crate::admin::propagate::Propagation::from_publish(Ok((StateVersion(3), report)), false)
            .failure
            .expect("the edit fails");
    assert!(failure.contains("policy.json is stale"), "{failure}");
    assert_eq!(d.dir.snapshot().unwrap().held.signed, v3, "kept its own");

    // The directory's own version, re-published (`policy push`): delivered.
    let report = publish_all(&admin, &badge, &v3, &only).await.unwrap();
    assert_eq!(report.delivered, only.to_vec(), "{report:?}");
    assert!(report.newer.is_empty());
    admin.close().await;
    d.stop().await;
}

/// A host restarted with its policy on disk serves at once, with no
/// directory up at all.
#[tokio::test]
async fn a_host_restarted_from_disk_serves_before_any_directory_answers() {
    let w = World::new().await;
    let v1 = w.policy(1, Settings::default(), 0);
    let ks = w.keystore(&w.hosts[0], &v1);
    let (addr, _stop) = w.host(0, &ks).await;
    assert_eq!(w.call(&addr).await.unwrap(), "hi\n");
}

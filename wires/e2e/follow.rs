//! Card 36c's acceptance: **hosts follow the directory by subscription**;
//! and card 49's: **a caller tells a host nothing until a directory other
//! than that host vouches for the head it holds.**
//!
//! Policies here are signed by the root directly and handed to a directory
//! by the admin's publish ([`publish_all`]) or [`Directory::accept`]; hosts
//! are [`Follower`]s, or whole hosts ([`serve_until`]) on hermetic loopback.
//!
//! - [`an_edit_reaches_every_subscribed_host_within_2s_as_one_update`]: 2 s
//!   after the publish is answered (the fan-out, not the admin's dial), and
//!   what it costs each host, in frames and bytes.
//! - [`a_host_that_missed_edits_catches_up_by_one_update_on_reconnect`]
//! - [`an_update_that_does_not_apply_makes_the_host_take_the_whole_policy`]
//! - [`an_update_this_host_already_holds_is_skipped_not_resynced`]
//! - [`with_every_directory_down_calls_fail_closed_until_one_is_back`]
//! - [`a_node_banned_host_that_is_a_directory_gets_no_token`]
//! - [`a_host_dropped_from_the_service_gets_no_token`]
//! - [`a_one_machine_network_calls_its_host`]
//! - [`a_host_restarted_from_disk_serves_before_any_directory_answers`]
//! - [`a_directory_serving_an_unadoptable_policy_is_passed_over`]
//! - [`a_publish_from_a_stale_copy_is_not_delivered`]
//! - [`a_directory_that_ends_the_subscription_with_denied_is_passed_over`]
//! - [`a_host_every_directory_refuses_backs_off`]

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use iroh::Endpoint;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::protocol::Router;
use library::{Matcher, NodeIdentity, Policy, Service, Settings, SignedPolicy, StateVersion};

use super::{PATIENCE, bind_in, call, hello, host_config, localhost_socks, role, service};
use crate::admin::keystore::Keystore;
use crate::caller::mock_idp::MockIdp;
use crate::clock::now_unix;
use crate::directory::node::Directory;
use crate::directory::serve::Running;
use crate::host::follow::{FollowStats, Follower};
use crate::host::freshness::Freshness;
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
        self.policy_edited(version, settings, bans, not_after, |_| {})
    }

    /// [`policy_until`](Self::policy_until), changed by `edit` before it is
    /// signed.
    fn policy_edited(
        &self,
        version: u64,
        settings: Settings,
        bans: u8,
        not_after: i64,
        edit: impl FnOnce(&mut Policy),
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
            },
        );
        for b in 0..bans {
            p.ban(NodeIdentity::from_seed([100 + b; 32]).node_id());
        }
        edit(&mut p);
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
        crate::testutil::join(&ks, &self.root, &[]);
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
        let running = Running::start(Arc::clone(&dir), endpoint.clone());
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
                freshness: Arc::clone(&freshness),
                runs_directory: false,
                stats: Arc::clone(&stats),
            }
            .run(),
        );
        Following {
            me: node.node_id(),
            ks: Arc::clone(ks),
            root,
            freshness,
            stats,
            task,
            _endpoint: endpoint,
        }
    }

    /// Host `i` serving `echo` from `ks` (a whole host: gate, exec,
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
            root: self.root.node_id(),
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
    /// refusal. Hand-rolled: it trusts the host without checking its proof.
    async fn call(&self, addr: &iroh::EndpointAddr) -> Result<String, String> {
        let hello = hello(&self.alice, 0, Some(&self.idp));
        match call(&self.alice, addr, hello, "echo", &[]).await {
            super::Outcome::Ran {
                code: 0, stdout, ..
            } => Ok(stdout),
            super::Outcome::Denied(reason) => Err(reason),
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// Alice as `wires call` makes her: her keystore holding `policy`'s view
    /// for her (and `fresh`, a directory's word for it), and her ID token.
    async fn caller(&self, policy: &SignedPolicy, fresh: Option<library::Fresh>) -> Caller {
        let ks = Keystore::at(crate::testutil::temp_dir());
        ks.save_node(&self.alice).unwrap();
        crate::testutil::join(&ks, &self.root, &[]);
        let token = self.idp.mint(
            &library::OidcNonce::for_node(&self.alice.node_id()),
            now_unix() + 3600,
        );
        std::fs::write(
            ks.path(crate::caller::login::ID_TOKEN_FILE),
            format!("{}\n", token.as_str()),
        )
        .unwrap();
        let caller = Caller {
            ks,
            creds: crate::caller::call::Credentials::of(
                self.alice.duplicate(),
                self.root.node_id(),
            ),
            endpoint: self.bind(&self.alice).await,
        };
        caller.hold(self, policy, fresh);
        caller
    }

    /// A host that shows `proof` for `who`, and records what callers send
    /// it (it serves nothing).
    async fn lying_host(&self, who: &NodeIdentity, proof: library::HostProof) -> Heard {
        let endpoint = self.bind(who).await;
        endpoint.set_alpns(vec![crate::host::transport::ALPN.to_vec()]);
        let heard = Heard::default();
        let log = heard.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let Ok(conn) = incoming.await else { continue };
                log.0.lock().unwrap().0 += 1;
                let Ok((mut send, mut recv)) = conn.accept_bi().await else {
                    continue;
                };
                let proof = library::Frame::Proof(proof.clone());
                let _ = crate::host::transport::write_frame(&mut send, &proof).await;
                while let Ok(Some(frame)) = crate::host::transport::read_frame(&mut recv).await {
                    if matches!(frame, library::Frame::Hello(_) | library::Frame::Invoke(_)) {
                        log.0.lock().unwrap().1 += 1;
                    }
                }
            }
        });
        heard
    }
}

/// What a [`World::lying_host`] heard: connections, and `Hello`s or
/// `Invoke`s.
#[derive(Clone, Default)]
struct Heard(Arc<std::sync::Mutex<(usize, usize)>>);

impl Heard {
    fn connections(&self) -> usize {
        self.0.lock().unwrap().0
    }
    fn hellos(&self) -> usize {
        self.0.lock().unwrap().1
    }
}

/// Alice's `wires call echo`, from her keystore.
struct Caller {
    ks: Keystore,
    creds: crate::caller::call::Credentials,
    endpoint: Endpoint,
}

impl Caller {
    /// Store `policy`'s view for alice (with `fresh`, a directory's word for
    /// it), as a directory would cut it.
    fn hold(&self, w: &World, policy: &SignedPolicy, fresh: Option<library::Fresh>) {
        let person = super::person(&w.idp, "alice@example.com");
        let held = crate::caller::view::HeldView::fetched(
            policy.view_for(w.alice.node_id(), Some(&person), None),
            fresh,
            now_unix(),
        );
        crate::caller::view::write(&self.ks, w.root.node_id(), &held).unwrap();
    }

    /// Call `echo` as `wires call` does (from the stored view, refreshing it
    /// from a directory when a host shows a newer head): its stdout, or the
    /// error as text.
    async fn call(&self, w: &World) -> Result<String, String> {
        let _ = w;
        let held = crate::caller::view::read(&self.ks, self.creds.root())
            .unwrap()
            .unwrap();
        let dial = crate::caller::call::ServiceDial {
            endpoint: &self.endpoint,
            hints: Default::default(),
            timeout: Duration::from_secs(3),
        };
        let mut stdout = Vec::new();
        let r = crate::caller::call::call_service_with(
            &self.creds,
            &self.ks,
            &held,
            &service("echo"),
            &dial,
            library::Argv::default(),
            std::io::Cursor::new(Vec::new()),
            &mut stdout,
            Vec::new(),
            Default::default(),
        )
        .await;
        match r {
            Ok(0) => Ok(String::from_utf8(stdout).unwrap()),
            Ok(code) => Err(format!("exit {code}")),
            Err(e) => Err(match e.downcast_ref::<crate::host::transport::Denied>() {
                Some(d) => format!("denied: {}", d.reason()),
                None => format!("{e:#}"),
            }),
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
    /// The host it follows for.
    me: library::NodeId,
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
                    && self.freshness.vouched(&h.signed.head, self.me, now_unix())
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
    let report = publish_all(&admin, &v2, &[w.dirs[0].node_id()])
        .await
        .unwrap();
    assert_eq!(report.delivered, vec![w.dirs[0].node_id()]);
    let published = started.elapsed();
    for h in &hosts {
        h.until(StateVersion(2)).await;
    }
    let took = started.elapsed();
    // The claim under test is that the directory pushes the edit to its
    // subscribers as it takes it (docs: "within seconds"), not on the next
    // beat (300 s by default) or a reconnect. So the budget is for the
    // fan-out after the directory answered the publish; the admin's own
    // dial and the publish (bounded by their timeouts) are printed, not
    // budgeted, so a loaded machine's slow handshake doesn't fail it.
    let fan_out = took - published;
    eprintln!("publish answered in {published:?}; both hosts held it {fan_out:?} later");
    assert!(
        fan_out < Duration::from_secs(2),
        "the subscribed hosts took {fan_out:?} after the publish"
    );
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
    forked.ban(NodeIdentity::from_seed([7u8; 32]).node_id());
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

/// A host that is also a directory takes the admin's publish into its own
/// `policy.json` (its directory mirrors what it accepts) before the
/// directory it follows sends the same edit as an update from the version
/// before. That update is already held: it is skipped, its `Fresh` kept,
/// and nothing is resynced (it used to fail to apply, here on the ban the
/// edit lifts, and fetch the whole policy).
#[tokio::test]
async fn an_update_this_host_already_holds_is_skipped_not_resynced() {
    let w = World::new().await;
    let v1 = w.policy(1, Settings::default(), 1);
    let v2 = w.policy(2, Settings::default(), 0); // `wires restore`
    let ks = w.keystore(&w.hosts[0], &v1);
    let root = w.root.node_id();
    let endpoint = w.bind(&w.hosts[0]).await;
    let freshness = Arc::new(Freshness::load(
        Arc::clone(&ks),
        Some(&store::read(&ks, root).unwrap().unwrap().signed.head),
    ));
    let follower = Follower {
        endpoint: endpoint.clone(),
        ks: Arc::clone(&ks),
        root,
        freshness: Arc::clone(&freshness),
        runs_directory: true,
        stats: Arc::new(FollowStats::default()),
    };
    // Its own directory got there first.
    let now = now_unix();
    assert!(store::adopt_if_newer(&ks, &v2, root, now).unwrap());
    let fresh = library::Fresh::sign(&w.dirs[1], &v2.head, now, now + 300).unwrap();
    let update = library::SubFrame::PolicyUpdate {
        update: v2.update_from(&v1),
        fresh,
    };
    follower.take(update, now).unwrap();
    let held = store::read(&ks, root).unwrap().unwrap();
    assert_eq!(held.signed, v2);
    assert!(
        freshness.vouched(&held.signed.head, w.hosts[0].node_id(), now),
        "the update's Fresh vouches for the head it already holds"
    );
    endpoint.close().await;
}

/// Short intervals: a `Fresh` every second, good for three.
fn quick() -> Settings {
    Settings {
        beat_secs: 1,
        fresh_secs: 3,
    }
}

/// Card 49: with every directory stopped, no host can show a current word
/// for its policy, so a caller sends none of them anything and the call
/// fails closed, saying so (exit 1); once a directory is back, calls go
/// through again.
#[tokio::test]
async fn with_every_directory_down_calls_fail_closed_until_one_is_back() {
    let w = World::new().await;
    let v1 = w.policy(1, quick(), 0);
    let dir_ks = w.keystore(&w.dirs[0], &v1);
    let d = w.directory(0, &dir_ks).await;
    let ks = w.keystore(&w.hosts[0], &v1);
    let (_addr, _stop) = w.host(0, &ks).await;
    let caller = w.caller(&v1, None).await;
    // Served once a directory has vouched for the host's policy.
    eventually("a vouched call", || async { caller.call(&w).await.ok() }).await;
    d.stop().await;
    let refused = eventually("a call that fails closed", || async {
        caller
            .call(&w)
            .await
            .err()
            .filter(|e| e.contains("no directory has vouched"))
    })
    .await;
    assert!(refused.contains("no directory has vouched"), "{refused}");
    assert!(!refused.contains("denied"), "not a refusal: {refused}");
    // The directory comes back (from directory.redb): calls go through again.
    let d = w.directory(0, &dir_ks).await;
    let out = eventually("a call after", || async { caller.call(&w).await.ok() }).await;
    assert_eq!(out, "hi\n");
    d.stop().await;
}

/// Card 49, the attack, end to end: host X (host 0) is also one of the two
/// directories. The admin takes it out (`how`), the directory and host 1
/// take the edit, and a caller whose view predates it still lists X. X
/// keeps the old head and vouches for it itself; the honest directory's word
/// for that head has lapsed. X is sent no `Hello` (no ID token) and no
/// `Invoke`; the call reaches host 1.
async fn a_removed_host_that_is_a_directory_gets_nothing(how: Removal) {
    let w = World::new().await;
    let x = &w.hosts[0];
    let both = |p: &mut Policy| p.directories = vec![w.dirs[0].node_id(), x.node_id()];
    let v1 = w.policy_edited(1, quick(), 0, i64::MAX, both);
    let d = w.directory(0, &w.keystore(&w.dirs[0], &v1)).await;
    let y_ks = w.keystore(&w.hosts[1], &v1);
    let (_y, _stop) = w.host(1, &y_ks).await;
    // The caller's view, vouched for by the directory then.
    let old_word = d.dir.snapshot().unwrap().fresh.clone().unwrap();
    let caller = w.caller(&v1, Some(old_word.clone())).await;

    let x_id = x.node_id();
    let v2 = w.policy_edited(2, quick(), 0, i64::MAX, |p| match how {
        Removal::NodeBan => {
            for svc in p.services.values_mut() {
                svc.hosts.retain(|h| *h != x_id);
            }
            p.ban(x_id);
        }
        Removal::FromTheService => {
            both(p);
            p.services
                .get_mut(&service("echo"))
                .unwrap()
                .hosts
                .retain(|h| *h != x_id);
        }
    });
    let admin = w.bind(&w.admin).await;
    let report = publish_all(&admin, &v2, &[w.dirs[0].node_id()])
        .await
        .unwrap();
    assert_eq!(report.delivered, vec![w.dirs[0].node_id()]);
    // Past the old word's `until`: the window is `fresh_secs`.
    tokio::time::sleep(Duration::from_millis(3_500)).await;
    assert!(!old_word.is_current(now_unix()));

    // What X shows: its old head, with its own fresh word for it and the
    // directory's lapsed one; or, still a directory, the current head with
    // the directory's current word, which a caller checks against its view
    // refreshed to that head.
    let now = now_unix();
    let proof = match how {
        Removal::NodeBan => library::HostProof {
            head: v1.head.clone(),
            fresh: vec![
                library::Fresh::sign(x, &v1.head, now, now + 3).unwrap(),
                old_word,
            ],
        },
        Removal::FromTheService => library::HostProof {
            head: v2.head.clone(),
            fresh: vec![d.dir.snapshot().unwrap().fresh.clone().unwrap()],
        },
    };
    let heard = w.lying_host(x, proof).await;
    let mut calls = 0;
    while heard.connections() == 0 {
        assert!(calls < 40, "the random order never tried X");
        // From the view that predates the edit each time (a call that
        // reached host 1 refreshed it).
        caller.hold(&w, &v1, None);
        assert_eq!(caller.call(&w).await.unwrap(), "hi\n", "host 1 served it");
        calls += 1;
    }
    assert_eq!(heard.hellos(), 0, "X got no Hello, no ID token, no Invoke");
    admin.close().await;
    d.stop().await;
}

/// How the admin takes host X out.
#[derive(Clone, Copy)]
enum Removal {
    /// `wires remove <x>`: banned, dropped from every service and from the
    /// directories.
    NodeBan,
    /// `wires service rm-host`: dropped from the service, still a directory.
    FromTheService,
}

#[tokio::test]
async fn a_node_banned_host_that_is_a_directory_gets_no_token() {
    a_removed_host_that_is_a_directory_gets_nothing(Removal::NodeBan).await;
}

#[tokio::test]
async fn a_host_dropped_from_the_service_gets_no_token() {
    a_removed_host_that_is_a_directory_gets_nothing(Removal::FromTheService).await;
}

/// Card 49: a one-machine network (the host is the only directory) works
/// as it did: the caller takes the host's own word, and keeps it, so its
/// next call speaks at once.
#[tokio::test]
async fn a_one_machine_network_calls_its_host() {
    let w = World::new().await;
    let me = w.hosts[0].node_id();
    let v1 = w.policy_edited(1, Settings::default(), 0, i64::MAX, |p| {
        p.directories = vec![me];
        p.services.get_mut(&service("echo")).unwrap().hosts = vec![me];
    });
    let ks = w.keystore(&w.hosts[0], &v1);
    let (_addr, _stop) = w.host(0, &ks).await;
    let caller = w.caller(&v1, None).await;
    let out = eventually("a call", || async { caller.call(&w).await.ok() }).await;
    assert_eq!(out, "hi\n");
    let held = crate::caller::view::read(&caller.ks, w.root.node_id())
        .unwrap()
        .unwrap();
    assert!(
        held.fresh
            .vouching(&held.view.head, me, now_unix())
            .is_some(),
        "the host's own word, kept: the next call speaks at once"
    );
    assert_eq!(caller.call(&w).await.unwrap(), "hi\n");
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
    let only = [w.dirs[0].node_id()];

    // Two versions behind: its version 2 is older than the directory's 3.
    let report = publish_all(&admin, &v2, &only).await.unwrap();
    assert_eq!(report.newer, vec![(only[0], StateVersion(3))], "{report:?}");
    assert!(report.delivered.is_empty(), "{report:?}");
    // One behind: another version 3, signed from its copy of version 2.
    let other_v3 = w.policy(3, Settings::default(), 5);
    assert_ne!(other_v3.head, v3.head);
    let report = publish_all(&admin, &other_v3, &only).await.unwrap();
    assert_eq!(report.newer, vec![(only[0], StateVersion(3))], "{report:?}");
    let failure =
        crate::admin::propagate::Propagation::from_publish(Ok((StateVersion(3), report)), false)
            .failure
            .expect("the edit fails");
    assert!(failure.contains("policy.json is stale"), "{failure}");
    assert_eq!(d.dir.snapshot().unwrap().held.signed, v3, "kept its own");

    // The directory's own version, re-published (`policy push`): delivered.
    let report = publish_all(&admin, &v3, &only).await.unwrap();
    assert_eq!(report.delivered, only.to_vec(), "{report:?}");
    assert!(report.newer.is_empty());
    admin.close().await;
    d.stop().await;
}

/// A directory that ends the host's subscription with `denied` (here: the
/// new head no longer lists it) is passed over at once: the host follows
/// the next directory and takes the new head from it, and doesn't ask the
/// one that refused again.
#[tokio::test]
async fn a_directory_that_ends_the_subscription_with_denied_is_passed_over() {
    let w = World::new().await;
    let v1 = w.policy(1, Settings::default(), 0);
    let first = w.directory(0, &w.keystore(&w.dirs[0], &v1)).await;
    let second = w.directory(1, &w.keystore(&w.dirs[1], &v1)).await;
    let h = w.follower(0, &w.keystore(&w.hosts[0], &v1)).await;
    h.until(StateVersion(1)).await;
    let beats = |d: &Dir| d.dir.snapshot().unwrap().fresh.is_some();
    assert!(beats(&first) && beats(&second));

    // Version 2 lists only the second directory; both hold it.
    let second_only = vec![w.dirs[1].node_id()];
    let v2 = w.policy_edited(2, Settings::default(), 0, i64::MAX, |p| {
        p.directories = second_only.clone();
    });
    let now = now_unix();
    assert!(first.dir.accept(&v2, now).unwrap());
    assert!(second.dir.accept(&v2, now).unwrap());
    h.until(StateVersion(2)).await;
    // Past the pause a retry of the first directory would have waited.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    assert_eq!(h.stats.denials.load(Ordering::SeqCst), 1, "asked once");
    h.task.abort();
    first.stop().await;
    second.stop().await;
}

/// A host every directory refuses (here: banned) backs off between rounds
/// (1 s, 2 s, …): a handful of refusals over seconds, never a tight loop.
#[tokio::test]
async fn a_host_every_directory_refuses_backs_off() {
    let w = World::new().await;
    let v1 = w.policy(1, Settings::default(), 0);
    let first = w.directory(0, &w.keystore(&w.dirs[0], &v1)).await;
    let second = w.directory(1, &w.keystore(&w.dirs[1], &v1)).await;
    let h = w.follower(0, &w.keystore(&w.hosts[0], &v1)).await;
    h.until(StateVersion(1)).await;
    let host = w.hosts[0].node_id();
    let banned = w.policy_edited(2, Settings::default(), 0, i64::MAX, |p| {
        for svc in p.services.values_mut() {
            svc.hosts.retain(|h| *h != host);
        }
        p.ban(host);
    });
    let now = now_unix();
    assert!(first.dir.accept(&banned, now).unwrap());
    assert!(second.dir.accept(&banned, now).unwrap());
    tokio::time::sleep(Duration::from_millis(4_500)).await;
    // Rounds at about 0, 1 and 3 s: two refusals each.
    let denials = h.stats.denials.load(Ordering::SeqCst);
    assert!((2..=8).contains(&denials), "{denials} refusals in 4.5 s");
    h.task.abort();
    first.stop().await;
    second.stop().await;
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

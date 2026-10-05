//! Card 48: **an admin edit made right after a directory restarts reaches
//! it.**
//!
//! What was seen: in hand runs of the walkthrough, the first edit after a
//! host that is also a directory was restarted said `published to 1 of 2`.
//! The cause: a restarted node binds a new port, and the admin, dialing it
//! by key, can't find it there for a few seconds. With n0 discovery the
//! node's new record isn't resolvable for about 3 s after it starts (the
//! dial fails at once: "No addressing information available"); with a
//! stale line in the `hints` file the dial spends its whole
//! [`DIAL_TIMEOUT`] on the old port, and iroh looks the key up only when a
//! dial begins. The directory never sees the publish; nothing in it refuses
//! one. The admin tried each directory once.
//!
//! Here the admin's address book is its own [`MemoryLookup`], standing in
//! for discovery and the hints file, and the restarted directory's new
//! address enters it [`LAG`] after the restart. Every publish binds a fresh
//! endpoint, as each `wires` command does.
//!
//! - [`an_edit_right_after_a_directory_restarts_reaches_it`]: one try
//!   misses it (no address yet); the admin's publish, trying again within
//!   [`PUBLISH_BUDGET`], reaches both.
//! - [`a_stale_address_costs_one_dial_timeout_then_the_next_try_finds_it`]
//! - [`a_directory_that_missed_an_edit_holds_the_old_one_and_the_edit_fails`]:
//!   card 45, nothing hands an edit on; `wires policy push` does.
//! - [`a_busy_directory_is_tried_again`]: busy is no refusal.
//! - [`a_dead_directory_the_edit_drops_is_tried_once_and_not_waited_for`]

use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh::address_lookup::memory::MemoryLookup;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr};
use library::{NodeId, NodeIdentity, StateVersion};

use super::{bind_in, localhost_socks};
use crate::admin::init::{InitArgs, init_in};
use crate::admin::keystore::Keystore;
use crate::admin::propagate::{Propagation, settle};
use crate::admin::remove::{WhoArgs, remove_in};
use crate::admin::service::{directory_add, directory_rm};
use crate::admin::ttl::Ttl;
use crate::clock::now_unix;
use crate::directory::node::{Directory, MAX_ADMITTED};
use crate::directory::serve::Running;
use crate::directory::wire::DIAL_TIMEOUT;
use crate::host::transport::{endpoint_addr, endpoint_id};
use crate::policy::fetch::{
    PUBLISH_BUDGET, PublishReport, Retry, held_directories, publish_current_on, publish_retrying,
};
use crate::policy::store;

/// Less than the pause before a second try: a publish that tried a
/// directory once (a dial timeout at most) took less than that plus this.
const RETRY_SLACK: Duration = Duration::from_millis(900);

/// How long after its restart the admin can find the directory by its key
/// (n0 discovery: about 3 s on a real network).
const LAG: Duration = Duration::from_millis(1500);

/// An admin and two directories, each with its own keystore. The
/// directories find each other through `book`; the admin through
/// `admin_book`, which the tests hold behind.
struct Net {
    admin: Keystore,
    admin_node: NodeIdentity,
    root: NodeId,
    dirs: Vec<NodeIdentity>,
    dir_ks: Vec<Arc<Keystore>>,
    book: MemoryLookup,
    admin_book: MemoryLookup,
}

/// A directory serving on its own endpoint, beats included.
struct Dir {
    dir: Arc<Directory>,
    endpoint: Endpoint,
    router: Router,
    running: Running,
}

impl Dir {
    /// Where it listens.
    fn addr(&self) -> EndpointAddr {
        let me = crate::host::transport::to_node_id(&self.endpoint.id());
        endpoint_addr(&me, &localhost_socks(&self.endpoint), None).unwrap()
    }

    /// Stop it as a killed `wires serve` stops: loops, protocols, endpoint,
    /// and the store closed (so it can open again).
    async fn stop(self) {
        self.running.stop().await;
        self.router.shutdown().await.unwrap();
        self.endpoint.close().await;
        drop(self.dir);
    }
}

impl Net {
    /// `wires init`, then two nodes named directories (empty keystores,
    /// joined).
    fn new() -> Net {
        let admin = Keystore::at(crate::testutil::temp_dir());
        init_in(&admin, InitArgs::default()).unwrap();
        let root = admin.read_root_identity().unwrap().unwrap();
        let admin_node = admin.read_node_identity().unwrap().unwrap();
        let dirs: Vec<NodeIdentity> = (0..2).map(|_| NodeIdentity::generate()).collect();
        let dir_ks = dirs
            .iter()
            .map(|d| {
                directory_add(&admin, d.node_id(), Ttl::default()).unwrap();
                let ks = Arc::new(Keystore::at(crate::testutil::temp_dir()));
                ks.save_node(d).unwrap();
                crate::testutil::join(&ks, &root, &[]);
                ks
            })
            .collect();
        Net {
            admin,
            admin_node,
            root: root.node_id(),
            dirs,
            dir_ks,
            book: MemoryLookup::new(),
            admin_book: MemoryLookup::new(),
        }
    }

    /// Directory `i`, opened from its keystore on a new endpoint (a new
    /// port), findable by the other directory at once.
    async fn start(&self, i: usize) -> Dir {
        let node = &self.dirs[i];
        let dir = Directory::open(
            node.duplicate(),
            self.root,
            Arc::clone(&self.dir_ks[i]),
            64,
            now_unix(),
        )
        .unwrap();
        let endpoint = bind_in(node, &self.book).await;
        let router = Running::mount(Router::builder(endpoint.clone()), &dir).spawn();
        let running = Running::start(Arc::clone(&dir));
        let served = Dir {
            dir,
            endpoint,
            router,
            running,
        };
        self.book.add_endpoint_info(served.addr());
        served
    }

    /// The admin's stored policy version.
    fn version(&self) -> StateVersion {
        store::read(&self.admin, self.root)
            .unwrap()
            .unwrap()
            .version()
    }

    /// Publish the admin's stored policy as a `wires` command does: a fresh
    /// endpoint, the publish, settled (its note, and `reached.json`).
    async fn publish(&self, retry: Retry) -> Propagation {
        self.publish_since(&held_directories(&self.admin).unwrap(), retry)
            .await
            .0
    }

    /// [`publish`](Self::publish) after an edit, `earlier` being the
    /// directories the policy listed before it (as `run_edit` records them);
    /// and how long the publish took (not counting the endpoint's close).
    async fn publish_since(
        &self,
        earlier: &std::collections::BTreeSet<NodeId>,
        retry: Retry,
    ) -> (Propagation, Duration) {
        let endpoint = bind_in(&self.admin_node, &self.admin_book).await;
        let started = Instant::now();
        let report = publish_current_on(&endpoint, &self.admin, earlier, retry).await;
        let took = started.elapsed();
        endpoint.close().await;
        (
            settle(&self.admin, report.map(|r| (self.version(), r))),
            took,
        )
    }

    /// One try at each directory, no second: what every publish did before
    /// card 48.
    async fn publish_once(&self) -> PublishReport {
        let targets: Vec<NodeId> = self.dirs.iter().map(|d| d.node_id()).collect();
        self.publish_to(&targets, Duration::ZERO).await
    }

    /// Publish the admin's stored policy to `targets` only, trying each
    /// again within `budget`.
    async fn publish_to(&self, targets: &[NodeId], budget: Duration) -> PublishReport {
        let endpoint = bind_in(&self.admin_node, &self.admin_book).await;
        let held = store::read(&self.admin, self.root).unwrap().unwrap();
        let report = publish_retrying(
            &endpoint,
            &held.signed,
            targets,
            &targets.iter().copied().collect(),
            budget,
        )
        .await
        .unwrap();
        endpoint.close().await;
        report
    }

    /// `wires remove alice@example.com` (a person ban), not yet published.
    fn remove_alice(&self) {
        remove_in(
            &self.admin,
            WhoArgs {
                who: "alice@example.com".into(),
                issuer: None,
                policy_ttl: Ttl::default(),
            },
        )
        .unwrap();
    }

    /// Both directories up, known to the admin, holding the first policy
    /// (`wires policy push`: both took it, so both are in `reached.json`).
    async fn running(&self) -> (Dir, Dir) {
        let (d0, d1) = (self.start(0).await, self.start(1).await);
        for d in [&d0, &d1] {
            self.admin_book.add_endpoint_info(d.addr());
        }
        let pushed = self.publish(Retry::Every).await;
        assert_eq!(pushed.failure, None, "{}", pushed.note);
        assert!(
            pushed.note.contains("published to 2 of 2"),
            "{}",
            pushed.note
        );
        (d0, d1)
    }

    /// Stop directory 0 and start it again on a new port. The admin's book
    /// forgets it (or, `stale`, keeps only its old address), and learns the
    /// new address [`LAG`] later, as discovery would.
    async fn restart_0(&self, d0: Dir, stale: bool) -> Dir {
        let old = d0.addr();
        d0.stop().await;
        let d0 = self.start(0).await;
        let id = endpoint_id(&self.dirs[0].node_id()).unwrap();
        self.admin_book.remove_endpoint_info(id);
        if stale {
            self.admin_book.add_endpoint_info(old);
        }
        let (book, new) = (self.admin_book.clone(), d0.addr());
        tokio::spawn(async move {
            tokio::time::sleep(LAG).await;
            book.add_endpoint_info(new);
        });
        d0
    }
}

/// A removal made right after a directory restarted reaches both
/// directories. One try (what the admin did before) misses the restarted
/// one: it has no address yet, and the directory never sees the publish.
#[tokio::test]
async fn an_edit_right_after_a_directory_restarts_reaches_it() {
    let net = Net::new();
    let (d0, d1) = net.running().await;
    let d0 = net.restart_0(d0, false).await;
    net.remove_alice();
    let version = net.version();

    let once = net.publish_once().await;
    assert_eq!(once.missed, vec![net.dirs[0].node_id()], "{once:?}");
    assert!(once.refused.is_empty(), "nothing refused it: {once:?}");

    let started = Instant::now();
    let published = net.publish(Retry::Reached).await;
    assert_eq!(published.failure, None, "{}", published.note);
    assert!(
        published.note.contains(&format!(
            "policy version {}: published to 2 of 2",
            version.0
        )),
        "{}",
        published.note
    );
    assert!(started.elapsed() < PUBLISH_BUDGET);
    assert_eq!(d0.dir.version(), version);
    assert_eq!(d1.dir.version(), version);
    d0.stop().await;
    d1.stop().await;
}

/// The hints-file case: the admin holds the restarted directory's old
/// address. The first try spends its [`DIAL_TIMEOUT`] there; the next dial
/// looks the key up again and finds the new one.
#[tokio::test]
async fn a_stale_address_costs_one_dial_timeout_then_the_next_try_finds_it() {
    let net = Net::new();
    let (d0, d1) = net.running().await;
    let d0 = net.restart_0(d0, true).await;
    net.remove_alice();
    let started = Instant::now();
    let published = net.publish(Retry::Reached).await;
    let took = started.elapsed();
    assert!(
        published.note.contains("published to 2 of 2"),
        "{}",
        published.note
    );
    assert!(took >= DIAL_TIMEOUT, "the first try ended early: {took:?}");
    assert!(took < PUBLISH_BUDGET, "{took:?}");
    assert_eq!(d0.dir.version(), net.version());
    d0.stop().await;
    d1.stop().await;
}

/// Card 45: a directory the admin can't reach at all after its restart
/// misses the edit, and nothing hands it on: it holds the policy before it,
/// and the admin's command fails (it ran before, so it is no first run),
/// saying `wires policy push` brings it; which, once it is findable again,
/// it does.
#[tokio::test]
async fn a_directory_that_missed_an_edit_holds_the_old_one_and_the_edit_fails() {
    let net = Net::new();
    let (d0, d1) = net.running().await;
    let before = d0.dir.version();
    let d0 = net.restart_0(d0, false).await;
    // Not findable by the admin this time.
    let id = endpoint_id(&net.dirs[0].node_id()).unwrap();
    tokio::time::sleep(LAG + Duration::from_millis(100)).await;
    net.admin_book.remove_endpoint_info(id);
    net.remove_alice();
    let version = net.version();
    let once = net.publish_once().await;
    assert_eq!(once.delivered, vec![net.dirs[1].node_id()], "{once:?}");
    let settled = settle(&net.admin, Ok((version, once)));
    let failure = settled.failure.expect("a running directory missed it");
    assert!(
        failure.contains("nothing else will bring it there"),
        "{failure}"
    );
    assert!(failure.contains("wires policy push"), "{failure}");
    assert!(
        settled.note.contains("nothing but a publish brings it"),
        "{}",
        settled.note
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(d0.dir.version(), before, "nothing handed it on");
    // `wires policy push`, once the admin can find it again.
    net.admin_book.add_endpoint_info(d0.addr());
    let pushed = net.publish(Retry::Every).await;
    assert_eq!(pushed.failure, None, "{}", pushed.note);
    assert_eq!(
        d0.dir.snapshot().unwrap().held.signed,
        d1.dir.snapshot().unwrap().held.signed
    );
    d0.stop().await;
    d1.stop().await;
}

/// A directory whose slots are all taken answers "busy": no decision, so
/// the publish tries it again, and it takes the policy once a slot is free.
#[tokio::test]
async fn a_busy_directory_is_tried_again() {
    let net = Net::new();
    let (d0, d1) = net.running().await;
    let full = Arc::clone(&d0.dir.admitted)
        .acquire_many_owned(MAX_ADMITTED as u32)
        .await
        .unwrap();
    tokio::spawn(async move {
        tokio::time::sleep(LAG).await;
        drop(full);
    });
    net.remove_alice();
    // Only to the busy one.
    let only = [net.dirs[0].node_id()];
    let report = net.publish_to(&only, PUBLISH_BUDGET).await;
    assert_eq!(report.delivered, only.to_vec(), "{report:?}");
    assert!(report.refused.is_empty(), "{report:?}");
    assert_eq!(d0.dir.version(), net.version());
    d0.stop().await;
    d1.stop().await;
}

/// `wires directory rm` of a directory that is down: it is published to
/// once (one that is up learns it was dropped), not tried again for the
/// budget, its miss fails nothing, and the line doesn't say it catches up
/// (the others no longer let it follow them).
#[tokio::test]
async fn a_dead_directory_the_edit_drops_is_tried_once_and_not_waited_for() {
    let net = Net::new();
    let (d0, d1) = net.running().await;
    d0.stop().await;
    let gone = net.dirs[0].node_id();
    let earlier = held_directories(&net.admin).unwrap();
    directory_rm(&net.admin, gone, Ttl::default()).unwrap();
    let (published, took) = net.publish_since(&earlier, Retry::Reached).await;
    assert_eq!(published.failure, None, "{}", published.note);
    assert!(
        published.note.contains("published to 1 of 2"),
        "{}",
        published.note
    );
    assert!(
        published
            .note
            .contains(&format!("dropped by this edit: {}…", gone.short())),
        "{}",
        published.note
    );
    assert!(
        !published.note.contains("hosts that follow it"),
        "{}",
        published.note
    );
    assert!(took < DIAL_TIMEOUT + RETRY_SLACK, "tried again: {took:?}");
    assert_eq!(d1.dir.version(), net.version());
    d1.stop().await;
}

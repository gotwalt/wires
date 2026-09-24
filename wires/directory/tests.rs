//! Card 36b's acceptance, over hermetic loopback: the admin publishes to a
//! directory and never dials a host; hosts and callers fetch from it; a
//! restarted directory serves the same head with a new `Fresh`; tampered,
//! mixed and older policies and a stranger's `Fresh` are refused; a
//! directory that missed a publish catches up from a replica; and
//! `wires directory serve` refuses the admin's keystore and an unlisted node.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use iroh::Endpoint;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use library::{
    Ban, DIRECTORY_ALPN, DirectoryAnswer, DirectoryRequest, Fresh, Item, Membership, NodeIdentity,
    ServiceName, SignedPolicy, StateVersion,
};

use super::node::Directory;
use super::serve::{Running, open_standalone};
use super::wire;
use crate::admin::init::{InitArgs, init_in};
use crate::admin::keystore::Keystore;
use crate::admin::ledger::Ledger;
use crate::admin::service::{self, ServiceEdit, directory_add};
use crate::admin::ttl::Ttl;
use crate::clock::now_unix;
use crate::host::transport;
use crate::policy::{fetch, store};
use crate::testutil::temp_dir;

/// The longest any wait here may take (never reached when passing).
const PATIENCE: Duration = Duration::from_secs(20);

/// A hermetic endpoint for `node`, findable through `book`.
async fn bind(node: &NodeIdentity, book: &MemoryLookup) -> Endpoint {
    let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(transport::secret_key(node))
        .address_lookup(book.clone())
        .bind()
        .await
        .unwrap();
    let socks: Vec<std::net::SocketAddr> = endpoint
        .bound_sockets()
        .into_iter()
        .map(crate::net::dialable)
        .collect();
    book.add_endpoint_info(transport::endpoint_addr(&node.node_id(), &socks, None).unwrap());
    endpoint
}

/// A network: the admin (initialized), and `n` other nodes it invited, none
/// joined yet.
struct Fabric {
    admin: Arc<Keystore>,
    admin_node: NodeIdentity,
    root: NodeIdentity,
    nodes: Vec<NodeIdentity>,
    book: MemoryLookup,
}

impl Fabric {
    fn new(n: usize) -> Fabric {
        let admin = Arc::new(Keystore::at(temp_dir()));
        init_in(&admin, InitArgs::default()).unwrap();
        let root = admin.read_root_identity().unwrap().unwrap();
        let admin_node = admin.read_node_identity().unwrap().unwrap();
        let nodes: Vec<NodeIdentity> = (0..n).map(|_| NodeIdentity::generate()).collect();
        let mut ledger = Ledger::load(&admin).unwrap();
        for node in &nodes {
            ledger.record(node.node_id(), None, i64::MAX);
        }
        ledger.save(&admin).unwrap();
        Fabric {
            admin,
            admin_node,
            root,
            nodes,
            book: MemoryLookup::new(),
        }
    }

    /// Node `i` joined: its key, its badge, and the admin's policy now.
    fn join(&self, i: usize) -> Arc<Keystore> {
        let ks = Arc::new(Keystore::at(temp_dir()));
        let node = &self.nodes[i];
        ks.save_node(node).unwrap();
        ks.save_membership(&self.badge(node)).unwrap();
        store::adopt_if_newer(&ks, &self.policy().signed, self.root.node_id(), now_unix()).unwrap();
        ks
    }

    fn badge(&self, node: &NodeIdentity) -> Membership {
        Membership::mint(&self.root, node.node_id(), 0, i64::MAX).unwrap()
    }

    /// The admin's current policy.
    fn policy(&self) -> store::Held {
        store::read(&self.admin, self.root.node_id())
            .unwrap()
            .unwrap()
    }

    /// Node `i` as the admin's directory.
    fn list_directory(&self, i: usize) {
        directory_add(&self.admin, self.nodes[i].node_id(), Ttl::default()).unwrap();
    }

    /// Assign service `name` to node `i` (the admin's edit).
    fn assign(&self, name: &str, i: usize) -> store::Held {
        service::add(
            &self.admin,
            ServiceName::new(name).unwrap(),
            ServiceEdit {
                hosts: Some(vec![self.nodes[i].node_id()]),
                ..ServiceEdit::default()
            },
            Ttl::default(),
        )
        .unwrap()
    }

    /// The admin's endpoint.
    async fn admin_endpoint(&self) -> Endpoint {
        bind(&self.admin_node, &self.book).await
    }

    /// Node `i`'s directory, open from `ks`, serving on its own endpoint
    /// (and following its peers when `replicate`).
    async fn directory(&self, i: usize, ks: &Arc<Keystore>, replicate: bool) -> Serving {
        let node = &self.nodes[i];
        let dir = Directory::open(
            node.duplicate(),
            self.root.node_id(),
            Arc::clone(ks),
            64,
            now_unix(),
        )
        .unwrap();
        let endpoint = bind(node, &self.book).await;
        let router = Running::mount(Router::builder(endpoint.clone()), &dir).spawn();
        let running =
            replicate.then(|| Running::start(Arc::clone(&dir), endpoint.clone(), self.badge(node)));
        Serving {
            dir,
            endpoint,
            _router: router,
            _running: running,
        }
    }
}

/// A directory on the network.
struct Serving {
    dir: Arc<Directory>,
    endpoint: Endpoint,
    _router: Router,
    _running: Option<Running>,
}

/// Counts every connection on an ALPN, and closes it.
#[derive(Debug, Clone, Default)]
struct Counter(Arc<AtomicUsize>);

impl ProtocolHandler for Counter {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        conn.close(0u32.into(), b"counted");
        Ok(())
    }
}

/// Wait until `dir` holds `version`.
async fn until_version(dir: &Directory, version: StateVersion) {
    tokio::time::timeout(PATIENCE, async {
        let mut changes = dir.watch();
        while dir.version() < version {
            changes.changed().await.unwrap();
        }
    })
    .await
    .expect("the directory never caught up");
}

/// An admin edit reaches the directory, a host and a caller fetch it from
/// there, and nothing dials the host.
#[tokio::test]
async fn an_edit_reaches_the_directory_and_hosts_fetch_it_nobody_dials_them() {
    let f = Fabric::new(3); // 0: directory, 1: host, 2: caller
    f.list_directory(0);
    let dir_ks = f.join(0);
    let (host_ks, caller_ks) = (f.join(1), f.join(2));
    let dir = f.directory(0, &dir_ks, false).await;
    // The host listens, counting anything that dials it.
    let host_ep = bind(&f.nodes[1], &f.book).await;
    let dials = Counter::default();
    let _host_router = Router::builder(host_ep.clone())
        .accept(transport::ALPN, dials.clone())
        .accept(DIRECTORY_ALPN, dials.clone())
        .spawn();
    let admin_ep = f.admin_endpoint().await;

    let earlier = fetch::held_directories(&f.admin).unwrap();
    let edit = f.assign("orders-db", 1);
    let report = tokio::time::timeout(
        Duration::from_secs(2),
        fetch::publish_current_on(&admin_ep, &f.admin, &earlier),
    )
    .await
    .expect("the publish took over 2 s")
    .unwrap();
    assert_eq!(report.delivered, vec![f.nodes[0].node_id()]);
    assert!(report.missed.is_empty(), "{report:?}");
    assert_eq!(dir.dir.version(), edit.version());
    assert_eq!(dir.dir.accepted(), 1);
    // The directory keeps its own keystore's copy in step.
    let mirrored = store::read(&dir_ks, f.root.node_id()).unwrap().unwrap();
    assert_eq!(mirrored.version(), edit.version());
    assert_eq!(dials.0.load(Ordering::SeqCst), 0, "the admin dialed a host");

    // The host: `head` shows a newer version, so it fetches the policy.
    let fetched = fetch::check_once(&host_ep, &host_ks).await.unwrap();
    assert_eq!(fetched.map(|p| p.version()), Some(edit.version()));
    let held = store::read(&host_ks, f.root.node_id()).unwrap().unwrap();
    assert!(held.policy.assigns(
        &ServiceName::new("orders-db").unwrap(),
        f.nodes[1].node_id()
    ));
    // Current now: `head` says so, and nothing more is fetched.
    assert!(
        fetch::check_once(&host_ep, &host_ks)
            .await
            .unwrap()
            .is_none()
    );

    // A caller's cold fetch.
    let caller_ep = bind(&f.nodes[2], &f.book).await;
    let fetched = fetch::catch_up(&caller_ep, &caller_ks).await.unwrap();
    assert_eq!(fetched.map(|p| p.version()), Some(edit.version()));
    // Asked again, the directory vouches that it is current.
    assert!(
        fetch::catch_up(&caller_ep, &caller_ks)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!store::is_stale(&caller_ks, now_unix()));
    assert_eq!(dials.0.load(Ordering::SeqCst), 0);
    admin_ep.close().await;
    let _ = dir.endpoint;
}

/// A publish that reaches no directory is reported, and the admin's
/// command fails on it.
#[tokio::test]
async fn a_publish_that_reaches_no_directory_is_reported() {
    let f = Fabric::new(1);
    f.list_directory(0);
    // Known, but not listening.
    let _silent = bind(&f.nodes[0], &f.book).await;
    let admin_ep = f.admin_endpoint().await;
    f.assign("status", 0);
    let report = fetch::publish_current_on(&admin_ep, &f.admin, &Default::default())
        .await
        .unwrap();
    assert!(report.reached_none(), "{report:?}");
    admin_ep.close().await;
}

/// A directory restarted from `directory.redb` serves the same head, and a
/// new `Fresh`.
#[tokio::test]
async fn a_restarted_directory_serves_the_same_head_and_a_new_fresh() {
    let f = Fabric::new(1);
    f.list_directory(0);
    let ks = f.join(0);
    let now = now_unix();
    let edit = f.assign("status", 0);
    let (head, fresh) = {
        let dir = Directory::open(
            f.nodes[0].duplicate(),
            f.root.node_id(),
            Arc::clone(&ks),
            8,
            now,
        )
        .unwrap();
        assert!(dir.accept(&edit.signed, now).unwrap());
        let c = dir.snapshot().unwrap();
        (c.held.signed.head.clone(), c.fresh.clone().unwrap())
    };
    // `policy.json` is behind on purpose: the store alone must serve it.
    std::fs::remove_file(ks.path(store::POLICY_FILE)).unwrap();
    let later = now + 60;
    let dir = Directory::open(
        f.nodes[0].duplicate(),
        f.root.node_id(),
        Arc::clone(&ks),
        8,
        later,
    )
    .unwrap();
    let c = dir.snapshot().unwrap();
    assert_eq!(c.held.signed.head, head);
    let renewed = c.fresh.clone().unwrap();
    assert_ne!(renewed, fresh);
    assert_eq!(renewed.at, later);
    renewed.verify(&head).unwrap();
    // The answer to `head` carries it.
    let DirectoryAnswer::Head {
        head: served,
        fresh,
    } = dir.answer(f.admin_node.node_id(), DirectoryRequest::Head {}, later)
    else {
        panic!("expected a head");
    };
    assert_eq!((served, fresh), (head, renewed));
    // A beat signs yet another, and says so to subscribers.
    let changes = dir.watch();
    dir.beat(later + 300).unwrap();
    assert!(changes.has_changed().unwrap());
    assert_eq!(
        dir.snapshot().unwrap().fresh.clone().unwrap().at,
        later + 300
    );
}

/// A tampered item, items under another head, and an older head are each
/// refused (nothing stored changes).
#[tokio::test]
async fn tampered_mixed_and_older_policies_are_refused() {
    let f = Fabric::new(2);
    f.list_directory(0);
    let ks = f.join(0);
    let now = now_unix();
    let dir = Directory::open(
        f.nodes[0].duplicate(),
        f.root.node_id(),
        Arc::clone(&ks),
        8,
        now,
    )
    .unwrap();
    let v_old = f.assign("status", 1);
    let v_new = f.assign("orders-db", 1);
    assert!(dir.accept(&v_new.signed, now).unwrap());
    let held = dir.version();

    // A tampered item: the items no longer hash to the head's.
    let mut tampered = v_new.signed.clone();
    for item in &mut tampered.items {
        if let Item::Service(entry) = item {
            entry.service.hosts.push(f.nodes[0].node_id());
        }
    }
    let e = dir.accept(&tampered, now).unwrap_err();
    assert!(format!("{e:#}").contains("commits to"), "{e:#}");
    // Another head's items under a newer head's signature.
    let mixed = SignedPolicy {
        head: v_new.signed.head.clone(),
        items: v_old.signed.items.clone(),
    };
    assert!(dir.accept(&mixed, now).is_err());
    // A head whose version was bumped without the root signing it.
    let mut forged = v_new.signed.clone();
    forged.head.head.version = StateVersion(held.0 + 5);
    assert!(dir.accept(&forged, now).is_err());
    // An older head: verified, but not adopted.
    assert!(!dir.accept(&v_old.signed, now).unwrap());
    // Answered as a publish: the version held, not the one offered.
    let answer = dir.answer(
        f.admin_node.node_id(),
        DirectoryRequest::Publish {
            head: v_old.signed.head.clone(),
            items: v_old.signed.items.clone(),
        },
        now,
    );
    assert_eq!(answer, DirectoryAnswer::Published { version: held });
    assert!(matches!(
        dir.answer(
            f.admin_node.node_id(),
            DirectoryRequest::Publish {
                head: tampered.head,
                items: tampered.items,
            },
            now,
        ),
        DirectoryAnswer::Denied { .. }
    ));
    assert_eq!(dir.version(), held);
    assert_eq!(dir.accepted(), 1);
}

/// A directory the head doesn't list: it can't vouch, and a `Fresh` from its
/// key is refused by whoever fetches from it.
#[tokio::test]
async fn a_fresh_from_a_key_not_in_directories_is_refused() {
    let f = Fabric::new(2); // 0: listed directory, 1: a node that pretends
    f.list_directory(0);
    let caller_ks = f.join(1);
    let edit = f.assign("status", 0);
    let rogue = NodeIdentity::generate();
    // A rogue that answers every request with the newer policy and a
    // `Fresh` it signed itself (as if it were listed).
    let mut pretend = edit.policy.clone();
    pretend.directories.push(rogue.node_id());
    let pretend_head = crate::testutil::signed_policy(&f.root, pretend).head;
    let forged = Fresh::sign(&rogue, &pretend_head, now_unix(), now_unix() + 900).unwrap();
    forged.verify(&pretend_head).unwrap();
    assert!(
        forged.verify(&edit.signed.head).is_err(),
        "not listed in the real head"
    );
    #[derive(Debug, Clone)]
    struct Rogue(DirectoryAnswer);
    impl ProtocolHandler for Rogue {
        async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
            let (mut send, mut recv) = conn.accept_bi().await?;
            let _ = wire::read_request(&mut recv).await;
            let _ = wire::read_request(&mut recv).await;
            let _ = wire::write(&mut send, &self.0.encode().unwrap()).await;
            let _ = send.finish();
            let _ = tokio::time::timeout(Duration::from_secs(2), conn.closed()).await;
            Ok(())
        }
    }
    let rogue_ep = bind(&rogue, &f.book).await;
    let answer = DirectoryAnswer::Policy {
        policy: edit.signed.clone(),
        fresh: forged.clone(),
    };
    let _router = Router::builder(rogue_ep)
        .accept(DIRECTORY_ALPN, Rogue(answer))
        .spawn();
    let caller_ep = bind(&f.nodes[1], &f.book).await;
    let before = store::read(&caller_ks, f.root.node_id()).unwrap().unwrap();
    let got = fetch::fetch(&caller_ep, &caller_ks, &[rogue.node_id()])
        .await
        .unwrap();
    assert!(got.is_none());
    assert_eq!(
        store::read(&caller_ks, f.root.node_id()).unwrap().unwrap(),
        before,
        "adopted a policy vouched for by a stranger"
    );

    // A directory opened on an unlisted node signs nothing, and says so.
    let ks = f.join(1);
    let dir = Directory::open(f.nodes[1].duplicate(), f.root.node_id(), ks, 8, now_unix()).unwrap();
    assert!(dir.snapshot().unwrap().fresh.is_none());
    assert!(matches!(
        dir.answer(f.nodes[0].node_id(), DirectoryRequest::Head {}, now_unix()),
        DirectoryAnswer::Denied { .. }
    ));
}

/// Two directories following each other: a publish that reached only one
/// reaches the other through its replica subscription.
#[tokio::test]
async fn a_directory_that_missed_a_publish_catches_up_from_a_replica() {
    let f = Fabric::new(2);
    f.list_directory(0);
    f.list_directory(1);
    let (ks0, ks1) = (f.join(0), f.join(1));
    let d0 = f.directory(0, &ks0, true).await;
    let d1 = f.directory(1, &ks1, true).await;
    let before = d1.dir.version();
    let admin_ep = f.admin_endpoint().await;
    let edit = f.assign("status", 0);
    // Only directory 0 hears the admin.
    let report = fetch::publish_all(
        &admin_ep,
        &f.admin.read_membership().unwrap().unwrap(),
        &edit.signed,
        &[f.nodes[0].node_id()],
    )
    .await
    .unwrap();
    assert_eq!(report.delivered, vec![f.nodes[0].node_id()]);
    assert!(edit.version() > before);
    until_version(&d1.dir, edit.version()).await;
    assert_eq!(
        d1.dir.snapshot().unwrap().held.signed,
        d0.dir.snapshot().unwrap().held.signed
    );
    // Its own `Fresh` for the head it caught up to.
    let fresh = d1.dir.snapshot().unwrap().fresh.clone().unwrap();
    assert_eq!(fresh.directory, f.nodes[1].node_id());
    admin_ep.close().await;
}

/// Anyone without a badge from this root hears only "not a member", and a
/// banned node's badge admits it nowhere.
#[tokio::test]
async fn strangers_and_banned_nodes_hear_only_not_a_member() {
    let f = Fabric::new(2);
    f.list_directory(0);
    let ks = f.join(0);
    let d = f.directory(0, &ks, false).await;
    let stranger = NodeIdentity::generate();
    let other_root = NodeIdentity::generate();
    let stranger_ep = bind(&stranger, &f.book).await;
    let badge = Membership::mint(&other_root, stranger.node_id(), 0, i64::MAX).unwrap();
    let answer = wire::ask(
        &stranger_ep,
        f.nodes[0].node_id(),
        &badge,
        None,
        &DirectoryRequest::Head {},
    )
    .await
    .unwrap();
    assert_eq!(
        answer,
        DirectoryAnswer::Denied {
            reason: crate::host::gate::NOT_ADMITTED.into()
        }
    );
    // A member is answered; once banned, it isn't.
    let member_ep = bind(&f.nodes[1], &f.book).await;
    let badge = f.badge(&f.nodes[1]);
    let ask = || {
        wire::ask(
            &member_ep,
            f.nodes[0].node_id(),
            &badge,
            None,
            &DirectoryRequest::Head {},
        )
    };
    assert!(matches!(ask().await.unwrap(), DirectoryAnswer::Head { .. }));
    let mut banned = f.policy().policy;
    banned.version = StateVersion(banned.version.0 + 1);
    banned
        .bans
        .insert(f.nodes[1].node_id(), Ban { until: i64::MAX });
    assert!(
        d.dir
            .accept(&crate::testutil::signed_policy(&f.root, banned), now_unix())
            .unwrap()
    );
    assert_eq!(
        ask().await.unwrap(),
        DirectoryAnswer::Denied {
            reason: crate::host::gate::NOT_ADMITTED.into()
        }
    );
}

/// `wires directory serve` runs from a joined, listed node's keystore with
/// no `host.json`, and refuses the admin's keystore and an unlisted node.
#[test]
fn directory_serve_needs_a_listed_node_that_is_not_the_admin() {
    let f = Fabric::new(2);
    let Err(e) = open_standalone(Arc::clone(&f.admin), 8, now_unix()) else {
        panic!("expected a refusal");
    };
    assert!(format!("{e:#}").contains("root.seed"), "{e:#}");
    // Joined, but the policy it holds doesn't list it.
    let unlisted = f.join(1);
    let Err(e) = open_standalone(unlisted, 8, now_unix()) else {
        panic!("expected a refusal");
    };
    assert!(
        format!("{e:#}").contains("not one of the network's directories"),
        "{e:#}"
    );
    // Listed (and joined after): it runs.
    f.list_directory(0);
    let listed = f.join(0);
    let (dir, node, _) = open_standalone(listed, 8, now_unix()).unwrap();
    assert_eq!(node.node_id(), f.nodes[0].node_id());
    assert!(dir.snapshot().unwrap().fresh.is_some());
    // An empty keystore joined no network.
    let empty = Arc::new(Keystore::at(temp_dir()));
    empty.save_node(&NodeIdentity::generate()).unwrap();
    assert!(open_standalone(empty, 8, now_unix()).is_err());
}

/// The admin's edits of `directories`: listed nodes show up in the head
/// every node holds, and a removed node leaves it.
#[test]
fn directory_edits_are_head_edits() {
    let f = Fabric::new(2);
    f.list_directory(0);
    f.list_directory(1);
    assert_eq!(
        f.policy().directories(),
        &[f.nodes[0].node_id(), f.nodes[1].node_id()]
    );
    let out = super::edit_in(
        &f.admin,
        super::DirectoryCmd::Rm(super::DirectoryEditArgs {
            node: f.nodes[0].node_id().hex(),
            ttl: Ttl::default(),
        }),
    )
    .unwrap();
    assert!(out.contains("removed"), "{out}");
    assert_eq!(f.policy().directories(), &[f.nodes[1].node_id()]);
    // Removing a node (a ban) drops it from the directories too.
    crate::admin::invite::remove_in(
        &f.admin,
        crate::admin::invite::RemoveArgs {
            member: f.nodes[1].node_id().hex(),
            state_ttl: Ttl::default(),
        },
    )
    .unwrap();
    assert!(f.policy().directories().is_empty());
}

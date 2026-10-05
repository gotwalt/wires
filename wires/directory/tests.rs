//! Card 36b's acceptance, over hermetic loopback: the admin publishes to a
//! directory and never dials a host; a host fetches from it and a caller is
//! refused the whole policy; a restarted directory serves the same head with
//! a new `Fresh`; tampered, mixed and older policies and a stranger's `Fresh`
//! are refused; a directory that missed a publish catches up from a replica; and
//! `wires directory serve` refuses the admin's keystore and an unlisted node.
//! Card 41: a directory admits a node the policy names or a caller whose ID
//! token verifies, and anyone may publish, but only a root-signed newer head
//! makes it read the items; the first directory starts empty and takes the
//! first publish. Card 47: a caller is admitted only when a role matches it
//! (and its sign-in carries a verified email); callers' view subscriptions
//! have a pool of their own, capped per person, and end when the token
//! expires or the person is no longer admitted.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use iroh::Endpoint;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use library::{
    DIRECTORY_ALPN, DirectoryAnswer, DirectoryRequest, Fresh, IdToken, Item, NodeIdentity,
    ServiceName, SignedPolicy, StateVersion,
};

use super::node::{Directory, HeadCheck, Peer};
use super::serve::{Running, open_standalone};
use super::wire;
use crate::admin::init::{InitArgs, init_in};
use crate::admin::keystore::Keystore;
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

/// A network: the admin (initialized, trusting the test IdP too, with role
/// `member` for anyone at `example.com` it verifies), and `n` other nodes,
/// none joined yet.
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
        service::issuer_set(
            &admin,
            crate::testutil::test_idp().issuer.clone(),
            service::issuer_config(crate::caller::mock_idp::MOCK_CLIENT_ID, &[]).unwrap(),
            Ttl::default(),
        )
        .unwrap();
        service::role_set(
            &admin,
            library::RoleName::new("member").unwrap(),
            vec![library::Matcher {
                email: Some("*@example.com".parse().unwrap()),
                ..library::Matcher::new(crate::testutil::test_idp().issuer.as_str())
            }],
            Ttl::default(),
        )
        .unwrap();
        Fabric {
            admin,
            admin_node,
            root,
            nodes,
            book: MemoryLookup::new(),
        }
    }

    /// Node `i` joined (its key and the network string), holding the
    /// admin's policy now (as a host or directory that fetched it would).
    fn join(&self, i: usize) -> Arc<Keystore> {
        let ks = self.join_empty(i, &[]);
        store::adopt_if_newer(&ks, &self.policy().signed, self.root.node_id(), now_unix()).unwrap();
        ks
    }

    /// Node `i` joined with a network string naming `directories`, holding
    /// no policy.
    fn join_empty(&self, i: usize, directories: &[library::NodeId]) -> Arc<Keystore> {
        let ks = Arc::new(Keystore::at(temp_dir()));
        ks.save_node(&self.nodes[i]).unwrap();
        crate::testutil::join(&ks, &self.root, directories);
        ks
    }

    /// Node `i`'s ID token from the test IdP, bound to its key.
    fn token(&self, i: usize) -> Option<IdToken> {
        Some(crate::testutil::test_id_token(&self.nodes[i].node_id()))
    }

    /// Node `i`'s ID token for `who` (a verified email only when
    /// `with_email`), expiring at `exp`.
    fn token_for(&self, i: usize, who: &str, with_email: bool, exp: i64) -> Option<IdToken> {
        let nonce = library::OidcNonce::for_node(&self.nodes[i].node_id());
        Some(crate::testutil::test_idp().mint_for(who, with_email, &nonce, exp))
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
        self.directory_with(i, ks, replicate, None).await
    }

    /// [`directory`](Self::directory), with a shorter `stream_deadline`.
    async fn directory_with(
        &self,
        i: usize,
        ks: &Arc<Keystore>,
        replicate: bool,
        stream_deadline: Option<Duration>,
    ) -> Serving {
        self.directory_capped(i, ks, replicate, stream_deadline, 64)
            .await
    }

    /// [`directory_with`](Self::directory_with), each subscriber pool
    /// holding `max_subscribers`.
    async fn directory_capped(
        &self,
        i: usize,
        ks: &Arc<Keystore>,
        replicate: bool,
        stream_deadline: Option<Duration>,
        max_subscribers: usize,
    ) -> Serving {
        let node = &self.nodes[i];
        let mut dir = Directory::open(
            node.duplicate(),
            self.root.node_id(),
            Arc::clone(ks),
            max_subscribers,
            now_unix(),
        )
        .unwrap();
        if let Some(deadline) = stream_deadline {
            Arc::get_mut(&mut dir)
                .expect("no other handle yet")
                .stream_deadline = deadline;
        }
        let endpoint = bind(node, &self.book).await;
        let router = Running::mount(Router::builder(endpoint.clone()), &dir).spawn();
        let running = replicate.then(|| Running::start(Arc::clone(&dir), endpoint.clone()));
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

/// An admin edit reaches the directory, a host fetches it from there (a
/// caller is refused it), and nothing dials the host.
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

    // The host fetches the newer policy (`policy {have}`).
    let fetched = fetch::catch_up(&host_ep, &host_ks).await.unwrap();
    assert_eq!(fetched.map(|p| p.version()), Some(edit.version()));
    let held = store::read(&host_ks, f.root.node_id()).unwrap().unwrap();
    assert!(held.policy.assigns(
        &ServiceName::new("orders-db").unwrap(),
        f.nodes[1].node_id()
    ));
    // Current now: the directory says so, and nothing more is fetched.
    assert!(fetch::catch_up(&host_ep, &host_ks).await.unwrap().is_none());

    // Card 37: a caller (neither a host nor a directory) is refused the
    // whole policy: with no token it is not admitted at all, and signed in
    // it asks for its view instead.
    let caller_ep = bind(&f.nodes[2], &f.book).await;
    let before = store::read(&caller_ks, f.root.node_id())
        .unwrap()
        .unwrap()
        .version();
    assert!(
        fetch::catch_up(&caller_ep, &caller_ks)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store::read(&caller_ks, f.root.node_id())
            .unwrap()
            .unwrap()
            .version(),
        before,
        "the caller got no newer policy"
    );
    let policy = DirectoryRequest::Policy {
        have: StateVersion(0),
    };
    let answer = wire::ask(&caller_ep, f.nodes[0].node_id(), None, &policy)
        .await
        .unwrap();
    assert_eq!(
        answer,
        DirectoryAnswer::Denied {
            reason: crate::host::gate::NOT_ADMITTED.into()
        }
    );
    let answer = wire::ask(&caller_ep, f.nodes[0].node_id(), f.token(2), &policy)
        .await
        .unwrap();
    assert!(
        matches!(&answer, DirectoryAnswer::Denied { reason } if reason.contains("view")),
        "{answer:?}"
    );
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
    // A publish of that head is answered with it, read no further.
    let HeadCheck::Held {
        version,
        head: served,
    } = dir.check_head(&head, later)
    else {
        panic!("expected the held head");
    };
    assert_eq!((version, served), (edit.version(), head.hash().unwrap()));
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
    // Answered as a publish: the version held, not the one offered, and
    // its items never read.
    let held_hash = dir.snapshot().unwrap().held.signed.head.hash().unwrap();
    assert!(matches!(
        dir.check_head(&v_old.signed.head, now),
        HeadCheck::Held { version, head }
            if version == held && head == held_hash
    ));
    // A forged head is refused before any item is read.
    assert!(matches!(
        dir.check_head(&forged.head, now),
        HeadCheck::Refused(_)
    ));
    // Tampered items under a genuine newer head: read, and refused whole.
    let mut newer = v_new.signed.clone();
    let v_newer = f.assign("deploy", 1);
    newer.head = v_newer.signed.head.clone();
    assert!(matches!(
        dir.check_head(&newer.head, now),
        HeadCheck::Wanted
    ));
    assert!(matches!(
        dir.publish(f.admin_node.node_id(), newer.head, tampered.items, now),
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
    let host = Peer {
        node: f.nodes[0].node_id(),
        named: true,
        principal: None,
    };
    assert!(matches!(
        dir.answer(
            &host,
            DirectoryRequest::Policy {
                have: StateVersion(0)
            },
            now_unix()
        ),
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
    let report = fetch::publish_all(&admin_ep, &edit.signed, &[f.nodes[0].node_id()])
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

/// A node with no token that the policy doesn't name hears only "not
/// admitted" (it may publish, nothing more); a host the policy names is
/// answered, and once banned it isn't.
#[tokio::test]
async fn strangers_and_banned_nodes_hear_only_not_admitted() {
    let f = Fabric::new(2); // 0: directory, 1: host
    f.list_directory(0);
    f.assign("status", 1);
    let ks = f.join(0);
    let d = f.directory(0, &ks, false).await;
    let stranger = NodeIdentity::generate();
    let stranger_ep = bind(&stranger, &f.book).await;
    let policy = DirectoryRequest::Policy {
        have: StateVersion(0),
    };
    let not_admitted = DirectoryAnswer::Denied {
        reason: crate::host::gate::NOT_ADMITTED.into(),
    };
    for request in [
        policy.clone(),
        DirectoryRequest::Resolve {
            service: ServiceName::new("status").unwrap(),
        },
    ] {
        let answer = wire::ask(&stranger_ep, f.nodes[0].node_id(), None, &request)
            .await
            .unwrap();
        assert_eq!(answer, not_admitted);
    }
    // A token another key's sign-in minted: not this stranger's.
    let theirs = wire::ask(&stranger_ep, f.nodes[0].node_id(), f.token(1), &policy)
        .await
        .unwrap();
    assert_eq!(theirs, not_admitted);
    // The host is answered; once banned, it isn't.
    let host_ep = bind(&f.nodes[1], &f.book).await;
    let ask = || wire::ask(&host_ep, f.nodes[0].node_id(), None, &policy);
    assert!(matches!(
        ask().await.unwrap(),
        DirectoryAnswer::Policy { .. }
    ));
    let mut banned = f.policy().policy;
    banned.version = StateVersion(banned.version.0 + 1);
    banned.services.clear();
    banned.bans.insert(f.nodes[1].node_id());
    assert!(
        d.dir
            .accept(&crate::testutil::signed_policy(&f.root, banned), now_unix())
            .unwrap()
    );
    assert_eq!(ask().await.unwrap(), not_admitted);
}

/// Anyone may publish, but only a head the root signed, newer than the
/// held one, makes the directory read the items that follow: a forged head
/// is refused at once, with a (never sent) 16 MiB items frame announced.
#[tokio::test]
async fn only_a_root_signed_newer_head_makes_a_directory_read_the_items() {
    let f = Fabric::new(1);
    f.list_directory(0);
    let ks = f.join(0);
    let d = f.directory(0, &ks, false).await;
    let stranger = NodeIdentity::generate();
    let ep = bind(&stranger, &f.book).await;
    let rogue = NodeIdentity::generate();
    let mut forged = f.policy().policy;
    forged.fabric = rogue.node_id();
    forged.version = StateVersion(forged.version.0 + 1);
    let forged = forged.sign(&rogue).unwrap();
    let conn = dial(&ep, f.nodes[0].node_id(), DIRECTORY_ALPN).await;
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    for frame in [
        DirectoryRequest::Hello { id_token: None },
        DirectoryRequest::Publish { head: forged.head },
    ] {
        wire::write(&mut send, &frame.encode().unwrap())
            .await
            .unwrap();
    }
    // An items frame that announces 16 MiB, and nothing more.
    let prefix = (library::MAX_DIRECTORY_FRAME as u32).to_be_bytes();
    wire::write(&mut send, &prefix).await.unwrap();
    let answer = tokio::time::timeout(Duration::from_secs(3), wire::read_answer(&mut recv))
        .await
        .expect("the directory waited for the items of a forged head")
        .unwrap();
    assert!(
        matches!(&answer, DirectoryAnswer::Denied { reason } if reason.contains("does not verify")),
        "{answer:?}"
    );
    assert_eq!(d.dir.accepted(), 0);
    // The admin's genuine publish, from a node the policy doesn't name,
    // is taken.
    let admin_ep = f.admin_endpoint().await;
    let edit = f.assign("status", 0);
    let report = fetch::publish_current_on(&admin_ep, &f.admin, &Default::default())
        .await
        .unwrap();
    assert_eq!(report.delivered, vec![f.nodes[0].node_id()]);
    assert_eq!(d.dir.version(), edit.version());
    admin_ep.close().await;
}

/// The first directory starts empty: it holds no policy, admits nobody (no
/// issuer is trusted yet, no node is named) and answers everything but a
/// publish with what it waits for; the admin's first publish fills it, and it serves from then.
#[tokio::test]
async fn the_first_directory_starts_empty_and_takes_the_first_publish() {
    let f = Fabric::new(2); // 0: directory, 1: caller
    f.list_directory(0);
    let ks = f.join_empty(0, &[f.nodes[0].node_id()]);
    assert!(super::serve::listed(&ks, f.root.node_id(), f.nodes[0].node_id()).unwrap());
    let (dir, _) = open_standalone(Arc::clone(&ks), 8, now_unix()).unwrap();
    assert!(dir.snapshot().is_none(), "it starts empty");
    drop(dir);
    let d = f.directory(0, &ks, false).await;
    let caller_ep = bind(&f.nodes[1], &f.book).await;
    let view = DirectoryRequest::View {
        have: StateVersion(0),
        query: None,
        held: None,
    };
    let before = wire::ask(&caller_ep, f.nodes[0].node_id(), f.token(1), &view)
        .await
        .unwrap();
    assert_eq!(
        before,
        DirectoryAnswer::Denied {
            reason: super::node::EMPTY.into()
        }
    );
    let admin_ep = f.admin_endpoint().await;
    let report = fetch::publish_current_on(&admin_ep, &f.admin, &Default::default())
        .await
        .unwrap();
    assert_eq!(report.delivered, vec![f.nodes[0].node_id()]);
    assert_eq!(d.dir.version(), f.policy().version());
    let after = wire::ask(&caller_ep, f.nodes[0].node_id(), f.token(1), &view)
        .await
        .unwrap();
    assert!(matches!(after, DirectoryAnswer::View { .. }), "{after:?}");
    admin_ep.close().await;
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
    let (dir, node) = open_standalone(listed, 8, now_unix()).unwrap();
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
    crate::admin::remove::remove_in(
        &f.admin,
        crate::admin::remove::WhoArgs {
            who: f.nodes[1].node_id().hex(),
            issuer: None,
            policy_ttl: Ttl::default(),
        },
    )
    .unwrap();
    assert!(f.policy().directories().is_empty());
}

/// A beat never rolls back a publish accepted while it signs: what it
/// announces and vouches for is the newest head held.
#[test]
fn a_beat_never_rolls_back_a_concurrent_accept() {
    let f = Fabric::new(1);
    f.list_directory(0);
    let ks = f.join(0);
    let now = now_unix();
    let dir = Directory::open(f.nodes[0].duplicate(), f.root.node_id(), ks, 8, now).unwrap();
    let newer = f.assign("status", 0);
    // While the beat is between signing and announcing, a publish arrives
    // on another thread, given a moment to land if nothing holds it off.
    let (took_tx, took_rx) = std::sync::mpsc::channel();
    let accepter = Arc::clone(&dir);
    let candidate = newer.signed.clone();
    *dir.beat_hook.lock().unwrap() = Some(Box::new(move || {
        std::thread::spawn(move || {
            took_tx
                .send(accepter.accept(&candidate, now).unwrap())
                .unwrap();
        });
        std::thread::sleep(Duration::from_millis(300));
    }));
    dir.beat(now + 1).unwrap();
    assert!(
        took_rx.recv_timeout(PATIENCE).unwrap(),
        "the publish was taken"
    );
    assert_eq!(dir.version(), newer.version(), "the beat rolled it back");
    let c = dir.snapshot().unwrap();
    assert_eq!(c.held.signed, newer.signed);
    c.fresh.clone().unwrap().verify(&newer.signed.head).unwrap();
}

/// A raw connection from `ep` to directory `to` on `alpn`.
async fn dial(ep: &Endpoint, to: library::NodeId, alpn: &[u8]) -> Connection {
    let addr = transport::endpoint_addr(&to, &[], None).unwrap();
    tokio::time::timeout(PATIENCE, ep.connect(addr, alpn))
        .await
        .expect("dialing took too long")
        .unwrap()
}

/// Subscribe to directory `to` as `kind`, from `ep` presenting `id_token`:
/// the stream the frames arrive on.
async fn subscribe(
    ep: &Endpoint,
    to: library::NodeId,
    id_token: Option<IdToken>,
    kind: library::SubscriptionKind,
) -> (Connection, iroh::endpoint::RecvStream) {
    let conn = dial(ep, to, library::DIRECTORY_SUB_ALPN).await;
    let (mut send, recv) = conn.open_bi().await.unwrap();
    let hello = library::SubRequest::Hello { id_token };
    let sub = library::SubRequest::Subscribe {
        kind,
        have: StateVersion(0),
    };
    wire::write(&mut send, &hello.encode().unwrap())
        .await
        .unwrap();
    wire::write(&mut send, &sub.encode().unwrap())
        .await
        .unwrap();
    (conn, recv)
}

/// Read frames until the first `denied` (its reason), or `None` when the
/// stream ends without one; a few seconds at most.
async fn until_denied(recv: &mut iroh::endpoint::RecvStream) -> Option<String> {
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(frame) = wire::read_sub_frame(recv).await.unwrap() {
            if let library::SubFrame::Denied { reason } = frame {
                // Nothing follows a denied: the stream ends.
                assert!(wire::read_sub_frame(recv).await.unwrap().is_none());
                return Some(reason);
            }
        }
        None
    })
    .await
    .expect("the subscription went on")
}

/// The first frame of a subscription, which must not be `denied`.
async fn first_frame(recv: &mut iroh::endpoint::RecvStream) -> library::SubFrame {
    let frame = tokio::time::timeout(PATIENCE, wire::read_sub_frame(recv))
        .await
        .unwrap()
        .unwrap()
        .expect("a first frame");
    assert!(
        !matches!(frame, library::SubFrame::Denied { .. }),
        "{frame:?}"
    );
    frame
}

/// The policy `dir` holds with `edit` applied, at the next version,
/// root-signed.
fn next_policy(
    f: &Fabric,
    dir: &Directory,
    edit: impl FnOnce(&mut library::Policy),
) -> SignedPolicy {
    let mut p = dir.snapshot().unwrap().held.policy.clone();
    p.version = StateVersion(p.version.0 + 1);
    edit(&mut p);
    crate::testutil::signed_policy(&f.root, p)
}

/// A host's `policy` subscription ends with `denied` once a new head bans
/// it, or no longer names it as a host.
#[tokio::test]
async fn a_policy_subscription_ends_when_the_host_is_banned_or_unlisted() {
    use library::SubscriptionKind::Policy;
    let f = Fabric::new(2); // 0: directory, 1: host
    f.list_directory(0);
    f.assign("status", 1);
    let ks = f.join(0);
    let d = f.directory(0, &ks, false).await;
    let host = f.nodes[1].node_id();
    let ep = bind(&f.nodes[1], &f.book).await;

    let services = d.dir.snapshot().unwrap().held.policy.services.clone();

    // No longer a host: it holds its view, not the policy.
    let (_conn, mut recv) = subscribe(&ep, f.nodes[0].node_id(), None, Policy).await;
    first_frame(&mut recv).await;
    let unlisted = next_policy(&f, &d.dir, |p| p.services.clear());
    assert!(d.dir.accept(&unlisted, now_unix()).unwrap());
    let reason = until_denied(&mut recv).await.unwrap();
    assert!(reason.contains("view"), "{reason}");

    // A host again, then banned (which takes it off its services too).
    let relisted = next_policy(&f, &d.dir, |p| p.services = services);
    assert!(d.dir.accept(&relisted, now_unix()).unwrap());
    let (_conn, mut recv) = subscribe(&ep, f.nodes[0].node_id(), None, Policy).await;
    first_frame(&mut recv).await;
    let banned = next_policy(&f, &d.dir, |p| {
        p.services.clear();
        p.bans.insert(host);
    });
    assert!(d.dir.accept(&banned, now_unix()).unwrap());
    assert_eq!(
        until_denied(&mut recv).await.as_deref(),
        Some(crate::host::gate::NOT_ADMITTED)
    );
}

/// A caller's `view` subscription needs a token that verifies and a person
/// the policy admits; a new head that bans the caller's node or person, or
/// in which no role matches it any more, empties its view and ends the
/// subscription with `NOT_ADMITTED`; one that stops listing this directory
/// ends it with `denied` (it can no longer vouch).
#[tokio::test]
async fn a_view_subscription_ends_on_a_ban_and_when_the_directory_is_unlisted() {
    use library::SubscriptionKind::View;
    let f = Fabric::new(2); // 0: directory, 1: caller
    f.list_directory(0);
    let (staff, matchers) = crate::testutil::staff_role();
    service::role_set(&f.admin, staff.clone(), matchers, Ttl::default()).unwrap();
    service::add(
        &f.admin,
        ServiceName::new("status").unwrap(),
        ServiceEdit {
            allow: Some(vec![staff]),
            hosts: Some(vec![f.nodes[0].node_id()]),
            ..ServiceEdit::default()
        },
        Ttl::default(),
    )
    .unwrap();
    let ks = f.join(0);
    let d = f.directory(0, &ks, false).await;
    let caller = f.nodes[1].node_id();
    let ep = bind(&f.nodes[1], &f.book).await;

    // No token: refused at the hello.
    let (_conn, mut recv) = subscribe(&ep, f.nodes[0].node_id(), None, View).await;
    assert_eq!(
        until_denied(&mut recv).await.as_deref(),
        Some(crate::host::gate::NOT_ADMITTED)
    );

    let entries = |frame: &library::SubFrame| match frame {
        library::SubFrame::View { view, .. } => view.entries.len(),
        other => panic!("expected a view, got {other:?}"),
    };
    let status = ServiceName::new("status").unwrap();
    // An update that empties the view, then the fixed refusal ending it.
    let emptied_then_refused = async |recv: &mut iroh::endpoint::RecvStream| {
        let library::SubFrame::ViewUpdate { update, .. } = first_frame(recv).await else {
            panic!("expected a view update");
        };
        assert_eq!(update.removed, vec![status.clone()]);
        assert_eq!(
            until_denied(recv).await.as_deref(),
            Some(crate::host::gate::NOT_ADMITTED)
        );
    };
    let (_conn, mut recv) = subscribe(&ep, f.nodes[0].node_id(), f.token(1), View).await;
    assert_eq!(entries(&first_frame(&mut recv).await), 1);
    // The caller's node banned.
    let banned = next_policy(&f, &d.dir, |p| {
        p.bans.insert(caller);
    });
    assert!(d.dir.accept(&banned, now_unix()).unwrap());
    emptied_then_refused(&mut recv).await;
    // Restored, then the person banned: the same, from the same node.
    let restored = next_policy(&f, &d.dir, |p| {
        p.bans.remove(&caller);
    });
    assert!(d.dir.accept(&restored, now_unix()).unwrap());
    let (_conn, mut recv) = subscribe(&ep, f.nodes[0].node_id(), f.token(1), View).await;
    assert_eq!(entries(&first_frame(&mut recv).await), 1);
    let person = library::Person::new(
        crate::testutil::test_idp().issuer.clone(),
        "caller@example.com",
    );
    let banned_person = next_policy(&f, &d.dir, |p| {
        p.person_bans.insert(person.clone());
    });
    assert!(d.dir.accept(&banned_person, now_unix()).unwrap());
    emptied_then_refused(&mut recv).await;
    // Removed, they can't subscribe again.
    let (_conn, mut recv) = subscribe(&ep, f.nodes[0].node_id(), f.token(1), View).await;
    assert_eq!(
        until_denied(&mut recv).await.as_deref(),
        Some(crate::host::gate::NOT_ADMITTED)
    );
    // Restored, then no role matches any more: the same.
    let restored = next_policy(&f, &d.dir, |p| {
        p.person_bans.remove(&person);
    });
    assert!(d.dir.accept(&restored, now_unix()).unwrap());
    let (_conn, mut recv) = subscribe(&ep, f.nodes[0].node_id(), f.token(1), View).await;
    assert_eq!(entries(&first_frame(&mut recv).await), 1);
    let roleless = next_policy(&f, &d.dir, |p| {
        p.services.clear();
        p.roles.clear();
    });
    assert!(d.dir.accept(&roleless, now_unix()).unwrap());
    emptied_then_refused(&mut recv).await;
    // A role again; then the directory is unlisted.
    let services_again = next_policy(&f, &d.dir, |p| {
        let (staff, matchers) = crate::testutil::staff_role();
        p.roles.insert(staff.clone(), matchers);
        p.services.insert(
            status.clone(),
            library::Service {
                description: String::new(),
                allow: vec![staff],
                hosts: vec![f.nodes[0].node_id()],
            },
        );
    });
    assert!(d.dir.accept(&services_again, now_unix()).unwrap());
    let (_conn, mut recv) = subscribe(&ep, f.nodes[0].node_id(), f.token(1), View).await;
    assert_eq!(entries(&first_frame(&mut recv).await), 1);

    let me = f.nodes[0].node_id();
    let unlisted = next_policy(&f, &d.dir, |p| {
        p.directories.retain(|d| *d != me);
    });
    assert!(d.dir.accept(&unlisted, now_unix()).unwrap());
    let reason = until_denied(&mut recv).await.unwrap();
    assert!(reason.contains("no longer a directory"), "{reason}");
}

/// A `hello` is small: one that announces a publish-sized body is refused
/// from its prefix, before the directory reads (or waits for) the body.
#[tokio::test]
async fn a_large_hello_is_refused_before_its_body_is_read() {
    let f = Fabric::new(1);
    f.list_directory(0);
    let ks = f.join(0);
    let _d = f.directory(0, &ks, false).await;
    let stranger = NodeIdentity::generate();
    let ep = bind(&stranger, &f.book).await;
    for alpn in [DIRECTORY_ALPN, library::DIRECTORY_SUB_ALPN] {
        let conn = dial(&ep, f.nodes[0].node_id(), alpn).await;
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        // A 1 MiB frame that opens like a hello, and nothing more.
        let mut bytes = ((1usize << 20) as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(br#"{"type":"hello""#);
        wire::write(&mut send, &bytes).await.unwrap();
        let refused = tokio::time::timeout(Duration::from_secs(3), async {
            if alpn == DIRECTORY_ALPN {
                wire::read_answer(&mut recv).await.unwrap()
                    == DirectoryAnswer::Denied {
                        reason: crate::host::gate::NOT_ADMITTED.into(),
                    }
            } else {
                matches!(
                    wire::read_sub_frame(&mut recv).await.unwrap(),
                    Some(library::SubFrame::Denied { .. })
                )
            }
        })
        .await
        .expect("the directory waited for a 1 MiB hello");
        assert!(refused);
    }
}

/// Peers that connect and never open a stream give up their undecided
/// slots at the stream deadline, so they can't lock admitted callers out.
#[tokio::test]
async fn idle_connections_do_not_hold_the_undecided_slots() {
    let f = Fabric::new(2);
    f.list_directory(0);
    let ks = f.join(0);
    let deadline = Duration::from_millis(500);
    let _d = f.directory_with(0, &ks, false, Some(deadline)).await;
    let stranger = NodeIdentity::generate();
    let stranger_ep = bind(&stranger, &f.book).await;
    let mut idle = Vec::new();
    for _ in 0..super::node::MAX_UNDECIDED {
        idle.push(dial(&stranger_ep, f.nodes[0].node_id(), DIRECTORY_ALPN).await);
    }
    tokio::time::sleep(deadline * 3).await;
    let member_ep = bind(&f.nodes[1], &f.book).await;
    let answer = wire::ask(&member_ep, f.nodes[0].node_id(), f.token(1), &view())
        .await
        .unwrap();
    assert!(matches!(answer, DirectoryAnswer::View { .. }), "{answer:?}");
    drop(idle);
}

/// Once a peer is admitted it no longer holds an undecided slot: admitted
/// peers that stall their request can't lock out new connections.
#[tokio::test]
async fn admitted_peers_do_not_hold_the_undecided_slots() {
    let f = Fabric::new(2);
    f.list_directory(0);
    let ks = f.join(0);
    let _d = f.directory(0, &ks, false).await;
    let member_ep = bind(&f.nodes[1], &f.book).await;
    let hello = DirectoryRequest::Hello {
        id_token: f.token(1),
    }
    .encode()
    .unwrap();
    let mut stalled = Vec::new();
    for _ in 0..super::node::MAX_UNDECIDED {
        let conn = dial(&member_ep, f.nodes[0].node_id(), DIRECTORY_ALPN).await;
        let (mut send, recv) = conn.open_bi().await.unwrap();
        // The hello, then no request.
        wire::write(&mut send, &hello).await.unwrap();
        stalled.push((conn, send, recv));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let answer = tokio::time::timeout(
        Duration::from_secs(3),
        wire::ask(&member_ep, f.nodes[0].node_id(), f.token(1), &view()),
    )
    .await
    .expect("no answer in time")
    .unwrap();
    assert!(matches!(answer, DirectoryAnswer::View { .. }), "{answer:?}");
    drop(stalled);
}

/// A person the IdP verifies but no role names, and one whose sign-in
/// carries no verified email, hear the same `NOT_ADMITTED` bytes as a
/// stranger: for a view, a `resolve`, and a view subscription.
#[tokio::test]
async fn a_verified_token_no_role_matches_hears_not_admitted() {
    use library::SubscriptionKind::View;
    let f = Fabric::new(2); // 0: directory, 1: the outsider's machine
    f.list_directory(0);
    let ks = f.join(0);
    let _d = f.directory(0, &ks, false).await;
    let ep = bind(&f.nodes[1], &f.book).await;
    let dir = f.nodes[0].node_id();
    let exp = now_unix() + 3600;
    let not_admitted = DirectoryAnswer::Denied {
        reason: crate::host::gate::NOT_ADMITTED.into(),
    };
    let resolve = DirectoryRequest::Resolve {
        service: ServiceName::new("status").unwrap(),
    };
    for token in [
        f.token_for(1, "outsider@elsewhere.example", true, exp),
        f.token_for(1, "caller@example.com", false, exp),
    ] {
        for request in [view(), resolve.clone()] {
            let answer = wire::ask(&ep, dir, token.clone(), &request).await.unwrap();
            assert_eq!(answer, not_admitted);
        }
        let (_conn, mut recv) = subscribe(&ep, dir, token, View).await;
        assert_eq!(
            until_denied(&mut recv).await.as_deref(),
            Some(crate::host::gate::NOT_ADMITTED)
        );
    }
    // A member of `example.com` is admitted.
    let answer = wire::ask(&ep, dir, f.token(1), &view()).await.unwrap();
    assert!(matches!(answer, DirectoryAnswer::View { .. }), "{answer:?}");
}

/// Callers' view subscriptions can't stop a host subscribing: they have a
/// pool of their own. With all 4,096 view slots taken, a 4,097th view
/// subscription is refused, and a host's `policy` subscription is still
/// served.
#[tokio::test]
async fn view_subscriptions_cannot_stop_a_host_subscribing() {
    use super::node::DEFAULT_MAX_SUBSCRIBERS;
    use library::SubscriptionKind::{Policy, View};
    let f = Fabric::new(3); // 0: directory, 1: host, 2: caller
    f.list_directory(0);
    f.assign("status", 1);
    let ks = f.join(0);
    let d = f
        .directory_capped(0, &ks, false, None, DEFAULT_MAX_SUBSCRIBERS)
        .await;
    let dir = f.nodes[0].node_id();
    // 4,096 callers following their views.
    let _taken = Arc::clone(&d.dir.view_subscribers)
        .try_acquire_many_owned(DEFAULT_MAX_SUBSCRIBERS as u32)
        .unwrap();
    let caller_ep = bind(&f.nodes[2], &f.book).await;
    let (_conn, mut recv) = subscribe(&caller_ep, dir, f.token(2), View).await;
    let refused = until_denied(&mut recv).await.unwrap();
    assert!(refused.contains("subscriber cap (4096)"), "{refused}");
    // The host still subscribes.
    let host_ep = bind(&f.nodes[1], &f.book).await;
    let (_conn, mut recv) = subscribe(&host_ep, dir, None, Policy).await;
    assert!(matches!(
        first_frame(&mut recv).await,
        library::SubFrame::Policy { .. }
    ));
}

/// One person holds at most 16 view subscriptions on a directory at once;
/// the 17th is refused, and another person is unaffected.
#[tokio::test]
async fn view_subscriptions_are_capped_per_person() {
    use super::node::MAX_VIEW_SUBSCRIPTIONS_PER_PERSON;
    use library::SubscriptionKind::View;
    let f = Fabric::new(3); // 0: directory, 1 and 2: callers
    f.list_directory(0);
    let ks = f.join(0);
    let _d = f.directory(0, &ks, false).await;
    let dir = f.nodes[0].node_id();
    let ep = bind(&f.nodes[1], &f.book).await;
    let mut held = Vec::new();
    for _ in 0..MAX_VIEW_SUBSCRIPTIONS_PER_PERSON {
        let (conn, mut recv) = subscribe(&ep, dir, f.token(1), View).await;
        first_frame(&mut recv).await;
        held.push((conn, recv));
    }
    let (_conn, mut recv) = subscribe(&ep, dir, f.token(1), View).await;
    let refused = until_denied(&mut recv).await.unwrap();
    assert!(refused.contains("16 view subscriptions"), "{refused}");
    let exp = now_unix() + 3600;
    let other_ep = bind(&f.nodes[2], &f.book).await;
    let other = f.token_for(2, "someone@example.com", true, exp);
    let (_conn, mut recv) = subscribe(&other_ep, dir, other, View).await;
    first_frame(&mut recv).await;
    drop(held);
}

/// A view subscription ends when the ID token it opened with expires, with
/// the sign-in-expired sentence (the client subscribes again with a fresh
/// one).
#[tokio::test]
async fn a_view_subscription_ends_at_its_tokens_expiry() {
    use library::SubscriptionKind::View;
    let f = Fabric::new(2);
    f.list_directory(0);
    let ks = f.join(0);
    let _d = f.directory(0, &ks, false).await;
    let ep = bind(&f.nodes[1], &f.book).await;
    let soon = f.token_for(1, "caller@example.com", true, now_unix() + 2);
    let (_conn, mut recv) = subscribe(&ep, f.nodes[0].node_id(), soon, View).await;
    first_frame(&mut recv).await;
    assert_eq!(
        until_denied(&mut recv).await.as_deref(),
        Some(crate::host::gate::SIGN_IN_EXPIRED)
    );
}

/// A caller's whole view, from version 0.
fn view() -> DirectoryRequest {
    DirectoryRequest::View {
        have: StateVersion(0),
        query: None,
        held: None,
    }
}

/// Once its head's `not_after` passes, a directory vouches for nothing,
/// answers nobody and admits nobody under that policy (protocol.md §3: an
/// expired policy admits nobody and no directory serves it).
#[tokio::test]
async fn an_expired_policy_is_served_to_nobody_and_admits_nobody() {
    let f = Fabric::new(2); // 0: directory, 1: a caller
    f.list_directory(0);
    let ks = f.join(0);
    let now = now_unix();
    let dir = Directory::open(f.nodes[0].duplicate(), f.root.node_id(), ks, 8, now).unwrap();
    let short = next_policy(&f, &dir, |p| p.not_after = now + 30);
    assert!(dir.accept(&short, now).unwrap());
    let host = Peer {
        node: f.nodes[1].node_id(),
        named: true,
        principal: None,
    };
    let policy = || DirectoryRequest::Policy {
        have: StateVersion(0),
    };
    // Before it expires: served, and the caller is admitted.
    assert!(matches!(
        dir.answer(&host, policy(), now + 10),
        DirectoryAnswer::Policy { .. }
    ));
    let caller = f.nodes[1].node_id();
    let token = f.token(1);
    assert!(dir.admit(caller, token.as_ref(), now + 10).await.admitted());
    // After: no `Fresh`, no answer, no admission.
    let later = now + 60;
    dir.beat(later).unwrap();
    assert!(dir.snapshot().unwrap().fresh.is_none());
    assert!(matches!(
        dir.answer(&host, policy(), later),
        DirectoryAnswer::Denied { .. }
    ));
    assert!(!dir.admit(caller, token.as_ref(), later).await.admitted());
}

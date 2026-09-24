//! Card 26b's acceptance tests: **call records are read from the host that
//! holds them, by readers it authorizes, and verified on receipt**; with
//! card 28's §5: "mine" is the person, a following reader is re-decided,
//! and marks are kept per host.
//!
//! One host serves `orders-db` (analyst; readers: security) and `status`
//! (staff: anyone the three IdPs verified; readers: security), writing its
//! real call log. alice (analyst) calls, from two nodes; sam (security)
//! reads; bob (staff, no reader role) and a stranger try to. The readers run
//! the production `wires watch` core ([`watch_with`]) over loopback.
//!
//! - [`readers_see_all_callers_see_their_own_members_see_nothing`]: `--mine`,
//!   a late reader's backlog, bob's own refusal only, the stranger's fixed
//!   refusal, and resuming from the mark.
//! - [`pre_auth_readers_are_capped_in_size_and_number`]: an oversized `Open`
//!   and one undecided reader too many are refused before anything is read.
//! - [`mine_is_the_person_not_the_node`], [`a_reader_with_no_token_sees_nothing_in_full`]
//! - [`a_follower_gets_live_records`], [`a_removed_reader_stops_mid_stream`],
//!   [`a_reader_dropped_from_readers_goes_down_to_mine`]
//! - [`a_tampered_log_is_reported`]: a flipped byte in the host's file.
//! - [`a_rewrite_is_caught_across_a_view_change`], [`a_rollback_is_an_alarm`],
//!   [`retention_is_a_notice_not_an_alarm`]: the per-host anchor.

use std::sync::Arc;
use std::time::Duration;

use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr};
use library::{
    AuditRecord, ChainBreak, Hello, LogEntry, LogSeq, Membership, NodeId, NodeIdentity, Policy,
    RoleName, Service, SignedPolicy,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::{
    Outcome, PATIENCE, adopt, bind, email_at, host_config, localhost_socks, role, service,
    signed_state,
};
use crate::admin::keystore::Keystore;
use crate::caller::login::ID_TOKEN_FILE;
use crate::caller::mock_idp::MockIdp;
use crate::caller::pick::Hints;
use crate::caller::watch_records::{Output, Report, WatchOpts, text_line, watch_with};
use crate::host::call_log::{self, CallLog};
use crate::host::gate::NOT_ADMITTED;
use crate::host::serve::{services_host, services_router};
use crate::host::transport::endpoint_addr;

/// Root 1, host 10, alice 2 and 7 (analyst; one person, two nodes), bob 3,
/// sam 5 (security).
struct World {
    root: NodeIdentity,
    host: NodeIdentity,
    alice: NodeIdentity,
    alice2: NodeIdentity,
    bob: NodeIdentity,
    sam: NodeIdentity,
    idp_alice: MockIdp,
    idp_bob: MockIdp,
    idp_sam: MockIdp,
}

impl World {
    async fn new() -> Self {
        Self {
            root: NodeIdentity::from_seed([1u8; 32]),
            host: NodeIdentity::from_seed([10u8; 32]),
            alice: NodeIdentity::from_seed([2u8; 32]),
            alice2: NodeIdentity::from_seed([7u8; 32]),
            bob: NodeIdentity::from_seed([3u8; 32]),
            sam: NodeIdentity::from_seed([5u8; 32]),
            idp_alice: MockIdp::start("alice@example.com").await,
            idp_bob: MockIdp::start("bob@example.com").await,
            idp_sam: MockIdp::start("sam@example.com").await,
        }
    }

    fn state(&self) -> SignedPolicy {
        self.state_v(1, |_| {})
    }

    /// The policy at `version`, changed by `edit` before it is signed. It
    /// bans [`banned`].
    fn state_v(&self, version: u64, edit: impl FnOnce(&mut Policy)) -> SignedPolicy {
        signed_state(&self.root, version, |s| {
            s.ban(banned().node_id(), i64::MAX);
            s.roles.insert(
                role("analyst"),
                vec![email_at(&self.idp_alice, "alice@example.com")],
            );
            s.roles.insert(
                role("security"),
                vec![email_at(&self.idp_sam, "sam@example.com")],
            );
            s.roles.insert(
                role("staff"),
                [&self.idp_alice, &self.idp_bob, &self.idp_sam]
                    .iter()
                    .map(|idp| library::Matcher::new(idp.issuer.as_str()))
                    .collect(),
            );
            let on_host = |allow: Vec<RoleName>| Service {
                description: String::new(),
                allow,
                hosts: vec![self.host.node_id()],
                readers: vec![role("security")],
            };
            s.services
                .insert(service("orders-db"), on_host(vec![role("analyst")]));
            s.services
                .insert(service("status"), on_host(vec![role("staff")]));
            edit(s);
        })
    }

    fn idp(&self, who: &NodeIdentity) -> &MockIdp {
        if [self.alice.node_id(), self.alice2.node_id()].contains(&who.node_id()) {
            &self.idp_alice
        } else if who.node_id() == self.bob.node_id() {
            &self.idp_bob
        } else {
            &self.idp_sam
        }
    }

    fn membership(&self, who: &NodeIdentity) -> Membership {
        super::membership(&self.root, who)
    }

    fn hello(&self, who: &NodeIdentity) -> Hello {
        super::hello(&self.root, who, 1, Some(self.idp(who)))
    }

    /// A reader's keystore: key, membership, the signed policy, an ID token.
    fn reader(&self, who: &NodeIdentity) -> Keystore {
        let ks = Keystore::at(crate::testutil::temp_dir());
        ks.save_node(who).unwrap();
        ks.save_membership(&self.membership(who)).unwrap();
        // Card 37: a reader holds its view (what it may read, or call).
        let email = if self.idp(who).issuer == self.idp_alice.issuer {
            "alice@example.com"
        } else if who.node_id() == self.bob.node_id() {
            "bob@example.com"
        } else {
            "sam@example.com"
        };
        let who_is = super::person(self.idp(who), email);
        super::hold_view(&ks, &self.root, &self.state(), Some(&who_is));
        let token = self.hello(who).id_token.unwrap();
        std::fs::write(ks.path(ID_TOKEN_FILE), token.as_str()).unwrap();
        ks
    }
}

/// The running host: its router, address, keystore and call-log file.
struct Host {
    _router: Router,
    keystore: Arc<Keystore>,
    endpoint: Endpoint,
    addr: EndpointAddr,
    log: std::path::PathBuf,
}

const SERVICES: &str = r#"{
    "orders-db": { "command": ["echo", "rows:"] },
    "status": { "command": ["echo", "up"] }
}"#;

impl Host {
    async fn start(w: &World) -> Host {
        let keystore = Arc::new(Keystore::at(crate::testutil::temp_dir()));
        adopt(&keystore, &w.root, &w.state());
        let config = host_config(&[&w.idp_alice, &w.idp_bob, &w.idp_sam], SERVICES, "");
        let mut host = services_host(
            w.host.node_id(),
            w.membership(&w.host),
            Arc::clone(&keystore),
            config,
        )
        .unwrap();
        host.preflight(crate::clock::now_unix()).unwrap();
        // The call log exactly as `serve` opens it.
        let log = keystore.path(call_log::LOG_FILE);
        let opened =
            CallLog::open(&log, w.host.duplicate(), library::Retention::default()).unwrap();
        let (sink, _tee) = call_log::start(opened, None);
        host.audit = Some(sink);
        let endpoint = bind(&w.host).await;
        let addr = endpoint_addr(&w.host.node_id(), &localhost_socks(&endpoint), None).unwrap();
        let router = services_router(endpoint.clone(), Arc::new(host), None, None);
        Host {
            _router: router,
            keystore,
            endpoint,
            addr,
            log,
        }
    }

    /// Adopt `state` (as a fetch from a directory would): the next decision uses it.
    fn adopt(&self, w: &World, state: &SignedPolicy) {
        adopt(&self.keystore, &w.root, state);
    }

    /// Replace the stored log with `entries` (a host rewriting its history).
    fn replace_log(&self, entries: &[LogEntry]) {
        let text: String = entries
            .iter()
            .map(|e| format!("{}\n", serde_json::to_string(e).unwrap()))
            .collect();
        std::fs::write(&self.log, text).unwrap();
    }

    fn hints(&self, w: &World) -> Hints {
        Hints::from_pairs([(w.host.node_id(), localhost_socks(&self.endpoint))])
    }

    /// Wait until the call log holds `n` entries.
    async fn logged(&self, n: usize) {
        timeout(PATIENCE, async {
            while call_log::read(&self.log).unwrap().len() < n {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the call log never reached the expected length");
    }
}

/// `who` calls `name args` on the host ([`super::call`]); whether it ran.
/// A node every [`World`] policy bans (its badge is genuine).
fn banned() -> NodeIdentity {
    NodeIdentity::from_seed([66u8; 32])
}

async fn call(w: &World, who: &NodeIdentity, host: &Host, name: &str, args: &[&str]) -> bool {
    matches!(
        super::call(who, &host.addr, w.hello(who), name, args).await,
        Outcome::Ran { .. }
    )
}

/// Run one `wires watch --once` as the reader in `ks`: the report and every
/// output (records as their text lines, alarms prefixed `!`).
async fn watch_once(
    w: &World,
    who: &NodeIdentity,
    ks: &Keystore,
    host: &Host,
    services: &[&str],
    mine: bool,
) -> (Report, Vec<String>) {
    let endpoint = bind(who).await;
    let opts = WatchOpts {
        services: services.iter().map(|s| service(s)).collect(),
        mine,
        follow: false,
    };
    let mut lines = Vec::new();
    let mut out = |o: Output| match o {
        Output::Record(s) => lines.push(text_line(&s)),
        Output::Alarm(a) => lines.push(format!("! {a}")),
        Output::Notice(n) => lines.push(format!("! note: {n}")),
    };
    let report = timeout(
        PATIENCE,
        watch_with(ks, &endpoint, &host.hints(w), None, &opts, &mut out),
    )
    .await
    .expect("the watch timed out")
    .unwrap();
    endpoint.close().await;
    (report, lines)
}

fn records(lines: &[String]) -> Vec<&String> {
    lines.iter().filter(|l| !l.starts_with('!')).collect()
}

#[tokio::test]
async fn readers_see_all_callers_see_their_own_members_see_nothing() {
    let w = World::new().await;
    let host = Host::start(&w).await;

    // alice runs orders-db and status; bob is refused orders-db.
    assert!(call(&w, &w.alice, &host, "orders-db", &["select-1"]).await);
    assert!(call(&w, &w.alice, &host, "status", &[]).await);
    assert!(!call(&w, &w.bob, &host, "orders-db", &["drop"]).await);
    host.logged(5).await;

    // sam (security) starts late and gets the whole backlog.
    let sam = w.reader(&w.sam);
    let (report, lines) = watch_once(&w, &w.sam, &sam, &host, &[], false).await;
    assert!(
        report.broken.is_empty() && report.refused.is_empty(),
        "{report:?}"
    );
    let recs = records(&lines);
    assert_eq!(recs.len(), 5, "{lines:#?}");
    assert!(recs[0].contains("orders-db ▶") && recs[0].contains("alice@example.com"));
    assert!(recs[0].contains("select-1"), "{}", recs[0]);
    // The label is the reader's own, from the signed Started: its Finished
    // is labeled orders-db too.
    assert!(
        recs.iter()
            .any(|l| l.contains(" orders-db ■ ") && l.contains("exit 0")),
        "{lines:#?}"
    );
    assert!(
        recs.iter()
            .any(|l| l.contains("✗") && l.contains("orders-db denied"))
    );

    // alice --mine: her own four, not bob's refusal.
    let alice = w.reader(&w.alice);
    let (_, lines) = watch_once(&w, &w.alice, &alice, &host, &[], true).await;
    let recs = records(&lines);
    assert_eq!(recs.len(), 4, "{lines:#?}");
    assert!(recs.iter().all(|l| !l.contains("✗")));

    // bob, a member in no reader role: orders-db is not in his view (card
    // 37: he may neither call nor read it), so his refusal there, though
    // recorded, is not his to read; status is, and he never called it.
    let bob = w.reader(&w.bob);
    let (report, lines) = watch_once(&w, &w.bob, &bob, &host, &[], false).await;
    assert!(report.refused.is_empty());
    assert!(records(&lines).is_empty(), "{lines:#?}");
    // …and nothing at all of status, where he never called.
    let bob2 = w.reader(&w.bob);
    let (_, lines) = watch_once(&w, &w.bob, &bob2, &host, &["status"], false).await;
    assert!(records(&lines).is_empty(), "{lines:#?}");

    // A banned node (its badge is genuine) is refused outright.
    let stranger = banned();
    let ks = w.reader(&stranger);
    let (report, lines) = watch_once(&w, &stranger, &ks, &host, &[], false).await;
    assert_eq!(report.refused.len(), 1, "{lines:#?}");
    assert!(records(&lines).is_empty());
    assert_eq!(report.refused[0].1, NOT_ADMITTED, "{report:?}");

    // sam again: resumes from his mark, so only what is new.
    let (_, lines) = watch_once(&w, &w.sam, &sam, &host, &[], false).await;
    assert!(records(&lines).is_empty(), "{lines:#?}");
    assert!(call(&w, &w.alice, &host, "orders-db", &["select-2"]).await);
    host.logged(7).await;
    let (_, lines) = watch_once(&w, &w.sam, &sam, &host, &[], false).await;
    let recs = records(&lines);
    assert_eq!(recs.len(), 2, "{lines:#?}");
    assert!(recs[0].contains("select-2"));
}

/// Card 28 §9: before the host knows who is reading, an `Open` over
/// [`MAX_OPEN_FRAME`] is refused from its length prefix (not waited for),
/// and at most [`MAX_PREAUTH_READERS`] readers may be undecided at once;
/// a member decided later is served as usual.
#[tokio::test]
async fn pre_auth_readers_are_capped_in_size_and_number() {
    use crate::host::record_stream::{
        ALPN as RECORDS_ALPN, MAX_OPEN_FRAME, MAX_PREAUTH_READERS, read_frame as read_record,
    };
    let w = World::new().await;
    let host = Host::start(&w).await;
    let stranger = NodeIdentity::from_seed([66u8; 32]);
    let dialer = bind(&stranger).await;

    // A prefix one byte over the cap, and the stream held open: the host
    // closes it at once rather than wait out the open timeout for the body.
    let conn = dialer
        .connect(host.addr.clone(), RECORDS_ALPN)
        .await
        .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&((MAX_OPEN_FRAME + 1) as u32).to_be_bytes())
        .await
        .unwrap();
    let answered = timeout(Duration::from_secs(3), read_record(&mut recv))
        .await
        .expect("refused from the prefix, not after the open timeout");
    assert!(
        matches!(answered, Ok(None) | Err(_)),
        "nothing is granted: {answered:?}"
    );
    conn.close(0u32.into(), b"done");

    // MAX_PREAUTH_READERS undecided readers (each sent one byte of a
    // prefix), then one more: closed unanswered.
    let mut held = Vec::new();
    for _ in 0..MAX_PREAUTH_READERS {
        let conn = dialer
            .connect(host.addr.clone(), RECORDS_ALPN)
            .await
            .unwrap();
        let (mut send, recv) = conn.open_bi().await.unwrap();
        send.write_all(&[0]).await.unwrap();
        held.push((conn, send, recv));
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let conn = dialer
        .connect(host.addr.clone(), RECORDS_ALPN)
        .await
        .unwrap();
    let closed = timeout(PATIENCE, conn.closed()).await.expect("closed");
    assert!(format!("{closed:?}").contains("busy"), "{closed:?}");

    // Once they go, a member is served again.
    for (conn, ..) in held.drain(..) {
        conn.close(0u32.into(), b"done");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let sam = w.reader(&w.sam);
    let (report, _) = watch_once(&w, &w.sam, &sam, &host, &[], false).await;
    assert!(
        report.refused.is_empty() && report.failed.is_empty(),
        "{report:?}"
    );
    dialer.close().await;
}

#[tokio::test]
async fn a_follower_gets_live_records() {
    let w = World::new().await;
    let host = Host::start(&w).await;
    let sam = w.reader(&w.sam);
    let endpoint = bind(&w.sam).await;
    let hints = host.hints(&w);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let watcher = tokio::spawn(async move {
        let opts = WatchOpts {
            services: vec![service("orders-db")],
            mine: false,
            follow: true,
        };
        let mut out = |o: Output| {
            let _ = tx.send(o);
        };
        watch_with(&sam, &endpoint, &hints, None, &opts, &mut out).await
    });
    assert!(call(&w, &w.alice, &host, "orders-db", &["live"]).await);
    let first = timeout(PATIENCE, rx.recv()).await.unwrap().unwrap();
    match first {
        Output::Record(s) => match &s.entry.record {
            AuditRecord::Started { argv, .. } => assert_eq!(argv.as_slice(), ["live"]),
            other => panic!("expected started, got {other:?}"),
        },
        other => panic!("expected a record, got {other:?}"),
    }
    watcher.abort();
}

#[tokio::test]
async fn a_tampered_log_is_reported() {
    let w = World::new().await;
    let host = Host::start(&w).await;
    assert!(call(&w, &w.alice, &host, "orders-db", &["select-1"]).await);
    assert!(call(&w, &w.alice, &host, "orders-db", &["select-2"]).await);
    host.logged(4).await;

    // Flip one byte of the stored log: alice's first argument.
    let text = std::fs::read_to_string(&host.log).unwrap();
    assert!(text.contains("select-1"));
    std::fs::write(&host.log, text.replacen("select-1", "select-9", 1)).unwrap();

    // sam sees the entry itself and reports it.
    let sam = w.reader(&w.sam);
    let (report, lines) = watch_once(&w, &w.sam, &sam, &host, &[], false).await;
    assert_eq!(
        report.broken,
        vec![(
            w.host.node_id(),
            ChainBreak::BadSignature {
                seq: library::LogSeq(0)
            }
        )],
        "{lines:#?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("ALERT") && l.contains("does not verify"))
    );
    assert!(
        records(&lines).is_empty(),
        "nothing after a break is shown: {lines:#?}"
    );

    // bob can't see the entry, but its hash no longer links: reported too.
    let bob = w.reader(&w.bob);
    let (report, _) = watch_once(&w, &w.bob, &bob, &host, &[], false).await;
    assert_eq!(report.broken.len(), 1, "{report:?}");
    assert!(
        matches!(report.broken[0].1, ChainBreak::BrokenLink { .. }),
        "{report:?}"
    );
}

/// Start `wires watch` (following) as `who` over `services`: its outputs,
/// and the task (which ends when every host's stream has).
fn follow(
    w: &World,
    who: &NodeIdentity,
    ks: Keystore,
    host: &Host,
    services: &[&str],
) -> (
    tokio::task::JoinHandle<Report>,
    mpsc::UnboundedReceiver<Output>,
) {
    let hints = host.hints(w);
    let who = who.duplicate();
    let opts = WatchOpts {
        services: services.iter().map(|s| service(s)).collect(),
        mine: false,
        follow: true,
    };
    let (tx, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let endpoint = bind(&who).await;
        let mut out = |o: Output| {
            let _ = tx.send(o);
        };
        let report = watch_with(&ks, &endpoint, &hints, None, &opts, &mut out)
            .await
            .unwrap();
        endpoint.close().await;
        report
    });
    (task, rx)
}

/// The next output, within [`PATIENCE`].
async fn next(rx: &mut mpsc::UnboundedReceiver<Output>) -> Output {
    timeout(PATIENCE, rx.recv())
        .await
        .expect("no output in time")
        .expect("the watch ended")
}

/// The caller node of a `Started` output.
fn started_by(o: &Output) -> NodeId {
    match o {
        Output::Record(s) => match &s.entry.record {
            AuditRecord::Started { caller, .. } => *caller,
            other => panic!("expected started, got {other:?}"),
        },
        other => panic!("expected a record, got {other:?}"),
    }
}

/// Skip a following watch's outputs up to the next `Started`.
async fn next_started(rx: &mut mpsc::UnboundedReceiver<Output>) -> Output {
    loop {
        let o = next(rx).await;
        if let Output::Record(s) = &o
            && !matches!(s.entry.record, AuditRecord::Started { .. })
        {
            continue;
        }
        return o;
    }
}

/// "Mine" is the verified person: alice's second node sees what her first
/// node ran; bob, another person, doesn't.
#[tokio::test]
async fn mine_is_the_person_not_the_node() {
    let w = World::new().await;
    let host = Host::start(&w).await;
    assert!(call(&w, &w.alice, &host, "orders-db", &["from-node-2"]).await);
    assert!(call(&w, &w.bob, &host, "status", &[]).await);
    host.logged(4).await;

    let alice2 = w.reader(&w.alice2);
    let (report, lines) = watch_once(&w, &w.alice2, &alice2, &host, &[], false).await;
    assert!(report.refused.is_empty(), "{report:?}");
    let recs = records(&lines);
    assert_eq!(recs.len(), 2, "{lines:#?}");
    assert!(recs[0].contains("from-node-2") && recs[0].contains("alice@example.com"));

    // bob sees his own status call, none of alice's: orders-db is not even
    // in his view (card 37).
    let bob = w.reader(&w.bob);
    let (_, lines) = watch_once(&w, &w.bob, &bob, &host, &["status"], false).await;
    let recs = records(&lines);
    assert_eq!(recs.len(), 2, "{lines:#?}");
    assert!(
        recs.iter()
            .all(|l| l.contains("bob@example.com") || l.contains("exit 0"))
    );
    assert!(recs.iter().all(|l| !l.contains("from-node-2")));
}

/// A reader with no verified principal sees nothing in full, not even what
/// its own node ran; it isn't refused (it may still check the chain).
#[tokio::test]
async fn a_reader_with_no_token_sees_nothing_in_full() {
    let w = World::new().await;
    let host = Host::start(&w).await;
    assert!(call(&w, &w.sam, &host, "status", &[]).await);
    host.logged(2).await;
    let sam = w.reader(&w.sam);
    std::fs::remove_file(sam.path(ID_TOKEN_FILE)).unwrap();
    let (report, lines) = watch_once(&w, &w.sam, &sam, &host, &[], false).await;
    assert!(
        report.refused.is_empty() && report.broken.is_empty(),
        "{report:?}"
    );
    assert!(records(&lines).is_empty(), "{lines:#?}");
}

/// A following reader removed from the network (banned) is refused
/// mid-stream and gets nothing logged after the removal.
#[tokio::test]
async fn a_removed_reader_stops_mid_stream() {
    let w = World::new().await;
    let host = Host::start(&w).await;
    let (task, mut rx) = follow(&w, &w.sam, w.reader(&w.sam), &host, &["orders-db"]);
    assert!(call(&w, &w.alice, &host, "orders-db", &["before"]).await);
    assert_eq!(started_by(&next(&mut rx).await), w.alice.node_id());

    let sam = w.sam.node_id();
    host.adopt(
        &w,
        &w.state_v(2, |s| {
            s.ban(sam, i64::MAX);
        }),
    );
    assert!(call(&w, &w.alice, &host, "orders-db", &["after"]).await);
    let report = timeout(PATIENCE, task)
        .await
        .expect("the stream was not closed")
        .unwrap();
    let mut rest = Vec::new();
    while let Ok(o) = rx.try_recv() {
        rest.push(o);
    }
    assert!(
        rest.iter().all(|o| match o {
            Output::Record(s) => !format!("{:?}", s.entry.record).contains("after"),
            _ => true,
        }),
        "{rest:#?}"
    );
    assert_eq!(
        report.refused,
        vec![(w.host.node_id(), NOT_ADMITTED.to_string())],
        "{rest:#?}"
    );
}

/// A following reader dropped from a service's `readers` goes down to its
/// own records: another caller's next call is hidden, its own is shown.
#[tokio::test]
async fn a_reader_dropped_from_readers_goes_down_to_mine() {
    let w = World::new().await;
    let host = Host::start(&w).await;
    let (task, mut rx) = follow(&w, &w.sam, w.reader(&w.sam), &host, &["status"]);
    assert!(call(&w, &w.alice, &host, "status", &["as-reader"]).await);
    assert_eq!(started_by(&next_started(&mut rx).await), w.alice.node_id());

    host.adopt(
        &w,
        &w.state_v(2, |s| {
            s.services
                .get_mut(&service("status"))
                .unwrap()
                .readers
                .clear();
        }),
    );
    assert!(call(&w, &w.alice, &host, "status", &["hidden-now"]).await);
    assert!(call(&w, &w.sam, &host, "status", &["own"]).await);
    assert_eq!(started_by(&next_started(&mut rx).await), w.sam.node_id());
    task.abort();
}

/// Rewrite the host's log from entry `at` on, re-signed with the host's key
/// so it is consistent in itself: `edit` changes that entry's record.
fn rewrite(
    w: &World,
    entries: &[LogEntry],
    at: usize,
    edit: impl FnOnce(&mut AuditRecord),
) -> Vec<LogEntry> {
    let mut out: Vec<LogEntry> = entries[..at].to_vec();
    let mut edit = Some(edit);
    for e in &entries[at..] {
        let mut r = e.record.clone();
        if let Some(edit) = edit.take() {
            edit(&mut r);
        }
        let tip = out.last().map(|e| e.point().unwrap());
        out.push(LogEntry::next(&w.host, tip, e.at_ms, r).unwrap());
    }
    out
}

/// Marks are per host: a view the reader never used before (`watch
/// orders-db` after `watch`) still checks the host's log against the anchor
/// the other view left, and catches a rewrite that is consistent in itself,
/// showing nothing from it.
#[tokio::test]
async fn a_rewrite_is_caught_across_a_view_change() {
    let w = World::new().await;
    let host = Host::start(&w).await;
    assert!(call(&w, &w.alice, &host, "orders-db", &["select-1"]).await);
    assert!(call(&w, &w.alice, &host, "orders-db", &["select-2"]).await);
    host.logged(4).await;
    let sam = w.reader(&w.sam);
    let (report, _) = watch_once(&w, &w.sam, &sam, &host, &[], false).await;
    assert!(report.broken.is_empty(), "{report:?}");

    let entries = call_log::read(&host.log).unwrap();
    host.replace_log(&rewrite(&w, &entries, 0, |r| {
        if let AuditRecord::Started { argv, .. } = r {
            *argv = library::Argv::new(vec!["select-9".into()]).unwrap();
        }
    }));
    let (report, lines) = watch_once(&w, &w.sam, &sam, &host, &["orders-db"], false).await;
    assert_eq!(
        report.broken,
        vec![(w.host.node_id(), ChainBreak::Fork { seq: LogSeq(3) })],
        "{lines:#?}"
    );
    assert!(records(&lines).is_empty(), "{lines:#?}");
}

/// A log cut back below what the reader verified is a rollback: an alarm.
#[tokio::test]
async fn a_rollback_is_an_alarm() {
    let w = World::new().await;
    let host = Host::start(&w).await;
    assert!(call(&w, &w.alice, &host, "orders-db", &["select-1"]).await);
    assert!(call(&w, &w.alice, &host, "orders-db", &["select-2"]).await);
    host.logged(4).await;
    let sam = w.reader(&w.sam);
    watch_once(&w, &w.sam, &sam, &host, &[], false).await;

    let entries = call_log::read(&host.log).unwrap();
    host.replace_log(&entries[..2]);
    let (report, lines) = watch_once(&w, &w.sam, &sam, &host, &[], false).await;
    assert_eq!(
        report.broken,
        vec![(w.host.node_id(), ChainBreak::RolledBack { seq: LogSeq(3) })],
        "{lines:#?}"
    );
    assert!(lines.iter().any(|l| l.contains("ALERT")), "{lines:#?}");
}

/// Entries pruned from the front past the reader's anchor are retention: a
/// notice, no alarm, and the records still held are shown and verified.
#[tokio::test]
async fn retention_is_a_notice_not_an_alarm() {
    let w = World::new().await;
    let host = Host::start(&w).await;
    for arg in ["one", "two", "three"] {
        assert!(call(&w, &w.alice, &host, "orders-db", &[arg]).await);
    }
    host.logged(6).await;
    let sam = w.reader(&w.sam);
    watch_once(&w, &w.sam, &sam, &host, &[], false).await;
    for arg in ["four", "five"] {
        assert!(call(&w, &w.alice, &host, "orders-db", &[arg]).await);
    }
    host.logged(10).await;

    // What `CallLog::prune` leaves: the newest entries, from seq 8.
    let entries = call_log::read(&host.log).unwrap();
    host.replace_log(&entries[8..]);
    let (report, lines) = watch_once(&w, &w.sam, &sam, &host, &[], false).await;
    assert!(report.broken.is_empty(), "{lines:#?}");
    assert_eq!(report.pruned, vec![(w.host.node_id(), LogSeq(8))]);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("pruned entries before seq 8") && !l.contains("ALERT")),
        "{lines:#?}"
    );
    let recs = records(&lines);
    assert_eq!(recs.len(), 2, "{lines:#?}");
    assert!(recs[0].contains("five"));

    // The anchor now stands on what is held: no notice the next time.
    let (report, _) = watch_once(&w, &w.sam, &sam, &host, &[], false).await;
    assert!(
        report.pruned.is_empty() && report.broken.is_empty(),
        "{report:?}"
    );
}

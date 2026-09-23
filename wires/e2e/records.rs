//! Card 26b's acceptance tests: **call records are read from the host that
//! holds them, by readers it authorizes, and verified on receipt**.
//!
//! One v2 host serves `orders-db` (analyst; readers: security) and `status`
//! (member; readers: security), writing its real call log. alice (analyst)
//! calls; sam (security) reads; bob (a member, no reader role) and a stranger
//! try to. The readers run the production `wires watch` core
//! ([`watch_with`]) over loopback.
//!
//! - [`readers_see_all_callers_see_their_own_members_see_nothing`]: `--mine`,
//!   a late reader's backlog, bob's zero records, the stranger's refusal, and
//!   resuming from the mark.
//! - [`a_follower_gets_live_records`]
//! - [`a_tampered_log_is_reported`]: a flipped byte in the host's file.

use std::sync::Arc;
use std::time::Duration;

use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr};
use library::{
    AuditRecord, ChainBreak, Frame, Hello, Invocation, Matcher, Membership, NodeId, NodeIdentity,
    OidcNonce, RoleName, Service, ServiceName, SignedState, State, StateVersion, ToolName,
};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::{PATIENCE, localhost_socks};
use crate::admin::keystore::Keystore;
use crate::caller::login::ID_TOKEN_FILE;
use crate::caller::mock_idp::{MOCK_CLIENT_ID, MockIdp};
use crate::caller::pick::Hints;
use crate::caller::watch_records::{Output, Report, WatchOpts, text_line, watch_with};
use crate::host::call_log::{self, CallLog};
use crate::host::config_v2::HostConfigV2;
use crate::host::serve::{services_host, services_router};
use crate::host::transport::{ALPN, endpoint_addr, secret_key};

/// Root 1, host 10, alice 2 (analyst), bob 3, sam 5 (security).
struct World {
    root: NodeIdentity,
    host: NodeIdentity,
    alice: NodeIdentity,
    bob: NodeIdentity,
    sam: NodeIdentity,
    idp_alice: MockIdp,
    idp_bob: MockIdp,
    idp_sam: MockIdp,
}

fn role(s: &str) -> RoleName {
    RoleName::new(s).unwrap()
}

fn service(s: &str) -> ServiceName {
    ServiceName::new(s).unwrap()
}

impl World {
    async fn new() -> Self {
        Self {
            root: NodeIdentity::from_seed([1u8; 32]),
            host: NodeIdentity::from_seed([10u8; 32]),
            alice: NodeIdentity::from_seed([2u8; 32]),
            bob: NodeIdentity::from_seed([3u8; 32]),
            sam: NodeIdentity::from_seed([5u8; 32]),
            idp_alice: MockIdp::start("alice@example.com").await,
            idp_bob: MockIdp::start("bob@example.com").await,
            idp_sam: MockIdp::start("sam@example.com").await,
        }
    }

    fn state(&self) -> SignedState {
        let mut s = State::new(self.root.node_id());
        s.version = StateVersion(1);
        s.issued = crate::now_unix();
        s.not_after = i64::MAX;
        for n in [&self.host, &self.alice, &self.bob, &self.sam] {
            s.members.insert(n.node_id());
        }
        s.hosts.insert(self.host.node_id());
        let email = |e: &str| Matcher {
            email: Some(e.parse().unwrap()),
            ..Default::default()
        };
        s.roles
            .insert(role("analyst"), vec![email("alice@example.com")]);
        s.roles
            .insert(role("security"), vec![email("sam@example.com")]);
        let on_host = |allow: Vec<RoleName>| Service {
            description: String::new(),
            allow,
            hosts: vec![self.host.node_id()],
            readers: vec![role("security")],
        };
        s.services
            .insert(service("orders-db"), on_host(vec![role("analyst")]));
        s.services
            .insert(service("status"), on_host(vec![RoleName::member()]));
        s.sign(&self.root).unwrap()
    }

    fn idp(&self, who: &NodeIdentity) -> &MockIdp {
        if who.node_id() == self.alice.node_id() {
            &self.idp_alice
        } else if who.node_id() == self.bob.node_id() {
            &self.idp_bob
        } else {
            &self.idp_sam
        }
    }

    fn membership(&self, who: &NodeIdentity) -> Membership {
        Membership::mint(&self.root, who.node_id(), 0, i64::MAX).unwrap()
    }

    fn hello(&self, who: &NodeIdentity) -> Hello {
        Hello {
            membership: self.membership(who),
            state_version: StateVersion(1),
            id_token: Some(self.idp(who).mint(
                &OidcNonce::for_node(&who.node_id()),
                crate::now_unix() + 3600,
            )),
        }
    }

    /// A reader's keystore: key, membership, the signed state, an ID token.
    fn reader(&self, who: &NodeIdentity) -> Keystore {
        let ks = Keystore::at(crate::testutil::temp_dir());
        ks.save_node(who, true).unwrap();
        ks.save_membership(&self.membership(who)).unwrap();
        crate::state::store::adopt_if_newer(
            &ks,
            &self.state(),
            self.root.node_id(),
            crate::now_unix(),
        )
        .unwrap();
        let token = self.hello(who).id_token.unwrap();
        std::fs::write(ks.path(ID_TOKEN_FILE), token.as_str()).unwrap();
        ks
    }
}

/// The running host: its router, address, and call-log file.
struct Host {
    _router: Router,
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
        let home = crate::testutil::temp_dir();
        let keystore = Arc::new(Keystore::at(home.clone()));
        crate::state::store::adopt_if_newer(
            &keystore,
            &w.state(),
            w.root.node_id(),
            crate::now_unix(),
        )
        .unwrap();
        let issuers: Vec<String> = [&w.idp_alice, &w.idp_bob, &w.idp_sam]
            .iter()
            .map(|idp| {
                format!(
                    r#"{{"issuer":"{}","audiences":["{MOCK_CLIENT_ID}"]}}"#,
                    idp.issuer.as_str()
                )
            })
            .collect();
        let config = HostConfigV2::parse(&format!(
            r#"{{"version":2,"identity":{{"issuers":[{}]}},"services":{SERVICES}}}"#,
            issuers.join(",")
        ))
        .unwrap();
        let mut host = services_host(
            w.host.node_id(),
            w.membership(&w.host),
            Arc::clone(&keystore),
            &home,
            config,
        )
        .unwrap();
        host.preflight(crate::now_unix()).unwrap();
        // The call log exactly as `serve` opens it.
        let log = keystore.path(call_log::LOG_FILE);
        let opened = CallLog::open(
            &log,
            NodeIdentity::from_seed(w.host.seed_bytes()),
            library::Retention::default(),
        )
        .unwrap();
        let (sink, _, _tee) = call_log::start(opened, None, false);
        host.audit = Some(sink);
        let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(secret_key(&w.host))
            .bind()
            .await
            .unwrap();
        let addr = endpoint_addr(&w.host.node_id(), &localhost_socks(&endpoint), None).unwrap();
        let router = services_router(endpoint.clone(), Arc::new(host), None);
        Host {
            _router: router,
            endpoint,
            addr,
            log,
        }
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

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Option<Frame> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await.ok()?;
    let mut buf = len.to_vec();
    buf.resize(4 + u32::from_be_bytes(len) as usize, 0);
    r.read_exact(&mut buf[4..]).await.ok()?;
    Frame::decode(&buf).unwrap().map(|(f, _)| f)
}

/// `who` calls `name args` on the host; returns whether it ran.
async fn call(w: &World, who: &NodeIdentity, host: &Host, name: &str, args: &[&str]) -> bool {
    let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(secret_key(who))
        .bind()
        .await
        .unwrap();
    let ran = timeout(PATIENCE, async {
        let conn = endpoint.connect(host.addr.clone(), ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let invoke = Frame::Invoke(Invocation {
            tool: ToolName::new(name).unwrap(),
            argv: library::Argv::new(args.iter().map(|a| a.to_string()).collect()).unwrap(),
        });
        for frame in [Frame::Hello(w.hello(who)), invoke] {
            send.write_all(&frame.encode().unwrap()).await.unwrap();
        }
        send.finish().unwrap();
        loop {
            match read_frame(&mut recv).await {
                Some(Frame::Denied { .. }) | None => return false,
                Some(Frame::Exit(_)) => {
                    conn.close(0u32.into(), b"done");
                    return true;
                }
                Some(_) => {}
            }
        }
    })
    .await
    .expect("the call timed out");
    endpoint.close().await;
    ran
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
    let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(secret_key(who))
        .bind()
        .await
        .unwrap();
    let opts = WatchOpts {
        services: services.iter().map(|s| service(s)).collect(),
        mine,
        follow: false,
    };
    let mut lines = Vec::new();
    let mut out = |o: Output| match o {
        Output::Record(s) => lines.push(text_line(&s)),
        Output::Alarm(a) => lines.push(format!("! {a}")),
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

    // bob, a member in no reader role: only his own refusal.
    let bob = w.reader(&w.bob);
    let (report, lines) = watch_once(&w, &w.bob, &bob, &host, &[], false).await;
    assert!(report.refused.is_empty());
    let recs = records(&lines);
    assert_eq!(recs.len(), 1, "{lines:#?}");
    assert!(recs[0].contains("✗"));
    // …and nothing at all of status, where he never called.
    let bob2 = w.reader(&w.bob);
    let (_, lines) = watch_once(&w, &w.bob, &bob2, &host, &["status"], false).await;
    assert!(records(&lines).is_empty(), "{lines:#?}");

    // A stranger is refused outright.
    let stranger = NodeIdentity::from_seed([66u8; 32]);
    let ks = w.reader(&stranger);
    let (report, lines) = watch_once(&w, &stranger, &ks, &host, &[], false).await;
    assert_eq!(report.refused.len(), 1, "{lines:#?}");
    assert!(records(&lines).is_empty());
    assert!(report.refused[0].1.contains("not a member"), "{report:?}");

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

#[tokio::test]
async fn a_follower_gets_live_records() {
    let w = World::new().await;
    let host = Host::start(&w).await;
    let sam = w.reader(&w.sam);
    let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(secret_key(&w.sam))
        .bind()
        .await
        .unwrap();
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
        Output::Alarm(a) => panic!("alarm: {a}"),
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
    let _: NodeId = w.host.node_id();
}

//! Card 27c's acceptance tests: **a `host.json` v2 host decides every call
//! by the admin-signed state it holds**, re-read per connection.
//!
//! The state is signed in the test by the fabric root and adopted into the
//! host's keystore exactly as `wires/state` does
//! ([`adopt_if_newer`](crate::state::store::adopt_if_newer)). Callers dial
//! the real session ALPN over loopback with a hand-rolled `Hello` + `Invoke`
//! (the dial half is lane 27b's), presenting ID tokens minted by
//! [`MockIdp`]s that the host trusts.
//!
//! - [`the_registry_decides_who_runs_what`]: an allowed role runs; a
//!   disallowed one, and a caller with no token, are refused with the reason
//!   (and the refusal is in the call log).
//! - [`also_require_only_tightens`]
//! - [`an_unassigned_service_refuses_to_start`]
//! - [`a_removed_member_is_refused_on_the_next_call`]: the state bump
//!   applies with no restart; an older caller copy gets the newer state back.
//! - [`push_follows_the_signed_state`]: card 23's push and inbox fetch,
//!   authorized by the registry roles in `push.allow`.
//! - [`a_fetch_with_a_token_makes_a_caller_reachable_by_role`]: a logged-in
//!   member who never called is reachable by role once its `wires inbox`
//!   fetch presented its token, and a direct push lands in a waiting inbox.
//! - [`nothing_is_broadcast_to_a_bystander`]: calls, refusals and pushes
//!   between others send a member that takes part in none of them nothing.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use iroh::address_lookup::memory::MemoryLookup;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr};
use library::{
    AuditRecord, Frame, Hello, HelloAck, Invocation, Matcher, Membership, NodeId, NodeIdentity,
    OidcNonce, PushBody, RoleName, Service, ServiceName, SignedState, State, StateVersion, Subject,
    ToolName,
};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::{PATIENCE, localhost_socks};
use crate::admin::keystore::Keystore;
use crate::caller::inbox::{Fetched, InboxReceiver, Mailbox, fetch_from};
use crate::caller::mock_idp::{MOCK_CLIENT_ID, MockIdp};
use crate::host::config_v2::HostConfigV2;
use crate::host::push::{PushHost, PushSpec};
use crate::host::serve::{services_host, services_router};
use crate::host::transport::{ALPN, AuditSink, endpoint_addr, secret_key};

/// The fabric: root 1, host 10, alice 2, bob 3, carol 4.
struct World {
    root: NodeIdentity,
    host: NodeIdentity,
    alice: NodeIdentity,
    bob: NodeIdentity,
    carol: NodeIdentity,
    /// One IdP per person, each signing in only them.
    idp_alice: MockIdp,
    idp_bob: MockIdp,
    idp_carol: MockIdp,
}

impl World {
    async fn new() -> Self {
        Self {
            root: NodeIdentity::from_seed([1u8; 32]),
            host: NodeIdentity::from_seed([10u8; 32]),
            alice: NodeIdentity::from_seed([2u8; 32]),
            bob: NodeIdentity::from_seed([3u8; 32]),
            carol: NodeIdentity::from_seed([4u8; 32]),
            idp_alice: MockIdp::start("alice@example.com").await,
            idp_bob: MockIdp::start("bob@example.com").await,
            idp_carol: MockIdp::start("carol@example.com").await,
        }
    }

    /// The signed state at `version`: `members` plus the host; roles
    /// `analyst` (alice, carol) and `sre` (carol); `orders-db` (analyst) and
    /// `status` (member), both on the host.
    fn state(&self, version: u64, members: &[NodeId]) -> SignedState {
        let mut s = State::new(self.root.node_id());
        s.version = StateVersion(version);
        s.issued = crate::now_unix();
        s.not_after = i64::MAX;
        s.members.extend(members.iter().copied());
        s.members.insert(self.host.node_id());
        s.hosts.insert(self.host.node_id());
        let email = |e: &str| Matcher {
            email: Some(e.parse().unwrap()),
            ..Default::default()
        };
        s.roles.insert(
            role("analyst"),
            vec![email("alice@example.com"), email("carol@example.com")],
        );
        s.roles
            .insert(role("sre"), vec![email("carol@example.com")]);
        let on_host = |allow: Vec<RoleName>| Service {
            description: String::new(),
            allow,
            hosts: vec![self.host.node_id()],
            readers: vec![],
        };
        s.services
            .insert(service("orders-db"), on_host(vec![role("analyst")]));
        s.services
            .insert(service("status"), on_host(vec![RoleName::member()]));
        s.sign(&self.root).unwrap()
    }

    fn everyone(&self) -> Vec<NodeId> {
        vec![
            self.alice.node_id(),
            self.bob.node_id(),
            self.carol.node_id(),
        ]
    }

    /// A `host.json` v2 trusting all three IdPs, with `services` spliced in.
    fn host_json(&self, services: &str, push: bool) -> HostConfigV2 {
        let issuers: Vec<String> = [&self.idp_alice, &self.idp_bob, &self.idp_carol]
            .iter()
            .map(|idp| {
                format!(
                    r#"{{"issuer":"{}","audiences":["{MOCK_CLIENT_ID}"]}}"#,
                    idp.issuer.as_str()
                )
            })
            .collect();
        let push = if push {
            r#","push":{"allow":["analyst"]}"#
        } else {
            ""
        };
        HostConfigV2::parse(&format!(
            r#"{{"version":2,"identity":{{"issuers":[{}]}},"services":{services}{push}}}"#,
            issuers.join(",")
        ))
        .unwrap()
    }

    fn membership(&self, who: &NodeIdentity) -> Membership {
        Membership::mint(&self.root, who.node_id(), 0, i64::MAX).unwrap()
    }

    /// `who`'s `Hello`: its membership, the state version it holds, and a
    /// fresh token from its own IdP when `logged_in`.
    fn hello(&self, who: &NodeIdentity, version: u64, logged_in: bool) -> Hello {
        let idp = if who.node_id() == self.alice.node_id() {
            &self.idp_alice
        } else if who.node_id() == self.bob.node_id() {
            &self.idp_bob
        } else {
            &self.idp_carol
        };
        Hello {
            membership: self.membership(who),
            state_version: StateVersion(version),
            id_token: logged_in.then(|| {
                idp.mint(
                    &OidcNonce::for_node(&who.node_id()),
                    crate::now_unix() + 3600,
                )
            }),
        }
    }
}

fn role(s: &str) -> RoleName {
    RoleName::new(s).unwrap()
}

fn service(s: &str) -> ServiceName {
    ServiceName::new(s).unwrap()
}

/// A running v2 host: its router, where to dial it, its keystore, its call
/// log's records, and its push service (if any).
struct Host {
    _router: Router,
    addr: EndpointAddr,
    /// The host endpoint's address book: where it can dial members (push).
    book: MemoryLookup,
    keystore: Arc<Keystore>,
    records: mpsc::Receiver<AuditRecord>,
    push: Option<Arc<PushHost>>,
}

impl Host {
    /// Start `config` on `w.host`, holding `state`. Fails as `serve` would
    /// when the preflight refuses.
    async fn start(w: &World, config: HostConfigV2, state: &SignedState) -> anyhow::Result<Host> {
        let home = crate::testutil::temp_dir();
        let keystore = Arc::new(Keystore::at(home.clone()));
        crate::state::store::adopt_if_newer(&keystore, state, w.root.node_id(), crate::now_unix())?;
        let mut host = services_host(
            w.host.node_id(),
            w.membership(&w.host),
            Arc::clone(&keystore),
            &home,
            config,
        )?;
        host.preflight(crate::now_unix())?;
        let (sink, records) = AuditSink::channel(64);
        host.audit = Some(sink);
        let host = Arc::new(host);
        let push = host
            .config
            .push
            .is_some()
            .then(|| Arc::new(PushHost::from_state(Arc::clone(&host))));
        let book = MemoryLookup::new();
        let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(secret_key(&w.host))
            .address_lookup(book.clone())
            .bind()
            .await
            .unwrap();
        let addr = endpoint_addr(&w.host.node_id(), &localhost_socks(&endpoint), None).unwrap();
        let router = services_router(endpoint, Arc::clone(&host), push.clone());
        Ok(Host {
            _router: router,
            addr,
            book,
            keystore,
            records,
            push,
        })
    }

    /// The admin's newer state reaches this host (as `wires/state` would).
    fn adopt(&self, w: &World, state: &SignedState) {
        assert!(
            crate::state::store::adopt_if_newer(
                &self.keystore,
                state,
                w.root.node_id(),
                crate::now_unix()
            )
            .unwrap()
        );
    }

    /// The next call-log record.
    async fn record(&mut self) -> AuditRecord {
        timeout(PATIENCE, self.records.recv())
            .await
            .expect("no record in time")
            .expect("the sink closed")
    }
}

/// What a call came to.
#[derive(Debug)]
enum Outcome {
    /// Admitted: the ack, the exit code, and stdout.
    Ran {
        ack: Box<HelloAck>,
        code: i32,
        stdout: String,
    },
    /// Refused with this reason.
    Denied(String),
}

impl Outcome {
    fn denied(&self) -> &str {
        match self {
            Outcome::Denied(reason) => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    fn stdout(&self) -> &str {
        match self {
            Outcome::Ran {
                code: 0, stdout, ..
            } => stdout,
            other => panic!("expected a successful run, got {other:?}"),
        }
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

/// Dial `host` as `who`, say `hello`, invoke `name` with `args`, close stdin,
/// and collect the outcome.
async fn call(who: &NodeIdentity, host: &Host, hello: Hello, name: &str, args: &[&str]) -> Outcome {
    let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(secret_key(who))
        .bind()
        .await
        .unwrap();
    let outcome = timeout(PATIENCE, async {
        let conn = endpoint.connect(host.addr.clone(), ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let invoke = Frame::Invoke(Invocation {
            tool: ToolName::new(name).unwrap(),
            argv: library::Argv::new(args.iter().map(|a| a.to_string()).collect()).unwrap(),
        });
        for frame in [Frame::Hello(hello), invoke] {
            send.write_all(&frame.encode().unwrap()).await.unwrap();
        }
        send.finish().unwrap();
        let ack = match read_frame(&mut recv).await {
            Some(Frame::HelloAck(ack)) => ack,
            Some(Frame::Denied { reason }) => return Outcome::Denied(reason),
            other => panic!("unexpected first answer: {other:?}"),
        };
        let mut stdout = Vec::new();
        loop {
            match read_frame(&mut recv).await {
                Some(Frame::Stdout(chunk)) => stdout.extend_from_slice(chunk.as_bytes()),
                Some(Frame::Stderr(_)) => {}
                Some(Frame::Exit(code)) => {
                    conn.close(0u32.into(), b"done");
                    return Outcome::Ran {
                        ack: Box::new(ack),
                        code,
                        stdout: String::from_utf8(stdout).unwrap(),
                    };
                }
                other => panic!("unexpected frame: {other:?}"),
            }
        }
    })
    .await
    .expect("the call timed out");
    endpoint.close().await;
    outcome
}

/// `orders-db` echoes its args; `status` prints `up` and the role.
const SERVICES: &str = r#"{
    "orders-db": { "command": ["echo", "rows:"] },
    "status": { "command": ["sh", "-c", "printf \"up as $WIRES_ROLE\""] }
}"#;

#[tokio::test]
async fn the_registry_decides_who_runs_what() {
    let w = World::new().await;
    let state = w.state(1, &w.everyone());
    let mut host = Host::start(&w, w.host_json(SERVICES, false), &state)
        .await
        .unwrap();

    // alice is an analyst: she runs orders-db, with her arguments appended.
    let out = call(
        &w.alice,
        &host,
        w.hello(&w.alice, 1, true),
        "orders-db",
        &["42"],
    )
    .await;
    assert_eq!(out.stdout(), "rows: 42\n");
    let Outcome::Ran { ack, .. } = &out else {
        unreachable!()
    };
    assert_eq!(ack.state_version, StateVersion(1));
    assert!(ack.newer_state.is_none(), "her copy is current");
    match host.record().await {
        AuditRecord::Started {
            principal, role, ..
        } => {
            assert_eq!(
                principal.unwrap().email.as_deref(),
                Some("alice@example.com")
            );
            assert_eq!(role.as_deref(), Some("analyst"));
        }
        other => panic!("expected started, got {other:?}"),
    }
    assert!(matches!(host.record().await, AuditRecord::Finished { .. }));

    // bob verifies, but is in no allowed role: refused, by name, and logged.
    let out = call(&w.bob, &host, w.hello(&w.bob, 1, true), "orders-db", &[]).await;
    assert_eq!(
        out.denied(),
        "bob@example.com is in no role allowed to call orders-db (analyst)"
    );
    match host.record().await {
        AuditRecord::Denied { caller, reason, .. } => {
            assert_eq!(caller, w.bob.node_id());
            assert_eq!(reason, out.denied());
        }
        other => panic!("expected denied, got {other:?}"),
    }

    // alice without a token: told why she has no identity, and what to do.
    let out = call(
        &w.alice,
        &host,
        w.hello(&w.alice, 1, false),
        "orders-db",
        &[],
    )
    .await;
    assert!(
        out.denied().starts_with("no ID token presented; run `wires login`; orders-db needs a verified identity in role analyst"),
        "{}",
        out.denied()
    );

    // `member` needs no identity; the role reaches the service's env.
    let out = call(&w.bob, &host, w.hello(&w.bob, 1, false), "status", &[]).await;
    assert_eq!(out.stdout(), "up as member");

    // A name the registry doesn't know, and a stranger.
    let out = call(&w.alice, &host, w.hello(&w.alice, 1, true), "nope", &[]).await;
    assert_eq!(out.denied(), "unknown service: nope");
    let stranger = NodeIdentity::from_seed([66u8; 32]);
    let out = call(
        &stranger,
        &host,
        w.hello(&stranger, 1, false),
        "status",
        &[],
    )
    .await;
    assert_eq!(
        out.denied(),
        "not a member of the current signed state (version 1)"
    );
}

#[tokio::test]
async fn also_require_only_tightens() {
    let w = World::new().await;
    let state = w.state(1, &w.everyone());
    let strict = r#"{ "orders-db": { "command": ["echo", "ok"], "also_require": ["sre"] } }"#;
    let host = Host::start(&w, w.host_json(strict, false), &state)
        .await
        .unwrap();

    // carol is analyst (registry) and sre (host): admitted.
    let out = call(
        &w.carol,
        &host,
        w.hello(&w.carol, 1, true),
        "orders-db",
        &[],
    )
    .await;
    assert_eq!(out.stdout(), "ok\n");
    // alice is an analyst but not sre: this host says no.
    let out = call(
        &w.alice,
        &host,
        w.hello(&w.alice, 1, true),
        "orders-db",
        &[],
    )
    .await;
    assert_eq!(
        out.denied(),
        "alice@example.com is not in every role this host also requires for orders-db (sre)"
    );
    // bob is in neither: the registry refuses first (the host can't widen).
    let out = call(&w.bob, &host, w.hello(&w.bob, 1, true), "orders-db", &[]).await;
    assert!(out.denied().contains("no role allowed to call orders-db"));
}

#[tokio::test]
async fn an_unassigned_service_refuses_to_start() {
    let w = World::new().await;
    let mut state = w.state(1, &w.everyone()).state;
    // `status` moves to another host.
    let other = NodeIdentity::from_seed([11u8; 32]).node_id();
    state.members.insert(other);
    state.hosts.insert(other);
    state.services.get_mut(&service("status")).unwrap().hosts = vec![other];
    let state = state.sign(&w.root).unwrap();
    let Err(e) = Host::start(&w, w.host_json(SERVICES, false), &state).await else {
        panic!("a host must not serve a name the registry gives someone else");
    };
    let e = format!("{e:#}");
    assert!(
        e.contains("service status") && e.contains("does not assign it to this host"),
        "{e}"
    );

    // And with no signed state at all, nothing is served.
    let home = crate::testutil::temp_dir();
    let host = services_host(
        w.host.node_id(),
        w.membership(&w.host),
        Arc::new(Keystore::at(home.clone())),
        &home,
        w.host_json(SERVICES, false),
    )
    .unwrap();
    let e = format!("{:#}", host.preflight(crate::now_unix()).unwrap_err());
    assert!(e.contains("no signed state"), "{e}");
}

#[tokio::test]
async fn a_removed_member_is_refused_on_the_next_call() {
    let w = World::new().await;
    let host = Host::start(&w, w.host_json(SERVICES, false), &w.state(1, &w.everyone()))
        .await
        .unwrap();
    let out = call(
        &w.alice,
        &host,
        w.hello(&w.alice, 1, true),
        "orders-db",
        &["1"],
    )
    .await;
    assert_eq!(out.stdout(), "rows: 1\n");

    // `wires remove alice`: version 2 without her reaches the host; no restart.
    let v2 = w.state(2, &[w.bob.node_id(), w.carol.node_id()]);
    host.adopt(&w, &v2);
    // She still presents version 1 (and a valid token): the host's copy decides.
    let out = call(
        &w.alice,
        &host,
        w.hello(&w.alice, 1, true),
        "orders-db",
        &["2"],
    )
    .await;
    assert_eq!(
        out.denied(),
        "not a member of the current signed state (version 2)"
    );
    // bob, still holding version 1, is served and handed version 2.
    let out = call(&w.bob, &host, w.hello(&w.bob, 1, false), "status", &[]).await;
    let Outcome::Ran { ack, .. } = &out else {
        panic!("{out:?}")
    };
    assert_eq!(ack.state_version, StateVersion(2));
    assert_eq!(ack.newer_state.as_ref(), Some(&v2));
    // Claiming a newer version than the host's changes nothing.
    let out = call(
        &w.alice,
        &host,
        w.hello(&w.alice, 9, true),
        "orders-db",
        &[],
    )
    .await;
    assert!(out.denied().starts_with("not a member"));
}

#[tokio::test]
async fn push_follows_the_signed_state() {
    let w = World::new().await;
    let host = Host::start(&w, w.host_json(SERVICES, true), &w.state(1, &w.everyone()))
        .await
        .unwrap();
    let push = host.push.clone().unwrap();
    let spec = |to: &NodeIdentity| PushSpec {
        to: to.node_id().hex(),
        subject: Subject::new("build-41").unwrap(),
        body: PushBody::new("failed").unwrap(),
        ttl_secs: None,
    };

    // alice's identity is known here once she has called with her token.
    let out = call(&w.alice, &host, w.hello(&w.alice, 1, true), "status", &[]).await;
    assert_eq!(out.stdout(), "up as member");
    let report = push.send(spec(&w.alice)).await.unwrap();
    assert!(report.any_accepted(), "{}", report.render());
    // bob, unknown here, is told to log in; once known (a member, not an
    // analyst) he is refused at send and at fetch.
    let report = push.send(spec(&w.bob)).await.unwrap();
    assert!(
        report.render().contains("needs a verified identity"),
        "{}",
        report.render()
    );
    call(&w.bob, &host, w.hello(&w.bob, 1, true), "status", &[]).await;
    let report = push.send(spec(&w.bob)).await.unwrap();
    assert!(!report.any_accepted(), "{}", report.render());

    assert!(matches!(
        fetch(&w, &w.alice, &host, None).await,
        Fetched::Messages(1)
    ));
    let Fetched::Refused(why) = fetch(&w, &w.bob, &host, None).await else {
        panic!("bob may not fetch");
    };
    assert!(why.contains("no role allowed to receive pushes"), "{why}");

    // Removed from the state: her queue is dropped and her fetch refused.
    push.send(spec(&w.alice)).await.unwrap();
    host.adopt(&w, &w.state(2, &[w.bob.node_id(), w.carol.node_id()]));
    let Fetched::Refused(why) = fetch(&w, &w.alice, &host, None).await else {
        panic!("a removed member may not fetch");
    };
    assert!(
        why.contains("is not a member of the current signed state (version 2)"),
        "{why}"
    );
}

/// `wires inbox`'s fetch from `host`, as `who`, presenting `id_token`.
async fn fetch(
    w: &World,
    who: &NodeIdentity,
    host: &Host,
    id_token: Option<library::IdToken>,
) -> Fetched {
    let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(secret_key(who))
        .bind()
        .await
        .unwrap();
    let mailbox = Mailbox::open(&crate::testutil::temp_dir()).unwrap();
    let hello = library::InboxFrame::Hello {
        membership: w.membership(who),
        id_token,
    };
    let fetched = timeout(
        PATIENCE,
        fetch_from(
            &endpoint,
            host.addr.clone(),
            &hello,
            Duration::ZERO,
            &mailbox,
        ),
    )
    .await
    .expect("the fetch timed out")
    .unwrap();
    endpoint.close().await;
    fetched
}

/// A member's endpoint that counts every connection it is offered, on every
/// ALPN a wires node speaks, and answers none.
async fn counting_node(who: &NodeIdentity) -> (Router, EndpointAddr, Arc<AtomicUsize>) {
    #[derive(Clone, Debug)]
    struct Count(Arc<AtomicUsize>);
    impl iroh::protocol::ProtocolHandler for Count {
        async fn accept(
            &self,
            conn: iroh::endpoint::Connection,
        ) -> std::result::Result<(), iroh::protocol::AcceptError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            conn.close(0u32.into(), b"counted");
            Ok(())
        }
    }
    let seen = Arc::new(AtomicUsize::new(0));
    let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(secret_key(who))
        .bind()
        .await
        .unwrap();
    let addr = endpoint_addr(&who.node_id(), &localhost_socks(&endpoint), None).unwrap();
    let mut router = Router::builder(endpoint);
    for alpn in [
        ALPN,
        library::INBOX_ALPN,
        library::STATE_ALPN,
        crate::host::record_stream::ALPN,
    ] {
        router = router.accept(alpn, Count(Arc::clone(&seen)));
    }
    (router.spawn(), addr, seen)
}

#[tokio::test]
async fn a_fetch_with_a_token_makes_a_caller_reachable_by_role() {
    let w = World::new().await;
    let state = w.state(1, &w.everyone());
    let host = Host::start(&w, w.host_json(SERVICES, true), &state)
        .await
        .unwrap();
    let push = host.push.clone().unwrap();
    let to_analysts = || PushSpec {
        to: "analyst".into(),
        subject: Subject::new("report").unwrap(),
        body: PushBody::new("ready").unwrap(),
        ttl_secs: None,
    };
    // carol (an analyst) has never called this host: nobody is reachable.
    let e = format!("{:#}", push.send(to_analysts()).await.unwrap_err());
    assert!(e.contains("wires inbox"), "{e}");

    // Her `wires inbox` presents her token: now the host knows who she is.
    let token = w.hello(&w.carol, 1, true).id_token;
    assert!(matches!(
        fetch(&w, &w.carol, &host, token).await,
        Fetched::Messages(0)
    ));

    // And while `wires inbox --wait` runs, a push is delivered directly.
    let home = crate::testutil::temp_dir();
    let ks = Arc::new(Keystore::at(&home));
    crate::state::store::adopt_if_newer(&ks, &state, w.root.node_id(), crate::now_unix()).unwrap();
    let mailbox = Mailbox::open(&home).unwrap();
    let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(secret_key(&w.carol))
        .bind()
        .await
        .unwrap();
    host.book.add_endpoint_info(
        endpoint_addr(&w.carol.node_id(), &localhost_socks(&endpoint), None).unwrap(),
    );
    let _receiver = Router::builder(endpoint)
        .accept(
            library::INBOX_ALPN,
            InboxReceiver {
                me: w.carol.node_id(),
                fabric: w.root.node_id(),
                keystore: Arc::clone(&ks),
                mailbox: mailbox.clone(),
            },
        )
        .spawn();
    let report = push.send(to_analysts()).await.unwrap();
    assert_eq!(report.results.len(), 1, "{}", report.render());
    assert_eq!(report.results[0].to, w.carol.node_id());
    assert_eq!(
        report.results[0].outcome,
        library::PushOutcome::Delivered,
        "{}",
        report.render()
    );
    let unread = mailbox.take_unread().unwrap();
    assert_eq!(unread.len(), 1);
    assert_eq!(unread[0].from, w.host.node_id());
}

#[tokio::test]
async fn nothing_is_broadcast_to_a_bystander() {
    let w = World::new().await;
    let host = Host::start(&w, w.host_json(SERVICES, true), &w.state(1, &w.everyone()))
        .await
        .unwrap();
    // carol is a member the host could dial, and takes part in nothing.
    let (_carol, carol_addr, seen) = counting_node(&w.carol).await;
    host.book.add_endpoint_info(carol_addr);

    // alice calls (twice), bob is refused, the host pushes to alice and
    // she fetches it.
    let out = call(
        &w.alice,
        &host,
        w.hello(&w.alice, 1, true),
        "orders-db",
        &["1"],
    )
    .await;
    assert_eq!(out.stdout(), "rows: 1\n");
    call(&w.alice, &host, w.hello(&w.alice, 1, true), "status", &[]).await;
    let out = call(&w.bob, &host, w.hello(&w.bob, 1, true), "orders-db", &[]).await;
    out.denied();
    let push = host.push.clone().unwrap();
    let report = push
        .send(PushSpec {
            to: w.alice.node_id().hex(),
            subject: Subject::new("done").unwrap(),
            body: PushBody::new("ok").unwrap(),
            ttl_secs: None,
        })
        .await
        .unwrap();
    assert!(report.any_accepted(), "{}", report.render());
    assert!(matches!(
        fetch(&w, &w.alice, &host, None).await,
        Fetched::Messages(1)
    ));

    // The bystander heard nothing about any of it: no connection at all.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(seen.load(Ordering::SeqCst), 0);
}

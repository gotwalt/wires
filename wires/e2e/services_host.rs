//! Card 27c's acceptance tests: **a host decides every call
//! by the admin-signed state it holds**, re-read per connection.
//!
//! The state is signed in the test by the network root and adopted into the
//! host's keystore exactly as `wires/state` does
//! ([`adopt_if_newer`](crate::state::store::adopt_if_newer)). Callers dial
//! the real session ALPN over loopback with a hand-rolled `Hello` + `Invoke`
//! ([`super::call`]), presenting ID tokens minted by [`MockIdp`]s that the
//! host trusts.
//!
//! - [`the_registry_decides_who_runs_what`]: an allowed role runs; a
//!   disallowed one, and a caller with no token, are refused with the reason
//!   (and the refusal is in the call log). Every role needs a verified
//!   identity, even "anyone signed in".
//! - [`a_trusted_issuer_cannot_vouch_for_another_issuers_people`]: a matcher
//!   admits only its own issuer's principals.
//! - [`also_require_only_tightens`]
//! - [`an_unassigned_service_refuses_to_start`]
//! - [`a_removed_member_is_refused_on_the_next_call`]: the ban applies with
//!   no restart; an older caller copy gets the newer state back.
//! - [`push_follows_the_signed_state`]: card 23's push and inbox fetch,
//!   authorized by the registry roles in `push.allow`.
//! - [`a_fetch_with_a_token_makes_a_caller_reachable_by_role`]: a logged-in
//!   member who never called is reachable by role once its `wires inbox`
//!   fetch presented its token, and a direct push lands in a waiting inbox.

use std::sync::Arc;
use std::time::Duration;

use iroh::EndpointAddr;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::protocol::Router;
use library::{
    AuditRecord, Hello, Membership, NodeId, NodeIdentity, OidcNonce, PushBody, RoleName, Service,
    SignedState, StateVersion, Subject,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::{
    Outcome, PATIENCE, adopt, bind, bind_in, email_at, host_config, localhost_socks, role, service,
    signed_state,
};
use crate::admin::keystore::Keystore;
use crate::caller::inbox::{Fetched, InboxReceiver, Mailbox, fetch_from};
use crate::caller::mock_idp::MockIdp;
use crate::host::config::HostConfig;
use crate::host::push::{PushHost, PushSpec};
use crate::host::serve::{services_host, services_router};
use crate::host::transport::{AuditSink, endpoint_addr};

/// The network: root 1, host 10, alice 2, bob 3, carol 4.
///
/// The host trusts all four IdPs; the roles name only the first three.
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
    /// A partner IdP the host also trusts, which vouches for
    /// `alice@example.com` too; no role names it.
    idp_partner: MockIdp,
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
            idp_partner: MockIdp::start("alice@example.com").await,
        }
    }

    /// The signed state at `version`, banning `banned`; roles
    /// `analyst` (alice, carol) and `sre` (carol), each email at its own
    /// IdP, and `staff` (anyone the three people's IdPs verified);
    /// `orders-db` (analyst) and `status` (staff), both on the host.
    fn state(&self, version: u64, banned: &[NodeId]) -> SignedState {
        signed_state(&self.root, version, |s| {
            for b in banned {
                s.ban(*b, i64::MAX);
            }
            s.roles.insert(
                role("analyst"),
                vec![
                    email_at(&self.idp_alice, "alice@example.com"),
                    email_at(&self.idp_carol, "carol@example.com"),
                ],
            );
            s.roles.insert(
                role("sre"),
                vec![email_at(&self.idp_carol, "carol@example.com")],
            );
            s.roles.insert(
                role("staff"),
                [&self.idp_alice, &self.idp_bob, &self.idp_carol]
                    .iter()
                    .map(|idp| library::Matcher::new(idp.issuer.as_str()))
                    .collect(),
            );
            let on_host = |allow: Vec<RoleName>| Service {
                description: String::new(),
                allow,
                hosts: vec![self.host.node_id()],
                readers: vec![],
            };
            s.services
                .insert(service("orders-db"), on_host(vec![role("analyst")]));
            s.services
                .insert(service("status"), on_host(vec![role("staff")]));
        })
    }

    /// A `host.json` trusting all four IdPs, with `services` spliced in.
    fn host_json(&self, services: &str, push: bool) -> HostConfig {
        let push = if push {
            r#","push":{"allow":["analyst"]}"#
        } else {
            ""
        };
        host_config(
            &[
                &self.idp_alice,
                &self.idp_bob,
                &self.idp_carol,
                &self.idp_partner,
            ],
            services,
            push,
        )
    }

    fn membership(&self, who: &NodeIdentity) -> Membership {
        super::membership(&self.root, who)
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
        super::hello(&self.root, who, version, logged_in.then_some(idp))
    }
}

/// A running host: its router, where to dial it, its keystore, its call
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
    async fn start(w: &World, config: HostConfig, state: &SignedState) -> anyhow::Result<Host> {
        let keystore = Arc::new(Keystore::at(crate::testutil::temp_dir()));
        adopt(&keystore, &w.root, state);
        let mut host = services_host(
            w.host.node_id(),
            w.membership(&w.host),
            Arc::clone(&keystore),
            config,
        )?;
        host.preflight(crate::clock::now_unix())?;
        let (sink, records) = AuditSink::channel(64);
        host.audit = Some(sink);
        let host = Arc::new(host);
        let push = host
            .config
            .push
            .is_some()
            .then(|| Arc::new(PushHost::from_state(Arc::clone(&host))));
        let book = MemoryLookup::new();
        let endpoint = bind_in(&w.host, &book).await;
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
        assert!(adopt(&self.keystore, &w.root, state));
    }

    /// The next call-log record.
    async fn record(&mut self) -> AuditRecord {
        timeout(PATIENCE, self.records.recv())
            .await
            .expect("no record in time")
            .expect("the sink closed")
    }
}

/// [`super::call`] to `host`.
async fn call(who: &NodeIdentity, host: &Host, hello: Hello, name: &str, args: &[&str]) -> Outcome {
    super::call(who, &host.addr, hello, name, args).await
}

/// `orders-db` echoes its args; `status` prints `up` and the role.
const SERVICES: &str = r#"{
    "orders-db": { "command": ["echo", "rows:"] },
    "status": { "command": ["sh", "-c", "printf \"up as $WIRES_ROLE\""] }
}"#;

#[tokio::test]
async fn the_registry_decides_who_runs_what() {
    let w = World::new().await;
    let state = w.state(1, &[]);
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
            assert_eq!(role.as_str(), "analyst");
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

    // No role admits a member without a verified identity, not even
    // "anyone signed in"; with one, the role reaches the service's env.
    let out = call(&w.bob, &host, w.hello(&w.bob, 1, false), "status", &[]).await;
    assert!(
        out.denied()
            .starts_with("no ID token presented; run `wires login`"),
        "{}",
        out.denied()
    );
    let out = call(&w.bob, &host, w.hello(&w.bob, 1, true), "status", &[]).await;
    assert_eq!(out.stdout(), "up as staff");

    // A name the registry doesn't know, and a stranger (another network's
    // badge).
    let out = call(&w.alice, &host, w.hello(&w.alice, 1, true), "nope", &[]).await;
    assert_eq!(out.denied(), "unknown service: nope");
    let stranger = NodeIdentity::from_seed([66u8; 32]);
    let mut hello = w.hello(&stranger, 1, false);
    hello.membership = super::membership(&NodeIdentity::from_seed([67u8; 32]), &stranger);
    let out = call(&stranger, &host, hello, "status", &[]).await;
    assert_eq!(out.denied(), crate::host::gate::NOT_ADMITTED);
}

#[tokio::test]
async fn a_trusted_issuer_cannot_vouch_for_another_issuers_people() {
    let w = World::new().await;
    let host = Host::start(&w, w.host_json(SERVICES, false), &w.state(1, &[]))
        .await
        .unwrap();
    // The partner IdP verifies alice@example.com, and the host trusts it,
    // but every role names alice's own IdP (or others): nothing admits her.
    let partner_hello = Hello {
        id_token: Some(w.idp_partner.mint(
            &OidcNonce::for_node(&w.alice.node_id()),
            crate::clock::now_unix() + 3600,
        )),
        ..w.hello(&w.alice, 1, false)
    };
    for svc in ["orders-db", "status"] {
        let out = call(&w.alice, &host, partner_hello.clone(), svc, &[]).await;
        assert!(
            out.denied().starts_with(&format!(
                "alice@example.com is in no role allowed to call {svc}"
            )),
            "{}",
            out.denied()
        );
    }
    // Her own IdP's token is admitted.
    let out = call(
        &w.alice,
        &host,
        w.hello(&w.alice, 1, true),
        "orders-db",
        &["1"],
    )
    .await;
    assert_eq!(out.stdout(), "rows: 1\n");
}

#[tokio::test]
async fn also_require_only_tightens() {
    let w = World::new().await;
    let state = w.state(1, &[]);
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
        "alice@example.com is not admitted to orders-db by this host's own rules"
    );
    // bob is in neither: the registry refuses first (the host can't widen).
    let out = call(&w.bob, &host, w.hello(&w.bob, 1, true), "orders-db", &[]).await;
    assert!(out.denied().contains("no role allowed to call orders-db"));
}

#[tokio::test]
async fn an_unassigned_service_refuses_to_start() {
    let w = World::new().await;
    let mut state = w.state(1, &[]).state;
    // `status` moves to another host.
    let other = NodeIdentity::from_seed([11u8; 32]).node_id();
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
        w.host_json(SERVICES, false),
    )
    .unwrap();
    let e = format!(
        "{:#}",
        host.preflight(crate::clock::now_unix()).unwrap_err()
    );
    assert!(e.contains("no signed state"), "{e}");
}

#[tokio::test]
async fn a_removed_member_is_refused_on_the_next_call() {
    let w = World::new().await;
    let host = Host::start(&w, w.host_json(SERVICES, false), &w.state(1, &[]))
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

    // `wires remove alice`: version 2, banning her, reaches the host; no
    // restart. Her badge is still genuine and unexpired.
    let v2 = w.state(2, &[w.alice.node_id()]);
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
    assert_eq!(out.denied(), crate::host::gate::NOT_ADMITTED);
    // bob, still holding version 1, is served and handed version 2.
    let out = call(&w.bob, &host, w.hello(&w.bob, 1, true), "status", &[]).await;
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
    assert_eq!(out.denied(), crate::host::gate::NOT_ADMITTED);
}

#[tokio::test]
async fn push_follows_the_signed_state() {
    let w = World::new().await;
    let host = Host::start(&w, w.host_json(SERVICES, true), &w.state(1, &[]))
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
    assert_eq!(out.stdout(), "up as staff");
    let report = push.send(spec(&w.alice)).await.unwrap();
    assert!(report.any_accepted(), "{}", report.render());
    // bob, unknown here, is told to log in; once known (staff, not an
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

    // Banned by the state: her queue is dropped and her fetch refused.
    push.send(spec(&w.alice)).await.unwrap();
    host.adopt(&w, &w.state(2, &[w.alice.node_id()]));
    let Fetched::Refused(why) = fetch(&w, &w.alice, &host, None).await else {
        panic!("a removed member may not fetch");
    };
    assert!(why.contains(crate::host::gate::NOT_ADMITTED), "{why}");
}

/// `wires inbox`'s fetch from `host`, as `who`, presenting `id_token`.
async fn fetch(
    w: &World,
    who: &NodeIdentity,
    host: &Host,
    id_token: Option<library::IdToken>,
) -> Fetched {
    let endpoint = bind(who).await;
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

#[tokio::test]
async fn a_fetch_with_a_token_makes_a_caller_reachable_by_role() {
    let w = World::new().await;
    let state = w.state(1, &[]);
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
    // Nor does a role that matches every signed-in person reach anyone
    // whose identity the host has not seen.
    let to_staff = PushSpec {
        to: "staff".into(),
        ..to_analysts()
    };
    assert!(push.send(to_staff).await.is_err());

    // Her `wires inbox` presents her token: now the host knows who she is.
    let token = w.hello(&w.carol, 1, true).id_token;
    assert!(matches!(
        fetch(&w, &w.carol, &host, token).await,
        Fetched::Messages(0)
    ));

    // And while `wires inbox --wait` runs, a push is delivered directly.
    let home = crate::testutil::temp_dir();
    let ks = Arc::new(Keystore::at(&home));
    adopt(&ks, &w.root, &state);
    let mailbox = Mailbox::open(&home).unwrap();
    let endpoint = bind(&w.carol).await;
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

//! Card 15's acceptance tests: **the channel is the directory.**
//!
//! Hosts run the production resident loop with `host.json`'s policy, its
//! identity index and its [`Announcer`]; callers are machines that did
//! nothing but `wires join` (and, for role-gated tools, `wires login`), and
//! find tools through [`refresh_on`] + [`Directory::resolve`] — the same
//! steps `wires tools` and `wires call` take — then dial what resolved.
//!
//! - [`an_analyst_sees_db_query_and_a_non_analyst_neither_sees_nor_runs_it`]:
//!   tools are visible only to members allowed to run them, and a hidden
//!   tool asked for by name gets the host's refusal with its reason.
//! - [`a_joined_caller_finds_calls_disambiguates_and_sees_a_stopped_host_go_stale`]:
//!   no manual configuration; two hosts with the same tool are ambiguous
//!   until qualified; a host that stops announcing is marked stale.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use iroh::Endpoint;
use library::{Argv, ChannelRecord, NodeId, TopicTicket};
use tokio::sync::oneshot;
use tokio::time::timeout;

use super::PATIENCE;
use super::onboard::{Machine, TIMING, bind_hermetic, invite};
use crate::admin::init::{InitArgs, init_in};
use crate::caller::call::Dial;
use crate::caller::join::{id_in, join_in};
use crate::caller::jwks::KeyFetcher;
use crate::caller::login::run_flow;
use crate::caller::mock_idp::{MOCK_CLIENT_ID, MockIdp};
use crate::caller::resolve::{Directory, refresh_on};
use crate::host::announce::Announcer;
use crate::host::config::HostConfig;
use crate::host::identity::{Identities, IdentityGate};
use crate::host::transport::{
    AuditSink, CrlSource, Denied, HeadSource, ServeConfig, SessionProtocol, secret_key,
};
use crate::now_unix;

/// How long each directory refresh may take here (the CLI's is 2 s; a loaded
/// CI machine gets more).
const BUDGET: Duration = Duration::from_secs(10);

/// Run `m` as `wires serve host.json` does — the resident loop with the
/// session ALPN, `host`'s policy and identities, and an announcer with
/// `heartbeat` — and hand back its bootstrap hint once bound.
fn serve(
    m: &Machine,
    host: &HostConfig,
    heartbeat: Duration,
) -> (
    tokio::task::JoinHandle<()>,
    oneshot::Receiver<library::TopicPeer>,
) {
    let ctx = m.context();
    let identity = m.node();
    let identities = Arc::new(Identities::new(
        KeyFetcher::new(None).unwrap(),
        host.trust(),
    ));
    let gate = Arc::new(IdentityGate::new(Arc::clone(&identities), "ops"));
    let policy: Arc<dyn crate::host::policy::Policy> = Arc::new(host.policy());
    let (sink, records) = AuditSink::channel(crate::host::audit::AUDIT_QUEUE);
    let serve = ServeConfig {
        trust_root: ctx.fabric_root,
        require_grant: false,
        crl: CrlSource::Fixed(library::Crl::new()),
        head: HeadSource::Keystore {
            path: m.ks.path("roster-head.json"),
            armed: AtomicBool::new(true),
        },
        membership: ctx.membership.clone(),
        proof: None,
        tools: host.commands(),
        audit: Some(sink),
        identity: Some(Arc::clone(&gate)),
        policy: Arc::clone(&policy),
    };
    let announcer = Announcer::new(
        identity.node_id(),
        policy,
        gate,
        Arc::clone(&identities),
        host.descriptions(),
        heartbeat,
    )
    .watching_keys(Arc::clone(&m.ks));
    let hosted = crate::host::audit::Hosted {
        session: SessionProtocol(Arc::new(serve)),
        records,
        identities,
        announcer: Some(announcer),
    };
    let (ready, ready_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let run =
            crate::channel::watch::run_tail_on(&ctx, 0, false, Some(hosted), async move |cfg| {
                let node = bind_hermetic(&identity, cfg).await?;
                let _ = ready.send(super::hint(&node));
                Ok(node)
            });
        if let Err(e) = run.await {
            panic!("a host ended: {e:#}");
        }
    });
    (task, ready_rx)
}

/// `m`'s directory after a refresh from the channel: until `until` holds
/// (`None`: one catch-up) — `wires tools` / `wires call`'s own step, over a
/// hermetic endpoint.
async fn refreshed(m: &Machine, until: Option<&dyn Fn(&Directory) -> bool>) -> Directory {
    let ctx = m.context();
    let identity = m.node();
    let mut dir = Directory::load(&Directory::path(&m.home), &ctx.name);
    refresh_on(&ctx, &mut dir, BUDGET, until, async move |cfg| {
        bind_hermetic(&identity, cfg).await
    })
    .await
    .unwrap();
    dir.save(&Directory::path(&m.home)).unwrap();
    dir
}

/// Refresh `m`'s directory until `until` holds, retrying (each refresh is
/// bounded) up to [`PATIENCE`].
async fn refreshed_until(m: &Machine, what: &str, until: impl Fn(&Directory) -> bool) -> Directory {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        let dir = refreshed(m, Some(&until)).await;
        if until(&dir) {
            return dir;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}: {dir:?}"
        );
    }
}

/// `wires call <query>` from `m`: resolve through its directory, then dial
/// what resolved with `m`'s credentials, stdin `stdin`.
async fn call(
    m: &Machine,
    dir: &Directory,
    query: &str,
    stdin: &[u8],
) -> (anyhow::Result<i32>, Vec<u8>) {
    let resolved = dir
        .resolve(query, crate::host::audit::now_ms(), &[])
        .unwrap();
    let plan = Dial::resolve(&resolved.tool, Argv::default()).unwrap();
    let target = crate::host::transport::endpoint_addr(&plan.target, &plan.addrs, None).unwrap();
    let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(secret_key(&m.node()))
        .bind()
        .await
        .unwrap();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let result = timeout(
        PATIENCE,
        crate::host::transport::call_on(
            endpoint,
            target,
            m.ks.read_membership().unwrap().unwrap(),
            None,
            m.ks.read_inclusion_proof().unwrap(),
            plan.ticketless,
            plan.invocation,
            std::io::Cursor::new(stdin.to_vec()),
            &mut out,
            &mut err,
        ),
    )
    .await
    .expect("the call timed out");
    (result, out)
}

/// `wires login --topic ops` on `m` at `idp`: sign in (the browser replaced
/// by the mock's redirect) and publish the claim one-shot.
async fn log_in(m: &Machine, idp: &MockIdp) {
    let login = run_flow(
        &KeyFetcher::new(None).unwrap(),
        &idp.client(),
        m.node().node_id(),
        0,
        idp.browser(),
        PATIENCE,
    )
    .await
    .unwrap();
    let text = ChannelRecord::Identity(login.claim).to_text().unwrap();
    let identity = m.node();
    crate::channel::publish::publish_one_shot_on(
        &m.context(),
        crate::channel::publish::Messages::One(Some(text)),
        PATIENCE,
        TIMING.linger,
        async move |cfg| bind_hermetic(&identity, cfg).await,
    )
    .await
    .unwrap();
}

/// The admin inits `ops`; each joiner makes its key (`wires id`). Returns
/// the fabric and the joiners' node ids.
fn onboard(admin: &Machine, joiners: &[&Machine]) -> (NodeId, Vec<NodeId>) {
    init_in(
        &admin.ks,
        InitArgs {
            channel: "ops".into(),
            ttl: super::onboard::ttl(),
        },
    )
    .unwrap();
    let fabric = admin.ks.read_root_identity().unwrap().unwrap().node_id();
    let ids: Vec<NodeId> = joiners.iter().map(|m| id_in(&m.ks).unwrap().0).collect();
    (fabric, ids)
}

/// Join `m` with an invite that bootstraps from `peer`.
async fn join(
    admin: &Machine,
    fabric: NodeId,
    m: &Machine,
    id: NodeId,
    name: &str,
    peer: Option<&library::TopicPeer>,
) {
    let ticket = peer.map(|p| {
        TopicTicket::new(fabric, "ops", vec![p.clone()])
            .encode()
            .unwrap()
    });
    let token = invite(admin, id, name, ticket).await;
    join_in(&m.ks, &m.home, &token, now_unix()).unwrap();
}

/// The directory's tool names on `host`, in order.
fn names_on(dir: &Directory, host: NodeId) -> Vec<String> {
    dir.hosts
        .iter()
        .find(|h| h.node == host)
        .map(|h| h.listing.tools.iter().map(|t| t.name.to_string()).collect())
        .unwrap_or_default()
}

/// **Card 15, visibility.** The host serves `db_query` for role `analyst`
/// (`*@example.com`). Alice (an analyst) logs in and her directory lists
/// `db_query`; Bob logs in at a trusted IdP as `bob@other.org` — authenticated,
/// in no role — and his directory knows the host but lists nothing, and
/// `wires tools` says so; asking for `db_query` by name anyway reaches the
/// host and is refused with the reason.
#[tokio::test]
async fn an_analyst_sees_db_query_and_a_non_analyst_neither_sees_nor_runs_it() {
    let corp = MockIdp::start("alice@example.com").await;
    let other = MockIdp::start("bob@other.org").await;
    let admin = Machine::new();
    let host = Machine::new();
    let alice = Machine::new();
    let bob = Machine::new();
    let (fabric, ids) = onboard(&admin, &[&host, &alice, &bob]);
    let (host_id, alice_id, bob_id) = (ids[0], ids[1], ids[2]);

    let config = HostConfig::parse(&format!(
        r#"{{"version":1,"channel":"ops",
            "identity":{{"issuers":[
              {{"issuer":"{corp}","audiences":["{aud}"]}},
              {{"issuer":"{other}","audiences":["{aud}"]}}]}},
            "roles":{{"analyst":[{{"email":"*@example.com"}}]}},
            "tools":{{"db_query":{{"description":"Read-only SQL","command":["cat"],"allow":["analyst"]}}}}}}"#,
        corp = corp.issuer.as_str(),
        other = other.issuer.as_str(),
        aud = MOCK_CLIENT_ID,
    ))
    .unwrap();
    join(&admin, fabric, &host, host_id, "host", None).await;
    let (host_task, ready) = serve(&host, &config, Duration::from_secs(600));
    let host_hint = timeout(PATIENCE, ready).await.unwrap().unwrap();
    join(&admin, fabric, &alice, alice_id, "alice", Some(&host_hint)).await;
    join(&admin, fabric, &bob, bob_id, "bob", Some(&host_hint)).await;

    // Before anyone logs in: the host exists, nothing is listed.
    let dir = refreshed_until(&alice, "the host's announcement", |d| !d.hosts.is_empty()).await;
    assert!(names_on(&dir, host_id).is_empty(), "{dir:?}");

    log_in(&alice, &corp).await;
    log_in(&bob, &other).await;

    // Alice: the host verified her claim and re-announced, db_query sealed to her.
    let dir = refreshed_until(&alice, "db_query for the analyst", |d| {
        !names_on(d, host_id).is_empty()
    })
    .await;
    assert_eq!(names_on(&dir, host_id), ["db_query"]);
    let (text, note) = dir.render(crate::host::audit::now_ms());
    assert!(text.starts_with("db_query  on "), "{text}");
    assert!(text.ends_with("Read-only SQL"), "{text}");
    assert!(note.is_none(), "{note:?}");
    let (code, out) = call(&alice, &dir, "db_query", b"select 1").await;
    assert_eq!(code.unwrap(), 0);
    assert_eq!(out, b"select 1");

    // Bob: authenticated, in no role. His directory knows the host (it has
    // his claim, and has announced since), and lists nothing.
    let dir = refreshed(&bob, None).await;
    assert!(dir.hosts.iter().any(|h| h.node == host_id), "{dir:?}");
    assert!(
        names_on(&dir, host_id).is_empty(),
        "bob sees no tool: {dir:?}"
    );
    let (text, note) = dir.render(crate::host::audit::now_ms());
    assert!(!text.contains("db_query"), "{text}");
    assert!(
        note.unwrap().contains("announces nothing you may use"),
        "wires tools says the host shows bob nothing"
    );
    // Asked for by name anyway, the one host is dialed and refuses by rule.
    // (His claim may still be on its way to the host: retry until it is the
    // role, not the missing identity, that refuses him.)
    let deadline = tokio::time::Instant::now() + PATIENCE;
    let reason = loop {
        let (res, out) = call(&bob, &dir, "db_query", b"select 1").await;
        assert!(out.is_empty(), "nothing ran for bob");
        let e = res.expect_err("bob is refused");
        let reason = e
            .downcast_ref::<Denied>()
            .unwrap_or_else(|| panic!("a refusal, not a failure: {e:#}"))
            .reason()
            .to_string();
        if !reason.starts_with("no identity claim") || tokio::time::Instant::now() > deadline {
            break reason;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(
        reason.contains("identity bob@other.org")
            && reason.contains("is in no role allowed to run db_query"),
        "{reason}"
    );

    host_task.abort();
}

/// **Card 15, the directory.** Host A serves `db_query` to every member. A
/// caller that has only joined finds it with no configuration and runs it.
/// Host B joins serving `db_query` too: the bare name is now ambiguous, with
/// both `host8/db_query` forms in the error, and the qualified form runs on B.
/// B stops: once three of its heartbeats pass it is shown stale, and the bare
/// name goes to the live host again.
#[tokio::test]
async fn a_joined_caller_finds_calls_disambiguates_and_sees_a_stopped_host_go_stale() {
    let admin = Machine::new();
    let a = Machine::new();
    let b = Machine::new();
    let caller = Machine::new();
    let (fabric, ids) = onboard(&admin, &[&a, &b, &caller]);
    let (a_id, b_id, caller_id) = (ids[0], ids[1], ids[2]);
    let config = |who: &str| {
        HostConfig::parse(&format!(
            r#"{{"version":1,"channel":"ops",
                "tools":{{"db_query":{{"description":"SQL on {who}","command":["cat"],"allow":["member"]}}}}}}"#
        ))
        .unwrap()
    };
    let heartbeat = Duration::from_millis(500);

    join(&admin, fabric, &a, a_id, "a", None).await;
    let (a_task, ready) = serve(&a, &config("a"), heartbeat);
    let a_hint = timeout(PATIENCE, ready).await.unwrap().unwrap();
    join(&admin, fabric, &caller, caller_id, "caller", Some(&a_hint)).await;

    // Only joined: `wires tools` lists A's db_query, `wires call` runs it.
    let dir = refreshed_until(&caller, "A's db_query", |d| !names_on(d, a_id).is_empty()).await;
    assert_eq!(names_on(&dir, a_id), ["db_query"]);
    let (code, out) = call(&caller, &dir, "db_query", b"on a").await;
    assert_eq!(code.unwrap(), 0);
    assert_eq!(out, b"on a");

    // B joins and serves the same name.
    join(&admin, fabric, &b, b_id, "b", Some(&a_hint)).await;
    let (b_task, ready) = serve(&b, &config("b"), heartbeat);
    timeout(PATIENCE, ready).await.unwrap().unwrap();
    let dir = refreshed_until(&caller, "B's db_query", |d| !names_on(d, b_id).is_empty()).await;
    let now = crate::host::audit::now_ms();
    let e = format!("{:#}", dir.resolve("db_query", now, &[]).unwrap_err());
    let (a8, b8) = (&a_id.hex()[..8], &b_id.hex()[..8]);
    assert!(e.contains("served by 2 hosts"), "{e}");
    assert!(e.contains(&format!("{a8}/db_query")), "{e}");
    assert!(e.contains(&format!("{b8}/db_query")), "{e}");
    let (code, out) = call(&caller, &dir, &format!("{b8}/db_query"), b"on b").await;
    assert_eq!(code.unwrap(), 0);
    assert_eq!(out, b"on b");

    // B stops. A keeps its heartbeat; after three of B's, B is stale.
    b_task.abort();
    tokio::time::sleep(heartbeat * 4).await;
    let dir = refreshed(&caller, None).await;
    let now = crate::host::audit::now_ms();
    let b_host = dir.hosts.iter().find(|h| h.node == b_id).unwrap();
    let a_host = dir.hosts.iter().find(|h| h.node == a_id).unwrap();
    assert!(b_host.is_stale(now), "{b_host:?}");
    assert!(!a_host.is_stale(now), "A heartbeats: {a_host:?}");
    let (text, _) = dir.render(now);
    let b_line = text.lines().find(|l| l.contains(b8)).unwrap();
    assert!(b_line.contains("(stale: last announced"), "{text}");
    // The bare name goes to the live host.
    let (code, out) = call(&caller, &dir, "db_query", b"on a again").await;
    assert_eq!(code.unwrap(), 0);
    assert_eq!(out, b"on a again");

    a_task.abort();
}

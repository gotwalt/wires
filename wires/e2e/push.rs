//! Card 23's acceptance tests: **a host pushes to a caller by key.**
//!
//! Hosts run the production resident loop with `host.json`'s `push` section
//! and its [`PushHost`]; tests send as `wires push` does
//! ([`PushHost::send`], the handler behind the control socket). Callers
//! receive either through a resident `wires watch` (its inbox receiver) or
//! by fetching the way `wires inbox` does ([`fetch_from`]). What reached the
//! channel is read back from a member's log after a catch-up.
//!
//! - [`a_resident_receiver_gets_a_push_within_a_second`]
//! - [`without_a_receiver_the_inbox_fetches_waits_and_expiry_is_recorded`]:
//!   queued → fetched; a long poll answered by a later push; a role not in
//!   `push.allow` gets nothing (send and fetch); a TTL runs out on the record.
//! - [`a_removed_member_gets_nothing_and_the_attempt_is_denied`]

use std::sync::Arc;
use std::time::Duration;

use iroh::Endpoint;
use library::{AuditRecord, ChannelRecord, NodeId, PushBody, PushOutcome, Subject};
use tokio::time::timeout;

use super::PATIENCE;
use super::directory::{
    join, log_in, names_on, onboard, refreshed, refreshed_until, serve_pushing,
};
use super::onboard::{Machine, TIMING, bind_hermetic};
use crate::caller::inbox::{Fetched, Mailbox, fetch_from, hello};
use crate::caller::mock_idp::{MOCK_CLIENT_ID, MockIdp};
use crate::host::config::HostConfig;
use crate::host::push::{PushHost, PushSpec};
use crate::host::transport::secret_key;

/// `host.json`: `db_query` and pushes, both for role analyst
/// (`*@example.com`), under two trusted IdPs.
fn host_json(corp: &MockIdp, other: &MockIdp) -> HostConfig {
    HostConfig::parse(&format!(
        r#"{{"version":1,"channel":"ops",
            "identity":{{"issuers":[
              {{"issuer":"{corp}","audiences":["{aud}"]}},
              {{"issuer":"{other}","audiences":["{aud}"]}}]}},
            "roles":{{"analyst":[{{"email":"*@example.com"}}]}},
            "tools":{{"db_query":{{"command":["cat"],"allow":["analyst"]}}}},
            "push":{{"allow":["analyst"]}}}}"#,
        corp = corp.issuer.as_str(),
        other = other.issuer.as_str(),
        aud = MOCK_CLIENT_ID,
    ))
    .unwrap()
}

/// `wires push --to <node> --subject <subject> [--ttl] -- <body>`.
fn spec(to: NodeId, subject: &str, body: &str, ttl_secs: Option<u64>) -> PushSpec {
    PushSpec {
        to: to.hex(),
        subject: Subject::new(subject).unwrap(),
        body: PushBody::new(body).unwrap(),
        ttl_secs,
    }
}

/// `wires inbox`'s fetch from `host`, as `m`, holding up to `wait`.
async fn fetch(m: &Machine, host: &library::TopicPeer, wait: Duration) -> Fetched {
    let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(secret_key(&m.node()))
        .bind()
        .await
        .unwrap();
    let target = crate::host::transport::endpoint_addr(&host.node, &host.addrs, None).unwrap();
    let mailbox = Mailbox::open(&m.home).unwrap();
    let fetched = timeout(
        PATIENCE + wait,
        fetch_from(&endpoint, target, &hello(&m.context()), wait, &mailbox),
    )
    .await
    .expect("the fetch timed out")
    .unwrap();
    endpoint.close().await;
    fetched
}

/// Every push record and inbox refusal `reader` holds after a catch-up:
/// `(outcome or "refused", subject, reason)`.
async fn channel_says(reader: &Machine) -> Vec<(String, String, String)> {
    refreshed(reader, None).await;
    let ctx = reader.context();
    let store = crate::channel::store::TopicStore::open(&ctx.home, ctx.topic).unwrap();
    let mut keyring = crate::channel::printer::Keyring::load(Arc::clone(&reader.ks)).unwrap();
    keyring.quiet = true;
    store
        .read_backfill(10_000)
        .unwrap()
        .into_iter()
        .filter_map(|e| {
            let plain = keyring.open(&e)?;
            match ChannelRecord::parse(&String::from_utf8_lossy(&plain))? {
                ChannelRecord::Audit(AuditRecord::Push {
                    outcome,
                    subject,
                    reason,
                    ..
                }) => Some((
                    outcome.as_str().to_string(),
                    subject.to_string(),
                    reason.unwrap_or_default(),
                )),
                ChannelRecord::Audit(AuditRecord::Denied { reason, .. })
                    if reason.starts_with("inbox fetch refused") =>
                {
                    Some(("refused".into(), String::new(), reason))
                }
                _ => None,
            }
        })
        .collect()
}

/// Poll `reader`'s view of the channel until a record matches.
async fn wait_for_record(
    reader: &Machine,
    what: &str,
    want: impl Fn(&(String, String, String)) -> bool,
) -> (String, String, String) {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        let says = channel_says(reader).await;
        if let Some(r) = says.iter().find(|r| want(r)) {
            return r.clone();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no {what} on the channel: {says:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// The admin, a pushing host, and analysts Alice (and, when asked, Carol),
/// signed in and verified by the host (it has sealed `db_query` to them).
struct World {
    admin: Machine,
    host: Machine,
    host_id: NodeId,
    host_hint: library::TopicPeer,
    push: Arc<PushHost>,
    task: tokio::task::JoinHandle<()>,
    alice: Machine,
    bob: Machine,
    _idps: (MockIdp, MockIdp),
}

/// Stand up [`World`]: Alice logs in at the corp IdP (analyst), Bob at the
/// other (`bob@other.org`, no role).
async fn world() -> World {
    let corp = MockIdp::start("alice@example.com").await;
    let other = MockIdp::start("bob@other.org").await;
    let admin = Machine::new();
    let host = Machine::new();
    let alice = Machine::new();
    let bob = Machine::new();
    let (fabric, ids) = onboard(&admin, &[&host, &alice, &bob]);
    join(&admin, fabric, &host, ids[0], "host", None).await;
    let (task, ready, push) =
        serve_pushing(&host, &host_json(&corp, &other), Duration::from_secs(600));
    let host_hint = timeout(PATIENCE, ready).await.unwrap().unwrap();
    join(&admin, fabric, &alice, ids[1], "alice", Some(&host_hint)).await;
    join(&admin, fabric, &bob, ids[2], "bob", Some(&host_hint)).await;
    log_in(&alice, &corp).await;
    log_in(&bob, &other).await;
    // The host has verified Alice's claim once it seals db_query to her.
    refreshed_until(&alice, "db_query for the analyst", |d| {
        !names_on(d, ids[0]).is_empty()
    })
    .await;
    World {
        admin,
        host,
        host_id: ids[0],
        host_hint,
        push: push.expect("host.json has a push section"),
        task,
        alice,
        bob,
        _idps: (corp, other),
    }
}

/// **A resident receiver gets a push within 1 s.** Alice runs `wires watch`
/// (its inbox receiver); the host dials her by key and she acknowledges; the
/// message is in her mailbox, from the host, and on the channel as
/// `delivered`.
#[tokio::test]
async fn a_resident_receiver_gets_a_push_within_a_second() {
    let w = world().await;
    let alice_id = w.alice.node().node_id();
    let ctx = w.alice.context();
    let identity = w.alice.node();
    let (ready, ready_rx) = tokio::sync::oneshot::channel();
    let watch = tokio::spawn(async move {
        let _ = crate::channel::watch::run_tail_on(&ctx, 0, true, None, async move |cfg| {
            let node = bind_hermetic(&identity, cfg).await?;
            let _ = ready.send(());
            Ok(node)
        })
        .await;
    });
    timeout(PATIENCE, ready_rx).await.unwrap().unwrap();

    // The first push also finds the path to her (her watch dialed the host
    // to join the mesh); it may queue until her receiver is up.
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        let r = w
            .push
            .send(spec(alice_id, "warm-up", "", None))
            .await
            .unwrap();
        if r.results[0].outcome == PushOutcome::Delivered {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "never delivered: {r:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let mailbox = Mailbox::open(&w.alice.home).unwrap();
    mailbox.take_unread().unwrap();
    let sent = tokio::time::Instant::now();
    let r = w
        .push
        .send(spec(
            alice_id,
            "build-41",
            "failed: test_orders_total",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(r.results[0].outcome, PushOutcome::Delivered, "{r:?}");
    let got = loop {
        let got = mailbox.take_unread().unwrap();
        if !got.is_empty() || sent.elapsed() > Duration::from_secs(1) {
            break got;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let took = sent.elapsed();
    assert!(took <= Duration::from_secs(1), "took {took:?}");
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].from, w.host_id, "the verified sender");
    assert_eq!(got[0].subject.as_str(), "build-41");
    assert_eq!(got[0].body.as_str(), "failed: test_orders_total");
    let line = crate::caller::inbox::line(&got[0]);
    assert!(
        line.contains(&format!(
            "from host {} (verified)  build-41",
            &w.host_id.hex()[..8]
        )),
        "{line}"
    );

    let (_, subject, _) = wait_for_record(&w.bob, "a delivered record", |r| {
        r.0 == "delivered" && r.1 == "build-41"
    })
    .await;
    assert_eq!(subject, "build-41");

    watch.abort();
    w.task.abort();
}

/// **No resident receiver.** A push to Alice is queued; her `wires inbox`
/// fetch takes it from the host's queue (recorded `fetched`), and a second
/// fetch finds nothing. A fetch held open (`--wait`) is answered by a push
/// sent while it waits. Bob (verified, in no role) is refused at send and at
/// fetch. A push with a 1 s TTL that nobody takes is recorded `expired`.
#[tokio::test]
async fn without_a_receiver_the_inbox_fetches_waits_and_expiry_is_recorded() {
    let w = world().await;
    let alice_id = w.alice.node().node_id();
    let bob_id = w.bob.node().node_id();

    let r = w
        .push
        .send(spec(alice_id, "build-41", "failed", None))
        .await
        .unwrap();
    assert_eq!(r.results[0].outcome, PushOutcome::Queued, "{r:?}");
    match fetch(&w.alice, &w.host_hint, Duration::ZERO).await {
        Fetched::Messages(1) => {}
        other => panic!("expected one message, got {other:?}"),
    }
    let mailbox = Mailbox::open(&w.alice.home).unwrap();
    let got = mailbox.take_unread().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(
        (got[0].from, got[0].subject.as_str()),
        (w.host_id, "build-41")
    );
    assert!(matches!(
        fetch(&w.alice, &w.host_hint, Duration::ZERO).await,
        Fetched::Messages(0)
    ));

    // A long poll: the fetch waits; a push lands while it does.
    let waiting = {
        let alice = Machine {
            ks: Arc::clone(&w.alice.ks),
            home: w.alice.home.clone(),
        };
        let hint = w.host_hint.clone();
        tokio::spawn(async move { fetch(&alice, &hint, Duration::from_secs(20)).await })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    let sent = tokio::time::Instant::now();
    w.push
        .send(spec(alice_id, "build-42", "passed", None))
        .await
        .unwrap();
    let fetched = timeout(PATIENCE, waiting).await.unwrap().unwrap();
    assert!(matches!(fetched, Fetched::Messages(1)), "{fetched:?}");
    assert!(
        sent.elapsed() < Duration::from_secs(10),
        "the long poll answered promptly"
    );
    assert_eq!(
        mailbox.take_unread().unwrap()[0].subject.as_str(),
        "build-42"
    );

    // Bob: authenticated, in no role — nothing at send, nothing at fetch.
    let r = w
        .push
        .send(spec(bob_id, "secret", "x", None))
        .await
        .unwrap();
    assert_eq!(r.results[0].outcome, PushOutcome::Denied, "{r:?}");
    let why = r.results[0].reason.clone().unwrap();
    assert!(
        why.contains("is in no role allowed to receive pushes"),
        "{why}"
    );
    match fetch(&w.bob, &w.host_hint, Duration::ZERO).await {
        Fetched::Refused(reason) => {
            assert!(reason.starts_with("inbox fetch refused: "), "{reason}")
        }
        other => panic!("bob was not refused: {other:?}"),
    }
    assert!(!Mailbox::open(&w.bob.home).unwrap().has_unread());

    // A TTL that runs out.
    let r = w
        .push
        .send(spec(alice_id, "short-lived", "", Some(1)))
        .await
        .unwrap();
    assert_eq!(r.results[0].outcome, PushOutcome::Queued);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(matches!(
        fetch(&w.alice, &w.host_hint, Duration::ZERO).await,
        Fetched::Messages(0)
    ));

    let says = {
        wait_for_record(&w.admin, "an expired record", |r| {
            r.0 == "expired" && r.1 == "short-lived"
        })
        .await;
        channel_says(&w.admin).await
    };
    let has = |outcome: &str, subject: &str| says.iter().any(|r| r.0 == outcome && r.1 == subject);
    assert!(has("queued", "build-41"), "{says:?}");
    assert!(has("fetched", "build-41"), "{says:?}");
    assert!(has("fetched", "build-42"), "{says:?}");
    assert!(has("denied", "secret"), "{says:?}");
    // A policy refusal of a fetch is answered, not recorded: a resident
    // receiver polls, and would fill the channel with them.
    assert!(
        !says.iter().any(|r| r.0 == "refused"),
        "bob's refused fetch is not on the channel: {says:?}"
    );
    assert!(!has("fetched", "short-lived"), "{says:?}");

    w.task.abort();
}

/// **A removed member gets nothing.** A push to Alice is queued; the admin
/// removes her; her fetch is refused as removed — on the channel too — her
/// queue is dropped (`denied`), and the next push to her is refused at send.
#[tokio::test]
async fn a_removed_member_gets_nothing_and_the_attempt_is_denied() {
    let w = world().await;
    let alice_id = w.alice.node().node_id();
    let r = w
        .push
        .send(spec(alice_id, "before-removal", "", None))
        .await
        .unwrap();
    assert_eq!(r.results[0].outcome, PushOutcome::Queued, "{r:?}");

    let identity = w.admin.node();
    crate::admin::invite::remove_in(
        &w.admin.ks,
        &w.admin.home,
        crate::admin::invite::RemoveArgs {
            member: "alice".into(),
            ttl: super::onboard::ttl(),
        },
        TIMING,
        async move |cfg| bind_hermetic(&identity, cfg).await,
    )
    .await
    .unwrap();
    let v = w.admin.head_version().unwrap();
    // The host adopts the removal off the channel.
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while w.host.head_version() != Some(v) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the host never adopted {v:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    match fetch(&w.alice, &w.host_hint, Duration::ZERO).await {
        Fetched::Refused(reason) => assert!(
            reason.contains("roster inclusion rejected: not in the current roster (removed"),
            "{reason}"
        ),
        other => panic!("the removed alice was not refused: {other:?}"),
    }
    assert!(!Mailbox::open(&w.alice.home).unwrap().has_unread());
    let r = w
        .push
        .send(spec(alice_id, "after-removal", "", None))
        .await
        .unwrap();
    assert_eq!(r.results[0].outcome, PushOutcome::Denied, "{r:?}");
    assert!(
        r.results[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("not in the channel's current roster"),
        "{r:?}"
    );

    let (_, _, reason) = wait_for_record(&w.bob, "the refused fetch", |r| r.0 == "refused").await;
    assert!(reason.contains("removed"), "{reason}");
    wait_for_record(&w.bob, "the dropped queue", |r| {
        r.0 == "denied" && r.1 == "before-removal"
    })
    .await;
    wait_for_record(&w.bob, "the refused send", |r| {
        r.0 == "denied" && r.1 == "after-removal"
    })
    .await;
    w.task.abort();
}

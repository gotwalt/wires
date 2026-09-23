//! Card 04's end-to-end claim: **a node logs in, publishes its identity on a
//! topic, and an observer verifies it independently.** And card 05's: **a
//! responder gates calls on those identities (`serve --require-idp`), across
//! two IdPs, and its call records name the person.**
//!
//! A child of [`crate::e2e`] so it reuses the
//! fabric/member fixtures without widening their visibility. The IdP is the
//! hermetic [`MockIdp`]; the two nodes run real endpoints, real admission and
//! a real gossip mesh over loopback. The observer shares nothing with the
//! publisher but the channel: its own key fetcher, its own JWKS cache, its own
//! trust settings.

use super::*;

use library::{Audience, ChannelRecord, IdentityClaim};

use crate::caller::jwks::KeyFetcher;
use crate::caller::login::run_flow;
use crate::caller::mock_idp::MockIdp;
use crate::channel::idp_view::{IdpTrust, render_identity};

#[tokio::test]
async fn a_published_login_claim_is_verified_by_an_independent_observer() {
    let idp = MockIdp::start("alice@example.com").await;
    let a = Member::new("ia", [2u8; 32]);
    let o = Member::new("io", [3u8; 32]);
    let mut fab = Fabric::new("ops");
    let v1 = fab.commit(&[a.id(), o.id()]);
    a.import(fab.at(v1));
    o.import(fab.at(v1));

    let store_a = a.store(&fab);
    let node_a = a
        .spawn_on_store(&fab, v1, SLOW_RECHECK, Arc::clone(&store_a))
        .await;
    let node_o = o.spawn(&fab, v1, SLOW_RECHECK).await;
    let (send_a, mut rx_a) = node_a.join(fab.topic, &[]).await.unwrap();
    let (_send_o, mut rx_o) = node_o.join(fab.topic, &[hint(&node_a)]).await.unwrap();
    wait_neighbor_up(&mut rx_a, o.id()).await;
    wait_neighbor_up(&mut rx_o, a.id()).await;

    // A: `wires login` against the mock, the browser replaced by an HTTP
    // client following the redirect.
    let fetcher_a = KeyFetcher::new(None).unwrap();
    let login = run_flow(
        &fetcher_a,
        &idp.client(),
        a.id(),
        0,
        idp.browser(),
        PATIENCE,
    )
    .await
    .unwrap();
    let text = ChannelRecord::Identity(login.claim.clone())
        .to_text()
        .unwrap();
    publish(&fab, v1, &a.identity, &store_a, &send_a, &text).await;

    // O: decrypt, parse, and verify against the issuer's keys itself.
    let envelope = next_message(&mut rx_o).await;
    assert_eq!(envelope.sender, a.id());
    let plaintext = o.keyring().open(&envelope).expect("O holds the key");
    let Some(ChannelRecord::Identity(claim)) =
        ChannelRecord::parse(std::str::from_utf8(&plaintext).unwrap())
    else {
        panic!("the message is an identity record");
    };
    let fetcher_o = KeyFetcher::new(Some(o.home.path().join("jwks"))).unwrap();
    let trust = IdpTrust {
        issuers: vec![idp.issuer.clone()],
        audiences: vec![Audience::new(idp.client_id.clone())],
    };
    let line = render_identity(&fetcher_o, &trust, &claim, crate::now_unix()).await;
    assert_eq!(
        line,
        format!(
            "identity {} is alice@example.com (verified by {})",
            &a.id().hex()[..8],
            idp.issuer
        )
    );

    // The token is bound to A's key: re-published as O's identity it fails.
    let replayed = IdentityClaim {
        node: o.id(),
        ..claim.clone()
    };
    let line = render_identity(&fetcher_o, &trust, &replayed, crate::now_unix()).await;
    assert!(line.contains("UNVERIFIED: nonce"), "{line}");

    // An observer that does not trust this issuer says so rather than
    // fetching keys from wherever the token points.
    let google_only = IdpTrust::from_vars(None, Some(&idp.client_id));
    let line = render_identity(&fetcher_o, &google_only, &claim, crate::now_unix()).await;
    assert!(line.contains("not trusted"), "{line}");
}

// ---------------------------------------------------------------------------
// Card 05: `serve --require-idp`
// ---------------------------------------------------------------------------

/// `m` signs in at `idp` (browser replaced by the mock's redirect) and its
/// claim goes on the channel: sealed on **m's own chain** — a claim only
/// counts from the node it names — and relayed into the mesh by `relay`.
async fn log_in_and_publish(
    idp: &MockIdp,
    m: &Member,
    fab: &Fabric,
    version: RosterVersion,
    relay: &TopicSender,
) {
    let login = run_flow(
        &KeyFetcher::new(None).unwrap(),
        &idp.client(),
        m.id(),
        0,
        idp.browser(),
        PATIENCE,
    )
    .await
    .unwrap();
    let text = ChannelRecord::Identity(login.claim).to_text().unwrap();
    let envelope = append(fab, version, &m.identity, &m.store(fab), &text);
    relay.broadcast(&envelope).await.unwrap();
}

/// One `wires call cat` from `m` to `target`, stdin `ping`.
async fn call_as(
    m: &Member,
    fab: &Fabric,
    version: RosterVersion,
    target: &iroh::EndpointAddr,
) -> (anyhow::Result<i32>, Vec<u8>) {
    let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(secret_key(&m.identity))
        .bind()
        .await
        .unwrap();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let result = timeout(
        PATIENCE,
        crate::host::transport::call_on(
            endpoint,
            target.clone(),
            library::Membership::mint(&fab.root, m.id(), 0, i64::MAX).unwrap(),
            None,
            Some(fab.at(version).proofs[&m.id()].clone()),
            false,
            library::Invocation {
                tool: library::ToolName::new("cat").unwrap(),
                argv: library::Argv::new(Vec::new()).unwrap(),
            },
            std::io::Cursor::new(b"ping".to_vec()),
            &mut out,
            &mut err,
        ),
    )
    .await
    .expect("the call timed out");
    (result, out)
}

/// The reason a dialer-side refusal carried.
fn denied_reason(res: anyhow::Result<i32>) -> String {
    let e = res.expect_err("expected a refusal");
    e.downcast_ref::<Denied>()
        .unwrap_or_else(|| panic!("a refusal, not a failure: {e:#}"))
        .reason()
        .to_string()
}

/// O's view of a refusal: the record, carrying the reason the caller got.
async fn expect_denied(
    rx: &mut mpsc::Receiver<TopicEvent>,
    keyring: &mut Keyring,
    who: NodeId,
    told: &str,
) {
    let record = next_record(rx, keyring).await;
    let library::AuditRecord::Denied { caller, reason, .. } = record else {
        panic!("expected Denied, got {record:?}");
    };
    assert_eq!(caller, who);
    assert_eq!(reason, told, "the record carries the reason the caller got");
}

/// O's view of an admitted call: `Started` names the person, then `Finished`.
async fn expect_ran_as(
    rx: &mut mpsc::Receiver<TopicEvent>,
    keyring: &mut Keyring,
    who: NodeId,
    email: &str,
) {
    let started = next_record(rx, keyring).await;
    let library::AuditRecord::Started {
        caller, principal, ..
    } = &started
    else {
        panic!("expected Started, got {started:?}");
    };
    assert_eq!(*caller, who);
    assert_eq!(
        principal.as_ref().and_then(|p| p.email.as_deref()),
        Some(email)
    );
    let line = crate::channel::render::audit_line(&started);
    assert!(line.contains(email), "the observer sees the name: {line}");
    let finished = next_record(rx, keyring).await;
    assert!(
        matches!(finished, library::AuditRecord::Finished { exit: 0, .. }),
        "{finished:?}"
    );
}

/// **Card 05.** R serves `cat` with `--audit-topic ops` and two
/// `--require-idp` rules — `*@example.com` at the corp IdP, `*@partner.org`
/// at a partner IdP (federation: two issuers, one channel). O observes.
///
/// Alice calls before logging in and is refused (no claim); she logs in, her
/// claim lands on the topic, and her **next** call runs — no restart — with
/// `Started.principal` naming her. Bob, from the partner IdP, is allowed by
/// the second rule. Eve's IdP is trusted (her token verifies) but no rule
/// admits `eve@evil.net`, so she is refused by name. Every refusal is on the
/// channel with the reason the caller got.
#[tokio::test]
async fn require_idp_admits_verified_federated_identities_only() {
    use crate::caller::mock_idp::MOCK_CLIENT_ID;
    use crate::host::identity::{Identities, IdentityGate};
    use crate::host::idp_policy::IdpPolicy;
    use crate::host::transport::{AuditSink, CrlSource, ServeConfig, SessionProtocol};

    let corp = MockIdp::start("alice@example.com").await;
    let partner = MockIdp::start("bob@partner.org").await;
    let stranger = MockIdp::start("eve@evil.net").await;

    let r_seed = [31u8; 32];
    let r = Member::new("pr", r_seed);
    let o = Member::new("po", [32u8; 32]);
    let alice = Member::new("pa", [33u8; 32]);
    let bob = Member::new("pb", [34u8; 32]);
    let eve = Member::new("pe", [35u8; 32]);
    let mut fab = Fabric::new("ops");
    let v1 = fab.commit(&[r.id(), o.id(), alice.id(), bob.id(), eve.id()]);
    for m in [&r, &o, &alice, &bob, &eve] {
        m.import(fab.at(v1));
    }

    // R's identity index and gate, as `serve_identities` builds them from
    // `--require-idp … --oidc-audience …` (the third issuer via
    // `--oidc-issuer`: trusted, just not allowed).
    let identities = Arc::new(Identities::new(
        KeyFetcher::new(None).unwrap(),
        IdpTrust {
            issuers: vec![
                corp.issuer.clone(),
                partner.issuer.clone(),
                stranger.issuer.clone(),
            ],
            audiences: vec![Audience::new(MOCK_CLIENT_ID)],
        },
    ));
    let policy = IdpPolicy::parse(&[
        format!("iss={},email=*@example.com", corp.issuer.as_str()),
        format!("iss={},email=*@partner.org", partner.issuer.as_str()),
    ])
    .unwrap();
    let (sink, records) = AuditSink::channel(crate::host::audit::AUDIT_QUEUE);
    let r_membership = library::Membership::mint(&fab.root, r.id(), 0, i64::MAX).unwrap();
    let serve = ServeConfig {
        trust_root: fab.id(),
        require_grant: false,
        crl: CrlSource::Fixed(library::Crl::new()),
        head: HeadSource::Keystore {
            path: r.keystore.path("roster-head.json"),
            armed: AtomicBool::new(true),
        },
        membership: r_membership.clone(),
        proof: None,
        tools: std::collections::BTreeMap::from([(
            library::ToolName::new("cat").unwrap(),
            vec!["cat".to_string()],
        )]),
        audit: Some(sink),
        identity: Some(Arc::new(IdentityGate::new(
            Arc::clone(&identities),
            policy,
            "ops",
        ))),
    };
    let store_r = r.store(&fab);
    let mut cfg = TopicNodeConfig::new(
        fab.topic,
        fab.id(),
        Arc::new(HeadSource::Keystore {
            path: r.keystore.path("roster-head.json"),
            armed: AtomicBool::new(false),
        }),
        fab.at(v1).proofs[&r.id()].clone(),
        Arc::clone(&r.keystore),
        Arc::clone(&store_r),
    );
    cfg.admit_recheck = SLOW_RECHECK;
    cfg.protocols.push((
        crate::host::transport::ALPN,
        SessionProtocol(Arc::new(serve)).into(),
    ));
    let lookup = MemoryLookup::new();
    let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(secret_key(&r.identity))
        .address_lookup(lookup.clone())
        .bind()
        .await
        .unwrap();
    let node_r = TopicNode::spawn_on(endpoint, lookup, cfg).await.unwrap();
    let node_o = o.spawn(&fab, v1, SLOW_RECHECK).await;
    let (send_r, mut rx_r) = node_r.join(fab.topic, &[]).await.unwrap();
    let (send_o, mut rx_o) = node_o.join(fab.topic, &[hint(&node_r)]).await.unwrap();
    wait_neighbor_up(&mut rx_r, o.id()).await;
    wait_neighbor_up(&mut rx_o, r.id()).await;

    // R's tail loop, reduced to the two arms that matter here: the publish arm
    // (audit records out) and the live arm, printing every message through
    // the production `Printer::emit` — which is what feeds the index.
    let ctx = crate::TopicContext {
        node: NodeIdentity::from_seed(r_seed),
        membership: r_membership,
        proof: fab.at(v1).proofs[&r.id()].clone(),
        head_source: Arc::new(HeadSource::Keystore {
            path: r.keystore.path("roster-head.json"),
            armed: AtomicBool::new(true),
        }),
        keystore: Arc::clone(&r.keystore),
        home: r.home.path().to_path_buf(),
        name: "ops".into(),
        topic: fab.topic,
        fabric_root: fab.id(),
        ticket_peers: Vec::new(),
        relay_url: None,
    };
    let (tx, mut requests) = mpsc::channel::<crate::channel::ipc::PublishRequest>(32);
    let forwarder = tokio::spawn(crate::host::audit::forward(records, tx));
    let publisher = tokio::spawn({
        let store = Arc::clone(&store_r);
        async move {
            while let Some(request) = requests.recv().await {
                let outcome = crate::publish_from_tail(&ctx, &store, &send_r, &request.text)
                    .await
                    .map(|envelope| envelope.seq.0)
                    .map_err(|e| format!("{e:#}"));
                let _ = request.reply.send(outcome);
            }
        }
    });
    let live = tokio::spawn({
        let printer = Printer {
            json: false,
            identities: Some(Arc::clone(&identities)),
        };
        let mut keyring = r.keyring();
        async move {
            while let Some(event) = rx_r.recv().await {
                if let TopicEvent::Message(envelope) = event {
                    printer.emit(&envelope, &mut keyring).await;
                }
            }
        }
    });

    let target =
        crate::host::transport::endpoint_addr(&r.id(), &localhost_socks(node_r.endpoint()), None)
            .unwrap();
    let mut keyring_o = o.keyring();

    // 1. Alice, before logging in: refused, with the remedy.
    let (res, out) = call_as(&alice, &fab, v1, &target).await;
    let told = denied_reason(res);
    assert!(out.is_empty(), "nothing ran");
    assert!(told.starts_with("no identity claim for"), "{told}");
    assert!(told.contains("wires login --topic ops"), "{told}");
    expect_denied(&mut rx_o, &mut keyring_o, alice.id(), &told).await;

    // 2. She logs in; once R has seen the claim, her next call runs.
    log_in_and_publish(&corp, &alice, &fab, v1, &send_o).await;
    settle(
        || identities.current(alice.id(), crate::now_unix()).is_some(),
        "R to index Alice's claim",
    )
    .await;
    let (res, out) = call_as(&alice, &fab, v1, &target).await;
    assert_eq!(res.unwrap(), 0);
    assert_eq!(out, b"ping");
    expect_ran_as(&mut rx_o, &mut keyring_o, alice.id(), "alice@example.com").await;

    // 3. Federation: Bob, from the partner IdP, is admitted by the second rule.
    log_in_and_publish(&partner, &bob, &fab, v1, &send_o).await;
    settle(
        || identities.current(bob.id(), crate::now_unix()).is_some(),
        "R to index Bob's claim",
    )
    .await;
    let (res, _) = call_as(&bob, &fab, v1, &target).await;
    assert_eq!(res.unwrap(), 0);
    expect_ran_as(&mut rx_o, &mut keyring_o, bob.id(), "bob@partner.org").await;

    // 4. Eve's token verifies, but no rule admits her.
    log_in_and_publish(&stranger, &eve, &fab, v1, &send_o).await;
    settle(
        || identities.current(eve.id(), crate::now_unix()).is_some(),
        "R to index Eve's claim",
    )
    .await;
    let (res, out) = call_as(&eve, &fab, v1, &target).await;
    let told = denied_reason(res);
    assert!(out.is_empty(), "nothing ran");
    assert!(
        told.starts_with("identity eve@evil.net") && told.contains("not allowed"),
        "{told}"
    );
    expect_denied(&mut rx_o, &mut keyring_o, eve.id(), &told).await;

    live.abort();
    forwarder.abort();
    publisher.abort();
    node_o.shutdown().await.unwrap();
    node_r.shutdown().await.unwrap();
}

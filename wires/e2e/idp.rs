//! Card 04's end-to-end claim: **a node logs in, publishes its identity on a
//! topic, and an observer verifies it independently.** And cards 05/13's: **a
//! host gates calls on those identities (`host.json` roles), across two IdPs,
//! and its call records name the person and the role.**
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
    let trust = IdpTrust::per_issuer(vec![(
        idp.issuer.clone(),
        vec![Audience::new(idp.client_id.clone())],
    )]);
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
// Cards 05 + 13: `host.json` roles over verified identities
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
    call_tool_as("cat", m, fab, version, target).await
}

/// One `wires call <tool>` from `m` to `target`, stdin `ping`.
async fn call_tool_as(
    tool: &str,
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
            Some(fab.at(version).proofs[&m.id()].clone()),
            library::Invocation {
                tool: library::ToolName::new(tool).unwrap(),
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

/// O's view of an admitted call: `Started` names the person (if any) and the
/// admitting role, then `Finished`.
async fn expect_ran_as(
    rx: &mut mpsc::Receiver<TopicEvent>,
    keyring: &mut Keyring,
    who: NodeId,
    email: Option<&str>,
    as_role: &str,
) {
    let started = next_record(rx, keyring).await;
    let library::AuditRecord::Started {
        caller,
        principal,
        role,
        ..
    } = &started
    else {
        panic!("expected Started, got {started:?}");
    };
    assert_eq!(*caller, who);
    assert_eq!(principal.as_ref().and_then(|p| p.email.as_deref()), email);
    assert_eq!(role.as_deref(), Some(as_role));
    let line = crate::channel::render::audit_line(&started);
    if let Some(email) = email {
        assert!(line.contains(email), "the observer sees the name: {line}");
    }
    assert!(
        line.contains(&format!("[{as_role}]")),
        "the observer sees the role: {line}"
    );
    let finished = next_record(rx, keyring).await;
    assert!(
        matches!(finished, library::AuditRecord::Finished { exit: 0, .. }),
        "{finished:?}"
    );
}

/// **Cards 05 + 13.** R serves a `host.json` on channel `ops`: `cat` for role
/// `analyst` — `*@example.com` at the corp IdP **or** `*@partner.org` at a
/// partner IdP (federation: two issuers, one channel) — and `status` for the
/// built-in `member`. O observes.
///
/// Alice calls `cat` before logging in and is refused (no claim, and the rule
/// that needed one), yet runs `status` as `member` with no IdP at all. She
/// logs in, her claim lands on the topic, and her **next** `cat` runs — no
/// restart — with `Started` naming her and `[analyst]`. Bob, from the
/// partner IdP, is an analyst by the second matcher. Eve's IdP is trusted
/// (her token verifies) but she is in no allowed role, so she is refused by
/// name with the rule she failed. Every refusal is on the channel with the
/// reason the caller got.
#[tokio::test]
async fn host_json_roles_admit_verified_federated_identities_only() {
    use crate::caller::mock_idp::MOCK_CLIENT_ID;
    use crate::host::config::HostConfig;
    use crate::host::identity::{Identities, IdentityGate};
    use crate::host::transport::{AuditSink, ServeConfig, SessionProtocol};

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

    // R's host.json: all three IdPs trusted (the third just in no role).
    let host = HostConfig::parse(&format!(
        r#"{{
          "version": 1,
          "channel": "ops",
          "identity": {{ "issuers": [
            {{ "issuer": "{corp}", "audiences": ["{aud}"] }},
            {{ "issuer": "{partner}", "audiences": ["{aud}"] }},
            {{ "issuer": "{stranger}", "audiences": ["{aud}"] }}
          ] }},
          "roles": {{ "analyst": [
            {{ "issuer": "{corp}", "email": "*@example.com" }},
            {{ "issuer": "{partner}", "email": "*@partner.org" }}
          ] }},
          "tools": {{
            "cat": {{ "command": ["cat"], "allow": ["analyst"] }},
            "status": {{ "command": ["printf", "up"], "allow": ["member"] }}
          }}
        }}"#,
        corp = corp.issuer.as_str(),
        partner = partner.issuer.as_str(),
        stranger = stranger.issuer.as_str(),
        aud = MOCK_CLIENT_ID,
    ))
    .unwrap();
    // R's identity index, as `serve_identities` builds it from host.json.
    let identities = Arc::new(Identities::new(
        KeyFetcher::new(None).unwrap(),
        host.trust(),
    ));
    let (sink, records) = AuditSink::channel(crate::host::audit::AUDIT_QUEUE);
    let r_membership = library::Membership::mint(&fab.root, r.id(), 0, i64::MAX).unwrap();
    let serve = ServeConfig {
        trust_root: fab.id(),
        head: HeadSource::Keystore {
            path: r.keystore.path("roster-head.json"),
            armed: AtomicBool::new(true),
        },
        membership: r_membership.clone(),
        proof: None,
        tools: host.commands(),
        audit: Some(sink),
        identity: Some(Arc::new(IdentityGate::new(Arc::clone(&identities), "ops"))),
        policy: Arc::new(host.policy()),
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
    let ctx = crate::channel::context::TopicContext {
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
                let outcome =
                    crate::channel::watch::publish_from_tail(&ctx, &store, &send_r, &request.text)
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
            directory: None,
            shown: Default::default(),
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

    // 1. Alice, before logging in: refused `cat`, with the remedy and the
    //    rule that needed an identity ...
    let (res, out) = call_as(&alice, &fab, v1, &target).await;
    let told = denied_reason(res);
    assert!(out.is_empty(), "nothing ran");
    assert!(told.starts_with("no identity claim for"), "{told}");
    assert!(told.contains("wires login --topic ops"), "{told}");
    assert!(
        told.contains("cat needs a verified identity in role analyst (issuer="),
        "{told}"
    );
    expect_denied(&mut rx_o, &mut keyring_o, alice.id(), &told).await;
    // ... but `member` needs no IdP, because host.json says so explicitly.
    let (res, out) = call_tool_as("status", &alice, &fab, v1, &target).await;
    assert_eq!(res.unwrap(), 0);
    assert_eq!(out, b"up");
    expect_ran_as(&mut rx_o, &mut keyring_o, alice.id(), None, "member").await;

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
    expect_ran_as(
        &mut rx_o,
        &mut keyring_o,
        alice.id(),
        Some("alice@example.com"),
        "analyst",
    )
    .await;

    // 3. Federation: Bob, from the partner IdP, is an analyst by the second
    //    matcher.
    log_in_and_publish(&partner, &bob, &fab, v1, &send_o).await;
    settle(
        || identities.current(bob.id(), crate::now_unix()).is_some(),
        "R to index Bob's claim",
    )
    .await;
    let (res, _) = call_as(&bob, &fab, v1, &target).await;
    assert_eq!(res.unwrap(), 0);
    expect_ran_as(
        &mut rx_o,
        &mut keyring_o,
        bob.id(),
        Some("bob@partner.org"),
        "analyst",
    )
    .await;

    // 4. Eve's token verifies, but she is in no role allowed to run `cat`.
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
        told.starts_with(&format!(
            "identity eve@evil.net (from {}) is in no role allowed to run cat: analyst (",
            stranger.issuer.as_str()
        )),
        "{told}"
    );
    expect_denied(&mut rx_o, &mut keyring_o, eve.id(), &told).await;

    live.abort();
    forwarder.abort();
    publisher.abort();
    node_o.shutdown().await.unwrap();
    node_r.shutdown().await.unwrap();
}

//! Card 04's end-to-end claim: **a node logs in, publishes its identity on a
//! topic, and an observer verifies it independently.**
//!
//! A child of [`crate::e2e`] (declared there with `#[path]`) so it reuses the
//! fabric/member fixtures without widening their visibility. The IdP is the
//! hermetic [`MockIdp`]; the two nodes run real endpoints, real admission and
//! a real gossip mesh over loopback. The observer shares nothing with the
//! publisher but the channel: its own key fetcher, its own JWKS cache, its own
//! trust settings.

use super::*;

use library::{Audience, ChannelRecord, IdentityClaim};

use crate::idp_view::{IdpTrust, render_identity};
use crate::jwks::KeyFetcher;
use crate::login::run_flow;
use crate::mock_idp::MockIdp;

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

use std::time::Duration;
use tempfile::TempDir;
use wires_node::pair_pending;

#[tokio::test]
#[ignore]
async fn alice_pairs_bob_end_to_end() {
    let alice_td = TempDir::new().unwrap();
    let bob_td = TempDir::new().unwrap();

    // Alice: init with new root, create topic.
    wires_cli::cmd::init::run(alice_td.path(), true)
        .await
        .unwrap();
    wires_cli::cmd::topic::create(alice_td.path(), "home.notes")
        .await
        .unwrap();

    // Bob: identity-only init.
    wires_cli::cmd::init::run(bob_td.path(), false)
        .await
        .unwrap();

    // Bob: start pair-listen in background.
    let bob_path = bob_td.path().to_path_buf();
    let listen = tokio::spawn(async move {
        wires_cli::cmd::pair_listen::run(
            &bob_path,
            "chat-agent".into(),
            "Bob".into(),
            vec!["home.notes:read+write".into()],
            Duration::from_secs(60),
            false,
        )
        .await
        .map_err(|e| e.to_string())
    });

    // Wait for the pair_pending.json to appear.
    let mut token = None;
    for _ in 0..60 {
        if let Ok(Some(p)) = pair_pending::load(bob_td.path()) {
            token = Some(p.request_token);
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let token = token.expect("Bob should have written pair_pending.json");

    // Alice: pair-approve (yes, default scopes, no host since no `wires host pair`).
    wires_cli::cmd::pair_approve::run(
        alice_td.path(),
        &token,
        vec![],
        None,
        true, // no_host
        true, // yes
    )
    .await
    .unwrap();

    // Bob's listen task should resolve to Paired.
    let res = listen.await.unwrap();
    assert!(res.is_ok(), "pair_listen task returned err: {res:?}");
    assert!(!bob_td.path().join("pair_pending.json").exists());
    assert!(bob_td.path().join("caps.db").exists());
}

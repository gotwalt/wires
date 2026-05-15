use tempfile::TempDir;
use wires_net::pair::PairRequest;

#[tokio::test]
async fn pair_listen_emits_a_valid_token() {
    let td = TempDir::new().unwrap();
    wires_cli::cmd::init::run(td.path(), false).await.unwrap();
    let path = td.path().to_path_buf();
    // Use the minimum valid TTL (60 s). We abort the task after inspecting the
    // token rather than waiting for it to expire.
    let handle = tokio::spawn(async move {
        wires_cli::cmd::pair_listen::run(
            &path,
            "test".into(),
            "smoke".into(),
            vec!["home.notes:read+write".into()],
            std::time::Duration::from_secs(60),
            false,
        )
        .await
        .map_err(|e| e.to_string())
    });
    // Wait for pair_pending.json to be written.
    for _ in 0..20 {
        if let Ok(Some(_)) = wires_node::pair_pending::load(td.path()) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let pending = wires_node::pair_pending::load(td.path())
        .unwrap()
        .expect("pair_pending exists");
    let req = PairRequest::decode(&pending.request_token).unwrap();
    req.verify().unwrap();
    assert_eq!(req.manifest.role, "test");
    // Cancel the listen task — no need to wait for the full TTL.
    handle.abort();
    let _ = handle.await;
}

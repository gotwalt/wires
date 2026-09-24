//! Card 37's acceptance: **each caller holds only the services it may use.**
//!
//! A directory on hermetic loopback holds the policy (handed to it with
//! [`Directory::accept`]); callers ask it for their view with their own ID
//! token (the shared mock IdP, [`crate::testutil::test_idp`], which signs in
//! `caller@example.com`), or follow it by subscription.
//!
//! - [`a_callers_keystore_holds_only_its_view`]: no role, no ban, no node
//!   id but its services' hosts and the directories, and no service it may
//!   not use.
//! - [`without_a_verified_identity_the_view_is_empty`]: and `resolve` finds
//!   one service, only for a caller that may use it.
//! - [`a_grant_and_a_revocation_reach_a_running_mcp_within_2s`]: as
//!   `notifications/tools/list_changed`, through the same subscription,
//!   mapping and server `wires mcp` runs.
//! - [`a_view_that_cannot_be_updated_is_fetched_whole_again`]
//! - [`a_refresh_from_a_kept_head_is_an_update`]: a `view {have}` from a
//!   head the directory keeps is answered with what changed.

use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh::Endpoint;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::protocol::Router;
use library::{Matcher, Membership, NodeIdentity, Policy, Service, SignedPolicy, StateVersion};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

use super::{PATIENCE, bind_in, localhost_socks, role, service};
use crate::admin::keystore::Keystore;
use crate::caller::login::ID_TOKEN_FILE;
use crate::caller::mcp::{LIST_CHANGED, McpServer, serve_following, with_services};
use crate::caller::tools::ToolsConfig;
use crate::caller::view::{self, Asker, Follow, HeldView};
use crate::clock::now_unix;
use crate::directory::node::Directory;
use crate::directory::serve::Running;
use crate::host::transport::endpoint_addr;

/// Root 1; the directory 40; hosts 50 (ours) and 51 (payroll's); a
/// banned node 52; the caller 60 (`caller@example.com`).
struct World {
    root: NodeIdentity,
    dir_node: NodeIdentity,
    ours: NodeIdentity,
    payroll_host: NodeIdentity,
    banned: NodeIdentity,
    caller: NodeIdentity,
    book: MemoryLookup,
}

/// A running directory.
struct Serving {
    dir: Arc<Directory>,
    _router: Router,
}

impl World {
    fn new() -> World {
        World {
            root: NodeIdentity::from_seed([1u8; 32]),
            dir_node: NodeIdentity::from_seed([40u8; 32]),
            ours: NodeIdentity::from_seed([50u8; 32]),
            payroll_host: NodeIdentity::from_seed([51u8; 32]),
            banned: NodeIdentity::from_seed([52u8; 32]),
            caller: NodeIdentity::from_seed([60u8; 32]),
            book: MemoryLookup::new(),
        }
    }

    /// The policy at `version`: `staff` is anyone the mock IdP signed in,
    /// `payroll-team` a stranger; `orders-db` and `status` on our host for
    /// staff, `payroll` on another host for payroll-team; one ban; the
    /// directory listed; then `edit`.
    fn policy(&self, version: u64, edit: impl FnOnce(&mut Policy)) -> SignedPolicy {
        let idp = crate::testutil::test_idp();
        let mut p = Policy::new(self.root.node_id());
        p.version = StateVersion(version);
        p.issued = now_unix();
        p.not_after = i64::MAX;
        p.directories = vec![self.dir_node.node_id()];
        p.roles
            .insert(role("staff"), vec![Matcher::new(idp.issuer.as_str())]);
        p.roles.insert(
            role("payroll-team"),
            vec![Matcher {
                email: Some("paymaster@example.com".parse().unwrap()),
                ..Matcher::new(idp.issuer.as_str())
            }],
        );
        let on = |host: &NodeIdentity, allow: &str, description: &str| Service {
            description: description.into(),
            allow: vec![role(allow)],
            hosts: vec![host.node_id()],
            readers: vec![],
        };
        p.services.insert(
            service("orders-db"),
            on(&self.ours, "staff", "Read-only SQL over the orders"),
        );
        p.services
            .insert(service("status"), on(&self.ours, "staff", "Build status"));
        p.services.insert(
            service("payroll"),
            on(&self.payroll_host, "payroll-team", "Salaries"),
        );
        p.ban(self.banned.node_id(), i64::MAX);
        edit(&mut p);
        crate::testutil::signed_policy(&self.root, p)
    }

    /// The directory, holding `policy`, serving on loopback.
    async fn directory(&self, policy: &SignedPolicy) -> Serving {
        let ks = Arc::new(Keystore::at(crate::testutil::temp_dir()));
        let dir = Directory::open(
            self.dir_node.duplicate(),
            self.root.node_id(),
            ks,
            64,
            now_unix(),
        )
        .unwrap();
        assert!(dir.accept(policy, now_unix()).unwrap());
        let endpoint = bind_in(&self.dir_node, &self.book).await;
        self.book.add_endpoint_info(
            endpoint_addr(&self.dir_node.node_id(), &localhost_socks(&endpoint), None).unwrap(),
        );
        let router = Running::mount(Router::builder(endpoint), &dir).spawn();
        Serving {
            dir,
            _router: router,
        }
    }

    /// The caller's keystore as `wires join` leaves it (its key, badge and
    /// the directory ids), plus an ID token when `signed_in`.
    fn caller_keystore(&self, signed_in: bool) -> Keystore {
        let ks = Keystore::at(crate::testutil::temp_dir());
        ks.save_node(&self.caller).unwrap();
        ks.save_membership(&self.badge()).unwrap();
        view::save_joined_directories(&ks, &[self.dir_node.node_id()]).unwrap();
        if signed_in {
            let token = crate::testutil::test_id_token(&self.caller.node_id());
            std::fs::write(ks.path(ID_TOKEN_FILE), token.as_str()).unwrap();
        }
        ks
    }

    fn badge(&self) -> Membership {
        Membership::mint(&self.root, self.caller.node_id(), 0, i64::MAX).unwrap()
    }

    async fn caller_endpoint(&self) -> Endpoint {
        bind_in(&self.caller, &self.book).await
    }
}

/// Every file under `dir`, as text (lossy), with its name.
fn all_files(dir: &std::path::Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(all_files(&path));
        } else {
            let text = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
            out.push((path.display().to_string(), text));
        }
    }
    out
}

/// Card 37's first acceptance: after a view refresh, the caller's keystore
/// holds no role, no ban, no node id other than its services' hosts and
/// the directories, and no service it may not use.
#[tokio::test]
async fn a_callers_keystore_holds_only_its_view() {
    let w = World::new();
    let policy = w.policy(3, |_| {});
    let _dir = w.directory(&policy).await;
    let ks = w.caller_keystore(true);
    let endpoint = w.caller_endpoint().await;
    let asker = Asker {
        endpoint: &endpoint,
        badge: &w.badge(),
        id_token: crate::caller::hello::stored_token(&ks),
    };
    let held = view::refresh(&ks, &asker, false).await.unwrap();
    let names: Vec<&str> = held.callable().map(|e| e.entry.name.as_str()).collect();
    assert_eq!(names, ["orders-db", "status"]);
    assert_eq!(held.version(), StateVersion(3));
    assert!(held.fresh.is_some(), "the directory vouched for it");

    let files = all_files(&ks.path(""));
    assert!(
        files
            .iter()
            .any(|(name, _)| name.ends_with(view::VIEW_FILE))
    );
    assert!(
        !ks.path(crate::policy::store::POLICY_FILE).exists(),
        "no policy.json"
    );
    for (name, text) in &files {
        for absent in [
            "payroll",                       // a service it may not use
            "paymaster@example.com",         // a role's members
            "payroll-team",                  // a role it isn't in
            "\"roles\"",                     // any role definition
            "\"bans\"",                      // the ban list
            &w.banned.node_id().hex(),       // a banned node
            &w.payroll_host.node_id().hex(), // another service's host
        ] {
            assert!(!text.contains(absent), "{name} holds {absent:?}");
        }
    }
    // The only node ids it holds: the root, itself, its services' host and
    // the directory.
    let known = [
        w.root.node_id(),
        w.caller.node_id(),
        w.ours.node_id(),
        w.dir_node.node_id(),
    ];
    let text: String = files.iter().map(|(_, t)| t.as_str()).collect();
    for seed in 0..=255u8 {
        let id = NodeIdentity::from_seed([seed; 32]).node_id();
        if !known.contains(&id) {
            assert!(!text.contains(&id.hex()), "node {seed} is in the keystore");
        }
    }
    endpoint.close().await;
}

/// No token, no role: the view is empty. `resolve` finds one service only
/// for a caller that may use it.
#[tokio::test]
async fn without_a_verified_identity_the_view_is_empty() {
    let w = World::new();
    let _dir = w.directory(&w.policy(3, |_| {})).await;
    let endpoint = w.caller_endpoint().await;

    let anonymous = w.caller_keystore(false);
    let asker = Asker {
        endpoint: &endpoint,
        badge: &w.badge(),
        id_token: None,
    };
    let held = view::refresh(&anonymous, &asker, false).await.unwrap();
    assert!(held.view.entries.is_empty());
    assert_eq!(held.version(), StateVersion(3), "the head, though");
    let orders = service("orders-db");
    assert_eq!(
        view::resolve(&anonymous, &asker, &orders).await.unwrap(),
        None
    );

    let ks = w.caller_keystore(true);
    let asker = Asker {
        endpoint: &endpoint,
        badge: &w.badge(),
        id_token: crate::caller::hello::stored_token(&ks),
    };
    let found = view::resolve(&ks, &asker, &orders).await.unwrap().unwrap();
    assert_eq!(found.entry.name, orders);
    assert!(found.call);
    assert_eq!(
        view::resolve(&ks, &asker, &service("payroll"))
            .await
            .unwrap(),
        None,
        "a service it may not use resolves to nothing"
    );
    // A search by description, as `wires services orders` does locally.
    let held = view::refresh(&ks, &asker, false).await.unwrap();
    let found: Vec<&str> = held
        .view
        .matching("ORDERS")
        .iter()
        .map(|e| e.entry.name.as_str())
        .collect();
    assert_eq!(found, ["orders-db"]);
    endpoint.close().await;
}

/// Card 37: a new grant reaches a running `wires mcp` as
/// `tools/list_changed` within 2 s, and a revoked one disappears from its
/// tool list within 2 s.
#[tokio::test]
async fn a_grant_and_a_revocation_reach_a_running_mcp_within_2s() {
    let w = World::new();
    let v3 = w.policy(3, |_| {});
    let serving = w.directory(&v3).await;
    let ks = Arc::new(w.caller_keystore(true));
    let endpoint = w.caller_endpoint().await;

    // What `wires mcp` runs: the subscription, the mapping, the server.
    let token_ks = Arc::clone(&ks);
    let (mut views, follower) = view::follow(Follow {
        endpoint: endpoint.clone(),
        badge: w.badge(),
        id_token: Arc::new(move || crate::caller::hello::stored_token(&token_ks)),
        initial: None,
        fallback: view::joined_directories(&ks),
        persist: Some(Arc::clone(&ks)),
    });
    let first: Arc<HeldView> = tokio::time::timeout(PATIENCE, views.wait_for(Option::is_some))
        .await
        .unwrap()
        .unwrap()
        .clone()
        .unwrap();
    let tools = |held: &HeldView| with_services(ToolsConfig::default(), &held.view);
    let (tools_tx, tools_rx) = tokio::sync::watch::channel(tools(&first));
    let mapper = tokio::spawn(async move {
        while views.changed().await.is_ok() {
            let next = views.borrow_and_update().clone();
            if let Some(held) = next {
                tools_tx.send_replace(tools(&held));
            }
        }
    });
    let mut server = McpServer::new(tools(&first), NoCalls).with_list_changed();
    let (client, server_side) = tokio::io::duplex(64 * 1024);
    let (client_read, mut client_write) = tokio::io::split(client);
    let (server_read, server_write) = tokio::io::split(server_side);
    let served = tokio::spawn(async move {
        serve_following(
            &mut server,
            tokio::io::BufReader::new(server_read),
            server_write,
            Some(tools_rx),
        )
        .await
    });
    let mut lines = tokio::io::BufReader::new(client_read).lines();

    // A grant: `reports` for staff.
    let v4 = w.policy(4, |p| {
        p.services.insert(
            service("reports"),
            Service {
                description: "Weekly reports".into(),
                allow: vec![role("staff")],
                hosts: vec![w.ours.node_id()],
                readers: vec![],
            },
        );
    });
    let granted = Instant::now();
    assert!(serving.dir.accept(&v4, now_unix()).unwrap());
    let note: Value = serde_json::from_str(
        &tokio::time::timeout(Duration::from_secs(2), lines.next_line())
            .await
            .expect("no list_changed within 2 s of the grant")
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(note["method"], LIST_CHANGED);
    assert!(granted.elapsed() < Duration::from_secs(2));
    let names = |reply: &Value| -> Vec<String> {
        reply["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_owned())
            .collect()
    };
    let req = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
    client_write
        .write_all(format!("{req}\n").as_bytes())
        .await
        .unwrap();
    let reply: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(names(&reply), ["orders-db", "reports", "status"]);

    // A revocation: `reports` now needs payroll-team.
    let v5 = w.policy(5, |p| {
        p.services.insert(
            service("reports"),
            Service {
                description: "Weekly reports".into(),
                allow: vec![role("payroll-team")],
                hosts: vec![w.ours.node_id()],
                readers: vec![],
            },
        );
    });
    let revoked = Instant::now();
    assert!(serving.dir.accept(&v5, now_unix()).unwrap());
    let note: Value = serde_json::from_str(
        &tokio::time::timeout(Duration::from_secs(2), lines.next_line())
            .await
            .expect("no list_changed within 2 s of the revocation")
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(note["method"], LIST_CHANGED);
    let req = json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
    client_write
        .write_all(format!("{req}\n").as_bytes())
        .await
        .unwrap();
    let reply: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(names(&reply), ["orders-db", "status"]);
    assert!(revoked.elapsed() < Duration::from_secs(2));
    // The subscription kept view.json in step, for `wires call`.
    let stored = view::read(&ks, w.root.node_id()).unwrap().unwrap();
    assert_eq!(stored.version(), StateVersion(5));
    assert!(stored.entry(&service("reports")).is_none());

    drop(client_write);
    drop(lines);
    follower.abort();
    mapper.abort();
    let _ = served.await;
    endpoint.close().await;
}

/// A subscriber whose view doesn't take an update (here: it holds a view
/// cut for someone else) subscribes again and gets the whole view.
#[tokio::test]
async fn a_view_that_cannot_be_updated_is_fetched_whole_again() {
    let w = World::new();
    let v3 = w.policy(3, |_| {});
    let serving = w.directory(&v3).await;
    let ks = Arc::new(w.caller_keystore(true));
    let endpoint = w.caller_endpoint().await;
    let (mut views, follower) = view::follow(Follow {
        endpoint: endpoint.clone(),
        badge: w.badge(),
        id_token: Arc::new({
            let ks = Arc::clone(&ks);
            move || crate::caller::hello::stored_token(&ks)
        }),
        // A stale, wrong view: nothing in it.
        initial: Some(HeldView::fetched(v3.view_for(None, None), None, 0)),
        fallback: vec![],
        persist: None,
    });
    // The first frame is the whole view, whatever was held.
    let held = tokio::time::timeout(
        PATIENCE,
        views.wait_for(|v| v.as_ref().is_some_and(|h| !h.view.entries.is_empty())),
    )
    .await
    .unwrap()
    .unwrap()
    .clone()
    .unwrap();
    assert_eq!(held.callable().count(), 2);
    // Then updates apply on top of it.
    let v4 = w.policy(4, |p| {
        p.services.remove(&service("status"));
    });
    assert!(serving.dir.accept(&v4, now_unix()).unwrap());
    let held = tokio::time::timeout(
        PATIENCE,
        views.wait_for(|v| v.as_ref().is_some_and(|h| h.version() == StateVersion(4))),
    )
    .await
    .unwrap()
    .unwrap()
    .clone()
    .unwrap();
    let names: Vec<&str> = held.callable().map(|e| e.entry.name.as_str()).collect();
    assert_eq!(names, ["orders-db"]);
    follower.abort();
    endpoint.close().await;
}

/// A caller refreshing from a head the directory still keeps gets only
/// what changed (`view_update`), applies it, and holds the same view as a
/// whole fetch would give; a directory that no longer keeps it sends the
/// whole view.
#[tokio::test]
async fn a_refresh_from_a_kept_head_is_an_update() {
    use library::{DirectoryAnswer, DirectoryRequest};
    let w = World::new();
    let v3 = w.policy(3, |_| {});
    let serving = w.directory(&v3).await;
    let ks = w.caller_keystore(true);
    let endpoint = w.caller_endpoint().await;
    let asker = Asker {
        endpoint: &endpoint,
        badge: &w.badge(),
        id_token: crate::caller::hello::stored_token(&ks),
    };
    view::refresh(&ks, &asker, false).await.unwrap();
    // As the admin signs an edit: unchanged entries keep their signature.
    let mut p = v3.to_policy().unwrap();
    p.version = StateVersion(4);
    p.services.get_mut(&service("status")).unwrap().description = "Build status, now".into();
    let v4 = p.sign_after(&w.root, &v3).unwrap();
    assert!(serving.dir.accept(&v4, now_unix()).unwrap());
    // The frame itself: an update carrying the one changed entry.
    let answer = crate::directory::wire::ask(
        &endpoint,
        w.dir_node.node_id(),
        &w.badge(),
        asker.id_token.clone(),
        &DirectoryRequest::View {
            have: StateVersion(3),
            query: None,
        },
    )
    .await
    .unwrap();
    let DirectoryAnswer::ViewUpdate { update, .. } = answer else {
        panic!("expected a view_update, got {answer:?}");
    };
    assert_eq!(update.changed.len(), 1);
    assert!(update.removed.is_empty());
    // The caller's refresh applies it.
    let held = view::refresh(&ks, &asker, false).await.unwrap();
    assert_eq!(held.version(), StateVersion(4));
    let whole = w.caller_keystore(true);
    let fetched = view::refresh(&whole, &asker, true).await.unwrap();
    assert_eq!(held.view, fetched.view);
    endpoint.close().await;
}

/// A [`Caller`](crate::caller::call::Caller) for tests that list tools and
/// never call one.
struct NoCalls;

impl crate::caller::call::Caller for NoCalls {
    async fn call(
        &self,
        _tool: &crate::caller::tools::RemoteTool,
        _argv: library::Argv,
        _stdin: Vec<u8>,
    ) -> anyhow::Result<crate::caller::call::CallOutcome> {
        anyhow::bail!("this test calls nothing")
    }
}

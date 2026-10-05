//! Card 41's first run, as the admin, the workbench and the agent type it,
//! from empty keystores, every step a command's own code path over
//! hermetic loopback (a mock IdP stands in for Google, so `init` names it):
//!
//! ```text
//! admin$     wires init --client-id <id>
//! admin$     wires role set analyst '*@acme.com'
//! admin$     wires directory add workbench=<node id from `wires id` on the workbench>
//! admin$     wires service add orders-db --description "…" --allow analyst --host workbench
//! admin$     wires network                      # one string, for everyone
//! workbench$ wires join <network>
//! workbench$ wires serve host.json              # also the directory; waits for the first publish
//! admin$     wires policy push
//! agent$     wires login <network>
//! agent$     wires services
//! agent$     wires call orders-db -- "select count(*) from orders"
//! ```
//!
//! No step fails and none is repeated: the admin's edits before the
//! directory runs are notes, not failures; the directory starts empty and
//! takes the first publish; the agent signs in once. Then removal by person
//! (refused from a second machine too, within seconds of the publish), by
//! node, and `restore`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use iroh::address_lookup::memory::MemoryLookup;
use library::{Argv, NodeId, ServiceName};

use super::{PATIENCE, bind_in, localhost_socks};
use crate::admin::Report;
use crate::admin::init::init_in;
use crate::admin::keystore::{self, Keystore};
use crate::admin::propagate::{Propagation, settle};
use crate::caller::call::{CallOpts, Credentials, ServiceDial, call_service_with};
use crate::caller::join::{id_in, join_in};
use crate::caller::login::{
    ID_TOKEN_FILE, LoginArgs, OidcClient, read_settings, run_flow, save_secret,
};
use crate::caller::mock_idp::{MOCK_CLIENT_ID, MockIdp};
use crate::caller::pick::Hints;
use crate::caller::view::{self, Asker};
use crate::host::serve::{Binding, Serving, serve_until};
use crate::host::transport::{self, endpoint_addr};
use crate::policy::fetch::{held_directories, publish_current_on};
use crate::policy::store;
use crate::{Cli, Command};

/// `host.json` on the workbench: `orders-db` answers with a count.
const HOST_JSON: &str =
    r#"{"version":2,"services":{"orders-db":{"command":["sh","-c","echo 42"]}}}"#;

/// One admin command line, parsed as `wires` parses it.
fn cli(args: &[&str]) -> Command {
    Cli::try_parse_from(["wires"].iter().chain(args))
        .unwrap()
        .command
}

/// The network the first run builds, ready for more.
struct FirstRun {
    book: MemoryLookup,
    idp: MockIdp,
    admin: Keystore,
    admin_ep: iroh::Endpoint,
    root: NodeId,
    network: String,
    workbench: NodeId,
    workbench_ks: Arc<Keystore>,
    workbench_socks: Vec<std::net::SocketAddr>,
    agent: Agent,
    _serving: tokio::sync::oneshot::Sender<()>,
}

/// A signed-in caller on its own machine.
struct Agent {
    ks: Keystore,
    creds: Credentials,
    endpoint: iroh::Endpoint,
}

/// An admin edit as `run_edit` makes it: `edit` against `admin`, then the
/// publish over `endpoint`, settled; the command's notes and outcome.
async fn edit(
    admin: &Keystore,
    endpoint: &iroh::Endpoint,
    edit: impl FnOnce(&Keystore) -> Report,
) -> (Report, Propagation) {
    let earlier = held_directories(admin).unwrap();
    let report = edit(admin);
    let root = store::fabric(admin).unwrap().unwrap();
    let version = store::read(admin, root).unwrap().unwrap().version();
    let published = publish_current_on(endpoint, admin, &earlier).await;
    (report, settle(admin, published.map(|r| (version, r))))
}

/// `wires login <network>` on a fresh machine, over `book`:
/// join, sign in at the mock IdP (as the network string says), store the
/// token, and take the view from a directory.
async fn login(book: &MemoryLookup, idp: &MockIdp, network: &str) -> Agent {
    let ks = Keystore::at(crate::testutil::temp_dir());
    let joined = join_in(&ks, network).unwrap();
    let node = keystore::node_identity_in(&ks).unwrap();
    let me = node.node_id();
    let client = OidcClient::resolve(&LoginArgs::default(), read_settings(&ks)).unwrap();
    assert_eq!(client.issuer, idp.issuer);
    // As `wires login` builds it: the key cache in the keystore.
    let fetcher =
        crate::caller::jwks::KeyFetcher::new(Some(ks.path(crate::caller::jwks::JWKS_DIR))).unwrap();
    let signed_in = run_flow(&fetcher, &client, me, 0, idp.browser(), PATIENCE)
        .await
        .unwrap();
    save_secret(&ks.path(ID_TOKEN_FILE), signed_in.claim.id_token.as_str()).unwrap();
    let endpoint = bind_in(&node, book).await;
    let asker = Asker {
        endpoint: &endpoint,
        root: joined.root,
        id_token: crate::caller::hello::stored_token(&ks),
    };
    view::refresh(&ks, &asker, true).await.unwrap();
    Agent {
        creds: Credentials::of(node, joined.root),
        ks,
        endpoint,
    }
}

impl Agent {
    /// `wires services`: the listing from the view it holds.
    fn services(&self, root: NodeId) -> String {
        let held = view::read(&self.ks, root).unwrap().unwrap();
        crate::caller::services::render(&held.view.entries.iter().collect::<Vec<_>>(), false)
    }

    /// `wires call orders-db -- <arg>` against the workbench, from the view
    /// it holds (a fresh one: `wires call` asks no directory first): the
    /// exit code and stdout, or the host's refusal.
    async fn call(&self, run: &FirstRun, arg: &str) -> Result<(i32, String), String> {
        let held = view::read(&self.ks, run.root).unwrap().unwrap();
        let dial = ServiceDial {
            endpoint: &self.endpoint,
            hints: Hints::from_pairs([(run.workbench, run.workbench_socks.clone())]),
            timeout: Duration::from_secs(5),
        };
        let mut stdout = Vec::new();
        let r = call_service_with(
            &self.creds,
            &self.ks,
            &held,
            &ServiceName::new("orders-db").unwrap(),
            &dial,
            Argv::new(vec![arg.to_string()]).unwrap(),
            std::io::Cursor::new(Vec::new()),
            &mut stdout,
            Vec::new(),
            CallOpts::default(),
        )
        .await;
        match r {
            Ok(code) => Ok((code, String::from_utf8(stdout).unwrap())),
            Err(e) => match e.downcast_ref::<transport::Denied>() {
                Some(d) => Err(d.reason().to_string()),
                None => panic!("a call failed: {e:#}"),
            },
        }
    }
}

/// The eleven commands, in order, from empty keystores. Every step's
/// outcome is checked: none fails, and none is repeated.
async fn first_run() -> FirstRun {
    let book = MemoryLookup::new();
    let idp = MockIdp::start("alice@acme.com").await;

    // admin$ wires init --client-id <id>
    let admin = Keystore::at(crate::testutil::temp_dir());
    let Command::Init(mut init) = cli(&["init", "--client-id", MOCK_CLIENT_ID]) else {
        unreachable!()
    };
    // The mock IdP stands in for Google's default issuer.
    init.issuer = idp.issuer.as_str().to_string();
    init.public_client_secret = Some("not-so-secret".into());
    let out = init_in(&admin, init).unwrap();
    assert!(out.contains("wires directory add"), "{out}");
    let root = admin.network_root().unwrap().unwrap();
    let admin_node = keystore::node_identity_in(&admin).unwrap();
    let admin_ep = bind_in(&admin_node, &book).await;

    // admin$ wires role set analyst '*@acme.com'
    let Command::Role(role) = cli(&["role", "set", "analyst", "*@acme.com"]) else {
        unreachable!()
    };
    let (_, published) = edit(&admin, &admin_ep, |ks| Report {
        stdout: crate::admin::service::role_in(ks, role).unwrap(),
        ..Report::default()
    })
    .await;
    assert_eq!(published.failure, None, "{}", published.note);
    assert!(
        published.note.contains("no directory to publish to yet"),
        "{}",
        published.note
    );

    // admin$ wires directory add workbench=<node id from `wires id` there>
    let workbench_ks = Arc::new(Keystore::at(crate::testutil::temp_dir()));
    let (workbench, _) = id_in(&workbench_ks).unwrap();
    let Command::Directory(dir) = cli(&[
        "directory",
        "add",
        &format!("workbench={}", workbench.hex()),
    ]) else {
        unreachable!()
    };
    let (_, published) = edit(&admin, &admin_ep, |ks| {
        let stdout = crate::directory::edit_in(ks, dir.cmd).unwrap();
        let hint = crate::directory::next_step(ks, "workbench").unwrap();
        assert!(hint.contains("wires join <network>"), "{hint}");
        Report {
            stdout,
            hint: Some(hint),
            ..Report::default()
        }
    })
    .await;
    assert_eq!(published.failure, None, "{}", published.note);
    assert!(
        published.note.contains("wires policy push"),
        "{}",
        published.note
    );

    // admin$ wires service add orders-db --description "…" --allow analyst --host workbench
    let Command::Service(svc) = cli(&[
        "service",
        "add",
        "orders-db",
        "--description",
        "Read-only SQL over the orders database",
        "--allow",
        "analyst",
        "--host",
        "workbench",
    ]) else {
        unreachable!()
    };
    let (_, published) = edit(&admin, &admin_ep, |ks| Report {
        stdout: crate::admin::service::service_in(ks, svc).unwrap(),
        ..Report::default()
    })
    .await;
    assert_eq!(published.failure, None, "{}", published.note);

    // admin$ wires network
    let network = crate::admin::network::network_in(&admin).unwrap();
    assert!(network.notes.is_empty(), "{:?}", network.notes);
    let network = network.stdout;

    // workbench$ wires join <network>
    let joined = join_in(&workbench_ks, &network).unwrap();
    assert_eq!(joined.root, root);
    assert_eq!(joined.directories, [workbench]);

    // workbench$ wires serve host.json   (also the directory; waits)
    let workbench_node = keystore::node_identity_in(&workbench_ks).unwrap();
    let workbench_ep = bind_in(&workbench_node, &book).await;
    let workbench_socks = localhost_socks(&workbench_ep);
    book.add_endpoint_info(endpoint_addr(&workbench, &workbench_socks, None).unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let serving = Serving {
        node: workbench_node,
        root,
        keystore: Arc::clone(&workbench_ks),
        config: crate::host::config::HostConfig::parse(HOST_JSON).unwrap(),
        native: Default::default(),
        binding: Binding::Endpoint(workbench_ep),
    };
    tokio::spawn(async move {
        let r = serve_until(serving, async {
            let _ = stopped.await;
            Ok(())
        })
        .await;
        if let Err(e) = r {
            panic!("serve failed: {e:#}");
        }
    });
    // It runs, empty: no policy yet.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(store::read(&workbench_ks, root).unwrap().is_none());

    // admin$ wires policy push
    let earlier = held_directories(&admin).unwrap();
    let version = store::read(&admin, root).unwrap().unwrap().version();
    let pushed = publish_current_on(&admin_ep, &admin, &earlier).await;
    let pushed = settle(&admin, pushed.map(|r| (version, r)));
    assert_eq!(pushed.failure, None, "{}", pushed.note);
    assert!(
        pushed.note.contains("published to 1 of 1"),
        "{}",
        pushed.note
    );

    // agent$ wires login <network>
    let agent = login(&book, &idp, &network).await;

    let run = FirstRun {
        book,
        idp,
        admin,
        admin_ep,
        root,
        network,
        workbench,
        workbench_ks,
        workbench_socks,
        agent,
        _serving: stop,
    };
    // agent$ wires services
    let listed = run.agent.services(root);
    assert!(listed.starts_with("orders-db  Read-only SQL"), "{listed}");
    assert!(listed.contains("(analyst)"), "{listed}");
    // agent$ wires call orders-db -- "select count(*) from orders"
    let ran = run
        .agent
        .call(&run, "select count(*) from orders")
        .await
        .unwrap();
    assert_eq!(ran, (0, "42\n".to_string()));
    run
}

#[tokio::test]
async fn the_first_run_works_from_empty_keystores() {
    let run = first_run().await;
    // The network string is everything the agent needed to join.
    assert!(
        run.agent
            .ks
            .path(crate::admin::keystore::NETWORK_FILE)
            .exists()
    );
    // Every file the three keystores now hold is private (protocol.md §8):
    // the policy and its lock, the directory's store, the key cache, …
    #[cfg(unix)]
    for ks in [&run.admin, &*run.workbench_ks, &run.agent.ks] {
        crate::testutil::assert_private(&ks.path(""));
    }
    run.admin_ep.close().await;
}

/// `wires remove alice@acme.com`: refused on her machine and on a second
/// one she signs in from, within seconds of the publish; `wires restore`
/// lets her back.
#[tokio::test]
async fn a_removed_person_is_refused_from_every_machine_until_restored() {
    let run = first_run().await;
    let second = login(&run.book, &run.idp, &run.network).await;
    assert_eq!(second.call(&run, "1").await.unwrap().0, 0);

    let Command::Remove(who) = cli(&["remove", "alice@acme.com"]) else {
        unreachable!()
    };
    let removed_at = Instant::now();
    let (report, published) = edit(&run.admin, &run.admin_ep, |ks| {
        crate::admin::remove::remove_in(ks, who).unwrap()
    })
    .await;
    assert!(
        report.stdout.contains("removed alice@acme.com"),
        "{}",
        report.stdout
    );
    assert_eq!(published.failure, None, "{}", published.note);
    for agent in [&run.agent, &second] {
        let refused = agent.call(&run, "2").await.unwrap_err();
        assert_eq!(refused, crate::host::gate::NOT_ADMITTED);
    }
    assert!(
        removed_at.elapsed() < Duration::from_secs(5),
        "{:?}",
        removed_at.elapsed()
    );

    let Command::Restore(who) = cli(&["restore", "alice@acme.com"]) else {
        unreachable!()
    };
    let (_, published) = edit(&run.admin, &run.admin_ep, |ks| {
        crate::admin::remove::restore_in(ks, who).unwrap()
    })
    .await;
    assert_eq!(published.failure, None, "{}", published.note);
    assert_eq!(second.call(&run, "3").await.unwrap().0, 0);
    run.admin_ep.close().await;
}

/// `wires remove <node>`: that machine is refused whoever signs in on it,
/// and the same person on another machine is not; `restore` lifts it.
#[tokio::test]
async fn a_removed_node_is_refused_and_restored() {
    let run = first_run().await;
    let second = login(&run.book, &run.idp, &run.network).await;
    let laptop = run.agent.creds.node_id().hex();
    let Command::Remove(who) = cli(&["remove", &format!("laptop={laptop}")]) else {
        unreachable!()
    };
    let (_, published) = edit(&run.admin, &run.admin_ep, |ks| {
        crate::admin::remove::remove_in(ks, who).unwrap()
    })
    .await;
    assert_eq!(published.failure, None, "{}", published.note);
    let refused = run.agent.call(&run, "1").await.unwrap_err();
    assert_eq!(refused, crate::host::gate::NOT_ADMITTED);
    assert_eq!(second.call(&run, "2").await.unwrap().0, 0);

    let Command::Restore(who) = cli(&["restore", "laptop"]) else {
        unreachable!()
    };
    let (_, published) = edit(&run.admin, &run.admin_ep, |ks| {
        crate::admin::remove::restore_in(ks, who).unwrap()
    })
    .await;
    assert_eq!(published.failure, None, "{}", published.note);
    assert_eq!(run.agent.call(&run, "3").await.unwrap().0, 0);
    run.admin_ep.close().await;
}

/// Before any directory has taken a publish, an edit that reaches none is
/// a note; once one has, reaching none fails as ever.
#[tokio::test]
async fn reaching_no_directory_fails_only_after_the_first_run() {
    let run = first_run().await;
    drop(run._serving);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let Command::Role(role) = cli(&["role", "set", "ops", "*@acme.com"]) else {
        unreachable!()
    };
    let (_, published) = edit(&run.admin, &run.admin_ep, |ks| Report {
        stdout: crate::admin::service::role_in(ks, role).unwrap(),
        ..Report::default()
    })
    .await;
    assert!(published.failure.is_some(), "{}", published.note);
    run.admin_ep.close().await;
}

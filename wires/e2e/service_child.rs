//! Card 28 §1's acceptance tests: **the service child is not the host.**
//!
//! A real `serve`-shaped host (session ALPN, both push control sockets, the
//! push service) runs a service that prints its environment. The test then
//! plays that child: it uses exactly what the child was given.
//!
//! - [`a_child_gets_a_minimal_environment_and_a_push_capability`]: no
//!   `WIRES_HOME`, no `HOME`, nothing inherited beyond `PATH` and the
//!   locale; a `WIRES_PUSH_SOCKET` + `WIRES_PUSH_TOKEN` instead.
//! - [`the_capability_reaches_only_the_caller`]: the child's push reaches its
//!   caller and is logged under the call; another node, a role and the
//!   operator's request form are refused; the operator's own socket still
//!   pushes to a role.
//! - [`a_rolled_back_state_is_refused`]: a state older than one the host
//!   already decided under, copied back onto disk, decides nothing.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use iroh::EndpointAddr;
use iroh::protocol::Router;
use library::{AuditRecord, CallId, Hello, NodeIdentity, PushBody, Service, SignedState, Subject};
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::{
    Outcome, PATIENCE, adopt, bind, email_at, host_config, localhost_socks, membership, role,
    service, signed_state,
};
use crate::admin::keystore::Keystore;
use crate::caller::mock_idp::MockIdp;
use crate::host::config::HostConfig;
use crate::host::control::ControlClient;
use crate::host::push::{PushHost, PushSpec, host_socket};
use crate::host::serve::{push_sockets, services_host, services_router};
use crate::host::transport::{AuditSink, endpoint_addr};

/// Root 1, host 10, alice 2 (an analyst, signed in), bob 3.
struct World {
    root: NodeIdentity,
    host: NodeIdentity,
    alice: NodeIdentity,
    bob: NodeIdentity,
    idp: MockIdp,
}

impl World {
    async fn new() -> Self {
        Self {
            root: NodeIdentity::from_seed([1u8; 32]),
            host: NodeIdentity::from_seed([10u8; 32]),
            alice: NodeIdentity::from_seed([2u8; 32]),
            bob: NodeIdentity::from_seed([3u8; 32]),
            idp: MockIdp::start("alice@example.com").await,
        }
    }

    /// Everyone a member; role `analyst` = alice; service `env` (analyst) on
    /// the host.
    fn state(&self, version: u64) -> SignedState {
        signed_state(&self.root, version, |s| {
            s.members.extend([
                self.alice.node_id(),
                self.bob.node_id(),
                self.host.node_id(),
            ]);
            s.hosts.insert(self.host.node_id());
            s.roles.insert(
                role("analyst"),
                vec![email_at(&self.idp, "alice@example.com")],
            );
            s.services.insert(
                service("env"),
                Service {
                    description: String::new(),
                    allow: vec![role("analyst")],
                    hosts: vec![self.host.node_id()],
                    readers: vec![],
                },
            );
        })
    }

    /// `env` prints its environment; push to analysts.
    fn host_json(&self) -> HostConfig {
        host_config(
            &[&self.idp],
            r#"{"env":{"command":["env"],"env":{"FROM_HOST_JSON":"yes"}}}"#,
            r#","push":{"allow":["analyst"]}"#,
        )
    }

    fn hello(&self, who: &NodeIdentity) -> Hello {
        super::hello(&self.root, who, 1, Some(&self.idp))
    }
}

/// A running host with push on: router, both control sockets, the push
/// service, its call log's records.
struct Host {
    _router: Router,
    _sockets: Vec<tokio::task::JoinHandle<()>>,
    addr: EndpointAddr,
    home: PathBuf,
    records: mpsc::Receiver<AuditRecord>,
}

impl Host {
    async fn start(w: &World) -> Host {
        let home = crate::testutil::temp_dir();
        let keystore = Arc::new(Keystore::at(home.clone()));
        adopt(&keystore, &w.root, &w.state(1));
        let mut host = services_host(
            w.host.node_id(),
            membership(&w.root, &w.host),
            Arc::clone(&keystore),
            w.host_json(),
        )
        .unwrap();
        host.preflight(crate::clock::now_unix()).unwrap();
        let (sink, records) = AuditSink::channel(64);
        host.audit = Some(sink);
        let host = Arc::new(host);
        let push = Arc::new(PushHost::from_state(Arc::clone(&host)));
        let (tx, commands) = mpsc::channel(16);
        let sockets = push_sockets(&home, &host, tx).await.unwrap();
        tokio::spawn(Arc::clone(&push).run(commands));
        let endpoint = bind(&w.host).await;
        let addr = endpoint_addr(&w.host.node_id(), &localhost_socks(&endpoint), None).unwrap();
        let router = services_router(endpoint, host, Some(push));
        Host {
            _router: router,
            _sockets: sockets,
            addr,
            home,
            records,
        }
    }

    async fn record(&mut self) -> AuditRecord {
        timeout(PATIENCE, self.records.recv())
            .await
            .expect("no record in time")
            .expect("the sink closed")
    }
}

/// Call `env` on `host` as `who` ([`super::call`]): the child's environment,
/// or the refusal.
async fn call_env(
    w: &World,
    who: &NodeIdentity,
    host: &Host,
) -> Result<BTreeMap<String, String>, String> {
    match super::call(who, &host.addr, w.hello(who), "env", &[]).await {
        Outcome::Denied(reason) => Err(reason),
        ran => Ok(ran
            .stdout()
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()),
    }
}

fn spec(to: &str) -> PushSpec {
    PushSpec {
        to: to.to_string(),
        subject: Subject::new("build-41").unwrap(),
        body: PushBody::new("failed").unwrap(),
        ttl_secs: None,
    }
}

#[tokio::test]
async fn a_child_gets_a_minimal_environment_and_a_push_capability() {
    let w = World::new().await;
    let host = Host::start(&w).await;
    let env = call_env(&w, &w.alice, &host).await.unwrap();

    // Nothing of the host's own. (This test process has a HOME; the child
    // must not.)
    for gone in [
        "WIRES_HOME",
        "HOME",
        "SSH_AUTH_SOCK",
        "USER",
        "WIRES_NODE_SEED",
    ] {
        assert!(
            !env.contains_key(gone),
            "{gone} leaked into the child: {env:?}"
        );
    }
    for key in env.keys() {
        assert!(
            ["PATH", "LANG", "FROM_HOST_JSON", "PWD", "SHLVL", "_"].contains(&key.as_str())
                || key.starts_with("LC_")
                || key.starts_with("WIRES_"),
            "{key} is not on the child's allowlist: {env:?}"
        );
    }
    assert_eq!(env["FROM_HOST_JSON"], "yes");
    assert_eq!(env["WIRES_CALLER_NODE"], w.alice.node_id().hex());
    assert_eq!(env["WIRES_ROLE"], "analyst");
    // The capability, instead of the keystore.
    assert_eq!(env["WIRES_PUSH_TOKEN"].len(), 64);
    let socket = PathBuf::from(&env["WIRES_PUSH_SOCKET"]);
    assert_ne!(socket, host_socket(&host.home), "not the operator's socket");
    assert!(socket.exists());
    // Its path gives away neither the keystore nor the operator socket.
    let home = host.home.canonicalize().unwrap();
    let dir = socket.parent().unwrap().canonicalize().unwrap();
    assert!(
        !dir.starts_with(&home),
        "{} is inside the keystore {}",
        dir.display(),
        home.display()
    );
    assert_ne!(
        Some(dir.as_path()),
        host_socket(&host.home)
            .parent()
            .and_then(|p| p.canonicalize().ok())
            .as_deref()
    );
    for (key, value) in &env {
        assert!(
            !value.contains(home.to_str().unwrap()) && !value.contains(host.home.to_str().unwrap()),
            "{key} names the keystore: {value}"
        );
    }
}

#[tokio::test]
async fn the_capability_reaches_only_the_caller() {
    let w = World::new().await;
    let mut host = Host::start(&w).await;
    let env = call_env(&w, &w.alice, &host).await.unwrap();
    let call: CallId = match host.record().await {
        AuditRecord::Started { call, .. } => call,
        other => panic!("expected started, got {other:?}"),
    };
    assert!(matches!(host.record().await, AuditRecord::Finished { .. }));
    let socket = PathBuf::from(&env["WIRES_PUSH_SOCKET"]);
    let token = env["WIRES_PUSH_TOKEN"].clone();
    let mut child = ControlClient::connect_child(&socket)
        .await
        .unwrap()
        .unwrap();

    // Its caller, after the call ended: accepted, and logged under the call.
    let report = child
        .caller_push(token.clone(), spec(&w.alice.node_id().hex()))
        .await
        .unwrap();
    assert!(report.any_accepted(), "{}", report.render());
    match host.record().await {
        AuditRecord::Push { to, call: via, .. } => {
            assert_eq!(to, w.alice.node_id());
            assert_eq!(via, Some(call), "the record names the call's capability");
        }
        other => panic!("expected a push record, got {other:?}"),
    }

    // Anyone else, a role, or a guessed token: refused.
    for (token, to, why) in [
        (
            token.clone(),
            w.bob.node_id().hex(),
            "reaches only its caller",
        ),
        (
            token.clone(),
            "analyst".to_string(),
            "reaches only its caller",
        ),
        (
            "0".repeat(64),
            w.alice.node_id().hex(),
            "unknown or expired",
        ),
    ] {
        let e = format!(
            "{:#}",
            child.caller_push(token, spec(&to)).await.unwrap_err()
        );
        assert!(e.contains(why), "{to}: {e}");
    }
    // The operator's form, on the child socket: refused.
    let e = format!("{:#}", child.push(spec("analyst")).await.unwrap_err());
    assert!(e.contains("takes only a call's push"), "{e}");

    // The operator's own socket keeps full power: a role.
    let mut operator = ControlClient::connect(&host_socket(&host.home))
        .await
        .unwrap()
        .unwrap();
    let report = operator.push(spec("analyst")).await.unwrap();
    assert_eq!(report.results.len(), 1, "{}", report.render());
    assert_eq!(report.results[0].to, w.alice.node_id());
    match host.record().await {
        AuditRecord::Push { call: via, .. } => assert_eq!(via, None),
        other => panic!("expected a push record, got {other:?}"),
    }
}

#[tokio::test]
async fn a_rolled_back_state_is_refused() {
    let w = World::new().await;
    let host = Host::start(&w).await;
    let ks = Keystore::at(&host.home);
    assert!(adopt(&ks, &w.root, &w.state(2)));
    call_env(&w, &w.alice, &host).await.unwrap();
    // Version 1 copied back over version 2: it verifies, and is refused.
    let old = w.state(1).encode().unwrap();
    std::fs::write(ks.path(crate::state::store::STATE_FILE), format!("{old}\n")).unwrap();
    let refused = call_env(&w, &w.alice, &host).await.unwrap_err();
    assert_eq!(refused, "responder configuration error");
}

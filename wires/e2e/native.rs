//! Card 33's acceptance tests: **an app serves wires calls in-process**
//! through an embedded [`Host`](crate::Host), and to a caller it is a CLI
//! service like any other.
//!
//! The host is the one `examples/kv/` ships (included below), built with
//! [`Host::builder`](crate::Host::builder) from a joined keystore and served
//! on a hermetic loopback endpoint. Callers dial it with the dial `wires
//! call` uses ([`call_service_on`]).
//!
//! - [`a_native_service_is_called_like_a_cli`]: state kept across calls,
//!   keyed by the verified person; stdin in, stdout out, exit codes back.
//! - [`a_refused_caller_never_reaches_the_handler`]
//! - [`a_native_call_is_logged_like_a_cli_call`]: the host's own signed,
//!   hash-linked log (what `wires watch` streams) holds `Started` and
//!   `Finished` with the caller's identity, role, and stdio digests.
//! - [`an_unassigned_native_service_refuses_to_start`]
//! - [`a_native_service_pushes_to_its_caller`]: `push_to_caller` goes through
//!   the call's push capability and `push.allow`, and is logged naming the
//!   call; a host without push says so, and `push.allow` refuses a caller
//!   in none of its roles.
//! - [`each_verified_person_gets_their_own_kv`]: two admitted people, two
//!   namespaces.
//! - [`native_and_cli_services_share_one_host`]: `host.json`'s CLI services
//!   beside the native ones, through the same gate and log.
//! - [`a_stopped_host_closes_its_endpoint`]: nothing outlives `serve_until`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use iroh::{Endpoint, EndpointAddr};
use library::{
    AuditRecord, Hello, Invocation, Matcher, Membership, NodeIdentity, OidcNonce, OutputHasher,
    RoleName, Service as Registered, ServiceName, SignedState, State, StateVersion,
};
use tokio::sync::oneshot;

use super::{PATIENCE, localhost_socks};
use crate::admin::keystore::Keystore;
use crate::caller::mock_idp::{MOCK_CLIENT_ID, MockIdp};
use crate::host::transport::{Denied, call_service_on, endpoint_addr, secret_key};
use crate::{Call, CallIo, Host, Service};

#[path = "../examples/kv/store.rs"]
mod kv_example;

/// Root 1, the embedded host 20, alice 2 (role `analyst`), bob 3 (role
/// `ops`, which the tests allow only where they say so).
struct World {
    root: NodeIdentity,
    host: NodeIdentity,
    alice: NodeIdentity,
    bob: NodeIdentity,
    idp_alice: MockIdp,
    idp_bob: MockIdp,
}

impl World {
    async fn new() -> Self {
        Self {
            root: NodeIdentity::from_seed([1u8; 32]),
            host: NodeIdentity::from_seed([20u8; 32]),
            alice: NodeIdentity::from_seed([2u8; 32]),
            bob: NodeIdentity::from_seed([3u8; 32]),
            idp_alice: MockIdp::start("alice@example.com").await,
            idp_bob: MockIdp::start("bob@example.com").await,
        }
    }

    /// The signed state: alice and bob are members; role `analyst` is
    /// alice's email at her IdP and `ops` bob's at his; each of `services`
    /// is on the host, for `analyst`.
    fn state(&self, services: &[&str]) -> SignedState {
        self.state_allowing(services, &["analyst"])
    }

    /// [`state`](Self::state), with each service allowed to `allow`.
    fn state_allowing(&self, services: &[&str], allow: &[&str]) -> SignedState {
        let mut s = State::new(self.root.node_id());
        s.version = StateVersion(1);
        s.issued = crate::clock::now_unix();
        s.not_after = i64::MAX;
        s.members.extend([
            self.host.node_id(),
            self.alice.node_id(),
            self.bob.node_id(),
        ]);
        s.hosts.insert(self.host.node_id());
        s.roles.insert(
            RoleName::new("analyst").unwrap(),
            vec![Matcher {
                email: Some("alice@example.com".parse().unwrap()),
                ..Matcher::new(self.idp_alice.issuer.as_str())
            }],
        );
        s.roles.insert(
            RoleName::new("ops").unwrap(),
            vec![Matcher {
                email: Some("bob@example.com".parse().unwrap()),
                ..Matcher::new(self.idp_bob.issuer.as_str())
            }],
        );
        for name in services {
            s.services.insert(
                ServiceName::new(*name).unwrap(),
                Registered {
                    description: String::new(),
                    allow: allow.iter().map(|r| RoleName::new(*r).unwrap()).collect(),
                    hosts: vec![self.host.node_id()],
                    readers: vec![],
                },
            );
        }
        s.sign(&self.root).unwrap()
    }

    /// The host's keystore, as `wires id` + `wires join` leave it: its node
    /// key, its membership, and `state`.
    fn keystore(&self, state: &SignedState) -> std::path::PathBuf {
        let home = crate::testutil::temp_dir();
        let ks = Keystore::at(&home);
        ks.save_node(&self.host, false).unwrap();
        ks.save_membership(&self.membership(&self.host)).unwrap();
        crate::state::store::adopt_if_newer(
            &ks,
            state,
            self.root.node_id(),
            crate::clock::now_unix(),
        )
        .unwrap();
        home
    }

    fn membership(&self, who: &NodeIdentity) -> Membership {
        Membership::mint(&self.root, who.node_id(), 0, i64::MAX).unwrap()
    }

    /// A builder for the host on `home`, trusting both IdPs.
    fn builder(&self, home: &std::path::Path) -> crate::HostBuilder {
        Host::builder(home)
            .trust_issuer(self.idp_alice.issuer.as_str(), [MOCK_CLIENT_ID])
            .trust_issuer(self.idp_bob.issuer.as_str(), [MOCK_CLIENT_ID])
    }

    /// `who`'s `Hello`, signed in at its own IdP.
    fn hello(&self, who: &NodeIdentity) -> Hello {
        let idp = if who.node_id() == self.alice.node_id() {
            &self.idp_alice
        } else {
            &self.idp_bob
        };
        Hello {
            membership: self.membership(who),
            state_version: StateVersion(1),
            id_token: Some(idp.mint(
                &OidcNonce::for_node(&who.node_id()),
                crate::clock::now_unix() + 3600,
            )),
        }
    }
}

/// An embedded host serving on loopback until dropped.
struct Running {
    addr: EndpointAddr,
    /// The host's endpoint (a handle to the one it serves on).
    endpoint: Endpoint,
    home: std::path::PathBuf,
    stop: Option<oneshot::Sender<()>>,
    served: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Running {
    /// Serve `host` (built for `w.host`) on a fresh loopback endpoint.
    async fn start(w: &World, host: Host, home: std::path::PathBuf) -> Running {
        let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(secret_key(&w.host))
            .bind()
            .await
            .unwrap();
        let addr = endpoint_addr(&w.host.node_id(), &localhost_socks(&endpoint), None).unwrap();
        let (stop, stopped) = oneshot::channel::<()>();
        let served = tokio::spawn(host.on_endpoint(endpoint.clone()).serve_until(async move {
            let _ = stopped.await;
        }));
        Running {
            addr,
            endpoint,
            home,
            stop: Some(stop),
            served,
        }
    }

    /// Stop serving and return how serving ended.
    async fn stop(mut self) -> anyhow::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        tokio::time::timeout(PATIENCE, &mut self.served)
            .await
            .expect("the host should stop")
            .unwrap()
    }
}

/// What a call came to.
#[derive(Debug, PartialEq)]
enum Outcome {
    Ran {
        code: i32,
        stdout: String,
        stderr: String,
    },
    Denied(String),
}

/// `who` calls `name` with `args` and `stdin`, as `wires call` does,
/// retrying while the host is still starting (not yet accepting).
async fn call(
    w: &World,
    host: &Running,
    who: &NodeIdentity,
    name: &str,
    args: &[&str],
    stdin: &str,
) -> Outcome {
    let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(secret_key(who))
        .bind()
        .await
        .unwrap();
    let outcome = tokio::time::timeout(PATIENCE, async {
        loop {
            let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
            let dialed = call_service_on(
                &endpoint,
                std::slice::from_ref(&host.addr),
                std::time::Duration::from_secs(2),
                w.hello(who),
                Invocation {
                    service: ServiceName::new(name).unwrap(),
                    argv: library::Argv::new(args.iter().map(|a| a.to_string()).collect()).unwrap(),
                },
                |_, _| Ok(()),
                std::io::Cursor::new(stdin.as_bytes().to_vec()),
                &mut stdout,
                &mut stderr,
            )
            .await;
            match dialed {
                Ok(done) => {
                    return Outcome::Ran {
                        code: done.dialed.exit,
                        stdout: String::from_utf8(stdout).unwrap(),
                        stderr: String::from_utf8(stderr).unwrap(),
                    };
                }
                Err(e) => match e.downcast_ref::<Denied>() {
                    Some(d) => return Outcome::Denied(d.reason().to_string()),
                    // Not serving yet: the router isn't up.
                    None => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
                },
            }
        }
    })
    .await
    .expect("the call timed out");
    endpoint.close().await;
    outcome
}

fn ran(code: i32, stdout: &str) -> Outcome {
    Outcome::Ran {
        code,
        stdout: stdout.into(),
        stderr: String::new(),
    }
}

#[tokio::test]
async fn a_native_service_is_called_like_a_cli() {
    let w = World::new().await;
    let home = w.keystore(&w.state(&["kv"]));
    let host = w
        .builder(&home)
        .service("kv", kv_example::Kv::default())
        .build()
        .unwrap();
    let host = Running::start(&w, host, home).await;

    // State across calls, the value on stdin, the answer on stdout.
    assert_eq!(
        call(&w, &host, &w.alice, "kv", &["set", "greeting"], "hello").await,
        ran(0, "")
    );
    assert_eq!(
        call(&w, &host, &w.alice, "kv", &["get", "greeting"], "").await,
        ran(0, "hello")
    );
    assert_eq!(
        call(&w, &host, &w.alice, "kv", &["keys"], "").await,
        ran(0, "greeting\n")
    );
    // The handler's exit code and stderr are the caller's.
    assert_eq!(
        call(&w, &host, &w.alice, "kv", &["get", "nope"], "").await,
        Outcome::Ran {
            code: 1,
            stdout: String::new(),
            stderr: "kv: no such key\n".into()
        }
    );
    host.stop().await.unwrap();
}

#[tokio::test]
async fn a_refused_caller_never_reaches_the_handler() {
    /// Counts the calls that reached it.
    struct Counting(Arc<AtomicUsize>);
    impl Service for Counting {
        async fn call(&self, _call: Call, _io: CallIo) -> i32 {
            self.0.fetch_add(1, Ordering::SeqCst);
            0
        }
    }
    let w = World::new().await;
    let home = w.keystore(&w.state(&["count"]));
    let reached = Arc::new(AtomicUsize::new(0));
    let host = w
        .builder(&home)
        .service("count", Counting(Arc::clone(&reached)))
        .build()
        .unwrap();
    let host = Running::start(&w, host, home).await;

    assert_eq!(
        call(&w, &host, &w.bob, "count", &[], "").await,
        Outcome::Denied("bob@example.com is in no role allowed to call count (analyst)".into())
    );
    assert_eq!(
        reached.load(Ordering::SeqCst),
        0,
        "bob never reached the handler"
    );
    assert_eq!(
        call(&w, &host, &w.alice, "count", &[], "").await,
        ran(0, "")
    );
    assert_eq!(reached.load(Ordering::SeqCst), 1);
    host.stop().await.unwrap();
}

#[tokio::test]
async fn a_native_call_is_logged_like_a_cli_call() {
    let w = World::new().await;
    let home = w.keystore(&w.state(&["kv"]));
    let host = w
        .builder(&home)
        .service("kv", kv_example::Kv::default())
        .build()
        .unwrap();
    let host = Running::start(&w, host, home).await;
    assert_eq!(
        call(&w, &host, &w.alice, "kv", &["set", "k"], "v1").await,
        ran(0, "")
    );
    assert_eq!(
        call(&w, &host, &w.bob, "kv", &["keys"], "").await,
        Outcome::Denied("bob@example.com is in no role allowed to call kv (analyst)".into())
    );
    let home = host.home.clone();
    host.stop().await.unwrap();

    let entries = crate::host::call_log::read(&home.join(crate::host::call_log::LOG_FILE)).unwrap();
    library::verify_chain(w.host.node_id(), None, &entries).expect("a signed, unbroken chain");
    let records: Vec<&AuditRecord> = entries.iter().map(|e| &e.record).collect();
    let [started, finished, denied] = records.as_slice() else {
        panic!("expected Started, Finished, Denied; got {records:?}");
    };
    let AuditRecord::Started {
        call,
        caller,
        principal,
        service,
        argv,
        role,
        ..
    } = started
    else {
        panic!("expected Started first, got {started:?}");
    };
    assert_eq!(*caller, w.alice.node_id());
    assert_eq!(
        principal.as_ref().unwrap().email.as_deref(),
        Some("alice@example.com")
    );
    assert_eq!(
        (service.as_str(), argv.as_slice(), role.as_str()),
        ("kv", &["set".to_string(), "k".to_string()][..], "analyst")
    );
    let AuditRecord::Finished {
        call: done,
        exit,
        stdout_bytes,
        stdin_bytes,
        stdin_digest,
        stdin_head,
        ..
    } = finished
    else {
        panic!("expected Finished second, got {finished:?}");
    };
    let mut v1 = OutputHasher::new();
    v1.update(b"v1");
    assert_eq!((done, *exit, *stdout_bytes), (call, 0, 0));
    assert_eq!(
        (*stdin_bytes, *stdin_digest, stdin_head.as_deref()),
        (2, v1.finish(), Some("v1"))
    );
    assert!(matches!(denied, AuditRecord::Denied { caller, .. } if *caller == w.bob.node_id()));
}

#[tokio::test]
async fn an_unassigned_native_service_refuses_to_start() {
    let w = World::new().await;
    let home = w.keystore(&w.state(&["kv"]));
    let host = w
        .builder(&home)
        .service("kv", kv_example::Kv::default())
        .service("other", kv_example::Kv::default())
        .build()
        .unwrap();
    let served = Running::start(&w, host, home).await;
    let e = format!("{:#}", served.stop().await.unwrap_err());
    assert!(
        e.contains("native service other, but the signed state (version 1) has no such service"),
        "{e}"
    );
}

/// Pushes `subject` to its caller and prints the outcome (or the error, and
/// exits 1).
struct Notify;

impl Service for Notify {
    async fn call(&self, call: Call, mut io: CallIo) -> i32 {
        use tokio::io::AsyncWriteExt;
        let subject = call.args().first().cloned().unwrap_or_default();
        match call.push_to_caller(subject, "body").await {
            Ok(outcome) => {
                let _ = io.stdout.write_all(outcome.as_str().as_bytes()).await;
                0
            }
            Err(e) => {
                let _ = io.stderr.write_all(format!("{e:#}").as_bytes()).await;
                1
            }
        }
    }
}

#[tokio::test]
async fn a_native_service_pushes_to_its_caller() {
    let w = World::new().await;
    let state = w.state(&["notify"]);

    // With push allowed to analysts: alice's push is taken (no receiver is
    // listening, so it is queued for her `wires inbox`).
    let home = w.keystore(&state);
    let host = w
        .builder(&home)
        .push_allow(["analyst"])
        .service("notify", Notify)
        .build()
        .unwrap();
    let host = Running::start(&w, host, home).await;
    assert_eq!(
        call(&w, &host, &w.alice, "notify", &["deployed"], "").await,
        ran(0, "queued")
    );
    let home = host.home.clone();
    host.stop().await.unwrap();
    let entries = crate::host::call_log::read(&home.join(crate::host::call_log::LOG_FILE)).unwrap();
    let started = entries
        .iter()
        .find_map(|e| match &e.record {
            AuditRecord::Started { call, .. } => Some(*call),
            _ => None,
        })
        .expect("the call was logged");
    let pushed = entries
        .iter()
        .find_map(|e| match &e.record {
            AuditRecord::Push {
                to,
                call,
                subject,
                outcome,
                ..
            } => Some((*to, *call, subject.as_str().to_string(), *outcome)),
            _ => None,
        })
        .expect("the push was logged");
    assert_eq!(
        pushed,
        (
            w.alice.node_id(),
            Some(started),
            "deployed".to_string(),
            library::PushOutcome::Queued
        )
    );

    // A host with no push configured says so to the handler.
    let home = w.keystore(&state);
    let host = w.builder(&home).service("notify", Notify).build().unwrap();
    let host = Running::start(&w, host, home).await;
    assert_eq!(
        call(&w, &host, &w.alice, "notify", &["deployed"], "").await,
        Outcome::Ran {
            code: 1,
            stdout: String::new(),
            stderr: "this host doesn't push (it has no `push` configured)".into()
        }
    );
    host.stop().await.unwrap();
}

#[tokio::test]
async fn push_allow_refuses_a_caller_in_none_of_its_roles() {
    let w = World::new().await;
    let home = w.keystore(&w.state(&["notify"]));
    // Pushes go to `ops` only; alice is an analyst.
    let host = w
        .builder(&home)
        .push_allow(["ops"])
        .service("notify", Notify)
        .build()
        .unwrap();
    let host = Running::start(&w, host, home).await;
    let Outcome::Ran {
        code,
        stdout,
        stderr,
    } = call(&w, &host, &w.alice, "notify", &["deployed"], "").await
    else {
        panic!("alice may call notify");
    };
    assert_eq!((code, stdout.as_str()), (1, ""));
    assert!(stderr.starts_with("push refused: "), "{stderr}");
    let home = host.home.clone();
    host.stop().await.unwrap();
    // The refused push is in the log, as denied.
    let entries = crate::host::call_log::read(&home.join(crate::host::call_log::LOG_FILE)).unwrap();
    assert!(
        entries.iter().any(|e| matches!(
            &e.record,
            AuditRecord::Push {
                outcome: library::PushOutcome::Denied,
                ..
            }
        )),
        "the refused push should be logged"
    );
}

#[tokio::test]
async fn each_verified_person_gets_their_own_kv() {
    let w = World::new().await;
    let home = w.keystore(&w.state_allowing(&["kv"], &["analyst", "ops"]));
    let host = w
        .builder(&home)
        .service("kv", kv_example::Kv::default())
        .build()
        .unwrap();
    let host = Running::start(&w, host, home).await;
    for (who, value) in [(&w.alice, "alice's"), (&w.bob, "bob's")] {
        assert_eq!(
            call(&w, &host, who, "kv", &["set", "k"], value).await,
            ran(0, "")
        );
    }
    assert_eq!(
        call(&w, &host, &w.alice, "kv", &["get", "k"], "").await,
        ran(0, "alice's")
    );
    assert_eq!(
        call(&w, &host, &w.bob, "kv", &["get", "k"], "").await,
        ran(0, "bob's")
    );
    host.stop().await.unwrap();
}

#[tokio::test]
async fn native_and_cli_services_share_one_host() {
    let w = World::new().await;
    let home = w.keystore(&w.state(&["kv", "hello"]));
    let host_json = home.join("host.json");
    std::fs::write(
        &host_json,
        r#"{"version":2,"services":{"hello":{"command":["echo","hello from a CLI"]}}}"#,
    )
    .unwrap();
    let host = w
        .builder(&home)
        .host_json(&host_json)
        .service("kv", kv_example::Kv::default())
        .build()
        .unwrap();
    let host = Running::start(&w, host, home).await;
    assert_eq!(
        call(&w, &host, &w.alice, "hello", &[], "").await,
        ran(0, "hello from a CLI\n")
    );
    assert_eq!(
        call(&w, &host, &w.alice, "kv", &["set", "k"], "v").await,
        ran(0, "")
    );
    // One gate for both: bob is refused either way.
    for service in ["hello", "kv"] {
        assert!(matches!(
            call(&w, &host, &w.bob, service, &[], "").await,
            Outcome::Denied(_)
        ));
    }
    let home = host.home.clone();
    host.stop().await.unwrap();
    // One log for both.
    let entries = crate::host::call_log::read(&home.join(crate::host::call_log::LOG_FILE)).unwrap();
    let started: Vec<&str> = entries
        .iter()
        .filter_map(|e| match &e.record {
            AuditRecord::Started { service, .. } => Some(service.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(started, ["hello", "kv"]);
}

#[tokio::test]
async fn a_stopped_host_closes_its_endpoint() {
    let w = World::new().await;
    let home = w.keystore(&w.state(&["kv"]));
    let host = w
        .builder(&home)
        .service("kv", kv_example::Kv::default())
        .build()
        .unwrap();
    let host = Running::start(&w, host, home).await;
    assert_eq!(
        call(&w, &host, &w.alice, "kv", &["keys"], "").await,
        ran(0, "")
    );
    let endpoint = host.endpoint.clone();
    assert!(!endpoint.is_closed());
    host.stop().await.unwrap();
    assert!(
        endpoint.is_closed(),
        "serve_until must close the endpoint it served on"
    );
}

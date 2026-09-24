//! The integration tests: the whole stack — signed policy, the `Hello`
//! handshake, the registry gate, exec and the stdio bridge, push — driven
//! over hermetic loopback QUIC.
//!
//! Every endpoint here binds with
//! [`presets::Minimal`](iroh::endpoint::presets::Minimal): no DNS, no pkarr,
//! no relay, nothing that leaves the machine. Peers find each other through
//! address hints over loopback ([`localhost_socks`]).
//!
//! - [`services_host`] — card 27's acceptance: a host decides
//!   every call by the admin-signed policy (the registry's roles,
//!   `also_require`, removal with no restart, refusing unassigned services,
//!   push by the policy).
//! - [`records`] — card 26b: call records streamed from the host's own log
//!   to authorized readers (`wires watch`).
//! - [`service_child`] — card 28 §1: a service child gets a minimal
//!   environment and a per-call push capability, not the host's keystore.
//! - [`gateway`] — `wires gateway`: a web MCP client signs in (OAuth, a mock
//!   Google) and calls as its user, over real HTTP.
//! - [`first_run`] — starting a network: `init`, `directory add`, `invite`,
//!   `join`, `directory serve`, an edit, with no step failing.
//! - [`follow`] — card 36c: hosts follow a directory's `policy`
//!   subscription (deltas, resync, failover), and the signed freshness rule
//!   (`lenient` / `strict`) with every directory down.
//! - [`views`] — card 37: each caller holds only its view, and a running
//!   `wires mcp` hears of a grant or a revocation within 2 s.
//! - [`native`] — card 33: an embedded [`Host`](crate::Host) serves a native
//!   service (the `kv` example), called and logged like a CLI service.

use std::net::SocketAddr;
use std::time::Duration;

use iroh::address_lookup::memory::MemoryLookup;
use iroh::{Endpoint, EndpointAddr};
use library::{
    Frame, Hello, HelloAck, Invocation, Matcher, Membership, NodeIdentity, OidcNonce, Policy,
    RoleName, ServiceName, SignedPolicy, StateVersion,
};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

use crate::admin::keystore::Keystore;
use crate::caller::mock_idp::{MOCK_CLIENT_ID, MockIdp};
use crate::host::config::HostConfig;
use crate::host::transport::{ALPN, secret_key};

/// Card 27's host side: a host decides by the signed policy.
mod services_host;

/// Card 26b: call records streamed from the host's log to authorized readers.
mod records;

/// Starting a network: no step errors, in the order each step names.
mod first_run;
/// Card 36c: hosts follow the directory by subscription; the freshness rule.
mod follow;
/// `wires gateway`: OAuth sign-in and MCP over HTTP, end to end.
mod gateway;
/// Card 33: an app serves wires calls in-process through an embedded host.
mod native;
/// Card 28 §1: the service child is not the host.
mod service_child;
/// Card 37: each caller holds only its view; grants and revocations reach
/// a running `wires mcp`.
mod views;

/// The outer bound on any single wait here: generous, and never reached in
/// the passing case (every wait is on an event, not a clock).
const PATIENCE: Duration = Duration::from_secs(30);

/// The endpoint's bound sockets as hints can dial them (wildcard binds as
/// localhost, [`crate::net::dialable`]), so a peer reaches it with no
/// discovery service.
fn localhost_socks(endpoint: &Endpoint) -> Vec<SocketAddr> {
    endpoint
        .bound_sockets()
        .into_iter()
        .map(crate::net::dialable)
        .collect()
}

/// A hermetic endpoint for `who` ([`presets::Minimal`](iroh::endpoint::presets::Minimal)).
async fn bind(who: &NodeIdentity) -> Endpoint {
    Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(secret_key(who))
        .bind()
        .await
        .unwrap()
}

/// [`bind`], finding peers through `book` (so it can dial them, e.g. push).
async fn bind_in(who: &NodeIdentity, book: &MemoryLookup) -> Endpoint {
    Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(secret_key(who))
        .address_lookup(book.clone())
        .bind()
        .await
        .unwrap()
}

fn role(s: &str) -> RoleName {
    RoleName::new(s).unwrap()
}

fn service(s: &str) -> ServiceName {
    ServiceName::new(s).unwrap()
}

/// A matcher for `email` as verified by `idp`.
fn email_at(idp: &MockIdp, email: &str) -> Matcher {
    Matcher {
        email: Some(email.parse().unwrap()),
        ..Matcher::new(idp.issuer.as_str())
    }
}

/// The policy `root` signs at `version` (issued now, never expiring), after
/// `edit` fills it in.
fn signed_state(root: &NodeIdentity, version: u64, edit: impl FnOnce(&mut Policy)) -> SignedPolicy {
    let mut s = Policy::new(root.node_id());
    s.version = StateVersion(version);
    s.issued = crate::clock::now_unix();
    s.not_after = i64::MAX;
    edit(&mut s);
    crate::testutil::signed_policy(root, s)
}

/// `who`'s badge under `root`, never expiring.
fn membership(root: &NodeIdentity, who: &NodeIdentity) -> Membership {
    Membership::mint(root, who.node_id(), 0, i64::MAX).unwrap()
}

/// `who`'s `Hello` under `root`: the policy version it holds, and a fresh ID
/// token from `idp` when it is signed in there.
fn hello(root: &NodeIdentity, who: &NodeIdentity, version: u64, idp: Option<&MockIdp>) -> Hello {
    Hello {
        membership: membership(root, who),
        state_version: StateVersion(version),
        id_token: idp.map(|idp| {
            idp.mint(
                &OidcNonce::for_node(&who.node_id()),
                crate::clock::now_unix() + 3600,
            )
        }),
    }
}

/// `email` as `idp` verified it (the subject is the email).
fn person(idp: &MockIdp, email: &str) -> library::Principal {
    library::Principal {
        issuer: idp.issuer.as_str().into(),
        subject: email.into(),
        email: Some(email.into()),
        org: None,
        groups: vec![],
        not_after: i64::MAX,
    }
}

/// Store in a caller's `ks` the view a directory would cut from `state`
/// for `who` (card 37: a caller holds its view, not the policy).
fn hold_view(
    ks: &Keystore,
    root: &NodeIdentity,
    state: &SignedPolicy,
    who: Option<&library::Principal>,
) {
    let held = crate::caller::view::HeldView::fetched(
        state.view_for(who, None),
        None,
        crate::clock::now_unix(),
    );
    crate::caller::view::write(ks, root.node_id(), &held).unwrap();
}

/// Store `state` in `ks` as a fetch from a directory does; whether it was adopted.
fn adopt(ks: &Keystore, root: &NodeIdentity, state: &SignedPolicy) -> bool {
    crate::policy::store::adopt_if_newer(ks, state, root.node_id(), crate::clock::now_unix())
        .unwrap()
}

/// A `host.json` trusting each of `idps` (audience the mock client), with
/// `services` (a JSON object) and `extra` (`,"key":…` members) spliced in.
fn host_config(idps: &[&MockIdp], services: &str, extra: &str) -> HostConfig {
    let issuers: Vec<String> = idps
        .iter()
        .map(|idp| {
            format!(
                r#"{{"issuer":"{}","audiences":["{MOCK_CLIENT_ID}"]}}"#,
                idp.issuer.as_str()
            )
        })
        .collect();
    HostConfig::parse(&format!(
        r#"{{"version":2,"identity":{{"issuers":[{}]}},"services":{services}{extra}}}"#,
        issuers.join(",")
    ))
    .unwrap()
}

/// One session frame; `None` at the end of the stream.
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Option<Frame> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await.ok()?;
    let mut buf = len.to_vec();
    buf.resize(4 + u32::from_be_bytes(len) as usize, 0);
    r.read_exact(&mut buf[4..]).await.ok()?;
    Frame::decode(&buf).unwrap().map(|(f, _)| f)
}

/// What a call came to.
#[derive(Debug)]
enum Outcome {
    /// Admitted: the ack, the exit code, and stdout.
    Ran {
        ack: Box<HelloAck>,
        code: i32,
        stdout: String,
    },
    /// Refused with this reason.
    Denied(String),
}

impl Outcome {
    /// The refusal's reason; panics on a run.
    fn denied(&self) -> &str {
        match self {
            Outcome::Denied(reason) => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// A successful run's stdout; panics on anything else.
    fn stdout(&self) -> &str {
        match self {
            Outcome::Ran {
                code: 0, stdout, ..
            } => stdout,
            other => panic!("expected a successful run, got {other:?}"),
        }
    }
}

/// Dial the host at `addr` as `who` on the session ALPN, say `hello`, invoke
/// `name` with `args`, close stdin, and collect the outcome. Hand-rolled
/// frames, so a test can present any `Hello` (the dial `wires call` makes
/// has its own tests in `caller::call`).
async fn call(
    who: &NodeIdentity,
    addr: &EndpointAddr,
    hello: Hello,
    name: &str,
    args: &[&str],
) -> Outcome {
    let endpoint = bind(who).await;
    let outcome = timeout(PATIENCE, async {
        let conn = endpoint.connect(addr.clone(), ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let invoke = Frame::Invoke(Invocation {
            service: service(name),
            argv: library::Argv::new(args.iter().map(|a| a.to_string()).collect()).unwrap(),
        });
        for frame in [Frame::Hello(hello), invoke] {
            send.write_all(&frame.encode().unwrap()).await.unwrap();
        }
        send.finish().unwrap();
        let ack = match read_frame(&mut recv).await {
            Some(Frame::HelloAck(ack)) => ack,
            Some(Frame::Denied { reason }) => return Outcome::Denied(reason),
            other => panic!("unexpected first answer: {other:?}"),
        };
        let mut stdout = Vec::new();
        loop {
            match read_frame(&mut recv).await {
                Some(Frame::Stdout(chunk)) => stdout.extend_from_slice(chunk.as_bytes()),
                Some(Frame::Stderr(_)) => {}
                Some(Frame::Exit(code)) => {
                    conn.close(0u32.into(), b"done");
                    return Outcome::Ran {
                        ack: Box::new(ack),
                        code,
                        stdout: String::from_utf8(stdout).unwrap(),
                    };
                }
                other => panic!("unexpected frame: {other:?}"),
            }
        }
    })
    .await
    .expect("the call timed out");
    endpoint.close().await;
    outcome
}

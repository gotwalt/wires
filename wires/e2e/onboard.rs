//! Card 14's acceptance test: `init` → `invite` host, caller, observer →
//! `join` ×3 → a call works → `remove` the caller → the caller's next call
//! is refused, with **no manual import** on the host or the observer, and the
//! observer keeps reading what the host records after the removal.
//!
//! Every step runs the production code path — `init_in`, `invite_in`,
//! `join_in`, `remove_in`, the resident loop ([`run_tail_on`]) for the host
//! (with its session ALPN, as `serve --audit-topic` runs it) and for the
//! observer, and `call_on` for the caller — over hermetic loopback endpoints.
//! The admin's re-keys are the only thing that moves the host and the
//! observer from one commit to the next.
//!
//! Along the way it also pins the two things that let a node that was *not*
//! running during a re-key carry on: the caller joins with an invite a commit
//! older than the host's head and still gets in (the host's proof directory),
//! and each invite after the first reaches the running host as a re-key.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use iroh::Endpoint;
use iroh::address_lookup::memory::MemoryLookup;
use library::{
    AuditRecord, ChannelRecord, Membership, NodeId, NodeIdentity, RosterVersion, TopicPeer,
    TopicTicket,
};
use tokio::sync::oneshot;
use tokio::time::timeout;

use super::{PATIENCE, cat_invocation, cat_tool, hint, settle};
use crate::admin::commit::{Timing, Ttl};
use crate::admin::init::{InitArgs, init_in};
use crate::admin::invite::{InviteArgs, RemoveArgs, invite_in, remove_in};
use crate::admin::keystore::Keystore;
use crate::caller::join::{id_in, join_in};
use crate::channel::admission::AdmitHandler;
use crate::channel::context::{TopicArgs, TopicContext};
use crate::channel::printer::Keyring;
use crate::channel::store::TopicStore;
use crate::channel::topics::{TopicNode, TopicNodeConfig};
use crate::host::transport::{
    AuditSink, CrlSource, Denied, HeadSource, ServeConfig, SessionProtocol, secret_key,
};
use crate::now_unix;
use crate::testutil::temp_dir;

/// A one-shot distribution's timing here: wait for the host as long as any
/// other wait in the suite, and linger just long enough for gossip to flush.
const TIMING: Timing = Timing {
    wait: PATIENCE,
    linger: std::time::Duration::from_millis(500),
};

/// One machine: a keystore that is also its `$WIRES_HOME`.
struct Machine {
    ks: Arc<Keystore>,
    home: std::path::PathBuf,
}

impl Machine {
    fn new() -> Self {
        let home = temp_dir();
        Self {
            ks: Arc::new(Keystore::at(&home)),
            home,
        }
    }

    fn node(&self) -> NodeIdentity {
        self.ks.read_node_identity().unwrap().unwrap()
    }

    fn head_version(&self) -> Option<RosterVersion> {
        self.ks.read_roster_head().unwrap().map(|h| h.version)
    }

    /// The channel context `wires watch` / `serve --audit-topic` resolve here,
    /// with no flags: everything comes from what `init` / `join` installed.
    fn context(&self) -> TopicContext {
        TopicContext::resolve(
            Arc::clone(&self.ks),
            self.home.clone(),
            &TopicArgs::default(),
        )
        .unwrap()
    }
}

/// A hermetic topic node for `identity` (no relay, no DNS).
async fn bind_hermetic(identity: &NodeIdentity, cfg: TopicNodeConfig) -> anyhow::Result<TopicNode> {
    let lookup = MemoryLookup::new();
    let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(secret_key(identity))
        .address_lookup(lookup.clone())
        .bind()
        .await
        .map_err(|e| anyhow::anyhow!("binding: {e}"))?;
    TopicNode::spawn_on(endpoint, lookup, cfg).await
}

/// What a resident node hands back once it is bound.
type Ready = (TopicPeer, Arc<AdmitHandler>, Arc<TopicStore>);

/// Run the production resident loop for `m` as a task; `hosted` makes it the
/// `serve --audit-topic` host (serving `cat`).
fn resident(m: &Machine, hosted: bool) -> (tokio::task::JoinHandle<()>, oneshot::Receiver<Ready>) {
    let ctx = m.context();
    let identity = m.node();
    let hosted = hosted.then(|| {
        let (sink, records) = AuditSink::channel(crate::host::audit::AUDIT_QUEUE);
        let serve = ServeConfig {
            trust_root: ctx.fabric_root,
            require_grant: false,
            crl: CrlSource::Fixed(library::Crl::new()),
            head: HeadSource::Keystore {
                path: m.ks.path("roster-head.json"),
                armed: AtomicBool::new(true),
            },
            membership: ctx.membership.clone(),
            proof: None,
            tools: cat_tool(),
            audit: Some(sink),
            identity: None,
            policy: Arc::new(crate::host::policy::AnyMember),
        };
        crate::host::audit::Hosted {
            session: SessionProtocol(Arc::new(serve)),
            records,
            identities: Arc::new(crate::host::identity::Identities::new(
                crate::caller::jwks::KeyFetcher::new(None).unwrap(),
                crate::channel::idp_view::IdpTrust::from_vars(None, None),
            )),
        }
    });
    let (ready, ready_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let run = crate::channel::watch::run_tail_on(&ctx, 0, false, hosted, async move |cfg| {
            let node = bind_hermetic(&identity, cfg).await?;
            let _ = ready.send((
                hint(&node),
                Arc::clone(node.admit()),
                Arc::clone(node.store()),
            ));
            Ok(node)
        });
        if let Err(e) = run.await {
            panic!("a resident node ended: {e:#}");
        }
    });
    (task, ready_rx)
}

/// `wires call cat` from `m` to `host`, with whatever credentials `m`'s
/// keystore holds — exactly what `wires call` would present.
async fn call(m: &Machine, host: &TopicPeer) -> (anyhow::Result<i32>, Vec<u8>) {
    let identity = m.node();
    let membership: Membership = m.ks.read_membership().unwrap().unwrap();
    let proof = m.ks.read_inclusion_proof().unwrap();
    let target = crate::host::transport::endpoint_addr(&host.node, &host.addrs, None).unwrap();
    let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(secret_key(&identity))
        .bind()
        .await
        .unwrap();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let result = timeout(
        PATIENCE,
        crate::host::transport::call_on(
            endpoint,
            target,
            membership,
            None,
            proof,
            false,
            cat_invocation(),
            std::io::Cursor::new(b"card 14".to_vec()),
            &mut out,
            &mut err,
        ),
    )
    .await
    .expect("the call timed out");
    (result, out)
}

fn ttl() -> Ttl {
    Ttl::DEFAULT.parse().unwrap()
}

/// `wires invite <id> --name <name> [--peer <ticket>]` on the admin.
async fn invite(admin: &Machine, who: NodeId, name: &str, peer: Option<String>) -> String {
    let identity = admin.node();
    let report = invite_in(
        &admin.ks,
        &admin.home,
        InviteArgs {
            node_id: who.hex(),
            name: Some(name.into()),
            ttl: ttl(),
            peer: peer.into_iter().collect(),
        },
        TIMING,
        async move |cfg| bind_hermetic(&identity, cfg).await,
    )
    .await
    .unwrap();
    report.stdout
}

#[tokio::test]
async fn invite_join_remove_needs_no_manual_import() {
    let admin = Machine::new();
    let host = Machine::new();
    let caller = Machine::new();
    let observer = Machine::new();

    // The admin starts the fabric; each joiner makes its key (`wires id`).
    init_in(
        &admin.ks,
        InitArgs {
            channel: "ops".into(),
            ttl: ttl(),
        },
    )
    .unwrap();
    let fabric = admin.ks.read_root_identity().unwrap().unwrap().node_id();
    let [host_id, caller_id, observer_id] =
        [&host, &caller, &observer].map(|m| id_in(&m.ks).unwrap().0);

    // The host first: nobody else to re-key yet. It joins and serves.
    let token = invite(&admin, host_id, "host", None).await;
    join_in(&host.ks, &host.home, &token, now_unix()).unwrap();
    let (host_task, ready) = resident(&host, true);
    let (host_hint, host_admit, _) = timeout(PATIENCE, ready).await.unwrap().unwrap();
    let ticket = TopicTicket::new(fabric, "ops", vec![host_hint.clone()])
        .encode()
        .unwrap();

    // The caller, then the observer. Each invite is a commit, and each is
    // published to the running host as a re-key — which it adopts on its own.
    let caller_token = invite(&admin, caller_id, "caller", Some(ticket)).await;
    let v_caller = admin.head_version().unwrap();
    settle(
        || host.head_version() == Some(v_caller),
        "the host adopting the caller's commit",
    )
    .await;
    let observer_token = invite(&admin, observer_id, "observer", None).await;
    let v_observer = admin.head_version().unwrap();
    settle(
        || host.head_version() == Some(v_observer),
        "the host adopting the observer's commit",
    )
    .await;
    assert!(
        host.ks.latest_fabric_key().unwrap().map(|(v, _)| v) == Some(v_observer),
        "the host opened its own part of the re-key"
    );

    join_in(&caller.ks, &caller.home, &caller_token, now_unix()).unwrap();
    join_in(&observer.ks, &observer.home, &observer_token, now_unix()).unwrap();
    // The caller's credentials are a commit behind the host's head.
    assert!(caller.head_version().unwrap() < v_observer);

    // The observer watches, bootstrapping from the peers its token carried.
    let (observer_task, ready) = resident(&observer, false);
    let (_, _, observer_store) = timeout(PATIENCE, ready).await.unwrap().unwrap();
    settle(
        || host_admit.admitted.is_admitted(observer_id, now_unix()),
        "the host admitting the observer",
    )
    .await;

    // A call works — with a proof one commit stale, via the host's directory.
    let (code, out) = call(&caller, &host_hint).await;
    assert_eq!(code.unwrap(), 0);
    assert_eq!(out, b"card 14");

    // A one-shot publish from the stale caller (what `wires login` does with
    // its identity claim) catches up on the re-key it missed first, and goes
    // out under the current key rather than being refused at the source.
    let caller_ctx = caller.context();
    let identity = caller.node();
    let reached = crate::channel::publish::publish_one_shot_on(
        &caller_ctx,
        crate::channel::publish::Messages::One(Some("hello from a late joiner".into())),
        PATIENCE,
        TIMING.linger,
        async move |cfg| bind_hermetic(&identity, cfg).await,
    )
    .await
    .unwrap();
    assert_eq!(reached, Some(host_id));
    assert_eq!(caller.head_version(), Some(v_observer));
    assert_eq!(
        caller.ks.latest_fabric_key().unwrap().map(|(v, _)| v),
        Some(v_observer),
        "the caller adopted the re-key it missed"
    );

    // Remove the caller: one command, published to the host and the observer.
    let identity = admin.node();
    let report = remove_in(
        &admin.ks,
        &admin.home,
        RemoveArgs {
            member: "caller".into(),
            ttl: ttl(),
        },
        TIMING,
        async move |cfg| bind_hermetic(&identity, cfg).await,
    )
    .await
    .unwrap();
    assert!(
        report.stdout.contains(&caller_id.hex()),
        "{}",
        report.stdout
    );
    let v_removed = admin.head_version().unwrap();
    for (who, m) in [("host", &host), ("observer", &observer)] {
        settle(
            || {
                m.head_version() == Some(v_removed)
                    && m.ks.latest_fabric_key().unwrap().map(|(v, _)| v) == Some(v_removed)
            },
            &format!("the {who} adopting the removal with no import"),
        )
        .await;
    }

    // The caller's next call is refused (exit 77 in the CLI)...
    let (refused, out) = call(&caller, &host_hint).await;
    let e = refused.expect_err("a removed caller is refused");
    let reason = e
        .downcast_ref::<Denied>()
        .unwrap_or_else(|| panic!("a refusal, not a failure: {e:#}"))
        .reason()
        .to_string();
    assert!(reason.contains("roster inclusion rejected"), "{reason}");
    assert!(out.is_empty(), "nothing ran");

    // ...and the observer reads the host's record of it, sealed under the
    // key the removal minted — which the caller never received.
    let mut keyring = Keyring::load(Arc::clone(&observer.ks)).unwrap();
    let mut seen = false;
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while !seen {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the observer never read the host's Denied record"
        );
        for envelope in observer_store.read_backfill(1000).unwrap() {
            if envelope.sender != host_id || envelope.key_version != v_removed {
                continue;
            }
            let Some(plain) = keyring.open(&envelope) else {
                continue;
            };
            if let Some(ChannelRecord::Audit(AuditRecord::Denied { caller: who, .. })) =
                ChannelRecord::parse(&String::from_utf8_lossy(&plain))
            {
                seen |= who == caller_id;
            }
        }
        tokio::time::sleep(super::BEAT).await;
    }
    assert!(
        caller
            .ks
            .latest_fabric_key()
            .unwrap()
            .is_some_and(|(v, _)| v < v_removed),
        "the removed caller holds no key for the new commit"
    );

    observer_task.abort();
    host_task.abort();
}

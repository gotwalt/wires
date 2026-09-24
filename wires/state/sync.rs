//! Moving the signed state by key over [`STATE_ALPN`](library::STATE_ALPN).
//! The frames are [`library::StateFrame`].
//!
//! - [`push_all`]: after `invite` / `remove` / `service` / `role`, the admin
//!   offers the new state to every member, **hosts first** (they enforce it),
//!   then everyone else. A member it can't reach is reported, not queued:
//!   it catches up by [`pull`] (below), or from a host's `HelloAck`.
//! - [`pull`]: a cold command whose copy was last checked more than
//!   [`STALE_AFTER_SECS`] ago asks the admin or any host for a newer one
//!   ([`refresh_cold`]); a running `wires serve` does the same on a timer
//!   ([`refresh_loop`]).
//! - [`respond`] / [`StateResponder`]: the side a running host serves on the
//!   ALPN: answer a pull, adopt an offer.
//!
//! One bi-stream per exchange, one frame each way. Nothing is ever adopted
//! except through [`store::adopt_if_newer`] (verified under the root, fresh,
//! strictly newer), so a lying peer can only fail to help.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use iroh::Endpoint;
use iroh::endpoint::Connection;
use library::{NodeId, STATE_ALPN, SignedState, StateFrame, StateVersion};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::store;
use crate::admin::keystore::{self, Keystore};
use crate::host::transport;
use crate::now_unix;

/// How old a local copy may be before a cold command pulls.
pub(crate) const STALE_AFTER_SECS: i64 = 10 * 60;

/// How long one dial may take.
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the answer to a frame may take.
const FRAME_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a cold command spends pulling, all peers together.
const COLD_PULL_BUDGET: Duration = Duration::from_secs(8);

/// Who took an offered state and who didn't.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PushReport {
    /// Members now holding at least the offered version.
    pub(crate) delivered: Vec<NodeId>,
    /// Members that couldn't be reached or refused (they catch up by pull).
    pub(crate) missed: Vec<NodeId>,
}

impl PushReport {
    /// One human line for the admin's stderr.
    pub(crate) fn line(&self, version: StateVersion) -> String {
        let mut out = format!(
            "state version {}: pushed to {} member(s)",
            version.0,
            self.delivered.len()
        );
        if !self.missed.is_empty() {
            out.push_str(&format!(
                "; {} not reachable now ({}) — they pull it on their next command",
                self.missed.len(),
                self.missed
                    .iter()
                    .map(|n| format!("{}…", &n.hex()[..8]))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Frame I/O
// ---------------------------------------------------------------------------

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &StateFrame) -> Result<()> {
    let bytes = frame.encode().context("encoding a state frame")?;
    w.write_all(&bytes).await.context("writing a state frame")
}

/// Read one frame within [`FRAME_TIMEOUT`]; the length prefix is checked
/// before the body is allocated.
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<StateFrame> {
    let read = async {
        let mut prefix = [0u8; 4];
        r.read_exact(&mut prefix)
            .await
            .context("reading a state frame")?;
        let len = StateFrame::length(&prefix)?.unwrap_or(0);
        let mut buf = prefix.to_vec();
        buf.resize(4 + len, 0);
        r.read_exact(&mut buf[4..])
            .await
            .context("reading a state frame body")?;
        match StateFrame::decode(&buf)? {
            Some((frame, _)) => Ok(frame),
            None => bail!("truncated state frame"),
        }
    };
    tokio::time::timeout(FRAME_TIMEOUT, read)
        .await
        .map_err(|_| anyhow!("no state frame within {FRAME_TIMEOUT:?}"))?
}

/// Dial `peer` by key, send `frame`, return its one answer.
async fn exchange(endpoint: &Endpoint, peer: NodeId, frame: &StateFrame) -> Result<StateFrame> {
    let addr = transport::endpoint_addr(&peer, &[], None)?;
    let conn = tokio::time::timeout(DIAL_TIMEOUT, endpoint.connect(addr, STATE_ALPN))
        .await
        .map_err(|_| anyhow!("no answer within {DIAL_TIMEOUT:?}"))?
        .map_err(|e| anyhow!("dialing {}…: {e}", &peer.hex()[..8]))?;
    let (mut send, mut recv) = conn.open_bi().await.context("opening a stream")?;
    write_frame(&mut send, frame).await?;
    send.finish().ok();
    let answer = read_frame(&mut recv).await;
    conn.close(0u32.into(), b"done");
    answer
}

// ---------------------------------------------------------------------------
// Push (admin)
// ---------------------------------------------------------------------------

/// Offer `state` to each of `members`: first every one that `state` names a
/// host (concurrently), then the rest (concurrently). A member counts as
/// delivered once it answers holding at least `state`'s version.
pub(crate) async fn push_all(
    endpoint: &Endpoint,
    state: &SignedState,
    members: &[NodeId],
) -> Result<PushReport> {
    let (hosts, others): (Vec<NodeId>, Vec<NodeId>) = members
        .iter()
        .copied()
        .partition(|m| state.state.is_host(*m));
    let mut report = PushReport::default();
    for wave in [hosts, others] {
        let mut set = tokio::task::JoinSet::new();
        for member in wave {
            let endpoint = endpoint.clone();
            let offer = StateFrame::Offer {
                state: state.clone(),
            };
            let want = state.state.version;
            set.spawn(async move {
                let ok = match exchange(&endpoint, member, &offer).await {
                    Ok(StateFrame::Have { version }) => version >= want,
                    Ok(StateFrame::Denied { reason }) => {
                        tracing::warn!(member = %member.hex(), "state push refused: {reason}");
                        false
                    }
                    Ok(_) => false,
                    Err(e) => {
                        tracing::debug!(member = %member.hex(), "state push failed: {e:#}");
                        false
                    }
                };
                (member, ok)
            });
        }
        while let Some(joined) = set.join_next().await {
            let (member, ok) = joined.context("a push task panicked")?;
            if ok {
                report.delivered.push(member);
            } else {
                report.missed.push(member);
            }
        }
    }
    Ok(report)
}

/// The admin's push of the stored state from `ks` over `endpoint`: every
/// member but this node, hosts first.
pub(crate) async fn push_current_on(endpoint: &Endpoint, ks: &Keystore) -> Result<PushReport> {
    let root = store::fabric(ks)?.ok_or_else(|| anyhow!("this keystore is in no fabric"))?;
    let state = store::read(ks, root)?.ok_or_else(|| anyhow!("no signed state here"))?;
    let me = transport::to_node_id(&endpoint.id());
    let members: Vec<NodeId> = state
        .state
        .members
        .iter()
        .copied()
        .filter(|m| *m != me)
        .collect();
    push_all(endpoint, &state, &members).await
}

/// [`push_current_on`] over a freshly bound endpoint for this keystore's
/// node (the admin CLI's form). Returns the line for stderr.
pub(crate) async fn push_current(ks: &Keystore) -> Result<String> {
    let root = store::fabric(ks)?.ok_or_else(|| anyhow!("this keystore is in no fabric"))?;
    let version = store::read(ks, root)?
        .map(|s| s.state.version)
        .ok_or_else(|| anyhow!("no signed state here"))?;
    let node = keystore::node_identity_in(ks)?;
    let endpoint = transport::bind_with_alpn(&node, None, STATE_ALPN).await?;
    let report = push_current_on(&endpoint, ks).await;
    endpoint.close().await;
    Ok(report?.line(version))
}

// ---------------------------------------------------------------------------
// Pull (members)
// ---------------------------------------------------------------------------

/// Ask `peers` in turn for a state newer than `have`; the first verified,
/// newer one is adopted and returned. Marks the copy checked once any peer
/// answered.
pub(crate) async fn pull(
    endpoint: &Endpoint,
    ks: &Keystore,
    peers: &[NodeId],
    have: StateVersion,
) -> Result<Option<SignedState>> {
    let root = store::fabric(ks)?.ok_or_else(|| anyhow!("this keystore is in no fabric"))?;
    let mut answered = false;
    for peer in peers {
        match exchange(endpoint, *peer, &StateFrame::Have { version: have }).await {
            Ok(StateFrame::Offer { state }) => {
                answered = true;
                match store::adopt_if_newer(ks, &state, root, now_unix()) {
                    Ok(true) => {
                        store::mark_checked(ks, now_unix())?;
                        return Ok(Some(state));
                    }
                    Ok(false) => {}
                    Err(e) => tracing::warn!(peer = %peer.hex(), "refused a pulled state: {e:#}"),
                }
            }
            Ok(StateFrame::Have { .. }) => answered = true,
            Ok(StateFrame::Denied { reason }) => {
                tracing::debug!(peer = %peer.hex(), "state pull refused: {reason}")
            }
            Err(e) => tracing::debug!(peer = %peer.hex(), "state pull failed: {e:#}"),
        }
    }
    if answered {
        store::mark_checked(ks, now_unix())?;
    }
    Ok(None)
}

/// Where this node pulls from: every host in its copy (they are up, serving),
/// then the admin if known (often a one-shot CLI), never itself.
pub(crate) fn pull_peers(ks: &Keystore, state: Option<&SignedState>, me: NodeId) -> Vec<NodeId> {
    let mut peers = Vec::new();
    if let Some(state) = state {
        peers.extend(state.state.hosts.iter().copied());
    }
    if let Ok(Some(admin)) = store::read_admin(ks) {
        peers.push(admin);
    }
    let mut seen = std::collections::BTreeSet::new();
    peers.retain(|p| *p != me && seen.insert(*p));
    peers
}

/// Pull over `endpoint` if the stored copy was last checked more than
/// [`STALE_AFTER_SECS`] ago. Returns the newly adopted state, if any.
pub(crate) async fn refresh_if_stale(
    endpoint: &Endpoint,
    ks: &Keystore,
) -> Result<Option<SignedState>> {
    let now = now_unix();
    if !store::is_stale(ks, now, STALE_AFTER_SECS) {
        return Ok(None);
    }
    let Some(root) = store::fabric(ks)? else {
        return Ok(None);
    };
    let held = store::read(ks, root)?;
    let have = held.as_ref().map_or(StateVersion(0), |s| s.state.version);
    let me = transport::to_node_id(&endpoint.id());
    let peers = pull_peers(ks, held.as_ref(), me);
    if peers.is_empty() {
        return Ok(None);
    }
    pull(endpoint, ks, &peers, have).await
}

/// A cold command's best-effort refresh: if this keystore is in a fabric and
/// its copy is stale, bind briefly and pull. Never fails the command.
pub(crate) async fn refresh_cold() {
    let run = async {
        let ks = Keystore::resolve()?;
        if store::fabric(&ks)?.is_none() || !store::is_stale(&ks, now_unix(), STALE_AFTER_SECS) {
            return Ok(None);
        }
        let node = keystore::node_identity_in(&ks)?;
        let endpoint = transport::bind_with_alpn(&node, None, STATE_ALPN).await?;
        let pulled = tokio::time::timeout(COLD_PULL_BUDGET, refresh_if_stale(&endpoint, &ks))
            .await
            .unwrap_or(Ok(None));
        endpoint.close().await;
        pulled
    };
    match run.await {
        Ok(Some(state)) => tracing::info!(version = state.state.version.0, "pulled a newer state"),
        Ok(None) => {}
        Err(e) => tracing::debug!("state refresh skipped: {e:#}"),
    }
}

/// A running host's refresh: every [`STALE_AFTER_SECS`], pull if stale (a
/// push it missed while down). Runs until the endpoint closes.
pub(crate) async fn refresh_loop(endpoint: Endpoint, ks: Arc<Keystore>) {
    let mut tick = tokio::time::interval(Duration::from_secs(STALE_AFTER_SECS as u64));
    loop {
        tick.tick().await;
        if endpoint.is_closed() {
            return;
        }
        if let Err(e) = refresh_if_stale(&endpoint, &ks).await {
            tracing::debug!("state refresh failed: {e:#}");
        }
    }
}

// ---------------------------------------------------------------------------
// The responder
// ---------------------------------------------------------------------------

/// Serve one incoming state-protocol connection: read one frame, answer it.
///
/// - `Offer`: adopted if it verifies under this node's root, is fresh and
///   strictly newer; answered `Have` with the version now held. The dialer
///   must be a member of the held copy or of the (verified) offered one.
/// - `Have`: the dialer must be a member of the held copy; answered with the
///   held copy if it is newer, else `Have`.
pub(crate) async fn respond(conn: Connection, ks: &Keystore) -> Result<()> {
    let caller = transport::to_node_id(&conn.remote_id());
    let (mut send, mut recv) = conn.accept_bi().await.context("accepting a stream")?;
    let frame = read_frame(&mut recv).await?;
    let answer = answer(ks, caller, frame, now_unix());
    let result = match answer {
        Ok(reply) => write_frame(&mut send, &reply).await,
        Err(reason) => {
            let reason = transport::truncate_reason(reason);
            write_frame(&mut send, &StateFrame::Denied { reason }).await
        }
    };
    send.finish().ok();
    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
    result
}

/// The decision behind [`respond`], without the network: the reply, or the
/// refusal reason.
pub(crate) fn answer(
    ks: &Keystore,
    caller: NodeId,
    frame: StateFrame,
    now: i64,
) -> std::result::Result<StateFrame, String> {
    let fail = |e: anyhow::Error| format!("{e:#}");
    let root = store::fabric(ks)
        .map_err(fail)?
        .ok_or("this node is in no fabric")?;
    let held = store::read(ks, root).map_err(fail)?;
    let is_member = |s: &Option<SignedState>| s.as_ref().is_some_and(|s| s.state.is_member(caller));
    let version = |s: &Option<SignedState>| s.as_ref().map_or(StateVersion(0), |s| s.state.version);
    match frame {
        StateFrame::Offer { state } => {
            let vouched = state.verify(root).is_ok() && state.state.is_member(caller);
            if !is_member(&held) && !vouched {
                return Err(format!("{}… is not a member", &caller.hex()[..8]));
            }
            if let Err(e) = store::adopt_if_newer(ks, &state, root, now) {
                return Err(format!("the offered state was refused: {e:#}"));
            }
            store::mark_checked(ks, now).map_err(fail)?;
            let held = store::read(ks, root).map_err(fail)?;
            Ok(StateFrame::Have {
                version: version(&held),
            })
        }
        StateFrame::Have { version: theirs } => {
            if !is_member(&held) {
                return Err(format!("{}… is not a member", &caller.hex()[..8]));
            }
            match held {
                Some(state) if state.state.version > theirs => Ok(StateFrame::Offer { state }),
                held => Ok(StateFrame::Have {
                    version: version(&held),
                }),
            }
        }
        StateFrame::Denied { .. } => Err("expected an offer or a have".into()),
    }
}

/// [`respond`] as a router protocol on [`STATE_ALPN`], for a running
/// node (a host's `serve`, a member's `watch`, the admin's).
#[derive(Clone)]
pub(crate) struct StateResponder(pub(crate) Arc<Keystore>);

impl std::fmt::Debug for StateResponder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateResponder").finish_non_exhaustive()
    }
}

impl iroh::protocol::ProtocolHandler for StateResponder {
    async fn accept(
        &self,
        conn: Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        respond(conn, &self.0).await.map_err(|e| {
            tracing::warn!("state exchange failed: {e:#}");
            iroh::protocol::AcceptError::from_boxed(e.into())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;
    use library::{Membership, NodeIdentity, State};

    /// A keystore for `node` in `root`'s fabric, holding `state` if given.
    fn member_ks(
        root: &NodeIdentity,
        node: &NodeIdentity,
        state: Option<&SignedState>,
    ) -> Keystore {
        let ks = Keystore::at(temp_dir());
        ks.save_node(node, false).unwrap();
        ks.save_membership(&Membership::mint(root, node.node_id(), 0, i64::MAX).unwrap())
            .unwrap();
        if let Some(s) = state {
            assert!(store::adopt_if_newer(&ks, s, root.node_id(), 10).unwrap());
        }
        ks
    }

    fn signed(root: &NodeIdentity, version: u64, members: &[NodeId]) -> SignedState {
        let mut s = State::new(root.node_id());
        s.version = StateVersion(version);
        s.not_after = i64::MAX;
        s.members.extend(members.iter().copied());
        s.sign(root).unwrap()
    }

    #[test]
    fn answers_offers_and_pulls() {
        let root = NodeIdentity::generate();
        let (me, peer, outsider) = (
            NodeIdentity::generate(),
            NodeIdentity::generate().node_id(),
            NodeIdentity::generate().node_id(),
        );
        let v1 = signed(&root, 1, &[me.node_id(), peer]);
        let v2 = signed(&root, 2, &[me.node_id(), peer]);
        let ks = member_ks(&root, &me, Some(&v1));

        // A pull from a member at the same version: Have.
        let have = |v| StateFrame::Have {
            version: StateVersion(v),
        };
        assert_eq!(answer(&ks, peer, have(1), 10), Ok(have(1)));
        // An offer of v2: adopted.
        let offer = |s: &SignedState| StateFrame::Offer { state: s.clone() };
        assert_eq!(answer(&ks, peer, offer(&v2), 10), Ok(have(2)));
        // An older offer: not adopted, and the answer says what is held.
        assert_eq!(answer(&ks, peer, offer(&v1), 10), Ok(have(2)));
        // A pull from behind: the held copy.
        assert_eq!(answer(&ks, peer, have(1), 10), Ok(offer(&v2)));
        // Non-members are refused either way.
        assert!(answer(&ks, outsider, have(0), 10).is_err());
        assert!(answer(&ks, outsider, offer(&v2), 10).is_err());
        // A forged offer is refused.
        let rogue = NodeIdentity::generate();
        let mut forged = signed(&rogue, 9, &[peer]).clone();
        forged.state.fabric = root.node_id();
        assert!(answer(&ks, peer, offer(&forged), 10).is_err());
        assert_eq!(
            store::read(&ks, root.node_id())
                .unwrap()
                .unwrap()
                .state
                .version,
            StateVersion(2)
        );
    }

    // -----------------------------------------------------------------------
    // Loopback e2e: the admin pushes, a host and a member adopt; pull covers
    // a missed push.
    // -----------------------------------------------------------------------

    mod e2e {
        use super::*;
        use crate::admin::init::{InitArgs, init_in};
        use crate::admin::service::{self, ServiceEdit};
        use crate::admin::ttl::Ttl;
        use iroh::address_lookup::memory::MemoryLookup;
        use iroh::protocol::Router;
        use library::ServiceName;

        fn ttl() -> Ttl {
            Ttl::DEFAULT.parse().unwrap()
        }

        /// A hermetic endpoint for `node` in the shared address book; with
        /// `serve`, a router answering the state ALPN from `ks`.
        async fn bind(
            node: &NodeIdentity,
            ks: &Arc<Keystore>,
            book: &MemoryLookup,
            serve: bool,
        ) -> (Endpoint, Option<Router>) {
            let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
                .secret_key(transport::secret_key(node))
                .address_lookup(book.clone())
                .bind()
                .await
                .unwrap();
            let socks: Vec<std::net::SocketAddr> = endpoint
                .bound_sockets()
                .into_iter()
                .map(|s| match s {
                    std::net::SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
                        (std::net::Ipv4Addr::LOCALHOST, v4.port()).into()
                    }
                    std::net::SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
                        (std::net::Ipv6Addr::LOCALHOST, v6.port()).into()
                    }
                    other => other,
                })
                .collect();
            book.add_endpoint_info(
                transport::endpoint_addr(&node.node_id(), &socks, None).unwrap(),
            );
            let router = serve.then(|| {
                Router::builder(endpoint.clone())
                    .accept(STATE_ALPN, StateResponder(Arc::clone(ks)))
                    .spawn()
            });
            (endpoint, router)
        }

        /// The fabric: an admin (initialized), a host and a member, both
        /// joined (holding the state the admin had when they joined).
        struct Fabric {
            admin: Arc<Keystore>,
            root: NodeId,
            host: (NodeIdentity, Arc<Keystore>),
            member: (NodeIdentity, Arc<Keystore>),
        }

        fn fabric() -> Fabric {
            let admin = Arc::new(Keystore::at(temp_dir()));
            init_in(&admin, InitArgs { ttl: ttl() }).unwrap();
            let root_id = admin.read_root_identity().unwrap().unwrap();
            let me = admin.read_node_identity().unwrap().unwrap().node_id();
            let (host, member) = (NodeIdentity::generate(), NodeIdentity::generate());
            let joined = service::edit_state(&admin, ttl(), |s| {
                s.members.extend([host.node_id(), member.node_id()]);
                Ok(())
            })
            .unwrap();
            let join = |node: &NodeIdentity| {
                let ks = Arc::new(member_ks(&root_id, node, None));
                store::adopt_if_newer(&ks, &joined, root_id.node_id(), now_unix()).unwrap();
                store::save_admin(&ks, me).unwrap();
                ks
            };
            Fabric {
                root: root_id.node_id(),
                host: (NodeIdentity::from_seed(host.seed_bytes()), join(&host)),
                member: (NodeIdentity::from_seed(member.seed_bytes()), join(&member)),
                admin,
            }
        }

        fn version(ks: &Keystore, root: NodeId) -> StateVersion {
            store::read(ks, root).unwrap().unwrap().state.version
        }

        /// Assign `orders-db` to the host: the admin's edit.
        fn assign(f: &Fabric) -> SignedState {
            service::add(
                &f.admin,
                ServiceName::new("orders-db").unwrap(),
                ServiceEdit {
                    description: Some("orders".into()),
                    allow: None,
                    hosts: Some(vec![f.host.0.node_id()]),
                    readers: None,
                },
                ttl(),
            )
            .unwrap()
        }

        #[tokio::test]
        async fn an_admin_change_reaches_a_host_and_a_member_within_two_seconds() {
            let f = fabric();
            let book = MemoryLookup::new();
            let admin_node = f.admin.read_node_identity().unwrap().unwrap();
            let (admin_ep, _) = bind(&admin_node, &f.admin, &book, false).await;
            let (_h, _hr) = bind(&f.host.0, &f.host.1, &book, true).await;
            let (_m, _mr) = bind(&f.member.0, &f.member.1, &book, true).await;

            let new = assign(&f);
            let started = std::time::Instant::now();
            let report =
                tokio::time::timeout(Duration::from_secs(2), push_current_on(&admin_ep, &f.admin))
                    .await
                    .expect("the push took over 2 s")
                    .unwrap();
            assert!(started.elapsed() < Duration::from_secs(2));
            assert!(report.missed.is_empty(), "{report:?}");
            assert_eq!(report.delivered.len(), 2);
            for ks in [&f.host.1, &f.member.1] {
                assert_eq!(version(ks, f.root), new.state.version);
                assert!(
                    store::read(ks, f.root)
                        .unwrap()
                        .unwrap()
                        .state
                        .is_host(f.host.0.node_id())
                );
            }

            // `remove`: the member is dropped, and the host holds that at once.
            let removed = service::edit_state(&f.admin, ttl(), |s| {
                s.members.remove(&f.member.0.node_id());
                Ok(())
            })
            .unwrap();
            let report = push_current_on(&admin_ep, &f.admin).await.unwrap();
            assert_eq!(report.delivered, vec![f.host.0.node_id()]);
            let held = store::read(&f.host.1, f.root).unwrap().unwrap();
            assert_eq!(held, removed);
            assert!(!held.state.is_member(f.member.0.node_id()));

            // The removed member can no longer pull from the host.
            let (m2, _) = bind(
                &NodeIdentity::from_seed(f.member.0.seed_bytes()),
                &f.member.1,
                &book,
                false,
            )
            .await;
            std::fs::remove_file(f.member.1.path("state-checked.txt")).ok();
            let pulled = pull(&m2, &f.member.1, &[f.host.0.node_id()], new.state.version)
                .await
                .unwrap();
            assert!(pulled.is_none());
            assert_eq!(version(&f.member.1, f.root), new.state.version);
            admin_ep.close().await;
        }

        #[tokio::test]
        async fn an_older_state_is_never_adopted() {
            let f = fabric();
            let book = MemoryLookup::new();
            let admin_node = f.admin.read_node_identity().unwrap().unwrap();
            let (admin_ep, _) = bind(&admin_node, &f.admin, &book, false).await;
            let (_h, _hr) = bind(&f.host.0, &f.host.1, &book, true).await;

            let old = store::read(&f.admin, f.root).unwrap().unwrap();
            let new = assign(&f);
            push_current_on(&admin_ep, &f.admin).await.unwrap();
            assert_eq!(version(&f.host.1, f.root), new.state.version);

            // Anyone replaying the genuine older state gets told what's held.
            // (The host answers with the newer version it holds.)
            let report = push_all(&admin_ep, &old, &[f.host.0.node_id()])
                .await
                .unwrap();
            assert_eq!(report.delivered, vec![f.host.0.node_id()]);
            assert_eq!(store::read(&f.host.1, f.root).unwrap().unwrap(), new);
            admin_ep.close().await;
        }

        #[tokio::test]
        async fn a_member_that_missed_the_push_pulls_it_from_a_host() {
            let f = fabric();
            let book = MemoryLookup::new();
            let admin_node = f.admin.read_node_identity().unwrap().unwrap();
            let (admin_ep, _) = bind(&admin_node, &f.admin, &book, false).await;
            let (_h, _hr) = bind(&f.host.0, &f.host.1, &book, true).await;
            // The member is up but not listening: the push misses it.
            let (member_ep, _) = bind(&f.member.0, &f.member.1, &book, false).await;

            // The member already knows the host (an earlier push it got)…
            let assigned = assign(&f);
            store::adopt_if_newer(&f.member.1, &assigned, f.root, now_unix()).unwrap();
            // …but misses this one.
            let new = service::set(
                &f.admin,
                ServiceName::new("orders-db").unwrap(),
                ServiceEdit {
                    description: Some("orders, v2".into()),
                    ..Default::default()
                },
                ttl(),
            )
            .unwrap();
            let report = push_current_on(&admin_ep, &f.admin).await.unwrap();
            assert_eq!(report.delivered, vec![f.host.0.node_id()]);
            assert_eq!(report.missed, vec![f.member.0.node_id()]);
            assert!(version(&f.member.1, f.root) < new.state.version);

            // Fresh copy: no pull. Stale: pulls from the host.
            store::mark_checked(&f.member.1, now_unix()).unwrap();
            assert!(
                refresh_if_stale(&member_ep, &f.member.1)
                    .await
                    .unwrap()
                    .is_none()
            );
            store::mark_checked(&f.member.1, now_unix() - STALE_AFTER_SECS - 1).unwrap();
            let pulled = tokio::time::timeout(
                Duration::from_secs(15),
                refresh_if_stale(&member_ep, &f.member.1),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(pulled.as_ref(), Some(&new));
            assert_eq!(store::read(&f.member.1, f.root).unwrap().unwrap(), new);
            assert!(!store::is_stale(&f.member.1, now_unix(), STALE_AFTER_SECS));
            admin_ep.close().await;
            member_ep.close().await;
        }
    }
}

//! Moving the signed state by key over [`STATE_ALPN`](library::STATE_ALPN).
//! The frames are [`library::StateFrame`].
//!
//! - [`push_all`]: after `invite` / `remove` / `service` / `role` (and
//!   `wires state push`), the admin offers the new state to every **host**
//!   (they enforce it, and they are the members that listen: only `serve`
//!   runs the responder), plus any node that hosted under the state before
//!   the edit. A host it can't reach is reported, not queued; the admin
//!   command fails when it reached none ([`PushReport::reached_no_host`]).
//! - [`pull`]: a cold command whose copy was last checked more than
//!   [`STALE_AFTER_SECS`] ago asks the hosts (the ones this node called
//!   before first) and then the admin for a newer one ([`refresh_cold`]),
//!   stopping at the first adopted state or the first vouched "you are
//!   current"; a running `wires serve` does the same on a timer
//!   ([`refresh_loop`]), and once before its preflight ([`pull_now`]).
//! - [`respond`] / [`StateResponder`]: the side a running host serves on the
//!   ALPN: answer a pull, adopt an offer.
//!
//! One bi-stream per exchange, one frame each way. Nothing is ever adopted
//! except through [`store::adopt_if_newer`] (verified under the root, fresh,
//! strictly newer), so a lying peer can only fail to help. An expired copy
//! vouches for nobody: its holder neither serves it nor hears a dialer on
//! its strength.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use iroh::Endpoint;
use iroh::endpoint::Connection;
use library::{NodeId, NodeIdentity, STATE_ALPN, SignedState, StateFrame, StateVersion};
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

/// Which hosts took an offered state and which didn't.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PushReport {
    /// Hosts now holding at least the offered version.
    pub(crate) delivered: Vec<NodeId>,
    /// Hosts that couldn't be reached or refused it.
    pub(crate) missed: Vec<NodeId>,
}

impl PushReport {
    /// One human line for the admin's stderr.
    pub(crate) fn line(&self, version: StateVersion) -> String {
        let total = self.delivered.len() + self.missed.len();
        if total == 0 {
            return format!(
                "state version {}: no host to push to yet (a new member gets it in its invite \
                 token)",
                version.0
            );
        }
        let mut out = format!(
            "state version {}: pushed to {} of {total} host(s)",
            version.0,
            self.delivered.len()
        );
        if !self.missed.is_empty() {
            out.push_str(&format!(
                "; not reached: {} (`wires state push` re-sends it)",
                self.missed
                    .iter()
                    .map(|n| format!("{}…", &n.hex()[..8]))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        out
    }

    /// Whether there were hosts to reach and not one took the state: the
    /// fabric is still enforcing the older one.
    pub(crate) fn reached_no_host(&self) -> bool {
        self.delivered.is_empty() && !self.missed.is_empty()
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

/// Offer `state` to each of `targets`, concurrently. A target counts as
/// delivered once it answers holding at least `state`'s version.
pub(crate) async fn push_all(
    endpoint: &Endpoint,
    state: &SignedState,
    targets: &[NodeId],
) -> Result<PushReport> {
    let mut report = PushReport::default();
    let mut set = tokio::task::JoinSet::new();
    for &target in targets {
        let endpoint = endpoint.clone();
        let offer = StateFrame::Offer {
            state: state.clone(),
        };
        let want = state.state.version;
        set.spawn(async move {
            let ok = match exchange(&endpoint, target, &offer).await {
                Ok(StateFrame::Have { version }) => version >= want,
                Ok(StateFrame::Denied { reason }) => {
                    tracing::warn!(host = %target.hex(), "state push refused: {reason}");
                    false
                }
                Ok(_) => false,
                Err(e) => {
                    tracing::debug!(host = %target.hex(), "state push failed: {e:#}");
                    false
                }
            };
            (target, ok)
        });
    }
    while let Some(joined) = set.join_next().await {
        let (target, ok) = joined.context("a push task panicked")?;
        if ok {
            report.delivered.push(target);
        } else {
            report.missed.push(target);
        }
    }
    report.delivered.sort();
    report.missed.sort();
    Ok(report)
}

/// Who the admin pushes `state` to: its hosts, plus `earlier` (the hosts of
/// the state before this edit, so a node that stops hosting learns it), never
/// `me`. Plain members aren't dialed: nothing listens there.
pub(crate) fn push_targets(
    state: &SignedState,
    earlier: &BTreeSet<NodeId>,
    me: NodeId,
) -> Vec<NodeId> {
    state
        .state
        .hosts
        .iter()
        .chain(earlier)
        .copied()
        .filter(|h| *h != me)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The admin's push of the stored state from `ks` over `endpoint`, to
/// [`push_targets`].
pub(crate) async fn push_current_on(
    endpoint: &Endpoint,
    ks: &Keystore,
    earlier: &BTreeSet<NodeId>,
) -> Result<PushReport> {
    let state = stored(ks)?;
    let me = transport::to_node_id(&endpoint.id());
    push_all(endpoint, &state, &push_targets(&state, earlier, me)).await
}

/// [`push_current_on`] over a freshly bound endpoint for this keystore's
/// node (the admin CLI's form): the version pushed and the report. Binds
/// nothing when there is no host to push to.
pub(crate) async fn push_current(
    ks: &Keystore,
    earlier: &BTreeSet<NodeId>,
) -> Result<(StateVersion, PushReport)> {
    let state = stored(ks)?;
    let node = keystore::node_identity_in(ks)?;
    let version = state.state.version;
    if push_targets(&state, earlier, node.node_id()).is_empty() {
        return Ok((version, PushReport::default()));
    }
    let endpoint = transport::bind_with_alpn(&node, None, STATE_ALPN).await?;
    let report = push_current_on(&endpoint, ks, earlier).await;
    endpoint.close().await;
    Ok((version, report?))
}

/// The hosts of the state `ks` holds now (empty when it holds none): what an
/// admin command records before its edit, for [`push_targets`].
pub(crate) fn held_hosts(ks: &Keystore) -> Result<BTreeSet<NodeId>> {
    let Some(root) = store::fabric(ks)? else {
        return Ok(BTreeSet::new());
    };
    Ok(store::read(ks, root)?.map_or_else(BTreeSet::new, |s| s.state.hosts))
}

/// The state `ks` holds, or an error saying there is none.
fn stored(ks: &Keystore) -> Result<SignedState> {
    let root = store::fabric(ks)?.ok_or_else(|| anyhow!("this keystore is in no fabric"))?;
    store::read(ks, root)?.ok_or_else(|| anyhow!("no signed state here"))
}

// ---------------------------------------------------------------------------
// Pull (members)
// ---------------------------------------------------------------------------

/// Ask `peers` in turn for a state newer than `have`, stopping at the
/// first one that settles it:
///
/// - a verified, fresh, newer `offer` is adopted and returned;
/// - a `have` at least `have` from a **vouched** peer (a host in the held
///   copy, or the recorded admin) says this node is current: `Ok(None)`.
///
/// Only those two outcomes mark the copy checked; a refusal, a peer that is
/// behind, or an unvouched answer does not (so the next command asks again).
pub(crate) async fn pull(
    endpoint: &Endpoint,
    ks: &Keystore,
    peers: &[NodeId],
    have: StateVersion,
) -> Result<Option<SignedState>> {
    let root = store::fabric(ks)?.ok_or_else(|| anyhow!("this keystore is in no fabric"))?;
    let held = store::read(ks, root)?;
    let admin = store::read_admin(ks).ok().flatten();
    let vouched = |p: NodeId| admin == Some(p) || held.as_ref().is_some_and(|s| s.state.is_host(p));
    for peer in peers {
        match exchange(endpoint, *peer, &StateFrame::Have { version: have }).await {
            Ok(StateFrame::Offer { state }) => {
                match store::adopt_if_newer(ks, &state, root, now_unix()) {
                    Ok(true) => {
                        store::mark_checked(ks, now_unix())?;
                        return Ok(Some(state));
                    }
                    Ok(false) => {}
                    Err(e) => tracing::warn!(peer = %peer.hex(), "refused a pulled state: {e:#}"),
                }
            }
            Ok(StateFrame::Have { version }) if version >= have && vouched(*peer) => {
                store::mark_checked(ks, now_unix())?;
                return Ok(None);
            }
            Ok(StateFrame::Have { version }) => {
                tracing::debug!(peer = %peer.hex(), version = version.0, "not a current answer")
            }
            Ok(StateFrame::Denied { reason }) => {
                tracing::debug!(peer = %peer.hex(), "state pull refused: {reason}")
            }
            Err(e) => tracing::debug!(peer = %peer.hex(), "state pull failed: {e:#}"),
        }
    }
    Ok(None)
}

/// Where this node pulls from, never itself: first the hosts this node
/// called before (`last-good.json`: the hosts of the services it actually
/// uses, which it has already reached), then every other host in its copy
/// (they are up, serving), then the admin if known (often a one-shot CLI,
/// so last).
pub(crate) fn pull_peers(ks: &Keystore, state: Option<&SignedState>, me: NodeId) -> Vec<NodeId> {
    let mut peers = Vec::new();
    if let Some(state) = state {
        let used = crate::caller::pick::LastGood::load(&crate::caller::pick::LastGood::path(ks));
        peers.extend(used.hosts().filter(|h| state.state.is_host(*h)));
        peers.extend(state.state.hosts.iter().copied());
    }
    if let Ok(Some(admin)) = store::read_admin(ks) {
        peers.push(admin);
    }
    let mut seen = std::collections::BTreeSet::new();
    peers.retain(|p| *p != me && seen.insert(*p));
    peers
}

/// Pull over `endpoint` from [`pull_peers`], whether or not the copy is
/// stale. Returns the newly adopted state, if any.
pub(crate) async fn catch_up(endpoint: &Endpoint, ks: &Keystore) -> Result<Option<SignedState>> {
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

/// `wires serve`'s catch-up when its preflight fails (a host assigned a
/// service while it was offline): bind as `node` briefly and [`catch_up`],
/// within the cold-pull budget.
pub(crate) async fn pull_now(
    ks: &Keystore,
    node: &NodeIdentity,
    relay_url: Option<&str>,
) -> Result<Option<SignedState>> {
    let endpoint = transport::bind_with_alpn(node, relay_url, STATE_ALPN).await?;
    let pulled = tokio::time::timeout(COLD_PULL_BUDGET, catch_up(&endpoint, ks))
        .await
        .unwrap_or(Ok(None));
    endpoint.close().await;
    pulled
}

/// Pull over `endpoint` if the stored copy was last checked more than
/// [`STALE_AFTER_SECS`] ago. Returns the newly adopted state, if any.
pub(crate) async fn refresh_if_stale(
    endpoint: &Endpoint,
    ks: &Keystore,
) -> Result<Option<SignedState>> {
    if !store::is_stale(ks, now_unix(), STALE_AFTER_SECS) {
        return Ok(None);
    }
    catch_up(endpoint, ks).await
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
/// An expired held copy vouches for nobody. So:
///
/// - `Offer`: the dialer must be a member of the fresh held copy or of the
///   (verified) offered one. The offer is run through `adopt_if_newer`
///   (verified, fresh, strictly newer). Adopted: answered `Have` with the new
///   version, and the copy is marked checked. Not adopted: answered `Have`
///   only if the dialer is a member of the fresh held copy, else `Denied`,
///   and the copy is **not** marked checked (a removed member re-offering
///   its old state must not stop this node pulling the newer one).
/// - `Have`: the held copy must exist and be fresh, and the dialer must be a
///   member of it; answered with the held copy if it is newer, else `Have`.
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
    // Membership counts only in a copy that is still fresh.
    let is_member = |s: &Option<SignedState>| {
        s.as_ref()
            .is_some_and(|s| s.check_fresh(now).is_ok() && s.state.is_member(caller))
    };
    let not_a_member = || format!("{}… is not a member", &caller.hex()[..8]);
    let version = |s: &Option<SignedState>| s.as_ref().map_or(StateVersion(0), |s| s.state.version);
    match frame {
        StateFrame::Offer { state } => {
            let vouched = state.verify(root).is_ok() && state.state.is_member(caller);
            if !is_member(&held) && !vouched {
                return Err(not_a_member());
            }
            let adopted = store::adopt_if_newer(ks, &state, root, now)
                .map_err(|e| format!("the offered state was refused: {e:#}"))?;
            let held = store::read(ks, root).map_err(fail)?;
            if adopted {
                store::mark_checked(ks, now).map_err(fail)?;
            } else if !is_member(&held) {
                return Err(not_a_member());
            }
            Ok(StateFrame::Have {
                version: version(&held),
            })
        }
        StateFrame::Have { version: theirs } => {
            let Some(state) = held else {
                return Err("this node holds no signed state".into());
            };
            if state.check_fresh(now).is_err() {
                return Err(format!(
                    "this node's signed state (version {}) has expired",
                    state.state.version.0
                ));
            }
            if !state.state.is_member(caller) {
                return Err(not_a_member());
            }
            if state.state.version > theirs {
                Ok(StateFrame::Offer { state })
            } else {
                Ok(StateFrame::Have {
                    version: state.state.version,
                })
            }
        }
        StateFrame::Denied { .. } => Err("expected an offer or a have".into()),
    }
}

/// [`respond`] as a router protocol on [`STATE_ALPN`], for a running
/// host (`wires serve` mounts it; nothing else listens).
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

    /// Card 28 §8: a removed member re-offering its old, still-fresh state
    /// is refused by a host that holds the newer one, and never marks a
    /// host's copy checked (so the host keeps pulling).
    #[test]
    fn a_removed_members_old_offer_is_denied_and_marks_nothing_checked() {
        let root = NodeIdentity::generate();
        let (me, removed) = (NodeIdentity::generate(), NodeIdentity::generate().node_id());
        let v1 = signed(&root, 1, &[me.node_id(), removed]);
        let v2 = signed(&root, 2, &[me.node_id()]);
        let offer = |s: &SignedState| StateFrame::Offer { state: s.clone() };

        // The host already holds v2: the old offer is refused outright.
        let ks = member_ks(&root, &me, Some(&v2));
        let err = answer(&ks, removed, offer(&v1), 10).unwrap_err();
        assert!(err.contains("not a member"), "{err}");
        assert!(store::is_stale(&ks, 10, STALE_AFTER_SECS));

        // The host missed v2: the removed member is still in its copy, so
        // it is told what is held, but the copy is not marked checked.
        let ks = member_ks(&root, &me, Some(&v1));
        let have1 = StateFrame::Have {
            version: StateVersion(1),
        };
        assert_eq!(answer(&ks, removed, offer(&v1), 10), Ok(have1));
        assert!(
            store::is_stale(&ks, 10, STALE_AFTER_SECS),
            "a non-adopting offer must not stop this node pulling"
        );
        // A real adopt does mark it.
        let v3 = signed(&root, 3, &[me.node_id()]);
        let answered = answer(&ks, me.node_id(), offer(&v3), 10);
        assert_eq!(
            answered,
            Ok(StateFrame::Have {
                version: StateVersion(3)
            })
        );
        assert!(!store::is_stale(&ks, 10, STALE_AFTER_SECS));
    }

    /// Card 28 §8: an expired held copy is not served, and vouches for no
    /// dialer; a fresh newer offer still repairs it.
    #[test]
    fn an_expired_copy_is_not_served_and_vouches_for_nobody() {
        let root = NodeIdentity::generate();
        let (me, peer) = (NodeIdentity::generate(), NodeIdentity::generate().node_id());
        let mut s = State::new(root.node_id());
        s.version = StateVersion(1);
        s.not_after = 100;
        s.members.extend([me.node_id(), peer]);
        let v1 = s.sign(&root).unwrap();
        let ks = member_ks(&root, &me, Some(&v1));
        let have = |v| StateFrame::Have {
            version: StateVersion(v),
        };
        let offer = |s: &SignedState| StateFrame::Offer { state: s.clone() };
        assert_eq!(answer(&ks, peer, have(0), 50), Ok(offer(&v1)), "fresh");
        let err = answer(&ks, peer, have(0), 200).unwrap_err();
        assert!(err.contains("expired"), "{err}");
        // An offer that isn't adopted is refused: nothing here vouches.
        assert!(answer(&ks, peer, offer(&v1), 200).is_err());
        // A fresh, newer state from a member of it is adopted.
        let v2 = signed(&root, 2, &[me.node_id(), peer]);
        assert_eq!(answer(&ks, peer, offer(&v2), 200), Ok(have(2)));
    }

    /// The admin pushes to the hosts (and the hosts before the edit), never
    /// to plain members or itself.
    #[test]
    fn push_targets_are_hosts_old_and_new() {
        let root = NodeIdentity::generate();
        let [admin, h1, h2, member] = [0; 4].map(|_| NodeIdentity::generate().node_id());
        let mut s = State::new(root.node_id());
        s.version = StateVersion(1);
        s.not_after = i64::MAX;
        s.members.extend([admin, h1, member]);
        s.hosts.insert(h1);
        s.services.insert(
            library::ServiceName::new("svc").unwrap(),
            library::Service {
                description: String::new(),
                allow: vec![],
                hosts: vec![h1],
                readers: vec![],
            },
        );
        let state = s.sign(&root).unwrap();
        let mut want = vec![h1, h2];
        want.sort();
        assert_eq!(
            push_targets(&state, &BTreeSet::from([h2, admin]), admin),
            want
        );
        assert_eq!(
            push_targets(&state, &BTreeSet::new(), h1),
            Vec::<NodeId>::new()
        );
    }

    #[test]
    fn the_push_line_says_which_hosts_it_missed() {
        let a = NodeIdentity::from_seed([1; 32]).node_id();
        let b = NodeIdentity::from_seed([2; 32]).node_id();
        let none = PushReport::default();
        assert!(!none.reached_no_host());
        assert!(none.line(StateVersion(3)).contains("no host to push to"));
        let missed = PushReport {
            delivered: vec![],
            missed: vec![a],
        };
        assert!(missed.reached_no_host());
        let line = missed.line(StateVersion(3));
        assert!(line.contains("pushed to 0 of 1 host(s)"), "{line}");
        assert!(line.contains(&a.hex()[..8]) && line.contains("wires state push"));
        let some = PushReport {
            delivered: vec![b],
            missed: vec![a],
        };
        assert!(!some.reached_no_host());
        assert!(
            some.line(StateVersion(3))
                .contains("pushed to 1 of 2 host(s)")
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
            init_in(&admin, InitArgs::default()).unwrap();
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

        /// Like `bind` with `serve`, but every state connection accepted is
        /// counted.
        async fn bind_counted(
            node: &NodeIdentity,
            ks: &Arc<Keystore>,
            book: &MemoryLookup,
        ) -> (Endpoint, Router, Arc<std::sync::atomic::AtomicUsize>) {
            #[derive(Debug, Clone)]
            struct Counted(StateResponder, Arc<std::sync::atomic::AtomicUsize>);
            impl iroh::protocol::ProtocolHandler for Counted {
                async fn accept(
                    &self,
                    conn: Connection,
                ) -> std::result::Result<(), iroh::protocol::AcceptError> {
                    self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    self.0.accept(conn).await
                }
            }
            let (endpoint, _) = bind(node, ks, book, false).await;
            let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let router = Router::builder(endpoint.clone())
                .accept(
                    STATE_ALPN,
                    Counted(StateResponder(Arc::clone(ks)), Arc::clone(&count)),
                )
                .spawn();
            (endpoint, router, count)
        }

        #[tokio::test]
        async fn an_admin_change_reaches_the_host_within_two_seconds_and_skips_members() {
            let f = fabric();
            let book = MemoryLookup::new();
            let admin_node = f.admin.read_node_identity().unwrap().unwrap();
            let (admin_ep, _) = bind(&admin_node, &f.admin, &book, false).await;
            let (_h, _hr) = bind(&f.host.0, &f.host.1, &book, true).await;
            let (_m, _mr, member_dials) = bind_counted(&f.member.0, &f.member.1, &book).await;
            let before = version(&f.member.1, f.root);

            let earlier = held_hosts(&f.admin).unwrap();
            let new = assign(&f);
            let started = std::time::Instant::now();
            let report = tokio::time::timeout(
                Duration::from_secs(2),
                push_current_on(&admin_ep, &f.admin, &earlier),
            )
            .await
            .expect("the push took over 2 s")
            .unwrap();
            assert!(started.elapsed() < Duration::from_secs(2));
            assert_eq!(report.delivered, vec![f.host.0.node_id()]);
            assert!(report.missed.is_empty(), "{report:?}");
            assert_eq!(version(&f.host.1, f.root), new.state.version);
            assert!(
                store::read(&f.host.1, f.root)
                    .unwrap()
                    .unwrap()
                    .state
                    .is_host(f.host.0.node_id())
            );
            // A plain member is not dialed (nothing listens there).
            assert_eq!(member_dials.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert_eq!(version(&f.member.1, f.root), before);

            // `remove`: the member is dropped, and the host holds that at once.
            let earlier = held_hosts(&f.admin).unwrap();
            let removed = service::edit_state(&f.admin, ttl(), |s| {
                s.members.remove(&f.member.0.node_id());
                Ok(())
            })
            .unwrap();
            let report = push_current_on(&admin_ep, &f.admin, &earlier)
                .await
                .unwrap();
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
            let pulled = pull(&m2, &f.member.1, &[f.host.0.node_id()], before)
                .await
                .unwrap();
            assert!(pulled.is_none());
            assert_eq!(version(&f.member.1, f.root), before);
            admin_ep.close().await;
        }

        /// A push that reaches none of the state's hosts says so.
        #[tokio::test]
        async fn a_push_that_reaches_no_host_is_reported() {
            let f = fabric();
            let book = MemoryLookup::new();
            let admin_node = f.admin.read_node_identity().unwrap().unwrap();
            let (admin_ep, _) = bind(&admin_node, &f.admin, &book, false).await;
            // The host is known but not listening.
            let (_h, _) = bind(&f.host.0, &f.host.1, &book, false).await;
            assign(&f);
            let report = push_current_on(&admin_ep, &f.admin, &BTreeSet::new())
                .await
                .unwrap();
            assert!(report.reached_no_host(), "{report:?}");
            assert_eq!(report.missed, vec![f.host.0.node_id()]);
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
            push_current_on(&admin_ep, &f.admin, &BTreeSet::new())
                .await
                .unwrap();
            assert_eq!(version(&f.host.1, f.root), new.state.version);

            // The admin (still a member) replaying the genuine older state is
            // told what's held.
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
            let (member_ep, _) = bind(&f.member.0, &f.member.1, &book, false).await;

            // The member already knows the host (an earlier state it got)…
            let assigned = assign(&f);
            store::adopt_if_newer(&f.member.1, &assigned, f.root, now_unix()).unwrap();
            // …but members aren't pushed to, so it misses this one.
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
            let report = push_current_on(&admin_ep, &f.admin, &BTreeSet::new())
                .await
                .unwrap();
            assert_eq!(report.delivered, vec![f.host.0.node_id()]);
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

        /// Three hosts, a member whose copy is current: the pull stops at
        /// the first host's "current" answer, and marks the copy checked.
        #[tokio::test]
        async fn a_pull_stops_at_the_first_current_answer() {
            let f = fabric();
            let book = MemoryLookup::new();
            let (h2, h3) = (NodeIdentity::generate(), NodeIdentity::generate());
            service::edit_state(&f.admin, ttl(), |s| {
                s.members.extend([h2.node_id(), h3.node_id()]);
                Ok(())
            })
            .unwrap();
            let hosts = vec![f.host.0.node_id(), h2.node_id(), h3.node_id()];
            let state = service::add(
                &f.admin,
                ServiceName::new("orders-db").unwrap(),
                ServiceEdit {
                    hosts: Some(hosts.clone()),
                    ..Default::default()
                },
                ttl(),
            )
            .unwrap();
            let join = |node: &NodeIdentity| {
                let root = f.admin.read_root_identity().unwrap().unwrap();
                let ks = Arc::new(member_ks(&root, node, None));
                store::adopt_if_newer(&ks, &state, f.root, now_unix()).unwrap();
                ks
            };
            let (h2_ks, h3_ks) = (join(&h2), join(&h3));
            for ks in [&f.host.1, &f.member.1] {
                store::adopt_if_newer(ks, &state, f.root, now_unix()).unwrap();
            }
            let mut counts = Vec::new();
            let mut keep = Vec::new();
            for (node, ks) in [(&f.host.0, &f.host.1), (&h2, &h2_ks), (&h3, &h3_ks)] {
                let (ep, router, count) = bind_counted(node, ks, &book).await;
                counts.push(count);
                keep.push((ep, router));
            }
            let (member_ep, _) = bind(&f.member.0, &f.member.1, &book, false).await;
            assert!(store::is_stale(&f.member.1, now_unix(), STALE_AFTER_SECS));
            let pulled = pull(&member_ep, &f.member.1, &hosts, state.state.version)
                .await
                .unwrap();
            assert!(pulled.is_none());
            let dials: usize = counts
                .iter()
                .map(|c| c.load(std::sync::atomic::Ordering::SeqCst))
                .sum();
            assert_eq!(dials, 1, "one current answer settles it");
            assert!(!store::is_stale(&f.member.1, now_unix(), STALE_AFTER_SECS));

            // The hosts this node has called go first.
            crate::caller::pick::LastGood::record(
                &crate::caller::pick::LastGood::path(&f.member.1),
                &ServiceName::new("orders-db").unwrap(),
                h3.node_id(),
            );
            let peers = pull_peers(&f.member.1, Some(&state), f.member.0.node_id());
            assert_eq!(peers[0], h3.node_id());
            assert_eq!(peers.len(), 4, "three hosts and the admin: {peers:?}");
            member_ep.close().await;
        }

        /// A removed member re-offers its old state to a host that missed
        /// the removal: the host is not marked checked, so it still pulls
        /// the newer state from another host. A host that holds the newer
        /// state refuses the offer.
        #[tokio::test]
        async fn a_removed_member_cannot_stop_a_host_pulling() {
            let f = fabric();
            let book = MemoryLookup::new();
            let h2 = NodeIdentity::generate();
            service::edit_state(&f.admin, ttl(), |s| {
                s.members.insert(h2.node_id());
                Ok(())
            })
            .unwrap();
            let old = service::add(
                &f.admin,
                ServiceName::new("orders-db").unwrap(),
                ServiceEdit {
                    hosts: Some(vec![f.host.0.node_id(), h2.node_id()]),
                    ..Default::default()
                },
                ttl(),
            )
            .unwrap();
            let root = f.admin.read_root_identity().unwrap().unwrap();
            let h2_ks = Arc::new(member_ks(&root, &h2, None));
            for ks in [&f.host.1, &h2_ks, &f.member.1] {
                store::adopt_if_newer(ks, &old, f.root, now_unix()).unwrap();
            }
            let removed = service::edit_state(&f.admin, ttl(), |s| {
                s.members.remove(&f.member.0.node_id());
                Ok(())
            })
            .unwrap();
            let admin_node = f.admin.read_node_identity().unwrap().unwrap();
            let (admin_ep, _) = bind(&admin_node, &f.admin, &book, false).await;
            let (_h1, _h1r) = bind(&f.host.0, &f.host.1, &book, true).await;
            let (h2_ep, _h2r) = bind(&h2, &h2_ks, &book, true).await;
            // Only host 1 gets the removal.
            let report = push_all(&admin_ep, &removed, &[f.host.0.node_id()])
                .await
                .unwrap();
            assert_eq!(report.delivered, vec![f.host.0.node_id()]);

            let (m_ep, _) = bind(&f.member.0, &f.member.1, &book, false).await;
            // Host 1 refuses the replay outright.
            let r1 = push_all(&m_ep, &old, &[f.host.0.node_id()]).await.unwrap();
            assert_eq!(r1.missed, vec![f.host.0.node_id()]);
            // Host 2 hears it (the member is in its copy) but isn't marked
            // checked by it…
            push_all(&m_ep, &old, &[h2.node_id()]).await.unwrap();
            assert!(store::is_stale(&h2_ks, now_unix(), STALE_AFTER_SECS));
            // …so its next refresh pulls the removal from host 1.
            let pulled = refresh_if_stale(&h2_ep, &h2_ks).await.unwrap();
            assert_eq!(pulled.as_ref(), Some(&removed));
            admin_ep.close().await;
            m_ep.close().await;
        }

        /// A host assigned a service while it was offline catches up from
        /// another host before its preflight (what `serve` runs).
        #[tokio::test]
        async fn a_host_assigned_while_offline_catches_up() {
            let f = fabric();
            let book = MemoryLookup::new();
            let late = NodeIdentity::generate();
            service::edit_state(&f.admin, ttl(), |s| {
                s.members.insert(late.node_id());
                Ok(())
            })
            .unwrap();
            let first = assign(&f);
            let root = f.admin.read_root_identity().unwrap().unwrap();
            let late_ks = Arc::new(member_ks(&root, &late, None));
            store::adopt_if_newer(&late_ks, &first, f.root, now_unix()).unwrap();
            store::adopt_if_newer(&f.host.1, &first, f.root, now_unix()).unwrap();
            // The admin adds `late` as a second host; only host 1 is up.
            let second = service::set(
                &f.admin,
                ServiceName::new("orders-db").unwrap(),
                ServiceEdit {
                    hosts: Some(vec![f.host.0.node_id(), late.node_id()]),
                    ..Default::default()
                },
                ttl(),
            )
            .unwrap();
            let admin_node = f.admin.read_node_identity().unwrap().unwrap();
            let (admin_ep, _) = bind(&admin_node, &f.admin, &book, false).await;
            let (_h, _hr) = bind(&f.host.0, &f.host.1, &book, true).await;
            push_current_on(&admin_ep, &f.admin, &BTreeSet::new())
                .await
                .unwrap();
            // `late` comes up: fresh check or not, it catches up.
            store::mark_checked(&late_ks, now_unix()).unwrap();
            let (late_ep, _) = bind(&late, &late_ks, &book, false).await;
            let pulled = catch_up(&late_ep, &late_ks).await.unwrap();
            assert_eq!(pulled.as_ref(), Some(&second));
            assert!(
                store::read(&late_ks, f.root)
                    .unwrap()
                    .unwrap()
                    .state
                    .assigns(&ServiceName::new("orders-db").unwrap(), late.node_id())
            );
            admin_ep.close().await;
            late_ep.close().await;
        }
    }
}

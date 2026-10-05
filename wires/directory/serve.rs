//! The directory on the network: its two ALPNs, its loops, and
//! `wires directory serve`.
//!
//! - [`DirectoryProtocol`] (`wires/directory/3`): one request per
//!   connection, after a `hello` ([`Directory::admit`]): a node the policy
//!   names, or a caller whose ID token verifies and whom the policy admits
//!   ([`library::check_admitted`]), may ask; anyone may publish (the head
//!   first, checked under the root, and only then its items); anyone else
//!   asking hears only [`NOT_ADMITTED`](super::node::NOT_ADMITTED), traced,
//!   not logged. A dialer that opens with `open` hears the directory's
//!   proof first ([`Directory::proof`]), and sends its `hello` after.
//! - [`SubscriptionProtocol`] (`wires/directory-sub/3`): a host's
//!   subscription to the whole policy ([`sub_policy`](super::sub_policy)).
//! - [`beat_loop`]: a new `Fresh` every `settings.beat_secs`.
//!
//! Directories don't follow each other (card 45): one that missed a
//! publish holds the policy before it until a publish reaches it.
//!
//! `wires serve` runs all of it when the policy lists its node, or, holding
//! none yet, its network string does ([`Running::start`]); `wires directory
//! serve` runs it alone, on a node with no `host.json` ([`serve_cmd`]).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use iroh::endpoint::Connection;
use library::{
    DIRECTORY_ALPN, DIRECTORY_SUB_ALPN, DirectoryAnswer, DirectoryRequest, NodeId, NodeIdentity,
    SubFrame, SubRequest,
};

use super::node::{DEFAULT_MAX_SUBSCRIBERS, Directory, HeadCheck, NOT_ADMITTED};
use super::wire;
use crate::admin::keystore::{self, Keystore};
use crate::clock::now_unix;
use crate::host::transport::{self, Throttle};

/// Refusals of directory peers not known to be admitted.
static STRANGERS: Throttle = Throttle::new();

/// `wires/directory/3` as a router protocol. See the module docs.
#[derive(Clone, Debug)]
pub(crate) struct DirectoryProtocol(pub(crate) Arc<Directory>);

impl iroh::protocol::ProtocolHandler for DirectoryProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), iroh::protocol::AcceptError> {
        let caller = transport::to_node_id(&conn.remote_id());
        let Ok(permit) = Arc::clone(&self.0.undecided).try_acquire_owned() else {
            STRANGERS.refused("directory", caller, "too many undecided streams");
            conn.close(1u32.into(), b"busy");
            return Ok(());
        };
        let result = one_request(&self.0, &conn, caller, permit).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
        if let Err(e) = result {
            tracing::debug!(peer = %caller.hex(), "directory request failed: {e:#}");
        }
        Ok(())
    }
}

/// Accept `conn`'s one stream within `dir.stream_deadline` (a peer that
/// never opens one gives up its undecided slot). The `hello` then gets as
/// long again.
async fn accept_stream(
    dir: &Directory,
    conn: &Connection,
) -> Result<(iroh::endpoint::SendStream, iroh::endpoint::RecvStream)> {
    tokio::time::timeout(dir.stream_deadline, conn.accept_bi())
        .await
        .map_err(|_| anyhow!("no stream within {:?}", dir.stream_deadline))?
        .context("accepting a stream")
}

/// Serve one request on `conn`: the `hello` (small, within the stream
/// deadline; after an `open`, the directory's proof first, then the
/// `hello`, within as long again), admission, the request, the answer. `undecided` is this
/// connection's undecided slot, released once the peer is admitted (or a
/// publisher's head checked out); admitted work holds one of
/// [`MAX_ADMITTED`](super::node::MAX_ADMITTED) slots instead, or hears
/// [`BUSY`](super::node::BUSY). A publish's items are read only after its
/// head verified under the root and is newer than the held one.
async fn one_request(
    dir: &Directory,
    conn: &Connection,
    caller: NodeId,
    undecided: tokio::sync::OwnedSemaphorePermit,
) -> Result<()> {
    let (mut send, mut recv) = accept_stream(dir, conn).await?;
    let refuse = |detail: String| {
        STRANGERS.refused("directory", caller, &detail);
        DirectoryAnswer::Denied {
            reason: NOT_ADMITTED.into(),
        }
    };
    let busy = || DirectoryAnswer::Denied {
        reason: super::node::BUSY.into(),
    };
    let mut hello = wire::read_hello(&mut recv, dir.stream_deadline).await;
    if let Ok(DirectoryRequest::Open {}) = hello {
        // A caller about to present its token: show it this directory is
        // current first (card 45), and read its `hello` after.
        match dir.proof(now_unix()) {
            Ok(proof) => write_frame(&mut send, &DirectoryAnswer::Proof { proof }).await?,
            Err(reason) => {
                return write_answer(&mut send, &DirectoryAnswer::Denied { reason }).await;
            }
        }
        hello = wire::read_hello(&mut recv, dir.stream_deadline).await;
    }
    let answer = match hello {
        Ok(DirectoryRequest::Hello { id_token }) => {
            let peer = dir.admit(caller, id_token.as_ref(), now_unix()).await;
            let request = if peer.admitted() {
                // Admitted: the request is read under the admitted bound.
                match admitted(dir, undecided) {
                    None => {
                        write_answer(&mut send, &busy()).await?;
                        return Ok(());
                    }
                    Some(slot) => (wire::read_request(&mut recv).await, Some(slot), None),
                }
            } else {
                // Not admitted: a publish at most, read under the undecided
                // bound (small, like every request).
                (wire::read_request(&mut recv).await, None, Some(undecided))
            };
            match request {
                (Ok(DirectoryRequest::Publish { head }), slot, undecided) => {
                    match dir.check_head(&head, now_unix()) {
                        HeadCheck::Held { version, head } => {
                            DirectoryAnswer::Published { version, head }
                        }
                        HeadCheck::Refused(reason) => {
                            tracing::info!(peer = %caller.hex(), "publish refused: {reason}");
                            DirectoryAnswer::Denied {
                                reason: transport::truncate_reason(reason),
                            }
                        }
                        // A root-signed, newer head: only now are its
                        // (possibly large) items read, as admitted work.
                        HeadCheck::Wanted => {
                            let slot = match (slot, undecided) {
                                (Some(slot), _) => Some(slot),
                                (None, Some(undecided)) => admitted(dir, undecided),
                                (None, None) => None,
                            };
                            match slot {
                                None => busy(),
                                Some(_slot) => match wire::read_items(&mut recv).await {
                                    Ok(items) => dir.publish(caller, head, items, now_unix()),
                                    Err(e) => {
                                        tracing::info!(peer = %caller.hex(), "unreadable publish: {e:#}");
                                        return Ok(());
                                    }
                                },
                            }
                        }
                    }
                }
                // Holding no policy, it admits nobody; it says what it waits
                // for (there is nothing to keep from anyone).
                (Ok(_), None, _) if dir.snapshot().is_none() => DirectoryAnswer::Denied {
                    reason: super::node::EMPTY.into(),
                },
                (Ok(_), None, _) => {
                    refuse("asked for more than a publish without admission".into())
                }
                (Ok(request), Some(_slot), _) => dir.answer(&peer, request, now_unix()),
                (Err(e), ..) => {
                    tracing::debug!(peer = %caller.hex(), "unreadable directory request: {e:#}");
                    return Ok(());
                }
            }
        }
        Ok(_) => refuse("expected a hello".into()),
        Err(e) => refuse(format!("{e:#}")),
    };
    write_answer(&mut send, &answer).await
}

/// Send a frame that isn't the last (the proof).
async fn write_frame(
    send: &mut iroh::endpoint::SendStream,
    answer: &DirectoryAnswer,
) -> Result<()> {
    wire::write(send, &answer.encode()?).await
}

/// Send the one answer and end the stream.
async fn write_answer(
    send: &mut iroh::endpoint::SendStream,
    answer: &DirectoryAnswer,
) -> Result<()> {
    wire::write(send, &answer.encode()?).await?;
    send.finish().ok();
    Ok(())
}

/// Trade an admitted peer's undecided slot for an admitted one: `None`
/// (busy) when [`MAX_ADMITTED`](super::node::MAX_ADMITTED) are in hand.
/// The undecided slot is released either way.
fn admitted(
    dir: &Directory,
    undecided: tokio::sync::OwnedSemaphorePermit,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    drop(undecided);
    Arc::clone(&dir.admitted).try_acquire_owned().ok()
}

/// `wires/directory-sub/3` as a router protocol. See the module docs.
#[derive(Clone, Debug)]
pub(crate) struct SubscriptionProtocol(pub(crate) Arc<Directory>);

impl iroh::protocol::ProtocolHandler for SubscriptionProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), iroh::protocol::AcceptError> {
        let caller = transport::to_node_id(&conn.remote_id());
        if let Err(e) = subscription(&self.0, &conn, caller).await {
            tracing::debug!(peer = %caller.hex(), "subscription ended: {e:#}");
        }
        // Let a last frame (a `denied`) reach the subscriber before the
        // connection goes: it closes once it has read the end.
        let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
        conn.close(0u32.into(), b"done");
        Ok(())
    }
}

/// Serve one subscription on `conn` until either side ends it.
async fn subscription(dir: &Directory, conn: &Connection, caller: NodeId) -> Result<()> {
    let Ok(undecided) = Arc::clone(&dir.undecided).try_acquire_owned() else {
        STRANGERS.refused(
            "directory subscription",
            caller,
            "too many undecided streams",
        );
        return Ok(());
    };
    let (mut send, mut recv) = accept_stream(dir, conn).await?;
    let deny = async |send: &mut iroh::endpoint::SendStream, reason: String| -> Result<()> {
        let frame = SubFrame::Denied {
            reason: transport::truncate_reason(reason),
        };
        wire::write(send, &frame.encode()?).await?;
        send.finish().ok();
        Ok(())
    };
    let hello = tokio::time::timeout(dir.stream_deadline, wire::read_sub_request(&mut recv))
        .await
        .unwrap_or_else(|_| Err(anyhow!("no hello within {:?}", dir.stream_deadline)));
    let id_token = match hello {
        Ok(SubRequest::Hello { id_token }) => id_token,
        other => {
            let detail = match other {
                Err(e) => format!("{e:#}"),
                Ok(_) => "expected a hello".into(),
            };
            STRANGERS.refused("directory subscription", caller, &detail);
            return deny(&mut send, NOT_ADMITTED.into()).await;
        }
    };
    let peer = dir.admit(caller, id_token.as_ref(), now_unix()).await;
    if !peer.admitted() {
        if dir.snapshot().is_none() {
            return deny(&mut send, super::node::EMPTY.into()).await;
        }
        let detail = format!("{}… is neither named nor signed in", caller.short());
        STRANGERS.refused("directory subscription", caller, &detail);
        return deny(&mut send, NOT_ADMITTED.into()).await;
    }
    // Admitted: the `subscribe` is read under the admitted bound; the
    // subscription itself then holds a subscriber slot.
    let Some(reading) = admitted(dir, undecided) else {
        return deny(&mut send, super::node::BUSY.into()).await;
    };
    let have = match wire::read_sub_request(&mut recv).await? {
        SubRequest::Subscribe { have } => have,
        SubRequest::Hello { .. } => return deny(&mut send, "a second hello".into()).await,
    };
    drop(reading);
    // Card 37: the whole policy is for hosts and directories; a caller asks
    // for its view.
    if !peer.named {
        return deny(&mut send, super::node::VIEW_NOT_POLICY.into()).await;
    }
    super::sub_policy::serve(dir, conn, &mut send, caller, have).await
}

/// Sign a new `Fresh` every `settings.beat_secs` (of the held policy) until
/// the task is dropped.
pub(crate) async fn beat_loop(dir: Arc<Directory>) {
    loop {
        let secs = dir.snapshot().map_or(library::DEFAULT_BEAT_SECS, |c| {
            c.held.policy.settings.beat_secs
        });
        tokio::time::sleep(Duration::from_secs(u64::from(secs.max(1)))).await;
        if let Err(e) = dir.beat(now_unix()) {
            tracing::warn!("directory: could not sign a new freshness timestamp: {e:#}");
        }
    }
}

/// A directory's loops on an endpoint, stopped when this is dropped (the
/// ALPNs are the router's, [`Running::mount`]).
pub(crate) struct Running {
    /// The beat loop.
    tasks: tokio::task::JoinSet<()>,
}

impl Running {
    /// Start `dir`'s loop.
    pub(crate) fn start(dir: Arc<Directory>) -> Running {
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(beat_loop(dir));
        Running { tasks }
    }

    /// Add both ALPNs, answered by `dir`, to a router.
    pub(crate) fn mount(
        builder: iroh::protocol::RouterBuilder,
        dir: &Arc<Directory>,
    ) -> iroh::protocol::RouterBuilder {
        builder
            .accept(DIRECTORY_ALPN, DirectoryProtocol(Arc::clone(dir)))
            .accept(DIRECTORY_SUB_ALPN, SubscriptionProtocol(Arc::clone(dir)))
    }

    /// Stop the loops.
    pub(crate) async fn stop(mut self) {
        self.tasks.shutdown().await;
    }
}

/// `wires directory serve` arguments.
#[derive(Args)]
pub(crate) struct DirectoryServeArgs {
    /// Use a self-hosted relay at this URL instead of the n0 default.
    #[arg(long, hide = true)]
    pub(crate) relay_url: Option<String>,
    /// How many hosts may follow the policy here at once (one more is refused).
    #[arg(long, default_value_t = DEFAULT_MAX_SUBSCRIBERS)]
    pub(crate) max_subscribers: usize,
}

/// The file whose presence marks an admin keystore.
const ROOT_SEED: &str = "root.seed";

/// Whether `me` runs the directory mode from `ks`: the policy it holds
/// lists it, or, holding none yet, its network string does (the first
/// directory, which starts empty and takes the admin's first publish).
pub(crate) fn listed(ks: &Keystore, root: NodeId, me: NodeId) -> Result<bool> {
    Ok(match crate::policy::store::read(ks, root)? {
        Some(held) => held.directories().contains(&me),
        None => ks
            .read_network()?
            .is_some_and(|n| n.directories.contains(&me)),
    })
}

/// Open the directory a standalone `wires directory serve` runs from `ks`:
/// refuses the admin's keystore (it holds the root key), a keystore that
/// joined no network, and a node neither the policy it holds nor (holding
/// none) its network string lists in `directories`.
pub(crate) fn open_standalone(
    ks: Arc<Keystore>,
    max_subscribers: usize,
    now: i64,
) -> Result<(Arc<Directory>, NodeIdentity)> {
    if ks.path(ROOT_SEED).exists() {
        bail!(
            "{} holds the admin key ({ROOT_SEED}); a directory must not share a keystore with \
             the network's root. Run `wires directory serve` from the directory node's own \
             keystore (WIRES_HOME=<another dir> wires join <network>)",
            ks.path("").display()
        );
    }
    let node = keystore::node_identity_in(&ks)?;
    let root = ks.read_network()?.context(crate::help::NOT_JOINED)?.root;
    if !listed(&ks, root, node.node_id())? {
        bail!(
            "this node ({}…) is not one of the network's directories; on the admin run `wires \
             directory add <label>={}`, then `wires policy push` once this runs",
            node.node_id().short(),
            node.node_id().hex()
        );
    }
    let dir = Directory::open(node.duplicate(), root, ks, max_subscribers, now)?;
    Ok((dir, node))
}

/// `wires directory serve`: run the directory alone, on a node that hosts
/// nothing (no `host.json`), until Ctrl-C.
pub(crate) async fn serve_cmd(a: DirectoryServeArgs) -> Result<()> {
    crate::init_logging();
    let ks = Arc::new(Keystore::resolve()?);
    let (dir, node) = open_standalone(Arc::clone(&ks), a.max_subscribers, now_unix())?;
    let endpoint = transport::bind_with(
        &node,
        a.relay_url.as_deref(),
        DIRECTORY_ALPN,
        false,
        Some(&ks),
    )
    .await?;
    if let Err(e) = crate::caller::pick::write_own_hint(&ks, &endpoint) {
        tracing::warn!("could not write this directory's hint line: {e:#}");
    }
    let router = Running::mount(iroh::protocol::Router::builder(endpoint.clone()), &dir).spawn();
    let running = Running::start(Arc::clone(&dir));
    tracing::info!(
        version = dir.version().0,
        node = %node.node_id().hex(),
        "serving the directory"
    );
    if dir.snapshot().is_none() {
        tracing::info!("{}", super::node::EMPTY);
    }
    let ended = tokio::signal::ctrl_c().await.context("waiting for ctrl-c");
    running.stop().await;
    if let Err(e) = router.shutdown().await {
        tracing::warn!("a protocol handler failed while shutting down: {e}");
    }
    endpoint.close().await;
    ended
}

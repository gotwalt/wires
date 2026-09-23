//! `wires watch <topic>`: the resident node — store, backfill, mesh, control
//! socket, catch-up and the live loop (spec §7.3).
//!
//! The observer's command, and the loop `serve host.json` runs its audit
//! channel on (the host's call records enter through the same publish queue
//! as the control socket's requests). `wires advanced tail` is a hidden alias.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Args;
use library::{NodeId, TopicEnvelope, TopicId, TopicPeer};

use super::context::{TopicArgs, TopicContext};
use super::local::{STORE_LOCK_WAIT, append_local, current_fabric_key, open_topic_store};
use super::peers::PeerBook;
use super::printer::{Keyring, Printer};
use super::{admission, idp_view, ipc, rekey, replay, store, topics};
use crate::admin::keystore;
use crate::caller::jwks;
use crate::host::{audit, identity, transport};
use crate::{init_logging, now_unix};

/// `watch` arguments: the shared topic arguments plus what to print.
#[derive(Args)]
pub(crate) struct WatchArgs {
    #[command(flatten)]
    pub(crate) common: TopicArgs,
    /// How many stored messages to print before going live.
    #[arg(long, default_value_t = DEFAULT_BACKFILL)]
    pub(crate) backfill: usize,
    /// Print NDJSON objects instead of `HH:MM:SS <sender8> <text>` lines.
    #[arg(long)]
    pub(crate) json: bool,
}

/// How many stored messages `wires watch` prints before it goes live.
const DEFAULT_BACKFILL: usize = 200;

/// First redial delay after the mesh empties (spec §7).
const REDIAL_MIN: Duration = Duration::from_secs(5);

/// Longest redial delay; the backoff doubles up to this and stays there.
const REDIAL_MAX: Duration = Duration::from_secs(60);

/// How many control-socket publishes may queue for the tail loop at once.
const CONTROL_QUEUE: usize = 32;

/// How often the resident tail runs a catch-up pass even when nothing happened.
///
/// Every other trigger is edge-driven — a live `Gap`, a new neighbor, a lag, a
/// successful redial — so a hole whose only holder is asleep stays open until
/// some unrelated event fires. On a quiet, stable mesh that is never, and the
/// hole is invisible: both messages are in the publisher's log the whole time.
/// A periodic pass is what turns "eventually consistent" into a promise with a
/// period on it.
const CATCHUP_INTERVAL: Duration = Duration::from_secs(60);

/// How often the resident tail refreshes admissions that are about to lapse.
///
/// Half of [`ADMIT_REFRESH`](crate::channel::admission::ADMIT_REFRESH), so two attempts
/// fit in the window before an admission actually expires and the far side's
/// watchdog closes the connection.
const READMIT_INTERVAL: Duration = Duration::from_secs(admission::ADMIT_REFRESH.as_secs() / 2);

/// How long one round of dialing peers — a redial, or a refresh of admissions
/// about to lapse — may take before the rest is left to the next round.
///
/// Each dial is individually bounded, but a peer book with fifty stale entries
/// is fifty deadlines in a row, and the tail loop awaits these inline: signals,
/// live messages and control-socket publishes all wait behind them.
const PEER_ROUND_BUDGET: Duration = Duration::from_secs(30);

/// How many consecutive rounds in which every reachable peer refused this node
/// before the tail concludes it is off the roster and exits 77.
///
/// One round is not evidence. A peer that imported a new commit before this node
/// did answers `stale inclusion proof: proof targets version 1, head is version
/// 2` — a `Denied` — to a node that is still very much a member and only needs
/// `wires advanced import`; a peer whose own `roster-head.json` is briefly unreadable
/// answers `responder configuration error`. Exiting on the first of those turns
/// somebody else's misconfiguration into this node's death.
const DENIAL_STRIKES: usize = 3;

/// `watch`: preflight, then run the resident node.
pub(crate) async fn watch_cmd(a: WatchArgs) -> anyhow::Result<()> {
    init_logging();
    let ks = Arc::new(keystore::Keystore::resolve()?);
    let home = keystore::home()?;
    let ctx = TopicContext::resolve(ks, home, &a.common)?;
    run_tail(&ctx, a.backfill, a.json, None).await
}

/// The resident node: store, backfill, mesh, control socket, catch-up, live
/// loop (spec §7.3).
///
/// Returns `Ok(())` on `SIGINT`/`SIGTERM`, having closed the mesh and unlinked
/// the control socket. Every failure that is a *refusal* carries a
/// [`Denied`](crate::host::transport::Denied) so `main` can exit 77.
///
/// `hosted` is `serve host.json`'s addition: the session ALPN rides this
/// node's router, and call records enter the loop through the same publish
/// queue as the control socket's requests (see [`audit`]).
pub(crate) async fn run_tail(
    ctx: &TopicContext,
    backfill: usize,
    json: bool,
    hosted: Option<audit::Hosted>,
) -> anyhow::Result<()> {
    run_tail_on(ctx, backfill, json, hosted, async |cfg| {
        topics::TopicNode::spawn(&ctx.node, cfg).await
    })
    .await
}

/// [`run_tail`] over a node stood up by `bind` instead of
/// [`TopicNode::spawn`](topics::TopicNode::spawn).
///
/// The same split as [`TopicNode::spawn_on`](topics::TopicNode::spawn_on): the
/// loopback e2e tests bind a hermetic endpoint (no relay, no DNS) and drive the
/// production loop over it, which is the only way to assert what the *loop*
/// does — e.g. that call records keep flowing while a replay pass is stuck.
pub(crate) async fn run_tail_on<B>(
    ctx: &TopicContext,
    backfill: usize,
    json: bool,
    hosted: Option<audit::Hosted>,
    bind: B,
) -> anyhow::Result<()>
where
    B: AsyncFnOnce(topics::TopicNodeConfig) -> anyhow::Result<topics::TopicNode>,
{
    // Identity claims are verified by this reader itself: a responder under
    // its serve flags, a plain tail under `WIRES_OIDC_ISSUER` /
    // `WIRES_OIDC_AUDIENCE`.
    let identities = match &hosted {
        Some(h) => Arc::clone(&h.identities),
        None => Arc::new(identity::Identities::new(
            jwks::KeyFetcher::new(Some(ctx.home.join("jwks")))?,
            idp_view::IdpTrust::from_env(),
        )),
    };
    // A member's watch keeps its channel directory fresh (card 15); a host
    // needs none.
    let directory = hosted
        .is_none()
        .then(|| Arc::new(crate::caller::resolve::DirectoryHook::new(ctx)));
    let printer = Printer {
        json,
        identities: Some(Arc::clone(&identities)),
        directory: directory.clone(),
    };
    let mut keyring = Keyring::load(Arc::clone(&ctx.keystore))?;
    let store = Arc::new(open_topic_store(&ctx.home, ctx.topic, STORE_LOCK_WAIT).await?);

    // A responder prints no backfill, but its gate must know every caller that
    // logged in before it started.
    if hosted.is_some() {
        identities.prime(&store, &mut keyring, now_unix()).await;
    }
    // Announcements older than the backfill still name hosts.
    if let Some(hook) = &directory {
        hook.prime(&store, &mut keyring);
    }

    // 1. What is already known, before anything touches the network. Printed
    //    from the log, so a restart shows the same transcript the last run did.
    for envelope in store.read_backfill(backfill)? {
        printer.emit(&envelope, &mut keyring).await;
    }

    // 2. Bootstrap set: this run's tickets, unioned with what previous runs saw.
    let mut book = PeerBook::open(&ctx.home, ctx.topic);
    let mut changed = false;
    for peer in &ctx.ticket_peers {
        changed |= book.record(peer.clone());
    }
    if changed {
        book.save();
    }

    // 3. The node, then the banner (it needs the bound sockets).
    let mut cfg = ctx.node_config(Arc::clone(&store));
    let (records, session, announcer) = match hosted {
        Some(h) => (Some(h.records), Some(h.session), h.announcer),
        None => (None, None, None),
    };
    if let Some(session) = session {
        cfg.protocols.push((transport::ALPN, session.into()));
    }
    let node = bind(cfg).await?;
    let socket_path = ctx.socket_path();
    tail_banner(&node, ctx, &socket_path);

    // 4. The control socket, **before** the network join. The join dials every
    //    peer in the book, which is seconds at best; a `wires advanced publish` in that
    //    window used to find no socket, fall through to the one-shot path, and
    //    collide with this process on the topic log's exclusive redb lock —
    //    killing whichever lost. Bound first and the publish simply queues.
    let socket = ipc::ControlSocket::bind(&socket_path).await?;
    let (tx, mut requests) = tokio::sync::mpsc::channel(CONTROL_QUEUE);
    let forwarder = records.map(|rx| tokio::spawn(audit::forward(rx, tx.clone())));
    // A host announces its tools (card 15) through the same queue: this
    // loop stays the one allocator. Its dial hints are this node's own.
    let announcing = announcer.map(|a| {
        let reach = node
            .ticket(&ctx.name)
            .ok()
            .and_then(|t| t.peers.into_iter().next())
            .unwrap_or_else(|| TopicPeer::new(node.node_id()));
        tokio::spawn(a.run(tx.clone(), reach))
    });
    let server = socket.spawn(tx);

    // 5. The mesh — which is where a revoked node finds out (exit 77).
    let (mut sender, mut events) = node.join(ctx.topic, &book.list()).await?;

    // 6. Whatever the peers have that this node does not — as the first
    //    catch-up, which like every one after it runs beside the loop (see
    //    `catching_up`), never inline.

    // Live state: who the neighbors are, and when the four timers are due.
    let mut neighbors: HashSet<NodeId> = HashSet::new();
    let mut backoff = REDIAL_MIN;
    let mut rejoin_backoff = REDIAL_MIN;
    let mut strikes = Refusals::default();
    // The empty-mesh invariant below is reconciled after every select pass, so
    // it needs a starting point: a tail that came up with peers in its book and
    // no neighbor yet must already have a redial pending.
    let mut redial_at: Option<tokio::time::Instant> = book
        .list()
        .iter()
        .any(|peer| peer.node != node.node_id())
        .then(|| deadline(backoff));
    let mut catchup_at: Option<tokio::time::Instant> = Some(now_instant());
    // The catch-up in flight, if any. A task, not an inline await: a pass can
    // take up to `REPLAY_PASS_TIMEOUT` against a peer that has gone quiet, and
    // this loop is the single allocator every publish — `serve host.json`'s
    // call records included — waits on. One at a time: a deadline that comes
    // due while a pass runs waits for it (the timer arm is gated on this).
    let mut catching_up: Option<CatchUpTask> = None;
    let mut readmit_at: Option<tokio::time::Instant> = Some(deadline(READMIT_INTERVAL));
    let mut rejoin_at: Option<tokio::time::Instant> = None;
    // Both of these arms are over channels that stay *permanently ready* once
    // they close, so an arm that logs and continues is a hot loop. They are
    // disabled instead, and re-armed by the thing that can actually fix them.
    let mut live = true;
    let mut control_open = true;
    let mut sigint = signal_stream(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = signal_stream(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            _ = sigint.recv() => break,
            _ = sigterm.recv() => break,

            // A publish from `wires advanced publish`, allocated and sealed here — the
            // single allocator, on the one task that owns the store.
            request = requests.recv(), if control_open => {
                let Some(request) = request else {
                    // Every sender is gone: the socket server task died. The
                    // receiver is now ready forever, so this arm disables
                    // itself rather than spinning on a dead channel.
                    tracing::warn!("the control socket server ended; publishes will not arrive");
                    control_open = false;
                    continue;
                };
                let outcome = publish_from_tail(ctx, &store, &sender, &request.text).await;
                let answer = match outcome {
                    Ok(envelope) => {
                        printer.emit(&envelope, &mut keyring).await;
                        Ok(envelope.seq.0)
                    }
                    Err(e) => {
                        tracing::warn!("refusing a control-socket publish: {e:#}");
                        Err(format!("{e:#}"))
                    }
                };
                let _ = request.reply.send(answer);
            }

            event = events.recv(), if live => match event {
                Some(topics::TopicEvent::Message(envelope)) => {
                    let ingested = ingest_live(&node, &store, ctx.topic, &envelope);
                    // Every verdict but a duplicate: a re-key can arrive after
                    // an admission already moved this node's head, and the
                    // epoch floor then refuses to store it — its content is
                    // still the root's (card 14; see `rekey::observe`).
                    if !matches!(ingested, Ok(replay::Ingested::Duplicate)) {
                        rekey::observe(&envelope, &mut keyring, &ctx.node, node.admit(), now_unix());
                    }
                    match ingested {
                        Ok(replay::Ingested::Inserted) => printer.emit(&envelope, &mut keyring).await,
                        Ok(replay::Ingested::Duplicate) => {}
                        // The hole heals by replay and the message comes back
                        // in order; printing it now would print it twice.
                        Ok(replay::Ingested::Gap { have }) => {
                            tracing::debug!(
                                sender = %envelope.sender.hex(),
                                seq = envelope.seq.0,
                                have = ?have.map(|s| s.0),
                                "chain gap; scheduling a catch-up"
                            );
                            arm(&mut catchup_at, replay::REPLAY_DEBOUNCE);
                        }
                        Err(e) => tracing::warn!(
                            sender = %envelope.sender.hex(),
                            seq = envelope.seq.0,
                            "refusing a message: {e:#}"
                        ),
                    }
                }
                Some(topics::TopicEvent::NeighborUp(peer)) => {
                    tracing::info!(peer = %peer.hex(), "neighbor up");
                    neighbors.insert(peer);
                    backoff = REDIAL_MIN;
                    redial_at = None;
                    strikes.admitted();
                    if book.record(TopicPeer::new(peer)) {
                        book.save();
                    }
                    // A new neighbor is the likeliest source of history this
                    // node is missing.
                    arm(&mut catchup_at, replay::REPLAY_DEBOUNCE);
                }
                Some(topics::TopicEvent::NeighborDown(peer)) => {
                    neighbors.remove(&peer);
                    tracing::info!(peer = %peer.hex(), left = neighbors.len(), "neighbor down");
                }
                Some(topics::TopicEvent::Lagged) => {
                    // Terminal for the subscription: re-join and replay what
                    // was dropped. Never a quiet exit (spec §7.4).
                    tracing::warn!("subscription lagged; re-joining and catching up");
                    live = false;
                    arm(&mut rejoin_at, Duration::ZERO);
                    arm(&mut catchup_at, replay::REPLAY_DEBOUNCE);
                }
                None => {
                    // The bridge task ended (the subscription closed). Same
                    // remedy as a lag — and, like a lag, the arm goes quiet
                    // until the re-join timer has actually replaced `events`.
                    tracing::warn!("the event bridge ended; re-joining");
                    live = false;
                    arm(&mut rejoin_at, Duration::ZERO);
                }
            },

            // Re-subscribe after a lag or a dead bridge. On its own timer, with
            // its own backoff: a `join` that keeps failing must not become a
            // spin that re-dials the whole peer book as fast as the CPU allows.
            _ = tokio::time::sleep_until(rejoin_at.unwrap_or_else(now_instant)),
                if rejoin_at.is_some() && !live =>
            {
                rejoin_at = None;
                match node.join(ctx.topic, &book.list()).await {
                    Ok((s, r)) => {
                        sender = s;
                        events = r;
                        live = true;
                        rejoin_backoff = REDIAL_MIN;
                        strikes.admitted();
                        // The old subscription's membership is not this one's:
                        // a peer that vanished while the bridge was down never
                        // produces a `NeighborDown` here, and a stale entry
                        // left in the set means the mesh looks populated
                        // forever and the redial timer is never armed again.
                        neighbors.clear();
                        arm(&mut catchup_at, replay::REPLAY_DEBOUNCE);
                    }
                    Err(e) => {
                        if e.downcast_ref::<transport::Denied>().is_some() && strikes.refused() {
                            return Err(e);
                        }
                        tracing::warn!(retry_in = ?rejoin_backoff, "re-join failed: {e:#}");
                        rejoin_at = Some(deadline(rejoin_backoff));
                        rejoin_backoff = (rejoin_backoff * 2).min(REDIAL_MAX);
                    }
                }
            }

            _ = tokio::time::sleep_until(redial_at.unwrap_or_else(now_instant)),
                if redial_at.is_some() =>
            {
                redial_at = None;
                let outcome = redial(&node, &sender, &book).await;
                if outcome.admitted > 0 {
                    tracing::info!(peers = outcome.admitted, "redial re-admitted peers");
                    backoff = REDIAL_MIN;
                    strikes.admitted();
                    arm(&mut catchup_at, replay::REPLAY_DEBOUNCE);
                    // Deliberately *not* "done": `admit_peer` proves the
                    // handshake, never that the gossip mesh formed. The
                    // reconciliation below re-arms this timer for as long as
                    // the neighbor count stays zero.
                } else {
                    // Every peer this node could reach refused it — which is
                    // the roster's verdict only if it keeps saying so.
                    match outcome.denial {
                        Some(denial) if outcome.denials == outcome.tried && strikes.refused() => {
                            return Err(denial);
                        }
                        Some(denial) => tracing::warn!(
                            strikes = strikes.consecutive,
                            "a peer refused this node's admission: {denial:#}"
                        ),
                        None => {}
                    }
                    backoff = (backoff * 2).min(REDIAL_MAX);
                    if outcome.tried == 0 {
                        // A tail that is first on its topic, which is ordinary:
                        // there is nobody to dial and nothing to report.
                        tracing::debug!(retry_in = ?backoff, "no known peer to redial");
                    } else {
                        tracing::warn!(retry_in = ?backoff, "no peer answered the redial");
                    }
                }
            }

            _ = tokio::time::sleep_until(catchup_at.unwrap_or_else(now_instant)),
                if catchup_at.is_some() && catching_up.is_none() =>
            {
                catchup_at = None;
                catching_up = Some(spawn_catch_up(&node));
            }

            done = async {
                match catching_up.as_mut() {
                    Some(task) => task.await,
                    None => std::future::pending().await,
                }
            }, if catching_up.is_some() => {
                catching_up = None;
                print_caught_up(done, &printer, &mut keyring, &ctx.node, node.admit()).await;
                // Always re-armed: every other trigger is edge-driven, and a
                // gap whose only holder is asleep needs a pass that is not.
                // `arm` keeps the sooner deadline, so a gap or a new neighbor
                // that asked for a pass while this one ran still gets one.
                arm(&mut catchup_at, CATCHUP_INTERVAL);
            }

            _ = tokio::time::sleep_until(readmit_at.unwrap_or_else(now_instant)),
                if readmit_at.is_some() =>
            {
                readmit_at = None;
                refresh_admissions(&node, &book).await;
                arm(&mut readmit_at, READMIT_INTERVAL);
            }
        }

        // One invariant, reconciled every pass instead of at each of the six
        // places that can break it: **an empty mesh always has a redial
        // pending**. `NeighborDown` reaching zero is not the only way to get
        // here — a re-join clears the set, a redial can report success without
        // a neighbor ever coming up, and a peer can vanish while the bridge is
        // down — and every one of those used to leave the tail sitting on an
        // empty mesh with no timer armed, silently printing nothing.
        if live && neighbors.is_empty() && redial_at.is_none() {
            redial_at = Some(deadline(backoff));
        }
    }

    eprintln!("wires watch: shutting down");
    server.abort();
    if let Some(task) = catching_up {
        task.abort();
    }
    if let Some(forwarder) = forwarder {
        forwarder.abort();
    }
    if let Some(announcing) = announcing {
        announcing.abort();
    }
    node.shutdown().await?;
    Ok(())
}

/// Consecutive rounds in which every peer this node could reach refused it.
///
/// The counter behind [`DENIAL_STRIKES`]: a refusal is evidence, not a verdict,
/// and the verdict ("this node is off the roster, exit 77") is only reached when
/// the evidence repeats with nothing admitting this node in between.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Refusals {
    /// How many rounds in a row ended in nothing but refusals.
    pub(crate) consecutive: usize,
}

impl Refusals {
    /// Record a round that ended in refusals only; `true` once that has
    /// happened [`DENIAL_STRIKES`] times in a row.
    pub(crate) fn refused(&mut self) -> bool {
        self.consecutive += 1;
        self.consecutive >= DENIAL_STRIKES
    }

    /// Record any evidence that this node is still in the roster.
    pub(crate) fn admitted(&mut self) {
        self.consecutive = 0;
    }
}

/// Ingest a live gossip message under this node's current epoch floor.
///
/// The floor is re-read per message for the same reason the admission handler
/// re-reads the head per handshake: a `wires advanced import` of a newer head must take
/// effect on the next message, not the next restart. A head that will not load
/// refuses the message — fail closed, like every other reader of it.
fn ingest_live(
    node: &topics::TopicNode,
    store: &store::TopicStore,
    topic: TopicId,
    envelope: &TopicEnvelope,
) -> anyhow::Result<replay::Ingested> {
    let floor = node
        .admit()
        .current_version()
        .context("resolving the epoch floor for ingest")?;
    replay::ingest(store, topic, envelope, Some(floor))
}

/// Schedule `slot` for `delay` from now, keeping whichever deadline is sooner.
///
/// `Option::get_or_insert` was the bug: once a periodic pass is pending an hour
/// out, an urgent two-second debounce inserted with it never moves the deadline
/// and the urgent reason waits for the periodic one.
pub(crate) fn arm(slot: &mut Option<tokio::time::Instant>, delay: Duration) {
    let at = deadline(delay);
    *slot = Some(match *slot {
        Some(existing) if existing <= at => existing,
        _ => at,
    });
}

/// `now + delay` as a tokio deadline.
pub(crate) fn deadline(delay: Duration) -> tokio::time::Instant {
    tokio::time::Instant::now() + delay
}

/// Now, as a tokio deadline (the disabled-branch placeholder in `select!`).
fn now_instant() -> tokio::time::Instant {
    tokio::time::Instant::now()
}

/// A unix signal stream, named in any failure.
fn signal_stream(
    kind: tokio::signal::unix::SignalKind,
) -> anyhow::Result<tokio::signal::unix::Signal> {
    tokio::signal::unix::signal(kind).context("installing a signal handler")
}

/// The startup banner, on **stderr** (stdout is messages only).
///
/// The last line is the whole bootstrap story: another member runs
/// `wires watch <topic> --peer <token>` with it and the two meshes become one.
fn tail_banner(node: &topics::TopicNode, ctx: &TopicContext, socket: &Path) {
    eprintln!(
        "wires watch: topic {:?} ({}) as {}",
        ctx.name,
        ctx.topic.hex(),
        node.node_id().hex()
    );
    match ctx
        .keystore
        .read_roster_head()
        .ok()
        .flatten()
        .map(|h| h.version.0)
    {
        Some(version) => eprintln!(
            "wires watch: fabric {}, roster version {version}",
            ctx.membership.fabric.hex()
        ),
        None => eprintln!("wires watch: fabric {}", ctx.membership.fabric.hex()),
    }
    // Not enforced here — topic admission is roster inclusion, not membership
    // TTL — but an expired membership is the usual reason a peer's `serve`
    // refuses this node, so it is worth saying out loud once.
    if ctx.membership.not_after < now_unix() {
        eprintln!(
            "wires watch: warning — this node's membership expired at {}; ask the operator to \
             re-mint it (`wires advanced member --subject {} --ttl …`)",
            ctx.membership.not_after,
            ctx.node.node_id().hex()
        );
    }
    eprintln!("wires watch: control socket {}", socket.display());
    match node.ticket(&ctx.name).and_then(|t| Ok(t.encode()?)) {
        Ok(token) => eprintln!("share to bootstrap: {token}"),
        Err(e) => eprintln!("wires watch: could not build this node's ticket: {e:#}"),
    }
}

/// Seal, append, and broadcast one message from the tail loop.
///
/// The fabric key is re-read per publish, not cached, so a `wires advanced import
/// --fabric-key …` after a `roster commit` takes effect on the next message
/// with no restart. A broadcast failure is **not** an error: the message is
/// already in the log and replay will carry it, so the publisher gets its
/// sequence and a warning goes to the log.
pub(crate) async fn publish_from_tail(
    ctx: &TopicContext,
    store: &store::TopicStore,
    sender: &topics::TopicSender,
    text: &str,
) -> anyhow::Result<TopicEnvelope> {
    let (version, key) = current_fabric_key(&ctx.keystore)?;
    let envelope = append_local(store, &ctx.node, ctx.topic, version, &key, text, now_unix())?;
    if let Err(e) = sender.broadcast(&envelope).await {
        tracing::warn!(
            seq = envelope.seq.0,
            "stored but not broadcast (replay will carry it): {e:#}"
        );
    }
    Ok(envelope)
}

/// A catch-up running beside the tail loop: its counts and what it inserted.
type CatchUpTask = tokio::task::JoinHandle<anyhow::Result<replay::CaughtUp>>;

/// Start a catch-up pass as a task.
///
/// Everything it needs is shared state the node already hands out — the
/// endpoint, the admission registry, the node's own log (never a second handle:
/// redb locks the file, and the replay server reads the same one) — so the
/// pass and the loop run side by side. The store serializes their writes, and
/// every append is classified against the chain inside one write transaction,
/// so a live message and a replayed copy of it land once.
fn spawn_catch_up(node: &topics::TopicNode) -> CatchUpTask {
    let endpoint = node.endpoint().clone();
    let admit = Arc::clone(node.admit());
    let store = Arc::clone(node.store());
    let topic = node.topic();
    tokio::spawn(async move {
        replay::catch_up_collect(&endpoint, &admit, &store, topic, replay::REPLAY_LIMIT).await
    })
}

/// Log a finished catch-up and print what it inserted, in display order.
///
/// Only what *this* pass inserted: live messages and this node's own publishes
/// were printed by their own arms as they landed, and each envelope is inserted
/// exactly once, so "print on `Inserted`" stays exact with the pass running
/// concurrently.
async fn print_caught_up(
    done: Result<anyhow::Result<replay::CaughtUp>, tokio::task::JoinError>,
    printer: &Printer,
    keyring: &mut Keyring,
    me: &library::NodeIdentity,
    admit: &admission::AdmitHandler,
) {
    let mut caught = match done {
        Ok(Ok(caught)) => caught,
        Ok(Err(e)) => {
            tracing::warn!("catch-up failed: {e:#}");
            return;
        }
        Err(e) => {
            tracing::warn!("the catch-up task ended abnormally: {e}");
            return;
        }
    };
    let counts = caught.counts;
    tracing::info!(
        peers = counts.peers,
        inserted = counts.inserted,
        duplicates = counts.duplicates,
        refused = counts.refused,
        "catch-up pass"
    );
    caught
        .fresh
        .sort_by_key(|envelope| (envelope.timestamp, envelope.sender, envelope.seq));
    for envelope in &caught.fresh {
        // A re-key this node missed while it was down comes back this way.
        rekey::observe(envelope, keyring, me, admit, now_unix());
        printer.emit(envelope, keyring).await;
    }
}

/// What one [`redial`] round found.
///
/// Counts rather than a `Result`, because "every peer refused" and "nobody
/// answered" and "one peer refused while four timed out" are three different
/// situations and only the first is evidence about *this* node's standing. The
/// caller decides; the round only reports.
#[derive(Debug, Default)]
struct Redial {
    /// Peers dialed (excluding this node itself).
    pub(crate) tried: usize,
    /// Peers that completed the mutual admission handshake.
    pub(crate) admitted: usize,
    /// Peers that answered with a `Denied` frame.
    pub(crate) denials: usize,
    /// The first refusal's reason, for the exit-77 error.
    pub(crate) denial: Option<anyhow::Error>,
}

/// Re-admit every known peer and hand the survivors to gossip.
///
/// Re-admission is not a formality: the responder re-loads its head, so a peer
/// that was removed from the roster since the last dial learns about it here,
/// as a [`Denied`](crate::host::transport::Denied). But one peer refusing is that
/// peer's verdict, and a refusal is not even always about the roster — a peer
/// whose own head is briefly unreadable, or whose clock is skewed, or that
/// imported a commit this node has not yet, all answer `Denied` to a node that
/// is still a member. So this returns what happened and the caller applies
/// [`DENIAL_STRIKES`]; a failure to hand the survivors to gossip is likewise a
/// warning, not a reason to kill a resident tail.
async fn redial(node: &topics::TopicNode, sender: &topics::TopicSender, book: &PeerBook) -> Redial {
    let now = now_unix();
    let until = tokio::time::Instant::now() + PEER_ROUND_BUDGET;
    let mut admitted = Vec::new();
    let mut out = Redial::default();
    for peer in book.list() {
        if peer.node == node.node_id() {
            continue;
        }
        if tokio::time::Instant::now() >= until {
            tracing::warn!("redial budget spent; the next round takes the rest of the book");
            break;
        }
        out.tried += 1;
        match admission::admit_peer(node.endpoint(), node.admit(), &peer, now).await {
            Ok(_) => admitted.push(peer.node),
            Err(e) => {
                if e.downcast_ref::<transport::Denied>().is_some() {
                    out.denials += 1;
                    out.denial.get_or_insert(e.context(format!(
                        "peer {} refused this node's admission",
                        peer.node.hex()
                    )));
                } else {
                    tracing::debug!(peer = %peer.node.hex(), "redial failed: {e:#}");
                }
            }
        }
    }
    out.admitted = admitted.len();
    if !admitted.is_empty()
        && let Err(e) = sender.join_peers(&admitted).await
    {
        // A dead subscription (the usual cause) is the re-join timer's problem,
        // not a reason to end the process on a transient, local condition.
        tracing::warn!("handing re-admitted peers to gossip: {e:#}");
    }
    out
}

/// Re-establish admissions that are about to lapse.
///
/// An admission is a lease of [`ADMIT_TTL`](crate::channel::admission::ADMIT_TTL), and
/// before this existed nothing renewed one on a healthy mesh: `admit_peer` ran
/// at bootstrap and on a redial, and a redial only happens when the neighbor
/// count reaches zero. So a perfectly stable topic tore its own mesh down every
/// five minutes — every peer's lease lapsed within one watchdog pass of the
/// others (they were all derived from the same wall clock), every gossip
/// connection was closed, and every node redialed at once. Over a week that is
/// some two thousand synchronized outages per node, each one passing through the
/// "zero neighbors, re-admitting" state that the rest of this loop's failure
/// modes live in.
async fn refresh_admissions(node: &topics::TopicNode, book: &PeerBook) {
    let now = now_unix();
    let soon = now.saturating_add(admission::ADMIT_REFRESH.as_secs() as i64);
    let due = node.admit().admitted.expiring_before(soon);
    if due.is_empty() {
        return;
    }
    let until = tokio::time::Instant::now() + PEER_ROUND_BUDGET;
    let hints: HashMap<NodeId, TopicPeer> = book.list().into_iter().map(|p| (p.node, p)).collect();
    for peer in due {
        if tokio::time::Instant::now() >= until {
            tracing::warn!("admission-refresh budget spent; the next round takes the rest");
            break;
        }
        // The book's hint if there is one (it carries addresses), else the bare
        // id — the endpoint already has a path to an admitted peer.
        let hint = hints
            .get(&peer)
            .cloned()
            .unwrap_or_else(|| TopicPeer::new(peer));
        match admission::admit_peer(node.endpoint(), node.admit(), &hint, now).await {
            Ok(_) => tracing::debug!(peer = %peer.hex(), "refreshed an admission before it lapsed"),
            // Not fatal and not even unusual: the peer may have gone away, in
            // which case the lease lapses, the watchdog closes the connection,
            // and the redial timer takes over.
            Err(e) => tracing::warn!(peer = %peer.hex(), "could not refresh an admission: {e:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advanced::{Advanced, AdvancedArgs};
    use crate::{Cli, Command};
    use clap::Parser;

    #[test]
    fn watch_parses_the_documented_flags() {
        let cli = Cli::try_parse_from(["wires", "watch", "ops"]).unwrap();
        match cli.command {
            Command::Watch(a) => {
                assert_eq!(a.common.topic, "ops");
                assert_eq!(a.backfill, DEFAULT_BACKFILL, "the spec's default is 200");
                assert!(!a.json);
                assert!(a.common.peer.is_empty());
            }
            _ => panic!("expected watch"),
        }
        // `--peer` is repeatable; the rest mirror `call`.
        let cli = Cli::try_parse_from([
            "wires",
            "watch",
            "ops",
            "--peer",
            "t1",
            "--peer",
            "t2",
            "--backfill",
            "7",
            "--json",
            "--relay-url",
            "https://r",
            "--node-seed",
            "ab",
        ])
        .unwrap();
        match cli.command {
            Command::Watch(a) => {
                assert_eq!(a.common.peer, vec!["t1".to_string(), "t2".to_string()]);
                assert_eq!(a.backfill, 7);
                assert!(a.json);
                assert_eq!(a.common.relay_url.as_deref(), Some("https://r"));
                assert_eq!(a.common.node_seed.as_deref(), Some("ab"));
            }
            _ => panic!("expected watch"),
        }
        // No topic is the joined channel (card 14), resolved at preflight.
        match Cli::try_parse_from(["wires", "watch"]).unwrap().command {
            Command::Watch(a) => assert!(a.common.topic.is_empty()),
            _ => panic!("expected watch"),
        }
        // The old name survives, hidden, under `advanced`.
        match Cli::try_parse_from(["wires", "advanced", "tail", "ops", "--json"])
            .unwrap()
            .command
        {
            Command::Advanced(AdvancedArgs {
                cmd: Advanced::Tail(a),
            }) => {
                assert_eq!(a.common.topic, "ops");
                assert!(a.json);
            }
            _ => panic!("expected advanced tail"),
        }
    }

    /// The two scheduling primitives the tail loop's liveness rests on.
    #[test]
    fn a_pending_deadline_keeps_the_sooner_of_the_two() {
        let mut slot: Option<tokio::time::Instant> = None;
        arm(&mut slot, Duration::from_secs(60));
        let far = slot.unwrap();
        arm(&mut slot, Duration::from_secs(2));
        let near = slot.unwrap();
        assert!(
            near < far,
            "an urgent reason must move a pending periodic deadline in"
        );
        arm(&mut slot, Duration::from_secs(60));
        assert_eq!(slot.unwrap(), near, "and a lazy one must not push it out");
    }

    /// Exit 77 is a verdict, and one refusal is not evidence enough for it.
    ///
    /// A peer that imported a commit before this node did answers `stale
    /// inclusion proof` — a `Denied` — to a node that is still a member and only
    /// needs `wires advanced import`; a peer whose own head is briefly unreadable answers
    /// `responder configuration error`. Exiting on the first of those turned
    /// somebody else's misconfiguration into this node's death.
    #[test]
    fn a_refusal_becomes_a_verdict_only_when_it_repeats() {
        let mut strikes = Refusals::default();
        for _ in 1..DENIAL_STRIKES {
            assert!(!strikes.refused(), "one round is not a verdict");
        }
        assert!(strikes.refused(), "{DENIAL_STRIKES} in a row is");

        // Any evidence that this node is still in the roster resets the count.
        let mut strikes = Refusals::default();
        assert!(!strikes.refused());
        strikes.admitted();
        for _ in 1..DENIAL_STRIKES {
            assert!(!strikes.refused());
        }
    }
}

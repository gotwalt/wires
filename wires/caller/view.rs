//! The caller's **view** (card 37): the services this node's verified person
//! may call, each a root-signed entry, and nothing else.
//!
//! A caller never holds the policy. It holds `$WIRES_HOME/view.json`
//! ([`HeldView`]): the root-signed head, the directory's newest [`Fresh`]
//! for it, and the signed entries a directory cut for its ID token. No
//! role, no ban, no other service, and no node id but its services' hosts
//! and the directories. Every entry verifies on its own under the root
//! ([`View::verify`]), so a directory can't forge one; what it could do is
//! withhold one, or serve a stale view, and neither lets anyone call
//! anything: the host decides every call from its whole, current policy.
//!
//! How a view stays current, without background traffic for one-shot
//! commands:
//!
//! - `wires login` asks for the view under the new identity, from the
//!   directories its network string names until a head names them all.
//! - `wires services`, `wires call` and `wires inbox` refresh first when
//!   the view is older than a day ([`VIEW_MAX_AGE_SECS`]), its head has
//!   expired, or a host reported a newer head ([`HeldView::is_stale`]);
//!   otherwise they dial from the view as it is ([`usable`]). A refresh no
//!   directory answers leaves the view as it is: calls keep working with
//!   every directory down, so the hard bound on dialing from an old view is
//!   its head's `not_after`, not a day. When the host's `HelloAck` reports a newer
//!   head, the caller records it ([`note_seen`]) and refreshes after the
//!   call; a name not in the view is asked of a directory with `resolve`
//!   before the call fails.
//! - `wires mcp`, the gateway and `inbox --wait` hold a subscription
//!   ([`follow`]): the whole view, then an update per new head.
//!
//! A node that holds the whole policy (the admin's, a host's, a
//! directory's) cuts its view from its own copy instead of asking
//! ([`refresh`]).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use iroh::Endpoint;
use library::{
    DIRECTORY_SUB_ALPN, DirectoryAnswer, DirectoryRequest, Fresh, IdToken, NodeId, ServiceName,
    SignedEntry, StateVersion, SubFrame, SubRequest, SubscriptionKind, View, ViewDigest,
};
use serde::{Deserialize, Serialize};

use crate::admin::keystore::{Keystore, write_private};
use crate::clock::now_unix;
use crate::directory::wire::{self, ask};
use crate::host::transport;
use crate::policy::store;

/// The caller's view, under `$WIRES_HOME`.
pub(crate) const VIEW_FILE: &str = "view.json";

/// How old a view may be before `wires services`, `wires call` or `wires
/// inbox` refreshes it: a day.
///
/// This is **not** a bound on how long a caller holding a view from before a
/// host's removal may still dial that host (protocol §5): when no directory
/// answers the refresh, the caller keeps its view; and a removed machine
/// that was also a directory the old head lists can answer `current` with
/// a `Fresh` it signs for that head, resetting the day. The hard bound is
/// the view's head's `not_after` (90 days by default): an expired view is
/// never dialed from.
pub(crate) const VIEW_MAX_AGE_SECS: i64 = 24 * 60 * 60;

/// How long a refresh spends asking, all directories together.
pub(crate) const REFRESH_BUDGET: Duration = Duration::from_secs(8);

/// The longest a subscriber waits between two attempts to follow.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// `view.json`: the view, the newest `Fresh` for its head, when a directory
/// last vouched for it, and the newest head version a host reported.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeldView {
    /// The view: the root-signed head and this caller's entries.
    pub(crate) view: View,
    /// The newest `Fresh` a directory signed for its head (none when the
    /// view was cut locally from a whole policy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) fresh: Option<Fresh>,
    /// When a directory last vouched for the view (unix seconds; 0: never).
    pub(crate) checked: i64,
    /// The newest head version a host reported in a `HelloAck` (0: none
    /// newer than the view's).
    pub(crate) seen: StateVersion,
}

impl HeldView {
    /// A view just fetched (or cut) at `now`.
    pub(crate) fn fetched(view: View, fresh: Option<Fresh>, now: i64) -> HeldView {
        HeldView {
            view,
            fresh,
            checked: now,
            seen: StateVersion(0),
        }
    }

    /// The view's head version.
    pub(crate) fn version(&self) -> StateVersion {
        self.view.head.head.version
    }

    /// The directories its head lists, in the admin's order.
    pub(crate) fn directories(&self) -> &[NodeId] {
        &self.view.head.head.directories
    }

    /// Whether `wires services`, `wires call` and `wires inbox` should refresh it first:
    /// last vouched for
    /// more than [`VIEW_MAX_AGE_SECS`] before `now`, its head expired, or a
    /// host reported a newer head.
    pub(crate) fn is_stale(&self, now: i64) -> bool {
        now.saturating_sub(self.checked) > VIEW_MAX_AGE_SECS
            || self.view.head.check_fresh(now).is_err()
            || self.seen > self.version()
    }

    /// The entry for `service`, if the view holds it.
    pub(crate) fn entry(&self, service: &ServiceName) -> Option<&SignedEntry> {
        self.view.entry(service)
    }
}

/// The stored view, verified under `root`; `None` before one is stored. A
/// present but invalid file is an error (fail closed).
pub(crate) fn read(ks: &Keystore, root: NodeId) -> Result<Option<HeldView>> {
    let path = ks.path(VIEW_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let held: HeldView =
        serde_json::from_str(text.trim()).with_context(|| format!("parsing {}", path.display()))?;
    held.view
        .verify(root)
        .with_context(|| format!("{} does not verify under the network root", path.display()))?;
    Ok(Some(held))
}

/// Store `held` (atomically, `0600`), after verifying it under `root`.
pub(crate) fn write(ks: &Keystore, root: NodeId, held: &HeldView) -> Result<()> {
    held.view
        .verify(root)
        .context("refusing to store a view that does not verify")?;
    let text = serde_json::to_string(held).context("encoding the view")?;
    write_private(&ks.path(VIEW_FILE), &format!("{text}\n"))
}

/// Record that a host reported head `version` (from a `HelloAck`): the
/// next `wires services`, `wires call` or `wires inbox` refreshes first.
/// Best effort; no view, no note.
pub(crate) fn note_seen(ks: &Keystore, root: NodeId, version: StateVersion) {
    let noted = (|| -> Result<()> {
        let Some(mut held) = read(ks, root)? else {
            return Ok(());
        };
        if version > held.seen && version > held.version() {
            held.seen = version;
            write(ks, root, &held)?;
        }
        Ok(())
    })();
    if let Err(e) = noted {
        tracing::debug!("noting a newer head: {e:#}");
    }
}

/// The directories the network string names (empty when none is stored).
pub(crate) fn joined_directories(ks: &Keystore) -> Vec<NodeId> {
    ks.read_network()
        .ok()
        .flatten()
        .map_or_else(Vec::new, |n| n.directories)
}

/// The directories this node asks, never itself: its view's head's (or,
/// holding none, the network string's).
pub(crate) fn directories(ks: &Keystore, root: NodeId, me: NodeId) -> Vec<NodeId> {
    let dirs = match read(ks, root) {
        Ok(Some(held)) if !held.directories().is_empty() => held.directories().to_vec(),
        _ => joined_directories(ks),
    };
    dirs.into_iter().filter(|d| *d != me).collect()
}

/// Every directory that answered a refresh refused this node with
/// [`NOT_ADMITTED`](crate::host::gate::NOT_ADMITTED), and none gave it a
/// view: the context of [`refresh`]'s error then, so a command can say
/// what the person can act on
/// ([`explain_not_admitted`](crate::caller::hello::explain_not_admitted)).
#[derive(Debug, thiserror::Error)]
#[error("a directory said this node is not admitted to the network")]
pub(crate) struct NotAdmitted;

/// A directory's `denied {reason}`, as an error (so [`refresh`] can tell a
/// refusal of admission from a directory that couldn't be reached).
#[derive(Debug, thiserror::Error)]
#[error("refused: {0}")]
pub(crate) struct Refused(pub(crate) String);

impl Refused {
    /// Whether the directory refused admission.
    fn is_not_admitted(e: &anyhow::Error) -> bool {
        e.downcast_ref::<Refused>()
            .is_some_and(|r| r.0 == crate::host::gate::NOT_ADMITTED)
    }
}

/// What a directory answered a `view` request with, verified.
#[allow(clippy::large_enum_variant)] // one per request, moved once
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Fetched {
    /// A whole view, verified under the root, with a `Fresh` that vouches
    /// for its head.
    View(View, Fresh),
    /// The view held is current: a `Fresh` for its head.
    Current(Fresh),
}

/// Ask directory `dir` for this node's view (presenting `id_token`, which
/// is what admits it), holding `held` (whose version it names as `have`), or the
/// entries matching `query`. A `view_update` is applied to `held`
/// ([`View::apply`]: each entry verified, none older than held) and comes
/// back as the whole new view. A `current` answer is only taken for a
/// `held` head its `Fresh` vouches for, current at `now`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn ask_view(
    endpoint: &Endpoint,
    dir: NodeId,
    id_token: Option<IdToken>,
    root: NodeId,
    held: Option<&View>,
    query: Option<String>,
    now: i64,
) -> Result<Fetched> {
    // What is held, named exactly: the directory answers `current` or an
    // update only for this view (one cut for another identity, or for none,
    // gets the whole view).
    let (have, held_digest) = match (&query, held) {
        (None, Some(view)) => (view.head.head.version, Some(ViewDigest::of(view)?)),
        _ => (StateVersion(0), None),
    };
    let request = DirectoryRequest::View {
        have,
        query,
        held: held_digest,
    };
    match ask(endpoint, dir, id_token, &request).await? {
        DirectoryAnswer::View { view, fresh } => {
            view.verify(root)
                .context("the directory's view does not verify")?;
            fresh
                .verify(&view.head)
                .context("the directory's freshness doesn't vouch for its view")?;
            Ok(Fetched::View(view, fresh))
        }
        DirectoryAnswer::ViewUpdate { update, fresh } => {
            let base =
                held.ok_or_else(|| anyhow!("an update for a view this node doesn't hold"))?;
            let view = base
                .apply(&update, root)
                .context("the directory's view update doesn't apply")?;
            fresh
                .verify(&view.head)
                .context("the directory's freshness doesn't vouch for its view")?;
            Ok(Fetched::View(view, fresh))
        }
        DirectoryAnswer::Current { fresh } => {
            let head = &held
                .ok_or_else(|| anyhow!("`current` for a view this node doesn't hold"))?
                .head;
            fresh
                .verify(head)
                .context("the directory's freshness doesn't vouch for the held view")?;
            if !fresh.is_current(now) {
                bail!("the directory's freshness has lapsed");
            }
            Ok(Fetched::Current(fresh))
        }
        DirectoryAnswer::Denied { reason } => Err(Refused(reason).into()),
        other => bail!("an unexpected answer to `view`: {other:?}"),
    }
}

/// Ask directory `dir` for `service` alone (`resolve`): the one-entry view,
/// or an empty one when this node may not use it (or it doesn't exist).
pub(crate) async fn ask_resolve(
    endpoint: &Endpoint,
    dir: NodeId,
    id_token: Option<IdToken>,
    root: NodeId,
    service: &ServiceName,
) -> Result<View> {
    let request = DirectoryRequest::Resolve {
        service: service.clone(),
    };
    match ask(endpoint, dir, id_token, &request).await? {
        DirectoryAnswer::View { view, fresh } => {
            view.verify(root)
                .context("the directory's view does not verify")?;
            fresh
                .verify(&view.head)
                .context("the directory's freshness doesn't vouch for its view")?;
            if view.entries.iter().any(|e| e.name != *service) {
                bail!("the directory resolved {service} to another service");
            }
            Ok(view)
        }
        DirectoryAnswer::Denied { reason } => Err(Refused(reason).into()),
        other => bail!("an unexpected answer to `resolve`: {other:?}"),
    }
}

/// Who this node is, for a refresh: its endpoint, the network's root, and
/// its stored ID token.
pub(crate) struct Asker<'a> {
    /// A bound endpoint for this node (not closed here).
    pub(crate) endpoint: &'a Endpoint,
    /// The network's root key.
    pub(crate) root: NodeId,
    /// The ID token to present (the one `wires login` stored).
    pub(crate) id_token: Option<IdToken>,
}

/// Bring the view in `ks` up to date, and return it:
///
/// - a node holding the whole policy (`policy.json`: the admin, a host, a
///   directory) cuts its view from that, for its own verified identity;
/// - any other asks the directories in turn ([`directories`]): the first
///   whole view, or `current` for the one held, settles it. `forget`
///   drops the held view first (a new sign-in: the old entries were for
///   someone else).
///
/// Errors when there is no view to be had (no directory answered, none
/// held), with [`NotAdmitted`] as its context when a directory refused this
/// node's admission and none gave it a view.
pub(crate) async fn refresh(ks: &Keystore, asker: &Asker<'_>, forget: bool) -> Result<HeldView> {
    let root = asker.root;
    let me = transport::to_node_id(&asker.endpoint.id());
    let now = now_unix();
    if let Some(whole) = store::read(ks, root)? {
        let principal = match crate::caller::services::my_principal(ks, me).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("your stored identity is not usable ({e:#}); run `wires login`");
                None
            }
        };
        let held = HeldView::fetched(
            whole.signed.view_for(me, principal.as_ref(), None),
            None,
            now,
        );
        write(ks, root, &held)?;
        return Ok(held);
    }
    let held = if forget { None } else { read(ks, root)? };
    let dirs = directories(ks, root, me);
    if dirs.is_empty() {
        return held.ok_or_else(|| {
            anyhow!(
                "this node knows no directory to ask for its view: ask your admin for the \
                 network string (`wires network`) and `wires login <network>` with it"
            )
        });
    }
    let mut failures = Vec::new();
    let mut not_admitted = false;
    for dir in dirs {
        let base = held.as_ref().map(|h| &h.view);
        let mut asked = ask_view(
            asker.endpoint,
            dir,
            asker.id_token.clone(),
            root,
            base,
            None,
            now,
        )
        .await;
        // An update that doesn't apply to what is held: the whole view.
        if asked.is_err() && base.is_some() {
            asked = ask_view(
                asker.endpoint,
                dir,
                asker.id_token.clone(),
                root,
                None,
                None,
                now,
            )
            .await;
        }
        match asked {
            Ok(Fetched::View(view, fresh)) => {
                let fetched = HeldView::fetched(view, Some(fresh), now);
                if let Some(old) = &held
                    && fetched.version() < old.version()
                {
                    failures.push(format!(
                        "{}: an older view (version {})",
                        dir.short(),
                        fetched.version().0
                    ));
                    continue;
                }
                write(ks, root, &fetched)?;
                return Ok(fetched);
            }
            Ok(Fetched::Current(fresh)) => {
                let mut current = held.clone().expect("current is only taken for a held view");
                current.fresh = Some(fresh);
                current.checked = now;
                write(ks, root, &current)?;
                return Ok(current);
            }
            Err(e) => {
                not_admitted |= Refused::is_not_admitted(&e);
                failures.push(format!("{}: {e:#}", dir.short()));
            }
        }
    }
    let failed = anyhow!(
        "no directory gave this node its view ({})",
        failures.join("; ")
    );
    Err(if not_admitted {
        failed.context(NotAdmitted)
    } else {
        failed
    })
}

/// Refuse an expired view, saying what to do about it.
pub(crate) fn check_fresh(held: &HeldView, now: i64) -> Result<()> {
    if held.view.head.check_fresh(now).is_err() {
        bail!(
            "this node's view (policy version {}) has expired and no newer one could be \
             fetched, so nothing was dialed; ask the admin to run `wires policy push`",
            held.version().0
        );
    }
    Ok(())
}

/// The view to dial from, as `wires call` and `wires inbox` take it: the
/// held view as it is, unless it is missing or stale
/// ([`HeldView::is_stale`]: older than a day, its head expired, or a host
/// reported a newer head); then a refresh ([`refresh_now`]). A refresh that
/// fails leaves a held view whose head hasn't expired, which is dialed from
/// as it is (so calls keep working with every directory down); with none, it
/// is an error, saying what the person can act on when a directory refused
/// this node ([`NotAdmitted`]). An expired view is never returned.
pub(crate) async fn usable(
    ks: &Keystore,
    node: &library::NodeIdentity,
    root: NodeId,
    relay: Option<&str>,
) -> Result<HeldView> {
    usable_with(ks, root, now_unix(), || {
        refresh_now(ks, node, root, relay, false)
    })
    .await
}

/// [`usable`] at `now`, refreshing with `refresh` (tests hand it one over
/// their own endpoint).
pub(crate) async fn usable_with<F>(
    ks: &Keystore,
    root: NodeId,
    now: i64,
    refresh: impl FnOnce() -> F,
) -> Result<HeldView>
where
    F: std::future::Future<Output = Result<HeldView>>,
{
    let held = read(ks, root)?.filter(|held| held.view.head.check_fresh(now).is_ok());
    if let Some(held) = &held
        && !held.is_stale(now)
    {
        return Ok(held.clone());
    }
    match (refresh().await, held) {
        (Ok(refreshed), _) => {
            check_fresh(&refreshed, now)?;
            Ok(refreshed)
        }
        (Err(e), Some(held)) => {
            tracing::debug!("refreshing a stale view: {e:#}; dialing from it as it is");
            Ok(held)
        }
        (Err(e), None) if e.downcast_ref::<NotAdmitted>().is_some() => {
            Err(e.context(crate::caller::hello::explain_not_admitted_in(ks)))
        }
        (Err(e), None) => Err(e.context(
            "this node holds no current view of its services, and no directory gave it one: \
             run `wires login` (or ask the admin to run `wires policy push`)",
        )),
    }
}

/// [`refresh`] as a one-shot command does it: bind an endpoint for `node`
/// (through `relay`), ask within [`REFRESH_BUDGET`], close.
pub(crate) async fn refresh_now(
    ks: &Keystore,
    node: &library::NodeIdentity,
    root: NodeId,
    relay: Option<&str>,
    forget: bool,
) -> Result<HeldView> {
    let endpoint =
        transport::bind_with(node, relay, library::DIRECTORY_ALPN, false, Some(ks)).await?;
    let asker = Asker {
        endpoint: &endpoint,
        root,
        id_token: crate::caller::hello::stored_token(ks),
    };
    let refreshed = tokio::time::timeout(REFRESH_BUDGET, refresh(ks, &asker, forget))
        .await
        .unwrap_or_else(|_| Err(anyhow!("no directory answered within {REFRESH_BUDGET:?}")));
    endpoint.close().await;
    refreshed
}

/// Ask the directories for `service` alone (`resolve`), for a name the
/// held view doesn't have: its entry, if this node may use it.
pub(crate) async fn resolve(
    ks: &Keystore,
    asker: &Asker<'_>,
    service: &ServiceName,
) -> Result<Option<SignedEntry>> {
    let root = asker.root;
    let me = transport::to_node_id(&asker.endpoint.id());
    let mut failures = Vec::new();
    for dir in directories(ks, root, me) {
        match ask_resolve(asker.endpoint, dir, asker.id_token.clone(), root, service).await {
            Ok(view) => {
                note_seen(ks, root, view.head.head.version);
                return Ok(view.entries.into_iter().next());
            }
            Err(e) => failures.push(format!("{}: {e:#}", dir.short())),
        }
    }
    if failures.is_empty() {
        return Ok(None);
    }
    bail!("no directory resolved {service} ({})", failures.join("; "))
}

/// Where a subscriber's view goes as it changes.
pub(crate) type ViewWatch = tokio::sync::watch::Receiver<Option<Arc<HeldView>>>;

/// What a [`follow`] subscription needs.
pub(crate) struct Follow {
    /// A bound endpoint for this node (kept open by the caller).
    pub(crate) endpoint: Endpoint,
    /// The network's root key.
    pub(crate) root: NodeId,
    /// The ID token to present at each (re)subscription: read afresh, so a
    /// new `wires login` takes effect at the next one.
    pub(crate) id_token: Arc<dyn Fn() -> Option<IdToken> + Send + Sync>,
    /// The view to start from (and to fall back on while no directory
    /// answers).
    pub(crate) initial: Option<HeldView>,
    /// Directories to ask while the view names none.
    pub(crate) fallback: Vec<NodeId>,
    /// Where to keep the view as it changes (`view.json`), if anywhere: a
    /// gateway's per-user views stay in memory.
    pub(crate) persist: Option<Arc<Keystore>>,
}

/// Follow this node's view on `wires/directory-sub/2` until the returned
/// task is aborted: the first directory that answers, then the next when it
/// goes (with a growing pause, at most [`MAX_BACKOFF`]). Every change (a new
/// view, an update applied with [`View::apply`], a new `Fresh`) is sent on
/// the returned channel; an update that doesn't apply ends that
/// subscription, and the next asks for the whole view again. A stream
/// silent past [`silence`] is taken for dead. A directory that answers
/// `denied` (this node is not admitted, or the directory is no longer one,
/// or busy), at once or ending the stream, is passed over for the next one
/// at once; a round that no directory served waits the growing pause, so
/// no directory is asked again in a tight loop.
pub(crate) fn follow(f: Follow) -> (ViewWatch, tokio::task::JoinHandle<()>) {
    let (tx, rx) = tokio::sync::watch::channel(f.initial.clone().map(Arc::new));
    let task = tokio::spawn(async move {
        let root = f.root;
        let me = transport::to_node_id(&f.endpoint.id());
        let mut held = f.initial.clone();
        let mut backoff = Duration::from_secs(1);
        loop {
            let dirs: Vec<NodeId> = held
                .as_ref()
                .map(|h| h.directories().to_vec())
                .filter(|d| !d.is_empty())
                .unwrap_or_else(|| f.fallback.clone())
                .into_iter()
                .filter(|d| *d != me)
                .collect();
            for dir in dirs {
                match follow_once(&f, dir, root, &mut held, &tx).await {
                    Ok(Ended::Closed) => backoff = Duration::from_secs(1),
                    Ok(Ended::Denied(reason)) => tracing::info!(
                        directory = %dir.hex(),
                        "view subscription refused: {reason}; trying the next directory"
                    ),
                    Err(e) => tracing::debug!(directory = %dir.hex(), "view subscription: {e:#}"),
                }
                if tx.is_closed() {
                    return;
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    });
    (rx, task)
}

/// How one view subscription ended.
#[derive(Debug, PartialEq, Eq)]
enum Ended {
    /// After at least one frame, the stream closed, broke, or went silent
    /// past [`silence`] (or nobody listens to the view any more).
    Closed,
    /// The directory answered `denied`, at once or ending the stream.
    Denied(String),
}

/// How long a view subscription may stay silent once it has answered: the
/// held `Fresh`'s lifetime (a live directory beats well within it, since
/// `fresh_secs >= beat_secs`) plus that again, at most 10 s, of slack; with
/// none held, two default beats and 10 s. (A caller's view carries no
/// settings, so the `Fresh` is what says how often to expect one.)
fn silence(held: Option<&HeldView>) -> Duration {
    match held.and_then(|h| h.fresh.as_ref()) {
        Some(f) => {
            let span = u64::try_from(f.until.saturating_sub(f.at))
                .unwrap_or(0)
                .max(1);
            Duration::from_secs(span + span.min(10))
        }
        None => Duration::from_secs(2 * u64::from(library::DEFAULT_BEAT_SECS) + 10),
    }
}

/// One subscription to `dir`, until it ends: apply every frame to `held`
/// and announce the result. The first frame must come within
/// [`wire::FRAME_TIMEOUT`], each later one within [`silence`]. `Err`: it
/// never answered, or sent a frame that can't be taken.
async fn follow_once(
    f: &Follow,
    dir: NodeId,
    root: NodeId,
    held: &mut Option<HeldView>,
    tx: &tokio::sync::watch::Sender<Option<Arc<HeldView>>>,
) -> Result<Ended> {
    let addr = transport::endpoint_addr(&dir, &[], None)?;
    let conn = tokio::time::timeout(
        wire::DIAL_TIMEOUT,
        f.endpoint.connect(addr, DIRECTORY_SUB_ALPN),
    )
    .await
    .map_err(|_| anyhow!("no answer within {:?}", wire::DIAL_TIMEOUT))?
    .map_err(|e| anyhow!("dialing {}…: {e}", dir.short()))?;
    let (mut send, mut recv) = conn.open_bi().await.context("opening a stream")?;
    let hello = SubRequest::Hello {
        id_token: (f.id_token)(),
    };
    let subscribe = SubRequest::Subscribe {
        kind: SubscriptionKind::View,
        have: held.as_ref().map_or(StateVersion(0), HeldView::version),
    };
    wire::write(&mut send, &hello.encode()?).await?;
    wire::write(&mut send, &subscribe.encode()?).await?;
    let result = async {
        let mut answered = false;
        loop {
            let wait = if answered {
                silence(held.as_ref())
            } else {
                wire::FRAME_TIMEOUT
            };
            let frame = match tokio::time::timeout(wait, wire::read_sub_frame(&mut recv)).await {
                Ok(Ok(Some(frame))) => frame,
                Ok(Ok(None)) if !answered => bail!("the directory closed without answering"),
                Ok(Err(e)) if !answered => return Err(e),
                Err(_) if !answered => bail!("no answer within {wait:?}"),
                Ok(Ok(None)) => return Ok(Ended::Closed),
                Ok(Err(e)) => {
                    tracing::debug!(directory = %dir.hex(), "view subscription broke: {e:#}");
                    return Ok(Ended::Closed);
                }
                Err(_) => {
                    tracing::info!(
                        directory = %dir.hex(),
                        "view subscription silent for {wait:?}; following again"
                    );
                    return Ok(Ended::Closed);
                }
            };
            let now = now_unix();
            let next = match frame {
                SubFrame::View { view, fresh } => {
                    view.verify(root)?;
                    fresh.verify(&view.head)?;
                    let mut next = HeldView::fetched(view, Some(fresh), now);
                    next.seen = held.as_ref().map_or(StateVersion(0), |h| h.seen);
                    next
                }
                SubFrame::ViewUpdate { update, fresh } => {
                    let Some(base) = held.as_ref() else {
                        bail!("an update before any view");
                    };
                    let view = base
                        .view
                        .apply(&update, root)
                        .context("an update that doesn't apply; subscribing again")?;
                    fresh.verify(&view.head)?;
                    HeldView {
                        view,
                        fresh: Some(fresh),
                        checked: now,
                        seen: base.seen,
                    }
                }
                SubFrame::Fresh { fresh } => {
                    let Some(base) = held.as_ref() else {
                        bail!("a beat before any view");
                    };
                    fresh.verify(&base.view.head)?;
                    HeldView {
                        fresh: Some(fresh),
                        checked: now,
                        ..base.clone()
                    }
                }
                SubFrame::Denied { reason } => return Ok(Ended::Denied(reason)),
                other => bail!("an unexpected frame for a view: {other:?}"),
            };
            answered = true;
            if let Some(ks) = &f.persist
                && let Err(e) = write(ks, root, &next)
            {
                tracing::warn!("could not keep view.json in step: {e:#}");
            }
            *held = Some(next.clone());
            if tx.send(Some(Arc::new(next))).is_err() {
                return Ok(Ended::Closed);
            }
        }
    }
    .await;
    conn.close(0u32.into(), b"done");
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{NodeIdentity, Policy, Service, SignedPolicy};

    fn root() -> NodeIdentity {
        NodeIdentity::from_seed([51; 32])
    }

    /// A policy at `version` with `orders-db` for anyone the mock IdP
    /// verified, hosted by node 52.
    fn signed(version: u64) -> SignedPolicy {
        let mut p = Policy::new(root().node_id());
        p.version = StateVersion(version);
        p.not_after = i64::MAX;
        let (staff, matchers) = crate::testutil::staff_role();
        p.roles.insert(staff.clone(), matchers);
        p.services.insert(
            ServiceName::new("orders-db").unwrap(),
            Service {
                description: "orders".into(),
                allow: vec![staff],
                hosts: vec![NodeIdentity::from_seed([52; 32]).node_id()],
            },
        );
        crate::testutil::signed_policy(&root(), p)
    }

    fn anyone() -> library::Principal {
        library::Principal {
            issuer: crate::testutil::test_idp().issuer.as_str().into(),
            subject: "1".into(),
            email: Some("me@example.com".into()),
            org: None,
            groups: vec![],
            not_after: i64::MAX,
        }
    }

    #[test]
    fn a_stored_view_round_trips_and_a_tampered_one_fails_closed() {
        let ks = Keystore::at(crate::testutil::temp_dir());
        let r = root().node_id();
        assert!(read(&ks, r).unwrap().is_none());
        let held = HeldView::fetched(
            signed(3).view_for(crate::testutil::any_node(), Some(&anyone()), None),
            None,
            10,
        );
        write(&ks, r, &held).unwrap();
        assert_eq!(read(&ks, r).unwrap(), Some(held.clone()));
        // Another root's view is refused on the way in and on the way out.
        let other = NodeIdentity::from_seed([9; 32]).node_id();
        assert!(write(&ks, other, &held).is_err());
        assert!(read(&ks, other).is_err());
        // A forged entry fails closed.
        let mut forged = held;
        forged.view.entries[0]
            .service
            .hosts
            .push(NodeIdentity::from_seed([66; 32]).node_id());
        std::fs::write(ks.path(VIEW_FILE), serde_json::to_string(&forged).unwrap()).unwrap();
        assert!(read(&ks, r).is_err());
    }

    #[test]
    fn a_view_goes_stale_after_a_day_or_when_a_host_saw_a_newer_head() {
        let held = HeldView::fetched(
            signed(3).view_for(crate::testutil::any_node(), Some(&anyone()), None),
            None,
            1_000,
        );
        assert!(!held.is_stale(1_000 + VIEW_MAX_AGE_SECS));
        assert!(held.is_stale(1_001 + VIEW_MAX_AGE_SECS));
        let ks = Keystore::at(crate::testutil::temp_dir());
        let r = root().node_id();
        write(&ks, r, &held).unwrap();
        note_seen(&ks, r, StateVersion(3));
        assert!(!read(&ks, r).unwrap().unwrap().is_stale(1_000));
        note_seen(&ks, r, StateVersion(4));
        assert!(read(&ks, r).unwrap().unwrap().is_stale(1_000));
    }

    #[test]
    fn directories_come_from_the_head_else_from_the_network_string() {
        let ks = Keystore::at(crate::testutil::temp_dir());
        let r = root().node_id();
        let me = NodeIdentity::from_seed([53; 32]).node_id();
        let d = NodeIdentity::from_seed([54; 32]).node_id();
        assert!(directories(&ks, r, me).is_empty());
        crate::testutil::join(&ks, &root(), &[d, me]);
        assert_eq!(directories(&ks, r, me), vec![d], "never itself");
        let mut p = signed(3).to_policy().unwrap();
        let listed = NodeIdentity::from_seed([55; 32]).node_id();
        p.directories = vec![listed];
        let view = crate::testutil::signed_policy(&root(), p).view_for(
            crate::testutil::any_node(),
            None,
            None,
        );
        write(&ks, r, &HeldView::fetched(view, None, 0)).unwrap();
        assert_eq!(directories(&ks, r, me), vec![listed]);
    }

    // -----------------------------------------------------------------------
    // Following: a silent or refusing directory (a fake one, on loopback)
    // -----------------------------------------------------------------------

    use std::sync::atomic::{AtomicUsize, Ordering};

    use iroh::address_lookup::memory::MemoryLookup;

    /// What a fake directory does on each view subscription.
    #[derive(Clone, Copy)]
    enum Script {
        /// The view once, then nothing, the stream held open.
        ViewThenSilence,
        /// The view, then `denied`.
        ViewThenDenied,
        /// `denied` at once.
        Denied,
    }

    /// Nodes 53 and 54: the fake directories.
    fn dir(i: u8) -> NodeIdentity {
        NodeIdentity::from_seed([53 + i; 32])
    }

    /// [`signed`] at version 1, listing both fake directories.
    fn listing() -> SignedPolicy {
        let mut p = signed(1).to_policy().unwrap();
        p.directories = vec![dir(0).node_id(), dir(1).node_id()];
        crate::testutil::signed_policy(&root(), p)
    }

    /// A loopback endpoint for `who`, found through `book`, speaking `alpns`.
    async fn endpoint(who: &NodeIdentity, book: &MemoryLookup, alpns: Vec<Vec<u8>>) -> Endpoint {
        let ep = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(transport::secret_key(who))
            .address_lookup(book.clone())
            .alpns(alpns)
            .bind()
            .await
            .unwrap();
        let socks: Vec<_> = ep
            .bound_sockets()
            .into_iter()
            .map(crate::net::dialable)
            .collect();
        book.add_endpoint_info(transport::endpoint_addr(&who.node_id(), &socks, None).unwrap());
        ep
    }

    /// Fake directory `i` playing `script` to every subscriber, its `Fresh`
    /// good for `span` seconds; the count of subscriptions it took.
    async fn fake_directory(
        i: u8,
        book: &MemoryLookup,
        script: Script,
        span: i64,
    ) -> Arc<AtomicUsize> {
        let ep = endpoint(&dir(i), book, vec![DIRECTORY_SUB_ALPN.to_vec()]).await;
        let policy = listing();
        let now = now_unix();
        let fresh = Fresh::sign(&dir(i), &policy.head, now, now + span).unwrap();
        let view = SubFrame::View {
            view: policy.view_for(crate::testutil::any_node(), Some(&anyone()), None),
            fresh,
        };
        let denied = SubFrame::Denied {
            reason: "no longer a directory of this network".into(),
        };
        let taken = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&taken);
        tokio::spawn(async move {
            while let Some(incoming) = ep.accept().await {
                let Ok(conn) = incoming.await else { continue };
                count.fetch_add(1, Ordering::SeqCst);
                let frames = match script {
                    Script::ViewThenSilence => vec![view.clone()],
                    Script::ViewThenDenied => vec![view.clone(), denied.clone()],
                    Script::Denied => vec![denied.clone()],
                };
                tokio::spawn(async move {
                    let Ok((mut send, mut recv)) = conn.accept_bi().await else {
                        return;
                    };
                    let _hello = wire::read_sub_request(&mut recv).await;
                    let _subscribe = wire::read_sub_request(&mut recv).await;
                    for frame in frames {
                        let _ = wire::write(&mut send, &frame.encode().unwrap()).await;
                    }
                    if matches!(script, Script::ViewThenSilence) {
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                    }
                    let _ = send.finish();
                    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
                });
            }
        });
        taken
    }

    /// A follower for node 55 over `book`, starting from no view and the
    /// fake directories.
    async fn follower(book: &MemoryLookup) -> Follow {
        let me = NodeIdentity::from_seed([55; 32]);
        Follow {
            endpoint: endpoint(&me, book, vec![]).await,
            root: root().node_id(),
            id_token: Arc::new(|| None),
            initial: None,
            fallback: vec![dir(0).node_id(), dir(1).node_id()],
            persist: None,
        }
    }

    /// The silence bound: the held `Fresh`'s lifetime plus that again, at
    /// most 10 s; two default beats and 10 s with none.
    #[test]
    fn silence_follows_the_freshness_lifetime() {
        let policy = listing();
        let held = |span: i64| {
            let fresh = Fresh::sign(&dir(0), &policy.head, 100, 100 + span).unwrap();
            HeldView::fetched(
                policy.view_for(crate::testutil::any_node(), None, None),
                Some(fresh),
                100,
            )
        };
        assert_eq!(silence(Some(&held(1))), Duration::from_secs(2));
        assert_eq!(silence(Some(&held(900))), Duration::from_secs(910));
        assert_eq!(silence(None), Duration::from_secs(610));
    }

    /// A directory that answers and then goes silent (no beat within the
    /// silence bound) ends the subscription, so the follower moves on,
    /// rather than waiting on it forever.
    #[tokio::test]
    async fn a_silent_view_subscription_is_taken_for_dead() {
        let book = MemoryLookup::new();
        let _taken = fake_directory(0, &book, Script::ViewThenSilence, 1).await;
        let f = follower(&book).await;
        let (tx, _rx) = tokio::sync::watch::channel(None);
        let mut held = None;
        let ended = tokio::time::timeout(
            Duration::from_secs(10),
            follow_once(&f, dir(0).node_id(), root().node_id(), &mut held, &tx),
        )
        .await
        .expect("ends within the silence bound")
        .unwrap();
        assert_eq!(ended, Ended::Closed);
        assert_eq!(held.unwrap().version(), StateVersion(1));
        f.endpoint.close().await;
    }

    /// A directory that ends the subscription with `denied` is passed over
    /// at once for the next one, and not asked again meanwhile.
    #[tokio::test]
    async fn a_denied_view_subscription_moves_to_the_next_directory() {
        let book = MemoryLookup::new();
        let first = fake_directory(0, &book, Script::ViewThenDenied, 3600).await;
        let second = fake_directory(1, &book, Script::ViewThenSilence, 3600).await;
        let f = follower(&book).await;
        let (tx, _rx) = tokio::sync::watch::channel(None);
        let mut held = None;
        let ended = follow_once(&f, dir(0).node_id(), root().node_id(), &mut held, &tx)
            .await
            .unwrap();
        assert!(matches!(ended, Ended::Denied(r) if r.contains("no longer a directory")));
        assert_eq!(first.load(Ordering::SeqCst), 1);

        let endpoint = f.endpoint.clone();
        let (_watch, task) = follow(f);
        tokio::time::timeout(Duration::from_secs(10), async {
            while second.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the second directory is followed");
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        assert_eq!(
            first.load(Ordering::SeqCst),
            2,
            "once more, then passed over"
        );
        assert_eq!(second.load(Ordering::SeqCst), 1, "followed, and still");
        task.abort();
        endpoint.close().await;
    }

    /// When every directory refuses, the follower pauses between rounds (1
    /// s, 2 s, …): a handful of attempts over seconds, never a tight loop.
    #[tokio::test]
    async fn a_follower_every_directory_refuses_backs_off() {
        let book = MemoryLookup::new();
        let first = fake_directory(0, &book, Script::Denied, 3600).await;
        let second = fake_directory(1, &book, Script::Denied, 3600).await;
        let f = follower(&book).await;
        let endpoint = f.endpoint.clone();
        let (_watch, task) = follow(f);
        tokio::time::sleep(Duration::from_millis(3_500)).await;
        task.abort();
        // Rounds at about 0, 1 and 3 s.
        for taken in [first, second] {
            let n = taken.load(Ordering::SeqCst);
            assert!((1..=4).contains(&n), "{n} subscriptions in 3.5 s");
        }
        endpoint.close().await;
    }
}

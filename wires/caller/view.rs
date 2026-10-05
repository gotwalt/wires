//! The caller's **view** (card 37): the services this node's verified person
//! may call, each a root-signed entry, and nothing else.
//!
//! A caller never holds the policy. It holds `$WIRES_HOME/view.json`
//! ([`HeldView`]): the root-signed head, the newest [`Fresh`] each directory
//! signed for it that this caller has seen (from a directory, or in a host's
//! proof), and the signed entries a directory cut for its ID token. No
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
//!   directory answers leaves the view as it is. That is not what bounds a
//!   call to a host the admin removed: a caller tells a host nothing until a
//!   current `Fresh` from a directory other than that host vouches for the
//!   head the host holds (card 49, [`vouch`](crate::caller::vouch)), so the
//!   bound is `fresh_secs`, and with every directory down calls fail closed.
//!   When the host's proof or `HelloAck` reports a newer head, the caller
//!   records it ([`note_seen`]) and refreshes; a name not in the view is
//!   asked of a directory with `resolve` before the call fails.
//! - `wires mcp` and `inbox --wait` ask again every minute ([`poll`]); the
//!   gateway asks for a web user's view at their first request after a
//!   minute ([`fetch`]).
//!
//! A view always travels whole (card 45). And a caller presents its ID
//! token to a directory only once that directory has shown it is current,
//! by the rule a host is held to (card 49): its head, no older than the
//! view's, that lists it, and a current `Fresh` for that head from another
//! directory ([`ask_proven`], [`directory_vouched`]). So a directory the
//! admin removed, or one that missed the edit, is told nothing once its
//! words have lapsed.
//!
//! A node that holds the whole policy (the admin's, a host's, a
//! directory's) cuts its view from its own copy instead of asking
//! ([`refresh`]).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use iroh::Endpoint;
use library::{
    DirectoryAnswer, DirectoryRequest, Fresh, FreshSet, HostProof, IdToken, NodeId, ServiceName,
    SignedEntry, StateVersion, View,
};
use serde::{Deserialize, Serialize};

use crate::admin::keystore::{Keystore, write_private};
use crate::clock::now_unix;
use crate::directory::wire;
use crate::host::transport;
use crate::policy::store;

/// The caller's view, under `$WIRES_HOME`.
pub(crate) const VIEW_FILE: &str = "view.json";

/// How old a view may be before `wires services`, `wires call` or `wires
/// inbox` refreshes it: a day.
///
/// This is **not** what bounds a call to a host the admin removed (protocol
/// §5): a caller sends a host nothing until a current `Fresh` from another
/// directory vouches for the host's head ([`vouch`](crate::caller::vouch)),
/// so that bound is the network's `fresh_secs`. An expired view is never
/// dialed from.
pub(crate) const VIEW_MAX_AGE_SECS: i64 = 24 * 60 * 60;

/// How long a refresh spends asking, all directories together.
pub(crate) const REFRESH_BUDGET: Duration = Duration::from_secs(8);

/// How often a long-running caller (`wires mcp`, `wires inbox --wait`, the
/// gateway for each web user) asks for its view again: a grant or a
/// revocation reaches it within this.
pub(crate) const POLL: Duration = Duration::from_secs(60);

/// `view.json`: the view, the newest `Fresh` per directory seen for it, when
/// a directory last vouched for it, and the newest head version a host
/// reported. Its `fresh` holds only words that verify for its view's head:
/// read back, the rest are dropped (second review: a forged word must
/// never sit in a slot).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "StoredView")]
pub(crate) struct HeldView {
    /// The view: the root-signed head and this caller's entries.
    pub(crate) view: View,
    /// The newest `Fresh` each directory signed that this caller has seen,
    /// from a directory or in a host's proof: what lets it speak to a host
    /// at once (card 49). Empty when the view was cut locally from a whole
    /// policy and no host has shown one yet. Only words verified for the
    /// view's head enter it.
    #[serde(skip_serializing_if = "FreshSet::is_empty")]
    pub(crate) fresh: FreshSet,
    /// When a directory last vouched for the view (unix seconds; 0: never).
    pub(crate) checked: i64,
    /// The newest head version a host reported in a `HelloAck` (0: none
    /// newer than the view's).
    pub(crate) seen: StateVersion,
}

/// `view.json` as read: its words not yet checked against its head.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredView {
    view: View,
    #[serde(default)]
    fresh: Vec<Fresh>,
    checked: i64,
    seen: StateVersion,
}

impl From<StoredView> for HeldView {
    /// Keep only the words that verify for the view's head (the head itself
    /// is verified under the root by [`read`]).
    fn from(s: StoredView) -> HeldView {
        let fresh = FreshSet::from_unverified(s.fresh, &s.view.head);
        HeldView {
            view: s.view,
            fresh,
            checked: s.checked,
            seen: s.seen,
        }
    }
}

impl HeldView {
    /// A view just fetched (or cut) at `now`, with the word that came with
    /// it, if it verifies for the view's head.
    pub(crate) fn fetched(view: View, fresh: Option<Fresh>, now: i64) -> HeldView {
        let mut set = FreshSet::default();
        if let Some(f) = fresh.and_then(|f| f.verified(&view.head).ok()) {
            set.insert(f, now);
        }
        HeldView {
            view,
            fresh: set,
            checked: now,
            seen: StateVersion(0),
        }
    }

    /// Keep, beside its own, what `old` had seen from each directory that
    /// vouches for this view's head too.
    pub(crate) fn keeping(mut self, old: Option<&HeldView>, now: i64) -> HeldView {
        self.learn_all(old.into_iter().flat_map(|o| o.fresh.iter()), now);
        self
    }

    /// Keep each of `words` that verifies for the view's head.
    pub(crate) fn learn_all<'a>(&mut self, words: impl Iterator<Item = &'a Fresh>, now: i64) {
        for f in words {
            if let Ok(v) = f.clone().verified(&self.view.head) {
                self.fresh.insert(v, now);
            }
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
    write_private(&ks.path(VIEW_FILE), format!("{text}\n"))
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

/// Keep `fresh` (a `Fresh` a host's proof carried, already checked) with the
/// stored view when it vouches for that view's head: the next call to a
/// host it vouches for speaks at once (card 49). Best effort; no view, or
/// a `Fresh` for another head, no note.
pub(crate) fn note_fresh(ks: &Keystore, root: NodeId, fresh: &Fresh) {
    let noted = (|| -> Result<()> {
        let Some(mut held) = read(ks, root)? else {
            return Ok(());
        };
        let Ok(fresh) = fresh.clone().verified(&held.view.head) else {
            return Ok(());
        };
        if held.fresh.insert(fresh, now_unix()) {
            write(ks, root, &held)?;
        }
        Ok(())
    })();
    if let Err(e) = noted {
        tracing::debug!("keeping a host's freshness: {e:#}");
    }
}

/// Record that a host refused a call made from the view: it may be behind
/// the host's policy, so the next `wires services`, `wires call` or `wires
/// inbox` refreshes first (as if no directory had vouched for it lately).
/// Best effort; no view, no note.
pub(crate) fn note_refused(ks: &Keystore, root: NodeId) {
    let noted = (|| -> Result<()> {
        let Some(mut held) = read(ks, root)? else {
            return Ok(());
        };
        held.checked = 0;
        write(ks, root, &held)
    })();
    if let Err(e) = noted {
        tracing::debug!("noting a refusal: {e:#}");
    }
}

/// The directories the network string names (empty when none is stored).
pub(crate) fn joined_directories(ks: &Keystore) -> Vec<NodeId> {
    ks.read_network()
        .ok()
        .flatten()
        .map_or_else(Vec::new, |n| n.directories)
}

/// The directories this node asks, never itself: its view's head's, then
/// the network string's not among them (so a view from before a directory
/// was added still reaches it; card 49 review).
pub(crate) fn directories(ks: &Keystore, root: NodeId, me: NodeId) -> Vec<NodeId> {
    let mut dirs = match read(ks, root) {
        Ok(Some(held)) => held.directories().to_vec(),
        _ => Vec::new(),
    };
    for d in joined_directories(ks) {
        if !dirs.contains(&d) {
            dirs.push(d);
        }
    }
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

/// What the asking in [`ask_proven`] came to when no directory gave an
/// answer that was taken: why each failed, and whether one refused this
/// node's admission.
#[derive(Debug, Default)]
pub(crate) struct Unanswered {
    /// One line per directory.
    pub(crate) failures: Vec<String>,
    /// A directory whose proof checked out answered
    /// [`NOT_ADMITTED`](crate::host::gate::NOT_ADMITTED).
    pub(crate) not_admitted: bool,
}

/// Whether directory `dir` may be told this caller's token, from its
/// `proof` (card 45): it holds a head the root signed, unexpired, that
/// lists `dir` as a directory; that head is no older than the caller's view
/// (`held`, when it holds one; at its version, the same head); and a
/// current `Fresh` from a directory other than `dir` vouches for it (or
/// from `dir`, when the head lists it alone) — the proof's own, or one in
/// `pool` (what the caller's view holds, and what every other directory
/// asked in the same round showed). The rule a host is held to (card 49,
/// [`HostProof::check`]), and its review's: `dir`'s own word counts (the
/// head listing it alone) only while `known`, the network string's
/// directories, names no other node, so an old one-directory head can't make
/// a later network look like a one-machine one.
pub(crate) fn directory_vouched(
    proof: &HostProof,
    pool: &FreshSet,
    root: NodeId,
    held: Option<&library::SignedPolicyHead>,
    known: &[NodeId],
    dir: NodeId,
    now: i64,
) -> Result<()> {
    if !proof.head.head.directories.contains(&dir) {
        bail!(
            "its policy (version {}) doesn't list it as a directory",
            proof.head.head.version.0
        );
    }
    // Its words count only once its head is the root's, and each verifies
    // for it (second review).
    proof.head.verify(root)?;
    let mut set = pool.clone();
    for f in proof.fresh.iter().take(library::MAX_FRESH_SET) {
        if let Ok(v) = f.clone().verified(&proof.head) {
            set.insert(v, now);
        }
    }
    let combined = HostProof {
        head: proof.head.clone(),
        fresh: set.current_for(&proof.head, now),
    };
    match held {
        Some(head) => {
            combined.check(root, head, dir, now)?;
        }
        None => {
            combined.head.verify(root)?;
            combined.head.check_fresh(now)?;
            combined.vouching(dir, now)?;
        }
    }
    let alone = known.iter().all(|d| *d == dir);
    if !combined
        .fresh
        .iter()
        .any(|f| f.vouches(&combined.head, dir, now).is_ok() && (f.directory != dir || alone))
    {
        bail!(
            "it vouched for its own policy, which lists it as the one directory, but the network \
             names others"
        );
    }
    Ok(())
}

/// The words of `proof` that may join the pool the other directories are
/// checked against (second review): none unless its head verifies under the
/// root, hasn't expired, and is no older than the caller's view (`held`);
/// then each that verifies for that head, at most [`library::MAX_FRESH_SET`].
/// A forged word, or one shown by a directory whose head is behind, never
/// takes a slot.
pub(crate) fn pool_words(
    proof: &HostProof,
    root: NodeId,
    held: Option<&library::SignedPolicyHead>,
    now: i64,
) -> Vec<library::VerifiedFresh> {
    let head = &proof.head;
    let usable = head.verify(root).is_ok()
        && head.check_fresh(now).is_ok()
        && held.is_none_or(|h| head.head.version >= h.head.version);
    if !usable {
        return Vec::new();
    }
    proof
        .fresh
        .iter()
        .take(library::MAX_FRESH_SET)
        .filter_map(|f| f.clone().verified(head).ok())
        .collect()
}

/// Ask `dirs` for `request`, presenting `id_token` only to a directory whose
/// proof checks out ([`directory_vouched`]): every directory is asked for
/// its proof at once (`open`, nothing else); as each proof arrives, the
/// `Fresh`es it carries that verify ([`pool_words`]) join the pool the
/// others are checked against, and
/// every directory whose proof now checks out is sent the token and the
/// request, one at a time, until `take` accepts an answer. A directory
/// whose proof never checks out was told nothing but `open`. Nothing waits
/// for the slowest directory once one has answered. `take` gets the head
/// the directory proved, which the answer must be under (second review).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn ask_proven<T>(
    endpoint: &Endpoint,
    root: NodeId,
    dirs: &[NodeId],
    known: &[NodeId],
    held: Option<&HeldView>,
    id_token: Option<IdToken>,
    request: &DirectoryRequest,
    mut take: impl FnMut(&library::SignedPolicyHead, DirectoryAnswer, &FreshSet) -> Result<T>,
) -> std::result::Result<T, Unanswered> {
    let mut asked = tokio::task::JoinSet::new();
    for &dir in dirs {
        let endpoint = endpoint.clone();
        asked.spawn(async move { (dir, wire::open(&endpoint, dir).await) });
    }
    let mut pool = held.map(|h| h.fresh.clone()).unwrap_or_default();
    let mut waiting: Vec<(NodeId, wire::Opened)> = Vec::new();
    let mut out = Unanswered::default();
    while let Some(joined) = asked.join_next().await {
        let Ok((dir, opened)) = joined else { continue };
        match opened {
            Ok(o) => {
                let now = now_unix();
                for v in pool_words(&o.proof, root, held.map(|h| &h.view.head), now) {
                    pool.insert(v, now);
                }
                waiting.push((dir, o));
            }
            Err(e) => out.failures.push(format!("{}: {e:#}", dir.short())),
        }
        // Every directory the pool now vouches for, in turn.
        let mut i = 0;
        while i < waiting.len() {
            let (dir, o) = &waiting[i];
            let vouched = directory_vouched(
                &o.proof,
                &pool,
                root,
                held.map(|h| &h.view.head),
                known,
                *dir,
                now_unix(),
            );
            if vouched.is_err() {
                i += 1;
                continue;
            }
            let (dir, o) = waiting.remove(i);
            let proved = o.proof.head.clone();
            match o.ask(id_token.clone(), request).await {
                Ok(DirectoryAnswer::Denied { reason }) => {
                    out.not_admitted |= reason == crate::host::gate::NOT_ADMITTED;
                    out.failures
                        .push(format!("{}: refused: {reason}", dir.short()));
                }
                Ok(answer) => match take(&proved, answer, &pool) {
                    Ok(t) => return Ok(t),
                    Err(e) => out.failures.push(format!("{}: {e:#}", dir.short())),
                },
                Err(e) => out.failures.push(format!("{}: {e:#}", dir.short())),
            }
        }
    }
    let now = now_unix();
    for (dir, o) in waiting {
        let held_head = held.map(|h| &h.view.head);
        let why = directory_vouched(&o.proof, &pool, root, held_head, known, dir, now)
            .err()
            .map_or_else(|| "it lapsed".to_string(), |e| format!("{e:#}"));
        tracing::debug!(directory = %dir.hex(), "told nothing: {why}");
        out.failures.push(format!(
            "{}: could not show a current policy ({why}); nothing was sent to it",
            dir.short()
        ));
    }
    Err(out)
}

/// Ask `dirs` (never this node; `known` the network string's, for the
/// one-directory rule) for this node's whole view, presenting
/// `id_token` only to a directory that has shown it is current
/// ([`ask_proven`]): the first view that verifies, under exactly the head
/// that directory proved, whose `Fresh` vouches for its head, and that is no
/// older than `held`. It keeps what `held` had seen from each directory, and
/// every `Fresh` the directories showed, that vouches for its head.
/// Errors when none gave one, with [`NotAdmitted`] as its context when a
/// directory refused this node's admission.
pub(crate) async fn fetch(
    endpoint: &Endpoint,
    root: NodeId,
    dirs: &[NodeId],
    known: &[NodeId],
    held: Option<&HeldView>,
    id_token: Option<IdToken>,
) -> Result<HeldView> {
    let now = now_unix();
    let request = DirectoryRequest::View { query: None };
    let taken = ask_proven(
        endpoint,
        root,
        dirs,
        known,
        held,
        id_token,
        &request,
        |proved, answer, pool| {
            let DirectoryAnswer::View { view, fresh } = answer else {
                bail!("an unexpected answer to `view`: {answer:?}");
            };
            if view.head != *proved {
                bail!("a view under another head than the one it proved");
            }
            view.verify(root)
                .context("the directory's view does not verify")?;
            fresh
                .verify(&view.head)
                .context("the directory's freshness doesn't vouch for its view")?;
            if let Some(old) = held
                && view.head.head.version < old.version()
            {
                bail!("an older view (version {})", view.head.head.version.0);
            }
            let mut fetched = HeldView::fetched(view, Some(fresh), now).keeping(held, now);
            fetched.learn_all(pool.iter(), now);
            Ok(fetched)
        },
    )
    .await;
    taken.map_err(|out| {
        let failed = anyhow!(
            "no directory gave this node its view ({})",
            out.failures.join("; ")
        );
        if out.not_admitted {
            failed.context(NotAdmitted)
        } else {
            failed
        }
    })
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
/// - any other asks the directories ([`directories`], [`fetch`]): the
///   first whole view from one whose proof checks out settles it. `forget`
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
    let fetched = fetch(
        asker.endpoint,
        root,
        &dirs,
        &joined_directories(ks),
        held.as_ref(),
        asker.id_token.clone(),
    )
    .await?;
    write(ks, root, &fetched)?;
    Ok(fetched)
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
/// as it is (each host still has to show a directory's current word before
/// it is told anything, [`vouch`](crate::caller::vouch)); with none, it
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
/// held view doesn't have: the one-entry view holding its entry (with the
/// `Fresh` for its head, which a call checks its hosts against), if this
/// node may use it.
pub(crate) async fn resolve(
    ks: &Keystore,
    asker: &Asker<'_>,
    service: &ServiceName,
) -> Result<Option<HeldView>> {
    let root = asker.root;
    let me = transport::to_node_id(&asker.endpoint.id());
    let dirs = directories(ks, root, me);
    if dirs.is_empty() {
        return Ok(None);
    }
    let held = read(ks, root).ok().flatten();
    let request = DirectoryRequest::Resolve {
        service: service.clone(),
    };
    let found = ask_proven(
        asker.endpoint,
        root,
        &dirs,
        &joined_directories(ks),
        held.as_ref(),
        asker.id_token.clone(),
        &request,
        |proved, answer, _| {
            let DirectoryAnswer::View { view, fresh } = answer else {
                bail!("an unexpected answer to `resolve`: {answer:?}");
            };
            if view.head != *proved {
                bail!("a view under another head than the one it proved");
            }
            view.verify(root)
                .context("the directory's view does not verify")?;
            fresh
                .verify(&view.head)
                .context("the directory's freshness doesn't vouch for its view")?;
            if view.entries.iter().any(|e| e.name != *service) {
                bail!("the directory resolved {service} to another service");
            }
            Ok((view, fresh))
        },
    )
    .await;
    match found {
        Ok((view, fresh)) => {
            note_seen(ks, root, view.head.head.version);
            if view.entries.is_empty() {
                return Ok(None);
            }
            Ok(Some(HeldView::fetched(view, Some(fresh), now_unix())))
        }
        Err(out) => bail!(
            "no directory resolved {service} ({})",
            out.failures.join("; ")
        ),
    }
}

/// Where a polled view goes as it changes.
pub(crate) type ViewWatch = tokio::sync::watch::Receiver<Option<Arc<HeldView>>>;

/// What a [`poll`] needs.
pub(crate) struct Poll {
    /// A bound endpoint for this node (kept open by the caller).
    pub(crate) endpoint: Endpoint,
    /// The network's root key.
    pub(crate) root: NodeId,
    /// The ID token to present at each ask: read afresh, so a new `wires
    /// login` takes effect at the next one.
    pub(crate) id_token: Arc<dyn Fn() -> Option<IdToken> + Send + Sync>,
    /// The view to start from (and to keep while no directory answers).
    pub(crate) initial: Option<HeldView>,
    /// The network string's directories: asked after the view's head's
    /// (card 49 review), and the one-directory rule's `known`.
    pub(crate) fallback: Vec<NodeId>,
    /// Where to keep the view as it changes (`view.json`), if anywhere.
    pub(crate) persist: Option<Arc<Keystore>>,
    /// How often to ask ([`POLL`]); while it holds no view, sooner (from
    /// 1 s, doubling up to this).
    pub(crate) every: Duration,
}

/// Ask for this node's view every [`Poll::every`] until the returned task is
/// aborted ([`fetch`]: only of a directory whose proof checks out), and send
/// each new one on the returned channel. A round no directory answers keeps
/// the view as it is.
pub(crate) fn poll(p: Poll) -> (ViewWatch, tokio::task::JoinHandle<()>) {
    let (tx, rx) = tokio::sync::watch::channel(p.initial.clone().map(Arc::new));
    let task = tokio::spawn(async move {
        let me = transport::to_node_id(&p.endpoint.id());
        let mut held = p.initial.clone();
        let mut pause = Duration::from_secs(1).min(p.every);
        if held.is_some() {
            tokio::time::sleep(p.every).await;
        }
        loop {
            let mut dirs: Vec<NodeId> = held
                .as_ref()
                .map(|h| h.directories().to_vec())
                .unwrap_or_default();
            for d in &p.fallback {
                if !dirs.contains(d) {
                    dirs.push(*d);
                }
            }
            dirs.retain(|d| *d != me);
            let token = (p.id_token)();
            match fetch(
                &p.endpoint,
                p.root,
                &dirs,
                &p.fallback,
                held.as_ref(),
                token,
            )
            .await
            {
                Ok(mut next) => {
                    next.seen = held.as_ref().map_or(StateVersion(0), |h| h.seen);
                    if let Some(ks) = &p.persist
                        && let Err(e) = write(ks, p.root, &next)
                    {
                        tracing::warn!("could not keep view.json in step: {e:#}");
                    }
                    held = Some(next.clone());
                    if tx.send(Some(Arc::new(next))).is_err() {
                        return;
                    }
                }
                Err(e) => tracing::debug!("asking for the view again: {e:#}"),
            }
            let wait = if held.is_some() { p.every } else { pause };
            pause = (pause * 2).min(p.every);
            tokio::time::sleep(wait).await;
        }
    });
    (rx, task)
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
    fn directories_come_from_the_head_then_the_network_string() {
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
        assert_eq!(directories(&ks, r, me), vec![listed, d], "the head's first");
    }

    /// A directory's proof: its head and the `Fresh`es of `by`, current at
    /// 1 000 for 900 s.
    fn proof(p: &SignedPolicy, by: &[&NodeIdentity]) -> HostProof {
        HostProof {
            head: p.head.clone(),
            fresh: by
                .iter()
                .map(|d| Fresh::sign(d, &p.head, 1_000, 1_900).unwrap())
                .collect(),
        }
    }

    /// `signed(version)` listing `dirs` as its directories.
    fn listing(version: u64, dirs: &[&NodeIdentity]) -> SignedPolicy {
        let mut p = signed(version).to_policy().unwrap();
        p.directories = dirs.iter().map(|d| d.node_id()).collect();
        crate::testutil::signed_policy(&root(), p)
    }

    /// Card 45: a directory is told a caller's token only on another
    /// directory's current word for a head it is listed in, no older than
    /// the caller's view: as a host is (card 49).
    #[test]
    fn a_directory_is_told_nothing_without_another_directorys_current_word() {
        let (a, b, c) = (
            NodeIdentity::from_seed([60; 32]),
            NodeIdentity::from_seed([61; 32]),
            NodeIdentity::from_seed([62; 32]),
        );
        let r = root().node_id();
        let v3 = listing(3, &[&a, &b]);
        let none = FreshSet::default();
        let at = 1_500;
        let ok = |proof: &HostProof, pool: &FreshSet, held: Option<&SignedPolicy>| {
            directory_vouched(proof, pool, r, held.map(|p| &p.head), &[], a.node_id(), at)
        };
        // Its own word alone: no (two directories listed).
        assert!(ok(&proof(&v3, &[&a]), &none, None).is_err());
        // Another's, in its proof or from the other directory asked.
        assert!(ok(&proof(&v3, &[&a, &b]), &none, None).is_ok());
        let mut pool = FreshSet::default();
        pool.insert(
            Fresh::sign(&b, &v3.head, 1_000, 1_900)
                .unwrap()
                .verified(&v3.head)
                .unwrap(),
            at,
        );
        assert!(ok(&proof(&v3, &[&a]), &pool, Some(&v3)).is_ok());
        // Lapsed: no.
        assert!(
            directory_vouched(
                &proof(&v3, &[&a, &b]),
                &none,
                r,
                None,
                &[],
                a.node_id(),
                1_901
            )
            .is_err()
        );
        // Behind the caller's view: no, whoever vouches.
        let v4 = listing(4, &[&a, &b]);
        assert!(ok(&proof(&v3, &[&a, &b]), &none, Some(&v4)).is_err());
        // Removed from the directories (a head that no longer lists it, with
        // the others' current words): no.
        let v5 = listing(5, &[&b, &c]);
        assert!(ok(&proof(&v5, &[&b, &c]), &none, Some(&v4)).is_err());
        // The one directory: its own word is all there is.
        let alone = listing(3, &[&a]);
        assert!(ok(&proof(&alone, &[&a]), &none, None).is_ok());
        // Unless the network string names another (card 49 review, 4).
        let own = proof(&alone, &[&a]);
        let known = [a.node_id(), b.node_id()];
        assert!(directory_vouched(&own, &none, r, None, &known, a.node_id(), at).is_err());
        assert!(directory_vouched(&own, &none, r, None, &known[..1], a.node_id(), at).is_ok());
    }
}

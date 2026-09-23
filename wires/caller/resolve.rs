//! The channel is the directory (board card 15): a caller finds a tool by
//! name through the hosts' announcements on the channel it joined.
//!
//! Hosts announce what they serve ([`HostAnnouncement`], sealed per allowed
//! member — see [`crate::host::announce`]). A caller keeps what it has read in
//! `$WIRES_HOME/directory.json`, a **cache**: the one thing ever handed out of
//! band is the admin's invite (`wires join`), and everything here is rebuilt
//! from the channel.
//!
//! - **Resident**: a running `wires watch` folds every announcement it prints
//!   into the cache ([`DirectoryHook`]).
//! - **Cold**: `wires call`, `wires mcp` and `wires tools` fold what the local
//!   log holds, then join the channel for at most [`CATCH_UP_BUDGET`] — a
//!   replay catch-up from the joined bootstrap peers, then live messages until
//!   the name resolves ([`refresh`]). When a resident watch holds the log (its
//!   redb lock), they use the cache it keeps instead.
//!
//! # Resolution ([`Directory::resolve`])
//!
//! 1. `host8/name` picks the host whose id starts with `host8`.
//! 2. A name one live host lists resolves to it; several → an ambiguity error
//!    naming each `host8/name`.
//! 3. A name nobody lists *to you* still dials, when exactly one host is known:
//!    you may be allowed a tool you cannot see yet (its announcement is on its
//!    way), and if not, the host refuses with its reason — "you can't see it"
//!    is privacy, the host's refusal is the access control.
//!
//! Aliases in `tools.json` (`wires tools add`) are checked first and always
//! win: they are explicit.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use library::{
    ChannelRecord, HostAnnouncement, HostListing, NodeId, NodeIdentity, ToolName, TopicEnvelope,
    TopicPeer,
};
use serde::{Deserialize, Serialize};

use crate::admin::keystore;
use crate::caller::call::CredArgs;
use crate::caller::tools::{RemoteTool, ToolTarget, ToolsConfig};
use crate::channel::context::{TopicArgs, TopicContext};
use crate::channel::peers::PeerBook;
use crate::channel::printer::Keyring;
use crate::channel::{rekey, replay, store, topics};
use crate::now_unix;

/// The cache file under `$WIRES_HOME`.
pub(crate) const DIRECTORY_FILE: &str = "directory.json";

/// How long a cold `call` / `mcp` / `tools` spends on the channel before
/// answering from what it has.
pub(crate) const CATCH_UP_BUDGET: Duration = Duration::from_secs(2);

/// One host as this caller knows it: when it last announced, and what it
/// showed *this* node.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) struct KnownHost {
    /// The host's node id.
    pub(crate) node: NodeId,
    /// Its latest announcement's timestamp (unix ms).
    pub(crate) at_ms: i64,
    /// Its heartbeat interval (ms; 0 = unknown, never stale).
    #[serde(default)]
    pub(crate) heartbeat_ms: u64,
    /// What it showed this node: tools and dial hints. Empty when it showed
    /// nothing — the host exists, and that is all this node may know.
    #[serde(default)]
    pub(crate) listing: HostListing,
}

impl KnownHost {
    /// No announcement for more than three heartbeats.
    pub(crate) fn is_stale(&self, now_ms: i64) -> bool {
        self.heartbeat_ms > 0
            && now_ms.saturating_sub(self.at_ms) > (self.heartbeat_ms as i64).saturating_mul(3)
    }

    /// The first 8 hex characters of the host's id.
    pub(crate) fn short(&self) -> String {
        self.node.hex()[..8].to_string()
    }

    /// Whether it listed `name` to this node.
    fn lists(&self, name: &ToolName) -> bool {
        self.listing.tools.iter().any(|t| &t.name == name)
    }

    /// The [`RemoteTool`] that dials `name` on this host (`local` is what the
    /// caller typed or the MCP name). `peers` fill in dial hints the listing
    /// lacks (the join's bootstrap peers).
    fn tool(&self, local: ToolName, name: &ToolName, peers: &[TopicPeer]) -> RemoteTool {
        let hint = peers.iter().find(|p| p.node == self.node);
        let addrs = if self.listing.addrs.is_empty() {
            hint.map(|p| p.addrs.clone()).unwrap_or_default()
        } else {
            self.listing.addrs.clone()
        };
        let relay_url = self
            .listing
            .relay_url
            .clone()
            .or_else(|| hint.and_then(|p| p.relay_url.clone()));
        let description = self
            .listing
            .tools
            .iter()
            .find(|t| &t.name == name)
            .map(|t| t.description.clone())
            .unwrap_or_default();
        RemoteTool {
            remote_tool: (&local != name).then(|| name.clone()),
            name: local,
            description,
            target: ToolTarget::Node {
                node: self.node,
                relay_url,
                addrs,
            },
        }
    }
}

/// `directory.json`: the hosts this caller has seen announce on its channel.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub(crate) struct Directory {
    /// The channel these hosts announced on (a different joined channel
    /// discards them).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) channel: Option<String>,
    /// One entry per host, in node-id order.
    #[serde(default)]
    pub(crate) hosts: Vec<KnownHost>,
}

/// How [`Directory::resolve`] found a tool.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Resolved {
    /// What to dial.
    pub(crate) tool: RemoteTool,
    /// Whether the host listed it to this node (`false`: the one known host
    /// is dialed anyway, and will answer or refuse).
    pub(crate) listed: bool,
    /// Whether that host is stale.
    pub(crate) stale: bool,
}

impl Directory {
    /// `$WIRES_HOME/directory.json`.
    pub(crate) fn path(home: &Path) -> PathBuf {
        home.join(DIRECTORY_FILE)
    }

    /// Load `path` as the directory of `channel`: a missing or unreadable
    /// file, or one for another channel, is an empty directory (it is a
    /// cache; the channel rebuilds it).
    pub(crate) fn load(path: &Path, channel: &str) -> Self {
        let dir: Directory = std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        if dir.channel.as_deref() == Some(channel) {
            dir
        } else {
            Directory {
                channel: Some(channel.to_string()),
                hosts: Vec::new(),
            }
        }
    }

    /// Write to `path` (temp file + rename).
    pub(crate) fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut json = serde_json::to_string_pretty(self)?;
        json.push('\n');
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    }

    /// Fold `ann`, which arrived in an envelope signed by `sender`, as seen
    /// by `me`. Ignored unless `sender` is the host it names (only a host
    /// announces itself) and it is at least as new as what is held. Returns
    /// whether anything changed.
    pub(crate) fn observe(
        &mut self,
        sender: NodeId,
        ann: &HostAnnouncement,
        me: &NodeIdentity,
    ) -> bool {
        if sender != ann.node || ann.node == me.node_id() {
            return false;
        }
        let known = KnownHost {
            node: ann.node,
            at_ms: ann.at_ms,
            heartbeat_ms: ann.heartbeat_ms,
            listing: ann.listing_for(me).unwrap_or_default(),
        };
        match self.hosts.iter_mut().find(|h| h.node == ann.node) {
            Some(held) if held.at_ms > ann.at_ms || *held == known => false,
            Some(held) => {
                *held = known;
                true
            }
            None => {
                self.hosts.push(known);
                self.hosts.sort_by_key(|h| h.node);
                true
            }
        }
    }

    /// Fold `envelope` if it is a host announcement `keyring` opens.
    pub(crate) fn observe_envelope(
        &mut self,
        envelope: &TopicEnvelope,
        keyring: &mut Keyring,
        me: &NodeIdentity,
    ) -> bool {
        let Some(plaintext) = keyring.open(envelope) else {
            return false;
        };
        match ChannelRecord::parse(&String::from_utf8_lossy(&plaintext)) {
            Some(ChannelRecord::Host(ann)) => self.observe(envelope.sender, &ann, me),
            _ => false,
        }
    }

    /// Find `query` (`name` or `host8/name`) at `now_ms`. `peers` are the
    /// join's bootstrap hints (dial hints for a host whose listing has none).
    /// See the module docs for the rules; the error says what to do.
    pub(crate) fn resolve(
        &self,
        query: &str,
        now_ms: i64,
        peers: &[TopicPeer],
    ) -> Result<Resolved> {
        let channel = self.channel.as_deref().unwrap_or("?");
        if let Some((prefix, name)) = query.split_once('/') {
            let name = ToolName::new(name).with_context(|| format!("tool name in `{query}`"))?;
            let prefix = prefix.to_ascii_lowercase();
            let hosts: Vec<&KnownHost> = self
                .hosts
                .iter()
                .filter(|h| !prefix.is_empty() && h.node.hex().starts_with(&prefix))
                .collect();
            return match hosts.as_slice() {
                [host] => Ok(Resolved {
                    tool: host.tool(name.clone(), &name, peers),
                    listed: host.lists(&name),
                    stale: host.is_stale(now_ms),
                }),
                [] => bail!(
                    "no host on channel {channel:?} has an id starting {prefix:?} (known: {})",
                    self.known_hosts()
                ),
                _ => bail!("{prefix:?} matches several hosts; use more of the id"),
            };
        }
        let name = ToolName::new(query).with_context(|| format!("tool name `{query}`"))?;
        let listing: Vec<&KnownHost> = self.hosts.iter().filter(|h| h.lists(&name)).collect();
        // Live hosts first: a stale one is only a candidate when no live one is.
        let live: Vec<&KnownHost> = listing
            .iter()
            .copied()
            .filter(|h| !h.is_stale(now_ms))
            .collect();
        let candidates = if live.is_empty() { listing } else { live };
        match candidates.as_slice() {
            [host] => Ok(Resolved {
                tool: host.tool(name.clone(), &name, peers),
                listed: true,
                stale: host.is_stale(now_ms),
            }),
            [] => match self.hosts.as_slice() {
                // Not listed to this node, and one host to ask: it answers
                // (the announcement may be on its way) or refuses with why.
                [host] => Ok(Resolved {
                    tool: host.tool(name.clone(), &name, peers),
                    listed: false,
                    stale: host.is_stale(now_ms),
                }),
                [] => bail!(
                    "no tool named `{name}`: no host has announced on channel {channel:?} yet \
                     (is one serving? `wires tools` lists what you can run)"
                ),
                _ => bail!(
                    "no host on channel {channel:?} announces `{name}` to you (hosts: {}); \
                     `wires tools` lists what you can run, and `<host>/{name}` asks one host \
                     directly",
                    self.known_hosts()
                ),
            },
            several => {
                let forms: Vec<String> = several
                    .iter()
                    .map(|h| format!("{}/{name}", h.short()))
                    .collect();
                bail!(
                    "`{name}` is served by {} hosts; pick one: {}",
                    several.len(),
                    forms.join(", ")
                )
            }
        }
    }

    /// Every tool this node can see, one [`RemoteTool`] each, for `wires
    /// mcp`: live hosts only; a name several hosts serve is exposed once per
    /// host as `<name>-<host8>`; names in `taken` (aliases) are skipped.
    pub(crate) fn visible_tools(
        &self,
        now_ms: i64,
        peers: &[TopicPeer],
        taken: &BTreeSet<ToolName>,
    ) -> Vec<RemoteTool> {
        let live: Vec<&KnownHost> = self.hosts.iter().filter(|h| !h.is_stale(now_ms)).collect();
        let mut out = Vec::new();
        for host in &live {
            for t in &host.listing.tools {
                if taken.contains(&t.name) {
                    continue;
                }
                let shared = live.iter().filter(|h| h.lists(&t.name)).count() > 1;
                let local = if shared {
                    ToolName::new(format!("{}-{}", t.name, host.short()))
                        .unwrap_or_else(|_| t.name.clone())
                } else {
                    t.name.clone()
                };
                out.push(host.tool(local, &t.name, peers));
            }
        }
        out
    }

    /// `eacc34e0, 1234abcd` (or `none`).
    fn known_hosts(&self) -> String {
        if self.hosts.is_empty() {
            return "none".into();
        }
        self.hosts
            .iter()
            .map(KnownHost::short)
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// `wires tools`: one line per tool this node can see, then (on the
    /// returned note) the hosts that show it nothing.
    pub(crate) fn render(&self, now_ms: i64) -> (String, Option<String>) {
        let mut rows: Vec<(String, String, String)> = Vec::new();
        let mut silent = Vec::new();
        for host in &self.hosts {
            let stale = host.is_stale(now_ms).then(|| {
                format!(
                    " (stale: last announced {} ago)",
                    ago(now_ms.saturating_sub(host.at_ms))
                )
            });
            if host.listing.tools.is_empty() {
                silent.push(format!("{}{}", host.short(), stale.unwrap_or_default()));
                continue;
            }
            for t in &host.listing.tools {
                rows.push((
                    t.name.to_string(),
                    format!("on {}{}", host.short(), stale.clone().unwrap_or_default()),
                    t.description.clone(),
                ));
            }
        }
        let name_w = rows.iter().map(|r| r.0.len()).max().unwrap_or(0);
        let host_w = rows.iter().map(|r| r.1.len()).max().unwrap_or(0);
        let text = rows
            .iter()
            .map(|(n, h, d)| {
                format!("{n:<name_w$}  {h:<host_w$}  {}", one_line(d))
                    .trim_end()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");
        let channel = self.channel.as_deref().unwrap_or("?");
        let note = match silent.len() {
            0 => None,
            n => Some(format!(
                "{n} host{} on channel {channel:?} announce{} nothing you may use: {}",
                if n == 1 { "" } else { "s" },
                if n == 1 { "s" } else { "" },
                silent.join(", ")
            )),
        };
        (text, note)
    }
}

/// `45s`, `12m`, `3h`, `2d`.
fn ago(ms: i64) -> String {
    let s = ms.max(0) / 1000;
    match s {
        0..60 => format!("{s}s"),
        60..3600 => format!("{}m", s / 60),
        3600..86_400 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86_400),
    }
}

/// A description on one line (hosts write them; a newline would break the
/// table).
fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// What a [`refresh`] could do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refreshed {
    /// It read the log and (if there were peers) the channel.
    Read,
    /// A resident `wires watch` holds the log; the cache it keeps is all
    /// there is.
    Locked,
}

/// Fold every announcement the log holds into `dir`.
fn fold_store(
    store: &store::TopicStore,
    keyring: &mut Keyring,
    me: &NodeIdentity,
    dir: &mut Directory,
) {
    match store.read_backfill(usize::MAX) {
        Ok(all) => {
            for envelope in &all {
                dir.observe_envelope(envelope, keyring, me);
            }
        }
        Err(e) => tracing::warn!("reading the log for host announcements: {e:#}"),
    }
}

/// What a [`refresh`] waits for once it has caught up.
pub(crate) type Until<'a> = Option<&'a dyn Fn(&Directory) -> bool>;

/// Bring `dir` up to date from the channel `ctx` names, spending at most
/// `budget`: fold the log, catch up from the bootstrap peers, then — with
/// `until` — keep reading live messages until `until(dir)` holds (`None`:
/// stop after the catch-up). See the module docs.
pub(crate) async fn refresh(
    ctx: &TopicContext,
    dir: &mut Directory,
    budget: Duration,
    until: Until<'_>,
) -> Result<Refreshed> {
    refresh_on(ctx, dir, budget, until, async |cfg| {
        topics::TopicNode::spawn(&ctx.node, cfg).await
    })
    .await
}

/// [`refresh`] over a node stood up by `bind` (the loopback e2e tests bind a
/// hermetic endpoint).
pub(crate) async fn refresh_on<B>(
    ctx: &TopicContext,
    dir: &mut Directory,
    budget: Duration,
    until: Until<'_>,
    bind: B,
) -> Result<Refreshed>
where
    B: AsyncFnOnce(topics::TopicNodeConfig) -> Result<topics::TopicNode>,
{
    let deadline = tokio::time::Instant::now() + budget;
    // A resident watch holds the log: never wait on it (its cache is fresh).
    let store = match store::TopicStore::open(&ctx.home, ctx.topic) {
        Ok(store) => Arc::new(store),
        Err(e) => {
            tracing::debug!("the channel log is held by another wires process: {e:#}");
            return Ok(Refreshed::Locked);
        }
    };
    let mut keyring = Keyring::load(Arc::clone(&ctx.keystore))?;
    keyring.quiet = true;
    let me = &ctx.node;
    fold_store(&store, &mut keyring, me, dir);

    let mut book = PeerBook::open(&ctx.home, ctx.topic);
    for peer in &ctx.ticket_peers {
        book.record(peer.clone());
    }
    let bootstrap: Vec<TopicPeer> = book
        .list()
        .into_iter()
        .filter(|p| p.node != me.node_id())
        .collect();
    if bootstrap.is_empty() || until.is_some_and(|f| f(dir)) {
        return Ok(Refreshed::Read);
    }

    let node =
        match tokio::time::timeout_at(deadline, bind(ctx.node_config(Arc::clone(&store)))).await {
            Ok(node) => node?,
            Err(_) => return Ok(Refreshed::Read),
        };
    match tokio::time::timeout_at(deadline, node.join(ctx.topic, &bootstrap)).await {
        Ok(Ok((_sender, mut events))) => {
            // History first: whatever the peers hold that this log does not.
            if let Ok(Ok(caught)) = tokio::time::timeout_at(
                deadline,
                replay::catch_up_collect(
                    node.endpoint(),
                    node.admit(),
                    &store,
                    ctx.topic,
                    replay::REPLAY_LIMIT,
                ),
            )
            .await
            {
                // Re-keys this node missed while it was not running come
                // first: an announcement sealed under a key it lacks opens
                // once they are adopted (the same step `wires login` takes).
                let adopted = caught
                    .fresh
                    .iter()
                    .filter(|e| {
                        rekey::observe(e, &mut keyring, me, node.admit(), now_unix()).is_some()
                    })
                    .count();
                if adopted > 0 {
                    fold_store(&store, &mut keyring, me, dir);
                } else {
                    for envelope in &caught.fresh {
                        dir.observe_envelope(envelope, &mut keyring, me);
                    }
                }
            }
            // Then live, until the question is answered or the budget is
            // spent: an announcement answering a fresh login lands here.
            while until.is_some_and(|f| !f(dir)) {
                match tokio::time::timeout_at(deadline, events.recv()).await {
                    Ok(Some(topics::TopicEvent::Message(envelope))) => {
                        rekey::observe(&envelope, &mut keyring, me, node.admit(), now_unix());
                        let floor = node.admit().current_version().ok();
                        if matches!(
                            replay::ingest(&store, ctx.topic, &envelope, floor),
                            Ok(replay::Ingested::Inserted)
                        ) {
                            dir.observe_envelope(&envelope, &mut keyring, me);
                        }
                    }
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => break,
                }
            }
        }
        Ok(Err(e)) => tracing::debug!("joining the channel for the directory: {e:#}"),
        Err(_) => tracing::debug!("joining the channel for the directory timed out"),
    }
    if let Err(e) = node.shutdown().await {
        tracing::debug!("closing the directory's node: {e:#}");
    }
    Ok(Refreshed::Read)
}

/// The joined channel's context for a caller with `creds` (the keystore's
/// channel, peers and credentials; `--node-seed` etc. override).
pub(crate) fn caller_context(creds: &CredArgs) -> Result<TopicContext> {
    let args = TopicArgs {
        topic: String::new(),
        peer: Vec::new(),
        node_seed: creds.node_seed.clone(),
        node_seed_file: creds.node_seed_file.clone(),
        relay_url: creds.relay_url.clone(),
        membership: creds.membership.clone(),
        membership_file: creds.membership_file.clone(),
        inclusion_proof: creds.inclusion_proof.clone(),
        inclusion_proof_file: creds.inclusion_proof_file.clone(),
    };
    TopicContext::resolve(
        Arc::new(keystore::Keystore::resolve()?),
        keystore::home()?,
        &args,
    )
}

/// Unix milliseconds now.
fn now_ms() -> i64 {
    crate::host::audit::now_ms()
}

/// The directory for `ctx`'s channel: the cache if `until` already holds on
/// it, else refreshed (see [`refresh`]) and saved.
pub(crate) async fn fresh_directory(
    ctx: &TopicContext,
    budget: Duration,
    until: Until<'_>,
) -> Result<Directory> {
    let path = Directory::path(&ctx.home);
    let mut dir = Directory::load(&path, &ctx.name);
    if until.is_some_and(|f| f(&dir)) {
        return Ok(dir);
    }
    match refresh(ctx, &mut dir, budget, until).await? {
        Refreshed::Read => {
            if let Err(e) = dir.save(&path) {
                tracing::warn!("caching the directory: {e:#}");
            }
        }
        // The watch writes the cache; reload what it has now.
        Refreshed::Locked => dir = Directory::load(&path, &ctx.name),
    }
    Ok(dir)
}

/// `wires call`'s lookup: an alias in `tools.json`, else the channel
/// directory (see the module docs).
pub(crate) async fn resolve_tool(
    config: &ToolsConfig,
    query: &str,
    creds: &CredArgs,
) -> Result<RemoteTool> {
    if let Ok(alias) = crate::caller::call::lookup(config, query) {
        return Ok(alias.clone());
    }
    let ctx = match caller_context(creds) {
        Ok(ctx) => ctx,
        // Not on a channel: the alias file is all there is.
        Err(e) => {
            bail!("no tool named `{query}` in tools.json, and no channel to look it up on: {e:#}")
        }
    };
    let peers = PeerBook::open(&ctx.home, ctx.topic).list();
    let resolves = |dir: &Directory| {
        dir.resolve(query, now_ms(), &peers)
            .is_ok_and(|r| r.listed && !r.stale)
    };
    let dir = fresh_directory(&ctx, CATCH_UP_BUDGET, Some(&resolves)).await?;
    Ok(dir.resolve(query, now_ms(), &peers)?.tool)
}

/// `wires mcp`'s tool set: the aliases in `config`, then every tool the
/// channel shows this node (see [`Directory::visible_tools`]). Without a
/// joined channel, just the aliases.
pub(crate) async fn with_announced(mut config: ToolsConfig, creds: &CredArgs) -> ToolsConfig {
    let ctx = match caller_context(creds) {
        Ok(ctx) => ctx,
        Err(e) => {
            tracing::debug!("no channel for the directory: {e:#}");
            return config;
        }
    };
    let dir = match fresh_directory(&ctx, CATCH_UP_BUDGET, None).await {
        Ok(dir) => dir,
        Err(e) => {
            tracing::warn!("reading the channel directory: {e:#}");
            return config;
        }
    };
    let peers = PeerBook::open(&ctx.home, ctx.topic).list();
    let taken: BTreeSet<ToolName> = config.tools.iter().map(|t| t.name.clone()).collect();
    config
        .tools
        .extend(dir.visible_tools(now_ms(), &peers, &taken));
    config
}

/// `wires tools` with no subcommand: refresh from the channel, then list what
/// this node can run (and, on stderr, hosts that show it nothing).
pub(crate) async fn list_cmd(config: &ToolsConfig) -> Result<String> {
    let ctx = match caller_context(&CredArgs::default()) {
        Ok(ctx) => ctx,
        Err(e) if config.tools.is_empty() => {
            return Err(e.context("`wires tools` lists the tools announced on your channel"));
        }
        Err(_) => return Ok(crate::caller::tools::render_aliases(config)),
    };
    let dir = fresh_directory(&ctx, CATCH_UP_BUDGET, None).await?;
    let (mut text, note) = dir.render(now_ms());
    if let Some(note) = note {
        eprintln!("wires tools: {note}");
    }
    if !config.tools.is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&crate::caller::tools::render_aliases(config));
    }
    if text.is_empty() && dir.hosts.is_empty() {
        eprintln!(
            "wires tools: no host has announced on channel {:?} yet",
            ctx.name
        );
    }
    // An agent without a shell learns how to filter from the listing itself.
    if !text.is_empty() {
        text.push_str(&format!("\n# {}", crate::caller::shape::CALL_HINT));
    }
    Ok(text)
}

/// What a resident `wires watch` does with announcements: fold each into the
/// cache, so a cold `call` finds it without touching the log the watch holds.
pub(crate) struct DirectoryHook {
    /// `directory.json`.
    path: PathBuf,
    /// This node (announcements are opened as it).
    me: NodeIdentity,
    /// The cache, as last written.
    dir: Mutex<Directory>,
}

impl DirectoryHook {
    /// A hook for `ctx`'s channel.
    pub(crate) fn new(ctx: &TopicContext) -> Self {
        let path = Directory::path(&ctx.home);
        let dir = Directory::load(&path, &ctx.name);
        Self {
            path,
            me: NodeIdentity::from_seed(ctx.node.seed_bytes()),
            dir: Mutex::new(dir),
        }
    }

    /// Fold every announcement already in `store` (what a watch does at
    /// startup, since it prints only a bounded backfill).
    pub(crate) fn prime(&self, store: &store::TopicStore, keyring: &mut Keyring) {
        let mut dir = self.dir.lock().expect("directory poisoned");
        let before = dir.clone();
        fold_store(store, keyring, &self.me, &mut dir);
        if *dir != before
            && let Err(e) = dir.save(&self.path)
        {
            tracing::warn!("caching the directory: {e:#}");
        }
    }

    /// Fold one announcement `sender` published; write the cache if it
    /// changed anything.
    pub(crate) fn observe(&self, sender: NodeId, ann: &HostAnnouncement) {
        let mut dir = self.dir.lock().expect("directory poisoned");
        if dir.observe(sender, ann, &self.me)
            && let Err(e) = dir.save(&self.path)
        {
            tracing::warn!("caching the directory: {e:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{ListedTool, SealedListing};
    use proptest::prelude::*;

    fn id(seed: u8) -> NodeIdentity {
        NodeIdentity::from_seed([seed; 32])
    }

    fn listing(names: &[&str]) -> HostListing {
        HostListing {
            tools: names
                .iter()
                .map(|n| ListedTool {
                    name: ToolName::new(*n).unwrap(),
                    description: format!("{n} it"),
                })
                .collect(),
            addrs: vec!["127.0.0.1:7".parse().unwrap()],
            relay_url: None,
        }
    }

    /// An announcement by host `h` at `at` showing `me` the tools `names`.
    fn ann_for(h: u8, at: i64, me: &NodeIdentity, names: &[&str]) -> HostAnnouncement {
        let entry =
            SealedListing::seal(id(h).node_id(), at, &me.node_id(), &listing(names)).unwrap();
        HostAnnouncement::new(id(h).node_id(), at, 1_000, None, vec![entry])
    }

    fn dir_with(me: &NodeIdentity, anns: &[HostAnnouncement]) -> Directory {
        let mut dir = Directory {
            channel: Some("ops".into()),
            hosts: vec![],
        };
        for a in anns {
            dir.observe(a.node, a, me);
        }
        dir
    }

    fn host8(seed: u8) -> String {
        id(seed).node_id().hex()[..8].to_string()
    }

    #[test]
    fn a_name_one_host_lists_resolves_to_it() {
        let me = id(9);
        let dir = dir_with(&me, &[ann_for(1, 100, &me, &["db_query"])]);
        let r = dir.resolve("db_query", 100, &[]).unwrap();
        assert!(r.listed && !r.stale);
        assert_eq!(r.tool.description, "db_query it");
        let ToolTarget::Node { node, addrs, .. } = &r.tool.target else {
            unreachable!()
        };
        assert_eq!(*node, id(1).node_id());
        assert_eq!(addrs, &listing(&[]).addrs);
    }

    #[test]
    fn two_hosts_are_ambiguous_until_qualified() {
        let me = id(9);
        let dir = dir_with(
            &me,
            &[
                ann_for(1, 100, &me, &["db_query"]),
                ann_for(2, 100, &me, &["db_query"]),
            ],
        );
        let e = format!("{:#}", dir.resolve("db_query", 100, &[]).unwrap_err());
        assert!(e.contains("served by 2 hosts"), "{e}");
        assert!(e.contains(&format!("{}/db_query", host8(1))), "{e}");
        assert!(e.contains(&format!("{}/db_query", host8(2))), "{e}");
        let r = dir
            .resolve(&format!("{}/db_query", host8(2)), 100, &[])
            .unwrap();
        let ToolTarget::Node { node, .. } = r.tool.target else {
            unreachable!()
        };
        assert_eq!(node, id(2).node_id());
        assert_eq!(r.tool.name.as_str(), "db_query");
    }

    /// A stale host loses to a live one, is still used alone, and is marked.
    #[test]
    fn stale_hosts_step_aside() {
        let me = id(9);
        let dir = dir_with(
            &me,
            &[
                ann_for(1, 0, &me, &["db_query"]),
                ann_for(2, 3_000, &me, &["db_query"]),
            ],
        );
        let r = dir.resolve("db_query", 3_500, &[]).unwrap();
        let ToolTarget::Node { node, .. } = r.tool.target else {
            unreachable!()
        };
        assert_eq!(node, id(2).node_id(), "the live one");
        let only_stale = dir_with(&me, &[ann_for(1, 0, &me, &["db_query"])]);
        assert!(only_stale.resolve("db_query", 3_500, &[]).unwrap().stale);
        let (text, _) = only_stale.render(3_500);
        assert!(text.contains("(stale: last announced 3s ago)"), "{text}");
    }

    /// Not listed to me, one host known: dial it (it refuses with its
    /// reason). Several hosts: say so. None: say that.
    #[test]
    fn a_hidden_name_still_reaches_the_one_host() {
        let me = id(9);
        let other = id(8);
        // Sealed to someone else: this node sees the host, not the tool.
        let dir = dir_with(&me, &[ann_for(1, 100, &other, &["db_query"])]);
        assert!(dir.hosts[0].listing.tools.is_empty());
        let peers =
            vec![TopicPeer::new(id(1).node_id()).with_addrs(vec!["127.0.0.1:9".parse().unwrap()])];
        let r = dir.resolve("db_query", 100, &peers).unwrap();
        assert!(!r.listed);
        let ToolTarget::Node { addrs, .. } = &r.tool.target else {
            unreachable!()
        };
        assert_eq!(addrs, &peers[0].addrs, "dial hints from the join's peers");

        let two = dir_with(
            &me,
            &[
                ann_for(1, 100, &other, &["db_query"]),
                ann_for(2, 100, &other, &["x"]),
            ],
        );
        let e = format!("{:#}", two.resolve("db_query", 100, &[]).unwrap_err());
        assert!(e.contains("announces `db_query` to you"), "{e}");
        let e = format!(
            "{:#}",
            Directory::default()
                .resolve("db_query", 0, &[])
                .unwrap_err()
        );
        assert!(e.contains("no host has announced"), "{e}");
    }

    /// Only the host itself may announce itself, and an older announcement
    /// never replaces a newer one.
    #[test]
    fn observe_takes_only_the_hosts_own_and_newest() {
        let me = id(9);
        let mut dir = Directory::default();
        let newer = ann_for(1, 200, &me, &["a"]);
        assert!(!dir.observe(id(2).node_id(), &newer, &me), "wrong sender");
        assert!(dir.observe(id(1).node_id(), &newer, &me));
        assert!(!dir.observe(id(1).node_id(), &ann_for(1, 100, &me, &["b"]), &me));
        assert_eq!(dir.hosts[0].listing.tools[0].name.as_str(), "a");
        assert!(dir.observe(id(1).node_id(), &ann_for(1, 300, &me, &[]), &me));
        assert!(dir.hosts[0].listing.tools.is_empty(), "access withdrawn");
    }

    #[test]
    fn render_lists_tools_and_notes_silent_hosts() {
        let me = id(9);
        let dir = dir_with(
            &me,
            &[
                ann_for(1, 100, &me, &["db_query", "gh"]),
                ann_for(2, 100, &id(8), &["secret"]),
            ],
        );
        let (text, note) = dir.render(100);
        let h1 = host8(1);
        assert_eq!(
            text,
            format!("db_query  on {h1}  db_query it\ngh        on {h1}  gh it")
        );
        assert!(!text.contains("secret"));
        let note = note.unwrap();
        assert!(
            note.starts_with("1 host on channel \"ops\" announces nothing you may use"),
            "{note}"
        );
        assert!(note.contains(&host8(2)), "{note}");
    }

    #[test]
    fn visible_tools_qualify_shared_names_and_skip_aliases() {
        let me = id(9);
        let dir = dir_with(
            &me,
            &[
                ann_for(1, 100, &me, &["db_query", "gh"]),
                ann_for(2, 100, &me, &["db_query"]),
            ],
        );
        let taken = BTreeSet::from([ToolName::new("gh").unwrap()]);
        let tools = dir.visible_tools(100, &[], &taken);
        let names: BTreeSet<String> = tools.iter().map(|t| t.name.to_string()).collect();
        assert_eq!(
            names,
            BTreeSet::from([
                format!("db_query-{}", host8(1)),
                format!("db_query-{}", host8(2))
            ])
        );
        assert!(
            tools
                .iter()
                .all(|t| t.remote_tool.as_ref().unwrap().as_str() == "db_query")
        );
    }

    #[test]
    fn the_cache_round_trips_and_another_channel_starts_empty() {
        let me = id(9);
        let home = crate::testutil::temp_dir();
        let path = Directory::path(&home);
        let dir = dir_with(&me, &[ann_for(1, 100, &me, &["db_query"])]);
        dir.save(&path).unwrap();
        assert_eq!(Directory::load(&path, "ops"), dir);
        assert!(Directory::load(&path, "eng").hosts.is_empty());
        std::fs::write(&path, "not json").unwrap();
        assert!(Directory::load(&path, "ops").hosts.is_empty());
    }

    fn name() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9_]{0,12}"
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// Whatever one live host lists resolves to that host, by name and
        /// by its qualified form, and names it does not list never resolve
        /// as listed.
        #[test]
        fn listed_names_resolve_to_their_host(
            names in proptest::collection::btree_set(name(), 1..5),
            other in name(),
        ) {
            let me = id(9);
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            let dir = dir_with(&me, &[ann_for(1, 100, &me, &names)]);
            for n in &names {
                let r = dir.resolve(n, 100, &[]).unwrap();
                prop_assert!(r.listed);
                let q = dir.resolve(&format!("{}/{n}", host8(1)), 100, &[]).unwrap();
                prop_assert_eq!(q.tool.target, r.tool.target);
            }
            if !names.contains(&other.as_str()) {
                prop_assert!(!dir.resolve(&other, 100, &[]).unwrap().listed);
            }
        }
    }
}

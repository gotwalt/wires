//! `wires` — the multi-call CLI for the session layer.
//!
//! Offline admin (`keygen` / `grant` / `revoke` / `import`) is built from pure
//! functions over `library`; the network commands (`serve` / `connect`) run on
//! the iroh transport in [`transport`]. Secrets and the CRL resolve through
//! flag → env → `--…-file` → on-disk keystore (see [`keystore`]), so the
//! network commands work without seeds on the command line — and, once
//! `wires import` has installed an agent's credentials, `wires connect --ticket
//! <T>` needs no other flags, which is what lets it drop straight into an MCP
//! client's config as `"command": "wires"`.
//!
//! `connect` keeps stdout **byte-pure** (only the bridged session bytes): every
//! diagnostic goes to stderr, and the exit code carries the outcome —
//! the child's own code on success, [`EXIT_DENIED`] when the responder refused
//! the credentials, `1` for any local or transport failure.

mod admission;
mod audit;
mod call;
mod idp_view;
mod ipc;
mod jwks;
mod keystore;
mod login;
mod mcp;
mod render;
mod replay;
mod store;
mod tools;
mod topics;
mod transport;

/// The five money-shot integration tests of spec §9 — the whole stack over
/// hermetic loopback, in one place because none of them belongs to a single
/// module's seam.
///
/// Declared `#[cfg(test)]` rather than carrying an inner `#![cfg(test)]`: the
/// `srcs = glob(["*.rs"])` in `BUILD` hands `e2e.rs` to both the binary and the
/// test target, and gating the `mod` item is what keeps it out of the shipped
/// binary entirely instead of compiling to an empty module.
#[cfg(test)]
mod e2e;

/// A hermetic OIDC issuer for the `wires login` tests (card 04).
#[cfg(test)]
mod mock_idp;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::{ArgGroup, Args, Parser, Subcommand};
use library::{
    CapabilityTicket, ChainState, Crl, FabricKey, Grant, InclusionProof, Membership, NodeId,
    NodeIdentity, RosterHead, RosterVersion, Scope, SealedFabricKey, Seq, TopicEnvelope, TopicId,
    TopicPeer, TopicTicket,
};

/// wires: a capability-addressed stdio/MCP session layer.
#[derive(Parser)]
#[command(name = "wires", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate (or re-derive) the node + root keys and print their seeds + ids.
    Keygen(KeygenArgs),
    /// Mint a capability grant and print its base64 ticket.
    Grant(GrantArgs),
    /// Mint a fabric membership and print its base64 token.
    Member(MemberArgs),
    /// Author the fabric roster (add/remove members, sign a committed head).
    Roster(RosterArgs),
    /// Add a subject to the CRL (keystore by default) and print the result.
    Revoke(RevokeArgs),
    /// Install credentials (membership, inclusion proof, roster head, sealed
    /// fabric key) into the keystore.
    Import(ImportArgs),
    /// Responder: verify a grant, exec a command, bridge its stdio.
    Serve(ServeArgs),
    /// Dial a capability and pipe local stdio over the session.
    Connect(ConnectArgs),
    /// Publish a message to a topic (through a resident `wires tail`, or
    /// one-shot when none is running).
    Publish(PublishArgs),
    /// Join a topic and stream it: the resident node (store, mesh, admission,
    /// replay, control socket).
    Tail(TailArgs),
    /// Run a remote CLI from `tools.json`: stdio passes through, its exit
    /// code becomes ours, a refusal exits 77.
    Call(call::CallArgs),
    /// Serve the `tools.json` CLIs as MCP tools over stdio.
    Mcp(mcp::McpArgs),
    /// Edit `tools.json`: the local map of remote CLIs (add / list / rm).
    Tools(tools::ToolsArgs),
    /// Sign in with your IdP (OIDC), binding this node's key to your identity;
    /// with `--topic`, publish the claim for every reader to verify.
    Login(login::LoginArgs),
}

/// `keygen` arguments: optional seeds to re-derive, and whether to persist.
#[derive(Args)]
struct KeygenArgs {
    /// Hex 32-byte seed to use for the node key (else a random one is generated).
    #[arg(long)]
    node_seed: Option<String>,
    /// Hex 32-byte seed to use for the root key (else a random one is generated).
    #[arg(long)]
    root_seed: Option<String>,
    /// Also write the node key to the keystore (`node.seed`).
    #[arg(long)]
    save_node: bool,
    /// Also write the root key to the keystore (`root.seed`).
    #[arg(long)]
    save_root: bool,
    /// Overwrite existing keystore files when saving.
    #[arg(long)]
    force: bool,
}

/// `grant` arguments: the root key, who/what/where, and an expiry.
#[derive(Args)]
struct GrantArgs {
    /// Hex 32-byte seed of the root (signing) key. Falls back to `$WIRES_ROOT_SEED`,
    /// then `--root-seed-file`, then the keystore (`root.seed`).
    #[arg(long)]
    root_seed: Option<String>,
    /// Read the root key seed (hex) from this file instead of the keystore.
    #[arg(long)]
    root_seed_file: Option<PathBuf>,
    /// Hex node id of the subject this grant authorizes.
    #[arg(long)]
    subject: String,
    /// Hex node id of the responder to dial (the ticket target).
    #[arg(long)]
    target: String,
    /// Scope name to authorize (e.g. `tools.rg`).
    #[arg(long)]
    scope: String,
    /// Direct socket address where the target is reachable, embedded in the
    /// ticket so the dialer needs no discovery. Repeatable.
    #[arg(long = "addr")]
    addr: Vec<SocketAddr>,
    /// Relay URL to reach the target through, embedded in the ticket.
    #[arg(long)]
    relay_url: Option<String>,
    /// Seconds from now until expiry (mutually exclusive with `--not-after`).
    #[arg(long, conflicts_with = "not_after")]
    ttl: Option<i64>,
    /// Absolute expiry, unix seconds (mutually exclusive with `--ttl`).
    #[arg(long)]
    not_after: Option<i64>,
}

/// `member` arguments: the root key, who to include, and an expiry. All offline
/// (no network); the fabric id is the root's node id and is recoverable from the
/// minted token, so nothing else need cross machines.
#[derive(Args)]
struct MemberArgs {
    /// Hex 32-byte seed of the root (signing) key. Falls back to `$WIRES_ROOT_SEED`,
    /// then `--root-seed-file`, then the keystore (`root.seed`).
    #[arg(long)]
    root_seed: Option<String>,
    /// Read the root key seed (hex) from this file instead of the keystore.
    #[arg(long)]
    root_seed_file: Option<PathBuf>,
    /// Hex node id of the member this membership includes.
    #[arg(long)]
    subject: String,
    /// Seconds from now until expiry (mutually exclusive with `--not-after`).
    #[arg(long, conflicts_with = "not_after")]
    ttl: Option<i64>,
    /// Absolute expiry, unix seconds (mutually exclusive with `--ttl`).
    #[arg(long)]
    not_after: Option<i64>,
    /// Also write the minted membership to the keystore (`membership.json`).
    #[arg(long)]
    save: bool,
}

/// `roster` has four offline operations on the local `roster.json`.
#[derive(Args)]
struct RosterArgs {
    #[command(subcommand)]
    cmd: RosterCmd,
}

#[derive(Subcommand)]
enum RosterCmd {
    /// Add a member to the local roster (no signing).
    Add(RosterMemberArgs),
    /// Remove a member from the local roster (no signing).
    Remove(RosterMemberArgs),
    /// Bump the version, build the tree, sign a head, and emit per-member proofs.
    Commit(RosterCommitArgs),
    /// Print the current head token (from the keystore `roster-head.json`).
    Head,
}

/// `roster add` / `roster remove`: the member to (de)list and an optional fabric
/// override (defaults to the keystore root identity's node id).
#[derive(Args)]
struct RosterMemberArgs {
    /// Hex node id of the member to add/remove.
    #[arg(long)]
    member: String,
    /// Hex node id of the fabric (defaults to the keystore root key's node id),
    /// used only when creating a fresh `roster.json`.
    #[arg(long)]
    fabric: Option<String>,
}

/// `roster commit`: the root signing key, the head's expiry, and where to write
/// the emitted per-member proofs and sealed fabric keys.
#[derive(Args)]
struct RosterCommitArgs {
    /// Hex 32-byte seed of the root (signing) key. Falls back to env / file /
    /// keystore (`root.seed`).
    #[arg(long)]
    root_seed: Option<String>,
    /// Read the root key seed (hex) from this file instead of the keystore.
    #[arg(long)]
    root_seed_file: Option<PathBuf>,
    /// Seconds from now until the head expires (mutually exclusive with `--not-after`).
    #[arg(long, conflicts_with = "not_after")]
    ttl: Option<i64>,
    /// Absolute head expiry, unix seconds (mutually exclusive with `--ttl`).
    #[arg(long)]
    not_after: Option<i64>,
    /// Directory to write each member's `<node-id>.proof` and `<node-id>.key`
    /// tokens into. When omitted, both are printed to stdout.
    #[arg(long)]
    out: Option<PathBuf>,
}

/// `revoke` arguments: the subject to revoke and which CRL to extend.
///
/// With neither `--crl-json` nor `--crl-file`, the keystore's `crl.json` is read
/// and rewritten in place. `--crl-file` is read and rewritten in place;
/// `--crl-json` is a one-shot transform printed to stdout.
#[derive(Args)]
struct RevokeArgs {
    /// Hex node id of the subject to revoke.
    #[arg(long)]
    subject: String,
    /// Start from this CRL JSON literal and print the result (no file written).
    #[arg(long, conflicts_with = "crl_file")]
    crl_json: Option<String>,
    /// Read/update this CRL file in place (absent file = empty CRL).
    #[arg(long)]
    crl_file: Option<PathBuf>,
}

/// `import` arguments: any combination of the four credentials an agent
/// receives from its operator, inline or as a file.
///
/// This is the last provisioning step, and it is entirely offline. The operator
/// mints tokens (`wires member`, `wires roster commit --out DIR`) and hands them
/// over; the agent runs `wires import` **once**; after that `wires connect
/// --ticket <T>` needs no other flags — which is what makes `wires` usable as a
/// bare `command` in an MCP client config.
#[derive(Args)]
#[command(group(ArgGroup::new("creds").required(true).multiple(true)
    .args(["membership", "membership_file", "inclusion_proof", "inclusion_proof_file", "roster_head", "roster_head_file", "fabric_key", "fabric_key_file"])))]
struct ImportArgs {
    /// The base64 membership token to install as `membership.json`.
    #[arg(long, conflicts_with = "membership_file")]
    membership: Option<String>,
    /// Read the membership token from this file (e.g. the operator's output).
    #[arg(long)]
    membership_file: Option<PathBuf>,
    /// The base64 inclusion proof token to install as `inclusion-proof.json`.
    #[arg(long, conflicts_with = "inclusion_proof_file")]
    inclusion_proof: Option<String>,
    /// Read the inclusion proof from this file (`roster commit --out DIR` writes
    /// `<node-id>.proof`).
    #[arg(long)]
    inclusion_proof_file: Option<PathBuf>,
    /// The base64 roster head token to install as `roster-head.json`.
    #[arg(long, conflicts_with = "roster_head_file")]
    roster_head: Option<String>,
    /// Read the roster head token from this file.
    #[arg(long)]
    roster_head_file: Option<PathBuf>,
    /// The base64 sealed fabric key to open and install as `keyring/<version>.key`.
    #[arg(long, conflicts_with = "fabric_key_file")]
    fabric_key: Option<String>,
    /// Read the sealed fabric key from this file (`roster commit --out DIR`
    /// writes `<node-id>.key`).
    #[arg(long)]
    fabric_key_file: Option<PathBuf>,
    /// Install a roster head that is *older* than the one already stored.
    ///
    /// Refused by default: the stored head is a highest-seen watermark, and
    /// walking it backwards re-admits everyone the newer commit removed.
    #[arg(long)]
    force: bool,
}

/// `serve` arguments: the responder key, what it trusts, and the child to exec.
#[derive(Args)]
struct ServeArgs {
    /// Hex 32-byte seed of this responder's node key. Falls back to
    /// `$WIRES_NODE_SEED`, then `--node-seed-file`, then the keystore (`node.seed`).
    #[arg(long)]
    node_seed: Option<String>,
    /// Read the node key seed (hex) from this file instead of the keystore.
    #[arg(long)]
    node_seed_file: Option<PathBuf>,
    /// Hex node id of the trusted fabric root whose memberships and grants are
    /// honored.
    #[arg(long)]
    trust_root: String,
    /// The scope this responder serves; a grant's scope must match exactly. Omit
    /// for an inclusion-only responder (then `--allow-any-member` is required).
    /// Not used with `--expose`, where a grant must be scoped `tool:<name>` or
    /// `tool:*`.
    #[arg(long, conflicts_with_all = ["expose", "expose_file"])]
    scope: Option<String>,
    /// Serve any fabric member when no `--scope` is set (inclusion-only). An
    /// explicit acknowledgement of the authorization downgrade: the child execs
    /// for any member and must authorize from the injected identity.
    #[arg(long)]
    allow_any_member: bool,
    /// CRL JSON literal of revoked subjects (overrides `--crl-file` / keystore).
    #[arg(long, conflicts_with = "crl_file")]
    crl_json: Option<String>,
    /// Read the CRL from this file (else the keystore's `crl.json`, else empty).
    #[arg(long)]
    crl_file: Option<PathBuf>,
    /// Use a self-hosted relay at this URL instead of the n0 default.
    #[arg(long)]
    relay_url: Option<String>,
    /// The responder's own membership token, presented in the handshake ack so a
    /// ticket-less dialer can verify it. Falls back to `$WIRES_MEMBERSHIP`, then
    /// `--membership-file`, then the keystore (`membership.json`).
    #[arg(long)]
    membership: Option<String>,
    /// Read the responder's membership token from this file.
    #[arg(long)]
    membership_file: Option<PathBuf>,
    /// The signed roster head this responder enforces (inclusion proof required
    /// from callers). Falls back to `$WIRES_ROSTER_HEAD`, then
    /// `--roster-head-file`, then the keystore (`roster-head.json`, re-checked
    /// per connection — a head imported later enforces on the next dial, with
    /// no restart). With no head at all: membership + CRL + TTL only.
    #[arg(long)]
    roster_head: Option<String>,
    /// Read the roster head token from this file.
    #[arg(long)]
    roster_head_file: Option<PathBuf>,
    /// The responder's own inclusion proof token (optional; presented in the ack).
    #[arg(long)]
    inclusion_proof: Option<String>,
    /// Read the responder's inclusion proof from this file.
    #[arg(long)]
    inclusion_proof_file: Option<PathBuf>,
    /// Expose a CLI as a named tool: `NAME=COMMAND ARGS…` (repeatable). The
    /// command is split on ASCII whitespace — no quoting, no shell — and each
    /// call's arguments are appended to it. Callers need a grant scoped
    /// `tool:NAME` (or `tool:*`) unless `--allow-any-member`. For a SQL tool
    /// use sqlite3's `-safe` flag (3.37+), which disables dot-commands like
    /// `.shell`/`.system`: `--expose 'db_query=sqlite3 -safe -readonly orders.db'`.
    #[arg(long, value_name = "NAME=COMMAND")]
    expose: Vec<String>,
    /// Expose the tools in this JSON file, `{"NAME": ["program", "arg", …]}`,
    /// for argv that needs spaces. Combines with `--expose`.
    #[arg(long)]
    expose_file: Option<PathBuf>,
    /// Publish a record of every call (started, finished, denied) to this
    /// topic. The responder hosts the topic node itself — same endpoint, same
    /// key — so it must be a provisioned member of the channel (membership,
    /// inclusion proof, roster head and fabric key in the keystore).
    #[arg(long)]
    audit_topic: Option<String>,
    /// A base64 topic ticket to bootstrap the audit topic from (repeatable).
    #[arg(long = "audit-peer", requires = "audit_topic")]
    audit_peer: Vec<String>,
    /// The command (program + args) to exec per session, after `--`
    /// (single-command mode; mutually exclusive with `--expose`).
    #[arg(
        last = true,
        required_unless_present_any = ["expose", "expose_file"],
        conflicts_with_all = ["expose", "expose_file"]
    )]
    command: Vec<String>,
}

/// `connect` arguments: the dialer key, its membership, and where to dial.
///
/// Exactly one of `--ticket` (a scoped session, grant from the ticket) or
/// `--target` (an inclusion-only session, no grant) is required.
#[derive(Args)]
#[command(group(ArgGroup::new("dest").required(true).args(["ticket", "target"])))]
struct ConnectArgs {
    /// Hex 32-byte seed of this dialer's node key. Falls back to
    /// `$WIRES_NODE_SEED`, then `--node-seed-file`, then the keystore (`node.seed`).
    #[arg(long)]
    node_seed: Option<String>,
    /// Read the node key seed (hex) from this file instead of the keystore.
    #[arg(long)]
    node_seed_file: Option<PathBuf>,
    /// Use a self-hosted relay at this URL instead of the n0 default.
    #[arg(long)]
    relay_url: Option<String>,
    /// The base64 capability ticket (target + scope + grant) for a scoped
    /// session. Mutually exclusive with `--target`.
    #[arg(long)]
    ticket: Option<String>,
    /// Hex node id of the target for an inclusion-only session (membership only,
    /// no grant). Mutually exclusive with `--ticket`.
    #[arg(long)]
    target: Option<String>,
    /// Direct socket address where the `--target` is reachable, so the dialer
    /// needs no discovery. Repeatable; only used with `--target`.
    #[arg(long = "addr")]
    addr: Vec<SocketAddr>,
    /// The base64 membership token to present. Falls back to `$WIRES_MEMBERSHIP`,
    /// then `--membership-file`, then the keystore (`membership.json`).
    #[arg(long)]
    membership: Option<String>,
    /// Read the membership token from this file instead of the keystore.
    #[arg(long)]
    membership_file: Option<PathBuf>,
    /// The inclusion proof token to present (required by a head-enforcing
    /// responder). Falls back to `$WIRES_INCLUSION_PROOF`, then
    /// `--inclusion-proof-file`, then the keystore (`inclusion-proof.json`).
    #[arg(long)]
    inclusion_proof: Option<String>,
    /// Read the inclusion proof token from this file.
    #[arg(long)]
    inclusion_proof_file: Option<PathBuf>,
    /// Call this tool on a multi-tool responder (`wires serve --expose`).
    #[arg(long)]
    tool: Option<String>,
    /// Arguments for `--tool`, after `--`; appended to the tool's command on
    /// the responder, never through a shell.
    #[arg(last = true, requires = "tool")]
    args: Vec<String>,
}

/// The arguments `publish` and `tail` share: which topic, who to bootstrap
/// from, and the same credential resolution `connect` uses (spec §7.2).
///
/// The topic is a *name*, not an id: every member derives the same
/// [`TopicId`] from its own membership's fabric plus this name, so there is no
/// `topic create` and nothing to register (spec §1).
#[derive(Args, Clone, Debug, Default)]
struct TopicArgs {
    /// The topic name, derived under this node's fabric (e.g. `ops`).
    topic: String,
    /// A base64 topic ticket to bootstrap from. Repeatable; every peer in every
    /// ticket is tried, and the ones that answer are remembered.
    #[arg(long = "peer")]
    peer: Vec<String>,
    /// Hex 32-byte seed of this node's key. Falls back to `$WIRES_NODE_SEED`,
    /// then `--node-seed-file`, then the keystore (`node.seed`).
    #[arg(long)]
    node_seed: Option<String>,
    /// Read the node key seed (hex) from this file instead of the keystore.
    #[arg(long)]
    node_seed_file: Option<PathBuf>,
    /// Use a self-hosted relay at this URL instead of the n0 default.
    #[arg(long)]
    relay_url: Option<String>,
    /// The base64 membership token to use. Falls back to the keystore
    /// (`membership.json`); its `fabric` is the topic's fabric root.
    #[arg(long, conflicts_with = "membership_file")]
    membership: Option<String>,
    /// Read the membership token from this file instead of the keystore.
    #[arg(long)]
    membership_file: Option<PathBuf>,
    /// The base64 inclusion proof presented at admission. Falls back to the
    /// keystore (`inclusion-proof.json`).
    #[arg(long, conflicts_with = "inclusion_proof_file")]
    inclusion_proof: Option<String>,
    /// Read the inclusion proof from this file instead of the keystore.
    #[arg(long)]
    inclusion_proof_file: Option<PathBuf>,
}

/// `tail` arguments: the shared topic arguments plus what to print.
#[derive(Args)]
struct TailArgs {
    #[command(flatten)]
    common: TopicArgs,
    /// How many stored messages to print before going live.
    #[arg(long, default_value_t = DEFAULT_BACKFILL)]
    backfill: usize,
    /// Print NDJSON objects instead of `HH:MM:SS <sender8> <text>` lines.
    #[arg(long)]
    json: bool,
}

/// `publish` arguments: the shared topic arguments plus the message.
///
/// With no `--message`, stdin is read and **each line is published
/// separately** — so `tail -f log | wires publish ops` is a live feed and not
/// one enormous message.
#[derive(Args)]
struct PublishArgs {
    #[command(flatten)]
    common: TopicArgs,
    /// The message text. Omit to publish one message per line of stdin.
    #[arg(long, short = 'm')]
    message: Option<String>,
}

/// The four lines `keygen` prints: each key's seed and derived node id (hex).
struct KeygenOutput {
    node_seed: String,
    node_id: String,
    root_seed: String,
    root_id: String,
}

impl fmt::Display for KeygenOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "node_seed {}", self.node_seed)?;
        writeln!(f, "node_id {}", self.node_id)?;
        writeln!(f, "root_seed {}", self.root_seed)?;
        write!(f, "root_id {}", self.root_id)
    }
}

/// Generate or re-derive the node + root identities and report their material.
///
/// A seed argument (hex) re-derives that key deterministically; `None`
/// generates a fresh one from OS entropy.
fn run_keygen(node_seed: Option<&str>, root_seed: Option<&str>) -> library::Result<KeygenOutput> {
    let node = match node_seed {
        Some(s) => NodeIdentity::from_seed_hex(s)?,
        None => NodeIdentity::generate(),
    };
    let root = match root_seed {
        Some(s) => NodeIdentity::from_seed_hex(s)?,
        None => NodeIdentity::generate(),
    };
    Ok(KeygenOutput {
        node_seed: node.seed_hex(),
        node_id: node.node_id().hex(),
        root_seed: root.seed_hex(),
        root_id: root.node_id().hex(),
    })
}

/// Mint a grant binding `subject` to `scope` until `not_after`, then pack it
/// into a [`CapabilityTicket`] for `target` and return its base64 text.
fn run_grant(
    root: &NodeIdentity,
    subject: &str,
    target: &str,
    scope: &str,
    not_after: i64,
    addrs: Vec<SocketAddr>,
    relay_url: Option<String>,
) -> library::Result<String> {
    let subject = NodeId::from_hex(subject)?;
    let target = NodeId::from_hex(target)?;
    let scope = Scope::new(scope);
    let grant = Grant::mint(root, subject, scope.clone(), not_after)?;
    CapabilityTicket::new(target, scope, grant)
        .with_addrs(addrs)
        .with_relay_url(relay_url)
        .encode()
}

/// Mint a fabric membership binding `subject` to the root's fabric until
/// `not_after`. The fabric id is `root.node_id()` and is recoverable from the
/// returned credential.
fn run_member(
    root: &NodeIdentity,
    subject: &str,
    issued: i64,
    not_after: i64,
) -> library::Result<Membership> {
    let subject = NodeId::from_hex(subject)?;
    Membership::mint(root, subject, issued, not_after)
}

/// Insert `subject` into `existing` (or a fresh CRL when `None`/blank) and
/// return the updated CRL as JSON. Idempotent in `subject`.
fn run_revoke(existing: Option<&str>, subject: &str) -> library::Result<String> {
    let mut crl = match existing {
        Some(s) if !s.trim().is_empty() => Crl::from_json(s)?,
        _ => Crl::new(),
    };
    crl.insert(NodeId::from_hex(subject)?);
    crl.to_json()
}

/// Resolve the grant's absolute expiry from the mutually-exclusive `--ttl` /
/// `--not-after` flags, requiring exactly one.
fn resolve_not_after(
    ttl: Option<i64>,
    not_after: Option<i64>,
    now_unix: i64,
) -> Result<i64, String> {
    match (ttl, not_after) {
        (Some(_), Some(_)) => Err("pass only one of --ttl or --not-after".into()),
        (Some(ttl), None) => Ok(now_unix.saturating_add(ttl)),
        (None, Some(na)) => Ok(na),
        (None, None) => Err("specify --ttl <seconds> or --not-after <unix>".into()),
    }
}

/// Exit code for an authorization refusal by the responder (sysexits
/// `EX_NOPERM`), distinct from 1 = local/transport failure. An MCP client that
/// wraps `wires connect` can tell "you are not allowed" apart from "the network
/// is down" without parsing text.
const EXIT_DENIED: i32 = 77;

/// Current unix time in seconds.
pub(crate) fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `serve`: bind, verify membership (and, when scoped, a grant) against the
/// trust root, exec + bridge. A missing `--scope` requires `--allow-any-member`.
async fn serve_cmd(a: ServeArgs) -> anyhow::Result<()> {
    init_logging();
    let node = keystore::node_identity(a.node_seed.as_deref(), a.node_seed_file.as_deref())?;
    let trust_root = NodeId::from_hex(&a.trust_root)?;
    // `--audit-topic`: resolve the channel credentials *before* serving, so a
    // responder that is not a member of its audit channel fails closed here.
    let audit_ctx = match a.audit_topic.as_deref() {
        Some(name) => Some(audit_context_in(
            Arc::new(keystore::Keystore::resolve()?),
            keystore::home()?,
            &a,
            name,
            node.node_id(),
            trust_root,
        )?),
        None => None,
    };
    let tools = transport::exposed_tools(&a.expose, a.expose_file.as_deref())?;
    // Multi-tool: grants are per tool (`tool:<name>` / `tool:*`), so the served
    // scope only says "a grant is required".
    let scope = if tools.is_empty() {
        a.scope.map(Scope::new)
    } else {
        (!a.allow_any_member).then(|| Scope::new(transport::TOOL_SCOPE_ANY))
    };
    if tools.is_empty() && scope.is_none() && !a.allow_any_member {
        anyhow::bail!(
            "refusing to serve: pass --scope <name>, or --allow-any-member for an \
             inclusion-only responder (any fabric member may connect)"
        );
    }
    // Credential *sources*, not values: a file-backed CRL or head is re-read on
    // every connection, so `wires revoke` / `wires roster commit` take effect on
    // the next dial without bouncing this process.
    let crl = keystore::crl_source(a.crl_json.as_deref(), a.crl_file.clone())?;
    let membership = keystore::membership(a.membership.as_deref(), a.membership_file.as_deref())?;
    let head = keystore::roster_head_source(a.roster_head.as_deref(), a.roster_head_file.clone())?;
    let proof = keystore::inclusion_proof(
        a.inclusion_proof.as_deref(),
        a.inclusion_proof_file.as_deref(),
    )?;
    let (sink, records) = match audit_ctx {
        Some(_) => {
            let (sink, rx) = transport::AuditSink::channel(audit::AUDIT_QUEUE);
            (Some(sink), Some(rx))
        }
        None => (None, None),
    };
    let config = transport::ServeConfig {
        tools,
        audit: sink,
        trust_root,
        scope,
        crl,
        head,
        membership,
        proof,
        command: a.command,
    };
    match (audit_ctx, records) {
        (Some(ctx), Some(records)) => {
            tracing::info!(topic = %ctx.name, "serving the session ALPN on the audit topic's node");
            let hosted = audit::Hosted {
                session: transport::SessionProtocol(Arc::new(config)),
                records,
            };
            run_tail(&ctx, 0, false, Some(hosted)).await
        }
        _ => transport::serve(node, config, a.relay_url.as_deref()).await,
    }
}

/// Resolve `serve --audit-topic <name>` into the same [`TopicContext`] `wires
/// tail` would build, failing (with the `wires import` remedy) when this node
/// is not a provisioned member of the channel, or when the channel's fabric is
/// not the one this responder trusts.
///
/// The testable form (the `_in` pattern): `serve` passes the resolved keystore
/// and home.
fn audit_context_in(
    ks: Arc<keystore::Keystore>,
    home: PathBuf,
    a: &ServeArgs,
    name: &str,
    node: NodeId,
    trust_root: NodeId,
) -> anyhow::Result<TopicContext> {
    let args = TopicArgs {
        topic: name.to_string(),
        peer: a.audit_peer.clone(),
        node_seed: a.node_seed.clone(),
        node_seed_file: a.node_seed_file.clone(),
        relay_url: a.relay_url.clone(),
        membership: a.membership.clone(),
        membership_file: a.membership_file.clone(),
        inclusion_proof: a.inclusion_proof.clone(),
        inclusion_proof_file: a.inclusion_proof_file.clone(),
    };
    let ctx = TopicContext::resolve(ks, home, &args)
        .context("--audit-topic needs this responder to be a member of the channel")?;
    if ctx.node.node_id() != node {
        anyhow::bail!("--audit-topic resolved a different node key than the one serving");
    }
    if ctx.fabric_root != trust_root {
        anyhow::bail!(
            "--audit-topic: this node's membership is in fabric {}, but --trust-root is {}",
            ctx.fabric_root.hex(),
            trust_root.hex()
        );
    }
    Ok(ctx)
}

/// Local consistency checks run before dialing: the ticket's grant and the
/// membership must both name *this* keystore's node.
///
/// Catches the two most common misconfigurations — a ticket copied to the wrong
/// machine, a membership from another fabric — without a network round-trip, so
/// they never masquerade as a refusal by the responder.
fn preflight(node: NodeId, membership: &Membership, grant: Option<&Grant>) -> Result<(), String> {
    if let Some(grant) = grant
        && grant.subject != node
    {
        return Err(format!(
            "this ticket was issued to node {}, but this keystore's node is {} — use the \
             keystore that requested the ticket (or re-issue it)",
            grant.subject.hex(),
            node.hex()
        ));
    }
    if membership.member != node {
        return Err(format!(
            "this membership was issued to node {}, but this keystore's node is {} — import \
             the membership minted for this node (`wires import --membership …`)",
            membership.member.hex(),
            node.hex()
        ));
    }
    Ok(())
}

/// `connect`: present the dialer's membership, dial the target (from a ticket or
/// `--target`), present the ticket's grant when scoped, and bridge local stdio.
/// Returns the child's exit code.
async fn connect_cmd(a: ConnectArgs) -> anyhow::Result<i32> {
    init_quiet_logging();
    let node = keystore::node_identity(a.node_seed.as_deref(), a.node_seed_file.as_deref())?;
    let membership = keystore::membership(a.membership.as_deref(), a.membership_file.as_deref())?;
    let proof = keystore::inclusion_proof(
        a.inclusion_proof.as_deref(),
        a.inclusion_proof_file.as_deref(),
    )?;

    // A bare `--target` (no ticket) is a ticket-less session: verify the
    // responder's ack before streaming stdin.
    let ticketless = a.ticket.is_none();

    // Resolve where to dial and whether a grant rides along. The clap group
    // guarantees exactly one of `--ticket` / `--target`.
    let (target_id, addrs, grant, ticket_relay) = match a.ticket.as_deref() {
        Some(text) => {
            let t = CapabilityTicket::decode(text)
                .context("--ticket (is the pasted base64 ticket complete?)")?;
            (t.target, t.addrs, Some(t.grant), t.relay_url)
        }
        None => {
            let id = NodeId::from_hex(
                a.target
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("--ticket or --target is required"))?,
            )?;
            (id, a.addr.clone(), None, None)
        }
    };
    // Fail locally, before any network I/O, when the credentials on hand were
    // not issued to this node.
    preflight(node.node_id(), &membership, grant.as_ref()).map_err(anyhow::Error::msg)?;

    // `--relay-url` overrides the ticket's relay hint; both feed the dialed
    // address and the endpoint's relay configuration.
    let relay = a.relay_url.or(ticket_relay);
    let target = transport::endpoint_addr(&target_id, &addrs, relay.as_deref())?;
    if let Some(tool) = a.tool {
        let invocation = library::Invocation {
            tool: library::ToolName::new(tool.as_str())
                .with_context(|| format!("--tool {tool:?}"))?,
            argv: library::Argv::new(a.args).context("--tool arguments")?,
        };
        let endpoint = transport::bind(&node, relay.as_deref()).await?;
        return transport::call_on(
            endpoint,
            target,
            membership,
            grant,
            proof,
            ticketless,
            invocation,
            tokio::io::stdin(),
            tokio::io::stdout(),
            tokio::io::stderr(),
        )
        .await;
    }
    transport::connect_io(
        node,
        target,
        membership,
        grant,
        proof,
        ticketless,
        relay.as_deref(),
        tokio::io::stdin(),
        tokio::io::stdout(),
        tokio::io::stderr(),
    )
    .await
}

/// Build a multi-threaded tokio runtime for the network subcommands.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("building tokio runtime")
}

/// Initialize tracing for the network subcommands, writing to **stderr** so it
/// never corrupts `connect`'s piped stdout.
///
/// The default filter is [`LOG_FILTER`]: wires' own startup / accept /
/// reject lines print, while iroh's relay and discovery chatter stays out of an
/// MCP client's server-log pane. `$RUST_LOG` overrides it entirely (e.g.
/// `RUST_LOG=iroh=debug`).
fn init_logging() {
    init_logging_with(LOG_FILTER);
}

/// [`init_logging`] for the dialing commands (`call`, `mcp`, `connect`), whose
/// stderr belongs to the remote CLI: [`QUIET_LOG_FILTER`] by default, so a
/// successful call leaves nothing of wires' own on it.
fn init_quiet_logging() {
    init_logging_with(QUIET_LOG_FILTER);
}

/// The default log filter of the long-running commands.
const LOG_FILTER: &str = "warn,wires=info";

/// The default log filter of the dialing commands: only warnings from wires
/// itself, and iroh (plus `iroh_*`, which the target prefix also matches)
/// entirely off — its endpoint teardown logs `ERROR … relay_recv_channel
/// closed` at the end of every perfectly normal call.
const QUIET_LOG_FILTER: &str = "warn,iroh=off";

/// Install the stderr subscriber with `default` unless `$RUST_LOG` is set.
fn init_logging_with(default: &str) {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default)),
        )
        .with_writer(std::io::stderr)
        .try_init();
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        // Offline admin commands print to stdout (or fail with a message).
        Command::Keygen(_)
        | Command::Grant(_)
        | Command::Member(_)
        | Command::Revoke(_)
        | Command::Import(_)
        | Command::Roster(_) => match cli_admin(cli.command) {
            Ok(out) => println!("{out}"),
            Err(e) => {
                eprintln!("wires: {e}");
                std::process::exit(1);
            }
        },
        Command::Serve(a) => {
            if let Err(e) = runtime().block_on(serve_cmd(a)) {
                eprintln!("wires: {e:#}");
                std::process::exit(1);
            }
        }
        Command::Connect(a) => match runtime().block_on(connect_cmd(a)) {
            Ok(code) => std::process::exit(code),
            Err(e) => exit_with(e),
        },
        // Both topic commands keep stdout for messages and report the same way
        // `connect` does — including exit 77 when the refusal came from the
        // roster rather than from the network.
        Command::Publish(a) => {
            if let Err(e) = runtime().block_on(publish_cmd(a)) {
                exit_with(e);
            }
        }
        Command::Tail(a) => {
            if let Err(e) = runtime().block_on(tail_cmd(a)) {
                exit_with(e);
            }
        }
        Command::Call(a) => {
            init_quiet_logging();
            match runtime().block_on(call::call_cmd(a)) {
                Ok(code) => std::process::exit(code),
                Err(e) => exit_with(e),
            }
        }
        Command::Mcp(a) => {
            init_quiet_logging();
            if let Err(e) = runtime().block_on(mcp::mcp_cmd(a)) {
                eprintln!("wires: {e:#}");
                std::process::exit(1);
            }
        }
        Command::Tools(a) => match tools::run_tools_cmd(a) {
            Ok(out) if out.is_empty() => {}
            Ok(out) => println!("{out}"),
            Err(e) => {
                eprintln!("wires: {e:#}");
                std::process::exit(1);
            }
        },
        Command::Login(a) => {
            if let Err(e) = runtime().block_on(login::login_cmd(a)) {
                exit_with(e);
            }
        }
    }
}

/// Report a network-command failure and exit.
///
/// An authorization refusal is its own outcome: print the responder's own
/// words and exit [`EXIT_DENIED`], not the generic 1. The downcast walks
/// anyhow's context chain, so a `Denied` wrapped in "peer X refused this node's
/// admission" still lands here.
fn exit_with(e: anyhow::Error) -> ! {
    if let Some(d) = e.downcast_ref::<transport::Denied>() {
        eprintln!("wires: denied by responder: {}", d.reason());
        std::process::exit(EXIT_DENIED);
    }
    eprintln!("wires: {e:#}");
    std::process::exit(1);
}

/// Run an offline admin subcommand, returning its stdout text.
fn cli_admin(command: Command) -> Result<String, String> {
    match command {
        Command::Keygen(a) => run_keygen_cmd(a).map_err(stringify),
        Command::Grant(a) => {
            let root = keystore::root_identity(a.root_seed.as_deref(), a.root_seed_file.as_deref())
                .map_err(stringify)?;
            let not_after = resolve_not_after(a.ttl, a.not_after, now_unix())?;
            run_grant(
                &root,
                &a.subject,
                &a.target,
                &a.scope,
                not_after,
                a.addr,
                a.relay_url,
            )
            .map_err(stringify)
        }
        Command::Member(a) => run_member_cmd(a),
        Command::Roster(a) => run_roster_cmd(a),
        Command::Revoke(a) => run_revoke_cmd(a).map_err(stringify),
        Command::Import(a) => run_import_cmd(a).map_err(|e| format!("{e:#}")),
        Command::Serve(_)
        | Command::Connect(_)
        | Command::Publish(_)
        | Command::Tail(_)
        | Command::Call(_)
        | Command::Mcp(_)
        | Command::Tools(_)
        | Command::Login(_) => {
            unreachable!("handled in main")
        }
    }
}

/// `member`: mint a membership for `--subject`, optionally persist it to the
/// keystore (`membership.json`), and return its base64 token.
fn run_member_cmd(a: MemberArgs) -> Result<String, String> {
    let root = keystore::root_identity(a.root_seed.as_deref(), a.root_seed_file.as_deref())
        .map_err(stringify)?;
    let not_after = resolve_not_after(a.ttl, a.not_after, now_unix())?;
    let membership = run_member(&root, &a.subject, now_unix(), not_after).map_err(stringify)?;
    if a.save {
        let ks = keystore::Keystore::resolve().map_err(stringify)?;
        ks.save_membership(&membership).map_err(stringify)?;
    }
    membership.encode().map_err(stringify)
}

/// `roster`: dispatch the four offline roster operations.
fn run_roster_cmd(a: RosterArgs) -> Result<String, String> {
    match a.cmd {
        RosterCmd::Add(m) => roster_edit(&m, true).map_err(stringify),
        RosterCmd::Remove(m) => roster_edit(&m, false).map_err(stringify),
        RosterCmd::Commit(c) => roster_commit(c).map_err(stringify),
        RosterCmd::Head => roster_head_token().map_err(stringify),
    }
}

/// Add or remove `member` in the keystore `roster.json`, persisting the result.
/// Creates the roster (fabric = `--fabric` or the root key's node id) on first use.
fn roster_edit(a: &RosterMemberArgs, add: bool) -> anyhow::Result<String> {
    let ks = keystore::Keystore::resolve()?;
    let member = NodeId::from_hex(&a.member)?;
    let mut roster = match ks.read_roster()? {
        Some(r) => r,
        None => {
            let fabric = match a.fabric.as_deref() {
                Some(hex) => NodeId::from_hex(hex)?,
                None => keystore::root_identity(None, None)
                    .context("resolving fabric id from the root key (or pass --fabric)")?
                    .node_id(),
            };
            library::Roster::new(fabric)
        }
    };
    let changed = if add {
        roster.insert(member)
    } else {
        roster.remove(&member)
    };
    ks.save_roster(&roster)?;
    Ok(format!(
        "{} {} ({} members, version {})",
        if !changed {
            "no change for"
        } else if add {
            "added"
        } else {
            "removed"
        },
        member.hex(),
        roster.members.len(),
        roster.version.0,
    ))
}

/// Sign a head over the current `roster.json`, persist the bumped roster and the
/// head, and emit each member's proof (to `--out` or stdout). Returns the head token.
fn roster_commit(a: RosterCommitArgs) -> anyhow::Result<String> {
    roster_commit_in(&keystore::Keystore::resolve()?, a)
}

/// [`roster_commit`] against an explicit keystore (the testable form).
///
/// Each commit also mints one fresh [`FabricKey`] — the data key every envelope
/// published under this roster version is encrypted with — and seals a copy to
/// each member beside their proof. Rotating on every commit is what makes
/// removal *confidential* immediately: a member dropped by this commit is not a
/// recipient of this key, so nothing published after it is readable by them,
/// whatever the network does about eviction.
///
/// The root does **not** retain the plaintext key: it is generated here, sealed
/// N times, and dropped. The authority that decides who is in the fabric is
/// deliberately not an authority that can read the fabric's traffic.
fn roster_commit_in(ks: &keystore::Keystore, a: RosterCommitArgs) -> anyhow::Result<String> {
    let root = keystore::root_identity(a.root_seed.as_deref(), a.root_seed_file.as_deref())?;
    let not_after =
        resolve_not_after(a.ttl, a.not_after, now_unix()).map_err(anyhow::Error::msg)?;
    let mut roster = ks.read_roster()?.ok_or_else(|| {
        anyhow::anyhow!("no roster.json; run `wires roster add --member <id>` first")
    })?;

    let (head, proofs) = roster.commit(&root, now_unix(), not_after)?;

    // Minted once per commit, sealed per member, never written down here.
    let key = FabricKey::generate();

    // Seal to *every* member before anything is persisted. Sealing is the one
    // step here that can fail on operator input — `SealedFabricKey::seal`
    // refuses a weak or undecompressable member key (spec §3), and nothing
    // upstream validates the 64 hex characters typed into `roster add`. Doing
    // it first keeps a bad member from advancing the roster version and
    // publishing a head that no member holds a key for: the command errors
    // with the keystore untouched, the operator fixes the member, and re-runs.
    let sealed: Vec<_> = proofs
        .iter()
        .map(|(member, proof)| {
            let sealed = SealedFabricKey::seal(&root, *member, head.version, &key)
                .with_context(|| format!("sealing the fabric key to {}", member.hex()))?;
            anyhow::Ok((member, proof, sealed))
        })
        .collect::<anyhow::Result<_>>()?;

    ks.save_roster(&roster)?; // persist the version bump
    ks.save_roster_head(&head)?;

    let mut lines = Vec::new();
    for (member, proof, sealed) in &sealed {
        for (kind, token) in [("proof", proof.encode()?), ("key", sealed.encode()?)] {
            match a.out.as_deref() {
                Some(dir) => {
                    std::fs::create_dir_all(dir)
                        .with_context(|| format!("creating {}", dir.display()))?;
                    let path = dir.join(format!("{}.{kind}", member.hex()));
                    std::fs::write(&path, &token)
                        .with_context(|| format!("writing {}", path.display()))?;
                    lines.push(format!("{kind} {} -> {}", member.hex(), path.display()));
                }
                None => lines.push(format!("{kind} {} {token}", member.hex())),
            }
        }
    }
    let head_token = head.encode()?;
    Ok(format!(
        "committed roster version {} ({} members, each with a proof and a sealed fabric key)\
         \nhead {}\n{}",
        head.version.0,
        proofs.len(),
        head_token,
        lines.join("\n")
    ))
}

/// Print the current head token from the keystore `roster-head.json`.
fn roster_head_token() -> anyhow::Result<String> {
    let ks = keystore::Keystore::resolve()?;
    let head = ks
        .read_roster_head()?
        .ok_or_else(|| anyhow::anyhow!("no roster-head.json; run `wires roster commit` first"))?;
    head.encode().map_err(Into::into)
}

/// Read a credential token from an inline flag or a file, trimming whitespace.
/// `None` when neither was supplied.
fn token_arg(
    inline: Option<&str>,
    file: Option<&Path>,
    flag: &str,
) -> anyhow::Result<Option<String>> {
    if let Some(text) = inline {
        return Ok(Some(text.trim().to_string()));
    }
    match file {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("{flag}-file: reading {}", path.display()))?;
            Ok(Some(text.trim().to_string()))
        }
        None => Ok(None),
    }
}

/// `import`: decode each supplied credential and write it into the keystore
/// under the name the network commands look for. Returns one `wrote <path>`
/// line per installed credential.
fn run_import_cmd(a: ImportArgs) -> anyhow::Result<String> {
    run_import_in(&keystore::Keystore::resolve()?, a)
}

/// [`run_import_cmd`] against an explicit keystore (the testable form).
///
/// The credentials are installed in dependency order: the membership first,
/// because a sealed fabric key is verified against *its* fabric root, so
/// `wires import --membership <m> --fabric-key <k>` works as one command on a
/// blank keystore.
fn run_import_in(ks: &keystore::Keystore, a: ImportArgs) -> anyhow::Result<String> {
    let mut lines = Vec::new();

    if let Some(text) = token_arg(
        a.membership.as_deref(),
        a.membership_file.as_deref(),
        "--membership",
    )? {
        let membership = Membership::decode(&text).context("--membership")?;
        lines.push(format!(
            "wrote {}",
            ks.save_membership(&membership)?.display()
        ));
    }
    if let Some(text) = token_arg(
        a.inclusion_proof.as_deref(),
        a.inclusion_proof_file.as_deref(),
        "--inclusion-proof",
    )? {
        let proof = InclusionProof::decode(&text).context("--inclusion-proof")?;
        lines.push(format!(
            "wrote {}",
            ks.save_inclusion_proof(&proof)?.display()
        ));
    }
    if let Some(text) = token_arg(
        a.roster_head.as_deref(),
        a.roster_head_file.as_deref(),
        "--roster-head",
    )? {
        let head = RosterHead::decode(&text).context("--roster-head")?;
        // Monotone, like the admission path's compare-and-swap (spec §2.2). The
        // stored head is what the running tail enforces on every handshake and
        // every watchdog pass, so importing an older one immediately downgrades
        // the live roster and re-admits members a later commit removed — and a
        // head token is public, freely copyable, and held by every past member,
        // so "paste the head you were given" is a realistic thing to induce an
        // operator to do. There is no reason to walk it backwards except to undo
        // a mistake, which is what `--force` is for.
        match ks.read_roster_head()? {
            Some(stored) if head.version < stored.version && !a.force => anyhow::bail!(
                "--roster-head: refusing to install roster version {} over the stored version {}: \
                 a head only ever moves forward (pass --force if you really mean to roll it back)",
                head.version.0,
                stored.version.0
            ),
            _ => {}
        }
        lines.push(format!("wrote {}", ks.save_roster_head(&head)?.display()));
    }
    if let Some(text) = token_arg(
        a.fabric_key.as_deref(),
        a.fabric_key_file.as_deref(),
        "--fabric-key",
    )? {
        lines.push(format!("wrote {}", import_fabric_key(ks, &text)?.display()));
    }
    Ok(lines.join("\n"))
}

/// Open the sealed fabric key `token` as this node and install the plaintext in
/// the keyring, returning the written path.
///
/// The trust anchor is the installed membership's `fabric`: the same root that
/// vouches for this node's *presence* in the fabric is the only one whose keys
/// it will install, so a key token pasted from a stranger's fabric is refused
/// rather than silently added to the keyring. The member binding (this node is
/// the sealed recipient) and the root signature are checked by
/// [`SealedFabricKey::open`] itself.
fn import_fabric_key(ks: &keystore::Keystore, token: &str) -> anyhow::Result<PathBuf> {
    let sealed = SealedFabricKey::decode(token).context("--fabric-key")?;
    let membership = ks.read_membership()?.ok_or_else(|| {
        anyhow::anyhow!(
            "--fabric-key: no membership installed, so there is no fabric root to check the key \
             against; import the membership first (`wires import --membership <token>`, or pass \
             both in one command) — looked for {}",
            ks.path("membership.json").display()
        )
    })?;
    let node = keystore::node_identity_in(ks)?;
    if sealed.member != node.node_id() {
        anyhow::bail!(
            "--fabric-key: sealed to {} but this node is {}; ask the operator for this node's own \
             <node-id>.key from `wires roster commit --out DIR`",
            sealed.member.hex(),
            node.node_id().hex()
        );
    }
    let key = sealed.open(&node, membership.fabric).with_context(|| {
        format!(
            "--fabric-key: opening the roster version {} key against fabric {}",
            sealed.version.0,
            membership.fabric.hex()
        )
    })?;
    ks.save_fabric_key(sealed.version, &key)
}

/// Render any error as a string for the admin-command error channel.
fn stringify<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// `keygen`: generate/re-derive keys, optionally persist them, and print.
fn run_keygen_cmd(a: KeygenArgs) -> anyhow::Result<String> {
    let out = run_keygen(a.node_seed.as_deref(), a.root_seed.as_deref())?;
    if a.save_node || a.save_root {
        let ks = keystore::Keystore::resolve()?;
        if a.save_node {
            ks.save_node(&NodeIdentity::from_seed_hex(&out.node_seed)?, a.force)?;
        }
        if a.save_root {
            ks.save_root(&NodeIdentity::from_seed_hex(&out.root_seed)?, a.force)?;
        }
    }
    Ok(out.to_string())
}

/// `revoke`: insert `subject` into the chosen CRL and persist it in place
/// (keystore by default, or `--crl-file`), or transform a `--crl-json` literal.
fn run_revoke_cmd(a: RevokeArgs) -> anyhow::Result<String> {
    if let Some(json) = a.crl_json.as_deref() {
        return Ok(run_revoke(Some(json), &a.subject)?);
    }
    if let Some(path) = a.crl_file.as_deref() {
        let start = keystore::read_crl_text(path)?;
        let out = run_revoke(start.as_deref(), &a.subject)?;
        keystore::write_crl_text(path, &out)?;
        return Ok(out);
    }
    let ks = keystore::Keystore::resolve()?;
    let start = ks.read_crl_json()?;
    let out = run_revoke(start.as_deref(), &a.subject)?;
    ks.save_crl_json(&out)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Topics: `wires tail` and `wires publish` (spec §7)
// ---------------------------------------------------------------------------

/// How many stored messages `wires tail` prints before it goes live.
const DEFAULT_BACKFILL: usize = 200;

/// How long a one-shot `wires publish` waits for its first mesh neighbor before
/// giving up and storing the message locally.
///
/// A bound, not a sleep: the wait ends on the first
/// [`TopicEvent::NeighborUp`](crate::topics::TopicEvent::NeighborUp), and this
/// is only how long "nobody is there" takes to establish.
const PUBLISH_NEIGHBOR_WAIT: Duration = Duration::from_secs(15);

/// How long a one-shot `wires publish` stays up after broadcasting, so gossip
/// can actually put the bytes on the wire before the endpoint closes.
const PUBLISH_LINGER: Duration = Duration::from_secs(1);

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
/// Half of [`ADMIT_REFRESH`](crate::admission::ADMIT_REFRESH), so two attempts
/// fit in the window before an admission actually expires and the far side's
/// watchdog closes the connection.
const READMIT_INTERVAL: Duration = Duration::from_secs(admission::ADMIT_REFRESH.as_secs() / 2);

/// How long an operation waits for another process to release the topic log's
/// exclusive redb lock.
///
/// `wires tail` and `wires publish` both open the same file, and the window
/// between them is routine: a login script that starts a tail and publishes in
/// the next line, or a tail restarting while a one-shot publish is lingering.
/// Without a wait, whichever loses fails hard — and if the *tail* loses, a
/// routine publish killed the resident node.
const STORE_LOCK_WAIT: Duration = Duration::from_secs(20);

/// How many times a streaming `wires publish` retries one line before dropping
/// it and moving on to the next.
const PUBLISH_ATTEMPTS: usize = 3;

/// How long a streaming `wires publish` waits before reconnecting to a tail that
/// just refused it or hung up.
const PUBLISH_RETRY_DELAY: Duration = Duration::from_millis(500);

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
/// `wires import`; a peer whose own `roster-head.json` is briefly unreadable
/// answers `responder configuration error`. Exiting on the first of those turns
/// somebody else's misconfiguration into this node's death.
const DENIAL_STRIKES: usize = 3;

/// Everything the topic commands resolve *before* touching the network
/// (spec §7.2).
///
/// The preflight exists so that a missing credential is a local error naming
/// the command that fixes it, rather than a QUIC dial that eventually fails
/// with something about a handshake. Five things must be on hand — a node key,
/// a membership, an inclusion proof, a roster head, and at least one fabric key
/// — and every one of them has a one-line remedy.
struct TopicContext {
    /// This node's signing identity (also the endpoint's key).
    node: NodeIdentity,
    /// The membership whose `fabric` is the trusted root here.
    membership: Membership,
    /// This node's inclusion proof, presented at every admission.
    proof: InclusionProof,
    /// Where the roster head is re-read from, per admission and per watchdog
    /// pass. Armed: preflight proved a head exists, so a later missing one
    /// fails closed.
    head_source: Arc<transport::HeadSource>,
    /// The keystore the keyring, the head, and adopted heads live in.
    keystore: Arc<keystore::Keystore>,
    /// The wires home — the parent of `topics/` and `run/`.
    home: PathBuf,
    /// The topic name as typed.
    name: String,
    /// The derived topic id.
    topic: TopicId,
    /// `membership.fabric`: the root every signature is checked against.
    fabric_root: NodeId,
    /// Peers named by `--peer` tickets.
    ticket_peers: Vec<TopicPeer>,
    /// A self-hosted relay, if one was configured.
    relay_url: Option<String>,
}

impl fmt::Debug for TopicContext {
    /// Names the topic and the fabric, never the identity: this struct holds
    /// the node's signing key, and a `Debug` that prints it would put a seed in
    /// a log line the first time something goes wrong.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TopicContext")
            .field("name", &self.name)
            .field("topic", &self.topic.hex())
            .field("fabric_root", &self.fabric_root.hex())
            .field("node", &self.node.node_id().hex())
            .field("home", &self.home)
            .field("ticket_peers", &self.ticket_peers.len())
            .field("relay_url", &self.relay_url)
            .finish_non_exhaustive()
    }
}

impl TopicContext {
    /// Resolve every credential the topic commands need against `ks`, or fail
    /// with a message naming the `wires` command that supplies what is missing.
    ///
    /// The testable form (the `_in` pattern): `wires tail` and `wires publish`
    /// call it with the resolved keystore and home.
    fn resolve(
        ks: Arc<keystore::Keystore>,
        home: PathBuf,
        a: &TopicArgs,
    ) -> anyhow::Result<TopicContext> {
        if a.topic.trim().is_empty() {
            anyhow::bail!("the topic name is empty; pass one, e.g. `wires tail ops`");
        }
        let node = match (a.node_seed.as_deref(), a.node_seed_file.as_deref()) {
            (Some(hex), _) => NodeIdentity::from_seed_hex(hex).context("--node-seed")?,
            (None, Some(path)) => keystore::read_identity_file(path)?,
            (None, None) => keystore::node_identity_in(&ks)?,
        };
        let membership = match token_arg(
            a.membership.as_deref(),
            a.membership_file.as_deref(),
            "--membership",
        )? {
            Some(text) => Membership::decode(&text).context("--membership")?,
            None => ks.read_membership()?.ok_or_else(|| {
                anyhow::anyhow!(
                    "no membership: run `wires import --membership <token>` with the token your \
                     operator minted (looked for {})",
                    ks.path("membership.json").display()
                )
            })?,
        };
        // The same two consistency checks `connect` runs, for the same reason:
        // credentials issued to another node must not masquerade as a network
        // failure later.
        preflight(node.node_id(), &membership, None).map_err(anyhow::Error::msg)?;

        let proof = match token_arg(
            a.inclusion_proof.as_deref(),
            a.inclusion_proof_file.as_deref(),
            "--inclusion-proof",
        )? {
            Some(text) => InclusionProof::decode(&text).context("--inclusion-proof")?,
            None => ks.read_inclusion_proof()?.ok_or_else(|| {
                anyhow::anyhow!(
                    "no inclusion proof: topics admit peers by roster inclusion, so this node \
                     needs its own proof — run `wires import --inclusion-proof-file \
                     <node-id>.proof` from `wires roster commit --out DIR` (looked for {})",
                    ks.path("inclusion-proof.json").display()
                )
            })?,
        };
        let head = ks.read_roster_head()?.ok_or_else(|| {
            anyhow::anyhow!(
                "no roster head: admission checks every peer's proof against a signed head, so \
                 this node needs the current one — run `wires import --roster-head <token>` \
                 (looked for {})",
                ks.path("roster-head.json").display()
            )
        })?;
        if ks.latest_fabric_key()?.is_none() {
            anyhow::bail!(
                "no fabric key in the keyring: topics are end-to-end encrypted, so a member with \
                 no key can neither publish nor read — run `wires import --fabric-key-file \
                 <node-id>.key` from `wires roster commit --out DIR` (looked in {})",
                ks.keyring_dir().display()
            );
        }

        let fabric_root = membership.fabric;
        let topic = TopicId::derive(fabric_root, &a.topic);
        let mut ticket_peers = Vec::new();
        for text in &a.peer {
            let ticket = TopicTicket::decode(text.trim())
                .context("--peer (is the pasted base64 ticket complete?)")?;
            if ticket.fabric != fabric_root {
                anyhow::bail!(
                    "--peer: this ticket is for fabric {}, but this node's membership is in \
                     fabric {}; a ticket from another fabric can never be admitted",
                    ticket.fabric.hex(),
                    fabric_root.hex()
                );
            }
            if ticket.name != a.topic {
                anyhow::bail!(
                    "--peer: this ticket is for topic {:?}, not {:?}; the peers on it are on a \
                     different mesh",
                    ticket.name,
                    a.topic
                );
            }
            ticket_peers.extend(ticket.peers);
        }
        tracing::debug!(
            topic = %topic.hex(),
            head = head.version.0,
            peers = ticket_peers.len(),
            "preflight ok"
        );
        Ok(TopicContext {
            node,
            membership,
            proof,
            head_source: Arc::new(transport::HeadSource::Keystore {
                path: ks.path("roster-head.json"),
                // Seen: a head that disappears later must fail closed, not
                // silently drop back to admitting nobody's proof.
                armed: std::sync::atomic::AtomicBool::new(true),
            }),
            keystore: ks,
            home,
            name: a.topic.clone(),
            topic,
            fabric_root,
            ticket_peers,
            relay_url: a.relay_url.clone(),
        })
    }

    /// The node config for this context's topic.
    fn node_config(&self, store: Arc<store::TopicStore>) -> topics::TopicNodeConfig {
        let mut cfg = topics::TopicNodeConfig::new(
            self.topic,
            self.fabric_root,
            Arc::clone(&self.head_source),
            self.proof.clone(),
            Arc::clone(&self.keystore),
            store,
        );
        cfg.relay_url = self.relay_url.clone();
        cfg
    }

    /// This topic's control socket path.
    fn socket_path(&self) -> PathBuf {
        ipc::socket_path(&self.home, self.topic)
    }
}

// ---------------------------------------------------------------------------
// Printing
// ---------------------------------------------------------------------------

/// The keys a tail opens messages with, reloaded when an unknown version shows
/// up.
///
/// Envelopes are storable before their key arrives (spec §4.1), so an unknown
/// `key_version` is not an error: the message is in the log, and the display
/// heals the moment `wires import --fabric-key …` lands — which is why a miss
/// re-reads the keyring before giving up. The warning is **once per version**,
/// because the alternative is one line of stderr per message for as long as the
/// key is missing.
struct Keyring {
    /// Where the keyring is re-read from.
    keystore: Arc<keystore::Keystore>,
    /// Versions this tail holds keys for.
    keys: BTreeMap<RosterVersion, FabricKey>,
    /// Versions already complained about.
    warned: BTreeSet<RosterVersion>,
}

impl Keyring {
    /// Load the installed keyring.
    fn load(keystore: Arc<keystore::Keystore>) -> anyhow::Result<Self> {
        let keys = keystore.read_keyring()?;
        Ok(Self {
            keystore,
            keys,
            warned: BTreeSet::new(),
        })
    }

    /// Decrypt `envelope`, or `None` when this node holds no key for it.
    fn open(&mut self, envelope: &TopicEnvelope) -> Option<Vec<u8>> {
        let version = envelope.key_version;
        if !self.keys.contains_key(&version) {
            // A key imported since startup is the common case here.
            match self.keystore.read_keyring() {
                Ok(keys) => self.keys = keys,
                Err(e) => tracing::warn!("re-reading the keyring: {e:#}"),
            }
        }
        match self.keys.get(&version) {
            Some(key) => match envelope.open(key) {
                Ok(plaintext) => Some(plaintext),
                Err(e) => {
                    tracing::warn!(
                        sender = %envelope.sender.hex(),
                        seq = envelope.seq.0,
                        version = version.0,
                        "stored but undecryptable: {e:#}"
                    );
                    None
                }
            },
            None => {
                if self.warned.insert(version) {
                    eprintln!(
                        "wires tail: no key for roster version {} — those messages are stored but \
                         not shown; run `wires import --fabric-key-file <node-id>.key` for that \
                         commit and they appear",
                        version.0
                    );
                }
                None
            }
        }
    }
}

/// How a tail renders a message on **stdout**.
///
/// stdout is byte-pure message lines and nothing else — every diagnostic in
/// this file goes to stderr or through [`init_logging`] — so a tail can be
/// piped into a file, a pager, or another program without a filter.
struct Printer {
    /// NDJSON instead of the human line.
    json: bool,
}

/// One `--json` output record: the machine-readable form of a message line.
#[derive(serde::Serialize)]
struct JsonLine {
    /// The sender's claimed unix timestamp (informational, spec §4.1).
    ts: i64,
    /// The sender's full node id, hex.
    sender: String,
    /// The message's sequence in that sender's chain.
    seq: u64,
    /// The decrypted UTF-8 text (lossy for non-UTF-8 payloads). Absent when
    /// the text is a [`ChannelRecord`](library::ChannelRecord).
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    /// The parsed record, when the text is one (see [`render`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    record: Option<library::ChannelRecord>,
}

impl Printer {
    /// Render one message, or nothing when no key opens it.
    ///
    /// Called only for an envelope whose append reported
    /// [`Appended::Inserted`](crate::store::Appended) — which is what makes
    /// deduplication across live gossip, replay, and restart structural rather
    /// than a remembered set of ids (spec §7).
    fn emit(&self, envelope: &TopicEnvelope, keyring: &mut Keyring) {
        let Some(plaintext) = keyring.open(envelope) else {
            return;
        };
        let text = String::from_utf8_lossy(&plaintext);
        let line = self.render(envelope, &text);
        let mut out = std::io::stdout().lock();
        // Piped stdout is block-buffered, so an unflushed tail looks hung.
        if writeln!(out, "{line}").and_then(|()| out.flush()).is_err() {
            // A closed stdout (the pager quit) is not this tail's problem to
            // report on every message.
            tracing::debug!("stdout closed");
        }
    }

    /// The exact text of one output line (the testable half of
    /// [`emit`](Self::emit)).
    ///
    /// A message whose text is a [`ChannelRecord`](library::ChannelRecord)
    /// renders through [`render::record_line`] (or, with `--json`, as the
    /// parsed `record` object instead of `text`).
    fn render(&self, envelope: &TopicEnvelope, text: &str) -> String {
        let record = library::ChannelRecord::parse(text);
        if self.json {
            let line = JsonLine {
                ts: envelope.timestamp,
                sender: envelope.sender.hex(),
                seq: envelope.seq.0,
                text: record.is_none().then(|| text.to_string()),
                record,
            };
            serde_json::to_string(&line).unwrap_or_else(|e| format!("{{\"err\":\"{e}\"}}"))
        } else {
            let body = match &record {
                Some(record) => render::record_line(record),
                None => text.to_string(),
            };
            format!(
                "{} {} {body}",
                format_clock(envelope.timestamp),
                short_id(envelope.sender)
            )
        }
    }
}

/// `HH:MM:SS` **UTC** for a unix timestamp.
///
/// UTC and not local time on purpose: the timestamp is sender-chosen and
/// unverifiable (spec §4.1), so two members reading the same transcript should
/// at least see the same clock. Dateless because a tail is a live feed; the
/// full timestamp is one `--json` away.
fn format_clock(ts: i64) -> String {
    let secs = ts.rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// The first 8 hex characters of a node id — enough to tell members apart in a
/// transcript, short enough to leave room for the message.
fn short_id(node: NodeId) -> String {
    let hex = node.hex();
    hex[..8.min(hex.len())].to_string()
}

// ---------------------------------------------------------------------------
// Persisted peers
// ---------------------------------------------------------------------------

/// The peers this node knows on a topic, persisted across restarts.
///
/// There is no discovery service (spec §10): a tail that is restarted with no
/// `--peer` must still find its way back to the mesh, so every peer learned
/// from a ticket or from a `NeighborUp` is written to
/// `topics/<topic-hex>.peers.json`. Hints only — admission still decides who is
/// in — so a stale file costs a failed dial, never an admission.
struct PeerBook {
    /// Where the list is persisted.
    path: PathBuf,
    /// Known peers by node id; a hint with addresses replaces one without.
    peers: HashMap<NodeId, TopicPeer>,
}

impl PeerBook {
    /// Load the persisted peers for `topic` (an unreadable file is a warning
    /// and an empty book — a corrupt hint list must not stop a tail).
    fn open(home: &Path, topic: TopicId) -> Self {
        let path = peers_path(home, topic);
        let peers = match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<Vec<TopicPeer>>(&text) {
                Ok(list) => list.into_iter().map(|p| (p.node, p)).collect(),
                Err(e) => {
                    tracing::warn!(path = %path.display(), "ignoring an unreadable peer list: {e}");
                    HashMap::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => {
                tracing::warn!(path = %path.display(), "ignoring an unreadable peer list: {e}");
                HashMap::new()
            }
        };
        Self { path, peers }
    }

    /// Record `peer`, returning whether anything changed.
    ///
    /// A hint that carries addresses wins over one that does not: the ticket
    /// form knows where the peer was, and a `NeighborUp` only knows who it is.
    fn record(&mut self, peer: TopicPeer) -> bool {
        match self.peers.get(&peer.node) {
            Some(held) if held == &peer => false,
            Some(held)
                if peer.addrs.is_empty() && peer.relay_url.is_none() && !held.addrs.is_empty() =>
            {
                false
            }
            _ => {
                self.peers.insert(peer.node, peer);
                true
            }
        }
    }

    /// The known peers, in node-id order (so the file is stable).
    fn list(&self) -> Vec<TopicPeer> {
        let mut peers: Vec<_> = self.peers.values().cloned().collect();
        peers.sort_by_key(|p| p.node);
        peers
    }

    /// Persist the list (best effort: a tail that cannot write its hints is
    /// still a working tail).
    fn save(&self) {
        if let Err(e) = self.try_save() {
            tracing::warn!(path = %self.path.display(), "could not persist the peer list: {e:#}");
        }
    }

    fn try_save(&self) -> anyhow::Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let text = serde_json::to_string_pretty(&self.list())?;
        std::fs::write(&self.path, text)
            .with_context(|| format!("writing {}", self.path.display()))?;
        Ok(())
    }
}

/// Where a topic's persisted peer hints live.
fn peers_path(home: &Path, topic: TopicId) -> PathBuf {
    home.join("topics")
        .join(format!("{}.peers.json", topic.hex()))
}

// ---------------------------------------------------------------------------
// The single sequence allocator
// ---------------------------------------------------------------------------

/// Allocate this node's next sequence on `topic`, seal `text` under `key`, and
/// append it — the one place a message is minted (spec §7).
///
/// Sequence and previous-hash both come from the store's chain state, inside
/// the process that holds the store's exclusive lock, which is what makes "one
/// allocator per (node, topic)" structural rather than a convention. A
/// [`Duplicate`](crate::store::Appended::Duplicate) here would mean two
/// allocators raced, so it is an error, not a shrug.
fn append_local(
    store: &store::TopicStore,
    node: &NodeIdentity,
    topic: TopicId,
    version: RosterVersion,
    key: &FabricKey,
    text: &str,
    now: i64,
) -> anyhow::Result<TopicEnvelope> {
    let state = store
        .chain_state(node.node_id())
        .context("reading this node's chain state")?;
    let seq = match state {
        None => Seq::ZERO,
        Some(state) => state.seq.checked_next().ok_or_else(|| {
            anyhow::anyhow!("this node's chain on the topic is full (sequence u64::MAX)")
        })?,
    };
    let envelope = TopicEnvelope::seal(
        node,
        topic,
        seq,
        library::next_prev_hash(state),
        version,
        key,
        now,
        text.as_bytes(),
    )
    .context("sealing the message")?;
    match store.append(&envelope)? {
        store::Appended::Inserted => Ok(envelope),
        store::Appended::Duplicate => anyhow::bail!(
            "sequence {} was already stored for this node: another process is allocating \
             sequences on this topic",
            seq.0
        ),
    }
}

// ---------------------------------------------------------------------------
// `wires tail`
// ---------------------------------------------------------------------------

/// `tail`: preflight, then run the resident node.
async fn tail_cmd(a: TailArgs) -> anyhow::Result<()> {
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
/// [`Denied`](crate::transport::Denied) so `main` can exit 77.
///
/// `hosted` is `serve --audit-topic`'s addition: the session ALPN rides this
/// node's router, and call records enter the loop through the same publish
/// queue as the control socket's requests (see [`audit`]).
async fn run_tail(
    ctx: &TopicContext,
    backfill: usize,
    json: bool,
    hosted: Option<audit::Hosted>,
) -> anyhow::Result<()> {
    let printer = Printer { json };
    let mut keyring = Keyring::load(Arc::clone(&ctx.keystore))?;
    let store = Arc::new(open_topic_store(&ctx.home, ctx.topic, STORE_LOCK_WAIT).await?);

    // 1. What is already known, before anything touches the network. Printed
    //    from the log, so a restart shows the same transcript the last run did.
    for envelope in store.read_backfill(backfill)? {
        printer.emit(&envelope, &mut keyring);
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
    let (records, session) = match hosted {
        Some(h) => (Some(h.records), Some(h.session)),
        None => (None, None),
    };
    if let Some(session) = session {
        cfg.protocols.push((transport::ALPN, session.into()));
    }
    let node = topics::TopicNode::spawn(&ctx.node, cfg).await?;
    let socket_path = ctx.socket_path();
    tail_banner(&node, ctx, &socket_path);

    // 4. The control socket, **before** the network join. The join dials every
    //    peer in the book, which is seconds at best; a `wires publish` in that
    //    window used to find no socket, fall through to the one-shot path, and
    //    collide with this process on the topic log's exclusive redb lock —
    //    killing whichever lost. Bound first and the publish simply queues.
    let socket = ipc::ControlSocket::bind(&socket_path).await?;
    let (tx, mut requests) = tokio::sync::mpsc::channel(CONTROL_QUEUE);
    let forwarder = records.map(|rx| tokio::spawn(audit::forward(rx, tx.clone())));
    let server = socket.spawn(tx);

    // 5. The mesh — which is where a revoked node finds out (exit 77).
    let (mut sender, mut events) = node.join(ctx.topic, &book.list()).await?;

    // 6. Whatever the peers have that this node does not.
    catch_up_and_print(&node, &printer, &mut keyring).await;

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
    let mut catchup_at: Option<tokio::time::Instant> = Some(deadline(CATCHUP_INTERVAL));
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

            // A publish from `wires publish`, allocated and sealed here — the
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
                        printer.emit(&envelope, &mut keyring);
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
                    match ingest_live(&node, &store, ctx.topic, &envelope) {
                        Ok(replay::Ingested::Inserted) => printer.emit(&envelope, &mut keyring),
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
                if catchup_at.is_some() =>
            {
                catchup_at = None;
                catch_up_and_print(&node, &printer, &mut keyring).await;
                // Always re-armed: every other trigger is edge-driven, and a
                // gap whose only holder is asleep needs a pass that is not.
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

    eprintln!("wires tail: shutting down");
    server.abort();
    if let Some(forwarder) = forwarder {
        forwarder.abort();
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
struct Refusals {
    /// How many rounds in a row ended in nothing but refusals.
    consecutive: usize,
}

impl Refusals {
    /// Record a round that ended in refusals only; `true` once that has
    /// happened [`DENIAL_STRIKES`] times in a row.
    fn refused(&mut self) -> bool {
        self.consecutive += 1;
        self.consecutive >= DENIAL_STRIKES
    }

    /// Record any evidence that this node is still in the roster.
    fn admitted(&mut self) {
        self.consecutive = 0;
    }
}

/// Ingest a live gossip message under this node's current epoch floor.
///
/// The floor is re-read per message for the same reason the admission handler
/// re-reads the head per handshake: a `wires import` of a newer head must take
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
fn arm(slot: &mut Option<tokio::time::Instant>, delay: Duration) {
    let at = deadline(delay);
    *slot = Some(match *slot {
        Some(existing) if existing <= at => existing,
        _ => at,
    });
}

/// Open the topic log, waiting out an exclusive redb lock held by another
/// process for up to `wait`.
///
/// redb locks the file for the life of the handle, and two `wires` commands
/// legitimately want it seconds apart — a tail starting while a one-shot publish
/// lingers, a publish landing while a tail is coming up. Failing immediately
/// makes the loser's work disappear (and, when the loser is the tail, takes the
/// resident node with it); waiting makes the overlap a pause.
async fn open_topic_store(
    home: &Path,
    topic: TopicId,
    wait: Duration,
) -> anyhow::Result<store::TopicStore> {
    let until = tokio::time::Instant::now() + wait;
    let mut warned = false;
    loop {
        match store::TopicStore::open(home, topic) {
            Ok(store) => return Ok(store),
            Err(e) if tokio::time::Instant::now() < until => {
                if !warned {
                    warned = true;
                    tracing::info!(
                        "the topic log is locked by another wires process; waiting up to {}s: {e:#}",
                        wait.as_secs()
                    );
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// `now + delay` as a tokio deadline.
fn deadline(delay: Duration) -> tokio::time::Instant {
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
/// `wires tail <topic> --peer <token>` with it and the two meshes become one.
fn tail_banner(node: &topics::TopicNode, ctx: &TopicContext, socket: &Path) {
    eprintln!(
        "wires tail: topic {:?} ({}) as {}",
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
            "wires tail: fabric {}, roster version {version}",
            ctx.membership.fabric.hex()
        ),
        None => eprintln!("wires tail: fabric {}", ctx.membership.fabric.hex()),
    }
    // Not enforced here — topic admission is roster inclusion, not membership
    // TTL — but an expired membership is the usual reason a peer's `serve`
    // refuses this node, so it is worth saying out loud once.
    if ctx.membership.not_after < now_unix() {
        eprintln!(
            "wires tail: warning — this node's membership expired at {}; ask the operator to \
             re-mint it (`wires member --subject {} --ttl …`)",
            ctx.membership.not_after,
            ctx.node.node_id().hex()
        );
    }
    eprintln!("wires tail: control socket {}", socket.display());
    match node.ticket(&ctx.name).and_then(|t| Ok(t.encode()?)) {
        Ok(token) => eprintln!("share to bootstrap: {token}"),
        Err(e) => eprintln!("wires tail: could not build this node's ticket: {e:#}"),
    }
}

/// Seal, append, and broadcast one message from the tail loop.
///
/// The fabric key is re-read per publish, not cached, so a `wires import
/// --fabric-key …` after a `roster commit` takes effect on the next message
/// with no restart. A broadcast failure is **not** an error: the message is
/// already in the log and replay will carry it, so the publisher gets its
/// sequence and a warning goes to the log.
async fn publish_from_tail(
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

/// The fabric key to publish under, refusing a superseded one.
///
/// Re-read per publish, not cached, so a `wires import --fabric-key …` after a
/// `roster commit` takes effect on the next message with no restart.
///
/// The version check is the publish-side half of the epoch floor
/// ([`replay::ingest`]): once the roster has moved, a message sealed under the
/// previous commit's key is refused at ingest by every peer that holds the new
/// head. Sealing it anyway would put a line in this node's log that no one else
/// will ever accept — a silent one-way loss. Failing here instead names the one
/// command that fixes it.
fn current_fabric_key(ks: &keystore::Keystore) -> anyhow::Result<(RosterVersion, FabricKey)> {
    let (version, key) = ks.latest_fabric_key()?.ok_or_else(|| {
        anyhow::anyhow!(
            "no fabric key in the keyring; run `wires import --fabric-key-file <node-id>.key`"
        )
    })?;
    if let Some(head) = ks.read_roster_head()?
        && version < head.version
    {
        anyhow::bail!(
            "this node's newest fabric key is for roster version {}, but the roster is at version \
             {}: a message sealed under a superseded key is refused by every peer that holds the \
             current head — run `wires import --fabric-key-file <node-id>.key` from the latest \
             `wires roster commit --out DIR`",
            version.0,
            head.version.0
        );
    }
    Ok((version, key))
}

/// Run a catch-up pass and print whatever it inserted.
///
/// The printing is a before/after diff of the per-publisher high-water marks:
/// [`catch_up`](crate::replay::catch_up) ingests straight into the store, and
/// what it *inserted* is exactly what the marks moved over — which keeps the
/// "print on `Inserted`" rule intact without threading a callback through
/// replay.
async fn catch_up_and_print(node: &topics::TopicNode, printer: &Printer, keyring: &mut Keyring) {
    // The node's own log, never a second handle: `catch_up` ingests into the
    // store the replay server reads, and the before/after diff below is only
    // the set of newly inserted messages if it is diffing that same store.
    let store = node.store();
    let before = match store.hwm_all() {
        Ok(marks) => marks,
        Err(e) => {
            tracing::warn!("reading the high-water marks before catch-up: {e:#}");
            return;
        }
    };
    match replay::catch_up(
        node.endpoint(),
        node.admit(),
        store,
        node.topic(),
        replay::REPLAY_LIMIT,
    )
    .await
    {
        Ok(counts) => {
            tracing::info!(
                peers = counts.peers,
                inserted = counts.inserted,
                duplicates = counts.duplicates,
                refused = counts.refused,
                "catch-up pass"
            );
            if counts.inserted > 0
                && let Err(e) = print_new_since(store, &before, printer, keyring)
            {
                tracing::warn!("printing caught-up messages: {e:#}");
            }
        }
        Err(e) => tracing::warn!("catch-up failed: {e:#}"),
    }
}

/// Print every message stored past the marks in `before`, in display order.
fn print_new_since(
    store: &store::TopicStore,
    before: &BTreeMap<NodeId, ChainState>,
    printer: &Printer,
    keyring: &mut Keyring,
) -> anyhow::Result<()> {
    let mut fresh = Vec::new();
    for (sender, state) in store.hwm_all()? {
        let from = before.get(&sender).map(|held| held.seq);
        if from == Some(state.seq) {
            continue;
        }
        // Bounded by what just landed: `read_after` starts at the old mark.
        fresh.extend(store.read_after(sender, from, usize::MAX)?);
    }
    fresh.sort_by_key(|envelope| (envelope.timestamp, envelope.sender, envelope.seq));
    for envelope in &fresh {
        printer.emit(envelope, keyring);
    }
    Ok(())
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
    tried: usize,
    /// Peers that completed the mutual admission handshake.
    admitted: usize,
    /// Peers that answered with a `Denied` frame.
    denials: usize,
    /// The first refusal's reason, for the exit-77 error.
    denial: Option<anyhow::Error>,
}

/// Re-admit every known peer and hand the survivors to gossip.
///
/// Re-admission is not a formality: the responder re-loads its head, so a peer
/// that was removed from the roster since the last dial learns about it here,
/// as a [`Denied`](crate::transport::Denied). But one peer refusing is that
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
/// An admission is a lease of [`ADMIT_TTL`](crate::admission::ADMIT_TTL), and
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

// ---------------------------------------------------------------------------
// `wires publish`
// ---------------------------------------------------------------------------

/// Where a `wires publish` invocation's messages come from.
///
/// Streaming rather than collected, so `tail -f app.log | wires publish ops`
/// publishes each line as it appears instead of waiting for an end of input
/// that never comes.
enum Messages {
    /// A single `--message`, once.
    One(Option<String>),
    /// One message per line of stdin.
    Stdin(tokio::io::Lines<tokio::io::BufReader<tokio::io::Stdin>>),
}

impl Messages {
    /// The next message, skipping blank lines; `None` at the end.
    async fn next(&mut self) -> anyhow::Result<Option<String>> {
        match self {
            Messages::One(text) => Ok(text.take()),
            Messages::Stdin(lines) => loop {
                match lines.next_line().await.context("reading stdin")? {
                    Some(line) if line.trim().is_empty() => continue,
                    other => return Ok(other),
                }
            },
        }
    }
}

/// `publish`: hand the message to the resident tail if there is one, else do it
/// one-shot (spec §7.2).
async fn publish_cmd(a: PublishArgs) -> anyhow::Result<()> {
    init_logging();
    let ks = Arc::new(keystore::Keystore::resolve()?);
    let home = keystore::home()?;
    let ctx = TopicContext::resolve(ks, home, &a.common)?;
    let messages = match a.message {
        Some(text) => Messages::One(Some(text)),
        None => {
            use tokio::io::AsyncBufReadExt as _;
            Messages::Stdin(tokio::io::BufReader::new(tokio::io::stdin()).lines())
        }
    };

    if let Some(client) = ipc::ControlClient::connect(&ctx.socket_path()).await? {
        return publish_through_tail(&ctx, client, messages).await;
    }
    publish_one_shot(&ctx, messages, PUBLISH_NEIGHBOR_WAIT, PUBLISH_LINGER).await
}

/// Stream every message through the resident tail, surviving a refusal.
///
/// `tail -f app.log | wires publish ops` is the documented use, and it used to
/// end on the first error: a `{"err":…}` reply — which the tail sends for
/// something as ordinary as "no fabric key for the current commit yet", in the
/// window between a `roster commit` and the operator's `wires import` — or the
/// socket closing because the tail was restarted. The pipe died permanently and
/// every subsequent line was silently never published.
///
/// So a failure retries the same line, reconnecting first (a closed socket is
/// the common case, and the tail may be back), and only after
/// [`PUBLISH_ATTEMPTS`] does it give up on *that line* and move to the next.
/// The command fails only if nothing at all got through.
async fn publish_through_tail(
    ctx: &TopicContext,
    client: ipc::ControlClient,
    mut messages: Messages,
) -> anyhow::Result<()> {
    let socket = ctx.socket_path();
    let mut client = Some(client);
    let (mut published, mut dropped) = (0usize, 0usize);
    while let Some(text) = messages.next().await? {
        match publish_line(&mut client, &socket, &text, PUBLISH_RETRY_DELAY).await {
            Ok(seq) => {
                tracing::info!(seq, "published through the resident tail");
                published += 1;
            }
            Err(e) => {
                dropped += 1;
                eprintln!(
                    "wires publish: dropping a line after {PUBLISH_ATTEMPTS} attempts: {e:#}"
                );
            }
        }
    }
    match (published, dropped) {
        (0, 0) => eprintln!("wires publish: nothing to publish"),
        (0, _) => anyhow::bail!("no message could be published through the resident tail"),
        (_, 0) => {}
        (_, n) => eprintln!("wires publish: {n} line(s) were not published"),
    }
    Ok(())
}

/// Publish one line through the resident tail, reconnecting between attempts.
///
/// `client` is taken as a slot rather than a value because a failure discards
/// the connection: a `{"err":…}` reply leaves it usable and a closed socket does
/// not, and reconnecting costs less than telling those apart. The caller keeps
/// the slot across lines, so a healthy stream reconnects zero times.
async fn publish_line(
    client: &mut Option<ipc::ControlClient>,
    socket: &Path,
    text: &str,
    retry_delay: Duration,
) -> anyhow::Result<u64> {
    let mut last: Option<anyhow::Error> = None;
    for attempt in 0..PUBLISH_ATTEMPTS {
        if client.is_none() {
            if attempt > 0 {
                tokio::time::sleep(retry_delay).await;
            }
            *client = ipc::ControlClient::connect(socket).await.unwrap_or(None);
        }
        let Some(open) = client.as_mut() else {
            last = Some(anyhow::anyhow!(
                "no resident tail on {} to publish through",
                socket.display()
            ));
            continue;
        };
        match open.publish(text).await {
            Ok(seq) => return Ok(seq),
            Err(e) => {
                tracing::warn!(attempt = attempt + 1, "publish refused: {e:#}");
                *client = None;
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("the publish was never attempted")))
}

/// Publish without a resident tail: bind, admit, join, wait for one neighbor,
/// then seal/append/broadcast each message and linger.
///
/// With no reachable peer the messages are still appended locally and the
/// command exits 0 with a warning: the log is the authority, and the next tail
/// on this node replays them out (spec §7.2).
async fn publish_one_shot(
    ctx: &TopicContext,
    mut messages: Messages,
    wait: Duration,
    linger: Duration,
) -> anyhow::Result<()> {
    // The tail may be *starting*: it binds its control socket before it joins,
    // but a publish that arrived a moment earlier saw no socket and got here.
    // Waiting out the redb lock turns that race into a pause instead of a lost
    // message (or, in the other order, a dead resident node).
    let store = Arc::new(open_topic_store(&ctx.home, ctx.topic, STORE_LOCK_WAIT).await?);
    let node = topics::TopicNode::spawn(&ctx.node, ctx.node_config(Arc::clone(&store))).await?;

    let mut book = PeerBook::open(&ctx.home, ctx.topic);
    let mut changed = false;
    for peer in &ctx.ticket_peers {
        changed |= book.record(peer.clone());
    }
    if changed {
        book.save();
    }
    let bootstrap = book.list();
    let (sender, mut events) = node.join(ctx.topic, &bootstrap).await?;

    let neighbor = if bootstrap.is_empty() {
        // Nothing to wait *for*: this endpoint bound a moment ago on a random
        // port and no peer has been told about it, so the 15 seconds would buy
        // only a 15-second pause on every publish from a node that has never
        // been given a ticket.
        eprintln!(
            "wires publish: no known peer on topic {:?} — storing locally (pass `--peer <ticket>`, \
             or keep a `wires tail` running)",
            ctx.name
        );
        None
    } else {
        wait_for_neighbor(&mut events, wait).await
    };
    match neighbor {
        Some(peer) => {
            tracing::info!(peer = %peer.hex(), "neighbor up; publishing");
            if book.record(TopicPeer::new(peer)) {
                book.save();
            }
        }
        None if !bootstrap.is_empty() => eprintln!(
            "wires publish: no reachable peer on topic {:?} after {}s — the message is stored \
             locally and reaches the topic on the next catch-up",
            ctx.name,
            wait.as_secs()
        ),
        None => {}
    }

    let (version, key) = current_fabric_key(&ctx.keystore)?;
    let mut published = 0usize;
    while let Some(text) = messages.next().await? {
        let envelope = append_local(
            &store,
            &ctx.node,
            ctx.topic,
            version,
            &key,
            &text,
            now_unix(),
        )?;
        if neighbor.is_some()
            && let Err(e) = sender.broadcast(&envelope).await
        {
            // Warned, never fatal — the same rule the tail's publish path
            // follows, and for the same reason: the sequence is *already*
            // allocated and the message is already in the log, so aborting here
            // would drop every remaining line and invite a retry that
            // republishes this one under a fresh sequence (a duplicate line on
            // the topic, from a peer restart).
            tracing::warn!(
                seq = envelope.seq.0,
                "stored but not broadcast (replay will carry it): {e:#}"
            );
        }
        tracing::info!(seq = envelope.seq.0, "published");
        published += 1;
    }
    if published == 0 {
        eprintln!("wires publish: nothing to publish");
    } else if neighbor.is_some() {
        // Gossip needs a moment to actually put the bytes on the wire; closing
        // the endpoint first would drop them.
        tokio::time::sleep(linger).await;
    }
    node.shutdown().await?;
    Ok(())
}

/// Wait up to `wait` for the first mesh neighbor, discarding other events.
async fn wait_for_neighbor(
    events: &mut tokio::sync::mpsc::Receiver<topics::TopicEvent>,
    wait: Duration,
) -> Option<NodeId> {
    let until = deadline(wait);
    loop {
        match tokio::time::timeout_at(until, events.recv()).await {
            Ok(Some(topics::TopicEvent::NeighborUp(peer))) => return Some(peer),
            // Nothing else here is worth waiting on: a one-shot publish neither
            // prints nor ingests.
            Ok(Some(_)) => continue,
            Ok(None) => return None,
            Err(_) => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::check_accept;
    use proptest::prelude::*;

    fn seed() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    #[test]
    fn keygen_is_deterministic_given_seeds() {
        let node = NodeIdentity::from_seed([3u8; 32]);
        let root = NodeIdentity::from_seed([4u8; 32]);
        let out = run_keygen(Some(&node.seed_hex()), Some(&root.seed_hex())).unwrap();
        assert_eq!(out.node_seed, node.seed_hex());
        assert_eq!(out.node_id, node.node_id().hex());
        assert_eq!(out.root_seed, root.seed_hex());
        assert_eq!(out.root_id, root.node_id().hex());
    }

    #[test]
    fn keygen_generated_seed_redrives_same_id() {
        let out = run_keygen(None, None).unwrap();
        assert_eq!(out.node_seed.len(), 64);
        let redrived = NodeIdentity::from_seed_hex(&out.node_seed).unwrap();
        assert_eq!(redrived.node_id().hex(), out.node_id);
    }

    #[test]
    fn keygen_rejects_bad_seed() {
        assert!(run_keygen(Some("nothex"), None).is_err());
    }

    #[test]
    fn serve_takes_expose_or_a_command_but_not_both() {
        let base = ["wires", "serve", "--trust-root", "00"];
        let parse = |extra: &[&str]| Cli::try_parse_from(base.iter().chain(extra));
        let Command::Serve(a) = parse(&["--expose", "a=cat", "--expose", "b=rg -n"])
            .unwrap()
            .command
        else {
            panic!("expected serve");
        };
        assert_eq!(a.expose, ["a=cat", "b=rg -n"]);
        assert!(a.command.is_empty());
        assert!(parse(&["--expose-file", "t.json"]).is_ok());
        assert!(parse(&["--", "cat"]).is_ok());
        assert!(parse(&[]).is_err(), "neither --expose nor a command");
        assert!(parse(&["--expose", "a=cat", "--", "cat"]).is_err());
        assert!(parse(&["--expose", "a=cat", "--scope", "s"]).is_err());
    }

    #[test]
    fn connect_tool_takes_trailing_args() {
        let cli = Cli::try_parse_from([
            "wires", "connect", "--target", "00", "--tool", "db", "--", "-c", "select 1",
        ])
        .unwrap();
        let Command::Connect(a) = cli.command else {
            panic!("expected connect");
        };
        assert_eq!(a.tool.as_deref(), Some("db"));
        assert_eq!(a.args, ["-c", "select 1"]);
        // Arguments without a tool have nowhere to go.
        assert!(Cli::try_parse_from(["wires", "connect", "--target", "00", "--", "x"]).is_err());
    }

    #[test]
    fn resolve_not_after_rules() {
        assert_eq!(resolve_not_after(Some(10), None, 100), Ok(110));
        assert_eq!(resolve_not_after(None, Some(500), 100), Ok(500));
        assert!(resolve_not_after(Some(1), Some(2), 0).is_err());
        assert!(resolve_not_after(None, None, 0).is_err());
    }

    proptest! {
        /// A minted ticket decodes back, points at the right target/subject, and
        /// is accepted for its subject before expiry.
        #[test]
        fn grant_ticket_is_acceptable(
            rs in seed(), ss in seed(), ts in seed(),
            scope in "[a-z.]{1,16}", not_after in 1i64..=i64::MAX,
        ) {
            let root = NodeIdentity::from_seed(rs);
            let subject = NodeIdentity::from_seed(ss).node_id();
            let target = NodeIdentity::from_seed(ts).node_id();

            let text = run_grant(&root, &subject.hex(), &target.hex(), &scope, not_after, Vec::new(), None).unwrap();
            let ticket = CapabilityTicket::decode(&text).unwrap();

            prop_assert_eq!(ticket.target, target);
            prop_assert_eq!(ticket.grant.subject, subject);
            prop_assert_eq!(ticket.scope.as_str(), scope.as_str());
            prop_assert!(check_accept(&ticket.grant, root.node_id(), subject, 0, &Crl::new()).is_ok());
        }
    }

    #[test]
    fn grant_rejects_bad_subject() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let target = NodeIdentity::from_seed([2u8; 32]).node_id();
        assert!(
            run_grant(
                &root,
                "nothex",
                &target.hex(),
                "tools.rg",
                1,
                Vec::new(),
                None
            )
            .is_err()
        );
    }

    proptest! {
        /// A minted membership token decodes back, names the right member and
        /// fabric, and is accepted for that member before expiry.
        #[test]
        fn member_token_is_includable(rs in seed(), ms in seed(), not_after in 1i64..=i64::MAX) {
            let root = NodeIdentity::from_seed(rs);
            let member = NodeIdentity::from_seed(ms).node_id();
            let token = run_member(&root, &member.hex(), 0, not_after).unwrap().encode().unwrap();
            let m = Membership::decode(&token).unwrap();
            prop_assert_eq!(m.member, member);
            prop_assert_eq!(m.fabric, root.node_id());
            prop_assert!(library::check_inclusion(&m, root.node_id(), member, 0, &Crl::new()).is_ok());
        }
    }

    #[test]
    fn member_rejects_bad_subject() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        assert!(run_member(&root, "nothex", 0, 1).is_err());
    }

    #[test]
    fn revoke_inserts_and_is_idempotent() {
        let a = NodeIdentity::from_seed([7u8; 32]).node_id();
        let b = NodeIdentity::from_seed([8u8; 32]).node_id();

        let out1 = run_revoke(None, &a.hex()).unwrap();
        let crl1 = Crl::from_json(&out1).unwrap();
        assert!(crl1.contains(&a));
        assert_eq!(crl1.len(), 1);

        // Revoking the same subject again does not grow the list.
        let out2 = run_revoke(Some(&out1), &a.hex()).unwrap();
        assert_eq!(Crl::from_json(&out2).unwrap().len(), 1);

        // A different subject does.
        let out3 = run_revoke(Some(&out1), &b.hex()).unwrap();
        let crl3 = Crl::from_json(&out3).unwrap();
        assert_eq!(crl3.len(), 2);
        assert!(crl3.contains(&a) && crl3.contains(&b));
    }

    #[test]
    fn revoke_treats_blank_input_as_empty() {
        let a = NodeIdentity::from_seed([9u8; 32]).node_id();
        let out = run_revoke(Some("   "), &a.hex()).unwrap();
        assert_eq!(Crl::from_json(&out).unwrap().len(), 1);
    }

    #[test]
    fn revoke_cmd_crl_json_is_one_shot() {
        // `--crl-json` is a pure transform: insert and print, write nothing.
        let a = NodeIdentity::from_seed([7u8; 32]).node_id();
        let out = run_revoke_cmd(RevokeArgs {
            subject: a.hex(),
            crl_json: Some(String::new()),
            crl_file: None,
        })
        .unwrap();
        assert!(Crl::from_json(&out).unwrap().contains(&a));
    }

    #[test]
    fn revoke_cmd_crl_file_updates_in_place() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let base = std::env::var_os("TEST_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = base.join(format!(
            "wires-revtest-{}-{}.json",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);

        let a = NodeIdentity::from_seed([7u8; 32]).node_id();
        let b = NodeIdentity::from_seed([8u8; 32]).node_id();

        // First revoke creates the file; the printed output equals what's on disk.
        let out = run_revoke_cmd(RevokeArgs {
            subject: a.hex(),
            crl_json: None,
            crl_file: Some(path.clone()),
        })
        .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), out);
        assert!(Crl::from_json(&out).unwrap().contains(&a));

        // Re-revoking the same subject is idempotent; a new one grows the list.
        let again = run_revoke_cmd(RevokeArgs {
            subject: a.hex(),
            crl_json: None,
            crl_file: Some(path.clone()),
        })
        .unwrap();
        assert_eq!(Crl::from_json(&again).unwrap().len(), 1);

        let two = run_revoke_cmd(RevokeArgs {
            subject: b.hex(),
            crl_json: None,
            crl_file: Some(path.clone()),
        })
        .unwrap();
        assert_eq!(Crl::from_json(&two).unwrap().len(), 2);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn import_requires_at_least_one_credential() {
        // Bare `wires import` is a usage error: there is nothing to install.
        assert!(Cli::try_parse_from(["wires", "import"]).is_err());
    }

    #[test]
    fn import_parses_a_single_credential_flag() {
        let cli = Cli::try_parse_from(["wires", "import", "--membership-file", "x"]).unwrap();
        match cli.command {
            Command::Import(a) => {
                assert_eq!(a.membership_file.as_deref(), Some(Path::new("x")));
                assert!(a.membership.is_none());
            }
            _ => panic!("expected the import subcommand"),
        }
    }

    #[test]
    fn import_rejects_a_credential_given_twice() {
        // Inline and file for the same credential is ambiguous, not additive.
        assert!(
            Cli::try_parse_from([
                "wires",
                "import",
                "--membership",
                "tok",
                "--membership-file",
                "x"
            ])
            .is_err()
        );
    }

    #[test]
    fn preflight_accepts_credentials_issued_to_this_node() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let me = NodeIdentity::from_seed([2u8; 32]).node_id();
        let membership = Membership::mint(&root, me, 0, i64::MAX).unwrap();
        let grant = Grant::mint(&root, me, Scope::new("tools.rg"), i64::MAX).unwrap();
        assert_eq!(preflight(me, &membership, Some(&grant)), Ok(()));
        assert_eq!(preflight(me, &membership, None), Ok(()));
    }

    #[test]
    fn preflight_rejects_a_ticket_for_another_node() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let me = NodeIdentity::from_seed([2u8; 32]).node_id();
        let other = NodeIdentity::from_seed([3u8; 32]).node_id();
        let membership = Membership::mint(&root, me, 0, i64::MAX).unwrap();
        // A ticket minted for someone else — the "copied to the wrong machine" case.
        let grant = Grant::mint(&root, other, Scope::new("tools.rg"), i64::MAX).unwrap();
        let msg = preflight(me, &membership, Some(&grant)).unwrap_err();
        assert!(
            msg.contains(&other.hex()) && msg.contains(&me.hex()),
            "{msg}"
        );
    }

    #[test]
    fn preflight_rejects_a_membership_for_another_node() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let me = NodeIdentity::from_seed([2u8; 32]).node_id();
        let other = NodeIdentity::from_seed([3u8; 32]).node_id();
        let membership = Membership::mint(&root, other, 0, i64::MAX).unwrap();
        let msg = preflight(me, &membership, None).unwrap_err();
        assert!(
            msg.contains(&other.hex()) && msg.contains(&me.hex()),
            "{msg}"
        );
    }

    #[test]
    fn roster_commit_emits_includable_proofs() {
        // Build a roster directly (the CLI editing path is exercised via keystore
        // tests); assert commit's proofs pass check_roster_inclusion.
        let root = NodeIdentity::from_seed([1u8; 32]);
        let member = NodeIdentity::from_seed([2u8; 32]).node_id();
        let mut roster = library::Roster::new(root.node_id());
        roster.insert(member);
        let before = roster.version.0;
        let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        assert_eq!(head.version.0, before + 1);
        let proof = proofs.into_iter().find(|(m, _)| *m == member).unwrap().1;
        assert!(library::check_roster_inclusion(&head, &proof, root.node_id(), member, 0).is_ok());
    }

    /// A fresh empty directory, under `$TEST_TMPDIR` when bazel provides one.
    fn temp_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let base = std::env::var_os("TEST_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join(format!(
            "wires-cli-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// `roster commit` arguments with everything but the root seed defaulted.
    fn commit_args(root: &NodeIdentity, out: Option<PathBuf>) -> RosterCommitArgs {
        RosterCommitArgs {
            root_seed: Some(root.seed_hex()),
            root_seed_file: None,
            ttl: None,
            not_after: Some(i64::MAX),
            out,
        }
    }

    /// `import` arguments with no credential selected.
    fn import_args() -> ImportArgs {
        ImportArgs {
            force: false,
            membership: None,
            membership_file: None,
            inclusion_proof: None,
            inclusion_proof_file: None,
            roster_head: None,
            roster_head_file: None,
            fabric_key: None,
            fabric_key_file: None,
        }
    }

    /// A keystore holding a two-member `roster.json`, plus the root and the two
    /// member identities.
    fn fabric_fixture() -> (keystore::Keystore, NodeIdentity, NodeIdentity, NodeIdentity) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let bob = NodeIdentity::from_seed([3u8; 32]);
        let ks = keystore::Keystore::at(temp_dir());
        let mut roster = library::Roster::new(root.node_id());
        roster.insert(alice.node_id());
        roster.insert(bob.node_id());
        ks.save_roster(&roster).unwrap();
        (ks, root, alice, bob)
    }

    #[test]
    fn commit_writes_a_sealed_key_per_member_openable_only_by_that_member() {
        let (ks, root, alice, bob) = fabric_fixture();
        let out = temp_dir();
        let summary = roster_commit_in(&ks, commit_args(&root, Some(out.clone()))).unwrap();

        // One `<node-id>.key` beside each `<node-id>.proof`, and the summary
        // says so.
        assert!(summary.contains("sealed fabric key"), "{summary}");
        let head = ks.read_roster_head().unwrap().unwrap();
        let mut keys = Vec::new();
        for member in [&alice, &bob] {
            let hex = member.node_id().hex();
            assert!(out.join(format!("{hex}.proof")).is_file());
            let token = std::fs::read_to_string(out.join(format!("{hex}.key"))).unwrap();
            assert!(summary.contains(&format!("key {hex} -> ")), "{summary}");

            let sealed = SealedFabricKey::decode(token.trim()).unwrap();
            assert_eq!(sealed.version, head.version);
            keys.push(sealed.open(member, root.node_id()).unwrap());
        }

        // Every member's copy is the same key (one data key per commit) …
        assert_eq!(keys[0], keys[1]);
        // … and it is *their* copy: Bob's node cannot open Alice's.
        let alices = SealedFabricKey::decode(
            std::fs::read_to_string(out.join(format!("{}.key", alice.node_id().hex())))
                .unwrap()
                .trim(),
        )
        .unwrap();
        assert!(alices.open(&bob, root.node_id()).is_err());
        // Nor can anyone check it against a root that did not sign it.
        assert!(alices.open(&alice, bob.node_id()).is_err());
    }

    #[test]
    fn commit_without_out_prints_key_tokens_and_root_keeps_nothing() {
        let (ks, root, alice, _bob) = fabric_fixture();
        let summary = roster_commit_in(&ks, commit_args(&root, None)).unwrap();

        // The key rides on stdout next to the proof, same shape.
        let hex = alice.node_id().hex();
        let token = summary
            .lines()
            .find_map(|l| l.strip_prefix(&format!("key {hex} ")))
            .unwrap_or_else(|| panic!("no key line for {hex} in:\n{summary}"));
        assert!(
            summary
                .lines()
                .any(|l| l.starts_with(&format!("proof {hex} ")))
        );
        SealedFabricKey::decode(token)
            .unwrap()
            .open(&alice, root.node_id())
            .unwrap();

        // Blind root: committing wrote no plaintext key into the root's own
        // keystore, so compromising the operator reads no traffic.
        assert!(ks.read_keyring().unwrap().is_empty());
    }

    #[test]
    fn commit_rotates_the_key_on_every_commit() {
        let (ks, root, alice, _bob) = fabric_fixture();
        let key_of = |summary: &str| {
            let hex = alice.node_id().hex();
            let token = summary
                .lines()
                .find_map(|l| l.strip_prefix(&format!("key {hex} ")))
                .unwrap();
            SealedFabricKey::decode(token)
                .unwrap()
                .open(&alice, root.node_id())
                .unwrap()
        };
        let first = roster_commit_in(&ks, commit_args(&root, None)).unwrap();
        let second = roster_commit_in(&ks, commit_args(&root, None)).unwrap();
        // A removed member's last key must not decrypt what comes after them.
        assert_ne!(key_of(&first), key_of(&second));
    }

    #[test]
    fn a_member_that_cannot_be_sealed_to_aborts_the_commit_before_it_persists() {
        let (ks, root, _alice, _bob) = fabric_fixture();
        roster_commit_in(&ks, commit_args(&root, None)).unwrap();
        let committed = ks.read_roster_head().unwrap().unwrap();

        // A small-order point: 64 well-formed hex characters that decompress to
        // a weak key, which is exactly what an operator can paste into
        // `roster add` and what `SealedFabricKey::seal` refuses (spec §3).
        let mut weak = [0u8; 32];
        weak[0] = 1;
        let mut roster = ks.read_roster().unwrap().unwrap();
        roster.insert(library::NodeId::from_bytes(weak));
        ks.save_roster(&roster).unwrap();

        let err = roster_commit_in(&ks, commit_args(&root, None)).unwrap_err();
        assert!(
            format!("{err:#}").contains("sealing the fabric key"),
            "{err:#}"
        );

        // The version bump and the head are still the previous commit's: the
        // failure left nothing half-committed for the members to import.
        let after = ks.read_roster_head().unwrap().unwrap();
        assert_eq!(after.version, committed.version);
        assert_eq!(
            ks.read_roster().unwrap().unwrap().version,
            committed.version
        );
    }

    /// A member's keystore (node seed + installed membership) and the sealed
    /// key token that `roster commit` emitted for them.
    fn member_fixture(member: &NodeIdentity) -> (keystore::Keystore, NodeIdentity, String) {
        let (root_ks, root, _alice, _bob) = fabric_fixture();
        let summary = roster_commit_in(&root_ks, commit_args(&root, None)).unwrap();
        let token = summary
            .lines()
            .find_map(|l| l.strip_prefix(&format!("key {} ", member.node_id().hex())))
            .unwrap_or_else(|| panic!("no key line in:\n{summary}"))
            .to_string();

        let ks = keystore::Keystore::at(temp_dir());
        ks.save_node(member, false).unwrap();
        (ks, root, token)
    }

    #[test]
    fn import_installs_a_sealed_fabric_key_into_the_keyring() {
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let (ks, root, token) = member_fixture(&alice);
        let membership = Membership::mint(&root, alice.node_id(), 0, i64::MAX).unwrap();

        // Membership and key in one command: the membership installed first is
        // the trust anchor the key is checked against.
        let out = run_import_in(
            &ks,
            ImportArgs {
                membership: Some(membership.encode().unwrap()),
                fabric_key: Some(token.clone()),
                ..import_args()
            },
        )
        .unwrap();

        let version = SealedFabricKey::decode(&token).unwrap().version;
        let path = ks.fabric_key_path(version);
        assert!(out.contains(&format!("wrote {}", path.display())), "{out}");
        let installed = ks.read_fabric_key(version).unwrap().unwrap();
        assert_eq!(
            ks.latest_fabric_key().unwrap().unwrap(),
            (version, installed.clone())
        );
        assert_eq!(
            SealedFabricKey::decode(&token)
                .unwrap()
                .open(&alice, root.node_id())
                .unwrap(),
            installed
        );

        // Re-running the same import is a no-op, not an error.
        run_import_in(
            &ks,
            ImportArgs {
                fabric_key: Some(token),
                ..import_args()
            },
        )
        .unwrap();
        assert_eq!(ks.read_fabric_key(version).unwrap().unwrap(), installed);
    }

    /// A head only ever moves forward, on the import path too.
    ///
    /// `persist_head` exists because two concurrent admissions could roll the
    /// stored head backwards — but the compare-and-swap covered only the two
    /// network adoption paths. `wires import --roster-head` wrote whatever token
    /// it was handed, with no comparison and no lock, and the running tail
    /// re-reads that file on every handshake and every watchdog pass: importing
    /// an older head downgraded the enforced roster in place and re-admitted
    /// every member the newer commit removed. A head token is public and every
    /// past member holds one, so "paste the head you were given" is a realistic
    /// thing to induce.
    #[test]
    fn import_refuses_a_roster_head_that_walks_backwards() {
        let (ks, root, _alice, _bob) = fabric_fixture();
        roster_commit_in(&ks, commit_args(&root, None)).unwrap();
        let v1 = ks.read_roster_head().unwrap().unwrap();
        roster_commit_in(&ks, commit_args(&root, None)).unwrap();
        let v2 = ks.read_roster_head().unwrap().unwrap();
        assert!(v2.version > v1.version);

        let err = run_import_in(
            &ks,
            ImportArgs {
                roster_head: Some(v1.encode().unwrap()),
                ..import_args()
            },
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("only ever moves forward") && msg.contains("--force"),
            "the refusal must name the remedy: {msg}"
        );
        assert_eq!(
            ks.read_roster_head().unwrap().unwrap(),
            v2,
            "the enforced head must not have moved"
        );

        // The same version again is not a rollback, and neither is a newer one.
        run_import_in(
            &ks,
            ImportArgs {
                roster_head: Some(v2.encode().unwrap()),
                ..import_args()
            },
        )
        .unwrap();
        assert_eq!(ks.read_roster_head().unwrap().unwrap(), v2);

        // ...and an operator who really means it can still undo a mistake.
        run_import_in(
            &ks,
            ImportArgs {
                roster_head: Some(v1.encode().unwrap()),
                force: true,
                ..import_args()
            },
        )
        .unwrap();
        assert_eq!(ks.read_roster_head().unwrap().unwrap(), v1);
    }

    /// Publishing under a superseded fabric key is refused at the source.
    ///
    /// The receiving half of this rule is [`replay::ingest`]'s epoch floor: once
    /// the roster has moved, a message sealed under the previous commit's key is
    /// refused by every peer that holds the new head. Sealing it anyway would
    /// put a line in this node's log that nobody else will ever accept — a
    /// silent, one-way loss — so the publish fails here instead, naming the one
    /// command that fixes it.
    #[test]
    fn publishing_refuses_a_superseded_fabric_key() {
        let (ks, root, alice, _bob) = fabric_fixture();
        ks.save_node(&alice, false).unwrap();
        roster_commit_in(&ks, commit_args(&root, None)).unwrap();
        let v1 = ks.read_roster_head().unwrap().unwrap().version;
        ks.save_fabric_key(v1, &FabricKey::generate()).unwrap();

        let (version, _key) = current_fabric_key(&ks).expect("v1 key under a v1 head");
        assert_eq!(version, v1);

        // The root commits again; this node imported the head (or adopted it at
        // admission) but not yet the key.
        roster_commit_in(&ks, commit_args(&root, None)).unwrap();
        let v2 = ks.read_roster_head().unwrap().unwrap().version;
        let err = current_fabric_key(&ks).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("superseded") && msg.contains("--fabric-key-file"),
            "the refusal must name the remedy: {msg}"
        );

        // The import it asked for makes publishing work again, with no restart.
        ks.save_fabric_key(v2, &FabricKey::generate()).unwrap();
        assert_eq!(current_fabric_key(&ks).unwrap().0, v2);
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
    /// needs `wires import`; a peer whose own head is briefly unreadable answers
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

    /// A publish and a tail racing for the topic log wait for each other.
    ///
    /// redb locks the file for the life of the handle, and the window between
    /// the two commands is routine — a login script that starts a tail and
    /// publishes on the next line. Failing immediately made the loser's message
    /// disappear, or, when the loser was the tail, killed the resident node.
    #[tokio::test]
    async fn opening_the_topic_log_waits_out_another_process() {
        let home = temp_dir();
        let topic = TopicId::derive(NodeIdentity::from_seed([1u8; 32]).node_id(), "ops");
        let held = store::TopicStore::open(&home, topic).unwrap();

        // While it is held, the wait expires and the error is the lock's.
        let e = open_topic_store(&home, topic, Duration::from_millis(200))
            .await
            .expect_err("two handles on one redb file cannot both open");
        assert!(format!("{e:#}").to_lowercase().contains("lock"), "{e:#}");

        // Released mid-wait, the second open succeeds — the race is a pause.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            drop(held);
        });
        open_topic_store(&home, topic, Duration::from_secs(10))
            .await
            .expect("the log must open once the other process lets go");
    }

    #[test]
    fn import_refuses_a_key_sealed_to_another_member() {
        // Bob's keystore, Alice's copy of the key.
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let bob = NodeIdentity::from_seed([3u8; 32]);
        let (_alice_ks, root, alices_token) = member_fixture(&alice);
        let ks = keystore::Keystore::at(temp_dir());
        ks.save_node(&bob, false).unwrap();
        ks.save_membership(&Membership::mint(&root, bob.node_id(), 0, i64::MAX).unwrap())
            .unwrap();

        let err = run_import_in(
            &ks,
            ImportArgs {
                fabric_key: Some(alices_token),
                ..import_args()
            },
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains(&alice.node_id().hex()), "{msg}");
        assert!(msg.contains(&bob.node_id().hex()), "{msg}");
        assert!(ks.read_keyring().unwrap().is_empty());
    }

    #[test]
    fn import_refuses_a_key_from_a_foreign_fabric() {
        // A membership from a different root: the key is genuine, but not from
        // the authority this node trusts.
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let (ks, _root, token) = member_fixture(&alice);
        let impostor = NodeIdentity::from_seed([9u8; 32]);
        ks.save_membership(&Membership::mint(&impostor, alice.node_id(), 0, i64::MAX).unwrap())
            .unwrap();

        let err = run_import_in(
            &ks,
            ImportArgs {
                fabric_key: Some(token),
                ..import_args()
            },
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains(&impostor.node_id().hex()),
            "{err:#}"
        );
        assert!(ks.read_keyring().unwrap().is_empty());
    }

    #[test]
    fn import_fabric_key_without_a_membership_names_the_remedy() {
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let (ks, _root, token) = member_fixture(&alice); // node.seed only

        let err = run_import_in(
            &ks,
            ImportArgs {
                fabric_key: Some(token),
                ..import_args()
            },
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("wires import --membership"), "{msg}");
        assert!(
            msg.contains(&ks.path("membership.json").display().to_string()),
            "{msg}"
        );
        assert!(ks.read_keyring().unwrap().is_empty());
    }

    #[test]
    fn import_accepts_the_fabric_key_flags() {
        // The key is a credential of the `creds` group: it alone is a valid
        // invocation, and inline-plus-file is still ambiguous.
        let cli = Cli::try_parse_from(["wires", "import", "--fabric-key-file", "k"]).unwrap();
        match cli.command {
            Command::Import(a) => {
                assert_eq!(a.fabric_key_file.as_deref(), Some(Path::new("k")));
                assert!(a.fabric_key.is_none());
            }
            _ => panic!("expected the import subcommand"),
        }
        assert!(
            Cli::try_parse_from([
                "wires",
                "import",
                "--fabric-key",
                "tok",
                "--fabric-key-file",
                "k"
            ])
            .is_err()
        );
    }

    // -----------------------------------------------------------------------
    // Topics: preflight, printing, peers, and the control socket (spec §7)
    // -----------------------------------------------------------------------

    /// A member keystore provisioned exactly as `wires import` would leave it:
    /// node key, membership, inclusion proof, roster head, and one fabric key.
    ///
    /// The keystore directory doubles as `$WIRES_HOME`, which is what it is in
    /// production — `topics/` and `run/` sit beside `node.seed`.
    struct Member {
        /// The provisioned keystore (also the home directory).
        ks: Arc<keystore::Keystore>,
        /// That keystore's directory.
        home: PathBuf,
        /// The fabric root that signed everything.
        root: NodeIdentity,
        /// This member's identity.
        node: NodeIdentity,
        /// The data key the (single) commit minted.
        key: FabricKey,
        /// The version that key belongs to.
        version: RosterVersion,
    }

    /// Provision `who` as a member of a two-member fabric.
    fn provisioned(who: [u8; 32]) -> Member {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let node = NodeIdentity::from_seed(who);
        let other = NodeIdentity::from_seed([9u8; 32]);
        let mut roster = library::Roster::new(root.node_id());
        roster.insert(node.node_id());
        roster.insert(other.node_id());
        let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let proof = proofs
            .into_iter()
            .find(|(m, _)| *m == node.node_id())
            .unwrap()
            .1;
        let key = FabricKey::generate();

        let home = temp_dir();
        let ks = keystore::Keystore::at(&home);
        ks.save_node(&node, true).unwrap();
        ks.save_membership(&Membership::mint(&root, node.node_id(), 0, i64::MAX).unwrap())
            .unwrap();
        ks.save_inclusion_proof(&proof).unwrap();
        ks.save_roster_head(&head).unwrap();
        ks.save_fabric_key(head.version, &key).unwrap();
        Member {
            ks: Arc::new(ks),
            home,
            root,
            node,
            key,
            version: head.version,
        }
    }

    impl Member {
        /// `--topic ops --node-seed <this member>`, nothing else.
        fn args(&self) -> TopicArgs {
            TopicArgs {
                topic: "ops".into(),
                node_seed: Some(self.node.seed_hex()),
                ..TopicArgs::default()
            }
        }

        /// Resolve a context against this keystore.
        fn resolve(&self, args: &TopicArgs) -> anyhow::Result<TopicContext> {
            TopicContext::resolve(Arc::clone(&self.ks), self.home.clone(), args)
        }

        /// The message log for the resolved topic.
        fn store(&self) -> store::TopicStore {
            store::TopicStore::open(&self.home, TopicId::derive(self.root.node_id(), "ops"))
                .unwrap()
        }
    }

    #[test]
    fn tail_parses_the_documented_flags() {
        let cli = Cli::try_parse_from(["wires", "tail", "ops"]).unwrap();
        match cli.command {
            Command::Tail(a) => {
                assert_eq!(a.common.topic, "ops");
                assert_eq!(a.backfill, DEFAULT_BACKFILL, "the spec's default is 200");
                assert!(!a.json);
                assert!(a.common.peer.is_empty());
            }
            _ => panic!("expected tail"),
        }
        // `--peer` is repeatable; the rest mirror `connect`.
        let cli = Cli::try_parse_from([
            "wires",
            "tail",
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
            Command::Tail(a) => {
                assert_eq!(a.common.peer, vec!["t1".to_string(), "t2".to_string()]);
                assert_eq!(a.backfill, 7);
                assert!(a.json);
                assert_eq!(a.common.relay_url.as_deref(), Some("https://r"));
                assert_eq!(a.common.node_seed.as_deref(), Some("ab"));
            }
            _ => panic!("expected tail"),
        }
        // A topic is required.
        assert!(Cli::try_parse_from(["wires", "tail"]).is_err());
    }

    #[test]
    fn publish_parses_the_documented_flags() {
        let cli = Cli::try_parse_from(["wires", "publish", "ops", "-m", "ship it"]).unwrap();
        match cli.command {
            Command::Publish(a) => {
                assert_eq!(a.common.topic, "ops");
                assert_eq!(a.message.as_deref(), Some("ship it"));
            }
            _ => panic!("expected publish"),
        }
        // No `--message` is the stdin form, not an error.
        let cli = Cli::try_parse_from(["wires", "publish", "ops"]).unwrap();
        match cli.command {
            Command::Publish(a) => assert!(a.message.is_none()),
            _ => panic!("expected publish"),
        }
    }

    #[test]
    fn preflight_resolves_a_provisioned_member() {
        let member = provisioned([2u8; 32]);
        let ctx = member.resolve(&member.args()).unwrap();
        assert_eq!(ctx.fabric_root, member.root.node_id());
        assert_eq!(ctx.topic, TopicId::derive(member.root.node_id(), "ops"));
        assert_eq!(ctx.membership.member, member.node.node_id());
        assert_eq!(ctx.name, "ops");
        assert!(ctx.ticket_peers.is_empty());
        // The socket is the one this home's topic resolves to (under the home,
        // or — for a home as deep as the test sandbox's — the short fallback;
        // `ipc`'s suite asserts both shapes).
        assert_eq!(ctx.socket_path(), ipc::socket_path(&member.home, ctx.topic));
    }

    #[test]
    fn preflight_names_the_import_for_a_missing_membership() {
        let member = provisioned([2u8; 32]);
        std::fs::remove_file(member.ks.path("membership.json")).unwrap();
        let err = member.resolve(&member.args()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("wires import --membership"), "{msg}");
    }

    #[test]
    fn preflight_names_the_import_for_a_missing_proof() {
        let member = provisioned([2u8; 32]);
        std::fs::remove_file(member.ks.path("inclusion-proof.json")).unwrap();
        let err = member.resolve(&member.args()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("wires import --inclusion-proof"), "{msg}");
        assert!(msg.contains("roster commit --out"), "{msg}");
    }

    #[test]
    fn preflight_names_the_import_for_a_missing_head() {
        let member = provisioned([2u8; 32]);
        std::fs::remove_file(member.ks.path("roster-head.json")).unwrap();
        let err = member.resolve(&member.args()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("wires import --roster-head"), "{msg}");
    }

    #[test]
    fn preflight_names_the_import_for_an_empty_keyring() {
        let member = provisioned([2u8; 32]);
        std::fs::remove_dir_all(member.ks.keyring_dir()).unwrap();
        let err = member.resolve(&member.args()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("wires import --fabric-key"), "{msg}");
        assert!(msg.contains("end-to-end encrypted"), "{msg}");
    }

    #[test]
    fn preflight_refuses_a_credential_issued_to_another_node() {
        // Bob's keystore, but Alice's node seed on the command line.
        let member = provisioned([2u8; 32]);
        let stranger = NodeIdentity::from_seed([7u8; 32]);
        let args = TopicArgs {
            node_seed: Some(stranger.seed_hex()),
            ..member.args()
        };
        let msg = format!("{:#}", member.resolve(&args).unwrap_err());
        assert!(msg.contains(&stranger.node_id().hex()), "{msg}");
        assert!(msg.contains("wires import --membership"), "{msg}");
    }

    #[test]
    fn preflight_refuses_a_ticket_from_another_fabric_or_topic() {
        let member = provisioned([2u8; 32]);
        let stranger = NodeIdentity::from_seed([8u8; 32]).node_id();

        let foreign = TopicTicket::new(stranger, "ops", vec![TopicPeer::new(stranger)])
            .encode()
            .unwrap();
        let args = TopicArgs {
            peer: vec![foreign],
            ..member.args()
        };
        let msg = format!("{:#}", member.resolve(&args).unwrap_err());
        assert!(
            msg.contains("another fabric") || msg.contains("for fabric"),
            "{msg}"
        );

        let other_topic = TopicTicket::new(member.root.node_id(), "eng", Vec::new())
            .encode()
            .unwrap();
        let args = TopicArgs {
            peer: vec![other_topic],
            ..member.args()
        };
        let msg = format!("{:#}", member.resolve(&args).unwrap_err());
        assert!(msg.contains("\"eng\""), "{msg}");
    }

    #[test]
    fn preflight_takes_the_peers_off_a_good_ticket() {
        let member = provisioned([2u8; 32]);
        let peer = TopicPeer::new(NodeIdentity::from_seed([9u8; 32]).node_id())
            .with_addrs(vec!["127.0.0.1:4242".parse().unwrap()]);
        let ticket = TopicTicket::new(member.root.node_id(), "ops", vec![peer.clone()])
            .encode()
            .unwrap();
        let args = TopicArgs {
            peer: vec![ticket],
            ..member.args()
        };
        let ctx = member.resolve(&args).unwrap();
        assert_eq!(ctx.ticket_peers, vec![peer]);
    }

    #[test]
    fn append_local_allocates_a_dense_chain() {
        // The one-shot publish path with no network in it at all: allocate,
        // seal, append. Two calls must produce seq 0 then 1, linked.
        let member = provisioned([2u8; 32]);
        let ctx = member.resolve(&member.args()).unwrap();
        let store = member.store();

        let first = append_local(
            &store,
            &member.node,
            ctx.topic,
            member.version,
            &member.key,
            "one",
            1_000,
        )
        .unwrap();
        let second = append_local(
            &store,
            &member.node,
            ctx.topic,
            member.version,
            &member.key,
            "two",
            1_001,
        )
        .unwrap();

        assert_eq!(first.seq, Seq(0));
        assert_eq!(second.seq, Seq(1));
        assert!(first.prev_hash.is_zero(), "genesis links to nothing");
        assert_eq!(second.prev_hash, first.message_hash().unwrap());
        assert_eq!(first.open(&member.key).unwrap(), b"one");

        // Both are in the log, and the chain state agrees with the last one.
        let state = store.chain_state(member.node.node_id()).unwrap().unwrap();
        assert_eq!(state.seq, Seq(1));
        assert_eq!(state.hash, second.message_hash().unwrap());
        assert_eq!(store.read_backfill(10).unwrap(), vec![first, second]);
    }

    #[tokio::test]
    async fn publish_reaches_a_minimal_tail_loop_over_the_control_socket() {
        let member = provisioned([2u8; 32]);
        let ctx = member.resolve(&member.args()).unwrap();
        let store = Arc::new(member.store());

        // The socket lives under a short scratch path on purpose: a unix socket
        // path is capped at ~104 bytes and Bazel's temp root is longer than
        // that. `socket_path`'s own shape is asserted in `ipc`'s suite.
        let scratch = ipc::ScratchDir::new("pub");
        let path = scratch.socket("p.sock");
        let socket = ipc::ControlSocket::bind(&path).await.unwrap();
        let (tx, mut requests) = tokio::sync::mpsc::channel(4);
        let server = socket.spawn(tx);

        // The tail loop, reduced to the part `wires publish` talks to: the
        // single sequence allocator.
        let loop_store = Arc::clone(&store);
        let node = NodeIdentity::from_seed([2u8; 32]);
        let (topic, version, key) = (ctx.topic, member.version, member.key.clone());
        let tail = tokio::spawn(async move {
            while let Some(request) = requests.recv().await {
                let answer =
                    append_local(&loop_store, &node, topic, version, &key, &request.text, 5)
                        .map(|envelope| envelope.seq.0)
                        .map_err(|e| format!("{e:#}"));
                let _ = request.reply.send(answer);
            }
        });

        let mut client = ipc::ControlClient::connect(&path).await.unwrap().unwrap();
        assert_eq!(client.publish("hello").await.unwrap(), 0);
        assert_eq!(client.publish("again").await.unwrap(), 1);

        // The tail — not the publisher — allocated and stored them.
        let stored = store.read_backfill(10).unwrap();
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0].open(&member.key).unwrap(), b"hello");
        assert_eq!(stored[1].open(&member.key).unwrap(), b"again");
        assert_eq!(stored[1].prev_hash, stored[0].message_hash().unwrap());

        drop(client);
        server.abort();
        tail.abort();
    }

    /// A streaming publish survives a refusal and a tail restart.
    ///
    /// `tail -f app.log | wires publish ops` used to end on the first error —
    /// and the tail answers `{"err":…}` for something as ordinary as "no fabric
    /// key for the current commit yet", in the window between a `roster commit`
    /// and the operator's `wires import`. The pipe died permanently and every
    /// later line was silently never published.
    #[tokio::test]
    async fn a_streaming_publish_survives_a_refusal_and_a_reconnect() {
        let scratch = ipc::ScratchDir::new("retry");
        let path = scratch.socket("r.sock");

        // A "tail" that refuses the first line the way a keyless one does, then
        // answers normally.
        let socket = ipc::ControlSocket::bind(&path).await.unwrap();
        let (tx, mut requests) = tokio::sync::mpsc::channel(4);
        let server = socket.spawn(tx);
        let tail = tokio::spawn(async move {
            let mut seen = 0u64;
            while let Some(request) = requests.recv().await {
                let answer = if seen == 0 {
                    Err("no fabric key in the keyring".to_string())
                } else {
                    Ok(seen)
                };
                seen += 1;
                let _ = request.reply.send(answer);
            }
        });

        let mut client = ipc::ControlClient::connect(&path).await.unwrap();
        assert!(client.is_some(), "the fixture tail is listening");
        let seq = publish_line(&mut client, &path, "first", Duration::from_millis(10))
            .await
            .expect("a refusal must cost a retry, not the whole feed");
        assert_eq!(seq, 1, "the retry is what got through");
        let seq = publish_line(&mut client, &path, "second", Duration::from_millis(10))
            .await
            .expect("and the stream carries on");
        assert_eq!(seq, 2);

        // The tail goes away mid-stream: the line is reported, once, after its
        // attempts — never a silent stop.
        tail.abort();
        server.abort();
        std::fs::remove_file(&path).ok();
        let e = publish_line(&mut client, &path, "third", Duration::from_millis(10))
            .await
            .expect_err("with no tail there is nothing to publish through");
        assert!(format!("{e:#}").contains("no resident tail"), "{e:#}");
    }

    /// A publisher does not wait forever on a tail that never answers.
    #[tokio::test]
    async fn a_publish_gives_up_on_a_tail_that_never_answers() {
        let scratch = ipc::ScratchDir::new("mute");
        let path = scratch.socket("m.sock");
        let socket = ipc::ControlSocket::bind(&path).await.unwrap();
        // Bound and accepting, but nothing ever reads the request channel: the
        // shape of a tail wedged on a slow peer.
        let (tx, _requests) = tokio::sync::mpsc::channel(4);
        let server = socket.spawn(tx);

        let mut client = ipc::ControlClient::connect(&path).await.unwrap().unwrap();
        let e = client
            .publish_within("anyone there?", Duration::from_millis(50))
            .await
            .expect_err("a wedged tail must be reported, not waited on");
        assert!(format!("{e:#}").contains("did not answer"), "{e:#}");
        server.abort();
    }

    #[test]
    fn a_message_line_has_a_fixed_shape() {
        let member = provisioned([2u8; 32]);
        let ctx = member.resolve(&member.args()).unwrap();
        let store = member.store();
        // 01:02:05 UTC, fixed, so the line is byte-comparable.
        let envelope = append_local(
            &store,
            &member.node,
            ctx.topic,
            member.version,
            &member.key,
            "ship it",
            3_725,
        )
        .unwrap();

        let printer = Printer { json: false };
        assert_eq!(
            printer.render(&envelope, "ship it"),
            format!("01:02:05 {} ship it", &member.node.node_id().hex()[..8])
        );
        // The clock is dateless and wraps by day; a pre-epoch timestamp still
        // renders rather than panicking.
        assert_eq!(format_clock(0), "00:00:00");
        assert_eq!(format_clock(86_399), "23:59:59");
        assert_eq!(format_clock(86_400 + 61), "00:01:01");
        assert_eq!(format_clock(-1), "23:59:59");
    }

    #[test]
    fn the_json_line_carries_the_documented_fields() {
        let member = provisioned([2u8; 32]);
        let ctx = member.resolve(&member.args()).unwrap();
        let store = member.store();
        let envelope = append_local(
            &store,
            &member.node,
            ctx.topic,
            member.version,
            &member.key,
            "ship it",
            1_700_000_000,
        )
        .unwrap();

        let line = Printer { json: true }.render(&envelope, "ship it");
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["ts"], 1_700_000_000i64);
        assert_eq!(value["sender"], member.node.node_id().hex());
        assert_eq!(value["seq"], 0);
        assert_eq!(value["text"], "ship it");
        assert!(
            value.get("record").is_none(),
            "plain text carries no record"
        );
        // One line, so NDJSON stays NDJSON.
        assert!(!line.contains('\n'));
    }

    /// `wires serve --audit-topic ops …` for `member`, parsed from the CLI.
    fn audit_serve_args(member: &Member) -> ServeArgs {
        let cli = Cli::try_parse_from([
            "wires",
            "serve",
            "--trust-root",
            &member.root.node_id().hex(),
            "--allow-any-member",
            "--node-seed",
            &member.node.seed_hex(),
            "--audit-topic",
            "ops",
            "--audit-peer",
            "t1",
            "--",
            "cat",
        ])
        .unwrap();
        match cli.command {
            Command::Serve(a) => a,
            _ => panic!("expected serve"),
        }
    }

    /// Run the serve-side audit preflight against `member`'s keystore.
    fn audit_preflight(member: &Member, a: &ServeArgs) -> anyhow::Result<TopicContext> {
        audit_context_in(
            Arc::clone(&member.ks),
            member.home.clone(),
            a,
            "ops",
            member.node.node_id(),
            member.root.node_id(),
        )
    }

    #[test]
    fn serve_parses_the_audit_flags() {
        let member = provisioned([2u8; 32]);
        let a = audit_serve_args(&member);
        assert_eq!(a.audit_topic.as_deref(), Some("ops"));
        assert_eq!(a.audit_peer, vec!["t1".to_string()]);
        // `--audit-peer` means nothing without a topic.
        assert!(
            Cli::try_parse_from([
                "wires",
                "serve",
                "--trust-root",
                "ab",
                "--audit-peer",
                "t",
                "--",
                "cat"
            ])
            .is_err()
        );
    }

    #[test]
    fn audit_topic_preflight_accepts_a_provisioned_member() {
        let member = provisioned([2u8; 32]);
        let mut a = audit_serve_args(&member);
        a.audit_peer.clear();
        let ctx = audit_preflight(&member, &a).unwrap();
        assert_eq!(ctx.topic, TopicId::derive(member.root.node_id(), "ops"));
    }

    #[test]
    fn audit_topic_refuses_to_start_without_a_fabric_key() {
        let member = provisioned([2u8; 32]);
        std::fs::remove_dir_all(member.ks.keyring_dir()).unwrap();
        let mut a = audit_serve_args(&member);
        a.audit_peer.clear();
        let e = format!("{:#}", audit_preflight(&member, &a).unwrap_err());
        assert!(e.contains("--audit-topic"), "{e}");
        assert!(e.contains("wires import --fabric-key-file"), "{e}");
    }

    #[test]
    fn audit_topic_refuses_to_start_without_an_inclusion_proof() {
        let member = provisioned([2u8; 32]);
        std::fs::remove_file(member.ks.path("inclusion-proof.json")).unwrap();
        let mut a = audit_serve_args(&member);
        a.audit_peer.clear();
        let e = format!("{:#}", audit_preflight(&member, &a).unwrap_err());
        assert!(e.contains("wires import --inclusion-proof-file"), "{e}");
    }

    #[test]
    fn audit_topic_refuses_a_channel_in_another_fabric() {
        let member = provisioned([2u8; 32]);
        let mut a = audit_serve_args(&member);
        a.audit_peer.clear();
        let e = audit_context_in(
            Arc::clone(&member.ks),
            member.home.clone(),
            &a,
            "ops",
            member.node.node_id(),
            NodeIdentity::from_seed([77u8; 32]).node_id(),
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("--trust-root"), "{e:#}");
    }

    #[test]
    fn a_record_renders_as_its_record_line_and_json_object() {
        let member = provisioned([2u8; 32]);
        let ctx = member.resolve(&member.args()).unwrap();
        let store = member.store();
        let record = library::ChannelRecord::Audit(library::AuditRecord::Denied {
            caller: member.node.node_id(),
            tool: None,
            reason: "roster inclusion rejected: revoked".into(),
            at_ms: 0,
        });
        let text = record.to_text().unwrap();
        let envelope = append_local(
            &store,
            &member.node,
            ctx.topic,
            member.version,
            &member.key,
            &text,
            3_725,
        )
        .unwrap();
        let short = &member.node.node_id().hex()[..8];

        assert_eq!(
            Printer { json: false }.render(&envelope, &text),
            format!(
                "01:02:05 {short} ✗ {}… denied: roster inclusion rejected: revoked",
                &short[..4]
            )
        );
        let line = Printer { json: true }.render(&envelope, &text);
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!(value.get("text").is_none(), "a record replaces the text");
        assert_eq!(value["record"]["type"], "audit");
        assert_eq!(value["record"]["kind"], "denied");
        assert_eq!(
            serde_json::from_value::<library::ChannelRecord>(value["record"].clone()).unwrap(),
            record
        );
    }

    #[test]
    fn an_unknown_key_version_warns_once_and_heals_on_import() {
        let member = provisioned([2u8; 32]);
        let ctx = member.resolve(&member.args()).unwrap();
        let store = member.store();
        let envelope = append_local(
            &store,
            &member.node,
            ctx.topic,
            member.version,
            &member.key,
            "later",
            1,
        )
        .unwrap();

        // A keystore with no keyring at all: the message is stored, not shown.
        let empty = Arc::new(keystore::Keystore::at(temp_dir()));
        let mut keyring = Keyring::load(Arc::clone(&empty)).unwrap();
        assert!(keyring.open(&envelope).is_none());
        assert!(keyring.open(&envelope).is_none());
        assert_eq!(
            keyring.warned.len(),
            1,
            "one warning per version, not per message"
        );

        // The key arrives; the next message opens without a restart.
        empty.save_fabric_key(member.version, &member.key).unwrap();
        assert_eq!(keyring.open(&envelope).unwrap(), b"later");
    }

    #[test]
    fn the_peer_book_unions_hints_and_survives_a_restart() {
        let home = temp_dir();
        let topic = TopicId::derive(NodeIdentity::from_seed([1u8; 32]).node_id(), "ops");
        let node = NodeIdentity::from_seed([2u8; 32]).node_id();
        let hinted = TopicPeer::new(node).with_addrs(vec!["127.0.0.1:9".parse().unwrap()]);

        let mut book = PeerBook::open(&home, topic);
        assert!(book.list().is_empty());
        assert!(book.record(hinted.clone()));
        assert!(
            !book.record(hinted.clone()),
            "recording twice changes nothing"
        );
        // A bare `NeighborUp` for a peer whose addresses are known must not
        // erase them — a hint with no address is not an improvement.
        assert!(!book.record(TopicPeer::new(node)));
        assert_eq!(book.list(), vec![hinted.clone()]);
        book.save();

        // A second peer, learned live, joins the file.
        let live = NodeIdentity::from_seed([3u8; 32]).node_id();
        assert!(book.record(TopicPeer::new(live)));
        book.save();

        let reopened = PeerBook::open(&home, topic);
        let mut expected = vec![hinted, TopicPeer::new(live)];
        expected.sort_by_key(|p| p.node);
        assert_eq!(reopened.list(), expected);
        assert!(peers_path(&home, topic).is_file());
    }

    #[test]
    fn a_corrupt_peer_file_is_ignored_rather_than_fatal() {
        let home = temp_dir();
        let topic = TopicId::derive(NodeIdentity::from_seed([1u8; 32]).node_id(), "ops");
        let path = peers_path(&home, topic);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{not json").unwrap();
        assert!(PeerBook::open(&home, topic).list().is_empty());
    }

    #[test]
    fn roster_add_remove_changes_membership() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let m = NodeIdentity::from_seed([2u8; 32]).node_id();
        let mut roster = library::Roster::new(root.node_id());
        assert!(roster.insert(m));
        assert!(!roster.insert(m)); // idempotent
        assert!(roster.contains(&m));
        assert!(roster.remove(&m));
        assert!(!roster.contains(&m));
    }
}

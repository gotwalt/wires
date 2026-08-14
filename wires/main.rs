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
mod keystore;
mod pair;
mod store;
mod transport;

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{ArgGroup, Args, Parser, Subcommand};
use library::{
    CapabilityTicket, Crl, FabricKey, Grant, InclusionProof, Membership, NodeId, NodeIdentity,
    RosterHead, Scope, SealedFabricKey,
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
    /// Issue a grant over the wire (announce/consent), instead of pasting ids.
    Pair(PairArgs),
    /// Responder: verify a grant, exec a command, bridge its stdio.
    Serve(ServeArgs),
    /// Dial a capability and pipe local stdio over the session.
    Connect(ConnectArgs),
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
    #[arg(long)]
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
    /// The command (program + args) to exec per session, after `--`.
    #[arg(last = true, required = true)]
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
}

/// `pair` has two sides: `accept` (operator, holds the root key) and `request`
/// (the node that wants a capability).
#[derive(Args)]
struct PairArgs {
    #[command(subcommand)]
    cmd: PairCmd,
}

#[derive(Subcommand)]
enum PairCmd {
    /// Operator: listen, consent, and mint a ticket bound to the requester.
    Accept(PairAcceptArgs),
    /// Requester: dial the operator, announce a scope, print the issued ticket.
    Request(PairRequestArgs),
}

/// `pair accept` arguments: the operator's keys, the terms to grant, and how
/// requesters reach the operator.
#[derive(Args)]
struct PairAcceptArgs {
    /// Operator node key seed (hex). Falls back to env / file / keystore.
    #[arg(long)]
    node_seed: Option<String>,
    /// Read the operator node key seed (hex) from this file.
    #[arg(long)]
    node_seed_file: Option<PathBuf>,
    /// Root signing key seed (hex). Falls back to env / file / keystore.
    #[arg(long)]
    root_seed: Option<String>,
    /// Read the root key seed (hex) from this file.
    #[arg(long)]
    root_seed_file: Option<PathBuf>,
    /// Hex node id of the responder the issued ticket points at.
    #[arg(long)]
    target: String,
    /// The scope to grant (authoritative).
    #[arg(long)]
    scope: String,
    /// Direct address hints for the target, embedded in the issued ticket.
    #[arg(long = "target-addr")]
    target_addr: Vec<SocketAddr>,
    /// Seconds from now until expiry (mutually exclusive with `--not-after`).
    #[arg(long, conflicts_with = "not_after")]
    ttl: Option<i64>,
    /// Absolute expiry, unix seconds (mutually exclusive with `--ttl`).
    #[arg(long)]
    not_after: Option<i64>,
    /// Relay URL: reaches the operator *and* is embedded in the issued ticket.
    #[arg(long)]
    relay_url: Option<String>,
    /// Consent to every request without prompting (for automation).
    #[arg(long)]
    yes: bool,
    /// Exit after the first pairing instead of staying up.
    #[arg(long)]
    once: bool,
}

/// `pair request` arguments: the requester's key and how to reach the operator.
#[derive(Args)]
struct PairRequestArgs {
    /// Requester node key seed (hex). Falls back to env / file / keystore.
    #[arg(long)]
    node_seed: Option<String>,
    /// Read the requester node key seed (hex) from this file.
    #[arg(long)]
    node_seed_file: Option<PathBuf>,
    /// Hex node id of the operator to pair with.
    #[arg(long)]
    operator: String,
    /// Direct address where the operator is reachable (repeatable).
    #[arg(long = "addr")]
    addr: Vec<SocketAddr>,
    /// Relay URL to reach the operator through.
    #[arg(long)]
    relay_url: Option<String>,
    /// The scope being requested (advisory; the operator decides).
    #[arg(long)]
    scope: String,
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
    let scope = a.scope.map(Scope::new);
    if scope.is_none() && !a.allow_any_member {
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
    let config = transport::ServeConfig {
        trust_root,
        scope,
        crl,
        head,
        membership,
        proof,
        command: a.command,
    };
    transport::serve(node, config, a.relay_url.as_deref()).await
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
    init_logging();
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
/// The default filter is `warn,wires=info`: wires' own startup / accept /
/// reject lines print, while iroh's relay and discovery chatter stays out of an
/// MCP client's server-log pane. `$RUST_LOG` overrides it entirely (e.g.
/// `RUST_LOG=iroh=debug`).
fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn,wires=info")),
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
        Command::Pair(a) => match runtime().block_on(pair_cmd(a)) {
            Ok(Some(out)) => println!("{out}"),
            Ok(None) => {}
            Err(e) => {
                eprintln!("wires: {e:#}");
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
            Err(e) => {
                // An authorization refusal is its own outcome: print the
                // responder's own words and exit 77, not the generic 1.
                if let Some(d) = e.downcast_ref::<transport::Denied>() {
                    eprintln!("wires: denied by responder: {}", d.reason());
                    std::process::exit(EXIT_DENIED);
                }
                eprintln!("wires: {e:#}");
                std::process::exit(1);
            }
        },
    }
}

/// `pair`: dispatch to the operator (`accept`) or requester (`request`) side.
/// Returns `Some(ticket)` for `request` (printed), `None` for `accept`.
async fn pair_cmd(a: PairArgs) -> anyhow::Result<Option<String>> {
    match a.cmd {
        PairCmd::Accept(x) => {
            pair_accept_cmd(x).await?;
            Ok(None)
        }
        PairCmd::Request(x) => Ok(Some(pair_request_cmd(x).await?)),
    }
}

async fn pair_accept_cmd(a: PairAcceptArgs) -> anyhow::Result<()> {
    init_logging();
    let node = keystore::node_identity(a.node_seed.as_deref(), a.node_seed_file.as_deref())?;
    let root = keystore::root_identity(a.root_seed.as_deref(), a.root_seed_file.as_deref())?;
    let not_after =
        resolve_not_after(a.ttl, a.not_after, now_unix()).map_err(anyhow::Error::msg)?;
    let terms = pair::PairTerms {
        target: NodeId::from_hex(&a.target)?,
        scope: Scope::new(a.scope),
        not_after,
        addrs: a.target_addr,
        relay_url: a.relay_url.clone(),
    };
    let yes = a.yes;
    let consent = move |requester: NodeId, scope: &str| -> bool {
        if yes {
            return true;
        }
        eprint!("wires pair: grant '{scope}' to {}? [y/N] ", requester.hex());
        use std::io::Write;
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok();
        matches!(line.trim(), "y" | "Y" | "yes")
    };
    pair::pair_accept(node, root, terms, a.relay_url.as_deref(), consent, a.once).await
}

async fn pair_request_cmd(a: PairRequestArgs) -> anyhow::Result<String> {
    init_logging();
    let node = keystore::node_identity(a.node_seed.as_deref(), a.node_seed_file.as_deref())?;
    let operator = transport::endpoint_addr(
        &NodeId::from_hex(&a.operator)?,
        &a.addr,
        a.relay_url.as_deref(),
    )?;
    pair::pair_request(node, operator, Scope::new(a.scope), a.relay_url.as_deref()).await
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
        Command::Pair(_) | Command::Serve(_) | Command::Connect(_) => {
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

//! `wires` — the multi-call CLI for the session layer.
//!
//! Offline admin (`keygen` / `grant` / `revoke`) is built from pure functions
//! over `library`; the network commands (`serve` / `connect`) run on the iroh
//! transport in [`transport`]. Secrets and the CRL resolve through
//! flag → env → `--…-file` → on-disk keystore (see [`keystore`]), so the
//! network commands work without seeds on the command line.

mod keystore;
mod transport;

use std::fmt;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use library::{CapabilityTicket, Crl, Grant, NodeId, NodeIdentity, Scope};

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
    /// Add a subject to the CRL (keystore by default) and print the result.
    Revoke(RevokeArgs),
    /// Operator side of pairing.
    Pair,
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
    /// Seconds from now until expiry (mutually exclusive with `--not-after`).
    #[arg(long, conflicts_with = "not_after")]
    ttl: Option<i64>,
    /// Absolute expiry, unix seconds (mutually exclusive with `--ttl`).
    #[arg(long)]
    not_after: Option<i64>,
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
    /// Hex node id of the trusted fabric root whose grants are honored.
    #[arg(long)]
    trust_root: String,
    /// The scope this responder serves; a grant's scope must match exactly.
    #[arg(long)]
    scope: String,
    /// CRL JSON literal of revoked subjects (overrides `--crl-file` / keystore).
    #[arg(long, conflicts_with = "crl_file")]
    crl_json: Option<String>,
    /// Read the CRL from this file (else the keystore's `crl.json`, else empty).
    #[arg(long)]
    crl_file: Option<PathBuf>,
    /// The command (program + args) to exec per session, after `--`.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

/// `connect` arguments: the dialer key and the capability ticket to present.
#[derive(Args)]
struct ConnectArgs {
    /// Hex 32-byte seed of this dialer's node key. Falls back to
    /// `$WIRES_NODE_SEED`, then `--node-seed-file`, then the keystore (`node.seed`).
    #[arg(long)]
    node_seed: Option<String>,
    /// Read the node key seed (hex) from this file instead of the keystore.
    #[arg(long)]
    node_seed_file: Option<PathBuf>,
    /// The base64 capability ticket (target + scope + grant).
    #[arg(long)]
    ticket: String,
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
) -> library::Result<String> {
    let subject = NodeId::from_hex(subject)?;
    let target = NodeId::from_hex(target)?;
    let scope = Scope::new(scope);
    let grant = Grant::mint(root, subject, scope.clone(), not_after)?;
    let ticket = CapabilityTicket {
        target,
        scope,
        grant,
    };
    ticket.encode()
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

/// Current unix time in seconds.
pub(crate) fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `serve`: bind, verify grants against the trust root, exec + bridge.
async fn serve_cmd(a: ServeArgs) -> anyhow::Result<()> {
    let node = keystore::node_identity(a.node_seed.as_deref(), a.node_seed_file.as_deref())?;
    let trust_root = NodeId::from_hex(&a.trust_root)?;
    let scope = Scope::new(a.scope);
    let crl = keystore::load_crl(a.crl_json.as_deref(), a.crl_file.as_deref())?;
    transport::serve(node, trust_root, scope, crl, a.command).await
}

/// `connect`: dial the ticket's target, present its grant, bridge local stdio.
/// Returns the child's exit code.
async fn connect_cmd(a: ConnectArgs) -> anyhow::Result<i32> {
    let node = keystore::node_identity(a.node_seed.as_deref(), a.node_seed_file.as_deref())?;
    let ticket = CapabilityTicket::decode(&a.ticket)?;
    let target = transport::endpoint_addr(&ticket.target)?;
    transport::connect_io(
        node,
        target,
        ticket.grant,
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

fn main() {
    let cli = Cli::parse();
    match cli.command {
        // Offline admin commands print to stdout (or fail with a message).
        Command::Keygen(_) | Command::Grant(_) | Command::Revoke(_) | Command::Pair => {
            match cli_admin(cli.command) {
                Ok(out) => println!("{out}"),
                Err(e) => {
                    eprintln!("wires: {e}");
                    std::process::exit(1);
                }
            }
        }
        Command::Serve(a) => {
            if let Err(e) = runtime().block_on(serve_cmd(a)) {
                eprintln!("wires: {e:#}");
                std::process::exit(1);
            }
        }
        Command::Connect(a) => match runtime().block_on(connect_cmd(a)) {
            Ok(code) => std::process::exit(code),
            Err(e) => {
                eprintln!("wires: {e:#}");
                std::process::exit(1);
            }
        },
    }
}

/// Run an offline admin subcommand, returning its stdout text.
fn cli_admin(command: Command) -> Result<String, String> {
    match command {
        Command::Keygen(a) => run_keygen_cmd(a).map_err(stringify),
        Command::Grant(a) => {
            let root = keystore::root_identity(a.root_seed.as_deref(), a.root_seed_file.as_deref())
                .map_err(stringify)?;
            let not_after = resolve_not_after(a.ttl, a.not_after, now_unix())?;
            run_grant(&root, &a.subject, &a.target, &a.scope, not_after).map_err(stringify)
        }
        Command::Revoke(a) => run_revoke_cmd(a).map_err(stringify),
        Command::Pair => Err("pair: not implemented (network phase)".to_string()),
        Command::Serve(_) | Command::Connect(_) => unreachable!("handled in main"),
    }
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

            let text = run_grant(&root, &subject.hex(), &target.hex(), &scope, not_after).unwrap();
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
        assert!(run_grant(&root, "nothex", &target.hex(), "tools.rg", 1).is_err());
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
}

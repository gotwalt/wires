//! `wires` — the multi-call CLI for the session layer.
//!
//! This phase implements the offline trust-root/admin subcommands —
//! [`keygen`](run_keygen), [`grant`](run_grant), [`revoke`](run_revoke) — as
//! pure functions over `library`, moving key material and the CRL through flags
//! / env / stdin↔stdout (no on-disk state yet). The network subcommands
//! (`serve`, `connect`, `pair`) remain stubs until the iroh transport phase.

use std::fmt;
use std::io::Read;

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
    /// Add a subject to a CRL (read on stdin / `--crl-json`) and print the result.
    Revoke(RevokeArgs),
    /// Operator side of pairing.
    Pair,
    /// Responder: verify a grant, exec a command, bridge its stdio.
    Serve,
    /// Dial a capability and pipe local stdio over the session.
    Connect,
}

/// `keygen` arguments: optional seeds to re-derive instead of generating.
#[derive(Args)]
struct KeygenArgs {
    /// Hex 32-byte seed to use for the node key (else a random one is generated).
    #[arg(long)]
    node_seed: Option<String>,
    /// Hex 32-byte seed to use for the root key (else a random one is generated).
    #[arg(long)]
    root_seed: Option<String>,
}

/// `grant` arguments: the root key, who/what/where, and an expiry.
#[derive(Args)]
struct GrantArgs {
    /// Hex 32-byte seed of the root (signing) key. Falls back to `$WIRES_ROOT_SEED`.
    #[arg(long)]
    root_seed: Option<String>,
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

/// `revoke` arguments: the subject to revoke and the CRL to extend.
#[derive(Args)]
struct RevokeArgs {
    /// Hex node id of the subject to revoke.
    #[arg(long)]
    subject: String,
    /// Existing CRL JSON; if omitted, read from stdin (empty stdin = empty CRL).
    #[arg(long)]
    crl_json: Option<String>,
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
    root_seed: &str,
    subject: &str,
    target: &str,
    scope: &str,
    not_after: i64,
) -> library::Result<String> {
    let root = NodeIdentity::from_seed_hex(root_seed)?;
    let subject = NodeId::from_hex(subject)?;
    let target = NodeId::from_hex(target)?;
    let scope = Scope::new(scope);
    let grant = Grant::mint(&root, subject, scope.clone(), not_after)?;
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
fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Read all of stdin into a string (used when `revoke` has no `--crl-json`).
fn read_stdin() -> Result<String, String> {
    let mut s = String::new();
    std::io::stdin()
        .read_to_string(&mut s)
        .map_err(|e| format!("reading stdin: {e}"))?;
    Ok(s)
}

fn main() {
    let cli = Cli::parse();
    let result: Result<String, String> = match cli.command {
        Command::Keygen(a) => run_keygen(a.node_seed.as_deref(), a.root_seed.as_deref())
            .map(|o| o.to_string())
            .map_err(|e| e.to_string()),
        Command::Grant(a) => {
            let root_seed = a
                .root_seed
                .or_else(|| std::env::var("WIRES_ROOT_SEED").ok());
            match (root_seed, resolve_not_after(a.ttl, a.not_after, now_unix())) {
                (None, _) => Err("missing --root-seed (or $WIRES_ROOT_SEED)".into()),
                (_, Err(e)) => Err(e),
                (Some(root_seed), Ok(not_after)) => {
                    run_grant(&root_seed, &a.subject, &a.target, &a.scope, not_after)
                        .map_err(|e| e.to_string())
                }
            }
        }
        Command::Revoke(a) => {
            let existing = match a.crl_json {
                Some(s) => Ok(s),
                None => read_stdin(),
            };
            existing.and_then(|s| run_revoke(Some(&s), &a.subject).map_err(|e| e.to_string()))
        }
        Command::Pair => Err("pair: not implemented (network phase)".into()),
        Command::Serve => Err("serve: not implemented (network phase)".into()),
        Command::Connect => Err("connect: not implemented (network phase)".into()),
    };
    match result {
        Ok(out) => println!("{out}"),
        Err(e) => {
            eprintln!("wires: {e}");
            std::process::exit(1);
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

            let text = run_grant(&root.seed_hex(), &subject.hex(), &target.hex(), &scope, not_after).unwrap();
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
        assert!(run_grant(&root.seed_hex(), "nothex", &target.hex(), "tools.rg", 1).is_err());
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

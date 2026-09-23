//! Keys, grants, memberships and the CRL: the root's offline minting commands
//! (`wires advanced keygen | grant | member | revoke`).
//!
//! Each command is a pure function over `library` (the testable half) plus a
//! thin `_cmd` wrapper that resolves keys through the [`keystore`] and
//! persists what it was asked to.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Args;
use library::{CapabilityTicket, Crl, Grant, Membership, NodeId, NodeIdentity, Scope};

use super::{keystore, stringify};
use crate::now_unix;

/// `keygen` arguments: optional seeds to re-derive, and whether to persist.
#[derive(Args)]
pub(crate) struct KeygenArgs {
    /// Hex 32-byte seed to use for the node key (else a random one is generated).
    #[arg(long)]
    pub(crate) node_seed: Option<String>,
    /// Hex 32-byte seed to use for the root key (else a random one is generated).
    #[arg(long)]
    pub(crate) root_seed: Option<String>,
    /// Also write the node key to the keystore (`node.seed`).
    #[arg(long)]
    pub(crate) save_node: bool,
    /// Also write the root key to the keystore (`root.seed`).
    #[arg(long)]
    pub(crate) save_root: bool,
    /// Overwrite existing keystore files when saving.
    #[arg(long)]
    pub(crate) force: bool,
}

/// `grant` arguments: the root key, who/what/where, and an expiry.
#[derive(Args)]
pub(crate) struct GrantArgs {
    /// Hex 32-byte seed of the root (signing) key. Falls back to `$WIRES_ROOT_SEED`,
    /// then `--root-seed-file`, then the keystore (`root.seed`).
    #[arg(long)]
    pub(crate) root_seed: Option<String>,
    /// Read the root key seed (hex) from this file instead of the keystore.
    #[arg(long)]
    pub(crate) root_seed_file: Option<PathBuf>,
    /// Hex node id of the subject this grant authorizes.
    #[arg(long)]
    pub(crate) subject: String,
    /// Hex node id of the responder to dial (the ticket target).
    #[arg(long)]
    pub(crate) target: String,
    /// Scope name to authorize (e.g. `tools.rg`).
    #[arg(long)]
    pub(crate) scope: String,
    /// Direct socket address where the target is reachable, embedded in the
    /// ticket so the dialer needs no discovery. Repeatable.
    #[arg(long = "addr")]
    pub(crate) addr: Vec<SocketAddr>,
    /// Relay URL to reach the target through, embedded in the ticket.
    #[arg(long)]
    pub(crate) relay_url: Option<String>,
    /// Seconds from now until expiry (mutually exclusive with `--not-after`).
    #[arg(long, conflicts_with = "not_after")]
    pub(crate) ttl: Option<i64>,
    /// Absolute expiry, unix seconds (mutually exclusive with `--ttl`).
    #[arg(long)]
    pub(crate) not_after: Option<i64>,
}

/// `member` arguments: the root key, who to include, and an expiry. All offline
/// (no network); the fabric id is the root's node id and is recoverable from the
/// minted token, so nothing else need cross machines.
#[derive(Args)]
pub(crate) struct MemberArgs {
    /// Hex 32-byte seed of the root (signing) key. Falls back to `$WIRES_ROOT_SEED`,
    /// then `--root-seed-file`, then the keystore (`root.seed`).
    #[arg(long)]
    pub(crate) root_seed: Option<String>,
    /// Read the root key seed (hex) from this file instead of the keystore.
    #[arg(long)]
    pub(crate) root_seed_file: Option<PathBuf>,
    /// Hex node id of the member this membership includes.
    #[arg(long)]
    pub(crate) subject: String,
    /// Seconds from now until expiry (mutually exclusive with `--not-after`).
    #[arg(long, conflicts_with = "not_after")]
    pub(crate) ttl: Option<i64>,
    /// Absolute expiry, unix seconds (mutually exclusive with `--ttl`).
    #[arg(long)]
    pub(crate) not_after: Option<i64>,
    /// Also write the minted membership to the keystore (`membership.json`).
    #[arg(long)]
    pub(crate) save: bool,
}

/// `revoke` arguments: the subject to revoke and which CRL to extend.
///
/// With neither `--crl-json` nor `--crl-file`, the keystore's `crl.json` is read
/// and rewritten in place. `--crl-file` is read and rewritten in place;
/// `--crl-json` is a one-shot transform printed to stdout.
#[derive(Args)]
pub(crate) struct RevokeArgs {
    /// Hex node id of the subject to revoke.
    #[arg(long)]
    pub(crate) subject: String,
    /// Start from this CRL JSON literal and print the result (no file written).
    #[arg(long, conflicts_with = "crl_file")]
    pub(crate) crl_json: Option<String>,
    /// Read/update this CRL file in place (absent file = empty CRL).
    #[arg(long)]
    pub(crate) crl_file: Option<PathBuf>,
}

/// The four lines `keygen` prints: each key's seed and derived node id (hex).
struct KeygenOutput {
    pub(crate) node_seed: String,
    pub(crate) node_id: String,
    pub(crate) root_seed: String,
    pub(crate) root_id: String,
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
pub(crate) fn resolve_not_after(
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

/// `keygen`: generate/re-derive keys, optionally persist them, and print.
pub(crate) fn run_keygen_cmd(a: KeygenArgs) -> anyhow::Result<String> {
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

/// `member`: mint a membership for `--subject`, optionally persist it to the
/// keystore (`membership.json`), and return its base64 token.
pub(crate) fn run_member_cmd(a: MemberArgs) -> Result<String, String> {
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

/// `revoke`: insert `subject` into the chosen CRL and persist it in place
/// (keystore by default, or `--crl-file`), or transform a `--crl-json` literal.
pub(crate) fn run_revoke_cmd(a: RevokeArgs) -> anyhow::Result<String> {
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

/// `grant`: mint a grant with the root key for `--subject`, scoped `--scope`,
/// and return the base64 ticket for `--target`.
pub(crate) fn run_grant_cmd(a: GrantArgs) -> Result<String, String> {
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
}

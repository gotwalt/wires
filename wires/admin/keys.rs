//! Memberships: the root's offline minting command (`wires advanced member`).
//!
//! Each command is a pure function over `library` (the testable half) plus a
//! thin `_cmd` wrapper that resolves keys through the [`keystore`] and
//! persists what it was asked to.

use std::path::PathBuf;

use clap::Args;
use library::{Membership, NodeId, NodeIdentity};

use super::{keystore, stringify};
use crate::now_unix;

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

/// Resolve a credential's absolute expiry from the mutually-exclusive `--ttl` /
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn seed() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    #[test]
    fn resolve_not_after_rules() {
        assert_eq!(resolve_not_after(Some(10), None, 100), Ok(110));
        assert_eq!(resolve_not_after(None, Some(500), 100), Ok(500));
        assert!(resolve_not_after(Some(1), Some(2), 0).is_err());
        assert!(resolve_not_after(None, None, 0).is_err());
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
            prop_assert!(library::check_inclusion(&m, root.node_id(), member, 0).is_ok());
        }
    }

    #[test]
    fn member_rejects_bad_subject() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        assert!(run_member(&root, "nothex", 0, 1).is_err());
    }
}

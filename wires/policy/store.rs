//! `$WIRES_HOME/policy.json`: this node's newest verified [`SignedPolicy`].
//!
//! Written only through [`adopt_if_newer`], a compare-and-swap under one
//! exclusive lock (`policy.json.lock`, an OS file lock, so it also holds
//! across processes): re-read the stored copy, verify the candidate under the
//! root, require it to be fresh and strictly newer, write atomically. Without
//! the lock a removed member presenting a genuine older policy could roll a
//! node back.
//!
//! Hosts and directories hold the whole policy; callers do too until card
//! 37 gives each its view. A directory keeps its own copy in
//! `directory.redb` ([`crate::directory`]).

use std::fs::OpenOptions;

use anyhow::{Context, Result, bail};
use library::{Membership, NodeId, Policy, SignedPolicy, StateVersion};

use crate::admin::keystore::{Keystore, create_private_dir, write_text_mode};

/// The file name under `$WIRES_HOME`.
pub(crate) const POLICY_FILE: &str = "policy.json";

/// The lock file guarding [`POLICY_FILE`] rewrites.
const LOCK_FILE: &str = "policy.json.lock";

/// When this node last checked its copy with a directory
/// (`policy-checked.txt`, unix seconds): what [`is_stale`] measures against.
const CHECKED_FILE: &str = "policy-checked.txt";

/// A signed policy this node verified under its root, and the typed
/// [`Policy`] its items make: what every role decides and lists from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Held {
    /// The root-signed head and every item, as stored and as served.
    pub(crate) signed: SignedPolicy,
    /// The same items as typed maps.
    pub(crate) policy: Policy,
}

impl Held {
    /// Verify `signed` under `root` and type its items.
    pub(crate) fn verify(signed: SignedPolicy, root: NodeId) -> Result<Held> {
        signed
            .verify(root)
            .context("the policy does not verify under the network root")?;
        let policy = signed.to_policy()?;
        Ok(Held { signed, policy })
    }

    /// Its version.
    pub(crate) fn version(&self) -> StateVersion {
        self.signed.version()
    }

    /// [`library::Error::Expired`] when `now` is past the head's
    /// `not_after`.
    pub(crate) fn check_fresh(&self, now: i64) -> library::Result<()> {
        self.signed.head.check_fresh(now)
    }

    /// The directories the head lists, in the admin's order.
    pub(crate) fn directories(&self) -> &[NodeId] {
        &self.signed.head.head.directories
    }
}

/// This node's membership and its policy (verified under the membership's
/// root), both required: what a command that acts as a member needs first.
/// Either missing is an error that says to run `wires join`.
pub(crate) fn require(ks: &Keystore) -> Result<(Membership, Held)> {
    let membership = ks
        .read_membership()?
        .context("this node has no membership: run `wires join <token>` first")?;
    let held = require_policy(ks, membership.fabric)?;
    Ok((membership, held))
}

/// [`read`], required to exist (for a membership resolved elsewhere, such as
/// a `--membership` flag).
pub(crate) fn require_policy(ks: &Keystore, root: NodeId) -> Result<Held> {
    read(ks, root)?.context("this node holds no signed policy yet: run `wires join <token>` first")
}

/// The stored policy, verified under `root`; `None` if this node has none
/// yet. A present but invalid file is an error (fail closed).
pub(crate) fn read(ks: &Keystore, root: NodeId) -> Result<Option<Held>> {
    let path = ks.path(POLICY_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let signed: SignedPolicy =
        serde_json::from_str(text.trim()).with_context(|| format!("parsing {}", path.display()))?;
    let held = Held::verify(signed, root).with_context(|| format!("{}", path.display()))?;
    Ok(Some(held))
}

/// Store `candidate` if it verifies under `root`, is fresh at `now`, and is
/// strictly newer than the stored copy. Returns whether it was adopted.
pub(crate) fn adopt_if_newer(
    ks: &Keystore,
    candidate: &SignedPolicy,
    root: NodeId,
    now: i64,
) -> Result<bool> {
    candidate
        .verify(root)
        .context("the offered policy does not verify under the network root")?;
    candidate
        .head
        .check_fresh(now)
        .context("the offered policy is not fresh")?;

    let lock_path = ks.path(LOCK_FILE);
    if let Some(dir) = lock_path.parent() {
        create_private_dir(dir)?;
    }
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("opening {}", lock_path.display()))?;
    lock.lock()
        .with_context(|| format!("locking {}", lock_path.display()))?;

    // Under the lock: the stored copy can't change until we release it.
    if let Some(stored) = read(ks, root)?
        && !candidate.is_newer_than(&stored.signed)
    {
        return Ok(false);
    }
    let text = serde_json::to_string(candidate).context("encoding the policy")?;
    if text.contains('\n') {
        bail!("an encoded policy must be one line");
    }
    write_text_mode(&ks.path(POLICY_FILE), &format!("{text}\n"), Some(0o600))?;
    Ok(true)
}

/// The network root this keystore belongs to (its membership's `fabric`);
/// `None` before `init` or `join`.
pub(crate) fn fabric(ks: &Keystore) -> Result<Option<NodeId>> {
    Ok(ks.read_membership()?.map(|m| m.fabric))
}

/// Record that this node's copy was checked against a directory at `now`.
pub(crate) fn mark_checked(ks: &Keystore, now: i64) -> Result<()> {
    write_text_mode(&ks.path(CHECKED_FILE), &format!("{now}\n"), None)
}

/// Whether this node's copy was last checked more than
/// [`STALE_AFTER_SECS`](super::fetch::STALE_AFTER_SECS) before `now` (or
/// never).
pub(crate) fn is_stale(ks: &Keystore, now: i64) -> bool {
    std::fs::read_to_string(ks.path(CHECKED_FILE))
        .ok()
        .and_then(|t| t.trim().parse::<i64>().ok())
        .is_none_or(|at| now.saturating_sub(at) > super::fetch::STALE_AFTER_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::NodeIdentity;

    fn signed(root: &NodeIdentity, version: u64) -> SignedPolicy {
        let mut p = Policy::new(root.node_id());
        p.version = StateVersion(version);
        p.issued = 1;
        p.not_after = i64::MAX;
        crate::testutil::signed_policy(root, p)
    }

    fn keystore() -> Keystore {
        Keystore::at(crate::testutil::temp_dir())
    }

    #[test]
    fn empty_keystore_has_no_policy() {
        let root = NodeIdentity::generate();
        assert!(read(&keystore(), root.node_id()).unwrap().is_none());
    }

    #[test]
    fn adopts_only_strictly_newer_fresh_policies() {
        let root = NodeIdentity::generate();
        let ks = keystore();
        assert!(adopt_if_newer(&ks, &signed(&root, 2), root.node_id(), 10).unwrap());
        assert!(!adopt_if_newer(&ks, &signed(&root, 2), root.node_id(), 10).unwrap());
        assert!(!adopt_if_newer(&ks, &signed(&root, 1), root.node_id(), 10).unwrap());
        assert!(adopt_if_newer(&ks, &signed(&root, 3), root.node_id(), 10).unwrap());
        let stored = read(&ks, root.node_id()).unwrap().unwrap();
        assert_eq!(stored.version(), StateVersion(3));
        // An expired one is refused, however new.
        let mut p = Policy::new(root.node_id());
        p.version = StateVersion(9);
        p.not_after = 5;
        let expired = crate::testutil::signed_policy(&root, p);
        assert!(adopt_if_newer(&ks, &expired, root.node_id(), 10).is_err());
    }

    #[test]
    fn refuses_a_policy_signed_by_another_root() {
        let root = NodeIdentity::generate();
        let other = NodeIdentity::generate();
        let ks = keystore();
        assert!(adopt_if_newer(&ks, &signed(&other, 5), root.node_id(), 10).is_err());
        assert!(read(&ks, root.node_id()).unwrap().is_none());
    }

    #[test]
    fn a_tampered_file_fails_closed() {
        let root = NodeIdentity::generate();
        let ks = keystore();
        adopt_if_newer(&ks, &signed(&root, 1), root.node_id(), 10).unwrap();
        // Bump the version inside the signed head without re-signing.
        let path = ks.path(POLICY_FILE);
        let mut forged: SignedPolicy =
            serde_json::from_str(std::fs::read_to_string(&path).unwrap().trim()).unwrap();
        forged.head.head.version = StateVersion(9);
        std::fs::write(&path, serde_json::to_string(&forged).unwrap()).unwrap();
        assert!(read(&ks, root.node_id()).is_err());
    }

    /// Card 28 §10: a keystore directory the store creates is `0700`, and
    /// the policy file `0600`.
    #[cfg(unix)]
    #[test]
    fn a_new_keystore_dir_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let root = NodeIdentity::generate();
        let dir = crate::testutil::temp_dir().join("fresh-home");
        let ks = Keystore::at(&dir);
        assert!(adopt_if_newer(&ks, &signed(&root, 1), root.node_id(), 10).unwrap());
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&ks.path(POLICY_FILE)), 0o600);
    }

    #[test]
    fn staleness() {
        let ks = keystore();
        let max = super::super::fetch::STALE_AFTER_SECS;
        assert!(is_stale(&ks, 1_000), "never checked is stale");
        mark_checked(&ks, 1_000).unwrap();
        assert!(!is_stale(&ks, 1_000 + max));
        assert!(is_stale(&ks, 1_001 + max));
    }
}

//! `$WIRES_HOME/state.json`: this node's newest verified [`SignedState`].
//!
//! Written only through [`adopt_if_newer`], a compare-and-swap under one
//! exclusive lock (`state.json.lock`, an OS file lock, so it also holds across
//! processes): re-read the stored copy, verify the candidate under the root,
//! require it to be strictly newer, write atomically. Without the lock a
//! removed member presenting a genuine older state could roll a node back.

use std::fs::OpenOptions;

use anyhow::{Context, Result, bail};
use library::{Membership, NodeId, SignedState};

use crate::admin::keystore::{Keystore, create_private_dir, write_text_mode};

/// The file name under `$WIRES_HOME`.
pub(crate) const STATE_FILE: &str = "state.json";

/// The lock file guarding [`STATE_FILE`] rewrites.
const LOCK_FILE: &str = "state.json.lock";

/// This node's membership and its signed state (verified under the
/// membership's root), both required: what a command that acts as a member
/// needs first. Either missing is an error that says to run `wires join`.
pub(crate) fn require(ks: &Keystore) -> Result<(Membership, SignedState)> {
    let membership = ks
        .read_membership()?
        .context("this node has no membership: run `wires join <token>` first")?;
    let state = require_state(ks, membership.fabric)?;
    Ok((membership, state))
}

/// [`read`], required to exist (for a membership resolved elsewhere, such as
/// a `--membership` flag).
pub(crate) fn require_state(ks: &Keystore, root: NodeId) -> Result<SignedState> {
    read(ks, root)?.context("this node holds no signed state yet: run `wires join <token>` first")
}

/// The stored state, verified under `root`; `None` if this node has none yet.
/// A present but invalid file is an error (fail closed).
pub(crate) fn read(ks: &Keystore, root: NodeId) -> Result<Option<SignedState>> {
    let path = ks.path(STATE_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let state =
        SignedState::decode(text.trim()).with_context(|| format!("parsing {}", path.display()))?;
    state
        .verify(root)
        .with_context(|| format!("{} does not verify under the network root", path.display()))?;
    Ok(Some(state))
}

/// Store `candidate` if it verifies under `root`, is fresh at `now`, and is
/// strictly newer than the stored copy. Returns whether it was adopted.
pub(crate) fn adopt_if_newer(
    ks: &Keystore,
    candidate: &SignedState,
    root: NodeId,
    now: i64,
) -> Result<bool> {
    candidate
        .verify(root)
        .context("the offered state does not verify under the network root")?;
    candidate
        .check_fresh(now)
        .context("the offered state is not fresh")?;

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
    let stored = read(ks, root)?;
    if let Some(stored) = &stored
        && !candidate.is_newer_than(stored)
    {
        return Ok(false);
    }
    let text = candidate.encode().context("encoding the state")?;
    if text.contains('\n') {
        bail!("an encoded state must be one line");
    }
    write_text_mode(&ks.path(STATE_FILE), &format!("{text}\n"), Some(0o600))?;
    Ok(true)
}

/// The admin's node id (`state-admin.txt`): where a member pulls newer
/// states from, besides the hosts. An unsigned hint from `init` or the
/// invite token.
const ADMIN_FILE: &str = "state-admin.txt";

/// When this node last checked its copy with a peer (`state-checked.txt`,
/// unix seconds): what [`is_stale`] measures against.
const CHECKED_FILE: &str = "state-checked.txt";

/// The network root this keystore belongs to (its membership's `fabric`);
/// `None` before `init` or `join`.
pub(crate) fn fabric(ks: &Keystore) -> Result<Option<NodeId>> {
    Ok(ks.read_membership()?.map(|m| m.fabric))
}

/// The recorded admin node id, if any.
pub(crate) fn read_admin(ks: &Keystore) -> Result<Option<NodeId>> {
    match std::fs::read_to_string(ks.path(ADMIN_FILE)) {
        Ok(text) => Ok(Some(
            NodeId::from_hex(text.trim()).context("parsing state-admin.txt")?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("reading state-admin.txt"),
    }
}

/// Record the admin's node id.
pub(crate) fn save_admin(ks: &Keystore, admin: NodeId) -> Result<()> {
    write_text_mode(&ks.path(ADMIN_FILE), &format!("{}\n", admin.hex()), None)
}

/// Record that this node's copy was checked against a peer at `now`.
pub(crate) fn mark_checked(ks: &Keystore, now: i64) -> Result<()> {
    write_text_mode(&ks.path(CHECKED_FILE), &format!("{now}\n"), None)
}

/// Whether this node's copy was last checked more than
/// [`STALE_AFTER_SECS`](super::sync::STALE_AFTER_SECS) before `now` (or
/// never).
pub(crate) fn is_stale(ks: &Keystore, now: i64) -> bool {
    std::fs::read_to_string(ks.path(CHECKED_FILE))
        .ok()
        .and_then(|t| t.trim().parse::<i64>().ok())
        .is_none_or(|at| now.saturating_sub(at) > super::sync::STALE_AFTER_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{NodeIdentity, State, StateVersion};

    fn signed(root: &NodeIdentity, version: u64) -> SignedState {
        let mut state = State::new(root.node_id());
        state.version = StateVersion(version);
        state.issued = 1;
        state.not_after = i64::MAX;
        state.sign(root).unwrap()
    }

    fn keystore() -> Keystore {
        Keystore::at(crate::testutil::temp_dir())
    }

    #[test]
    fn empty_keystore_has_no_state() {
        let root = NodeIdentity::generate();
        assert!(read(&keystore(), root.node_id()).unwrap().is_none());
    }

    #[test]
    fn adopts_only_strictly_newer_states() {
        let root = NodeIdentity::generate();
        let ks = keystore();
        assert!(adopt_if_newer(&ks, &signed(&root, 2), root.node_id(), 10).unwrap());
        assert!(!adopt_if_newer(&ks, &signed(&root, 2), root.node_id(), 10).unwrap());
        assert!(!adopt_if_newer(&ks, &signed(&root, 1), root.node_id(), 10).unwrap());
        assert!(adopt_if_newer(&ks, &signed(&root, 3), root.node_id(), 10).unwrap());
        let stored = read(&ks, root.node_id()).unwrap().unwrap();
        assert_eq!(stored.state.version, StateVersion(3));
    }

    #[test]
    fn refuses_a_state_signed_by_another_root() {
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
        // Bump the version inside the signed body without re-signing.
        let path = ks.path(STATE_FILE);
        let mut forged =
            SignedState::decode(std::fs::read_to_string(&path).unwrap().trim()).unwrap();
        forged.state.version = StateVersion(9);
        std::fs::write(&path, format!("{}\n", forged.encode().unwrap())).unwrap();
        assert!(read(&ks, root.node_id()).is_err());
    }

    /// Card 28 §10: a keystore directory the store creates is `0700`, and
    /// the state file `0600`.
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
        assert_eq!(mode(&ks.path(STATE_FILE)), 0o600);
    }

    #[test]
    fn staleness_and_the_admin_hint() {
        let ks = keystore();
        let max = super::super::sync::STALE_AFTER_SECS;
        assert!(is_stale(&ks, 1_000), "never checked is stale");
        mark_checked(&ks, 1_000).unwrap();
        assert!(!is_stale(&ks, 1_000 + max));
        assert!(is_stale(&ks, 1_001 + max));
        assert_eq!(read_admin(&ks).unwrap(), None);
        let admin = NodeIdentity::generate().node_id();
        save_admin(&ks, admin).unwrap();
        assert_eq!(read_admin(&ks).unwrap(), Some(admin));
    }
}

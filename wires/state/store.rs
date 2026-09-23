//! `$WIRES_HOME/state.json`: this node's newest verified [`SignedState`].
//!
//! Written only through [`adopt_if_newer`], a compare-and-swap under one
//! exclusive lock (`state.json.lock`, an OS file lock, so it also holds across
//! processes): re-read the stored copy, verify the candidate under the root,
//! require it to be strictly newer, write atomically. Without the lock a
//! removed member presenting a genuine older state could roll a node back.

// Nothing calls these until lanes 27a/27b/27c wire them in.
#![allow(dead_code)]

use std::fs::OpenOptions;

use anyhow::{Context, Result, bail};
use library::{NodeId, SignedState};

use crate::admin::keystore::{Keystore, write_text_mode};

/// The file name under `$WIRES_HOME`.
pub(crate) const STATE_FILE: &str = "state.json";

/// The lock file guarding [`STATE_FILE`] rewrites.
const LOCK_FILE: &str = "state.json.lock";

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
        .with_context(|| format!("{} does not verify under the fabric root", path.display()))?;
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
        .context("the offered state does not verify under the fabric root")?;
    candidate
        .check_fresh(now)
        .context("the offered state is not fresh")?;

    let lock_path = ks.path(LOCK_FILE);
    if let Some(dir) = lock_path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
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
    // `lock` drops here, releasing the file lock.
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
}

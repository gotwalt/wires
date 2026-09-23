//! Adopting the admin's re-keys: every member's half of `wires invite` and
//! `wires remove`.
//!
//! A commit invalidates every member's credentials at once. The admin
//! publishes the commit as [`ChannelRecord::Rekey`](library::ChannelRecord)
//! records (see [`library::rekey`]); a member that reads one here verifies it
//! against the fabric root and installs its own part — the new fabric key and
//! inclusion proof — plus the head and the proof directory, exactly where
//! `wires advanced import` would have put them. Everything that re-reads the
//! keystore (the admission handler, the watchdog, the ingest floor, the
//! session gate of `serve`, the keyring) then moves to the new commit with no
//! restart and no manual import.
//!
//! Three places feed this module:
//!
//! - the resident loop ([`crate::channel::watch`]) — every live message and
//!   every envelope a catch-up pass inserted;
//! - a one-shot publish whose newest key is a commit behind
//!   ([`catch_up_rekeys`]) — how a caller that was not running during a re-key
//!   (`wires login`) gets the key it must seal under;
//! - the admin's own commit ([`install`]), and `wires join`.
//!
//! The verifier side of the same records is the **proof directory**
//! ([`library::ProofDirectory`]): [`directory_for`] and
//! [`AdmitHandler::load_directory`](crate::channel::admission::AdmitHandler)
//! hand it to the session gate and the topic gate, so a member presenting last
//! commit's proof is still admitted — which is what lets a caller that never
//! ran during the re-key keep calling.

use std::path::Path;

use anyhow::Context;
use library::{
    ChannelRecord, NodeId, NodeIdentity, ProofDirectory, Rekey, RosterHead, RosterVersion,
    TopicEnvelope,
};

use super::admission::AdmitHandler;
use super::printer::Keyring;
use crate::admin::keystore::{DIRECTORY_FILE, Keystore};
use crate::host::transport::HeadSource;

/// What adopting one re-key changed on this node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Adoption {
    /// The record's roster version.
    pub(crate) version: RosterVersion,
    /// The stored head moved forward to it.
    pub(crate) head_advanced: bool,
    /// This node's own proof and fabric key were in the record and installed.
    pub(crate) own: bool,
    /// The record was for an older head than the one stored; only this node's
    /// key (for reading history) was taken from it.
    pub(crate) superseded: bool,
}

/// Verify `rekey` and install what it holds for `me` into `ks`.
///
/// In order, so that no reader ever pairs the new head with the old
/// credentials: `me`'s fabric key (always, if the record has an entry for
/// `me` — even an old commit's key reads old history), then `me`'s proof (if
/// newer than the stored one), then the proof directory, and **last** the
/// head, through `persist_head` — the caller's compare-and-swap (the
/// admission handler's, on a running node), which only ever moves it
/// forward.
///
/// A record for a head older than the stored one changes nothing but the
/// keyring. A record with no entry for `me` still advances the head: the root
/// signed it, and a node the commit removed must learn that it is out.
pub(crate) fn adopt(
    rekey: &Rekey,
    me: &NodeIdentity,
    fabric_root: NodeId,
    ks: &Keystore,
    persist_head: impl FnOnce(&RosterHead) -> anyhow::Result<Option<RosterHead>>,
    now_unix: i64,
) -> anyhow::Result<Adoption> {
    rekey
        .verify(fabric_root, now_unix)
        .context("verifying the re-key against the fabric root")?;
    let version = rekey.head.version;
    let mut adoption = Adoption {
        version,
        head_advanced: false,
        own: false,
        superseded: false,
    };

    let own = rekey
        .open_for(me, fabric_root)
        .context("opening this node's part of the re-key")?;
    if let Some((_, key)) = &own {
        ks.save_fabric_key(version, key)?;
    }

    let stored = ks.read_roster_head()?;
    if stored.as_ref().is_some_and(|h| h.version > version) {
        adoption.superseded = true;
        return Ok(adoption);
    }

    if let Some((proof, _)) = own {
        let current = ks.read_inclusion_proof()?;
        if current
            .as_ref()
            .is_none_or(|p| p.version < proof.version || p.member != me.node_id())
        {
            ks.save_inclusion_proof(&proof)?;
        }
        adoption.own = true;
    }

    let directory = match ks.read_directory() {
        Ok(Some(mut dir)) if dir.head == rekey.head => dir.absorb(rekey).then_some(dir),
        Ok(Some(dir)) if dir.head.version > version => None,
        Ok(_) => Some(ProofDirectory::from_rekey(rekey)),
        // An unreadable directory is replaced, not fatal: it is a cache of
        // public proofs, and the record in hand is a valid start of a new one.
        Err(e) => {
            tracing::warn!("replacing an unreadable proof directory: {e:#}");
            Some(ProofDirectory::from_rekey(rekey))
        }
    };
    if let Some(directory) = directory {
        ks.save_directory(&directory)?;
    }

    adoption.head_advanced = persist_head(&rekey.head)?.is_some();
    Ok(adoption)
}

/// [`adopt`] for a node with no running admission handler (`wires join`,
/// the admin's own commit): the head is written directly, forward only.
pub(crate) fn install(
    rekey: &Rekey,
    me: &NodeIdentity,
    fabric_root: NodeId,
    ks: &Keystore,
    now_unix: i64,
) -> anyhow::Result<Adoption> {
    adopt(
        rekey,
        me,
        fabric_root,
        ks,
        |head| {
            let stored = ks.read_roster_head()?;
            let advance = match &stored {
                Some(stored) => library::adopt_if_newer(stored, head, fabric_root, now_unix),
                None => Some(head.clone()),
            };
            if let Some(head) = &advance {
                ks.save_roster_head(head)?;
            }
            Ok(advance)
        },
        now_unix,
    )
}

/// If `envelope` is a re-key, adopt it on a running node; `None` otherwise.
///
/// Called for **every** envelope the resident node receives — whatever its
/// ingest verdict. A re-key sealed under the outgoing key can arrive after
/// this node already took the new head from an admission, and the epoch floor
/// then refuses to *store* it; its content is still the root's, so it is
/// still adopted. Nothing a sender controls is trusted here: see
/// [`library::rekey`] for why the record needs no signature of its own.
pub(crate) fn observe(
    envelope: &TopicEnvelope,
    keyring: &mut Keyring,
    me: &NodeIdentity,
    admit: &AdmitHandler,
    now_unix: i64,
) -> Option<Adoption> {
    let plaintext = keyring.open(envelope)?;
    let Some(ChannelRecord::Rekey(rekey)) =
        ChannelRecord::parse(&String::from_utf8_lossy(&plaintext))
    else {
        return None;
    };
    let result = adopt(
        &rekey,
        me,
        admit.fabric_root,
        &admit.keystore,
        |head| admit.persist_head(head, now_unix),
        now_unix,
    );
    match result {
        Ok(adoption) => {
            report(&adoption, envelope.sender);
            Some(adoption)
        }
        Err(e) => {
            tracing::warn!(
                sender = %envelope.sender.hex(),
                "ignoring a re-key that does not verify: {e:#}"
            );
            None
        }
    }
}

/// Log an adoption once, at the level it deserves.
fn report(adoption: &Adoption, sender: NodeId) {
    if adoption.superseded {
        tracing::debug!(version = adoption.version.0, "a superseded re-key");
    } else if adoption.own {
        tracing::info!(
            version = adoption.version.0,
            from = %sender.hex(),
            "adopted a re-key: new head, proof and fabric key installed"
        );
    } else if adoption.head_advanced {
        tracing::warn!(
            version = adoption.version.0,
            "adopted a re-key that has no entry for this node: it is no longer in the roster"
        );
    }
}

/// Whether this node's newest fabric key is older than its head — the state a
/// member is in when it missed a re-key, and the one in which a publish is
/// refused ([`current_fabric_key`](super::local::current_fabric_key)).
pub(crate) fn key_is_stale(ks: &Keystore) -> anyhow::Result<bool> {
    let head = ks.read_roster_head()?.map(|h| h.version);
    let key = ks.latest_fabric_key()?.map(|(v, _)| v);
    Ok(matches!((head, key), (Some(head), Some(key)) if key < head))
}

/// One catch-up pass from the peers this node is admitted to, adopting every
/// re-key it brings in. Returns how many were adopted with this node's own
/// part.
///
/// For a node that is not resident — a `wires login` publishing its claim —
/// and missed the re-key while it was not running: admission already moved
/// its head forward (the peer's ack carries the current one), but its newest
/// key is still a commit behind, so it could not publish. The re-key is in
/// every member's log; replay is epoch-permissive, so it comes back here.
pub(crate) async fn catch_up_rekeys(node: &super::topics::TopicNode, me: &NodeIdentity) -> usize {
    let caught = match super::replay::catch_up_collect(
        node.endpoint(),
        node.admit(),
        node.store(),
        node.topic(),
        super::replay::REPLAY_LIMIT,
    )
    .await
    {
        Ok(caught) => caught,
        Err(e) => {
            tracing::warn!("catching up on re-keys: {e:#}");
            return 0;
        }
    };
    let mut keyring = match Keyring::load(std::sync::Arc::clone(&node.admit().keystore)) {
        Ok(keyring) => keyring,
        Err(e) => {
            tracing::warn!("loading the keyring: {e:#}");
            return 0;
        }
    };
    let mut fresh = caught.fresh;
    fresh.sort_by_key(|e| (e.key_version, e.timestamp, e.seq));
    fresh
        .iter()
        .filter_map(|e| observe(e, &mut keyring, me, node.admit(), crate::now_unix()))
        .filter(|a| a.own)
        .count()
}

/// The proof directory beside the head `source` reads, for the session gate.
///
/// Only a keystore-backed head has a well-defined place for one (the
/// directory is written next to `roster-head.json` by [`adopt`]); a pinned
/// or explicit-file head has none, and gets the strict, proof-only check.
/// Unreadable is `None` with a warning: the directory only ever *adds*
/// admissions, so failing without it is failing closed.
pub(crate) fn directory_for(source: &HeadSource) -> Option<ProofDirectory> {
    match source {
        HeadSource::Keystore { path, .. } => read_directory_beside(path),
        _ => None,
    }
}

/// Read the proof directory in the same directory as `head_path`.
fn read_directory_beside(head_path: &Path) -> Option<ProofDirectory> {
    let path = head_path.with_file_name(DIRECTORY_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => match serde_json::from_str(&text) {
            Ok(directory) => Some(directory),
            Err(e) => {
                tracing::warn!(path = %path.display(), "ignoring an unreadable proof directory: {e}");
                None
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            tracing::warn!(path = %path.display(), "ignoring an unreadable proof directory: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;
    use library::{FabricKey, RekeyEntry, Roster, SealedFabricKey};

    /// A root, two members, and a keystore for member `a` holding commit v1.
    struct World {
        root: NodeIdentity,
        a: NodeIdentity,
        b: NodeIdentity,
        roster: Roster,
        ks: Keystore,
    }

    fn commit(root: &NodeIdentity, roster: &mut Roster) -> (Rekey, FabricKey) {
        let (head, proofs) = roster.commit(root, 0, i64::MAX).unwrap();
        let key = FabricKey::generate();
        let entries = proofs
            .into_iter()
            .map(|(m, proof)| RekeyEntry {
                proof,
                key: SealedFabricKey::seal(root, m, head.version, &key).unwrap(),
            })
            .collect();
        (Rekey::new(head, entries), key)
    }

    fn world() -> (World, Rekey) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let a = NodeIdentity::from_seed([2u8; 32]);
        let b = NodeIdentity::from_seed([3u8; 32]);
        let mut roster = Roster::new(root.node_id());
        roster.insert(a.node_id());
        roster.insert(b.node_id());
        let (v1, _) = commit(&root, &mut roster);
        let ks = Keystore::at(temp_dir());
        install(&v1, &a, root.node_id(), &ks, 0).unwrap();
        (
            World {
                root,
                a,
                b,
                roster,
                ks,
            },
            v1,
        )
    }

    #[test]
    fn a_member_installs_its_part_and_the_head_last() {
        let (mut w, v1) = world();
        assert_eq!(w.ks.read_roster_head().unwrap(), Some(v1.head.clone()));

        let (v2, key) = commit(&w.root, &mut w.roster);
        let adoption = install(&v2, &w.a, w.root.node_id(), &w.ks, 0).unwrap();
        assert!(adoption.own && adoption.head_advanced && !adoption.superseded);
        assert_eq!(w.ks.read_roster_head().unwrap(), Some(v2.head.clone()));
        assert_eq!(
            w.ks.read_inclusion_proof().unwrap().unwrap().version,
            v2.head.version
        );
        assert_eq!(
            w.ks.latest_fabric_key().unwrap(),
            Some((v2.head.version, key))
        );
        let dir = w.ks.read_directory().unwrap().unwrap();
        assert_eq!(dir, ProofDirectory::from_rekey(&v2));
        assert!(!key_is_stale(&w.ks).unwrap());
    }

    #[test]
    fn a_removed_member_learns_the_head_and_gets_nothing_else() {
        let (mut w, v1) = world();
        w.roster.remove(&w.a.node_id());
        let (v2, _) = commit(&w.root, &mut w.roster);
        let adoption = install(&v2, &w.a, w.root.node_id(), &w.ks, 0).unwrap();
        assert!(!adoption.own && adoption.head_advanced);
        assert_eq!(w.ks.read_roster_head().unwrap(), Some(v2.head.clone()));
        // Its proof and newest key are still v1's: it can no longer be admitted
        // or publish, which is the point.
        assert_eq!(
            w.ks.read_inclusion_proof().unwrap().unwrap().version,
            v1.head.version
        );
        assert!(key_is_stale(&w.ks).unwrap());
    }

    #[test]
    fn an_older_re_key_moves_nothing_backwards() {
        let (mut w, v1) = world();
        let (v2, _) = commit(&w.root, &mut w.roster);
        install(&v2, &w.a, w.root.node_id(), &w.ks, 0).unwrap();
        let again = install(&v1, &w.a, w.root.node_id(), &w.ks, 0).unwrap();
        assert!(again.superseded && !again.head_advanced);
        assert_eq!(w.ks.read_roster_head().unwrap(), Some(v2.head.clone()));
        assert_eq!(
            w.ks.read_inclusion_proof().unwrap().unwrap().version,
            v2.head.version
        );
        assert_eq!(w.ks.read_directory().unwrap().unwrap().head, v2.head);
    }

    #[test]
    fn a_forged_re_key_is_refused_and_changes_nothing() {
        let (w, v1) = world();
        let forger = NodeIdentity::from_seed([66u8; 32]);
        let mut fake = Roster::new(forger.node_id());
        fake.insert(w.a.node_id());
        fake.insert(w.b.node_id());
        let (forged, _) = commit(&forger, &mut fake);
        assert!(install(&forged, &w.a, w.root.node_id(), &w.ks, 0).is_err());
        assert_eq!(w.ks.read_roster_head().unwrap(), Some(v1.head));
    }

    #[test]
    fn chunks_of_one_commit_fill_one_directory() {
        let (mut w, _) = world();
        let (v2, _) = commit(&w.root, &mut w.roster);
        for part in Rekey::chunks(v2.head.clone(), v2.entries.clone(), 1) {
            install(&part, &w.a, w.root.node_id(), &w.ks, 0).unwrap();
        }
        assert_eq!(
            w.ks.read_directory().unwrap().unwrap(),
            ProofDirectory::from_rekey(&v2)
        );
    }

    #[test]
    fn the_session_gate_reads_the_directory_beside_a_keystore_head_only() {
        let (w, v1) = world();
        let keystore_head = HeadSource::Keystore {
            path: w.ks.path("roster-head.json"),
            armed: std::sync::atomic::AtomicBool::new(true),
        };
        assert_eq!(
            directory_for(&keystore_head),
            Some(ProofDirectory::from_rekey(&v1))
        );
        assert_eq!(directory_for(&HeadSource::Fixed(v1.head.clone())), None);
        assert_eq!(
            directory_for(&HeadSource::File(w.ks.path("roster-head.json"))),
            None
        );
    }
}

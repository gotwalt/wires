//! Re-keys: one roster commit's credentials for every member, as one
//! self-verifying record, and the proof directory a verifier keeps from it.
//!
//! Every `roster commit` invalidates every member's credentials at once: the
//! head moves, every [`InclusionProof`] is re-issued against the new Merkle
//! root, and a fresh [`FabricKey`](crate::FabricKey) is sealed to each
//! survivor. Before this module the admin handed each of those out by hand. A
//! [`Rekey`] carries all of them — the head, and per member its proof and its
//! [`SealedFabricKey`] — so the admin can publish one record on the channel
//! and every member adopts its own part.
//!
//! # Why a Rekey needs no signature of its own
//!
//! Nothing in a `Rekey` is the publisher's word. The head is signed by the
//! fabric root; each proof is a Merkle path that either recomputes the head's
//! root or does not; each sealed key is root-signed and sealed to one member's
//! X25519 key. [`Rekey::verify`] checks all of it against the fabric root, so
//! a record forged, replayed, or re-published by anyone — a removed member
//! included — can do exactly two things to a reader: advance its head to a
//! *newer root-signed* one (the same monotone adoption admission already
//! performs), and hand it a key the root sealed to it. It cannot name a head
//! the root did not sign, admit a node the root did not commit, or deliver a
//! key the reader did not already have a right to.
//!
//! # What it reveals
//!
//! The record rides the channel sealed under the *outgoing* fabric key — the
//! only key the members it is for already hold — so everyone who could read
//! the channel before the commit can read it, including a member that commit
//! removes. That reader learns the new head (public anyway), the surviving
//! members' node ids and Merkle paths, and sealed boxes it cannot open. It
//! does **not** learn the new fabric key: that key exists in plaintext only
//! inside each survivor's keyring.
//!
//! # The proof directory
//!
//! A verifier that holds a [`ProofDirectory`] for its current head can admit a
//! member whose own proof is stale — a caller that was not running when the
//! re-key went out still presents last commit's proof, and the directory has
//! its current one. Substituting it is exactly as strong as the caller
//! presenting it: the proof is a public, root-committed statement about one
//! node id, and the caller is still the key the transport authenticated.
//! [`check_roster_inclusion_via`] is that rule.
//!
//! ```
//! use library::{
//!     check_roster_inclusion_via, FabricKey, NodeIdentity, ProofDirectory, Rekey, RekeyEntry,
//!     Roster, SealedFabricKey,
//! };
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let alice = NodeIdentity::from_seed([2u8; 32]);
//! let bob = NodeIdentity::from_seed([3u8; 32]);
//! let mut roster = Roster::new(root.node_id());
//! roster.insert(alice.node_id());
//! roster.insert(bob.node_id());
//! let (v1, v1_proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
//! let alice_v1 = v1_proofs.iter().find(|(m, _)| *m == alice.node_id()).unwrap().1.clone();
//!
//! // The next commit, as one record: a proof and a sealed key per member.
//! roster.insert(NodeIdentity::from_seed([4u8; 32]).node_id());
//! let (v2, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
//! let key = FabricKey::generate();
//! let entries = proofs
//!     .into_iter()
//!     .map(|(member, proof)| RekeyEntry {
//!         proof,
//!         key: SealedFabricKey::seal(&root, member, v2.version, &key).unwrap(),
//!     })
//!     .collect();
//! let rekey = Rekey::new(v2.clone(), entries);
//! rekey.verify(root.node_id(), 0).unwrap();
//!
//! // Alice opens her own part.
//! let (proof, opened) = rekey.open_for(&alice, root.node_id()).unwrap().unwrap();
//! assert_eq!(proof.version, v2.version);
//! assert_eq!(opened, key);
//!
//! // Bob, a verifier holding the directory, admits Alice's *stale* proof.
//! let directory = ProofDirectory::from_rekey(&rekey);
//! assert!(library::check_roster_inclusion(&v2, &alice_v1, root.node_id(), alice.node_id(), 0).is_err());
//! check_roster_inclusion_via(&v2, Some(&alice_v1), Some(&directory), root.node_id(), alice.node_id(), 0)
//!     .unwrap();
//! # let _ = v1;
//! ```

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::fabric_key::{FabricKey, SealedFabricKey};
use crate::identity::{NodeId, NodeIdentity};
use crate::policy::check_roster_inclusion;
use crate::roster::{InclusionProof, RosterHead};

/// How many members' entries go in one published [`Rekey`] record.
///
/// An entry is roughly 750 bytes of JSON, and an envelope carries its
/// ciphertext as hex, so 32 entries is ~50 KiB on the wire — under the 64 KiB
/// gossip message ceiling the resident node configures. A larger roster is
/// published as several records for the same head (see [`Rekey::chunks`]).
pub const REKEY_ENTRIES_PER_RECORD: usize = 32;

/// One member's part of a commit: its proof under the new head and the new
/// fabric key sealed to it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RekeyEntry {
    /// The member's inclusion proof under the record's head.
    pub proof: InclusionProof,
    /// The commit's fabric key, root-signed and sealed to `proof.member`.
    pub key: SealedFabricKey,
}

impl RekeyEntry {
    /// The member this entry is for.
    pub fn member(&self) -> NodeId {
        self.proof.member
    }

    /// Check this entry belongs to `head` under `fabric_root`: the proof
    /// targets the head's version and recomputes its root, and the sealed key
    /// is the root's, for the same version, sealed to the same member.
    ///
    /// Does **not** check the head itself — [`Rekey::verify`] does that once.
    pub fn verify_under(&self, head: &RosterHead, fabric_root: NodeId) -> Result<()> {
        if self.proof.version != head.version {
            return Err(Error::StaleProof {
                proof: self.proof.version.0,
                head: head.version.0,
            });
        }
        if self.proof.recompute_root() != head.root {
            return Err(Error::NotInRoster);
        }
        self.key.verify(fabric_root)?;
        if self.key.member != self.proof.member {
            return Err(Error::InconsistentRekey(
                "a sealed key is addressed to another member than its proof",
            ));
        }
        if self.key.version != head.version {
            return Err(Error::InconsistentRekey(
                "a sealed key is for another roster version than the head",
            ));
        }
        Ok(())
    }
}

/// A commit's head plus some (usually all) members' entries under it. See the
/// module docs.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Rekey {
    /// The root-signed head this commit produced.
    pub head: RosterHead,
    /// Per-member proofs and sealed keys under `head`, in member order.
    pub entries: Vec<RekeyEntry>,
}

impl Rekey {
    /// A record for `head` carrying `entries` (sorted by member, so two
    /// records built from the same commit are byte-identical).
    pub fn new(head: RosterHead, mut entries: Vec<RekeyEntry>) -> Self {
        entries.sort_by_key(RekeyEntry::member);
        Self { head, entries }
    }

    /// Split one commit's entries into records of at most `per` entries each
    /// (at least one record, even with no entries; `per == 0` is treated as 1).
    pub fn chunks(head: RosterHead, entries: Vec<RekeyEntry>, per: usize) -> Vec<Rekey> {
        let all = Rekey::new(head, entries);
        if all.entries.is_empty() {
            return vec![all];
        }
        all.entries
            .chunks(per.max(1))
            .map(|part| Rekey {
                head: all.head.clone(),
                entries: part.to_vec(),
            })
            .collect()
    }

    /// Verify the whole record against `fabric_root` at `now_unix`: the head's
    /// signature and freshness, then every entry
    /// ([`RekeyEntry::verify_under`]), and that no member appears twice.
    pub fn verify(&self, fabric_root: NodeId, now_unix: i64) -> Result<()> {
        self.head.verify(fabric_root)?;
        if now_unix > self.head.not_after {
            return Err(Error::Expired {
                not_after: self.head.not_after,
            });
        }
        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            if !seen.insert(entry.member()) {
                return Err(Error::InconsistentRekey("a member is listed twice"));
            }
            entry.verify_under(&self.head, fabric_root)?;
        }
        Ok(())
    }

    /// The entry for `member`, if this record carries one.
    pub fn entry_for(&self, member: NodeId) -> Option<&RekeyEntry> {
        self.entries.iter().find(|e| e.member() == member)
    }

    /// `me`'s own part, opened: its proof and the plaintext fabric key.
    /// `Ok(None)` when the record has no entry for `me` — the reader was
    /// removed by this commit, or its entry is in another chunk.
    ///
    /// Opens only an entry that passes [`RekeyEntry::verify_under`]; call
    /// [`verify`](Self::verify) first to also check the head.
    pub fn open_for(
        &self,
        me: &NodeIdentity,
        fabric_root: NodeId,
    ) -> Result<Option<(InclusionProof, FabricKey)>> {
        let Some(entry) = self.entry_for(me.node_id()) else {
            return Ok(None);
        };
        entry.verify_under(&self.head, fabric_root)?;
        let key = entry.key.open(me, fabric_root)?;
        Ok(Some((entry.proof.clone(), key)))
    }
}

/// The current head's proofs for every member a verifier has heard of — what
/// lets it admit a member whose own proof is a commit behind. See the module
/// docs and [`check_roster_inclusion_via`].
///
/// Holds only public material; still, it lists the member set, so the CLI
/// stores it at the same privacy as the root's `roster.json`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ProofDirectory {
    /// The head every proof here targets.
    pub head: RosterHead,
    /// One proof per member, in member order.
    pub proofs: Vec<InclusionProof>,
}

impl ProofDirectory {
    /// A directory holding `rekey`'s head and each of its entries' proofs.
    pub fn from_rekey(rekey: &Rekey) -> Self {
        let mut dir = Self {
            head: rekey.head.clone(),
            proofs: Vec::new(),
        };
        dir.absorb(rekey);
        dir
    }

    /// Merge `rekey`'s proofs into this directory if it is for the same head.
    /// Returns whether anything was added.
    ///
    /// A record for a *different* head is ignored here: which head wins is
    /// the caller's decision (the newer one, by
    /// [`adopt_if_newer`](crate::adopt_if_newer)), after which it starts a
    /// fresh directory with [`from_rekey`](Self::from_rekey).
    pub fn absorb(&mut self, rekey: &Rekey) -> bool {
        if rekey.head != self.head {
            return false;
        }
        let mut changed = false;
        for entry in &rekey.entries {
            if !self.proofs.iter().any(|p| p.member == entry.member()) {
                self.proofs.push(entry.proof.clone());
                changed = true;
            }
        }
        self.proofs.sort_by_key(|p| p.member);
        changed
    }

    /// `member`'s proof, if this directory is for exactly `head` and lists it.
    pub fn proof_for(&self, head: &RosterHead, member: NodeId) -> Option<&InclusionProof> {
        if &self.head != head {
            return None;
        }
        self.proofs.iter().find(|p| p.member == member)
    }
}

/// [`check_roster_inclusion`], falling back to a verifier's
/// [`ProofDirectory`] when the caller's own proof does not hold.
///
/// Accepts iff `presented` passes against `head`, or `directory` is for
/// exactly `head` and its proof for `caller` passes against `head`. Either
/// way the accepted proof is re-verified here against the head — nothing is
/// taken on trust from the file the directory was read from.
///
/// On refusal the error is the presented proof's (a stale proof stays a
/// "stale inclusion proof", so the caller learns what to fix), or
/// [`Error::InclusionProofRequired`] when there was neither.
///
/// The same invariant as `check_roster_inclusion`: only sound when `caller`
/// is the peer the transport authenticated.
pub fn check_roster_inclusion_via(
    head: &RosterHead,
    presented: Option<&InclusionProof>,
    directory: Option<&ProofDirectory>,
    fabric_root: NodeId,
    caller: NodeId,
    now_unix: i64,
) -> Result<()> {
    let direct = presented.map(|p| check_roster_inclusion(head, p, fabric_root, caller, now_unix));
    if let Some(Ok(())) = direct {
        return Ok(());
    }
    if let Some(proof) = directory.and_then(|d| d.proof_for(head, caller))
        && check_roster_inclusion(head, proof, fabric_root, caller, now_unix).is_ok()
    {
        return Ok(());
    }
    match direct {
        Some(err) => err,
        None => Err(Error::InclusionProofRequired),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::{Roster, RosterVersion};
    use proptest::prelude::*;

    /// A committed roster of `n` members (seeds 10..), with every member's
    /// entry under the commit and the key it sealed.
    struct Fixture {
        root: NodeIdentity,
        members: Vec<NodeIdentity>,
        rekey: Rekey,
        key: FabricKey,
        previous: RosterHead,
        previous_proofs: Vec<(NodeId, InclusionProof)>,
    }

    fn fixture(n: u8) -> Fixture {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let members: Vec<_> = (0..n)
            .map(|i| NodeIdentity::from_seed([10 + i; 32]))
            .collect();
        let mut roster = Roster::new(root.node_id());
        for m in &members {
            roster.insert(m.node_id());
        }
        let (previous, previous_proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let key = FabricKey::generate();
        let entries = proofs
            .into_iter()
            .map(|(member, proof)| RekeyEntry {
                proof,
                key: SealedFabricKey::seal(&root, member, head.version, &key).unwrap(),
            })
            .collect();
        Fixture {
            root,
            members,
            rekey: Rekey::new(head, entries),
            key,
            previous,
            previous_proofs,
        }
    }

    #[test]
    fn a_whole_commit_verifies_and_every_member_opens_its_own_part() {
        let f = fixture(3);
        f.rekey.verify(f.root.node_id(), 0).unwrap();
        for m in &f.members {
            let (proof, key) = f
                .rekey
                .open_for(m, f.root.node_id())
                .unwrap()
                .expect("an entry for every member");
            assert_eq!(proof.member, m.node_id());
            assert_eq!(key, f.key);
        }
        let outsider = NodeIdentity::from_seed([99u8; 32]);
        assert_eq!(f.rekey.open_for(&outsider, f.root.node_id()).unwrap(), None);
    }

    #[test]
    fn a_record_from_another_fabric_is_refused() {
        let f = fixture(2);
        let stranger = NodeIdentity::from_seed([7u8; 32]).node_id();
        assert!(f.rekey.verify(stranger, 0).is_err());
    }

    #[test]
    fn an_expired_head_is_refused() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut roster = Roster::new(root.node_id());
        roster.insert(NodeIdentity::from_seed([2u8; 32]).node_id());
        let (head, _) = roster.commit(&root, 0, 100).unwrap();
        let rekey = Rekey::new(head, Vec::new());
        assert!(rekey.verify(root.node_id(), 100).is_ok());
        assert!(matches!(
            rekey.verify(root.node_id(), 101),
            Err(Error::Expired { not_after: 100 })
        ));
    }

    #[test]
    fn an_entry_from_the_previous_commit_is_refused() {
        let mut f = fixture(2);
        let (member, stale) = f.previous_proofs[0].clone();
        f.rekey.entries[0] = RekeyEntry {
            proof: stale,
            key: SealedFabricKey::seal(&f.root, member, f.rekey.head.version, &f.key).unwrap(),
        };
        assert!(matches!(
            f.rekey.verify(f.root.node_id(), 0),
            Err(Error::StaleProof { .. })
        ));
    }

    #[test]
    fn a_key_sealed_to_someone_else_or_another_version_is_refused() {
        let f = fixture(2);
        let (a, b) = (f.members[0].node_id(), f.members[1].node_id());

        let mut swapped = f.rekey.clone();
        let for_b = swapped.entry_for(b).unwrap().key.clone();
        swapped
            .entries
            .iter_mut()
            .find(|e| e.member() == a)
            .unwrap()
            .key = for_b;
        assert!(matches!(
            swapped.verify(f.root.node_id(), 0),
            Err(Error::InconsistentRekey(_))
        ));

        let mut old = f.rekey.clone();
        old.entries[0].key =
            SealedFabricKey::seal(&f.root, old.entries[0].member(), RosterVersion(1), &f.key)
                .unwrap();
        assert!(matches!(
            old.verify(f.root.node_id(), 0),
            Err(Error::InconsistentRekey(_))
        ));
    }

    #[test]
    fn a_key_the_root_did_not_sign_is_refused() {
        let mut f = fixture(2);
        let forger = NodeIdentity::from_seed([66u8; 32]);
        let member = f.rekey.entries[0].member();
        let mut forged = SealedFabricKey::seal(
            &forger,
            member,
            f.rekey.head.version,
            &FabricKey::generate(),
        )
        .unwrap();
        forged.fabric = f.root.node_id(); // claim the real root; the sig says otherwise
        f.rekey.entries[0].key = forged;
        assert!(matches!(
            f.rekey.verify(f.root.node_id(), 0),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn a_member_listed_twice_is_refused() {
        let mut f = fixture(2);
        let dup = f.rekey.entries[0].clone();
        f.rekey.entries.push(dup);
        assert!(matches!(
            f.rekey.verify(f.root.node_id(), 0),
            Err(Error::InconsistentRekey(_))
        ));
    }

    #[test]
    fn chunks_cover_every_entry_exactly_once_under_one_head() {
        let f = fixture(5);
        let parts = Rekey::chunks(f.rekey.head.clone(), f.rekey.entries.clone(), 2);
        assert_eq!(parts.len(), 3);
        let mut dir = ProofDirectory::from_rekey(&parts[0]);
        for part in &parts {
            assert_eq!(part.head, f.rekey.head);
            part.verify(f.root.node_id(), 0).unwrap();
            dir.absorb(part);
        }
        assert_eq!(dir, ProofDirectory::from_rekey(&f.rekey));
        // No entries is still one (empty) record.
        assert_eq!(Rekey::chunks(f.rekey.head.clone(), Vec::new(), 2).len(), 1);
    }

    #[test]
    fn a_directory_ignores_a_record_for_another_head() {
        let f = fixture(2);
        let mut dir = ProofDirectory::from_rekey(&f.rekey);
        let other = Rekey::new(f.previous.clone(), Vec::new());
        assert!(!dir.absorb(&other));
        assert_eq!(dir.proofs.len(), 2);
    }

    #[test]
    fn the_directory_admits_a_stale_proof_only_for_its_own_head() {
        let f = fixture(2);
        let fabric = f.root.node_id();
        let dir = ProofDirectory::from_rekey(&f.rekey);
        let (who, stale) = f.previous_proofs[0].clone();
        let head = &f.rekey.head;

        // Stale alone: refused, and the error says so.
        assert!(matches!(
            check_roster_inclusion_via(head, Some(&stale), None, fabric, who, 0),
            Err(Error::StaleProof { .. })
        ));
        // With the directory: admitted — and with no proof at all, too.
        check_roster_inclusion_via(head, Some(&stale), Some(&dir), fabric, who, 0).unwrap();
        check_roster_inclusion_via(head, None, Some(&dir), fabric, who, 0).unwrap();
        // A directory for another head is no help.
        assert!(check_roster_inclusion_via(&f.previous, None, Some(&dir), fabric, who, 0).is_err());
        // Nothing presented, nothing known: the proof is required.
        assert!(matches!(
            check_roster_inclusion_via(head, None, None, fabric, who, 0),
            Err(Error::InclusionProofRequired)
        ));
    }

    #[test]
    fn the_directory_never_admits_a_node_the_commit_left_out() {
        let f = fixture(2);
        let fabric = f.root.node_id();
        let dir = ProofDirectory::from_rekey(&f.rekey);
        let outsider = NodeIdentity::from_seed([99u8; 32]).node_id();
        // Not even with another member's (valid) proof in hand.
        let borrowed = dir.proofs[0].clone();
        assert!(
            check_roster_inclusion_via(
                &f.rekey.head,
                Some(&borrowed),
                Some(&dir),
                fabric,
                outsider,
                0
            )
            .is_err()
        );
    }

    #[test]
    fn a_rekey_round_trips_through_json() {
        let f = fixture(3);
        let text = serde_json::to_string(&f.rekey).unwrap();
        assert_eq!(serde_json::from_str::<Rekey>(&text).unwrap(), f.rekey);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Whatever the roster size and whoever reads it, a member opens
        /// exactly the commit's key and a non-member opens nothing.
        #[test]
        fn every_member_and_only_members_open_the_key(n in 1u8..8, pick in 0u8..16) {
            let f = fixture(n);
            f.rekey.verify(f.root.node_id(), 0).unwrap();
            let reader = NodeIdentity::from_seed([10 + pick; 32]);
            let opened = f.rekey.open_for(&reader, f.root.node_id()).unwrap();
            if pick < n {
                prop_assert_eq!(opened.map(|(_, k)| k), Some(f.key.clone()));
            } else {
                prop_assert!(opened.is_none());
            }
        }

        /// The directory built from a commit admits every member of it, with
        /// any stale proof or none.
        #[test]
        fn the_directory_admits_every_member(n in 1u8..8) {
            let f = fixture(n);
            let dir = ProofDirectory::from_rekey(&f.rekey);
            for (who, stale) in &f.previous_proofs {
                prop_assert!(check_roster_inclusion_via(
                    &f.rekey.head, Some(stale), Some(&dir), f.root.node_id(), *who, 0
                ).is_ok());
            }
        }
    }
}

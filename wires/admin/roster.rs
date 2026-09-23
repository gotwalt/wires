//! The committed roster, authored offline by the root
//! (`wires advanced roster add | remove | commit | head`).
//!
//! A commit bumps the version, signs a head, emits each member's inclusion
//! proof, and mints one fresh fabric key sealed to every member.

use std::path::PathBuf;

use anyhow::Context;
use clap::{Args, Subcommand};
use library::{FabricKey, NodeId, SealedFabricKey};

use super::keys::resolve_not_after;
use super::{keystore, stringify};
use crate::now_unix;

/// `roster` has four offline operations on the local `roster.json`.
#[derive(Args)]
pub(crate) struct RosterArgs {
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
    pub(crate) member: String,
    /// Hex node id of the fabric (defaults to the keystore root key's node id),
    /// used only when creating a fresh `roster.json`.
    #[arg(long)]
    pub(crate) fabric: Option<String>,
}

/// `roster commit`: the root signing key, the head's expiry, and where to write
/// the emitted per-member proofs and sealed fabric keys.
#[derive(Args)]
pub(crate) struct RosterCommitArgs {
    /// Hex 32-byte seed of the root (signing) key. Falls back to env / file /
    /// keystore (`root.seed`).
    #[arg(long)]
    pub(crate) root_seed: Option<String>,
    /// Read the root key seed (hex) from this file instead of the keystore.
    #[arg(long)]
    pub(crate) root_seed_file: Option<PathBuf>,
    /// Seconds from now until the head expires (mutually exclusive with `--not-after`).
    #[arg(long, conflicts_with = "not_after")]
    pub(crate) ttl: Option<i64>,
    /// Absolute head expiry, unix seconds (mutually exclusive with `--ttl`).
    #[arg(long)]
    pub(crate) not_after: Option<i64>,
    /// Directory to write each member's `<node-id>.proof` and `<node-id>.key`
    /// tokens into. When omitted, both are printed to stdout.
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
}

/// `roster`: dispatch the four offline roster operations.
pub(crate) fn run_roster_cmd(a: RosterArgs) -> Result<String, String> {
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
pub(crate) fn roster_commit_in(
    ks: &keystore::Keystore,
    a: RosterCommitArgs,
) -> anyhow::Result<String> {
    let root = keystore::root_identity(a.root_seed.as_deref(), a.root_seed_file.as_deref())?;
    let not_after =
        resolve_not_after(a.ttl, a.not_after, now_unix()).map_err(anyhow::Error::msg)?;
    let mut roster = ks.read_roster()?.ok_or_else(|| {
        anyhow::anyhow!("no roster.json; run `wires advanced roster add --member <id>` first")
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
    let head = ks.read_roster_head()?.ok_or_else(|| {
        anyhow::anyhow!("no roster-head.json; run `wires advanced roster commit` first")
    })?;
    head.encode().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{commit_args, fabric_fixture, temp_dir};
    use library::NodeIdentity;

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

//! Installing what the admin hands out (`wires advanced import`): the
//! membership, inclusion proof, roster head and sealed fabric key, each
//! checked before it is written into the keystore.

use std::path::PathBuf;

use anyhow::Context;
use clap::{ArgGroup, Args};
use library::{InclusionProof, Membership, RosterHead, SealedFabricKey};

use super::keystore::{self, token_arg};

/// `import` arguments: any combination of the four credentials an agent
/// receives from its operator, inline or as a file.
///
/// This is the last provisioning step, and it is entirely offline. The operator
/// mints tokens (`wires advanced member`, `wires advanced roster commit --out DIR`) and hands them
/// over; the agent runs `wires advanced import` **once**; after that `wires call` and
/// `wires mcp` need no other flags — which is what makes `wires` usable as a
/// bare `command` in an MCP client config.
#[derive(Args)]
#[command(group(ArgGroup::new("creds").required(true).multiple(true)
    .args(["membership", "membership_file", "inclusion_proof", "inclusion_proof_file", "roster_head", "roster_head_file", "fabric_key", "fabric_key_file"])))]
pub(crate) struct ImportArgs {
    /// The base64 membership token to install as `membership.json`.
    #[arg(long, conflicts_with = "membership_file")]
    pub(crate) membership: Option<String>,
    /// Read the membership token from this file (e.g. the operator's output).
    #[arg(long)]
    pub(crate) membership_file: Option<PathBuf>,
    /// The base64 inclusion proof token to install as `inclusion-proof.json`.
    #[arg(long, conflicts_with = "inclusion_proof_file")]
    pub(crate) inclusion_proof: Option<String>,
    /// Read the inclusion proof from this file (`roster commit --out DIR` writes
    /// `<node-id>.proof`).
    #[arg(long)]
    pub(crate) inclusion_proof_file: Option<PathBuf>,
    /// The base64 roster head token to install as `roster-head.json`.
    #[arg(long, conflicts_with = "roster_head_file")]
    pub(crate) roster_head: Option<String>,
    /// Read the roster head token from this file.
    #[arg(long)]
    pub(crate) roster_head_file: Option<PathBuf>,
    /// The base64 sealed fabric key to open and install as `keyring/<version>.key`.
    #[arg(long, conflicts_with = "fabric_key_file")]
    pub(crate) fabric_key: Option<String>,
    /// Read the sealed fabric key from this file (`roster commit --out DIR`
    /// writes `<node-id>.key`).
    #[arg(long)]
    pub(crate) fabric_key_file: Option<PathBuf>,
    /// Install a roster head that is *older* than the one already stored.
    ///
    /// Refused by default: the stored head is a highest-seen watermark, and
    /// walking it backwards re-admits everyone the newer commit removed.
    #[arg(long)]
    pub(crate) force: bool,
}

/// `import`: decode each supplied credential and write it into the keystore
/// under the name the network commands look for. Returns one `wrote <path>`
/// line per installed credential.
pub(crate) fn run_import_cmd(a: ImportArgs) -> anyhow::Result<String> {
    run_import_in(&keystore::Keystore::resolve()?, a)
}

/// [`run_import_cmd`] against an explicit keystore (the testable form).
///
/// The credentials are installed in dependency order: the membership first,
/// because a sealed fabric key is verified against *its* fabric root, so
/// `wires advanced import --membership <m> --fabric-key <k>` works as one command on a
/// blank keystore.
fn run_import_in(ks: &keystore::Keystore, a: ImportArgs) -> anyhow::Result<String> {
    let mut lines = Vec::new();

    if let Some(text) = token_arg(
        a.membership.as_deref(),
        a.membership_file.as_deref(),
        "--membership",
    )? {
        let membership = Membership::decode(&text).context("--membership")?;
        lines.push(format!(
            "wrote {}",
            ks.save_membership(&membership)?.display()
        ));
    }
    if let Some(text) = token_arg(
        a.inclusion_proof.as_deref(),
        a.inclusion_proof_file.as_deref(),
        "--inclusion-proof",
    )? {
        let proof = InclusionProof::decode(&text).context("--inclusion-proof")?;
        lines.push(format!(
            "wrote {}",
            ks.save_inclusion_proof(&proof)?.display()
        ));
    }
    if let Some(text) = token_arg(
        a.roster_head.as_deref(),
        a.roster_head_file.as_deref(),
        "--roster-head",
    )? {
        let head = RosterHead::decode(&text).context("--roster-head")?;
        // Monotone, like the admission path's compare-and-swap (spec §2.2). The
        // stored head is what the running tail enforces on every handshake and
        // every watchdog pass, so importing an older one immediately downgrades
        // the live roster and re-admits members a later commit removed — and a
        // head token is public, freely copyable, and held by every past member,
        // so "paste the head you were given" is a realistic thing to induce an
        // operator to do. There is no reason to walk it backwards except to undo
        // a mistake, which is what `--force` is for.
        match ks.read_roster_head()? {
            Some(stored) if head.version < stored.version && !a.force => anyhow::bail!(
                "--roster-head: refusing to install roster version {} over the stored version {}: \
                 a head only ever moves forward (pass --force if you really mean to roll it back)",
                head.version.0,
                stored.version.0
            ),
            _ => {}
        }
        lines.push(format!("wrote {}", ks.save_roster_head(&head)?.display()));
    }
    if let Some(text) = token_arg(
        a.fabric_key.as_deref(),
        a.fabric_key_file.as_deref(),
        "--fabric-key",
    )? {
        lines.push(format!("wrote {}", import_fabric_key(ks, &text)?.display()));
    }
    Ok(lines.join("\n"))
}

/// Open the sealed fabric key `token` as this node and install the plaintext in
/// the keyring, returning the written path.
///
/// The trust anchor is the installed membership's `fabric`: the same root that
/// vouches for this node's *presence* in the fabric is the only one whose keys
/// it will install, so a key token pasted from a stranger's fabric is refused
/// rather than silently added to the keyring. The member binding (this node is
/// the sealed recipient) and the root signature are checked by
/// [`SealedFabricKey::open`] itself.
fn import_fabric_key(ks: &keystore::Keystore, token: &str) -> anyhow::Result<PathBuf> {
    let sealed = SealedFabricKey::decode(token).context("--fabric-key")?;
    let membership = ks.read_membership()?.ok_or_else(|| {
        anyhow::anyhow!(
            "--fabric-key: no membership installed, so there is no fabric root to check the key \
             against; import the membership first (`wires advanced import --membership <token>`, or pass \
             both in one command) — looked for {}",
            ks.path("membership.json").display()
        )
    })?;
    let node = keystore::node_identity_in(ks)?;
    if sealed.member != node.node_id() {
        anyhow::bail!(
            "--fabric-key: sealed to {} but this node is {}; ask the operator for this node's own \
             <node-id>.key from `wires advanced roster commit --out DIR`",
            sealed.member.hex(),
            node.node_id().hex()
        );
    }
    let key = sealed.open(&node, membership.fabric).with_context(|| {
        format!(
            "--fabric-key: opening the roster version {} key against fabric {}",
            sealed.version.0,
            membership.fabric.hex()
        )
    })?;
    ks.save_fabric_key(sealed.version, &key)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::admin::roster::roster_commit_in;
    use crate::advanced::{Advanced, AdvancedArgs};
    use crate::testutil::{commit_args, fabric_fixture, temp_dir};
    use crate::{Cli, Command};
    use clap::Parser;
    use library::NodeIdentity;

    /// `import` arguments with no credential selected.
    fn import_args() -> ImportArgs {
        ImportArgs {
            force: false,
            membership: None,
            membership_file: None,
            inclusion_proof: None,
            inclusion_proof_file: None,
            roster_head: None,
            roster_head_file: None,
            fabric_key: None,
            fabric_key_file: None,
        }
    }

    /// A member's keystore (node seed + installed membership) and the sealed
    /// key token that `roster commit` emitted for them.
    fn member_fixture(member: &NodeIdentity) -> (keystore::Keystore, NodeIdentity, String) {
        let (root_ks, root, _alice, _bob) = fabric_fixture();
        let summary = roster_commit_in(&root_ks, commit_args(&root, None)).unwrap();
        let token = summary
            .lines()
            .find_map(|l| l.strip_prefix(&format!("key {} ", member.node_id().hex())))
            .unwrap_or_else(|| panic!("no key line in:\n{summary}"))
            .to_string();

        let ks = keystore::Keystore::at(temp_dir());
        ks.save_node(member, false).unwrap();
        (ks, root, token)
    }

    #[test]
    fn import_requires_at_least_one_credential() {
        // Bare `wires advanced import` is a usage error: there is nothing to install.
        assert!(Cli::try_parse_from(["wires", "advanced", "import"]).is_err());
    }

    #[test]
    fn import_parses_a_single_credential_flag() {
        let cli =
            Cli::try_parse_from(["wires", "advanced", "import", "--membership-file", "x"]).unwrap();
        match cli.command {
            Command::Advanced(AdvancedArgs {
                cmd: Advanced::Import(a),
            }) => {
                assert_eq!(a.membership_file.as_deref(), Some(Path::new("x")));
                assert!(a.membership.is_none());
            }
            _ => panic!("expected the import subcommand"),
        }
    }

    #[test]
    fn import_rejects_a_credential_given_twice() {
        // Inline and file for the same credential is ambiguous, not additive.
        assert!(
            Cli::try_parse_from([
                "wires",
                "advanced",
                "import",
                "--membership",
                "tok",
                "--membership-file",
                "x"
            ])
            .is_err()
        );
    }

    #[test]
    fn import_accepts_the_fabric_key_flags() {
        // The key is a credential of the `creds` group: it alone is a valid
        // invocation, and inline-plus-file is still ambiguous.
        let cli =
            Cli::try_parse_from(["wires", "advanced", "import", "--fabric-key-file", "k"]).unwrap();
        match cli.command {
            Command::Advanced(AdvancedArgs {
                cmd: Advanced::Import(a),
            }) => {
                assert_eq!(a.fabric_key_file.as_deref(), Some(Path::new("k")));
                assert!(a.fabric_key.is_none());
            }
            _ => panic!("expected the import subcommand"),
        }
        assert!(
            Cli::try_parse_from([
                "wires",
                "advanced",
                "import",
                "--fabric-key",
                "tok",
                "--fabric-key-file",
                "k"
            ])
            .is_err()
        );
    }

    #[test]
    fn import_installs_a_sealed_fabric_key_into_the_keyring() {
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let (ks, root, token) = member_fixture(&alice);
        let membership = Membership::mint(&root, alice.node_id(), 0, i64::MAX).unwrap();

        // Membership and key in one command: the membership installed first is
        // the trust anchor the key is checked against.
        let out = run_import_in(
            &ks,
            ImportArgs {
                membership: Some(membership.encode().unwrap()),
                fabric_key: Some(token.clone()),
                ..import_args()
            },
        )
        .unwrap();

        let version = SealedFabricKey::decode(&token).unwrap().version;
        let path = ks.fabric_key_path(version);
        assert!(out.contains(&format!("wrote {}", path.display())), "{out}");
        let installed = ks.read_fabric_key(version).unwrap().unwrap();
        assert_eq!(
            ks.latest_fabric_key().unwrap().unwrap(),
            (version, installed.clone())
        );
        assert_eq!(
            SealedFabricKey::decode(&token)
                .unwrap()
                .open(&alice, root.node_id())
                .unwrap(),
            installed
        );

        // Re-running the same import is a no-op, not an error.
        run_import_in(
            &ks,
            ImportArgs {
                fabric_key: Some(token),
                ..import_args()
            },
        )
        .unwrap();
        assert_eq!(ks.read_fabric_key(version).unwrap().unwrap(), installed);
    }

    /// A head only ever moves forward, on the import path too.
    ///
    /// `persist_head` exists because two concurrent admissions could roll the
    /// stored head backwards — but the compare-and-swap covered only the two
    /// network adoption paths. `wires advanced import --roster-head` wrote whatever token
    /// it was handed, with no comparison and no lock, and the running tail
    /// re-reads that file on every handshake and every watchdog pass: importing
    /// an older head downgraded the enforced roster in place and re-admitted
    /// every member the newer commit removed. A head token is public and every
    /// past member holds one, so "paste the head you were given" is a realistic
    /// thing to induce.
    #[test]
    fn import_refuses_a_roster_head_that_walks_backwards() {
        let (ks, root, _alice, _bob) = fabric_fixture();
        roster_commit_in(&ks, commit_args(&root, None)).unwrap();
        let v1 = ks.read_roster_head().unwrap().unwrap();
        roster_commit_in(&ks, commit_args(&root, None)).unwrap();
        let v2 = ks.read_roster_head().unwrap().unwrap();
        assert!(v2.version > v1.version);

        let err = run_import_in(
            &ks,
            ImportArgs {
                roster_head: Some(v1.encode().unwrap()),
                ..import_args()
            },
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("only ever moves forward") && msg.contains("--force"),
            "the refusal must name the remedy: {msg}"
        );
        assert_eq!(
            ks.read_roster_head().unwrap().unwrap(),
            v2,
            "the enforced head must not have moved"
        );

        // The same version again is not a rollback, and neither is a newer one.
        run_import_in(
            &ks,
            ImportArgs {
                roster_head: Some(v2.encode().unwrap()),
                ..import_args()
            },
        )
        .unwrap();
        assert_eq!(ks.read_roster_head().unwrap().unwrap(), v2);

        // ...and an operator who really means it can still undo a mistake.
        run_import_in(
            &ks,
            ImportArgs {
                roster_head: Some(v1.encode().unwrap()),
                force: true,
                ..import_args()
            },
        )
        .unwrap();
        assert_eq!(ks.read_roster_head().unwrap().unwrap(), v1);
    }

    #[test]
    fn import_refuses_a_key_sealed_to_another_member() {
        // Bob's keystore, Alice's copy of the key.
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let bob = NodeIdentity::from_seed([3u8; 32]);
        let (_alice_ks, root, alices_token) = member_fixture(&alice);
        let ks = keystore::Keystore::at(temp_dir());
        ks.save_node(&bob, false).unwrap();
        ks.save_membership(&Membership::mint(&root, bob.node_id(), 0, i64::MAX).unwrap())
            .unwrap();

        let err = run_import_in(
            &ks,
            ImportArgs {
                fabric_key: Some(alices_token),
                ..import_args()
            },
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains(&alice.node_id().hex()), "{msg}");
        assert!(msg.contains(&bob.node_id().hex()), "{msg}");
        assert!(ks.read_keyring().unwrap().is_empty());
    }

    #[test]
    fn import_refuses_a_key_from_a_foreign_fabric() {
        // A membership from a different root: the key is genuine, but not from
        // the authority this node trusts.
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let (ks, _root, token) = member_fixture(&alice);
        let impostor = NodeIdentity::from_seed([9u8; 32]);
        ks.save_membership(&Membership::mint(&impostor, alice.node_id(), 0, i64::MAX).unwrap())
            .unwrap();

        let err = run_import_in(
            &ks,
            ImportArgs {
                fabric_key: Some(token),
                ..import_args()
            },
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains(&impostor.node_id().hex()),
            "{err:#}"
        );
        assert!(ks.read_keyring().unwrap().is_empty());
    }

    #[test]
    fn import_fabric_key_without_a_membership_names_the_remedy() {
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let (ks, _root, token) = member_fixture(&alice); // node.seed only

        let err = run_import_in(
            &ks,
            ImportArgs {
                fabric_key: Some(token),
                ..import_args()
            },
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("wires advanced import --membership"), "{msg}");
        assert!(
            msg.contains(&ks.path("membership.json").display().to_string()),
            "{msg}"
        );
        assert!(ks.read_keyring().unwrap().is_empty());
    }
}

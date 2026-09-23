//! Fixtures shared by the unit tests of more than one role module: scratch
//! directories, a root keystore with a roster to commit, and a member
//! provisioned exactly as `wires advanced import` would leave it.

use std::path::PathBuf;
use std::sync::Arc;

use library::{FabricKey, Membership, NodeIdentity, RosterVersion, TopicId};

use crate::admin::keystore;
use crate::admin::roster::RosterCommitArgs;
use crate::channel::context::{TopicArgs, TopicContext};
use crate::channel::store;

/// A fresh empty directory, under `$TEST_TMPDIR` when bazel provides one.
pub(crate) fn temp_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let base = std::env::var_os("TEST_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!(
        "wires-cli-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `roster commit` arguments with everything but the root seed defaulted.
pub(crate) fn commit_args(root: &NodeIdentity, out: Option<PathBuf>) -> RosterCommitArgs {
    RosterCommitArgs {
        root_seed: Some(root.seed_hex()),
        root_seed_file: None,
        ttl: None,
        not_after: Some(i64::MAX),
        out,
    }
}

/// A keystore holding a two-member `roster.json`, plus the root and the two
/// member identities.
pub(crate) fn fabric_fixture() -> (keystore::Keystore, NodeIdentity, NodeIdentity, NodeIdentity) {
    let root = NodeIdentity::from_seed([1u8; 32]);
    let alice = NodeIdentity::from_seed([2u8; 32]);
    let bob = NodeIdentity::from_seed([3u8; 32]);
    let ks = keystore::Keystore::at(temp_dir());
    let mut roster = library::Roster::new(root.node_id());
    roster.insert(alice.node_id());
    roster.insert(bob.node_id());
    ks.save_roster(&roster).unwrap();
    (ks, root, alice, bob)
}

/// A member keystore provisioned exactly as `wires advanced import` would leave it:
/// node key, membership, inclusion proof, roster head, and one fabric key.
///
/// The keystore directory doubles as `$WIRES_HOME`, which is what it is in
/// production — `topics/` and `run/` sit beside `node.seed`.
pub(crate) struct Member {
    /// The provisioned keystore (also the home directory).
    pub(crate) ks: Arc<keystore::Keystore>,
    /// That keystore's directory.
    pub(crate) home: PathBuf,
    /// The fabric root that signed everything.
    pub(crate) root: NodeIdentity,
    /// This member's identity.
    pub(crate) node: NodeIdentity,
    /// The data key the (single) commit minted.
    pub(crate) key: FabricKey,
    /// The version that key belongs to.
    pub(crate) version: RosterVersion,
}

/// Provision `who` as a member of a two-member fabric.
pub(crate) fn provisioned(who: [u8; 32]) -> Member {
    let root = NodeIdentity::from_seed([1u8; 32]);
    let node = NodeIdentity::from_seed(who);
    let other = NodeIdentity::from_seed([9u8; 32]);
    let mut roster = library::Roster::new(root.node_id());
    roster.insert(node.node_id());
    roster.insert(other.node_id());
    let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
    let proof = proofs
        .into_iter()
        .find(|(m, _)| *m == node.node_id())
        .unwrap()
        .1;
    let key = FabricKey::generate();

    let home = temp_dir();
    let ks = keystore::Keystore::at(&home);
    ks.save_node(&node, true).unwrap();
    ks.save_membership(&Membership::mint(&root, node.node_id(), 0, i64::MAX).unwrap())
        .unwrap();
    ks.save_inclusion_proof(&proof).unwrap();
    ks.save_roster_head(&head).unwrap();
    ks.save_fabric_key(head.version, &key).unwrap();
    Member {
        ks: Arc::new(ks),
        home,
        root,
        node,
        key,
        version: head.version,
    }
}

impl Member {
    /// `--topic ops --node-seed <this member>`, nothing else.
    pub(crate) fn args(&self) -> TopicArgs {
        TopicArgs {
            topic: "ops".into(),
            node_seed: Some(self.node.seed_hex()),
            ..TopicArgs::default()
        }
    }

    /// Resolve a context against this keystore.
    pub(crate) fn resolve(&self, args: &TopicArgs) -> anyhow::Result<TopicContext> {
        TopicContext::resolve(Arc::clone(&self.ks), self.home.clone(), args)
    }

    /// The message log for the resolved topic.
    pub(crate) fn store(&self) -> store::TopicStore {
        store::TopicStore::open(&self.home, TopicId::derive(self.root.node_id(), "ops")).unwrap()
    }
}

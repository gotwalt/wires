//! The five money-shot integration tests of spec §9: the whole Phase 2 stack —
//! roster gate, gossip mesh, hash-chained log, per-commit fabric keys, and
//! peer-symmetric replay — driven over hermetic loopback QUIC.
//!
//! Every other suite in this crate asserts one seam. `admission.rs` proves the
//! watchdog evicts a peer the head no longer includes, over an in-memory duplex.
//! `replay.rs` proves `catch_up` converges, with the gossip mesh absent.
//! `topics.rs` proves two admitted nodes exchange an envelope. Each of those is
//! true and none of them is the claim: the claim is that *revoking a member
//! actually costs the member something*, and that is a property of the seams
//! together. A gate that evicts but leaves the data key in place, or a key
//! rotation on a mesh that never drops the connection, would pass every unit
//! test in the tree and fail the demo.
//!
//! So these tests are deliberately expensive. Each one binds real endpoints
//! (with [`presets::Minimal`](iroh::endpoint::presets::Minimal): no DNS, no
//! pkarr, no relay, nothing that leaves the machine), opens real redb logs under
//! `$TEST_TMPDIR`, and runs the real admission handshake, the real watchdog, and
//! the real replay server. What they do *not* do is wait: every interval the
//! production code reads from a constant is a [`TopicNodeConfig`] field, so the
//! watchdog runs at 20 ms here and the whole suite finishes in seconds.
//!
//! # The five claims
//!
//! | test | spec | the claim |
//! |------|------|-----------|
//! | [`revocation_evicts_neighbor_between_rechecks`] | §2.4.3 | mesh eviction within one watchdog interval of the head landing, and no way back in |
//! | [`removed_member_cannot_read_after_head_advance`] | §2.4.1 | confidentiality is immediate and independent of eviction |
//! | [`late_joiner_cannot_read_pre_join_history`] | §3 | replay hands over the whole log; the keyring is what bounds what is readable |
//! | [`tail_catches_up_after_offline`] | §6 | exactly-once delivery across a restart |
//! | [`live_gap_triggers_replay_and_heals`] | §6 | a hole in the live stream is healed by replay, not papered over |
//!
//! # Reading the fixtures
//!
//! [`Fabric`] is a root that can commit more than once — the one thing the
//! per-module fixtures in `topics.rs` and `replay.rs` cannot do, and the thing
//! every test here turns on. Each [`Commit`] carries the head, every member's
//! inclusion proof under it, and the [`FabricKey`] that commit minted; a
//! [`Member`] "imports" a commit by writing exactly what `wires import` writes,
//! into a real keystore. A member that is not handed a commit simply does not
//! hold its key, which is the entire mechanism behind two of the five tests.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use iroh::Endpoint;
use iroh::address_lookup::memory::MemoryLookup;
use library::{
    ChainState, FabricKey, InclusionProof, NodeId, NodeIdentity, Roster, RosterHead, RosterVersion,
    Seq, TopicEnvelope, TopicId, TopicPeer, next_prev_hash,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::admission::admit_peer;
use crate::ipc::ScratchDir;
use crate::keystore::Keystore;
use crate::replay::{self, Ingested};
use crate::store::{Appended, TopicStore};
use crate::topics::{TopicEvent, TopicNode, TopicNodeConfig, TopicSender};
use crate::transport::{Denied, HeadSource, secret_key};
use crate::{Keyring, Printer};

/// The outer bound on any single wait here.
///
/// Generous because a QUIC handshake plus a gossip join on a loaded CI machine
/// is not instantaneous, and never reached in the passing case: every wait is on
/// an *event* or on a condition polled at [`BEAT`], not on a clock. A hang must
/// fail as a hang, well inside the sandbox's own budget.
const PATIENCE: Duration = Duration::from_secs(30);

/// How often [`settle`] re-checks a condition that has no event to await.
const BEAT: Duration = Duration::from_millis(10);

/// The watchdog interval for a node whose gate is supposed to move during the
/// test. Milliseconds, because [`ADMIT_RECHECK`](crate::admission::ADMIT_RECHECK)
/// is injectable precisely so no test waits 30 seconds for a revocation.
const FAST_RECHECK: Duration = Duration::from_millis(20);

/// The watchdog interval for a node whose gate must *not* move during the test.
///
/// Not "disabled" — there is no such setting, and a node with no watchdog would
/// be a different program. An hour is simply longer than any test here runs, so
/// eviction cannot smuggle itself into a test that is asserting something else
/// (the confidentiality test in particular must fail if the *key* rotation stops
/// working, not pass because the peer happened to be evicted first).
const SLOW_RECHECK: Duration = Duration::from_secs(3600);

// ---------------------------------------------------------------------------
// The fabric
// ---------------------------------------------------------------------------

/// One `roster commit`: the head it signed, every member's proof under it, and
/// the data key it minted.
///
/// The key is generated here rather than sealed per member because these tests
/// exercise *possession*, not distribution: `library/fabric_key.rs` proves
/// sealing and opening, and a member "imports" by having the plaintext key
/// written into its keyring — byte-identical to what `wires import
/// --fabric-key-file` leaves behind.
struct Commit {
    /// The root-signed head this commit produced.
    head: RosterHead,
    /// Each member's inclusion proof under [`head`](Self::head).
    proofs: HashMap<NodeId, InclusionProof>,
    /// The fabric data key this commit minted, sealed (in production) only to
    /// the members listed in it.
    key: FabricKey,
}

/// A fabric root that can commit repeatedly, keeping every version's head,
/// proofs, and data key.
///
/// The multi-commit part is the whole point. Revocation, key rotation, and late
/// joining are all "what changed between version *v* and *v+1*", and a fixture
/// that can only commit once cannot express any of them.
struct Fabric {
    /// The root identity that signs every head and proof.
    root: NodeIdentity,
    /// The live roster the commits are taken from.
    roster: Roster,
    /// The member set as of the last commit, so [`commit`](Self::commit) can be
    /// told a target set rather than a diff.
    members: BTreeSet<NodeId>,
    /// The one topic every fixture here serves.
    topic: TopicId,
    /// Every commit so far, oldest first.
    commits: Vec<Commit>,
}

impl Fabric {
    /// A fresh fabric whose topic is `name` under a fixed root.
    fn new(name: &str) -> Self {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let roster = Roster::new(root.node_id());
        let topic = TopicId::derive(root.node_id(), name);
        Self {
            root,
            roster,
            members: BTreeSet::new(),
            topic,
            commits: Vec::new(),
        }
    }

    /// The fabric root's node id.
    fn id(&self) -> NodeId {
        self.root.node_id()
    }

    /// Commit a roster whose members are **exactly** `members`, minting that
    /// commit's data key, and return the new version.
    ///
    /// Absolute rather than incremental (`add this` / `remove that`) so the test
    /// body reads as the membership timeline it is: `commit(&[a, b])` then
    /// `commit(&[a])` is a revocation, spelled the way the operator thinks of it.
    fn commit(&mut self, members: &[NodeId]) -> RosterVersion {
        let want: BTreeSet<NodeId> = members.iter().copied().collect();
        for gone in self.members.difference(&want) {
            self.roster.remove(gone);
        }
        for added in want.difference(&self.members) {
            self.roster.insert(*added);
        }
        self.members = want;
        let (head, proofs) = self.roster.commit(&self.root, 0, i64::MAX).unwrap();
        let version = head.version;
        self.commits.push(Commit {
            head,
            proofs: proofs.into_iter().collect(),
            key: FabricKey::generate(),
        });
        version
    }

    /// The commit that produced `version`.
    fn at(&self, version: RosterVersion) -> &Commit {
        self.commits
            .iter()
            .find(|c| c.head.version == version)
            .unwrap_or_else(|| panic!("no commit at version {}", version.0))
    }
}

// ---------------------------------------------------------------------------
// Members and their nodes
// ---------------------------------------------------------------------------

/// One member of the fabric: an identity, a `$WIRES_HOME`, and the keystore in
/// it.
///
/// Deliberately separate from the [`TopicNode`] it spawns, because two of these
/// tests stop a node and start another one over the same home — which is the
/// only honest way to test a restart, and the reason the store is opened inside
/// [`spawn`](Self::spawn) rather than held here.
struct Member {
    /// The signing identity, which is also this node's endpoint key.
    identity: NodeIdentity,
    /// `$WIRES_HOME`, removed when the test ends.
    home: ScratchDir,
    /// The keystore under [`home`](Self::home): heads, keyring, proofs.
    keystore: Arc<Keystore>,
}

impl Member {
    /// A member with a fixed identity and an empty home under a short scratch
    /// path (`tag` keeps unix socket paths inside the 104-byte limit, which is
    /// why [`ScratchDir`] exists at all).
    ///
    /// Takes the *seed* rather than a [`NodeIdentity`] because a node identity
    /// is a secret and is deliberately not `Clone`: one member owns exactly one,
    /// and everything that needs to sign borrows it from here.
    fn new(tag: &str, seed: [u8; 32]) -> Self {
        let home = ScratchDir::new(tag);
        let keystore = Arc::new(Keystore::at(home.path()));
        Self {
            identity: NodeIdentity::from_seed(seed),
            home,
            keystore,
        }
    }

    /// This member's node id.
    fn id(&self) -> NodeId {
        self.identity.node_id()
    }

    /// What `wires import --roster-head … --fabric-key-file <node-id>.key` does:
    /// install this commit's head and its data key.
    ///
    /// The per-commit member tax of spec §10, spelled out. A member who is not
    /// handed a commit holds neither its head nor its key, and both halves of
    /// that matter: the head is what its gate enforces, and the key is what its
    /// tail can read.
    fn import(&self, commit: &Commit) {
        self.keystore.save_roster_head(&commit.head).unwrap();
        self.keystore
            .save_fabric_key(commit.head.version, &commit.key)
            .unwrap();
    }

    /// This member's topic log, opened from its home the way `wires tail` opens
    /// it. redb locks the file, so at most one live handle at a time.
    fn store(&self, fab: &Fabric) -> Arc<TopicStore> {
        Arc::new(TopicStore::open(self.home.path(), fab.topic).unwrap())
    }

    /// Stand a resident node up for this member: a hermetic endpoint, the one
    /// router with all three ALPNs, a fresh log, and a watchdog at `recheck`.
    ///
    /// `version` selects which commit's inclusion proof this node presents —
    /// the proof is a startup input in production too (`wires tail` reads it
    /// once), so a node that has not re-imported after a commit keeps presenting
    /// the old one.
    async fn spawn(&self, fab: &Fabric, version: RosterVersion, recheck: Duration) -> TopicNode {
        let store = self.store(fab);
        self.spawn_on_store(fab, version, recheck, store).await
    }

    /// [`spawn`](Self::spawn) over a log the caller already opened.
    async fn spawn_on_store(
        &self,
        fab: &Fabric,
        version: RosterVersion,
        recheck: Duration,
        store: Arc<TopicStore>,
    ) -> TopicNode {
        let mut cfg = TopicNodeConfig::new(
            fab.topic,
            fab.id(),
            Arc::new(HeadSource::Keystore {
                path: self.keystore.path("roster-head.json"),
                armed: AtomicBool::new(false),
            }),
            fab.at(version).proofs[&self.id()].clone(),
            Arc::clone(&self.keystore),
            store,
        );
        cfg.admit_recheck = recheck;
        cfg.replay_debounce = Duration::from_millis(50);
        let lookup = MemoryLookup::new();
        let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(secret_key(&self.identity))
            .address_lookup(lookup.clone())
            .bind()
            .await
            .unwrap();
        TopicNode::spawn_on(endpoint, lookup, cfg).await.unwrap()
    }

    /// The keys this member currently holds, as a tail would load them.
    fn keyring(&self) -> Keyring {
        Keyring::load(Arc::clone(&self.keystore)).unwrap()
    }
}

// ---------------------------------------------------------------------------
// Loopback plumbing
// ---------------------------------------------------------------------------

/// The endpoint's bound sockets with wildcard binds rewritten to localhost, so a
/// hint reaches it with no discovery service (the `transport.rs` idiom).
fn localhost_socks(endpoint: &Endpoint) -> Vec<SocketAddr> {
    endpoint
        .bound_sockets()
        .into_iter()
        .map(|sock| match sock {
            SocketAddr::V4(v4) if v4.ip().is_unspecified() => SocketAddr::V4(
                std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, v4.port()),
            ),
            SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
                SocketAddr::V6(std::net::SocketAddrV6::new(
                    std::net::Ipv6Addr::LOCALHOST,
                    v6.port(),
                    v6.flowinfo(),
                    v6.scope_id(),
                ))
            }
            other => other,
        })
        .collect()
}

/// A bootstrap hint pointing at `node` over loopback.
fn hint(node: &TopicNode) -> TopicPeer {
    TopicPeer::new(node.node_id()).with_addrs(localhost_socks(node.endpoint()))
}

/// Wait for `who` to come up as a neighbor, ignoring everything else.
async fn wait_neighbor_up(rx: &mut mpsc::Receiver<TopicEvent>, who: NodeId) {
    wait_event(
        rx,
        "neighbor up",
        |event| matches!(event, TopicEvent::NeighborUp(peer) if *peer == who),
    )
    .await;
}

/// Wait for `who` to drop out of the mesh, ignoring everything else.
async fn wait_neighbor_down(rx: &mut mpsc::Receiver<TopicEvent>, who: NodeId) {
    wait_event(
        rx,
        "neighbor down",
        |event| matches!(event, TopicEvent::NeighborDown(peer) if *peer == who),
    )
    .await;
}

/// Wait for the next message on the mesh, ignoring neighbor churn.
async fn next_message(rx: &mut mpsc::Receiver<TopicEvent>) -> TopicEnvelope {
    let mut found = None;
    wait_event(rx, "a message", |event| match event {
        TopicEvent::Message(envelope) => {
            found = Some(envelope.clone());
            true
        }
        _ => false,
    })
    .await;
    found.expect("the predicate only returns true after filling this")
}

/// Pump `rx` until `want` accepts an event, or fail after [`PATIENCE`].
///
/// An event wait, never a sleep: the thing being waited for is a message the
/// mesh delivers, so the test proceeds the moment it lands.
async fn wait_event<F>(rx: &mut mpsc::Receiver<TopicEvent>, what: &str, mut want: F)
where
    F: FnMut(&TopicEvent) -> bool,
{
    loop {
        match timeout(PATIENCE, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
        {
            Some(event) => {
                if want(&event) {
                    return;
                }
            }
            None => panic!("the event bridge ended before {what}"),
        }
    }
}

/// Poll `cond` until it holds, or fail after [`PATIENCE`].
///
/// The one shape in this suite that polls rather than awaits, and only where
/// there is nothing to await: the admission watchdog's verdict lands in a
/// `HashMap`, not on a channel. Same pattern as
/// `the_spawned_watchdog_evicts_on_its_own_interval` in `admission.rs`. The
/// interval being polled for is [`FAST_RECHECK`], so this returns in a beat or
/// two — [`PATIENCE`] is the failure bound, not the expected wait.
async fn settle<F: FnMut() -> bool>(mut cond: F, what: &str) {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        if cond() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(BEAT).await;
    }
}

// ---------------------------------------------------------------------------
// Publishing and reading, as the tail does it
// ---------------------------------------------------------------------------

/// Seal `text` as `who`'s next message under `version`'s key and append it —
/// [`publish_from_tail`](crate::publish_from_tail) without the broadcast.
///
/// Split from [`publish`] so a test can decide which messages reach the mesh:
/// `live_gap_triggers_replay_and_heals` needs a message that exists in the
/// publisher's log and was never put on the wire, which is exactly what a
/// dropped datagram looks like from the far side.
fn append(
    fab: &Fabric,
    version: RosterVersion,
    who: &NodeIdentity,
    store: &TopicStore,
    text: &str,
) -> TopicEnvelope {
    let state = store.chain_state(who.node_id()).unwrap();
    let seq = match state {
        None => Seq::ZERO,
        Some(held) => held
            .seq
            .checked_next()
            .expect("a test never reaches Seq::MAX"),
    };
    let envelope = TopicEnvelope::seal(
        who,
        fab.topic,
        seq,
        next_prev_hash(state),
        version,
        &fab.at(version).key,
        0,
        text.as_bytes(),
    )
    .unwrap();
    assert_eq!(store.append(&envelope).unwrap(), Appended::Inserted);
    envelope
}

/// [`append`] and then broadcast — the whole of `wires publish` against a
/// resident tail, minus the control socket.
async fn publish(
    fab: &Fabric,
    version: RosterVersion,
    who: &NodeIdentity,
    store: &TopicStore,
    sender: &TopicSender,
    text: &str,
) -> TopicEnvelope {
    // A fixture guard, not a property under test: passing the wrong node's
    // sender would broadcast into a mesh nobody in this test is listening on,
    // and the resulting failure would look like a lost message.
    assert_eq!(sender.topic(), fab.topic);
    let envelope = append(fab, version, who, store, text);
    sender.broadcast(&envelope).await.unwrap();
    envelope
}

/// The sequences `store` holds for `sender`, in order — dense `0..=n` is what a
/// healed chain looks like.
fn seqs(store: &TopicStore, sender: NodeId) -> Vec<u64> {
    store
        .read_after(sender, None, usize::MAX)
        .unwrap()
        .into_iter()
        .map(|envelope| envelope.seq.0)
        .collect()
}

/// The lines a tail would print for everything stored past `before`.
///
/// A mirror of [`print_new_since`](crate::print_new_since) that returns the
/// lines instead of writing them to stdout, over the same two halves of
/// [`Printer::emit`](crate::Printer): the high-water-mark diff decides *what* is
/// new, [`Keyring::open`](crate::Keyring::open) decides whether it can be shown,
/// and [`Printer::render`](crate::Printer::render) is the production formatter.
/// A message with no key is silently absent here for the same reason it is
/// silently absent from stdout.
fn new_since(
    store: &TopicStore,
    before: &BTreeMap<NodeId, ChainState>,
    printer: &Printer,
    keyring: &mut Keyring,
) -> Vec<String> {
    let mut fresh = Vec::new();
    for (sender, state) in store.hwm_all().unwrap() {
        let from = before.get(&sender).map(|held| held.seq);
        if from == Some(state.seq) {
            continue;
        }
        fresh.extend(store.read_after(sender, from, usize::MAX).unwrap());
    }
    fresh.sort_by_key(|envelope| (envelope.timestamp, envelope.sender, envelope.seq));
    fresh
        .iter()
        .filter_map(|envelope| {
            let plaintext = keyring.open(envelope)?;
            Some(printer.render(envelope, &String::from_utf8_lossy(&plaintext)))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 1. Revocation evicts a meshed neighbor
// ---------------------------------------------------------------------------

/// **Spec §2.4.3.** A member removed by a `roster commit` is out of the mesh
/// within one watchdog interval of the survivor holding the new head — and
/// cannot dial its way back in.
///
/// The shape of the demo, at test speed. A and B are meshed under v1. The root
/// commits v2 without B and A imports it; nothing tells A's running node
/// anything, and B is not consulted at all. A's watchdog re-reads
/// `roster-head.json` on its next tick, finds B's stored proof no longer
/// verifies, and evicts — which closes the connections A tracked for B, so B
/// watches its neighbor disappear.
///
/// The three assertions are three different failures:
///
/// - **out of the registry** — the gate would otherwise keep letting B's
///   *future* connections through.
/// - **the live connection is closed** — the gate is on `accept`, so a
///   connection already through it is never re-checked; dropping the map entry
///   alone would leave B attached until it chose to hang up.
/// - **re-admission is refused** — otherwise eviction is a speed bump, not a
///   revocation: B redials on its own backoff and is back in the mesh.
#[tokio::test]
async fn revocation_evicts_neighbor_between_rechecks() {
    let a = Member::new("ea", [2u8; 32]);
    let b = Member::new("eb", [3u8; 32]);
    let mut fab = Fabric::new("ops");
    let v1 = fab.commit(&[a.id(), b.id()]);
    a.import(fab.at(v1));
    b.import(fab.at(v1));

    // Only A's gate is allowed to move: B's watchdog is parked so the test is
    // asserting A's eviction and not a symmetric coincidence.
    let node_a = a.spawn(&fab, v1, FAST_RECHECK).await;
    let node_b = b.spawn(&fab, v1, SLOW_RECHECK).await;

    let (_send_a, mut rx_a) = node_a.join(fab.topic, &[]).await.unwrap();
    let (_send_b, mut rx_b) = node_b.join(fab.topic, &[hint(&node_a)]).await.unwrap();
    wait_neighbor_up(&mut rx_a, b.id()).await;
    wait_neighbor_up(&mut rx_b, a.id()).await;
    assert!(
        node_a.admitted().peers().contains(&b.id()),
        "the mesh is up because both sides completed admission"
    );

    // The root removes B. A imports the new head; that is the whole event.
    let v2 = fab.commit(&[a.id()]);
    a.import(fab.at(v2));

    settle(
        || !node_a.admitted().peers().contains(&b.id()),
        "the watchdog to evict the removed member",
    )
    .await;

    // Eviction closes what the admission left attached, so B sees it happen
    // rather than sitting in a mesh that has already forgotten it.
    wait_neighbor_down(&mut rx_b, a.id()).await;

    // And B cannot buy its way back: the handshake is re-decided against the
    // head that removed it, and the refusal says so.
    let refusal = admit_peer(
        node_b.endpoint(),
        node_b.admit(),
        &hint(&node_a),
        crate::now_unix(),
    )
    .await
    .expect_err("a removed member must not be able to re-admit itself");
    let denied = refusal
        .downcast_ref::<Denied>()
        .expect("a policy refusal, not a transport failure");
    assert!(
        denied.reason().contains("roster inclusion rejected"),
        "the refusal must name the roster so the operator knows what to fix: {}",
        denied.reason()
    );
    assert!(
        !node_a.admitted().peers().contains(&b.id()),
        "a refused handshake must not put the peer back in the registry"
    );

    node_a.shutdown().await.unwrap();
    node_b.shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// 2. Confidentiality does not wait for eviction
// ---------------------------------------------------------------------------

/// **Spec §2.4.1.** A removed member cannot read what is published after the
/// commit that removed it, *whatever it is still connected to*.
///
/// The watchdogs are parked at [`SLOW_RECHECK`] on purpose, so B is still a
/// neighbour in good standing when the message arrives. That is the point: this
/// test must fail if key rotation stops working, and must not pass merely
/// because eviction got there first. B receives the ciphertext, verifies it,
/// stores it — every step short of reading it — and the store keeps it
/// provisionally (spec §4.1: an envelope whose key never arrives is still a
/// storable envelope, because a later `wires import` heals the display).
///
/// C, who survived the commit and holds the new key, reads the same bytes.
#[tokio::test]
async fn removed_member_cannot_read_after_head_advance() {
    let a = Member::new("ea", [2u8; 32]);
    let b = Member::new("eb", [3u8; 32]);
    let c = Member::new("ec", [4u8; 32]);
    let mut fab = Fabric::new("ops");
    let v1 = fab.commit(&[a.id(), b.id(), c.id()]);
    for member in [&a, &b, &c] {
        member.import(fab.at(v1));
    }

    let node_a = a.spawn(&fab, v1, SLOW_RECHECK).await;
    let node_b = b.spawn(&fab, v1, SLOW_RECHECK).await;
    let node_c = c.spawn(&fab, v1, SLOW_RECHECK).await;

    let (send_a, mut rx_a) = node_a.join(fab.topic, &[]).await.unwrap();
    let (_send_b, mut rx_b) = node_b.join(fab.topic, &[hint(&node_a)]).await.unwrap();
    let (_send_c, mut rx_c) = node_c
        .join(fab.topic, &[hint(&node_a), hint(&node_b)])
        .await
        .unwrap();
    wait_neighbor_up(&mut rx_b, a.id()).await;
    wait_neighbor_up(&mut rx_c, a.id()).await;
    wait_neighbor_up(&mut rx_a, b.id()).await;

    // The root removes B and mints v2's key. A and C are sealed it; B is not,
    // and B is told nothing at all — not even that the head moved.
    let v2 = fab.commit(&[a.id(), c.id()]);
    a.import(fab.at(v2));
    c.import(fab.at(v2));

    let secret = publish(
        &fab,
        v2,
        &a.identity,
        node_a.store(),
        &send_a,
        "the layoff list is final",
    )
    .await;
    assert_eq!(
        secret.key_version, v2,
        "the point of the commit is that this rides on the new key"
    );

    // B is still meshed, and still receives the bytes.
    let at_b = next_message(&mut rx_b).await;
    assert_eq!(at_b, secret, "the ciphertext crosses unchanged");
    assert_eq!(
        replay::ingest(node_b.store(), fab.topic, &at_b).unwrap(),
        Ingested::Inserted,
        "it verifies and chains, so it is stored provisionally (spec §4.1)"
    );

    // ...and cannot read a byte of it. Not with the keyring a tail would load,
    // and not with the last key B was ever sealed.
    let mut keyring_b = b.keyring();
    assert!(
        keyring_b.open(&at_b).is_none(),
        "no key for v2 means `Printer::emit` returns without printing"
    );
    assert!(
        at_b.open(&fab.at(v1).key).is_err(),
        "the key B does hold is the wrong one, and says so"
    );
    assert!(
        b.keystore.read_fabric_key(v2).unwrap().is_none(),
        "B was never sealed v2's key, which is the mechanism, not a side effect"
    );

    // What B stored really is the message, not a placeholder: C, who survived
    // the commit, reads the same envelope out of its own log.
    let at_c = next_message(&mut rx_c).await;
    assert_eq!(at_c, secret);
    assert_eq!(
        replay::ingest(node_c.store(), fab.topic, &at_c).unwrap(),
        Ingested::Inserted
    );
    let mut keyring_c = c.keyring();
    assert_eq!(
        keyring_c.open(&at_c).as_deref(),
        Some(b"the layoff list is final".as_slice()),
        "a surviving member reads it immediately"
    );

    // The bytes are in B's log, verbatim — this is a confidentiality claim, not
    // a delivery one.
    assert_eq!(
        node_b.store().read_after(a.id(), None, 10).unwrap(),
        vec![secret],
    );

    node_a.shutdown().await.unwrap();
    node_b.shutdown().await.unwrap();
    node_c.shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// 3. A late joiner gets the log, not the history
// ---------------------------------------------------------------------------

/// **Spec §3.** A member added at v+1 catches the whole log up by replay, and
/// the chain verifies — but the keyring is what bounds what it can *read*, so
/// everything published before it joined stays ciphertext.
///
/// This is the honest version of "you can't read history": the messages are not
/// withheld. Replay is peer-symmetric and the log is a chain, so hiding a prefix
/// would break the very verification that makes the suffix trustworthy. C gets
/// all three envelopes, verifies all three, stores all three — and opens one,
/// because old keys are never sealed to new members (spec §3: keys are kept
/// forever so replayed history stays readable *to those who held them*).
#[tokio::test]
async fn late_joiner_cannot_read_pre_join_history() {
    let a = Member::new("ea", [2u8; 32]);
    let b = Member::new("eb", [3u8; 32]);
    let c = Member::new("ec", [4u8; 32]);
    let mut fab = Fabric::new("ops");
    let v1 = fab.commit(&[a.id(), b.id()]);
    a.import(fab.at(v1));

    // Two messages from the days before C existed, sealed under v1's key.
    let a_store = a.store(&fab);
    let before_one = append(&fab, v1, &a.identity, &a_store, "we are hiring c");
    let before_two = append(&fab, v1, &a.identity, &a_store, "offer accepted");
    drop(a_store);

    // The root adds C and mints v2's key. A imports it (head, proof, and key);
    // C is sealed v2's key and nothing older.
    let v2 = fab.commit(&[a.id(), b.id(), c.id()]);
    a.import(fab.at(v2));
    c.import(fab.at(v2));

    let node_a = a.spawn(&fab, v2, SLOW_RECHECK).await;
    let after = append(&fab, v2, &a.identity, node_a.store(), "welcome, c");

    let node_c = c.spawn(&fab, v2, SLOW_RECHECK).await;
    timeout(
        PATIENCE,
        admit_peer(
            node_c.endpoint(),
            node_c.admit(),
            &hint(&node_a),
            crate::now_unix(),
        ),
    )
    .await
    .expect("admission timed out")
    .expect("C is a member under v2, and so is A");

    let counts = timeout(
        PATIENCE,
        replay::catch_up(
            node_c.endpoint(),
            node_c.admit(),
            node_c.store(),
            fab.topic,
            replay::REPLAY_LIMIT,
        ),
    )
    .await
    .expect("catch-up timed out")
    .unwrap();

    assert_eq!(
        counts.inserted, 3,
        "the whole log crossed, not just the tail"
    );
    assert_eq!(counts.refused, 0, "and every link of it verified");
    assert_eq!(
        seqs(node_c.store(), a.id()),
        vec![0, 1, 2],
        "the chain C holds is dense from genesis"
    );
    assert_eq!(
        node_c.store().hwm_all().unwrap(),
        node_a.store().hwm_all().unwrap(),
        "the two logs agree, chain hashes included"
    );

    // Now the part that is not delivery: what C can read.
    let mut keyring_c = c.keyring();
    assert!(
        keyring_c.open(&before_one).is_none(),
        "pre-join history is stored, verified, and unreadable"
    );
    assert!(keyring_c.open(&before_two).is_none());
    assert_eq!(
        keyring_c.open(&after).as_deref(),
        Some(b"welcome, c".as_slice()),
        "everything from C's own commit onward opens"
    );
    assert!(
        c.keystore.read_fabric_key(v1).unwrap().is_none(),
        "C was never sealed v1's key — that is the whole mechanism"
    );

    // The same verdict through the printer: one line, not three.
    let printer = Printer { json: false };
    assert_eq!(
        new_since(node_c.store(), &BTreeMap::new(), &printer, &mut keyring_c).len(),
        1,
        "a tail on C prints only what C can open"
    );

    node_a.shutdown().await.unwrap();
    node_c.shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// 4. Offline, then caught up exactly once
// ---------------------------------------------------------------------------

/// **Spec §6.** A tail that was down while three messages were published gets
/// exactly those three on restart — no gap, and no duplicate of what it already
/// had.
///
/// Exactly-once here is structural, not remembered: nothing persists a set of
/// seen ids across the restart. B's high-water marks are in its log, the replay
/// request carries them, the server streams only past them, and the printer
/// fires on `Inserted`. The assertion is therefore a before/after diff of those
/// marks — the same diff [`print_new_since`](crate::print_new_since) uses to
/// decide what a caught-up tail puts on stdout.
///
/// The restart is real: the node is shut down, the redb handle dropped, and a
/// fresh [`TopicNode`] opened over the same home with the same identity.
#[tokio::test]
async fn tail_catches_up_after_offline() {
    let a = Member::new("ea", [2u8; 32]);
    let b = Member::new("eb", [3u8; 32]);
    let mut fab = Fabric::new("ops");
    let v1 = fab.commit(&[a.id(), b.id()]);
    a.import(fab.at(v1));
    b.import(fab.at(v1));

    let node_a = a.spawn(&fab, v1, SLOW_RECHECK).await;
    let node_b = b.spawn(&fab, v1, SLOW_RECHECK).await;
    let (send_a, mut rx_a) = node_a.join(fab.topic, &[]).await.unwrap();
    let (_send_b, mut rx_b) = node_b.join(fab.topic, &[hint(&node_a)]).await.unwrap();
    wait_neighbor_up(&mut rx_a, b.id()).await;
    wait_neighbor_up(&mut rx_b, a.id()).await;

    // One message while B is up, so the restart has a mark to resume from and
    // "no duplicates" is a claim with something to duplicate.
    let live = publish(
        &fab,
        v1,
        &a.identity,
        node_a.store(),
        &send_a,
        "before you left",
    )
    .await;
    let at_b = next_message(&mut rx_b).await;
    assert_eq!(at_b, live);
    assert_eq!(
        replay::ingest(node_b.store(), fab.topic, &at_b).unwrap(),
        Ingested::Inserted
    );

    // B goes away. The redb handle must go with it, or the restart cannot open
    // its own log.
    node_b.shutdown().await.unwrap();

    for text in [
        "while you were out (1)",
        "while you were out (2)",
        "and (3)",
    ] {
        publish(&fab, v1, &a.identity, node_a.store(), &send_a, text).await;
    }

    // B comes back: new endpoint, new node, same identity and same home.
    let node_b = b.spawn(&fab, v1, SLOW_RECHECK).await;
    assert_eq!(
        seqs(node_b.store(), a.id()),
        vec![0],
        "the restart remembers exactly what the last run stored"
    );
    let before = node_b.store().hwm_all().unwrap();

    timeout(
        PATIENCE,
        admit_peer(
            node_b.endpoint(),
            node_b.admit(),
            &hint(&node_a),
            crate::now_unix(),
        ),
    )
    .await
    .expect("admission timed out")
    .expect("both are still members");
    let counts = timeout(
        PATIENCE,
        replay::catch_up(
            node_b.endpoint(),
            node_b.admit(),
            node_b.store(),
            fab.topic,
            replay::REPLAY_LIMIT,
        ),
    )
    .await
    .expect("catch-up timed out")
    .unwrap();

    assert_eq!(counts.inserted, 3, "exactly the three it missed");
    assert_eq!(
        counts.duplicates, 0,
        "the high-water mark stopped the server re-streaming what B had"
    );
    assert_eq!(counts.refused, 0);
    assert_eq!(seqs(node_b.store(), a.id()), vec![0, 1, 2, 3]);

    // The diff a tail would print: three lines, in order, with the message from
    // before the restart absent because it was already shown.
    let printer = Printer { json: false };
    let mut keyring = b.keyring();
    let printed = new_since(node_b.store(), &before, &printer, &mut keyring);
    assert_eq!(
        printed
            .iter()
            .map(|line| line.rsplit_once(' ').unwrap().1.to_string())
            .collect::<Vec<_>>(),
        vec!["(1)", "(2)", "(3)"],
        "exactly the missed run, in chain order: {printed:?}"
    );

    // Once more, to prove the delivery is once and not at-least-once.
    let again = timeout(
        PATIENCE,
        replay::catch_up(
            node_b.endpoint(),
            node_b.admit(),
            node_b.store(),
            fab.topic,
            replay::REPLAY_LIMIT,
        ),
    )
    .await
    .expect("catch-up timed out")
    .unwrap();
    assert_eq!(again.inserted, 0, "a second pass inserts nothing");
    let after = node_b.store().hwm_all().unwrap();
    assert!(
        new_since(node_b.store(), &after, &printer, &mut keyring).is_empty(),
        "and therefore prints nothing"
    );

    node_a.shutdown().await.unwrap();
    node_b.shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// 5. A hole in the live stream heals by replay
// ---------------------------------------------------------------------------

/// **Spec §6.** A message that lands ahead of its publisher's chain is not
/// stored, is not printed, and is not lost: the gap schedules a debounced
/// catch-up, replay fills the run, and the log ends dense.
///
/// The drop is injected the only way it can be made deterministic: A appends
/// three messages to its own log and broadcasts the first and the third. From
/// B's side that is indistinguishable from a lost datagram — seq 0 arrives, seq
/// 1 never does, seq 2 arrives and cannot be chained.
///
/// The pump below is the ingest arm of the tail loop
/// ([`run_tail`](crate::run_tail)) with nothing else in it: ingest, and on a
/// [`Ingested::Gap`] raise the signal. The debounce and the pass are the real
/// [`spawn_gap_healer`](crate::replay::spawn_gap_healer), at 50 ms instead of
/// two seconds.
#[tokio::test]
async fn live_gap_triggers_replay_and_heals() {
    let a = Member::new("ea", [2u8; 32]);
    let b = Member::new("eb", [3u8; 32]);
    let mut fab = Fabric::new("ops");
    let v1 = fab.commit(&[a.id(), b.id()]);
    a.import(fab.at(v1));
    b.import(fab.at(v1));

    let node_a = a.spawn(&fab, v1, SLOW_RECHECK).await;
    let node_b = b.spawn(&fab, v1, SLOW_RECHECK).await;
    let (send_a, mut rx_a) = node_a.join(fab.topic, &[]).await.unwrap();
    let (_send_b, mut rx_b) = node_b.join(fab.topic, &[hint(&node_a)]).await.unwrap();
    wait_neighbor_up(&mut rx_a, b.id()).await;
    wait_neighbor_up(&mut rx_b, a.id()).await;

    let store_b = Arc::clone(node_b.store());
    let (signal, healer) = replay::spawn_gap_healer(
        node_b.endpoint().clone(),
        Arc::clone(node_b.admit()),
        Arc::clone(node_b.store()),
        fab.topic,
        replay::REPLAY_LIMIT,
        Duration::from_millis(50),
    );

    let gaps = Arc::new(AtomicUsize::new(0));
    let pump = tokio::spawn({
        let store = Arc::clone(&store_b);
        let gaps = Arc::clone(&gaps);
        let topic = fab.topic;
        let signal = signal.clone();
        async move {
            while let Some(event) = rx_b.recv().await {
                let TopicEvent::Message(envelope) = event else {
                    continue;
                };
                match replay::ingest(&store, topic, &envelope) {
                    Ok(Ingested::Gap { .. }) => {
                        gaps.fetch_add(1, Ordering::SeqCst);
                        signal.raise();
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!("the pump refused a message: {e:#}"),
                }
            }
        }
    });

    // Seq 1 is sealed and logged by A, and never put on the wire.
    let zero = append(&fab, v1, &a.identity, node_a.store(), "zero");
    let one = append(
        &fab,
        v1,
        &a.identity,
        node_a.store(),
        "one (dropped in flight)",
    );
    let two = append(&fab, v1, &a.identity, node_a.store(), "two");
    send_a.broadcast(&zero).await.unwrap();
    send_a.broadcast(&two).await.unwrap();

    settle(
        || gaps.load(Ordering::SeqCst) > 0,
        "the live stream to surface a chain gap",
    )
    .await;
    settle(
        || seqs(&store_b, a.id()) == vec![0, 1, 2],
        "the debounced catch-up to heal the gap",
    )
    .await;

    // Healed means healed: the run is dense, the hashes agree with A's, and the
    // message that was never broadcast is readable.
    assert_eq!(
        store_b.hwm_all().unwrap(),
        node_a.store().hwm_all().unwrap(),
        "B's chain state matches the publisher's, hash included"
    );
    let mut keyring = b.keyring();
    assert_eq!(
        store_b.read_after(a.id(), None, usize::MAX).unwrap(),
        vec![zero, one.clone(), two],
        "every envelope, in chain order"
    );
    assert_eq!(
        keyring.open(&one).as_deref(),
        Some(b"one (dropped in flight)".as_slice()),
        "the message that never crossed the mesh arrived by replay"
    );

    pump.abort();
    healer.abort();
    node_a.shutdown().await.unwrap();
    node_b.shutdown().await.unwrap();
}

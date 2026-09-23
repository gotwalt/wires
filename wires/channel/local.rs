//! This node's own log on a topic: opening it (waiting out another process's
//! lock), picking the fabric key to publish under, and minting a message —
//! the one place a sequence number is allocated.

use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use library::{FabricKey, NodeIdentity, RosterVersion, Seq, TopicEnvelope, TopicId};

use super::store;
use crate::admin::keystore;

/// How long an operation waits for another process to release the topic log's
/// exclusive redb lock.
///
/// `wires watch` and `wires advanced publish` both open the same file, and the window
/// between them is routine: a login script that starts a tail and publishes in
/// the next line, or a tail restarting while a one-shot publish is lingering.
/// Without a wait, whichever loses fails hard — and if the *tail* loses, a
/// routine publish killed the resident node.
pub(crate) const STORE_LOCK_WAIT: Duration = Duration::from_secs(20);

/// Allocate this node's next sequence on `topic`, seal `text` under `key`, and
/// append it — the one place a message is minted (spec §7).
///
/// Sequence and previous-hash both come from the store's chain state, inside
/// the process that holds the store's exclusive lock, which is what makes "one
/// allocator per (node, topic)" structural rather than a convention. A
/// [`Duplicate`](crate::channel::store::Appended::Duplicate) here would mean two
/// allocators raced, so it is an error, not a shrug.
pub(crate) fn append_local(
    store: &store::TopicStore,
    node: &NodeIdentity,
    topic: TopicId,
    version: RosterVersion,
    key: &FabricKey,
    text: &str,
    now: i64,
) -> anyhow::Result<TopicEnvelope> {
    let state = store
        .chain_state(node.node_id())
        .context("reading this node's chain state")?;
    let seq = match state {
        None => Seq::ZERO,
        Some(state) => state.seq.checked_next().ok_or_else(|| {
            anyhow::anyhow!("this node's chain on the topic is full (sequence u64::MAX)")
        })?,
    };
    let envelope = TopicEnvelope::seal(
        node,
        topic,
        seq,
        library::next_prev_hash(state),
        version,
        key,
        now,
        text.as_bytes(),
    )
    .context("sealing the message")?;
    match store.append(&envelope)? {
        store::Appended::Inserted => Ok(envelope),
        store::Appended::Duplicate => anyhow::bail!(
            "sequence {} was already stored for this node: another process is allocating \
             sequences on this topic",
            seq.0
        ),
    }
}

/// Open the topic log, waiting out an exclusive redb lock held by another
/// process for up to `wait`.
///
/// redb locks the file for the life of the handle, and two `wires` commands
/// legitimately want it seconds apart — a tail starting while a one-shot publish
/// lingers, a publish landing while a tail is coming up. Failing immediately
/// makes the loser's work disappear (and, when the loser is the tail, takes the
/// resident node with it); waiting makes the overlap a pause.
pub(crate) async fn open_topic_store(
    home: &Path,
    topic: TopicId,
    wait: Duration,
) -> anyhow::Result<store::TopicStore> {
    let until = tokio::time::Instant::now() + wait;
    let mut warned = false;
    loop {
        match store::TopicStore::open(home, topic) {
            Ok(store) => return Ok(store),
            Err(e) if tokio::time::Instant::now() < until => {
                if !warned {
                    warned = true;
                    tracing::info!(
                        "the topic log is locked by another wires process; waiting up to {}s: {e:#}",
                        wait.as_secs()
                    );
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// The fabric key to publish under, refusing a superseded one.
///
/// Re-read per publish, not cached, so a `wires advanced import --fabric-key …` after a
/// `roster commit` takes effect on the next message with no restart.
///
/// The version check is the publish-side half of the epoch floor
/// ([`replay::ingest`]): once the roster has moved, a message sealed under the
/// previous commit's key is refused at ingest by every peer that holds the new
/// head. Sealing it anyway would put a line in this node's log that no one else
/// will ever accept — a silent one-way loss. Failing here instead names the one
/// command that fixes it.
pub(crate) fn current_fabric_key(
    ks: &keystore::Keystore,
) -> anyhow::Result<(RosterVersion, FabricKey)> {
    let (version, key) = ks.latest_fabric_key()?.ok_or_else(|| {
        anyhow::anyhow!(
            "no fabric key in the keyring; run `wires advanced import --fabric-key-file <node-id>.key`"
        )
    })?;
    if let Some(head) = ks.read_roster_head()?
        && version < head.version
    {
        anyhow::bail!(
            "this node's newest fabric key is for roster version {}, but the roster is at version \
             {}: a message sealed under a superseded key is refused by every peer that holds the \
             current head — run `wires advanced import --fabric-key-file <node-id>.key` from the latest \
             `wires advanced roster commit --out DIR`",
            version.0,
            head.version.0
        );
    }
    Ok((version, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::roster::roster_commit_in;
    use crate::testutil::{commit_args, fabric_fixture, provisioned, temp_dir};

    #[test]
    fn append_local_allocates_a_dense_chain() {
        // The one-shot publish path with no network in it at all: allocate,
        // seal, append. Two calls must produce seq 0 then 1, linked.
        let member = provisioned([2u8; 32]);
        let ctx = member.resolve(&member.args()).unwrap();
        let store = member.store();

        let first = append_local(
            &store,
            &member.node,
            ctx.topic,
            member.version,
            &member.key,
            "one",
            1_000,
        )
        .unwrap();
        let second = append_local(
            &store,
            &member.node,
            ctx.topic,
            member.version,
            &member.key,
            "two",
            1_001,
        )
        .unwrap();

        assert_eq!(first.seq, Seq(0));
        assert_eq!(second.seq, Seq(1));
        assert!(first.prev_hash.is_zero(), "genesis links to nothing");
        assert_eq!(second.prev_hash, first.message_hash().unwrap());
        assert_eq!(first.open(&member.key).unwrap(), b"one");

        // Both are in the log, and the chain state agrees with the last one.
        let state = store.chain_state(member.node.node_id()).unwrap().unwrap();
        assert_eq!(state.seq, Seq(1));
        assert_eq!(state.hash, second.message_hash().unwrap());
        assert_eq!(store.read_backfill(10).unwrap(), vec![first, second]);
    }

    /// Publishing under a superseded fabric key is refused at the source.
    ///
    /// The receiving half of this rule is [`replay::ingest`]'s epoch floor: once
    /// the roster has moved, a message sealed under the previous commit's key is
    /// refused by every peer that holds the new head. Sealing it anyway would
    /// put a line in this node's log that nobody else will ever accept — a
    /// silent, one-way loss — so the publish fails here instead, naming the one
    /// command that fixes it.
    #[test]
    fn publishing_refuses_a_superseded_fabric_key() {
        let (ks, root, alice, _bob) = fabric_fixture();
        ks.save_node(&alice, false).unwrap();
        roster_commit_in(&ks, commit_args(&root, None)).unwrap();
        let v1 = ks.read_roster_head().unwrap().unwrap().version;
        ks.save_fabric_key(v1, &FabricKey::generate()).unwrap();

        let (version, _key) = current_fabric_key(&ks).expect("v1 key under a v1 head");
        assert_eq!(version, v1);

        // The root commits again; this node imported the head (or adopted it at
        // admission) but not yet the key.
        roster_commit_in(&ks, commit_args(&root, None)).unwrap();
        let v2 = ks.read_roster_head().unwrap().unwrap().version;
        let err = current_fabric_key(&ks).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("superseded") && msg.contains("--fabric-key-file"),
            "the refusal must name the remedy: {msg}"
        );

        // The import it asked for makes publishing work again, with no restart.
        ks.save_fabric_key(v2, &FabricKey::generate()).unwrap();
        assert_eq!(current_fabric_key(&ks).unwrap().0, v2);
    }

    /// A publish and a tail racing for the topic log wait for each other.
    ///
    /// redb locks the file for the life of the handle, and the window between
    /// the two commands is routine — a login script that starts a tail and
    /// publishes on the next line. Failing immediately made the loser's message
    /// disappear, or, when the loser was the tail, killed the resident node.
    #[tokio::test]
    async fn opening_the_topic_log_waits_out_another_process() {
        let home = temp_dir();
        let topic = TopicId::derive(NodeIdentity::from_seed([1u8; 32]).node_id(), "ops");
        let held = store::TopicStore::open(&home, topic).unwrap();

        // While it is held, the wait expires and the error is the lock's.
        let e = open_topic_store(&home, topic, Duration::from_millis(200))
            .await
            .expect_err("two handles on one redb file cannot both open");
        assert!(format!("{e:#}").to_lowercase().contains("lock"), "{e:#}");

        // Released mid-wait, the second open succeeds — the race is a pause.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            drop(held);
        });
        open_topic_store(&home, topic, Duration::from_secs(10))
            .await
            .expect("the log must open once the other process lets go");
    }
}

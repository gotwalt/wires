//! Integration test for wires channels v1 — DM independent derivation.
//!
//! Two `Node` instances share a household root. Both compute the DM
//! topic_id and epoch key independently from public material + their
//! own x25519 secret; the keys must match without any on-wire exchange.
//! Alice publishes a Standard-encrypted message; Bob installs the
//! locally-derived key, ingests the envelope, and replays the DM view
//! to verify the decrypted content is accessible.
//!
//! Asserts the substrate guarantee: no `__topic.history_grant` envelope
//! ever appears in Alice's DM log — keys come from the DH derivation,
//! not from a sealed history-grant message.

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_core::cap::Right;
use wires_core::channel::derive::{dm_epoch_key, dm_topic_id, dm_topic_name, sort_participants};
use wires_core::wire::MessageKind;
use wires_core::{CanonicalContent, Capability};
use wires_node::{Node, NodeConfig};

fn open_node(data_dir: &std::path::Path, root_pk: &[u8; 32]) -> Node {
    let cfg = NodeConfig {
        data_dir: data_dir.to_path_buf(),
        root_pubkey_hex: hex::encode(root_pk),
        host: None,
        retention: None,
    };
    std::fs::create_dir_all(data_dir).unwrap();
    Node::open(cfg).unwrap()
}

fn mint_cap(
    root_sk: &SigningKey,
    agent_pk: [u8; 32],
    topics: Vec<String>,
    rights: Vec<Right>,
    now: i64,
) -> Capability {
    let mut cap = Capability::new_unsigned(agent_pk, topics, rights, now, None);
    cap.sign(root_sk).unwrap();
    cap
}

#[test]
fn dm_independent_derivation_and_no_key_exchange() {
    // 1. Household root + two agents in distinct data dirs.
    let root_sk = SigningKey::generate(&mut OsRng);
    let root_pk = root_sk.verifying_key().to_bytes();

    let alice_dir = TempDir::new().unwrap();
    let alice = open_node(alice_dir.path(), &root_pk);
    let alice_pk = alice.ed_sk.verifying_key().to_bytes();
    let alice_x_pk = alice.x_pk;
    let alice_x_sk = alice.x_sk.to_bytes();

    let bob_dir = TempDir::new().unwrap();
    let bob = open_node(bob_dir.path(), &root_pk);
    let bob_pk = bob.ed_sk.verifying_key().to_bytes();
    let bob_x_pk = bob.x_pk;
    let bob_x_sk = bob.x_sk.to_bytes();

    // 2. Both sides compute dm_topic_id from the same sorted participant list.
    let participants = sort_participants(vec![alice_pk, bob_pk]);
    let topic_id_alice = dm_topic_id(&root_pk, &participants);
    let topic_id_bob = dm_topic_id(&root_pk, &participants);
    assert_eq!(
        topic_id_alice, topic_id_bob,
        "dm_topic_id is a pure function — both sides must agree"
    );
    let topic_id = topic_id_alice;
    let topic_name = dm_topic_name(&topic_id);

    // 3. Both sides compute dm_epoch_key independently using their own x25519
    //    secret + the other side's x25519 pubkey. X25519 is commutative.
    let key_alice = dm_epoch_key(&alice_x_sk, &bob_x_pk, &root_pk, &participants);
    let key_bob = dm_epoch_key(&bob_x_sk, &alice_x_pk, &root_pk, &participants);
    assert_eq!(
        key_alice, key_bob,
        "DH-derived DM epoch keys must match across endpoints"
    );
    let epoch_key = key_alice;

    // 4. Install the locally-derived epoch key on each side. No on-wire
    //    exchange happens — that is the substrate guarantee.
    alice.install_epoch_key(topic_id, 0, epoch_key).unwrap();
    bob.install_epoch_key(topic_id, 0, epoch_key).unwrap();

    // 5. Caps for both sides over `channels.dm.<hex>` (which matches the
    //    `channels.**` glob, but we use the more specific form to mirror what
    //    a DM-scoped cap might look like).
    let now: i64 = 1_700_000_000_000;
    let alice_cap = mint_cap(
        &root_sk,
        alice_pk,
        vec![topic_name.clone()],
        vec![Right::Read, Right::Write],
        now,
    );
    let alice_cap_id = alice_cap.cap_id.0;
    alice.caps.upsert_grant(&alice_cap).unwrap();
    // Bob needs alice's cap installed locally to accept her envelopes
    // (caps don't propagate over gossip in v1).
    bob.caps.upsert_grant(&alice_cap).unwrap();

    // 6. Alice publishes a Standard-encrypted note to the DM topic.
    let secret = "hi bob, this is a private note";
    let msg = alice
        .publish_standard(
            topic_id,
            alice_cap_id,
            CanonicalContent::new("agent.note", secret),
        )
        .unwrap();

    // 7. Hand Alice's envelope to Bob via handle_inbound.
    let outcome = bob.handle_inbound(msg.clone()).unwrap();
    match outcome {
        wires_node::Inbound::Accepted { content, .. } => {
            let c = content.expect("bob must decrypt with the derived epoch key");
            assert_eq!(c.type_, "agent.note");
            assert_eq!(c.text, secret);
        }
        other => panic!("expected Accepted with decrypted content, got: {other:?}"),
    }

    // 8. Replay Bob's DM view from his on-disk log. The message must be
    //    folded into the view (channel-layer fold is type-driven — `agent.note`
    //    isn't a member_meta/create/invite, so members/pending stay empty —
    //    but the log read + decrypt is the substantive check).
    let bob_log = bob.open_topic_log(&topic_id).unwrap();
    let view =
        wires_node::channel::open_dm(topic_id, participants.clone(), &bob_log, &epoch_key).unwrap();
    assert_eq!(
        view.topic_id, topic_id,
        "view must mirror the requested topic_id"
    );
    if let wires_core::channel::ChannelVariant::Dm { participants: p } = &view.variant {
        assert_eq!(p, &participants, "DM view carries sorted participant list");
    } else {
        panic!("expected ChannelVariant::Dm");
    }

    // 9. Substrate guarantee: no `__topic.history_grant` was ever published on
    //    the DM. Iterate Alice's log directly — every envelope must be
    //    Standard-mode (no SealedTo grant message).
    let alice_log = alice.open_topic_log(&topic_id).unwrap();
    let entries = alice_log.read_all().unwrap();
    assert_eq!(
        entries.len(),
        1,
        "DM should have exactly one envelope (Alice's note)"
    );
    for env in &entries {
        assert!(
            matches!(env.kind, MessageKind::Standard),
            "DM topic must never carry a SealedTo envelope — DH derivation \
             replaces history-grant exchange"
        );
    }
}

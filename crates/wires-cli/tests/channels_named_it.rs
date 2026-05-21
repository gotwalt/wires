//! Integration test for wires channels v1 — named channel
//! create + invite + roster.
//!
//! Drives `wires_node::channel::*` helpers directly on two `Node`
//! instances. No iroh endpoint, no gossip, no NodeRuntime — we
//! simulate the host relay path by feeding Alice's topic-log entries
//! into Bob's `handle_inbound` and assert the resulting `ChannelView`
//! state machine for each side.

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_core::Capability;
use wires_core::cap::Right;
use wires_core::channel::types::MemberKind;
use wires_node::{Node, NodeConfig};

/// Build a `Node` rooted at `data_dir`, with `root_pubkey_hex` pointing at
/// `root_pk`. `Node::open` creates the agent identity files on first call.
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

/// Mint a cap signed by `root_sk` for `agent_pk` over the given globs.
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
fn named_channel_create_invite_roster() {
    // 1. Alice — household root + agent identity.
    let root_sk = SigningKey::generate(&mut OsRng);
    let root_pk = root_sk.verifying_key().to_bytes();

    let alice_dir = TempDir::new().unwrap();
    let alice = open_node(alice_dir.path(), &root_pk);
    let alice_pk = alice.ed_sk.verifying_key().to_bytes();

    // 2. Bob — separate data_dir, his own agent identity.
    let bob_dir = TempDir::new().unwrap();
    let bob = open_node(bob_dir.path(), &root_pk);
    let bob_pk = bob.ed_sk.verifying_key().to_bytes();

    // Both agents need caps covering `channels.**` signed by the household root.
    let now: i64 = 1_700_000_000_000;
    let alice_cap = mint_cap(
        &root_sk,
        alice_pk,
        vec!["channels.**".into()],
        vec![Right::Read, Right::Write],
        now,
    );
    let alice_cap_id = alice_cap.cap_id.0;
    alice.caps.upsert_grant(&alice_cap).unwrap();

    let bob_cap = mint_cap(
        &root_sk,
        bob_pk,
        vec!["channels.**".into()],
        vec![Right::Read, Right::Write],
        now,
    );
    let bob_cap_id = bob_cap.cap_id.0;
    bob.caps.upsert_grant(&bob_cap).unwrap();

    // 3. Alice allocates the named channel and publishes the create + her meta.
    let (topic_id, epoch_key) = wires_node::channel::allocate_named(&alice).unwrap();
    let topic_name = "channels.coord";
    wires_node::channel::publish_create_and_meta(
        &alice,
        topic_id,
        topic_name,
        alice_cap_id,
        Some("household coordination"),
        "alice",
        MemberKind::Cli,
        now,
    )
    .unwrap();

    // 4. Alice invites Bob (publishes a sealed history_grant + public invite).
    wires_node::channel::invite_member(&alice, topic_id, alice_cap_id, bob_pk, &epoch_key, now + 1)
        .unwrap();

    // 5. Replay Alice's log → Bob is in pending (until his own meta lands).
    {
        let log = alice.open_topic_log(&topic_id).unwrap();
        let view = wires_node::channel::open_named(topic_id, &log, &epoch_key).unwrap();
        assert!(
            view.members.contains_key(&alice_pk),
            "alice should be a member on her side after publish_create_and_meta"
        );
        assert!(
            view.pending.contains(&bob_pk),
            "bob should be pending after invite, before he asserts member_meta"
        );
        assert!(
            !view.members.contains_key(&bob_pk),
            "bob is not yet a full member"
        );
    }

    // 6. Bob needs to know about Alice's cap to accept her messages. In v1 caps
    //    do not propagate over gossip, so we install it directly. This mirrors
    //    what `__cap.grant` propagation would do in a fuller implementation.
    bob.caps.upsert_grant(&alice_cap).unwrap();

    // 7. Replay Alice's topic log into Bob's node via `handle_inbound`. This
    //    simulates the host-side relay path: each message Alice published is
    //    delivered to Bob, who persists ciphertext and decrypts what he can.
    let alice_log = alice.open_topic_log(&topic_id).unwrap();
    let entries = alice_log.read_all().unwrap();
    assert!(
        !entries.is_empty(),
        "alice's log should have at least create + meta + grant + invite"
    );
    for msg in entries {
        let _ = bob.handle_inbound(msg).unwrap();
    }

    // 8. Install the epoch key on Bob (would normally be delivered via the
    //    sealed `__topic.history_grant` envelope, which targets Bob's x25519).
    //    The handle_inbound path persists the sealed envelope but doesn't yet
    //    install the key on Bob's epoch_keys store — that hook isn't built in
    //    v1. So we mirror what the grant would do.
    bob.install_epoch_key(topic_id, 0, epoch_key).unwrap();

    // 9. Bob publishes his own `__channel.member_meta` to upgrade pending →
    //    member. Use the shared `publish_create_and_meta`-style flow by going
    //    through the lower-level helper directly: it doesn't include a create
    //    event from Bob, just his meta.
    let bob_meta = wires_core::channel::ChannelMemberMeta {
        kind: MemberKind::Cli,
        display_name: "bob".to_string(),
        description: None,
        asserted_at: now + 2,
    };
    let meta_value = serde_json::to_value(&bob_meta).unwrap();
    wires_node::channel::publish_public(
        &bob,
        topic_id,
        bob_cap_id,
        wires_core::channel::TYPE_MEMBER_META,
        "member bob",
        meta_value,
        now + 2,
    )
    .unwrap();

    // 10. Replay Bob's log → both alice and bob in `members`, pending empty.
    let bob_log = bob.open_topic_log(&topic_id).unwrap();
    let view_bob = wires_node::channel::open_named(topic_id, &bob_log, &epoch_key).unwrap();
    assert!(
        view_bob.members.contains_key(&alice_pk),
        "alice's meta replayed from her log entries"
    );
    assert!(
        view_bob.members.contains_key(&bob_pk),
        "bob's own meta lifts him from pending to members"
    );
    assert!(
        view_bob.pending.is_empty(),
        "no one is pending once member_meta arrives"
    );
    assert_eq!(
        view_bob.members.get(&bob_pk).unwrap().display_name,
        "bob",
        "bob's meta should carry his display name"
    );
    assert_eq!(
        view_bob.members.get(&alice_pk).unwrap().display_name,
        "alice",
        "alice's meta should carry her display name"
    );
}

//! Integration test for wires channels v1 — three-agent named-channel
//! acceptance scenario (spec §13).
//!
//! Drives `wires_node::channel::*` helpers directly on three `Node`
//! instances. The "live iroh + replay" framing in the spec is approximated
//! with a unit-shaped simulation: we queue every envelope each agent
//! publishes into a `Vec<WireMessage>` and feed it into the recipient
//! agents' `handle_inbound` at the appropriate time. This mimics what
//! `wires-host` + `iroh-gossip` would do without bringing real endpoints
//! online — fast, deterministic, and isolates the channel-layer fold from
//! transport flakiness. Marked `#[ignore]` per the plan.
//!
//! Scenario:
//!   1. Alice creates `channels.coord` + her member_meta, invites Bob.
//!   2. Bob receives Alice's log, installs the epoch key, publishes his
//!      own member_meta → both Alice and Bob are full members.
//!   3. Bob invites Carol. Alice goes "offline" — anything Bob/Carol
//!      publishes from now on is queued, not delivered to Alice.
//!   4. Carol receives the queued envelopes, installs the epoch key,
//!      publishes her member_meta. Bob and Carol exchange Standard-
//!      encrypted `agent.note` messages.
//!   5. Alice reconnects. All queued envelopes flow into her node via
//!      `handle_inbound`. Her `ChannelView` shows Alice + Bob + Carol in
//!      `members`, `pending` empty, and her decrypted-message tail
//!      contains both Bob's and Carol's notes.

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_core::cap::Right;
use wires_core::channel::types::MemberKind;
use wires_core::{CanonicalContent, Capability, MessageKind, WireMessage};
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

/// Read every envelope in `node`'s log for `topic_id` whose seq is strictly
/// greater than `cursor[&sender]` (defaulting to "from genesis"). Updates
/// `cursor` to the new high-water mark per sender. Returns the envelopes in
/// log iteration order — which is `(sender, seq)` lexicographic, the same
/// order replay would deliver them.
fn drain_new(
    node: &Node,
    topic_id: &[u8; 32],
    cursor: &mut std::collections::HashMap<[u8; 32], u64>,
) -> Vec<WireMessage> {
    let log = node.open_topic_log(topic_id).unwrap();
    let entries = log.read_all().unwrap();
    let mut out = Vec::new();
    for msg in entries {
        let cur = cursor.get(&msg.sender).copied();
        let take = match cur {
            None => true,
            Some(hwm) => msg.seq > hwm,
        };
        if take {
            cursor.insert(msg.sender, msg.seq);
            out.push(msg);
        }
    }
    out
}

#[test]
#[ignore = "Acceptance scenario — runs under --ignored. Drives 3 wires-nodes via channel-layer helpers + simulated host replay, no live iroh."]
fn three_agent_named_channel_acceptance() {
    // ---- 1. Bootstrap: one household root, three agents. ---------------
    let root_sk = SigningKey::generate(&mut OsRng);
    let root_pk = root_sk.verifying_key().to_bytes();

    let alice_dir = TempDir::new().unwrap();
    let alice = open_node(alice_dir.path(), &root_pk);
    let alice_pk = alice.ed_sk.verifying_key().to_bytes();

    let bob_dir = TempDir::new().unwrap();
    let bob = open_node(bob_dir.path(), &root_pk);
    let bob_pk = bob.ed_sk.verifying_key().to_bytes();
    let bob_x_pk = bob.x_pk;

    let carol_dir = TempDir::new().unwrap();
    let carol = open_node(carol_dir.path(), &root_pk);
    let carol_pk = carol.ed_sk.verifying_key().to_bytes();
    let carol_x_pk = carol.x_pk;

    // Each agent gets a root-signed cap over `channels.**`. In a real
    // household these would land via the pair-approve flow.
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

    let carol_cap = mint_cap(
        &root_sk,
        carol_pk,
        vec!["channels.**".into()],
        vec![Right::Read, Right::Write],
        now,
    );
    let carol_cap_id = carol_cap.cap_id.0;
    carol.caps.upsert_grant(&carol_cap).unwrap();

    // Caps don't propagate over gossip in v1, so each agent that will
    // ingest another's envelopes must have the publisher's cap installed
    // locally. We install caps lazily — only when an agent first becomes
    // a recipient — to mirror the responder-driven pairing flow.

    // ---- 2. Alice creates `channels.coord` and invites Bob. ------------
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
    wires_node::channel::invite_member(&alice, topic_id, alice_cap_id, bob_pk, &epoch_key, now + 1)
        .unwrap();

    // Sanity check Alice's local view: she's a member, Bob is pending.
    {
        let log = alice.open_topic_log(&topic_id).unwrap();
        let view = wires_node::channel::open_named(topic_id, &log, &epoch_key).unwrap();
        assert!(
            view.members.contains_key(&alice_pk),
            "alice must be a member after publish_create_and_meta"
        );
        assert!(view.pending.contains(&bob_pk), "bob must be pending");
    }

    // ---- 3. Bob ingests Alice's log + becomes a full member. -----------
    // Bob needs Alice's cap installed to accept her envelopes.
    bob.caps.upsert_grant(&alice_cap).unwrap();

    // Track per-sender high-water marks per receiver so we never deliver
    // the same envelope twice.
    let mut bob_cursor: std::collections::HashMap<[u8; 32], u64> = std::collections::HashMap::new();
    let alice_phase1 = drain_new(&alice, &topic_id, &mut bob_cursor);
    assert!(
        !alice_phase1.is_empty(),
        "alice's log must hold create + meta + grant + invite"
    );
    for msg in alice_phase1 {
        bob.handle_inbound(msg).unwrap();
    }

    // The sealed `__topic.history_grant` envelope is persisted by
    // `handle_inbound`, but in v1 the channel layer doesn't auto-install
    // the key on the recipient — that's a substrate-side hook not yet
    // built. Install it directly to mirror what the grant would do.
    bob.install_epoch_key(topic_id, 0, epoch_key).unwrap();

    // Bob publishes his own member_meta → upgrade pending → member.
    let bob_meta = wires_core::channel::ChannelMemberMeta {
        kind: MemberKind::Cli,
        display_name: "bob".to_string(),
        description: None,
        asserted_at: now + 2,
    };
    let bob_meta_value = serde_json::to_value(&bob_meta).unwrap();
    wires_node::channel::publish_public(
        &bob,
        topic_id,
        bob_cap_id,
        wires_core::channel::TYPE_MEMBER_META,
        "member bob",
        bob_meta_value,
        now + 2,
    )
    .unwrap();

    // ---- 4. Bob invites Carol. Alice "goes offline" here. --------------
    // Anything Bob (or later Carol) publishes from this point is held in
    // `queue_for_alice` until Alice reconnects in phase 5.
    let mut queue_for_alice: Vec<WireMessage> = Vec::new();
    let mut alice_cursor: std::collections::HashMap<[u8; 32], u64> =
        std::collections::HashMap::new();
    // Seed Alice's cursor with what's already in her own log (the entries
    // she published herself) so we don't try to redeliver them.
    let _ = drain_new(&alice, &topic_id, &mut alice_cursor);

    // Snapshot Bob's new envelopes (his meta) — Alice will need them too.
    queue_for_alice.extend(drain_new(&bob, &topic_id, &mut alice_cursor));

    // Bob invites Carol. The history_grant is sealed to carol_x_pk.
    wires_node::channel::invite_member(&bob, topic_id, bob_cap_id, carol_pk, &epoch_key, now + 3)
        .unwrap();
    // Stash Bob's invite + grant for Alice.
    queue_for_alice.extend(drain_new(&bob, &topic_id, &mut alice_cursor));

    // ---- 5. Carol ingests the chain so far + joins. --------------------
    // Carol needs both Alice's and Bob's caps installed to accept their
    // envelopes (no gossip propagation in v1).
    carol.caps.upsert_grant(&alice_cap).unwrap();
    carol.caps.upsert_grant(&bob_cap).unwrap();

    // Carol replays Alice's full log (create, meta, grant-for-bob,
    // invite-bob) and then Bob's full log (his meta, his grant-to-carol,
    // his invite-carol). Order matters within a single sender (chain
    // verify), but across senders the per-publisher chains are
    // independent — `drain_new` keeps them grouped correctly.
    let mut carol_cursor: std::collections::HashMap<[u8; 32], u64> =
        std::collections::HashMap::new();
    for msg in drain_new(&alice, &topic_id, &mut carol_cursor) {
        carol.handle_inbound(msg).unwrap();
    }
    for msg in drain_new(&bob, &topic_id, &mut carol_cursor) {
        carol.handle_inbound(msg).unwrap();
    }

    // Carol installs the epoch key (same hook gap as Bob in phase 3).
    carol.install_epoch_key(topic_id, 0, epoch_key).unwrap();

    // Carol publishes her own member_meta.
    let carol_meta = wires_core::channel::ChannelMemberMeta {
        kind: MemberKind::Cli,
        display_name: "carol".to_string(),
        description: None,
        asserted_at: now + 4,
    };
    let carol_meta_value = serde_json::to_value(&carol_meta).unwrap();
    wires_node::channel::publish_public(
        &carol,
        topic_id,
        carol_cap_id,
        wires_core::channel::TYPE_MEMBER_META,
        "member carol",
        carol_meta_value,
        now + 4,
    )
    .unwrap();

    // ---- 6. Bob and Carol exchange Standard-encrypted notes. -----------
    // First, Carol's meta needs to reach Bob so Bob's local fold puts her
    // in `members`. Drain Carol's new entries into Bob's node.
    let mut bob_from_carol_cursor: std::collections::HashMap<[u8; 32], u64> =
        std::collections::HashMap::new();
    for msg in drain_new(&carol, &topic_id, &mut bob_from_carol_cursor) {
        bob.handle_inbound(msg).unwrap();
    }

    let bob_note = bob
        .publish_standard(
            topic_id,
            bob_cap_id,
            CanonicalContent::new("agent.note", "hi carol, bob here"),
        )
        .unwrap();
    // Hand Bob's note directly to Carol so she can fold it locally too.
    carol.handle_inbound(bob_note.clone()).unwrap();

    let carol_note = carol
        .publish_standard(
            topic_id,
            carol_cap_id,
            CanonicalContent::new("agent.note", "hello bob, this is carol"),
        )
        .unwrap();
    bob.handle_inbound(carol_note.clone()).unwrap();

    // Queue every fresh envelope on Bob's and Carol's logs for Alice.
    queue_for_alice.extend(drain_new(&bob, &topic_id, &mut alice_cursor));
    queue_for_alice.extend(drain_new(&carol, &topic_id, &mut alice_cursor));

    // ---- 7. Alice reconnects. Host replay drains the queue into her. ---
    // She needs Bob's and Carol's caps to accept their envelopes.
    alice.caps.upsert_grant(&bob_cap).unwrap();
    alice.caps.upsert_grant(&carol_cap).unwrap();

    assert!(
        !queue_for_alice.is_empty(),
        "queue must hold the envelopes Alice missed"
    );

    let mut saw_bob_note = false;
    let mut saw_carol_note = false;
    for msg in &queue_for_alice {
        let outcome = alice.handle_inbound(msg.clone()).unwrap();
        if let wires_node::Inbound::Accepted {
            content: Some(c), ..
        } = outcome
            && c.type_ == "agent.note"
        {
            if msg.sender == bob_pk && c.text == "hi carol, bob here" {
                saw_bob_note = true;
            }
            if msg.sender == carol_pk && c.text == "hello bob, this is carol" {
                saw_carol_note = true;
            }
        }
    }
    assert!(
        saw_bob_note,
        "alice must decrypt bob's note after reconnecting"
    );
    assert!(
        saw_carol_note,
        "alice must decrypt carol's note after reconnecting"
    );

    // ---- 8. Final state: Alice's ChannelView contains the full roster. -
    let alice_log = alice.open_topic_log(&topic_id).unwrap();
    let view = wires_node::channel::open_named(topic_id, &alice_log, &epoch_key).unwrap();
    assert!(
        view.members.contains_key(&alice_pk),
        "alice in members after reconnect"
    );
    assert!(
        view.members.contains_key(&bob_pk),
        "bob in members after reconnect"
    );
    assert!(
        view.members.contains_key(&carol_pk),
        "carol in members after reconnect"
    );
    assert!(
        view.pending.is_empty(),
        "no pending members after all metas land"
    );
    assert_eq!(view.members.get(&alice_pk).unwrap().display_name, "alice");
    assert_eq!(view.members.get(&bob_pk).unwrap().display_name, "bob");
    assert_eq!(view.members.get(&carol_pk).unwrap().display_name, "carol");

    // Sanity-check the sealed history-grant envelopes were on-wire
    // (a substrate detail: each invite emits exactly one SealedTo).
    let sealed_grants: Vec<_> = alice_log
        .read_all()
        .unwrap()
        .into_iter()
        .filter(|m| matches!(m.kind, MessageKind::SealedTo(_)))
        .collect();
    assert_eq!(
        sealed_grants.len(),
        2,
        "exactly two history_grant envelopes: alice→bob and bob→carol"
    );
    // `invite_member` seals to the invitee's Ed25519 pubkey (see
    // `wires_node::channel::invite_member`'s `SealedTo(invitee)`); the
    // pubkey type that lands in the envelope's `SealedTo` is the agent's
    // Ed25519 identity, not their X25519 pubkey. Touch `bob_x_pk` /
    // `carol_x_pk` so the unused-binding warning doesn't fire — they are
    // the substrate-level material the grant *would* target if v1
    // delivered keys via the sealed path instead of via direct install.
    let _ = (bob_x_pk, carol_x_pk);
    let bob_grant = sealed_grants
        .iter()
        .find(|m| m.sender == alice_pk)
        .expect("alice's grant should be in the log");
    let carol_grant = sealed_grants
        .iter()
        .find(|m| m.sender == bob_pk)
        .expect("bob's grant should be in the log");
    match bob_grant.kind {
        MessageKind::SealedTo(target) => {
            assert_eq!(target, bob_pk, "alice's grant is addressed to bob")
        }
        _ => unreachable!(),
    }
    match carol_grant.kind {
        MessageKind::SealedTo(target) => {
            assert_eq!(target, carol_pk, "bob's grant is addressed to carol")
        }
        _ => unreachable!(),
    }
}

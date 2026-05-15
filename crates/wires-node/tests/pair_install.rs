use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;
use wires_core::Capability;
use wires_core::cap::Right;
use wires_net::pair::{PairGrant, TopicEpochKey, TopicNameEntry};
use wires_node::{Node, NodeConfig, install_grant};

fn fresh_node(td: &TempDir) -> (Node, [u8; 32]) {
    let agent_sk = SigningKey::generate(&mut OsRng);
    let agent_pk = agent_sk.verifying_key().to_bytes();
    std::fs::write(td.path().join("identity.ed25519"), agent_sk.to_bytes()).unwrap();
    let xsk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    std::fs::write(td.path().join("identity.x25519"), xsk.to_bytes()).unwrap();
    let cfg = NodeConfig {
        data_dir: td.path().to_path_buf(),
        root_pubkey_hex: String::new(),
        host: None,
    };
    std::fs::write(
        td.path().join("config.toml"),
        toml::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();
    let node = Node::open(cfg).unwrap();
    (node, agent_pk)
}

fn make_signed_cap(root_sk: &SigningKey, agent_pk: [u8; 32]) -> Capability {
    let mut cap = Capability::new_unsigned(
        agent_pk,
        vec!["home.notes".into()],
        vec![Right::Read, Right::Write],
        1_700_000_000_000,
        None,
    );
    cap.sign(root_sk).unwrap();
    cap
}

#[test]
fn happy_path_installs_all_artifacts() {
    let td = TempDir::new().unwrap();
    let (node, agent_pk) = fresh_node(&td);
    let root_sk = SigningKey::generate(&mut OsRng);
    let root_pk = root_sk.verifying_key().to_bytes();
    let topic_id = [42u8; 32];
    let grant = PairGrant {
        version: 1,
        root_pubkey: root_pk,
        cap: make_signed_cap(&root_sk, agent_pk),
        topic_keys: vec![TopicEpochKey {
            topic_id,
            epoch: 0,
            key: [7u8; 32],
        }],
        topic_names: vec![TopicNameEntry {
            topic_id,
            name: "home.notes".into(),
        }],
        host: None,
        nonce: [9u8; 32],
        issued_at: 1_700_000_000_000,
    };
    let out = install_grant(td.path(), &node, &agent_pk, &grant).unwrap();
    assert_eq!(out.cap_id, grant.cap.cap_id.0);
    let cfg: NodeConfig =
        toml::from_str(&std::fs::read_to_string(td.path().join("config.toml")).unwrap()).unwrap();
    assert_eq!(cfg.root_pubkey_hex, hex::encode(root_pk));
    let names: std::collections::HashMap<String, String> =
        serde_json::from_str(&std::fs::read_to_string(td.path().join("topic_names.json")).unwrap())
            .unwrap();
    assert_eq!(names.get("home.notes"), Some(&hex::encode(topic_id)));
}

#[test]
fn rejects_cap_for_other_agent() {
    let td = TempDir::new().unwrap();
    let (node, agent_pk) = fresh_node(&td);
    let root_sk = SigningKey::generate(&mut OsRng);
    let bogus_target = [0xfe; 32];
    let grant = PairGrant {
        version: 1,
        root_pubkey: root_sk.verifying_key().to_bytes(),
        cap: make_signed_cap(&root_sk, bogus_target),
        topic_keys: vec![],
        topic_names: vec![],
        host: None,
        nonce: [9u8; 32],
        issued_at: 1_700_000_000_000,
    };
    assert!(install_grant(td.path(), &node, &agent_pk, &grant).is_err());
}

#[test]
fn rejects_cap_signed_by_wrong_root() {
    let td = TempDir::new().unwrap();
    let (node, agent_pk) = fresh_node(&td);
    let real_root = SigningKey::generate(&mut OsRng);
    let imposter_root = SigningKey::generate(&mut OsRng);
    let grant = PairGrant {
        version: 1,
        root_pubkey: real_root.verifying_key().to_bytes(),
        cap: make_signed_cap(&imposter_root, agent_pk),
        topic_keys: vec![],
        topic_names: vec![],
        host: None,
        nonce: [9u8; 32],
        issued_at: 0,
    };
    assert!(install_grant(td.path(), &node, &agent_pk, &grant).is_err());
}

#[test]
fn idempotent_on_replay() {
    let td = TempDir::new().unwrap();
    let (node, agent_pk) = fresh_node(&td);
    let root_sk = SigningKey::generate(&mut OsRng);
    let topic_id = [42u8; 32];
    let grant = PairGrant {
        version: 1,
        root_pubkey: root_sk.verifying_key().to_bytes(),
        cap: make_signed_cap(&root_sk, agent_pk),
        topic_keys: vec![TopicEpochKey {
            topic_id,
            epoch: 0,
            key: [7u8; 32],
        }],
        topic_names: vec![TopicNameEntry {
            topic_id,
            name: "home.notes".into(),
        }],
        host: None,
        nonce: [9u8; 32],
        issued_at: 0,
    };
    let a = install_grant(td.path(), &node, &agent_pk, &grant).unwrap();
    let b = install_grant(td.path(), &node, &agent_pk, &grant).unwrap();
    assert_eq!(a.cap_id, b.cap_id);
}

//! DM topic_id and epoch-key derivation. Spec §5.

use crate::wire::{Pubkey, TopicId};

const TOPIC_DOMAIN: &[u8] = b"wires.dm.v1\0";
const EPOCH_DOMAIN: &[u8] = b"wires.dm.epoch.v1\0";

/// Returns a sorted clone of `participants` (byte-lexicographic).
pub fn sort_participants(mut participants: Vec<Pubkey>) -> Vec<Pubkey> {
    participants.sort();
    participants
}

/// Compute the DM topic_id per spec §5.1:
///   BLAKE3("wires.dm.v1\0" || root_pubkey || "\0" || sorted_pubkey_concat)
pub fn dm_topic_id(root: &Pubkey, sorted_participants: &[Pubkey]) -> TopicId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TOPIC_DOMAIN);
    hasher.update(root);
    hasher.update(b"\0");
    for pk in sorted_participants {
        hasher.update(pk);
    }
    *hasher.finalize().as_bytes()
}

/// Build the canonical name string used for cap-glob matching on a DM topic.
/// Format: `channels.dm.<hex(topic_id)>`. Falls under the broad `channels.**`
/// glob without needing a separate prefix.
pub fn dm_topic_name(topic_id: &TopicId) -> String {
    format!("channels.dm.{}", hex::encode(topic_id))
}

/// 32-byte symmetric AEAD key.
pub type EpochKey = [u8; 32];

/// Compute the DM epoch key per spec §5.2.
///
/// ```text
/// shared = X25519(self_x25519_sk, other_x25519_pk)
/// epoch_key = BLAKE3(shared || "wires.dm.epoch.v1\0" || root || sorted_pubkey_concat)
/// ```
///
/// Both DM participants arrive at the same key by passing the other side's
/// public key in as `other_x25519_pk`; X25519 is commutative.
pub fn dm_epoch_key(
    self_x25519_sk: &[u8; 32],
    other_x25519_pk: &[u8; 32],
    root: &Pubkey,
    sorted_participants: &[Pubkey],
) -> EpochKey {
    let sk = x25519_dalek::StaticSecret::from(*self_x25519_sk);
    let pk = x25519_dalek::PublicKey::from(*other_x25519_pk);
    let shared = sk.diffie_hellman(&pk);

    let mut hasher = blake3::Hasher::new();
    hasher.update(shared.as_bytes());
    hasher.update(EPOCH_DOMAIN);
    hasher.update(root);
    for pk in sorted_participants {
        hasher.update(pk);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dm_topic_id_is_independent_of_input_order() {
        let alice: Pubkey = [1u8; 32];
        let bob: Pubkey = [2u8; 32];
        let root: Pubkey = [9u8; 32];
        let a = dm_topic_id(&root, &sort_participants(vec![alice, bob]));
        let b = dm_topic_id(&root, &sort_participants(vec![bob, alice]));
        assert_eq!(a, b);
    }

    #[test]
    fn dm_topic_id_distinct_per_fabric() {
        let alice: Pubkey = [1u8; 32];
        let bob: Pubkey = [2u8; 32];
        let participants = sort_participants(vec![alice, bob]);
        let id_a = dm_topic_id(&[7u8; 32], &participants);
        let id_b = dm_topic_id(&[8u8; 32], &participants);
        assert_ne!(id_a, id_b, "different roots must yield different topic ids");
    }

    #[test]
    fn dm_topic_id_distinct_per_participant_set() {
        let alice: Pubkey = [1u8; 32];
        let bob: Pubkey = [2u8; 32];
        let carol: Pubkey = [3u8; 32];
        let root: Pubkey = [9u8; 32];
        let id_ab = dm_topic_id(&root, &sort_participants(vec![alice, bob]));
        let id_ac = dm_topic_id(&root, &sort_participants(vec![alice, carol]));
        assert_ne!(id_ab, id_ac);
    }

    #[test]
    fn dm_topic_name_is_under_channels_glob() {
        use crate::cap::glob_matches;
        let id: TopicId = [0xab; 32];
        let name = dm_topic_name(&id);
        assert!(glob_matches("channels.**", &name).unwrap());
    }

    #[test]
    fn dm_epoch_key_is_commutative() {
        // Two random x25519 keypairs, same root, same participants.
        use rand_core::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};

        let alice_sk = StaticSecret::random_from_rng(OsRng);
        let bob_sk = StaticSecret::random_from_rng(OsRng);
        let alice_pk_bytes: [u8; 32] = PublicKey::from(&alice_sk).to_bytes();
        let bob_pk_bytes: [u8; 32] = PublicKey::from(&bob_sk).to_bytes();
        let alice_sk_bytes = alice_sk.to_bytes();
        let bob_sk_bytes = bob_sk.to_bytes();

        let root: Pubkey = [9u8; 32];
        // Use ed25519-shaped pubkeys for the derivation (different from the
        // x25519 pubkeys used in DH — the participants are identified by their
        // ed25519 identities).
        let participants = sort_participants(vec![[1u8; 32], [2u8; 32]]);

        let alice_key = dm_epoch_key(&alice_sk_bytes, &bob_pk_bytes, &root, &participants);
        let bob_key = dm_epoch_key(&bob_sk_bytes, &alice_pk_bytes, &root, &participants);
        assert_eq!(
            alice_key, bob_key,
            "X25519 commutativity must yield identical keys"
        );
    }

    #[test]
    fn dm_epoch_key_distinct_per_root() {
        use rand_core::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};
        let alice_sk = StaticSecret::random_from_rng(OsRng);
        let bob_sk = StaticSecret::random_from_rng(OsRng);
        let alice_sk_bytes = alice_sk.to_bytes();
        let bob_pk_bytes: [u8; 32] = PublicKey::from(&bob_sk).to_bytes();
        let participants = sort_participants(vec![[1u8; 32], [2u8; 32]]);

        let key_a = dm_epoch_key(&alice_sk_bytes, &bob_pk_bytes, &[7u8; 32], &participants);
        let key_b = dm_epoch_key(&alice_sk_bytes, &bob_pk_bytes, &[8u8; 32], &participants);
        assert_ne!(key_a, key_b);
    }
}

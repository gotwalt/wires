//! DM topic_id and epoch-key derivation. Spec §5.

use crate::wire::{Pubkey, TopicId};

const TOPIC_DOMAIN: &[u8] = b"wires.dm.v1\0";
#[allow(dead_code)]
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
    fn dm_topic_id_distinct_per_household() {
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
}

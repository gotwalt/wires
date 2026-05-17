//! `generate_topic_id_and_epoch0` — random 32-byte topic id + epoch-0 key.

use rand_core::{OsRng, RngCore};

use crate::types::NewTopic;

pub fn generate_topic_id_and_epoch0() -> NewTopic {
    let mut topic_id = [0u8; 32];
    let mut epoch_key = [0u8; 32];
    OsRng.fill_bytes(&mut topic_id);
    OsRng.fill_bytes(&mut epoch_key);
    NewTopic {
        topic_id_hex: hex::encode(topic_id),
        epoch_0_key: epoch_key.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_nonzero_distinct() {
        let a = generate_topic_id_and_epoch0();
        let b = generate_topic_id_and_epoch0();
        assert_eq!(a.topic_id_hex.len(), 64);
        assert_eq!(a.epoch_0_key.len(), 32);
        assert_ne!(a.topic_id_hex, b.topic_id_hex);
        assert_ne!(a.epoch_0_key, b.epoch_0_key);
        assert!(a.epoch_0_key.iter().any(|b| *b != 0));
    }
}

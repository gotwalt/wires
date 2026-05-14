use snafu::ensure;

use crate::error::{ChainBreakSnafu, Result};
use crate::wire::{MessageHash, WireMessage};

/// Verify that `msg.prev_hash == hash(previous)`. The first message
/// in a (sender, topic) chain has `seq=0` and `prev_hash=[0; 32]`.
pub fn verify_chain_link(msg: &WireMessage, previous: Option<&WireMessage>) -> Result<()> {
    match (msg.seq, previous) {
        (0, None) => {
            ensure!(msg.prev_hash == [0u8; 32], ChainBreakSnafu);
            Ok(())
        }
        (0, Some(_)) => {
            // Two messages both claiming seq=0 from the same sender on the same topic is a fork.
            ChainBreakSnafu.fail()
        }
        (_, None) => {
            // We received seq=N>0 but have no prior — caller must do a gap-repair replay.
            ChainBreakSnafu.fail()
        }
        (_, Some(prev)) => {
            let expected = prev.message_hash()?;
            ensure!(msg.prev_hash == expected, ChainBreakSnafu);
            ensure!(msg.seq == prev.seq + 1, ChainBreakSnafu);
            Ok(())
        }
    }
}

/// Construct the next message's `prev_hash` from the previous message.
pub fn next_prev_hash(previous: Option<&WireMessage>) -> Result<MessageHash> {
    match previous {
        None => Ok([0u8; 32]),
        Some(p) => p.message_hash(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::MessageKind;

    fn make(seq: u64, prev_hash: MessageHash) -> WireMessage {
        WireMessage {
            topic_id: [1u8; 32],
            epoch: 0,
            kind: MessageKind::Standard,
            sender: [2u8; 32],
            cap_id: [0u8; 16],
            seq,
            prev_hash,
            timestamp: seq as i64,
            payload_len: 1,
            signature: [0u8; 64],
            ciphertext: vec![seq as u8],
        }
    }

    #[test]
    fn first_link_must_have_zero_prev_hash() {
        let msg = make(0, [0u8; 32]);
        verify_chain_link(&msg, None).unwrap();
        let bad = make(0, [1u8; 32]);
        assert!(verify_chain_link(&bad, None).is_err());
    }

    #[test]
    fn second_link_must_match_prior_hash() {
        let first = make(0, [0u8; 32]);
        let prev_hash = first.message_hash().unwrap();
        let second = make(1, prev_hash);
        verify_chain_link(&second, Some(&first)).unwrap();

        let mut bad = make(1, [0u8; 32]);
        bad.prev_hash = [9u8; 32];
        assert!(verify_chain_link(&bad, Some(&first)).is_err());
    }

    #[test]
    fn seq_must_be_strictly_incrementing() {
        let first = make(0, [0u8; 32]);
        let prev_hash = first.message_hash().unwrap();
        let skipping = make(5, prev_hash);
        assert!(verify_chain_link(&skipping, Some(&first)).is_err());
    }

    #[test]
    fn fork_at_genesis_detected() {
        let first = make(0, [0u8; 32]);
        let fork = make(0, [0u8; 32]);
        assert!(verify_chain_link(&fork, Some(&first)).is_err());
    }

    #[test]
    fn seq_gt_zero_without_previous_rejected() {
        let m = make(5, [0u8; 32]);
        assert!(verify_chain_link(&m, None).is_err());
    }

    #[test]
    fn next_prev_hash_matches_message_hash() {
        let msg = make(0, [0u8; 32]);
        let nph = next_prev_hash(Some(&msg)).unwrap();
        assert_eq!(nph, msg.message_hash().unwrap());
        let nph_none = next_prev_hash(None).unwrap();
        assert_eq!(nph_none, [0u8; 32]);
    }
}

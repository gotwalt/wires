//! Per-publisher hash chains: how a reader knows it has the whole story.
//!
//! Each publisher on a topic keeps its own log — 0-based, dense sequence
//! numbers, each envelope carrying the hash of its predecessor. There is no
//! global order and no consensus; the guarantee is per-sender and purely local:
//! given a sender's messages, a reader can tell *complete* from *truncated*
//! from *rewritten*.
//!
//! [`classify_link`] turns a freshly received envelope plus the reader's stored
//! [`ChainState`] into one of four verdicts:
//!
//! | verdict | meaning | what the caller does |
//! |---|---|---|
//! | [`LinkStatus::Ok`] | the expected next message | store it, display it |
//! | [`LinkStatus::Duplicate`] | already held, same hash | drop it silently — this is the dedupe that keeps live/replay/restart from double-printing |
//! | [`LinkStatus::Gap`] | seq jumped ahead | do **not** store; schedule a replay pass, the message comes back in order |
//! | [`LinkStatus::Fork`] | same slot, different content | refuse and log |
//!
//! A gap is never a silent drop-forever: replay ([`crate::replay`]) heals it.
//!
//! Fork handling is **detect and refuse**, not resolve. A fork means a sender's
//! key signed two different messages for one slot, which is either a bug or an
//! equivocating node; either way this layer will not pick a winner. Fork choice
//! is deferred.

use serde::{Deserialize, Serialize};

use crate::envelope::{MessageHash, Seq, TopicEnvelope};
use crate::error::Result;

/// A reader's high-water mark for one publisher: the last sequence number it
/// holds and that message's hash.
///
/// Serializable because it rides in [`ReplayFrame::Request`](crate::replay::ReplayFrame)
/// — the requester tells the server what it already has, and the hash lets the
/// server detect that the two disagree about history.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ChainState {
    /// The highest sequence number held for this publisher.
    pub seq: Seq,
    /// That message's [`TopicEnvelope::message_hash`].
    pub hash: MessageHash,
}

impl ChainState {
    /// The state after holding `seq` with link hash `hash`.
    pub fn new(seq: Seq, hash: MessageHash) -> Self {
        Self { seq, hash }
    }
}

/// How a received envelope relates to the chain the reader already holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkStatus {
    /// The expected next message: `seq == prev + 1` (or a well-formed genesis)
    /// and `prev_hash` matches what the reader holds.
    Ok,
    /// Already held: same `(sender, seq)` and the same hash. Idempotent
    /// re-delivery, not an error.
    Duplicate,
    /// The sequence jumped: the reader is missing at least one message.
    Gap {
        /// The highest sequence the reader holds for this sender, or `None`
        /// when it holds nothing at all.
        have: Option<Seq>,
    },
    /// Irreconcilable: a different message occupies a slot the reader already
    /// filled, a genesis with a non-zero `prev_hash`, or a `prev_hash` that
    /// does not match the held predecessor.
    Fork,
}

/// Classify `env` against the reader's chain state for that sender.
///
/// `state` is the reader's high-water mark for `env.sender` (`None` if it holds
/// nothing). `held_hash_at_seq` is the hash of the message the reader already
/// holds at `env.seq`, when it holds one — that is what separates a
/// [`LinkStatus::Duplicate`] from a [`LinkStatus::Fork`] for a backfilled slot.
///
/// This function is pure and does no signature checking: the caller runs
/// [`TopicEnvelope::verify`] first, since classifying an unauthenticated
/// envelope would let anyone manufacture a "fork".
///
/// # The truth table
///
/// The first rule is structural and applies before the reader's state is even
/// consulted: `prev_hash == ZERO` **iff** `seq == 0`. An envelope that breaks
/// the equivalence — a genesis pointing at a predecessor, or a successor
/// claiming to be one — is a [`LinkStatus::Fork`] outright. Then:
///
/// | reader holds | `env.seq` | verdict |
/// |---|---|---|
/// | nothing | `0` | [`Ok`](LinkStatus::Ok) |
/// | nothing | `> 0` | [`Gap`](LinkStatus::Gap) `{ have: None }` |
/// | up to `s` | `s + 1`, `prev_hash == state.hash` | [`Ok`](LinkStatus::Ok) |
/// | up to `s` | `s + 1`, `prev_hash != state.hash` | [`Fork`](LinkStatus::Fork) |
/// | up to `s` | `> s + 1` | [`Gap`](LinkStatus::Gap) `{ have: Some(s) }` |
/// | up to `s` | `<= s`, held hash matches | [`Duplicate`](LinkStatus::Duplicate) |
/// | up to `s` | `<= s`, held hash differs | [`Fork`](LinkStatus::Fork) |
///
/// For the last two rows, `held_hash_at_seq` is the lookup; when `env.seq`
/// *is* the high-water mark, `state.hash` is used as the fallback so the common
/// live re-delivery needs no store hit. If the caller reports no held hash for a
/// slot at or below its own high-water mark, the verdict is
/// [`LinkStatus::Fork`]: logs are dense, so a reader claiming `s` necessarily
/// holds everything below it, and an unlinkable fill-in for a slot it cannot
/// produce is exactly the "refuse, do not guess" case.
pub fn classify_link(
    env: &TopicEnvelope,
    state: Option<ChainState>,
    held_hash_at_seq: Option<MessageHash>,
) -> Result<LinkStatus> {
    // `prev_hash == ZERO` iff genesis — checked before anything else, so a
    // malformed link never reaches the state comparison.
    if env.prev_hash.is_zero() != (env.seq == Seq::ZERO) {
        return Ok(LinkStatus::Fork);
    }

    let Some(state) = state else {
        return Ok(if env.seq == Seq::ZERO {
            LinkStatus::Ok
        } else {
            LinkStatus::Gap { have: None }
        });
    };

    if state.seq.0.checked_add(1) == Some(env.seq.0) {
        return Ok(if env.prev_hash == state.hash {
            LinkStatus::Ok
        } else {
            LinkStatus::Fork
        });
    }
    if env.seq > state.seq {
        return Ok(LinkStatus::Gap {
            have: Some(state.seq),
        });
    }

    // At or below the high-water mark: a slot the reader already covers.
    let held = held_hash_at_seq.or_else(|| (env.seq == state.seq).then_some(state.hash));
    Ok(match held {
        Some(held) if held == env.message_hash()? => LinkStatus::Duplicate,
        _ => LinkStatus::Fork,
    })
}

/// The `prev_hash` a publisher should stamp on its next message:
/// `state.hash`, or [`MessageHash::ZERO`] at genesis.
///
/// ```
/// use library::{ChainState, MessageHash, Seq, next_prev_hash};
/// assert_eq!(next_prev_hash(None), MessageHash::ZERO);
/// let hash = MessageHash::from_bytes([7u8; 32]);
/// assert_eq!(next_prev_hash(Some(ChainState::new(Seq(4), hash))), hash);
/// ```
pub fn next_prev_hash(state: Option<ChainState>) -> MessageHash {
    state.map_or(MessageHash::ZERO, |s| s.hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fabric_key::FabricKey;
    use crate::identity::NodeIdentity;
    use crate::roster::RosterVersion;
    use crate::topic::TopicId;
    use proptest::prelude::*;

    fn seed() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    /// A publisher sealing a real chain, so every test classifies envelopes
    /// that were actually produced by [`TopicEnvelope::seal`] rather than
    /// hand-assembled ones.
    struct Publisher {
        identity: NodeIdentity,
        topic: TopicId,
        key: FabricKey,
        state: Option<ChainState>,
    }

    impl Publisher {
        fn new(sender_seed: [u8; 32], fabric_seed: [u8; 32]) -> Self {
            let fabric = NodeIdentity::from_seed(fabric_seed).node_id();
            Self {
                identity: NodeIdentity::from_seed(sender_seed),
                topic: TopicId::derive(fabric, "ops"),
                key: FabricKey::from_bytes([7u8; 32]),
                state: None,
            }
        }

        /// Seal the next message in the chain *without* advancing the local
        /// state, so a caller can classify it against the pre-append state.
        fn next(&self, body: &[u8]) -> TopicEnvelope {
            let seq = self.state.map_or(Seq::ZERO, |s| s.seq.next());
            TopicEnvelope::seal(
                &self.identity,
                self.topic,
                seq,
                next_prev_hash(self.state),
                RosterVersion(1),
                &self.key,
                1_700_000_000 + seq.0 as i64,
                body,
            )
            .unwrap()
        }

        /// Seal and append: the publisher's own single-allocator step.
        fn append(&mut self, body: &[u8]) -> TopicEnvelope {
            let env = self.next(body);
            self.state = Some(ChainState::new(env.seq, env.message_hash().unwrap()));
            env
        }
    }

    proptest! {
        /// A chain built by sealing classifies `Ok` at every link, and the
        /// same envelope re-delivered immediately classifies `Duplicate`.
        #[test]
        fn sealed_chain_classifies_ok_at_every_link(ss in seed(), fs in seed(), n in 1usize..12) {
            let mut pubr = Publisher::new(ss, fs);
            let mut history: Vec<(Option<ChainState>, TopicEnvelope)> = Vec::new();

            for i in 0..n {
                let before = pubr.state;
                let env = pubr.next(format!("message {i}").as_bytes());
                prop_assert_eq!(
                    classify_link(&env, before, None).unwrap(),
                    LinkStatus::Ok
                );
                pubr.state = Some(ChainState::new(env.seq, env.message_hash().unwrap()));
                history.push((before, env));
            }

            // Re-delivery of the newest message is a Duplicate against the
            // post-append state — the structural dedupe.
            let (_, newest) = history.last().unwrap();
            prop_assert_eq!(
                classify_link(newest, pubr.state, None).unwrap(),
                LinkStatus::Duplicate
            );

            // Re-delivery of any older message is a Duplicate too, given its
            // held hash.
            for (_, env) in &history {
                let held = env.message_hash().unwrap();
                prop_assert_eq!(
                    classify_link(env, pubr.state, Some(held)).unwrap(),
                    LinkStatus::Duplicate
                );
            }
        }

        /// Perturbing a single bit of `seq` never classifies `Ok`: the
        /// perturbed message either lands in a filled slot (Fork), skips ahead
        /// (Gap), or breaks the genesis rule (Fork).
        #[test]
        fn single_bit_seq_perturbation_is_never_ok(ss in seed(), fs in seed(), n in 1usize..8, bit in 0u32..64) {
            let mut pubr = Publisher::new(ss, fs);
            for i in 0..n {
                let before = pubr.state;
                let mut env = pubr.append(format!("message {i}").as_bytes());
                env.seq = Seq(env.seq.0 ^ (1u64 << bit));
                prop_assert_ne!(
                    classify_link(&env, before, None).unwrap(),
                    LinkStatus::Ok
                );
            }
        }

        /// Perturbing a single bit of `prev_hash` never classifies `Ok`.
        #[test]
        fn single_bit_prev_hash_perturbation_is_never_ok(ss in seed(), fs in seed(), n in 1usize..8, byte in 0usize..32, bit in 0u32..8) {
            let mut pubr = Publisher::new(ss, fs);
            for i in 0..n {
                let before = pubr.state;
                let mut env = pubr.append(format!("message {i}").as_bytes());
                let mut prev = *env.prev_hash.as_bytes();
                prev[byte] ^= 1u8 << bit;
                env.prev_hash = MessageHash::from_bytes(prev);
                prop_assert_ne!(
                    classify_link(&env, before, None).unwrap(),
                    LinkStatus::Ok
                );
            }
        }

        /// Perturbing the *content* of a message that occupies an already-held
        /// slot is a Fork, not a Duplicate: same `(sender, seq)`, different
        /// hash is precisely equivocation.
        #[test]
        fn rewritten_content_in_a_held_slot_is_a_fork(ss in seed(), fs in seed()) {
            let mut pubr = Publisher::new(ss, fs);
            let genesis = pubr.append(b"original");

            // The same publisher signs a *different* genesis.
            let equivocation = TopicEnvelope::seal(
                &pubr.identity,
                pubr.topic,
                Seq::ZERO,
                MessageHash::ZERO,
                RosterVersion(1),
                &pubr.key,
                1_700_000_000,
                b"rewritten",
            )
            .unwrap();

            prop_assert_ne!(
                genesis.message_hash().unwrap(),
                equivocation.message_hash().unwrap()
            );
            prop_assert_eq!(
                classify_link(&equivocation, pubr.state, None).unwrap(),
                LinkStatus::Fork
            );
        }

        /// Skipping any positive number of messages is a Gap reporting the
        /// reader's actual high-water mark.
        #[test]
        fn skipping_messages_is_a_gap(ss in seed(), fs in seed(), held in 1usize..6, skip in 1u64..6) {
            let mut pubr = Publisher::new(ss, fs);
            for i in 0..held {
                pubr.append(format!("message {i}").as_bytes());
            }
            let reader_state = pubr.state;
            // The publisher runs ahead; the reader misses the middle.
            for i in 0..skip {
                pubr.append(format!("skipped {i}").as_bytes());
            }
            let ahead = pubr.append(b"far ahead");

            prop_assert_eq!(
                classify_link(&ahead, reader_state, None).unwrap(),
                LinkStatus::Gap { have: Some(reader_state.unwrap().seq) }
            );
        }

        /// `next_prev_hash` is exactly the state's hash, or ZERO at genesis —
        /// and feeding it back into `seal` reproduces an `Ok` link.
        #[test]
        fn next_prev_hash_matches_state(ss in seed(), fs in seed(), h in seed()) {
            prop_assert_eq!(next_prev_hash(None), MessageHash::ZERO);
            let hash = MessageHash::from_bytes(h);
            prop_assert_eq!(next_prev_hash(Some(ChainState::new(Seq(4), hash))), hash);

            let mut pubr = Publisher::new(ss, fs);
            pubr.append(b"genesis");
            let before = pubr.state;
            let env = pubr.next(b"successor");
            prop_assert_eq!(env.prev_hash, next_prev_hash(before));
            prop_assert_eq!(classify_link(&env, before, None).unwrap(), LinkStatus::Ok);
        }

        /// `ChainState` survives a serde round-trip (it rides in the replay
        /// request).
        #[test]
        fn chain_state_serde_roundtrips(s in any::<u64>(), h in seed()) {
            let state = ChainState::new(Seq(s), MessageHash::from_bytes(h));
            let json = serde_json::to_string(&state).unwrap();
            prop_assert_eq!(serde_json::from_str::<ChainState>(&json).unwrap(), state);
        }
    }

    /// A publisher whose chain is `genesis -> one -> two`, plus the reader
    /// state after each step, for the truth-table examples below.
    fn chain() -> (Publisher, Vec<TopicEnvelope>, Vec<Option<ChainState>>) {
        let mut pubr = Publisher::new([2u8; 32], [1u8; 32]);
        let mut envs = Vec::new();
        let mut states = vec![None];
        for body in [b"genesis".as_slice(), b"one", b"two"] {
            let env = pubr.append(body);
            envs.push(env);
            states.push(pubr.state);
        }
        (pubr, envs, states)
    }

    /// Truth table, row 1: a well-formed genesis against an empty reader.
    #[test]
    fn genesis_against_empty_reader_is_ok() {
        let (_, envs, states) = chain();
        assert_eq!(
            classify_link(&envs[0], states[0], None).unwrap(),
            LinkStatus::Ok
        );
    }

    /// Truth table, row 2: the expected next message.
    #[test]
    fn increment_is_ok() {
        let (_, envs, states) = chain();
        assert_eq!(
            classify_link(&envs[1], states[1], None).unwrap(),
            LinkStatus::Ok
        );
        assert_eq!(
            classify_link(&envs[2], states[2], None).unwrap(),
            LinkStatus::Ok
        );
    }

    /// Truth table, row 3: the same message twice.
    #[test]
    fn duplicate_is_duplicate() {
        let (_, envs, states) = chain();
        // Against the state that already includes it, with no store lookup.
        assert_eq!(
            classify_link(&envs[2], states[3], None).unwrap(),
            LinkStatus::Duplicate
        );
        // And an older slot, with the store's held hash supplied.
        let held = envs[0].message_hash().unwrap();
        assert_eq!(
            classify_link(&envs[0], states[3], Some(held)).unwrap(),
            LinkStatus::Duplicate
        );
    }

    /// Truth table, row 4: a jump forward.
    #[test]
    fn gap_reports_what_the_reader_has() {
        let (_, envs, states) = chain();
        // Reader holds nothing, message is seq 2.
        assert_eq!(
            classify_link(&envs[2], None, None).unwrap(),
            LinkStatus::Gap { have: None }
        );
        // Reader holds seq 0, message is seq 2.
        assert_eq!(
            classify_link(&envs[2], states[1], None).unwrap(),
            LinkStatus::Gap { have: Some(Seq(0)) }
        );
    }

    /// Truth table, row 5: `seq` is right but the link is not.
    #[test]
    fn broken_link_at_the_next_seq_is_a_fork() {
        let (_, envs, states) = chain();
        let mut forged = envs[1].clone();
        forged.prev_hash = MessageHash::from_bytes([0xaa; 32]);
        assert_eq!(
            classify_link(&forged, states[1], None).unwrap(),
            LinkStatus::Fork
        );
    }

    /// A genesis carrying a non-zero `prev_hash` is malformed, whatever the
    /// reader holds.
    #[test]
    fn genesis_with_a_predecessor_is_a_fork() {
        let (_, envs, states) = chain();
        let mut forged = envs[0].clone();
        forged.prev_hash = MessageHash::from_bytes([0xaa; 32]);
        for state in &states {
            assert_eq!(
                classify_link(&forged, *state, None).unwrap(),
                LinkStatus::Fork
            );
        }
    }

    /// The converse: a non-genesis claiming the ZERO link is malformed too.
    #[test]
    fn successor_claiming_the_genesis_link_is_a_fork() {
        let (_, envs, states) = chain();
        let mut forged = envs[1].clone();
        forged.prev_hash = MessageHash::ZERO;
        for state in &states {
            assert_eq!(
                classify_link(&forged, *state, None).unwrap(),
                LinkStatus::Fork
            );
        }
    }

    /// A fill-in for a slot at or below the high-water mark that the reader
    /// cannot produce a hash for is refused rather than guessed at.
    #[test]
    fn backfill_with_no_held_hash_is_a_fork() {
        let (_, envs, states) = chain();
        assert_eq!(
            classify_link(&envs[0], states[3], None).unwrap(),
            LinkStatus::Fork
        );
    }

    /// A held hash that disagrees with the presented message is the
    /// equivocation case.
    #[test]
    fn backfill_with_a_disagreeing_held_hash_is_a_fork() {
        let (_, envs, states) = chain();
        assert_eq!(
            classify_link(
                &envs[0],
                states[3],
                Some(MessageHash::from_bytes([0xaa; 32]))
            )
            .unwrap(),
            LinkStatus::Fork
        );
    }

    /// The reader's high-water mark being `u64::MAX` must not overflow the
    /// "is this the next seq?" arithmetic.
    #[test]
    fn saturated_high_water_mark_does_not_overflow() {
        let (_, envs, _) = chain();
        let state = Some(ChainState::new(
            Seq(u64::MAX),
            MessageHash::from_bytes([0xaa; 32]),
        ));
        // envs[1] is seq 1, far below the mark, with no held hash → Fork.
        assert_eq!(
            classify_link(&envs[1], state, None).unwrap(),
            LinkStatus::Fork
        );
    }

    /// Classification never depends on the payload being decryptable: the
    /// chain is checked on ciphertext alone.
    #[test]
    fn classification_ignores_the_key() {
        let (_, envs, states) = chain();
        assert!(envs[1].open(&FabricKey::from_bytes([9u8; 32])).is_err());
        assert_eq!(
            classify_link(&envs[1], states[1], None).unwrap(),
            LinkStatus::Ok
        );
    }
}

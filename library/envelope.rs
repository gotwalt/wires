//! The topic envelope: one encrypted, signed, chain-linked message.
//!
//! Every message published to a topic is a [`TopicEnvelope`]: ciphertext sealed
//! under the [`FabricKey`] for a roster version, signed by the sender, and
//! linked to that sender's previous message by hash. The three properties are
//! separable on purpose:
//!
//! - **Signature** — anyone can verify authorship and integrity with
//!   [`verify`](TopicEnvelope::verify) alone, holding no key material. That is
//!   what lets a node *store* messages whose fabric key it does not have yet;
//!   when a late `wires import` installs the key, the history heals and
//!   displays.
//! - **Encryption** — [`open`](TopicEnvelope::open) needs the key for
//!   `key_version`. Authorization is roster inclusion plus key possession;
//!   there is no per-message capability.
//! - **Chain link** — `prev_hash` is checked by [`crate::chain`], not here, so
//!   verification never depends on having the rest of the log.
//!
//! # Nonce discipline
//!
//! The AEAD nonce is `blake3(topic ‖ sender ‖ seq_le)[..12]` — deterministic,
//! which is only safe because a `(node, topic)` pair has exactly one sequence
//! allocator (the resident `wires tail` process). Reusing a seq under the same
//! key would reuse a nonce, so seq allocation is structurally single-writer
//! rather than lock-protected.
//!
//! # What is deliberately absent
//!
//! No capability id (authorization is roster inclusion + key possession), no
//! message kind (control traffic would be a new format, not a new variant), no
//! payload length (retention is out of scope), and no epoch — `key_version` is
//! the roster version, so the key and the member set advance together.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::fabric_key::FabricKey;
use crate::grant::AlgorithmId;
use crate::identity::{NodeId, NodeIdentity, Signature};
use crate::roster::RosterVersion;
use crate::topic::TopicId;

/// The current (and only) topic-envelope format version.
pub const ENVELOPE_V1: u8 = 1;

/// ChaCha20-Poly1305's nonce width, and therefore how much of the nonce hash
/// is used.
const NONCE_LEN: usize = 12;

/// The deterministic AEAD nonce for one `(topic, sender, seq)` slot:
/// `blake3(topic ‖ sender ‖ seq_le)[..12]`.
///
/// Deterministic rather than random so that a re-seal of the same slot is
/// byte-identical, and *safe* only because a `(node, topic)` pair has exactly
/// one sequence allocator (see the module docs). `seq` is encoded
/// little-endian; the three inputs are fixed-width except `seq`, which is last,
/// so the concatenation is unambiguous.
fn nonce_for(topic: &TopicId, sender: &NodeId, seq: Seq) -> [u8; NONCE_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(topic.as_bytes());
    hasher.update(sender.as_bytes());
    hasher.update(&seq.0.to_le_bytes());
    let digest = hasher.finalize();
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&digest.as_bytes()[..NONCE_LEN]);
    nonce
}

/// A per-sender message sequence number: 0-based and dense (no holes), so a
/// reader can tell "I am missing something" from "there is nothing more".
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct Seq(pub u64);

impl Seq {
    /// The genesis sequence number.
    pub const ZERO: Seq = Seq(0);

    /// The next sequence number after this one.
    pub fn next(self) -> Seq {
        Seq(self.0 + 1)
    }
}

/// The blake3 digest of an envelope's signing bytes — the link a successor
/// message points back to. Serializes as lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct MessageHash([u8; 32]);

impl MessageHash {
    /// The all-zero hash: the `prev_hash` of a genesis message (`seq == 0`),
    /// and only of a genesis message.
    pub const ZERO: MessageHash = MessageHash([0u8; 32]);

    /// Wrap raw digest bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw 32 digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Whether this is [`MessageHash::ZERO`] (i.e. a genesis link).
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Lowercase-hex rendering of the digest.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a `MessageHash` from its lowercase-hex rendering.
    ///
    /// Returns [`crate::Error::BadHex`] for non-hex text and
    /// [`crate::Error::BadKeyLength`] when the decoded byte count is not 32.
    pub fn from_hex(s: &str) -> Result<MessageHash> {
        let bytes = hex::decode(s)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| crate::error::Error::BadKeyLength)?;
        Ok(MessageHash(arr))
    }
}

impl Serialize for MessageHash {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for MessageHash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("MessageHash expects 32 bytes"))?;
        Ok(MessageHash(arr))
    }
}

/// An envelope's encrypted payload (ChaCha20-Poly1305 ciphertext plus tag).
///
/// A newtype (never a bare `Vec<u8>`) with lowercase-hex serde, so the whole
/// envelope canonicalizes deterministically for signing.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ciphertext(Vec<u8>);

impl Ciphertext {
    /// Wrap owned ciphertext bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the ciphertext bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The ciphertext's length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the ciphertext is empty (true only for a malformed envelope —
    /// even an empty plaintext seals to a non-empty tag).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Lowercase-hex rendering of the ciphertext.
    pub fn hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl Serialize for Ciphertext {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Ciphertext {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(Ciphertext(
            hex::decode(&s).map_err(serde::de::Error::custom)?,
        ))
    }
}

/// The signed portion of a v1 envelope: every field except `sig`. Serialized to
/// canonical JSON to produce the exact bytes the sender signs and a verifier
/// recomputes.
///
/// The same struct, with `ciphertext` set to an empty [`Ciphertext`], is the
/// AEAD associated data — so the encryption is bound to the topic, sender,
/// sequence, link, key version, and timestamp it claims.
#[derive(Serialize)]
struct EnvelopeBody<'a> {
    format: u8,
    topic: &'a TopicId,
    sender: &'a NodeId,
    seq: u64,
    prev_hash: &'a MessageHash,
    key_version: u64,
    timestamp: i64,
    ciphertext: &'a Ciphertext,
    alg: &'a AlgorithmId,
}

/// One published message: sender-signed, fabric-key-encrypted, hash-linked.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TopicEnvelope {
    /// Format discriminant; `= ENVELOPE_V1`. A *signed* field.
    pub format: u8,
    /// The topic this message belongs to. Signed, so an envelope cannot be
    /// replayed into a different topic (see [`crate::Error::TopicMismatch`]).
    pub topic: TopicId,
    /// The publishing node. Authorship, and half of the chain's identity — the
    /// log is per-publisher, not global.
    pub sender: NodeId,
    /// This sender's 0-based, dense sequence number for this topic.
    pub seq: Seq,
    /// The [`message_hash`](Self::message_hash) of this sender's previous
    /// message, or [`MessageHash::ZERO`] iff `seq == 0`.
    pub prev_hash: MessageHash,
    /// Which roster version's [`FabricKey`] the ciphertext is sealed under.
    pub key_version: RosterVersion,
    /// The sender's clock at publish time, unix seconds. **Informational and
    /// unverifiable** — used only for display ordering, never for any decision.
    pub timestamp: i64,
    /// The encrypted payload.
    pub ciphertext: Ciphertext,
    /// Which scheme `sig` was produced with.
    pub alg: AlgorithmId,
    /// Sender signature over the canonical-JSON envelope body.
    pub sig: Signature,
}

impl TopicEnvelope {
    /// Seal `plaintext` and sign the resulting envelope as `sender`
    /// (encrypt-then-sign).
    ///
    /// The caller supplies `seq` and `prev_hash` from its chain state (see
    /// [`crate::chain::next_prev_hash`]) and `key_version` from the fabric key
    /// it holds. The nonce is derived from `(topic, sender, seq)`, so calling
    /// this twice with the same triple under the same key is a nonce reuse —
    /// the single-allocator rule in the module docs is what prevents it.
    ///
    /// ```
    /// use library::{FabricKey, MessageHash, NodeIdentity, RosterVersion, Seq, TopicEnvelope, TopicId};
    /// let sender = NodeIdentity::from_seed([2u8; 32]);
    /// let fabric = NodeIdentity::from_seed([1u8; 32]).node_id();
    /// let topic = TopicId::derive(fabric, "ops");
    /// let key = FabricKey::generate();
    /// let env = TopicEnvelope::seal(
    ///     &sender, topic, Seq::ZERO, MessageHash::ZERO, RosterVersion(1), &key, 1_700_000_000,
    ///     b"ship it",
    /// ).unwrap();
    /// assert!(env.verify().is_ok());
    /// assert_eq!(env.open(&key).unwrap(), b"ship it");
    /// ```
    // Eight arguments, by design: every one of them is a *signed* field, and
    // bundling them into a params struct would just move the same list one
    // level down while hiding which of them the signature covers.
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        sender: &NodeIdentity,
        topic: TopicId,
        seq: Seq,
        prev_hash: MessageHash,
        key_version: RosterVersion,
        key: &FabricKey,
        timestamp: i64,
        plaintext: &[u8],
    ) -> Result<TopicEnvelope> {
        let alg = AlgorithmId::Ed25519;
        let sender_id = sender.node_id();

        // The AAD is the body with an *empty* ciphertext — the same bytes both
        // sides can compute, binding the payload to every other field.
        let empty = Ciphertext::from_bytes(Vec::new());
        let aad = canonical_bytes(&EnvelopeBody {
            format: ENVELOPE_V1,
            topic: &topic,
            sender: &sender_id,
            seq: seq.0,
            prev_hash: &prev_hash,
            key_version: key_version.0,
            timestamp,
            ciphertext: &empty,
            alg: &alg,
        })?;

        let cipher = ChaCha20Poly1305::new(&Key::from(*key.as_bytes()));
        let ciphertext = Ciphertext::from_bytes(
            cipher
                .encrypt(
                    &Nonce::from(nonce_for(&topic, &sender_id, seq)),
                    Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::SealedKeyOpen)?,
        );

        let sig = sender.sign(&canonical_bytes(&EnvelopeBody {
            format: ENVELOPE_V1,
            topic: &topic,
            sender: &sender_id,
            seq: seq.0,
            prev_hash: &prev_hash,
            key_version: key_version.0,
            timestamp,
            ciphertext: &ciphertext,
            alg: &alg,
        })?);

        Ok(TopicEnvelope {
            format: ENVELOPE_V1,
            topic,
            sender: sender_id,
            seq,
            prev_hash,
            key_version,
            timestamp,
            ciphertext,
            alg,
            sig,
        })
    }

    /// This envelope's body, with `ciphertext` replaced by `ciphertext` —
    /// the real payload for [`signing_bytes`](Self::signing_bytes), an empty
    /// one for the AEAD associated data.
    fn body<'a>(&'a self, ciphertext: &'a Ciphertext) -> EnvelopeBody<'a> {
        EnvelopeBody {
            format: self.format,
            topic: &self.topic,
            sender: &self.sender,
            seq: self.seq.0,
            prev_hash: &self.prev_hash,
            key_version: self.key_version.0,
            timestamp: self.timestamp,
            ciphertext,
            alg: &self.alg,
        }
    }

    /// Verify structure and signature only: supported algorithm, known
    /// `format`, and a `sender` signature over the canonical body.
    ///
    /// Deliberately does **not** decrypt and does **not** consult the chain —
    /// an envelope is verifiable, and therefore storable, before its key or its
    /// predecessors arrive.
    pub fn verify(&self) -> Result<()> {
        if self.alg != AlgorithmId::Ed25519 {
            return Err(Error::UnsupportedAlgorithm);
        }
        if self.format != ENVELOPE_V1 {
            return Err(Error::UnsupportedVersion);
        }
        self.sender.verify(&self.signing_bytes()?, &self.sig)
    }

    /// Decrypt the payload with `key`.
    ///
    /// The caller must select the key matching `key_version`
    /// ([`crate::Error::KeyVersionUnknown`] when it holds none) — passing the
    /// wrong key, or a tampered body, fails the AEAD tag and surfaces as
    /// [`crate::Error::SealedKeyOpen`] — the crate's single "an AEAD open
    /// failed" error, kept distinct from the sender-signature failure
    /// [`verify`](Self::verify) reports.
    pub fn open(&self, key: &FabricKey) -> Result<Vec<u8>> {
        let empty = Ciphertext::from_bytes(Vec::new());
        let aad = canonical_bytes(&self.body(&empty))?;
        let cipher = ChaCha20Poly1305::new(&Key::from(*key.as_bytes()));
        cipher
            .decrypt(
                &Nonce::from(nonce_for(&self.topic, &self.sender, self.seq)),
                Payload {
                    msg: self.ciphertext.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| Error::SealedKeyOpen)
    }

    /// The exact canonical bytes covered by [`sig`](Self::sig) — every field
    /// except the signature itself.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(&self.body(&self.ciphertext))
    }

    /// This message's link hash: `blake3(signing_bytes())`. The value a
    /// successor carries as its `prev_hash`.
    pub fn message_hash(&self) -> Result<MessageHash> {
        Ok(MessageHash::from_bytes(
            *blake3::hash(&self.signing_bytes()?).as_bytes(),
        ))
    }

    /// The wire form: canonical JSON bytes. Gossip and replay are binary
    /// channels, so there is no base64 layer here (unlike the human-pasted
    /// tickets and credentials).
    ///
    /// ```
    /// use library::{FabricKey, MessageHash, NodeIdentity, RosterVersion, Seq, TopicEnvelope, TopicId};
    /// let sender = NodeIdentity::from_seed([2u8; 32]);
    /// let topic = TopicId::from_bytes([7u8; 32]);
    /// let key = FabricKey::generate();
    /// let env = TopicEnvelope::seal(
    ///     &sender, topic, Seq::ZERO, MessageHash::ZERO, RosterVersion(1), &key, 0, b"hello",
    /// ).unwrap();
    ///
    /// // Round-tripping the wire form preserves the signed bytes exactly.
    /// let back = TopicEnvelope::from_wire(&env.to_wire().unwrap()).unwrap();
    /// assert_eq!(back, env);
    /// assert!(back.verify().is_ok());
    /// assert_eq!(back.message_hash().unwrap(), env.message_hash().unwrap());
    /// ```
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        canonical_bytes(self)
    }

    /// Parse an envelope from its wire bytes. Does not verify — the caller runs
    /// [`verify`](Self::verify) before trusting anything in it.
    pub fn from_wire(bytes: &[u8]) -> Result<TopicEnvelope> {
        serde_json::from_slice(bytes).map_err(Error::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn seed() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    fn payload() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..256)
    }

    /// The pieces every envelope needs, drawn together so each property test
    /// exercises a fresh sender / topic / key / slot.
    #[derive(Debug, Clone)]
    struct Parts {
        sender_seed: [u8; 32],
        fabric_seed: [u8; 32],
        name: String,
        key_bytes: [u8; 32],
        seq: u64,
        prev: [u8; 32],
        key_version: u64,
        timestamp: i64,
    }

    impl Parts {
        fn sender(&self) -> NodeIdentity {
            NodeIdentity::from_seed(self.sender_seed)
        }
        fn topic(&self) -> TopicId {
            TopicId::derive(
                NodeIdentity::from_seed(self.fabric_seed).node_id(),
                &self.name,
            )
        }
        fn key(&self) -> FabricKey {
            FabricKey::from_bytes(self.key_bytes)
        }
        /// `prev_hash` obeying the "ZERO iff genesis" rule.
        fn prev_hash(&self) -> MessageHash {
            if self.seq == 0 {
                MessageHash::ZERO
            } else {
                MessageHash::from_bytes(self.prev)
            }
        }
        fn seal(&self, plaintext: &[u8]) -> TopicEnvelope {
            TopicEnvelope::seal(
                &self.sender(),
                self.topic(),
                Seq(self.seq),
                self.prev_hash(),
                RosterVersion(self.key_version),
                &self.key(),
                self.timestamp,
                plaintext,
            )
            .unwrap()
        }
    }

    fn parts() -> impl Strategy<Value = Parts> {
        (
            seed(),
            seed(),
            "[a-z]{1,12}",
            seed(),
            any::<u64>(),
            seed(),
            any::<u64>(),
            any::<i64>(),
        )
            .prop_map(
                |(sender_seed, fabric_seed, name, key_bytes, seq, prev, key_version, timestamp)| {
                    Parts {
                        sender_seed,
                        fabric_seed,
                        name,
                        key_bytes,
                        seq,
                        prev,
                        key_version,
                        timestamp,
                    }
                },
            )
    }

    proptest! {
        /// Seal, then verify and open: the payload comes back byte-identical
        /// and every field is what the caller asked for.
        #[test]
        fn seal_verify_open_roundtrips(p in parts(), msg in payload()) {
            let env = p.seal(&msg);
            prop_assert_eq!(env.format, ENVELOPE_V1);
            prop_assert_eq!(env.topic, p.topic());
            prop_assert_eq!(env.sender, p.sender().node_id());
            prop_assert_eq!(env.seq, Seq(p.seq));
            prop_assert_eq!(env.prev_hash, p.prev_hash());
            prop_assert_eq!(env.key_version, RosterVersion(p.key_version));
            prop_assert_eq!(env.timestamp, p.timestamp);
            prop_assert!(env.verify().is_ok());
            prop_assert_eq!(env.open(&p.key()).unwrap(), msg);
        }

        /// Even an empty payload seals to a non-empty ciphertext (the tag), so
        /// `Ciphertext::is_empty` really does mean "malformed".
        #[test]
        fn empty_payload_still_has_a_tag(p in parts()) {
            let env = p.seal(b"");
            prop_assert!(!env.ciphertext.is_empty());
            prop_assert_eq!(env.ciphertext.len(), 16);
            prop_assert_eq!(env.open(&p.key()).unwrap(), Vec::<u8>::new());
        }

        /// Verification needs no key material at all — the property that lets a
        /// node store messages whose fabric key has not arrived yet.
        #[test]
        fn verify_needs_no_key(p in parts(), msg in payload(), other in seed()) {
            prop_assume!(other != p.key_bytes);
            let env = p.seal(&msg);
            prop_assert!(env.verify().is_ok());
            // Opening with the wrong key fails, but verification still passes.
            prop_assert!(env.open(&FabricKey::from_bytes(other)).is_err());
            prop_assert!(env.verify().is_ok());
        }

        /// A different sender's key does not verify the signature.
        #[test]
        fn wrong_sender_key_fails_verify(p in parts(), msg in payload(), other in seed()) {
            prop_assume!(other != p.sender_seed);
            let mut env = p.seal(&msg);
            env.sender = NodeIdentity::from_seed(other).node_id();
            prop_assert!(matches!(env.verify(), Err(Error::InvalidSignature)));
        }

        /// Tampering with **every** signed field in turn breaks `verify`, and
        /// (because the same body is the AAD) also breaks `open`. `ciphertext`
        /// is the one field that is not in the AAD, so it is checked for the
        /// signature failure alone.
        #[test]
        fn tampering_any_signed_field_fails_verify_and_open(p in parts(), msg in payload(), other in seed()) {
            prop_assume!(other != p.sender_seed && other != p.fabric_seed);
            let base = p.seal(&msg);
            let key = p.key();
            let other_id = NodeIdentity::from_seed(other).node_id();

            // format
            let mut t = base.clone();
            t.format = ENVELOPE_V1 + 1;
            prop_assert!(matches!(t.verify(), Err(Error::UnsupportedVersion)));
            prop_assert!(t.open(&key).is_err());

            // topic — an envelope cannot be replayed into another topic.
            let mut t = base.clone();
            t.topic = TopicId::derive(other_id, "elsewhere");
            prop_assert!(matches!(t.verify(), Err(Error::InvalidSignature)));
            prop_assert!(t.open(&key).is_err());

            // sender
            let mut t = base.clone();
            t.sender = other_id;
            prop_assert!(matches!(t.verify(), Err(Error::InvalidSignature)));
            prop_assert!(t.open(&key).is_err());

            // seq
            let mut t = base.clone();
            t.seq = Seq(p.seq.wrapping_add(1));
            prop_assert!(matches!(t.verify(), Err(Error::InvalidSignature)));
            prop_assert!(t.open(&key).is_err());

            // prev_hash
            let mut t = base.clone();
            let mut prev = *t.prev_hash.as_bytes();
            prev[0] ^= 0x01;
            t.prev_hash = MessageHash::from_bytes(prev);
            prop_assert!(matches!(t.verify(), Err(Error::InvalidSignature)));
            prop_assert!(t.open(&key).is_err());

            // key_version
            let mut t = base.clone();
            t.key_version = RosterVersion(p.key_version.wrapping_add(1));
            prop_assert!(matches!(t.verify(), Err(Error::InvalidSignature)));
            prop_assert!(t.open(&key).is_err());

            // timestamp — informational, but still signed and still AAD.
            let mut t = base.clone();
            t.timestamp = p.timestamp.wrapping_add(1);
            prop_assert!(matches!(t.verify(), Err(Error::InvalidSignature)));
            prop_assert!(t.open(&key).is_err());

            // ciphertext — signed, and its own AEAD tag also catches it.
            let mut t = base.clone();
            let mut ct = t.ciphertext.as_bytes().to_vec();
            ct[0] ^= 0x01;
            t.ciphertext = Ciphertext::from_bytes(ct);
            prop_assert!(matches!(t.verify(), Err(Error::InvalidSignature)));
            prop_assert!(matches!(t.open(&key), Err(Error::SealedKeyOpen)));

            // alg — only one scheme exists; locked so adding a second cannot
            // silently skip the check.
            prop_assert_eq!(base.alg, AlgorithmId::Ed25519);

            // sig
            let mut t = base.clone();
            let mut sig = *t.sig.as_bytes();
            sig[0] ^= 0x01;
            t.sig = Signature::from_bytes(sig);
            prop_assert!(matches!(t.verify(), Err(Error::InvalidSignature)));
        }

        /// A tampered field that is re-signed by the sender still fails to
        /// open: the AAD binds the ciphertext to the body independently of the
        /// signature. This is the AAD's whole job.
        #[test]
        fn aad_tamper_fails_open_even_when_resigned(p in parts(), msg in payload()) {
            let base = p.seal(&msg);
            let sender = p.sender();

            let mut t = base.clone();
            t.timestamp = p.timestamp.wrapping_add(1);
            t.sig = sender.sign(&t.signing_bytes().unwrap());

            // The signature is valid again...
            prop_assert!(t.verify().is_ok());
            // ...but the AEAD still refuses: the AAD moved.
            prop_assert!(matches!(t.open(&p.key()), Err(Error::SealedKeyOpen)));
        }

        /// The nonce is a deterministic function of `(topic, sender, seq)` and
        /// nothing else.
        #[test]
        fn nonce_is_deterministic(p in parts()) {
            let (topic, sender) = (p.topic(), p.sender().node_id());
            prop_assert_eq!(
                nonce_for(&topic, &sender, Seq(p.seq)),
                nonce_for(&topic, &sender, Seq(p.seq))
            );
        }

        /// Distinct sequence numbers give distinct nonces — the property the
        /// single-allocator rule turns into nonce-reuse safety.
        #[test]
        fn nonce_differs_per_seq(p in parts(), other in any::<u64>()) {
            prop_assume!(other != p.seq);
            let (topic, sender) = (p.topic(), p.sender().node_id());
            prop_assert_ne!(
                nonce_for(&topic, &sender, Seq(p.seq)),
                nonce_for(&topic, &sender, Seq(other))
            );
        }

        /// Distinct senders and distinct topics also give distinct nonces, so
        /// two publishers sharing a fabric key never collide.
        #[test]
        fn nonce_differs_per_sender_and_topic(p in parts(), other in seed()) {
            prop_assume!(other != p.sender_seed && other != p.fabric_seed);
            let (topic, sender) = (p.topic(), p.sender().node_id());
            let other_id = NodeIdentity::from_seed(other).node_id();
            prop_assert_ne!(
                nonce_for(&topic, &sender, Seq(p.seq)),
                nonce_for(&topic, &other_id, Seq(p.seq))
            );
            prop_assert_ne!(
                nonce_for(&topic, &sender, Seq(p.seq)),
                nonce_for(&TopicId::derive(other_id, "elsewhere"), &sender, Seq(p.seq))
            );
        }

        /// Sealing the same slot twice is byte-identical: the nonce is
        /// deterministic, so a republish produces the same envelope rather
        /// than a fork.
        #[test]
        fn resealing_a_slot_is_byte_identical(p in parts(), msg in payload()) {
            prop_assert_eq!(p.seal(&msg), p.seal(&msg));
        }

        /// An envelope survives the wire round-trip unchanged and still
        /// verifies and opens.
        #[test]
        fn wire_roundtrips(p in parts(), msg in payload()) {
            let env = p.seal(&msg);
            let back = TopicEnvelope::from_wire(&env.to_wire().unwrap()).unwrap();
            prop_assert_eq!(&back, &env);
            prop_assert!(back.verify().is_ok());
            prop_assert_eq!(back.open(&p.key()).unwrap(), msg);
            prop_assert_eq!(back.message_hash().unwrap(), env.message_hash().unwrap());
        }

        /// The wire form is canonical: re-encoding a decoded envelope is
        /// byte-stable, which is what makes `message_hash` reproducible.
        #[test]
        fn wire_form_is_canonical(p in parts(), msg in payload()) {
            let bytes = p.seal(&msg).to_wire().unwrap();
            let reencoded = TopicEnvelope::from_wire(&bytes).unwrap().to_wire().unwrap();
            prop_assert_eq!(reencoded, bytes);
        }

        /// Arbitrary bytes decode to an `Err`, never a panic.
        #[test]
        fn garbage_from_wire_never_panics(b in proptest::collection::vec(any::<u8>(), 0..128)) {
            let _ = TopicEnvelope::from_wire(&b);
        }

        /// Any strict prefix of a valid wire form is also an `Err`, never a
        /// panic (the channel is binary; a short read must not be fatal).
        #[test]
        fn truncated_wire_never_panics(p in parts(), msg in payload()) {
            let bytes = p.seal(&msg).to_wire().unwrap();
            for cut in 0..bytes.len() {
                prop_assert!(TopicEnvelope::from_wire(&bytes[..cut]).is_err());
            }
        }

        /// Distinct messages have distinct link hashes, and the hash is a pure
        /// function of the signing bytes.
        #[test]
        fn message_hash_is_the_signing_bytes_digest(p in parts(), msg in payload()) {
            let env = p.seal(&msg);
            let expected = blake3::hash(&env.signing_bytes().unwrap());
            let actual = env.message_hash().unwrap();
            prop_assert_eq!(actual.as_bytes(), expected.as_bytes());
            prop_assert!(!actual.is_zero());
        }

        /// `MessageHash` hex and serde round-trip.
        #[test]
        fn message_hash_roundtrips(h in seed()) {
            let hash = MessageHash::from_bytes(h);
            prop_assert_eq!(MessageHash::from_hex(&hash.hex()).unwrap(), hash);
            let json = serde_json::to_string(&hash).unwrap();
            prop_assert_eq!(serde_json::from_str::<MessageHash>(&json).unwrap(), hash);
        }
    }

    fn fixture() -> (Parts, TopicEnvelope) {
        let p = Parts {
            sender_seed: [2u8; 32],
            fabric_seed: [1u8; 32],
            name: "ops".to_string(),
            key_bytes: [7u8; 32],
            seq: 3,
            prev: [0x11u8; 32],
            key_version: 5,
            timestamp: 1_700_000_000,
        };
        let env = p.seal(b"ship it");
        (p, env)
    }

    /// The guard, ported from the PoC: the signed body must cover **every**
    /// field of the envelope except `sig`. Adding a field to `TopicEnvelope`
    /// without adding it to `EnvelopeBody` fails here rather than shipping an
    /// unauthenticated field.
    #[test]
    fn signing_bytes_covers_every_non_signature_field() {
        let (_, env) = fixture();
        let full: serde_json::Value = serde_json::from_slice(&env.to_wire().unwrap()).unwrap();
        let signed: serde_json::Value =
            serde_json::from_slice(&env.signing_bytes().unwrap()).unwrap();

        let mut expected = full.as_object().unwrap().clone();
        assert!(expected.remove("sig").is_some(), "sig must be present");
        assert_eq!(signed.as_object().unwrap(), &expected);
    }

    /// The AAD is the signing body with an emptied `ciphertext` — same key set,
    /// one differing value. Pins the "AAD = body minus payload" rule.
    #[test]
    fn aad_is_the_body_with_an_empty_ciphertext() {
        let (_, env) = fixture();
        let empty = Ciphertext::from_bytes(Vec::new());
        let aad: serde_json::Value =
            serde_json::from_slice(&canonical_bytes(&env.body(&empty)).unwrap()).unwrap();
        let signed: serde_json::Value =
            serde_json::from_slice(&env.signing_bytes().unwrap()).unwrap();

        assert_eq!(
            aad.as_object().unwrap().keys().collect::<Vec<_>>(),
            signed.as_object().unwrap().keys().collect::<Vec<_>>()
        );
        assert_eq!(aad["ciphertext"], serde_json::json!(""));
        assert_ne!(signed["ciphertext"], serde_json::json!(""));
    }

    /// Known answer: the signed body canonicalizes to exactly these bytes
    /// (sorted keys, compact, hex byte-blobs). Guards the canonicalization the
    /// signature and the link hash both depend on.
    #[test]
    fn body_canonical_bytes_known_answer() {
        let topic = TopicId::from_bytes([0x22u8; 32]);
        let sender = NodeId::from_bytes([0x11u8; 32]);
        let prev_hash = MessageHash::ZERO;
        let ciphertext = Ciphertext::from_bytes(vec![0xab, 0xcd]);
        let alg = AlgorithmId::Ed25519;
        let body = EnvelopeBody {
            format: ENVELOPE_V1,
            topic: &topic,
            sender: &sender,
            seq: 0,
            prev_hash: &prev_hash,
            key_version: 5,
            timestamp: 1_700_000_000,
            ciphertext: &ciphertext,
            alg: &alg,
        };
        let expected = format!(
            r#"{{"alg":"ed25519","ciphertext":"abcd","format":1,"key_version":5,"prev_hash":"{}","sender":"{}","seq":0,"timestamp":1700000000,"topic":"{}"}}"#,
            "00".repeat(32),
            "11".repeat(32),
            "22".repeat(32),
        );
        assert_eq!(canonical_bytes(&body).unwrap(), expected.into_bytes());
    }

    /// Known answer: the nonce derivation for a fixed slot is frozen — a change
    /// would make every stored message unopenable.
    #[test]
    fn nonce_known_answer() {
        let topic = TopicId::from_bytes([0x22u8; 32]);
        let sender = NodeId::from_bytes([0x11u8; 32]);
        assert_eq!(
            hex::encode(nonce_for(&topic, &sender, Seq(0))),
            "c87a7c727b6b4b03cad0c623"
        );
        assert_eq!(
            hex::encode(nonce_for(&topic, &sender, Seq(1))),
            "0bd074e2fe7049c653056490"
        );
    }

    /// The nonce matches the documented formula computed a second way.
    #[test]
    fn nonce_matches_documented_formula() {
        let topic = TopicId::from_bytes([0x22u8; 32]);
        let sender = NodeId::from_bytes([0x11u8; 32]);
        let mut material = Vec::new();
        material.extend_from_slice(topic.as_bytes());
        material.extend_from_slice(sender.as_bytes());
        material.extend_from_slice(&7u64.to_le_bytes());
        let expected = blake3::hash(&material);
        assert_eq!(
            nonce_for(&topic, &sender, Seq(7)),
            expected.as_bytes()[..NONCE_LEN]
        );
    }

    /// A future format version is rejected outright.
    #[test]
    fn future_format_is_unsupported() {
        let (_, mut env) = fixture();
        env.format = 2;
        assert!(matches!(env.verify(), Err(Error::UnsupportedVersion)));
    }

    /// `Seq` helpers behave: `ZERO` is genesis and `next` increments.
    #[test]
    fn seq_helpers() {
        assert_eq!(Seq::ZERO, Seq(0));
        assert_eq!(Seq::ZERO.next(), Seq(1));
        assert!(Seq(1) > Seq(0));
    }

    /// `MessageHash::ZERO` is the genesis link and nothing else.
    #[test]
    fn zero_hash_is_the_genesis_link() {
        assert!(MessageHash::ZERO.is_zero());
        assert_eq!(MessageHash::ZERO.hex(), "0".repeat(64));
        assert!(!MessageHash::from_bytes([1u8; 32]).is_zero());
        assert!(matches!(
            MessageHash::from_hex("00"),
            Err(Error::BadKeyLength)
        ));
        assert!(matches!(
            MessageHash::from_hex(&"z".repeat(64)),
            Err(Error::BadHex(_))
        ));
    }

    /// `Ciphertext` serializes as a lowercase-hex string.
    #[test]
    fn ciphertext_serializes_as_hex_string() {
        let c = Ciphertext::from_bytes(vec![0xde, 0xad]);
        assert_eq!(serde_json::to_string(&c).unwrap(), "\"dead\"");
        assert_eq!(c.hex(), "dead");
        assert_eq!(c.len(), 2);
        assert_eq!(serde_json::from_str::<Ciphertext>("\"dead\"").unwrap(), c);
    }

    /// A late-arriving key heals display: an envelope stored without the key
    /// (verifiable, unopenable) opens the moment the right key shows up.
    #[test]
    fn late_key_heals_a_stored_envelope() {
        let (p, env) = fixture();
        let stored = TopicEnvelope::from_wire(&env.to_wire().unwrap()).unwrap();
        assert!(stored.verify().is_ok());
        assert!(stored.open(&FabricKey::from_bytes([9u8; 32])).is_err());
        assert_eq!(stored.open(&p.key()).unwrap(), b"ship it");
    }
}

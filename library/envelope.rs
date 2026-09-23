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
//! # Nonce discipline: a synthetic IV, not a slot counter
//!
//! The AEAD nonce is a **synthetic IV**: a keyed hash of the message and
//! everything it claims about itself,
//! `blake3::derive_key(ctx, fabric_key ‖ slot_bytes ‖ plaintext)[..12]`, carried
//! on the wire as the signed [`nonce`](TopicEnvelope::nonce) field and
//! re-derived and *checked* by [`open`](TopicEnvelope::open).
//!
//! It is deterministic — re-sealing an identical message in an identical slot
//! is byte-identical, so an idempotent republish is a
//! [`Duplicate`](crate::LinkStatus::Duplicate) rather than a fork — while a
//! change in *anything*, the payload included, produces a fresh nonce.
//!
//! The obvious alternative, `blake3(topic ‖ sender ‖ seq)`, is what this
//! replaces, and the reason is that it makes any sequence rollback a keystream
//! reuse under a still-current fabric key. Keys rotate only on a root
//! `roster commit`, while the seq allocator is a per-topic database: restore
//! `$WIRES_HOME` from an older backup, lose the topic db, or point a second
//! home at the same `--node-seed`, and the node republishes seq `0..N` with
//! different plaintexts under the same key version. Same key, same nonce, two
//! messages: `C1 ⊕ C2 = P1 ⊕ P2`, crib-draggable for chat text, and the
//! Poly1305 one-time key for that nonce falls out with it. The chain classifier
//! would call the second envelope a `Fork` — but only *after* it had been
//! broadcast to every peer. A late joiner that is not supposed to be able to
//! read pre-join history would hold the pair.
//!
//! With a synthetic IV, reuse requires the same key, the same slot, the same
//! `prev_hash`, `key_version` and `timestamp`, **and** the same plaintext — at
//! which point the two envelopes are the same envelope and reuse is harmless.
//! [`open`](TopicEnvelope::open) re-derives the nonce after decrypting and
//! rejects an envelope whose nonce is not the one its own contents imply, so a
//! buggy or malicious sender cannot hand a reader a reused nonce either.
//!
//! Because the derivation is keyed on the fabric key, the nonce also leaks
//! nothing to an observer who does not hold it.
//!
//! The operational rule still stands: a `(node, topic)` pair has exactly one
//! sequence allocator (the resident `wires tail` process). This is what makes a
//! rollback survivable rather than catastrophic, not a licence to skip it.
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

/// The blake3 `derive_key` context for the synthetic IV. Frozen: changing it
/// makes every stored message unopenable.
pub const ENVELOPE_NONCE_CONTEXT: &str = "wires topic-envelope nonce v1";

/// An envelope's AEAD nonce: a synthetic IV, 12 bytes, lowercase-hex serde.
///
/// A newtype rather than a bare `[u8; 12]` so it cannot be confused with the
/// other byte blobs riding in the envelope, and so it canonicalizes the same
/// way they do.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct MessageNonce([u8; NONCE_LEN]);

impl MessageNonce {
    /// The all-zero nonce — the placeholder used while deriving the real one
    /// (see [`TopicEnvelope::seal`]), never a value a sealer emits except by a
    /// 1-in-2^96 coincidence.
    pub const ZERO: MessageNonce = MessageNonce([0u8; NONCE_LEN]);

    /// Wrap raw nonce bytes.
    pub fn from_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw 12 nonce bytes.
    pub fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }

    /// Lowercase-hex rendering of the nonce.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a nonce from its lowercase-hex rendering.
    ///
    /// Returns [`crate::Error::BadHex`] for non-hex text and
    /// [`crate::Error::BadKeyLength`] when the decoded byte count is not 12.
    pub fn from_hex(s: &str) -> Result<MessageNonce> {
        let bytes = hex::decode(s)?;
        let arr: [u8; NONCE_LEN] = bytes.try_into().map_err(|_| Error::BadKeyLength)?;
        Ok(MessageNonce(arr))
    }
}

impl Serialize for MessageNonce {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for MessageNonce {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; NONCE_LEN] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("MessageNonce expects 12 bytes"))?;
        Ok(MessageNonce(arr))
    }
}

/// Derive the synthetic IV:
/// `blake3::derive_key(ENVELOPE_NONCE_CONTEXT, key ‖ slot ‖ plaintext)[..12]`.
///
/// `slot` is the canonical JSON of the envelope body with an empty ciphertext
/// and a [`MessageNonce::ZERO`] nonce — i.e. everything the envelope claims
/// about itself, minus the two fields that depend on this derivation. Keying it
/// on the fabric key makes the nonce a pseudorandom function of the message
/// rather than a public fingerprint of it.
///
/// The three inputs are absorbed as separate `update` calls over a fixed-width
/// key and a self-delimiting JSON object, so the concatenation is unambiguous.
fn nonce_for(key: &FabricKey, slot: &[u8], plaintext: &[u8]) -> MessageNonce {
    let mut hasher = blake3::Hasher::new_derive_key(ENVELOPE_NONCE_CONTEXT);
    hasher.update(key.as_bytes());
    hasher.update(slot);
    hasher.update(plaintext);
    let mut nonce = [0u8; NONCE_LEN];
    hasher.finalize_xof().fill(&mut nonce);
    MessageNonce(nonce)
}

/// A per-sender message sequence number: 0-based and dense (no holes), so a
/// reader can tell "I am missing something" from "there is nothing more".
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct Seq(pub u64);

impl Seq {
    /// The genesis sequence number.
    pub const ZERO: Seq = Seq(0);

    /// The last sequence number a publisher can ever occupy.
    pub const MAX: Seq = Seq(u64::MAX);

    /// The next sequence number after this one, or `None` at
    /// [`Seq::MAX`] — the publisher's log is full and there is no slot to
    /// allocate.
    ///
    /// Checked, not wrapping, because the value this is applied to comes off
    /// the wire: a replay [`Request`](crate::ReplayFrame::Request) carries a
    /// peer-chosen [`ChainState`](crate::ChainState) per publisher, and "the
    /// slot after what you told me you hold" is the natural read cursor. An
    /// unchecked `+ 1` there is a panic in a debug build and a silent wrap to
    /// genesis — replaying a whole log from scratch — in a release one.
    ///
    /// ```
    /// use library::Seq;
    /// assert_eq!(Seq::ZERO.checked_next(), Some(Seq(1)));
    /// assert_eq!(Seq::MAX.checked_next(), None);
    /// ```
    pub fn checked_next(self) -> Option<Seq> {
        self.0.checked_add(1).map(Seq)
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
/// The same struct serves three purposes, distinguished by what is put in its
/// two derived fields:
///
/// | `ciphertext` | `nonce` | what the bytes are |
/// |---|---|---|
/// | real | real | the signing bytes |
/// | empty | real | the AEAD associated data |
/// | empty | [`MessageNonce::ZERO`] | the *slot* fed to [`nonce_for`] |
///
/// So the encryption is bound to the topic, sender, sequence, link, key
/// version, timestamp and nonce it claims, and the nonce in turn is bound to
/// everything but itself and the payload it protects.
#[derive(Serialize)]
struct EnvelopeBody<'a> {
    format: u8,
    topic: &'a TopicId,
    sender: &'a NodeId,
    seq: u64,
    prev_hash: &'a MessageHash,
    key_version: u64,
    timestamp: i64,
    nonce: &'a MessageNonce,
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
    /// The AEAD nonce: a synthetic IV over the fabric key, this body, and the
    /// plaintext (see the module docs). Signed, and re-derived and checked by
    /// [`open`](Self::open), so it is not a value a peer gets to choose freely.
    pub nonce: MessageNonce,
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
    /// it holds. The nonce is derived from the whole signed body, so calling
    /// this twice with an identical body under the same key re-seals the same
    /// envelope byte-for-byte (harmless), while a republish of the same slot
    /// with anything else changed gets a fresh nonce. The single-allocator rule
    /// in the module docs is still the primary guarantee.
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
        let empty = Ciphertext::from_bytes(Vec::new());
        let body = |nonce: &MessageNonce, ciphertext: &Ciphertext| -> Result<Vec<u8>> {
            canonical_bytes(&EnvelopeBody {
                format: ENVELOPE_V1,
                topic: &topic,
                sender: &sender_id,
                seq: seq.0,
                prev_hash: &prev_hash,
                key_version: key_version.0,
                timestamp,
                nonce,
                ciphertext,
                alg: &alg,
            })
        };

        // The synthetic IV: derived from the slot (this body with no nonce and
        // no ciphertext yet) *and* the plaintext, so no two distinct messages
        // ever share one. See the module docs on nonce discipline.
        let nonce = nonce_for(key, &body(&MessageNonce::ZERO, &empty)?, plaintext);

        // The AAD is the body with an *empty* ciphertext — the same bytes both
        // sides can compute, binding the payload to every other field.
        let aad = body(&nonce, &empty)?;

        let cipher = ChaCha20Poly1305::new(&Key::from(*key.as_bytes()));
        let ciphertext = Ciphertext::from_bytes(
            cipher
                .encrypt(
                    &Nonce::from(*nonce.as_bytes()),
                    Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::SealedKeyOpen)?,
        );

        let sig = sender.sign(&body(&nonce, &ciphertext)?);

        Ok(TopicEnvelope {
            format: ENVELOPE_V1,
            topic,
            sender: sender_id,
            seq,
            prev_hash,
            key_version,
            timestamp,
            nonce,
            ciphertext,
            alg,
            sig,
        })
    }

    /// This envelope's body with `ciphertext` and `nonce` substituted — the
    /// real values for [`signing_bytes`](Self::signing_bytes), an empty
    /// ciphertext for the AEAD associated data, and a zero nonce on top of that
    /// for the slot bytes [`nonce_for`] hashes.
    fn body<'a>(&'a self, nonce: &'a MessageNonce, ciphertext: &'a Ciphertext) -> EnvelopeBody<'a> {
        EnvelopeBody {
            format: self.format,
            topic: &self.topic,
            sender: &self.sender,
            seq: self.seq.0,
            prev_hash: &self.prev_hash,
            key_version: self.key_version.0,
            timestamp: self.timestamp,
            nonce,
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
    ///
    /// After a successful decryption the synthetic IV is **re-derived from the
    /// recovered plaintext and compared**. An envelope whose `nonce` is not the
    /// one its own contents imply is rejected, also as
    /// [`crate::Error::SealedKeyOpen`]: that is what stops a sender — buggy,
    /// rolled back, or hostile — from handing readers two different messages
    /// under one (key, nonce) pair.
    pub fn open(&self, key: &FabricKey) -> Result<Vec<u8>> {
        let empty = Ciphertext::from_bytes(Vec::new());
        let aad = canonical_bytes(&self.body(&self.nonce, &empty))?;
        let cipher = ChaCha20Poly1305::new(&Key::from(*key.as_bytes()));
        let plaintext = cipher
            .decrypt(
                &Nonce::from(*self.nonce.as_bytes()),
                Payload {
                    msg: self.ciphertext.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| Error::SealedKeyOpen)?;

        let slot = canonical_bytes(&self.body(&MessageNonce::ZERO, &empty))?;
        if nonce_for(key, &slot, &plaintext) != self.nonce {
            return Err(Error::SealedKeyOpen);
        }
        Ok(plaintext)
    }

    /// The exact canonical bytes covered by [`sig`](Self::sig) — every field
    /// except the signature itself.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(&self.body(&self.nonce, &self.ciphertext))
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

    /// Two payloads that always differ, each at least 16 bytes long.
    ///
    /// The keystream test compares ciphertext XOR against plaintext XOR over
    /// the shared prefix; with a 1-byte prefix two independent keystreams
    /// agree by chance 1 time in 256. Sixteen bytes makes that 2^-128. `b` is
    /// `a` with one byte flipped at `at` and a random tail, so the pair never
    /// needs `prop_assume!` to be distinct.
    fn distinct_payloads() -> impl Strategy<Value = (Vec<u8>, Vec<u8>)> {
        (
            proptest::collection::vec(any::<u8>(), 16..256),
            any::<proptest::sample::Index>(),
            1u8..=255,
            proptest::collection::vec(any::<u8>(), 0..64),
        )
            .prop_map(|(a, at, flip, tail)| {
                let mut b = a.clone();
                let i = at.index(b.len());
                b[i] ^= flip;
                b.extend(tail);
                (a, b)
            })
    }

    /// The synthetic IV an envelope *should* carry, recomputed from the outside
    /// the way [`TopicEnvelope::open`] does.
    fn expected_nonce(env: &TopicEnvelope, key: &FabricKey, plaintext: &[u8]) -> MessageNonce {
        let empty = Ciphertext::from_bytes(Vec::new());
        let slot = canonical_bytes(&env.body(&MessageNonce::ZERO, &empty)).unwrap();
        nonce_for(key, &slot, plaintext)
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

            // nonce — signed, and inside the AAD, so both gates catch it.
            let mut t = base.clone();
            let mut nonce = *t.nonce.as_bytes();
            nonce[0] ^= 0x01;
            t.nonce = MessageNonce::from_bytes(nonce);
            prop_assert!(matches!(t.verify(), Err(Error::InvalidSignature)));
            prop_assert!(matches!(t.open(&key), Err(Error::SealedKeyOpen)));

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

        /// The synthetic IV an envelope carries is exactly the one its own
        /// contents imply, and it is reproducible: re-sealing the same message
        /// in the same slot under the same key derives the same nonce.
        #[test]
        fn nonce_is_the_synthetic_iv_of_its_own_contents(p in parts(), msg in payload()) {
            let env = p.seal(&msg);
            prop_assert_eq!(env.nonce, expected_nonce(&env, &p.key(), &msg));
            prop_assert_eq!(env.nonce, p.seal(&msg).nonce);
        }

        /// Distinct sequence numbers give distinct nonces — the property the
        /// single-allocator rule turns into nonce-reuse safety.
        #[test]
        fn nonce_differs_per_seq(p in parts(), msg in payload(), other in any::<u64>()) {
            prop_assume!(other != p.seq);
            let mut q = p.clone();
            q.seq = other;
            prop_assert_ne!(p.seal(&msg).nonce, q.seal(&msg).nonce);
        }

        /// Distinct senders and distinct topics also give distinct nonces, so
        /// two publishers sharing a fabric key never collide.
        #[test]
        fn nonce_differs_per_sender_and_topic(p in parts(), msg in payload(), other in seed()) {
            prop_assume!(other != p.sender_seed && other != p.fabric_seed);
            let base = p.seal(&msg).nonce;

            let mut q = p.clone();
            q.sender_seed = other;
            prop_assert_ne!(base, q.seal(&msg).nonce);

            let mut q = p.clone();
            q.fabric_seed = other;
            prop_assert_ne!(base, q.seal(&msg).nonce);
        }

        /// Distinct *keys* give distinct nonces: the synthetic IV is keyed, so
        /// it is a pseudorandom function of the message rather than a public
        /// fingerprint an observer could match against a guessed plaintext.
        #[test]
        fn nonce_differs_per_key(p in parts(), msg in payload(), other in seed()) {
            prop_assume!(other != p.key_bytes);
            let mut q = p.clone();
            q.key_bytes = other;
            prop_assert_ne!(p.seal(&msg).nonce, q.seal(&msg).nonce);
        }

        /// **The rollback property.** Two different messages in the *same slot*
        /// under the *same key* — what a node restored from an old backup
        /// republishes — never share a nonce, so they never share a keystream.
        ///
        /// This is the whole reason the nonce is a synthetic IV rather than
        /// `blake3(topic ‖ sender ‖ seq)`: under that derivation these two
        /// ciphertexts would XOR to the XOR of their plaintexts, handing anyone
        /// who holds both (a late joiner replaying history, say) the plaintext
        /// of messages it was never given a key for.
        #[test]
        fn republishing_a_slot_with_different_content_never_reuses_the_keystream(
            p in parts(),
            (a, b) in distinct_payloads(),
        ) {
            prop_assert_ne!(&a, &b);
            // Byte-for-byte the same slot: same topic, sender, seq, prev_hash,
            // key_version, key — and the same timestamp, so not even the clock
            // is doing the work here.
            let before = p.seal(&a);
            let after = p.seal(&b);

            prop_assert_eq!(before.seq, after.seq);
            prop_assert_eq!(before.sender, after.sender);
            prop_assert_eq!(before.topic, after.topic);
            prop_assert_eq!(before.timestamp, after.timestamp);
            prop_assert_ne!(before.nonce, after.nonce);

            // The concrete consequence: no two-time pad. Under a shared
            // keystream the ciphertexts' XOR would equal the plaintexts' XOR
            // over the overlapping prefix.
            let n = a.len().min(b.len());
            if n > 0 {
                let ct_xor: Vec<u8> = before.ciphertext.as_bytes()[..n]
                    .iter()
                    .zip(&after.ciphertext.as_bytes()[..n])
                    .map(|(x, y)| x ^ y)
                    .collect();
                let pt_xor: Vec<u8> = a[..n].iter().zip(&b[..n]).map(|(x, y)| x ^ y).collect();
                prop_assert_ne!(ct_xor, pt_xor);
            }
        }

        /// A hand-picked nonce is not accepted: `open` re-derives the synthetic
        /// IV from the recovered plaintext, so a sender cannot serve two
        /// messages under one (key, nonce) pair even by re-signing.
        #[test]
        fn a_substituted_nonce_is_refused_by_open(p in parts(), msg in payload(), fake in proptest::array::uniform12(any::<u8>())) {
            let base = p.seal(&msg);
            prop_assume!(fake != *base.nonce.as_bytes());

            let mut t = base.clone();
            t.nonce = MessageNonce::from_bytes(fake);
            // Re-signed, so the signature is genuine again...
            t.sig = p.sender().sign(&t.signing_bytes().unwrap());
            prop_assert!(t.verify().is_ok());
            // ...and the AEAD refuses it, because the nonce is in the AAD.
            prop_assert!(matches!(t.open(&p.key()), Err(Error::SealedKeyOpen)));
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

    /// The frozen synthetic IV of [`fixture`]'s envelope.
    const NONCE_KNOWN_ANSWER: &str = "ab26c73b6e96e3a875c9b4ee";

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
    /// one differing value. Pins the "AAD = body minus payload" rule, and that
    /// the nonce rides *inside* the AAD (which is what makes a substituted
    /// nonce fail the tag).
    #[test]
    fn aad_is_the_body_with_an_empty_ciphertext() {
        let (_, env) = fixture();
        let empty = Ciphertext::from_bytes(Vec::new());
        let aad: serde_json::Value =
            serde_json::from_slice(&canonical_bytes(&env.body(&env.nonce, &empty)).unwrap())
                .unwrap();
        let signed: serde_json::Value =
            serde_json::from_slice(&env.signing_bytes().unwrap()).unwrap();

        assert_eq!(
            aad.as_object().unwrap().keys().collect::<Vec<_>>(),
            signed.as_object().unwrap().keys().collect::<Vec<_>>()
        );
        assert_eq!(aad["ciphertext"], serde_json::json!(""));
        assert_ne!(signed["ciphertext"], serde_json::json!(""));
        assert_eq!(aad["nonce"], serde_json::json!(env.nonce.hex()));

        // And the slot bytes are the AAD with the nonce zeroed — the only
        // difference, so the nonce derivation cannot depend on itself.
        let slot: serde_json::Value = serde_json::from_slice(
            &canonical_bytes(&env.body(&MessageNonce::ZERO, &empty)).unwrap(),
        )
        .unwrap();
        assert_eq!(slot["nonce"], serde_json::json!("0".repeat(24)));
        let mut expected = aad.as_object().unwrap().clone();
        expected["nonce"] = serde_json::json!("0".repeat(24));
        assert_eq!(slot.as_object().unwrap(), &expected);
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
        let nonce = MessageNonce::from_bytes([0xee; NONCE_LEN]);
        let body = EnvelopeBody {
            format: ENVELOPE_V1,
            topic: &topic,
            sender: &sender,
            seq: 0,
            prev_hash: &prev_hash,
            key_version: 5,
            timestamp: 1_700_000_000,
            nonce: &nonce,
            ciphertext: &ciphertext,
            alg: &alg,
        };
        let expected = format!(
            r#"{{"alg":"ed25519","ciphertext":"abcd","format":1,"key_version":5,"nonce":"{}","prev_hash":"{}","sender":"{}","seq":0,"timestamp":1700000000,"topic":"{}"}}"#,
            "ee".repeat(12),
            "00".repeat(32),
            "11".repeat(32),
            "22".repeat(32),
        );
        assert_eq!(canonical_bytes(&body).unwrap(), expected.into_bytes());
    }

    /// Known answer: the synthetic-IV derivation is frozen — a change would make
    /// every stored message unopenable.
    #[test]
    fn nonce_known_answer() {
        let (_, env) = fixture();
        assert_eq!(
            env.nonce.hex(),
            NONCE_KNOWN_ANSWER,
            "the nonce derivation is frozen; changing it orphans stored history"
        );
        assert_eq!(ENVELOPE_NONCE_CONTEXT, "wires topic-envelope nonce v1");
    }

    /// The nonce matches the documented formula computed a second way: the
    /// first 12 bytes of `derive_key(context, key ‖ slot ‖ plaintext)`, where
    /// the slot is the signed body with an empty ciphertext and a zero nonce.
    #[test]
    fn nonce_matches_documented_formula() {
        let (p, env) = fixture();
        let empty = Ciphertext::from_bytes(Vec::new());
        let slot = canonical_bytes(&env.body(&MessageNonce::ZERO, &empty)).unwrap();

        let mut hasher = blake3::Hasher::new_derive_key(ENVELOPE_NONCE_CONTEXT);
        hasher.update(p.key().as_bytes());
        hasher.update(&slot);
        hasher.update(b"ship it");
        let mut expected = [0u8; NONCE_LEN];
        hasher.finalize_xof().fill(&mut expected);

        assert_eq!(env.nonce, MessageNonce::from_bytes(expected));
        assert_eq!(env.nonce, expected_nonce(&env, &p.key(), b"ship it"));
    }

    /// The payload is part of the derivation, so two different messages in one
    /// slot get different nonces even when every signed field but the payload
    /// matches — the case a body-only derivation would miss. Written as a
    /// known-answer pair so a regression to `blake3(topic ‖ sender ‖ seq)` (or
    /// to any slot-only formula) fails here loudly.
    #[test]
    fn the_payload_is_part_of_the_nonce() {
        let (p, env) = fixture();
        // Same length, so even the ciphertext length is identical.
        let other = p.seal(b"other!!");
        assert_eq!(env.ciphertext.len(), other.ciphertext.len());
        assert_eq!(env.seq, other.seq);
        assert_eq!(env.timestamp, other.timestamp);
        assert_ne!(env.nonce, other.nonce);
        assert_eq!(env.nonce.hex(), NONCE_KNOWN_ANSWER);
    }

    /// `MessageNonce` hex round-trips and rejects the wrong width.
    #[test]
    fn message_nonce_hex_roundtrips() {
        let nonce = MessageNonce::from_bytes([0xab; NONCE_LEN]);
        assert_eq!(nonce.hex(), "ab".repeat(12));
        assert_eq!(MessageNonce::from_hex(&nonce.hex()).unwrap(), nonce);
        assert_eq!(
            serde_json::to_string(&nonce).unwrap(),
            format!("\"{}\"", "ab".repeat(12))
        );
        assert_eq!(
            serde_json::from_str::<MessageNonce>(&format!("\"{}\"", nonce.hex())).unwrap(),
            nonce
        );
        assert!(matches!(
            MessageNonce::from_hex("00"),
            Err(Error::BadKeyLength)
        ));
        assert!(matches!(
            MessageNonce::from_hex(&"z".repeat(24)),
            Err(Error::BadHex(_))
        ));
        assert_eq!(MessageNonce::ZERO.hex(), "0".repeat(24));
    }

    /// A future format version is rejected outright.
    #[test]
    fn future_format_is_unsupported() {
        let (_, mut env) = fixture();
        env.format = 2;
        assert!(matches!(env.verify(), Err(Error::UnsupportedVersion)));
    }

    /// `Seq` helpers behave: `ZERO` is genesis, `checked_next` increments — and
    /// stops at the ceiling instead of overflowing.
    ///
    /// The ceiling is not hypothetical: a replay `Request` carries a peer-chosen
    /// `ChainState` per publisher, so `u64::MAX` is a value an admitted peer can
    /// simply assert. An unchecked `+ 1` would panic the connection task in a
    /// debug build and wrap to genesis — re-streaming an entire log — in a
    /// release one.
    #[test]
    fn seq_helpers() {
        assert_eq!(Seq::ZERO, Seq(0));
        assert_eq!(Seq::ZERO.checked_next(), Some(Seq(1)));
        assert!(Seq(1) > Seq(0));

        assert_eq!(Seq::MAX, Seq(u64::MAX));
        assert_eq!(Seq(u64::MAX - 1).checked_next(), Some(Seq::MAX));
        assert_eq!(Seq::MAX.checked_next(), None);
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

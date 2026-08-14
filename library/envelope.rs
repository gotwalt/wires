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

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::Result;
use crate::fabric_key::FabricKey;
use crate::grant::AlgorithmId;
use crate::identity::{NodeId, NodeIdentity, Signature};
use crate::roster::RosterVersion;
use crate::topic::TopicId;

/// The current (and only) topic-envelope format version.
pub const ENVELOPE_V1: u8 = 1;

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
        todo!("derive nonce, AEAD-seal the plaintext, sign the canonical body")
    }

    /// Verify structure and signature only: supported algorithm, known
    /// `format`, and a `sender` signature over the canonical body.
    ///
    /// Deliberately does **not** decrypt and does **not** consult the chain —
    /// an envelope is verifiable, and therefore storable, before its key or its
    /// predecessors arrive.
    pub fn verify(&self) -> Result<()> {
        todo!("check alg/format, then verify sig over signing_bytes under sender")
    }

    /// Decrypt the payload with `key`.
    ///
    /// The caller must select the key matching `key_version`
    /// ([`crate::Error::KeyVersionUnknown`] when it holds none) — passing the
    /// wrong key fails the AEAD tag.
    pub fn open(&self, key: &FabricKey) -> Result<Vec<u8>> {
        todo!("derive nonce and AEAD-open the ciphertext with the body as AAD")
    }

    /// The exact canonical bytes covered by [`sig`](Self::sig) — every field
    /// except the signature itself.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        todo!("canonical_bytes of the envelope body")
    }

    /// This message's link hash: `blake3(signing_bytes())`. The value a
    /// successor carries as its `prev_hash`.
    pub fn message_hash(&self) -> Result<MessageHash> {
        todo!("blake3 over signing_bytes")
    }

    /// The wire form: canonical JSON bytes. Gossip and replay are binary
    /// channels, so there is no base64 layer here (unlike the human-pasted
    /// tickets and credentials).
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        todo!("canonical_bytes of the whole envelope")
    }

    /// Parse an envelope from its wire bytes. Does not verify — the caller runs
    /// [`verify`](Self::verify) before trusting anything in it.
    pub fn from_wire(bytes: &[u8]) -> Result<TopicEnvelope> {
        todo!("JSON parse the canonical bytes")
    }
}

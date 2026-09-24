//! Node identity: the Ed25519 keypair that *is* a node's address, plus the
//! `NodeId` and `Signature` byte-newtypes.
//!
//! Per the project convention no public API exposes a bare `[u8; N]`; `NodeId`
//! and `Signature` are newtypes. They serialize as lowercase-hex **strings** so
//! the canonical-JSON encoding stays compact and readable (and to sidestep
//! serde's lack of a built-in impl for arrays longer than 32).

use ed25519_dalek::{Signer, SigningKey, Verifier};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// An Ed25519 public key — a node's address on the network (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct NodeId([u8; 32]);

/// A detached Ed25519 signature (64 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature([u8; 64]);

/// Signature scheme a signed object (membership, signed policy, call-log
/// entry) was signed with. Only [`Ed25519`](Self::Ed25519) is implemented
/// today; the tag travels on the wire so a verifier can reject an object
/// signed with a scheme it does not support, and so other schemes can be
/// added later without a format change.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlgorithmId {
    /// Ed25519 — the zero-config default root scheme.
    Ed25519,
}

impl NodeId {
    /// Borrow the raw 32 public-key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Construct a `NodeId` from raw public-key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Lowercase-hex rendering of the public key.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The first 8 hex characters: how a node is named in a message or a
    /// list, where the full 64 would drown the line.
    ///
    /// ```
    /// let id = library::NodeIdentity::from_seed([5u8; 32]).node_id();
    /// assert_eq!(id.short(), id.hex()[..8]);
    /// ```
    pub fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }

    /// Parse a `NodeId` from its lowercase-hex rendering (the inverse of
    /// [`hex`](Self::hex)). Used to accept node ids as CLI input.
    ///
    /// Returns [`Error::BadHex`] for non-hex text and [`Error::BadLength`]
    /// when the decoded byte count is not 32.
    ///
    /// ```
    /// use library::{NodeId, NodeIdentity};
    /// let id = NodeIdentity::from_seed([5u8; 32]).node_id();
    /// assert_eq!(NodeId::from_hex(&id.hex()).unwrap(), id);
    /// ```
    pub fn from_hex(s: &str) -> Result<NodeId> {
        let bytes = hex::decode(s)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::BadLength)?;
        Ok(NodeId(arr))
    }

    /// Verify that `signature` over `message` was produced by the key this
    /// `NodeId` names.
    ///
    /// Returns [`Error::InvalidSignature`] on any mismatch or malformed key.
    ///
    /// ```
    /// use library::NodeIdentity;
    /// let id = NodeIdentity::from_seed([1u8; 32]);
    /// let sig = id.sign(b"hello");
    /// assert!(id.node_id().verify(b"hello", &sig).is_ok());
    /// assert!(id.node_id().verify(b"tampered", &sig).is_err());
    /// ```
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(&self.0)
            .map_err(|_| Error::InvalidSignature)?;
        let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
        key.verify(message, &sig)
            .map_err(|_| Error::InvalidSignature)
    }
}

impl Signature {
    /// Borrow the raw 64 signature bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Lowercase-hex rendering of the signature.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// A node's signing identity: the Ed25519 secret key plus its derived address.
///
/// Both fabric-root keys and node keys are `NodeIdentity` values — the role is
/// a matter of how the key is used (signing memberships vs. authenticating a
/// session), not of the type.
///
/// **The secret stays inside.** The key is a private field; it is scrubbed
/// from memory when the identity drops (ed25519-dalek's `ZeroizeOnDrop`); and
/// the type has no `Clone`, `Debug`, `Display` or `Serialize`, so no code
/// copies, logs or encodes it by accident. A second owner is an explicit
/// [`duplicate`](Self::duplicate), and the raw seed comes out only through the
/// `expose_*` methods, as a [`Zeroizing`] copy that is scrubbed when dropped.
/// That holds against safe Rust in this process. It does not hold against
/// `unsafe` code, a foreign-language runtime in the same process, a debugger
/// running as the same user, or a core dump: whatever runs in-process can
/// read the key.
///
/// No `Clone`:
///
/// ```compile_fail,E0599
/// let id = library::NodeIdentity::generate();
/// let _copy = id.clone();
/// ```
///
/// No `Debug` (so no `{:?}` in a log line or a panic message):
///
/// ```compile_fail,E0277
/// let id = library::NodeIdentity::generate();
/// let _text = format!("{id:?}");
/// ```
///
/// No `Serialize`:
///
/// ```compile_fail,E0277
/// let id = library::NodeIdentity::generate();
/// let _json = serde_json::to_string(&id);
/// ```
pub struct NodeIdentity {
    signing_key: SigningKey,
}

impl NodeIdentity {
    /// Generate a fresh random identity from OS entropy.
    ///
    /// ```
    /// let id = library::NodeIdentity::generate();
    /// assert_eq!(id.node_id().hex().len(), 64);
    /// ```
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *seed);
        Self::from_secret(&seed)
    }

    /// Reconstruct an identity from its 32-byte Ed25519 seed.
    ///
    /// For fixed seeds (tests, doc examples): the caller's `seed` is a plain
    /// array that nothing scrubs. A real key comes from
    /// [`generate`](Self::generate) or [`from_seed_hex`](Self::from_seed_hex).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self::from_secret(&seed)
    }

    /// The identity for `seed`, which the caller scrubs.
    fn from_secret(seed: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }

    /// Reconstruct an identity from the lowercase-hex of its 32-byte seed (the
    /// inverse of [`expose_seed_hex`](Self::expose_seed_hex)). Used to read
    /// `node.seed` / `root.seed` and to accept key seeds as CLI input. The
    /// decoded seed is scrubbed; the text `s` is the caller's to scrub.
    ///
    /// Returns [`Error::BadHex`] for non-hex text and [`Error::BadLength`]
    /// when the decoded byte count is not 32.
    ///
    /// ```
    /// use library::NodeIdentity;
    /// let id = NodeIdentity::from_seed_hex(&"01".repeat(32)).unwrap();
    /// assert_eq!(*id.expose_seed(), [1u8; 32]);
    /// ```
    pub fn from_seed_hex(s: &str) -> Result<NodeIdentity> {
        if s.len() != 64 {
            // Bad hex is reported before bad length, as a full decode would.
            let _decoded = Zeroizing::new(hex::decode(s)?);
            return Err(Error::BadLength);
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(s, &mut *seed)?;
        Ok(Self::from_secret(&seed))
    }

    /// A second owner of this key, for a task that must hold its own (the
    /// call log's signer beside the endpoint's). Each copy is scrubbed when
    /// it drops. Named rather than `Clone` so every copy is deliberate and
    /// easy to find.
    ///
    /// ```
    /// let id = library::NodeIdentity::generate();
    /// assert_eq!(id.duplicate().node_id(), id.node_id());
    /// ```
    pub fn duplicate(&self) -> NodeIdentity {
        Self {
            signing_key: self.signing_key.clone(),
        }
    }

    /// The 32-byte Ed25519 seed, for persisting the key or handing it to the
    /// transport (iroh's `SecretKey`, which scrubs its own copy). The copy
    /// is scrubbed when dropped; don't move the array out of it.
    /// Round-trips with [`from_seed`](Self::from_seed).
    pub fn expose_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing_key.to_bytes())
    }

    /// Lowercase-hex of the 32-byte seed (the inverse of
    /// [`from_seed_hex`](Self::from_seed_hex)), for writing `node.seed` /
    /// `root.seed`. Scrubbed when dropped.
    ///
    /// ```
    /// use library::NodeIdentity;
    /// let id = NodeIdentity::from_seed([1u8; 32]);
    /// let back = NodeIdentity::from_seed_hex(&id.expose_seed_hex()).unwrap();
    /// assert_eq!(back.node_id(), id.node_id());
    /// ```
    pub fn expose_seed_hex(&self) -> Zeroizing<String> {
        let mut text = Zeroizing::new(String::with_capacity(64));
        for byte in self.expose_seed().iter() {
            // Two hex digits per byte, written into the scrubbed buffer (no
            // intermediate `String`).
            const DIGITS: &[u8; 16] = b"0123456789abcdef";
            text.push(DIGITS[usize::from(byte >> 4)] as char);
            text.push(DIGITS[usize::from(byte & 0xf)] as char);
        }
        text
    }

    /// This identity's public `NodeId` (its address).
    pub fn node_id(&self) -> NodeId {
        NodeId(self.signing_key.verifying_key().to_bytes())
    }

    /// Sign an arbitrary message with this identity's secret key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.signing_key.sign(message).to_bytes())
    }
}

impl Serialize for NodeId {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("NodeId expects 32 bytes"))?;
        Ok(NodeId(arr))
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("Signature expects 64 bytes"))?;
        Ok(Signature(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn seed() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }
    fn message() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..256)
    }

    proptest! {
        /// A seed round-trips through an identity unchanged.
        #[test]
        fn seed_roundtrips(s in seed()) {
            prop_assert_eq!(*NodeIdentity::from_seed(s).expose_seed(), s);
        }

        /// A signature by an identity verifies under that identity's node id.
        #[test]
        fn sign_then_verify_ok(s in seed(), m in message()) {
            let id = NodeIdentity::from_seed(s);
            let sig = id.sign(&m);
            prop_assert!(id.node_id().verify(&m, &sig).is_ok());
        }

        /// A signature does not verify under a different key.
        #[test]
        fn wrong_key_fails(a in seed(), b in seed(), m in message()) {
            prop_assume!(a != b);
            let sig = NodeIdentity::from_seed(a).sign(&m);
            prop_assert!(NodeIdentity::from_seed(b).node_id().verify(&m, &sig).is_err());
        }

        /// `NodeId` survives a serde (hex-string) round-trip.
        #[test]
        fn node_id_serde_roundtrips(s in seed()) {
            let id = NodeIdentity::from_seed(s).node_id();
            let json = serde_json::to_string(&id).unwrap();
            let back: NodeId = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(id, back);
        }

        /// `NodeId::from_hex` inverts `NodeId::hex`.
        #[test]
        fn node_id_from_hex_roundtrips(s in seed()) {
            let id = NodeIdentity::from_seed(s).node_id();
            prop_assert_eq!(NodeId::from_hex(&id.hex()).unwrap(), id);
        }

        /// `expose_seed_hex` is exactly `hex::encode` of the seed.
        #[test]
        fn expose_seed_hex_is_lowercase_hex(s in seed()) {
            let id = NodeIdentity::from_seed(s);
            let text = id.expose_seed_hex();
            prop_assert_eq!(text.as_str(), hex::encode(s));
        }

        /// A duplicate is the same key: same address, same signatures.
        #[test]
        fn duplicate_is_the_same_key(s in seed(), m in message()) {
            let id = NodeIdentity::from_seed(s);
            let dup = id.duplicate();
            prop_assert_eq!(dup.node_id(), id.node_id());
            prop_assert_eq!(dup.sign(&m), id.sign(&m));
        }
    }

    #[test]
    fn from_seed_hex_rejects_bad_hex_before_bad_length() {
        assert!(matches!(
            NodeIdentity::from_seed_hex("zz"),
            Err(Error::BadHex(_))
        ));
        assert!(matches!(
            NodeIdentity::from_seed_hex(&"z".repeat(64)),
            Err(Error::BadHex(_))
        ));
        assert!(matches!(
            NodeIdentity::from_seed_hex("00"),
            Err(Error::BadLength)
        ));
        assert!(matches!(
            NodeIdentity::from_seed_hex(&"0".repeat(66)),
            Err(Error::BadLength)
        ));
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        assert!(matches!(NodeId::from_hex("00"), Err(Error::BadLength)));
    }

    #[test]
    fn from_hex_rejects_non_hex() {
        assert!(matches!(
            NodeId::from_hex(&"z".repeat(64)),
            Err(Error::BadHex(_))
        ));
    }

    #[test]
    fn node_id_serializes_as_hex_string() {
        let id = NodeId::from_bytes([0u8; 32]);
        assert_eq!(
            serde_json::to_string(&id).unwrap(),
            format!("\"{}\"", "0".repeat(64))
        );
    }
}

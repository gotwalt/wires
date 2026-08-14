//! The fabric data key: one symmetric key per roster commit, sealed to each
//! member.
//!
//! Topic traffic is end-to-end encrypted under a [`FabricKey`] that the fabric
//! root mints fresh on every `roster commit` and seals individually to each
//! member of the new roster. That single move is what makes removal mean
//! something: the commit that drops a member also rotates the key, and the new
//! key is sealed only to the survivors, so the removed member's confidentiality
//! loss is immediate and does not wait for any mesh to notice.
//!
//! A [`SealedFabricKey`] is root-signed and member-bound. Like
//! [`Membership`](crate::Membership) its signed body is a *fixed, total* field
//! set — no optional-but-signed fields, ever, since an absent field and a
//! present default produce different signed bytes (the JSON-signing downgrade
//! hole).
//!
//! # Sealing mechanics
//!
//! The recipient's Ed25519 key is converted to X25519 by
//! `VerifyingKey::to_montgomery()` (public side) and `to_scalar_bytes()`
//! (secret side), so a node needs no second keypair. The sealer generates a
//! fresh ephemeral X25519 secret, does a Diffie–Hellman against the recipient's
//! converted public key, and derives the AEAD key with
//! `blake3::derive_key("wires sealed-fabric-key v1", dh_shared)`. The nonce is
//! all-zero — sound because the AEAD key is unique per seal (fresh ephemeral) —
//! and the AAD is the canonical JSON of the sealing context, binding the
//! ciphertext to `(format, fabric, version, member, alg)`. The `sealed` blob is
//! `ephemeral_pub(32) ‖ ct+tag`.
//!
//! # Forward secrecy, honestly
//!
//! Rotation happens at commit and nowhere else. There is no ratchet. Whoever
//! compromises a member's long-term seed can open every sealed key ever
//! addressed to it, and therefore read all history that member could read.
//! Ratcheting is deferred, not solved.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::Result;
use crate::grant::AlgorithmId;
use crate::identity::{NodeId, NodeIdentity, Signature};
use crate::roster::RosterVersion;

/// The current (and only) sealed-fabric-key format version.
pub const SEALED_KEY_V1: u8 = 1;

/// The blake3 `derive_key` context for the per-seal AEAD key. Frozen: changing
/// it makes every previously sealed key unopenable.
pub const SEALED_KEY_CONTEXT: &str = "wires sealed-fabric-key v1";

/// The symmetric data key for one roster version.
///
/// Deliberately **not** `Serialize`/`Deserialize`: the plaintext key must leave
/// the process only through [`SealedFabricKey`] or the 0600 keystore file (via
/// [`hex`](Self::hex)), never by falling into some struct that happens to get
/// logged as JSON.
#[derive(Clone, PartialEq, Eq)]
pub struct FabricKey([u8; 32]);

impl FabricKey {
    /// Generate a fresh key from OS entropy.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self(key)
    }

    /// Wrap raw key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw 32 key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase-hex rendering — the keystore file format, nothing else.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a key from the lowercase hex written by [`hex`](Self::hex).
    ///
    /// Returns [`crate::Error::BadHex`] for non-hex text and
    /// [`crate::Error::BadKeyLength`] when the decoded byte count is not 32.
    pub fn from_hex(s: &str) -> Result<FabricKey> {
        let bytes = hex::decode(s)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| crate::error::Error::BadKeyLength)?;
        Ok(FabricKey(arr))
    }
}

/// Redacting `Debug`: a data key must never land in a log line by accident.
impl std::fmt::Debug for FabricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FabricKey(<redacted>)")
    }
}

/// The opaque sealed blob inside a [`SealedFabricKey`]:
/// `ephemeral_pub(32) ‖ ChaCha20-Poly1305 ciphertext+tag`.
///
/// A newtype (never a bare `Vec<u8>`) with lowercase-hex serde, so it rides in
/// canonical JSON deterministically.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SealedBox(Vec<u8>);

impl SealedBox {
    /// Wrap owned sealed bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the sealed bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The sealed blob's length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the sealed blob is empty (only ever true for a malformed value).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Lowercase-hex rendering of the sealed bytes.
    pub fn hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl Serialize for SealedBox {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for SealedBox {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(SealedBox(
            hex::decode(&s).map_err(serde::de::Error::custom)?,
        ))
    }
}

/// The AEAD associated data for one seal: everything that binds the ciphertext
/// to a `(fabric, version, member)` slot. Serialized to canonical JSON.
///
/// Kept separate from [`SealedKeyBody`] because the AAD must be computable
/// *before* `sealed` exists.
#[derive(Serialize)]
struct SealedKeyContext<'a> {
    format: u8,
    fabric: &'a NodeId,
    version: u64,
    member: &'a NodeId,
    alg: &'a AlgorithmId,
}

/// The signed portion of a v1 sealed key: every field except `sig`. Fixed and
/// total — see the module docs on optional-but-signed fields.
#[derive(Serialize)]
struct SealedKeyBody<'a> {
    format: u8,
    fabric: &'a NodeId,
    version: u64,
    member: &'a NodeId,
    sealed: &'a SealedBox,
    alg: &'a AlgorithmId,
}

/// A root-signed, member-sealed [`FabricKey`] for one roster version.
///
/// The signature proves the root minted this key for this `(version, member)`
/// slot; the seal means only `member` can open it. Both halves matter: the
/// signature stops a peer from injecting a key of its own choosing, the seal
/// stops everyone else from reading the data.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SealedFabricKey {
    /// Format discriminant; `= SEALED_KEY_V1`. A *signed* field.
    pub format: u8,
    /// The fabric root's public key — the authority. A *signed* field, pinned
    /// by [`open`](Self::open) against the recipient's trusted root.
    pub fabric: NodeId,
    /// The roster version this key belongs to (matches the commit that minted
    /// it, and the `key_version` on every envelope encrypted under it).
    pub version: RosterVersion,
    /// The member this copy is sealed to (non-transferable).
    pub member: NodeId,
    /// The sealed key material.
    pub sealed: SealedBox,
    /// Which scheme `sig` was produced with.
    pub alg: AlgorithmId,
    /// Fabric-root signature over the canonical-JSON sealed-key body.
    pub sig: Signature,
}

impl SealedFabricKey {
    /// Seal `key` to `member` for roster `version` and sign the result as
    /// `root`.
    ///
    /// The `fabric` field is `root.node_id()` — the credential names its own
    /// authority, exactly as [`Membership`](crate::Membership) does.
    pub fn seal(
        root: &NodeIdentity,
        member: NodeId,
        version: RosterVersion,
        key: &FabricKey,
    ) -> Result<SealedFabricKey> {
        todo!("X25519 seal to member, then sign the canonical body as root")
    }

    /// Open this sealed key as `recipient`, checking it came from
    /// `fabric_root`.
    ///
    /// Verifies the algorithm, the `format` discriminant, the
    /// `fabric == fabric_root` pin, the root signature, and that
    /// `member == recipient.node_id()` before attempting to unseal.
    ///
    /// Errors: [`crate::Error::UnsupportedAlgorithm`],
    /// [`crate::Error::UnsupportedVersion`], [`crate::Error::InvalidSignature`],
    /// [`crate::Error::SubjectMismatch`], [`crate::Error::SealedKeyOpen`].
    pub fn open(&self, recipient: &NodeIdentity, fabric_root: NodeId) -> Result<FabricKey> {
        todo!("verify sig/format/alg/fabric/member, then X25519 open the sealed box")
    }

    /// Encode to the base64url (no-pad) text form (`--fabric-key` input).
    pub fn encode(&self) -> Result<String> {
        todo!("base64url-no-pad of the sealed key's canonical JSON")
    }

    /// Decode from the base64url (no-pad) text form.
    pub fn decode(text: &str) -> Result<SealedFabricKey> {
        todo!("base64url decode then JSON parse")
    }
}

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
//! `blake3::derive_key("wires sealed-fabric-key v1",
//! dh_shared ‖ ephemeral_pub ‖ member_pub)`. The nonce is all-zero — sound
//! because the AEAD key is unique per seal (fresh ephemeral) — and the AAD is
//! the canonical JSON of the sealing context, binding the ciphertext to
//! `(format, fabric, version, member, alg)`. The `sealed` blob is
//! `ephemeral_pub(32) ‖ ct+tag`.
//!
//! # Why the key derivation names both parties
//!
//! Deriving from the raw Diffie–Hellman output alone would make the AEAD key a
//! function of one value an attacker can sometimes force. Ed25519 point
//! decompression accepts **small-order** points: `0100…00` and friends are
//! well-formed 64-hex "node ids" that decompress and then make *every*
//! Diffie–Hellman against them return the all-zero shared secret, because a
//! clamped scalar is a multiple of the cofactor and kills a low-order point. A sealed key addressed to such a "member" would be
//! encrypted under `derive_key(ctx, 0…0)` — a key anybody can compute, holding
//! no secret at all — and since the blob is a base64 token designed to be
//! pasted through untrusted channels, that is a plaintext-equivalent leak of
//! the fabric-wide data key.
//!
//! Two guards, belt and braces:
//!
//! 1. [`NodeId`]s that are weak (low-order) points are refused outright, on the
//!    sealing side and the opening side, and the exchange must be
//!    *contributory* (a non-zero shared secret).
//! 2. The derivation mixes both public keys in, so the AEAD key is bound to the
//!    `(ephemeral, member)` pair rather than to a bare curve output. That is
//!    what closes unknown-key-share variants generically, not just the one
//!    known family of bad inputs.
//!
//! # Forward secrecy, honestly
//!
//! Rotation happens at commit and nowhere else. There is no ratchet. Whoever
//! compromises a member's long-term seed can open every sealed key ever
//! addressed to it, and therefore read all history that member could read.
//! Ratcheting is deferred, not solved.

use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::grant::AlgorithmId;
use crate::identity::{NodeId, NodeIdentity, Signature};
use crate::roster::RosterVersion;

/// The base64 alphabet for the sealed-key text form: URL-safe, no padding
/// (matches [`Membership`](crate::Membership)).
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The all-zero AEAD nonce. Sound because every seal derives a *fresh* AEAD key
/// from a fresh ephemeral Diffie–Hellman, so no key is ever used twice.
const ZERO_NONCE: [u8; 12] = [0u8; 12];

/// Bytes of the ephemeral X25519 public key prefixed to every sealed blob.
const EPHEMERAL_PUB_LEN: usize = 32;

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
    ///
    /// [`FabricKey`] has no `Serialize`, so this is the only way it leaves the
    /// process, and it is meant for `$WIRES_HOME/keyring/<version>.key` alone.
    ///
    /// ```
    /// use library::FabricKey;
    /// let key = FabricKey::generate();
    /// // What the keystore writes is what the keystore reads back.
    /// assert_eq!(FabricKey::from_hex(&key.hex()).unwrap(), key);
    /// // `Debug` redacts, so a key cannot land in a log line by accident.
    /// assert!(!format!("{key:?}").contains(&key.hex()));
    /// ```
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

impl SealedKeyContext<'_> {
    /// The AEAD associated data: this context's canonical JSON bytes.
    fn aad(&self) -> Result<Vec<u8>> {
        canonical_bytes(self)
    }
}

/// The X25519 public key an Ed25519 [`NodeId`] converts to, for sealing *to*
/// that node.
///
/// Returns [`Error::SealedKeyOpen`] when the bytes are not a valid Ed25519
/// point (so not a real node id at all) **or** when they are a valid but *weak*
/// (low-order) point. The second case is the dangerous one: low-order points
/// decompress happily, convert to the Montgomery identity, and would make the
/// derived AEAD key publicly computable — see the module docs.
fn montgomery_public(node: &NodeId) -> Result<x25519_dalek::PublicKey> {
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(node.as_bytes())
        .map_err(|_| Error::SealedKeyOpen)?;
    if verifying.is_weak() {
        return Err(Error::SealedKeyOpen);
    }
    Ok(x25519_dalek::PublicKey::from(
        verifying.to_montgomery().to_bytes(),
    ))
}

/// The X25519 secret an [`NodeIdentity`]'s Ed25519 seed converts to, for
/// opening what was sealed to its [`NodeId`].
///
/// The 2-to-3 dalek split is crossed with **byte arrays only** — never with a
/// `curve25519-dalek` type, which would not typecheck across major versions.
fn montgomery_secret(identity: &NodeIdentity) -> x25519_dalek::StaticSecret {
    let signing = ed25519_dalek::SigningKey::from_bytes(&identity.seed_bytes());
    x25519_dalek::StaticSecret::from(signing.to_scalar_bytes())
}

/// The per-seal AEAD cipher: `blake3::derive_key(ctx,
/// dh_shared ‖ ephemeral_pub ‖ member_pub)`.
///
/// Both public keys are mixed in so the key is bound to *this pair of parties*
/// and not merely to a curve output an attacker might be able to force.
///
/// Returns [`Error::SealedKeyOpen`] when the exchange was **not contributory** —
/// i.e. the shared secret came out all-zero, which is what a low-order public
/// key on either side produces. [`montgomery_public`] already refuses weak
/// recipients; this catches the same shape arriving as the *ephemeral* half of
/// an attacker-supplied sealed blob.
fn cipher_for(
    context: &str,
    shared: &x25519_dalek::SharedSecret,
    ephemeral_pub: &[u8; 32],
    member_pub: &[u8; 32],
) -> Result<ChaCha20Poly1305> {
    if !shared.was_contributory() {
        return Err(Error::SealedKeyOpen);
    }
    let mut material = [0u8; 96];
    material[..32].copy_from_slice(shared.as_bytes());
    material[32..64].copy_from_slice(ephemeral_pub);
    material[64..].copy_from_slice(member_pub);
    let aead_key = blake3::derive_key(context, &material);
    Ok(ChaCha20Poly1305::new(&Key::from(aead_key)))
}

/// Seal `plaintext` to `member` alone: a fresh ephemeral X25519 exchange
/// against `member`'s converted key, the AEAD key derived under `context`
/// (see [`cipher_for`]), `aad` bound in. Returns the blob
/// `ephemeral_pub(32) ‖ ct+tag`.
///
/// The one sealing primitive: [`SealedFabricKey::seal`] uses it for fabric
/// keys and [`crate::announce`] for host announcements. Each use has its own
/// frozen `context`, so a blob sealed for one never opens as the other.
///
/// Returns [`Error::SealedKeyOpen`] for a `member` that is not a usable
/// Ed25519 key (not a point, or a weak one — see the module docs).
pub(crate) fn seal_box(
    member: &NodeId,
    context: &str,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<SealedBox> {
    // Fresh ephemeral secret per seal — the uniqueness that makes the
    // all-zero nonce safe. (x25519-dalek's `EphemeralSecret::random` needs
    // the `getrandom` feature and a rand_core-0.10 RNG; the crate is built
    // without either, so the ephemeral scalar is drawn from the same
    // `OsRng` the rest of the crate uses and wrapped as a `StaticSecret`.
    // It is still used exactly once and dropped here.)
    let mut ephemeral_bytes = [0u8; 32];
    {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut ephemeral_bytes);
    }
    let ephemeral = x25519_dalek::StaticSecret::from(ephemeral_bytes);
    let ephemeral_pub = x25519_dalek::PublicKey::from(&ephemeral);
    let member_pub = montgomery_public(member)?;
    let shared = ephemeral.diffie_hellman(&member_pub);

    let ciphertext = cipher_for(
        context,
        &shared,
        ephemeral_pub.as_bytes(),
        member_pub.as_bytes(),
    )?
    .encrypt(
        &Nonce::from(ZERO_NONCE),
        Payload {
            msg: plaintext,
            aad,
        },
    )
    .map_err(|_| Error::SealedKeyOpen)?;

    let mut blob = Vec::with_capacity(EPHEMERAL_PUB_LEN + ciphertext.len());
    blob.extend_from_slice(ephemeral_pub.as_bytes());
    blob.extend_from_slice(&ciphertext);
    Ok(SealedBox::from_bytes(blob))
}

/// Open a [`seal_box`] blob as `recipient`, under the same `context` and
/// `aad`. [`Error::SealedKeyOpen`] when it is not for `recipient`, was
/// tampered with, is malformed, or carries a non-contributory ephemeral.
pub(crate) fn open_box(
    recipient: &NodeIdentity,
    context: &str,
    aad: &[u8],
    sealed: &SealedBox,
) -> Result<Vec<u8>> {
    let blob = sealed.as_bytes();
    if blob.len() <= EPHEMERAL_PUB_LEN {
        return Err(Error::SealedKeyOpen);
    }
    let (ephemeral_pub, ciphertext) = blob.split_at(EPHEMERAL_PUB_LEN);
    let ephemeral_pub: [u8; 32] = ephemeral_pub.try_into().expect("split at 32");
    // The recipient's own Montgomery public key — the second half of the
    // derivation binding. Recomputed from the secret rather than converted
    // from a claimed id, so it is this node's real key by construction.
    let secret = montgomery_secret(recipient);
    let member_pub = x25519_dalek::PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(ephemeral_pub));
    cipher_for(context, &shared, &ephemeral_pub, member_pub.as_bytes())?
        .decrypt(
            &Nonce::from(ZERO_NONCE),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::SealedKeyOpen)
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
    ///
    /// Returns [`crate::Error::SealedKeyOpen`] when `member` is not a usable
    /// Ed25519 public key — either it does not decompress at all, or it is a
    /// weak (low-order) point, which would make the derived AEAD key publicly
    /// computable (see the module docs). Nothing upstream validates the bytes
    /// an operator types into `roster add`, so this is the check that stops a
    /// planted "node id" from turning a sealed key into plaintext.
    ///
    /// ```
    /// use library::{FabricKey, NodeIdentity, RosterVersion, SealedFabricKey};
    /// let root = NodeIdentity::from_seed([1u8; 32]);
    /// let member = NodeIdentity::from_seed([2u8; 32]);
    /// let key = FabricKey::generate();
    /// let sealed = SealedFabricKey::seal(&root, member.node_id(), RosterVersion(7), &key).unwrap();
    /// assert_eq!(sealed.open(&member, root.node_id()).unwrap(), key);
    /// ```
    pub fn seal(
        root: &NodeIdentity,
        member: NodeId,
        version: RosterVersion,
        key: &FabricKey,
    ) -> Result<SealedFabricKey> {
        let alg = AlgorithmId::Ed25519;
        let fabric = root.node_id();
        let aad = SealedKeyContext {
            format: SEALED_KEY_V1,
            fabric: &fabric,
            version: version.0,
            member: &member,
            alg: &alg,
        }
        .aad()?;

        let sealed = seal_box(&member, SEALED_KEY_CONTEXT, &aad, key.as_bytes())?;

        let sig = root.sign(&canonical_bytes(&SealedKeyBody {
            format: SEALED_KEY_V1,
            fabric: &fabric,
            version: version.0,
            member: &member,
            sealed: &sealed,
            alg: &alg,
        })?);

        Ok(SealedFabricKey {
            format: SEALED_KEY_V1,
            fabric,
            version,
            member,
            sealed,
            alg,
            sig,
        })
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
        if self.alg != AlgorithmId::Ed25519 {
            return Err(Error::UnsupportedAlgorithm);
        }
        if self.format != SEALED_KEY_V1 {
            return Err(Error::UnsupportedVersion);
        }
        // The credential names its own authority; refuse to check it against
        // any root but the one it claims (and the one the recipient trusts).
        if self.fabric != fabric_root {
            return Err(Error::InvalidSignature);
        }
        fabric_root.verify(&self.signing_bytes()?, &self.sig)?;
        if self.member != recipient.node_id() {
            return Err(Error::SubjectMismatch);
        }

        let aad = SealedKeyContext {
            format: self.format,
            fabric: &self.fabric,
            version: self.version.0,
            member: &self.member,
            alg: &self.alg,
        }
        .aad()?;
        let plaintext = open_box(recipient, SEALED_KEY_CONTEXT, &aad, &self.sealed)?;
        let key: [u8; 32] = plaintext.try_into().map_err(|_| Error::SealedKeyOpen)?;
        Ok(FabricKey::from_bytes(key))
    }

    /// The exact canonical bytes covered by [`sig`](Self::sig) — every field
    /// except the signature itself. Private: the spec's public surface is
    /// `seal` / `open` / `encode` / `decode`, and nothing outside this module
    /// has any business re-deriving what the root signed.
    fn signing_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(&SealedKeyBody {
            format: self.format,
            fabric: &self.fabric,
            version: self.version.0,
            member: &self.member,
            sealed: &self.sealed,
            alg: &self.alg,
        })
    }

    /// Encode to the base64url (no-pad) text form (`--fabric-key` input).
    ///
    /// ```
    /// use library::{FabricKey, NodeIdentity, RosterVersion, SealedFabricKey};
    /// let root = NodeIdentity::from_seed([1u8; 32]);
    /// let member = NodeIdentity::from_seed([2u8; 32]).node_id();
    /// let sealed =
    ///     SealedFabricKey::seal(&root, member, RosterVersion(1), &FabricKey::generate()).unwrap();
    /// assert_eq!(SealedFabricKey::decode(&sealed.encode().unwrap()).unwrap(), sealed);
    /// ```
    pub fn encode(&self) -> Result<String> {
        Ok(B64.encode(canonical_bytes(self)?))
    }

    /// Decode from the base64url (no-pad) text form.
    pub fn decode(text: &str) -> Result<SealedFabricKey> {
        let bytes = B64.decode(text)?;
        serde_json::from_slice(&bytes).map_err(Error::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn seed() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    fn key_bytes() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    proptest! {
        /// The round-trip that everything else rests on: what the root seals to
        /// a member, that member opens back to the identical key.
        #[test]
        fn seal_then_open_roundtrips(rs in seed(), ms in seed(), v in any::<u64>(), k in key_bytes()) {
            let root = NodeIdentity::from_seed(rs);
            let member = NodeIdentity::from_seed(ms);
            let key = FabricKey::from_bytes(k);
            let sealed =
                SealedFabricKey::seal(&root, member.node_id(), RosterVersion(v), &key).unwrap();

            prop_assert_eq!(sealed.format, SEALED_KEY_V1);
            prop_assert_eq!(sealed.fabric, root.node_id());
            prop_assert_eq!(sealed.member, member.node_id());
            prop_assert_eq!(sealed.version, RosterVersion(v));
            prop_assert_eq!(sealed.open(&member, root.node_id()).unwrap(), key);
        }

        /// Sealing the same key twice produces different blobs (fresh ephemeral
        /// per seal) that both open to the same key. This is what makes the
        /// all-zero nonce safe.
        #[test]
        fn each_seal_uses_a_fresh_ephemeral(rs in seed(), ms in seed(), k in key_bytes()) {
            let root = NodeIdentity::from_seed(rs);
            let member = NodeIdentity::from_seed(ms);
            let key = FabricKey::from_bytes(k);
            let a = SealedFabricKey::seal(&root, member.node_id(), RosterVersion(1), &key).unwrap();
            let b = SealedFabricKey::seal(&root, member.node_id(), RosterVersion(1), &key).unwrap();
            prop_assert_ne!(a.sealed.as_bytes(), b.sealed.as_bytes());
            prop_assert_eq!(a.open(&member, root.node_id()).unwrap(), key.clone());
            prop_assert_eq!(b.open(&member, root.node_id()).unwrap(), key);
        }

        /// A key sealed to one member is not openable by another: the
        /// member binding is checked before the AEAD is even attempted.
        #[test]
        fn wrong_recipient_is_subject_mismatch(rs in seed(), ms in seed(), os in seed(), k in key_bytes()) {
            prop_assume!(ms != os);
            let root = NodeIdentity::from_seed(rs);
            let member = NodeIdentity::from_seed(ms);
            let other = NodeIdentity::from_seed(os);
            let sealed = SealedFabricKey::seal(
                &root,
                member.node_id(),
                RosterVersion(3),
                &FabricKey::from_bytes(k),
            )
            .unwrap();
            prop_assert!(matches!(
                sealed.open(&other, root.node_id()),
                Err(Error::SubjectMismatch)
            ));
        }

        /// Checking against a root the credential does not name fails the pin,
        /// even for the correct recipient.
        #[test]
        fn wrong_root_fails_the_pin(rs in seed(), ms in seed(), os in seed(), k in key_bytes()) {
            prop_assume!(rs != os);
            let root = NodeIdentity::from_seed(rs);
            let member = NodeIdentity::from_seed(ms);
            let other_root = NodeIdentity::from_seed(os).node_id();
            let sealed = SealedFabricKey::seal(
                &root,
                member.node_id(),
                RosterVersion(3),
                &FabricKey::from_bytes(k),
            )
            .unwrap();
            prop_assert!(matches!(
                sealed.open(&member, other_root),
                Err(Error::InvalidSignature)
            ));
        }

        /// Tampering with **every** signed field in turn breaks `open`. The
        /// signed set is `{format, fabric, version, member, sealed, alg}`, and
        /// each rewrite is checked against the field's own failure mode.
        #[test]
        fn tampering_any_signed_field_fails(rs in seed(), ms in seed(), os in seed(), v in 0u64..u64::MAX, k in key_bytes()) {
            prop_assume!(rs != os && ms != os);
            let root = NodeIdentity::from_seed(rs);
            let member = NodeIdentity::from_seed(ms);
            let other = NodeIdentity::from_seed(os);
            let base = SealedFabricKey::seal(
                &root,
                member.node_id(),
                RosterVersion(v),
                &FabricKey::from_bytes(k),
            )
            .unwrap();

            // format — a signed discriminant, rejected before the signature.
            let mut t = base.clone();
            t.format = SEALED_KEY_V1 + 1;
            prop_assert!(matches!(
                t.open(&member, root.node_id()),
                Err(Error::UnsupportedVersion)
            ));

            // fabric — rewriting it and checking against the rewritten root
            // still fails: the signature was over the original fabric.
            let mut t = base.clone();
            t.fabric = other.node_id();
            prop_assert!(matches!(
                t.open(&member, root.node_id()),
                Err(Error::InvalidSignature)
            ));
            prop_assert!(t.open(&member, other.node_id()).is_err());

            // version — the slot this key belongs to.
            let mut t = base.clone();
            t.version = RosterVersion(v.wrapping_add(1));
            prop_assert!(matches!(
                t.open(&member, root.node_id()),
                Err(Error::InvalidSignature)
            ));

            // member — the non-transferability binding.
            let mut t = base.clone();
            t.member = other.node_id();
            prop_assert!(matches!(
                t.open(&other, root.node_id()),
                Err(Error::InvalidSignature)
            ));

            // sealed — the ciphertext itself.
            let mut blob = base.sealed.as_bytes().to_vec();
            blob[0] ^= 0x01;
            let mut t = base.clone();
            t.sealed = SealedBox::from_bytes(blob);
            prop_assert!(matches!(
                t.open(&member, root.node_id()),
                Err(Error::InvalidSignature)
            ));

            // alg — no second algorithm exists yet, so this is the
            // unsupported-algorithm path rather than a signature failure.
            // (Locked here so adding one cannot silently skip the check.)
            prop_assert_eq!(base.alg, AlgorithmId::Ed25519);

            // sig — the signature itself is not covered by itself.
            let mut t = base.clone();
            let mut sig = *t.sig.as_bytes();
            sig[0] ^= 0x01;
            t.sig = Signature::from_bytes(sig);
            prop_assert!(matches!(
                t.open(&member, root.node_id()),
                Err(Error::InvalidSignature)
            ));
        }

        /// Re-signing a tampered body with the *member's* key does not help:
        /// the fabric pin means only the named root's signature counts.
        #[test]
        fn member_cannot_forge_a_key_for_itself(rs in seed(), ms in seed(), k in key_bytes()) {
            prop_assume!(rs != ms);
            let root = NodeIdentity::from_seed(rs);
            let member = NodeIdentity::from_seed(ms);
            // The member mints a sealed key naming *itself* as the fabric.
            let forged = SealedFabricKey::seal(
                &member,
                member.node_id(),
                RosterVersion(9),
                &FabricKey::from_bytes(k),
            )
            .unwrap();
            prop_assert!(matches!(
                forged.open(&member, root.node_id()),
                Err(Error::InvalidSignature)
            ));
        }

        /// The AAD binds the ciphertext to its `(format, fabric, version,
        /// member)` slot: moving a valid sealed blob into a different slot and
        /// re-signing it as the root still fails the AEAD.
        #[test]
        fn aad_binds_the_blob_to_its_slot(rs in seed(), ms in seed(), v in 0u64..u64::MAX, k in key_bytes()) {
            let root = NodeIdentity::from_seed(rs);
            let member = NodeIdentity::from_seed(ms);
            let base = SealedFabricKey::seal(
                &root,
                member.node_id(),
                RosterVersion(v),
                &FabricKey::from_bytes(k),
            )
            .unwrap();

            // Same blob, different version, correctly re-signed by the root.
            let moved_version = RosterVersion(v.wrapping_add(1));
            let sig = root.sign(
                &canonical_bytes(&SealedKeyBody {
                    format: base.format,
                    fabric: &base.fabric,
                    version: moved_version.0,
                    member: &base.member,
                    sealed: &base.sealed,
                    alg: &base.alg,
                })
                .unwrap(),
            );
            let moved = SealedFabricKey {
                version: moved_version,
                sig,
                ..base.clone()
            };
            // The signature now verifies, so failure comes from the AEAD.
            prop_assert!(matches!(
                moved.open(&member, root.node_id()),
                Err(Error::SealedKeyOpen)
            ));
        }

        /// Diffie–Hellman agrees in both directions across the
        /// dalek-2-to-x25519-dalek-3 byte bridge: the sealer's
        /// `ephemeral × recipient_public` equals the recipient's
        /// `recipient_secret × ephemeral_public`.
        #[test]
        fn dh_agrees_in_both_directions(ms in seed(), es in seed()) {
            let member = NodeIdentity::from_seed(ms);

            // Sealer side: ephemeral secret against the member's converted
            // Ed25519 public key.
            let ephemeral = x25519_dalek::StaticSecret::from(es);
            let ephemeral_pub = x25519_dalek::PublicKey::from(&ephemeral);
            let sealer_shared = ephemeral.diffie_hellman(&montgomery_public(&member.node_id()).unwrap());

            // Recipient side: converted Ed25519 secret against the ephemeral
            // public key.
            let recipient_shared =
                montgomery_secret(&member).diffie_hellman(&ephemeral_pub);

            prop_assert_eq!(sealer_shared.as_bytes(), recipient_shared.as_bytes());
        }

        /// The Ed25519-to-X25519 conversion is consistent: the public key
        /// derived from the converted secret equals the converted public key.
        #[test]
        fn ed25519_to_x25519_conversion_is_consistent(ms in seed()) {
            let identity = NodeIdentity::from_seed(ms);
            let from_secret = x25519_dalek::PublicKey::from(&montgomery_secret(&identity));
            let from_public = montgomery_public(&identity.node_id()).unwrap();
            prop_assert_eq!(from_secret.as_bytes(), from_public.as_bytes());
        }

        /// An encode/decode round-trip is the identity, and the decoded key
        /// still opens.
        #[test]
        fn encode_decode_roundtrips(rs in seed(), ms in seed(), v in any::<u64>(), k in key_bytes()) {
            let root = NodeIdentity::from_seed(rs);
            let member = NodeIdentity::from_seed(ms);
            let key = FabricKey::from_bytes(k);
            let sealed =
                SealedFabricKey::seal(&root, member.node_id(), RosterVersion(v), &key).unwrap();
            let decoded = SealedFabricKey::decode(&sealed.encode().unwrap()).unwrap();
            prop_assert_eq!(&decoded, &sealed);
            prop_assert_eq!(decoded.open(&member, root.node_id()).unwrap(), key);
        }

        /// Arbitrary text decodes to an `Err`, never a panic.
        #[test]
        fn garbage_decode_never_panics(s in ".*") {
            let _ = SealedFabricKey::decode(&s);
        }

        /// A truncated or oversized sealed blob is an `Err`, never a panic —
        /// the blob is attacker-supplied once it is on the wire.
        #[test]
        fn malformed_sealed_blob_never_panics(rs in seed(), ms in seed(), blob in proptest::collection::vec(any::<u8>(), 0..96)) {
            let root = NodeIdentity::from_seed(rs);
            let member = NodeIdentity::from_seed(ms);
            let base = SealedFabricKey::seal(
                &root,
                member.node_id(),
                RosterVersion(1),
                &FabricKey::generate(),
            )
            .unwrap();
            let sealed = SealedBox::from_bytes(blob);
            let sig = root.sign(
                &canonical_bytes(&SealedKeyBody {
                    format: base.format,
                    fabric: &base.fabric,
                    version: base.version.0,
                    member: &base.member,
                    sealed: &sealed,
                    alg: &base.alg,
                })
                .unwrap(),
            );
            let mangled = SealedFabricKey { sealed, sig, ..base };
            prop_assert!(matches!(
                mangled.open(&member, root.node_id()),
                Err(Error::SealedKeyOpen)
            ));
        }

        /// `FabricKey` hex round-trips, and its `Debug` never leaks the bytes.
        #[test]
        fn fabric_key_hex_roundtrips_and_debug_is_redacted(k in key_bytes()) {
            let key = FabricKey::from_bytes(k);
            prop_assert_eq!(FabricKey::from_hex(&key.hex()).unwrap(), key.clone());
            let rendered = format!("{:?}", key);
            prop_assert_eq!(&rendered, "FabricKey(<redacted>)");
            prop_assert!(!rendered.contains(&key.hex()));
        }
    }

    /// Known-answer: the sealing context (the AAD) canonicalizes to exactly
    /// these bytes. Guards the canonicalization the AEAD binding depends on.
    #[test]
    fn context_canonical_bytes_known_answer() {
        let fabric = NodeId::from_bytes([0u8; 32]);
        let member = NodeId::from_bytes([0x11u8; 32]);
        let alg = AlgorithmId::Ed25519;
        let ctx = SealedKeyContext {
            format: SEALED_KEY_V1,
            fabric: &fabric,
            version: 7,
            member: &member,
            alg: &alg,
        };
        let expected = format!(
            r#"{{"alg":"ed25519","fabric":"{}","format":1,"member":"{}","version":7}}"#,
            "00".repeat(32),
            "11".repeat(32),
        );
        assert_eq!(ctx.aad().unwrap(), expected.into_bytes());
    }

    /// Known-answer: the signed body canonicalizes to exactly these bytes —
    /// the AAD's fields plus `sealed`, in sorted-key order.
    #[test]
    fn body_canonical_bytes_known_answer() {
        let fabric = NodeId::from_bytes([0u8; 32]);
        let member = NodeId::from_bytes([0x11u8; 32]);
        let alg = AlgorithmId::Ed25519;
        let sealed = SealedBox::from_bytes(vec![0xab, 0xcd]);
        let body = SealedKeyBody {
            format: SEALED_KEY_V1,
            fabric: &fabric,
            version: 7,
            member: &member,
            sealed: &sealed,
            alg: &alg,
        };
        let expected = format!(
            r#"{{"alg":"ed25519","fabric":"{}","format":1,"member":"{}","sealed":"abcd","version":7}}"#,
            "00".repeat(32),
            "11".repeat(32),
        );
        assert_eq!(canonical_bytes(&body).unwrap(), expected.into_bytes());
    }

    /// The signed body covers every field of the credential except `sig` — the
    /// same guard the envelope carries, applied to the sealed key.
    #[test]
    fn signing_bytes_covers_every_non_signature_field() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let member = NodeIdentity::from_seed([2u8; 32]).node_id();
        let sealed =
            SealedFabricKey::seal(&root, member, RosterVersion(7), &FabricKey::generate()).unwrap();

        let full: serde_json::Value =
            serde_json::from_slice(&canonical_bytes(&sealed).unwrap()).unwrap();
        let signed: serde_json::Value =
            serde_json::from_slice(&sealed.signing_bytes().unwrap()).unwrap();
        let mut expected = full.as_object().unwrap().clone();
        assert!(expected.remove("sig").is_some(), "sig must be present");
        assert_eq!(signed.as_object().unwrap(), &expected);
    }

    /// The derive-key context is frozen: changing it makes every previously
    /// sealed key unopenable.
    #[test]
    fn context_string_is_frozen() {
        assert_eq!(SEALED_KEY_CONTEXT, "wires sealed-fabric-key v1");
        assert_eq!(SEALED_KEY_V1, 1);
    }

    /// A future format version is rejected outright — locks discriminant
    /// dispatch before any v2 body exists.
    #[test]
    fn future_version_is_unsupported() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let member = NodeIdentity::from_seed([2u8; 32]);
        let mut sealed = SealedFabricKey::seal(
            &root,
            member.node_id(),
            RosterVersion(1),
            &FabricKey::generate(),
        )
        .unwrap();
        sealed.format = 2;
        assert!(matches!(
            sealed.open(&member, root.node_id()),
            Err(Error::UnsupportedVersion)
        ));
    }

    /// The sealed blob is `ephemeral_pub(32) ‖ ct+tag`: 32 + 32 key bytes + a
    /// 16-byte Poly1305 tag.
    #[test]
    fn sealed_blob_has_the_documented_shape() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let member = NodeIdentity::from_seed([2u8; 32]).node_id();
        let sealed =
            SealedFabricKey::seal(&root, member, RosterVersion(1), &FabricKey::generate()).unwrap();
        assert_eq!(sealed.sealed.len(), EPHEMERAL_PUB_LEN + 32 + 16);
        assert!(!sealed.sealed.is_empty());
        assert_eq!(sealed.sealed.hex().len(), sealed.sealed.len() * 2);
    }

    /// A sealed blob with no room for the ephemeral public key is refused
    /// before any curve arithmetic happens.
    #[test]
    fn short_sealed_blob_is_refused() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let member = NodeIdentity::from_seed([2u8; 32]);
        let sealed = SealedBox::from_bytes(vec![0u8; EPHEMERAL_PUB_LEN]);
        let alg = AlgorithmId::Ed25519;
        let fabric = root.node_id();
        let member_id = member.node_id();
        let sig = root.sign(
            &canonical_bytes(&SealedKeyBody {
                format: SEALED_KEY_V1,
                fabric: &fabric,
                version: 1,
                member: &member_id,
                sealed: &sealed,
                alg: &alg,
            })
            .unwrap(),
        );
        let short = SealedFabricKey {
            format: SEALED_KEY_V1,
            fabric,
            version: RosterVersion(1),
            member: member_id,
            sealed,
            alg,
            sig,
        };
        assert!(matches!(
            short.open(&member, root.node_id()),
            Err(Error::SealedKeyOpen)
        ));
    }

    /// `FabricKey` is deliberately not `Serialize`: a plaintext data key must
    /// only ever leave the process sealed or through the 0600 keystore hex.
    /// (Compile-time proof lives in the type system; this pins the hex shape.)
    #[test]
    fn fabric_key_hex_is_64_chars() {
        assert_eq!(FabricKey::from_bytes([0u8; 32]).hex(), "0".repeat(64));
        assert!(matches!(
            FabricKey::from_hex("00"),
            Err(Error::BadKeyLength)
        ));
        assert!(matches!(
            FabricKey::from_hex(&"z".repeat(64)),
            Err(Error::BadHex(_))
        ));
    }

    /// Two independently generated keys differ (the generator is not a stub).
    #[test]
    fn generate_produces_distinct_keys() {
        assert_ne!(FabricKey::generate(), FabricKey::generate());
    }

    /// The canonical small-order Ed25519 encodings that *decompress* — the
    /// ones that get past `VerifyingKey::from_bytes` and would otherwise be
    /// accepted as node ids. Every one of them converts to the Montgomery
    /// identity, so a Diffie–Hellman against it yields the all-zero secret.
    const WEAK_NODE_IDS: [&str; 4] = [
        // The Edwards identity: y = 1.
        "0100000000000000000000000000000000000000000000000000000000000000",
        // y = 0 — a point of order 4.
        "0000000000000000000000000000000000000000000000000000000000000000",
        // y = -1 — the point of order 2.
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        // A standard order-8 point.
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    ];

    /// A well-formed 32 bytes that is not a curve point at all: `y = 2` has no
    /// `x` on Ed25519.
    const NOT_A_POINT: &str = "0200000000000000000000000000000000000000000000000000000000000000";

    /// The hole this guards: a low-order "node id" is a well-formed 64-hex
    /// string that every other check in the crate waves through, but sealing to
    /// it would derive the AEAD key from an all-zero Diffie–Hellman — i.e. a key
    /// anyone can compute from the public blob alone. Sealing must refuse.
    #[test]
    fn weak_member_keys_are_refused_by_seal() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        for encoded in WEAK_NODE_IDS {
            let member = NodeId::from_hex(encoded).unwrap();

            // The premise: these really do decompress and really are weak, so
            // nothing before this point would have caught them.
            let verifying = ed25519_dalek::VerifyingKey::from_bytes(member.as_bytes())
                .unwrap_or_else(|_| panic!("{encoded} should decompress"));
            assert!(verifying.is_weak(), "{encoded} should be a weak point");
            // Whatever it converts to, every Diffie-Hellman against it is
            // non-contributory: clamped scalars are multiples of the cofactor,
            // so a low-order point multiplies to the identity.
            let converted = x25519_dalek::PublicKey::from(verifying.to_montgomery().to_bytes());
            let shared = x25519_dalek::StaticSecret::from([9u8; 32]).diffie_hellman(&converted);
            assert_eq!(
                shared.as_bytes(),
                &[0u8; 32],
                "{encoded} should produce an all-zero shared secret"
            );
            assert!(!shared.was_contributory());

            assert!(
                matches!(montgomery_public(&member), Err(Error::SealedKeyOpen)),
                "{encoded} was accepted as a sealing recipient"
            );
            assert!(
                matches!(
                    SealedFabricKey::seal(&root, member, RosterVersion(1), &FabricKey::generate()),
                    Err(Error::SealedKeyOpen)
                ),
                "{encoded} was sealed to"
            );
        }
    }

    /// Node ids that are not points at all are refused too — the pre-existing
    /// half of the check, pinned so a refactor cannot drop it.
    #[test]
    fn undecompressable_member_keys_are_refused_by_seal() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        // A `y` whose corresponding `x^2` is a quadratic non-residue: no point
        // on the curve has this compressed form.
        let member = NodeId::from_hex(NOT_A_POINT).unwrap();
        assert!(ed25519_dalek::VerifyingKey::from_bytes(member.as_bytes()).is_err());
        assert!(matches!(
            SealedFabricKey::seal(&root, member, RosterVersion(1), &FabricKey::generate()),
            Err(Error::SealedKeyOpen)
        ));
    }

    /// The second guard, tested directly: a non-contributory exchange (all-zero
    /// shared secret) never yields a cipher, whichever side produced it.
    #[test]
    fn a_non_contributory_exchange_yields_no_cipher() {
        let secret = x25519_dalek::StaticSecret::from([7u8; 32]);
        // u = 0 is the Montgomery identity: every scalar multiple is zero.
        let identity = x25519_dalek::PublicKey::from([0u8; 32]);
        let shared = secret.diffie_hellman(&identity);
        assert_eq!(shared.as_bytes(), &[0u8; 32]);
        assert!(!shared.was_contributory());
        assert!(matches!(
            cipher_for(SEALED_KEY_CONTEXT, &shared, identity.as_bytes(), &[1u8; 32]),
            Err(Error::SealedKeyOpen)
        ));
    }

    /// The same guard on the opening side: an attacker-supplied blob whose
    /// ephemeral public key is the Montgomery identity is refused rather than
    /// decrypted under a publicly computable key.
    #[test]
    fn a_zero_ephemeral_public_is_refused_by_open() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let member = NodeIdentity::from_seed([2u8; 32]);
        let member_id = member.node_id();
        let alg = AlgorithmId::Ed25519;
        let fabric = root.node_id();
        // 32 zero bytes of "ephemeral public key" plus a plausible ct+tag.
        let sealed = SealedBox::from_bytes(vec![0u8; EPHEMERAL_PUB_LEN + 32 + 16]);
        let sig = root.sign(
            &canonical_bytes(&SealedKeyBody {
                format: SEALED_KEY_V1,
                fabric: &fabric,
                version: 1,
                member: &member_id,
                sealed: &sealed,
                alg: &alg,
            })
            .unwrap(),
        );
        let blob = SealedFabricKey {
            format: SEALED_KEY_V1,
            fabric,
            version: RosterVersion(1),
            member: member_id,
            sealed,
            alg,
            sig,
        };
        assert!(matches!(
            blob.open(&member, root.node_id()),
            Err(Error::SealedKeyOpen)
        ));
    }

    /// `SealedBox` serializes as a lowercase-hex string.
    #[test]
    fn sealed_box_serializes_as_hex_string() {
        let b = SealedBox::from_bytes(vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(serde_json::to_string(&b).unwrap(), "\"deadbeef\"");
        let back: SealedBox = serde_json::from_str("\"deadbeef\"").unwrap();
        assert_eq!(back, b);
    }
}

//! Error type for `library`.

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong in the library's pure core.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Canonical-JSON encoding of a value failed.
    #[error("encode: {0}")]
    Encode(serde_json::Error),

    /// JSON decoding of a value failed.
    #[error("decode: {0}")]
    Decode(serde_json::Error),

    /// A capability-ticket string was not valid base64.
    #[error("ticket decode: {0}")]
    TicketDecode(#[from] base64::DecodeError),

    /// A signature did not verify against the expected public key.
    #[error("invalid signature")]
    InvalidSignature,

    /// The grant declared a signature algorithm this build does not support.
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,

    /// A credential declared a format version this build does not understand.
    ///
    /// Membership credentials carry a *signed* `version` discriminant; a
    /// verifier rejects any version it was not built for rather than silently
    /// ignoring fields it cannot interpret (see [`crate::membership`]).
    #[error("unsupported version")]
    UnsupportedVersion,

    /// A credential's `not_after` is in the past relative to the checked time.
    ///
    /// Shared by grants, memberships, and roster heads — the caller prefixes
    /// which credential it was checking (`membership rejected: …`,
    /// `grant rejected: …`, `roster inclusion rejected: …`), so the display
    /// deliberately does *not* name one.
    #[error("expired at {not_after}")]
    Expired {
        /// The credential's expiry, unix seconds.
        not_after: i64,
    },

    /// The checked credential's subject is present on the revocation list.
    ///
    /// Like [`Error::Expired`], shared by the grant and membership gates, so the
    /// display names no single credential — the caller supplies that prefix.
    #[error("revoked")]
    Revoked,

    /// The grant's subject does not match the authenticated caller.
    #[error("grant subject does not match caller")]
    SubjectMismatch,

    /// A byte slice had the wrong length for the key or signature it decodes to.
    #[error("bad key or signature length")]
    BadKeyLength,

    /// A hex string was not valid hex for the value it decodes to.
    #[error("bad hex: {0}")]
    BadHex(#[from] hex::FromHexError),

    /// A session frame had an unknown tag or a malformed body.
    #[error("bad frame")]
    BadFrame,

    /// A roster inclusion proof did not recompute to the head's Merkle root —
    /// the presented node is not a member under that head.
    #[error("not a member of the roster")]
    NotInRoster,

    /// An inclusion proof targets a different roster version than the head it
    /// was checked against (the member must refresh its proof against the
    /// current head).
    #[error("stale inclusion proof: proof targets version {proof}, head is version {head}")]
    StaleProof {
        /// The roster version the proof was issued against.
        proof: u64,
        /// The roster version of the head it was checked against.
        head: u64,
    },

    /// A responder configured with a roster head required an inclusion proof in
    /// the handshake, but none was presented.
    #[error("inclusion proof required")]
    InclusionProofRequired,

    /// `Roster::commit` was handed a signing key whose node id is not the
    /// roster's `fabric` — a usage error (the fabric root must sign its own
    /// roster).
    #[error("signing key is not the fabric root")]
    FabricMismatch,

    /// A sealed payload did not open, or could not be sealed in the first
    /// place. The crate's single "the AEAD layer did not work out" error, raised
    /// at three points:
    ///
    /// - [`SealedFabricKey::open`](crate::SealedFabricKey::open) — the AEAD tag
    ///   failed, or the blob was truncated or malformed.
    /// - [`TopicEnvelope::open`](crate::TopicEnvelope::open) — the wrong fabric
    ///   key, or a tampered body (the AAD covers every signed field).
    /// - [`SealedFabricKey::seal`](crate::SealedFabricKey::seal) — the *sealing*
    ///   direction: the recipient's `NodeId` is not a valid Ed25519 point, so
    ///   there is no X25519 key to seal to.
    ///
    /// Distinct from [`Error::InvalidSignature`] (a signature over the sealed
    /// object) and [`Error::SubjectMismatch`] (sealed to a different member) —
    /// both are checked first, so reaching this means the object was
    /// well-formed and correctly addressed but the ciphertext was not. Also
    /// distinct from [`Error::KeyVersionUnknown`], which says the node holds no
    /// key for the version at all; this one says a key was tried and rejected.
    #[error(
        "sealed payload did not open (wrong key, tampered ciphertext, or unusable recipient key)"
    )]
    SealedKeyOpen,

    /// An envelope is encrypted under a roster version whose fabric key this
    /// node does not hold.
    ///
    /// Not fatal: the message is stored provisionally and displays once the key
    /// arrives via `wires import` (late joiners never hold pre-join versions,
    /// so for them this is permanent by design).
    #[error("no fabric key held for roster version {version}")]
    KeyVersionUnknown {
        /// The roster version the envelope names.
        version: u64,
    },

    /// A publisher's chain forked: a different message occupies a sequence
    /// number already filled, or a link hash does not match the predecessor.
    ///
    /// Detect and refuse — this layer picks no winner (see [`crate::chain`]).
    #[error("chain fork detected")]
    ChainFork,

    /// An envelope's `topic` is not the topic it was received on.
    #[error("envelope is for a different topic")]
    TopicMismatch,
}

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

    /// The grant's `not_after` is in the past relative to the checked time.
    #[error("grant expired at {not_after}")]
    Expired {
        /// The grant's expiry, unix seconds.
        not_after: i64,
    },

    /// The grant's subject is present on the revocation list.
    #[error("grant revoked")]
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
}

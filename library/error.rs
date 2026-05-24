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
}

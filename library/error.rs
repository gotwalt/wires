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

    /// A member's proof targets an older roster version, and the verifier's
    /// [`ProofDirectory`](crate::ProofDirectory) for the current head does not
    /// list it: a commit since `proof` removed it. Tells the caller no more
    /// than it already knows (it was removed; the head's version is public).
    #[error("not in the current roster ({})", removal(*.proof, *.head))]
    RemovedFromRoster {
        /// The roster version the caller's (last valid) proof was issued
        /// against.
        proof: u64,
        /// The current head's version, which does not list the caller.
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
    /// arrives via `wires advanced import` (late joiners never hold pre-join versions,
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

    /// A tool name broke the [`ToolName`](crate::ToolName) rules.
    #[error("invalid tool name")]
    InvalidToolName,

    /// An argument list broke the [`Argv`](crate::Argv) limits.
    #[error("invalid argv")]
    InvalidArgv,

    /// A push message, or an inbox frame carrying one, broke the limits of
    /// [`crate::push`]: an empty or oversized subject, a control character in
    /// it, an oversized body, too many messages in one frame, or a frame
    /// larger than [`MAX_INBOX_FRAME`](crate::MAX_INBOX_FRAME). The string
    /// names which.
    #[error("invalid push: {0}")]
    InvalidPush(&'static str),

    /// A [`Rekey`](crate::Rekey) or [`Invite`](crate::Invite) whose parts do
    /// not belong together: an entry for another roster version, a sealed key
    /// addressed to someone other than its proof's member, a member listed
    /// twice, or an empty channel name. Every part may verify on its own; this
    /// is the check that they describe *one* commit.
    #[error("inconsistent re-key: {0}")]
    InconsistentRekey(&'static str),

    /// An [`IdentityClaim`](crate::IdentityClaim)'s ID token did not verify.
    /// The inner [`IdTokenError`] names the precise reason, so a renderer or
    /// a policy gate can say *why* ("expired", "wrong nonce") rather than
    /// just "unverified".
    #[error("id token rejected: {0}")]
    IdToken(#[from] IdTokenError),
}

/// Why an OIDC ID token failed [`verify_claim`](crate::verify_claim).
///
/// One variant per check, so each failure is distinguishable — the card-05
/// policy gate and the tail renderer both surface these verbatim.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IdTokenError {
    /// The token is not a well-formed compact JWS with JSON header and
    /// payload, or the issuer's JWKS is not well-formed JSON.
    #[error("malformed: {0}")]
    Malformed(&'static str),

    /// The JWS header names an algorithm other than `RS256` / `ES256`
    /// (including `none` and every HMAC variant).
    #[error("unsupported signing algorithm {0:?} (only RS256 and ES256 are accepted)")]
    UnsupportedAlgorithm(String),

    /// No key in the issuer's JWKS matches the header's `kid` (and type).
    /// A fetcher treats this as "refetch the JWKS once" — keys rotate.
    #[error("no signing key in the issuer's JWKS matches kid {kid:?}")]
    UnknownKey {
        /// The header's `kid`, if it had one.
        kid: Option<String>,
    },

    /// A key matched, but the signature does not verify under it.
    #[error("signature does not verify")]
    BadSignature,

    /// The `iss` claim is not the issuer whose keys were used.
    #[error("issuer {got:?} is not the expected {expected:?}")]
    WrongIssuer {
        /// The issuer the verifier expected.
        expected: String,
        /// The token's `iss`.
        got: String,
    },

    /// None of the token's `aud` values is an accepted audience.
    #[error("audience {got:?} is not accepted")]
    WrongAudience {
        /// The token's `aud` values.
        got: Vec<String>,
    },

    /// `exp` (plus the clock-skew allowance) is in the past.
    #[error("expired at {exp}")]
    Expired {
        /// The token's `exp`, unix seconds.
        exp: i64,
    },

    /// `iat` is further in the future than the clock-skew allowance.
    #[error("issued in the future (iat {iat})")]
    NotYetValid {
        /// The token's `iat`, unix seconds.
        iat: i64,
    },

    /// The `nonce` claim is not [`OidcNonce::for_node`](crate::OidcNonce::for_node)
    /// of the claim's node: the token was minted for another key (or replayed).
    #[error("nonce does not bind this token to node {node}")]
    WrongNonce {
        /// Hex id of the node the claim said the token was for.
        node: String,
    },

    /// A claim the verifier requires (`iss`, `sub`, `aud`, `exp`, `nonce`) is
    /// absent or has the wrong JSON type.
    #[error("missing or mistyped claim {0:?}")]
    MissingClaim(&'static str),
}

/// When [`Error::RemovedFromRoster`] says the member left: exactly the
/// head's version when the proof is one commit behind it, else only a range
/// (the verifier knows the member is absent from the current head, not at
/// which commit in between it went).
fn removal(proof: u64, head: u64) -> String {
    if head == proof.saturating_add(1) {
        format!("removed at version {head}")
    } else {
        format!("removed after version {proof}; head is version {head}")
    }
}

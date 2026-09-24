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

    /// A token (an invite, a membership, a signed state) was not valid
    /// base64.
    #[error("token decode: {0}")]
    TokenDecode(#[from] base64::DecodeError),

    /// A signature did not verify against the expected public key.
    #[error("invalid signature")]
    InvalidSignature,

    /// A signed object declared a signature algorithm this build does not support.
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
    /// Shared by memberships and signed states — the caller prefixes which
    /// credential it was checking (`membership rejected: …`), so the display
    /// deliberately does *not* name one.
    #[error("expired at {not_after}")]
    Expired {
        /// The credential's expiry, unix seconds.
        not_after: i64,
    },

    /// The credential's subject does not match the node checking it: a
    /// membership's member is not the authenticated caller, or an invite's
    /// state does not name the invitee.
    #[error("credential subject does not match caller")]
    SubjectMismatch,

    /// A byte slice had the wrong length for the key, signature, id or
    /// digest it decodes to.
    #[error("bad length for a key, signature, id or digest")]
    BadLength,

    /// A hex string was not valid hex for the value it decodes to.
    #[error("bad hex: {0}")]
    BadHex(#[from] hex::FromHexError),

    /// A session frame had an unknown tag or a malformed body.
    #[error("bad frame")]
    BadFrame,

    /// [`State::sign`](crate::State::sign) was handed a signing key whose
    /// node id is not the state's `fabric` — a usage error (the fabric root
    /// must sign its own state).
    #[error("signing key is not the network root")]
    FabricMismatch,

    /// A service name broke the [`ServiceName`](crate::ServiceName) rules.
    #[error("invalid service name")]
    InvalidServiceName,

    /// A role name broke the [`RoleName`](crate::RoleName) rules.
    #[error("invalid role name (expected 1-64 of [A-Za-z0-9_.-])")]
    InvalidRoleName,

    /// An `email` matcher was neither an address nor `*@domain` (see
    /// [`EmailPattern`](crate::EmailPattern)).
    #[error("invalid email pattern (an address, or `*@domain`)")]
    InvalidEmailPattern,

    /// A [`State`](crate::State) broke a structural rule of
    /// [`State::validate`](crate::State::validate); the string names which.
    #[error("invalid signed state: {0}")]
    InvalidState(String),

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

    /// An [`IdentityClaim`](crate::IdentityClaim)'s ID token did not verify.
    /// The inner [`IdTokenError`] names the precise reason, so a renderer or
    /// a policy gate can say *why* ("expired", "wrong nonce") rather than
    /// just "unverified".
    #[error("id token rejected: {0}")]
    IdToken(#[from] IdTokenError),

    /// A [`Policy`](crate::Policy) broke a structural rule of
    /// [`Policy::validate`](crate::Policy::validate), or a signed policy's
    /// items do not match its head; the string names which.
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    /// An [`InclusionProof`](crate::InclusionProof) does not prove its item
    /// under the head it was checked against (a tampered item or proof, or
    /// one issued under another head).
    #[error("inclusion proof does not match the policy head")]
    BadProof,

    /// A [`Fresh`](crate::Fresh) was signed by a key the policy head does not
    /// list in `directories`.
    #[error("freshness signed by a node that is not a directory")]
    NotADirectory,

    /// A [`Fresh`](crate::Fresh) vouches for another head than the one it
    /// was checked against (another version, or the same version with other
    /// content).
    #[error("freshness is for another policy head")]
    FreshMismatch,
}

/// Why an OIDC ID token failed [`verify_claim`](crate::verify_claim).
///
/// One variant per check, so each failure is distinguishable: `wires login`
/// reports it, and a host keeps it in its trace (its caller hears only a
/// generic refusal).
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

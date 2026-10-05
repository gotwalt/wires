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

    /// A token (a network string) was not valid base64.
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
    /// Signed objects carry a *signed* format discriminant; a verifier
    /// rejects any format it was not built for rather than silently
    /// ignoring fields it cannot interpret.
    #[error("unsupported version")]
    UnsupportedVersion,

    /// A `not_after` is in the past relative to the checked time.
    ///
    /// A policy head's expiry — the caller prefixes what it was checking,
    /// so the display deliberately does *not* name it.
    #[error("expired at {not_after}")]
    Expired {
        /// The credential's expiry, unix seconds.
        not_after: i64,
    },

    /// The signed policy bans the caller's node or person (the admin
    /// removed it; [`check_admitted`](crate::check_admitted)).
    #[error("removed from this network")]
    Banned,

    /// The caller's verified principal carries no verified email, which
    /// admission requires ([`check_admitted`](crate::check_admitted)): a
    /// person ban matches a verified email, so a principal without one could
    /// otherwise sidestep it.
    #[error("the sign-in carries no verified email")]
    NoVerifiedEmail,

    /// No role in the signed policy matches the caller's verified principal
    /// ([`check_admitted`](crate::check_admitted)): the IdP knows them, the
    /// network doesn't.
    #[error("no role in the policy matches this person")]
    NoRole,

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

    /// [`Policy::sign`](crate::Policy::sign) was handed a signing key whose
    /// node id is not the policy's `fabric` (its network root) — a usage
    /// error (the root must sign its own policy).
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

    /// A signed policy's items don't hash to its head's
    /// [`ItemsHash`](crate::ItemsHash): an item was tampered with, dropped or
    /// added, or the items belong to another head.
    #[error("the items are not the ones the policy head commits to")]
    ItemsMismatch,

    /// A [`Fresh`](crate::Fresh) was signed by a key the policy head does not
    /// list in `directories`.
    #[error("freshness signed by a node that is not a directory")]
    NotADirectory,

    /// A [`Fresh`](crate::Fresh) vouches for another head than the one it
    /// was checked against (another version, or the same version with other
    /// content).
    #[error("freshness is for another policy head")]
    FreshMismatch,

    /// A [`Fresh`](crate::Fresh) that verifies is not current: past its
    /// `until`, or signed further in the future than the clock skew allows.
    #[error("the freshness has lapsed")]
    FreshLapsed,

    /// A host presented a [`Fresh`](crate::Fresh) it signed itself, as one
    /// of several directories (card 49): a removed host that is also a
    /// directory could vouch for its own old head, so a caller takes a
    /// host's own word only when the head lists it as the one directory.
    #[error("the host vouched for its own policy, and the policy lists other directories")]
    SelfVouched,

    /// A host's [`HostProof`](crate::HostProof) names an older policy head
    /// than the caller's view.
    #[error("the host holds policy version {theirs}, older than this caller's {ours}")]
    OlderHead {
        /// The host's head version.
        theirs: u64,
        /// The caller's view's head version.
        ours: u64,
    },

    /// A host's [`HostProof`](crate::HostProof) carries no
    /// [`Fresh`](crate::Fresh) that vouches for its head to this caller
    /// (card 49): none current, none from a directory other than the host.
    #[error("no directory has vouched for this host's policy recently")]
    Unvouched,
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

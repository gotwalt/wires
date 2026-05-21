//! `GatewayError` follows the project's snafu convention: every variant has
//! `#[snafu(implicit)] location: Location`, no `message: String`, display
//! strings end with `, at {location}`, external errors are leaves linked via
//! `source`. Boundaries convert with `.context(...)`.

use snafu::{Location, Snafu};

pub type Result<T, E = GatewayError> = std::result::Result<T, E>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum GatewayError {
    // --- I/O / transport ---
    #[snafu(display("I/O failed: {source}, at {location}"))]
    Io {
        #[snafu(source)]
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Failed to bind HTTP listener: {source}, at {location}"))]
    BindHttp {
        #[snafu(source)]
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("HTTP serve failed: {source}, at {location}"))]
    ServeHttp {
        #[snafu(source)]
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },

    // --- OAuth protocol (rendered to RFC 6749 §5.2 JSON) ---
    #[snafu(display("OAuth invalid_request: {detail}, at {location}"))]
    InvalidRequest {
        detail: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("OAuth invalid_client, at {location}"))]
    InvalidClient {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("OAuth invalid_grant: {detail}, at {location}"))]
    InvalidGrant {
        detail: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("OAuth invalid_scope, at {location}"))]
    InvalidScope {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("OAuth unauthorized_client, at {location}"))]
    UnauthorizedClient {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("OAuth unsupported_grant_type, at {location}"))]
    UnsupportedGrantType {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("OAuth unsupported_response_type, at {location}"))]
    UnsupportedResponseType {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("OAuth invalid_target (RFC 8707), at {location}"))]
    InvalidResource {
        #[snafu(implicit)]
        location: Location,
    },

    // --- Authorize session ---
    #[snafu(display("Authorize session unknown, at {location}"))]
    UnknownSession {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Authorize session expired, at {location}"))]
    SessionExpired {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Authorize session already completed, at {location}"))]
    AlreadyDone {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("PKCE verification failed, at {location}"))]
    BadPkce {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("redirect_uri does not match the request's, at {location}"))]
    RedirectUriMismatch {
        #[snafu(implicit)]
        location: Location,
    },

    // --- Pair bridge ---
    #[snafu(display(
        "Pair install rejected: a wires user already exists for root {root_pubkey_hex}, at {location}"
    ))]
    AlreadyPaired {
        root_pubkey_hex: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Failed to move temp data dir: {source}, at {location}"))]
    TempDataDirMove {
        #[snafu(source)]
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },

    // --- Sign-in ---
    #[snafu(display("Sign-in assertion signature did not verify, at {location}"))]
    BadAssertionSignature {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Sign-in: unknown root pubkey {root_pubkey_hex}, at {location}"))]
    UnknownRootPubkey {
        root_pubkey_hex: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Sign-in challenge expired, at {location}"))]
    ExpiredChallenge {
        #[snafu(implicit)]
        location: Location,
    },

    // --- Tokens ---
    #[snafu(display("Token signature invalid, at {location}"))]
    BadTokenSignature {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Token expired, at {location}"))]
    ExpiredToken {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Token audience mismatch, at {location}"))]
    BadAudience {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Token jti revoked, at {location}"))]
    RevokedJti {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Token missing required scope, at {location}"))]
    MissingScope {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Token client_id is revoked, at {location}"))]
    RevokedClient {
        #[snafu(implicit)]
        location: Location,
    },

    // --- Fabrics ---
    #[snafu(display("Unknown wires user for sub {sub}, at {location}"))]
    UnknownUser {
        sub: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Failed to open per-user NodeRuntime: {source}, at {location}"))]
    OpenRuntime {
        #[snafu(source)]
        source: wires_node::NodeError,
        #[snafu(implicit)]
        location: Location,
    },

    // --- MCP dispatch ---
    #[snafu(display("Topic {topic} not found, at {location}"))]
    TopicNotFound {
        topic: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display(
        "Permission denied for topic_id {topic_id_hex} (need {right}), at {location}"
    ))]
    PermissionDenied {
        topic_id_hex: String,
        right: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Reserved topic {topic_id_hex} not writable through MCP, at {location}"))]
    ReservedTopic {
        topic_id_hex: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Invalid tail cursor: {source}, at {location}"))]
    InvalidCursor {
        #[snafu(source)]
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Failed to join topic: {source}, at {location}"))]
    JoinTopic {
        #[snafu(source)]
        source: wires_node::NodeError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Publish failed: {source}, at {location}"))]
    PublishFailed {
        #[snafu(source)]
        source: wires_node::NodeError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Tail read failed: {source}, at {location}"))]
    TailFailed {
        #[snafu(source)]
        source: wires_node::NodeError,
        #[snafu(implicit)]
        location: Location,
    },

    // --- Store ---
    #[snafu(display("Gateway redb storage failed: {source}, at {location}"))]
    Redb {
        #[snafu(source)]
        source: redb::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Failed to open gateway redb: {source}, at {location}"))]
    RedbOpen {
        #[snafu(source)]
        source: redb::DatabaseError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Gateway JSON (de)serialize failed: {source}, at {location}"))]
    Json {
        #[snafu(source)]
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Invalid [retention] config: {detail}, at {location}"))]
    InvalidRetention {
        detail: String,
        #[snafu(implicit)]
        location: Location,
    },
}

use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum CoreError {
    #[snafu(display("Failed to serialize message envelope, at {location}"))]
    SerializeEnvelope {
        #[snafu(source)]
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Failed to deserialize message envelope, at {location}"))]
    DeserializeEnvelope {
        #[snafu(source)]
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Signature verification failed, at {location}"))]
    BadSignature {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Hash chain link does not match prior message's hash, at {location}"))]
    ChainBreak {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Reserved type '{reserved_type}' used with disallowed encryption mode, at {location}"))]
    ReservedTypeWrongMode {
        reserved_type: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Capability signature invalid, at {location}"))]
    BadCapSignature {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Capability expired (issued={issued}, expires={expires:?}, now={now}), at {location}"))]
    CapExpired {
        issued: i64,
        expires: Option<i64>,
        now: i64,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Capability does not grant {right} on topic '{topic}', at {location}"))]
    CapDenied {
        right: String,
        topic: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Invalid glob pattern '{pattern}', at {location}"))]
    BadGlob {
        pattern: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Content missing required field '{field}', at {location}"))]
    ContentMissingField {
        field: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Failed to parse content JSON, at {location}"))]
    ParseContent {
        #[snafu(source)]
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Failed to encode content JSON, at {location}"))]
    EncodeContent {
        #[snafu(source)]
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T, E = CoreError> = core::result::Result<T, E>;

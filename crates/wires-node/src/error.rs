use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum NodeError {
    #[snafu(display("Core protocol error, at {location}"))]
    Core {
        #[snafu(source)]
        source: wires_core::CoreError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Crypto failure, at {location}"))]
    Crypto {
        #[snafu(source)]
        source: wires_crypto::CryptoError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Storage failure, at {location}"))]
    Store {
        #[snafu(source)]
        source: wires_store::StoreError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Network failure, at {location}"))]
    Net {
        #[snafu(source)]
        source: wires_net::NetError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Configuration error: {message}, at {location}"))]
    Config {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Missing epoch key for topic {topic_id_hex} epoch {epoch}, at {location}"))]
    MissingEpochKey {
        topic_id_hex: String,
        epoch: u32,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Capability {cap_id_hex} not found or revoked, at {location}"))]
    NoCap {
        cap_id_hex: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Reserved type used with wrong mode, at {location}"))]
    ReservedMisuse {
        #[snafu(source)]
        source: wires_core::CoreError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("I/O error, at {location}"))]
    Io {
        #[snafu(source)]
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Serialization failure, at {location}"))]
    Serde {
        #[snafu(source)]
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T, E = NodeError> = core::result::Result<T, E>;

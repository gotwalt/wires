//! Error type for `wires-cli`. Mirrors the snafu pattern used elsewhere in the
//! workspace: every variant carries a `Location`, no `message` is auto-derived
//! by snafu, and display strings end with `, at {location}`.

use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum CliError {
    #[snafu(display("I/O failure, at {location}"))]
    Io {
        #[snafu(source)]
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("TOML parse failure, at {location}"))]
    TomlParse {
        #[snafu(source)]
        source: toml::de::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("TOML serialize failure, at {location}"))]
    TomlSerialize {
        #[snafu(source)]
        source: toml::ser::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("JSON failure, at {location}"))]
    Json {
        #[snafu(source)]
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Hex decode failure, at {location}"))]
    Hex {
        #[snafu(source)]
        source: hex::FromHexError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Core error, at {location}"))]
    Core {
        #[snafu(source)]
        source: wires_core::CoreError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Node error, at {location}"))]
    Node {
        #[snafu(source)]
        source: wires_node::NodeError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Net error, at {location}"))]
    Net {
        #[snafu(source)]
        source: wires_net::NetError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Store error, at {location}"))]
    Store {
        #[snafu(source)]
        source: wires_store::StoreError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("iroh endpoint operation failed: {message}, at {location}"))]
    Endpoint {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{message}, at {location}"))]
    Invalid {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("host rejected request: {code:?} — {message}, at {location}"))]
    HostRejected {
        code: wires_net::fabric::FabricErrorCode,
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("unexpected host response: {message}, at {location}"))]
    UnexpectedResponse {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T, E = CliError> = core::result::Result<T, E>;

/// Build an [`CliError::Invalid`] from a literal or format string.
#[macro_export]
macro_rules! invalid {
    ($msg:expr) => {
        $crate::error::CliError::Invalid {
            message: $msg.to_string(),
            location: snafu::location!(),
        }
    };
    ($fmt:literal, $($arg:tt)*) => {
        $crate::error::CliError::Invalid {
            message: format!($fmt, $($arg)*),
            location: snafu::location!(),
        }
    };
}

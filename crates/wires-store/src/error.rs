use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum StoreError {
    #[snafu(display("Failed to open database at {path:?}, at {location}"))]
    OpenDb {
        path: std::path::PathBuf,
        #[snafu(source)]
        source: redb::DatabaseError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Failed to begin transaction, at {location}"))]
    BeginTxn {
        #[snafu(source)]
        source: redb::TransactionError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Failed to commit transaction, at {location}"))]
    CommitTxn {
        #[snafu(source)]
        source: redb::CommitError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Failed to open table, at {location}"))]
    OpenTable {
        #[snafu(source)]
        source: redb::TableError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Storage I/O failure, at {location}"))]
    StorageIo {
        #[snafu(source)]
        source: redb::StorageError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Failed to serialize stored value, at {location}"))]
    Serialize {
        #[snafu(source)]
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Failed to deserialize stored value, at {location}"))]
    Deserialize {
        #[snafu(source)]
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Core error from stored type, at {location}"))]
    Core {
        #[snafu(source)]
        source: wires_core::CoreError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Filesystem error at {path:?}, at {location}"))]
    Fs {
        path: std::path::PathBuf,
        #[snafu(source)]
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T, E = StoreError> = core::result::Result<T, E>;

use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum HostError {
    #[snafu(display("Failed to open host db file: {source}, at {location}"))]
    DbOpen {
        #[snafu(source)]
        source: redb::DatabaseError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Host storage I/O failed: {source}, at {location}"))]
    StorageIo {
        #[snafu(source)]
        source: redb::StorageError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Failed to (de)serialize host record: {source}, at {location}"))]
    Serde {
        #[snafu(source)]
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Tenant signature invalid, at {location}"))]
    TenantSignatureInvalid {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Tenant suspended (root={root_hex}), at {location}"))]
    TenantSuspended {
        root_hex: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Retention eviction failed: {source}, at {location}"))]
    RetentionEvictionFailed {
        #[snafu(source)]
        source: wires_store::StoreError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Store error: {source}, at {location}"))]
    Store {
        #[snafu(source)]
        source: wires_store::StoreError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Redb txn boundary failed: {source}, at {location}"))]
    Txn {
        #[snafu(source)]
        source: redb::TransactionError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Redb commit failed: {source}, at {location}"))]
    Commit {
        #[snafu(source)]
        source: redb::CommitError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Redb table-open failed: {source}, at {location}"))]
    Table {
        #[snafu(source)]
        source: redb::TableError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Filesystem I/O failed: {source}, at {location}"))]
    Io {
        #[snafu(source)]
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, HostError>;

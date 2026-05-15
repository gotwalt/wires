use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum NetError {
    #[snafu(display("iroh endpoint setup failed, at {location}"))]
    Endpoint {
        #[snafu(source(from(anyhow::Error, Box::new)))]
        source: Box<anyhow::Error>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Gossip subscription failed, at {location}"))]
    GossipSubscribe {
        #[snafu(source(from(anyhow::Error, Box::new)))]
        source: Box<anyhow::Error>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Gossip publish failed, at {location}"))]
    GossipPublish {
        #[snafu(source(from(anyhow::Error, Box::new)))]
        source: Box<anyhow::Error>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Replay RPC failed, at {location}"))]
    ReplayRpc {
        #[snafu(source(from(anyhow::Error, Box::new)))]
        source: Box<anyhow::Error>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Serialization failure in net layer, at {location}"))]
    Serde {
        #[snafu(source)]
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("I/O failure, at {location}"))]
    Io {
        #[snafu(source)]
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Tenant register failed, at {location}"))]
    TenantRegister {
        #[snafu(source(from(anyhow::Error, Box::new)))]
        source: Box<anyhow::Error>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Tenant stream closed unexpectedly, at {location}"))]
    TenantStreamClosed {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Tenant protocol returned a bad response: {message}, at {location}"))]
    TenantBadResponse {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Discovery fetch failed for {url}, at {location}"))]
    DiscoveryFetch {
        url: String,
        #[snafu(source)]
        source: reqwest::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Pair request bounds: {what} exceeds limit {limit}, at {location}"))]
    PairBounds {
        what: &'static str,
        limit: usize,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Pair signature verify failed, at {location}"))]
    PairSignature {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Pair request unsupported version {version}, at {location}"))]
    PairUnsupportedVersion {
        version: u8,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Pair request invalid characters in {field}, at {location}"))]
    PairInvalidChars {
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Pair sealed-box failure, at {location}"))]
    PairCrypto {
        #[snafu(source(from(wires_crypto::error::CryptoError, Box::new)))]
        source: Box<wires_crypto::error::CryptoError>,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T, E = NetError> = core::result::Result<T, E>;

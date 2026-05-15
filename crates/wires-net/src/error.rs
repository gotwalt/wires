use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum NetError {
    #[snafu(display("Gossip subscription failed: {source}, at {location}"))]
    GossipSubscribe {
        source: iroh_gossip::api::ApiError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Gossip publish failed: {source}, at {location}"))]
    GossipPublish {
        source: iroh_gossip::api::ApiError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Replay source read failed: {source}, at {location}"))]
    ReplaySource {
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Replay RPC connect failed: {source}, at {location}"))]
    ReplayConnect {
        source: iroh::endpoint::ConnectError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Replay RPC stream open failed: {source}, at {location}"))]
    ReplayOpenBi {
        source: iroh::endpoint::ConnectionError,
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
    #[snafu(display("Pair token base64 decode failed, at {location}"))]
    PairTokenDecode {
        #[snafu(source)]
        source: base64::DecodeError,
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
    #[snafu(display("Pair dial failed: {message}, at {location}"))]
    PairDial {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Pair stream error: {message}, at {location}"))]
    PairStream {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Pair rejected by responder: {code:?}: {message}, at {location}"))]
    PairRejected {
        code: crate::pair::PairRejectCode,
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("iroh endpoint bind failed: {source}, at {location}"))]
    EndpointBind {
        source: iroh::endpoint::BindError,
        #[snafu(implicit)]
        location: Location,
    },
    #[cfg(feature = "mdns")]
    #[snafu(display("mDNS address-lookup setup failed: {source}, at {location}"))]
    MdnsSetup {
        source: iroh::address_lookup::AddressLookupBuilderError,
        #[snafu(implicit)]
        location: Location,
    },
    #[cfg(feature = "mdns")]
    #[snafu(display("endpoint address-lookup registry unavailable: {source}, at {location}"))]
    AddressLookup {
        source: iroh::endpoint::EndpointError,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T, E = NetError> = core::result::Result<T, E>;

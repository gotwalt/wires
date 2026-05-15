pub mod discovery;
pub mod endpoint;
pub mod error;
pub mod framing;
pub mod gossip;
pub mod identity;
pub mod pair;
pub mod peer_hint;
pub mod replay;
pub mod tenant;
pub mod ticket;
pub mod time;

pub use discovery::{DiscoveryEndpoint, DiscoveryResponse, fetch_endpoints};
pub use endpoint::{bind_cloud, bind_lan};
pub use error::{NetError, Result};
pub use gossip::{GOSSIP_ALPN, Gossip, GossipHandle, GossipNode};
pub use identity::load_or_create_secret;
pub use pair::{
    ALPN as PAIR_ALPN, HostInfo as PairHostInfo, MAX_FRAME_LEN as PAIR_MAX_FRAME_LEN, PairAck,
    PairClient, PairDial, PairFrame, PairGrant, PairGrantEnvelope, PairHandler, PairManifest,
    PairProtocol, PairReject, PairRejectCode, PairRequest, RequestedScope, TopicEpochKey,
    TopicNameEntry,
};
pub use peer_hint::{
    PeerHint, cap_id_from_hex, endpoint_id_from_hex, first_reachable,
    first_reachable_with_discovery,
};
pub use replay::{
    ALPN, HwmEntry, ReplayClient, ReplayProtocol, ReplayRequest, ReplayResponseFrame, ReplaySource,
};
pub use tenant::{
    ALPN as TENANT_ALPN, TenantClient, TenantErrorCode, TenantErrorResponse, TenantHandler,
    TenantOp, TenantProtocol, TenantRegisterRequest, TenantRegisterResponse, TenantRequest,
    TenantResponse, TenantStatusKind, TenantStatusRequest, TenantStatusResponse,
    TopicRegisterRequest, TopicRegisterResponse, TopicUnregisterRequest, TopicUnregisterResponse,
    signing_bytes as tenant_signing_bytes,
};
pub use ticket::{HostTicket, MAX_HINT_ADDRS, MAX_TICKET_BYTES, TICKET_VERSION};
pub use time::unix_now_ms;

//! Thin wrappers around `wires-net::tenant` that the iOS app drives.
//! Stateless — each call uses the caller's bound endpoint, registers the
//! host's address hints into the endpoint's address-lookup table, and sends
//! one signed request. Host info reaches these via `parse_host_ticket`
//! upstream; there is no HTTPS discovery.

use std::sync::Arc;
use std::time::SystemTime;

use iroh::{Endpoint, EndpointAddr, TransportAddr};
use wires_net::peer_hint::endpoint_id_from_hex;
use wires_net::tenant::{TenantClient, TenantResponse};

use crate::error::{
    InternalSnafu, TenantRejectedSnafu, TenantStreamSnafu, TopicRegisterRejectedSnafu,
    TopicRegisterStreamSnafu, WiresError,
};
use crate::signer::{SwiftRootSigner, SwiftRootSignerAdapter};
use crate::types::{HostInfo, TenantRegistration};

pub async fn register_with_hosted_service(
    endpoint: Endpoint,
    root_signer: Arc<dyn SwiftRootSigner>,
    host: &HostInfo,
) -> Result<TenantRegistration, WiresError> {
    let peer = decode_endpoint_id(&host.endpoint_id_hex)?;
    register_hint_addrs(&endpoint, host);

    let adapter = SwiftRootSignerAdapter {
        inner: root_signer,
    };
    let host_eid_bytes = *peer.as_bytes();
    let now = now_ms()?;

    let client = TenantClient::new(endpoint);
    let resp = client
        .register_tenant(peer, &adapter, &host_eid_bytes, now)
        .await
        .map_err(|e| {
            TenantStreamSnafu {
                message: format!("{e}"),
            }
            .build()
        })?;

    match resp {
        TenantResponse::Register(r) if r.ok => Ok(TenantRegistration {
            caps_topic_id_hex: hex::encode(r.caps_topic_id),
            host_endpoint_id_hex: r.host_endpoint_id,
            server_time_ms: r.server_time,
        }),
        TenantResponse::Error(err) => Err(TenantRejectedSnafu {
            code: err.code,
            message: err.message,
        }
        .build()),
        other => Err(InternalSnafu {
            message: format!("unexpected tenant response: {other:?}"),
        }
        .build()),
    }
}

pub async fn register_topic(
    endpoint: Endpoint,
    root_signer: Arc<dyn SwiftRootSigner>,
    host: &HostInfo,
    topic_id: &[u8; 32],
) -> Result<(), WiresError> {
    let peer = decode_endpoint_id(&host.endpoint_id_hex)?;
    register_hint_addrs(&endpoint, host);

    let adapter = SwiftRootSignerAdapter {
        inner: root_signer,
    };
    let host_eid_bytes = *peer.as_bytes();
    let now = now_ms()?;

    let client = TenantClient::new(endpoint);
    let resp = client
        .register_topic(peer, &adapter, topic_id, &host_eid_bytes, now)
        .await
        .map_err(|e| {
            TopicRegisterStreamSnafu {
                message: format!("{e}"),
            }
            .build()
        })?;

    match resp {
        TenantResponse::TopicRegister(r) if r.ok => Ok(()),
        TenantResponse::Error(err) => Err(TopicRegisterRejectedSnafu {
            code: err.code,
            message: err.message,
        }
        .build()),
        other => Err(InternalSnafu {
            message: format!("unexpected tenant response: {other:?}"),
        }
        .build()),
    }
}

fn decode_endpoint_id(hex_s: &str) -> Result<iroh::EndpointId, WiresError> {
    endpoint_id_from_hex(hex_s).ok_or_else(|| {
        InternalSnafu {
            message: format!("invalid endpoint_id hex: {hex_s}"),
        }
        .build()
    })
}

/// Register the host's address hints into the endpoint's address-lookup table
/// so iroh can dial without falling back to pkarr/DNS. Mirrors the CLI's
/// `register_hint_addrs` helper in `wires-cli/src/cmd/host.rs`.
fn register_hint_addrs(ep: &Endpoint, host: &HostInfo) {
    let Some(id) = endpoint_id_from_hex(&host.endpoint_id_hex) else {
        return;
    };
    let mut addrs: Vec<TransportAddr> = Vec::new();
    for s in &host.addrs {
        if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
            addrs.push(TransportAddr::Ip(sa));
        } else {
            tracing::warn!(addr = %s, "dropping unparseable host addr");
        }
    }
    if let Some(relay) = host.relay.as_deref()
        && let Ok(url) = relay.parse::<iroh::RelayUrl>()
    {
        addrs.push(TransportAddr::Relay(url));
    }
    if addrs.is_empty() {
        return;
    }
    let endpoint_addr = EndpointAddr::from_parts(id, addrs);
    if let Ok(lookup) = ep.address_lookup() {
        lookup.add(
            iroh::address_lookup::memory::MemoryLookup::from_endpoint_info(vec![endpoint_addr]),
        );
    }
}

fn now_ms() -> Result<i64, WiresError> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| {
            InternalSnafu {
                message: e.to_string(),
            }
            .build()
        })?
        .as_millis() as i64)
}

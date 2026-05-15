//! Endpoint bind helpers — one per deployment shape.
//!
//! [`bind_lan`] is for on-LAN agents (CLI runtimes, `wires-ha`, all
//! `wires-cli` dial commands). It registers iroh's `MdnsAddressLookup`
//! alongside the n0 pkarr/DNS resolver, so peers on the same LAN resolve in
//! milliseconds without an internet round-trip. Cross-LAN resolution still
//! works via n0.
//!
//! [`bind_cloud`] is for cloud-resident infrastructure (`wires-host`). It
//! skips mDNS entirely — multicast is useless in cloud environments, and the
//! host is reached by explicit `EndpointId` from the HTTPS `/v1/bootstrap`
//! response or from `PairGrant.host.peer_hints`.
//!
//! Both helpers use `iroh::endpoint::presets::N0` under the hood, so n0
//! pkarr/DNS discovery is always available.

use iroh::{Endpoint, SecretKey, endpoint::presets};
use snafu::ResultExt;

use crate::error::{EndpointBindSnafu, NetError};

/// Bind an endpoint for an on-LAN agent. Enables iroh's mDNS address lookup
/// (under the `mdns` Cargo feature, on by default) for fast LAN resolution.
pub async fn bind_lan(secret: SecretKey, alpns: Vec<Vec<u8>>) -> Result<Endpoint, NetError> {
    let ep = Endpoint::builder(presets::N0)
        .secret_key(secret)
        .alpns(alpns)
        .bind()
        .await
        .context(EndpointBindSnafu)?;

    #[cfg(feature = "mdns")]
    {
        use iroh::address_lookup::MdnsAddressLookup;

        use crate::error::{AddressLookupSnafu, MdnsSetupSnafu};

        let mdns = MdnsAddressLookup::builder()
            .build(ep.id())
            .context(MdnsSetupSnafu)?;
        ep.address_lookup()
            .context(AddressLookupSnafu)?
            .add(mdns);
    }

    Ok(ep)
}

/// Bind an endpoint for cloud-resident infrastructure. Does NOT enable mDNS.
pub async fn bind_cloud(secret: SecretKey, alpns: Vec<Vec<u8>>) -> Result<Endpoint, NetError> {
    Endpoint::builder(presets::N0)
        .secret_key(secret)
        .alpns(alpns)
        .bind()
        .await
        .context(EndpointBindSnafu)
}

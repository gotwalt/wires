//! Capability ticket: the on-the-wire address a dialer presents.
//!
//! A [`CapabilityTicket`] bundles *whom to dial* (`target`), the requested
//! `scope`, and the root-signed `grant` proving the dialer may. Its base64 text
//! form *is* the address in the capability-addressed model.
//!
//! It can also carry **routing hints** — direct socket [`addrs`](CapabilityTicket::addrs)
//! and a [`relay_url`](CapabilityTicket::relay_url) — so a dialer can reach the
//! target without depending on a discovery service. These are *unsigned hints*:
//! iroh still authenticates the peer to `target`'s key during the handshake, so
//! a wrong or tampered address can only fail to connect, never impersonate.

use std::net::SocketAddr;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::grant::{Grant, Scope};
use crate::identity::NodeId;

/// The base64 alphabet for ticket text: URL-safe, no padding.
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// What a dialer holds and presents: target node id + scope + grant, plus
/// optional routing hints.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CapabilityTicket {
    /// The responder's node id to dial.
    pub target: NodeId,
    /// The scope being requested.
    pub scope: Scope,
    /// The root-signed grant authorizing the dialer.
    pub grant: Grant,
    /// Direct socket address(es) where `target` is reachable. Unsigned hints
    /// that let the dialer skip discovery; empty means "resolve via discovery".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addrs: Vec<SocketAddr>,
    /// A relay URL to reach `target` through, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
}

impl CapabilityTicket {
    /// A ticket with no routing hints (the dialer resolves `target` via
    /// discovery). Attach hints with [`with_addrs`](Self::with_addrs) /
    /// [`with_relay_url`](Self::with_relay_url).
    ///
    /// ```
    /// use library::{CapabilityTicket, Grant, NodeIdentity, Scope};
    /// let root = NodeIdentity::from_seed([1u8; 32]);
    /// let agent = NodeIdentity::from_seed([2u8; 32]);
    /// let target = NodeIdentity::from_seed([3u8; 32]).node_id();
    /// let scope = Scope::new("tools.rg");
    /// let grant = Grant::mint(&root, agent.node_id(), scope.clone(), i64::MAX).unwrap();
    /// let ticket = CapabilityTicket::new(target, scope, grant);
    /// let text = ticket.encode().unwrap();
    /// assert_eq!(CapabilityTicket::decode(&text).unwrap(), ticket);
    /// ```
    pub fn new(target: NodeId, scope: Scope, grant: Grant) -> Self {
        Self {
            target,
            scope,
            grant,
            addrs: Vec::new(),
            relay_url: None,
        }
    }

    /// Attach direct socket addresses for `target`.
    ///
    /// ```
    /// use library::{CapabilityTicket, Grant, NodeIdentity, Scope};
    /// let root = NodeIdentity::from_seed([1u8; 32]);
    /// let target = NodeIdentity::from_seed([3u8; 32]).node_id();
    /// let grant = Grant::mint(&root, target, Scope::new("tools.rg"), i64::MAX).unwrap();
    /// let ticket = CapabilityTicket::new(target, Scope::new("tools.rg"), grant)
    ///     .with_addrs(vec!["198.51.100.7:4433".parse().unwrap()]);
    /// assert_eq!(CapabilityTicket::decode(&ticket.encode().unwrap()).unwrap(), ticket);
    /// ```
    pub fn with_addrs(mut self, addrs: Vec<SocketAddr>) -> Self {
        self.addrs = addrs;
        self
    }

    /// Attach a relay URL to reach `target` through.
    pub fn with_relay_url(mut self, relay_url: Option<String>) -> Self {
        self.relay_url = relay_url;
        self
    }

    /// Encode to the base64url (no-pad) text form carried out of band.
    pub fn encode(&self) -> Result<String> {
        Ok(B64.encode(canonical_bytes(self)?))
    }

    /// Decode from the base64url (no-pad) text form.
    pub fn decode(text: &str) -> Result<Self> {
        let bytes = B64.decode(text)?;
        serde_json::from_slice(&bytes).map_err(Error::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use proptest::prelude::*;

    fn seed() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    proptest! {
        /// A ticket survives an encode/decode round-trip unchanged.
        #[test]
        fn ticket_roundtrips(ts in seed(), rs in seed(), ss in seed(), scope in "[a-z.]{1,16}", not_after in any::<i64>()) {
            let root = NodeIdentity::from_seed(rs);
            let subject = NodeIdentity::from_seed(ss).node_id();
            let target = NodeIdentity::from_seed(ts).node_id();
            let grant = Grant::mint(&root, subject, Scope::new(scope.clone()), not_after).unwrap();
            let ticket = CapabilityTicket::new(target, Scope::new(scope), grant);
            let decoded = CapabilityTicket::decode(&ticket.encode().unwrap()).unwrap();
            prop_assert_eq!(ticket, decoded);
        }

        /// Arbitrary text decodes to an `Err`, never a panic.
        #[test]
        fn garbage_decode_never_panics(s in ".*") {
            let _ = CapabilityTicket::decode(&s);
        }
    }

    fn fixture() -> CapabilityTicket {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let target = NodeIdentity::from_seed([3u8; 32]).node_id();
        let grant = Grant::mint(&root, target, Scope::new("tools.rg"), i64::MAX).unwrap();
        CapabilityTicket::new(target, Scope::new("tools.rg"), grant)
    }

    #[test]
    fn routing_hints_round_trip() {
        let ticket = fixture()
            .with_addrs(vec![
                "127.0.0.1:3340".parse().unwrap(),
                "[2001:db8::1]:4433".parse().unwrap(),
            ])
            .with_relay_url(Some("http://relay.example:3340".to_string()));
        let decoded = CapabilityTicket::decode(&ticket.encode().unwrap()).unwrap();
        assert_eq!(decoded, ticket);
        assert_eq!(decoded.addrs.len(), 2);
        assert_eq!(
            decoded.relay_url.as_deref(),
            Some("http://relay.example:3340")
        );
    }

    #[test]
    fn hintless_ticket_decodes_with_empty_defaults() {
        // `skip_serializing_if` means a hintless ticket encodes without the
        // `addrs` / `relay_url` keys, and decoding fills the defaults.
        let decoded = CapabilityTicket::decode(&fixture().encode().unwrap()).unwrap();
        assert!(decoded.addrs.is_empty());
        assert!(decoded.relay_url.is_none());
    }
}

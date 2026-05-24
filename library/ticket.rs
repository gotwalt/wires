//! Capability ticket: the on-the-wire address a dialer presents.
//!
//! A [`CapabilityTicket`] bundles *whom to dial* (`target`), the requested
//! `scope`, and the root-signed `grant` proving the dialer may. Its base64 text
//! form *is* the address in the capability-addressed model.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::grant::{Grant, Scope};
use crate::identity::NodeId;

/// The base64 alphabet for ticket text: URL-safe, no padding.
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// What a dialer holds and presents: target node id + scope + grant.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CapabilityTicket {
    /// The responder's node id to dial.
    pub target: NodeId,
    /// The scope being requested.
    pub scope: Scope,
    /// The root-signed grant authorizing the dialer.
    pub grant: Grant,
}

impl CapabilityTicket {
    /// Encode to the base64url (no-pad) text form carried out of band.
    ///
    /// ```
    /// use library::{CapabilityTicket, Grant, NodeIdentity, Scope};
    /// let root = NodeIdentity::from_seed([1u8; 32]);
    /// let agent = NodeIdentity::from_seed([2u8; 32]);
    /// let target = NodeIdentity::from_seed([3u8; 32]).node_id();
    /// let scope = Scope::new("tools.rg");
    /// let grant = Grant::mint(&root, agent.node_id(), scope.clone(), i64::MAX).unwrap();
    /// let ticket = CapabilityTicket { target, scope, grant };
    /// let text = ticket.encode().unwrap();
    /// assert_eq!(CapabilityTicket::decode(&text).unwrap(), ticket);
    /// ```
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
            let ticket = CapabilityTicket { target, scope: Scope::new(scope), grant };
            let decoded = CapabilityTicket::decode(&ticket.encode().unwrap()).unwrap();
            prop_assert_eq!(ticket, decoded);
        }

        /// Arbitrary text decodes to an `Err`, never a panic.
        #[test]
        fn garbage_decode_never_panics(s in ".*") {
            let _ = CapabilityTicket::decode(&s);
        }
    }
}

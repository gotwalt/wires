//! Topics: the multiway channel name, derived rather than created.
//!
//! A topic has no registry and no creation ceremony. Any member of a fabric
//! computes the same [`TopicId`] from its fabric root key plus a human-typed
//! name (`--topic ops`), so two members who agree on the name are already
//! subscribed to the same channel. Deriving the id from the fabric key also
//! scopes it: the same name under a different fabric is a different topic, and
//! a topic id leaks nothing about the name to an outsider who does not already
//! know the fabric.
//!
//! The derivation is `blake3::derive_key("wires topic-id v1", fabric ‖ name)`.
//! Concatenation is unambiguous without a separator because `fabric` is always
//! exactly 32 bytes, so no `(fabric, name)` pair can collide with another by
//! shifting the boundary.
//!
//! [`TopicTicket`] is the bootstrap blob a member shares out of band so a peer
//! can *find* the others: the fabric id, the topic name, and routing hints for
//! known peers. It is deliberately **unsigned** — iroh authenticates each peer
//! to its own key and topic admission (see [`crate::admission`]) proves roster
//! membership, so a tampered ticket can only fail to connect. It can never
//! admit anyone.

use std::net::SocketAddr;

use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::identity::NodeId;

/// The base64 alphabet for ticket text: URL-safe, no padding (matches
/// [`CapabilityTicket`](crate::CapabilityTicket) and [`Membership`](crate::Membership)).
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The blake3 `derive_key` context string for topic ids. Frozen: changing it
/// renames every topic in existence.
pub const TOPIC_ID_CONTEXT: &str = "wires topic-id v1";

/// A topic's 32-byte identifier, derived from `(fabric, name)`.
///
/// Serializes as lowercase hex, like [`NodeId`], so canonical JSON stays
/// deterministic. The same 32 bytes are handed to iroh-gossip as its own topic
/// id, so the gossip mesh and the wires topic are one namespace.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TopicId([u8; 32]);

impl TopicId {
    /// Derive the topic id for `name` under the fabric rooted at `fabric`.
    ///
    /// `blake3::derive_key(TOPIC_ID_CONTEXT, fabric_bytes ‖ name_utf8)`.
    ///
    /// ```
    /// use library::{NodeIdentity, TopicId};
    /// let fabric = NodeIdentity::from_seed([1u8; 32]).node_id();
    /// // Deriving is pure: two members who type the same name agree.
    /// assert_eq!(TopicId::derive(fabric, "ops"), TopicId::derive(fabric, "ops"));
    /// // The name and the fabric both scope the result.
    /// assert_ne!(TopicId::derive(fabric, "ops"), TopicId::derive(fabric, "eng"));
    /// ```
    pub fn derive(fabric: NodeId, name: &str) -> TopicId {
        let mut material = Vec::with_capacity(32 + name.len());
        material.extend_from_slice(fabric.as_bytes());
        material.extend_from_slice(name.as_bytes());
        TopicId(blake3::derive_key(TOPIC_ID_CONTEXT, &material))
    }

    /// Borrow the raw 32 topic bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Construct a `TopicId` from raw bytes (e.g. back from iroh-gossip).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Lowercase-hex rendering of the topic id — also the on-disk file stem for
    /// this topic's store and control socket.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a `TopicId` from its lowercase-hex rendering (the inverse of
    /// [`hex`](Self::hex)).
    ///
    /// Returns [`crate::Error::BadHex`] for non-hex text and
    /// [`crate::Error::BadKeyLength`] when the decoded byte count is not 32.
    pub fn from_hex(s: &str) -> Result<TopicId> {
        let bytes = hex::decode(s)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| crate::error::Error::BadKeyLength)?;
        Ok(TopicId(arr))
    }
}

impl Serialize for TopicId {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for TopicId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("TopicId expects 32 bytes"))?;
        Ok(TopicId(arr))
    }
}

/// A routing hint for one peer on a topic: whom to dial and where it was last
/// seen. Unsigned — see the module docs.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TopicPeer {
    /// The peer's node id (what iroh authenticates against).
    pub node: NodeId,
    /// Direct socket addresses the peer was reachable at; empty means "resolve
    /// via discovery / relay".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addrs: Vec<SocketAddr>,
    /// A relay URL to reach the peer through, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
}

impl TopicPeer {
    /// A peer hint with no addresses and no relay (discovery-only).
    pub fn new(node: NodeId) -> Self {
        Self {
            node,
            addrs: Vec::new(),
            relay_url: None,
        }
    }

    /// Attach direct socket addresses for this peer.
    pub fn with_addrs(mut self, addrs: Vec<SocketAddr>) -> Self {
        self.addrs = addrs;
        self
    }

    /// Attach a relay URL for this peer.
    pub fn with_relay_url(mut self, relay_url: Option<String>) -> Self {
        self.relay_url = relay_url;
        self
    }
}

/// The bootstrap blob for joining a topic: which fabric, which topic name, and
/// where to find peers already on it.
///
/// Text form is base64url-no-pad canonical JSON, like
/// [`CapabilityTicket`](crate::CapabilityTicket). Entirely unsigned routing
/// hints; membership is proved by admission, not by holding this.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TopicTicket {
    /// The fabric root's node id — the first half of the topic derivation.
    pub fabric: NodeId,
    /// The human-typed topic name — the second half of the derivation.
    pub name: String,
    /// Peers known to be on the topic, with their routing hints.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<TopicPeer>,
}

impl TopicTicket {
    /// A ticket for `name` under `fabric`, advertising `peers`.
    pub fn new(fabric: NodeId, name: impl Into<String>, peers: Vec<TopicPeer>) -> Self {
        Self {
            fabric,
            name: name.into(),
            peers,
        }
    }

    /// The topic id this ticket names (`TopicId::derive(fabric, name)`).
    pub fn topic_id(&self) -> TopicId {
        TopicId::derive(self.fabric, &self.name)
    }

    /// Encode to the base64url (no-pad) text form shared out of band.
    ///
    /// ```
    /// use library::{NodeIdentity, TopicPeer, TopicTicket};
    /// let fabric = NodeIdentity::from_seed([1u8; 32]).node_id();
    /// let peer = TopicPeer::new(NodeIdentity::from_seed([2u8; 32]).node_id());
    /// let ticket = TopicTicket::new(fabric, "ops", vec![peer]);
    /// assert_eq!(TopicTicket::decode(&ticket.encode().unwrap()).unwrap(), ticket);
    /// ```
    pub fn encode(&self) -> Result<String> {
        Ok(B64.encode(canonical_bytes(self)?))
    }

    /// Decode from the base64url (no-pad) text form.
    ///
    /// Returns [`crate::Error::TicketDecode`] for non-base64 text and
    /// [`crate::Error::Decode`] when the bytes are not a ticket.
    pub fn decode(text: &str) -> Result<TopicTicket> {
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

    fn peer() -> impl Strategy<Value = TopicPeer> {
        (seed(), any::<bool>(), any::<bool>()).prop_map(|(s, with_addrs, with_relay)| {
            let node = NodeIdentity::from_seed(s).node_id();
            let addrs = if with_addrs {
                vec![
                    "127.0.0.1:3340".parse().unwrap(),
                    "[2001:db8::1]:4433".parse().unwrap(),
                ]
            } else {
                Vec::new()
            };
            TopicPeer::new(node)
                .with_addrs(addrs)
                .with_relay_url(with_relay.then(|| "http://relay.example:3340".to_string()))
        })
    }

    proptest! {
        /// Derivation is a pure function of `(fabric, name)`.
        #[test]
        fn derive_is_deterministic(fs in seed(), name in ".*") {
            let fabric = NodeIdentity::from_seed(fs).node_id();
            prop_assert_eq!(TopicId::derive(fabric, &name), TopicId::derive(fabric, &name));
        }

        /// Different names under one fabric are different topics.
        #[test]
        fn distinct_names_are_distinct_topics(fs in seed(), a in ".*", b in ".*") {
            prop_assume!(a != b);
            let fabric = NodeIdentity::from_seed(fs).node_id();
            prop_assert_ne!(TopicId::derive(fabric, &a), TopicId::derive(fabric, &b));
        }

        /// The same name under different fabrics is a different topic — the
        /// scoping property that keeps two fabrics' `ops` channels apart.
        #[test]
        fn distinct_fabrics_are_distinct_topics(a in seed(), b in seed(), name in ".*") {
            prop_assume!(a != b);
            let (fa, fb) = (
                NodeIdentity::from_seed(a).node_id(),
                NodeIdentity::from_seed(b).node_id(),
            );
            prop_assert_ne!(TopicId::derive(fa, &name), TopicId::derive(fb, &name));
        }

        /// Concatenation is unambiguous because `fabric` is fixed-width: no
        /// `(fabric, name)` pair collides with another by shifting the
        /// boundary. Prefixing the name with an extra byte cannot reproduce
        /// the id.
        #[test]
        fn derivation_boundary_is_unambiguous(fs in seed(), name in "[a-z]{0,8}", extra in "[a-z]") {
            let fabric = NodeIdentity::from_seed(fs).node_id();
            let shifted = format!("{extra}{name}");
            prop_assert_ne!(
                TopicId::derive(fabric, &name),
                TopicId::derive(fabric, &shifted)
            );
        }

        /// `TopicId` survives a serde (hex-string) round-trip.
        #[test]
        fn topic_id_serde_roundtrips(fs in seed(), name in ".*") {
            let id = TopicId::derive(NodeIdentity::from_seed(fs).node_id(), &name);
            let json = serde_json::to_string(&id).unwrap();
            let back: TopicId = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(id, back);
        }

        /// `TopicId::from_hex` inverts `TopicId::hex`, and `from_bytes` inverts
        /// `as_bytes`.
        #[test]
        fn topic_id_hex_and_bytes_roundtrip(fs in seed(), name in ".*") {
            let id = TopicId::derive(NodeIdentity::from_seed(fs).node_id(), &name);
            prop_assert_eq!(TopicId::from_hex(&id.hex()).unwrap(), id);
            prop_assert_eq!(TopicId::from_bytes(*id.as_bytes()), id);
        }

        /// A ticket survives an encode/decode round-trip unchanged, and the
        /// decoded ticket names the same topic.
        #[test]
        fn ticket_roundtrips(fs in seed(), name in ".*", peers in proptest::collection::vec(peer(), 0..4)) {
            let fabric = NodeIdentity::from_seed(fs).node_id();
            let ticket = TopicTicket::new(fabric, name, peers);
            let decoded = TopicTicket::decode(&ticket.encode().unwrap()).unwrap();
            prop_assert_eq!(&decoded, &ticket);
            prop_assert_eq!(decoded.topic_id(), ticket.topic_id());
        }

        /// Arbitrary text decodes to an `Err`, never a panic.
        #[test]
        fn garbage_decode_never_panics(s in ".*") {
            let _ = TopicTicket::decode(&s);
        }

        /// Arbitrary text hex-parses to an `Err`, never a panic.
        #[test]
        fn garbage_from_hex_never_panics(s in ".*") {
            let _ = TopicId::from_hex(&s);
        }
    }

    /// Known answer: the derivation for a fixed `(fabric, name)` is frozen.
    /// Changing [`TOPIC_ID_CONTEXT`], the concatenation order, or the hash
    /// renames every topic in existence, so the exact bytes are pinned here.
    #[test]
    fn derive_known_answer() {
        let fabric = NodeIdentity::from_seed([1u8; 32]).node_id();
        assert_eq!(
            fabric.hex(),
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
        );
        assert_eq!(
            TopicId::derive(fabric, "ops").hex(),
            "d8aef584e4dc206686ba2c10f4fdc398fe217f0b51272e9993dee4f9f1f7cb19",
        );
    }

    /// The derivation matches the documented formula computed a second way
    /// (streaming `Hasher::new_derive_key` instead of the one-shot
    /// `derive_key`), so the known answer above is not merely self-consistent.
    #[test]
    fn derive_matches_documented_formula() {
        let fabric = NodeIdentity::from_seed([1u8; 32]).node_id();
        let mut hasher = blake3::Hasher::new_derive_key(TOPIC_ID_CONTEXT);
        hasher.update(fabric.as_bytes());
        hasher.update(b"ops");
        let expected: [u8; 32] = *hasher.finalize().as_bytes();
        assert_eq!(TopicId::derive(fabric, "ops").as_bytes(), &expected);
    }

    /// The context string is frozen (a rename is a fabric-wide breaking change).
    #[test]
    fn context_string_is_frozen() {
        assert_eq!(TOPIC_ID_CONTEXT, "wires topic-id v1");
    }

    #[test]
    fn topic_id_serializes_as_hex_string() {
        let id = TopicId::from_bytes([0u8; 32]);
        assert_eq!(
            serde_json::to_string(&id).unwrap(),
            format!("\"{}\"", "0".repeat(64))
        );
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        assert!(matches!(TopicId::from_hex("00"), Err(Error::BadKeyLength)));
    }

    #[test]
    fn from_hex_rejects_non_hex() {
        assert!(matches!(
            TopicId::from_hex(&"z".repeat(64)),
            Err(Error::BadHex(_))
        ));
    }

    fn fixture() -> TopicTicket {
        let fabric = NodeIdentity::from_seed([1u8; 32]).node_id();
        let peer = TopicPeer::new(NodeIdentity::from_seed([2u8; 32]).node_id());
        TopicTicket::new(fabric, "ops", vec![peer])
    }

    #[test]
    fn routing_hints_round_trip() {
        let fabric = NodeIdentity::from_seed([1u8; 32]).node_id();
        let peer = TopicPeer::new(NodeIdentity::from_seed([2u8; 32]).node_id())
            .with_addrs(vec![
                "127.0.0.1:3340".parse().unwrap(),
                "[2001:db8::1]:4433".parse().unwrap(),
            ])
            .with_relay_url(Some("http://relay.example:3340".to_string()));
        let ticket = TopicTicket::new(fabric, "ops", vec![peer]);
        let decoded = TopicTicket::decode(&ticket.encode().unwrap()).unwrap();
        assert_eq!(decoded, ticket);
        assert_eq!(decoded.peers[0].addrs.len(), 2);
        assert_eq!(
            decoded.peers[0].relay_url.as_deref(),
            Some("http://relay.example:3340")
        );
    }

    /// `skip_serializing_if` means a hintless ticket encodes without the
    /// `peers` / `addrs` / `relay_url` keys, and decoding fills the defaults.
    #[test]
    fn hintless_ticket_decodes_with_empty_defaults() {
        let fabric = NodeIdentity::from_seed([1u8; 32]).node_id();
        let bare = TopicTicket::new(fabric, "ops", Vec::new());
        let json = String::from_utf8(canonical_bytes(&bare).unwrap()).unwrap();
        assert!(!json.contains("peers"), "{json}");
        assert!(
            TopicTicket::decode(&bare.encode().unwrap())
                .unwrap()
                .peers
                .is_empty()
        );

        let decoded = TopicTicket::decode(&fixture().encode().unwrap()).unwrap();
        assert!(decoded.peers[0].addrs.is_empty());
        assert!(decoded.peers[0].relay_url.is_none());
    }

    /// A ticket's `topic_id()` is exactly `TopicId::derive(fabric, name)` — the
    /// ticket carries no independent id that could disagree with it.
    #[test]
    fn ticket_topic_id_is_the_derivation() {
        let t = fixture();
        assert_eq!(t.topic_id(), TopicId::derive(t.fabric, &t.name));
    }

    /// The ticket is unsigned by construction: tampering with the peer list
    /// still decodes cleanly (it can only fail to connect, never admit).
    #[test]
    fn tampered_ticket_still_decodes_because_it_is_unsigned() {
        let mut t = fixture();
        t.peers[0].node = NodeIdentity::from_seed([9u8; 32]).node_id();
        assert_eq!(TopicTicket::decode(&t.encode().unwrap()).unwrap(), t);
    }
}

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

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::Result;
use crate::identity::NodeId;

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
    pub fn derive(fabric: NodeId, name: &str) -> TopicId {
        todo!("derive_key over fabric bytes concatenated with the name")
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
    pub fn encode(&self) -> Result<String> {
        todo!("base64url-no-pad of the ticket's canonical JSON")
    }

    /// Decode from the base64url (no-pad) text form.
    pub fn decode(text: &str) -> Result<TopicTicket> {
        todo!("base64url decode then JSON parse")
    }
}

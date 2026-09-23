//! Host announcements: which tools a host serves, readable only by the members
//! allowed to use them.
//!
//! A host publishes a [`HostAnnouncement`] on its channel (as
//! [`ChannelRecord::Host`](crate::ChannelRecord::Host)) at startup, when its
//! audience changes, and on a heartbeat. The channel already encrypts it to
//! every roster member; the announcement adds a second, narrower layer:
//!
//! - [`open`](HostAnnouncement::open) — a [`HostListing`] any channel member
//!   may read: the tools the host's policy lets *every* member run.
//! - [`sealed`](HostAnnouncement::sealed) — one [`SealedListing`] per member
//!   whose verified identity earns it more, each sealed to that member's node
//!   key alone with the same ephemeral-X25519 construction as
//!   [`SealedFabricKey`](crate::SealedFabricKey), under its own frozen
//!   context [`ANNOUNCE_CONTEXT`].
//!
//! Sealed entries are **anonymous**: they carry no recipient id. A reader
//! trial-opens each one with its own key ([`HostAnnouncement::listing_for`]),
//! so a member who is not allowed learns that an announcement exists, from
//! which host, when, how many entries it has and roughly how large they are
//! (plaintexts are padded to [`LISTING_PAD`]-byte buckets) — and nothing about
//! which tools, or who else may use them. The AAD binds each entry to its
//! `(host, at_ms)`, so an entry cannot be lifted into another host's
//! announcement or an older one of the same host.
//!
//! Visibility is privacy, not access control: the host still decides every
//! call itself. A member who guesses a tool name it cannot see gets a proper
//! refusal from the host.
//!
//! ```
//! use library::{HostAnnouncement, HostListing, ListedTool, NodeIdentity, SealedListing, ToolName};
//! let host = NodeIdentity::generate();
//! let analyst = NodeIdentity::generate();
//! let stranger = NodeIdentity::generate();
//! let listing = HostListing {
//!     tools: vec![ListedTool { name: ToolName::new("db_query").unwrap(), description: "SQL".into() }],
//!     ..HostListing::default()
//! };
//! let entry = SealedListing::seal(host.node_id(), 7, &analyst.node_id(), &listing).unwrap();
//! let ann = HostAnnouncement::new(host.node_id(), 7, 600_000, None, vec![entry]);
//! assert_eq!(ann.listing_for(&analyst), Some(listing));
//! assert_eq!(ann.listing_for(&stranger), None);
//! ```

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::fabric_key::{SealedBox, open_box, seal_box};
use crate::identity::{NodeId, NodeIdentity};
use crate::invoke::ToolName;

/// The current (and only) sealed-listing format, bound into every entry's AAD.
pub const ANNOUNCE_V1: u8 = 1;

/// The blake3 `derive_key` context for a sealed listing's AEAD key. Frozen,
/// and distinct from [`SEALED_KEY_CONTEXT`](crate::SEALED_KEY_CONTEXT), so a
/// sealed fabric key never opens as a listing or the other way round.
pub const ANNOUNCE_CONTEXT: &str = "wires sealed-announcement v1";

/// Sealed plaintexts are space-padded up to a multiple of this many bytes, so
/// an entry's size says little about how many tools it names.
pub const LISTING_PAD: usize = 256;

/// One tool as a host announces it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ListedTool {
    /// The name callers run it by (`wires call <name>`).
    pub name: ToolName,
    /// One line saying what it does (`host.json`'s `description`).
    #[serde(default)]
    pub description: String,
}

/// What one reader of an announcement may see: tools, and how to reach the
/// host that serves them.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct HostListing {
    /// The tools, in the host's order.
    #[serde(default)]
    pub tools: Vec<ListedTool>,
    /// Direct socket addresses the host was reachable at when it announced.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addrs: Vec<SocketAddr>,
    /// The relay the host is reachable through, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
}

impl HostListing {
    /// `self`'s tools followed by those of `other` it does not already name;
    /// the dial hints are `self`'s when it has any, else `other`'s.
    pub fn merged(mut self, other: HostListing) -> HostListing {
        for tool in other.tools {
            if !self.tools.iter().any(|t| t.name == tool.name) {
                self.tools.push(tool);
            }
        }
        if self.addrs.is_empty() {
            self.addrs = other.addrs;
        }
        if self.relay_url.is_none() {
            self.relay_url = other.relay_url;
        }
        self
    }
}

/// The AEAD associated data of one sealed entry (canonical JSON).
#[derive(Serialize)]
struct ListingContext<'a> {
    format: u8,
    host: &'a NodeId,
    at_ms: i64,
}

impl ListingContext<'_> {
    fn aad(&self) -> Result<Vec<u8>> {
        canonical_bytes(self)
    }
}

/// A [`HostListing`] sealed to one member, anonymously: the blob is
/// `ephemeral_pub(32) ‖ ct+tag` and names no recipient.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SealedListing(SealedBox);

impl SealedListing {
    /// Seal `listing` to `member` for the announcement `(host, at_ms)`.
    ///
    /// [`Error::SealedKeyOpen`] when `member` is not a usable node key (not an
    /// Ed25519 point, or a weak one); [`Error::Encode`] if the listing does not
    /// encode.
    pub fn seal(host: NodeId, at_ms: i64, member: &NodeId, listing: &HostListing) -> Result<Self> {
        let aad = ListingContext {
            format: ANNOUNCE_V1,
            host: &host,
            at_ms,
        }
        .aad()?;
        let mut plaintext = serde_json::to_vec(listing).map_err(Error::Encode)?;
        let padded = plaintext.len().div_ceil(LISTING_PAD).max(1) * LISTING_PAD;
        plaintext.resize(padded, b' ');
        Ok(Self(seal_box(member, ANNOUNCE_CONTEXT, &aad, &plaintext)?))
    }

    /// Open this entry as `me`, for the announcement `(host, at_ms)`.
    ///
    /// [`Error::SealedKeyOpen`] when it is not for `me` (the ordinary case
    /// while trial-opening) or was moved from another announcement;
    /// [`Error::Decode`] if it opened but holds no listing.
    pub fn open(&self, host: NodeId, at_ms: i64, me: &NodeIdentity) -> Result<HostListing> {
        let aad = ListingContext {
            format: ANNOUNCE_V1,
            host: &host,
            at_ms,
        }
        .aad()?;
        let plaintext = open_box(me, ANNOUNCE_CONTEXT, &aad, &self.0)?;
        serde_json::from_slice(&plaintext).map_err(Error::Decode)
    }

    /// The sealed blob's size in bytes (what any member can see).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the blob is empty (only ever true for a malformed entry).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A host's announcement of what it serves. See the module docs.
///
/// Carried as [`ChannelRecord::Host`](crate::ChannelRecord::Host); a reader
/// must check that the envelope's sender **is** `node` (only a host announces
/// itself), the same rule as identity claims.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HostAnnouncement {
    /// The host's node id — what a caller dials.
    pub node: NodeId,
    /// When the host announced, unix milliseconds (sender-chosen).
    pub at_ms: i64,
    /// The host's heartbeat interval; a reader calls the host stale after
    /// three of them without a newer announcement. 0 = unknown.
    #[serde(default)]
    pub heartbeat_ms: u64,
    /// What every channel member may see, if anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open: Option<HostListing>,
    /// One anonymous entry per member allowed more than [`open`](Self::open).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sealed: Vec<SealedListing>,
}

impl HostAnnouncement {
    /// Assemble an announcement. The sealed entries are shuffled, so their
    /// order says nothing about who they are for.
    pub fn new(
        node: NodeId,
        at_ms: i64,
        heartbeat_ms: u64,
        open: Option<HostListing>,
        mut sealed: Vec<SealedListing>,
    ) -> Self {
        use rand::seq::SliceRandom;
        sealed.shuffle(&mut rand::rngs::OsRng);
        Self {
            node,
            at_ms,
            heartbeat_ms,
            open,
            sealed,
        }
    }

    /// What `me` may see: the open listing merged with the first sealed entry
    /// that opens for `me`. `None` when there is neither — the announcement
    /// shows `me` nothing but that it exists.
    pub fn listing_for(&self, me: &NodeIdentity) -> Option<HostListing> {
        let mine = self
            .sealed
            .iter()
            .find_map(|entry| entry.open(self.node, self.at_ms, me).ok());
        match (mine, self.open.clone()) {
            (Some(mine), Some(open)) => Some(mine.merged(open)),
            (Some(mine), None) => Some(mine),
            (None, open) => open,
        }
    }

    /// Whether the host is stale at `now_ms`: more than three heartbeats since
    /// it announced. An announcement without a heartbeat is never stale.
    pub fn is_stale(&self, now_ms: i64) -> bool {
        self.heartbeat_ms > 0
            && now_ms.saturating_sub(self.at_ms) > (self.heartbeat_ms as i64).saturating_mul(3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn id(seed: u8) -> NodeIdentity {
        NodeIdentity::from_seed([seed; 32])
    }

    fn tool(name: &str) -> ListedTool {
        ListedTool {
            name: ToolName::new(name).unwrap(),
            description: format!("{name} does things"),
        }
    }

    fn listing(names: &[&str]) -> HostListing {
        HostListing {
            tools: names.iter().map(|n| tool(n)).collect(),
            addrs: vec!["127.0.0.1:4433".parse().unwrap()],
            relay_url: None,
        }
    }

    fn tool_name() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9_-]{0,20}"
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// Only the member an entry was sealed to opens it; every other
        /// member sees exactly the open listing.
        #[test]
        fn only_the_recipient_opens_its_entry(
            hs in any::<[u8; 32]>(), ms in any::<[u8; 32]>(), os in any::<[u8; 32]>(),
            at in any::<i64>(), names in proptest::collection::vec(tool_name(), 0..8),
        ) {
            prop_assume!(ms != os);
            let host = NodeIdentity::from_seed(hs);
            let member = NodeIdentity::from_seed(ms);
            let other = NodeIdentity::from_seed(os);
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            let mine = listing(&names);
            let entry = SealedListing::seal(host.node_id(), at, &member.node_id(), &mine).unwrap();
            let ann = HostAnnouncement::new(host.node_id(), at, 1, None, vec![entry]);
            prop_assert_eq!(ann.listing_for(&member), Some(mine));
            prop_assert_eq!(ann.listing_for(&other), None);
        }

        /// A sealed entry's size is a multiple of the pad (plus the fixed
        /// ephemeral key and tag), whatever it lists.
        #[test]
        fn entry_sizes_are_bucketed(names in proptest::collection::vec(tool_name(), 0..6)) {
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            let entry = SealedListing::seal(id(1).node_id(), 0, &id(2).node_id(), &listing(&names)).unwrap();
            prop_assert_eq!((entry.len() - 32 - 16) % LISTING_PAD, 0);
        }

        /// Announcements round-trip through their record text.
        #[test]
        fn announcements_round_trip(at in any::<i64>(), hb in any::<u64>(), open in any::<bool>()) {
            let entry = SealedListing::seal(id(1).node_id(), at, &id(2).node_id(), &listing(&["a"])).unwrap();
            let ann = HostAnnouncement::new(
                id(1).node_id(), at, hb, open.then(|| listing(&["b"])), vec![entry],
            );
            let text = serde_json::to_string(&ann).unwrap();
            prop_assert_eq!(serde_json::from_str::<HostAnnouncement>(&text).unwrap(), ann);
        }
    }

    /// An entry lifted into another host's announcement, or into a later one
    /// of the same host, does not open: the AAD binds `(host, at_ms)`.
    #[test]
    fn entries_are_bound_to_their_announcement() {
        let (host, other_host, member) = (id(1), id(3), id(2));
        let entry =
            SealedListing::seal(host.node_id(), 10, &member.node_id(), &listing(&["x"])).unwrap();
        assert!(entry.open(host.node_id(), 10, &member).is_ok());
        assert!(matches!(
            entry.open(other_host.node_id(), 10, &member),
            Err(Error::SealedKeyOpen)
        ));
        assert!(matches!(
            entry.open(host.node_id(), 11, &member),
            Err(Error::SealedKeyOpen)
        ));
    }

    /// The open listing is everyone's; a member with an entry sees both,
    /// without duplicates.
    #[test]
    fn open_and_sealed_merge() {
        let (host, analyst, member) = (id(1), id(2), id(4));
        let entry = SealedListing::seal(
            host.node_id(),
            5,
            &analyst.node_id(),
            &listing(&["db_query", "status"]),
        )
        .unwrap();
        let ann = HostAnnouncement::new(
            host.node_id(),
            5,
            600_000,
            Some(listing(&["status"])),
            vec![entry],
        );
        let names = |l: HostListing| {
            l.tools
                .into_iter()
                .map(|t| t.name.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(ann.listing_for(&analyst).unwrap()),
            ["db_query", "status"]
        );
        assert_eq!(names(ann.listing_for(&member).unwrap()), ["status"]);
    }

    /// A fabric key sealed to a member is not a listing, even though the
    /// construction is shared: the contexts differ.
    #[test]
    fn a_sealed_fabric_key_never_opens_as_a_listing() {
        let (root, member) = (id(1), id(2));
        let sealed = crate::SealedFabricKey::seal(
            &root,
            member.node_id(),
            crate::RosterVersion(1),
            &crate::FabricKey::generate(),
        )
        .unwrap();
        let entry = SealedListing(sealed.sealed);
        assert!(entry.open(root.node_id(), 0, &member).is_err());
    }

    #[test]
    fn a_weak_member_key_is_refused_at_seal() {
        let mut weak = [0u8; 32];
        weak[0] = 1; // the identity point: small order
        let weak = NodeId::from_bytes(weak);
        assert!(matches!(
            SealedListing::seal(id(1).node_id(), 0, &weak, &listing(&["x"])),
            Err(Error::SealedKeyOpen)
        ));
    }

    #[test]
    fn staleness_is_three_heartbeats() {
        let ann = HostAnnouncement::new(id(1).node_id(), 1_000, 100, None, vec![]);
        assert!(!ann.is_stale(1_300));
        assert!(ann.is_stale(1_301));
        let forever = HostAnnouncement::new(id(1).node_id(), 0, 0, None, vec![]);
        assert!(!forever.is_stale(i64::MAX));
    }

    #[test]
    fn the_context_string_is_frozen() {
        assert_eq!(ANNOUNCE_CONTEXT, "wires sealed-announcement v1");
        assert_ne!(ANNOUNCE_CONTEXT, crate::SEALED_KEY_CONTEXT);
    }

    /// The wire shape, pinned: what a reader of another version must parse.
    #[test]
    fn record_shape() {
        let ann = HostAnnouncement::new(id(1).node_id(), 9, 600_000, None, vec![]);
        let v: serde_json::Value = serde_json::to_value(&ann).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"node": id(1).node_id().hex(), "at_ms": 9, "heartbeat_ms": 600_000})
        );
    }
}

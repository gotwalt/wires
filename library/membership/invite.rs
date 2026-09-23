//! The invite: everything a new member needs, in one pasteable token.
//!
//! `wires invite <node-id>` adds the node to the roster, commits, and bundles
//! the result for that one node: its [`Membership`], the new [`RosterHead`],
//! its [`RekeyEntry`] (inclusion proof + the fabric key sealed to it), the
//! channel name, and bootstrap peer hints. `wires join <token>` checks and
//! installs all of it.
//!
//! # Not a secret
//!
//! Every credential inside is either public (the membership, the head, the
//! proof) or sealed to the invitee's key (the fabric key). A copy in the wrong
//! hands admits nobody — admission binds every credential to the key the
//! transport authenticated — and opens nothing. What it does reveal is the
//! channel name and where its bootstrap peers were last seen.
//!
//! # Trust on first use
//!
//! A joiner has no fabric root to check the token against before it joins:
//! the token *introduces* the root (`membership.fabric`). [`Invite::verify`]
//! checks that every part is signed by that one root and addressed to this
//! node, which rules out a spliced or mis-addressed token, but not a token
//! from the wrong admin. The out-of-band channel the token travels over is
//! what vouches for the admin (see board card 18 for the open question of an
//! authenticated front door).
//!
//! ```
//! use library::{FabricKey, Invite, Membership, NodeIdentity, RekeyEntry, Roster, SealedFabricKey};
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let joiner = NodeIdentity::from_seed([2u8; 32]);
//! let mut roster = Roster::new(root.node_id());
//! roster.insert(joiner.node_id());
//! let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
//! let key = FabricKey::generate();
//! let entry = RekeyEntry {
//!     proof: proofs[0].1.clone(),
//!     key: SealedFabricKey::seal(&root, joiner.node_id(), head.version, &key).unwrap(),
//! };
//! let membership = Membership::mint(&root, joiner.node_id(), 0, i64::MAX).unwrap();
//! let invite = Invite::new("ops", membership, head, entry, Vec::new());
//!
//! let token = invite.encode().unwrap();
//! let received = Invite::decode(&token).unwrap();
//! assert_eq!(received.verify(&joiner, 0).unwrap(), key);
//! assert!(received.verify(&NodeIdentity::from_seed([3u8; 32]), 0).is_err());
//! ```

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::fabric_key::FabricKey;
use crate::identity::{NodeId, NodeIdentity};
use crate::membership::Membership;
use crate::policy::{Crl, check_inclusion};
use crate::rekey::{Rekey, RekeyEntry};
use crate::roster::RosterHead;
use crate::topic::TopicPeer;

/// The base64 alphabet for the token: URL-safe, no padding (as every other
/// wires token).
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The invite token's format discriminant.
pub const INVITE_V1: u8 = 1;

/// One node's invitation to a fabric. See the module docs.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Invite {
    /// Format discriminant; `= INVITE_V1`.
    pub format: u8,
    /// The channel (topic name) the fabric meets on, e.g. `ops`.
    pub channel: String,
    /// The invitee's root-signed membership; its `fabric` is the root.
    pub membership: Membership,
    /// The head of the commit that added the invitee.
    pub head: RosterHead,
    /// The invitee's inclusion proof and sealed fabric key under `head`.
    pub entry: RekeyEntry,
    /// Where the channel's members were last seen (unsigned hints).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<TopicPeer>,
}

impl Invite {
    /// Bundle an invitation (format [`INVITE_V1`]).
    pub fn new(
        channel: impl Into<String>,
        membership: Membership,
        head: RosterHead,
        entry: RekeyEntry,
        peers: Vec<TopicPeer>,
    ) -> Self {
        Self {
            format: INVITE_V1,
            channel: channel.into(),
            membership,
            head,
            entry,
            peers,
        }
    }

    /// The fabric root this invite introduces (`membership.fabric`).
    pub fn fabric(&self) -> NodeId {
        self.membership.fabric
    }

    /// Check the invite is for `me` and internally consistent, and open the
    /// fabric key sealed to `me`.
    ///
    /// The membership verifies under its own fabric root, names `me`, and is
    /// unexpired; the head, proof and sealed key form a valid
    /// [`Rekey`] entry under that same root; the entry is `me`'s; and the
    /// channel name is not empty.
    pub fn verify(&self, me: &NodeIdentity, now_unix: i64) -> Result<FabricKey> {
        if self.format != INVITE_V1 {
            return Err(Error::UnsupportedVersion);
        }
        if self.channel.trim().is_empty() {
            return Err(Error::InconsistentRekey("the invite names no channel"));
        }
        let fabric = self.fabric();
        check_inclusion(&self.membership, fabric, me.node_id(), now_unix, &Crl::new())?;
        if self.entry.member() != me.node_id() {
            return Err(Error::SubjectMismatch);
        }
        let rekey = Rekey::new(self.head.clone(), vec![self.entry.clone()]);
        rekey.verify(fabric, now_unix)?;
        self.entry.key.open(me, fabric)
    }

    /// Encode to the base64url (no-pad) token `wires join` takes.
    pub fn encode(&self) -> Result<String> {
        Ok(B64.encode(canonical_bytes(self)?))
    }

    /// Decode a token (surrounding whitespace is ignored).
    pub fn decode(text: &str) -> Result<Invite> {
        let bytes = B64.decode(text.trim())?;
        serde_json::from_slice(&bytes).map_err(Error::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fabric_key::SealedFabricKey;
    use crate::roster::Roster;
    use proptest::prelude::*;

    fn invite_for(joiner: &NodeIdentity, others: u8) -> (NodeIdentity, Invite, FabricKey) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut roster = Roster::new(root.node_id());
        roster.insert(joiner.node_id());
        for i in 0..others {
            roster.insert(NodeIdentity::from_seed([100 + i; 32]).node_id());
        }
        let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let proof = proofs
            .into_iter()
            .find(|(m, _)| *m == joiner.node_id())
            .unwrap()
            .1;
        let key = FabricKey::generate();
        let entry = RekeyEntry {
            proof,
            key: SealedFabricKey::seal(&root, joiner.node_id(), head.version, &key).unwrap(),
        };
        let membership = Membership::mint(&root, joiner.node_id(), 0, i64::MAX).unwrap();
        let peers = vec![TopicPeer::new(NodeIdentity::from_seed([5u8; 32]).node_id())];
        (
            root,
            Invite::new("ops", membership, head, entry, peers),
            key,
        )
    }

    #[test]
    fn the_invitee_opens_it_and_nobody_else_does() {
        let joiner = NodeIdentity::from_seed([2u8; 32]);
        let (_root, invite, key) = invite_for(&joiner, 2);
        assert_eq!(invite.verify(&joiner, 0).unwrap(), key);
        let other = NodeIdentity::from_seed([3u8; 32]);
        assert!(invite.verify(&other, 0).is_err());
    }

    #[test]
    fn a_spliced_invite_is_refused() {
        // Another fabric's membership around this fabric's commit.
        let joiner = NodeIdentity::from_seed([2u8; 32]);
        let (_root, mut invite, _key) = invite_for(&joiner, 1);
        let rogue = NodeIdentity::from_seed([66u8; 32]);
        invite.membership = Membership::mint(&rogue, joiner.node_id(), 0, i64::MAX).unwrap();
        assert!(invite.verify(&joiner, 0).is_err());
    }

    #[test]
    fn an_expired_membership_or_empty_channel_is_refused() {
        let joiner = NodeIdentity::from_seed([2u8; 32]);
        let (root, mut invite, _key) = invite_for(&joiner, 0);
        invite.membership = Membership::mint(&root, joiner.node_id(), 0, 10).unwrap();
        assert!(matches!(
            invite.verify(&joiner, 11),
            Err(Error::Expired { .. })
        ));

        let (_root, mut invite, _key) = invite_for(&joiner, 0);
        invite.channel = " ".into();
        assert!(matches!(
            invite.verify(&joiner, 0),
            Err(Error::InconsistentRekey(_))
        ));
    }

    #[test]
    fn garbage_is_a_decode_error() {
        assert!(Invite::decode("not a token!").is_err());
        assert!(Invite::decode("e30").is_err()); // "{}"
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Encode → decode is the identity, and the decoded token still
        /// verifies, for any roster size.
        #[test]
        fn tokens_round_trip(seed in proptest::array::uniform32(any::<u8>()), others in 0u8..6) {
            let joiner = NodeIdentity::from_seed(seed);
            let (_root, invite, key) = invite_for(&joiner, others);
            let token = invite.encode().unwrap();
            prop_assert!(!token.contains(['\n', ' ', '=']));
            let back = Invite::decode(&format!("  {token}\n")).unwrap();
            prop_assert_eq!(&back, &invite);
            prop_assert_eq!(back.verify(&joiner, 0).unwrap(), key);
        }
    }
}

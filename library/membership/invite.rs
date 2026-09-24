//! The invite: everything a new member needs, in one pasteable token.
//!
//! `wires invite <node-id>` adds the node to the admin-signed state and
//! bundles, for that one node: its root-signed [`Membership`], the new
//! [`SignedState`] (which names it as a member), and the admin's node id to
//! pull newer copies from. `wires join <token>` checks and installs all of
//! it.
//!
//! # Not a secret
//!
//! Everything inside is public: the membership and the state are signed, not
//! sealed. A copy in the wrong hands admits nobody, because every host binds
//! the membership to the key the transport authenticated. What it does
//! reveal is the member list, the role definitions and the service registry
//! (node ids, role matchers, service names and the roles they allow).
//!
//! # Trust on first use
//!
//! A joiner has no fabric root to check the token against before it joins:
//! the token *introduces* the root (`membership.fabric`). [`Invite::verify`]
//! checks that both parts are signed by that one root and name this node,
//! which rules out a spliced or mis-addressed token, but not a token from the
//! wrong admin. The out-of-band channel the token travels over is what
//! vouches for the admin (see board card 18 for the open question of an
//! authenticated front door).
//!
//! ```
//! use library::{Invite, Membership, NodeIdentity, State, StateVersion};
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let joiner = NodeIdentity::from_seed([2u8; 32]);
//! let mut state = State::new(root.node_id());
//! state.version = StateVersion(2);
//! state.not_after = i64::MAX;
//! state.members.insert(joiner.node_id());
//! let membership = Membership::mint(&root, joiner.node_id(), 0, i64::MAX).unwrap();
//! let invite = Invite::new(membership, state.sign(&root).unwrap(), root.node_id());
//!
//! let token = invite.encode().unwrap();
//! let received = Invite::decode(&token).unwrap();
//! assert!(received.verify(&joiner, 0).is_ok());
//! assert!(received.verify(&NodeIdentity::from_seed([3u8; 32]), 0).is_err());
//! ```

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::identity::{NodeId, NodeIdentity};
use crate::membership::Membership;
use crate::policy::check_inclusion;
use crate::state::SignedState;

/// The base64 alphabet for the token: URL-safe, no padding (as every other
/// wires token).
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The invite token's format discriminant. `2`: membership + signed state
/// (card 27); the channel-era `1` (roster head, sealed fabric key, bootstrap
/// peers) is refused.
pub const INVITE_V2: u8 = 2;

/// One node's invitation to a fabric. See the module docs.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invite {
    /// Format discriminant; `= INVITE_V2`.
    pub format: u8,
    /// The invitee's root-signed membership; its `fabric` is the root.
    pub membership: Membership,
    /// The current admin-signed state, naming the invitee as a member.
    pub state: SignedState,
    /// The admin's node id: where the invitee pulls newer states from (an
    /// unsigned hint).
    pub admin: NodeId,
}

impl Invite {
    /// Bundle an invitation (format [`INVITE_V2`]).
    pub fn new(membership: Membership, state: SignedState, admin: NodeId) -> Self {
        Self {
            format: INVITE_V2,
            membership,
            state,
            admin,
        }
    }

    /// The fabric root this invite introduces (`membership.fabric`).
    pub fn fabric(&self) -> NodeId {
        self.membership.fabric
    }

    /// Check the invite is for `me` and internally consistent: the
    /// membership verifies under its own fabric root, names `me`, and is
    /// unexpired; the state verifies under that same root, is fresh, and
    /// lists `me` as a member.
    pub fn verify(&self, me: &NodeIdentity, now_unix: i64) -> Result<()> {
        if self.format != INVITE_V2 {
            return Err(Error::UnsupportedVersion);
        }
        let fabric = self.fabric();
        check_inclusion(&self.membership, fabric, me.node_id(), now_unix)?;
        self.state.verify(fabric)?;
        self.state.check_fresh(now_unix)?;
        if !self.state.state.is_member(me.node_id()) {
            return Err(Error::SubjectMismatch);
        }
        Ok(())
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
    use crate::state::{State, StateVersion};
    use proptest::prelude::*;

    fn state_with(root: &NodeIdentity, members: &[NodeId]) -> State {
        let mut state = State::new(root.node_id());
        state.version = StateVersion(1);
        state.not_after = i64::MAX;
        state.members.extend(members.iter().copied());
        state
    }

    fn invite_for(joiner: &NodeIdentity, others: u8) -> (NodeIdentity, Invite) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut members = vec![joiner.node_id()];
        for i in 0..others {
            members.push(NodeIdentity::from_seed([100 + i; 32]).node_id());
        }
        let signed = state_with(&root, &members).sign(&root).unwrap();
        let membership = Membership::mint(&root, joiner.node_id(), 0, i64::MAX).unwrap();
        (
            NodeIdentity::from_seed([1u8; 32]),
            Invite::new(membership, signed, root.node_id()),
        )
    }

    #[test]
    fn the_invitee_verifies_it_and_nobody_else_does() {
        let joiner = NodeIdentity::from_seed([2u8; 32]);
        let (_root, invite) = invite_for(&joiner, 2);
        invite.verify(&joiner, 0).unwrap();
        let other = NodeIdentity::from_seed([3u8; 32]);
        assert!(invite.verify(&other, 0).is_err());
    }

    #[test]
    fn a_spliced_invite_is_refused() {
        // Another fabric's membership around this fabric's state.
        let joiner = NodeIdentity::from_seed([2u8; 32]);
        let (_root, mut invite) = invite_for(&joiner, 1);
        let rogue = NodeIdentity::from_seed([66u8; 32]);
        invite.membership = Membership::mint(&rogue, joiner.node_id(), 0, i64::MAX).unwrap();
        assert!(invite.verify(&joiner, 0).is_err());
    }

    #[test]
    fn an_expired_membership_is_refused() {
        let joiner = NodeIdentity::from_seed([2u8; 32]);
        let (root, mut invite) = invite_for(&joiner, 0);
        invite.membership = Membership::mint(&root, joiner.node_id(), 0, 10).unwrap();
        assert!(matches!(
            invite.verify(&joiner, 11),
            Err(Error::Expired { .. })
        ));
    }

    #[test]
    fn the_state_must_verify_and_name_the_invitee() {
        let joiner = NodeIdentity::from_seed([2u8; 32]);
        let (root, invite) = invite_for(&joiner, 0);
        // Not naming the invitee: refused.
        let mut bad = invite.clone();
        bad.state = state_with(&root, &[]).sign(&root).unwrap();
        assert!(bad.verify(&joiner, 0).is_err());
        // Signed by another root: refused.
        let rogue = NodeIdentity::from_seed([66u8; 32]);
        let mut forged = state_with(&root, &[joiner.node_id()]);
        forged.fabric = rogue.node_id();
        let mut bad = invite;
        bad.state = forged.sign(&rogue).unwrap();
        assert!(bad.verify(&joiner, 0).is_err());
    }

    #[test]
    fn garbage_and_old_tokens_are_refused() {
        assert!(Invite::decode("not a token!").is_err());
        assert!(Invite::decode("e30").is_err()); // "{}"
        let joiner = NodeIdentity::from_seed([2u8; 32]);
        let (_root, mut invite) = invite_for(&joiner, 0);
        invite.format = 1;
        assert!(matches!(
            invite.verify(&joiner, 0),
            Err(Error::UnsupportedVersion)
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Encode → decode is the identity, and the decoded token still
        /// verifies, for any member count.
        #[test]
        fn tokens_round_trip(seed in proptest::array::uniform32(any::<u8>()), others in 0u8..6) {
            let joiner = NodeIdentity::from_seed(seed);
            let (_root, invite) = invite_for(&joiner, others);
            let token = invite.encode().unwrap();
            prop_assert!(!token.contains(['\n', ' ', '=']));
            let back = Invite::decode(&format!("  {token}\n")).unwrap();
            prop_assert_eq!(&back, &invite);
            prop_assert!(back.verify(&joiner, 0).is_ok());
        }
    }
}

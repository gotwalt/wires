//! The invite: everything a new node needs, in one pasteable token.
//!
//! `wires invite <node-id>` mints the node's root-signed [`Membership`] (its
//! badge) and bundles it with the admin's current [`SignedPolicy`], whose
//! head names the fabric's directories: where the node fetches newer
//! policies. The policy doesn't change: the badge is what admits the node
//! (card 35), so inviting is no edit. `wires join <token>` checks and
//! installs all of it. (Card 37 shrinks the token to the badge and the
//! directory ids.)
//!
//! # Not a secret
//!
//! Everything inside is public: the membership and the policy are signed,
//! not sealed. A copy in the wrong hands admits nobody, because every host
//! binds the membership to the key the transport authenticated. What it does
//! reveal is the policy: the role definitions, the service registry (service
//! names, the roles they allow, their hosts' node ids), the bans, the
//! trusted IdPs and the directories. It names no other member.
//!
//! # Trust on first use
//!
//! A joiner has no fabric root to check the token against before it joins:
//! the token *introduces* the root (`membership.fabric`). [`Invite::verify`]
//! checks that both parts are signed by that one root, that the badge names
//! this node and the policy doesn't ban it, which rules out a spliced or
//! mis-addressed token, but not a token from the
//! wrong admin. The out-of-band channel the token travels over is what
//! vouches for the admin (see board card 18 for the open question of an
//! authenticated front door).
//!
//! ```
//! use library::{Invite, Membership, NodeIdentity, Policy, StateVersion};
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let joiner = NodeIdentity::from_seed([2u8; 32]);
//! let mut policy = Policy::new(root.node_id());
//! policy.version = StateVersion(2);
//! policy.not_after = i64::MAX;
//! let membership = Membership::mint(&root, joiner.node_id(), 0, i64::MAX).unwrap();
//! let invite = Invite::new(membership, policy.sign(&root).unwrap());
//!
//! let token = invite.encode().unwrap();
//! let received = Invite::decode(&token).unwrap();
//! assert!(received.verify(&joiner, 0).is_ok());
//! assert!(received.verify(&NodeIdentity::from_seed([3u8; 32]), 0).is_err());
//! ```

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::codec::B64;
use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::identity::{NodeId, NodeIdentity};
use crate::membership::Membership;
use crate::policy::check_admitted;
use crate::signed_policy::SignedPolicy;

/// The invite token's format discriminant (membership + signed policy). An
/// invite of any other format, including the state-carrying format 2, is
/// refused.
pub const INVITE_V3: u8 = 3;

/// One node's invitation to a fabric. See the module docs.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invite {
    /// Format discriminant; `= INVITE_V3`.
    pub format: u8,
    /// The invitee's root-signed membership; its `fabric` is the root.
    pub membership: Membership,
    /// The admin's current signed policy (it doesn't name the invitee). Its
    /// head lists the directories the invitee fetches newer ones from.
    pub policy: SignedPolicy,
}

impl Invite {
    /// Bundle an invitation (format [`INVITE_V3`]).
    pub fn new(membership: Membership, policy: SignedPolicy) -> Self {
        Self {
            format: INVITE_V3,
            membership,
            policy,
        }
    }

    /// The fabric root this invite introduces (`membership.fabric`).
    pub fn fabric(&self) -> NodeId {
        self.membership.fabric
    }

    /// The fabric's directories, in the admin's order: where the invitee
    /// fetches newer policies (from the signed head).
    pub fn directories(&self) -> &[NodeId] {
        &self.policy.head.head.directories
    }

    /// Check the invite is for `me` and internally consistent: the policy
    /// verifies under the membership's fabric root and is fresh, and under
    /// it `me` is admitted ([`check_admitted`]: the membership verifies
    /// under that root, names `me`, is unexpired, and the policy doesn't ban
    /// `me`).
    pub fn verify(&self, me: &NodeIdentity, now_unix: i64) -> Result<()> {
        if self.format != INVITE_V3 {
            return Err(Error::UnsupportedVersion);
        }
        let fabric = self.fabric();
        self.policy.verify(fabric)?;
        self.policy.head.check_fresh(now_unix)?;
        check_admitted(
            &self.membership,
            fabric,
            &self.policy.to_policy()?,
            me.node_id(),
            now_unix,
        )
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
    use crate::head::StateVersion;
    use crate::signed_policy::Policy;
    use proptest::prelude::*;

    /// A policy that bans `banned` and names one directory.
    fn policy_with(root: &NodeIdentity, banned: &[NodeId]) -> Policy {
        let mut policy = Policy::new(root.node_id());
        policy.version = StateVersion(1);
        policy.not_after = i64::MAX;
        policy.directories = vec![NodeIdentity::from_seed([30u8; 32]).node_id()];
        for b in banned {
            policy.ban(*b, i64::MAX);
        }
        policy
    }

    /// An invite for `joiner` whose policy bans `others` other nodes.
    fn invite_for(joiner: &NodeIdentity, others: u8) -> (NodeIdentity, Invite) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let banned: Vec<NodeId> = (0..others)
            .map(|i| NodeIdentity::from_seed([100 + i; 32]).node_id())
            .collect();
        let signed = policy_with(&root, &banned).sign(&root).unwrap();
        let membership = Membership::mint(&root, joiner.node_id(), 0, i64::MAX).unwrap();
        (root, Invite::new(membership, signed))
    }

    #[test]
    fn the_invitee_verifies_it_and_nobody_else_does() {
        let joiner = NodeIdentity::from_seed([2u8; 32]);
        let (_root, invite) = invite_for(&joiner, 2);
        invite.verify(&joiner, 0).unwrap();
        assert_eq!(
            invite.directories(),
            &[NodeIdentity::from_seed([30u8; 32]).node_id()]
        );
        let other = NodeIdentity::from_seed([3u8; 32]);
        assert!(invite.verify(&other, 0).is_err());
    }

    #[test]
    fn a_spliced_invite_is_refused() {
        // Another fabric's membership around this fabric's policy.
        let joiner = NodeIdentity::from_seed([2u8; 32]);
        let (_root, mut invite) = invite_for(&joiner, 1);
        let rogue = NodeIdentity::from_seed([66u8; 32]);
        invite.membership = Membership::mint(&rogue, joiner.node_id(), 0, i64::MAX).unwrap();
        assert!(invite.verify(&joiner, 0).is_err());
    }

    #[test]
    fn an_expired_membership_or_policy_is_refused() {
        let joiner = NodeIdentity::from_seed([2u8; 32]);
        let (root, mut invite) = invite_for(&joiner, 0);
        invite.membership = Membership::mint(&root, joiner.node_id(), 0, 10).unwrap();
        assert!(matches!(
            invite.verify(&joiner, 11),
            Err(Error::Expired { .. })
        ));
        let (root, mut invite) = invite_for(&joiner, 0);
        let mut p = policy_with(&root, &[]);
        p.not_after = 10;
        invite.policy = p.sign(&root).unwrap();
        assert!(matches!(
            invite.verify(&joiner, 11),
            Err(Error::Expired { not_after: 10 })
        ));
    }

    #[test]
    fn the_policy_must_verify_and_not_ban_the_invitee() {
        let joiner = NodeIdentity::from_seed([2u8; 32]);
        let (root, invite) = invite_for(&joiner, 0);
        // Banning the invitee: refused.
        let mut bad = invite.clone();
        bad.policy = policy_with(&root, &[joiner.node_id()]).sign(&root).unwrap();
        assert!(matches!(bad.verify(&joiner, 0), Err(Error::Banned { .. })));
        // Signed by another root: refused.
        let rogue = NodeIdentity::from_seed([66u8; 32]);
        let mut forged = policy_with(&root, &[]);
        forged.fabric = rogue.node_id();
        let mut bad = invite.clone();
        bad.policy = forged.sign(&rogue).unwrap();
        assert!(bad.verify(&joiner, 0).is_err());
        // An item the head doesn't commit to: refused.
        let mut bad = invite;
        bad.policy.items.pop();
        assert!(bad.verify(&joiner, 0).is_err());
    }

    #[test]
    fn garbage_and_unknown_formats_are_refused() {
        assert!(Invite::decode("not a token!").is_err());
        assert!(Invite::decode("e30").is_err()); // "{}"
        let joiner = NodeIdentity::from_seed([2u8; 32]);
        let (_root, mut invite) = invite_for(&joiner, 0);
        invite.format = 2;
        assert!(matches!(
            invite.verify(&joiner, 0),
            Err(Error::UnsupportedVersion)
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Encode → decode is the identity, and the decoded token still
        /// verifies, for any number of other nodes banned.
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

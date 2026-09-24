//! The invite: everything a new node needs, in one small pasteable token.
//!
//! `wires invite <node-id>` mints the node's root-signed [`Membership`] (its
//! badge, whose `fabric` is the root key) and bundles it with the fabric's
//! directory ids (where the node asks for the policy's head and, after
//! `wires login`, its view) and the fabric's [`LoginSettings`] (which IdP and
//! OAuth client `wires login` signs in with, so a joiner types no flags).
//! That is all a caller gets: under 1 KB, at any fabric size (card 37).
//! It holds no role, no ban and no service.
//!
//! A node the policy already names as a host or a directory also gets the
//! whole [`SignedPolicy`] ([`Invite::policy`]): such a node holds the whole
//! policy anyway, and a directory can't fetch its first copy from itself.
//!
//! The policy doesn't change: the badge is what admits the node (card 35),
//! so inviting is no edit. `wires join <token>` checks and installs it.
//!
//! # Not a secret
//!
//! Everything inside is public: the membership and the policy are signed,
//! not sealed, and the login settings name a *public* OAuth client (a
//! desktop client's secret is not confidential; a confidential one never
//! goes in an invite). A copy in the wrong hands admits nobody, because
//! every host binds the membership to the key the transport authenticated.
//!
//! # Trust on first use
//!
//! A joiner has no fabric root to check the token against before it joins:
//! the token *introduces* the root (`membership.fabric`). [`Invite::verify`]
//! checks that the badge is signed by that root and names this node (and,
//! when a policy rides along, that it is signed by that one root and doesn't
//! ban this node), which rules out a spliced or mis-addressed token, but not
//! a token from the wrong admin. The out-of-band channel the token travels
//! over is what vouches for the admin (see board card 18 for the open
//! question of an authenticated front door).
//!
//! ```
//! use library::{Audience, Invite, Issuer, LoginSettings, Membership, NodeIdentity};
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let joiner = NodeIdentity::from_seed([2u8; 32]);
//! let directory = NodeIdentity::from_seed([3u8; 32]).node_id();
//! let membership = Membership::mint(&root, joiner.node_id(), 0, i64::MAX).unwrap();
//! let login = LoginSettings {
//!     issuer: Issuer::new("https://accounts.google.com"),
//!     client_id: Audience::new("1234.apps.googleusercontent.com"),
//!     public_client_secret: None,
//! };
//! let invite = Invite::new(membership, vec![directory], Some(login));
//!
//! let token = invite.encode().unwrap();
//! assert!(token.len() < 1024);
//! let received = Invite::decode(&token).unwrap();
//! assert!(received.verify(&joiner, 0).is_ok());
//! assert!(received.verify(&NodeIdentity::from_seed([4u8; 32]), 0).is_err());
//! ```

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::codec::B64;
use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::identity::{NodeId, NodeIdentity};
use crate::idp::{Audience, Issuer};
use crate::membership::Membership;
use crate::policy::{check_admitted, check_inclusion};
use crate::signed_policy::SignedPolicy;

/// The invite token's format discriminant (badge + directory ids + login
/// settings, and the whole policy only for a host or directory). An invite
/// of any other format, including the policy-carrying format 3, is refused.
pub const INVITE_V4: u8 = 4;

/// The most directory ids an invite carries: enough to reach one when
/// another is down, and a token under 1 KB however many directories the
/// fabric runs (the head a joiner fetches lists them all).
pub const INVITE_MAX_DIRECTORIES: usize = 2;

/// A **public** OAuth client secret: the kind a Google "Desktop app" client
/// has, which its token endpoint still requires but which is not
/// confidential (it ships inside every copy of the app). Never a
/// confidential secret: an invite is not a secret.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicClientSecret(String);

impl PublicClientSecret {
    /// Wrap a public client secret.
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// The secret, as the token endpoint takes it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What `wires login` needs to sign in with no flags: the IdP, the OAuth
/// client registered there, and that client's public secret if it has one.
/// Flags and `$WIRES_OIDC_*` still override each.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginSettings {
    /// The OIDC issuer (one the policy's `issuer` items trust).
    pub issuer: Issuer,
    /// The OAuth client id `wires login` signs in under.
    pub client_id: Audience,
    /// The client's public secret, when the admin supplied one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_client_secret: Option<PublicClientSecret>,
}

/// One node's invitation to a fabric. See the module docs.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invite {
    /// Format discriminant; `= INVITE_V4`.
    pub format: u8,
    /// The invitee's root-signed membership; its `fabric` is the root.
    pub membership: Membership,
    /// The fabric's directories, in the admin's order: where the invitee
    /// asks for the head, its view, and (a host) the policy.
    pub directories: Vec<NodeId>,
    /// How `wires login` signs in, when the admin's policy trusts an IdP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<LoginSettings>,
    /// The whole signed policy, only for a node it names as a host or a
    /// directory (see the module docs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<SignedPolicy>,
}

impl Invite {
    /// A caller's invitation (format [`INVITE_V4`]): the badge, the first
    /// [`INVITE_MAX_DIRECTORIES`] of `directories` (the head the joiner
    /// asks one of them for names the rest), and the login settings; no
    /// policy.
    pub fn new(
        membership: Membership,
        mut directories: Vec<NodeId>,
        login: Option<LoginSettings>,
    ) -> Self {
        directories.truncate(INVITE_MAX_DIRECTORIES);
        Self {
            format: INVITE_V4,
            membership,
            directories,
            login,
            policy: None,
        }
    }

    /// Add the whole policy (for a host or directory; see the module docs).
    pub fn with_policy(mut self, policy: SignedPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// The fabric root this invite introduces (`membership.fabric`).
    pub fn fabric(&self) -> NodeId {
        self.membership.fabric
    }

    /// Check the invite is for `me` and internally consistent: the badge
    /// verifies under its own fabric root, names `me` and is unexpired; a
    /// policy that rides along verifies under that same root, is fresh, and
    /// doesn't ban `me` ([`check_admitted`]).
    pub fn verify(&self, me: &NodeIdentity, now_unix: i64) -> Result<()> {
        if self.format != INVITE_V4 {
            return Err(Error::UnsupportedVersion);
        }
        let fabric = self.fabric();
        match &self.policy {
            None => check_inclusion(&self.membership, fabric, me.node_id(), now_unix),
            Some(policy) => {
                policy.verify(fabric)?;
                policy.head.check_fresh(now_unix)?;
                check_admitted(
                    &self.membership,
                    fabric,
                    &policy.to_policy()?,
                    me.node_id(),
                    now_unix,
                )
            }
        }
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
    use crate::registry::{Service, ServiceName};
    use crate::role::RoleName;
    use crate::signed_policy::Policy;
    use proptest::prelude::*;

    fn root() -> NodeIdentity {
        NodeIdentity::from_seed([1u8; 32])
    }

    fn dirs(n: u8) -> Vec<NodeId> {
        (0..n)
            .map(|i| NodeIdentity::from_seed([30 + i; 32]).node_id())
            .collect()
    }

    /// Google-sized login settings: the longest a real invite carries.
    /// Fake values, split with `concat!` so secret scanners don't flag them.
    fn google() -> LoginSettings {
        LoginSettings {
            issuer: Issuer::new("https://accounts.google.com"),
            client_id: Audience::new(concat!(
                "123456789012-",
                "abcdefghijklmnopqrstuvwxyz012345",
                ".apps.googleusercontent.com"
            )),
            public_client_secret: Some(PublicClientSecret::new(concat!(
                "GOCSPX",
                "-abcdefghijklmnopqrstuvwxyz01"
            ))),
        }
    }

    /// A policy with `services` services and `bans` bans, one directory.
    fn big_policy(services: usize, bans: u8) -> SignedPolicy {
        let root = root();
        let mut policy = Policy::new(root.node_id());
        policy.version = StateVersion(1);
        policy.not_after = i64::MAX;
        policy.directories = dirs(2);
        let staff = RoleName::new("staff").unwrap();
        policy.issuers.insert(
            Issuer::new("https://idp"),
            crate::item::IssuerConfig {
                client_id: Audience::new("c"),
                audiences: vec![Audience::new("c")],
            },
        );
        policy.roles.insert(
            staff.clone(),
            vec![crate::role::Matcher::new("https://idp")],
        );
        for i in 0..services {
            policy.services.insert(
                ServiceName::new(format!("svc-{i}")).unwrap(),
                Service {
                    description: "a service with a description of ordinary length".into(),
                    allow: vec![staff.clone()],
                    hosts: dirs(1),
                    readers: vec![],
                },
            );
        }
        for b in 0..bans {
            policy.ban(NodeIdentity::from_seed([100 + b; 32]).node_id(), i64::MAX);
        }
        policy.sign(&root).unwrap()
    }

    fn caller_invite(joiner: &NodeIdentity) -> Invite {
        let membership = Membership::mint(&root(), joiner.node_id(), 0, i64::MAX).unwrap();
        Invite::new(membership, dirs(2), Some(google()))
    }

    #[test]
    fn the_invitee_verifies_it_and_nobody_else_does() {
        let joiner = NodeIdentity::from_seed([2u8; 32]);
        let invite = caller_invite(&joiner);
        invite.verify(&joiner, 0).unwrap();
        assert_eq!(invite.directories, dirs(2));
        let other = NodeIdentity::from_seed([3u8; 32]);
        assert!(invite.verify(&other, 0).is_err());
    }

    /// Card 37: a caller's token is under 1 KB whatever the fabric's size:
    /// nothing in it grows with the policy.
    #[test]
    fn a_callers_token_is_under_1_kb_at_any_fabric_size() {
        let joiner = NodeIdentity::from_seed([2u8; 32]);
        let small = caller_invite(&joiner).encode().unwrap();
        assert!(small.len() < 1024, "{} bytes", small.len());
        // The fabric grows; the caller's token doesn't (it never names a
        // service, a role or a ban).
        for services in [0, 100, 1000] {
            let _policy = big_policy(services, 30);
            assert_eq!(caller_invite(&joiner).encode().unwrap().len(), small.len());
        }
        // Nor do more directories: it carries at most two.
        let membership = Membership::mint(&root(), joiner.node_id(), 0, i64::MAX).unwrap();
        let many = Invite::new(membership, dirs(9), Some(google()));
        assert_eq!(many.directories, dirs(2));
        assert_eq!(many.encode().unwrap().len(), small.len());
    }

    #[test]
    fn a_hosts_invite_carries_the_policy_and_checks_it() {
        let joiner = NodeIdentity::from_seed([2u8; 32]);
        let invite = caller_invite(&joiner).with_policy(big_policy(3, 0));
        invite.verify(&joiner, 0).unwrap();
        // A policy that bans the invitee: refused.
        let mut banned =
            Policy::from_items(&big_policy(3, 0).head.head, &big_policy(3, 0).items).unwrap();
        banned.ban(joiner.node_id(), i64::MAX);
        let bad = caller_invite(&joiner).with_policy(banned.sign(&root()).unwrap());
        assert!(matches!(bad.verify(&joiner, 0), Err(Error::Banned { .. })));
        // Signed by another root: refused.
        let rogue = NodeIdentity::from_seed([66u8; 32]);
        let mut forged = Policy::new(rogue.node_id());
        forged.not_after = i64::MAX;
        let bad = caller_invite(&joiner).with_policy(forged.sign(&rogue).unwrap());
        assert!(bad.verify(&joiner, 0).is_err());
        // An item the head doesn't commit to: refused.
        let mut tampered = big_policy(3, 0);
        tampered.items.pop();
        let bad = caller_invite(&joiner).with_policy(tampered);
        assert!(bad.verify(&joiner, 0).is_err());
    }

    #[test]
    fn a_spliced_or_expired_invite_is_refused() {
        let joiner = NodeIdentity::from_seed([2u8; 32]);
        let rogue = NodeIdentity::from_seed([66u8; 32]);
        // Another fabric's policy around this fabric's badge.
        let mut forged = Policy::new(rogue.node_id());
        forged.not_after = i64::MAX;
        let spliced = caller_invite(&joiner).with_policy(forged.sign(&rogue).unwrap());
        assert!(spliced.verify(&joiner, 0).is_err());
        // An expired badge.
        let mut invite = caller_invite(&joiner);
        invite.membership = Membership::mint(&root(), joiner.node_id(), 0, 10).unwrap();
        assert!(matches!(
            invite.verify(&joiner, 11),
            Err(Error::Expired { .. })
        ));
    }

    #[test]
    fn garbage_and_unknown_formats_are_refused() {
        assert!(Invite::decode("not a token!").is_err());
        assert!(Invite::decode("e30").is_err()); // "{}"
        let joiner = NodeIdentity::from_seed([2u8; 32]);
        let mut invite = caller_invite(&joiner);
        invite.format = 3;
        assert!(matches!(
            invite.verify(&joiner, 0),
            Err(Error::UnsupportedVersion)
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Encode → decode is the identity, and the decoded token still
        /// verifies, with or without login settings and a policy.
        #[test]
        fn tokens_round_trip(
            seed in proptest::array::uniform32(any::<u8>()),
            n in 0u8..4,
            login in any::<bool>(),
            policy in any::<bool>(),
        ) {
            let joiner = NodeIdentity::from_seed(seed);
            let membership = Membership::mint(&root(), joiner.node_id(), 0, i64::MAX).unwrap();
            let mut invite = Invite::new(membership, dirs(n), login.then(google));
            if policy {
                invite = invite.with_policy(big_policy(2, 1));
            }
            let token = invite.encode().unwrap();
            prop_assert!(!token.contains(['\n', ' ', '=']));
            let back = Invite::decode(&format!("  {token}\n")).unwrap();
            prop_assert_eq!(&back, &invite);
            prop_assert!(back.verify(&joiner, 0).is_ok());
        }
    }
}

//! The whole policy: every item, as the admin edits it ([`Policy`]) and as
//! it is signed and published ([`SignedPolicy`]: the root-signed head and the
//! items it commits to). Card 36's replacement for the one-blob
//! [`State`](crate::State).
//!
//! The admin and the directories hold all of it; everyone else holds a
//! subset with proofs: a host its [`Slice`], a caller its [`View`], each cut
//! here as a pure function of the policy.
//!
//! [`Policy`] is typed maps, like the state, so an edit can't produce two
//! items with one key or a second settings item; [`Policy::items`] flattens
//! them into leaf order. [`Policy::validate`] carries over the state's rules
//! (every role a service names is defined, every matcher names a trusted
//! issuer, each host listed once) and adds the new kinds'.
//!
//! ```
//! use library::{
//!     IssuerConfig, Audience, Issuer, Matcher, NodeIdentity, Policy, RoleName, Service,
//!     ServiceName, StateVersion,
//! };
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let host = NodeIdentity::from_seed([2u8; 32]).node_id();
//! let idp = "https://accounts.google.com";
//! let mut policy = Policy::new(root.node_id());
//! policy.version = StateVersion(1);
//! policy.not_after = i64::MAX;
//! policy.issuers.insert(Issuer::new(idp), IssuerConfig {
//!     client_id: Audience::new("cli"),
//!     audiences: vec![Audience::new("cli")],
//! });
//! let staff = RoleName::new("staff").unwrap();
//! policy.roles.insert(staff.clone(), vec![Matcher::new(idp)]);
//! policy.services.insert(ServiceName::new("status").unwrap(), Service {
//!     description: "uptime".into(),
//!     allow: vec![staff],
//!     hosts: vec![host],
//!     readers: vec![],
//! });
//! let signed = policy.sign(&root).unwrap();
//! signed.verify(root.node_id()).unwrap();
//! assert_eq!(signed.head.head.item_count, 4); // role, service, issuer, settings
//! ```

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::head::{POLICY_V3, PolicyHead, SignedPolicyHead};
use crate::identity::{NodeId, NodeIdentity};
use crate::idp::{Issuer, Principal};
use crate::item::{Ban, IssuerConfig, Item, ItemKey, Settings};
use crate::merkle::{ItemHash, ItemTree};
use crate::registry::{Service, ServiceName};
use crate::role::{Matcher, RoleName};
use crate::slice::{ProvedItem, Slice, View, ViewEntry};
use crate::state::StateVersion;

/// The policy as the admin edits it: head fields plus every item, by kind.
/// See the module docs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The root's node id.
    pub fabric: NodeId,
    /// Monotonic version.
    pub version: StateVersion,
    /// When the admin signed it, unix seconds.
    pub issued: i64,
    /// Expiry, unix seconds, inclusive.
    pub not_after: i64,
    /// The directory nodes, in preference order, each once.
    pub directories: Vec<NodeId>,
    /// Role definitions: name → OR of matchers.
    pub roles: BTreeMap<RoleName, Vec<Matcher>>,
    /// The service registry.
    pub services: BTreeMap<ServiceName, Service>,
    /// Removed nodes, each until its badge would have expired.
    pub bans: BTreeMap<NodeId, Ban>,
    /// The trusted IdPs.
    pub issuers: BTreeMap<Issuer, IssuerConfig>,
    /// The fabric's settings.
    pub settings: Settings,
}

/// A signed policy: the root-signed head and every item it commits to, in
/// leaf order. What the admin publishes and a directory stores.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicy {
    /// The signed head.
    pub head: SignedPolicyHead,
    /// Every item, sorted by [`ItemKey`], each key once.
    pub items: Vec<Item>,
}

impl Policy {
    /// An empty policy for `fabric` at version 0, never valid (`not_after`
    /// 0), with default [`Settings`]: the starting point `wires init` fills
    /// in.
    pub fn new(fabric: NodeId) -> Policy {
        todo!("Policy::new {}", fabric.hex())
    }

    /// The structural rules the types can't say ([`Error::InvalidPolicy`]
    /// names the first one broken):
    ///
    /// - no directory is listed twice;
    /// - every role has matchers, and every matcher names a trusted issuer
    ///   (one with an `issuer` item);
    /// - every service's `allow` and `readers` name a defined role, and it
    ///   lists each host once;
    /// - every issuer is non-blank and accepts at least one non-blank
    ///   audience;
    /// - `settings.beat_secs > 0` and `settings.fresh_secs >= beat_secs`.
    pub fn validate(&self) -> Result<()> {
        todo!("Policy::validate")
    }

    /// Every item, in leaf ([`ItemKey`]) order.
    pub fn items(&self) -> Vec<Item> {
        todo!("Policy::items")
    }

    /// Rebuild a policy from a head's fields and its items (the inverse of
    /// [`items`](Self::items)). [`Error::InvalidPolicy`] if the items are not
    /// strictly in key order or hold no settings item.
    pub fn from_items(head: &PolicyHead, items: &[Item]) -> Result<Policy> {
        todo!("Policy::from_items {head:?} {}", items.len())
    }

    /// Validate, then sign as-is with the root key (the caller sets
    /// `version`, `issued` and `not_after`): the items' Merkle root and count
    /// go into the head. [`Error::FabricMismatch`] if `root` is not
    /// `fabric`.
    pub fn sign(&self, root: &NodeIdentity) -> Result<SignedPolicy> {
        todo!("Policy::sign {}", root.node_id().hex())
    }

    /// Whether `role` admits a caller presenting `principal`: a defined role
    /// one of whose matchers matches it. With no principal, or an undefined
    /// role, nothing admits (exactly [`role_admits`](crate::role_admits)).
    pub fn role_admits(&self, role: &RoleName, principal: Option<&Principal>) -> bool {
        todo!("Policy::role_admits {role} {principal:?}")
    }

    /// Whether `node` is banned at `now`.
    pub fn is_banned(&self, node: NodeId, now: i64) -> bool {
        todo!("Policy::is_banned {} {now}", node.hex())
    }
}

impl SignedPolicy {
    /// Verify the head under `root` ([`SignedPolicyHead::verify`]), that the
    /// items are strictly in key order and are exactly the tree the head
    /// commits to (count and root), then [`Policy::validate`]. Does not check
    /// freshness.
    pub fn verify(&self, root: NodeId) -> Result<()> {
        todo!("SignedPolicy::verify {}", root.hex())
    }

    /// The editable [`Policy`] this was signed from.
    pub fn to_policy(&self) -> Result<Policy> {
        Policy::from_items(&self.head.head, &self.items)
    }

    /// The Merkle tree over the items (one `O(n)` build; prove from it).
    pub fn tree(&self) -> Result<ItemTree> {
        todo!("SignedPolicy::tree")
    }

    /// `host`'s slice: the head and, with proofs, every service item naming
    /// `host`, every role those services' `allow` and `readers` name plus
    /// `extra_roles` (the roles its `host.json` names; undefined ones are
    /// skipped), every ban, every issuer, and the settings. Nothing else.
    pub fn slice_for_host(&self, host: NodeId, extra_roles: &[RoleName]) -> Result<Slice> {
        todo!("SignedPolicy::slice_for_host {} {extra_roles:?}", host.hex())
    }

    /// The view of a caller presenting `principal`: the head and, with
    /// proofs, each service item whose `allow` (marked `call`) or `readers`
    /// (marked `read`) admits it. No role, ban, issuer or settings, and no
    /// other service; with no principal, no entries (no role admits).
    pub fn view_for(&self, principal: Option<&Principal>) -> Result<View> {
        todo!("SignedPolicy::view_for {principal:?}")
    }
}

/// Whether `matchers` (a role's definition, if it has one) admit `principal`.
/// The one rule every admission check shares.
pub(crate) fn admits(matchers: Option<&[Matcher]>, principal: Option<&Principal>) -> bool {
    todo!("admits {matchers:?} {principal:?}")
}

#[cfg(test)]
mod tests {}

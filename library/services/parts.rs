//! The parts of the policy a directory hands out: a host's [`Slice`] and a
//! caller's [`View`] (cards 36 and 37), and the updates that move them from
//! one head to the next ([`SliceUpdate`], [`ViewUpdate`]).
//!
//! A part is the root-signed head, some items, and one [`MultiProof`] that
//! proves the **whole** set under that head, so the receiver checks all of it
//! against the head alone and a directory can neither forge an item nor serve
//! one from another head.
//!
//! What a part leaves out is the point: a host's slice holds no service that
//! doesn't name it and no role it doesn't need; a view holds no role, no ban
//! and no service its caller may not use. Both are cut by
//! [`SignedPolicy`](crate::SignedPolicy); a directory can still withhold,
//! which [`Fresh`](crate::Fresh) bounds.
//!
//! **Updates.** Every edit changes the tree's root, so a held proof never
//! carries over to a new head. An update therefore carries the new head, the
//! entries added or changed for this holder, the keys removed, and a new
//! multiproof over the holder's whole resulting set. The holder rebuilds the
//! set (held + changed − removed) and checks it all against the new head
//! ([`Slice::apply`]); after that every item it holds is proved under the new
//! head, never mixed with an older one. An update over an unchanged part is
//! the head and a multiproof: a few KB. A holder that can't apply one (it
//! missed a version, or the result doesn't prove) asks for the whole part.
//!
//! ```
//! use library::{Ban, NodeIdentity, Policy, StateVersion};
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let host = NodeIdentity::from_seed([2u8; 32]).node_id();
//! let mut policy = Policy::new(root.node_id());
//! policy.version = StateVersion(1);
//! policy.not_after = i64::MAX;
//! let v1 = policy.sign(&root).unwrap();
//! let slice = v1.slice_for_host(host, &[]).unwrap();
//! slice.verify(root.node_id()).unwrap();
//!
//! // The admin bans a node: the host receives the ban and a new proof.
//! policy.version = StateVersion(2);
//! policy.bans.insert(NodeIdentity::from_seed([9u8; 32]).node_id(), Ban { until: 100 });
//! let v2 = policy.sign(&root).unwrap();
//! let update = v2.slice_update(&slice, host, &[]).unwrap();
//! assert_eq!(update.changed.len(), 1);
//! let slice = slice.apply(&update, root.node_id()).unwrap();
//! assert_eq!(slice, v2.slice_for_host(host, &[]).unwrap());
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::head::SignedPolicyHead;
use crate::identity::NodeId;
use crate::idp::{Issuer, Principal};
use crate::item::{IssuerConfig, Item, ItemKey, Settings};
use crate::merkle::MultiProof;
use crate::registry::{Service, ServiceName};
use crate::role::{Matcher, RoleName};
use crate::signed_policy::admits;

/// A host's part of the policy. See the module docs and
/// [`SignedPolicy::slice_for_host`](crate::SignedPolicy::slice_for_host).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Slice {
    /// The root-signed head the items are proved under.
    pub head: SignedPolicyHead,
    /// The items, strictly in key order.
    pub items: Vec<Item>,
    /// Proves all of `items` under `head`.
    pub proof: MultiProof,
}

/// What moves a [`Slice`] to a newer head. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SliceUpdate {
    /// The new head.
    pub head: SignedPolicyHead,
    /// Items added to the slice or changed, in key order.
    pub changed: Vec<Item>,
    /// Keys the slice no longer holds, in order.
    pub removed: Vec<ItemKey>,
    /// Proves the whole resulting slice under `head`.
    pub proof: MultiProof,
}

impl Slice {
    /// Verify the head under `root`, that the items are strictly in key
    /// order and hold the settings, and the multiproof over all of them.
    /// Does not check freshness.
    pub fn verify(&self, root: NodeId) -> Result<()> {
        todo!("Slice::verify {}", root.hex())
    }

    /// The update that turns this slice into `newer` (the same host's slice
    /// under a newer head): what the directory sends a subscriber.
    pub fn update_to(&self, newer: &Slice) -> SliceUpdate {
        todo!("Slice::update_to {newer:?}")
    }

    /// Apply `update`: its head must verify under `root` and be no older
    /// than this one; every removed key must be held; the rebuilt set (held
    /// + changed − removed) must hold the settings and prove under the new
    /// head. Any failure is an error and this slice is unchanged: ask the
    /// directory for the whole slice.
    pub fn apply(&self, update: &SliceUpdate, root: NodeId) -> Result<Slice> {
        todo!("Slice::apply {update:?} {}", root.hex())
    }

    /// The fabric's settings (present in every verified slice).
    pub fn settings(&self) -> Option<&Settings> {
        self.items.iter().find_map(|item| match item {
            Item::Settings { body } => Some(body),
            _ => None,
        })
    }

    /// The service `name`, if this slice holds it.
    pub fn service(&self, name: &ServiceName) -> Option<&Service> {
        self.items.iter().find_map(|item| match item {
            Item::Service { key, body } if key == name => Some(body),
            _ => None,
        })
    }

    /// The matchers of role `name`, if this slice holds it.
    pub fn role(&self, name: &RoleName) -> Option<&[Matcher]> {
        self.items.iter().find_map(|item| match item {
            Item::Role { key, body } if key == name => Some(body.as_slice()),
            _ => None,
        })
    }

    /// The trusted issuer `iss`, if the policy names it.
    pub fn issuer(&self, iss: &Issuer) -> Option<&IssuerConfig> {
        self.items.iter().find_map(|item| match item {
            Item::Issuer { key, body } if key == iss => Some(body),
            _ => None,
        })
    }

    /// Whether `role` admits `principal`, by the roles this slice holds
    /// (same rule as [`role_admits`](crate::role_admits): no principal or
    /// an unheld role admits nothing).
    pub fn role_admits(&self, role: &RoleName, principal: Option<&Principal>) -> bool {
        admits(self.role(role), principal)
    }

    /// Whether `node` is banned at `now`.
    pub fn is_banned(&self, node: NodeId, now: i64) -> bool {
        self.items.iter().any(|item| match item {
            Item::Ban { key, body } => *key == node && body.holds(now),
            _ => false,
        })
    }

    /// Every item's key, in order.
    pub fn keys(&self) -> Vec<ItemKey> {
        self.items.iter().map(Item::key).collect()
    }
}

/// One service in a caller's [`View`], and what the caller may do with it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewEntry {
    /// The service item.
    pub item: Item,
    /// A role in its `allow` admits the caller.
    pub call: bool,
    /// A role in its `readers` admits the caller.
    pub read: bool,
}

impl ViewEntry {
    /// The service's name and entry (`None` if the item is not a service,
    /// which [`View::verify`] refuses).
    pub fn service(&self) -> Option<(&ServiceName, &Service)> {
        match &self.item {
            Item::Service { key, body } => Some((key, body)),
            _ => None,
        }
    }
}

/// A caller's part of the policy. See the module docs and
/// [`SignedPolicy::view_for`](crate::SignedPolicy::view_for).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct View {
    /// The root-signed head the entries are proved under.
    pub head: SignedPolicyHead,
    /// The services, strictly in name order.
    pub entries: Vec<ViewEntry>,
    /// Proves every entry's item under `head`.
    pub proof: MultiProof,
}

/// What moves a [`View`] to a newer head (or to new marks). See the module
/// docs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewUpdate {
    /// The new head.
    pub head: SignedPolicyHead,
    /// Entries added or changed (item or marks), in name order.
    pub changed: Vec<ViewEntry>,
    /// Keys the view no longer holds, in order.
    pub removed: Vec<ItemKey>,
    /// Proves every resulting entry's item under `head`.
    pub proof: MultiProof,
}

impl View {
    /// Verify the head under `root`, that every entry is a service marked
    /// `call` or `read`, strictly in name order, and the multiproof over all
    /// of them. Does not check freshness. (The marks are the directory's
    /// reading of roles the view doesn't carry; the host decides every call.)
    pub fn verify(&self, root: NodeId) -> Result<()> {
        todo!("View::verify {}", root.hex())
    }

    /// The update that turns this view into `newer`.
    pub fn update_to(&self, newer: &View) -> ViewUpdate {
        todo!("View::update_to {newer:?}")
    }

    /// Apply `update`, as [`Slice::apply`] does; the result must pass
    /// [`verify`](Self::verify)'s rules.
    pub fn apply(&self, update: &ViewUpdate, root: NodeId) -> Result<View> {
        todo!("View::apply {update:?} {}", root.hex())
    }

    /// The entry for service `name`, if the view holds it.
    pub fn entry(&self, name: &ServiceName) -> Option<&ViewEntry> {
        self.entries
            .iter()
            .find(|e| e.service().is_some_and(|(key, _)| key == name))
    }

    /// The entries whose name or description contains `query`, ignoring
    /// ASCII case (`wires services <query>`, card 37). A reading of the view;
    /// the view itself, and its proof, are unchanged.
    pub fn matching(&self, query: &str) -> Vec<&ViewEntry> {
        todo!("View::matching {query}")
    }
}

/// The set operations slices and views share: an entry is keyed and hashed
/// by its item.
trait Entry: Clone + PartialEq {
    fn item(&self) -> &Item;
}

impl Entry for Item {
    fn item(&self) -> &Item {
        self
    }
}

impl Entry for ViewEntry {
    fn item(&self) -> &Item {
        &self.item
    }
}

/// `(changed, removed)` from `old` to `new`: entries of `new` not equal in
/// `old`, and keys of `old` missing from `new`.
fn diff<E: Entry>(old: &[E], new: &[E]) -> (Vec<E>, Vec<ItemKey>) {
    todo!("diff {} {}", old.len(), new.len())
}

/// `held` + `changed` − `removed`, in key order. [`Error::InvalidPolicy`]
/// if a removed key isn't held, or a key is both changed and removed, or
/// changed twice.
fn merge<E: Entry>(held: &[E], changed: &[E], removed: &[ItemKey]) -> Result<Vec<E>> {
    todo!("merge {} {} {}", held.len(), changed.len(), removed.len())
}

/// The shared checks: `head` verifies under `root`, the entries are strictly
/// in key order, and `proof` proves all their items under `head`.
fn verify_set<E: Entry>(
    head: &SignedPolicyHead,
    entries: &[E],
    proof: &MultiProof,
    root: NodeId,
) -> Result<()> {
    todo!(
        "verify_set {head:?} {} {proof:?} {}",
        entries.len(),
        root.hex()
    )
}

/// [`Error::InvalidPolicy`] unless `newer` is the same fabric's head and no
/// older than `held`.
fn check_not_older(held: &SignedPolicyHead, newer: &SignedPolicyHead) -> Result<()> {
    todo!("check_not_older {held:?} {newer:?}")
}

#[cfg(test)]
mod tests {}

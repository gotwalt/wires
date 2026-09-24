//! The parts of the policy a directory hands out: a host's [`Slice`] and a
//! caller's [`View`] (cards 36 and 37). Each is the root-signed head plus
//! some items, every item with its [`InclusionProof`], so the receiver checks
//! all of it against the head alone and a directory can neither forge an
//! item nor serve one from another head.
//!
//! What a part leaves out is the point: a host's slice holds no service that
//! doesn't name it and no role it doesn't need; a view holds no role, no ban
//! and no service its caller may not use. Both are cut by
//! [`SignedPolicy`](crate::SignedPolicy); a directory can still withhold,
//! which [`Fresh`](crate::Fresh) bounds.
//!
//! ```
//! use library::{NodeIdentity, Policy, StateVersion};
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let host = NodeIdentity::from_seed([2u8; 32]).node_id();
//! let mut policy = Policy::new(root.node_id());
//! policy.version = StateVersion(1);
//! policy.not_after = i64::MAX;
//! let signed = policy.sign(&root).unwrap();
//! let slice = signed.slice_for_host(host, &[]).unwrap();
//! slice.verify(root.node_id()).unwrap();
//! assert_eq!(slice.settings(), Some(&policy.settings));
//! ```

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::head::{PolicyHead, SignedPolicyHead};
use crate::identity::NodeId;
use crate::idp::{Issuer, Principal};
use crate::item::{IssuerConfig, Item, ItemKey, Settings};
use crate::merkle::InclusionProof;
use crate::registry::{Service, ServiceName};
use crate::role::{Matcher, RoleName};

/// One item with its proof of inclusion under a head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvedItem {
    /// The item.
    pub item: Item,
    /// Its proof under the head it travels with.
    pub proof: InclusionProof,
}

impl ProvedItem {
    /// Check the proof against `head`'s `items_root` and `item_count`
    /// ([`Error::BadProof`]).
    pub fn verify(&self, head: &PolicyHead) -> Result<()> {
        todo!("ProvedItem::verify {head:?}")
    }
}

/// A host's part of the policy. See the module docs and
/// [`SignedPolicy::slice_for_host`](crate::SignedPolicy::slice_for_host).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Slice {
    /// The root-signed head every item is proved under.
    pub head: SignedPolicyHead,
    /// The items, in key order, each with its proof.
    pub items: Vec<ProvedItem>,
}

impl Slice {
    /// Verify the head under `root`, every proof against it, that no key
    /// appears twice, and that the settings item is there. Does not check
    /// freshness.
    pub fn verify(&self, root: NodeId) -> Result<()> {
        todo!("Slice::verify {}", root.hex())
    }

    /// The fabric's settings (present in every verified slice).
    pub fn settings(&self) -> Option<&Settings> {
        todo!("Slice::settings")
    }

    /// The service `name`, if this slice holds it.
    pub fn service(&self, name: &ServiceName) -> Option<&Service> {
        todo!("Slice::service {name}")
    }

    /// The matchers of role `name`, if this slice holds it.
    pub fn role(&self, name: &RoleName) -> Option<&[Matcher]> {
        todo!("Slice::role {name}")
    }

    /// The trusted issuer `iss`, if the policy names it.
    pub fn issuer(&self, iss: &Issuer) -> Option<&IssuerConfig> {
        todo!("Slice::issuer {iss}")
    }

    /// Whether `role` admits `principal`, by the roles this slice holds
    /// (same rule as [`role_admits`](crate::role_admits): no principal or
    /// an unheld role admits nothing).
    pub fn role_admits(&self, role: &RoleName, principal: Option<&Principal>) -> bool {
        todo!("Slice::role_admits {role} {principal:?}")
    }

    /// Whether `node` is banned at `now`.
    pub fn is_banned(&self, node: NodeId, now: i64) -> bool {
        todo!("Slice::is_banned {} {now}", node.hex())
    }

    /// Every item's key, in order.
    pub fn keys(&self) -> Vec<ItemKey> {
        todo!("Slice::keys")
    }
}

/// One service in a caller's [`View`], and what the caller may do with it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewEntry {
    /// The service item, with its proof.
    pub item: ProvedItem,
    /// A role in its `allow` admits the caller.
    pub call: bool,
    /// A role in its `readers` admits the caller.
    pub read: bool,
}

impl ViewEntry {
    /// The service's name and entry (`None` if the item is not a service,
    /// which [`View::verify`] refuses).
    pub fn service(&self) -> Option<(&ServiceName, &Service)> {
        todo!("ViewEntry::service")
    }
}

/// A caller's part of the policy. See the module docs and
/// [`SignedPolicy::view_for`](crate::SignedPolicy::view_for).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct View {
    /// The root-signed head every entry is proved under.
    pub head: SignedPolicyHead,
    /// The services, in name order.
    pub entries: Vec<ViewEntry>,
}

impl View {
    /// Verify the head under `root`, every proof against it, that every entry
    /// is a service marked `call` or `read`, and that none appears twice.
    /// Does not check freshness. (The marks are the directory's reading of
    /// roles the view doesn't carry; the host decides every call.)
    pub fn verify(&self, root: NodeId) -> Result<()> {
        todo!("View::verify {}", root.hex())
    }

    /// The entry for service `name`, if the view holds it.
    pub fn entry(&self, name: &ServiceName) -> Option<&ViewEntry> {
        todo!("View::entry {name}")
    }

    /// Keep only the entries whose name or description contains `query`,
    /// ignoring ASCII case (`wires services <query>`, card 37). Proofs stay
    /// valid: each is under the same head.
    pub fn retain_matching(&mut self, query: &str) {
        todo!("View::retain_matching {query}")
    }
}

/// Check every proof, that keys are unique; return the keys seen.
fn verify_items<'a>(
    head: &PolicyHead,
    items: impl IntoIterator<Item = &'a ProvedItem>,
) -> Result<BTreeSet<ItemKey>> {
    let mut seen = BTreeSet::new();
    for proved in items {
        proved.verify(head)?;
        if !seen.insert(proved.item.key()) {
            return Err(Error::InvalidPolicy(format!(
                "{} appears twice",
                proved.item.key()
            )));
        }
    }
    Ok(seen)
}

#[cfg(test)]
mod tests {}

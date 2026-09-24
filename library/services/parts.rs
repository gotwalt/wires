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
use crate::signed_policy::admits;

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
        self.proof
            .verify(&self.item, head.items_root, head.item_count)
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
        self.head.verify(root)?;
        let keys = verify_items(&self.head.head, &self.items)?;
        if !keys.contains(&ItemKey::Settings) {
            return Err(Error::InvalidPolicy("the slice has no settings".into()));
        }
        Ok(())
    }

    /// The fabric's settings (present in every verified slice).
    pub fn settings(&self) -> Option<&Settings> {
        self.items.iter().find_map(|p| match &p.item {
            Item::Settings { body } => Some(body),
            _ => None,
        })
    }

    /// The service `name`, if this slice holds it.
    pub fn service(&self, name: &ServiceName) -> Option<&Service> {
        self.items.iter().find_map(|p| match &p.item {
            Item::Service { key, body } if key == name => Some(body),
            _ => None,
        })
    }

    /// The matchers of role `name`, if this slice holds it.
    pub fn role(&self, name: &RoleName) -> Option<&[Matcher]> {
        self.items.iter().find_map(|p| match &p.item {
            Item::Role { key, body } if key == name => Some(body.as_slice()),
            _ => None,
        })
    }

    /// The trusted issuer `iss`, if the policy names it.
    pub fn issuer(&self, iss: &Issuer) -> Option<&IssuerConfig> {
        self.items.iter().find_map(|p| match &p.item {
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
        self.items.iter().any(|p| match &p.item {
            Item::Ban { key, body } => *key == node && body.holds(now),
            _ => false,
        })
    }

    /// Every item's key, in order.
    pub fn keys(&self) -> Vec<ItemKey> {
        self.items.iter().map(|p| p.item.key()).collect()
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
        match &self.item.item {
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
        self.head.verify(root)?;
        verify_items(&self.head.head, self.entries.iter().map(|e| &e.item))?;
        for entry in &self.entries {
            let key = entry.item.item.key();
            if entry.service().is_none() {
                return Err(Error::InvalidPolicy(format!("a view holds {key}")));
            }
            if !entry.call && !entry.read {
                return Err(Error::InvalidPolicy(format!(
                    "{key} is in the view but marked neither call nor read"
                )));
            }
        }
        Ok(())
    }

    /// The entry for service `name`, if the view holds it.
    pub fn entry(&self, name: &ServiceName) -> Option<&ViewEntry> {
        self.entries
            .iter()
            .find(|e| e.service().is_some_and(|(key, _)| key == name))
    }

    /// Keep only the entries whose name or description contains `query`,
    /// ignoring ASCII case (`wires services <query>`, card 37). Proofs stay
    /// valid: each is under the same head.
    pub fn retain_matching(&mut self, query: &str) {
        let query = query.to_ascii_lowercase();
        self.entries.retain(|e| {
            e.service().is_some_and(|(name, svc)| {
                name.as_str().contains(&query)
                    || svc.description.to_ascii_lowercase().contains(&query)
            })
        });
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
mod tests {
    use super::*;
    use crate::item::Ban;
    use crate::signed_policy::SignedPolicy;
    use crate::signed_policy::fixtures::*;

    fn signed() -> SignedPolicy {
        sample().sign(&root()).unwrap()
    }

    #[test]
    fn slice_accessors() {
        let slice = signed()
            .slice_for_host(node(10), &[role("oncall")])
            .unwrap();
        slice.verify(root().node_id()).unwrap();
        assert!(slice.service(&name("orders-db")).is_some());
        assert!(slice.service(&name("deploy")).is_none());
        assert_eq!(slice.role(&role("staff")), Some(&[Matcher::new(ISS)][..]));
        assert!(slice.role(&role("oncall")).is_some());
        assert!(slice.issuer(&Issuer::new(ISS)).is_some());
        assert!(slice.issuer(&Issuer::new("https://other")).is_none());
        let alice = who("alice@example.com");
        assert!(slice.role_admits(&role("analyst"), Some(&alice)));
        assert!(!slice.role_admits(&role("analyst"), None));
        assert!(!slice.role_admits(&role("ghost"), Some(&alice)));
        assert!(slice.is_banned(node(20), 500));
        assert!(!slice.is_banned(node(20), 501));
        assert!(!slice.is_banned(node(21), 0));
        assert_eq!(slice.settings(), Some(&Settings::default()));
    }

    #[test]
    fn a_tampered_slice_is_refused() {
        let good = signed().slice_for_host(node(10), &[]).unwrap();

        let mut t = good.clone();
        let Some(Item::Ban { body, .. }) = t
            .items
            .iter_mut()
            .map(|p| &mut p.item)
            .find(|i| matches!(i, Item::Ban { .. }))
        else {
            unreachable!()
        };
        *body = Ban { until: i64::MAX };
        assert!(matches!(t.verify(root().node_id()), Err(Error::BadProof)));

        let mut t = good.clone();
        t.items.retain(|p| !matches!(p.item, Item::Settings { .. }));
        assert!(matches!(
            t.verify(root().node_id()),
            Err(Error::InvalidPolicy(_))
        ));

        let mut t = good.clone();
        let first = t.items[0].clone();
        t.items.push(first);
        assert!(matches!(
            t.verify(root().node_id()),
            Err(Error::InvalidPolicy(_))
        ));

        // A proof moved onto another item.
        let mut t = good.clone();
        t.items[0].proof = good.items[1].proof.clone();
        assert!(t.verify(root().node_id()).is_err());

        assert!(good.verify(node(9)).is_err(), "another root");
    }

    #[test]
    fn a_view_carries_only_marked_services() {
        let s = signed();
        let good = s.view_for(Some(&who("carol@example.com"))).unwrap();
        good.verify(root().node_id()).unwrap();
        assert!(
            good.entry(&name("locked"))
                .is_some_and(|e| e.read && !e.call)
        );
        assert!(good.entry(&name("deploy")).is_none());

        let mut t = good.clone();
        t.entries[0].call = false;
        t.entries[0].read = false;
        assert!(matches!(
            t.verify(root().node_id()),
            Err(Error::InvalidPolicy(_))
        ));

        // A role item smuggled in as an entry, with a valid proof.
        let slice = s.slice_for_host(node(10), &[]).unwrap();
        let mut t = good.clone();
        t.entries.push(ViewEntry {
            item: slice.items[0].clone(),
            call: true,
            read: false,
        });
        assert!(matches!(
            t.verify(root().node_id()),
            Err(Error::InvalidPolicy(_))
        ));
        assert!(t.entries.last().unwrap().service().is_none());

        let mut t = good.clone();
        let first = t.entries[0].clone();
        t.entries.push(first);
        assert!(t.verify(root().node_id()).is_err());
    }

    #[test]
    fn search_narrows_a_view_and_keeps_it_valid() {
        let mut p = sample();
        p.services.get_mut(&name("status")).unwrap().description =
            "Uptime of the ORDERS stack".into();
        let s = p.sign(&root()).unwrap();
        let mut view = s.view_for(Some(&who("alice@example.com"))).unwrap();
        view.retain_matching("orders");
        let names: Vec<_> = view
            .entries
            .iter()
            .map(|e| e.service().unwrap().0.to_string())
            .collect();
        assert_eq!(names, vec!["orders-db", "status"]);
        view.retain_matching("DB");
        assert_eq!(view.entries.len(), 1);
        view.verify(root().node_id()).unwrap();
        view.retain_matching("nothing matches this");
        assert!(view.entries.is_empty());
        view.verify(root().node_id()).unwrap();
    }
}

//! How a node holding the whole policy follows it (card 36d): a
//! [`PolicyUpdate`] carries a new head and only the items that changed.
//!
//! Hosts and directories hold the whole [`SignedPolicy`]. When the admin
//! publishes a new one, a directory sends each subscriber the new head, the
//! items added or changed since the version it holds, and the keys removed
//! ([`SignedPolicy::update_from`]). The subscriber applies that to its copy,
//! recomputes the [`ItemsHash`](crate::ItemsHash), and checks the root's one
//! signature on the new head ([`SignedPolicy::apply`]). A mix of versions is
//! impossible, because that one signature covers the whole set: a tampered,
//! missing or extra item fails the hash, and the subscriber asks for the
//! whole policy instead.
//!
//! ```
//! use library::{Ban, NodeIdentity, Policy, StateVersion};
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let mut policy = Policy::new(root.node_id());
//! policy.version = StateVersion(1);
//! policy.not_after = i64::MAX;
//! let v1 = policy.sign(&root).unwrap();
//!
//! // The admin bans a node: the host receives the new head and the ban.
//! policy.version = StateVersion(2);
//! policy.bans.insert(NodeIdentity::from_seed([9u8; 32]).node_id(), Ban { until: 100 });
//! let v2 = policy.sign_after(&root, &v1).unwrap();
//! let update = v2.update_from(&v1);
//! assert_eq!(update.changed.len(), 1);
//! assert_eq!(v1.apply(&update, root.node_id()).unwrap(), v2);
//! ```

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::head::SignedPolicyHead;
use crate::identity::NodeId;
use crate::item::{Item, ItemKey};
use crate::signed_policy::SignedPolicy;

/// What moves a whole [`SignedPolicy`] to a newer head. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyUpdate {
    /// The new root-signed head.
    pub head: SignedPolicyHead,
    /// Items added or changed since the holder's version, in key order.
    pub changed: Vec<Item>,
    /// Keys the new policy no longer holds, in key order.
    pub removed: Vec<ItemKey>,
}

impl SignedPolicy {
    /// The update that turns `older` (the version a subscriber holds) into
    /// this policy: this head, every item of this policy not equal in
    /// `older`, and every key of `older` this policy doesn't hold. The
    /// directory side of [`apply`](Self::apply).
    pub fn update_from(&self, older: &SignedPolicy) -> PolicyUpdate {
        let before: BTreeMap<ItemKey, &Item> = older.items.iter().map(|i| (i.key(), i)).collect();
        let after: BTreeSet<ItemKey> = self.items.iter().map(Item::key).collect();
        PolicyUpdate {
            head: self.head.clone(),
            changed: self
                .items
                .iter()
                .filter(|i| before.get(&i.key()) != Some(i))
                .cloned()
                .collect(),
            removed: before.into_keys().filter(|k| !after.contains(k)).collect(),
        }
    }

    /// Apply `update` to this (verified) policy: its head must be the same
    /// fabric's and no older; every removed key must be held and named once;
    /// no key may be named twice; then the rebuilt policy (held items, plus
    /// the changed ones, less the removed ones) must pass
    /// [`verify`](Self::verify): the head's signature under `root`, the
    /// items' hash ([`Error::ItemsMismatch`] for a tampered, missing or extra
    /// item), each changed service entry's own signature, and the policy's
    /// rules. Any failure is an error and this policy is unchanged: ask the
    /// directory for the whole policy.
    pub fn apply(&self, update: &PolicyUpdate, root: NodeId) -> Result<SignedPolicy> {
        let bad = |why: String| Err(Error::InvalidPolicy(why));
        if update.head.head.fabric != self.head.head.fabric
            || update.head.head.version < self.head.head.version
        {
            return bad(format!(
                "the update's head (version {}) is older than the held one ({})",
                update.head.head.version.0, self.head.head.version.0
            ));
        }
        let mut set: BTreeMap<ItemKey, Item> =
            self.items.iter().map(|i| (i.key(), i.clone())).collect();
        for key in &update.removed {
            if set.remove(key).is_none() {
                return bad(format!("the update removes {key}, which isn't held"));
            }
        }
        let mut seen = BTreeSet::new();
        for item in &update.changed {
            let key = item.key();
            if update.removed.contains(&key) || !seen.insert(key.clone()) {
                return bad(format!("the update names {key} twice"));
            }
            set.insert(key, item.clone());
        }
        let next = SignedPolicy {
            head: update.head.clone(),
            items: set.into_values().collect(),
        };
        // The held entries were verified when this policy was; the hash under
        // the new head covers them, so only the changed ones need a check.
        let changed = update.changed.iter().filter_map(|item| match item {
            Item::Service(entry) => Some(entry),
            _ => None,
        });
        next.check_items(root, changed)?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::head::StateVersion;
    use crate::item::Ban;
    use crate::signed_policy::Policy;
    use crate::signed_policy::fixtures::*;
    use proptest::prelude::*;

    fn signed() -> SignedPolicy {
        sample().sign(&root()).unwrap()
    }

    /// `sample()` at version 4 after `edit`, signed after version 3.
    fn v4(edit: impl FnOnce(&mut Policy)) -> SignedPolicy {
        let mut p = sample();
        p.version = StateVersion(4);
        edit(&mut p);
        p.sign_after(&root(), &signed()).unwrap()
    }

    fn r() -> NodeId {
        root().node_id()
    }

    #[test]
    fn an_edit_elsewhere_sends_one_item() {
        let old = signed();
        let new = v4(|p| p.services.get_mut(&name("deploy")).unwrap().description = "x".into());
        let update = new.update_from(&old);
        assert_eq!(
            update.changed.iter().map(Item::key).collect::<Vec<_>>(),
            vec![ItemKey::Service(name("deploy"))]
        );
        assert!(update.removed.is_empty());
        assert_eq!(old.apply(&update, r()).unwrap(), new);
    }

    #[test]
    fn changes_additions_and_removals_apply() {
        let old = signed();
        let new = v4(|p| {
            p.bans.insert(node(21), Ban { until: 900 });
            p.services.remove(&name("locked"));
            p.roles
                .get_mut(&role("staff"))
                .unwrap()
                .push(email("x@example.com"));
        });
        let update = new.update_from(&old);
        assert_eq!(
            update.changed.iter().map(Item::key).collect::<Vec<_>>(),
            vec![ItemKey::Role(role("staff")), ItemKey::Ban(node(21))]
        );
        assert_eq!(update.removed, vec![ItemKey::Service(name("locked"))]);
        let applied = old.apply(&update, r()).unwrap();
        assert_eq!(applied, new);
        assert!(applied.to_policy().unwrap().bans_node(node(21)));

        // The same head again changes nothing.
        assert_eq!(new.apply(&new.update_from(&new), r()).unwrap(), new);
    }

    #[test]
    fn tampered_missing_and_extra_items_ask_for_the_whole_policy() {
        let old = signed();
        let new = v4(|p| {
            p.services.get_mut(&name("status")).unwrap().description = "SLOs".into();
            p.bans.insert(node(21), Ban { until: 900 });
        });
        let good = new.update_from(&old);
        assert_eq!(good.changed.len(), 2);

        // A change withheld: the held copy of it doesn't hash.
        let mut t = good.clone();
        t.changed.retain(|i| matches!(i, Item::Service(_)));
        assert!(matches!(old.apply(&t, r()), Err(Error::ItemsMismatch)));
        let mut t = good.clone();
        t.changed.retain(|i| matches!(i, Item::Ban { .. }));
        assert!(matches!(old.apply(&t, r()), Err(Error::ItemsMismatch)));

        // A tampered ban.
        let mut t = good.clone();
        for item in &mut t.changed {
            if let Item::Ban { body, .. } = item {
                body.until = i64::MAX;
            }
        }
        assert!(matches!(old.apply(&t, r()), Err(Error::ItemsMismatch)));

        // An extra item.
        let mut t = good.clone();
        t.changed.push(Item::Ban {
            key: node(22),
            body: Ban { until: 1 },
        });
        assert!(matches!(old.apply(&t, r()), Err(Error::ItemsMismatch)));

        // A false removal: of a held key, or of one not held.
        let mut t = good.clone();
        t.removed.push(ItemKey::Service(name("deploy")));
        assert!(matches!(old.apply(&t, r()), Err(Error::ItemsMismatch)));
        let mut t = good.clone();
        t.removed.push(ItemKey::Ban(node(55)));
        assert!(matches!(old.apply(&t, r()), Err(Error::InvalidPolicy(_))));

        // A key both changed and removed.
        let mut t = good.clone();
        t.removed.push(ItemKey::Ban(node(21)));
        assert!(old.apply(&t, r()).is_err());

        // A head whose version was bumped without the root.
        let mut t = good.clone();
        t.head.head.version = StateVersion(9);
        assert!(matches!(old.apply(&t, r()), Err(Error::InvalidSignature)));

        // An older head.
        let applied = old.apply(&good, r()).unwrap();
        assert!(applied.apply(&old.update_from(&old), r()).is_err());

        // Another root.
        assert!(old.apply(&good, node(9)).is_err());
        // And the held policy is unchanged by every failure.
        assert_eq!(old, signed());
    }

    #[test]
    fn a_forged_entry_fails_even_under_a_matching_hash() {
        // A root-signed head over an entry the root never signed: the hash
        // matches, but the entry's own signature doesn't.
        let old = signed();
        let mut items = v4(|_| {}).items;
        for item in &mut items {
            if let Item::Service(e) = item
                && e.name == name("status")
            {
                e.service.hosts.push(node(12));
            }
        }
        let mut head = v4(|_| {}).head.head;
        head.items_hash = crate::head::ItemsHash::of(&items).unwrap();
        let forged = SignedPolicy {
            head: head.sign(&root()).unwrap(),
            items,
        };
        let update = forged.update_from(&old);
        assert!(matches!(
            old.apply(&update, r()),
            Err(Error::InvalidSignature)
        ));
    }

    proptest! {
        /// Whatever the two policies, applying the directory's update to the
        /// older one yields exactly the newer one.
        #[test]
        fn updates_rebuild_exactly_the_newer_policy(a in arb_policy(), b in arb_policy()) {
            let old = a.sign(&root()).unwrap();
            let mut b = b;
            b.version = StateVersion(a.version.0 + 1);
            let new = b.sign_after(&root(), &old).unwrap();
            let update = new.update_from(&old);
            prop_assert_eq!(old.apply(&update, r()).unwrap(), new.clone());
            // Only what changed travels.
            for item in &update.changed {
                prop_assert!(!old.items.contains(item));
            }
        }

        /// Dropping, altering or adding any one item of an update makes the
        /// holder refuse it (and ask for the whole policy).
        #[test]
        fn any_damaged_update_is_refused(
            a in arb_policy(),
            b in arb_policy(),
            pick in any::<proptest::sample::Index>(),
            damage in 0u8..3,
        ) {
            let old = a.sign(&root()).unwrap();
            let mut b = b;
            b.version = StateVersion(a.version.0 + 1);
            let new = b.sign_after(&root(), &old).unwrap();
            let mut update = new.update_from(&old);
            match damage {
                0 => {
                    prop_assume!(!update.changed.is_empty());
                    update.changed.remove(pick.index(update.changed.len()));
                }
                1 => {
                    prop_assume!(!update.changed.is_empty());
                    let i = pick.index(update.changed.len());
                    match &mut update.changed[i] {
                        Item::Role { body, .. } => body.push(email("mallory@example.com")),
                        Item::Service(e) => e.service.description.push('!'),
                        Item::Ban { body, .. } => body.until = body.until.wrapping_add(1),
                        Item::Issuer { body, .. } => body.audiences.push(crate::Audience::new("x")),
                        Item::Settings { body } => body.fresh_secs += 1,
                    }
                }
                _ => update.changed.push(Item::Ban { key: node(99), body: Ban { until: 7 } }),
            }
            prop_assert!(old.apply(&update, r()).is_err());
        }
    }
}

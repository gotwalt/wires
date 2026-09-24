//! A caller's view of the policy (card 37): the services it may use, each a
//! root-signed [`SignedEntry`], and the updates that move a view to a newer
//! head ([`ViewUpdate`]).
//!
//! A view is the root-signed head (for its version, lifetime and the
//! directories whose [`Fresh`](crate::Fresh) vouches for it) and a list of
//! [`ViewEntry`]s: a signed entry marked `call` (a role in its `allow` admits
//! the caller) and/or `read` (a role in its `readers` does). Each entry
//! verifies on its own under the root, as a badge does, so a directory can't
//! forge one, move one from another fabric, or hand back an older version
//! than one the caller holds ([`View::apply`] keeps the newest version of
//! each entry). What a view leaves out is the point: no role, no ban, and no
//! service its caller may not use. It is cut by
//! [`SignedPolicy::view_for`](crate::SignedPolicy::view_for).
//!
//! A directory can still withhold an entry or serve a stale one, which
//! [`Fresh`](crate::Fresh) bounds; the marks are the directory's reading of
//! roles the view doesn't carry. Neither is a hole: the host decides every
//! call from its whole, current policy and refuses one it doesn't serve.
//!
//! ```
//! use library::{
//!     Audience, Issuer, IssuerConfig, Matcher, NodeIdentity, Policy, Principal, RoleName,
//!     Service, ServiceName, StateVersion,
//! };
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let mut policy = Policy::new(root.node_id());
//! policy.version = StateVersion(1);
//! policy.not_after = i64::MAX;
//! policy.issuers.insert(Issuer::new("https://idp"), IssuerConfig {
//!     client_id: Audience::new("cli"), audiences: vec![Audience::new("cli")],
//! });
//! let staff = RoleName::new("staff").unwrap();
//! policy.roles.insert(staff.clone(), vec![Matcher::new("https://idp")]);
//! let service = |description: &str| Service {
//!     description: description.into(), allow: vec![staff.clone()], hosts: vec![], readers: vec![],
//! };
//! policy.services.insert(ServiceName::new("status").unwrap(), service("uptime"));
//! let v1 = policy.sign(&root).unwrap();
//! let alice = Principal {
//!     issuer: "https://idp".into(), subject: "1".into(),
//!     email: None, org: None, groups: vec![], not_after: 0,
//! };
//! let view = v1.view_for(Some(&alice), None);
//!
//! // The admin adds a service: the update carries just that entry.
//! policy.version = StateVersion(2);
//! policy.services.insert(ServiceName::new("orders-db").unwrap(), service("orders"));
//! let v2 = policy.sign_after(&root, &v1).unwrap();
//! let update = view.update_to(&v2.view_for(Some(&alice), None));
//! assert_eq!(update.changed.len(), 1);
//! let view = view.apply(&update, root.node_id()).unwrap();
//! assert_eq!(view, v2.view_for(Some(&alice), None));
//! ```

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::entry::SignedEntry;
use crate::error::{Error, Result};
use crate::head::SignedPolicyHead;
use crate::identity::NodeId;
use crate::registry::ServiceName;
use crate::signed_policy::{check_entry_version, service_matches};

/// One service in a caller's [`View`], and what the caller may do with it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewEntry {
    /// The service's root-signed entry.
    pub entry: SignedEntry,
    /// A role in its `allow` admits the caller.
    pub call: bool,
    /// A role in its `readers` admits the caller.
    pub read: bool,
}

/// A caller's part of the policy. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct View {
    /// The root-signed head the view was cut under.
    pub head: SignedPolicyHead,
    /// The services, strictly in name order.
    pub entries: Vec<ViewEntry>,
}

/// What moves a [`View`] to a newer head (or to new marks): the new head,
/// the entries added or changed (the entry or its marks), and the services
/// the view no longer holds. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewUpdate {
    /// The new head.
    pub head: SignedPolicyHead,
    /// Entries added or changed, in name order.
    pub changed: Vec<ViewEntry>,
    /// Services the view no longer holds, in name order.
    pub removed: Vec<ServiceName>,
}

impl View {
    /// Verify the head under `root`, and that every entry verifies on its
    /// own under `root` at a version no later than the head's, is marked
    /// `call` or `read`, and that the entries are strictly in name order.
    /// Does not check freshness.
    pub fn verify(&self, root: NodeId) -> Result<()> {
        self.head.verify(root)?;
        if let Some(pair) = self
            .entries
            .windows(2)
            .find(|w| w[0].entry.name >= w[1].entry.name)
        {
            return Err(Error::InvalidPolicy(format!(
                "service {} is out of order or repeated in the view",
                pair[1].entry.name
            )));
        }
        for e in &self.entries {
            if !e.call && !e.read {
                return Err(Error::InvalidPolicy(format!(
                    "service {} is in the view but marked neither call nor read",
                    e.entry.name
                )));
            }
            check_entry_version(&e.entry, &self.head)?;
            e.entry.verify(root)?;
        }
        Ok(())
    }

    /// The update that turns this view into `newer` (the same caller's view
    /// under a newer head): what the directory sends a subscriber.
    pub fn update_to(&self, newer: &View) -> ViewUpdate {
        let before: BTreeMap<&ServiceName, &ViewEntry> =
            self.entries.iter().map(|e| (&e.entry.name, e)).collect();
        let after: BTreeSet<&ServiceName> = newer.entries.iter().map(|e| &e.entry.name).collect();
        ViewUpdate {
            head: newer.head.clone(),
            changed: newer
                .entries
                .iter()
                .filter(|e| before.get(&e.entry.name) != Some(e))
                .cloned()
                .collect(),
            removed: self
                .entries
                .iter()
                .map(|e| e.entry.name.clone())
                .filter(|n| !after.contains(n))
                .collect(),
        }
    }

    /// Apply `update`: its head must verify under `root` and be the same
    /// fabric's, no older than this one; every removed service must be held
    /// and named once; no service may be named twice; a changed entry must
    /// not be older than the one held (a caller keeps the newest version of
    /// each entry); and the result must pass [`verify`](Self::verify). Any
    /// failure is an error and this view is unchanged: ask the directory
    /// for the whole view.
    pub fn apply(&self, update: &ViewUpdate, root: NodeId) -> Result<View> {
        let bad = |why: String| Err(Error::InvalidPolicy(why));
        if update.head.head.fabric != self.head.head.fabric
            || update.head.head.version < self.head.head.version
        {
            return bad(format!(
                "the update's head (version {}) is older than the held one ({})",
                update.head.head.version.0, self.head.head.version.0
            ));
        }
        let mut set: BTreeMap<ServiceName, ViewEntry> = self
            .entries
            .iter()
            .map(|e| (e.entry.name.clone(), e.clone()))
            .collect();
        for name in &update.removed {
            if set.remove(name).is_none() {
                return bad(format!("the update removes {name}, which isn't held"));
            }
        }
        let mut seen = BTreeSet::new();
        for e in &update.changed {
            let name = &e.entry.name;
            if update.removed.contains(name) || !seen.insert(name) {
                return bad(format!("the update names {name} twice"));
            }
            if let Some(held) = set.get(name)
                && e.entry.version < held.entry.version
            {
                return bad(format!(
                    "the update's {name} (version {}) is older than the held one ({})",
                    e.entry.version.0, held.entry.version.0
                ));
            }
            set.insert(name.clone(), e.clone());
        }
        let view = View {
            head: update.head.clone(),
            entries: set.into_values().collect(),
        };
        view.verify(root)?;
        Ok(view)
    }

    /// The entry for service `name`, if the view holds it.
    pub fn entry(&self, name: &ServiceName) -> Option<&ViewEntry> {
        self.entries.iter().find(|e| e.entry.name == *name)
    }

    /// The entries whose name or description contains `query`, ignoring
    /// ASCII case (`wires services <query>`, card 37). A reading of the view;
    /// the view itself is unchanged.
    pub fn matching(&self, query: &str) -> Vec<&ViewEntry> {
        let query = query.to_ascii_lowercase();
        self.entries
            .iter()
            .filter(|e| service_matches(&e.entry.name, &e.entry.service, &query))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::head::StateVersion;
    use crate::identity::NodeIdentity;
    use crate::signed_policy::fixtures::*;
    use crate::signed_policy::{Policy, SignedPolicy};
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
    fn a_view_entry_verifies_alone() {
        let view = signed().view_for(Some(&who("carol@example.com")), None);
        view.verify(r()).unwrap();
        for e in &view.entries {
            e.entry.verify(r()).unwrap();
        }
        assert!(
            view.entry(&name("locked"))
                .is_some_and(|e| e.read && !e.call)
        );
        assert!(view.entry(&name("deploy")).is_none());
        assert!(view.verify(node(9)).is_err(), "another root");
    }

    #[test]
    fn forged_foreign_and_unmarked_entries_are_refused() {
        let good = signed().view_for(Some(&who("carol@example.com")), None);

        // A forged entry: its signature no longer covers it.
        let mut t = good.clone();
        t.entries[0].entry.service.hosts.push(node(12));
        assert!(matches!(t.verify(r()), Err(Error::InvalidSignature)));

        // An entry from another fabric, validly signed by its root.
        let other = NodeIdentity::from_seed([9u8; 32]);
        let mut t = good.clone();
        let e = &t.entries[0].entry;
        t.entries[0].entry =
            SignedEntry::sign(&other, e.version, e.name.clone(), e.service.clone()).unwrap();
        assert!(matches!(t.verify(r()), Err(Error::InvalidSignature)));

        // An entry from after the view's head.
        let mut t = good.clone();
        let e = &t.entries[0].entry;
        t.entries[0].entry =
            SignedEntry::sign(&root(), StateVersion(9), e.name.clone(), e.service.clone()).unwrap();
        assert!(matches!(t.verify(r()), Err(Error::InvalidPolicy(_))));

        let mut t = good.clone();
        t.entries[0].call = false;
        t.entries[0].read = false;
        assert!(matches!(t.verify(r()), Err(Error::InvalidPolicy(_))));

        let mut t = good.clone();
        t.entries.reverse();
        assert!(matches!(t.verify(r()), Err(Error::InvalidPolicy(_))));

        let mut t = good;
        let first = t.entries[0].clone();
        t.entries.insert(0, first);
        assert!(matches!(t.verify(r()), Err(Error::InvalidPolicy(_))));
    }

    #[test]
    fn matching_reads_the_view_without_changing_it() {
        let mut p = sample();
        p.services.get_mut(&name("status")).unwrap().description =
            "Uptime of the ORDERS stack".into();
        let s = p.sign(&root()).unwrap();
        let view = s.view_for(Some(&who("alice@example.com")), None);
        let names = |q| -> Vec<String> {
            view.matching(q)
                .iter()
                .map(|e| e.entry.name.to_string())
                .collect()
        };
        assert_eq!(names("orders"), vec!["orders-db", "status"]);
        assert_eq!(names("DB"), vec!["orders-db"]);
        assert!(names("nothing matches this").is_empty());
        view.verify(r()).unwrap();
    }

    #[test]
    fn views_update_on_grants_and_revocations() {
        let alice = who("alice@example.com");
        let old = signed().view_for(Some(&alice), None);

        // An unrelated edit: just the new head.
        let new = v4(|p| p.services.get_mut(&name("deploy")).unwrap().description = "x".into());
        let update = old.update_to(&new.view_for(Some(&alice), None));
        assert!(update.changed.is_empty() && update.removed.is_empty());
        assert_eq!(old.apply(&update, r()).unwrap().head, new.head);

        // Alice becomes an auditor: `locked` appears, and orders-db gains
        // `read` (same entry, new marks).
        let new = v4(|p| {
            p.roles
                .get_mut(&role("auditor"))
                .unwrap()
                .push(email("alice@example.com"));
        });
        let update = old.update_to(&new.view_for(Some(&alice), None));
        assert_eq!(update.changed.len(), 2, "{:?}", update.changed);
        let applied = old.apply(&update, r()).unwrap();
        assert_eq!(applied, new.view_for(Some(&alice), None));
        assert!(applied.entry(&name("locked")).is_some_and(|e| e.read));
        assert_eq!(
            applied.entry(&name("orders-db")).unwrap().entry.version,
            StateVersion(3),
            "unchanged entry, unchanged version"
        );

        // Staff is revoked: status leaves the view.
        let new = v4(|p| {
            p.services.get_mut(&name("status")).unwrap().allow = vec![role("oncall")];
        });
        let update = old.update_to(&new.view_for(Some(&alice), None));
        assert_eq!(update.removed, vec![name("status")]);
        let applied = old.apply(&update, r()).unwrap();
        assert!(applied.entry(&name("status")).is_none());
    }

    #[test]
    fn a_bad_view_update_is_refused() {
        let alice = who("alice@example.com");
        let old = signed().view_for(Some(&alice), None);
        let new = v4(|p| p.services.get_mut(&name("status")).unwrap().description = "new".into());
        let good = old.update_to(&new.view_for(Some(&alice), None));
        assert_eq!(good.changed.len(), 1);
        let held = old.apply(&good, r()).unwrap();

        // An older entry than the one held: refused, even under a newer head.
        let newer = {
            let mut p = sample();
            p.version = StateVersion(5);
            p.services.get_mut(&name("status")).unwrap().description = "new".into();
            p.sign_after(&root(), &new).unwrap()
        };
        let mut t = held.update_to(&newer.view_for(Some(&alice), None));
        t.changed.push(old.entry(&name("status")).unwrap().clone());
        assert!(matches!(held.apply(&t, r()), Err(Error::InvalidPolicy(_))));

        // A forged change.
        let mut t = good.clone();
        t.changed[0].entry.service.description = "forged".into();
        assert!(matches!(old.apply(&t, r()), Err(Error::InvalidSignature)));

        // Removing a service not held; naming one twice.
        let mut t = good.clone();
        t.removed.push(name("deploy"));
        assert!(old.apply(&t, r()).is_err());
        let mut t = good.clone();
        t.removed.push(name("status"));
        assert!(old.apply(&t, r()).is_err());

        // An older head.
        assert!(held.apply(&old.update_to(&old), r()).is_err());

        // Another root.
        assert!(old.apply(&good, node(9)).is_err());
    }

    proptest! {
        /// Whatever the two policies, applying the update computed between
        /// a caller's two views yields exactly the new view.
        #[test]
        fn updates_rebuild_exactly_the_new_view(
            a in arb_policy(),
            b in arb_policy(),
            principal in arb_principal(),
        ) {
            let old = a.sign(&root()).unwrap();
            let mut b = b;
            b.version = StateVersion(a.version.0 + 1);
            let new = b.sign_after(&root(), &old).unwrap();

            let from = old.view_for(principal.as_ref(), None);
            let to = new.view_for(principal.as_ref(), None);
            let update = from.update_to(&to);
            let applied = from.apply(&update, r()).unwrap();
            prop_assert!(applied.verify(r()).is_ok());
            prop_assert_eq!(&applied, &to);
            // Only what changed travels.
            for e in &update.changed {
                prop_assert!(from.entry(&e.entry.name) != Some(e));
            }
        }
    }
}

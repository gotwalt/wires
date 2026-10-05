//! A caller's view of the policy (card 37): the services it may use, each a
//! root-signed [`SignedEntry`]. A view always travels whole: a caller
//! replaces the one it holds with a newer one.
//!
//! A view is the root-signed head (for its version, lifetime and the
//! directories whose [`Fresh`](crate::Fresh) vouches for it) and the signed
//! entries of the services whose `allow` names a role that admits the
//! caller. Each entry verifies on its own under the root, so a directory
//! can't forge one or move one from another network. What a view leaves out is the point: no role, no ban, and no
//! service its caller may not use. It is cut by
//! [`SignedPolicy::view_for`](crate::SignedPolicy::view_for).
//!
//! A directory can still withhold an entry or serve a stale one, which
//! [`Fresh`](crate::Fresh) bounds; which entries a view holds is the
//! directory's reading of roles the view doesn't carry. Neither is a hole: the host decides every
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
//!     description: description.into(), allow: vec![staff.clone()], hosts: vec![],
//! };
//! policy.services.insert(ServiceName::new("status").unwrap(), service("uptime"));
//! let v1 = policy.sign(&root).unwrap();
//! let alice = Principal {
//!     issuer: "https://idp".into(), subject: "1".into(),
//!     email: Some("alice@example.com".into()), org: None, groups: vec![], not_after: 0,
//! };
//! let laptop = NodeIdentity::from_seed([2u8; 32]).node_id();
//! let view = v1.view_for(laptop, Some(&alice), None);
//!
//! // The admin adds a service: the caller's next view holds it too.
//! policy.version = StateVersion(2);
//! policy.services.insert(ServiceName::new("orders-db").unwrap(), service("orders"));
//! let v2 = policy.sign_after(&root, &v1).unwrap();
//! let newer = v2.view_for(laptop, Some(&alice), None);
//! newer.verify(root.node_id()).unwrap();
//! assert_eq!(view.entries.len() + 1, newer.entries.len());
//! ```

use serde::{Deserialize, Serialize};

use crate::entry::SignedEntry;
use crate::error::{Error, Result};
use crate::head::SignedPolicyHead;
use crate::identity::NodeId;
use crate::registry::ServiceName;
use crate::signed_policy::{check_entry_version, service_matches};

/// A caller's part of the policy. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct View {
    /// The root-signed head the view was cut under.
    pub head: SignedPolicyHead,
    /// The services' root-signed entries, strictly in name order.
    pub entries: Vec<SignedEntry>,
}

impl View {
    /// Verify the head under `root`, and that every entry verifies on its
    /// own under `root` at a version no later than the head's, and that the
    /// entries are strictly in name order.
    /// Does not check freshness.
    pub fn verify(&self, root: NodeId) -> Result<()> {
        self.head.verify(root)?;
        if let Some(pair) = self.entries.windows(2).find(|w| w[0].name >= w[1].name) {
            return Err(Error::InvalidPolicy(format!(
                "service {} is out of order or repeated in the view",
                pair[1].name
            )));
        }
        for e in &self.entries {
            check_entry_version(e, &self.head)?;
            e.verify(root)?;
        }
        Ok(())
    }

    /// The entry for service `name`, if the view holds it.
    pub fn entry(&self, name: &ServiceName) -> Option<&SignedEntry> {
        self.entries.iter().find(|e| e.name == *name)
    }

    /// The entries whose name or description contains `query`, ignoring
    /// ASCII case (`wires services <query>`, card 37). A reading of the view;
    /// the view itself is unchanged.
    pub fn matching(&self, query: &str) -> Vec<&SignedEntry> {
        let query = query.to_ascii_lowercase();
        self.entries
            .iter()
            .filter(|e| service_matches(&e.name, &e.service, &query))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::head::StateVersion;
    use crate::identity::NodeIdentity;
    use crate::signed_policy::SignedPolicy;
    use crate::signed_policy::fixtures::*;
    use proptest::prelude::*;

    fn signed() -> SignedPolicy {
        sample().sign(&root()).unwrap()
    }

    fn r() -> NodeId {
        root().node_id()
    }

    #[test]
    fn a_view_entry_verifies_alone() {
        let view = signed().view_for(node(2), Some(&who("carol@example.com")), None);
        view.verify(r()).unwrap();
        for e in &view.entries {
            e.verify(r()).unwrap();
        }
        assert!(view.entry(&name("locked")).is_some());
        assert!(view.entry(&name("orders-db")).is_none());
        assert!(view.entry(&name("deploy")).is_none());
        assert!(view.verify(node(9)).is_err(), "another root");
    }

    #[test]
    fn forged_foreign_and_misplaced_entries_are_refused() {
        let good = signed().view_for(node(2), Some(&who("carol@example.com")), None);

        // A forged entry: its signature no longer covers it.
        let mut t = good.clone();
        t.entries[0].service.hosts.push(node(12));
        assert!(matches!(t.verify(r()), Err(Error::InvalidSignature)));

        // An entry from another fabric, validly signed by its root.
        let other = NodeIdentity::from_seed([9u8; 32]);
        let mut t = good.clone();
        let e = &t.entries[0];
        t.entries[0] =
            SignedEntry::sign(&other, e.version, e.name.clone(), e.service.clone()).unwrap();
        assert!(matches!(t.verify(r()), Err(Error::InvalidSignature)));

        // An entry from after the view's head.
        let mut t = good.clone();
        let e = &t.entries[0];
        t.entries[0] =
            SignedEntry::sign(&root(), StateVersion(9), e.name.clone(), e.service.clone()).unwrap();
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
        let view = s.view_for(node(2), Some(&who("alice@example.com")), None);
        let names = |q| -> Vec<String> {
            view.matching(q)
                .iter()
                .map(|e| e.name.to_string())
                .collect()
        };
        assert_eq!(names("orders"), vec!["orders-db", "status"]);
        assert_eq!(names("DB"), vec!["orders-db"]);
        assert!(names("nothing matches this").is_empty());
        view.verify(r()).unwrap();
    }

    proptest! {
        /// Whatever the policy and the caller, the view cut for it verifies
        /// on its own, and holds exactly the services `authorize` allows it.
        #[test]
        fn a_view_holds_what_the_caller_may_call(a in arb_policy(), principal in arb_principal()) {
            let signed = a.sign(&root()).unwrap();
            let policy = signed.to_policy().unwrap();
            let view = signed.view_for(node(2), principal.as_ref(), None);
            prop_assert!(view.verify(r()).is_ok());
            for name in policy.services.keys() {
                let allowed = crate::access::authorize(&policy, node(2), principal.as_ref(), name).is_ok();
                prop_assert_eq!(view.entry(name).is_some(), allowed, "{}", name);
            }
        }
    }
}

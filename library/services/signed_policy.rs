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
use crate::item::{Ban, IssuerConfig, Item, Settings};
use crate::merkle::MultiProof;
use crate::merkle::{ItemHash, ItemTree};
use crate::parts::{Slice, SliceUpdate, View, ViewEntry, ViewUpdate};
use crate::registry::{Service, ServiceName};
use crate::role::{Matcher, RoleName};
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
    /// Every item, sorted by [`ItemKey`](crate::ItemKey), each key once.
    pub items: Vec<Item>,
}

impl Policy {
    /// An empty policy for `fabric` at version 0, never valid (`not_after`
    /// 0), with default [`Settings`]: the starting point `wires init` fills
    /// in.
    pub fn new(fabric: NodeId) -> Policy {
        Policy {
            fabric,
            version: StateVersion(0),
            issued: 0,
            not_after: 0,
            directories: Vec::new(),
            roles: BTreeMap::new(),
            services: BTreeMap::new(),
            bans: BTreeMap::new(),
            issuers: BTreeMap::new(),
            settings: Settings::default(),
        }
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
        let bad = |why: String| Err(Error::InvalidPolicy(why));
        let mut seen = BTreeSet::new();
        if let Some(d) = self.directories.iter().find(|d| !seen.insert(**d)) {
            return bad(format!("directory {} is listed twice", d.hex()));
        }
        for (iss, config) in &self.issuers {
            if iss.as_str().trim().is_empty() {
                return bad("an issuer is blank".into());
            }
            if config
                .audiences
                .iter()
                .all(|a| a.as_str().trim().is_empty())
            {
                return bad(format!("issuer {iss} accepts no audience"));
            }
        }
        for (role, matchers) in &self.roles {
            if matchers.is_empty() {
                return bad(format!("role {role} has no matchers"));
            }
            for m in matchers {
                if m.issuer.trim().is_empty() {
                    return bad(format!("role {role} has a matcher with no issuer"));
                }
                if !self.issuers.contains_key(&Issuer::new(m.issuer.as_str())) {
                    return bad(format!(
                        "role {role} names issuer {}, which is not trusted",
                        m.issuer
                    ));
                }
            }
        }
        for (name, svc) in &self.services {
            if let Some(role) = svc
                .allow
                .iter()
                .chain(&svc.readers)
                .find(|r| !self.roles.contains_key(*r))
            {
                return bad(format!("service {name} names undefined role {role}"));
            }
            let mut seen = BTreeSet::new();
            if let Some(h) = svc.hosts.iter().find(|h| !seen.insert(**h)) {
                return bad(format!("service {name} lists host {} twice", h.hex()));
            }
        }
        if self.settings.beat_secs == 0 {
            return bad("settings: beat_secs is 0".into());
        }
        if self.settings.fresh_secs < self.settings.beat_secs {
            return bad("settings: fresh_secs is shorter than beat_secs".into());
        }
        Ok(())
    }

    /// Every item, in leaf ([`ItemKey`](crate::ItemKey)) order.
    pub fn items(&self) -> Vec<Item> {
        // Each map iterates in its key's order, and the kinds follow in
        // `ItemKey`'s order, so the concatenation is sorted.
        let roles = self.roles.iter().map(|(k, v)| Item::Role {
            key: k.clone(),
            body: v.clone(),
        });
        let services = self.services.iter().map(|(k, v)| Item::Service {
            key: k.clone(),
            body: v.clone(),
        });
        let bans = self
            .bans
            .iter()
            .map(|(k, v)| Item::Ban { key: *k, body: *v });
        let issuers = self.issuers.iter().map(|(k, v)| Item::Issuer {
            key: k.clone(),
            body: v.clone(),
        });
        let settings = Item::Settings {
            body: self.settings,
        };
        roles
            .chain(services)
            .chain(bans)
            .chain(issuers)
            .chain([settings])
            .collect()
    }

    /// Rebuild a policy from a head's fields and its items (the inverse of
    /// [`items`](Self::items)). [`Error::InvalidPolicy`] if the items are not
    /// strictly in key order or hold no settings item.
    pub fn from_items(head: &PolicyHead, items: &[Item]) -> Result<Policy> {
        if let Some(pair) = items.windows(2).find(|w| w[0].key() >= w[1].key()) {
            return Err(Error::InvalidPolicy(format!(
                "items out of order at {}",
                pair[1].key()
            )));
        }
        let mut policy = Policy::new(head.fabric);
        policy.version = head.version;
        policy.issued = head.issued;
        policy.not_after = head.not_after;
        policy.directories = head.directories.clone();
        let mut settings = None;
        for item in items {
            match item {
                Item::Role { key, body } => {
                    policy.roles.insert(key.clone(), body.clone());
                }
                Item::Service { key, body } => {
                    policy.services.insert(key.clone(), body.clone());
                }
                Item::Ban { key, body } => {
                    policy.bans.insert(*key, *body);
                }
                Item::Issuer { key, body } => {
                    policy.issuers.insert(key.clone(), body.clone());
                }
                Item::Settings { body } => settings = Some(*body),
            }
        }
        policy.settings =
            settings.ok_or_else(|| Error::InvalidPolicy("no settings item".into()))?;
        Ok(policy)
    }

    /// Validate, then sign as-is with the root key (the caller sets
    /// `version`, `issued` and `not_after`): the items' Merkle root and count
    /// go into the head. [`Error::FabricMismatch`] if `root` is not
    /// `fabric`.
    pub fn sign(&self, root: &NodeIdentity) -> Result<SignedPolicy> {
        if root.node_id() != self.fabric {
            return Err(Error::FabricMismatch);
        }
        self.validate()?;
        let items = self.items();
        let tree = tree_of(&items)?;
        let head = PolicyHead {
            format: POLICY_V3,
            fabric: self.fabric,
            version: self.version,
            issued: self.issued,
            not_after: self.not_after,
            directories: self.directories.clone(),
            items_root: tree.root(),
            item_count: tree.len(),
        }
        .sign(root)?;
        Ok(SignedPolicy { head, items })
    }

    /// Whether `role` admits a caller presenting `principal`: a defined role
    /// one of whose matchers matches it. With no principal, or an undefined
    /// role, nothing admits (exactly [`role_admits`](crate::role_admits)).
    pub fn role_admits(&self, role: &RoleName, principal: Option<&Principal>) -> bool {
        admits(self.roles.get(role).map(Vec::as_slice), principal)
    }

    /// Whether `node` is banned at `now`.
    pub fn is_banned(&self, node: NodeId, now: i64) -> bool {
        self.bans.get(&node).is_some_and(|b| b.holds(now))
    }
}

impl SignedPolicy {
    /// Verify the head under `root` ([`SignedPolicyHead::verify`]), that the
    /// items are strictly in key order and are exactly the tree the head
    /// commits to (count and root), then [`Policy::validate`]. Does not check
    /// freshness.
    pub fn verify(&self, root: NodeId) -> Result<()> {
        self.head.verify(root)?;
        let policy = self.to_policy()?;
        let tree = tree_of(&self.items)?;
        let head = &self.head.head;
        if tree.len() != head.item_count || tree.root() != head.items_root {
            return Err(Error::InvalidPolicy(
                "the items are not the ones the head commits to".into(),
            ));
        }
        policy.validate()
    }

    /// The editable [`Policy`] this was signed from.
    pub fn to_policy(&self) -> Result<Policy> {
        Policy::from_items(&self.head.head, &self.items)
    }

    /// The Merkle tree over the items (one `O(n)` build; prove from it).
    pub fn tree(&self) -> Result<ItemTree> {
        tree_of(&self.items)
    }

    /// `host`'s slice: the head and, with proofs, every service item naming
    /// `host`, every role those services' `allow` and `readers` name plus
    /// `extra_roles` (the roles its `host.json` names; undefined ones are
    /// skipped), every ban, every issuer, and the settings. Nothing else.
    ///
    /// ```
    /// use library::{
    ///     Audience, Issuer, IssuerConfig, ItemKey, Matcher, NodeIdentity, Policy, RoleName,
    ///     Service, ServiceName, StateVersion,
    /// };
    /// let root = NodeIdentity::from_seed([1u8; 32]);
    /// let (a, b) = (NodeIdentity::from_seed([2u8; 32]).node_id(), NodeIdentity::from_seed([3u8; 32]).node_id());
    /// let mut p = Policy::new(root.node_id());
    /// p.version = StateVersion(1);
    /// p.not_after = i64::MAX;
    /// p.issuers.insert(Issuer::new("https://idp"), IssuerConfig {
    ///     client_id: Audience::new("cli"), audiences: vec![Audience::new("cli")],
    /// });
    /// for (role, service, host) in [("dba", "orders-db", a), ("sre", "deploy", b)] {
    ///     let role = RoleName::new(role).unwrap();
    ///     p.roles.insert(role.clone(), vec![Matcher::new("https://idp")]);
    ///     p.services.insert(ServiceName::new(service).unwrap(), Service {
    ///         description: String::new(), allow: vec![role], hosts: vec![host], readers: vec![],
    ///     });
    /// }
    /// let slice = p.sign(&root).unwrap().slice_for_host(a, &[]).unwrap();
    /// slice.verify(root.node_id()).unwrap();
    /// // Host a sees its own service and role, never b's.
    /// assert!(slice.service(&ServiceName::new("orders-db").unwrap()).is_some());
    /// assert!(slice.service(&ServiceName::new("deploy").unwrap()).is_none());
    /// assert!(!slice.keys().contains(&ItemKey::Role(RoleName::new("sre").unwrap())));
    /// ```
    pub fn slice_for_host(&self, host: NodeId, extra_roles: &[RoleName]) -> Result<Slice> {
        let mut roles: BTreeSet<&RoleName> = extra_roles.iter().collect();
        for item in &self.items {
            if let Item::Service { body, .. } = item
                && body.hosts.contains(&host)
            {
                roles.extend(body.allow.iter().chain(&body.readers));
            }
        }
        let wanted = |item: &Item| match item {
            Item::Service { body, .. } => body.hosts.contains(&host),
            Item::Role { key, .. } => roles.contains(key),
            Item::Ban { .. } | Item::Issuer { .. } | Item::Settings { .. } => true,
        };
        let (picked, proof) = self.prove_where(|item| wanted(item).then_some(()))?;
        Ok(Slice {
            head: self.head.clone(),
            items: picked.into_iter().map(|(item, ())| item).collect(),
            proof,
        })
    }

    /// The update that moves `from` (this host's slice under an older head)
    /// to its slice under this policy: [`slice_for_host`](Self::slice_for_host)
    /// then [`Slice::update_to`]. The directory recomputes `from` from the
    /// older policy the subscriber's `have` names.
    pub fn slice_update(
        &self,
        from: &Slice,
        host: NodeId,
        extra_roles: &[RoleName],
    ) -> Result<SliceUpdate> {
        Ok(from.update_to(&self.slice_for_host(host, extra_roles)?))
    }

    /// The view of a caller presenting `principal`: the head and, with
    /// proofs, each service item whose `allow` (marked `call`) or `readers`
    /// (marked `read`) admits it. No role, ban, issuer or settings, and no
    /// other service; with no principal, no entries (no role admits). With a
    /// `query`, only the entries whose name or description contain it
    /// (ignoring ASCII case), proved as a set of their own.
    ///
    /// ```
    /// use library::{
    ///     Audience, Issuer, IssuerConfig, Matcher, NodeIdentity, Policy, Principal, RoleName,
    ///     Service, ServiceName, StateVersion,
    /// };
    /// let root = NodeIdentity::from_seed([1u8; 32]);
    /// let mut p = Policy::new(root.node_id());
    /// p.version = StateVersion(1);
    /// p.not_after = i64::MAX;
    /// p.issuers.insert(Issuer::new("https://idp"), IssuerConfig {
    ///     client_id: Audience::new("cli"), audiences: vec![Audience::new("cli")],
    /// });
    /// let alice_only = RoleName::new("alice-only").unwrap();
    /// p.roles.insert(alice_only.clone(), vec![Matcher {
    ///     email: Some("alice@example.com".parse().unwrap()),
    ///     ..Matcher::new("https://idp")
    /// }]);
    /// p.services.insert(ServiceName::new("payroll").unwrap(), Service {
    ///     description: String::new(), allow: vec![alice_only], hosts: vec![], readers: vec![],
    /// });
    /// let signed = p.sign(&root).unwrap();
    /// let mut who = Principal {
    ///     issuer: "https://idp".into(), subject: "1".into(),
    ///     email: Some("alice@example.com".into()), org: None, groups: vec![], not_after: 0,
    /// };
    /// let view = signed.view_for(Some(&who), None).unwrap();
    /// view.verify(root.node_id()).unwrap();
    /// assert!(view.entries[0].call);
    /// // Bob doesn't learn the service exists; nor does a caller with no identity.
    /// who.email = Some("bob@example.com".into());
    /// assert!(signed.view_for(Some(&who), None).unwrap().entries.is_empty());
    /// assert!(signed.view_for(None, None).unwrap().entries.is_empty());
    /// ```
    pub fn view_for(&self, principal: Option<&Principal>, query: Option<&str>) -> Result<View> {
        let roles: BTreeMap<&RoleName, &[Matcher]> = self
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Role { key, body } => Some((key, body.as_slice())),
                _ => None,
            })
            .collect();
        let admitted = |allowed: &[RoleName]| {
            allowed
                .iter()
                .any(|r| admits(roles.get(r).copied(), principal))
        };
        let query = query.map(str::to_ascii_lowercase);
        let marks = |item: &Item| match item {
            Item::Service { key, body }
                if query
                    .as_deref()
                    .is_none_or(|q| service_matches(key, body, q)) =>
            {
                let (call, read) = (admitted(&body.allow), admitted(&body.readers));
                (call || read).then_some((call, read))
            }
            _ => None,
        };
        let (picked, proof) = self.prove_where(marks)?;
        Ok(View {
            head: self.head.clone(),
            entries: picked
                .into_iter()
                .map(|(item, (call, read))| ViewEntry { item, call, read })
                .collect(),
            proof,
        })
    }

    /// The update that moves `from` (this caller's view under an older head,
    /// or with older marks) to its view under this policy.
    pub fn view_update(&self, from: &View, principal: Option<&Principal>) -> Result<ViewUpdate> {
        Ok(from.update_to(&self.view_for(principal, None)?))
    }

    /// Every item `pick` returns something for, with what it said, in leaf
    /// order, and one multiproof over them all.
    fn prove_where<T>(
        &self,
        pick: impl Fn(&Item) -> Option<T>,
    ) -> Result<(Vec<(Item, T)>, MultiProof)> {
        todo!("prove_where {}", std::any::type_name_of_val(&pick))
    }
}

/// The Merkle tree over `items`, in the order given.
fn tree_of(items: &[Item]) -> Result<ItemTree> {
    Ok(ItemTree::new(
        items.iter().map(ItemHash::of).collect::<Result<_>>()?,
    ))
}

/// Whether service `name`'s name or description contains `query` (already
/// lowercased), ignoring ASCII case.
pub(crate) fn service_matches(name: &ServiceName, svc: &Service, query: &str) -> bool {
    name.as_str().contains(query) || svc.description.to_ascii_lowercase().contains(query)
}

/// Whether `matchers` (a role's definition, if it has one) admit `principal`.
/// The one rule every admission check shares.
pub(crate) fn admits(matchers: Option<&[Matcher]>, principal: Option<&Principal>) -> bool {
    let (Some(matchers), Some(p)) = (matchers, principal) else {
        return false;
    };
    matchers.iter().any(|m| m.matches(p))
}

/// Shared test fixtures: a small, valid policy, and random ones.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use crate::idp::Audience;
    use proptest::prelude::*;

    /// The one trusted issuer.
    pub(crate) const ISS: &str = "https://idp.example";

    pub(crate) fn root() -> NodeIdentity {
        NodeIdentity::from_seed([1u8; 32])
    }

    pub(crate) fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    pub(crate) fn role(s: &str) -> RoleName {
        RoleName::new(s).unwrap()
    }

    pub(crate) fn name(s: &str) -> ServiceName {
        ServiceName::new(s).unwrap()
    }

    /// A principal verified by [`ISS`].
    pub(crate) fn who(email: &str) -> Principal {
        Principal {
            issuer: ISS.into(),
            subject: email.into(),
            email: Some(email.into()),
            org: None,
            groups: vec![],
            not_after: i64::MAX,
        }
    }

    pub(crate) fn service(allow: &[&str], readers: &[&str], hosts: &[u8]) -> Service {
        Service {
            description: String::new(),
            allow: allow.iter().map(|r| role(r)).collect(),
            hosts: hosts.iter().map(|h| node(*h)).collect(),
            readers: readers.iter().map(|r| role(r)).collect(),
        }
    }

    pub(crate) fn email(e: &str) -> Matcher {
        Matcher {
            email: Some(e.parse().unwrap()),
            ..Matcher::new(ISS)
        }
    }

    /// Version 3, one directory (30), hosts 10 and 11, one ban (20):
    ///
    /// | service | allow | readers | hosts |
    /// |---|---|---|---|
    /// | `orders-db` | analyst (alice) | auditor (carol) | 10 |
    /// | `status` | staff (anyone at ISS) | — | 10, 11 |
    /// | `deploy` | oncall (group sre) | — | 11 |
    /// | `locked` | — | auditor | 11 |
    pub(crate) fn sample() -> Policy {
        let mut p = Policy::new(root().node_id());
        p.version = StateVersion(3);
        p.issued = 1;
        p.not_after = 1_000;
        p.directories = vec![node(30)];
        p.issuers.insert(
            Issuer::new(ISS),
            IssuerConfig {
                client_id: Audience::new("cli"),
                audiences: vec![Audience::new("cli")],
            },
        );
        p.roles
            .insert(role("analyst"), vec![email("alice@example.com")]);
        p.roles
            .insert(role("auditor"), vec![email("carol@example.com")]);
        p.roles.insert(role("staff"), vec![Matcher::new(ISS)]);
        p.roles.insert(
            role("oncall"),
            vec![Matcher {
                group: Some("sre".into()),
                ..Matcher::new(ISS)
            }],
        );
        p.services.insert(
            name("orders-db"),
            service(&["analyst"], &["auditor"], &[10]),
        );
        p.services
            .insert(name("status"), service(&["staff"], &[], &[10, 11]));
        p.services
            .insert(name("deploy"), service(&["oncall"], &[], &[11]));
        p.services
            .insert(name("locked"), service(&[], &["auditor"], &[11]));
        p.bans.insert(node(20), Ban { until: 500 });
        p
    }

    /// A random policy over roles r0..r4, services s0..s7 and hosts 10..13.
    pub(crate) fn arb_policy() -> impl Strategy<Value = Policy> {
        let matcher = prop_oneof![
            Just(Matcher::new(ISS)),
            Just(email("alice@example.com")),
            Just(email("*@corp.example")),
            Just(Matcher {
                group: Some("sre".into()),
                ..Matcher::new(ISS)
            }),
        ];
        let roles = proptest::collection::vec(proptest::collection::vec(matcher, 1..3), 5);
        let subset = |n: usize| proptest::collection::btree_set(0..n, 0..=n);
        let services = proptest::collection::vec((subset(5), subset(5), subset(4)), 0..8);
        let bans = proptest::collection::btree_map(40u8..60, any::<i64>(), 0..5);
        (roles, services, bans).prop_map(|(roles, services, bans)| {
            let mut p = sample();
            p.roles.clear();
            p.services.clear();
            p.bans.clear();
            for (i, matchers) in roles.into_iter().enumerate() {
                p.roles.insert(role(&format!("r{i}")), matchers);
            }
            for (i, (allow, readers, hosts)) in services.into_iter().enumerate() {
                p.services.insert(
                    name(&format!("s{i}")),
                    Service {
                        description: format!("service {i}"),
                        allow: allow.into_iter().map(|r| role(&format!("r{r}"))).collect(),
                        hosts: hosts.into_iter().map(|h| node(10 + h as u8)).collect(),
                        readers: readers
                            .into_iter()
                            .map(|r| role(&format!("r{r}")))
                            .collect(),
                    },
                );
            }
            for (b, until) in bans {
                p.bans.insert(node(b), Ban { until });
            }
            p
        })
    }

    /// A random principal (or none) from a few emails, two issuers, and the
    /// `sre` group or not.
    pub(crate) fn arb_principal() -> impl Strategy<Value = Option<Principal>> {
        let email = prop_oneof![
            Just("alice@example.com"),
            Just("bob@corp.example"),
            Just("eve@elsewhere.example"),
        ];
        let issuer = prop_oneof![Just(ISS), Just("https://partner.example")];
        proptest::option::of((email, issuer, any::<bool>()).prop_map(|(e, iss, sre)| {
            let mut p = who(e);
            p.issuer = iss.into();
            if sre {
                p.groups = vec!["sre".into()];
            }
            p
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::idp::Audience;
    use crate::item::ItemKey;
    use proptest::prelude::*;

    /// The rule `validate` says `p` breaks.
    fn broken_rule(p: &Policy) -> String {
        match p.validate() {
            Err(Error::InvalidPolicy(why)) => why,
            other => panic!("expected InvalidPolicy, got {other:?}"),
        }
    }

    fn keys(items: &[Item]) -> Vec<ItemKey> {
        items.iter().map(Item::key).collect()
    }

    #[test]
    fn sign_verify_round_trip() {
        let signed = sample().sign(&root()).unwrap();
        signed.verify(root().node_id()).unwrap();
        assert_eq!(signed.to_policy().unwrap(), sample());
        let back: SignedPolicy =
            serde_json::from_str(&serde_json::to_string(&signed).unwrap()).unwrap();
        assert_eq!(back, signed);
        back.verify(root().node_id()).unwrap();
        assert_eq!(signed.head.head.format, POLICY_V3);
        assert_eq!(signed.head.head.directories, vec![node(30)]);
        assert_eq!(signed.head.head.item_count, 4 + 4 + 1 + 1 + 1);
        assert_eq!(signed.head.head.items_root, signed.tree().unwrap().root());
    }

    #[test]
    fn items_come_out_in_key_order() {
        let items = sample().items();
        let k = keys(&items);
        assert!(k.windows(2).all(|w| w[0] < w[1]), "{k:?}");
        assert_eq!(
            k,
            vec![
                ItemKey::Role(role("analyst")),
                ItemKey::Role(role("auditor")),
                ItemKey::Role(role("oncall")),
                ItemKey::Role(role("staff")),
                ItemKey::Service(name("deploy")),
                ItemKey::Service(name("locked")),
                ItemKey::Service(name("orders-db")),
                ItemKey::Service(name("status")),
                ItemKey::Ban(node(20)),
                ItemKey::Issuer(Issuer::new(ISS)),
                ItemKey::Settings,
            ]
        );
    }

    #[test]
    fn a_new_policy_is_just_its_settings() {
        let p = Policy::new(root().node_id());
        assert_eq!(p.version, StateVersion(0));
        assert_eq!(p.not_after, 0);
        assert_eq!(p.settings, Settings::default());
        assert_eq!(p.items().len(), 1);
        p.validate().unwrap();
    }

    #[test]
    fn validation_rules() {
        sample().validate().unwrap();

        let mut p = sample();
        p.directories.push(node(30));
        assert!(broken_rule(&p).contains("twice"));
        assert!(matches!(p.sign(&root()), Err(Error::InvalidPolicy(_))));

        let mut p = sample();
        p.roles.insert(role("x"), vec![]);
        assert_eq!(broken_rule(&p), "role x has no matchers");

        let mut p = sample();
        p.roles.insert(role("x"), vec![Matcher::new(" ")]);
        assert_eq!(broken_rule(&p), "role x has a matcher with no issuer");

        let mut p = sample();
        p.roles
            .insert(role("x"), vec![Matcher::new("https://untrusted")]);
        assert_eq!(
            broken_rule(&p),
            "role x names issuer https://untrusted, which is not trusted"
        );

        let mut p = sample();
        p.services.get_mut(&name("status")).unwrap().allow = vec![role("ghost")];
        assert_eq!(broken_rule(&p), "service status names undefined role ghost");

        let mut p = sample();
        p.services.get_mut(&name("status")).unwrap().readers = vec![role("ghost")];
        assert_eq!(broken_rule(&p), "service status names undefined role ghost");

        let mut p = sample();
        p.services.get_mut(&name("status")).unwrap().hosts = vec![node(10), node(10)];
        assert!(broken_rule(&p).contains("twice"));

        let mut p = sample();
        p.issuers.insert(
            Issuer::new(" "),
            IssuerConfig {
                client_id: Audience::new(""),
                audiences: vec![Audience::new("a")],
            },
        );
        assert_eq!(broken_rule(&p), "an issuer is blank");

        let mut p = sample();
        p.issuers.get_mut(&Issuer::new(ISS)).unwrap().audiences = vec![];
        assert_eq!(broken_rule(&p), format!("issuer {ISS} accepts no audience"));

        let mut p = sample();
        p.issuers.get_mut(&Issuer::new(ISS)).unwrap().audiences = vec![Audience::new(" ")];
        assert_eq!(broken_rule(&p), format!("issuer {ISS} accepts no audience"));

        let mut p = sample();
        p.settings.beat_secs = 0;
        assert_eq!(broken_rule(&p), "settings: beat_secs is 0");

        let mut p = sample();
        p.settings.fresh_secs = p.settings.beat_secs - 1;
        assert_eq!(
            broken_rule(&p),
            "settings: fresh_secs is shorter than beat_secs"
        );
    }

    #[test]
    fn only_the_root_signs() {
        assert!(matches!(
            sample().sign(&NodeIdentity::from_seed([9u8; 32])),
            Err(Error::FabricMismatch)
        ));
        let signed = sample().sign(&root()).unwrap();
        assert!(signed.verify(node(9)).is_err());
    }

    #[test]
    fn items_must_be_exactly_what_the_head_commits_to() {
        let signed = sample().sign(&root()).unwrap();
        let verify = |s: &SignedPolicy| s.verify(root().node_id());

        let mut t = signed.clone();
        t.items.swap(0, 1);
        assert!(matches!(verify(&t), Err(Error::InvalidPolicy(_))));

        let mut t = signed.clone();
        t.items.remove(0);
        assert!(verify(&t).is_err());

        let mut t = signed.clone();
        t.items.insert(
            8,
            Item::Ban {
                key: node(21),
                body: Ban { until: 1 },
            },
        );
        assert!(verify(&t).is_err());

        let mut t = signed.clone();
        let Some(Item::Ban { body, .. }) =
            t.items.iter_mut().find(|i| matches!(i, Item::Ban { .. }))
        else {
            unreachable!()
        };
        body.until += 1;
        assert!(verify(&t).is_err());

        // A second settings item, even correctly signed, is refused.
        let mut items = sample().items();
        items.push(Item::Settings {
            body: Settings::default(),
        });
        assert!(Policy::from_items(&signed.head.head, &items).is_err());

        // Another version's head over these items.
        let mut p = sample();
        p.version = StateVersion(4);
        p.bans.clear();
        let mut t = signed;
        t.head = p.sign(&root()).unwrap().head;
        assert!(verify(&t).is_err());
    }

    #[test]
    fn roles_admit_only_verified_principals_of_their_issuer() {
        let p = sample();
        let alice = who("alice@example.com");
        assert!(p.role_admits(&role("analyst"), Some(&alice)));
        assert!(p.role_admits(&role("staff"), Some(&alice)));
        assert!(!p.role_admits(&role("auditor"), Some(&alice)));
        assert!(!p.role_admits(&role("staff"), None));
        assert!(!p.role_admits(&role("ghost"), Some(&alice)));
        let mut elsewhere = alice;
        elsewhere.issuer = "https://partner.example".into();
        assert!(!p.role_admits(&role("analyst"), Some(&elsewhere)));
    }

    #[test]
    fn bans_hold_until_their_until() {
        let p = sample();
        assert!(p.is_banned(node(20), 500));
        assert!(!p.is_banned(node(20), 501));
        assert!(!p.is_banned(node(21), 0));
    }

    #[test]
    fn a_host_slice_holds_only_what_the_host_needs() {
        let signed = sample().sign(&root()).unwrap();
        let slice = signed.slice_for_host(node(10), &[]).unwrap();
        slice.verify(root().node_id()).unwrap();
        assert_eq!(
            slice.keys(),
            vec![
                ItemKey::Role(role("analyst")),
                ItemKey::Role(role("auditor")),
                ItemKey::Role(role("staff")),
                ItemKey::Service(name("orders-db")),
                ItemKey::Service(name("status")),
                ItemKey::Ban(node(20)),
                ItemKey::Issuer(Issuer::new(ISS)),
                ItemKey::Settings,
            ]
        );
        // host.json's roles come along; an undefined one is skipped.
        let slice = signed
            .slice_for_host(node(11), &[role("analyst"), role("ghost")])
            .unwrap();
        slice.verify(root().node_id()).unwrap();
        assert_eq!(
            slice.keys(),
            vec![
                ItemKey::Role(role("analyst")),
                ItemKey::Role(role("auditor")),
                ItemKey::Role(role("oncall")),
                ItemKey::Role(role("staff")),
                ItemKey::Service(name("deploy")),
                ItemKey::Service(name("locked")),
                ItemKey::Service(name("status")),
                ItemKey::Ban(node(20)),
                ItemKey::Issuer(Issuer::new(ISS)),
                ItemKey::Settings,
            ]
        );
        // A node that hosts nothing still gets bans, issuers and settings.
        let slice = signed.slice_for_host(node(99), &[]).unwrap();
        assert_eq!(
            slice.keys(),
            vec![
                ItemKey::Ban(node(20)),
                ItemKey::Issuer(Issuer::new(ISS)),
                ItemKey::Settings,
            ]
        );
    }

    #[test]
    fn a_view_holds_only_what_its_caller_may_use() {
        let signed = sample().sign(&root()).unwrap();
        let marks = |p: Option<&Principal>| -> Vec<(String, bool, bool)> {
            let view = signed.view_for(p, None).unwrap();
            view.verify(root().node_id()).unwrap();
            view.entries
                .iter()
                .map(|e| (e.service().unwrap().0.to_string(), e.call, e.read))
                .collect()
        };
        assert_eq!(
            marks(Some(&who("alice@example.com"))),
            vec![
                ("orders-db".into(), true, false),
                ("status".into(), true, false)
            ]
        );
        assert_eq!(
            marks(Some(&who("carol@example.com"))),
            vec![
                ("locked".into(), false, true),
                ("orders-db".into(), false, true),
                ("status".into(), true, false),
            ]
        );
        let mut sre = who("dan@example.com");
        sre.groups = vec!["sre".into()];
        assert_eq!(
            marks(Some(&sre)),
            vec![
                ("deploy".into(), true, false),
                ("status".into(), true, false)
            ]
        );
        assert!(marks(None).is_empty());
        let mut elsewhere = who("alice@example.com");
        elsewhere.issuer = "https://partner.example".into();
        assert!(marks(Some(&elsewhere)).is_empty());
    }

    #[test]
    fn a_view_query_is_a_view_of_its_own() {
        let mut p = sample();
        p.services.get_mut(&name("status")).unwrap().description =
            "Uptime of the ORDERS stack".into();
        let signed = p.sign(&root()).unwrap();
        let alice = who("alice@example.com");
        let names = |q| -> Vec<String> {
            let view = signed.view_for(Some(&alice), q).unwrap();
            view.verify(root().node_id()).unwrap();
            view.entries
                .iter()
                .map(|e| e.service().unwrap().0.to_string())
                .collect()
        };
        assert_eq!(names(Some("orders")), vec!["orders-db", "status"]);
        assert_eq!(names(Some("DB")), vec!["orders-db"]);
        assert!(names(Some("deploy")).is_empty(), "not alice's to see");
        assert!(names(Some("no such thing")).is_empty());
    }

    #[test]
    fn a_part_cut_from_one_head_fails_under_another() {
        let v3 = sample().sign(&root()).unwrap();
        let mut p = sample();
        p.version = StateVersion(4);
        p.bans.insert(node(21), Ban { until: 900 });
        let v4 = p.sign(&root()).unwrap();

        let mut slice = v3.slice_for_host(node(10), &[]).unwrap();
        slice.head = v4.head.clone();
        assert!(matches!(
            slice.verify(root().node_id()),
            Err(Error::BadProof)
        ));

        let mut view = v3.view_for(Some(&who("alice@example.com")), None).unwrap();
        view.head = v4.head;
        assert!(matches!(
            view.verify(root().node_id()),
            Err(Error::BadProof)
        ));
    }

    proptest! {
        #[test]
        fn any_policy_round_trips(p in arb_policy()) {
            let signed = p.sign(&root()).unwrap();
            prop_assert!(signed.verify(root().node_id()).is_ok());
            prop_assert_eq!(signed.to_policy().unwrap(), p);
        }

        #[test]
        fn slices_hold_exactly_what_their_host_needs(
            p in arb_policy(),
            host in 10u8..15,
            extra in proptest::collection::vec(0usize..7, 0..3),
        ) {
            let signed = p.sign(&root()).unwrap();
            let extra: Vec<RoleName> = extra.iter().map(|r| role(&format!("r{r}"))).collect();
            let slice = signed.slice_for_host(node(host), &extra).unwrap();
            prop_assert!(slice.verify(root().node_id()).is_ok());

            let mine: BTreeSet<&ServiceName> = p
                .services
                .iter()
                .filter(|(_, s)| s.hosts.contains(&node(host)))
                .map(|(n, _)| n)
                .collect();
            let needed: BTreeSet<&RoleName> = mine
                .iter()
                .flat_map(|n| p.services[*n].allow.iter().chain(&p.services[*n].readers))
                .chain(extra.iter())
                .filter(|r| p.roles.contains_key(*r))
                .collect();
            let mut services = BTreeSet::new();
            let mut roles = BTreeSet::new();
            let mut bans = 0;
            for item in &slice.items {
                match item {
                    Item::Service { key, body } => {
                        prop_assert!(body.hosts.contains(&node(host)), "{key} doesn't name the host");
                        services.insert(key);
                    }
                    Item::Role { key, .. } => {
                        prop_assert!(needed.contains(key), "role {key} isn't needed");
                        roles.insert(key);
                    }
                    Item::Ban { .. } => bans += 1,
                    Item::Issuer { .. } | Item::Settings { .. } => {}
                }
            }
            prop_assert_eq!(services, mine);
            prop_assert_eq!(roles, needed);
            prop_assert_eq!(bans, p.bans.len());
            prop_assert_eq!(slice.settings(), Some(&p.settings));
        }

        #[test]
        fn views_hold_exactly_what_their_caller_may_use(
            p in arb_policy(),
            principal in arb_principal(),
        ) {
            let signed = p.sign(&root()).unwrap();
            let view = signed.view_for(principal.as_ref(), None).unwrap();
            prop_assert!(view.verify(root().node_id()).is_ok());
            // The rule, spelled out independently of `admits`.
            let admits = |r: &RoleName| match (&principal, p.roles.get(r)) {
                (Some(who), Some(ms)) => ms.iter().any(|m| m.matches(who)),
                _ => false,
            };
            let want: Vec<(ServiceName, bool, bool)> = p
                .services
                .iter()
                .map(|(n, s)| (n.clone(), s.allow.iter().any(admits), s.readers.iter().any(admits)))
                .filter(|(_, call, read)| *call || *read)
                .collect();
            let got: Vec<(ServiceName, bool, bool)> = view
                .entries
                .iter()
                .map(|e| (e.service().unwrap().0.clone(), e.call, e.read))
                .collect();
            prop_assert_eq!(got, want);
            if principal.is_none() {
                prop_assert!(view.entries.is_empty());
            }
        }
    }
}

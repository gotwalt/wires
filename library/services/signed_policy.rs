//! The whole policy: every item, as the admin edits it ([`Policy`]) and as
//! it is signed and published ([`SignedPolicy`]: the root-signed head and the
//! items it commits to). Card 36's replacement for the one-blob state.
//!
//! **The root signs the policy, and each service entry, like a badge.** The
//! head signs an [`ItemsHash`] over every item, so a node holding the whole
//! policy (the admin, a directory, a host) checks it all with one signature,
//! and a directory can't forge, drop or mix items. Each service item is also
//! a [`SignedEntry`] with its own root signature, so a caller can hold just
//! the services it may use (its [`View`], cut here by
//! [`view_for`](SignedPolicy::view_for)) and check each one alone. Hosts
//! follow the policy by [`PolicyUpdate`](crate::PolicyUpdate)s
//! ([`SignedPolicy::apply`]).
//!
//! [`Policy`] is typed maps, like the state, so an edit can't produce two
//! items with one key or a second settings item; [`Policy::items`] flattens
//! them into key order, signing each service entry. [`Policy::validate`]
//! carries over the state's rules (every role a service names is defined,
//! every matcher names a trusted issuer, each host listed once) and adds the
//! new kinds'.
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
//! assert_eq!(signed.items.len(), 4); // role, service, issuer, settings
//! ```

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::entry::SignedEntry;
use crate::error::{Error, Result};
use crate::head::StateVersion;
use crate::head::{ItemsHash, POLICY_V3, PolicyHead, SignedPolicyHead};
use crate::identity::{NodeId, NodeIdentity};
use crate::idp::{Issuer, Principal};
use crate::item::{Ban, IssuerConfig, Item, Settings};
use crate::registry::{Service, ServiceName};
use crate::role::{Matcher, RoleName};
use crate::view::{View, ViewEntry};

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
/// key order. What the admin publishes, and what a directory and every host
/// hold.
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
    ///   lists each host once, none of them banned;
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
            if let Some(h) = svc.hosts.iter().find(|h| self.bans.contains_key(h)) {
                return bad(format!("service {name}: host {} is banned", h.hex()));
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

    /// Every item, in key ([`ItemKey`](crate::ItemKey)) order. Each service
    /// is signed by `root` at this policy's version, unless `previous` holds
    /// the same entry (same fabric, name and body), which is kept with its
    /// signature and version. [`Error::FabricMismatch`] if `root` is not
    /// `fabric`.
    pub fn items(&self, root: &NodeIdentity, previous: Option<&SignedPolicy>) -> Result<Vec<Item>> {
        if root.node_id() != self.fabric {
            return Err(Error::FabricMismatch);
        }
        let kept: BTreeMap<&ServiceName, &SignedEntry> = previous
            .map(|p| p.entries().map(|e| (&e.name, e)).collect())
            .unwrap_or_default();
        // Each map iterates in its key's order, and the kinds follow in
        // `ItemKey`'s order, so the concatenation is sorted.
        let roles = self.roles.iter().map(|(k, v)| Item::Role {
            key: k.clone(),
            body: v.clone(),
        });
        let mut items: Vec<Item> = roles.collect();
        for (name, svc) in &self.services {
            let entry = match kept.get(name) {
                Some(e) if e.is_for(self.fabric, name, svc) && e.version <= self.version => {
                    (*e).clone()
                }
                _ => SignedEntry::sign(root, self.version, name.clone(), svc.clone())?,
            };
            items.push(Item::Service(entry));
        }
        items.extend(
            self.bans
                .iter()
                .map(|(k, v)| Item::Ban { key: *k, body: *v }),
        );
        items.extend(self.issuers.iter().map(|(k, v)| Item::Issuer {
            key: k.clone(),
            body: v.clone(),
        }));
        items.push(Item::Settings {
            body: self.settings,
        });
        Ok(items)
    }

    /// Rebuild a policy from a head's fields and its items (the inverse of
    /// [`items`](Self::items); entries lose their signatures).
    /// [`Error::InvalidPolicy`] if the items are not strictly in key order or
    /// hold no settings item.
    pub fn from_items(head: &PolicyHead, items: &[Item]) -> Result<Policy> {
        check_order(items)?;
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
                Item::Service(entry) => {
                    policy
                        .services
                        .insert(entry.name.clone(), entry.service.clone());
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
    /// `version`, `issued` and `not_after`): every service entry at this
    /// version, and the head over the items' hash.
    /// [`Error::FabricMismatch`] if `root` is not `fabric`. An edit uses
    /// [`sign_after`](Self::sign_after) instead, so unchanged entries keep
    /// their version.
    pub fn sign(&self, root: &NodeIdentity) -> Result<SignedPolicy> {
        self.sign_with(root, None)
    }

    /// [`sign`](Self::sign), keeping from `previous` (the policy this one
    /// edits) every service entry the edit didn't change, with its signature
    /// and version: the admin re-signs only what changed, and a caller
    /// holding an unchanged entry needs nothing new.
    ///
    /// ```
    /// use library::{Item, NodeIdentity, Policy, Service, ServiceName, StateVersion};
    /// let root = NodeIdentity::from_seed([1u8; 32]);
    /// let mut p = Policy::new(root.node_id());
    /// p.version = StateVersion(1);
    /// p.not_after = i64::MAX;
    /// for name in ["a", "b"] {
    ///     p.services.insert(ServiceName::new(name).unwrap(), Service {
    ///         description: String::new(), allow: vec![], hosts: vec![], readers: vec![],
    ///     });
    /// }
    /// let v1 = p.sign(&root).unwrap();
    /// p.version = StateVersion(2);
    /// p.services.get_mut(&ServiceName::new("b").unwrap()).unwrap().description = "new".into();
    /// let v2 = p.sign_after(&root, &v1).unwrap();
    /// let versions: Vec<u64> = v2.entries().map(|e| e.version.0).collect();
    /// assert_eq!(versions, [1, 2], "only b was re-signed");
    /// ```
    pub fn sign_after(&self, root: &NodeIdentity, previous: &SignedPolicy) -> Result<SignedPolicy> {
        self.sign_with(root, Some(previous))
    }

    fn sign_with(
        &self,
        root: &NodeIdentity,
        previous: Option<&SignedPolicy>,
    ) -> Result<SignedPolicy> {
        if root.node_id() != self.fabric {
            return Err(Error::FabricMismatch);
        }
        self.validate()?;
        let items = self.items(root, previous)?;
        let head = PolicyHead {
            format: POLICY_V3,
            fabric: self.fabric,
            version: self.version,
            issued: self.issued,
            not_after: self.not_after,
            directories: self.directories.clone(),
            items_hash: ItemsHash::of(&items)?,
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

    /// Whether the policy holds a ban for `node`, whatever its `until`: the
    /// rule every gate applies (a ban holds until an edit prunes it, and by
    /// then the badge it cancels has expired). [`is_banned`](Self::is_banned)
    /// also lets it lapse at `until`; both agree while that badge is valid.
    pub fn bans_node(&self, node: NodeId) -> bool {
        self.bans.contains_key(&node)
    }

    /// Every host: each node that some service's `hosts` names. Derived, so
    /// assigning a service is what makes a node a host.
    pub fn hosts(&self) -> BTreeSet<NodeId> {
        self.services
            .values()
            .flat_map(|s| s.hosts.iter().copied())
            .collect()
    }

    /// Whether `node` is a host: some service names it, and it is not banned.
    pub fn is_host(&self, node: NodeId) -> bool {
        !self.bans_node(node) && self.services.values().any(|s| s.hosts.contains(&node))
    }

    /// The registry entry for `name`, if any.
    pub fn service(&self, name: &ServiceName) -> Option<&Service> {
        self.services.get(name)
    }

    /// Whether the registry assigns `service` to `host`, which is not
    /// banned: what a host checks before serving a name, and what a caller
    /// checks before dialing.
    ///
    /// ```
    /// use library::{NodeIdentity, Policy, Service, ServiceName};
    /// let mut p = Policy::new(NodeIdentity::from_seed([1u8; 32]).node_id());
    /// let host = NodeIdentity::from_seed([2u8; 32]).node_id();
    /// let status = ServiceName::new("status").unwrap();
    /// p.services.insert(status.clone(), Service {
    ///     description: String::new(), allow: vec![], hosts: vec![host], readers: vec![],
    /// });
    /// assert!(p.assigns(&status, host) && p.is_host(host));
    /// p.ban(host, i64::MAX);
    /// assert!(!p.assigns(&status, host) && !p.is_host(host));
    /// ```
    pub fn assigns(&self, service: &ServiceName, host: NodeId) -> bool {
        !self.bans_node(host)
            && self
                .service(service)
                .is_some_and(|s| s.hosts.contains(&host))
    }

    /// Whether `node` is banned at `now` (`now <= until`). Same verdict as
    /// [`bans_node`](Self::bans_node) on a pruned policy: a ban
    /// past its `until` cancels a badge that has expired anyway.
    pub fn is_banned(&self, node: NodeId, now: i64) -> bool {
        self.bans.get(&node).is_some_and(|b| b.holds(now))
    }

    /// Ban `node` until `until` (unix seconds); a node already banned keeps
    /// the later of its two `until`s.
    ///
    /// ```
    /// use library::{NodeIdentity, Policy};
    /// let mut p = Policy::new(NodeIdentity::from_seed([1u8; 32]).node_id());
    /// let node = NodeIdentity::from_seed([2u8; 32]).node_id();
    /// p.ban(node, 200);
    /// p.ban(node, 100);
    /// assert!(p.is_banned(node, 200));
    /// assert_eq!(p.prune_bans(201), 1);
    /// assert!(p.bans.is_empty());
    /// ```
    pub fn ban(&mut self, node: NodeId, until: i64) {
        let ban = self.bans.entry(node).or_insert(Ban { until });
        ban.until = ban.until.max(until);
    }

    /// Drop every ban whose `until` is before `now` (every admin edit runs
    /// it, so the policy tracks recent removals, not every node ever
    /// removed). Returns how many were dropped.
    pub fn prune_bans(&mut self, now: i64) -> usize {
        let before = self.bans.len();
        self.bans.retain(|_, ban| ban.holds(now));
        before - self.bans.len()
    }
}

impl SignedPolicy {
    /// This policy's version (its head's).
    pub fn version(&self) -> StateVersion {
        self.head.head.version
    }

    /// Whether this policy should replace `other`: same fabric and a strictly
    /// higher version ([`SignedPolicyHead::is_newer_than`]). Says nothing
    /// about signatures; verify first.
    pub fn is_newer_than(&self, other: &SignedPolicy) -> bool {
        self.head.is_newer_than(&other.head)
    }

    /// The one check for a whole signed policy: the head verifies under
    /// `root` ([`SignedPolicyHead::verify`]); the items are strictly in key
    /// order and hash to the head's `items_hash`
    /// ([`Error::ItemsMismatch`]); every service entry verifies on its own
    /// under `root`, at a version no higher than the head's; then
    /// [`Policy::validate`]. Does not check freshness.
    pub fn verify(&self, root: NodeId) -> Result<()> {
        self.check_items(root, self.entries())
    }

    /// [`verify`](Self::verify), checking the signatures of only `entries`
    /// (those not already verified in a policy this one was built from).
    pub(crate) fn check_items<'a>(
        &self,
        root: NodeId,
        entries: impl IntoIterator<Item = &'a SignedEntry>,
    ) -> Result<()> {
        self.head.verify(root)?;
        let policy = self.to_policy()?;
        if ItemsHash::of(&self.items)? != self.head.head.items_hash {
            return Err(Error::ItemsMismatch);
        }
        for entry in self.entries() {
            check_entry_version(entry, &self.head)?;
        }
        for entry in entries {
            entry.verify(root)?;
        }
        policy.validate()
    }

    /// The editable [`Policy`] this was signed from.
    pub fn to_policy(&self) -> Result<Policy> {
        Policy::from_items(&self.head.head, &self.items)
    }

    /// Every service entry, in name order.
    pub fn entries(&self) -> impl Iterator<Item = &SignedEntry> {
        self.items.iter().filter_map(|item| match item {
            Item::Service(entry) => Some(entry),
            _ => None,
        })
    }

    /// The view of a caller presenting `principal`: the head and each
    /// service entry whose `allow` (marked `call`) or `readers` (marked
    /// `read`) admits it, each with its own root signature. No role, ban,
    /// issuer or settings, and no other service; with no principal, no
    /// entries (no role admits). With a `query`, only the entries whose name
    /// or description contain it (ignoring ASCII case).
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
    /// let view = signed.view_for(Some(&who), None);
    /// view.verify(root.node_id()).unwrap();
    /// assert!(view.entries[0].call);
    /// // Each entry verifies on its own, too.
    /// view.entries[0].entry.verify(root.node_id()).unwrap();
    /// // Bob doesn't learn the service exists; nor does a caller with no identity.
    /// who.email = Some("bob@example.com".into());
    /// assert!(signed.view_for(Some(&who), None).entries.is_empty());
    /// assert!(signed.view_for(None, None).entries.is_empty());
    /// ```
    pub fn view_for(&self, principal: Option<&Principal>, query: Option<&str>) -> View {
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
        let entries = self
            .entries()
            .filter(|e| {
                query
                    .as_deref()
                    .is_none_or(|q| service_matches(&e.name, &e.service, q))
            })
            .filter_map(|e| {
                let (call, read) = (admitted(&e.service.allow), admitted(&e.service.readers));
                (call || read).then(|| ViewEntry {
                    entry: e.clone(),
                    call,
                    read,
                })
            })
            .collect();
        View {
            head: self.head.clone(),
            entries,
        }
    }
}

/// [`Error::InvalidPolicy`] unless `items` are strictly in key order (so no
/// key is repeated).
pub(crate) fn check_order(items: &[Item]) -> Result<()> {
    match items.windows(2).find(|w| w[0].key() >= w[1].key()) {
        Some(pair) => Err(Error::InvalidPolicy(format!(
            "items out of order at {}",
            pair[1].key()
        ))),
        None => Ok(()),
    }
}

/// [`Error::InvalidPolicy`] unless `entry` belongs to `head`'s fabric and
/// was last changed no later than `head`'s version.
pub(crate) fn check_entry_version(entry: &SignedEntry, head: &SignedPolicyHead) -> Result<()> {
    if entry.fabric != head.head.fabric {
        return Err(Error::InvalidSignature);
    }
    if entry.version > head.head.version {
        return Err(Error::InvalidPolicy(format!(
            "service {} is at version {}, after its head's {}",
            entry.name, entry.version.0, head.head.version.0
        )));
    }
    Ok(())
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

    /// The service entry `n` of `signed`.
    fn entry<'a>(signed: &'a SignedPolicy, n: &str) -> &'a SignedEntry {
        signed.entries().find(|e| e.name == name(n)).unwrap()
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
        assert_eq!(signed.items.len(), 4 + 4 + 1 + 1 + 1);
        assert_eq!(
            signed.head.head.items_hash,
            ItemsHash::of(&signed.items).unwrap()
        );
        // Every entry is signed at the policy's version, and verifies alone.
        for e in signed.entries() {
            assert_eq!(e.version, StateVersion(3));
            e.verify(root().node_id()).unwrap();
        }
    }

    #[test]
    fn items_come_out_in_key_order() {
        let items = sample().items(&root(), None).unwrap();
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
        assert!(matches!(
            sample().items(&NodeIdentity::from_seed([9u8; 32]), None),
            Err(Error::FabricMismatch)
        ));
    }

    #[test]
    fn a_new_policy_is_just_its_settings() {
        let p = Policy::new(root().node_id());
        assert_eq!(p.version, StateVersion(0));
        assert_eq!(p.not_after, 0);
        assert_eq!(p.settings, Settings::default());
        assert_eq!(p.items(&root(), None).unwrap().len(), 1);
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

        // Missing, extra and tampered items no longer hash to the head's.
        let mut t = signed.clone();
        t.items.remove(0);
        assert!(matches!(verify(&t), Err(Error::ItemsMismatch)));

        let mut t = signed.clone();
        t.items.insert(
            8,
            Item::Ban {
                key: node(21),
                body: Ban { until: 1 },
            },
        );
        t.items.sort_by_key(Item::key);
        assert!(matches!(verify(&t), Err(Error::ItemsMismatch)));

        let mut t = signed.clone();
        let Some(Item::Ban { body, .. }) =
            t.items.iter_mut().find(|i| matches!(i, Item::Ban { .. }))
        else {
            unreachable!()
        };
        body.until += 1;
        assert!(matches!(verify(&t), Err(Error::ItemsMismatch)));

        // A second settings item, even correctly signed, is refused.
        let mut items = sample().items(&root(), None).unwrap();
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

    /// The head's hash covers every entry, but each entry must also verify on
    /// its own: a policy whose head the root signed over an entry it didn't
    /// is refused, as is one carrying an entry from after its head.
    #[test]
    fn every_entry_verifies_on_its_own() {
        let resign = |mut items: Vec<Item>, edit: &dyn Fn(&mut SignedEntry)| {
            for item in &mut items {
                if let Item::Service(e) = item
                    && e.name == name("status")
                {
                    edit(e);
                }
            }
            let mut head = sample().sign(&root()).unwrap().head.head;
            head.items_hash = ItemsHash::of(&items).unwrap();
            SignedPolicy {
                head: head.sign(&root()).unwrap(),
                items,
            }
        };
        let items = sample().items(&root(), None).unwrap();
        resign(items.clone(), &|_| {})
            .verify(root().node_id())
            .unwrap();

        let forged = resign(items.clone(), &|e| e.service.hosts.push(node(12)));
        assert!(matches!(
            forged.verify(root().node_id()),
            Err(Error::InvalidSignature)
        ));
        let other = NodeIdentity::from_seed([9u8; 32]);
        let foreign = resign(items.clone(), &|e| {
            *e = SignedEntry::sign(&other, e.version, e.name.clone(), e.service.clone()).unwrap();
        });
        assert!(matches!(
            foreign.verify(root().node_id()),
            Err(Error::InvalidSignature)
        ));
        let future = resign(items, &|e| {
            *e = SignedEntry::sign(&root(), StateVersion(4), e.name.clone(), e.service.clone())
                .unwrap();
        });
        assert!(matches!(
            future.verify(root().node_id()),
            Err(Error::InvalidPolicy(_))
        ));
    }

    #[test]
    fn an_edit_re_signs_only_the_entries_it_changes() {
        let v3 = sample().sign(&root()).unwrap();
        let mut p = sample();
        p.version = StateVersion(4);
        p.services.get_mut(&name("status")).unwrap().description = "SLOs".into();
        p.services.remove(&name("deploy"));
        p.services
            .insert(name("new"), service(&["staff"], &[], &[10]));
        p.bans.insert(node(21), Ban { until: 900 });
        let v4 = p.sign_after(&root(), &v3).unwrap();
        v4.verify(root().node_id()).unwrap();
        let versions: Vec<(String, u64)> = v4
            .entries()
            .map(|e| (e.name.to_string(), e.version.0))
            .collect();
        assert_eq!(
            versions,
            [
                ("locked".into(), 3),
                ("new".into(), 4),
                ("orders-db".into(), 3),
                ("status".into(), 4),
            ]
        );
        assert_eq!(entry(&v4, "orders-db"), entry(&v3, "orders-db"));
        // A plain sign re-signs every entry.
        assert!(
            p.sign(&root())
                .unwrap()
                .entries()
                .all(|e| e.version == StateVersion(4))
        );
        // Another fabric's policy lends nothing: every entry is its own.
        let other = NodeIdentity::from_seed([9u8; 32]);
        let mut q = p.clone();
        q.fabric = other.node_id();
        let theirs = q.sign_after(&other, &v3).unwrap();
        theirs.verify(other.node_id()).unwrap();
        assert!(
            theirs
                .entries()
                .all(|e| e.version == StateVersion(4) && e.fabric == other.node_id())
        );
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
    fn bans_follow_the_state_rules() {
        let mut p = sample();
        p.ban(node(20), 400); // earlier: the later until (500) stays
        assert_eq!(p.bans[&node(20)].until, 500);
        p.ban(node(20), 700);
        assert_eq!(p.bans[&node(20)].until, 700);
        p.ban(node(21), 600);
        assert_eq!(p.prune_bans(600), 0, "until is inclusive");
        assert_eq!(p.prune_bans(601), 1);
        assert!(p.is_banned(node(20), 700));
        assert!(!p.bans.contains_key(&node(21)));

        // After an edit's prune, the gates' rule (a ban held, whatever its
        // until) and the clocked one agree.
        let mut q = Policy::new(root().node_id());
        for (n, until) in [(1, 10), (2, 20), (1, 30), (3, 5)] {
            q.ban(node(n), until);
        }
        for now in [0, 5, 6, 20, 21, 30, 31] {
            let mut q = q.clone();
            q.prune_bans(now);
            for n in 1..=3 {
                assert_eq!(
                    q.bans_node(node(n)),
                    q.is_banned(node(n), now),
                    "{n} at {now}"
                );
            }
        }
    }

    #[test]
    fn a_view_holds_only_what_its_caller_may_use() {
        let signed = sample().sign(&root()).unwrap();
        let marks = |p: Option<&Principal>| -> Vec<(String, bool, bool)> {
            let view = signed.view_for(p, None);
            view.verify(root().node_id()).unwrap();
            view.entries
                .iter()
                .map(|e| (e.entry.name.to_string(), e.call, e.read))
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
            let view = signed.view_for(Some(&alice), q);
            view.verify(root().node_id()).unwrap();
            view.entries
                .iter()
                .map(|e| e.entry.name.to_string())
                .collect()
        };
        assert_eq!(names(Some("orders")), vec!["orders-db", "status"]);
        assert_eq!(names(Some("DB")), vec!["orders-db"]);
        assert!(names(Some("deploy")).is_empty(), "not alice's to see");
        assert!(names(Some("no such thing")).is_empty());
    }

    #[test]
    fn view_entries_are_the_policy_s_own_signed_entries() {
        let signed = sample().sign(&root()).unwrap();
        let view = signed.view_for(Some(&who("alice@example.com")), None);
        for e in &view.entries {
            assert_eq!(&e.entry, entry(&signed, e.entry.name.as_str()));
        }
    }

    proptest! {
        #[test]
        fn any_policy_round_trips(p in arb_policy()) {
            let signed = p.sign(&root()).unwrap();
            prop_assert!(signed.verify(root().node_id()).is_ok());
            prop_assert_eq!(signed.to_policy().unwrap(), p);
        }

        /// Signing after any older policy keeps exactly the entries it
        /// shares, and the result verifies and reads back as the new policy.
        #[test]
        fn sign_after_keeps_exactly_the_unchanged_entries(a in arb_policy(), b in arb_policy()) {
            let old = a.sign(&root()).unwrap();
            let mut b = b;
            b.version = StateVersion(a.version.0 + 1);
            let new = b.sign_after(&root(), &old).unwrap();
            prop_assert!(new.verify(root().node_id()).is_ok());
            prop_assert_eq!(new.to_policy().unwrap(), b.clone());
            for e in new.entries() {
                let same = a.services.get(&e.name) == Some(&e.service);
                prop_assert_eq!(e.version, if same { a.version } else { b.version });
            }
        }

        #[test]
        fn views_hold_exactly_what_their_caller_may_use(
            p in arb_policy(),
            principal in arb_principal(),
        ) {
            let signed = p.sign(&root()).unwrap();
            let view = signed.view_for(principal.as_ref(), None);
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
                .map(|e| (e.entry.name.clone(), e.call, e.read))
                .collect();
            prop_assert_eq!(got, want);
            if principal.is_none() {
                prop_assert!(view.entries.is_empty());
            }
        }
    }
}

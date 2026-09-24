//! The admin-signed state: one versioned, root-signed document that says
//! which roles and services exist, which hosts run each service, and which
//! nodes are banned.
//!
//! [`State`] is the content; [`SignedState`] is that content plus the root's
//! signature. It is the thing every node holds: `wires join` installs it,
//! the admin pushes each new version to the hosts, and other nodes pull a
//! newer copy from a host. Nothing in it is secret, and it is checked
//! offline. It lists no members: a node is admitted by its root-signed badge
//! ([`Membership`](crate::Membership)) and not being in [`State::bans`]
//! ([`check_admitted`](crate::check_admitted)), so admitting a node is no
//! edit of the state (card 35; the directory that replaces "every node holds
//! the whole state" is `docs/fabric.md`).
//!
//! - **Signed bytes:** [`STATE_CONTEXT`] followed by the canonical JSON of
//!   `{alg, state}`. The context separates it from every other object the
//!   same root key signs (memberships).
//! - **Versioning:** [`StateVersion`] only goes up. A node keeps the newest
//!   copy it has verified ([`SignedState::is_newer_than`]) and never accepts
//!   an older one; that is how a ban sticks.
//! - **Hosts are derived:** a host is a node some service's `hosts` names
//!   ([`State::hosts`]); there is no separate host list.
//! - **Bans:** node → `until` (unix seconds, the removed badge's expiry). A
//!   ban never needs to outlive the badge it cancels, so an edit drops the
//!   bans whose `until` has passed ([`State::prune_bans`]).
//! - **Format:** [`State::format`] is a signed discriminant ([`STATE_V2`]);
//!   any other format, including the member-listing format 1, is refused.
//!   Unknown fields are refused at decode, so a reader never silently drops
//!   a field it doesn't know.
//!
//! ```
//! use library::{Matcher, NodeIdentity, RoleName, Service, ServiceName, State, StateVersion};
//!
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let host = NodeIdentity::from_seed([2u8; 32]).node_id();
//! let mut state = State::new(root.node_id());
//! state.version = StateVersion(1);
//! state.not_after = i64::MAX;
//! let staff = RoleName::new("staff").unwrap();
//! state.roles.insert(staff.clone(), vec![Matcher::new("https://accounts.google.com")]);
//! state.services.insert(
//!     ServiceName::new("orders-db").unwrap(),
//!     Service {
//!         description: "Read-only SQL".into(),
//!         allow: vec![staff],
//!         hosts: vec![host],
//!         readers: vec![],
//!     },
//! );
//! let signed = state.sign(&root).unwrap();
//! signed.verify(root.node_id()).unwrap();
//! assert!(signed.state.assigns(&ServiceName::new("orders-db").unwrap(), host));
//! assert!(signed.state.is_host(host));
//! ```

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::codec::B64;
use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::identity::{AlgorithmId, NodeId, NodeIdentity, Signature};
use crate::registry::{Service, ServiceName};
use crate::role::{Matcher, RoleName};

/// The current (and only) state format: no member list, bans instead
/// (card 35). Format 1 (which listed every member) is refused.
pub const STATE_V2: u8 = 2;

/// Domain-separation prefix of the signed bytes.
pub const STATE_CONTEXT: &[u8] = b"wires/state/v1\0";

/// A monotonic state version: every admin change bumps it by one, and a node
/// never replaces its copy with a lower one.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StateVersion(pub u64);

/// The content of the admin-signed state. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    /// Format discriminant; [`STATE_V2`]. Signed.
    pub format: u8,
    /// The root's node id: the authority, pinned by [`SignedState::verify`].
    pub fabric: NodeId,
    /// Monotonic version.
    pub version: StateVersion,
    /// When the admin signed it, unix seconds.
    pub issued: i64,
    /// Expiry, unix seconds, inclusive. An expired state admits nobody until
    /// the admin signs a newer one.
    pub not_after: i64,
    /// Removed nodes: node → `until`, unix seconds (the removed badge's
    /// `not_after`). A banned node is refused everywhere this state is
    /// held, whatever badge it presents. After `until` its badge has expired
    /// anyway, and the next edit drops the entry ([`State::prune_bans`]).
    pub bans: BTreeMap<NodeId, i64>,
    /// Role definitions: name → OR of matchers. There is no built-in role:
    /// a service's `allow` and `readers` name only roles defined here.
    pub roles: BTreeMap<RoleName, Vec<Matcher>>,
    /// The service registry.
    pub services: BTreeMap<ServiceName, Service>,
}

/// A [`State`] with the root's signature over it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedState {
    /// The signed content.
    pub state: State,
    /// Which scheme `sig` was produced with.
    pub alg: AlgorithmId,
    /// The root's signature over [`STATE_CONTEXT`] ‖ canonical `{alg, state}`.
    pub sig: Signature,
}

/// The signed portion of a [`SignedState`].
#[derive(Serialize)]
struct SignedBody<'a> {
    alg: &'a AlgorithmId,
    state: &'a State,
}

fn signed_bytes(state: &State, alg: &AlgorithmId) -> Result<Vec<u8>> {
    let mut bytes = STATE_CONTEXT.to_vec();
    bytes.extend(canonical_bytes(&SignedBody { alg, state })?);
    Ok(bytes)
}

impl State {
    /// An empty state for `fabric` at version 0, never valid (`not_after` 0):
    /// the starting point `wires init` fills in.
    pub fn new(fabric: NodeId) -> State {
        State {
            format: STATE_V2,
            fabric,
            version: StateVersion(0),
            issued: 0,
            not_after: 0,
            bans: BTreeMap::new(),
            roles: BTreeMap::new(),
            services: BTreeMap::new(),
        }
    }

    /// The structural rules the types can't say ([`Error::InvalidState`]
    /// names the first one broken):
    ///
    /// - `format` is [`STATE_V2`] (else [`Error::UnsupportedVersion`]);
    /// - every role has matchers, and every matcher names an issuer;
    /// - every service's `allow` and `readers` name a defined role, and its
    ///   `hosts` are each listed once and none is banned.
    pub fn validate(&self) -> Result<()> {
        let bad = |why: String| Err(Error::InvalidState(why));
        if self.format != STATE_V2 {
            return Err(Error::UnsupportedVersion);
        }
        for (role, matchers) in &self.roles {
            if matchers.is_empty() {
                return bad(format!("role {role} has no matchers"));
            }
            if matchers.iter().any(|m| m.issuer.trim().is_empty()) {
                return bad(format!("role {role} has a matcher with no issuer"));
            }
        }
        for (name, svc) in &self.services {
            for role in svc.allow.iter().chain(&svc.readers) {
                if !self.roles.contains_key(role) {
                    return bad(format!("service {name} names undefined role {role}"));
                }
            }
            let mut seen = BTreeSet::new();
            for h in &svc.hosts {
                if self.is_banned(*h) {
                    return bad(format!("service {name}: host {} is banned", h.hex()));
                }
                if !seen.insert(h) {
                    return bad(format!("service {name} lists host {} twice", h.hex()));
                }
            }
        }
        Ok(())
    }

    /// Validate, then sign as-is with the root key (the caller sets
    /// `version`, `issued` and `not_after`). [`Error::FabricMismatch`] if
    /// `root` is not this state's `fabric`.
    pub fn sign(&self, root: &NodeIdentity) -> Result<SignedState> {
        if root.node_id() != self.fabric {
            return Err(Error::FabricMismatch);
        }
        self.validate()?;
        let alg = AlgorithmId::Ed25519;
        let sig = root.sign(&signed_bytes(self, &alg)?);
        Ok(SignedState {
            state: self.clone(),
            alg,
            sig,
        })
    }

    /// Whether `node` is banned: removed by the admin. A banned node is
    /// admitted nowhere, whatever badge it presents. A ban holds until the
    /// next edit after its `until` drops it, and by then the badge it
    /// cancels has expired.
    pub fn is_banned(&self, node: NodeId) -> bool {
        self.bans.contains_key(&node)
    }

    /// Ban `node` until `until` (unix seconds). A node already banned keeps
    /// the later of its two `until`s.
    pub fn ban(&mut self, node: NodeId, until: i64) {
        let entry = self.bans.entry(node).or_insert(until);
        *entry = (*entry).max(until);
    }

    /// Drop every ban whose `until` is before `now`: the badge it cancelled
    /// has expired, so it admits nobody anyway. Every admin edit runs this,
    /// which is why the state's size tracks recent removals, not every node
    /// ever removed. Returns how many were dropped.
    pub fn prune_bans(&mut self, now: i64) -> usize {
        let before = self.bans.len();
        self.bans.retain(|_, until| *until >= now);
        before - self.bans.len()
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
        !self.is_banned(node) && self.services.values().any(|s| s.hosts.contains(&node))
    }

    /// The registry entry for `name`, if any.
    pub fn service(&self, name: &ServiceName) -> Option<&Service> {
        self.services.get(name)
    }

    /// Whether the registry assigns `service` to `host`, which is not
    /// banned: what a host checks before serving a name, and what a caller
    /// checks before dialing.
    pub fn assigns(&self, service: &ServiceName, host: NodeId) -> bool {
        !self.is_banned(host)
            && self
                .service(service)
                .is_some_and(|s| s.hosts.contains(&host))
    }
}

impl SignedState {
    /// Verify it was signed by `root` for that fabric: algorithm, the
    /// `fabric == root` pin, the signature, then [`State::validate`] (which
    /// checks the format). Does not check freshness
    /// ([`check_fresh`](Self::check_fresh)).
    pub fn verify(&self, root: NodeId) -> Result<()> {
        if self.alg != AlgorithmId::Ed25519 {
            return Err(Error::UnsupportedAlgorithm);
        }
        if self.state.fabric != root {
            return Err(Error::InvalidSignature);
        }
        root.verify(&signed_bytes(&self.state, &self.alg)?, &self.sig)?;
        self.state.validate()
    }

    /// [`Error::Expired`] when `now > not_after`.
    pub fn check_fresh(&self, now: i64) -> Result<()> {
        if now > self.state.not_after {
            return Err(Error::Expired {
                not_after: self.state.not_after,
            });
        }
        Ok(())
    }

    /// Whether this copy should replace `other`: same fabric and a strictly
    /// higher version. Says nothing about signatures; verify first.
    pub fn is_newer_than(&self, other: &SignedState) -> bool {
        self.state.fabric == other.state.fabric && self.state.version > other.state.version
    }

    /// base64url-no-pad of the canonical JSON: one copy-pasteable token.
    ///
    /// ```
    /// use library::{NodeIdentity, SignedState, State};
    /// let root = NodeIdentity::from_seed([1u8; 32]);
    /// let signed = State::new(root.node_id()).sign(&root).unwrap();
    /// assert_eq!(SignedState::decode(&signed.encode().unwrap()).unwrap(), signed);
    /// ```
    pub fn encode(&self) -> Result<String> {
        Ok(B64.encode(canonical_bytes(self)?))
    }

    /// Decode from [`encode`](Self::encode)'s token. Does not verify.
    pub fn decode(text: &str) -> Result<SignedState> {
        let bytes = B64.decode(text)?;
        serde_json::from_slice(&bytes).map_err(Error::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn root() -> NodeIdentity {
        NodeIdentity::from_seed([1u8; 32])
    }

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    fn sample() -> State {
        let mut s = State::new(root().node_id());
        s.version = StateVersion(3);
        s.not_after = 1_000;
        let host = node(3);
        s.ban(node(5), 900);
        s.roles.insert(
            RoleName::new("analyst").unwrap(),
            vec![Matcher {
                email: Some("*@example.com".parse().unwrap()),
                ..Matcher::new("https://idp.example")
            }],
        );
        s.services.insert(
            ServiceName::new("orders-db").unwrap(),
            Service {
                description: "orders".into(),
                allow: vec![RoleName::new("analyst").unwrap()],
                hosts: vec![host],
                readers: vec![RoleName::new("analyst").unwrap()],
            },
        );
        s
    }

    #[test]
    fn sign_verify_round_trip() {
        let signed = sample().sign(&root()).unwrap();
        signed.verify(root().node_id()).unwrap();
        let back = SignedState::decode(&signed.encode().unwrap()).unwrap();
        assert_eq!(back, signed);
        back.verify(root().node_id()).unwrap();
    }

    #[test]
    fn wrong_root_is_refused() {
        let signed = sample().sign(&root()).unwrap();
        assert!(signed.verify(node(9)).is_err());
        assert!(matches!(
            sample().sign(&NodeIdentity::from_seed([9u8; 32])),
            Err(Error::FabricMismatch)
        ));
    }

    #[test]
    fn tampering_breaks_the_signature() {
        let signed = sample().sign(&root()).unwrap();
        let mut t = signed.clone();
        t.state.bans.insert(node(7), 1);
        assert!(matches!(
            t.verify(root().node_id()),
            Err(Error::InvalidSignature)
        ));
        let mut t = signed;
        t.state.services.values_mut().for_each(|s| s.allow = vec![]);
        assert!(t.verify(root().node_id()).is_err());
    }

    #[test]
    fn freshness_and_ordering() {
        let a = sample().sign(&root()).unwrap();
        let mut s = sample();
        s.version = StateVersion(4);
        let b = s.sign(&root()).unwrap();
        assert!(b.is_newer_than(&a));
        assert!(!a.is_newer_than(&b));
        assert!(!a.is_newer_than(&a));
        assert!(a.check_fresh(1_000).is_ok());
        assert!(matches!(
            a.check_fresh(1_001),
            Err(Error::Expired { not_after: 1_000 })
        ));
    }

    /// The rule `validate` says `s` breaks.
    fn broken_rule(s: &State) -> String {
        match s.validate() {
            Err(Error::InvalidState(why)) => why,
            other => panic!("expected InvalidState, got {other:?}"),
        }
    }

    #[test]
    fn validation_rules() {
        sample().validate().unwrap();

        let mut s = sample();
        s.roles.insert(RoleName::new("x").unwrap(), vec![]);
        assert_eq!(broken_rule(&s), "role x has no matchers");

        let mut s = sample();
        s.roles
            .insert(RoleName::new("x").unwrap(), vec![Matcher::new(" ")]);
        assert_eq!(broken_rule(&s), "role x has a matcher with no issuer");

        let mut s = sample();
        s.services.values_mut().for_each(|svc| {
            svc.allow = vec![RoleName::new("ghost").unwrap()];
        });
        assert_eq!(
            broken_rule(&s),
            "service orders-db names undefined role ghost"
        );

        let mut s = sample();
        s.services.values_mut().for_each(|svc| {
            svc.readers = vec![RoleName::new("ghost").unwrap()];
        });
        assert_eq!(
            broken_rule(&s),
            "service orders-db names undefined role ghost"
        );

        let mut s = sample();
        s.ban(node(3), 2_000); // the service's one host
        assert!(matches!(s.sign(&root()), Err(Error::InvalidState(_))));
        assert!(
            broken_rule(&s).ends_with("is banned"),
            "{}",
            broken_rule(&s)
        );

        let mut s = sample();
        s.services.values_mut().for_each(|svc| {
            let h = svc.hosts[0];
            svc.hosts.push(h);
        });
        assert!(broken_rule(&s).contains("twice"));

        let mut s = sample();
        s.format = STATE_V2 + 1;
        assert!(matches!(s.validate(), Err(Error::UnsupportedVersion)));
    }

    /// A format-1 state (it listed `members` and `hosts`) is refused: at
    /// decode for its fields, and by `validate` for its format.
    #[test]
    fn format_1_is_refused() {
        let signed = sample().sign(&root()).unwrap();
        let mut v = serde_json::to_value(&signed).unwrap();
        v["state"]["format"] = serde_json::json!(1);
        v["state"]["members"] = serde_json::json!([]);
        v["state"]["hosts"] = serde_json::json!([]);
        assert!(serde_json::from_value::<SignedState>(v).is_err());
        let mut s = sample();
        s.format = 1;
        assert!(matches!(s.validate(), Err(Error::UnsupportedVersion)));
    }

    #[test]
    fn bans_keep_the_later_until_and_drop_once_it_has_passed() {
        let mut s = sample();
        let (a, b) = (node(20), node(21));
        s.ban(a, 100);
        s.ban(a, 50);
        assert_eq!(s.bans[&a], 100, "the later until wins");
        s.ban(b, 200);
        assert!(s.is_banned(a) && s.is_banned(b));
        // `until` is inclusive: at 100 the badge may still be valid.
        let before = s.bans.len();
        s.prune_bans(100);
        assert_eq!(s.bans.len(), before);
        assert!(s.is_banned(a));
        s.prune_bans(101);
        assert!(!s.is_banned(a) && s.is_banned(b));
    }

    #[test]
    fn hosts_are_derived_from_services_and_never_banned() {
        let s = sample();
        assert_eq!(s.hosts(), [node(3)].into());
        assert!(s.is_host(node(3)));
        assert!(!s.is_host(node(2)));
        // An unvalidated state that bans a listed host: not a host, not
        // assigned (what a caller skips).
        let mut s = sample();
        s.bans.insert(node(3), i64::MAX);
        assert!(!s.is_host(node(3)));
        assert!(!s.assigns(&ServiceName::new("orders-db").unwrap(), node(3)));
    }

    #[test]
    fn unknown_fields_are_refused() {
        let signed = sample().sign(&root()).unwrap();
        let mut v = serde_json::to_value(&signed).unwrap();
        v["state"]["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<SignedState>(v).is_err());
    }

    #[test]
    fn assigns_only_registered_hosts() {
        let s = sample();
        let name = ServiceName::new("orders-db").unwrap();
        assert!(s.assigns(&name, node(3)));
        assert!(!s.assigns(&name, node(2)));
        assert!(!s.assigns(&ServiceName::new("deploy").unwrap(), node(3)));
    }

    proptest! {
        #[test]
        fn any_ban_set_round_trips(
            bans in proptest::collection::btree_map(any::<u8>(), any::<i64>(), 0..8),
            version in any::<u64>(),
        ) {
            let mut s = State::new(root().node_id());
            s.version = StateVersion(version);
            s.bans.extend(bans.iter().map(|(b, until)| (node(*b), *until)));
            let signed = s.sign(&root()).unwrap();
            let back = SignedState::decode(&signed.encode().unwrap()).unwrap();
            prop_assert!(back.verify(root().node_id()).is_ok());
            prop_assert_eq!(back, signed);
        }

        /// After pruning at `now`, exactly the bans with `until >= now`
        /// remain, untouched.
        #[test]
        fn pruning_keeps_exactly_the_live_bans(
            bans in proptest::collection::btree_map(any::<u8>(), -50i64..50, 0..16),
            now in -60i64..60,
        ) {
            let mut s = State::new(root().node_id());
            s.bans.extend(bans.iter().map(|(b, until)| (node(*b), *until)));
            let live: BTreeMap<NodeId, i64> =
                s.bans.iter().filter(|(_, u)| **u >= now).map(|(n, u)| (*n, *u)).collect();
            s.prune_bans(now);
            prop_assert_eq!(&s.bans, &live);
        }

        #[test]
        fn a_changed_version_never_verifies(version in any::<u64>(), other in any::<u64>()) {
            prop_assume!(version != other);
            let mut s = sample();
            s.version = StateVersion(version);
            let mut signed = s.sign(&root()).unwrap();
            signed.state.version = StateVersion(other);
            prop_assert!(signed.verify(root().node_id()).is_err());
        }
    }
}

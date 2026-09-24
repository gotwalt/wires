//! The admin-signed state: one versioned, root-signed document that says who
//! is in, which members are hosts, what the roles are, and which services
//! exist.
//!
//! [`State`] is the content; [`SignedState`] is that content plus the root's
//! signature. It is the thing every node holds: `wires join` installs it,
//! the admin pushes each new version to the hosts, and other members pull a
//! newer copy from a host. Nothing in it is secret: every member holds the
//! whole document (cards 35–37 replace that with a directory; `docs/fabric.md`), and it is
//! checked offline.
//!
//! - **Signed bytes:** [`STATE_CONTEXT`] followed by the canonical JSON of
//!   `{alg, state}`. The context separates it from every other object the
//!   same root key signs (memberships).
//! - **Versioning:** [`StateVersion`] only goes up. A node keeps the newest
//!   copy it has verified ([`SignedState::is_newer_than`]) and never accepts
//!   an older one; that is how a removal sticks.
//! - **Format:** [`State::format`] is a signed discriminant ([`STATE_V1`]).
//!   Unknown fields are refused at decode, so a v1 reader never silently drops
//!   a v2 field.
//!
//! ```
//! use library::{Matcher, NodeIdentity, RoleName, Service, ServiceName, State, StateVersion};
//!
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let host = NodeIdentity::from_seed([2u8; 32]).node_id();
//! let mut state = State::new(root.node_id());
//! state.version = StateVersion(1);
//! state.not_after = i64::MAX;
//! state.members.insert(host);
//! state.hosts.insert(host);
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

/// The current (and only) state format.
pub const STATE_V1: u8 = 1;

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
    /// Format discriminant; [`STATE_V1`]. Signed.
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
    /// Every member's node id. Removal is omission.
    pub members: BTreeSet<NodeId>,
    /// The members that may serve services (a subset of `members`).
    pub hosts: BTreeSet<NodeId>,
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
            format: STATE_V1,
            fabric,
            version: StateVersion(0),
            issued: 0,
            not_after: 0,
            members: BTreeSet::new(),
            hosts: BTreeSet::new(),
            roles: BTreeMap::new(),
            services: BTreeMap::new(),
        }
    }

    /// The structural rules the types can't say ([`Error::InvalidState`]
    /// names the first one broken):
    ///
    /// - `format` is [`STATE_V1`];
    /// - every host is a member;
    /// - every role has matchers, and every matcher names an issuer;
    /// - every service's `allow` and `readers` name a defined role, and its
    ///   `hosts` are hosts, each listed once.
    pub fn validate(&self) -> Result<()> {
        let bad = |why: String| Err(Error::InvalidState(why));
        if self.format != STATE_V1 {
            return Err(Error::UnsupportedVersion);
        }
        if let Some(h) = self.hosts.iter().find(|h| !self.members.contains(h)) {
            return bad(format!("host {} is not a member", h.hex()));
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
                if !self.hosts.contains(h) {
                    return bad(format!("service {name}: {} is not a host", h.hex()));
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

    /// Whether `node` is a member.
    pub fn is_member(&self, node: NodeId) -> bool {
        self.members.contains(&node)
    }

    /// Whether `node` is a host.
    pub fn is_host(&self, node: NodeId) -> bool {
        self.hosts.contains(&node)
    }

    /// The registry entry for `name`, if any.
    pub fn service(&self, name: &ServiceName) -> Option<&Service> {
        self.services.get(name)
    }

    /// Whether the registry assigns `service` to `host`: what a host checks
    /// before serving a name, and what a caller checks before dialing.
    pub fn assigns(&self, service: &ServiceName, host: NodeId) -> bool {
        self.is_host(host)
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
        let (alice, host) = (node(2), node(3));
        s.members.extend([alice, host]);
        s.hosts.insert(host);
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
        t.state.members.insert(node(7));
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
        s.hosts.insert(node(8));
        assert!(matches!(s.sign(&root()), Err(Error::InvalidState(_))));
        assert!(broken_rule(&s).ends_with("is not a member"));

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
        s.services
            .values_mut()
            .for_each(|svc| svc.hosts = vec![node(2)]); // a member, not a host
        assert!(broken_rule(&s).ends_with("is not a host"));

        let mut s = sample();
        s.services.values_mut().for_each(|svc| {
            let h = svc.hosts[0];
            svc.hosts.push(h);
        });
        assert!(broken_rule(&s).contains("twice"));

        let mut s = sample();
        s.format = STATE_V1 + 1;
        assert!(matches!(s.validate(), Err(Error::UnsupportedVersion)));
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
        fn any_member_set_round_trips(
            seeds in proptest::collection::btree_set(any::<u8>(), 0..8),
            version in any::<u64>(),
        ) {
            let mut s = State::new(root().node_id());
            s.version = StateVersion(version);
            s.members.extend(seeds.iter().map(|b| node(*b)));
            let signed = s.sign(&root()).unwrap();
            let back = SignedState::decode(&signed.encode().unwrap()).unwrap();
            prop_assert!(back.verify(root().node_id()).is_ok());
            prop_assert_eq!(back, signed);
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

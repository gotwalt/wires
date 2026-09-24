//! The services-era call gate (card 27, lane **27c**): what a host checks on
//! every [`Hello`](library::Hello) + [`Invoke`](library::Frame::Invoke),
//! in order, the first failure being the refusal the caller hears and the
//! call log records:
//!
//! 1. the host's signed state is fresh ([`SignedState::check_fresh`]);
//! 2. the caller is a member of it (removal is omission; no restart needed,
//!    because the state is re-read per connection);
//! 3. the service is registered, and assigned to **this** host
//!    ([`State::assigns`](library::State::assigns));
//! 4. the registry allows the caller's role ([`library::authorize`]);
//! 5. the host's own `also_require` roles (`host.json` v2), which can only
//!    narrow: the caller must be in **every** one of them.
//!
//! The caller's principal is verified before [`admit`] runs (the ID token
//! from the `Hello`, nonce-bound to the iroh-authenticated caller, under the
//! host's `identity.issuers`: [`ServicesHost::principal`]), so [`admit`] is
//! pure and clock-free except for `now`.
//!
//! [`ServicesHost`] is everything a v2 host decides with: its own
//! credentials, where its signed state lives (re-read per connection), its
//! `host.json` v2, the identity verifier and the call-log sink. The session
//! transport ([`ServicesProtocol`](crate::host::transport::ServicesProtocol))
//! and the push service ([`push`](crate::host::push)) both ask it.

use std::fmt;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use library::{
    IdToken, Membership, NodeId, Principal, Refusal, RoleName, ServiceName, SignedState,
    StateVersion, authorize, role_admits,
};

use crate::admin::keystore::Keystore;
use crate::caller::jwks::VerifyError;
use crate::host::config_v2::HostConfigV2;
use crate::host::identity::{Identities, principal_name};
use crate::host::transport::AuditSink;

/// A call the gate admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Admitted {
    /// The registry role that admitted the caller (recorded in the log).
    pub(crate) role: RoleName,
    /// The state version the decision was made under.
    pub(crate) state_version: StateVersion,
}

/// Why [`admit`] refused. `Display` is the text the caller is sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GateRefusal {
    /// The host's own state has expired: it admits nobody until the admin
    /// signs a newer one.
    Stale {
        /// The expired state's version.
        version: StateVersion,
        /// Why it is not fresh.
        why: String,
    },
    /// The registry refused ([`library::authorize`]).
    Registry {
        /// The registry's reason.
        refusal: Refusal,
        /// The state version it decided under.
        version: StateVersion,
    },
    /// The service exists, but the registry doesn't assign it to this host.
    NotAssigned {
        /// The service.
        service: ServiceName,
        /// The state version it decided under.
        version: StateVersion,
    },
    /// The registry admitted the caller, but this host's `also_require`
    /// did not.
    AlsoRequire {
        /// The service.
        service: ServiceName,
        /// Every role this host requires on top of the registry.
        roles: Vec<RoleName>,
        /// Who the caller verified as, if anyone.
        principal: Option<String>,
    },
}

impl GateRefusal {
    /// Whether presenting a verified identity could change the answer (so a
    /// refusal of a caller with none should say why it has none).
    pub(crate) fn needs_identity(&self) -> bool {
        matches!(
            self,
            GateRefusal::Registry {
                refusal: Refusal::NotInRole {
                    principal: None,
                    ..
                },
                ..
            } | GateRefusal::AlsoRequire {
                principal: None,
                ..
            }
        )
    }
}

impl fmt::Display for GateRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let roles = |rs: &[RoleName]| {
            rs.iter()
                .map(RoleName::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        };
        match self {
            GateRefusal::Stale { version, why } => write!(
                f,
                "this host's signed state (version {}) is not fresh ({why}); the admin must sign \
                 a newer one",
                version.0
            ),
            GateRefusal::Registry {
                refusal: Refusal::NotAMember,
                version,
            } => write!(f, "{} (version {})", Refusal::NotAMember, version.0),
            GateRefusal::Registry { refusal, .. } => write!(f, "{refusal}"),
            GateRefusal::NotAssigned { service, version } => write!(
                f,
                "service {service} is not assigned to this host (signed state version {})",
                version.0
            ),
            GateRefusal::AlsoRequire {
                service,
                roles: rs,
                principal: Some(who),
            } => write!(
                f,
                "{who} is not in every role this host also requires for {service} ({})",
                roles(rs)
            ),
            GateRefusal::AlsoRequire {
                service,
                roles: rs,
                principal: None,
            } => write!(
                f,
                "{service} on this host also needs a verified identity in role {}; run `wires \
                 login`",
                roles(rs)
            ),
        }
    }
}

/// Run the checks in the module docs. `me` is this host.
pub(crate) fn admit(
    state: &SignedState,
    config: &HostConfigV2,
    me: NodeId,
    caller: NodeId,
    principal: Option<&Principal>,
    service: &ServiceName,
    now: i64,
) -> Result<Admitted, GateRefusal> {
    let version = state.state.version;
    state.check_fresh(now).map_err(|e| GateRefusal::Stale {
        version,
        why: e.to_string(),
    })?;
    let s = &state.state;
    let registry = |refusal| GateRefusal::Registry { refusal, version };
    if !s.is_member(caller) {
        return Err(registry(Refusal::NotAMember));
    }
    if s.service(service).is_none() {
        return Err(registry(Refusal::UnknownService(service.clone())));
    }
    if !s.assigns(service, me) {
        return Err(GateRefusal::NotAssigned {
            service: service.clone(),
            version,
        });
    }
    let role = authorize(s, caller, principal, service).map_err(registry)?;
    let also = config
        .services
        .get(service)
        .map(|svc| svc.also_require.as_slice())
        .unwrap_or_default();
    if !also.iter().all(|r| role_admits(s, r, principal)) {
        return Err(GateRefusal::AlsoRequire {
            service: service.clone(),
            roles: also.to_vec(),
            principal: principal.map(principal_name),
        });
    }
    Ok(Admitted {
        role,
        state_version: version,
    })
}

/// Everything a v2 host (`wires serve` with a `host.json` v2) decides with.
/// Built once per `serve`, shared by every session and the push service.
pub(crate) struct ServicesHost {
    /// This host.
    pub(crate) me: NodeId,
    /// The fabric root whose signed state and memberships are honored.
    pub(crate) trust_root: NodeId,
    /// The host's own membership, presented in the `HelloAck`.
    pub(crate) membership: Membership,
    /// Where the signed state is read from, per connection (so a newer
    /// state adopted by `wires/state` takes effect on the next dial).
    pub(crate) keystore: Arc<Keystore>,
    /// `host.json` v2.
    pub(crate) config: HostConfigV2,
    /// Verifies the ID tokens callers present, and remembers the verified
    /// principals (what push authorization reads).
    pub(crate) identities: Arc<Identities>,
    /// The call log (card 26a), if any.
    pub(crate) audit: Option<AuditSink>,
}

impl fmt::Debug for ServicesHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServicesHost")
            .field("me", &self.me.hex())
            .finish_non_exhaustive()
    }
}

impl ServicesHost {
    /// This host's signed state, verified under the trust root. A host with
    /// none (or an unreadable one) serves nobody: fail closed.
    pub(crate) fn state(&self) -> Result<SignedState> {
        crate::state::store::read(&self.keystore, self.trust_root)?
            .ok_or_else(|| anyhow!("this host holds no signed state (run `wires join`)"))
    }

    /// What `serve` checks before it binds: a fresh signed state that
    /// assigns every service in `host.json` to this host (the error names
    /// the first that isn't).
    pub(crate) fn preflight(&self, now: i64) -> Result<SignedState> {
        let state = self.state()?;
        state.check_fresh(now).with_context(|| {
            format!(
                "this host's signed state (version {}) has expired",
                state.state.version.0
            )
        })?;
        self.config.check_against(&state.state, self.me)?;
        Ok(state)
    }

    /// Verify the ID token `caller` presented (if any): its principal, or
    /// `None` and why there is none (with the `wires login` remedy).
    pub(crate) async fn principal(
        &self,
        caller: NodeId,
        token: Option<&IdToken>,
        now: i64,
    ) -> (Option<Principal>, Option<String>) {
        let Some(token) = token else {
            return (
                None,
                Some("no ID token presented; run `wires login`".to_string()),
            );
        };
        match self.identities.verify_token(caller, token, now).await {
            Ok(p) => (Some(p), None),
            Err(VerifyError::Expired(p)) => (
                None,
                Some(format!(
                    "the ID token for {} expired; run `wires login`",
                    principal_name(&p)
                )),
            ),
            Err(e) => (
                None,
                Some(format!(
                    "the ID token did not verify ({e}); run `wires login`"
                )),
            ),
        }
    }

    /// [`admit`] under `state`, as the text the caller is sent: a refusal
    /// that a verified identity could change leads with why there is none.
    pub(crate) fn decide(
        &self,
        state: &SignedState,
        caller: NodeId,
        principal: Option<&Principal>,
        missing: Option<&str>,
        service: &ServiceName,
        now: i64,
    ) -> std::result::Result<Admitted, String> {
        admit(
            state,
            &self.config,
            self.me,
            caller,
            principal,
            service,
            now,
        )
        .map_err(|r| match missing {
            Some(why) if r.needs_identity() => {
                // Both say "run `wires login`"; say it once.
                let r = r.to_string();
                let r = r.strip_suffix("; run `wires login`").unwrap_or(&r);
                format!("{why}; {r}")
            }
            _ => r.to_string(),
        })
    }

    /// Whether `node` may receive pushes from this host at `now`: a member of
    /// the current signed state, in the first `push.allow` role that admits
    /// it (with the principal it last verified as here). `Err` is the reason
    /// and whether it is membership (not the push rule) that refused.
    pub(crate) fn decide_push(
        &self,
        node: NodeId,
        now: i64,
    ) -> std::result::Result<(Option<Principal>, RoleName), (String, bool)> {
        let state = self.state().map_err(|e| {
            tracing::warn!("signed state unusable: {e:#}");
            ("responder configuration error".to_string(), false)
        })?;
        if let Err(e) = state.check_fresh(now) {
            return Err((
                format!(
                    "this host's signed state (version {}) is not fresh ({e})",
                    state.state.version.0
                ),
                false,
            ));
        }
        if !state.state.is_member(node) {
            return Err((
                format!(
                    "{} is not a member of the current signed state (version {})",
                    &node.hex()[..8],
                    state.state.version.0
                ),
                true,
            ));
        }
        let allow = self
            .config
            .push
            .as_ref()
            .map(|p| p.allow.as_slice())
            .unwrap_or_default();
        if allow.is_empty() {
            return Err((
                "this host's host.json `push.allow` is empty: it pushes to no one".to_string(),
                false,
            ));
        }
        let principal = self.identities.current(node, now);
        if let Some(role) = allow
            .iter()
            .find(|r| role_admits(&state.state, r, principal.as_ref()))
        {
            return Ok((principal, role.clone()));
        }
        let roles = allow
            .iter()
            .map(RoleName::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        Err((
            match &principal {
                Some(p) => format!(
                    "{} is in no role allowed to receive pushes ({roles})",
                    principal_name(p)
                ),
                None => format!(
                    "receiving pushes needs a verified identity in role {roles} (call this host \
                     after `wires login`)"
                ),
            },
            false,
        ))
    }

    /// The members `role` names at `now` (never this host): every member
    /// whose last verified principal here is in the role. A member with no
    /// verified identity here is in no role.
    pub(crate) fn push_recipients(&self, role: &RoleName, now: i64) -> Vec<NodeId> {
        let Ok(state) = self.state() else {
            return Vec::new();
        };
        let s = &state.state;
        let mut nodes: Vec<NodeId> = self
            .identities
            .nodes()
            .into_iter()
            .filter(|n| s.is_member(*n))
            .filter(|n| role_admits(s, role, self.identities.current(*n, now).as_ref()))
            .collect();
        nodes.retain(|n| *n != self.me);
        nodes.sort();
        nodes.dedup();
        nodes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{Matcher, NodeIdentity, Service, State};
    use proptest::prelude::*;

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    const ISS: &str = "https://idp.example";

    fn who(email: &str) -> Principal {
        Principal {
            issuer: ISS.into(),
            subject: email.into(),
            email: Some(email.into()),
            org: None,
            groups: vec![],
            not_after: i64::MAX,
            claims: Default::default(),
        }
    }

    fn name(s: &str) -> ServiceName {
        ServiceName::new(s).unwrap()
    }

    fn role(s: &str) -> RoleName {
        RoleName::new(s).unwrap()
    }

    /// Root 1; members 2 (caller) and 3 (this host); `status` (staff:
    /// anyone [`ISS`] verified) on 3.
    fn setup() -> (SignedState, HostConfigV2) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut s = State::new(root.node_id());
        s.version = StateVersion(5);
        s.not_after = 100;
        s.members.extend([node(2), node(3)]);
        s.hosts.insert(node(3));
        s.roles.insert(role("staff"), vec![Matcher::new(ISS)]);
        s.services.insert(
            name("status"),
            Service {
                description: String::new(),
                allow: vec![role("staff")],
                hosts: vec![node(3)],
                readers: vec![],
            },
        );
        let cfg =
            HostConfigV2::parse(r#"{"version":2,"services":{"status":{"command":["true"]}}}"#)
                .unwrap();
        (s.sign(&root).unwrap(), cfg)
    }

    /// [`setup`] plus roles `analyst` (alice) and `sre` (alice, carol),
    /// `orders-db` allowing analyst on 3, and host.json requiring sre too.
    fn strict() -> (SignedState, HostConfigV2) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let (signed, _) = setup();
        let mut s = signed.state;
        let email = |e: &str| Matcher {
            email: Some(e.parse().unwrap()),
            ..Matcher::new(ISS)
        };
        s.roles.insert(role("analyst"), vec![email("alice@x.com")]);
        s.roles.insert(
            role("sre"),
            vec![email("alice@x.com"), email("carol@x.com")],
        );
        s.services.insert(
            name("orders-db"),
            Service {
                description: String::new(),
                allow: vec![role("analyst")],
                hosts: vec![node(3)],
                readers: vec![],
            },
        );
        let cfg = HostConfigV2::parse(
            r#"{"version":2,"services":{"orders-db":{"command":["true"],"also_require":["sre"]}}}"#,
        )
        .unwrap();
        (s.sign(&root).unwrap(), cfg)
    }

    #[test]
    fn every_role_needs_a_verified_identity() {
        let (s, cfg) = setup();
        let status = name("status");
        let e = admit(&s, &cfg, node(3), node(2), None, &status, 0).unwrap_err();
        assert!(e.needs_identity(), "{e}");
        let bob = who("bob@x.com");
        let ok = admit(&s, &cfg, node(3), node(2), Some(&bob), &status, 0).unwrap();
        assert_eq!(ok.state_version, StateVersion(5));
        assert_eq!(ok.role, role("staff"));
    }

    #[test]
    fn refusals_in_order() {
        let (s, cfg) = setup();
        let status = name("status");
        assert!(matches!(
            admit(&s, &cfg, node(3), node(2), None, &status, 101),
            Err(GateRefusal::Stale { .. })
        ));
        let e = admit(&s, &cfg, node(3), node(9), None, &status, 0).unwrap_err();
        assert_eq!(
            e.to_string(),
            "not a member of the current signed state (version 5)"
        );
        assert!(matches!(
            admit(&s, &cfg, node(2), node(2), None, &status, 0),
            Err(GateRefusal::NotAssigned { .. })
        ));
        assert!(matches!(
            admit(&s, &cfg, node(3), node(2), None, &name("nope"), 0),
            Err(GateRefusal::Registry {
                refusal: Refusal::UnknownService(_),
                ..
            })
        ));
    }

    #[test]
    fn also_require_only_narrows() {
        let (s, cfg) = strict();
        let db = name("orders-db");
        // alice: analyst (registry) and sre (host) — admitted as analyst.
        let alice = who("alice@x.com");
        let ok = admit(&s, &cfg, node(3), node(2), Some(&alice), &db, 0).unwrap();
        assert_eq!(ok.role, role("analyst"));
        // carol: sre but not analyst — the host's rule can't widen.
        let carol = who("carol@x.com");
        assert!(matches!(
            admit(&s, &cfg, node(3), node(2), Some(&carol), &db, 0),
            Err(GateRefusal::Registry { .. })
        ));
        // alice without sre on the host side: refused by also_require.
        let mut state = s.state.clone();
        state.roles.insert(
            role("sre"),
            vec![Matcher {
                email: Some("carol@x.com".parse().unwrap()),
                ..Matcher::new(ISS)
            }],
        );
        let s2 = state.sign(&NodeIdentity::from_seed([1u8; 32])).unwrap();
        let e = admit(&s2, &cfg, node(3), node(2), Some(&alice), &db, 0).unwrap_err();
        assert!(matches!(e, GateRefusal::AlsoRequire { .. }));
        assert!(e.to_string().contains("also requires"), "{e}");
    }

    #[test]
    fn only_identity_refusals_ask_for_a_login() {
        let (s, cfg) = strict();
        let db = name("orders-db");
        let e = admit(&s, &cfg, node(3), node(2), None, &db, 0).unwrap_err();
        assert!(e.needs_identity());
        let e = admit(&s, &cfg, node(3), node(9), None, &db, 0).unwrap_err();
        assert!(!e.needs_identity());
    }

    proptest! {
        /// The host never admits more than the registry: whatever
        /// `also_require` says, an admission implies `authorize` admitted
        /// with the same role.
        #[test]
        fn the_gate_never_widens_the_registry(
            caller in 1u8..6,
            email in prop::option::of(prop::sample::select(vec![
                "alice@x.com", "carol@x.com", "eve@y.com",
            ])),
            also in prop::sample::subsequence(vec!["analyst", "sre", "staff"], 0..=3),
            service in prop::sample::select(vec!["status", "orders-db", "nope"]),
            now in 0i64..200,
        ) {
            let (s, _) = strict();
            let also: Vec<String> = also.iter().map(|r| format!("{r:?}")).collect();
            let cfg = HostConfigV2::parse(&format!(
                r#"{{"version":2,"services":{{"orders-db":{{"command":["true"],"also_require":[{}]}}}}}}"#,
                also.join(",")
            )).unwrap();
            let p = email.map(who);
            let svc = name(service);
            if let Ok(ok) = admit(&s, &cfg, node(3), node(caller), p.as_ref(), &svc, now) {
                prop_assert_eq!(
                    authorize(&s.state, node(caller), p.as_ref(), &svc),
                    Ok(ok.role)
                );
                prop_assert!(s.check_fresh(now).is_ok());
            }
        }
    }
}

//! The call gate: what a host checks on every [`Hello`](library::Hello) + [`Invoke`](library::Frame::Invoke),
//! in order, the first failure being the refusal the caller hears:
//!
//! 1. the caller is a member of the host's signed state (removal is
//!    omission; no restart needed, because the state is re-read per
//!    connection). Anyone else hears only [`NOT_ADMITTED`], and — checked
//!    first by [`ServicesHost::check_member`], before its ID token is even
//!    looked at — is traced, not written to the call log;
//! 2. the state is fresh ([`SignedState::check_fresh`]);
//! 3. the service is registered, and assigned to **this** host
//!    ([`State::assigns`](library::State::assigns));
//! 4. the registry allows the caller's role ([`library::authorize`]);
//! 5. the host's own `also_require` roles (`host.json`), which can only
//!    narrow: the caller must be in **every** one of them.
//!
//! A member's refusal is also written to the call log. The caller's
//! principal is verified after the membership check and before [`admit`]
//! runs (the ID token from the `Hello`, nonce-bound to the iroh-authenticated
//! caller, under the host's `identity.issuers`: [`ServicesHost::principal`]),
//! so [`admit`] is pure and clock-free except for `now`.
//!
//! [`ServicesHost`] is everything a host decides with: its own
//! credentials, where its signed state lives (re-read per connection), its
//! `host.json`, the identity verifier and the call-log sink. The session
//! transport ([`ServicesProtocol`](crate::host::transport::ServicesProtocol))
//! and the push service ([`push`](crate::host::push)) both ask it.

use std::fmt;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use library::{
    IdToken, Membership, NodeId, Principal, Refusal, RoleName, ServiceName, SignedState,
    StateVersion, authorize, role_admits,
};

use crate::admin::keystore::Keystore;
use crate::caller::jwks::VerifyError;
use crate::host::config::HostConfig;
use crate::host::identity::Identities;
use crate::host::transport::AuditSink;

/// The one refusal a peer that is not a member of this host's signed state
/// hears, whatever the reason (no credential, someone else's, expired,
/// removed, never invited). It says nothing about the state, its version or
/// who is in it; the exact reason goes only to the host's trace.
pub(crate) const NOT_ADMITTED: &str = "not a member of this network";

/// What a member hears when the ID token it presented did not verify
/// (untrusted issuer, bad signature, wrong audience or nonce). The exact
/// reason goes only to the host's trace.
pub(crate) const TOKEN_UNVERIFIED: &str = "your ID token could not be verified; run `wires login`";

/// What a member hears when this host could not fetch its issuer's keys.
/// The exact failure goes only to the host's trace.
pub(crate) const IDP_UNREACHABLE: &str =
    "the identity provider is unreachable from this host; try again later";

/// What a peer hears when this host can't decide at all (no readable signed
/// state, or one older than it already decided under): the operator's
/// problem, not the peer's. The cause goes only to the host's trace.
pub(crate) const HOST_MISCONFIGURED: &str = "responder configuration error";

/// Why [`ServicesHost::decide_push`] refused a recipient. `Display` is the
/// reason recorded and reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PushRefusal {
    /// Not a member of the current signed state: what is queued for it goes.
    NotAMember(String),
    /// A member the push rule refuses, or a host that can't decide now.
    Refused(String),
}

impl fmt::Display for PushRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PushRefusal::NotAMember(why) | PushRefusal::Refused(why) => f.write_str(why),
        }
    }
}

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
        match self {
            GateRefusal::Stale { version, why } => write!(
                f,
                "this host's signed state (version {}) is not fresh ({why}); the admin must sign \
                 a newer one",
                version.0
            ),
            GateRefusal::Registry {
                refusal: Refusal::NotAMember,
                ..
            } => f.write_str(NOT_ADMITTED),
            GateRefusal::Registry { refusal, .. } => write!(f, "{refusal}"),
            GateRefusal::NotAssigned { service, version } => write!(
                f,
                "service {service} is not assigned to this host (signed state version {})",
                version.0
            ),
            // The roles are this host's own (`host.json`); they stay in its
            // trace, not in what the caller hears.
            GateRefusal::AlsoRequire {
                service,
                principal: Some(who),
                ..
            } => write!(
                f,
                "{who} is not admitted to {service} by this host's own rules"
            ),
            GateRefusal::AlsoRequire {
                service,
                principal: None,
                ..
            } => write!(
                f,
                "{service} on this host also needs a verified identity; run `wires login`"
            ),
        }
    }
}

/// Run the checks in the module docs. `me` is this host.
pub(crate) fn admit(
    state: &SignedState,
    config: &HostConfig,
    me: NodeId,
    caller: NodeId,
    principal: Option<&Principal>,
    service: &ServiceName,
    now: i64,
) -> Result<Admitted, GateRefusal> {
    let version = state.state.version;
    let s = &state.state;
    let registry = |refusal| GateRefusal::Registry { refusal, version };
    // Membership before anything a non-member could learn from (the state's
    // freshness and version).
    if !s.is_member(caller) {
        return Err(registry(Refusal::NotAMember));
    }
    state.check_fresh(now).map_err(|e| GateRefusal::Stale {
        version,
        why: e.to_string(),
    })?;
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
            principal: principal.map(Principal::name),
        });
    }
    Ok(Admitted {
        role,
        state_version: version,
    })
}

/// How a host implements one service: a `host.json` command, or an app's
/// in-process handler (card 33).
pub(crate) enum Implementation<'a> {
    /// A CLI child, from `host.json`.
    Command(&'a crate::host::config::ServiceImpl),
    /// A native service.
    Native(Arc<dyn crate::host::native::DynService>),
}

/// Everything a host (`wires serve` with a `host.json`) decides with.
/// Built once per `serve`, shared by every session and the push service.
pub(crate) struct ServicesHost {
    /// This host.
    pub(crate) me: NodeId,
    /// The network root whose signed state and memberships are honored.
    pub(crate) trust_root: NodeId,
    /// The host's own membership, presented in the `HelloAck`.
    pub(crate) membership: Membership,
    /// Where the signed state is read from, per connection (so a newer
    /// state adopted by `wires/state` takes effect on the next dial).
    pub(crate) keystore: Arc<Keystore>,
    /// `host.json`.
    pub(crate) config: HostConfig,
    /// The services an app implements in-process (card 33), beside
    /// `config`'s CLI services. Empty for `wires serve`.
    pub(crate) native: crate::host::native::NativeServices,
    /// Verifies the ID tokens callers present, and remembers the verified
    /// principals (what push authorization reads).
    pub(crate) identities: Arc<Identities>,
    /// The call log (card 26a), if any.
    pub(crate) audit: Option<AuditSink>,
    /// The per-call push capability (when `host.json` enables push): the
    /// live tokens and the child socket a service is told about.
    pub(crate) push_grants: Option<crate::host::capability::PushGrants>,
    /// The push service, when it runs: where a native service's
    /// [`push_to_caller`](crate::Call::push_to_caller) goes.
    pub(crate) push_commands: Option<tokio::sync::mpsc::Sender<crate::host::push::PushCommand>>,
    /// The highest state version this host has decided under, in memory:
    /// [`state`](Self::state) refuses anything older read back from disk.
    pub(crate) high_water: std::sync::atomic::AtomicU64,
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
    ///
    /// Also fail closed on a **rollback**: the file is re-read on every
    /// decision, and anyone who can write it could put back an older state
    /// that still verifies (one that still lists a removed member). So the
    /// host keeps the highest version it has used in memory
    /// ([`high_water`](Self::high_water)) and refuses to decide under a
    /// lower one until a state at least that new is back on disk.
    pub(crate) fn state(&self) -> Result<SignedState> {
        use std::sync::atomic::Ordering;
        let state = crate::state::store::read(&self.keystore, self.trust_root)?
            .ok_or_else(|| anyhow!("this host holds no signed state (run `wires join`)"))?;
        let version = state.state.version.0;
        let seen = self.high_water.fetch_max(version, Ordering::SeqCst);
        if version < seen {
            tracing::error!(
                on_disk = version,
                seen,
                "refusing to decide: the signed state on disk is older than one this host already \
                 used (rolled back?)"
            );
            anyhow::bail!(
                "the signed state on disk (version {version}) is older than version {seen}, which \
                 this host already decided under; refusing to decide until a state at least that \
                 new is back"
            );
        }
        Ok(state)
    }

    /// What `serve` checks before it binds: a fresh signed state that
    /// assigns every service in `host.json`, and every native service, to
    /// this host (the error names the first that isn't). A name can't be
    /// both a `host.json` service and a native one.
    pub(crate) fn preflight(&self, now: i64) -> Result<SignedState> {
        let state = self.state()?;
        state.check_fresh(now).with_context(|| {
            format!(
                "this host's signed state (version {}) has expired",
                state.state.version.0
            )
        })?;
        self.config.check_against(&state.state, self.me)?;
        let version = state.state.version.0;
        let me8 = self.me.short();
        for name in self.native.keys() {
            if self.config.services.contains_key(name) {
                bail!("service {name} is both in host.json and a native service; pick one");
            }
            if state.state.service(name).is_none() {
                bail!(
                    "this host implements native service {name}, but the signed state (version \
                     {version}) has no such service"
                );
            }
            if !state.state.assigns(name, self.me) {
                bail!(
                    "this host implements native service {name}, but the signed state (version \
                     {version}) does not assign it to this host ({me8}); refusing to serve it"
                );
            }
        }
        Ok(state)
    }

    /// How this host implements `service`, if it does.
    pub(crate) fn implementation(&self, service: &ServiceName) -> Option<Implementation<'_>> {
        match self.native.get(service) {
            Some(native) => Some(Implementation::Native(Arc::clone(native))),
            None => self
                .config
                .services
                .get(service)
                .map(Implementation::Command),
        }
    }

    /// Whether `caller`, presenting `membership`, is a member of `state`:
    /// the credential is the network root's for this very key and current at
    /// `now`, and the state lists the key. Checked before anything that
    /// costs this host (a token verification, a JWKS fetch, a call-log
    /// entry). `Err` is the exact reason, for this host's trace only; the
    /// peer hears [`NOT_ADMITTED`].
    pub(crate) fn check_member(
        &self,
        state: &SignedState,
        membership: &Membership,
        caller: NodeId,
        now: i64,
    ) -> std::result::Result<(), String> {
        library::check_inclusion(membership, self.trust_root, caller, now)
            .map_err(|e| format!("membership rejected: {e}"))?;
        if !state.state.is_member(caller) {
            return Err(format!(
                "not a member of the signed state (version {})",
                state.state.version.0
            ));
        }
        Ok(())
    }

    /// Verify the ID token `caller` presented (if any): its principal, or
    /// `None` and why there is none (with the `wires login` remedy). Only
    /// for a caller [`check_member`](Self::check_member) passed. Why a token
    /// failed is traced (by [`Identities`]); the caller hears
    /// [`TOKEN_UNVERIFIED`] or [`IDP_UNREACHABLE`].
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
                    p.name()
                )),
            ),
            Err(VerifyError::Unavailable(_)) => (None, Some(IDP_UNREACHABLE.to_string())),
            Err(_) => (None, Some(TOKEN_UNVERIFIED.to_string())),
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
        .inspect_err(|r| {
            if let GateRefusal::AlsoRequire { roles, .. } = r {
                tracing::info!(
                    caller = %caller.hex(),
                    service = %service,
                    also_require = ?roles.iter().map(RoleName::as_str).collect::<Vec<_>>(),
                    "refused by this host's also_require"
                );
            }
        })
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
    /// it (with the principal it last verified as here).
    pub(crate) fn decide_push(
        &self,
        node: NodeId,
        now: i64,
    ) -> std::result::Result<(Option<Principal>, RoleName), PushRefusal> {
        let state = self.state().map_err(|e| {
            tracing::warn!("signed state unusable: {e:#}");
            PushRefusal::Refused(HOST_MISCONFIGURED.to_string())
        })?;
        if let Err(e) = state.check_fresh(now) {
            return Err(PushRefusal::Refused(format!(
                "this host's signed state (version {}) is not fresh ({e})",
                state.state.version.0
            )));
        }
        if !state.state.is_member(node) {
            return Err(PushRefusal::NotAMember(format!(
                "{} is not a member of the current signed state (version {})",
                node.short(),
                state.state.version.0
            )));
        }
        let allow = self
            .config
            .push
            .as_ref()
            .map(|p| p.allow.as_slice())
            .unwrap_or_default();
        if allow.is_empty() {
            return Err(PushRefusal::Refused(
                "this host's host.json `push.allow` is empty: it pushes to no one".to_string(),
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
        Err(PushRefusal::Refused(match &principal {
            Some(p) => format!(
                "{} is in no role allowed to receive pushes ({roles})",
                p.name()
            ),
            None => format!(
                "receiving pushes needs a verified identity in role {roles} (call this host after \
                 `wires login`)"
            ),
        }))
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
    fn setup() -> (SignedState, HostConfig) {
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
        let cfg = HostConfig::parse(r#"{"version":2,"services":{"status":{"command":["true"]}}}"#)
            .unwrap();
        (s.sign(&root).unwrap(), cfg)
    }

    /// [`setup`] plus roles `analyst` (alice) and `sre` (alice, carol),
    /// `orders-db` allowing analyst on 3, and host.json requiring sre too.
    fn strict() -> (SignedState, HostConfig) {
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
        let cfg = HostConfig::parse(
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
        // A non-member hears the fixed sentence, even under an expired
        // state: membership is checked before freshness.
        for now in [0, 101] {
            let e = admit(&s, &cfg, node(3), node(9), None, &status, now).unwrap_err();
            assert_eq!(e.to_string(), NOT_ADMITTED);
        }
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
        // The host's own role names stay out of what the caller hears.
        assert_eq!(
            e.to_string(),
            "alice@x.com is not admitted to orders-db by this host's own rules"
        );
        assert!(!e.to_string().contains("sre"), "{e}");
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
        /// `also_require` says, an admitted caller is one `authorize`
        /// admits, is in **every** `also_require` role, and was decided
        /// under a fresh state.
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
            // The same `also_require` on both services: `status` admits any
            // verified staff, so it is where the host's rule has to narrow.
            let also = also.join(",");
            let cfg = HostConfig::parse(&format!(
                r#"{{"version":2,"services":{{
                    "orders-db":{{"command":["true"],"also_require":[{also}]}},
                    "status":{{"command":["true"],"also_require":[{also}]}}}}}}"#
            )).unwrap();
            let p = email.map(who);
            let svc = name(service);
            if admit(&s, &cfg, node(3), node(caller), p.as_ref(), &svc, now).is_ok() {
                prop_assert!(authorize(&s.state, node(caller), p.as_ref(), &svc).is_ok());
                let required = cfg.services.get(&svc).map(|i| i.also_require.clone());
                for r in required.unwrap_or_default() {
                    prop_assert!(role_admits(&s.state, &r, p.as_ref()), "not in {}", r);
                }
                prop_assert!(s.check_fresh(now).is_ok());
            }
        }
    }
}

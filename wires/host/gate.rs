//! The call gate: what a host checks on every [`Hello`](library::Hello) + [`Invoke`](library::Frame::Invoke),
//! in order, the first failure being the refusal the caller hears:
//!
//! 1. the caller is admitted ([`ServicesHost::admit_caller`]): the ID token
//!    in its `Hello` verifies under the policy's `issuer` items (as
//!    `host.json` narrows them), is unexpired and nonce-bound to the
//!    iroh-authenticated caller, and the host's signed policy bans neither
//!    the node nor the person (removal is a ban; no restart needed, because
//!    the policy is re-read per connection). Anyone else hears only
//!    [`NOT_ADMITTED`] (or [`SIGN_IN_EXPIRED`], [`IDP_UNREACHABLE`]) and is
//!    traced, throttled;
//! 2. the policy is fresh (its head's `not_after`) and, under the signed
//!    `settings.freshness: strict`, vouched for by a current `Fresh` from a
//!    directory ([`freshness`](super::freshness); `lenient`, the default,
//!    only traces a lapse);
//! 3. the service is registered, and assigned to **this** host
//!    ([`Policy::assigns`](library::Policy::assigns));
//! 4. the registry allows the caller's role ([`library::authorize`]);
//! 5. the host's own `also_require` roles (`host.json`), which can only
//!    narrow: the caller must be in **every** one of them.
//!
//! An admitted caller's refusal is also its log line
//! ([`call_trace`](crate::host::call_trace)). The caller's principal is
//! verified in step 1, before [`admit`] runs, so [`admit`] is pure and
//! clock-free except for `now`.
//!
//! [`ServicesHost`] is everything a host decides with: its node id, where
//! its signed policy lives (re-read per connection), its `host.json` and the
//! identity verifier. It holds no credential of its own: a caller trusts it
//! because the service's root-signed entry names its key. The session
//! transport ([`ServicesProtocol`](crate::host::transport::ServicesProtocol))
//! and the push service ([`push`](crate::host::push)) both ask it.

use std::fmt;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use library::{
    FreshnessMode, IdToken, NodeId, Principal, Refusal, RoleName, ServiceName, StateVersion,
    authorize, role_admits,
};

use crate::admin::keystore::Keystore;
use crate::caller::jwks::VerifyError;
use crate::host::config::HostConfig;
use crate::host::freshness::{Freshness, STALE, Vouched};
use crate::host::identity::{Identities, Verified};
use crate::host::transport::Throttle;
use crate::policy::store::Held;

/// The one refusal a peer that is not admitted hears, whatever the reason
/// (no ID token, a malformed one, an untrusted issuer, another audience,
/// another key's, a banned node or person). It says nothing about the
/// policy, its version or who is in it; the exact reason goes only to the
/// host's trace.
pub(crate) const NOT_ADMITTED: &str = "not admitted to this network; sign in with `wires login`";

/// What a caller hears when its ID token verified but has expired: it is
/// who it says, and signing in again is the whole remedy.
pub(crate) const SIGN_IN_EXPIRED: &str = "your sign-in has expired; run `wires login`";

/// What a caller hears when this host could not fetch its issuer's keys.
/// The exact failure goes only to the host's trace.
pub(crate) const IDP_UNREACHABLE: &str =
    "the identity provider is unreachable from this host; try again later";

/// What a peer hears when this host can't decide at all (no readable signed
/// policy, or one older than it already decided under): the operator's
/// problem, not the peer's. The cause goes only to the host's trace.
pub(crate) const HOST_MISCONFIGURED: &str = "host configuration error";

/// Calls decided while the host's policy was not vouched for (traced, not
/// once per call).
static LAPSES: Throttle = Throttle::new();

/// Why [`ServicesHost::decide_push`] refused a recipient. `Display` is the
/// reason traced and reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PushRefusal {
    /// Its node, or the person it verified as here, is banned by the current
    /// signed policy: what is queued for it goes.
    NotAdmitted(String),
    /// A node the push rule refuses, or a host that can't decide now.
    Refused(String),
}

impl fmt::Display for PushRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PushRefusal::NotAdmitted(why) | PushRefusal::Refused(why) => f.write_str(why),
        }
    }
}

/// A call the gate admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Admitted {
    /// The registry role that admitted the caller (`WIRES_ROLE`, and the
    /// call's log line).
    pub(crate) role: RoleName,
    /// The policy version the decision was made under.
    pub(crate) state_version: StateVersion,
    /// Who the caller verified as, and the token that says so: admission is
    /// that verification.
    pub(crate) caller: Verified,
}

/// Why [`admit`] refused. `Display` is the text the caller is sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GateRefusal {
    /// The host's own policy has expired: it admits nobody until the admin
    /// signs a newer one.
    Stale {
        /// The expired policy's version.
        version: StateVersion,
        /// Why it is not fresh.
        why: String,
    },
    /// `settings.freshness` is `strict` and no current `Fresh` vouches for
    /// the host's policy ([`STALE`]).
    Unvouched {
        /// The policy's version.
        version: StateVersion,
    },
    /// The registry refused ([`library::authorize`]).
    Registry {
        /// The registry's reason.
        refusal: Refusal,
        /// The policy version it decided under.
        version: StateVersion,
    },
    /// The service exists, but the registry doesn't assign it to this host.
    NotAssigned {
        /// The service.
        service: ServiceName,
        /// The policy version it decided under.
        version: StateVersion,
    },
    /// The registry admitted the caller, but this host's `also_require`
    /// did not.
    AlsoRequire {
        /// The service.
        service: ServiceName,
        /// Every role this host requires on top of the registry.
        roles: Vec<RoleName>,
        /// Who the caller verified as.
        principal: String,
    },
}

impl fmt::Display for GateRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GateRefusal::Stale { version, why } => write!(
                f,
                "this host's signed policy (version {}) is not fresh ({why}); the admin must sign \
                 a newer one",
                version.0
            ),
            GateRefusal::Unvouched { .. } => f.write_str(STALE),
            GateRefusal::Registry {
                refusal: Refusal::Banned,
                ..
            } => f.write_str(NOT_ADMITTED),
            GateRefusal::Registry { refusal, .. } => write!(f, "{refusal}"),
            GateRefusal::NotAssigned { service, version } => write!(
                f,
                "service {service} is not assigned to this host (signed policy version {})",
                version.0
            ),
            // The roles are this host's own (`host.json`); they stay in its
            // trace, not in what the caller hears.
            GateRefusal::AlsoRequire {
                service, principal, ..
            } => write!(
                f,
                "{principal} is not admitted to {service} by this host's own rules"
            ),
        }
    }
}

/// Run checks 2–5 in the module docs. `me` is this host; `verified` is the
/// caller's ID token and the principal admission verified from it.
pub(crate) fn admit(
    state: &Held,
    config: &HostConfig,
    me: NodeId,
    caller: NodeId,
    verified: &Verified,
    service: &ServiceName,
    now: i64,
) -> Result<Admitted, GateRefusal> {
    let principal = Some(&verified.principal);
    let version = state.version();
    let s = &state.policy;
    let registry = |refusal| GateRefusal::Registry { refusal, version };
    // The bans again before anything a banned caller could learn from (the
    // policy's freshness and version); admission checked them first
    // ([`ServicesHost::admit_caller`]).
    if library::check_admitted(s, caller, &verified.principal).is_err() {
        return Err(registry(Refusal::Banned));
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
            principal: verified.principal.name(),
        });
    }
    Ok(Admitted {
        role,
        state_version: version,
        caller: verified.clone(),
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
    /// The network root whose signed policy is honored.
    pub(crate) trust_root: NodeId,
    /// Where the signed policy is read from, per connection (so a newer
    /// policy fetched from a directory, say one with a new ban, takes
    /// effect on the next dial).
    pub(crate) keystore: Arc<Keystore>,
    /// `host.json`.
    pub(crate) config: HostConfig,
    /// The services an app implements in-process (card 33), beside
    /// `config`'s CLI services. Empty for `wires serve`.
    pub(crate) native: crate::host::native::NativeServices,
    /// Verifies the ID tokens callers present, and remembers the verified
    /// principals (what push authorization reads).
    pub(crate) identities: Arc<Identities>,
    /// The per-call push capability (when `host.json` enables push): the
    /// live tokens and the child socket a service is told about.
    pub(crate) push_grants: Option<crate::host::capability::PushGrants>,
    /// The push service, when it runs: where a native service's
    /// [`push_to_caller`](crate::Call::push_to_caller) goes.
    pub(crate) push_commands: Option<tokio::sync::mpsc::Sender<crate::host::push::PushCommand>>,
    /// The newest `Fresh` a directory signed for the held head, and so
    /// whether `settings.freshness` lets this host decide
    /// ([`freshness`](crate::host::freshness)).
    pub(crate) freshness: Arc<Freshness>,
    /// The highest policy version this host has decided under, in memory:
    /// [`policy`](Self::policy) refuses anything older read back from disk.
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
    /// This host's signed policy, verified under the trust root. A host
    /// with none (or an unreadable one) serves nobody: fail closed. The ID
    /// tokens it verifies from here on are checked under this policy's
    /// `issuer` items, narrowed by `host.json` ([`HostConfig::trust`]).
    ///
    /// Also fail closed on a **rollback**: the file is re-read on every
    /// decision, and anyone who can write it could put back an older policy
    /// that still verifies (one from before a ban). So the
    /// host keeps the highest version it has used in memory
    /// ([`high_water`](Self::high_water)) and refuses to decide under a
    /// lower one until a policy at least that new is back on disk.
    pub(crate) fn policy(&self) -> Result<Held> {
        use std::sync::atomic::Ordering;
        let state =
            crate::policy::store::read(&self.keystore, self.trust_root)?.ok_or_else(|| {
                anyhow!(
                    "this host holds no signed policy yet (the admin's next publish, or a \
                     directory, gives it one)"
                )
            })?;
        let version = state.version().0;
        let seen = self.high_water.fetch_max(version, Ordering::SeqCst);
        if version < seen {
            tracing::error!(
                on_disk = version,
                seen,
                "refusing to decide: the signed policy on disk is older than one this host \
                 already used (rolled back?)"
            );
            anyhow::bail!(
                "the signed policy on disk (version {version}) is older than version {seen}, \
                 which this host already decided under; refusing to decide until a policy at \
                 least that new is back"
            );
        }
        self.identities.set_trust(self.config.trust(&state.policy));
        Ok(state)
    }

    /// What `serve` checks before it binds: a fresh signed policy that
    /// assigns every service in `host.json`, and every native service, to
    /// this host (the error names the first that isn't). A name can't be
    /// both a `host.json` service and a native one.
    pub(crate) fn preflight(&self, now: i64) -> Result<Held> {
        let state = self.policy()?;
        state.check_fresh(now).with_context(|| {
            format!(
                "this host's signed policy (version {}) has expired",
                state.version().0
            )
        })?;
        self.config.check_against(&state.policy, self.me)?;
        let version = state.version().0;
        let me8 = self.me.short();
        for name in self.native.keys() {
            if self.config.services.contains_key(name) {
                bail!("service {name} is both in host.json and a native service; pick one");
            }
            if state.policy.service(name).is_none() {
                bail!(
                    "this host implements native service {name}, but the signed policy (version \
                     {version}) has no such service"
                );
            }
            if !state.policy.assigns(name, self.me) {
                bail!(
                    "this host implements native service {name}, but the signed policy (version \
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

    /// Admit `caller`, presenting `token` in its `Hello`, under `state`: the
    /// token verifies (trusted issuer and audience under this policy as
    /// `host.json` narrows it, signature, unexpired, nonce bound to
    /// `caller`), and the policy bans neither the node nor the person
    /// ([`library::check_admitted`]). `Err` is what the peer hears
    /// ([`NOT_ADMITTED`], [`SIGN_IN_EXPIRED`] or [`IDP_UNREACHABLE`]) and the
    /// exact reason, for this host's trace only.
    pub(crate) async fn admit_caller(
        &self,
        state: &Held,
        caller: NodeId,
        token: &IdToken,
        now: i64,
    ) -> std::result::Result<Verified, (&'static str, String)> {
        let principal = match self.identities.verify_token(caller, token, now).await {
            Ok(p) => p,
            Err(VerifyError::Expired(p)) => {
                return Err((
                    SIGN_IN_EXPIRED,
                    format!("the ID token for {} has expired", p.name()),
                ));
            }
            Err(VerifyError::Unavailable(e)) => {
                return Err((IDP_UNREACHABLE, format!("the IdP is unreachable: {e}")));
            }
            Err(e) => return Err((NOT_ADMITTED, format!("the ID token did not verify: {e}"))),
        };
        if library::check_admitted(&state.policy, caller, &principal).is_err() {
            return Err((
                NOT_ADMITTED,
                format!(
                    "{} on {}… is removed by the signed policy (version {})",
                    principal.name(),
                    caller.short(),
                    state.version().0
                ),
            ));
        }
        Ok(Verified {
            token: token.clone(),
            principal,
        })
    }

    /// Whether this host may decide under `state` at `now` by the signed
    /// freshness rule: always under `lenient` (a lapse is traced,
    /// throttled), and under `strict` only while a current `Fresh` vouches
    /// for its head.
    pub(crate) fn check_vouched(&self, state: &Held, now: i64) -> Result<(), GateRefusal> {
        let since = match self.freshness.vouched(&state.signed.head, now) {
            Vouched::Current => return Ok(()),
            Vouched::Lapsed { since } => since,
        };
        let version = state.version();
        match state.policy.settings.freshness {
            FreshnessMode::Strict => {
                if let Some(n) = LAPSES.tick(now.saturating_mul(1000)) {
                    tracing::warn!(
                        policy_version = version.0,
                        lapsed_at = ?since,
                        refused = n,
                        "strict: refusing calls, no directory has vouched for this host's policy \
                         recently"
                    );
                }
                Err(GateRefusal::Unvouched { version })
            }
            FreshnessMode::Lenient => {
                // A network with no directory has nothing to vouch: no news.
                if state.directories().is_empty() {
                    return Ok(());
                }
                if let Some(n) = LAPSES.tick(now.saturating_mul(1000)) {
                    tracing::warn!(
                        policy_version = version.0,
                        lapsed_at = ?since,
                        calls = n,
                        "lenient: still deciding under this host's policy, which no directory has \
                         vouched for recently (until its not_after)"
                    );
                }
                Ok(())
            }
        }
    }

    /// [`admit`] under `state`, as the text the caller is sent. First the
    /// freshness rule ([`check_vouched`](Self::check_vouched)).
    pub(crate) fn decide(
        &self,
        state: &Held,
        caller: NodeId,
        verified: &Verified,
        service: &ServiceName,
        now: i64,
    ) -> std::result::Result<Admitted, String> {
        self.check_vouched(state, now).map_err(|r| r.to_string())?;
        admit(state, &self.config, self.me, caller, verified, service, now)
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
            .map_err(|r| r.to_string())
    }

    /// Whether `node` may receive pushes from this host at `now`: neither it
    /// nor the person it last verified as here is banned by the current
    /// signed policy, and it is in the first `push.allow` role that admits
    /// it (with that principal). A node only has a principal here after it
    /// presented a token that verified (on a call or a fetch), so a node
    /// that never did is in no role.
    pub(crate) fn decide_push(
        &self,
        node: NodeId,
        now: i64,
    ) -> std::result::Result<(Option<Principal>, RoleName), PushRefusal> {
        let state = self.policy().map_err(|e| {
            tracing::warn!("signed policy unusable: {e:#}");
            PushRefusal::Refused(HOST_MISCONFIGURED.to_string())
        })?;
        if let Err(e) = state.check_fresh(now) {
            return Err(PushRefusal::Refused(format!(
                "this host's signed policy (version {}) is not fresh ({e})",
                state.version().0
            )));
        }
        let principal = self.identities.current(node, now);
        let person_banned = principal
            .as_ref()
            .is_some_and(|p| state.policy.bans_person(p));
        if state.policy.bans_node(node) || person_banned {
            return Err(PushRefusal::NotAdmitted(format!(
                "{} is removed by the current signed policy (version {})",
                node.short(),
                state.version().0
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
        if let Some(role) = allow
            .iter()
            .find(|r| role_admits(&state.policy, r, principal.as_ref()))
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

    /// The nodes `role` names at `now` (never this host): every node whose
    /// last verified principal here is in the role, neither the node nor the
    /// person banned. A node with no verified identity here is in no role.
    pub(crate) fn push_recipients(&self, role: &RoleName, now: i64) -> Vec<NodeId> {
        let Ok(state) = self.policy() else {
            return Vec::new();
        };
        let s = &state.policy;
        let mut nodes: Vec<NodeId> = self
            .identities
            .nodes()
            .into_iter()
            .filter(|n| {
                let principal = self.identities.current(*n, now);
                !s.bans_node(*n)
                    && !principal.as_ref().is_some_and(|p| s.bans_person(p))
                    && role_admits(s, role, principal.as_ref())
            })
            .collect();
        nodes.retain(|n| *n != self.me);
        nodes.sort();
        nodes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{Matcher, NodeIdentity, Policy, Service};
    use proptest::prelude::*;

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    const ISS: &str = "https://idp.example";

    fn who(email: &str) -> Verified {
        Verified {
            token: IdToken::new(format!("token-of-{email}")),
            principal: Principal {
                issuer: ISS.into(),
                subject: email.into(),
                email: Some(email.into()),
                org: None,
                groups: vec![],
                not_after: i64::MAX,
            },
        }
    }

    fn name(s: &str) -> ServiceName {
        ServiceName::new(s).unwrap()
    }

    fn role(s: &str) -> RoleName {
        RoleName::new(s).unwrap()
    }

    /// Root 1; 2 calls and 3 is this host; node 9 and mallory are banned;
    /// `status` (staff: anyone [`ISS`] verified) on 3.
    fn setup() -> (Held, HostConfig) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut s = Policy::new(root.node_id());
        s.version = StateVersion(5);
        s.not_after = 100;
        s.ban(node(9));
        s.ban_person(library::Person::new(
            library::Issuer::new(ISS),
            "mallory@x.com",
        ));
        s.roles.insert(role("staff"), vec![Matcher::new(ISS)]);
        s.services.insert(
            name("status"),
            Service {
                description: String::new(),
                allow: vec![role("staff")],
                hosts: vec![node(3)],
            },
        );
        let cfg = HostConfig::parse(r#"{"version":2,"services":{"status":{"command":["true"]}}}"#)
            .unwrap();
        (crate::testutil::held(&root, s), cfg)
    }

    /// [`setup`] plus roles `analyst` (alice) and `sre` (alice, carol),
    /// `orders-db` allowing analyst on 3, and host.json requiring sre too.
    fn strict() -> (Held, HostConfig) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let (signed, _) = setup();
        let mut s = signed.policy;
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
            },
        );
        let cfg = HostConfig::parse(
            r#"{"version":2,"services":{"orders-db":{"command":["true"],"also_require":["sre"]}}}"#,
        )
        .unwrap();
        (crate::testutil::held(&root, s), cfg)
    }

    #[test]
    fn an_admitted_call_carries_its_verified_identity() {
        let (s, cfg) = setup();
        let status = name("status");
        let bob = who("bob@x.com");
        let ok = admit(&s, &cfg, node(3), node(2), &bob, &status, 0).unwrap();
        assert_eq!(ok.state_version, StateVersion(5));
        assert_eq!(ok.role, role("staff"));
        // The admitted call carries the token and principal it verified.
        assert_eq!(ok.caller, bob);
    }

    #[test]
    fn refusals_in_order() {
        let (s, cfg) = setup();
        let status = name("status");
        let bob = who("bob@x.com");
        assert!(matches!(
            admit(&s, &cfg, node(3), node(2), &bob, &status, 101),
            Err(GateRefusal::Stale { .. })
        ));
        // A banned node or person hears the fixed sentence, even under an
        // expired policy: the bans are checked before freshness.
        let mallory = who("mallory@x.com");
        for now in [0, 101] {
            let e = admit(&s, &cfg, node(3), node(9), &bob, &status, now).unwrap_err();
            assert_eq!(e.to_string(), NOT_ADMITTED);
            let e = admit(&s, &cfg, node(3), node(2), &mallory, &status, now).unwrap_err();
            assert_eq!(e.to_string(), NOT_ADMITTED);
        }
        assert!(matches!(
            admit(&s, &cfg, node(2), node(2), &bob, &status, 0),
            Err(GateRefusal::NotAssigned { .. })
        ));
        assert!(matches!(
            admit(&s, &cfg, node(3), node(2), &bob, &name("nope"), 0),
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
        let ok = admit(&s, &cfg, node(3), node(2), &alice, &db, 0).unwrap();
        assert_eq!(ok.role, role("analyst"));
        // carol: sre but not analyst — the host's rule can't widen.
        let carol = who("carol@x.com");
        assert!(matches!(
            admit(&s, &cfg, node(3), node(2), &carol, &db, 0),
            Err(GateRefusal::Registry { .. })
        ));
        // alice without sre on the host side: refused by also_require.
        let mut state = s.policy.clone();
        state.roles.insert(
            role("sre"),
            vec![Matcher {
                email: Some("carol@x.com".parse().unwrap()),
                ..Matcher::new(ISS)
            }],
        );
        let s2 = crate::testutil::held(&NodeIdentity::from_seed([1u8; 32]), state);
        let e = admit(&s2, &cfg, node(3), node(2), &alice, &db, 0).unwrap_err();
        assert!(matches!(e, GateRefusal::AlsoRequire { .. }));
        // The host's own role names stay out of what the caller hears.
        assert_eq!(
            e.to_string(),
            "alice@x.com is not admitted to orders-db by this host's own rules"
        );
        assert!(!e.to_string().contains("sre"), "{e}");
    }

    proptest! {
        /// The host never admits more than the registry: whatever
        /// `also_require` says, an admitted caller is one `authorize`
        /// admits, is in **every** `also_require` role, and was decided
        /// under a fresh policy.
        #[test]
        fn the_gate_never_widens_the_registry(
            caller in 1u8..6,
            email in prop::sample::select(vec![
                "alice@x.com", "carol@x.com", "eve@y.com", "mallory@x.com",
            ]),
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
            let p = who(email);
            let svc = name(service);
            if let Ok(ok) = admit(&s, &cfg, node(3), node(caller), &p, &svc, now) {
                let principal = Some(&p.principal);
                prop_assert!(library::check_admitted(&s.policy, node(caller), &p.principal).is_ok());
                prop_assert!(authorize(&s.policy, node(caller), principal, &svc).is_ok());
                let required = cfg.services.get(&svc).map(|i| i.also_require.clone());
                for r in required.unwrap_or_default() {
                    prop_assert!(role_admits(&s.policy, &r, principal), "not in {}", r);
                }
                prop_assert!(s.check_fresh(now).is_ok());
                // Admitted is verified: the very token and principal given.
                prop_assert_eq!(&ok.caller, &p);
            }
        }
    }
}

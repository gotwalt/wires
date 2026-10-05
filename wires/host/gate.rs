//! The call gate: what a host checks on every [`Hello`](library::Hello) + [`Invoke`](library::Frame::Invoke),
//! in order, the first failure being the refusal the caller hears:
//!
//! 1. the caller is admitted ([`ServicesHost::admit_caller`]): the ID token
//!    in its `Hello` verifies under the policy's `issuer` items (as
//!    `host.json` narrows them), is unexpired and nonce-bound to the
//!    iroh-authenticated caller, and [`library::check_admitted`] passes: a
//!    verified email, neither the node nor the person banned (removal is a
//!    ban; no restart needed, because the policy is re-read per
//!    connection), and some role in the policy matches the person. Anyone
//!    else hears only [`NOT_ADMITTED`] (or [`SIGN_IN_EXPIRED`],
//!    [`IDP_UNREACHABLE`]) and is traced, throttled;
//! 2. the policy is fresh (its head's `not_after`). Whether a directory has
//!    vouched for it lately is the caller's check, made before it sent
//!    anything ([`freshness`](super::freshness), card 49);
//! 3. the policy allows the caller to call the service
//!    ([`library::authorize`]: it exists, and a role in its `allow` admits
//!    the caller). If not, whatever the reason, the caller hears one fixed
//!    sentence ([`not_callable`]) and the reason goes to the trace: a host
//!    tells an admitted caller nothing about services it may not call;
//! 4. the service is assigned to **this** host
//!    ([`Policy::assigns`](library::Policy::assigns));
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
    IdToken, NodeId, Principal, Refusal, RoleName, ServiceName, StateVersion, authorize,
};

use crate::admin::keystore::Keystore;
use crate::caller::jwks::VerifyError;
use crate::host::config::HostConfig;
use crate::host::freshness::Freshness;
use crate::host::identity::{Identities, Verified};
use crate::policy::store::Held;

/// The one refusal a peer that is not admitted hears, from a host or a
/// directory, whatever the reason (no ID token, a malformed one, an
/// untrusted issuer, another audience, another key's, no verified email, a
/// banned node or person, no role that matches). It says nothing about the
/// policy, its version or who is in it; the exact reason goes only to the
/// host's or directory's trace. A signed-in caller says more, from its own token
/// ([`crate::caller::hello::explain_not_admitted`]).
pub(crate) const NOT_ADMITTED: &str =
    "not admitted to this network: sign in with `wires login`, or ask your admin for a role";

/// What an admitted caller hears for a service it may not call, whatever
/// the reason (no such service, nobody allowed, no role of its in the
/// `allow`): no role name, no policy version.
pub(crate) fn not_callable(service: &ServiceName) -> String {
    format!("no service named `{service}` that you may call")
}

/// What an admitted inbox fetcher hears when this host won't hand it pushes
/// (`push.allow` doesn't admit it, the host pushes to no one, or can't
/// decide now): no role name. The reason goes to the trace.
pub(crate) const INBOX_REFUSED: &str = "inbox fetch refused: this host does not push to you";

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

/// Why [`ServicesHost::decide_push`] refused a recipient. `Display` is the
/// reason traced and reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PushRefusal {
    /// Its node, or the person it verified as here, is banned by the current
    /// signed policy: what is queued for it goes. (A principal the policy no
    /// longer admits for another reason is [`Refused`](Self::Refused).)
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

/// Why [`ServicesHost::admit_caller`] refused a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NotAdmitted {
    /// What the peer hears: [`NOT_ADMITTED`], [`SIGN_IN_EXPIRED`] or
    /// [`IDP_UNREACHABLE`].
    pub(crate) said: &'static str,
    /// The exact reason, for this host's trace only.
    pub(crate) why: String,
    /// The policy bans the node or the person (an inbox fetch drops what is
    /// queued for it).
    pub(crate) banned: bool,
}

/// A call the gate admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Admitted {
    /// The policy's role that admitted the caller (`WIRES_ROLE`, and the
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
    /// The policy no longer admits the caller ([`library::check_admitted`],
    /// checked again before anything a removed caller could learn from).
    /// The caller hears [`NOT_ADMITTED`].
    NotAdmitted {
        /// Why, for the trace.
        why: String,
    },
    /// The policy refused ([`library::authorize`]): no such service,
    /// nobody allowed, or no role of the caller's in its `allow`. The caller
    /// hears [`not_callable`] whichever it was.
    NotCallable {
        /// The service asked for.
        service: ServiceName,
        /// The policy's reason, for the trace only.
        refusal: Refusal,
    },
    /// The caller may call the service, but the policy doesn't assign it
    /// to this host.
    NotAssigned {
        /// The service.
        service: ServiceName,
        /// The policy version it decided under.
        version: StateVersion,
    },
    /// The policy admitted the caller, but this host's `also_require`
    /// did not.
    AlsoRequire {
        /// The service.
        service: ServiceName,
        /// Every role this host requires on top of the policy's `allow`.
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
            GateRefusal::NotAdmitted { .. } => f.write_str(NOT_ADMITTED),
            GateRefusal::NotCallable { service, .. } => f.write_str(&not_callable(service)),
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
    // Admission again before anything a removed caller could learn from
    // (the policy's freshness and version); admission checked it first
    // ([`ServicesHost::admit_caller`]).
    if let Err(e) = library::check_admitted(s, caller, &verified.principal) {
        return Err(GateRefusal::NotAdmitted { why: e.to_string() });
    }
    state.check_fresh(now).map_err(|e| GateRefusal::Stale {
        version,
        why: e.to_string(),
    })?;
    // Whether the caller may call it at all comes before anything about
    // this host, so a service it may not call is told apart from nothing.
    let role = authorize(s, caller, principal, service).map_err(|refusal| match refusal {
        Refusal::Banned => GateRefusal::NotAdmitted {
            why: refusal.to_string(),
        },
        refusal => GateRefusal::NotCallable {
            service: service.clone(),
            refusal,
        },
    })?;
    if !s.assigns(service, me) {
        return Err(GateRefusal::NotAssigned {
            service: service.clone(),
            version,
        });
    }
    let also = config
        .services
        .get(service)
        .map(|svc| svc.also_require.as_slice())
        .unwrap_or_default();
    if !also.iter().all(|r| s.role_admits(r, principal)) {
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
    /// The newest `Fresh` each directory signed for the held head: what this
    /// host shows a caller first ([`freshness`](crate::host::freshness)).
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
    /// `caller`), and [`library::check_admitted`] passes (a verified email,
    /// no ban on the node or the person, a role that matches). Only then is
    /// the principal remembered ([`Identities::record`]), so a token that
    /// fails, or a person the policy doesn't admit, leaves no entry. `Err`
    /// says what the peer hears and why ([`NotAdmitted`]).
    pub(crate) async fn admit_caller(
        &self,
        state: &Held,
        caller: NodeId,
        token: &IdToken,
        now: i64,
    ) -> std::result::Result<Verified, NotAdmitted> {
        // A banned node is banned whatever its token says.
        let refused = |said, why| NotAdmitted {
            said,
            why,
            banned: state.policy.bans_node(caller),
        };
        let principal = match self.identities.verify_token(caller, token, now).await {
            Ok(p) => p,
            Err(VerifyError::Expired(p)) => {
                // Genuine but expired: it still names the person, so a ban
                // on them still counts.
                return Err(NotAdmitted {
                    banned: state.policy.bans_node(caller) || state.policy.bans_person(&p),
                    ..refused(
                        SIGN_IN_EXPIRED,
                        format!("the ID token for {} has expired", p.name()),
                    )
                });
            }
            Err(VerifyError::Unavailable(e)) => {
                return Err(refused(
                    IDP_UNREACHABLE,
                    format!("the IdP is unreachable: {e}"),
                ));
            }
            Err(e) => {
                return Err(refused(
                    NOT_ADMITTED,
                    format!("the ID token did not verify: {e}"),
                ));
            }
        };
        if let Err(e) = library::check_admitted(&state.policy, caller, &principal) {
            return Err(NotAdmitted {
                said: NOT_ADMITTED,
                why: format!(
                    "{} on {}… is not admitted by the signed policy (version {}): {e}",
                    principal.name(),
                    caller.short(),
                    state.version().0
                ),
                banned: matches!(e, library::Error::Banned),
            });
        }
        self.identities.record(caller, &Ok(principal.clone()));
        Ok(Verified {
            token: token.clone(),
            principal,
        })
    }

    /// [`admit`] under `state`, as the text the caller is sent.
    pub(crate) fn decide(
        &self,
        state: &Held,
        caller: NodeId,
        verified: &Verified,
        service: &ServiceName,
        now: i64,
    ) -> std::result::Result<Admitted, String> {
        admit(state, &self.config, self.me, caller, verified, service, now)
            // The detail is for `debug`: the one `info` line a refusal makes
            // is its `call refused` line (call_trace).
            .inspect_err(|r| match r {
                GateRefusal::AlsoRequire { roles, .. } => tracing::debug!(
                    caller = %caller.hex(),
                    service = %service,
                    also_require = ?roles.iter().map(RoleName::as_str).collect::<Vec<_>>(),
                    "refused by this host's also_require"
                ),
                // The caller hears one fixed sentence; which it was is here.
                GateRefusal::NotCallable { refusal, .. } => tracing::debug!(
                    caller = %caller.hex(),
                    service = %service,
                    why = %refusal,
                    "refused by the signed policy"
                ),
                GateRefusal::NotAdmitted { why } => tracing::debug!(
                    caller = %caller.hex(),
                    service = %service,
                    why = %why,
                    "no longer admitted"
                ),
                _ => {}
            })
            .map_err(|r| r.to_string())
    }

    /// Whether `node` may receive pushes from this host at `now`: the node
    /// isn't banned, the person it last verified as here is still admitted
    /// ([`library::check_admitted`]; a ban is [`PushRefusal::NotAdmitted`],
    /// anything else [`PushRefusal::Refused`]), and it is in the first
    /// `push.allow` role that admits it (with that principal). A node only
    /// has a principal here after it was admitted (on a call or a fetch), so
    /// a node that never was is in no role.
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
        let admitted = match &principal {
            Some(p) => library::check_admitted(&state.policy, node, p),
            None if state.policy.bans_node(node) => Err(library::Error::Banned),
            None => Ok(()),
        };
        match admitted {
            Ok(()) => {}
            Err(library::Error::Banned) => {
                return Err(PushRefusal::NotAdmitted(format!(
                    "{} is removed by the current signed policy (version {})",
                    node.short(),
                    state.version().0
                )));
            }
            Err(e) => {
                return Err(PushRefusal::Refused(format!(
                    "{} is no longer admitted by the current signed policy (version {}): {e}",
                    node.short(),
                    state.version().0
                )));
            }
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
            .find(|r| state.policy.role_admits(r, principal.as_ref()))
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
    /// last verified principal here is in the role and still admitted
    /// ([`library::check_admitted`]). A node with no verified identity here
    /// is in no role.
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
                self.identities.current(*n, now).is_some_and(|p| {
                    library::check_admitted(s, *n, &p).is_ok() && s.role_admits(role, Some(&p))
                })
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
    /// `status` (staff: anyone [`ISS`] verified with an email) on 3.
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
        // A service bob may call, on a host it isn't assigned to.
        assert!(matches!(
            admit(&s, &cfg, node(2), node(2), &bob, &status, 0),
            Err(GateRefusal::NotAssigned { .. })
        ));
        assert!(matches!(
            admit(&s, &cfg, node(3), node(2), &bob, &name("nope"), 0),
            Err(GateRefusal::NotCallable {
                refusal: Refusal::UnknownService(_),
                ..
            })
        ));
    }

    /// An admitted caller probing a service it isn't allowed, one nobody
    /// is allowed, and one that doesn't exist hears the same bytes, naming
    /// no role and no policy version, whichever host it asks; only for a
    /// service it may call does it learn that this host doesn't serve it.
    #[test]
    fn a_service_you_may_not_call_sounds_like_one_that_does_not_exist() {
        let (s, cfg) = strict();
        let mut p = s.policy.clone();
        p.services.insert(
            name("locked"),
            Service {
                description: String::new(),
                allow: vec![],
                hosts: vec![node(3)],
            },
        );
        let s = crate::testutil::held(&NodeIdentity::from_seed([1u8; 32]), p);
        let bob = who("bob@x.com"); // staff, not analyst
        for me in [node(3), node(4)] {
            for probe in ["orders-db", "locked", "nope"] {
                let e = admit(&s, &cfg, me, node(2), &bob, &name(probe), 0).unwrap_err();
                assert!(matches!(e, GateRefusal::NotCallable { .. }), "{e:?}");
                let said = e.to_string();
                assert_eq!(
                    said,
                    format!("no service named `{probe}` that you may call")
                );
                for leak in ["analyst", "staff", "sre", "version", "5"] {
                    assert!(!said.contains(leak), "{said}");
                }
            }
        }
        // The same name, existing (not his to call) or not existing at all:
        // the same bytes.
        let mut gone = s.policy.clone();
        gone.services.remove(&name("orders-db"));
        let gone = crate::testutil::held(&NodeIdentity::from_seed([1u8; 32]), gone);
        let db = name("orders-db");
        let there = admit(&s, &cfg, node(3), node(2), &bob, &db, 0).unwrap_err();
        let absent = admit(&gone, &cfg, node(3), node(2), &bob, &db, 0).unwrap_err();
        assert_eq!(there.to_string().as_bytes(), absent.to_string().as_bytes());
        let status = admit(&s, &cfg, node(4), node(2), &bob, &name("status"), 0).unwrap_err();
        assert!(
            matches!(status, GateRefusal::NotAssigned { .. }),
            "{status:?}"
        );
    }

    /// A person the IdP verified but no role names, and one whose token
    /// carries no verified email, are not admitted, even under a role that
    /// names only the issuer.
    #[test]
    fn no_role_or_no_email_is_not_admitted() {
        let (s, cfg) = setup();
        let mut stranger = who("dave@elsewhere.example");
        stranger.principal.issuer = "https://other-idp.example".into();
        let mut no_email = who("bob@x.com");
        no_email.principal.email = None;
        for caller in [stranger, no_email] {
            let e = admit(&s, &cfg, node(3), node(2), &caller, &name("status"), 0).unwrap_err();
            assert!(matches!(e, GateRefusal::NotAdmitted { .. }), "{e:?}");
            assert_eq!(e.to_string(), NOT_ADMITTED);
        }
    }

    #[test]
    fn also_require_only_narrows() {
        let (s, cfg) = strict();
        let db = name("orders-db");
        // alice: analyst (policy) and sre (host) — admitted as analyst.
        let alice = who("alice@x.com");
        let ok = admit(&s, &cfg, node(3), node(2), &alice, &db, 0).unwrap();
        assert_eq!(ok.role, role("analyst"));
        // carol: sre but not analyst — the host's rule can't widen.
        let carol = who("carol@x.com");
        assert!(matches!(
            admit(&s, &cfg, node(3), node(2), &carol, &db, 0),
            Err(GateRefusal::NotCallable { .. })
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
        /// The host never admits more than the policy: whatever
        /// `also_require` says, an admitted caller is one `authorize`
        /// admits, is in **every** `also_require` role, and was decided
        /// under a fresh policy.
        #[test]
        fn the_gate_never_widens_the_policy(
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
                    prop_assert!(s.policy.role_admits(&r, principal), "not in {}", r);
                }
                prop_assert!(s.check_fresh(now).is_ok());
                // Admitted is verified: the very token and principal given.
                prop_assert_eq!(&ok.caller, &p);
            }
        }
    }
}

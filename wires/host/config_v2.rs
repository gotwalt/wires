//! `host.json` version 2: how this host implements the services the signed
//! state assigns to it (card 27).
//!
//! Who may call a service is no longer the host's to say: the admin-signed
//! registry names each service's roles and hosts. The host file shrinks to
//! the implementation plus local trust, and may only be **stricter**:
//!
//! ```json
//! {
//!   "version": 2,
//!   "identity": { "issuers": [
//!     { "issuer": "https://accounts.google.com", "audiences": ["476….apps.googleusercontent.com"] }
//!   ] },
//!   "services": {
//!     "orders-db": {
//!       "command": ["sqlite3", "-safe", "-readonly", "orders.db"],
//!       "cwd": "/srv/orders",
//!       "env": { "LC_ALL": "C" },
//!       "also_require": ["sre"]
//!     }
//!   },
//!   "push": { "allow": ["analyst"], "log_body": false },
//!   "audit": { "otlp": "https://collector.example:4318" }
//! }
//! ```
//!
//! - `version` (required, `2`). **Unknown keys are errors** at every level.
//! - `identity.issuers`: the IdPs whose ID tokens this host verifies, each
//!   with the OAuth client ids it accepts as `aud`. Local trust: the registry's roles match principals,
//!   but which IdPs to believe is the host's call.
//! - `services`: name → `command` (argv, never a shell; each call's
//!   arguments are appended), optional `cwd`, optional `env` (set on top of
//!   the scrubbed environment), and `also_require`: roles (defined in the
//!   signed state) the caller must **also** be in, on top of the registry's
//!   `allow`. It can only narrow.
//! - `push`: which registry roles may receive pushes from this host, and
//!   whether the call log keeps push bodies (card 23).
//! - `audit.otlp`: an OTLP/HTTP collector the call log is also exported to
//!   (card 26a).
//!
//! What this parser checks is the file on its own. Checks against the signed
//! state (every service here is assigned to this host; every role named is
//! defined) are [`HostConfigV2::check_against`], which `serve` runs before
//! it binds. Version 1 (tools and roles decided by the host, card 13) is
//! refused with a pointer to the signed state.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use library::{Audience, Issuer, NodeId, RoleName, ServiceName, State};
use serde::{Deserialize, Serialize};

use crate::host::identity::IdpTrust;

/// The `host.json` version this module reads.
pub(crate) const HOST_CONFIG_V2: u32 = 2;

/// A parsed, validated v2 `host.json`. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostConfigV2 {
    /// The format version; must be [`HOST_CONFIG_V2`].
    pub(crate) version: u32,
    /// Which IdPs the host trusts.
    #[serde(default)]
    pub(crate) identity: IdentityConfig,
    /// How each assigned service runs here, by name.
    pub(crate) services: BTreeMap<ServiceName, ServiceImpl>,
    /// Who may receive pushes from this host. Absent: nobody.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) push: Option<PushV2>,
    /// Where the host's call log is exported. Absent: nowhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) audit: Option<AuditConfig>,
}

/// How one service runs on this host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceImpl {
    /// The fixed argv; each call's arguments are appended. Never a shell.
    pub(crate) command: Vec<String>,
    /// The working directory. Absent: `serve`'s own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cwd: Option<PathBuf>,
    /// Extra environment, set after the scrub and before the `WIRES_*`
    /// variables (which always win).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) env: BTreeMap<String, String>,
    /// Roles (from the signed state) the caller must also be in. Empty: the
    /// registry's `allow` alone decides.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) also_require: Vec<RoleName>,
}

/// `push` in v2: registry roles that may receive pushes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PushV2 {
    /// The roles whose members may receive pushes, tried in order. Empty:
    /// nobody.
    #[serde(default)]
    pub(crate) allow: Vec<RoleName>,
    /// Record each push's body in the call log, not only its subject.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) log_body: bool,
}

/// `audit`: optional sinks for the host's call log, beyond the log itself.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditConfig {
    /// An OTLP/HTTP collector base URL (`/v1/logs` is appended).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) otlp: Option<String>,
}

/// `identity`: the IdPs the host verifies ID tokens from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityConfig {
    /// The trusted issuers.
    #[serde(default)]
    pub(crate) issuers: Vec<TrustedIssuer>,
}

impl IdentityConfig {
    /// The IdPs and per-issuer audiences to verify ID tokens under.
    pub(crate) fn trust(&self) -> IdpTrust {
        IdpTrust::per_issuer(
            self.issuers
                .iter()
                .map(|t| {
                    (
                        Issuer::new(t.issuer.clone()),
                        t.audiences
                            .iter()
                            .filter(|a| !a.trim().is_empty())
                            .map(|a| Audience::new(a.clone()))
                            .collect(),
                    )
                })
                .collect(),
        )
    }
}

/// One trusted IdP.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustedIssuer {
    /// The token `iss`, exactly (e.g. `https://accounts.google.com`).
    pub(crate) issuer: String,
    /// The OAuth client ids accepted as `aud` from this issuer.
    pub(crate) audiences: Vec<String>,
}

impl HostConfigV2 {
    /// Read and validate `host.json` at `path`.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("{} is not a valid host.json", path.display()))
    }

    /// Parse and validate v2 text: the schema, then
    /// [`validate`](Self::validate).
    pub(crate) fn parse(text: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct Peek {
            version: Option<u32>,
        }
        match serde_json::from_str::<Peek>(text)?.version {
            Some(HOST_CONFIG_V2) => {}
            Some(1) => bail!(
                "version 1 (tools and roles decided by the host) is no longer served: services \
                 and roles live in the admin-signed state (`wires service add`, `wires role \
                 set`), and host.json version 2 says how this host implements them"
            ),
            Some(v) => bail!("version {v} is not supported (this host reads version 2)"),
            None => bail!("missing `version`"),
        }
        let config: Self = serde_json::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    /// The rules the schema can't say, on the file alone:
    ///
    /// - `version` is [`HOST_CONFIG_V2`]; at least one service; no empty
    ///   command; no empty `cwd`;
    /// - `env` names are non-empty, contain no `=` or NUL, and don't start
    ///   with `WIRES_` (the server-derived variables are not settable);
    /// - each issuer is listed once, non-empty, with at least one audience;
    /// - `audit.otlp` is an https URL (or http to a loopback collector).
    pub(crate) fn validate(&self) -> Result<()> {
        if self.version != HOST_CONFIG_V2 {
            bail!(
                "version {} is not supported here (expected {HOST_CONFIG_V2})",
                self.version
            );
        }
        let mut issuers: Vec<&str> = Vec::new();
        for trusted in &self.identity.issuers {
            let iss = trusted.issuer.as_str();
            if iss.trim().is_empty() {
                bail!("identity.issuers: an issuer is empty");
            }
            if issuers.contains(&iss) {
                bail!("identity.issuers: {iss} is listed twice");
            }
            if trusted.audiences.iter().all(|a| a.trim().is_empty()) {
                bail!("identity.issuers: {iss} has no audiences");
            }
            issuers.push(iss);
        }
        if self.services.is_empty() {
            bail!("nothing is implemented: `services` is empty");
        }
        for (name, svc) in &self.services {
            if svc.command.is_empty() {
                bail!("service {name}: empty command");
            }
            if svc.cwd.as_ref().is_some_and(|c| c.as_os_str().is_empty()) {
                bail!("service {name}: empty cwd");
            }
            for key in svc.env.keys() {
                if key.is_empty() || key.contains(['=', '\0']) {
                    bail!("service {name}: env name {key:?} is not a variable name");
                }
                if key.starts_with("WIRES_") {
                    bail!("service {name}: env {key} is set by wires itself");
                }
            }
        }
        if let Some(url) = self.audit.as_ref().and_then(|a| a.otlp.as_deref()) {
            crate::host::otlp::logs_url(url).context("audit.otlp")?;
        }
        Ok(())
    }

    /// Check this file against the signed state, before `serve` starts and
    /// again whenever the state advances: every service here must be assigned
    /// to `me` ("refuses to serve a name the registry doesn't assign to
    /// it"), and every role in `also_require` and `push.allow` must be
    /// defined in `state` (or be `member`). The error names the first
    /// offender.
    pub(crate) fn check_against(&self, state: &State, me: NodeId) -> Result<()> {
        let version = state.version.0;
        let me8 = &me.hex()[..8];
        for name in self.services.keys() {
            if state.service(name).is_none() {
                bail!(
                    "host.json implements service {name}, but the signed state (version \
                     {version}) has no such service"
                );
            }
            if !state.assigns(name, me) {
                bail!(
                    "host.json implements service {name}, but the signed state (version \
                     {version}) does not assign it to this host ({me8}); refusing to serve it"
                );
            }
        }
        let defined = |r: &RoleName| r.is_member() || state.roles.contains_key(r);
        for (name, svc) in &self.services {
            if let Some(r) = svc.also_require.iter().find(|r| !defined(r)) {
                bail!(
                    "service {name}: also_require names role {r}, which the signed state \
                     (version {version}) does not define"
                );
            }
        }
        if let Some(r) = self
            .push
            .iter()
            .flat_map(|p| &p.allow)
            .find(|r| !defined(r))
        {
            bail!(
                "push.allow names role {r}, which the signed state (version {version}) does not \
                 define"
            );
        }
        Ok(())
    }

    /// What `wires serve --check` prints for a v2 file: the services it
    /// implements, their commands and `also_require`, trusted issuers, and
    /// push. Who may call is the signed state's, so it is not shown here.
    pub(crate) fn summary(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let _ = writeln!(out, "host.json ok (version {})", self.version);
        let _ = writeln!(out, "trusted issuers:");
        if self.identity.issuers.is_empty() {
            let _ = writeln!(out, "  (none: only `member` services can be called here)");
        }
        for t in &self.identity.issuers {
            let _ = writeln!(out, "  {}  audiences: {}", t.issuer, t.audiences.join(", "));
        }
        let _ = writeln!(
            out,
            "services (who may call each is in the admin-signed state):"
        );
        for (name, svc) in &self.services {
            let _ = writeln!(out, "  {name}");
            let _ = writeln!(out, "    command: {}", svc.command.join(" "));
            if let Some(cwd) = &svc.cwd {
                let _ = writeln!(out, "    cwd: {}", cwd.display());
            }
            if !svc.also_require.is_empty() {
                let roles: Vec<&str> = svc.also_require.iter().map(RoleName::as_str).collect();
                let _ = writeln!(out, "    also requires: {}", roles.join(", "));
            }
        }
        match &self.push {
            Some(p) if !p.allow.is_empty() => {
                let roles: Vec<&str> = p.allow.iter().map(RoleName::as_str).collect();
                let _ = writeln!(out, "push: to roles {}", roles.join(", "));
            }
            _ => {
                let _ = writeln!(out, "push: to no one");
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"{
      "version": 2,
      "identity": { "issuers": [ { "issuer": "https://idp.example", "audiences": ["cli"] } ] },
      "services": {
        "orders-db": {
          "command": ["sqlite3", "-readonly", "orders.db"],
          "cwd": "/srv/orders",
          "env": { "LC_ALL": "C" },
          "also_require": ["sre"]
        }
      },
      "push": { "allow": ["analyst"] },
      "audit": { "otlp": "https://collector.example:4318" }
    }"#;

    #[test]
    fn parses_the_example() {
        let c = HostConfigV2::parse(EXAMPLE).unwrap();
        let svc = &c.services[&ServiceName::new("orders-db").unwrap()];
        assert_eq!(svc.cwd.as_deref(), Some(Path::new("/srv/orders")));
        assert_eq!(svc.also_require, vec![RoleName::new("sre").unwrap()]);
        assert_eq!(c.push.unwrap().allow.len(), 1);
    }

    #[test]
    fn v1_is_refused_with_the_way_forward() {
        let v1 = r#"{"version":1,"tools":{"echo":{"command":["echo"],"allow":["member"]}}}"#;
        let e = format!("{:#}", HostConfigV2::parse(v1).unwrap_err());
        assert!(e.contains("wires service add"), "{e}");
    }

    #[test]
    fn unknown_keys_are_errors_at_every_level() {
        for bad in [
            r#"{"version":2,"services":{"a":{"command":["x"]}},"tools":{}}"#,
            r#"{"version":2,"services":{"a":{"command":["x"],"allow":["member"]}}}"#,
            r#"{"version":2,"services":{"a":{"command":["x"]}},"push":{"alow":[]}}"#,
        ] {
            assert!(HostConfigV2::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn validation_rules() {
        for bad in [
            r#"{"version":2,"services":{}}"#,
            r#"{"version":2,"services":{"a":{"command":[]}}}"#,
            r#"{"version":2,"services":{"a":{"command":["x"],"cwd":""}}}"#,
            r#"{"version":2,"services":{"a":{"command":["x"],"env":{"A=B":"1"}}}}"#,
            r#"{"version":2,"services":{"a":{"command":["x"],"env":{"WIRES_TOOL":"1"}}}}"#,
            r#"{"version":2,"services":{"Bad Name":{"command":["x"]}}}"#,
            r#"{"version":2,"services":{"a":{"command":["x"]}},"audit":{"otlp":"ftp://x"}}"#,
            r#"{"version":3,"services":{"a":{"command":["x"]}}}"#,
        ] {
            assert!(HostConfigV2::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn refuses_services_not_assigned_here() {
        use library::{NodeIdentity, Service, StateVersion};
        let root = NodeIdentity::from_seed([1u8; 32]);
        let (me, other) = (
            NodeIdentity::from_seed([2u8; 32]).node_id(),
            NodeIdentity::from_seed([3u8; 32]).node_id(),
        );
        let mut state = State::new(root.node_id());
        state.version = StateVersion(1);
        state.members.extend([me, other]);
        state.hosts.extend([me, other]);
        state.services.insert(
            ServiceName::new("orders-db").unwrap(),
            Service {
                description: String::new(),
                allow: vec![RoleName::member()],
                hosts: vec![other],
                readers: vec![],
            },
        );
        let text = r#"{"version":2,"services":{"orders-db":{"command":["x"]}}}"#;
        let c = HostConfigV2::parse(text).unwrap();
        let e = c.check_against(&state, me).unwrap_err().to_string();
        assert!(
            e.contains("orders-db") && e.contains("does not assign"),
            "{e}"
        );
        assert!(c.check_against(&state, other).is_ok());
        let check = |text: &str| {
            HostConfigV2::parse(text)
                .unwrap()
                .check_against(&state, other)
                .map_err(|e| e.to_string())
        };
        let e = check(r#"{"version":2,"services":{"ghost":{"command":["x"]}}}"#).unwrap_err();
        assert!(e.contains("no such service"), "{e}");
        let e = check(
            r#"{"version":2,"services":{"orders-db":{"command":["x"],"also_require":["sre"]}}}"#,
        )
        .unwrap_err();
        assert!(e.contains("does not define"), "{e}");
        assert!(
            check(
                r#"{"version":2,"services":{"orders-db":{"command":["x"]}},"push":{"allow":["analyst"]}}"#
            )
            .is_err()
        );
    }
}

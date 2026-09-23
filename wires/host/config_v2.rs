//! `host.json` version 2: how this host implements the services the signed
//! state assigns to it (card 27, lane **27c**).
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
//!   "audit": { "otlp": "http://collector:4318" }
//! }
//! ```
//!
//! - `version` (required, `2`). **Unknown keys are errors** at every level.
//! - `identity.issuers`: the IdPs whose ID tokens this host verifies (the
//!   same shape as v1). Local trust: the registry's roles match principals,
//!   but which IdPs to believe is the host's call.
//! - `services`: name → `command` (argv, never a shell; each call's
//!   arguments are appended), optional `cwd`, optional `env` (set on top of
//!   the scrubbed environment), and `also_require`: roles (defined in the
//!   signed state) the caller must **also** be in, on top of the registry's
//!   `allow`. It can only narrow.
//! - `push`: which registry roles may receive pushes from this host, and
//!   whether the call log keeps push bodies (card 23).
//! - `audit.otlp`: as v1 (card 26a).
//!
//! What this parser checks is the file on its own. Checks against the signed
//! state (every service here is assigned to this host; every role named is
//! defined) are [`HostConfigV2::check_against`], a 27c stub. v1
//! ([`HostConfig`](crate::host::config::HostConfig)) still parses;
//! [`AnyHostConfig::parse`] picks by `version`.

// Nothing outside tests reads this until lane 27c switches `serve` over.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use library::{NodeId, RoleName, ServiceName, State};
use serde::{Deserialize, Serialize};

use crate::host::config::{AuditConfig, HostConfig, IdentityConfig};

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

/// Either version of `host.json`, picked by its `version` key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AnyHostConfig {
    /// Card 13's shape: the host decides tools and roles.
    V1(HostConfig),
    /// Card 27's shape: the registry decides; the host implements.
    V2(HostConfigV2),
}

impl AnyHostConfig {
    /// Read and validate `host.json` at `path`, either version.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("{} is not a valid host.json", path.display()))
    }

    /// Parse either version: `version` 1 goes to the v1 parser, 2 to
    /// [`HostConfigV2::parse`]; anything else is an error.
    pub(crate) fn parse(text: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct Peek {
            version: Option<u32>,
        }
        let peek: Peek = serde_json::from_str(text)?;
        match peek.version {
            Some(1) => Ok(Self::V1(HostConfig::parse(text)?)),
            Some(HOST_CONFIG_V2) => Ok(Self::V2(HostConfigV2::parse(text)?)),
            Some(v) => bail!("version {v} is not supported (this host reads 1 and 2)"),
            None => bail!("missing `version`"),
        }
    }
}

impl HostConfigV2 {
    /// Parse and validate v2 text: the schema, then
    /// [`validate`](Self::validate).
    pub(crate) fn parse(text: &str) -> Result<Self> {
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
    /// - `audit.otlp` is an http(s) URL.
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
        let _ = (state, me);
        todo!("27c: host.json v2 against the signed state")
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
      "audit": { "otlp": "http://collector:4318" }
    }"#;

    #[test]
    fn parses_the_example() {
        let AnyHostConfig::V2(c) = AnyHostConfig::parse(EXAMPLE).unwrap() else {
            panic!("expected v2");
        };
        let svc = &c.services[&ServiceName::new("orders-db").unwrap()];
        assert_eq!(svc.cwd.as_deref(), Some(Path::new("/srv/orders")));
        assert_eq!(svc.also_require, vec![RoleName::new("sre").unwrap()]);
        assert_eq!(c.push.unwrap().allow.len(), 1);
    }

    #[test]
    fn v1_still_parses() {
        let v1 = r#"{"version":1,"tools":{"echo":{"command":["echo"],"allow":["member"]}}}"#;
        assert!(matches!(
            AnyHostConfig::parse(v1).unwrap(),
            AnyHostConfig::V1(_)
        ));
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
            assert!(AnyHostConfig::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    #[ignore = "27c"]
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
        assert!(c.check_against(&state, me).is_err());
        assert!(c.check_against(&state, other).is_ok());
    }
}

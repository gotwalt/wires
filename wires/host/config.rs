//! `host.json`: how this host implements the services the signed
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
//!     },
//!     "deploy": { "command": ["deployctl", "run"], "end_of_options": true }
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
//!   a minimal environment: only `PATH`, `LANG` and `LC_*` are inherited
//!   from `serve`; the server-derived `WIRES_*` values are set last), and
//!   `also_require`: roles (defined in the
//!   signed state) the caller must **also** be in, on top of the registry's
//!   `allow`. It can only narrow. `end_of_options: true` (default false)
//!   puts `--` between the fixed command and the caller's arguments, so a
//!   CLI that honours `--` takes none of them as an option (`-X DELETE`
//!   stays an operand). It only helps such CLIs: one that ignores `--`, or
//!   reads it as an operand, is no safer, and its fixed command must still
//!   be safe against any trailing arguments.
//! - `push`: which registry roles may receive pushes from this host, and
//!   whether the call log keeps push bodies (card 23).
//! - `audit.otlp`: an OTLP/HTTP collector the call log is also exported to
//!   (card 26a).
//!
//! What this parser checks is the file on its own. Checks against the signed
//! state (every service here is assigned to this host; every role named is
//! defined) are [`HostConfig::check_against`], which `serve` runs before
//! it binds.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use library::{Audience, Issuer, NodeId, RoleName, ServiceName, State};
use serde::{Deserialize, Serialize};

use crate::host::identity::IdpTrust;

/// The `host.json` version this module reads.
pub(crate) const HOST_CONFIG: u32 = 2;

/// A parsed, validated `host.json`. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostConfig {
    /// The format version; must be [`HOST_CONFIG`].
    pub(crate) version: u32,
    /// Which IdPs the host trusts.
    #[serde(default)]
    pub(crate) identity: IdentityConfig,
    /// How each assigned service runs here, by name.
    pub(crate) services: BTreeMap<ServiceName, ServiceImpl>,
    /// Who may receive pushes from this host. Absent: nobody.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) push: Option<Push>,
    /// Where the host's call log is exported. Absent: nowhere.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) audit: Option<AuditConfig>,
}

/// How one service runs on this host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceImpl {
    /// The fixed argv; each call's arguments are appended. Never a shell.
    pub(crate) command: Vec<String>,
    /// The working directory. Absent: `serve`'s own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cwd: Option<PathBuf>,
    /// Extra environment, set on top of a minimal one (only `PATH`, `LANG`
    /// and `LC_*` are inherited from `serve`) and before the `WIRES_*`
    /// variables (which always win). Anything else a service needs goes
    /// here.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) env: BTreeMap<String, String>,
    /// Roles (from the signed state) the caller must also be in. Empty: the
    /// registry's `allow` alone decides.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) also_require: Vec<RoleName>,
    /// Put `--` between `command` and the caller's arguments, so a CLI
    /// that honours `--` can't take them as options. Default false. It
    /// helps only CLIs that honour `--`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) end_of_options: bool,
}

impl ServiceImpl {
    /// What the child is run as for a call with the caller's arguments
    /// `caller`: the program, then its arguments (the fixed ones, `--` when
    /// [`end_of_options`](Self::end_of_options), then the caller's, element
    /// by element). `None` for an empty `command`.
    pub(crate) fn argv<'a>(&'a self, caller: &'a [String]) -> Option<(&'a str, Vec<&'a str>)> {
        let (program, fixed) = self.command.split_first()?;
        let args = fixed
            .iter()
            .map(String::as_str)
            .chain(self.end_of_options.then_some("--"))
            .chain(caller.iter().map(String::as_str))
            .collect();
        Some((program.as_str(), args))
    }
}

/// `push`: registry roles that may receive pushes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Push {
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
    #[serde(skip_serializing_if = "Option::is_none")]
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

impl HostConfig {
    /// Read and validate `host.json` at `path`.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        Self::read(path, Self::parse)
    }

    /// Read `host.json` at `path` for an app embedding the host: validated
    /// like [`load`](Self::load), except `services` may be empty, since the
    /// app's native services count too.
    pub(crate) fn load_embedded(path: &Path) -> Result<Self> {
        Self::read(path, |text| {
            let config = Self::parse_schema(text)?;
            config.validate_fields()?;
            Ok(config)
        })
    }

    /// Read `path` and make a config of it with `parse`, naming the file in
    /// either failure.
    fn read(path: &Path, parse: impl FnOnce(&str) -> Result<Self>) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        parse(&text).with_context(|| format!("{} is not a valid host.json", path.display()))
    }

    /// Parse and validate `host.json` text: the schema (and its version),
    /// then [`validate`](Self::validate).
    pub(crate) fn parse(text: &str) -> Result<Self> {
        let config = Self::parse_schema(text)?;
        config.validate()?;
        Ok(config)
    }

    /// The schema alone: the version, then the fields.
    fn parse_schema(text: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct Peek {
            version: Option<u32>,
        }
        match serde_json::from_str::<Peek>(text)?.version {
            Some(HOST_CONFIG) => {}
            Some(v) => {
                bail!("version {v} is not supported (this host reads version {HOST_CONFIG})")
            }
            None => bail!("missing `version`"),
        }
        Ok(serde_json::from_str(text)?)
    }

    /// The rules the schema can't say, on the file alone:
    ///
    /// - at least one service; no empty command; no empty `cwd`;
    /// - `env` names are non-empty, contain no `=` or NUL, and don't start
    ///   with `WIRES_` (the server-derived variables are not settable);
    /// - each issuer is listed once, non-empty, with at least one audience;
    /// - `audit.otlp` is an https URL (or http to a loopback collector).
    fn validate(&self) -> Result<()> {
        if self.services.is_empty() {
            bail!("nothing is implemented: `services` is empty");
        }
        self.validate_fields()
    }

    /// [`validate`](Self::validate) without "at least one service": what
    /// an embedding app's config must pass, since its native services count
    /// too.
    pub(crate) fn validate_fields(&self) -> Result<()> {
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

    /// Check this file against the signed state, when `serve` starts (only
    /// then: a later state that unassigns a service is enforced per call by
    /// the gate, which refuses it): every service here must be assigned
    /// to `me` ("refuses to serve a name the registry doesn't assign to
    /// it"), and every role in `also_require` and `push.allow` must be
    /// defined in `state`. The error names the first offender.
    pub(crate) fn check_against(&self, state: &State, me: NodeId) -> Result<()> {
        let version = state.version.0;
        let me8 = me.short();
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
        let defined = |r: &RoleName| state.roles.contains_key(r);
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

    /// What `wires serve --check` prints for a `host.json`: the services it
    /// implements, their commands and `also_require`, trusted issuers, and
    /// push. Who may call is the signed state's, so it is not shown here.
    pub(crate) fn summary(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let _ = writeln!(out, "host.json ok (version {})", self.version);
        let _ = writeln!(out, "trusted issuers:");
        if self.identity.issuers.is_empty() {
            let _ = writeln!(
                out,
                "  (none: no caller can be verified, so no service can be called here)"
            );
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
            if svc.end_of_options {
                let _ = writeln!(out, "    `--` before the caller's arguments");
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
        let c = HostConfig::parse(EXAMPLE).unwrap();
        let svc = &c.services[&ServiceName::new("orders-db").unwrap()];
        assert_eq!(svc.cwd.as_deref(), Some(Path::new("/srv/orders")));
        assert_eq!(svc.also_require, vec![RoleName::new("sre").unwrap()]);
        assert_eq!(c.push.unwrap().allow.len(), 1);
    }

    /// Card 28 §10: `end_of_options` puts `--` between the fixed command and
    /// the caller's arguments; off (the default), they follow directly.
    #[test]
    fn end_of_options_inserts_a_double_dash() {
        let c = HostConfig::parse(
            r#"{"version":2,"services":{
                "plain":{"command":["gh","api"]},
                "dashed":{"command":["gh","api"],"end_of_options":true},
                "bare":{"command":["tool"],"end_of_options":true}}}"#,
        )
        .unwrap();
        let svc = |n: &str| &c.services[&ServiceName::new(n).unwrap()];
        let caller: Vec<String> = ["-X", "DELETE", "repos/x"].map(String::from).to_vec();
        assert!(!svc("plain").end_of_options);
        assert_eq!(
            svc("plain").argv(&caller),
            Some(("gh", vec!["api", "-X", "DELETE", "repos/x"]))
        );
        assert_eq!(
            svc("dashed").argv(&caller),
            Some(("gh", vec!["api", "--", "-X", "DELETE", "repos/x"]))
        );
        assert_eq!(svc("bare").argv(&[]), Some(("tool", vec!["--"])));
        assert!(c.summary().contains("`--` before the caller's arguments"));
        // The default isn't written back out.
        let plain = serde_json::to_string(svc("plain")).unwrap();
        assert!(!plain.contains("end_of_options"), "{plain}");
    }

    #[test]
    fn unknown_keys_are_errors_at_every_level() {
        for bad in [
            r#"{"version":2,"services":{"a":{"command":["x"]}},"tools":{}}"#,
            r#"{"version":2,"services":{"a":{"command":["x"],"allow":["sre"]}}}"#,
            r#"{"version":2,"services":{"a":{"command":["x"]}},"push":{"alow":[]}}"#,
        ] {
            assert!(HostConfig::parse(bad).is_err(), "{bad}");
        }
    }

    /// Each rule refuses its case, and says which rule it was.
    #[test]
    fn validation_rules() {
        for (bad, why) in [
            (
                r#"{"services":{"a":{"command":["x"]}}}"#,
                "missing `version`",
            ),
            (
                r#"{"version":3,"services":{"a":{"command":["x"]}}}"#,
                "version 3 is not supported",
            ),
            (r#"{"version":2,"services":{}}"#, "`services` is empty"),
            (
                r#"{"version":2,"services":{"a":{"command":[]}}}"#,
                "service a: empty command",
            ),
            (
                r#"{"version":2,"services":{"a":{"command":["x"],"cwd":""}}}"#,
                "service a: empty cwd",
            ),
            (
                r#"{"version":2,"services":{"a":{"command":["x"],"env":{"A=B":"1"}}}}"#,
                "is not a variable name",
            ),
            (
                r#"{"version":2,"services":{"a":{"command":["x"],"env":{"WIRES_SERVICE":"1"}}}}"#,
                "env WIRES_SERVICE is set by wires itself",
            ),
            (
                r#"{"version":2,"services":{"Bad Name":{"command":["x"]}}}"#,
                "invalid service name",
            ),
            (
                r#"{"version":2,"identity":{"issuers":[{"issuer":" ","audiences":["a"]}]},"services":{"a":{"command":["x"]}}}"#,
                "an issuer is empty",
            ),
            (
                r#"{"version":2,"identity":{"issuers":[{"issuer":"https://i","audiences":["a"]},{"issuer":"https://i","audiences":["b"]}]},"services":{"a":{"command":["x"]}}}"#,
                "https://i is listed twice",
            ),
            (
                r#"{"version":2,"identity":{"issuers":[{"issuer":"https://i","audiences":[" "]}]},"services":{"a":{"command":["x"]}}}"#,
                "https://i has no audiences",
            ),
            (
                r#"{"version":2,"services":{"a":{"command":["x"]}},"audit":{"otlp":"ftp://x"}}"#,
                "audit.otlp",
            ),
        ] {
            let e = format!("{:#}", HostConfig::parse(bad).unwrap_err());
            assert!(e.contains(why), "{bad}: {e}");
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
        state.services.insert(
            ServiceName::new("orders-db").unwrap(),
            Service {
                description: String::new(),
                allow: vec![RoleName::new("staff").unwrap()],
                hosts: vec![other],
                readers: vec![],
            },
        );
        let text = r#"{"version":2,"services":{"orders-db":{"command":["x"]}}}"#;
        let c = HostConfig::parse(text).unwrap();
        let e = c.check_against(&state, me).unwrap_err().to_string();
        assert!(
            e.contains("orders-db") && e.contains("does not assign"),
            "{e}"
        );
        assert!(c.check_against(&state, other).is_ok());
        let check = |text: &str| {
            HostConfig::parse(text)
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

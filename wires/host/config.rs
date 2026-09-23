//! `host.json`: what a host exposes, and who may call it (board card 13).
//!
//! `wires serve host.json` reads everything the host decides from this one
//! file; `wires serve --check host.json` validates it and prints what it
//! means.
//!
//! ```json
//! {
//!   "version": 1,
//!   "channel": "ops",
//!   "identity": {
//!     "issuers": [
//!       { "issuer": "https://accounts.google.com",
//!         "audiences": ["476….apps.googleusercontent.com"] }
//!     ]
//!   },
//!   "roles": {
//!     "analyst": [ { "email": "*@example.com" }, { "email": "gotwalt@gmail.com" } ],
//!     "sre":     [ { "issuer": "https://acme.okta.com", "group": "sre" } ]
//!   },
//!   "tools": {
//!     "db_query": {
//!       "description": "Read-only SQL against the orders database",
//!       "command": ["sqlite3", "-safe", "-readonly", "orders.db"],
//!       "allow": ["analyst"]
//!     }
//!   }
//! }
//! ```
//!
//! - `version` (required, `1`). **Unknown keys are errors** at every level,
//!   so an older host never silently misreads a newer file.
//! - `channel`: the topic the host records every call on and reads callers'
//!   `wires login` claims from. It must be a provisioned member of it.
//!   Optional only for a host whose tools allow nothing but `member`.
//! - `identity.issuers`: the IdPs whose ID tokens this host verifies, each
//!   with the OAuth client ids (`aud`) it accepts **from that issuer**.
//! - `roles`: name → OR of matchers; a matcher is an AND of `issuer`,
//!   `email` (exact or `*@domain`), `org`, `group` (see
//!   [`Matcher`](crate::host::policy::Matcher)). `member` is built in (any
//!   roster member, no IdP) and cannot be redefined.
//! - `tools`: name → `command` (argv, never a shell; each call's arguments
//!   are appended), optional `description`, and `allow` (roles, in order).
//!   **Default deny**: a tool with no `allow` refuses every call.
//! - `push` (card 23): `allow` lists the roles whose members may receive
//!   pushes from this host (`wires push`; default deny, like a tool), and
//!   `log_body` (default `false`) records each push's body on the channel, not
//!   only its subject. Needs a `channel`.
//! - `audit` (card 26a): `otlp` is an OTLP/HTTP collector base URL (e.g.
//!   `http://collector:4318`); every entry of the host's call log is also
//!   exported there as an OTLP log record (see [`otlp`](crate::host::otlp)).
//!   Absent: no exporter. The host's own signed log is kept either way.
//!
//! The file becomes a [`RoleTable`] (the [`Policy`](crate::host::policy::Policy)),
//! the exposed command map, and the [`IdpTrust`] the host verifies claims
//! under.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result, bail};
use library::{Audience, Issuer, ToolName};
use serde::{Deserialize, Serialize};

use crate::channel::idp_view::IdpTrust;
use crate::host::policy::{MEMBER, Matcher, RoleName, RoleTable};

/// The only `host.json` version this host reads.
pub(crate) const HOST_CONFIG_VERSION: u32 = 1;

/// A parsed, validated `host.json`. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostConfig {
    /// The format version; must be [`HOST_CONFIG_VERSION`].
    pub(crate) version: u32,
    /// The channel (topic name) calls are recorded on and identities read
    /// from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) channel: Option<String>,
    /// Which IdPs the host trusts.
    #[serde(default)]
    pub(crate) identity: IdentityConfig,
    /// The roles, by name.
    #[serde(default)]
    pub(crate) roles: BTreeMap<RoleName, Vec<Matcher>>,
    /// The exposed tools, by name.
    pub(crate) tools: BTreeMap<ToolName, ToolConfig>,
    /// Who may receive pushes from this host (card 23). Absent: nobody.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) push: Option<PushConfig>,
    /// Where the host's call log is exported (card 26a). Absent: nowhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) audit: Option<AuditConfig>,
}

/// `audit`: optional sinks for the host's call log, beyond the log itself.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditConfig {
    /// An OTLP/HTTP collector base URL (`/v1/logs` is appended).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) otlp: Option<String>,
}

/// `push`: which roles may receive pushes from this host, and what its call
/// log records about them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PushConfig {
    /// The roles whose members may receive pushes, tried in order (like a
    /// tool's `allow`). Empty: nobody.
    #[serde(default)]
    pub(crate) allow: Vec<RoleName>,
    /// Record each push's body on the channel, not only its subject.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) log_body: bool,
}

/// `identity`: the IdPs the host verifies ID tokens from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityConfig {
    /// The trusted issuers.
    #[serde(default)]
    pub(crate) issuers: Vec<TrustedIssuer>,
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

/// One exposed tool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ToolConfig {
    /// What the tool does, for callers (and their agents).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    /// The fixed argv; each call's arguments are appended. Never a shell.
    pub(crate) command: Vec<String>,
    /// The roles that may run it, tried in order. Empty: nobody.
    #[serde(default)]
    pub(crate) allow: Vec<RoleName>,
}

impl HostConfig {
    /// Read and validate `host.json` at `path`.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("{} is not a valid host.json", path.display()))
    }

    /// Parse and validate `host.json` text: the schema (unknown keys and a
    /// missing `version` are errors), then [`validate`](Self::validate).
    pub(crate) fn parse(text: &str) -> Result<Self> {
        let config: Self = serde_json::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    /// The rules the schema can't say:
    ///
    /// - `version` is [`HOST_CONFIG_VERSION`]; at least one tool; no empty
    ///   command;
    /// - `member` is not redefined; every role has matchers, and no matcher
    ///   is empty (it would match everyone);
    /// - every `allow` names a defined role or `member`;
    /// - identity roles need `identity.issuers` and a `channel`; a matcher's
    ///   `issuer` must be one of `identity.issuers`;
    /// - each issuer is listed once, with at least one audience;
    /// - `push` needs a `channel` (pushes are recorded there, and the host's
    ///   resident node is what receivers fetch from), and its `allow` names
    ///   defined roles or `member`.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.version != HOST_CONFIG_VERSION {
            bail!(
                "version {} is not supported (this host reads version {HOST_CONFIG_VERSION})",
                self.version
            );
        }
        if let Some(channel) = &self.channel
            && channel.trim().is_empty()
        {
            bail!("`channel` is empty");
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
                bail!(
                    "identity.issuers: {iss} has no audiences (the OAuth client ids its tokens \
                     are minted for)"
                );
            }
            issuers.push(iss);
        }
        if !issuers.is_empty() && self.channel.is_none() {
            bail!("`identity` needs a `channel`: callers publish their logins there");
        }
        for (role, matchers) in &self.roles {
            if role.is_member() {
                bail!("role `{MEMBER}` is built in (any roster member); it cannot be redefined");
            }
            if matchers.is_empty() {
                bail!("role {role} has no matchers (a role is an OR of matchers)");
            }
            for (i, m) in matchers.iter().enumerate() {
                if m.is_empty() {
                    bail!(
                        "role {role}: matcher {} is empty (it would match everyone)",
                        i + 1
                    );
                }
                for (key, value) in [("issuer", &m.issuer), ("org", &m.org), ("group", &m.group)] {
                    if value.as_ref().is_some_and(|v| v.trim().is_empty()) {
                        bail!("role {role}: matcher {} has an empty {key}", i + 1);
                    }
                }
                if let Some(iss) = &m.issuer
                    && !issuers.contains(&iss.as_str())
                {
                    bail!("role {role}: issuer {iss} is not in identity.issuers");
                }
            }
            if issuers.is_empty() {
                bail!(
                    "role {role} matches verified identities, but identity.issuers is empty: \
                     list the IdPs this host trusts"
                );
            }
        }
        if self.tools.is_empty() {
            bail!("nothing is exposed: `tools` is empty");
        }
        for (tool, t) in &self.tools {
            if t.command.is_empty() {
                bail!("tool {tool}: empty command");
            }
            for role in &t.allow {
                if !self.is_role(role) {
                    bail!(
                        "tool {tool} allows unknown role {role} (roles: {})",
                        self.known_roles()
                    );
                }
            }
        }
        if let Some(push) = &self.push {
            if self.channel.is_none() {
                bail!(
                    "`push` needs a `channel`: pushes are recorded there, and receivers fetch \
                     from the host's node on it"
                );
            }
            for role in &push.allow {
                if !self.is_role(role) {
                    bail!(
                        "push allows unknown role {role} (roles: {})",
                        self.known_roles()
                    );
                }
            }
        }
        if let Some(url) = self.otlp_endpoint() {
            crate::host::otlp::logs_url(url).context("audit.otlp")?;
        }
        Ok(())
    }

    /// The OTLP/HTTP collector the call log is exported to, if any.
    pub(crate) fn otlp_endpoint(&self) -> Option<&str> {
        self.audit.as_ref().and_then(|a| a.otlp.as_deref())
    }

    /// Whether `role` is defined here or is the built-in [`MEMBER`].
    fn is_role(&self, role: &RoleName) -> bool {
        role.is_member() || self.roles.contains_key(role)
    }

    /// `analyst, sre, member`: the roles an `allow` may name, for errors.
    fn known_roles(&self) -> String {
        let mut known: Vec<&str> = self.roles.keys().map(RoleName::as_str).collect();
        known.push(MEMBER);
        known.join(", ")
    }

    /// Whether the host records push bodies on its channel (`push.log_body`).
    pub(crate) fn logs_push_bodies(&self) -> bool {
        self.push.as_ref().is_some_and(|p| p.log_body)
    }

    /// Each tool's fixed argv, for [`ServeConfig::tools`](crate::host::transport::ServeConfig::tools).
    pub(crate) fn commands(&self) -> BTreeMap<ToolName, Vec<String>> {
        self.tools
            .iter()
            .map(|(name, t)| (name.clone(), t.command.clone()))
            .collect()
    }

    /// Each tool's description (empty when `host.json` gives none) — what
    /// the host announces on its channel (card 15).
    pub(crate) fn descriptions(&self) -> BTreeMap<ToolName, String> {
        self.tools
            .iter()
            .map(|(name, t)| (name.clone(), t.description.clone().unwrap_or_default()))
            .collect()
    }

    /// The v1 policy this file describes.
    pub(crate) fn policy(&self) -> RoleTable {
        RoleTable::new(
            self.roles.clone(),
            self.tools
                .iter()
                .map(|(name, t)| (name.clone(), t.allow.clone()))
                .collect(),
        )
        .with_push(
            self.push
                .as_ref()
                .map(|p| p.allow.clone())
                .unwrap_or_default(),
        )
    }

    /// The IdPs and per-issuer audiences the host verifies claims under.
    pub(crate) fn trust(&self) -> IdpTrust {
        IdpTrust::per_issuer(
            self.identity
                .issuers
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

    /// What `wires serve --check` prints: the channel, the trusted issuers,
    /// the roles, and which roles may run which tool.
    pub(crate) fn summary(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "host.json ok (version {})", self.version);
        let _ = writeln!(
            out,
            "channel: {}",
            self.channel
                .as_deref()
                .unwrap_or("(none: calls are not recorded, identities not read)")
        );
        let _ = writeln!(out, "trusted issuers:");
        if self.identity.issuers.is_empty() {
            let _ = writeln!(out, "  (none)");
        }
        for t in &self.identity.issuers {
            let _ = writeln!(out, "  {}  audiences: {}", t.issuer, t.audiences.join(", "));
        }
        let _ = writeln!(out, "roles:");
        for (role, matchers) in &self.roles {
            let ms: Vec<String> = matchers.iter().map(Matcher::to_string).collect();
            let _ = writeln!(out, "  {role}  {}", ms.join(" | "));
        }
        let _ = writeln!(
            out,
            "  {MEMBER}  (built in) any roster member, no identity needed"
        );
        let _ = writeln!(out, "tools:");
        for (tool, t) in &self.tools {
            let who = if t.allow.is_empty() {
                "NO ONE (empty allow)".to_string()
            } else {
                t.allow
                    .iter()
                    .map(RoleName::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let _ = writeln!(out, "  {tool}  may run: {who}");
            let _ = writeln!(out, "    command: {}", t.command.join(" "));
            if let Some(d) = &t.description {
                let _ = writeln!(out, "    {d}");
            }
        }
        let receivers = match &self.push {
            Some(p) if !p.allow.is_empty() => p
                .allow
                .iter()
                .map(RoleName::as_str)
                .collect::<Vec<_>>()
                .join(", "),
            _ => "NO ONE".to_string(),
        };
        let bodies = if self.logs_push_bodies() {
            "subject and body logged"
        } else {
            "subject logged, body not"
        };
        let _ = writeln!(out, "push: may receive: {receivers} ({bodies})");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::policy::{CallContext, Policy};
    use library::{Argv, NodeIdentity, Principal};
    use proptest::prelude::*;

    /// The card's example, verbatim in shape.
    const CARD: &str = r#"{
      "version": 1,
      "channel": "ops",
      "identity": {
        "issuers": [
          { "issuer": "https://accounts.google.com",
            "audiences": ["476.apps.googleusercontent.com"] },
          { "issuer": "https://acme.okta.com", "audiences": ["wires"] }
        ]
      },
      "roles": {
        "analyst": [ { "email": "*@example.com" }, { "email": "gotwalt@gmail.com" } ],
        "sre":     [ { "issuer": "https://acme.okta.com", "group": "sre" } ]
      },
      "tools": {
        "db_query": {
          "description": "Read-only SQL against the orders database",
          "command": ["sqlite3", "-safe", "-readonly", "orders.db"],
          "allow": ["analyst"]
        },
        "status": { "command": ["uptime"], "allow": ["member"] },
        "locked": { "command": ["true"] }
      }
    }"#;

    fn edit(f: impl FnOnce(&mut serde_json::Value)) -> String {
        let mut v: serde_json::Value = serde_json::from_str(CARD).unwrap();
        f(&mut v);
        v.to_string()
    }

    fn err(text: &str) -> String {
        format!("{:#}", HostConfig::parse(text).unwrap_err())
    }

    #[test]
    fn the_card_example_parses_into_commands_policy_and_trust() {
        let c = HostConfig::parse(CARD).unwrap();
        assert_eq!(c.channel.as_deref(), Some("ops"));
        let db = ToolName::new("db_query").unwrap();
        assert_eq!(
            c.commands()[&db],
            ["sqlite3", "-safe", "-readonly", "orders.db"]
        );
        let trust = c.trust();
        assert_eq!(
            trust.issuers,
            vec![
                Issuer::new("https://accounts.google.com"),
                Issuer::new("https://acme.okta.com")
            ]
        );
        assert_eq!(
            trust.audiences_for(&Issuer::new("https://acme.okta.com")),
            [Audience::new("wires")]
        );
        assert!(
            trust
                .audiences_for(&Issuer::new("https://elsewhere"))
                .is_empty()
        );

        let alice = Principal {
            issuer: "https://accounts.google.com".into(),
            subject: "1".into(),
            email: Some("alice@example.com".into()),
            org: None,
            groups: vec![],
            not_after: 0,
            claims: Default::default(),
        };
        let argv = Argv::default();
        let d = c.policy().decide(&CallContext {
            principal: Some(&alice),
            caller: NodeIdentity::from_seed([1u8; 32]).node_id(),
            roster_version: None,
            tool: &db,
            argv: &argv,
        });
        assert!(d.allow, "{d:?}");
        assert_eq!(d.role.unwrap().as_str(), "analyst");
    }

    #[test]
    fn schema_errors() {
        // Unknown keys, at every level.
        for (text, why) in [
            (
                edit(|v| v["colour"] = "red".into()),
                "unknown field `colour`",
            ),
            (
                edit(|v| v["identity"]["trust"] = true.into()),
                "unknown field `trust`",
            ),
            (
                edit(|v| v["identity"]["issuers"][0]["jwks"] = "x".into()),
                "unknown field `jwks`",
            ),
            (
                edit(|v| v["roles"]["analyst"][0]["domain"] = "x".into()),
                "unknown field `domain`",
            ),
            (
                edit(|v| v["tools"]["db_query"]["shell"] = true.into()),
                "unknown field `shell`",
            ),
            (
                edit(|v| {
                    v.as_object_mut().unwrap().remove("version");
                }),
                "missing field `version`",
            ),
            (
                edit(|v| {
                    v.as_object_mut().unwrap().remove("tools");
                }),
                "missing field `tools`",
            ),
            (
                edit(|v| v["tools"]["Bad Name"] = v["tools"]["status"].clone()),
                "tool name",
            ),
            (
                edit(|v| v["roles"]["bad role"] = v["roles"]["analyst"].clone()),
                "role name",
            ),
            (
                edit(|v| v["roles"]["analyst"][0]["email"] = "*.example.com".into()),
                "email pattern",
            ),
            (
                edit(|v| v["push"] = serde_json::json!({"allow": [], "ttl": "1h"})),
                "unknown field `ttl`",
            ),
        ] {
            let e = err(&text);
            assert!(e.contains(why), "{why}: {e}");
        }
    }

    #[test]
    fn validation_errors() {
        use serde_json::json;
        for (text, why) in [
            (
                edit(|v| v["version"] = 2.into()),
                "version 2 is not supported",
            ),
            (edit(|v| v["tools"] = json!({})), "nothing is exposed"),
            (
                edit(|v| v["tools"]["status"]["command"] = json!([])),
                "status: empty command",
            ),
            (
                edit(|v| v["tools"]["status"]["allow"] = json!(["admins"])),
                "allows unknown role admins (roles: analyst, sre, member)",
            ),
            (
                edit(|v| v["roles"]["member"] = json!([{"email": "a@b.c"}])),
                "`member` is built in",
            ),
            (
                edit(|v| v["roles"]["sre"] = json!([])),
                "role sre has no matchers",
            ),
            (
                edit(|v| v["roles"]["sre"] = json!([{}])),
                "matcher 1 is empty",
            ),
            (
                edit(|v| v["roles"]["sre"] = json!([{"group": " "}])),
                "empty group",
            ),
            (
                edit(|v| v["roles"]["sre"][0]["issuer"] = "https://other".into()),
                "issuer https://other is not in identity.issuers",
            ),
            (
                edit(|v| v["identity"]["issuers"] = json!([])),
                "identity.issuers is empty",
            ),
            (
                edit(|v| v["identity"]["issuers"][1]["audiences"] = json!([])),
                "https://acme.okta.com has no audiences",
            ),
            (
                edit(|v| {
                    let dup = v["identity"]["issuers"][0].clone();
                    v["identity"]["issuers"].as_array_mut().unwrap().push(dup);
                }),
                "listed twice",
            ),
            (
                edit(|v| {
                    v.as_object_mut().unwrap().remove("channel");
                }),
                "`identity` needs a `channel`",
            ),
            (edit(|v| v["channel"] = " ".into()), "`channel` is empty"),
            (
                edit(|v| v["push"] = json!({"allow": ["admins"]})),
                "push allows unknown role admins (roles: analyst, sre, member)",
            ),
            (
                edit(|v| {
                    v.as_object_mut().unwrap().remove("channel");
                    v.as_object_mut().unwrap().remove("identity");
                    v.as_object_mut().unwrap().remove("roles");
                    v["tools"] = json!({"status": {"command": ["uptime"], "allow": ["member"]}});
                    v["push"] = json!({"allow": ["member"]});
                }),
                "`push` needs a `channel`",
            ),
        ] {
            let e = err(&text);
            assert!(e.contains(why), "{why}: {e}");
        }
    }

    #[test]
    fn a_member_only_host_needs_no_channel_or_identity() {
        let c = HostConfig::parse(
            r#"{"version":1,"tools":{"gh":{"command":["gh"],"allow":["member"]}}}"#,
        )
        .unwrap();
        assert_eq!(c.channel, None);
        assert!(c.trust().issuers.is_empty());
    }

    #[test]
    fn the_summary_says_who_may_run_what() {
        let s = HostConfig::parse(CARD).unwrap().summary();
        for want in [
            "host.json ok (version 1)",
            "channel: ops",
            "  https://accounts.google.com  audiences: 476.apps.googleusercontent.com",
            "  analyst  email=*@example.com | email=gotwalt@gmail.com",
            "  sre  issuer=https://acme.okta.com,group=sre",
            "  member  (built in)",
            "  db_query  may run: analyst",
            "    command: sqlite3 -safe -readonly orders.db",
            "  locked  may run: NO ONE (empty allow)",
            "  status  may run: member",
            "push: may receive: NO ONE (subject logged, body not)",
        ] {
            assert!(s.contains(want), "missing {want:?} in\n{s}");
        }
        let s = HostConfig::parse(&edit(|v| {
            v["push"] = serde_json::json!({"allow": ["analyst", "member"], "log_body": true})
        }))
        .unwrap()
        .summary();
        assert!(
            s.contains("push: may receive: analyst, member (subject and body logged)"),
            "{s}"
        );
    }

    /// `audit.otlp` is optional, must be an http(s) URL, and admits no other
    /// key (card 26a).
    #[test]
    fn the_audit_section_names_an_otlp_endpoint() {
        assert_eq!(HostConfig::parse(CARD).unwrap().otlp_endpoint(), None);
        let with = HostConfig::parse(&edit(|v| {
            v["audit"] = serde_json::json!({"otlp": "http://collector:4318"})
        }))
        .unwrap();
        assert_eq!(with.otlp_endpoint(), Some("http://collector:4318"));
        let e = err(&edit(|v| {
            v["audit"] = serde_json::json!({"otlp": "ftp://x"})
        }));
        assert!(e.contains("audit.otlp"), "{e}");
        let e = err(&edit(|v| {
            v["audit"] = serde_json::json!({"readers": ["security"]})
        }));
        assert!(e.contains("unknown field `readers`"), "{e}");
    }

    /// `push` parses, defaults to nobody and no bodies, and becomes the
    /// policy's push decision.
    #[test]
    fn the_push_section_decides_who_may_receive() {
        let none = HostConfig::parse(CARD).unwrap();
        assert_eq!(none.push, None);
        assert!(!none.logs_push_bodies());
        let empty = HostConfig::parse(&edit(|v| v["push"] = serde_json::json!({}))).unwrap();
        assert_eq!(empty.push, Some(PushConfig::default()));
        let c = HostConfig::parse(&edit(|v| {
            v["push"] = serde_json::json!({"allow": ["analyst"], "log_body": true})
        }))
        .unwrap();
        assert!(c.logs_push_bodies());
        let node = NodeIdentity::from_seed([1u8; 32]).node_id();
        let who = |email: &str| Principal {
            issuer: "https://accounts.google.com".into(),
            subject: "1".into(),
            email: Some(email.into()),
            org: None,
            groups: vec![],
            not_after: 0,
            claims: Default::default(),
        };
        for (config, principal, allowed) in [
            (&c, Some(who("alice@example.com")), true),
            (&c, Some(who("bob@other.org")), false),
            (&c, None, false),
            (&none, Some(who("alice@example.com")), false),
            (&empty, Some(who("alice@example.com")), false),
        ] {
            let d = config.policy().decide_push(principal.as_ref(), node);
            assert_eq!(d.allow, allowed, "{principal:?}: {d:?}");
        }
        let d = c
            .policy()
            .decide_push(Some(&who("alice@example.com")), node);
        assert_eq!(d.role.unwrap().as_str(), "analyst");
    }

    proptest! {
        /// Any valid config survives a serialize/parse round trip unchanged,
        /// and an `allow` that is empty never admits anyone.
        #[test]
        fn configs_round_trip_and_empty_allow_denies(
            tools in proptest::collection::btree_map(
                "[a-z][a-z0-9_]{0,6}",
                (proptest::collection::vec("[a-z]{1,6}", 1..4), any::<bool>()),
                1..5,
            )
        ) {
            let config = HostConfig {
                version: 1,
                channel: Some("ops".into()),
                identity: IdentityConfig {
                    issuers: vec![TrustedIssuer {
                        issuer: "https://idp.example".into(),
                        audiences: vec!["aud".into()],
                    }],
                },
                roles: BTreeMap::from([(
                    RoleName::new("analyst").unwrap(),
                    vec![serde_json::from_str(r#"{"email":"*@example.com"}"#).unwrap()],
                )]),
                tools: tools
                    .iter()
                    .map(|(name, (command, open))| {
                        (
                            ToolName::new(name.clone()).unwrap(),
                            ToolConfig {
                                description: None,
                                command: command.clone(),
                                allow: if *open { vec![RoleName::member()] } else { vec![] },
                            },
                        )
                    })
                    .collect(),
                push: None,
                audit: None,
            };
            config.validate().unwrap();
            let text = serde_json::to_string_pretty(&config).unwrap();
            prop_assert_eq!(&HostConfig::parse(&text).unwrap(), &config);
            let open: Vec<ToolName> = config
                .policy()
                .allowed_tools(None, NodeIdentity::from_seed([2u8; 32]).node_id());
            let want: Vec<ToolName> = tools
                .iter()
                .filter(|(_, (_, open))| *open)
                .map(|(n, _)| ToolName::new(n.clone()).unwrap())
                .collect();
            prop_assert_eq!(open, want);
        }
    }
}

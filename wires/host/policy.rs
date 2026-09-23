//! The host's one decision: **may this caller run this tool?** (board card 13)
//!
//! Every call that passes the credential checks in
//! [`transport::authorize`](crate::host::transport) — fabric inclusion, the
//! roster head — is put to a [`Policy`] as a [`CallContext`], and the
//! [`Decision`] it returns is final: a refusal is sent to the caller and
//! recorded on the channel with its reason; an admission names the role that
//! admitted the caller in [`AuditRecord::Started`](library::AuditRecord).
//!
//! # v1: a role table
//!
//! [`RoleTable`] is the policy `host.json` describes (see
//! [`config`](crate::host::config)):
//!
//! - a **role** is an OR of [`Matcher`]s; a matcher is an AND of its keys
//!   (`issuer`, `email`, `org`, `group`), tested against the caller's
//!   verified IdP [`Principal`];
//! - each tool's `allow` lists the roles that may run it, tried in order; the
//!   first that admits the caller is the [`Decision::role`];
//! - the built-in role [`MEMBER`] admits any roster member, verified identity
//!   or not. It is never implied: a tool must list it;
//! - **default deny**: a tool with an empty `allow` refuses every call.
//!
//! # Later: other engines
//!
//! The table is one implementation of [`Policy`], not the only one. An org
//! that needs rules the table can't say (CEL or Rego over the claims, a
//! webhook to its own authorizer) gets a second implementation behind a
//! `"policy": {"engine": …}` block in `host.json`; nothing in the transport
//! changes. That is why [`CallContext`] carries the whole call (caller node,
//! roster version, tool, argv) and why [`Principal::claims`] keeps every
//! verified claim, not just the email.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use anyhow::{Result, bail};
use library::{Argv, NodeId, Principal, ToolName};
use serde::{Deserialize, Serialize};

use crate::channel::idp_view::principal_name;

/// The built-in role: any roster member, with no IdP requirement.
pub(crate) const MEMBER: &str = "member";

/// The longest role name accepted.
const MAX_ROLE_NAME: usize = 64;

/// A role's name in `host.json`: 1–64 of `[A-Za-z0-9_.-]`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(crate) struct RoleName(String);

impl RoleName {
    /// Validate and wrap a role name.
    pub(crate) fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        if name.is_empty()
            || name.len() > MAX_ROLE_NAME
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        {
            bail!("role name {name:?}: expected 1-{MAX_ROLE_NAME} of [A-Za-z0-9_.-]");
        }
        Ok(Self(name))
    }

    /// The built-in [`MEMBER`] role.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn member() -> Self {
        Self(MEMBER.to_string())
    }

    /// Whether this is the built-in [`MEMBER`] role.
    pub(crate) fn is_member(&self) -> bool {
        self.0 == MEMBER
    }

    /// The name as a string slice.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RoleName {
    type Error = anyhow::Error;

    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}

impl From<RoleName> for String {
    fn from(r: RoleName) -> String {
        r.0
    }
}

impl fmt::Display for RoleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How an `email` key matches the verified email.
///
/// Emails and domains compare ASCII case-insensitively. `*@example.com`
/// matches `alice@example.com` but neither `alice@sub.example.com` nor
/// `alice@example.com.evil.net`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(crate) enum EmailPattern {
    /// One address (stored lowercased).
    Exact(String),
    /// `*@domain`: any address at exactly this domain (stored lowercased).
    Domain(String),
}

impl EmailPattern {
    /// Whether `email` matches.
    pub(crate) fn matches(&self, email: &str) -> bool {
        match self {
            EmailPattern::Exact(want) => email.eq_ignore_ascii_case(want),
            EmailPattern::Domain(domain) => email
                .rsplit_once('@')
                .is_some_and(|(local, d)| !local.is_empty() && d.eq_ignore_ascii_case(domain)),
        }
    }
}

impl FromStr for EmailPattern {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if let Some(domain) = s.strip_prefix("*@") {
            if domain.is_empty() || domain.contains(['*', '@']) {
                bail!("email pattern {s:?}: the only glob is `*@domain`");
            }
            return Ok(EmailPattern::Domain(domain.to_ascii_lowercase()));
        }
        if s.contains('*') {
            bail!("email pattern {s:?}: the only glob is `*@domain`");
        }
        match s.split_once('@') {
            Some((local, domain))
                if !local.is_empty() && !domain.is_empty() && !domain.contains('@') =>
            {
                Ok(EmailPattern::Exact(s.to_ascii_lowercase()))
            }
            _ => bail!("email pattern {s:?} is neither an address nor `*@domain`"),
        }
    }
}

impl TryFrom<String> for EmailPattern {
    type Error = anyhow::Error;

    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl From<EmailPattern> for String {
    fn from(p: EmailPattern) -> String {
        p.to_string()
    }
}

impl fmt::Display for EmailPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmailPattern::Exact(e) => f.write_str(e),
            EmailPattern::Domain(d) => write!(f, "*@{d}"),
        }
    }
}

/// One entry of a role: every key present must hold (AND).
///
/// | key      | matches                                                   |
/// |----------|-----------------------------------------------------------|
/// | `issuer` | [`Principal::issuer`], exactly                            |
/// | `email`  | the verified email: exact, or `*@domain` (the only glob)  |
/// | `org`    | [`Principal::org`] (Google's `hd`), ASCII case-insensitive|
/// | `group`  | one of [`Principal::groups`], exactly                     |
///
/// A matcher without `issuer` accepts every issuer the host trusts
/// (`identity.issuers`). A matcher never matches a caller without a verified
/// principal.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Matcher {
    /// `issuer`: the IdP, exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) issuer: Option<String>,
    /// `email`: the verified email.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) email: Option<EmailPattern>,
    /// `org`: the org / hosted domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) org: Option<String>,
    /// `group`: a group the IdP says the principal is in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) group: Option<String>,
}

impl Matcher {
    /// Whether no key is set (such a matcher would match everyone, so
    /// `host.json` refuses it).
    pub(crate) fn is_empty(&self) -> bool {
        self.issuer.is_none() && self.email.is_none() && self.org.is_none() && self.group.is_none()
    }

    /// Whether `p` satisfies every key.
    pub(crate) fn matches(&self, p: &Principal) -> bool {
        self.issuer.as_ref().is_none_or(|iss| p.issuer == *iss)
            && self
                .email
                .as_ref()
                .is_none_or(|pat| p.email.as_deref().is_some_and(|e| pat.matches(e)))
            && self.org.as_ref().is_none_or(|org| {
                p.org
                    .as_deref()
                    .is_some_and(|have| have.eq_ignore_ascii_case(org))
            })
            && self
                .group
                .as_ref()
                .is_none_or(|g| p.groups.iter().any(|have| have == g))
    }
}

impl fmt::Display for Matcher {
    /// `issuer=…,email=…,org=…,group=…` (the keys present, in that order).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if let Some(v) = &self.issuer {
            parts.push(format!("issuer={v}"));
        }
        if let Some(v) = &self.email {
            parts.push(format!("email={v}"));
        }
        if let Some(v) = &self.org {
            parts.push(format!("org={v}"));
        }
        if let Some(v) = &self.group {
            parts.push(format!("group={v}"));
        }
        f.write_str(&parts.join(","))
    }
}

/// Everything known about one call when the policy decides it.
///
/// Built by the transport after the credential checks, so `caller` is already
/// a roster member (when a head is enforced, of `roster_version`).
///
/// v1's [`RoleTable`] reads only `principal` and `tool`; the rest is here for
/// the engines that come later (see the module docs), hence the allow.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) struct CallContext<'a> {
    /// The caller's fresh, verified IdP principal — every claim kept — or
    /// `None` when it has not logged in (or its login expired).
    pub(crate) principal: Option<&'a Principal>,
    /// The iroh-authenticated caller.
    pub(crate) caller: NodeId,
    /// The roster version that admitted the caller, when a head is enforced.
    pub(crate) roster_version: Option<u64>,
    /// The tool the caller invoked.
    pub(crate) tool: &'a ToolName,
    /// The caller's arguments (appended to the tool's fixed command).
    pub(crate) argv: &'a Argv,
}

/// What a [`Policy`] concluded about one call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Decision {
    /// Whether the call may run.
    pub(crate) allow: bool,
    /// Why, in words: on a refusal this is what the caller is told and what
    /// the channel records.
    pub(crate) reason: String,
    /// The role that admitted the caller (`None` on a refusal).
    pub(crate) role: Option<RoleName>,
}

impl Decision {
    /// An admission by `role`.
    pub(crate) fn allow(role: RoleName, reason: impl Into<String>) -> Self {
        Self {
            allow: true,
            reason: reason.into(),
            role: Some(role),
        }
    }

    /// A refusal.
    pub(crate) fn deny(reason: impl Into<String>) -> Self {
        Self {
            allow: false,
            reason: reason.into(),
            role: None,
        }
    }
}

/// A host's authorization rule set. See the module docs.
///
/// Implementations are pure: no I/O, no clock (the principal handed in is
/// already known fresh), so a decision can be recomputed and explained.
pub(crate) trait Policy: Send + Sync {
    /// Decide one call.
    fn decide(&self, ctx: &CallContext<'_>) -> Decision;

    /// The tools `caller` (with `principal`, if it has logged in) may run at
    /// all — what a host shows each member (card 15's directory).
    ///
    /// A tool is listed when some call to it with no arguments would be
    /// allowed; a policy that looks at arguments may still refuse a
    /// particular call.
    fn allowed_tools(&self, principal: Option<&Principal>, caller: NodeId) -> Vec<ToolName>;

    /// The tools **every** roster member may run, whoever it is and whether
    /// or not it has logged in. A host announces these in the clear (to the
    /// channel, which is already encrypted to exactly the roster) and seals
    /// everything else per member — so a policy that cannot promise this for
    /// a tool must leave it out. The default promises nothing.
    fn member_tools(&self) -> Vec<ToolName> {
        Vec::new()
    }
}

/// The v1 policy: roles of matchers, and per tool the roles allowed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RoleTable {
    /// Each defined role's matchers (never [`MEMBER`], never empty).
    roles: BTreeMap<RoleName, Vec<Matcher>>,
    /// Each exposed tool's `allow` list, in `host.json` order.
    allow: BTreeMap<ToolName, Vec<RoleName>>,
}

impl RoleTable {
    /// A table over already-validated roles and allow lists (see
    /// [`HostConfig::parse`](crate::host::config::HostConfig::parse), which
    /// guarantees every allowed role is defined or [`MEMBER`]).
    pub(crate) fn new(
        roles: BTreeMap<RoleName, Vec<Matcher>>,
        allow: BTreeMap<ToolName, Vec<RoleName>>,
    ) -> Self {
        Self { roles, allow }
    }

    /// Whether `role` admits a caller with `principal`.
    fn admits(&self, role: &RoleName, principal: Option<&Principal>) -> bool {
        if role.is_member() {
            return true;
        }
        principal.is_some_and(|p| {
            self.roles
                .get(role)
                .is_some_and(|ms| ms.iter().any(|m| m.matches(p)))
        })
    }

    /// `analyst (email=*@example.com | email=bob@example.com)`: the role and
    /// its matchers, for reasons.
    fn describe(&self, role: &RoleName) -> String {
        if role.is_member() {
            return format!("{role} (any roster member)");
        }
        let matchers: Vec<String> = self
            .roles
            .get(role)
            .map(|ms| ms.iter().map(Matcher::to_string).collect())
            .unwrap_or_default();
        format!("{role} ({})", matchers.join(" | "))
    }
}

impl Policy for RoleTable {
    fn decide(&self, ctx: &CallContext<'_>) -> Decision {
        let tool = ctx.tool;
        let Some(allowed) = self.allow.get(tool) else {
            return Decision::deny(format!("unknown tool: {tool}"));
        };
        if allowed.is_empty() {
            return Decision::deny(format!(
                "tool {tool} allows no role (its host.json `allow` is empty)"
            ));
        }
        if let Some(role) = allowed.iter().find(|r| self.admits(r, ctx.principal)) {
            let who = ctx.principal.map_or_else(
                || format!("node {}", short(ctx.caller)),
                |p| principal_name(p),
            );
            return Decision::allow(
                role.clone(),
                format!("{who} is in role {}", self.describe(role)),
            );
        }
        let roles: Vec<String> = allowed.iter().map(|r| self.describe(r)).collect();
        let roles = roles.join("; ");
        Decision::deny(match ctx.principal {
            Some(p) => format!(
                "identity {} (from {}) is in no role allowed to run {tool}: {roles}",
                principal_name(p),
                p.issuer
            ),
            None => format!("{tool} needs a verified identity in role {roles}"),
        })
    }

    fn allowed_tools(&self, principal: Option<&Principal>, caller: NodeId) -> Vec<ToolName> {
        let argv = Argv::default();
        self.allow
            .keys()
            .filter(|tool| {
                self.decide(&CallContext {
                    principal,
                    caller,
                    roster_version: None,
                    tool,
                    argv: &argv,
                })
                .allow
            })
            .cloned()
            .collect()
    }

    /// Exactly the tools whose `allow` lists [`MEMBER`]: the table admits
    /// `member` for anyone, with or without a principal.
    fn member_tools(&self) -> Vec<ToolName> {
        self.allow
            .iter()
            .filter(|(_, roles)| roles.iter().any(RoleName::is_member))
            .map(|(tool, _)| tool.clone())
            .collect()
    }
}

/// Test-only: admits every call as [`MEMBER`] — the inclusion-only
/// responder, for tests of the credential checks and transport underneath
/// the policy. Unknown tools then reach the transport's own "unknown tool"
/// refusal.
#[cfg(test)]
pub(crate) struct AnyMember;

#[cfg(test)]
impl Policy for AnyMember {
    fn decide(&self, _: &CallContext<'_>) -> Decision {
        Decision::allow(RoleName::member(), "test policy: any member")
    }

    fn allowed_tools(&self, _: Option<&Principal>, _: NodeId) -> Vec<ToolName> {
        Vec::new()
    }
}

/// A node's first 8 hex characters, like the tail's sender column.
fn short(node: NodeId) -> String {
    let hex = node.hex();
    hex[..8.min(hex.len())].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::NodeIdentity;
    use proptest::prelude::*;

    const GOOGLE: &str = "https://accounts.google.com";
    const OKTA: &str = "https://acme.okta.com";

    fn principal(issuer: &str, email: Option<&str>) -> Principal {
        Principal {
            issuer: issuer.into(),
            subject: "1".into(),
            email: email.map(str::to_string),
            org: None,
            groups: vec![],
            not_after: 0,
            claims: Default::default(),
        }
    }

    fn node() -> NodeId {
        NodeIdentity::from_seed([9u8; 32]).node_id()
    }

    fn tool(name: &str) -> ToolName {
        ToolName::new(name).unwrap()
    }

    fn role(name: &str) -> RoleName {
        RoleName::new(name).unwrap()
    }

    fn matcher(json: &str) -> Matcher {
        serde_json::from_str(json).unwrap()
    }

    /// The card's table: `analyst` by email, `sre` by Okta group; `db_query`
    /// for analysts, `status` for any member, `restart` for sre then
    /// analyst, `locked` for no one.
    fn table() -> RoleTable {
        RoleTable::new(
            BTreeMap::from([
                (
                    role("analyst"),
                    vec![
                        matcher(r#"{"email":"*@example.com"}"#),
                        matcher(r#"{"email":"gotwalt@gmail.com"}"#),
                    ],
                ),
                (
                    role("sre"),
                    vec![matcher(&format!(r#"{{"issuer":"{OKTA}","group":"sre"}}"#))],
                ),
            ]),
            BTreeMap::from([
                (tool("db_query"), vec![role("analyst")]),
                (tool("status"), vec![RoleName::member()]),
                (tool("restart"), vec![role("sre"), role("analyst")]),
                (tool("locked"), vec![]),
            ]),
        )
    }

    fn decide(t: &RoleTable, name: &str, p: Option<&Principal>) -> Decision {
        let (tool, argv) = (tool(name), Argv::default());
        t.decide(&CallContext {
            principal: p,
            caller: node(),
            roster_version: Some(1),
            tool: &tool,
            argv: &argv,
        })
    }

    #[test]
    fn a_matching_role_admits_and_is_named() {
        let alice = principal(GOOGLE, Some("Alice@Example.com"));
        let d = decide(&table(), "db_query", Some(&alice));
        assert!(d.allow, "{d:?}");
        assert_eq!(d.role, Some(role("analyst")));
        assert!(
            d.reason.contains("Alice@Example.com is in role analyst"),
            "{}",
            d.reason
        );
    }

    #[test]
    fn the_first_admitting_role_in_allow_order_wins() {
        let mut both = principal(OKTA, Some("ops@example.com"));
        both.groups = vec!["sre".into()];
        assert_eq!(
            decide(&table(), "restart", Some(&both)).role,
            Some(role("sre"))
        );
        let analyst = principal(GOOGLE, Some("a@example.com"));
        assert_eq!(
            decide(&table(), "restart", Some(&analyst)).role,
            Some(role("analyst"))
        );
    }

    #[test]
    fn a_non_member_of_every_allowed_role_is_refused_with_the_rules() {
        let bob = principal(GOOGLE, Some("bob@other.org"));
        let d = decide(&table(), "db_query", Some(&bob));
        assert!(!d.allow);
        assert_eq!(d.role, None);
        assert_eq!(
            d.reason,
            format!(
                "identity bob@other.org (from {GOOGLE}) is in no role allowed to run db_query: \
                 analyst (email=*@example.com | email=gotwalt@gmail.com)"
            )
        );
    }

    #[test]
    fn no_principal_is_refused_by_identity_roles_and_admitted_by_member() {
        let d = decide(&table(), "db_query", None);
        assert!(!d.allow);
        assert!(
            d.reason
                .starts_with("db_query needs a verified identity in role analyst ("),
            "{}",
            d.reason
        );
        let d = decide(&table(), "status", None);
        assert!(d.allow, "{d:?}");
        assert_eq!(d.role, Some(RoleName::member()));
        assert!(d.reason.starts_with("node "), "{}", d.reason);
    }

    #[test]
    fn empty_allow_and_unknown_tools_deny_everyone() {
        let alice = principal(GOOGLE, Some("alice@example.com"));
        for p in [None, Some(&alice)] {
            let d = decide(&table(), "locked", p);
            assert!(!d.allow);
            assert!(d.reason.contains("allows no role"), "{}", d.reason);
            let d = decide(&table(), "nope", p);
            assert_eq!(d, Decision::deny("unknown tool: nope"));
        }
    }

    #[test]
    fn allowed_tools_lists_what_each_caller_may_run() {
        let t = table();
        assert_eq!(t.allowed_tools(None, node()), vec![tool("status")]);
        let alice = principal(GOOGLE, Some("alice@example.com"));
        assert_eq!(
            t.allowed_tools(Some(&alice), node()),
            vec![tool("db_query"), tool("restart"), tool("status")]
        );
        let mut sre = principal(OKTA, None);
        sre.groups = vec!["sre".into()];
        assert_eq!(
            t.allowed_tools(Some(&sre), node()),
            vec![tool("restart"), tool("status")]
        );
        assert_eq!(t.member_tools(), vec![tool("status")]);
        assert!(
            AnyMember.member_tools().is_empty(),
            "the default promises nothing"
        );
    }

    #[test]
    fn matcher_keys_are_anded() {
        let m = matcher(&format!(
            r#"{{"issuer":"{OKTA}","email":"*@acme.com","org":"Acme.com","group":"sre"}}"#
        ));
        let mut p = principal(OKTA, Some("x@acme.com"));
        assert!(!m.matches(&p), "no org, no group");
        p.org = Some("acme.com".into());
        assert!(!m.matches(&p), "no group");
        p.groups = vec!["dev".into(), "sre".into()];
        assert!(m.matches(&p));
        p.issuer = GOOGLE.into();
        assert!(!m.matches(&p), "wrong issuer");
        assert_eq!(
            m.to_string(),
            format!("issuer={OKTA},email=*@acme.com,org=Acme.com,group=sre")
        );
    }

    #[test]
    fn matchers_and_names_reject_bad_input() {
        for bad in [
            r#"{"email":"*"}"#,
            r#"{"email":"a*@example.com"}"#,
            r#"{"email":"*@*.example.com"}"#,
            r#"{"email":"nobody"}"#,
            r#"{"iss":"https://x"}"#,
            r#"{"email":"a@b","colour":"red"}"#,
        ] {
            assert!(serde_json::from_str::<Matcher>(bad).is_err(), "{bad}");
        }
        assert!(matcher("{}").is_empty());
        for bad in ["", "has space", "ünï", &"x".repeat(65)] {
            assert!(RoleName::new(bad).is_err(), "{bad:?}");
        }
        assert!(RoleName::new("on-call.eu_1").is_ok());
    }

    fn label() -> impl Strategy<Value = String> {
        "[a-z0-9]([a-z0-9-]{0,8}[a-z0-9])?"
    }

    fn domain() -> impl Strategy<Value = String> {
        proptest::collection::vec(label(), 1..4).prop_map(|l| l.join("."))
    }

    fn local() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9._+-]{1,12}"
    }

    fn arb_matcher() -> impl Strategy<Value = Matcher> {
        (
            proptest::option::of("https://[a-z]{1,8}\\.example"),
            proptest::option::of(prop_oneof![
                (local(), domain()).prop_map(|(l, d)| EmailPattern::Exact(
                    format!("{l}@{d}").to_ascii_lowercase()
                )),
                domain().prop_map(EmailPattern::Domain),
            ]),
            proptest::option::of(domain()),
            proptest::option::of("[a-z][a-z0-9_-]{0,8}"),
        )
            .prop_map(|(issuer, email, org, group)| Matcher {
                issuer,
                email,
                org,
                group,
            })
    }

    fn arb_principal() -> impl Strategy<Value = Principal> {
        (
            "https://[a-z]{1,8}\\.example",
            proptest::option::of((local(), domain()).prop_map(|(l, d)| format!("{l}@{d}"))),
            proptest::option::of(domain()),
            proptest::collection::vec("[a-z][a-z0-9_-]{0,8}", 0..3),
        )
            .prop_map(|(issuer, email, org, groups)| {
                let mut p = principal(&issuer, email.as_deref());
                p.org = org;
                p.groups = groups;
                p
            })
    }

    proptest! {
        /// `*@domain` matches every address at exactly that domain, in any
        /// ASCII case, and nothing at a sub-, super- or look-alike domain.
        #[test]
        fn domain_glob_matches_exactly_that_domain(
            l in local(), d in domain(), other in domain(), upper in any::<bool>()
        ) {
            let pattern: EmailPattern = format!("*@{d}").parse().unwrap();
            let email = format!("{l}@{d}");
            let email = if upper { email.to_ascii_uppercase() } else { email };
            let (sub, lookalike, no_local, elsewhere) = (
                format!("{l}@sub.{d}"),
                format!("{l}@{d}.evil.net"),
                format!("@{d}"),
                format!("{l}@{other}"),
            );
            prop_assert!(pattern.matches(&email));
            prop_assert!(!pattern.matches(&sub));
            prop_assert!(!pattern.matches(&lookalike));
            prop_assert!(!pattern.matches(&no_local));
            if !other.eq_ignore_ascii_case(&d) {
                prop_assert!(!pattern.matches(&elsewhere));
            }
        }

        /// A matcher pinned to one issuer never admits a principal from
        /// another, whatever else matches.
        #[test]
        fn a_pinned_issuer_is_never_bypassed(m in arb_matcher(), p in arb_principal()) {
            if let Some(iss) = &m.issuer && *iss != p.issuer {
                prop_assert!(!m.matches(&p));
            }
        }

        /// A matcher is the AND of its keys: it matches iff each one-key
        /// matcher made from its keys does.
        #[test]
        fn a_matcher_is_the_and_of_its_keys(m in arb_matcher(), p in arb_principal()) {
            let singles = [
                Matcher { issuer: m.issuer.clone(), ..Matcher::default() },
                Matcher { email: m.email.clone(), ..Matcher::default() },
                Matcher { org: m.org.clone(), ..Matcher::default() },
                Matcher { group: m.group.clone(), ..Matcher::default() },
            ];
            prop_assert_eq!(m.matches(&p), singles.iter().all(|s| s.matches(&p)));
        }

        /// Matchers survive the host.json round trip.
        #[test]
        fn matchers_round_trip_through_json(m in arb_matcher()) {
            let json = serde_json::to_string(&m).unwrap();
            prop_assert_eq!(serde_json::from_str::<Matcher>(&json).unwrap(), m);
        }

        /// Default deny: whatever the caller, an allowed call names a role
        /// from the tool's `allow`, and a refusal names none and says why.
        #[test]
        fn every_decision_is_explained(
            p in proptest::option::of(arb_principal()),
            name in prop::sample::select(vec!["db_query", "status", "restart", "locked", "nope"]),
        ) {
            let t = table();
            let d = decide(&t, name, p.as_ref());
            prop_assert!(!d.reason.is_empty());
            match &d.role {
                Some(r) => {
                    prop_assert!(d.allow);
                    prop_assert!(t.allow[&tool(name)].contains(r));
                }
                None => prop_assert!(!d.allow),
            }
            if name == "locked" || name == "nope" {
                prop_assert!(!d.allow);
            }
            prop_assert_eq!(
                d.allow,
                t.allowed_tools(p.as_ref(), node()).contains(&tool(name))
            );
        }
    }
}

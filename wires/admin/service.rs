//! `wires service add | set | rm`, `wires role set | rm`, `wires issuer set |
//! rm` and `wires directory add | rm` (cards 27, 36): the admin edits the
//! admin-signed policy, signs the next version, and publishes it to the
//! directories ([`super::propagate`]).
//!
//! ```text
//! wires role set analyst '*@example.com' 'issuer=https://idp,group=dba'
//! wires issuer set https://acme.okta.com --client-id 0oa…   # trust an IdP
//! wires role set staff --issuer https://acme.okta.com 'issuer=https://acme.okta.com'
//! wires service add orders-db --description "Read-only SQL" --allow analyst --host workbench
//! wires service set orders-db --host workbench --host spare     # failover
//! wires service rm  orders-db
//! ```
//!
//! Every edit goes through [`edit_policy`]: the stored policy, changed, its
//! expired bans dropped, the version bumped by one, re-signed (which
//! validates it: every matcher's issuer must be trusted by an `issuer` item)
//! and stored through the compare-and-swap. **The host set is
//! derived:** a node is a host exactly when some service names it, so
//! assigning a service is what makes a node a host, and dropping its last
//! service makes it a plain node again. A `--host` must be a node this
//! admin invited (it is in the ledger) and not banned.

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use library::{
    Audience, EmailPattern, GOOGLE_ISSUER, Issuer, IssuerConfig, Matcher, NodeId, Policy, RoleName,
    Service, ServiceName, StateVersion,
};

use super::invite::resolve_member;
use super::keystore::Keystore;
use super::ledger::Ledger;
use super::ttl::Ttl;
use super::{Report, run_edit};
use crate::clock::now_unix;
use crate::policy::store::{self, Held};

/// `service` arguments.
#[derive(Args)]
pub(crate) struct ServiceArgs {
    #[command(subcommand)]
    pub(crate) cmd: ServiceCmd,
}

/// The `service` subcommands.
#[derive(Subcommand)]
pub(crate) enum ServiceCmd {
    /// Register a new service and publish the new policy
    #[command(
        after_help = "Example:\n  wires service add orders-db --description \"Read-only SQL over the orders database\" \\\n    --allow analyst --reader security --host workbench --host spare"
    )]
    Add(ServiceEditArgs),
    /// Change an existing service (each flag given replaces that list)
    #[command(after_help = "Example:\n  wires service set orders-db --allow analyst --allow sre")]
    Set(ServiceEditArgs),
    /// Drop a service and publish the new policy
    #[command(after_help = "Example:\n  wires service rm orders-db")]
    Rm(ServiceRmArgs),
}

/// `service add | set` arguments.
#[derive(Args)]
pub(crate) struct ServiceEditArgs {
    /// The service's name (`[a-z][a-z0-9_-]*`).
    pub(crate) name: String,
    /// What it does, shown in `wires services`.
    #[arg(long)]
    pub(crate) description: Option<String>,
    /// A role allowed to call it (one defined with `wires role set`).
    /// Repeatable.
    #[arg(long = "allow")]
    pub(crate) allow: Vec<String>,
    /// A node that implements it: an `invite --name` label or a node id.
    /// Repeatable (failover).
    #[arg(long = "host")]
    pub(crate) host: Vec<String>,
    /// A role that may read its call records. Repeatable.
    #[arg(long = "reader")]
    pub(crate) reader: Vec<String>,
    /// Lifetime of the new policy, from now (`90d`, `12h`, … or seconds);
    /// never shortens the current one.
    #[arg(long = "policy-ttl", default_value = Ttl::POLICY_DEFAULT, hide = true)]
    pub(crate) ttl: Ttl,
}

/// `service rm` arguments.
#[derive(Args)]
pub(crate) struct ServiceRmArgs {
    /// The service to drop.
    pub(crate) name: String,
    /// Lifetime of the new policy, from now; never shortens the current one.
    #[arg(long = "policy-ttl", default_value = Ttl::POLICY_DEFAULT, hide = true)]
    pub(crate) ttl: Ttl,
}

/// `role` arguments.
#[derive(Args)]
pub(crate) struct RoleArgs {
    #[command(subcommand)]
    pub(crate) cmd: RoleCmd,
}

/// The `role` subcommands.
#[derive(Subcommand)]
pub(crate) enum RoleCmd {
    /// Define (or replace) a role as an OR of matchers, and publish
    #[command(
        after_help = "Examples:\n  wires role set analyst --issuer https://accounts.google.com '*@example.com'\n  wires role set sre 'issuer=https://idp.example.com,group=sre'"
    )]
    Set(RoleSetArgs),
    /// Drop a role no service names any more, and publish
    #[command(after_help = "Example:\n  wires role rm analyst")]
    Rm(RoleRmArgs),
}

/// `role set` arguments.
#[derive(Args)]
pub(crate) struct RoleSetArgs {
    /// The role's name.
    pub(crate) name: String,
    /// `*@example.com`, `alice@example.com`, or `issuer=…,email=…,org=…,group=…`
    // Comma-separated keys must all hold. A matcher without `issuer=` takes
    // `--issuer`.
    #[arg(required = true)]
    pub(crate) matchers: Vec<String>,
    /// The IdP a matcher trusts when it names none: its exact `iss`.
    #[arg(long, default_value = GOOGLE_ISSUER)]
    pub(crate) issuer: String,
    /// Lifetime of the new policy, from now; never shortens the current one.
    #[arg(long = "policy-ttl", default_value = Ttl::POLICY_DEFAULT, hide = true)]
    pub(crate) ttl: Ttl,
}

/// `role rm` arguments.
#[derive(Args)]
pub(crate) struct RoleRmArgs {
    /// The role to drop.
    pub(crate) name: String,
    /// Lifetime of the new policy, from now; never shortens the current one.
    #[arg(long = "policy-ttl", default_value = Ttl::POLICY_DEFAULT, hide = true)]
    pub(crate) ttl: Ttl,
}

/// `issuer` arguments.
#[derive(Args)]
pub(crate) struct IssuerArgs {
    #[command(subcommand)]
    pub(crate) cmd: IssuerCmd,
}

/// The `issuer` subcommands: the IdPs the network trusts (signed `issuer`
/// items; a host's `host.json` can narrow them, never widen them).
#[derive(Subcommand)]
pub(crate) enum IssuerCmd {
    /// Trust an IdP (or change one), and publish
    #[command(
        after_help = "Example:\n  wires issuer set https://idp.example.com --client-id <client id>"
    )]
    Set(IssuerSetArgs),
    /// Stop trusting an IdP no role names any more, and publish
    #[command(after_help = "Example:\n  wires issuer rm https://idp.example.com")]
    Rm(IssuerRmArgs),
}

/// `issuer set` arguments.
#[derive(Args)]
pub(crate) struct IssuerSetArgs {
    /// The IdP's exact `iss` (e.g. `https://accounts.google.com`).
    pub(crate) issuer: String,
    /// The OAuth client id `wires login` signs in under.
    #[arg(long)]
    pub(crate) client_id: String,
    /// An `aud` value hosts accept from this IdP (repeatable; default: the client id).
    #[arg(long = "audience")]
    pub(crate) audience: Vec<String>,
    /// The client's public secret, which invites carry to `wires login`.
    // A Google "Desktop app" client's; kept in this keystore, not in the
    // signed policy. Never pass a confidential secret.
    #[arg(long)]
    pub(crate) public_client_secret: Option<String>,
    /// Make this the IdP invites tell `wires login` to use (default: init's).
    #[arg(long)]
    pub(crate) login: bool,
    /// Lifetime of the new policy, from now; never shortens the current one.
    #[arg(long = "policy-ttl", default_value = Ttl::POLICY_DEFAULT, hide = true)]
    pub(crate) ttl: Ttl,
}

/// `issuer rm` arguments.
#[derive(Args)]
pub(crate) struct IssuerRmArgs {
    /// The IdP's exact `iss`.
    pub(crate) issuer: String,
    /// Lifetime of the new policy, from now; never shortens the current one.
    #[arg(long = "policy-ttl", default_value = Ttl::POLICY_DEFAULT, hide = true)]
    pub(crate) ttl: Ttl,
}

/// A change to one registry entry. `None` fields keep the current value
/// (`set`); `add` requires the service not to exist, `set` requires it to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ServiceEdit {
    /// The service's description.
    pub(crate) description: Option<String>,
    /// Its `allow` roles, replacing the list.
    pub(crate) allow: Option<Vec<RoleName>>,
    /// Its hosts, replacing the list (each must be a node this admin
    /// invited, and not banned).
    pub(crate) hosts: Option<Vec<NodeId>>,
    /// Its record readers, replacing the list.
    pub(crate) readers: Option<Vec<RoleName>>,
}

impl ServiceEdit {
    /// Apply to `svc`, field by field.
    fn apply(self, svc: &mut Service) {
        if let Some(d) = self.description {
            svc.description = d;
        }
        if let Some(a) = self.allow {
            svc.allow = a;
        }
        if let Some(h) = self.hosts {
            svc.hosts = h;
        }
        if let Some(r) = self.readers {
            svc.readers = r;
        }
    }
}

// ---------------------------------------------------------------------------
// The one edit path
// ---------------------------------------------------------------------------

/// Sign and store the next version of this keystore's policy: the stored
/// one (or, for `wires init`, an empty one) changed by `change`, bans whose
/// `until` has passed dropped ([`Policy::prune_bans`]: the badge each one
/// cancelled has expired), version + 1, valid until `ttl` from now or the
/// stored one's expiry, whichever is later (an edit never shortens the
/// policy's lifetime). Only the service entries the edit changed are
/// re-signed ([`Policy::sign_after`]); the rest keep their signature and
/// version. Validation failures name the broken rule.
pub(crate) fn edit_policy(
    ks: &Keystore,
    ttl: Ttl,
    change: impl FnOnce(&mut Policy) -> Result<()>,
) -> Result<Held> {
    let root = ks
        .read_root_identity()?
        .ok_or_else(|| anyhow!("no root key here; run `wires init` first (on the admin)"))?;
    let held = store::read(ks, root.node_id())?;
    let mut next = match &held {
        Some(h) => h.policy.clone(),
        None => Policy::new(root.node_id()),
    };
    change(&mut next)?;
    let now = now_unix();
    next.prune_bans(now);
    next.version = StateVersion(next.version.0 + 1);
    next.issued = now;
    next.not_after = ttl
        .not_after(now)
        .max(held.as_ref().map_or(i64::MIN, |h| h.policy.not_after));
    let signed = match &held {
        Some(h) => next.sign_after(&root, &h.signed),
        None => next.sign(&root),
    }
    .context("the new policy is not valid")?;
    if !store::adopt_if_newer(ks, &signed, root.node_id(), now)? {
        bail!("another admin command changed the policy meanwhile; run this one again");
    }
    Held::verify(signed, root.node_id())
}

/// `wires service add <name>`: register a new service.
pub(crate) fn add(ks: &Keystore, name: ServiceName, edit: ServiceEdit, ttl: Ttl) -> Result<Held> {
    let ledger = Ledger::load(ks)?;
    edit_policy(ks, ttl, |s| {
        if s.services.contains_key(&name) {
            bail!("service {name} already exists; change it with `wires service set`");
        }
        check_hosts(s, &ledger, edit.hosts.as_deref())?;
        let mut svc = Service {
            description: String::new(),
            allow: Vec::new(),
            hosts: Vec::new(),
            readers: Vec::new(),
        };
        edit.apply(&mut svc);
        s.services.insert(name, svc);
        Ok(())
    })
}

/// `wires service set <name>`: change an existing service.
pub(crate) fn set(ks: &Keystore, name: ServiceName, edit: ServiceEdit, ttl: Ttl) -> Result<Held> {
    let ledger = Ledger::load(ks)?;
    edit_policy(ks, ttl, |s| {
        check_hosts(s, &ledger, edit.hosts.as_deref())?;
        let svc = s
            .services
            .get_mut(&name)
            .ok_or_else(|| anyhow!("no service {name}; register it with `wires service add`"))?;
        edit.apply(svc);
        Ok(())
    })
}

/// `wires service rm <name>`: drop a service.
pub(crate) fn rm(ks: &Keystore, name: ServiceName, ttl: Ttl) -> Result<Held> {
    edit_policy(ks, ttl, |s| {
        s.services
            .remove(&name)
            .map(|_| ())
            .ok_or_else(|| anyhow!("no service {name}"))
    })
}

/// `wires role set <name> <matcher>…`: define or replace a role.
pub(crate) fn role_set(
    ks: &Keystore,
    name: RoleName,
    matchers: Vec<Matcher>,
    ttl: Ttl,
) -> Result<Held> {
    if matchers.is_empty() {
        bail!("a role needs at least one matcher");
    }
    edit_policy(ks, ttl, |s| {
        s.roles.insert(name, matchers);
        Ok(())
    })
}

/// `wires role rm <name>`: drop a role (refused while a service names it).
pub(crate) fn role_rm(ks: &Keystore, name: RoleName, ttl: Ttl) -> Result<Held> {
    edit_policy(ks, ttl, |s| {
        if s.roles.remove(&name).is_none() {
            bail!("no role {name}");
        }
        Ok(())
    })
}

/// `wires issuer set <iss>`: trust an IdP, or change its client id and
/// audiences.
pub(crate) fn issuer_set(
    ks: &Keystore,
    issuer: Issuer,
    config: IssuerConfig,
    ttl: Ttl,
) -> Result<Held> {
    edit_policy(ks, ttl, |p| {
        p.issuers.insert(issuer, config);
        Ok(())
    })
}

/// `wires issuer rm <iss>`: stop trusting an IdP (refused while a role's
/// matcher names it).
pub(crate) fn issuer_rm(ks: &Keystore, issuer: &Issuer, ttl: Ttl) -> Result<Held> {
    edit_policy(ks, ttl, |p| {
        if p.issuers.remove(issuer).is_none() {
            bail!("no trusted issuer {issuer}");
        }
        Ok(())
    })
}

/// The `issuer` item `init` and `issuer set` sign: `client_id`, and the
/// audiences hosts accept (the client id when none are given).
pub(crate) fn issuer_config(client_id: &str, audiences: &[String]) -> Result<IssuerConfig> {
    let client_id = client_id.trim();
    if client_id.is_empty() {
        bail!("the OAuth client id is empty");
    }
    let audiences: Vec<Audience> = if audiences.is_empty() {
        vec![Audience::new(client_id)]
    } else {
        audiences.iter().map(|a| Audience::new(a.trim())).collect()
    };
    Ok(IssuerConfig {
        client_id: Audience::new(client_id),
        audiences,
    })
}

/// `wires directory add <node>`: list a node as one of the network's
/// directories (a node this admin invited, not banned, listed once).
pub(crate) fn directory_add(ks: &Keystore, node: NodeId, ttl: Ttl) -> Result<Held> {
    let ledger = Ledger::load(ks)?;
    edit_policy(ks, ttl, |p| {
        check_hosts(p, &ledger, Some(&[node]))?;
        if p.directories.contains(&node) {
            bail!("{} is already a directory", node.short());
        }
        p.directories.push(node);
        Ok(())
    })
}

/// `wires directory rm <node>`: stop listing a node as a directory.
pub(crate) fn directory_rm(ks: &Keystore, node: NodeId, ttl: Ttl) -> Result<Held> {
    edit_policy(ks, ttl, |p| {
        let before = p.directories.len();
        p.directories.retain(|d| *d != node);
        if p.directories.len() == before {
            bail!("{} is not a directory", node.short());
        }
        Ok(())
    })
}

/// Each proposed host (or directory) must be a node this admin invited (in
/// its ledger), and not banned.
pub(crate) fn check_hosts(s: &Policy, ledger: &Ledger, hosts: Option<&[NodeId]>) -> Result<()> {
    for h in hosts.unwrap_or_default() {
        if let Some(ban) = s.bans.get(h) {
            bail!(
                "{} was removed (banned until {}); `wires invite` it again first",
                h.short(),
                ban.until
            );
        }
        if !ledger.contains(*h) {
            bail!(
                "{} was never invited here; `wires invite` it first",
                h.short()
            );
        }
    }
    Ok(())
}

/// Parse one matcher: a bare email pattern (`*@example.com`,
/// `alice@example.com`), or comma-separated `key=value` pairs over `issuer`
/// (or `iss`), `email`, `org`, `group`. A matcher that names no issuer
/// trusts `default_issuer` (`role set --issuer`, Google by default): every
/// matcher names one.
pub(crate) fn parse_matcher(text: &str, default_issuer: &str) -> Result<Matcher> {
    let text = text.trim();
    let default_issuer = default_issuer.trim();
    if default_issuer.is_empty() {
        bail!("--issuer is empty");
    }
    if !text.contains('=') {
        let email: EmailPattern = text
            .parse()
            .map_err(|_| anyhow!("{text:?} is not an email or *@domain (or key=value pairs)"))?;
        return Ok(Matcher {
            email: Some(email),
            ..Matcher::new(default_issuer)
        });
    }
    let mut issuer: Option<String> = None;
    let mut m = Matcher::new(default_issuer);
    for part in text.split(',') {
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| anyhow!("{part:?}: expected key=value"))?;
        let value = value.trim();
        if value.is_empty() {
            bail!("{part:?}: the value is empty");
        }
        let slot = match key.trim() {
            "issuer" | "iss" => &mut issuer,
            "org" => &mut m.org,
            "group" => &mut m.group,
            "email" => {
                if m.email.is_some() {
                    bail!("{text:?}: email given twice");
                }
                m.email = Some(
                    value
                        .parse()
                        .map_err(|_| anyhow!("{value:?} is not an email or *@domain"))?,
                );
                continue;
            }
            other => bail!("unknown matcher key {other:?} (use issuer, email, org, group)"),
        };
        if slot.replace(value.to_string()).is_some() {
            bail!("{text:?}: {key} given twice");
        }
    }
    if let Some(issuer) = issuer {
        m.issuer = issuer;
    }
    Ok(m)
}

// ---------------------------------------------------------------------------
// The commands
// ---------------------------------------------------------------------------

fn role_names(texts: &[String]) -> Result<Option<Vec<RoleName>>> {
    if texts.is_empty() {
        return Ok(None);
    }
    texts
        .iter()
        .map(|t| RoleName::new(t.trim()).map_err(|_| anyhow!("{t:?} is not a role name")))
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

/// `--host` labels or ids → node ids, through the admin's ledger.
fn host_ids(ks: &Keystore, texts: &[String]) -> Result<Option<Vec<NodeId>>> {
    if texts.is_empty() {
        return Ok(None);
    }
    let ledger = Ledger::load(ks)?;
    let mut out = Vec::new();
    for t in texts {
        let (id, _) = resolve_member(&ledger, t)?;
        if !out.contains(&id) {
            out.push(id);
        }
    }
    Ok(Some(out))
}

fn service_name(text: &str) -> Result<ServiceName> {
    ServiceName::new(text.trim())
        .map_err(|_| anyhow!("{text:?} is not a service name ([a-z][a-z0-9_-]*, ≤ 64 bytes)"))
}

/// The edit a `service add | set` command line asks for.
pub(crate) fn edit_from(ks: &Keystore, a: &ServiceEditArgs) -> Result<ServiceEdit> {
    Ok(ServiceEdit {
        description: a.description.clone(),
        allow: role_names(&a.allow)?,
        hosts: host_ids(ks, &a.host)?,
        readers: role_names(&a.reader)?,
    })
}

/// Run a `service` subcommand against `ks` (no publish): what changed.
pub(crate) fn service_in(ks: &Keystore, a: ServiceArgs) -> Result<String> {
    let (verb, name, signed) = match a.cmd {
        ServiceCmd::Add(e) => {
            let name = service_name(&e.name)?;
            let edit = edit_from(ks, &e)?;
            ("added", name.clone(), add(ks, name, edit, e.ttl)?)
        }
        ServiceCmd::Set(e) => {
            let name = service_name(&e.name)?;
            let edit = edit_from(ks, &e)?;
            ("changed", name.clone(), set(ks, name, edit, e.ttl)?)
        }
        ServiceCmd::Rm(r) => {
            let name = service_name(&r.name)?;
            ("removed", name.clone(), rm(ks, name, r.ttl)?)
        }
    };
    Ok(format!(
        "service {name} {verb} (policy version {})",
        signed.version().0
    ))
}

/// Run a `role` subcommand against `ks` (no publish): what changed.
pub(crate) fn role_in(ks: &Keystore, a: RoleArgs) -> Result<String> {
    let role = |t: &str| RoleName::new(t.trim()).map_err(|_| anyhow!("{t:?} is not a role name"));
    let (verb, name, signed) = match a.cmd {
        RoleCmd::Set(r) => {
            let name = role(&r.name)?;
            let matchers = r
                .matchers
                .iter()
                .map(|m| parse_matcher(m, &r.issuer))
                .collect::<Result<Vec<_>>>()?;
            ("set", name.clone(), role_set(ks, name, matchers, r.ttl)?)
        }
        RoleCmd::Rm(r) => {
            let name = role(&r.name)?;
            ("removed", name.clone(), role_rm(ks, name, r.ttl)?)
        }
    };
    Ok(format!(
        "role {name} {verb} (policy version {})",
        signed.version().0
    ))
}

/// Run an `issuer` subcommand against `ks` (no publish): what changed.
pub(crate) fn issuer_in(ks: &Keystore, a: IssuerArgs) -> Result<String> {
    let (verb, iss, signed) = match a.cmd {
        IssuerCmd::Set(i) => {
            let iss = Issuer::new(i.issuer.trim());
            let config = issuer_config(&i.client_id, &i.audience)?;
            let signed = issuer_set(ks, iss.clone(), config, i.ttl)?;
            // Card 37: what invites tell `wires login` (not signed).
            super::login_client::LoginClient::record(
                ks,
                &iss,
                i.public_client_secret.as_deref(),
                i.login,
            )?;
            ("trusted", iss, signed)
        }
        IssuerCmd::Rm(i) => {
            let iss = Issuer::new(i.issuer.trim());
            (
                "no longer trusted",
                iss.clone(),
                issuer_rm(ks, &iss, i.ttl)?,
            )
        }
    };
    Ok(format!(
        "issuer {iss} {verb} (policy version {})",
        signed.version().0
    ))
}

/// `wires issuer …` against the resolved keystore, then publish.
pub(crate) async fn issuer_cmd(a: IssuerArgs) -> Result<Report> {
    run_edit(|ks| {
        Ok(Report {
            stdout: issuer_in(ks, a)?,
            ..Report::default()
        })
    })
    .await
}

/// `wires service …` against the resolved keystore, then publish.
pub(crate) async fn service_cmd(a: ServiceArgs) -> Result<Report> {
    run_edit(|ks| {
        Ok(Report {
            stdout: service_in(ks, a)?,
            ..Report::default()
        })
    })
    .await
}

/// `wires role …` against the resolved keystore, then publish.
pub(crate) async fn role_cmd(a: RoleArgs) -> Result<Report> {
    run_edit(|ks| {
        Ok(Report {
            stdout: role_in(ks, a)?,
            ..Report::default()
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::init::{InitArgs, init_in};
    use crate::testutil::temp_dir;
    use library::NodeIdentity;
    use proptest::prelude::*;

    /// An initialized admin keystore that has invited `extra`.
    fn admin_with(extra: &[NodeId]) -> Keystore {
        let ks = Keystore::at(temp_dir());
        init_in(&ks, InitArgs::default()).unwrap();
        let mut ledger = Ledger::load(&ks).unwrap();
        for n in extra {
            ledger.record(*n, None, i64::MAX);
        }
        ledger.save(&ks).unwrap();
        ks
    }

    fn ttl() -> Ttl {
        Ttl::default()
    }

    fn svc(n: &str) -> ServiceName {
        ServiceName::new(n).unwrap()
    }

    fn role(n: &str) -> RoleName {
        RoleName::new(n).unwrap()
    }

    #[test]
    fn service_lifecycle_bumps_the_version_and_derives_hosts() {
        let host = NodeIdentity::generate().node_id();
        let ks = admin_with(&[host]);
        let root = ks.read_root_identity().unwrap().unwrap().node_id();
        let v0 = store::read(&ks, root).unwrap().unwrap().version();

        let s = role_set(
            &ks,
            role("analyst"),
            vec![parse_matcher("*@x.com", GOOGLE_ISSUER).unwrap()],
            ttl(),
        )
        .unwrap();
        assert_eq!(s.version(), StateVersion(v0.0 + 1));
        let edit = ServiceEdit {
            description: Some("orders".into()),
            allow: Some(vec![role("analyst")]),
            hosts: Some(vec![host]),
            readers: None,
        };
        let s = add(&ks, svc("orders-db"), edit.clone(), ttl()).unwrap();
        assert!(s.policy.assigns(&svc("orders-db"), host));
        assert!(s.policy.is_host(host));
        assert!(add(&ks, svc("orders-db"), edit, ttl()).is_err(), "twice");

        let s = set(
            &ks,
            svc("orders-db"),
            ServiceEdit {
                description: Some("new".into()),
                ..Default::default()
            },
            ttl(),
        )
        .unwrap();
        assert_eq!(s.policy.services[&svc("orders-db")].description, "new");
        assert_eq!(s.policy.services[&svc("orders-db")].hosts, vec![host]);
        assert!(set(&ks, svc("nope"), ServiceEdit::default(), ttl()).is_err());

        // A role still in use can't go; after the service goes, it can.
        assert!(role_rm(&ks, role("analyst"), ttl()).is_err());
        let s = rm(&ks, svc("orders-db"), ttl()).unwrap();
        assert!(!s.policy.is_host(host), "no service left, no longer a host");
        role_rm(&ks, role("analyst"), ttl()).unwrap();
        let stored = store::read(&ks, root).unwrap().unwrap();
        assert_eq!(stored.version(), StateVersion(v0.0 + 5));
    }

    /// An edit re-signs only the service entries it changes; the rest keep
    /// their root signature and the version they last changed at, so a
    /// caller holding them needs nothing new (card 36d).
    #[test]
    fn an_edit_re_signs_only_the_entries_it_changes() {
        let ks = admin_with(&[]);
        let matcher = vec![parse_matcher("*@x.com", GOOGLE_ISSUER).unwrap()];
        role_set(&ks, role("analyst"), matcher, ttl()).unwrap();
        let edit = |d: &str| ServiceEdit {
            description: Some(d.into()),
            allow: Some(vec![role("analyst")]),
            ..Default::default()
        };
        add(&ks, svc("a"), edit("a"), ttl()).unwrap();
        let at_b = add(&ks, svc("b"), edit("b"), ttl()).unwrap();
        let s = set(&ks, svc("b"), edit("b, changed"), ttl()).unwrap();
        let versions = |h: &Held| -> Vec<(String, u64)> {
            h.signed
                .entries()
                .map(|e| (e.name.to_string(), e.version.0))
                .collect()
        };
        let now = s.version().0;
        assert_eq!(
            versions(&s),
            [("a".into(), now - 2), ("b".into(), now)],
            "a kept its version"
        );
        let a = |h: &Held| h.signed.entries().next().unwrap().clone();
        assert_eq!(a(&s), a(&at_b), "and its signature");
        // A role edit changes no entry.
        let s = role_set(
            &ks,
            role("analyst"),
            vec![parse_matcher("*@y.com", GOOGLE_ISSUER).unwrap()],
            ttl(),
        )
        .unwrap();
        assert_eq!(versions(&s), [("a".into(), now - 2), ("b".into(), now)]);
    }

    #[test]
    fn invalid_edits_are_refused_and_nothing_is_stored() {
        let ks = admin_with(&[]);
        let root = ks.read_root_identity().unwrap().unwrap().node_id();
        let before = store::read(&ks, root).unwrap().unwrap();
        let stranger = NodeIdentity::generate().node_id();
        let edit = ServiceEdit {
            hosts: Some(vec![stranger]),
            ..Default::default()
        };
        assert!(add(&ks, svc("x"), edit, ttl()).is_err(), "never invited");
        let edit = ServiceEdit {
            allow: Some(vec![role("ghost")]),
            ..Default::default()
        };
        assert!(add(&ks, svc("x"), edit, ttl()).is_err(), "undefined role");
        assert_eq!(store::read(&ks, root).unwrap().unwrap(), before);
    }

    /// Card 35: a ban drops out at the first edit after its `until`, and a
    /// banned node can't be made a host.
    #[test]
    fn a_ban_drops_out_at_the_first_edit_after_its_until() {
        let (lapsed, live) = (
            NodeIdentity::generate().node_id(),
            NodeIdentity::generate().node_id(),
        );
        let ks = admin_with(&[lapsed, live]);
        let root = ks.read_root_identity().unwrap().unwrap();
        let now = now_unix();
        // A policy someone signed a while ago, holding a ban that has since
        // lapsed (as if its `until` passed after that edit).
        let mut s = store::read(&ks, root.node_id()).unwrap().unwrap().policy;
        s.version = StateVersion(s.version.0 + 1);
        s.ban(lapsed, now - 10);
        s.ban(live, now + 3_600);
        let signed = crate::testutil::signed_policy(&root, s.clone());
        assert!(store::adopt_if_newer(&ks, &signed, root.node_id(), now).unwrap());
        assert!(s.bans_node(lapsed), "held until an edit");

        let edit = ServiceEdit {
            hosts: Some(vec![live]),
            ..Default::default()
        };
        let err = add(&ks, svc("x"), edit, ttl()).unwrap_err();
        assert!(format!("{err:#}").contains("banned"), "{err:#}");

        let next = role_set(
            &ks,
            role("staff"),
            vec![parse_matcher("*@x.com", GOOGLE_ISSUER).unwrap()],
            ttl(),
        )
        .unwrap();
        assert!(!next.policy.bans_node(lapsed), "dropped at the first edit");
        assert!(next.policy.bans_node(live), "still in force");
    }

    /// Card 36: every matcher names a trusted issuer; `init` trusts one, and
    /// `issuer set | rm` edit the rest.
    #[test]
    fn a_role_needs_a_trusted_issuer() {
        let ks = admin_with(&[]);
        let okta = "https://acme.okta.com";
        let matcher = || vec![parse_matcher("*@acme.com", okta).unwrap()];
        let e = role_set(&ks, role("staff"), matcher(), ttl()).unwrap_err();
        assert!(format!("{e:#}").contains("not trusted"), "{e:#}");
        let config = issuer_config("0oa1", &["api://x".into()]).unwrap();
        assert_eq!(config.audiences, vec![Audience::new("api://x")]);
        issuer_set(&ks, Issuer::new(okta), config, ttl()).unwrap();
        role_set(&ks, role("staff"), matcher(), ttl()).unwrap();
        // Still named by a role: can't go.
        assert!(issuer_rm(&ks, &Issuer::new(okta), ttl()).is_err());
        role_rm(&ks, role("staff"), ttl()).unwrap();
        let held = issuer_rm(&ks, &Issuer::new(okta), ttl()).unwrap();
        assert!(!held.policy.issuers.contains_key(&Issuer::new(okta)));
        assert!(issuer_config(" ", &[]).is_err());
    }

    #[test]
    fn directories_are_invited_nodes_listed_once() {
        let dir = NodeIdentity::generate().node_id();
        let ks = admin_with(&[dir]);
        let held = directory_add(&ks, dir, ttl()).unwrap();
        assert_eq!(held.directories(), &[dir]);
        assert!(directory_add(&ks, dir, ttl()).is_err(), "twice");
        let stranger = NodeIdentity::generate().node_id();
        assert!(
            directory_add(&ks, stranger, ttl()).is_err(),
            "never invited"
        );
        let held = directory_rm(&ks, dir, ttl()).unwrap();
        assert!(held.directories().is_empty());
        assert!(directory_rm(&ks, dir, ttl()).is_err(), "not listed");
    }

    #[test]
    fn matchers_parse_like_card_13() {
        let m = parse_matcher("*@example.com", GOOGLE_ISSUER).unwrap();
        assert_eq!(m.email, Some("*@example.com".parse().unwrap()));
        assert_eq!(m.issuer, GOOGLE_ISSUER, "shorthand takes the default");
        let m = parse_matcher("iss=https://idp,group=dba,org=example.com", GOOGLE_ISSUER).unwrap();
        assert_eq!(m.issuer, "https://idp", "an explicit issuer wins");
        assert_eq!(m.group.as_deref(), Some("dba"));
        assert_eq!(m.org.as_deref(), Some("example.com"));
        let m = parse_matcher("group=dba", "https://okta.example").unwrap();
        assert_eq!(
            m.issuer, "https://okta.example",
            "long form takes the default too"
        );
        let m = parse_matcher("email=bob@x.com,issuer=https://i", GOOGLE_ISSUER).unwrap();
        assert_eq!(
            parse_matcher(&m.to_string(), "https://unused").unwrap(),
            m,
            "Display round-trips"
        );
        assert!(parse_matcher("*@x.com", " ").is_err(), "an empty --issuer");
        for bad in [
            "",
            "nope",
            "color=red",
            "group=",
            "group=a,group=b",
            "email=*@*",
            "issuer=a,iss=b",
            "issuer=",
        ] {
            assert!(parse_matcher(bad, GOOGLE_ISSUER).is_err(), "{bad:?}");
        }
    }

    /// Run `wires role …` (the parsed command line) against `ks`: the
    /// policy it stored.
    fn role_cli(ks: &Keystore, args: &[&str]) -> Result<Held> {
        use crate::{Cli, Command};
        use clap::Parser;
        let cli = Cli::try_parse_from(["wires", "role"].iter().chain(args))?;
        let Command::Role(a) = cli.command else {
            panic!("expected role");
        };
        role_in(ks, a)?;
        let root = ks.read_root_identity()?.unwrap().node_id();
        Ok(store::read(ks, root)?.unwrap())
    }

    #[test]
    fn role_set_names_google_unless_told_otherwise() {
        let ks = admin_with(&[]);
        for iss in ["https://acme.okta.com", "https://other"] {
            issuer_set(
                &ks,
                Issuer::new(iss),
                issuer_config("cli", &[]).unwrap(),
                ttl(),
            )
            .unwrap();
        }
        let s = role_cli(&ks, &["set", "analyst", "*@acme.com", "alice@x.com"]).unwrap();
        let ms = &s.policy.roles[&role("analyst")];
        assert!(ms.iter().all(|m| m.issuer == GOOGLE_ISSUER), "{ms:?}");

        let s = role_cli(
            &ks,
            &[
                "set",
                "analyst",
                "--issuer",
                "https://acme.okta.com",
                "*@acme.com",
                "issuer=https://other,group=dba",
            ],
        )
        .unwrap();
        let ms = &s.policy.roles[&role("analyst")];
        assert_eq!(ms[0].issuer, "https://acme.okta.com");
        assert_eq!(ms[1].issuer, "https://other");
    }

    #[test]
    fn the_cli_shapes_parse() {
        use crate::{Cli, Command};
        use clap::Parser;
        let ok = |args: &[&str]| Cli::try_parse_from(["wires"].iter().chain(args)).is_ok();
        assert!(ok(&[
            "service", "add", "db", "--allow", "a", "--host", "h", "--host", "g"
        ]));
        assert!(ok(&["service", "set", "db", "--description", "d"]));
        assert!(ok(&["service", "rm", "db"]));
        assert!(ok(&["role", "set", "analyst", "*@x.com", "group=dba"]));
        assert!(!ok(&["role", "set", "analyst"]), "a matcher is required");
        assert!(ok(&["role", "rm", "analyst"]));
        assert!(ok(&["issuer", "set", "https://i", "--client-id", "c"]));
        assert!(
            !ok(&["issuer", "set", "https://i"]),
            "a client id is required"
        );
        assert!(ok(&["issuer", "rm", "https://i"]));
        let Command::Service(a) = Cli::try_parse_from(["wires", "service", "rm", "db"])
            .unwrap()
            .command
        else {
            panic!("expected service");
        };
        assert!(matches!(a.cmd, ServiceCmd::Rm(_)));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Any sequence of edits only ever moves the version up by one each.
        #[test]
        fn every_edit_is_one_version_up(descs in proptest::collection::vec("[a-z ]{0,12}", 1..5)) {
            let ks = admin_with(&[]);
            let root = ks.read_root_identity().unwrap().unwrap().node_id();
            add(&ks, svc("s"), ServiceEdit::default(), ttl()).unwrap();
            for d in descs {
                let before = store::read(&ks, root).unwrap().unwrap().version();
                let after = set(&ks, svc("s"), ServiceEdit { description: Some(d), ..Default::default() }, ttl())
                    .unwrap()
                    .version();
                prop_assert_eq!(after, StateVersion(before.0 + 1));
            }
        }
    }
}

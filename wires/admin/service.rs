//! `wires service add | set | rm` and `wires role set | rm` (card 27): the
//! admin edits the admin-signed state, signs the next version,
//! and pushes it to every member, hosts first.
//!
//! ```text
//! wires role set analyst '*@example.com' 'issuer=https://idp,group=dba'
//! wires role set staff --issuer https://acme.okta.com 'issuer=https://acme.okta.com'
//! wires service add orders-db --description "Read-only SQL" --allow analyst --host workbench
//! wires service set orders-db --host workbench --host spare     # failover
//! wires service rm  orders-db
//! ```
//!
//! Every edit goes through [`edit_state`]: the stored state, changed, with
//! the version bumped by one, re-signed (which validates it) and stored
//! through the compare-and-swap. **The host set is derived:** a member is a
//! host exactly when some service names it, so assigning a service is what
//! makes a node a host, and dropping its last service makes it a plain
//! member again.

use std::collections::BTreeSet;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use library::{
    EmailPattern, GOOGLE_ISSUER, Matcher, NodeId, RoleName, Service, ServiceName, SignedState,
    State, StateVersion,
};

use super::invite::{Report, resolve_member};
use super::keystore::Keystore;
use super::propagate;
use super::ttl::Ttl;
use crate::now_unix;
use crate::state::{store, sync};

/// `service` arguments.
#[derive(Args)]
pub(crate) struct ServiceArgs {
    #[command(subcommand)]
    pub(crate) cmd: ServiceCmd,
}

/// The `service` subcommands.
#[derive(Subcommand)]
pub(crate) enum ServiceCmd {
    /// Register a new service and push the new state.
    Add(ServiceEditArgs),
    /// Change an existing service (each flag given replaces that list).
    Set(ServiceEditArgs),
    /// Drop a service and push the new state.
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
    /// A member that implements it: an `invite --name` label or a node id.
    /// Repeatable (failover).
    #[arg(long = "host")]
    pub(crate) host: Vec<String>,
    /// A role that may read its call records. Repeatable.
    #[arg(long = "reader")]
    pub(crate) reader: Vec<String>,
    /// Lifetime of the new state, from now (`30d`, `12h`, … or seconds);
    /// never shortens the current one.
    #[arg(long = "state-ttl", default_value = Ttl::DEFAULT)]
    pub(crate) ttl: Ttl,
}

/// `service rm` arguments.
#[derive(Args)]
pub(crate) struct ServiceRmArgs {
    /// The service to drop.
    pub(crate) name: String,
    /// Lifetime of the new state, from now; never shortens the current one.
    #[arg(long = "state-ttl", default_value = Ttl::DEFAULT)]
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
    /// Define (or replace) a role as an OR of matchers, and push.
    Set(RoleSetArgs),
    /// Drop a role no service names any more, and push.
    Rm(RoleRmArgs),
}

/// `role set` arguments.
#[derive(Args)]
pub(crate) struct RoleSetArgs {
    /// The role's name.
    pub(crate) name: String,
    /// One matcher each: `*@example.com`, `alice@example.com`, or
    /// comma-separated keys `issuer=…,email=…,org=…,group=…` (all must hold).
    /// A matcher without `issuer=` takes `--issuer`.
    #[arg(required = true)]
    pub(crate) matchers: Vec<String>,
    /// The IdP a matcher trusts when it names none: its exact `iss`.
    #[arg(long, default_value = GOOGLE_ISSUER)]
    pub(crate) issuer: String,
    /// Lifetime of the new state, from now; never shortens the current one.
    #[arg(long = "state-ttl", default_value = Ttl::DEFAULT)]
    pub(crate) ttl: Ttl,
}

/// `role rm` arguments.
#[derive(Args)]
pub(crate) struct RoleRmArgs {
    /// The role to drop.
    pub(crate) name: String,
    /// Lifetime of the new state, from now; never shortens the current one.
    #[arg(long = "state-ttl", default_value = Ttl::DEFAULT)]
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
    /// Its hosts, replacing the list (each must be a member).
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

/// Sign and store the next version of this keystore's state: the stored one
/// (or, for `wires init`, an empty one) changed by `change`, hosts
/// re-derived, version + 1, valid until `ttl` from now or the stored one's
/// expiry, whichever is later (an edit never shortens the state's
/// lifetime). Validation failures name the broken rule.
pub(crate) fn edit_state(
    ks: &Keystore,
    ttl: Ttl,
    change: impl FnOnce(&mut State) -> Result<()>,
) -> Result<SignedState> {
    let root = ks
        .read_root_identity()?
        .ok_or_else(|| anyhow!("no root key here; run `wires init` first (on the admin)"))?;
    let held = store::read(ks, root.node_id())?;
    let mut next = match &held {
        Some(s) => s.state.clone(),
        None => State::new(root.node_id()),
    };
    change(&mut next)?;
    next.hosts = next
        .services
        .values()
        .flat_map(|s| s.hosts.iter().copied())
        .collect();
    let now = now_unix();
    next.version = StateVersion(next.version.0 + 1);
    next.issued = now;
    next.not_after = ttl
        .not_after(now)
        .max(held.as_ref().map_or(i64::MIN, |s| s.state.not_after));
    let signed = next.sign(&root).context("the new state is not valid")?;
    if !store::adopt_if_newer(ks, &signed, root.node_id(), now)? {
        bail!("another admin command changed the state meanwhile; run this one again");
    }
    Ok(signed)
}

/// `wires service add <name>`: register a new service.
pub(crate) fn add(
    ks: &Keystore,
    name: ServiceName,
    edit: ServiceEdit,
    ttl: Ttl,
) -> Result<SignedState> {
    edit_state(ks, ttl, |s| {
        if s.services.contains_key(&name) {
            bail!("service {name} already exists; change it with `wires service set`");
        }
        check_hosts(s, edit.hosts.as_deref())?;
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
pub(crate) fn set(
    ks: &Keystore,
    name: ServiceName,
    edit: ServiceEdit,
    ttl: Ttl,
) -> Result<SignedState> {
    edit_state(ks, ttl, |s| {
        check_hosts(s, edit.hosts.as_deref())?;
        let svc = s
            .services
            .get_mut(&name)
            .ok_or_else(|| anyhow!("no service {name}; register it with `wires service add`"))?;
        edit.apply(svc);
        Ok(())
    })
}

/// `wires service rm <name>`: drop a service.
pub(crate) fn rm(ks: &Keystore, name: ServiceName, ttl: Ttl) -> Result<SignedState> {
    edit_state(ks, ttl, |s| {
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
) -> Result<SignedState> {
    if matchers.is_empty() {
        bail!("a role needs at least one matcher");
    }
    edit_state(ks, ttl, |s| {
        s.roles.insert(name, matchers);
        Ok(())
    })
}

/// `wires role rm <name>`: drop a role (refused while a service names it).
pub(crate) fn role_rm(ks: &Keystore, name: RoleName, ttl: Ttl) -> Result<SignedState> {
    edit_state(ks, ttl, |s| {
        if s.roles.remove(&name).is_none() {
            bail!("no role {name}");
        }
        Ok(())
    })
}

/// Each proposed host must be a member.
fn check_hosts(s: &State, hosts: Option<&[NodeId]>) -> Result<()> {
    for h in hosts.unwrap_or_default() {
        if !s.is_member(*h) {
            bail!(
                "{} is not a member; `wires invite` it first",
                &h.hex()[..16]
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

/// `--host` labels or ids → node ids, through the admin's `names.json`.
fn host_ids(ks: &Keystore, texts: &[String]) -> Result<Option<Vec<NodeId>>> {
    if texts.is_empty() {
        return Ok(None);
    }
    let names = ks.read_names()?;
    let mut out = Vec::new();
    for t in texts {
        let (id, _) = resolve_member(&names, t)?;
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

/// Run a `service` subcommand against `ks` (no push): what changed.
pub(crate) fn service_in(ks: &Keystore, a: ServiceArgs) -> Result<(String, SignedState)> {
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
    Ok((
        format!(
            "service {name} {verb} (state version {})",
            signed.state.version.0
        ),
        signed,
    ))
}

/// Run a `role` subcommand against `ks` (no push): what changed.
pub(crate) fn role_in(ks: &Keystore, a: RoleArgs) -> Result<(String, SignedState)> {
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
    Ok((
        format!(
            "role {name} {verb} (state version {})",
            signed.state.version.0
        ),
        signed,
    ))
}

/// Push the stored state to the hosts (and `earlier`, the hosts before the
/// edit) and fold the outcome into a [`Report`].
async fn pushed(ks: &Keystore, stdout: String, earlier: &BTreeSet<NodeId>) -> Result<Report> {
    let report = Report {
        stdout,
        notes: Vec::new(),
        failure: None,
    };
    Ok(propagate::fold(
        report,
        propagate::propagate(ks, earlier).await,
    ))
}

/// `wires service …` against the resolved keystore, then push.
pub(crate) async fn service_cmd(a: ServiceArgs) -> Result<Report> {
    let ks = Keystore::resolve()?;
    let earlier = sync::held_hosts(&ks)?;
    let (stdout, _) = service_in(&ks, a)?;
    pushed(&ks, stdout, &earlier).await
}

/// `wires role …` against the resolved keystore, then push.
pub(crate) async fn role_cmd(a: RoleArgs) -> Result<Report> {
    let ks = Keystore::resolve()?;
    let earlier = sync::held_hosts(&ks)?;
    let (stdout, _) = role_in(&ks, a)?;
    pushed(&ks, stdout, &earlier).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::init::{InitArgs, init_in};
    use crate::testutil::temp_dir;
    use library::NodeIdentity;
    use proptest::prelude::*;

    /// An initialized admin keystore with `extra` more members in its state.
    pub(crate) fn admin_with(extra: &[NodeId]) -> Keystore {
        let ks = Keystore::at(temp_dir());
        init_in(&ks, InitArgs::default()).unwrap();
        let extra = extra.to_vec();
        edit_state(&ks, ttl(), |s| {
            s.members.extend(extra);
            Ok(())
        })
        .unwrap();
        ks
    }

    fn ttl() -> Ttl {
        Ttl::DEFAULT.parse().unwrap()
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
        let v0 = store::read(&ks, root).unwrap().unwrap().state.version;

        let s = role_set(
            &ks,
            role("analyst"),
            vec![parse_matcher("*@x.com", GOOGLE_ISSUER).unwrap()],
            ttl(),
        )
        .unwrap();
        assert_eq!(s.state.version, StateVersion(v0.0 + 1));
        let edit = ServiceEdit {
            description: Some("orders".into()),
            allow: Some(vec![role("analyst")]),
            hosts: Some(vec![host]),
            readers: None,
        };
        let s = add(&ks, svc("orders-db"), edit.clone(), ttl()).unwrap();
        assert!(s.state.assigns(&svc("orders-db"), host));
        assert!(s.state.is_host(host));
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
        assert_eq!(s.state.services[&svc("orders-db")].description, "new");
        assert_eq!(s.state.services[&svc("orders-db")].hosts, vec![host]);
        assert!(set(&ks, svc("nope"), ServiceEdit::default(), ttl()).is_err());

        // A role still in use can't go; after the service goes, it can.
        assert!(role_rm(&ks, role("analyst"), ttl()).is_err());
        let s = rm(&ks, svc("orders-db"), ttl()).unwrap();
        assert!(!s.state.is_host(host), "no service left, no longer a host");
        role_rm(&ks, role("analyst"), ttl()).unwrap();
        let stored = store::read(&ks, root).unwrap().unwrap();
        assert_eq!(stored.state.version, StateVersion(v0.0 + 5));
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
        assert!(add(&ks, svc("x"), edit, ttl()).is_err(), "not a member");
        let edit = ServiceEdit {
            allow: Some(vec![role("ghost")]),
            ..Default::default()
        };
        assert!(add(&ks, svc("x"), edit, ttl()).is_err(), "undefined role");
        assert_eq!(store::read(&ks, root).unwrap().unwrap(), before);
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

    /// Run `wires role …` (the parsed command line) against `ks`.
    fn role_cli(ks: &Keystore, args: &[&str]) -> Result<SignedState> {
        use crate::{Cli, Command};
        use clap::Parser;
        let cli = Cli::try_parse_from(["wires", "role"].iter().chain(args))?;
        let Command::Role(a) = cli.command else {
            panic!("expected role");
        };
        role_in(ks, a).map(|(_, s)| s)
    }

    #[test]
    fn role_set_names_google_unless_told_otherwise() {
        let ks = admin_with(&[]);
        let s = role_cli(&ks, &["set", "analyst", "*@acme.com", "alice@x.com"]).unwrap();
        let ms = &s.state.roles[&role("analyst")];
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
        let ms = &s.state.roles[&role("analyst")];
        assert_eq!(ms[0].issuer, "https://acme.okta.com");
        assert_eq!(ms[1].issuer, "https://other");
    }

    #[test]
    fn member_is_an_ordinary_role_name() {
        let ks = admin_with(&[]);
        let s = role_cli(&ks, &["set", "member", "issuer=https://idp"]).unwrap();
        assert_eq!(
            s.state.roles[&role("member")],
            vec![Matcher::new("https://idp")]
        );
        role_cli(&ks, &["rm", "member"]).unwrap();
        // Undefined, `member` is an unknown role like any other.
        let edit = ServiceEdit {
            allow: Some(vec![role("member")]),
            ..Default::default()
        };
        assert!(add(&ks, svc("x"), edit, ttl()).is_err());
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
                let before = store::read(&ks, root).unwrap().unwrap().state.version;
                let after = set(&ks, svc("s"), ServiceEdit { description: Some(d), ..Default::default() }, ttl())
                    .unwrap()
                    .state
                    .version;
                prop_assert_eq!(after, StateVersion(before.0 + 1));
            }
        }
    }
}

//! `wires remove <who>` and `wires restore <who>`: bans in the signed
//! policy, by person or by node.
//!
//! - **An email** is a **person ban**, and how a person is removed: every
//!   host and every directory refuses that person from any machine (each
//!   gate checks the verified principal, [`library::check_admitted`]). The
//!   issuer is `--issuer`, by default the one the network string names (the
//!   issuer `wires login` signs in with).
//! - **A node id or label** ([`super::labels`]) is a **node ban**: the node
//!   is refused everywhere, whoever signs in on it, and is dropped from
//!   every service's hosts and from the directories. It removes a host or
//!   directory machine, or one specific key; it doesn't keep a person out
//!   (a new key is one `WIRES_HOME` away).
//!
//! A ban has no expiry: it holds until `wires restore` lifts it. Each is an
//! edit, published to the directories; a host refuses the next call once it
//! holds the new policy (it re-reads its policy per connection, so no
//! restart). Disabling someone at the IdP also cuts them off, within one
//! token lifetime, with no wires action.

use anyhow::{Result, bail};
use clap::Args;
use library::{Issuer, NodeId, Person, Policy};

use super::keystore::{self, Keystore};
use super::labels::{Labels, Named};
use super::service::edit_policy;
use super::ttl::Ttl;
use super::{Report, run_edit};

/// `remove` and `restore` arguments.
#[derive(Args)]
pub(crate) struct WhoArgs {
    /// A person's email, or a node's label or id
    pub(crate) who: String,
    /// The IdP that verifies the email: its exact `iss` (default: the one
    /// the network string names).
    #[arg(long)]
    pub(crate) issuer: Option<String>,
    /// Lifetime of the new signed policy, from now (`90d`, `12h`, … or
    /// seconds). Never shortens the current policy's expiry.
    #[arg(long, default_value = Ttl::POLICY_DEFAULT, hide = true)]
    pub(crate) policy_ttl: Ttl,
}

/// Who a `remove` or `restore` names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Who {
    /// A person, by issuer and email.
    Person(Person),
    /// A node, by id (and the admin's label for it).
    Node(Named),
}

impl std::fmt::Display for Who {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Who::Person(p) => write!(f, "{p}"),
            Who::Node(n) => write!(f, "node {n}"),
        }
    }
}

/// The issuer `role set` and `remove` assume when none is given: the one
/// the network string names (`init`'s, or `issuer set --login`'s), else
/// Google.
pub(crate) fn default_issuer(ks: &Keystore, policy: &Policy) -> Result<Issuer> {
    Ok(super::login_client::LoginClient::load(ks)?
        .settings(policy)
        .map(|s| s.issuer)
        .unwrap_or_else(|| Issuer::new(library::GOOGLE_ISSUER)))
}

/// Parse `a.who` against `ks`: an email (with `@`) is a person, anything
/// else a node (binding a label written `label=<node id>`).
fn parse_who(ks: &Keystore, policy: &Policy, a: &WhoArgs) -> Result<Who> {
    let text = a.who.trim();
    if text.contains('@') && !text.contains('=') {
        let issuer = match &a.issuer {
            Some(iss) if !iss.trim().is_empty() => Issuer::new(iss.trim()),
            Some(_) => bail!("--issuer is empty"),
            None => default_issuer(ks, policy)?,
        };
        let (local, domain) = text.split_once('@').unwrap_or_default();
        if local.is_empty() || domain.is_empty() || text.chars().any(char::is_whitespace) {
            bail!("{text:?} is not an email address");
        }
        return Ok(Who::Person(Person::new(issuer, text)));
    }
    if a.issuer.is_some() {
        bail!("--issuer applies to a person (an email), not to a node");
    }
    let mut labels = Labels::load(ks)?;
    let before = labels.clone();
    let named = labels.resolve(text)?;
    if labels != before {
        labels.save(ks)?;
    }
    Ok(Who::Node(named))
}

/// `remove` against the resolved keystore, then published.
pub(crate) async fn remove_cmd(a: WhoArgs) -> Result<Report> {
    run_edit(|ks| remove_in(ks, a)).await
}

/// `restore` against the resolved keystore, then published.
pub(crate) async fn restore_cmd(a: WhoArgs) -> Result<Report> {
    run_edit(|ks| restore_in(ks, a)).await
}

/// The admin's stored policy (refusing a keystore that isn't the admin's).
fn admin_held(ks: &Keystore) -> Result<crate::policy::store::Held> {
    let root = ks
        .read_root_identity()?
        .ok_or_else(|| anyhow::anyhow!("no root key here: this runs on the admin"))?;
    super::service::admin_policy(ks, root.node_id())
}

/// [`remove_cmd`] against an explicit keystore, without the publish (the
/// testable form).
pub(crate) fn remove_in(ks: &Keystore, a: WhoArgs) -> Result<Report> {
    let held = admin_held(ks)?;
    let who = parse_who(ks, &held.policy, &a)?;
    let state = match &who {
        Who::Person(person) => {
            if !held.policy.issuers.contains_key(&person.issuer) {
                bail!(
                    "{} is not a trusted issuer, so it admits nobody to ban; pass the issuer \
                     that verifies {} with --issuer",
                    person.issuer,
                    person.email()
                );
            }
            edit_policy(ks, a.policy_ttl, |p| {
                if !p.ban_person(person.clone()) {
                    bail!("{person} is already removed");
                }
                Ok(())
            })?
        }
        Who::Node(named) => {
            let node = named.node;
            refuse_own_node(ks, node)?;
            edit_policy(ks, a.policy_ttl, |p| {
                if !p.ban(node) {
                    bail!("node {named} is already removed");
                }
                for svc in p.services.values_mut() {
                    svc.hosts.retain(|h| *h != node);
                }
                p.directories.retain(|d| *d != node);
                Ok(())
            })?
        }
    };
    Ok(Report {
        stdout: format!(
            "removed {who} (policy version {}; {} node and {} person ban(s); `wires restore` \
             lifts it)",
            state.version().0,
            state.policy.bans.len(),
            state.policy.person_bans.len()
        ),
        ..Report::default()
    })
}

/// [`restore_cmd`] against an explicit keystore, without the publish.
pub(crate) fn restore_in(ks: &Keystore, a: WhoArgs) -> Result<Report> {
    let held = admin_held(ks)?;
    let who = parse_who(ks, &held.policy, &a)?;
    let state = edit_policy(ks, a.policy_ttl, |p| {
        let lifted = match &who {
            Who::Person(person) => p.unban_person(person),
            Who::Node(named) => p.unban(named.node),
        };
        if !lifted {
            bail!("{who} is not removed");
        }
        Ok(())
    })?;
    let after = match &who {
        Who::Person(_) => String::new(),
        Who::Node(_) => {
            "; it hosts nothing and is no directory until you add it again (`wires service set \
             --host`, `wires directory add`)"
                .to_string()
        }
    };
    Ok(Report {
        stdout: format!(
            "restored {who} (policy version {}){after}",
            state.version().0
        ),
        ..Report::default()
    })
}

/// Refuse to ban this machine's own node: nobody would be left to publish
/// the next policy from.
fn refuse_own_node(ks: &Keystore, node: NodeId) -> Result<()> {
    if node == keystore::node_identity_in(ks)?.node_id() {
        bail!(
            "{} is this machine's own node: removing it would leave nobody to sign and publish \
             the next policy from",
            node.hex()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::init::{InitArgs, init_in};
    use library::NodeIdentity;

    fn admin() -> Keystore {
        let ks = Keystore::at(crate::testutil::temp_dir());
        init_in(&ks, InitArgs::default()).unwrap();
        ks
    }

    fn who(text: &str) -> WhoArgs {
        WhoArgs {
            who: text.into(),
            issuer: None,
            policy_ttl: Ttl::default(),
        }
    }

    fn stored(ks: &Keystore) -> crate::policy::store::Held {
        let root = ks.read_root_identity().unwrap().unwrap().node_id();
        crate::policy::store::read(ks, root).unwrap().unwrap()
    }

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    #[test]
    fn removing_a_person_bans_them_under_the_login_issuer_until_restored() {
        let ks = admin();
        let out = remove_in(&ks, who("Eve@Example.com")).unwrap().stdout;
        assert!(out.contains("eve@example.com"), "{out}");
        let held = stored(&ks);
        let eve = Person::new(Issuer::new(library::GOOGLE_ISSUER), "eve@example.com");
        assert!(held.policy.person_bans.contains(&eve));
        assert_eq!(held.version(), library::StateVersion(2));
        // Twice is refused, and changes nothing.
        let e = remove_in(&ks, who("eve@example.com")).unwrap_err();
        assert!(format!("{e:#}").contains("already removed"), "{e:#}");
        assert_eq!(stored(&ks).version(), library::StateVersion(2));
        // Restore lifts it; restoring again is refused.
        restore_in(&ks, who("eve@example.com")).unwrap();
        assert!(stored(&ks).policy.person_bans.is_empty());
        let e = restore_in(&ks, who("eve@example.com")).unwrap_err();
        assert!(format!("{e:#}").contains("not removed"), "{e:#}");
    }

    #[test]
    fn a_person_ban_needs_a_trusted_issuer() {
        let ks = admin();
        let a = WhoArgs {
            issuer: Some("https://untrusted.example".into()),
            ..who("eve@example.com")
        };
        let e = remove_in(&ks, a).unwrap_err();
        assert!(format!("{e:#}").contains("not a trusted issuer"), "{e:#}");
        let a = WhoArgs {
            issuer: Some(library::GOOGLE_ISSUER.into()),
            ..who(&node(2).hex())
        };
        assert!(remove_in(&ks, a).is_err(), "--issuer is for a person");
    }

    #[test]
    fn removing_a_node_drops_it_from_hosts_and_directories() {
        let ks = admin();
        crate::admin::service::directory_add(&ks, node(4), Ttl::default()).unwrap();
        let out = remove_in(&ks, who(&format!("dir={}", node(4).hex())))
            .unwrap()
            .stdout;
        assert!(out.contains("dir"), "{out}");
        let held = stored(&ks);
        assert!(held.policy.bans_node(node(4)));
        assert!(held.directories().is_empty());
        // The label stays, for restore.
        let out = restore_in(&ks, who("dir")).unwrap().stdout;
        assert!(out.contains("hosts nothing"), "{out}");
        assert!(!stored(&ks).policy.bans_node(node(4)));
        assert!(stored(&ks).directories().is_empty(), "not put back");
    }

    #[test]
    fn this_machines_own_node_is_never_removed() {
        let ks = admin();
        let me = keystore::node_identity_in(&ks).unwrap().node_id();
        let e = remove_in(&ks, who(&me.hex())).unwrap_err();
        assert!(format!("{e:#}").contains("own node"), "{e:#}");
    }

    /// Under strict freshness, removing the last directory would leave
    /// nothing to vouch for the policy: refused, naming the way out, and
    /// nothing changes.
    #[test]
    fn removing_the_last_directory_under_strict_is_refused() {
        let ks = admin();
        let dir = node(4);
        crate::admin::service::directory_add(&ks, dir, Ttl::default()).unwrap();
        crate::admin::settings::settings_in(
            &ks,
            &crate::admin::settings::SettingsArgs {
                freshness: Some(crate::admin::settings::Freshness::Strict),
                ..Default::default()
            },
        )
        .unwrap();
        let before = stored(&ks).version();
        let err = format!("{:#}", remove_in(&ks, who(&dir.hex())).unwrap_err());
        assert!(err.contains("freshness is strict"), "{err}");
        assert!(err.contains("--freshness lenient"), "{err}");
        assert_eq!(stored(&ks).version(), before);
        assert_eq!(stored(&ks).directories(), &[dir]);
    }

    #[test]
    fn not_an_email_and_not_a_node_is_refused() {
        let ks = admin();
        for bad in ["@example.com", "eve@", "nobody"] {
            assert!(remove_in(&ks, who(bad)).is_err(), "{bad}");
        }
    }
}

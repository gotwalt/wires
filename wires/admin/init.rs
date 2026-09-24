//! `wires init`: a new network in one step.
//!
//! Creates the root key and this machine's node key in one keystore, mints
//! this node's badge (its membership: the admin's node is admitted like any
//! other, which is what lets it publish every later policy to the
//! directories by key), records it in the ledger, and signs the first
//! policy: one trusted IdP (its `issuer` item, Google unless `--issuer`
//! says otherwise: every role's matchers must name a trusted issuer), no
//! roles, no services, no bans, no directories yet.

use anyhow::{Context, bail};
use clap::Args;
use library::{GOOGLE_ISSUER, Issuer, Membership, NodeIdentity};

use super::keystore::Keystore;
use super::ledger::Ledger;
use super::ttl::Ttl;
use crate::clock::now_unix;

/// `init` arguments.
#[derive(Args)]
pub(crate) struct InitArgs {
    /// Lifetime of this node's badge (`30d`, `12h`, … or seconds; at most 30d).
    #[arg(long, default_value = Ttl::DEFAULT)]
    pub(crate) ttl: Ttl,
    /// Lifetime of the first signed policy.
    #[arg(long, default_value = Ttl::POLICY_DEFAULT, hide = true)]
    pub(crate) state_ttl: Ttl,
    /// The IdP the network trusts first: its exact `iss` (more: `wires issuer set`).
    #[arg(long, default_value = GOOGLE_ISSUER)]
    pub(crate) issuer: String,
    /// The OAuth client id `wires login` signs in under (or `$WIRES_OIDC_CLIENT_ID`).
    #[arg(long)]
    pub(crate) client_id: Option<String>,
    /// An `aud` value hosts accept from that IdP (repeatable; default: the client id).
    #[arg(long = "audience")]
    pub(crate) audience: Vec<String>,
    /// That client's public secret, which invites carry to `wires login`.
    // A Google "Desktop app" client's, which its token endpoint requires and
    // which is not confidential. Never pass a confidential secret.
    #[arg(long)]
    pub(crate) public_client_secret: Option<String>,
}

#[cfg(test)]
impl Default for InitArgs {
    /// The default lifetimes, Google, and a test client id.
    fn default() -> Self {
        Self {
            ttl: Ttl::default(),
            state_ttl: Ttl::policy_default(),
            issuer: GOOGLE_ISSUER.to_string(),
            client_id: Some("wires-test-client".into()),
            audience: Vec::new(),
            public_client_secret: None,
        }
    }
}

/// `init` against the resolved keystore.
pub(crate) fn init_cmd(a: InitArgs) -> anyhow::Result<String> {
    init_in(&Keystore::resolve()?, a)
}

/// [`init_cmd`] against an explicit keystore (the testable form).
pub(crate) fn init_in(ks: &Keystore, a: InitArgs) -> anyhow::Result<String> {
    if let Some(fabric) = crate::policy::store::fabric(ks)? {
        bail!(
            "this keystore is already in network {}…; `wires init` starts a new network — use \
             another $WIRES_HOME for that",
            fabric.short()
        );
    }
    let client_id = a
        .client_id
        .clone()
        .or_else(|| std::env::var("WIRES_OIDC_CLIENT_ID").ok())
        .filter(|c| !c.trim().is_empty())
        .with_context(|| {
            format!(
                "no OAuth client id for {}: pass --client-id (or set $WIRES_OIDC_CLIENT_ID); \
                 every role names a trusted IdP, and `wires login` signs in under this client id",
                a.issuer
            )
        })?;
    let issuer = Issuer::new(a.issuer.trim());
    let config = super::service::issuer_config(&client_id, &a.audience)?;
    let root = match ks.read_root_identity()? {
        Some(root) => root,
        None => {
            let root = NodeIdentity::generate();
            ks.save_root(&root)?;
            root
        }
    };
    let me = match ks.read_node_identity()? {
        Some(node) => node,
        None => {
            let node = NodeIdentity::generate();
            ks.save_node(&node)?;
            node
        }
    };

    let now = now_unix();
    let badge = Membership::mint(&root, me.node_id(), now, a.ttl.badge()?.not_after(now))?;
    ks.save_membership(&badge)?;
    let mut ledger = Ledger::load(ks)?;
    ledger.record(me.node_id(), None, badge.not_after);
    ledger.save(ks)?;
    let held = super::service::edit_policy(ks, a.state_ttl, |p| {
        p.issuers.insert(issuer.clone(), config);
        Ok(())
    })?;
    // Card 37: invites tell `wires login` to sign in here.
    super::login_client::LoginClient::record(ks, &issuer, a.public_client_secret.as_deref(), true)?;

    Ok(format!(
        "network {}\nnode {}\npolicy version {} (trusts {issuer})\n\
         next: on each joining machine run `wires id`, then here `wires invite <node-id> --name \
         <label>`; name a directory with `wires directory add <label>`",
        root.node_id().hex(),
        me.node_id().hex(),
        held.version().0,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;

    #[test]
    fn init_badges_this_node_and_signs_a_policy_trusting_one_idp() {
        let ks = Keystore::at(temp_dir());
        let out = init_in(&ks, InitArgs::default()).unwrap();
        let root = ks.read_root_identity().unwrap().unwrap();
        let me = ks.read_node_identity().unwrap().unwrap();
        assert!(out.contains(&root.node_id().hex()), "{out}");
        assert!(out.contains(&me.node_id().hex()), "{out}");

        let membership = ks.read_membership().unwrap().unwrap();
        assert_eq!(membership.member, me.node_id());
        assert_eq!(membership.fabric, root.node_id());
        let held = crate::policy::store::read(&ks, root.node_id())
            .unwrap()
            .unwrap();
        assert_eq!(held.version(), library::StateVersion(1));
        assert!(held.policy.services.is_empty());
        assert!(held.policy.bans.is_empty());
        assert!(held.directories().is_empty());
        let google = &held.policy.issuers[&Issuer::new(GOOGLE_ISSUER)];
        assert_eq!(google.client_id.as_str(), "wires-test-client");
        assert_eq!(google.audiences, vec![google.client_id.clone()]);
        // 90 days by default: freshness, not expiry, keeps copies current.
        assert!(held.policy.not_after >= now_unix() + 89 * 86_400);
        let ledger = Ledger::load(&ks).unwrap();
        assert_eq!(
            ledger.get(me.node_id()).map(|i| i.not_after),
            Some(membership.not_after)
        );
    }

    #[test]
    fn init_names_another_idp_and_needs_a_client_id() {
        let ks = Keystore::at(temp_dir());
        let a = InitArgs {
            issuer: "https://idp.example".into(),
            client_id: Some("cli".into()),
            audience: vec!["api://a".into(), "api://b".into()],
            ..InitArgs::default()
        };
        init_in(&ks, a).unwrap();
        let root = ks.read_root_identity().unwrap().unwrap().node_id();
        let held = crate::policy::store::read(&ks, root).unwrap().unwrap();
        let idp = &held.policy.issuers[&Issuer::new("https://idp.example")];
        assert_eq!(idp.audiences.len(), 2);
        assert!(
            !held
                .policy
                .issuers
                .contains_key(&Issuer::new(GOOGLE_ISSUER))
        );

        let ks = Keystore::at(temp_dir());
        let a = InitArgs {
            client_id: Some("  ".into()),
            ..InitArgs::default()
        };
        let e = init_in(&ks, a).unwrap_err();
        assert!(format!("{e:#}").contains("--client-id"), "{e:#}");
        assert!(ks.read_root_identity().unwrap().is_none(), "nothing made");
    }

    #[test]
    fn init_twice_is_refused_and_an_existing_node_key_is_kept() {
        let ks = Keystore::at(temp_dir());
        let node = NodeIdentity::from_seed([5u8; 32]);
        ks.save_node(&node).unwrap();
        init_in(&ks, InitArgs::default()).unwrap();
        assert_eq!(
            ks.read_node_identity().unwrap().unwrap().node_id(),
            node.node_id()
        );
        let err = init_in(&ks, InitArgs::default()).unwrap_err();
        assert!(format!("{err:#}").contains("already in network"), "{err:#}");
    }
}

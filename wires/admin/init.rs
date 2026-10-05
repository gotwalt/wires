//! `wires init`: a new network in one step.
//!
//! Creates the root key and this machine's node key (what it dials the
//! directories with when it publishes) in one keystore, and signs the first
//! policy: one trusted IdP (its `issuer` item, Google unless `--issuer`
//! says otherwise: every role's matchers must name a trusted issuer), no
//! roles, no services, no bans, no directories yet. Nothing is minted for
//! any node and nothing is published: the network string (`wires network`)
//! is what every other node joins with.

use anyhow::{Context, bail};
use clap::Args;
use library::{GOOGLE_ISSUER, Issuer, NodeIdentity};

use super::keystore::Keystore;
use super::ttl::Ttl;

/// `init` arguments.
#[derive(Args)]
pub(crate) struct InitArgs {
    /// Lifetime of the first signed policy.
    #[arg(long, default_value = Ttl::POLICY_DEFAULT, hide = true)]
    pub(crate) policy_ttl: Ttl,
    /// The IdP the network trusts first: its exact `iss` (more: `wires issuer set`).
    #[arg(long, default_value = GOOGLE_ISSUER)]
    pub(crate) issuer: String,
    /// The OAuth client id `wires login` signs in under (or `$WIRES_OIDC_CLIENT_ID`).
    #[arg(long)]
    pub(crate) client_id: Option<String>,
    /// An `aud` value hosts accept from that IdP (repeatable; default: the client id).
    #[arg(long = "audience")]
    pub(crate) audience: Vec<String>,
    /// That client's public secret, which the network string carries to `wires login`.
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
            policy_ttl: Ttl::policy_default(),
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
    if let Some(fabric) = ks.network_root()? {
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

    let held = super::service::first_policy(ks, a.policy_ttl, |p| {
        p.issuers.insert(issuer.clone(), config);
        Ok(())
    })?;
    // The network string tells `wires login` to sign in here.
    super::login_client::LoginClient::record(ks, &issuer, a.public_client_secret.as_deref(), true)?;

    Ok(format!(
        "network {}\nnode {}\npolicy version {} (trusts {issuer}), stored here\n\
         next: run `wires id` on the machine that will be the directory, then `wires directory \
         add <label>=<node id>` here; `wires network` prints the string every node joins with",
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
    fn init_makes_the_keys_and_signs_a_policy_trusting_one_idp() {
        let ks = Keystore::at(temp_dir());
        let out = init_in(&ks, InitArgs::default()).unwrap();
        let root = ks.read_root_identity().unwrap().unwrap();
        let me = ks.read_node_identity().unwrap().unwrap();
        assert!(out.contains(&root.node_id().hex()), "{out}");
        assert!(out.contains(&me.node_id().hex()), "{out}");

        // Nothing minted, nothing joined: the root key names the network.
        assert!(ks.read_network().unwrap().is_none());
        assert_eq!(ks.network_root().unwrap(), Some(root.node_id()));
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
        assert!(held.policy.not_after >= crate::clock::now_unix() + 89 * 86_400);
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

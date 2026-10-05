//! `wires id` and `wires join <network>`: what a node runs to be in a
//! network, signing nobody in.
//!
//! The network string ([`library::Network`], printed by the admin's `wires
//! network`) is the same for every node and not secret: the root key, the
//! first directories, the login settings. `wires join` checks it decodes
//! and stores it as `network.json`, making the node key first if there is
//! none; it contacts nobody. That is all a host, a directory or the gateway
//! needs: the admin names hosts and directories by key in the signed policy
//! (`wires id` prints this node's), a host fetches its policy from a
//! directory, and the first directory takes the admin's first publish.
//!
//! A caller runs `wires login <network>` instead, which joins the same way
//! ([`join_in`]) and then signs in ([`crate::caller::login`]).

use anyhow::{Context, bail};
use clap::Args;
use library::{Network, NodeId, NodeIdentity};

use crate::admin::keystore::{self, Keystore};

/// `join` arguments.
#[derive(Args)]
pub(crate) struct JoinArgs {
    /// The network string your admin prints with `wires network`.
    pub(crate) network: String,
}

/// `id`: this node's id, creating the node key on first use.
pub(crate) fn id_cmd() -> anyhow::Result<String> {
    let (id, created) = id_in(&Keystore::resolve()?)?;
    if created {
        eprintln!("wires id: generated this node's key (node.seed)");
    }
    Ok(id.hex())
}

/// [`id_cmd`] against an explicit keystore: the node id, and whether the key
/// was generated just now.
pub(crate) fn id_in(ks: &Keystore) -> anyhow::Result<(NodeId, bool)> {
    if let Ok(node) = keystore::node_identity_in(ks) {
        return Ok((node.node_id(), false));
    }
    let node = NodeIdentity::generate();
    ks.save_node(&node)?;
    Ok((node.node_id(), true))
}

/// `join`: install the network string; say what this node is and what's
/// next.
pub(crate) fn join_cmd(a: JoinArgs) -> anyhow::Result<String> {
    let ks = Keystore::resolve()?;
    let network = join_in(&ks, &a.network)?;
    let me = keystore::node_identity_in(&ks)?.node_id();
    Ok(format!(
        "joined network {}… as node {}\nnext: a host runs `wires serve host.json`, a \
         directory `wires directory serve` (the admin names this node by that id); a caller \
         runs `wires login` instead",
        network.root.short(),
        me.hex()
    ))
}

/// [`join_cmd`] against an explicit keystore (the testable form): decode
/// `text`, make the node key if there is none, and store the string. A
/// keystore already in a *different* network is refused (one keystore, one
/// network: use another `$WIRES_HOME`), and so is the admin's own (its root
/// key names its network). Joining the same network again rewrites the
/// string (its directories may have changed).
pub(crate) fn join_in(ks: &Keystore, text: &str) -> anyhow::Result<Network> {
    let network = Network::decode(text).context(
        "the network string does not decode; paste it whole (`wires network` on the admin \
         prints it)",
    )?;
    if ks.read_root_identity()?.is_some() {
        bail!(
            "{} is the admin's keystore (it holds root.seed): it is in its network already; \
             join from the node's own keystore (WIRES_HOME=<another dir>)",
            ks.path("").display()
        );
    }
    if let Some(held) = ks.read_network()?
        && held.root != network.root
    {
        bail!(
            "this keystore is already in network {}…; the string is for network {}… — use \
             another $WIRES_HOME to join a second network",
            held.root.short(),
            network.root.short()
        );
    }
    id_in(ks)?;
    ks.save_network(&network)?;
    Ok(network)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;
    use library::{Audience, Issuer, LoginSettings};

    fn network(root: u8) -> Network {
        Network::new(
            NodeIdentity::from_seed([root; 32]).node_id(),
            vec![NodeIdentity::from_seed([4u8; 32]).node_id()],
            LoginSettings {
                issuer: Issuer::new("https://idp.example"),
                client_id: Audience::new("desktop-client"),
                public_client_secret: None,
            },
        )
    }

    #[test]
    fn id_creates_the_key_once() {
        let ks = Keystore::at(temp_dir());
        let (first, created) = id_in(&ks).unwrap();
        assert!(created);
        assert_eq!(id_in(&ks).unwrap(), (first, false));
    }

    #[test]
    fn join_stores_the_string_and_makes_the_key_and_nothing_else() {
        let ks = Keystore::at(temp_dir());
        let joined = join_in(&ks, &network(1).encode().unwrap()).unwrap();
        assert_eq!(joined, network(1));
        assert_eq!(ks.read_network().unwrap(), Some(network(1)));
        assert!(ks.read_node_identity().unwrap().is_some(), "a key, made");
        assert!(!ks.path(crate::policy::store::POLICY_FILE).exists());
        assert!(!ks.path(crate::caller::view::VIEW_FILE).exists());
        // Again, with the same network: fine, and the key is kept.
        let me = keystore::node_identity_in(&ks).unwrap().node_id();
        join_in(&ks, &network(1).encode().unwrap()).unwrap();
        assert_eq!(keystore::node_identity_in(&ks).unwrap().node_id(), me);
    }

    #[test]
    fn join_refuses_a_second_network_garbage_and_the_admins_keystore() {
        let ks = Keystore::at(temp_dir());
        join_in(&ks, &network(1).encode().unwrap()).unwrap();
        let err = join_in(&ks, &network(66).encode().unwrap()).unwrap_err();
        assert!(
            format!("{err:#}").contains("another $WIRES_HOME"),
            "{err:#}"
        );
        assert_eq!(ks.read_network().unwrap(), Some(network(1)));
        assert!(join_in(&ks, "garbage!").is_err());

        let admin = Keystore::at(temp_dir());
        admin
            .save_root(&NodeIdentity::from_seed([1u8; 32]))
            .unwrap();
        let err = join_in(&admin, &network(1).encode().unwrap()).unwrap_err();
        assert!(format!("{err:#}").contains("admin's keystore"), "{err:#}");
        assert!(admin.read_network().unwrap().is_none());
    }
}

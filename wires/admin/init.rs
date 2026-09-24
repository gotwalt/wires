//! `wires init`: a new network in one step.
//!
//! Creates the root key and this machine's node key in one keystore, mints
//! this node's badge (its membership: the admin's node is admitted like any
//! other, which is what lets it push every later state to the hosts by key),
//! records it in the ledger, and signs the first admin-signed state: no
//! roles, no services, no bans.

use anyhow::bail;
use clap::Args;
use library::{Membership, NodeIdentity};

use super::keystore::Keystore;
use super::ledger::Ledger;
use super::ttl::Ttl;
use crate::clock::now_unix;

/// `init` arguments.
#[derive(Args)]
pub(crate) struct InitArgs {
    /// Lifetime of this node's badge (`30d`, `12h`, … or seconds; at most
    /// 30 days).
    #[arg(long, default_value = Ttl::DEFAULT)]
    pub(crate) ttl: Ttl,
    /// Lifetime of the first signed state.
    #[arg(long, default_value = Ttl::DEFAULT)]
    pub(crate) state_ttl: Ttl,
}

impl Default for InitArgs {
    /// Both lifetimes at [`Ttl::DEFAULT`].
    fn default() -> Self {
        Self {
            ttl: Ttl::default(),
            state_ttl: Ttl::default(),
        }
    }
}

/// `init` against the resolved keystore.
pub(crate) fn init_cmd(a: InitArgs) -> anyhow::Result<String> {
    init_in(&Keystore::resolve()?, a)
}

/// [`init_cmd`] against an explicit keystore (the testable form).
pub(crate) fn init_in(ks: &Keystore, a: InitArgs) -> anyhow::Result<String> {
    if let Some(fabric) = crate::state::store::fabric(ks)? {
        bail!(
            "this keystore is already in network {}…; `wires init` starts a new network — use \
             another $WIRES_HOME for that",
            fabric.short()
        );
    }
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
    let state = super::service::edit_state(ks, a.state_ttl, |_| Ok(()))?;
    crate::state::store::save_admin(ks, me.node_id())?;

    Ok(format!(
        "network {}\nnode {}\nstate version {}\n\
         next: on each joining machine run `wires id`, then here `wires invite <node-id> --name <label>`",
        root.node_id().hex(),
        me.node_id().hex(),
        state.state.version.0,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;

    #[test]
    fn init_badges_this_node_and_signs_an_empty_state() {
        let ks = Keystore::at(temp_dir());
        let out = init_in(&ks, InitArgs::default()).unwrap();
        let root = ks.read_root_identity().unwrap().unwrap();
        let me = ks.read_node_identity().unwrap().unwrap();
        assert!(out.contains(&root.node_id().hex()), "{out}");
        assert!(out.contains(&me.node_id().hex()), "{out}");

        let membership = ks.read_membership().unwrap().unwrap();
        assert_eq!(membership.member, me.node_id());
        assert_eq!(membership.fabric, root.node_id());
        let state = crate::state::store::read(&ks, root.node_id())
            .unwrap()
            .unwrap();
        assert_eq!(state.state.version, library::StateVersion(1));
        assert!(state.state.services.is_empty());
        assert!(state.state.bans.is_empty());
        let ledger = Ledger::load(&ks).unwrap();
        assert_eq!(
            ledger.get(me.node_id()).map(|i| i.not_after),
            Some(membership.not_after)
        );
        assert_eq!(
            crate::state::store::read_admin(&ks).unwrap(),
            Some(me.node_id())
        );
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

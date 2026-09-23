//! `wires init`: a new fabric in one step.
//!
//! Creates the root key and this machine's node key in one keystore, mints
//! this node's membership, and signs the first admin-signed state with this
//! node as its one member — the admin is a member too, which is what lets it
//! push every later state to the others by key.

use anyhow::bail;
use clap::Args;
use library::{Membership, NodeIdentity};

use super::keystore::Keystore;
use super::ttl::Ttl;
use crate::now_unix;

/// `init` arguments.
#[derive(Args)]
pub(crate) struct InitArgs {
    /// Lifetime of this node's membership and of the first signed state
    /// (`30d`, `12h`, … or seconds).
    #[arg(long, default_value = Ttl::DEFAULT)]
    pub(crate) ttl: Ttl,
}

/// `init` against the resolved keystore.
pub(crate) fn init_cmd(a: InitArgs) -> anyhow::Result<String> {
    init_in(&Keystore::resolve()?, a)
}

/// [`init_cmd`] against an explicit keystore (the testable form).
pub(crate) fn init_in(ks: &Keystore, a: InitArgs) -> anyhow::Result<String> {
    if let Some(fabric) = crate::state::store::fabric(ks)? {
        bail!(
            "this keystore is already in fabric {}…; `wires init` starts a new fabric — use \
             another $WIRES_HOME for that",
            &fabric.hex()[..8]
        );
    }
    let root = match ks.read_root_identity()? {
        Some(root) => root,
        None => {
            let root = NodeIdentity::generate();
            ks.save_root(&root, false)?;
            root
        }
    };
    let me = match ks.read_node_identity()? {
        Some(node) => node,
        None => {
            let node = NodeIdentity::generate();
            ks.save_node(&node, false)?;
            node
        }
    };

    let now = now_unix();
    ks.save_membership(&Membership::mint(
        &root,
        me.node_id(),
        now,
        a.ttl.not_after(now),
    )?)?;
    ks.save_names(&Default::default())?;
    let state = super::service::edit_state(ks, a.ttl, |s| {
        s.members.insert(me.node_id());
        Ok(())
    })?;
    crate::state::store::save_admin(ks, me.node_id())?;

    Ok(format!(
        "fabric {}\nnode {}\nstate version {} (1 member: this node)\n\
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

    fn args() -> InitArgs {
        InitArgs {
            ttl: Ttl::DEFAULT.parse().unwrap(),
        }
    }

    #[test]
    fn init_makes_this_node_the_first_member() {
        let ks = Keystore::at(temp_dir());
        let out = init_in(&ks, args()).unwrap();
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
        assert_eq!(state.state.members, [me.node_id()].into());
        assert!(state.state.services.is_empty());
        assert_eq!(
            crate::state::store::read_admin(&ks).unwrap(),
            Some(me.node_id())
        );
    }

    #[test]
    fn init_twice_is_refused_and_an_existing_node_key_is_kept() {
        let ks = Keystore::at(temp_dir());
        let node = NodeIdentity::from_seed([5u8; 32]);
        ks.save_node(&node, false).unwrap();
        init_in(&ks, args()).unwrap();
        assert_eq!(
            ks.read_node_identity().unwrap().unwrap().node_id(),
            node.node_id()
        );
        let err = init_in(&ks, args()).unwrap_err();
        assert!(format!("{err:#}").contains("already in fabric"), "{err:#}");
    }
}

//! `wires init`: a new fabric in one step.
//!
//! Creates the root key and this machine's node key in one keystore, puts
//! this node in the roster, commits, and installs its credentials — the
//! admin is a member too, which is what lets `wires invite` and `wires remove`
//! publish re-keys on the channel from this machine. Records the channel name
//! for every later command.

use std::collections::BTreeMap;

use anyhow::bail;
use clap::Args;
use library::{Membership, NodeIdentity, Roster};

use super::commit::{Ttl, commit_locally};
use super::keystore::Keystore;
use crate::now_unix;

/// `init` arguments.
#[derive(Args)]
pub(crate) struct InitArgs {
    /// The channel (topic name) the fabric meets on.
    #[arg(long, default_value = "ops")]
    pub(crate) channel: String,
    /// Lifetime of the first roster head and this node's membership (`30d`,
    /// `12h`, … or seconds).
    #[arg(long, default_value = Ttl::DEFAULT)]
    pub(crate) ttl: Ttl,
}

/// `init` against the resolved keystore.
pub(crate) fn init_cmd(a: InitArgs) -> anyhow::Result<String> {
    init_in(&Keystore::resolve()?, a)
}

/// [`init_cmd`] against an explicit keystore (the testable form).
///
/// Refuses a keystore that already has a roster: a second `init` would mint
/// a second fabric over the first one's files. An existing node key is kept
/// (it may already be what a peer knows this machine as); an existing root
/// key is kept too.
pub(crate) fn init_in(ks: &Keystore, a: InitArgs) -> anyhow::Result<String> {
    let channel = a.channel.trim().to_string();
    if channel.is_empty() {
        bail!("--channel: the channel name is empty");
    }
    if ks.read_roster()?.is_some() {
        bail!(
            "this keystore already has a roster ({}); `wires init` starts a new fabric — use \
             another $WIRES_HOME for that",
            ks.path("roster.json").display()
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
    let not_after = a.ttl.not_after(now);
    let mut roster = Roster::new(root.node_id());
    roster.insert(me.node_id());
    ks.save_membership(&Membership::mint(&root, me.node_id(), now, not_after)?)?;
    let rekey = commit_locally(ks, &root, &me, &mut roster, not_after)?;
    ks.save_channel(&channel)?;
    ks.save_names(&BTreeMap::new())?;
    // Card 27: the first admin-signed state, this node its one member.
    let state = super::service::edit_state(ks, a.ttl, |_| Ok(()))?;
    crate::state::store::save_admin(ks, me.node_id())?;

    Ok(format!(
        "fabric {}\nnode {}\nchannel {channel:?} (roster version {}, state version {}, 1 member: this node)\n\
         next: on each joining machine run `wires id`, then here `wires invite <node-id> --name <label>`",
        root.node_id().hex(),
        me.node_id().hex(),
        rekey.head.version.0,
        state.state.version.0,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;

    fn args(channel: &str) -> InitArgs {
        InitArgs {
            channel: channel.into(),
            ttl: Ttl::DEFAULT.parse().unwrap(),
        }
    }

    #[test]
    fn init_makes_this_node_the_first_member() {
        let ks = Keystore::at(temp_dir());
        let out = init_in(&ks, args("ops")).unwrap();
        let root = ks.read_root_identity().unwrap().unwrap();
        let me = ks.read_node_identity().unwrap().unwrap();
        assert!(out.contains(&root.node_id().hex()), "{out}");
        assert!(out.contains(&me.node_id().hex()), "{out}");

        let roster = ks.read_roster().unwrap().unwrap();
        assert!(roster.contains(&me.node_id()));
        let head = ks.read_roster_head().unwrap().unwrap();
        assert_eq!(head.version, roster.version);
        let proof = ks.read_inclusion_proof().unwrap().unwrap();
        library::check_roster_inclusion(&head, &proof, root.node_id(), me.node_id(), now_unix())
            .unwrap();
        let membership = ks.read_membership().unwrap().unwrap();
        assert_eq!(membership.member, me.node_id());
        assert_eq!(membership.fabric, root.node_id());
        assert_eq!(
            ks.latest_fabric_key().unwrap().map(|(v, _)| v),
            Some(head.version)
        );
        assert_eq!(ks.read_channel().unwrap().as_deref(), Some("ops"));
        let state = crate::state::store::read(&ks, root.node_id())
            .unwrap()
            .unwrap();
        assert_eq!(state.state.version, library::StateVersion(1));
        assert_eq!(state.state.members, [me.node_id()].into());
        assert_eq!(
            crate::state::store::read_admin(&ks).unwrap(),
            Some(me.node_id())
        );
        // The topic commands resolve with no flags at all.
        let ctx = crate::channel::context::TopicContext::resolve(
            std::sync::Arc::new(Keystore::at(ks.path(""))),
            ks.path(""),
            &crate::channel::context::TopicArgs::default(),
        )
        .unwrap();
        assert_eq!(ctx.name, "ops");
    }

    #[test]
    fn init_twice_is_refused_and_an_existing_node_key_is_kept() {
        let ks = Keystore::at(temp_dir());
        let node = NodeIdentity::from_seed([5u8; 32]);
        ks.save_node(&node, false).unwrap();
        init_in(&ks, args("eng")).unwrap();
        assert_eq!(
            ks.read_node_identity().unwrap().unwrap().node_id(),
            node.node_id()
        );
        let err = init_in(&ks, args("eng")).unwrap_err();
        assert!(
            format!("{err:#}").contains("already has a roster"),
            "{err:#}"
        );
        assert!(init_in(&Keystore::at(temp_dir()), args(" ")).is_err());
    }
}

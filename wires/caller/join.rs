//! `wires id` and `wires join`: the joiner's two steps, for any role.
//!
//! A host and a caller join the same way: send the admin this node's id
//! (`wires id`), paste back the token `wires invite` printed (`wires join
//! <token>`). Join checks the token is for this node, signed by one root
//! throughout, and not banned by its state, then installs the membership
//! (this node's badge: what admits it) and the admin-signed state where
//! every other command looks for them, and records the admin's node id to
//! pull newer states from.
//!
//! After this, newer states arrive by push from the admin (hosts only: a
//! running `serve` is what listens), or are pulled from a host on a cold
//! command or handed back in a call's `HelloAck`; nothing needs importing by
//! hand again.

use anyhow::{Context, bail};
use clap::Args;
use library::{Invite, NodeId, NodeIdentity};

use crate::admin::keystore::{self, Keystore};
use crate::clock::now_unix;

/// `join` arguments.
#[derive(Args)]
pub(crate) struct JoinArgs {
    /// The token `wires invite` printed. Omit it to print this node's id — the
    /// thing to send the admin first.
    pub(crate) token: Option<String>,
}

/// `id`: this node's id, creating the node key on first use.
pub(crate) fn id_cmd() -> anyhow::Result<String> {
    let (id, created) = id_in(&Keystore::resolve()?)?;
    if created {
        eprintln!("wires id: generated this node's key (node.seed); send the id to your admin");
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

/// `join`: install the token, or print this node's id when there is none.
pub(crate) fn join_cmd(a: JoinArgs) -> anyhow::Result<String> {
    let ks = Keystore::resolve()?;
    match a.token {
        Some(token) => join_in(&ks, &token, now_unix()),
        None => {
            let (id, _) = id_in(&ks)?;
            Ok(format!(
                "{}\nsend this node id to your admin; they run `wires invite {}` and send back \
                 the token for `wires join <token>`",
                id.hex(),
                id.hex()
            ))
        }
    }
}

/// [`join_cmd`] with a token, against an explicit keystore (the testable
/// form). Returns the summary for stdout.
///
/// Nothing is written until the whole token has verified. A keystore already
/// in a *different* fabric is refused (one keystore, one fabric — use another
/// `$WIRES_HOME`); re-joining the same fabric never moves the stored state
/// backwards.
pub(crate) fn join_in(ks: &Keystore, token: &str, now: i64) -> anyhow::Result<String> {
    let invite = Invite::decode(token).context("the invite token (is the paste complete?)")?;
    let me = keystore::node_identity_in(ks).map_err(|_| {
        anyhow::anyhow!(
            "this keystore has no node key, so this invite (for node {}) cannot be for it — run \
             `wires id` here, and ask the admin to invite that id",
            invite.membership.member.hex()
        )
    })?;
    if invite.membership.member != me.node_id() {
        bail!(
            "this invite is for node {}, but this keystore's node is {} — join from the machine \
             that ran `wires id` for it (or ask for an invite for {})",
            invite.membership.member.hex(),
            me.node_id().hex(),
            me.node_id().hex()
        );
    }
    invite.verify(&me, now).context("checking the invite")?;
    let fabric = invite.fabric();
    if let Some(held) = ks.read_membership()?
        && held.fabric != fabric
    {
        bail!(
            "this keystore is already in network {}…; the invite is for network {}… — use another \
             $WIRES_HOME to join a second network",
            held.fabric.short(),
            fabric.short()
        );
    }

    ks.save_membership(&invite.membership)?;
    crate::state::store::adopt_if_newer(ks, &invite.state, fabric, now)?;
    crate::state::store::mark_checked(ks, now)?;
    crate::state::store::save_admin(ks, invite.admin)?;
    let held = crate::state::store::read(ks, fabric)?
        .map_or(invite.state.state.version, |s| s.state.version);
    Ok(format!(
        "joined network {}… as {}… (state version {})\nnext: `wires login` to sign in, then \
         `wires services`",
        fabric.short(),
        me.node_id().short(),
        held.0,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;
    use library::{Membership, SignedState, State, StateVersion};

    /// A state at `version`, signed by `root`.
    fn signed(root: &NodeIdentity, version: u64) -> SignedState {
        let mut s = State::new(root.node_id());
        s.version = StateVersion(version);
        s.not_after = i64::MAX;
        s.sign(root).unwrap()
    }

    /// An invite for `joiner` in the fabric of `root`, at state `version`.
    fn invite_for(root: &NodeIdentity, joiner: NodeId, version: u64) -> Invite {
        let admin = NodeIdentity::from_seed([4u8; 32]).node_id();
        Invite::new(
            Membership::mint(root, joiner, 0, i64::MAX).unwrap(),
            signed(root, version),
            admin,
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
    fn join_installs_the_membership_state_and_admin() {
        let ks = Keystore::at(temp_dir());
        let (me, _) = id_in(&ks).unwrap();
        let root = NodeIdentity::from_seed([1u8; 32]);
        let invite = invite_for(&root, me, 3);
        let out = join_in(&ks, &invite.encode().unwrap(), 0).unwrap();
        assert!(out.contains("state version 3"), "{out}");
        assert_eq!(
            ks.read_membership().unwrap(),
            Some(invite.membership.clone())
        );
        let held = crate::state::store::read(&ks, root.node_id())
            .unwrap()
            .unwrap();
        assert_eq!(held.state.version, StateVersion(3));
        assert_eq!(
            crate::state::store::read_admin(&ks).unwrap(),
            Some(invite.admin)
        );

        // Re-joining with an older token keeps the newer state.
        join_in(&ks, &invite_for(&root, me, 2).encode().unwrap(), 0).unwrap();
        let held = crate::state::store::read(&ks, root.node_id())
            .unwrap()
            .unwrap();
        assert_eq!(held.state.version, StateVersion(3));
    }

    #[test]
    fn join_refuses_someone_elses_token_and_writes_nothing() {
        let ks = Keystore::at(temp_dir());
        id_in(&ks).unwrap();
        let root = NodeIdentity::from_seed([1u8; 32]);
        let other = NodeIdentity::from_seed([7u8; 32]).node_id();
        let invite = invite_for(&root, other, 1);
        let err = join_in(&ks, &invite.encode().unwrap(), 0).unwrap_err();
        assert!(format!("{err:#}").contains(&other.hex()), "{err:#}");
        assert!(ks.read_membership().unwrap().is_none());

        // No node key at all is its own, named failure.
        let bare = Keystore::at(temp_dir());
        let err = join_in(&bare, &invite.encode().unwrap(), 0).unwrap_err();
        assert!(format!("{err:#}").contains("wires id"), "{err:#}");
        assert!(join_in(&ks, "garbage!", 0).is_err());
    }

    #[test]
    fn join_refuses_a_second_fabric() {
        let ks = Keystore::at(temp_dir());
        let (me, _) = id_in(&ks).unwrap();
        let root = NodeIdentity::from_seed([1u8; 32]);
        let invite = invite_for(&root, me, 1);
        join_in(&ks, &invite.encode().unwrap(), 0).unwrap();

        let rogue = NodeIdentity::from_seed([66u8; 32]);
        let other = invite_for(&rogue, me, 1);
        let err = join_in(&ks, &other.encode().unwrap(), 0).unwrap_err();
        assert!(
            format!("{err:#}").contains("another $WIRES_HOME"),
            "{err:#}"
        );
        assert_eq!(ks.read_membership().unwrap(), Some(invite.membership));
    }
}

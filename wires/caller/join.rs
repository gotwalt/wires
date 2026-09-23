//! `wires id` and `wires join`: the joiner's two steps, for any role.
//!
//! A host, a caller and an observer all join the same way: send the admin
//! this node's id (`wires id`), paste back the token `wires invite` printed
//! (`wires join <token>`). Join checks the token is for this node and signed
//! by one root throughout, then installs the membership, inclusion proof,
//! roster head and fabric key where every other command looks for them, and
//! records the channel and its bootstrap peers — so `wires watch`, `wires
//! login` and `serve --audit-topic` need no `--peer`, and `wires watch` needs
//! no topic name.
//!
//! After this, the admin's re-keys arrive over the channel; nothing needs
//! importing by hand again.

use std::path::Path;

use anyhow::{Context, bail};
use clap::Args;
use library::{Invite, NodeId, NodeIdentity, Rekey, TopicId};

use crate::admin::keystore::{self, Keystore};
use crate::channel::peers::PeerBook;
use crate::channel::rekey;
use crate::now_unix;

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
    ks.save_node(&node, false)?;
    Ok((node.node_id(), true))
}

/// `join`: install the token, or print this node's id when there is none.
pub(crate) fn join_cmd(a: JoinArgs) -> anyhow::Result<String> {
    let ks = Keystore::resolve()?;
    match a.token {
        Some(token) => join_in(&ks, &keystore::home()?, &token, now_unix()),
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

/// [`join_cmd`] with a token, against an explicit keystore and home (the
/// testable form). Returns the summary for stdout.
///
/// Nothing is written until the whole token has verified. A keystore already
/// in a *different* fabric is refused (one keystore, one fabric — use another
/// `$WIRES_HOME`); re-joining the same fabric is how a member that missed
/// re-keys catches up, and never moves its head backwards.
pub(crate) fn join_in(ks: &Keystore, home: &Path, token: &str, now: i64) -> anyhow::Result<String> {
    let invite = Invite::decode(token).context("the invite token (is the paste complete?)")?;
    let me = keystore::node_identity_in(ks).map_err(|_| {
        anyhow::anyhow!(
            "this keystore has no node key, so this invite (for node {}) cannot be for it — run \
             `wires id` here, and ask the admin to invite that id",
            invite.entry.member().hex()
        )
    })?;
    if invite.entry.member() != me.node_id() {
        bail!(
            "this invite is for node {}, but this keystore's node is {} — join from the machine \
             that ran `wires id` for it (or ask for an invite for {})",
            invite.entry.member().hex(),
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
            "this keystore is already in fabric {}…; the invite is for fabric {}… — use another \
             $WIRES_HOME to join a second fabric",
            &held.fabric.hex()[..8],
            &fabric.hex()[..8]
        );
    }

    ks.save_membership(&invite.membership)?;
    let adoption = rekey::install(
        &Rekey::new(invite.head.clone(), vec![invite.entry.clone()]),
        &me,
        fabric,
        ks,
        now,
    )?;
    ks.save_channel(&invite.channel)?;
    let mut book = PeerBook::open(home, TopicId::derive(fabric, &invite.channel));
    for peer in &invite.peers {
        book.record(peer.clone());
    }
    book.save();

    let mut out = format!(
        "joined fabric {}… as {}… on channel {:?} (roster version {})",
        &fabric.hex()[..8],
        &me.node_id().hex()[..8],
        invite.channel,
        invite.head.version.0,
    );
    if adoption.superseded {
        out.push_str("\nthis keystore already holds a newer roster head; kept it");
    }
    out.push_str(&match invite.peers.len() {
        0 => "\nno bootstrap peers in the token: this node is the channel's first — `wires serve \
              --audit-topic …` or `wires watch` prints the ticket others bootstrap from"
            .to_string(),
        n => format!("\n{n} bootstrap peer(s) recorded; `wires watch` needs no --peer"),
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;
    use library::{FabricKey, Membership, RekeyEntry, Roster, SealedFabricKey, TopicPeer};

    /// An invite for `joiner` in a fresh fabric, and the key it carries.
    fn invite_for(joiner: NodeId, peers: Vec<TopicPeer>) -> (Invite, FabricKey) {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut roster = Roster::new(root.node_id());
        roster.insert(joiner);
        let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
        let key = FabricKey::generate();
        let entry = RekeyEntry {
            proof: proofs[0].1.clone(),
            key: SealedFabricKey::seal(&root, joiner, head.version, &key).unwrap(),
        };
        let membership = Membership::mint(&root, joiner, 0, i64::MAX).unwrap();
        (Invite::new("ops", membership, head, entry, peers), key)
    }

    #[test]
    fn id_creates_the_key_once() {
        let ks = Keystore::at(temp_dir());
        let (first, created) = id_in(&ks).unwrap();
        assert!(created);
        assert_eq!(id_in(&ks).unwrap(), (first, false));
    }

    #[test]
    fn join_installs_everything_the_other_commands_read() {
        let home = temp_dir();
        let ks = Keystore::at(&home);
        let (me, _) = id_in(&ks).unwrap();
        let peer = TopicPeer::new(NodeIdentity::from_seed([9u8; 32]).node_id())
            .with_addrs(vec!["127.0.0.1:4242".parse().unwrap()]);
        let (invite, key) = invite_for(me, vec![peer.clone()]);
        let out = join_in(&ks, &home, &invite.encode().unwrap(), 0).unwrap();
        assert!(out.contains("\"ops\""), "{out}");

        assert_eq!(
            ks.read_membership().unwrap(),
            Some(invite.membership.clone())
        );
        assert_eq!(ks.read_roster_head().unwrap(), Some(invite.head.clone()));
        assert_eq!(
            ks.read_inclusion_proof().unwrap(),
            Some(invite.entry.proof.clone())
        );
        assert_eq!(
            ks.latest_fabric_key().unwrap(),
            Some((invite.head.version, key))
        );
        assert_eq!(ks.read_channel().unwrap().as_deref(), Some("ops"));
        let topic = TopicId::derive(invite.fabric(), "ops");
        assert_eq!(PeerBook::open(&home, topic).list(), vec![peer]);
    }

    #[test]
    fn join_refuses_someone_elses_token_and_writes_nothing() {
        let home = temp_dir();
        let ks = Keystore::at(&home);
        id_in(&ks).unwrap();
        let other = NodeIdentity::from_seed([7u8; 32]).node_id();
        let (invite, _) = invite_for(other, Vec::new());
        let err = join_in(&ks, &home, &invite.encode().unwrap(), 0).unwrap_err();
        assert!(format!("{err:#}").contains(&other.hex()), "{err:#}");
        assert!(ks.read_membership().unwrap().is_none());
        assert!(ks.read_channel().unwrap().is_none());

        // No node key at all is its own, named failure.
        let bare = Keystore::at(temp_dir());
        let err = join_in(&bare, &home, &invite.encode().unwrap(), 0).unwrap_err();
        assert!(format!("{err:#}").contains("wires id"), "{err:#}");
        assert!(join_in(&ks, &home, "garbage!", 0).is_err());
    }

    #[test]
    fn join_refuses_a_second_fabric() {
        let home = temp_dir();
        let ks = Keystore::at(&home);
        let (me, _) = id_in(&ks).unwrap();
        let (invite, _) = invite_for(me, Vec::new());
        join_in(&ks, &home, &invite.encode().unwrap(), 0).unwrap();

        let rogue = NodeIdentity::from_seed([66u8; 32]);
        let mut roster = Roster::new(rogue.node_id());
        roster.insert(me);
        let (head, proofs) = roster.commit(&rogue, 0, i64::MAX).unwrap();
        let entry = RekeyEntry {
            proof: proofs[0].1.clone(),
            key: SealedFabricKey::seal(&rogue, me, head.version, &FabricKey::generate()).unwrap(),
        };
        let other = Invite::new(
            "ops",
            Membership::mint(&rogue, me, 0, i64::MAX).unwrap(),
            head,
            entry,
            Vec::new(),
        );
        let err = join_in(&ks, &home, &other.encode().unwrap(), 0).unwrap_err();
        assert!(
            format!("{err:#}").contains("another $WIRES_HOME"),
            "{err:#}"
        );
        assert_eq!(ks.read_membership().unwrap(), Some(invite.membership));
    }
}

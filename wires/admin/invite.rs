//! `wires invite` and `wires remove`: admitting and removing a member, one
//! command each.
//!
//! Both are a roster edit plus [`commit_and_distribute`]: the commit is
//! published on the channel as a re-key, so the members already in adopt it
//! with no manual import. `invite` then bundles the new member's part into
//! one [`Invite`] token; `remove` has nothing to hand out — the removed node
//! is simply not in the re-key, and every host that adopts it refuses the
//! node's next call (revocation stays immediate at every node holding the new
//! head, as before).
//!
//! Names (`--name alice`) are the admin's local labels in `names.json`, for
//! `wires remove alice`. They are not identity: nothing on the wire carries
//! them.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::Args;
use library::{Invite, Membership, NodeId, TopicId, TopicPeer, TopicTicket};

use super::commit::{Committed, Timing, Ttl, commit_and_distribute};
use super::keystore::{self, Keystore};
use crate::channel::peers::PeerBook;
use crate::channel::topics;
use crate::now_unix;

/// `invite` arguments.
#[derive(Args)]
pub(crate) struct InviteArgs {
    /// The joiner's node id, hex (what `wires id` prints on the joining
    /// machine).
    pub(crate) node_id: String,
    /// A local label for this member, for `wires remove <name>`.
    #[arg(long)]
    pub(crate) name: Option<String>,
    /// Lifetime of the invitee's membership and of the new roster head (`30d`,
    /// `12h`, … or seconds).
    #[arg(long, default_value = Ttl::DEFAULT)]
    pub(crate) ttl: Ttl,
    /// A channel ticket to remember as a bootstrap peer (e.g. the `share to
    /// bootstrap:` line of a host's `wires serve`). Repeatable; remembered for
    /// every later invite and re-key.
    #[arg(long = "peer")]
    pub(crate) peer: Vec<String>,
}

/// `remove` arguments.
#[derive(Args)]
pub(crate) struct RemoveArgs {
    /// The member to remove: a name given to `wires invite --name`, or a hex
    /// node id.
    pub(crate) member: String,
    /// Lifetime of the new roster head (`30d`, `12h`, … or seconds).
    #[arg(long, default_value = Ttl::DEFAULT)]
    pub(crate) ttl: Ttl,
}

/// What an admin command prints: `stdout` is the result (the token, for
/// `invite`), `notes` go to stderr.
#[derive(Debug)]
pub(crate) struct Report {
    /// The command's result, for stdout.
    pub(crate) stdout: String,
    /// Progress and hints, for stderr.
    pub(crate) notes: Vec<String>,
}

/// `invite` against the resolved keystore, publishing through a real
/// endpoint.
pub(crate) async fn invite_cmd(a: InviteArgs) -> anyhow::Result<Report> {
    let ks = Arc::new(Keystore::resolve()?);
    let home = keystore::home()?;
    invite_in(&ks, &home, a, Timing::CLI, async |cfg| {
        topics::TopicNode::spawn(&keystore::node_identity_in(&ks)?, cfg).await
    })
    .await
}

/// [`invite_cmd`] against an explicit keystore, with the one-shot node stood
/// up by `bind` (the testable form).
pub(crate) async fn invite_in<B>(
    ks: &Arc<Keystore>,
    home: &Path,
    a: InviteArgs,
    timing: Timing,
    bind: B,
) -> anyhow::Result<Report>
where
    B: AsyncFnOnce(topics::TopicNodeConfig) -> anyhow::Result<topics::TopicNode>,
{
    let invitee = NodeId::from_hex(a.node_id.trim())
        .context("the node id to invite (64 hex characters, as `wires id` prints it)")?;
    let root = ks
        .read_root_identity()?
        .ok_or_else(|| anyhow::anyhow!("no root key here; run `wires init` first"))?;
    let channel = ks
        .read_channel()?
        .ok_or_else(|| anyhow::anyhow!("no channel here; run `wires init` first"))?;
    let mut roster = ks
        .read_roster()?
        .ok_or_else(|| anyhow::anyhow!("no roster here; run `wires init` first"))?;
    let mut names = ks.read_names()?;
    if let Some(name) = &a.name {
        check_name(name)?;
        if let Some(held) = names.get(name)
            && *held != invitee
        {
            bail!(
                "--name {name:?} already labels {}; pick another (or `wires remove {name}` first)",
                held.hex()
            );
        }
    }

    // Bootstrap hints: this invite's tickets join the ones remembered.
    let topic = TopicId::derive(roster.fabric, &channel);
    let mut book = PeerBook::open(home, topic);
    for text in &a.peer {
        let ticket = TopicTicket::decode(text.trim())
            .context("--peer (is the pasted base64 ticket complete?)")?;
        if ticket.fabric != roster.fabric || ticket.name != channel {
            bail!(
                "--peer: this ticket is for channel {:?} of fabric {}…, not {channel:?} of this \
                 fabric",
                ticket.name,
                &ticket.fabric.hex()[..8]
            );
        }
        for peer in ticket.peers {
            book.record(peer);
        }
    }
    book.save();

    let now = now_unix();
    let not_after = a.ttl.not_after(now);
    let rejoin = !roster.insert(invitee);
    let committed = commit_and_distribute(
        ks,
        home,
        &root,
        &mut roster,
        (!rejoin).then_some(invitee),
        not_after,
        timing,
        bind,
    )
    .await?;
    let entry = committed
        .entry_for(invitee)
        .context("the commit has no entry for the invitee")?
        .clone();
    if let Some(name) = &a.name {
        names.insert(name.clone(), invitee);
        ks.save_names(&names)?;
    }

    // Re-read: a one-shot distribution records the neighbors it reached.
    let peers: Vec<TopicPeer> = PeerBook::open(home, topic)
        .list()
        .into_iter()
        .filter(|p| p.node != invitee)
        .collect();
    let membership = Membership::mint(&root, invitee, now, not_after)?;
    let token = Invite::new(
        channel.clone(),
        membership,
        committed.rekey.head.clone(),
        entry,
        peers.clone(),
    )
    .encode()?;

    let mut notes = vec![
        format!(
            "{} {}{} (roster version {}, {} members)",
            if rejoin { "re-invited" } else { "invited" },
            invitee.hex(),
            a.name
                .as_deref()
                .map(|n| format!(" as {n:?}"))
                .unwrap_or_default(),
            committed.rekey.head.version.0,
            roster.members.len()
        ),
        committed.told_line(),
    ];
    if peers.is_empty() {
        notes.push(
            "no bootstrap peer is known yet, so the token carries none: the joiner can still \
             serve (and be everyone else's bootstrap) — pass its ticket to the next \
             `wires invite --peer <ticket>`"
                .into(),
        );
    }
    notes.push(format!("on the joining machine: wires join {token}"));
    Ok(Report {
        stdout: token,
        notes,
    })
}

/// `remove` against the resolved keystore.
pub(crate) async fn remove_cmd(a: RemoveArgs) -> anyhow::Result<Report> {
    let ks = Arc::new(Keystore::resolve()?);
    let home = keystore::home()?;
    remove_in(&ks, &home, a, Timing::CLI, async |cfg| {
        topics::TopicNode::spawn(&keystore::node_identity_in(&ks)?, cfg).await
    })
    .await
}

/// [`remove_cmd`] against an explicit keystore (the testable form).
pub(crate) async fn remove_in<B>(
    ks: &Arc<Keystore>,
    home: &Path,
    a: RemoveArgs,
    timing: Timing,
    bind: B,
) -> anyhow::Result<Report>
where
    B: AsyncFnOnce(topics::TopicNodeConfig) -> anyhow::Result<topics::TopicNode>,
{
    let root = ks
        .read_root_identity()?
        .ok_or_else(|| anyhow::anyhow!("no root key here; run `wires init` first"))?;
    let mut roster = ks
        .read_roster()?
        .ok_or_else(|| anyhow::anyhow!("no roster here; run `wires init` first"))?;
    let mut names = ks.read_names()?;
    let (member, label) = resolve_member(&names, &a.member)?;
    if member == keystore::node_identity_in(ks)?.node_id() {
        bail!(
            "{} is this machine's own node: removing it would leave nobody to publish the next \
             re-key from",
            member.hex()
        );
    }
    if !roster.remove(&member) {
        bail!("{} is not in the roster", member.hex());
    }
    let committed: Committed = commit_and_distribute(
        ks,
        home,
        &root,
        &mut roster,
        None,
        a.ttl.not_after(now_unix()),
        timing,
        bind,
    )
    .await?;
    if let Some(label) = &label {
        names.remove(label);
    }
    names.retain(|_, id| *id != member);
    ks.save_names(&names)?;

    Ok(Report {
        stdout: format!(
            "removed {}{} (roster version {}, {} members)",
            member.hex(),
            label.map(|n| format!(" ({n})")).unwrap_or_default(),
            committed.rekey.head.version.0,
            roster.members.len()
        ),
        notes: vec![committed.told_line()],
    })
}

/// A name or a hex node id → the member, and the label it was known by.
fn resolve_member(
    names: &std::collections::BTreeMap<String, NodeId>,
    text: &str,
) -> anyhow::Result<(NodeId, Option<String>)> {
    let text = text.trim();
    if let Some(id) = names.get(text) {
        return Ok((*id, Some(text.to_string())));
    }
    match NodeId::from_hex(text) {
        Ok(id) => {
            let label = names
                .iter()
                .find(|(_, held)| **held == id)
                .map(|(n, _)| n.clone());
            Ok((id, label))
        }
        Err(_) => bail!(
            "{text:?} is neither a name given to `wires invite --name` nor a hex node id \
             (known names: {})",
            if names.is_empty() {
                "none".to_string()
            } else {
                names.keys().cloned().collect::<Vec<_>>().join(", ")
            }
        ),
    }
}

/// A label must be one word that cannot be mistaken for a node id.
fn check_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() || name.chars().any(char::is_whitespace) {
        bail!("--name must be one word");
    }
    if NodeId::from_hex(name).is_ok() {
        bail!("--name must not look like a node id");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::NodeIdentity;

    #[test]
    fn a_member_is_found_by_name_or_by_id() {
        let alice = NodeIdentity::from_seed([2u8; 32]).node_id();
        let bob = NodeIdentity::from_seed([3u8; 32]).node_id();
        let names = std::collections::BTreeMap::from([("alice".to_string(), alice)]);
        assert_eq!(
            resolve_member(&names, "alice").unwrap(),
            (alice, Some("alice".into()))
        );
        assert_eq!(
            resolve_member(&names, &alice.hex()).unwrap(),
            (alice, Some("alice".into()))
        );
        assert_eq!(resolve_member(&names, &bob.hex()).unwrap(), (bob, None));
        let err = resolve_member(&names, "carol").unwrap_err();
        assert!(format!("{err:#}").contains("alice"), "{err:#}");
    }

    #[test]
    fn names_are_one_word_and_not_ids() {
        assert!(check_name("workbench").is_ok());
        assert!(check_name("").is_err());
        assert!(check_name("two words").is_err());
        assert!(check_name(&NodeIdentity::from_seed([2u8; 32]).node_id().hex()).is_err());
    }
}

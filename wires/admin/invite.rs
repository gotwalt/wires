//! `wires invite` and `wires remove`: admitting and removing a member, one
//! command each.
//!
//! Both are an edit of the admin-signed state ([`edit_state`]), pushed to
//! every member by key (hosts first). `invite` also mints the new member's
//! membership and bundles it with the new state into one [`Invite`] token;
//! `remove` has nothing to hand out — the removed node is simply not in the
//! new state, and every host refuses its next call (the host re-reads its
//! state per connection, so no restart). There is no key to rotate: nothing
//! is encrypted to the member set.
//!
//! Names (`--name alice`) are the admin's local labels in `names.json`, for
//! `wires remove alice`. They are not identity: nothing on the wire carries
//! them.

use anyhow::{Context, bail};
use clap::Args;
use library::{Invite, Membership, NodeId, SignedState};

use super::keystore::{self, Keystore};
use super::service::edit_state;
use super::ttl::Ttl;
use crate::now_unix;

/// `invite` arguments.
#[derive(Args)]
pub(crate) struct InviteArgs {
    /// The joiner's node id, hex (what `wires id` prints on the joining
    /// machine).
    pub(crate) node_id: String,
    /// A local label for this member, for `wires remove <name>` and
    /// `wires service add --host <name>`.
    #[arg(long)]
    pub(crate) name: Option<String>,
    /// Lifetime of the invitee's membership and of the new signed state
    /// (`30d`, `12h`, … or seconds).
    #[arg(long, default_value = Ttl::DEFAULT)]
    pub(crate) ttl: Ttl,
}

/// `remove` arguments.
#[derive(Args)]
pub(crate) struct RemoveArgs {
    /// The member to remove: a name given to `wires invite --name`, or a hex
    /// node id.
    pub(crate) member: String,
    /// Lifetime of the new signed state (`30d`, `12h`, … or seconds).
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

/// `invite` against the resolved keystore, then push the new state.
pub(crate) async fn invite_cmd(a: InviteArgs) -> anyhow::Result<Report> {
    let ks = Keystore::resolve()?;
    let mut report = invite_in(&ks, a)?;
    report
        .notes
        .insert(report.notes.len() - 1, push_note(&ks).await);
    Ok(report)
}

/// Push the stored state to every member (hosts first) and say how it went.
async fn push_note(ks: &Keystore) -> String {
    match crate::state::sync::push_current(ks).await {
        Ok(line) => line,
        Err(e) => format!("the new state is stored but was not pushed: {e:#}"),
    }
}

/// [`invite_cmd`] against an explicit keystore, without the push (the
/// testable form).
pub(crate) fn invite_in(ks: &Keystore, a: InviteArgs) -> anyhow::Result<Report> {
    let invitee = NodeId::from_hex(a.node_id.trim())
        .context("the node id to invite (64 hex characters, as `wires id` prints it)")?;
    let root = ks
        .read_root_identity()?
        .ok_or_else(|| anyhow::anyhow!("no root key here; run `wires init` first"))?;
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
    let now = now_unix();
    let membership = Membership::mint(&root, invitee, now, a.ttl.not_after(now))?;
    let rejoin =
        crate::state::store::read(ks, root.node_id())?.is_some_and(|s| s.state.is_member(invitee));
    let state = edit_state(ks, a.ttl, |s| {
        s.members.insert(invitee);
        Ok(())
    })?;
    if let Some(name) = &a.name {
        names.insert(name.clone(), invitee);
        ks.save_names(&names)?;
    }
    let token = Invite::new(
        membership,
        state.clone(),
        keystore::node_identity_in(ks)?.node_id(),
    )
    .encode()?;
    let notes = vec![
        format!(
            "{} {}{} (state version {}, {} members)",
            if rejoin { "re-invited" } else { "invited" },
            invitee.hex(),
            a.name
                .as_deref()
                .map(|n| format!(" as {n:?}"))
                .unwrap_or_default(),
            state.state.version.0,
            state.state.members.len()
        ),
        format!("on the joining machine: wires join {token}"),
    ];
    Ok(Report {
        stdout: token,
        notes,
    })
}

/// `remove` against the resolved keystore: out of the signed state, then
/// pushed (hosts first).
pub(crate) async fn remove_cmd(a: RemoveArgs) -> anyhow::Result<Report> {
    let ks = Keystore::resolve()?;
    let mut report = remove_in(&ks, a)?;
    report.notes.push(push_note(&ks).await);
    Ok(report)
}

/// [`remove_cmd`] against an explicit keystore, without the push (the
/// testable form).
pub(crate) fn remove_in(ks: &Keystore, a: RemoveArgs) -> anyhow::Result<Report> {
    let (member, label) = resolve_removal(ks, &a.member)?;
    let Some(state) = drop_from_state(ks, member, a.ttl)? else {
        bail!("{} is not a member", member.hex());
    };
    let mut names = ks.read_names()?;
    names.retain(|_, id| *id != member);
    ks.save_names(&names)?;
    Ok(Report {
        stdout: format!(
            "removed {}{} (state version {}, {} members)",
            member.hex(),
            label.map(|n| format!(" ({n})")).unwrap_or_default(),
            state.state.version.0,
            state.state.members.len()
        ),
        notes: Vec::new(),
    })
}

/// The member `wires remove <text>` means, refusing this machine's own node.
fn resolve_removal(ks: &Keystore, text: &str) -> anyhow::Result<(NodeId, Option<String>)> {
    let (member, label) = resolve_member(&ks.read_names()?, text)?;
    if member == keystore::node_identity_in(ks)?.node_id() {
        bail!(
            "{} is this machine's own node: removing it would leave nobody to sign and push the \
             next state from",
            member.hex()
        );
    }
    Ok((member, label))
}

/// Drop `member` from the signed state (and from every service it hosted);
/// `None` when it is already out.
fn drop_from_state(ks: &Keystore, member: NodeId, ttl: Ttl) -> anyhow::Result<Option<SignedState>> {
    let Some(root) = ks.read_root_identity()? else {
        return Ok(None);
    };
    let held = crate::state::store::read(ks, root.node_id())?;
    if held.is_some_and(|s| !s.state.is_member(member)) {
        return Ok(None);
    }
    edit_state(ks, ttl, |s| {
        s.members.remove(&member);
        for svc in s.services.values_mut() {
            svc.hosts.retain(|h| *h != member);
        }
        Ok(())
    })
    .map(Some)
}

/// A name or a hex node id → the member, and the label it was known by.
pub(crate) fn resolve_member(
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

    #[test]
    fn invite_then_remove_edits_the_signed_state() {
        use crate::admin::init::{InitArgs, init_in};
        let ks = Keystore::at(crate::testutil::temp_dir());
        init_in(
            &ks,
            InitArgs {
                ttl: Ttl::DEFAULT.parse().unwrap(),
            },
        )
        .unwrap();
        let root = ks.read_root_identity().unwrap().unwrap();
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let report = invite_in(
            &ks,
            InviteArgs {
                node_id: alice.node_id().hex(),
                name: Some("alice".into()),
                ttl: Ttl::DEFAULT.parse().unwrap(),
            },
        )
        .unwrap();
        let invite = Invite::decode(&report.stdout).unwrap();
        invite.verify(&alice, now_unix()).unwrap();
        assert_eq!(invite.state.state.version, library::StateVersion(2));
        let removed = remove_in(
            &ks,
            RemoveArgs {
                member: "alice".into(),
                ttl: Ttl::DEFAULT.parse().unwrap(),
            },
        )
        .unwrap();
        assert!(
            removed.stdout.contains("state version 3"),
            "{}",
            removed.stdout
        );
        let state = crate::state::store::read(&ks, root.node_id())
            .unwrap()
            .unwrap();
        assert!(!state.state.is_member(alice.node_id()));
        assert!(ks.read_names().unwrap().is_empty());
        // Removing again, or removing this machine's own node, is refused.
        let again = RemoveArgs {
            member: alice.node_id().hex(),
            ttl: Ttl::DEFAULT.parse().unwrap(),
        };
        assert!(remove_in(&ks, again).is_err());
        let me = RemoveArgs {
            member: keystore::node_identity_in(&ks).unwrap().node_id().hex(),
            ttl: Ttl::DEFAULT.parse().unwrap(),
        };
        assert!(format!("{:#}", remove_in(&ks, me).unwrap_err()).contains("own node"));
    }
}

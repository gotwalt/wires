//! `wires id` and `wires join`: the joiner's two steps, for any role.
//!
//! A host and a caller join the same way: send the admin this node's id
//! (`wires id`), paste back the token `wires invite` printed (`wires join
//! <token>`). Join checks the token is for this node and signed by one root
//! throughout, then installs what it carries where every other command
//! looks for it (card 37):
//!
//! - the membership (this node's badge: what admits it);
//! - the directory ids (`directories.json`): where the head, the view and
//!   (for a host) the policy are asked for;
//! - the login settings (`login.json`): which IdP and OAuth client `wires
//!   login` signs in with, so it needs no flags;
//! - for a node the policy names as a host or directory, the whole signed
//!   policy.
//!
//! A caller then asks a directory for the head, so it knows the fabric's
//! version and directories at once (its view, empty until it signs in; the
//! services come with `wires login`). Nothing needs importing by hand again:
//! a host follows the policy from a directory, a caller its view.

use anyhow::{Context, bail};
use clap::Args;
use library::{Invite, NodeId, NodeIdentity, View};

use crate::admin::keystore::{self, Keystore};
use crate::caller::view::{self, HeldView};
use crate::clock::now_unix;

/// `join` arguments.
#[derive(Args)]
pub(crate) struct JoinArgs {
    /// The token your admin sent (`wires invite` printed it).
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

/// `join`: install the token (and, for a caller, ask a directory for the
/// head), or print this node's id when there is none.
pub(crate) async fn join_cmd(a: JoinArgs) -> anyhow::Result<String> {
    let ks = Keystore::resolve()?;
    let Some(token) = a.token else {
        let (id, _) = id_in(&ks)?;
        return Ok(format!(
            "{}\nsend this node id to your admin; they run `wires invite {}` and send back the \
             token for `wires join <token>`",
            id.hex(),
            id.hex()
        ));
    };
    let joined = join_in(&ks, &token, now_unix())?;
    let mut out = joined.summary;
    if joined.caller {
        match fetch_head(&ks).await {
            Ok(held) => out.push_str(&format!(" (policy version {})", held.version().0)),
            Err(e) => {
                tracing::debug!("asking a directory for the head: {e:#}");
                out.push_str(
                    " (no directory answered yet; `wires login` asks again for your services)",
                )
            }
        }
    }
    out.push_str("\nnext: `wires login` to sign in, then `wires services`");
    Ok(out)
}

/// What [`join_in`] installed.
#[derive(Debug)]
pub(crate) struct Joined {
    /// The first line for stdout.
    pub(crate) summary: String,
    /// The invite carried no policy (a caller): ask a directory for the head.
    pub(crate) caller: bool,
}

/// [`join_cmd`] with a token, against an explicit keystore, without the
/// network (the testable form).
///
/// Nothing is written until the whole token has verified. A keystore already
/// in a *different* fabric is refused (one keystore, one fabric — use another
/// `$WIRES_HOME`); re-joining the same fabric never moves a stored policy
/// backwards.
pub(crate) fn join_in(ks: &Keystore, token: &str, now: i64) -> anyhow::Result<Joined> {
    let invite = Invite::decode(token).context(
        "the invite token does not decode; paste it whole, or ask your admin to send it again",
    )?;
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
    invite
        .verify(&me, now)
        .context("the invite does not check out; ask your admin for a fresh one")?;
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
    view::save_joined_directories(ks, &invite.directories)?;
    if let Some(login) = &invite.login {
        crate::caller::login::save_settings(ks, login)?;
    }
    let mut summary = format!(
        "joined network {}… as {}…",
        fabric.short(),
        me.node_id().short()
    );
    if let Some(policy) = &invite.policy {
        crate::policy::store::adopt_if_newer(ks, policy, fabric, now)?;
        crate::policy::store::mark_checked(ks, now)?;
        let held =
            crate::policy::store::read(ks, fabric)?.map_or(policy.version(), |s| s.version());
        summary.push_str(&format!(
            " as a host or directory (policy version {})",
            held.0
        ));
    }
    Ok(Joined {
        summary,
        caller: invite.policy.is_none(),
    })
}

/// A new caller's first question: the head, from a directory the invite
/// named, stored as an empty view (no entry before `wires login`). Keeps a
/// view already held at a newer head.
async fn fetch_head(ks: &Keystore) -> anyhow::Result<HeldView> {
    let node = keystore::node_identity_in(ks)?;
    let badge = ks
        .read_membership()?
        .context("no membership after joining")?;
    let root = badge.fabric;
    if let Some(held) = view::read(ks, root)? {
        return Ok(held);
    }
    let endpoint =
        crate::host::transport::bind_with(&node, None, library::DIRECTORY_ALPN, false, Some(ks))
            .await?;
    let asked = async {
        let mut failures = Vec::new();
        for dir in view::directories(ks, root, node.node_id()) {
            match view::ask_head(&endpoint, dir, &badge, root).await {
                Ok((head, fresh)) => {
                    let empty = View {
                        head,
                        entries: Vec::new(),
                    };
                    let held = HeldView::fetched(empty, Some(fresh), now_unix());
                    view::write(ks, root, &held)?;
                    return Ok(held);
                }
                Err(e) => failures.push(format!("{}: {e:#}", dir.short())),
            }
        }
        bail!("no directory answered ({})", failures.join("; "))
    };
    let result = tokio::time::timeout(view::REFRESH_BUDGET, asked)
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("no directory answered in time")));
    endpoint.close().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;
    use library::{
        Audience, Issuer, LoginSettings, Membership, Policy, SignedPolicy, StateVersion,
    };

    /// A policy at `version`, signed by `root`.
    fn signed(root: &NodeIdentity, version: u64) -> SignedPolicy {
        let mut s = Policy::new(root.node_id());
        s.version = StateVersion(version);
        s.not_after = i64::MAX;
        s.directories = vec![dir()];
        crate::testutil::signed_policy(root, s)
    }

    fn dir() -> NodeId {
        NodeIdentity::from_seed([4u8; 32]).node_id()
    }

    fn login() -> LoginSettings {
        LoginSettings {
            issuer: Issuer::new("https://idp.example"),
            client_id: Audience::new("desktop-client"),
            public_client_secret: None,
        }
    }

    /// A caller's invite for `joiner` in the fabric of `root`.
    fn invite_for(root: &NodeIdentity, joiner: NodeId) -> Invite {
        Invite::new(
            Membership::mint(root, joiner, 0, i64::MAX).unwrap(),
            vec![dir()],
            Some(login()),
        )
    }

    #[test]
    fn id_creates_the_key_once() {
        let ks = Keystore::at(temp_dir());
        let (first, created) = id_in(&ks).unwrap();
        assert!(created);
        assert_eq!(id_in(&ks).unwrap(), (first, false));
    }

    /// Card 37: a caller's join installs the badge, the directory ids and
    /// the login settings, and no policy.
    #[test]
    fn a_callers_join_installs_the_badge_directories_and_login_and_no_policy() {
        let ks = Keystore::at(temp_dir());
        let (me, _) = id_in(&ks).unwrap();
        let root = NodeIdentity::from_seed([1u8; 32]);
        let invite = invite_for(&root, me);
        let joined = join_in(&ks, &invite.encode().unwrap(), 0).unwrap();
        assert!(joined.caller);
        assert_eq!(
            ks.read_membership().unwrap(),
            Some(invite.membership.clone())
        );
        assert_eq!(view::joined_directories(&ks), vec![dir()]);
        assert_eq!(crate::caller::login::read_settings(&ks), Some(login()));
        assert!(
            crate::policy::store::read(&ks, root.node_id())
                .unwrap()
                .is_none()
        );
        assert!(!ks.path(crate::policy::store::POLICY_FILE).exists());
    }

    #[test]
    fn a_hosts_join_installs_the_policy_and_never_rolls_it_back() {
        let ks = Keystore::at(temp_dir());
        let (me, _) = id_in(&ks).unwrap();
        let root = NodeIdentity::from_seed([1u8; 32]);
        let v3 = invite_for(&root, me).with_policy(signed(&root, 3));
        let joined = join_in(&ks, &v3.encode().unwrap(), 0).unwrap();
        assert!(!joined.caller);
        assert!(joined.summary.contains("policy version 3"), "{joined:?}");
        let held = crate::policy::store::read(&ks, root.node_id())
            .unwrap()
            .unwrap();
        assert_eq!(held.version(), StateVersion(3));
        // Re-joining with an older token keeps the newer policy.
        let v2 = invite_for(&root, me).with_policy(signed(&root, 2));
        join_in(&ks, &v2.encode().unwrap(), 0).unwrap();
        let held = crate::policy::store::read(&ks, root.node_id())
            .unwrap()
            .unwrap();
        assert_eq!(held.version(), StateVersion(3));
    }

    #[test]
    fn join_refuses_someone_elses_token_and_writes_nothing() {
        let ks = Keystore::at(temp_dir());
        id_in(&ks).unwrap();
        let root = NodeIdentity::from_seed([1u8; 32]);
        let other = NodeIdentity::from_seed([7u8; 32]).node_id();
        let invite = invite_for(&root, other);
        let err = join_in(&ks, &invite.encode().unwrap(), 0).unwrap_err();
        assert!(format!("{err:#}").contains(&other.hex()), "{err:#}");
        assert!(ks.read_membership().unwrap().is_none());
        assert!(view::joined_directories(&ks).is_empty());

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
        let invite = invite_for(&root, me);
        join_in(&ks, &invite.encode().unwrap(), 0).unwrap();

        let rogue = NodeIdentity::from_seed([66u8; 32]);
        let other = invite_for(&rogue, me);
        let err = join_in(&ks, &other.encode().unwrap(), 0).unwrap_err();
        assert!(
            format!("{err:#}").contains("another $WIRES_HOME"),
            "{err:#}"
        );
        assert_eq!(ks.read_membership().unwrap(), Some(invite.membership));
    }
}

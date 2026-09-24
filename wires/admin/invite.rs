//! `wires invite` and `wires remove`: admitting and removing a node, one
//! command each.
//!
//! **`invite` is not an edit** (card 35). It mints the node's root-signed
//! badge (its membership), records it in the admin's ledger
//! ([`super::ledger`]), and bundles it into one [`Invite`] token with the
//! directory ids and the login settings ([`super::login_client`]):
//! under 1 KB at any network size (card 37). A node the policy already names
//! as a host or directory also gets the whole policy (it holds it anyway).
//! The policy's version doesn't move and nothing is published: every host
//! admits any badge the root signed. Two cases do edit, and then publish:
//! re-inviting a node the policy bans lifts the ban, and a policy that has
//! expired is re-signed.
//!
//! **`remove` is a ban**: an edit that adds the node to the policy's bans
//! until its badge would expire anyway (the ledger's `not_after`, or the
//! longest badge lifetime for a node the ledger doesn't know), drops it from
//! every service it hosted and from the directories, and is published to
//! the directories. Every host refuses its next connection once it holds
//! the new policy (it re-reads its policy per connection, so no restart).
//!
//! Names (`--name alice`) are the admin's local labels in the ledger, for
//! `wires remove alice`. They are not identity: nothing on the wire carries
//! them.

use anyhow::{Context, bail};
use clap::Args;
use library::{Invite, Membership, NodeId};

use super::keystore::{self, Keystore};
use super::ledger::Ledger;
use super::service::edit_policy;
use super::ttl::Ttl;
use super::{Report, run_edit, run_if_edited};
use crate::clock::now_unix;

/// `invite` arguments.
#[derive(Args)]
pub(crate) struct InviteArgs {
    /// The joiner's node id (what `wires id` printed on its machine).
    pub(crate) node_id: String,
    /// A local label for it, for `wires remove` and `wires service add --host`.
    #[arg(long)]
    pub(crate) name: Option<String>,
    /// Lifetime of the invitee's badge (`30d`, `12h`, … or seconds; at most 30d).
    #[arg(long, default_value = Ttl::DEFAULT)]
    pub(crate) ttl: Ttl,
    /// Lifetime of the signed policy, from now, if this invite has to edit
    /// it (lifting a ban, or re-signing an expired policy). Never shortens
    /// the current policy's expiry.
    #[arg(long, default_value = Ttl::POLICY_DEFAULT, hide = true)]
    pub(crate) policy_ttl: Ttl,
}

/// `remove` arguments.
#[derive(Args)]
pub(crate) struct RemoveArgs {
    /// The node to remove: its `wires invite --name` label, or its node id.
    pub(crate) member: String,
    /// Lifetime of the new signed policy, from now (`90d`, `12h`, … or
    /// seconds). Never shortens the current policy's expiry.
    #[arg(long, default_value = Ttl::POLICY_DEFAULT, hide = true)]
    pub(crate) policy_ttl: Ttl,
}

/// `invite` against the resolved keystore. Publishes only when it edited
/// the policy (see the module docs); the token is printed even when that
/// publish reached no directory (the invitee can still join), but the
/// command fails.
pub(crate) async fn invite_cmd(a: InviteArgs) -> anyhow::Result<Report> {
    run_if_edited(|ks| invite_in(ks, a)).await
}

/// [`invite_cmd`] against an explicit keystore, without any publish (the
/// testable form).
pub(crate) fn invite_in(ks: &Keystore, a: InviteArgs) -> anyhow::Result<Report> {
    let invitee = NodeId::from_hex(a.node_id.trim())
        .context("the node id to invite (64 hex characters, as `wires id` prints it)")?;
    let root = ks
        .read_root_identity()?
        .ok_or_else(|| anyhow::anyhow!("no root key here; run `wires init` first"))?;
    let ttl = a.ttl.badge()?;
    let mut ledger = Ledger::load(ks)?;
    if let Some(name) = &a.name {
        check_name(name)?;
        if let Some(held) = ledger.by_label(name)
            && held != invitee
        {
            bail!(
                "--name {name:?} already labels {}; pick another (or `wires remove {name}` first)",
                held.hex()
            );
        }
    }
    let held = super::service::admin_policy(ks, root.node_id())?;
    let now = now_unix();
    let badge = Membership::mint(&root, invitee, now, ttl.not_after(now))?;
    let rejoin = ledger.contains(invitee);
    let ban = held.policy.bans.get(&invitee).map(|b| b.until);
    let stale = held.check_fresh(now).is_err();
    let state = if ban.is_some() || stale {
        edit_policy(ks, a.policy_ttl, |s| {
            s.bans.remove(&invitee);
            Ok(())
        })?
    } else {
        held
    };
    // A lifted ban revives the node's older badges too: the ledger keeps
    // the latest expiry of them all, for the next `remove`.
    ledger.record(
        invitee,
        a.name.clone(),
        badge.not_after.max(ban.unwrap_or(i64::MIN)),
    );
    ledger.save(ks)?;
    // Card 37: a caller's token is its badge, the directory ids and the
    // login settings (under 1 KB at any fabric size); a node the policy
    // names as a host or directory, which holds the whole policy anyway,
    // gets that too.
    let login = super::login_client::LoginClient::load(ks)?.settings(&state.policy);
    let mut invite = Invite::new(badge.clone(), state.directories().to_vec(), login);
    if state.policy.is_host(invitee) || state.directories().contains(&invitee) {
        invite = invite.with_policy(state.signed.clone());
    }
    let token = invite.encode()?;
    let edit = match (ban, stale) {
        (Some(_), _) => format!("lifted its ban: policy version {}", state.version().0),
        (None, true) => format!(
            "re-signed the expired policy: version {}",
            state.version().0
        ),
        (None, false) => format!("policy version {} unchanged", state.version().0),
    };
    let note = format!(
        "{} {}{} (badge until {}; {edit})",
        if rejoin { "re-invited" } else { "invited" },
        invitee.hex(),
        a.name
            .as_deref()
            .map(|n| format!(" as {n:?}"))
            .unwrap_or_default(),
        badge.not_after,
    );
    Ok(Report {
        hint: Some(format!("on the joining machine: wires join {token}")),
        stdout: token,
        notes: vec![note],
        failure: None,
    })
}

/// `remove` against the resolved keystore: a ban in the signed policy, then
/// published to the directories.
pub(crate) async fn remove_cmd(a: RemoveArgs) -> anyhow::Result<Report> {
    run_edit(|ks| remove_in(ks, a)).await
}

/// [`remove_cmd`] against an explicit keystore, without the publish (the
/// testable form).
pub(crate) fn remove_in(ks: &Keystore, a: RemoveArgs) -> anyhow::Result<Report> {
    let mut ledger = Ledger::load(ks)?;
    let (member, label) = resolve_removal(ks, &ledger, &a.member)?;
    let root = ks
        .read_root_identity()?
        .ok_or_else(|| anyhow::anyhow!("no root key here: `wires remove` runs on the admin"))?;
    let held = super::service::admin_policy(ks, root.node_id())?;
    if let Some(ban) = held.policy.bans.get(&member) {
        bail!(
            "{} is already removed (banned until {})",
            member.hex(),
            ban.until
        );
    }
    let now = now_unix();
    let until = ledger.ban_until(member, now);
    let state = edit_policy(ks, a.policy_ttl, |s| {
        s.ban(member, until);
        for svc in s.services.values_mut() {
            svc.hosts.retain(|h| *h != member);
        }
        s.directories.retain(|d| *d != member);
        Ok(())
    })?;
    ledger.forget(member);
    ledger.save(ks)?;
    let banned = if state.policy.bans_node(member) {
        format!("banned until {until}")
    } else {
        // Its badge had already expired: the edit's pruning dropped the ban.
        format!("its badge expired at {until}, so no ban is needed")
    };
    Ok(Report {
        stdout: format!(
            "removed {}{} ({banned}; policy version {}, {} ban(s))",
            member.hex(),
            label.map(|n| format!(" ({n})")).unwrap_or_default(),
            state.version().0,
            state.policy.bans.len()
        ),
        ..Report::default()
    })
}

/// The node `wires remove <text>` means, refusing this machine's own node.
fn resolve_removal(
    ks: &Keystore,
    ledger: &Ledger,
    text: &str,
) -> anyhow::Result<(NodeId, Option<String>)> {
    let (member, label) = resolve_member(ledger, text)?;
    if member == keystore::node_identity_in(ks)?.node_id() {
        bail!(
            "{} is this machine's own node: removing it would leave nobody to sign and publish \
             the next policy from",
            member.hex()
        );
    }
    Ok((member, label))
}

/// A label or a hex node id → the node, and the label it was known by.
pub(crate) fn resolve_member(
    ledger: &Ledger,
    text: &str,
) -> anyhow::Result<(NodeId, Option<String>)> {
    let text = text.trim();
    if let Some(id) = ledger.by_label(text) {
        return Ok((id, Some(text.to_string())));
    }
    match NodeId::from_hex(text) {
        Ok(id) => Ok((id, ledger.get(id).and_then(|i| i.label.clone()))),
        Err(_) => {
            let labels = ledger.labels();
            bail!(
                "{text:?} is neither a name given to `wires invite --name` nor a hex node id \
                 (known names: {})",
                if labels.is_empty() {
                    "none".to_string()
                } else {
                    labels.join(", ")
                }
            )
        }
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
    use crate::admin::init::{InitArgs, init_in};
    use crate::admin::propagate::Propagation;
    use library::{NodeIdentity, StateVersion};

    fn admin() -> Keystore {
        let ks = Keystore::at(crate::testutil::temp_dir());
        init_in(&ks, InitArgs::default()).unwrap();
        ks
    }

    fn invite(ks: &Keystore, node: NodeId, name: Option<&str>) -> Invite {
        let report = invite_in(
            ks,
            InviteArgs {
                node_id: node.hex(),
                name: name.map(str::to_string),
                ttl: Ttl::default(),
                policy_ttl: Ttl::default(),
            },
        )
        .unwrap();
        Invite::decode(&report.stdout).unwrap()
    }

    fn remove(ks: &Keystore, who: &str) -> anyhow::Result<Report> {
        remove_in(
            ks,
            RemoveArgs {
                member: who.into(),
                policy_ttl: Ttl::default(),
            },
        )
    }

    fn stored(ks: &Keystore) -> crate::policy::store::Held {
        let root = ks.read_root_identity().unwrap().unwrap().node_id();
        crate::policy::store::read(ks, root).unwrap().unwrap()
    }

    #[test]
    fn a_member_is_found_by_name_or_by_id() {
        let alice = NodeIdentity::from_seed([2u8; 32]).node_id();
        let bob = NodeIdentity::from_seed([3u8; 32]).node_id();
        let mut ledger = Ledger::default();
        ledger.record(alice, Some("alice".into()), 1);
        assert_eq!(
            resolve_member(&ledger, "alice").unwrap(),
            (alice, Some("alice".into()))
        );
        assert_eq!(
            resolve_member(&ledger, &alice.hex()).unwrap(),
            (alice, Some("alice".into()))
        );
        assert_eq!(resolve_member(&ledger, &bob.hex()).unwrap(), (bob, None));
        let err = resolve_member(&ledger, "carol").unwrap_err();
        assert!(format!("{err:#}").contains("alice"), "{err:#}");
    }

    /// Under strict freshness, removing the last directory would leave
    /// nothing to vouch for the policy: refused, naming the way out, and
    /// nothing changes.
    #[test]
    fn removing_the_last_directory_under_strict_is_refused() {
        let ks = admin();
        let dir = NodeIdentity::from_seed([4u8; 32]).node_id();
        invite(&ks, dir, Some("dir"));
        crate::admin::service::directory_add(&ks, dir, Ttl::default()).unwrap();
        crate::admin::settings::settings_in(
            &ks,
            &crate::admin::settings::SettingsArgs {
                freshness: Some(crate::admin::settings::Freshness::Strict),
                ..Default::default()
            },
        )
        .unwrap();
        let before = stored(&ks).version();
        let err = format!("{:#}", remove(&ks, "dir").unwrap_err());
        assert!(err.contains("freshness is strict"), "{err}");
        assert!(err.contains("--freshness lenient"), "{err}");
        assert_eq!(stored(&ks).version(), before);
        assert_eq!(stored(&ks).directories(), &[dir]);
    }

    #[test]
    fn names_are_one_word_and_not_ids() {
        assert!(check_name("workbench").is_ok());
        assert!(check_name("").is_err());
        assert!(check_name("two words").is_err());
        assert!(check_name(&NodeIdentity::from_seed([2u8; 32]).node_id().hex()).is_err());
    }

    /// Card 35: an invite mints a badge and edits nothing; a removal is a
    /// ban until that badge's expiry, and drops the node's label.
    #[test]
    fn invite_mints_a_badge_and_remove_bans_it() {
        let ks = admin();
        let v1 = stored(&ks).version();
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let invite = invite(&ks, alice.node_id(), Some("alice"));
        invite.verify(&alice, now_unix()).unwrap();
        assert_eq!(stored(&ks).version(), v1, "no edit");
        assert_eq!(invite.policy, None, "a caller gets no policy");
        assert_eq!(invite.directories, stored(&ks).directories());
        let issued = Ledger::load(&ks).unwrap();
        assert_eq!(
            issued.get(alice.node_id()).unwrap().not_after,
            invite.membership.not_after
        );

        let removed = remove(&ks, "alice").unwrap();
        assert!(
            removed
                .stdout
                .contains(&format!("policy version {}", v1.0 + 1)),
            "{}",
            removed.stdout
        );
        let state = stored(&ks);
        assert_eq!(
            state.policy.bans.get(&alice.node_id()).map(|b| b.until),
            Some(invite.membership.not_after),
            "banned until the badge would expire"
        );
        assert_eq!(Ledger::load(&ks).unwrap().by_label("alice"), None);
        // Removing again, or removing this machine's own node, is refused.
        let again = remove(&ks, &alice.node_id().hex()).unwrap_err();
        assert!(
            format!("{again:#}").contains("already removed"),
            "{again:#}"
        );
        let me = keystore::node_identity_in(&ks).unwrap().node_id().hex();
        assert!(format!("{:#}", remove(&ks, &me).unwrap_err()).contains("own node"));
    }

    #[test]
    fn a_node_the_ledger_never_saw_is_banned_for_the_longest_badge() {
        let ks = admin();
        let stranger = NodeIdentity::from_seed([7u8; 32]).node_id();
        let before = now_unix();
        remove(&ks, &stranger.hex()).unwrap();
        let until = stored(&ks).policy.bans[&stranger].until;
        assert!(until >= Ttl::max_badge().not_after(before), "{until}");
        assert!(until <= Ttl::max_badge().not_after(now_unix()), "{until}");
    }

    /// Re-inviting a removed node is the one invite that edits: it lifts
    /// the ban, and the ledger remembers the old badge's expiry too.
    #[test]
    fn re_inviting_a_removed_node_lifts_its_ban() {
        let ks = admin();
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let first = invite(&ks, alice.node_id(), None);
        remove(&ks, &alice.node_id().hex()).unwrap();
        let banned = stored(&ks).version();
        let back = invite(&ks, alice.node_id(), None);
        back.verify(&alice, now_unix()).unwrap();
        assert_eq!(stored(&ks).version(), StateVersion(banned.0 + 1));
        assert!(!stored(&ks).policy.bans_node(alice.node_id()));
        assert!(
            Ledger::load(&ks)
                .unwrap()
                .get(alice.node_id())
                .unwrap()
                .not_after
                >= first.membership.not_after
        );
    }

    /// Card 35's first acceptance: onboarding 1,000 nodes changes no policy
    /// version and publishes nothing, and the policy's size doesn't depend
    /// on how many badges were issued.
    #[tokio::test]
    async fn onboarding_a_thousand_nodes_edits_nothing_and_pushes_nothing() {
        let ks = admin();
        let before = stored(&ks);
        let size = |p: &library::SignedPolicy| serde_json::to_vec(p).unwrap().len();
        let bytes = size(&before.signed);
        let pushes = std::cell::Cell::new(0usize);
        for i in 0..1_000u32 {
            let mut seed = [9u8; 32];
            seed[..4].copy_from_slice(&i.to_le_bytes());
            let node = NodeIdentity::from_seed(seed).node_id();
            let report = super::super::run_if_edited_in(
                &ks,
                |ks| {
                    invite_in(
                        ks,
                        InviteArgs {
                            node_id: node.hex(),
                            name: None,
                            ttl: Ttl::default(),
                            policy_ttl: Ttl::default(),
                        },
                    )
                },
                async |_, _| {
                    pushes.set(pushes.get() + 1);
                    Propagation {
                        note: String::new(),
                        failure: None,
                    }
                },
            )
            .await
            .unwrap();
            let invite = Invite::decode(&report.stdout).unwrap();
            assert!(invite.policy.is_none());
        }
        assert_eq!(pushes.get(), 0, "nothing was pushed");
        let after = stored(&ks);
        assert_eq!(after, before, "no edit");
        assert_eq!(size(&after.signed), bytes);
        // A removal is an edit, so it does push.
        let victim = NodeIdentity::from_seed([9u8; 32]).node_id();
        super::super::run_if_edited_in(
            &ks,
            |ks| remove(ks, &victim.hex()),
            async |_, _| {
                pushes.set(pushes.get() + 1);
                Propagation {
                    note: String::new(),
                    failure: None,
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(pushes.get(), 1);
    }

    /// Card 37: a caller's token is its badge, the directory ids and the
    /// login settings, under 1 KB however large the fabric grows (here with
    /// a Google-sized client id and public secret, three directories (it
    /// carries the first two), and a
    /// thousand services); a host's carries the whole policy too.
    #[test]
    fn a_callers_invite_is_under_1_kb_at_any_fabric_size() {
        use library::{Audience, Issuer, RoleName, Service, ServiceName};
        let ks = admin();
        let google = Issuer::new(library::GOOGLE_ISSUER);
        let client = concat!(
            "123456789012-",
            "abcdefghijklmnopqrstuvwxyz012345",
            ".apps.googleusercontent.com"
        );
        super::super::service::issuer_set(
            &ks,
            google.clone(),
            super::super::service::issuer_config(client, &[]).unwrap(),
            Ttl::default(),
        )
        .unwrap();
        super::super::login_client::LoginClient::record(
            &ks,
            &google,
            Some(concat!("GOCSPX", "-abcdefghijklmnopqrstuvwxyz01")),
            true,
        )
        .unwrap();
        let (d1, d2, host) = (
            NodeIdentity::from_seed([31u8; 32]).node_id(),
            NodeIdentity::from_seed([32u8; 32]).node_id(),
            NodeIdentity::from_seed([33u8; 32]).node_id(),
        );
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let mut sizes = Vec::new();
        for services in [0usize, 100, 1000] {
            edit_policy(&ks, Ttl::default(), |p| {
                p.directories = vec![d1, d2, NodeIdentity::from_seed([34u8; 32]).node_id()];
                let staff = RoleName::new("staff").unwrap();
                p.roles.insert(
                    staff.clone(),
                    vec![library::Matcher::new(library::GOOGLE_ISSUER)],
                );
                for i in p.services.len()..services {
                    p.services.insert(
                        ServiceName::new(format!("svc-{i}")).unwrap(),
                        Service {
                            description: "a service with an ordinary description".into(),
                            allow: vec![staff.clone()],
                            hosts: vec![host],
                            readers: vec![],
                        },
                    );
                }
                Ok(())
            })
            .unwrap();
            let report = invite_in(
                &ks,
                InviteArgs {
                    node_id: alice.node_id().hex(),
                    name: None,
                    ttl: Ttl::default(),
                    policy_ttl: Ttl::default(),
                },
            )
            .unwrap();
            let token = report.stdout;
            assert!(
                token.len() < 1024,
                "{services} services: {} bytes",
                token.len()
            );
            sizes.push(token.len());
            let invite = Invite::decode(&token).unwrap();
            invite.verify(&alice, now_unix()).unwrap();
            assert_eq!(invite.directories, vec![d1, d2]);
            let login = invite.login.unwrap();
            assert_eq!(login.issuer, google);
            assert_eq!(login.client_id, Audience::new(client));
            assert!(login.public_client_secret.is_some());
            assert!(invite.policy.is_none());
        }
        assert!(sizes.windows(2).all(|w| w[0] == w[1]), "{sizes:?}");
        // A host the policy names gets the whole policy.
        let host_invite = invite(&ks, host, None);
        assert_eq!(host_invite.policy, Some(stored(&ks).signed));
        // The secret is not in the signed policy.
        let text = serde_json::to_string(&stored(&ks).signed).unwrap();
        assert!(!text.contains("GOCSPX"));
    }

    /// Card 28 §8: `invite --ttl` is the badge's lifetime only, capped at
    /// 30 days; the policy's comes from `--policy-ttl`, and never moves
    /// earlier.
    #[test]
    fn invite_ttl_is_the_badge_and_never_shortens_the_policy() {
        let ks = admin();
        let before = stored(&ks).policy.not_after;
        let alice = NodeIdentity::from_seed([2u8; 32]);
        let report = invite_in(
            &ks,
            InviteArgs {
                node_id: alice.node_id().hex(),
                name: None,
                ttl: "1h".parse().unwrap(),
                policy_ttl: Ttl::default(),
            },
        )
        .unwrap();
        let invite = Invite::decode(&report.stdout).unwrap();
        let now = now_unix();
        assert!(invite.membership.not_after <= now + 3600);
        assert_eq!(stored(&ks).policy.not_after, before);
        let long = invite_in(
            &ks,
            InviteArgs {
                node_id: alice.node_id().hex(),
                name: None,
                ttl: "90d".parse().unwrap(),
                policy_ttl: Ttl::default(),
            },
        );
        assert!(format!("{:#}", long.unwrap_err()).contains("at most"));
    }
}

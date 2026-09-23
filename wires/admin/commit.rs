//! One roster commit, end to end: sign it, tell the channel, install it here.
//!
//! What `wires init`, `wires invite` and `wires remove` share. The old
//! four-step dance (`roster add|remove` → `roster commit --out DIR` → hand
//! every member its `<node-id>.proof` and `<node-id>.key` → each runs
//! `advanced import`) becomes one call: the commit is sealed into a
//! [`Rekey`] (the head, and per member its proof and sealed fabric key),
//! published on the channel for the members that already hold the outgoing
//! key, and installed into this keystore, whose node is a member too.
//!
//! # Publish under the old commit, install the new one after
//!
//! The record goes out **before** this node adopts the commit, under the
//! credentials it had a moment ago — the old head, proof and key — because
//! those are the only ones the other members can check and open: they have
//! not heard of the new commit yet, their ingest floor is the old version,
//! and the re-key is how they hear. Only then does this node install its own
//! part. `roster.json` is bumped first, before anything is published, so a
//! crash in between cannot hand out two different commits under one version.

use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use library::{
    FabricKey, NodeId, NodeIdentity, REKEY_ENTRIES_PER_RECORD, Rekey, RekeyEntry, Roster,
    SealedFabricKey,
};

use super::keystore::Keystore;
use crate::channel::context::{TopicArgs, TopicContext};
use crate::channel::publish::{self, Messages};
use crate::channel::{ipc, rekey, topics};
use crate::now_unix;

/// A lifetime typed the way people say it: `30d`, `12h`, `90m`, `45s`, `2w`,
/// or bare seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ttl(i64);

impl Ttl {
    /// The default for heads and memberships minted by `init` / `invite` /
    /// `remove`: long, because nothing renews them yet (card 14 notes the
    /// renewal story as a follow-up).
    pub(crate) const DEFAULT: &'static str = "30d";

    /// The expiry `now_unix + self`, saturating.
    pub(crate) fn not_after(self, now_unix: i64) -> i64 {
        now_unix.saturating_add(self.0)
    }
}

impl FromStr for Ttl {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (digits, unit) = match s.char_indices().last() {
            Some((i, c)) if c.is_ascii_alphabetic() => (&s[..i], c),
            _ => (s, 's'),
        };
        let n: i64 = digits
            .parse()
            .map_err(|_| format!("{s:?} is not a lifetime (try 30d, 12h, 90m or 3600)"))?;
        let unit = match unit {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            'w' => 7 * 86_400,
            other => {
                return Err(format!(
                    "unknown unit {other:?} in {s:?} (use s, m, h, d or w)"
                ));
            }
        };
        if n <= 0 {
            return Err(format!("{s:?}: a lifetime must be positive"));
        }
        n.checked_mul(unit)
            .map(Ttl)
            .ok_or_else(|| format!("{s:?} is too long"))
    }
}

/// How the commit reached the other members.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Told {
    /// No other member held the outgoing key — nobody to tell.
    Nobody,
    /// Handed to this machine's resident `wires watch`, which broadcasts it.
    Resident,
    /// Broadcast one-shot; this peer was reached.
    Neighbor(NodeId),
    /// No peer answered: the record is in this node's log only, and reaches
    /// the others when a node of this keystore is next on the channel.
    StoredOnly,
}

/// How long a one-shot distribution waits for a neighbor and lingers after
/// broadcasting (the [`publish`] constants in production; short in tests).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Timing {
    /// The first-neighbor wait.
    pub(crate) wait: Duration,
    /// The post-broadcast linger.
    pub(crate) linger: Duration,
}

impl Timing {
    /// The CLI's timing.
    pub(crate) const CLI: Timing = Timing {
        wait: publish::PUBLISH_NEIGHBOR_WAIT,
        linger: publish::PUBLISH_LINGER,
    };
}

/// A commit, signed, told and installed.
#[derive(Debug)]
pub(crate) struct Committed {
    /// The whole commit: the head and every member's entry.
    pub(crate) rekey: Rekey,
    /// How the other members heard of it.
    pub(crate) told: Told,
}

impl Committed {
    /// `member`'s entry in this commit.
    pub(crate) fn entry_for(&self, member: NodeId) -> Option<&RekeyEntry> {
        self.rekey.entry_for(member)
    }

    /// One human line on how the commit went out.
    pub(crate) fn told_line(&self) -> String {
        let v = self.rekey.head.version.0;
        match &self.told {
            Told::Nobody => format!("roster version {v}: no other member to re-key"),
            Told::Resident => {
                format!("roster version {v}: re-key handed to this machine's `wires watch`")
            }
            Told::Neighbor(peer) => format!(
                "roster version {v}: re-key published on the channel (via {}…)",
                &peer.hex()[..8]
            ),
            Told::StoredOnly => format!(
                "roster version {v}: no member was reachable — the re-key is stored here and goes \
                 out the next time this machine is on the channel (`wires watch`); a member that \
                 missed it can also be re-invited"
            ),
        }
    }
}

/// Commit `roster` under `root` with no one to tell: mint, seal, persist, and
/// install this node's part. `wires init`'s commit.
pub(crate) fn commit_locally(
    ks: &Keystore,
    root: &NodeIdentity,
    me: &NodeIdentity,
    roster: &mut Roster,
    not_after: i64,
) -> anyhow::Result<Rekey> {
    let now = now_unix();
    let rekey = seal_commit(root, roster, now, not_after)?;
    ks.save_roster(roster)?;
    rekey::install(&rekey, me, root.node_id(), ks, now)?;
    Ok(rekey)
}

/// Commit `roster` under `root`, publish the re-key to the members that were
/// already in (see the module docs for the order), and install this node's
/// part. `bind` stands up the one-shot node when no resident `wires watch`
/// holds the channel. `newcomer` is a member this very commit adds (the
/// invitee): it holds no key yet, so it is not among those told — its part
/// travels in its invite token.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn commit_and_distribute<B>(
    ks: &Arc<Keystore>,
    home: &Path,
    root: &NodeIdentity,
    roster: &mut Roster,
    newcomer: Option<NodeId>,
    not_after: i64,
    timing: Timing,
    bind: B,
) -> anyhow::Result<Committed>
where
    B: AsyncFnOnce(topics::TopicNodeConfig) -> anyhow::Result<topics::TopicNode>,
{
    let channel = ks
        .read_channel()?
        .ok_or_else(|| anyhow::anyhow!("this keystore has no channel; run `wires init` first"))?;
    let me = super::keystore::node_identity_in(ks)?;
    // Resolved *before* the commit is installed: these are the credentials the
    // other members can still check (module docs).
    let ctx = TopicContext::resolve(
        Arc::clone(ks),
        home.to_path_buf(),
        &TopicArgs {
            topic: channel,
            ..TopicArgs::default()
        },
    )
    .context("this node's own credentials for the channel")?;
    let mut before = roster.members.clone();
    if let Some(newcomer) = newcomer {
        before.remove(&newcomer);
    }

    let now = now_unix();
    let rekey = seal_commit(root, roster, now, not_after)?;
    ks.save_roster(roster)?;

    let others = rekey
        .entries
        .iter()
        .filter(|e| e.member() != me.node_id() && before.contains(&e.member()))
        .count();
    let told = if others == 0 {
        Told::Nobody
    } else {
        let mut texts = std::collections::VecDeque::new();
        for part in Rekey::chunks(
            rekey.head.clone(),
            rekey.entries.clone(),
            REKEY_ENTRIES_PER_RECORD,
        ) {
            texts.push_back(library::ChannelRecord::Rekey(part).to_text()?);
        }
        match ipc::ControlClient::connect(&ctx.socket_path()).await? {
            Some(client) => {
                publish::publish_through_tail(&ctx, client, Messages::Many(texts)).await?;
                Told::Resident
            }
            None => match publish::publish_one_shot_on(
                &ctx,
                Messages::Many(texts),
                timing.wait,
                timing.linger,
                bind,
            )
            .await?
            {
                Some(peer) => Told::Neighbor(peer),
                None => Told::StoredOnly,
            },
        }
    };

    rekey::install(&rekey, &me, root.node_id(), ks, now_unix())
        .context("installing this node's part of the commit")?;
    Ok(Committed { rekey, told })
}

/// Sign the next head over `roster`, mint one fabric key, and seal it to every
/// member — all before anything is persisted, because sealing is the step
/// that can fail on operator input (a weak or malformed node id; see
/// `roster commit`).
fn seal_commit(
    root: &NodeIdentity,
    roster: &mut Roster,
    now: i64,
    not_after: i64,
) -> anyhow::Result<Rekey> {
    let mut draft = roster.clone();
    let (head, proofs) = draft.commit(root, now, not_after)?;
    let key = FabricKey::generate();
    let entries = proofs
        .into_iter()
        .map(|(member, proof)| {
            let key = SealedFabricKey::seal(root, member, head.version, &key)
                .with_context(|| format!("sealing the fabric key to {}", member.hex()))?;
            anyhow::Ok(RekeyEntry { proof, key })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    *roster = draft;
    Ok(Rekey::new(head, entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn lifetimes_parse_the_way_people_type_them() {
        assert_eq!("30d".parse(), Ok(Ttl(30 * 86_400)));
        assert_eq!("12h".parse(), Ok(Ttl(12 * 3600)));
        assert_eq!("90m".parse(), Ok(Ttl(5400)));
        assert_eq!("45s".parse(), Ok(Ttl(45)));
        assert_eq!("2w".parse(), Ok(Ttl(14 * 86_400)));
        assert_eq!("3600".parse(), Ok(Ttl(3600)));
        for bad in ["", "d", "0d", "-1h", "3y", "1.5h", "99999999999999999w"] {
            assert!(bad.parse::<Ttl>().is_err(), "{bad:?} parsed");
        }
        assert_eq!(
            Ttl::DEFAULT.parse::<Ttl>().unwrap().not_after(100),
            100 + 30 * 86_400
        );
    }

    #[test]
    fn a_bad_member_key_leaves_the_roster_untouched() {
        let root = NodeIdentity::from_seed([1u8; 32]);
        let mut roster = Roster::new(root.node_id());
        roster.insert(NodeIdentity::from_seed([2u8; 32]).node_id());
        // The identity point: a well-formed 64-hex "node id" that is weak.
        let mut weak = [0u8; 32];
        weak[0] = 1;
        roster.insert(NodeId::from_bytes(weak));
        let before = roster.clone();
        assert!(seal_commit(&root, &mut roster, 0, i64::MAX).is_err());
        assert_eq!(roster, before, "the version was not consumed");
    }

    proptest! {
        #[test]
        fn every_unit_scales(n in 1i64..100_000, unit in prop::sample::select(vec!['s', 'm', 'h', 'd', 'w'])) {
            let secs = match unit { 's' => 1, 'm' => 60, 'h' => 3600, 'd' => 86_400, _ => 604_800 };
            prop_assert_eq!(format!("{n}{unit}").parse::<Ttl>(), Ok(Ttl(n * secs)));
        }

        /// A commit seals one key to every member and nobody else.
        #[test]
        fn a_commit_carries_every_member(n in 1u8..6) {
            let root = NodeIdentity::from_seed([1u8; 32]);
            let mut roster = Roster::new(root.node_id());
            let members: Vec<_> = (0..n).map(|i| NodeIdentity::from_seed([10 + i; 32])).collect();
            for m in &members { roster.insert(m.node_id()); }
            let rekey = seal_commit(&root, &mut roster, 0, i64::MAX).unwrap();
            prop_assert_eq!(rekey.head.version, roster.version);
            prop_assert!(rekey.verify(root.node_id(), 0).is_ok());
            let key = rekey.open_for(&members[0], root.node_id()).unwrap().unwrap().1;
            for m in &members {
                prop_assert_eq!(&rekey.open_for(m, root.node_id()).unwrap().unwrap().1, &key);
            }
        }
    }
}

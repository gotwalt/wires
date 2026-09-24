//! `issued.json`: the admin's private ledger of the badges it minted.
//!
//! The signed policy lists no members (card 35): a node is admitted by its
//! root-signed badge. So the admin keeps its own record of what it issued,
//! for two things:
//!
//! - **Bans.** `wires remove` bans a node until its badge would expire
//!   anyway ([`Ledger::ban_until`]), so the ban can drop out of the policy
//!   then. A node missing from the ledger (a lost ledger, an id typed by
//!   hand) is banned for the longest badge lifetime `invite` allows
//!   ([`Ttl::MAX_BADGE`]), which outlasts any badge this admin could have
//!   minted since.
//! - **Labels.** `invite --name alice` records the label, for `wires remove
//!   alice` and `wires service add --host alice`. Labels are not identity:
//!   nothing on the wire carries them. (This file replaces `names.json`.)
//!
//! The ledger is policy-adjacent but not policy: it is never signed, never
//! sent, and says who is in, so it is kept `0600` in the admin's keystore.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use library::NodeId;
use serde::{Deserialize, Serialize};

use super::keystore::{Keystore, create_private_dir, write_text_mode};
use super::ttl::Ttl;

/// The ledger's file name in the admin's keystore.
pub(crate) const LEDGER_FILE: &str = "issued.json";

/// What the admin issued to one node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Issued {
    /// The local label (`invite --name`), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) label: Option<String>,
    /// The latest expiry among the badges minted for this node, unix
    /// seconds: until then, some badge of its may still admit it.
    pub(crate) not_after: i64,
}

/// Every node the admin minted a badge for: node → [`Issued`]. See the
/// module docs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct Ledger(BTreeMap<NodeId, Issued>);

impl Ledger {
    /// Read the ledger from `ks`; empty when there is none yet.
    pub(crate) fn load(ks: &Keystore) -> Result<Ledger> {
        let path = ks.path(LEDGER_FILE);
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Ledger::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Write the ledger to `ks` (mode `0600`: it says who is in).
    pub(crate) fn save(&self, ks: &Keystore) -> Result<()> {
        create_private_dir(&ks.path(""))?;
        let json = serde_json::to_string_pretty(self).context("encoding the ledger")?;
        write_text_mode(&ks.path(LEDGER_FILE), &format!("{json}\n"), Some(0o600))
    }

    /// Record a badge minted for `node` until `not_after`. The node keeps
    /// the later of its expiries (an earlier badge may outlive a newer,
    /// shorter one), and `label`, when given, replaces its label.
    pub(crate) fn record(&mut self, node: NodeId, label: Option<String>, not_after: i64) {
        let entry = self.0.entry(node).or_insert(Issued {
            label: None,
            not_after,
        });
        entry.not_after = entry.not_after.max(not_after);
        if label.is_some() {
            entry.label = label;
        }
    }

    /// Forget `node` (it was removed): what the ledger held for it.
    pub(crate) fn forget(&mut self, node: NodeId) -> Option<Issued> {
        self.0.remove(&node)
    }

    /// What the ledger holds for `node`.
    pub(crate) fn get(&self, node: NodeId) -> Option<&Issued> {
        self.0.get(&node)
    }

    /// Whether this admin minted a badge for `node`.
    pub(crate) fn contains(&self, node: NodeId) -> bool {
        self.0.contains_key(&node)
    }

    /// The node labelled `label`, if any.
    pub(crate) fn by_label(&self, label: &str) -> Option<NodeId> {
        self.0
            .iter()
            .find(|(_, i)| i.label.as_deref() == Some(label))
            .map(|(n, _)| *n)
    }

    /// Every label, in order (for "known names: …").
    pub(crate) fn labels(&self) -> Vec<String> {
        let mut out: Vec<String> = self.0.values().filter_map(|i| i.label.clone()).collect();
        out.sort();
        out
    }

    /// How long a ban on `node` must last, from `now`: the latest expiry of
    /// the badges recorded for it, or, for a node this ledger doesn't know,
    /// the longest lifetime a badge minted from now could have
    /// ([`Ttl::MAX_BADGE`]).
    pub(crate) fn ban_until(&self, node: NodeId, now: i64) -> i64 {
        match self.get(node) {
            Some(issued) => issued.not_after,
            None => Ttl::max_badge().not_after(now),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::NodeIdentity;
    use proptest::prelude::*;

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    #[test]
    fn a_ledger_round_trips_through_the_keystore_privately() {
        let ks = Keystore::at(crate::testutil::temp_dir());
        assert_eq!(Ledger::load(&ks).unwrap(), Ledger::default());
        let mut l = Ledger::default();
        l.record(node(2), Some("alice".into()), 100);
        l.record(node(3), None, 200);
        l.save(&ks).unwrap();
        assert_eq!(Ledger::load(&ks).unwrap(), l);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(ks.path(LEDGER_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn labels_find_nodes_and_a_new_label_replaces_the_old() {
        let mut l = Ledger::default();
        l.record(node(2), Some("alice".into()), 100);
        assert_eq!(l.by_label("alice"), Some(node(2)));
        l.record(node(2), None, 100);
        assert_eq!(l.by_label("alice"), Some(node(2)), "no label keeps the old");
        l.record(node(2), Some("al".into()), 100);
        assert_eq!(l.by_label("alice"), None);
        assert_eq!(l.labels(), vec!["al".to_string()]);
        assert!(l.forget(node(2)).is_some());
        assert!(!l.contains(node(2)));
    }

    #[test]
    fn an_unknown_node_is_banned_for_the_longest_badge() {
        let mut l = Ledger::default();
        l.record(node(2), None, 500);
        assert_eq!(l.ban_until(node(2), 1_000), 500);
        assert_eq!(
            l.ban_until(node(9), 1_000),
            Ttl::max_badge().not_after(1_000)
        );
    }

    proptest! {
        /// Whatever order badges are recorded in, a node's ban lasts until
        /// the latest of them expires.
        #[test]
        fn the_ban_outlasts_every_recorded_badge(expiries in proptest::collection::vec(any::<i64>(), 1..8)) {
            let mut l = Ledger::default();
            for e in &expiries {
                l.record(node(2), None, *e);
            }
            prop_assert_eq!(l.ban_until(node(2), 0), *expiries.iter().max().unwrap());
        }
    }
}

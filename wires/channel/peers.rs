//! The peers this node knows on a topic, persisted across restarts.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use library::{NodeId, TopicId, TopicPeer};

/// The peers this node knows on a topic, persisted across restarts.
///
/// There is no discovery service (spec §10): a tail that is restarted with no
/// `--peer` must still find its way back to the mesh, so every peer learned
/// from a ticket or from a `NeighborUp` is written to
/// `topics/<topic-hex>.peers.json`. Hints only — admission still decides who is
/// in — so a stale file costs a failed dial, never an admission.
pub(crate) struct PeerBook {
    /// Where the list is persisted.
    pub(crate) path: PathBuf,
    /// Known peers by node id; a hint with addresses replaces one without.
    pub(crate) peers: HashMap<NodeId, TopicPeer>,
}

impl PeerBook {
    /// Load the persisted peers for `topic` (an unreadable file is a warning
    /// and an empty book — a corrupt hint list must not stop a tail).
    pub(crate) fn open(home: &Path, topic: TopicId) -> Self {
        let path = peers_path(home, topic);
        let peers = match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<Vec<TopicPeer>>(&text) {
                Ok(list) => list.into_iter().map(|p| (p.node, p)).collect(),
                Err(e) => {
                    tracing::warn!(path = %path.display(), "ignoring an unreadable peer list: {e}");
                    HashMap::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => {
                tracing::warn!(path = %path.display(), "ignoring an unreadable peer list: {e}");
                HashMap::new()
            }
        };
        Self { path, peers }
    }

    /// Record `peer`, returning whether anything changed.
    ///
    /// A hint that carries addresses wins over one that does not: the ticket
    /// form knows where the peer was, and a `NeighborUp` only knows who it is.
    pub(crate) fn record(&mut self, peer: TopicPeer) -> bool {
        match self.peers.get(&peer.node) {
            Some(held) if held == &peer => false,
            Some(held)
                if peer.addrs.is_empty() && peer.relay_url.is_none() && !held.addrs.is_empty() =>
            {
                false
            }
            _ => {
                self.peers.insert(peer.node, peer);
                true
            }
        }
    }

    /// The known peers, in node-id order (so the file is stable).
    pub(crate) fn list(&self) -> Vec<TopicPeer> {
        let mut peers: Vec<_> = self.peers.values().cloned().collect();
        peers.sort_by_key(|p| p.node);
        peers
    }

    /// Persist the list (best effort: a tail that cannot write its hints is
    /// still a working tail).
    pub(crate) fn save(&self) {
        if let Err(e) = self.try_save() {
            tracing::warn!(path = %self.path.display(), "could not persist the peer list: {e:#}");
        }
    }

    fn try_save(&self) -> anyhow::Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let text = serde_json::to_string_pretty(&self.list())?;
        std::fs::write(&self.path, text)
            .with_context(|| format!("writing {}", self.path.display()))?;
        Ok(())
    }
}

/// Where a topic's persisted peer hints live.
fn peers_path(home: &Path, topic: TopicId) -> PathBuf {
    home.join("topics")
        .join(format!("{}.peers.json", topic.hex()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;
    use library::NodeIdentity;

    #[test]
    fn the_peer_book_unions_hints_and_survives_a_restart() {
        let home = temp_dir();
        let topic = TopicId::derive(NodeIdentity::from_seed([1u8; 32]).node_id(), "ops");
        let node = NodeIdentity::from_seed([2u8; 32]).node_id();
        let hinted = TopicPeer::new(node).with_addrs(vec!["127.0.0.1:9".parse().unwrap()]);

        let mut book = PeerBook::open(&home, topic);
        assert!(book.list().is_empty());
        assert!(book.record(hinted.clone()));
        assert!(
            !book.record(hinted.clone()),
            "recording twice changes nothing"
        );
        // A bare `NeighborUp` for a peer whose addresses are known must not
        // erase them — a hint with no address is not an improvement.
        assert!(!book.record(TopicPeer::new(node)));
        assert_eq!(book.list(), vec![hinted.clone()]);
        book.save();

        // A second peer, learned live, joins the file.
        let live = NodeIdentity::from_seed([3u8; 32]).node_id();
        assert!(book.record(TopicPeer::new(live)));
        book.save();

        let reopened = PeerBook::open(&home, topic);
        let mut expected = vec![hinted, TopicPeer::new(live)];
        expected.sort_by_key(|p| p.node);
        assert_eq!(reopened.list(), expected);
        assert!(peers_path(&home, topic).is_file());
    }

    #[test]
    fn a_corrupt_peer_file_is_ignored_rather_than_fatal() {
        let home = temp_dir();
        let topic = TopicId::derive(NodeIdentity::from_seed([1u8; 32]).node_id(), "ops");
        let path = peers_path(&home, topic);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{not json").unwrap();
        assert!(PeerBook::open(&home, topic).list().is_empty());
    }
}

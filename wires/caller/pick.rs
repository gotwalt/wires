//! Service name → host (card 27, lane **27b**). The caller never names a
//! host: it takes the service's `hosts` from the signed state, tries the
//! last one that worked first, then the rest in the admin's order, moving to
//! the next on a dial failure (not on a refusal: a host that refused has
//! decided). `--verbose` says which host answered.
//!
//! The last host that answered for each service is remembered in
//! `$WIRES_HOME/last-good.json` ([`LastGood`]); a hint, never an authority —
//! a host the state no longer assigns is skipped.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use iroh::EndpointAddr;
use library::{NodeId, ServiceName, State, TopicId};
use serde::{Deserialize, Serialize};

use crate::admin::keystore::Keystore;
use crate::host::transport;

/// The file name under `$WIRES_HOME`.
pub(crate) const LAST_GOOD_FILE: &str = "last-good.json";

/// The hosts to try for `service`, in order: `last_good` first if it still
/// implements it, then the registry's order. Empty if the service is unknown
/// or has no hosts.
pub(crate) fn candidates(
    state: &State,
    service: &ServiceName,
    last_good: Option<NodeId>,
) -> Vec<NodeId> {
    let Some(svc) = state.service(service) else {
        return Vec::new();
    };
    let mut hosts = svc.hosts.clone();
    if let Some(good) = last_good
        && let Some(at) = hosts.iter().position(|h| *h == good)
    {
        let good = hosts.remove(at);
        hosts.insert(0, good);
    }
    hosts
}

/// `last-good.json`: service → the host that last answered it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LastGood(BTreeMap<ServiceName, NodeId>);

impl LastGood {
    /// `$WIRES_HOME/last-good.json`.
    pub(crate) fn path(ks: &Keystore) -> PathBuf {
        ks.path(LAST_GOOD_FILE)
    }

    /// Load from `path`; missing or unreadable is empty (it is only a hint).
    pub(crate) fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    /// The host that last answered `service`.
    pub(crate) fn get(&self, service: &ServiceName) -> Option<NodeId> {
        self.0.get(service).copied()
    }

    /// Remember that `host` answered `service`, and save (best effort).
    pub(crate) fn record(path: &Path, service: &ServiceName, host: NodeId) {
        let mut me = Self::load(path);
        if me.0.get(service) == Some(&host) {
            return;
        }
        me.0.insert(service.clone(), host);
        let saved = serde_json::to_string_pretty(&me)
            .map_err(anyhow::Error::from)
            .and_then(|json| {
                crate::admin::keystore::write_text_mode(path, &format!("{json}\n"), Some(0o600))
            });
        if let Err(e) = saved {
            tracing::debug!("remembering the last good host: {e:#}");
        }
    }
}

/// Dial hints this node already holds for hosts: address and relay hints
/// from the channel's `directory.json` and peer book, when a channel is
/// joined. Dialing by key alone works without them (iroh discovery); they
/// only make it faster, or possible on a network without discovery.
#[derive(Clone, Debug, Default)]
pub(crate) struct Hints(BTreeMap<NodeId, (Vec<std::net::SocketAddr>, Option<String>)>);

impl Hints {
    /// What `ks` knows; empty when no channel is joined.
    pub(crate) fn load(ks: &Keystore, fabric: NodeId) -> Self {
        let home = ks.path("");
        let home = home.as_path();
        let mut out = BTreeMap::new();
        let Ok(Some(channel)) = ks.read_channel() else {
            return Self(out);
        };
        let topic = TopicId::derive(fabric, &channel);
        for p in crate::channel::peers::PeerBook::open(home, topic).list() {
            out.insert(p.node, (p.addrs, p.relay_url));
        }
        let dir = crate::caller::resolve::Directory::load(
            &crate::caller::resolve::Directory::path(home),
            &channel,
        );
        for h in dir.hosts {
            let entry = out.entry(h.node).or_insert_with(|| (Vec::new(), None));
            if !h.listing.addrs.is_empty() {
                entry.0 = h.listing.addrs.clone();
            }
            if h.listing.relay_url.is_some() {
                entry.1 = h.listing.relay_url.clone();
            }
        }
        Self(out)
    }

    /// Hints for exactly these hosts, for tests and pinned setups.
    #[cfg(test)]
    pub(crate) fn from_pairs(
        pairs: impl IntoIterator<Item = (NodeId, Vec<std::net::SocketAddr>)>,
    ) -> Self {
        Self(pairs.into_iter().map(|(n, a)| (n, (a, None))).collect())
    }

    /// `hosts` as dial targets, in order: each with its hints, and `relay`
    /// when no hint names one. A key that isn't a valid Ed25519 point is
    /// skipped.
    pub(crate) fn targets(&self, hosts: &[NodeId], relay: Option<&str>) -> Vec<EndpointAddr> {
        hosts
            .iter()
            .filter_map(|h| {
                let (addrs, hint_relay) = self.0.get(h).cloned().unwrap_or_default();
                let relay = relay.map(str::to_string).or(hint_relay);
                transport::endpoint_addr(h, &addrs, relay.as_deref()).ok()
            })
            .collect()
    }
}

/// The short form of a host key that `--verbose` prints.
pub(crate) fn short(node: &NodeId) -> String {
    node.hex()[..8].to_string()
}

/// Every host of the services in `names`, once each, in first-seen order
/// (for `wires inbox`: fetch from the hosts of the services you use).
pub(crate) fn hosts_of<'a>(
    state: &State,
    names: impl IntoIterator<Item = &'a ServiceName>,
) -> Vec<NodeId> {
    let mut out: Vec<NodeId> = Vec::new();
    for name in names {
        for h in state
            .service(name)
            .map(|s| s.hosts.clone())
            .unwrap_or_default()
        {
            if !out.contains(&h) {
                out.push(h);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{NodeIdentity, RoleName, Service, StateVersion};

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    fn state() -> State {
        let mut s = State::new(node(1));
        s.version = StateVersion(1);
        s.members.extend([node(2), node(3), node(4)]);
        s.hosts.extend([node(2), node(3)]);
        let svc = |hosts: Vec<NodeId>| Service {
            description: String::new(),
            allow: vec![RoleName::member()],
            hosts,
            readers: vec![],
        };
        s.services.insert(
            ServiceName::new("orders-db").unwrap(),
            svc(vec![node(2), node(3)]),
        );
        s.services
            .insert(ServiceName::new("status").unwrap(), svc(vec![node(3)]));
        s
    }

    #[test]
    fn last_good_first_then_registry_order() {
        let s = state();
        let name = ServiceName::new("orders-db").unwrap();
        assert_eq!(candidates(&s, &name, None), vec![node(2), node(3)]);
        assert_eq!(candidates(&s, &name, Some(node(3))), vec![node(3), node(2)]);
        assert_eq!(candidates(&s, &name, Some(node(4))), vec![node(2), node(3)]);
        let other = ServiceName::new("nope").unwrap();
        assert!(candidates(&s, &other, None).is_empty());
    }

    #[test]
    fn last_good_round_trips_and_a_bad_file_is_empty() {
        let dir = crate::testutil::temp_dir();
        let path = dir.join(LAST_GOOD_FILE);
        let name = ServiceName::new("orders-db").unwrap();
        assert_eq!(LastGood::load(&path).get(&name), None);
        LastGood::record(&path, &name, node(3));
        assert_eq!(LastGood::load(&path).get(&name), Some(node(3)));
        LastGood::record(&path, &name, node(2));
        assert_eq!(LastGood::load(&path).get(&name), Some(node(2)));
        std::fs::write(&path, "not json").unwrap();
        assert_eq!(LastGood::load(&path).get(&name), None);
    }

    #[test]
    fn hosts_of_the_services_you_use_once_each() {
        let s = state();
        let names = [
            ServiceName::new("status").unwrap(),
            ServiceName::new("orders-db").unwrap(),
            ServiceName::new("nope").unwrap(),
        ];
        assert_eq!(hosts_of(&s, &names), vec![node(3), node(2)]);
    }

    #[test]
    fn targets_carry_hints_in_order() {
        let addr: std::net::SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let hints = Hints::from_pairs([(node(3), vec![addr])]);
        let t = hints.targets(&[node(3), node(2)], None);
        assert_eq!(t.len(), 2);
        assert_eq!(transport::to_node_id(&t[0].id), node(3));
        assert!(t[0].ip_addrs().any(|a| *a == addr));
        assert_eq!(t[1].ip_addrs().count(), 0);
    }
}

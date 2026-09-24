//! Service name → host (card 27). The caller never names a
//! host: it takes the service's `hosts` from the signed state, tries the
//! last one that worked first, then the rest in the admin's order, moving to
//! the next on a dial failure (not on a refusal: a host that refused has
//! decided). `--verbose` says which host answered.
//!
//! The last host that answered for each service is remembered in
//! `$WIRES_HOME/last-good.json` ([`LastGood`]); a hint, never an authority —
//! a host the state no longer assigns is skipped.
//!
//! # Addressing
//!
//! Hosts are dialed **by key**: iroh's n0 discovery (DNS/pkarr, plus the
//! relays) finds where a key is reachable, so by default a caller needs no
//! address at all. [`Hints`] is the optional, **local, unsigned** override
//! for networks without discovery (a hermetic loopback demo, an air-gapped
//! lab): `$WIRES_HOME/hints`, one line per node,
//!
//! ```text
//! # node id (64 hex)                                                 addresses…
//! 3f2a…c9  127.0.0.1:52011  192.168.1.20:52011
//! ```
//!
//! A hint only says where to try: iroh still authenticates the far side to
//! the key, so a wrong or stale hint fails the dial, never reaches an
//! impostor. `wires serve` writes its own line to `$WIRES_HOME/run/hint`
//! ([`write_own_hint`]) for a script to copy. Every endpoint this binary
//! binds ([`transport::bind`]) registers the file, so calls, state sync,
//! push and inbox fetches all use it.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use iroh::EndpointAddr;
use library::{NodeId, ServiceName, State};
use serde::{Deserialize, Serialize};

use crate::admin::keystore::Keystore;
use crate::host::transport;

/// The file name under `$WIRES_HOME`.
pub(crate) const LAST_GOOD_FILE: &str = "last-good.json";

/// The local address-hint file under `$WIRES_HOME` (see the module docs).
pub(crate) const HINTS_FILE: &str = "hints";

/// Where `wires serve` writes its own hint line, under `$WIRES_HOME`.
pub(crate) const OWN_HINT_FILE: &str = "run/hint";

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

    /// Every host remembered here (the hosts this node has called), in
    /// service order.
    pub(crate) fn hosts(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.0.values().copied()
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

/// Local, unsigned dial hints: node → direct addresses (see the module
/// docs). Empty when there is no hints file, which is the normal case.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Hints(BTreeMap<NodeId, Vec<SocketAddr>>);

impl Hints {
    /// `$WIRES_HOME/hints` of `ks`; missing is empty. A line that doesn't
    /// parse is skipped with a warning (a hint is never an authority).
    pub(crate) fn load(ks: &Keystore) -> Self {
        match std::fs::read_to_string(ks.path(HINTS_FILE)) {
            Ok(text) => Self::parse(&text),
            Err(_) => Self::default(),
        }
    }

    /// Parse the hints format: `<node hex> <addr>…` per line, `#` comments.
    pub(crate) fn parse(text: &str) -> Self {
        let mut out: BTreeMap<NodeId, Vec<SocketAddr>> = BTreeMap::new();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            let mut words = line.split_whitespace();
            let Some(node) = words.next() else { continue };
            let Ok(node) = NodeId::from_hex(node) else {
                tracing::warn!("hints: skipping a line with a bad node id: {line:?}");
                continue;
            };
            let entry = out.entry(node).or_default();
            for word in words {
                match word.parse::<SocketAddr>() {
                    Ok(addr) if !entry.contains(&addr) => entry.push(addr),
                    Ok(_) => {}
                    Err(_) => tracing::warn!("hints: skipping {word:?} (not ip:port)"),
                }
            }
        }
        Self(out)
    }

    /// Every hinted node as an [`EndpointAddr`] (what [`transport::bind`]
    /// registers in the endpoint's address lookup).
    pub(crate) fn endpoint_addrs(&self) -> Vec<EndpointAddr> {
        self.0
            .iter()
            .filter_map(|(n, addrs)| transport::endpoint_addr(n, addrs, None).ok())
            .collect()
    }

    /// Hints for exactly these hosts, for tests and pinned setups.
    #[cfg(test)]
    pub(crate) fn from_pairs(
        pairs: impl IntoIterator<Item = (NodeId, Vec<std::net::SocketAddr>)>,
    ) -> Self {
        Self(pairs.into_iter().collect())
    }

    /// `hosts` as dial targets, in order: each with its hints, and `relay`
    /// if given. A key that isn't a valid Ed25519 point is skipped.
    pub(crate) fn targets(&self, hosts: &[NodeId], relay: Option<&str>) -> Vec<EndpointAddr> {
        hosts
            .iter()
            .filter_map(|h| {
                let addrs = self.0.get(h).map(Vec::as_slice).unwrap_or_default();
                transport::endpoint_addr(h, addrs, relay).ok()
            })
            .collect()
    }
}

/// One hints-file line for `node` at `addrs`.
pub(crate) fn hint_line(node: NodeId, addrs: &[SocketAddr]) -> String {
    let addrs: Vec<String> = addrs.iter().map(SocketAddr::to_string).collect();
    format!("{} {}", node.hex(), addrs.join(" "))
}

/// Write this host's own hint line (its node id and loopback-rewritten
/// bound sockets, plus iroh's view of its interface addresses) to
/// `$WIRES_HOME/run/hint`, for a script to append to a caller's `hints`.
pub(crate) fn write_own_hint(ks: &Keystore, endpoint: &iroh::Endpoint) -> anyhow::Result<()> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    let mut addrs: Vec<SocketAddr> = endpoint.addr().ip_addrs().copied().collect();
    for sock in endpoint.bound_sockets() {
        let dialable = match sock {
            SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
                SocketAddr::from((Ipv4Addr::LOCALHOST, v4.port()))
            }
            SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
                SocketAddr::from((Ipv6Addr::LOCALHOST, v6.port()))
            }
            other => other,
        };
        if !addrs.contains(&dialable) {
            addrs.push(dialable);
        }
    }
    let path = ks.path(OWN_HINT_FILE);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let me = transport::to_node_id(&endpoint.id());
    crate::admin::keystore::write_text_mode(&path, &format!("{}\n", hint_line(me, &addrs)), None)
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
            allow: vec![RoleName::new("staff").unwrap()],
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
    fn the_hints_file_parses_and_skips_what_it_cannot_read() {
        let a: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let b: SocketAddr = "[::1]:4433".parse().unwrap();
        let text = format!(
            "# a comment\n{}\n{} 127.0.0.1:4433 # again\nnot-a-node 1.2.3.4:5\n{} nope\n\n",
            hint_line(node(3), &[a, b]),
            node(3).hex(),
            node(2).hex(),
        );
        let hints = Hints::parse(&text);
        assert_eq!(
            hints,
            Hints(BTreeMap::from([(node(3), vec![a, b]), (node(2), vec![]),]))
        );
        assert_eq!(hints.endpoint_addrs().len(), 2);
        let ks = Keystore::at(crate::testutil::temp_dir());
        assert_eq!(Hints::load(&ks), Hints::default());
        std::fs::write(ks.path(HINTS_FILE), &text).unwrap();
        assert_eq!(Hints::load(&ks), hints);
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

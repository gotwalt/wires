//! Service name → host (card 27). The caller never names a
//! host: it takes the service's `hosts` from the root-signed entry in its
//! view (card 37), orders them at random afresh for each call (card 46), so
//! a service's calls spread across its hosts, and moves to the next on a
//! dial failure (not on a refusal: a host that refused has decided).
//! `--verbose` says which host answered.
//!
//! The only memory is of failure: a host that failed to answer this
//! caller's dial in the last [`DEMOTE_SECS`] seconds goes last, so a host
//! that is down costs one dial timeout a minute rather than one in every few
//! calls. That is `$WIRES_HOME/unanswered.json` ([`Unanswered`]); a hint,
//! never an authority — a host the entry no longer lists is never tried.
//!
//! Hosts share the signed policy and nothing else: what a service keeps
//! between calls, the callers a host has verified, and its push queue stay
//! on that host (`docs/protocol.md` §5 *What stays on one host*).
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
//! binds ([`transport::bind`]) registers the file, so calls, policy sync,
//! push and inbox fetches all use it.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use iroh::EndpointAddr;
use library::{NodeId, Service, ServiceName, View};
use rand::Rng;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

use crate::admin::keystore::Keystore;
use crate::host::transport;

/// The file name under `$WIRES_HOME`.
pub(crate) const UNANSWERED_FILE: &str = "unanswered.json";

/// How long a host that failed to answer goes last, in seconds: long enough
/// that a host that is down costs each caller one dial timeout a minute,
/// short enough that one back from a restart takes its share again soon.
pub(crate) const DEMOTE_SECS: i64 = 60;

/// The local address-hint file under `$WIRES_HOME` (see the module docs).
pub(crate) const HINTS_FILE: &str = "hints";

/// Where `wires serve` writes its own hint line, under `$WIRES_HOME`.
pub(crate) const OWN_HINT_FILE: &str = "run/hint";

/// The hosts to try for `service` (its root-signed entry's), in order: a
/// fresh random order from `rng` (so calls spread across the hosts; the
/// admin's order means nothing), except that a host `unanswered` says failed
/// within [`DEMOTE_SECS`] of `now` goes last, the oldest failure first. A
/// caller holds no ban list: a signed policy never lists a banned host (the
/// admin's `remove` drops it from every service), and the host decides
/// every call anyway.
pub(crate) fn candidates<R: Rng + ?Sized>(
    service: &Service,
    unanswered: &Unanswered,
    now: i64,
    rng: &mut R,
) -> Vec<NodeId> {
    let mut hosts: Vec<NodeId> = service.hosts.clone();
    hosts.shuffle(rng);
    // Stable: the shuffle's order survives among the hosts not demoted
    // (`None` sorts before every `Some`).
    hosts.sort_by_key(|h| unanswered.failed_recently(*h, now));
    hosts
}

/// `unanswered.json`: host → when (Unix seconds) it last failed to answer
/// this caller's dial. Only entries under [`DEMOTE_SECS`] old matter; older
/// ones are dropped at the next save.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Unanswered(BTreeMap<NodeId, i64>);

impl Unanswered {
    /// `$WIRES_HOME/unanswered.json`.
    pub(crate) fn path(ks: &Keystore) -> PathBuf {
        ks.path(UNANSWERED_FILE)
    }

    /// Load from `path`; missing or unreadable is empty (it is only a hint).
    pub(crate) fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    /// When `host` last failed to answer, if that was within
    /// [`DEMOTE_SECS`] of `now` (a time ahead of `now` counts: a clock
    /// stepped back shouldn't promote a host that is down).
    pub(crate) fn failed_recently(&self, host: NodeId, now: i64) -> Option<i64> {
        self.0
            .get(&host)
            .copied()
            .filter(|at| now.saturating_sub(*at) < DEMOTE_SECS)
    }

    /// The call tried `tried` in order and `answered` answered: every host
    /// before it failed to answer at `now`, and `answered` is cleared.
    /// Entries [`DEMOTE_SECS`] old are dropped.
    pub(crate) fn note(&mut self, tried: &[NodeId], answered: NodeId, now: i64) {
        for host in tried.iter().take_while(|h| **h != answered) {
            self.0.insert(*host, now);
        }
        self.0.remove(&answered);
        self.0.retain(|_, at| now.saturating_sub(*at) < DEMOTE_SECS);
    }

    /// [`Unanswered::note`] on the file at `path`, saved (best effort) when
    /// it changed.
    pub(crate) fn record(path: &Path, tried: &[NodeId], answered: NodeId, now: i64) {
        let before = Self::load(path);
        let mut me = before.clone();
        me.note(tried, answered, now);
        if me == before {
            return;
        }
        let saved = serde_json::to_string_pretty(&me)
            .map_err(anyhow::Error::from)
            .and_then(|json| crate::admin::keystore::write_private(path, format!("{json}\n")));
        if let Err(e) = saved {
            tracing::debug!("remembering the hosts that did not answer: {e:#}");
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
    let mut addrs: Vec<SocketAddr> = endpoint.addr().ip_addrs().copied().collect();
    for sock in endpoint.bound_sockets() {
        let dialable = crate::net::dialable(sock);
        if !addrs.contains(&dialable) {
            addrs.push(dialable);
        }
    }
    let path = ks.path(OWN_HINT_FILE);
    if let Some(dir) = path.parent() {
        crate::admin::keystore::create_private_dir(dir)?;
    }
    let me = transport::to_node_id(&endpoint.id());
    crate::admin::keystore::write_private(&path, format!("{}\n", hint_line(me, &addrs)))
}

/// Every host of the services in `names` that `view` holds, once each, in
/// first-seen order (for `wires inbox`: the hosts of the services you
/// use).
pub(crate) fn hosts_of<'a>(
    view: &View,
    names: impl IntoIterator<Item = &'a ServiceName>,
) -> Vec<NodeId> {
    let mut out: Vec<NodeId> = Vec::new();
    for name in names {
        for h in view
            .entry(name)
            .map(|e| e.service.hosts.clone())
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
    use library::{NodeIdentity, Policy, Principal, StateVersion};
    use proptest::prelude::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    /// Anyone the mock IdP signed in.
    fn anyone() -> Principal {
        Principal {
            issuer: crate::testutil::test_idp().issuer.as_str().into(),
            subject: "1".into(),
            email: Some("me@example.com".into()),
            org: None,
            groups: vec![],
            not_after: i64::MAX,
        }
    }

    /// A view holding `orders-db` (hosts 2, 3) and `status` (host 3).
    fn view() -> View {
        let root = NodeIdentity::from_seed([1; 32]);
        let mut s = Policy::new(root.node_id());
        s.version = StateVersion(1);
        s.not_after = i64::MAX;
        let (staff, matchers) = crate::testutil::staff_role();
        s.roles.insert(staff.clone(), matchers);
        let svc = |hosts: Vec<NodeId>| Service {
            description: String::new(),
            allow: vec![staff.clone()],
            hosts,
        };
        s.services.insert(
            ServiceName::new("orders-db").unwrap(),
            svc(vec![node(2), node(3)]),
        );
        s.services
            .insert(ServiceName::new("status").unwrap(), svc(vec![node(3)]));
        crate::testutil::signed_policy(&root, s).view_for(
            crate::testutil::any_node(),
            Some(&anyone()),
            None,
        )
    }

    /// A service on `hosts`.
    fn on(hosts: Vec<NodeId>) -> Service {
        Service {
            description: String::new(),
            allow: vec![],
            hosts,
        }
    }

    /// A seeded generator, so a test's draws are the same every run.
    fn rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    const NOW: i64 = 1_000_000;

    #[test]
    fn every_host_comes_first_over_many_calls() {
        let hosts = vec![node(2), node(3), node(4)];
        let svc = on(hosts.clone());
        let mut r = rng(46);
        let mut first: BTreeMap<NodeId, u32> = BTreeMap::new();
        for _ in 0..300 {
            let order = candidates(&svc, &Unanswered::default(), NOW, &mut r);
            *first.entry(order[0]).or_default() += 1;
        }
        for h in &hosts {
            let n = first.get(h).copied().unwrap_or(0);
            assert!(
                (60..=140).contains(&n),
                "{} came first {n} of 300",
                h.short()
            );
        }
    }

    #[test]
    fn a_host_that_just_failed_goes_last_until_the_window_passes() {
        let svc = on(vec![node(2), node(3), node(4)]);
        let mut down = Unanswered::default();
        // node 3 was tried first and failed; node 2 answered.
        down.note(&[node(3), node(2)], node(2), NOW);
        assert_eq!(down.failed_recently(node(3), NOW), Some(NOW));
        assert_eq!(down.failed_recently(node(2), NOW), None);
        let mut r = rng(7);
        for _ in 0..50 {
            let order = candidates(&svc, &down, NOW + DEMOTE_SECS - 1, &mut r);
            assert_eq!(order[2], node(3));
        }
        // After the window it takes its share again.
        let later = NOW + DEMOTE_SECS;
        assert_eq!(down.failed_recently(node(3), later), None);
        let firsts: Vec<NodeId> = (0..50)
            .map(|_| candidates(&svc, &down, later, &mut r)[0])
            .collect();
        assert!(firsts.contains(&node(3)));
        // And an answer clears it at once.
        down.note(&[node(3)], node(3), NOW + 1);
        assert_eq!(down, Unanswered::default());
    }

    #[test]
    fn noting_an_answer_records_the_hosts_before_it_and_drops_old_entries() {
        let mut u = Unanswered::default();
        u.note(&[node(2), node(3), node(4)], node(4), NOW);
        assert_eq!(
            u,
            Unanswered(BTreeMap::from([(node(2), NOW), (node(3), NOW)]))
        );
        // Later: node 2 answers first; node 3's entry ages out.
        u.note(&[node(2)], node(2), NOW + DEMOTE_SECS);
        assert_eq!(u, Unanswered::default());
        // A host the call never reached (after the one that answered) is untouched.
        u.note(&[node(5), node(6), node(7)], node(6), NOW);
        assert_eq!(u, Unanswered(BTreeMap::from([(node(5), NOW)])));
    }

    #[test]
    fn unanswered_round_trips_and_a_bad_file_is_empty() {
        let dir = crate::testutil::temp_dir();
        let path = dir.join(UNANSWERED_FILE);
        assert_eq!(Unanswered::load(&path), Unanswered::default());
        Unanswered::record(&path, &[node(3), node(2)], node(2), NOW);
        assert_eq!(
            Unanswered::load(&path).failed_recently(node(3), NOW),
            Some(NOW)
        );
        Unanswered::record(&path, &[node(3)], node(3), NOW + 1);
        assert_eq!(Unanswered::load(&path), Unanswered::default());
        std::fs::write(&path, "not json").unwrap();
        assert_eq!(Unanswered::load(&path), Unanswered::default());
    }

    /// Hosts from distinct seeds, each with when it last failed (seconds
    /// before now: some within the window, some past it, some ahead of a
    /// clock stepped back), or never.
    fn arb_hosts() -> impl Strategy<Value = Vec<(NodeId, Option<i64>)>> {
        proptest::collection::btree_map(
            any::<u8>(),
            proptest::option::of(-10..(2 * DEMOTE_SECS)),
            1..7,
        )
        .prop_map(|m| m.into_iter().map(|(b, ago)| (node(b), ago)).collect())
    }

    fn split(hosts: &[(NodeId, Option<i64>)]) -> (Service, Unanswered) {
        let svc = on(hosts.iter().map(|(h, _)| *h).collect());
        let failed = hosts
            .iter()
            .filter_map(|(h, ago)| ago.map(|ago| (*h, NOW - ago)))
            .collect();
        (svc, Unanswered(failed))
    }

    proptest! {
        /// The order is always a permutation of the service's hosts, with
        /// every recently failed host after every other, the oldest failure
        /// first.
        #[test]
        fn the_order_is_the_hosts_with_recent_failures_last(
            hosts in arb_hosts(),
            seed in any::<u64>(),
        ) {
            let (svc, down) = split(&hosts);
            let order = candidates(&svc, &down, NOW, &mut rng(seed));
            let mut got = order.clone();
            got.sort();
            let mut want = svc.hosts.clone();
            want.sort();
            prop_assert_eq!(got, want);
            let keys: Vec<Option<i64>> =
                order.iter().map(|h| down.failed_recently(*h, NOW)).collect();
            prop_assert!(keys.windows(2).all(|w| w[0] <= w[1]), "{:?}", keys);
        }

        /// Over many calls, every host not recently failed comes first.
        #[test]
        fn every_healthy_host_takes_a_turn_first(
            hosts in arb_hosts(),
            seed in any::<u64>(),
        ) {
            let (svc, down) = split(&hosts);
            let healthy: Vec<NodeId> = svc
                .hosts
                .iter()
                .copied()
                .filter(|h| down.failed_recently(*h, NOW).is_none())
                .collect();
            let mut r = rng(seed);
            let firsts: Vec<NodeId> = (0..200)
                .map(|_| candidates(&svc, &down, NOW, &mut r)[0])
                .collect();
            for h in &healthy {
                prop_assert!(firsts.contains(h), "{} never came first", h.short());
            }
            if healthy.is_empty() {
                // All failed recently: the oldest failure is always first.
                let oldest = svc.hosts.iter().copied()
                    .min_by_key(|h| down.failed_recently(*h, NOW)).unwrap();
                let first_key = down.failed_recently(firsts[0], NOW);
                prop_assert_eq!(first_key, down.failed_recently(oldest, NOW));
            }
        }
    }

    #[test]
    fn hosts_of_the_services_you_use_once_each() {
        let s = view();
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

//! What every channel command resolves before it touches the network: the
//! topic's name and bootstrap peers ([`TopicArgs`]) and this node's
//! credentials for it ([`TopicContext`]).

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Args;
use library::{InclusionProof, Membership, NodeId, NodeIdentity, TopicId, TopicPeer, TopicTicket};

use super::{ipc, store, topics};
use crate::admin::keystore::{self, preflight, token_arg};
use crate::host::transport;

/// The arguments `publish` and `watch` share: which topic, who to bootstrap
/// from, and the same credential resolution `call` uses (spec §7.2).
///
/// The topic is a *name*, not an id: every member derives the same
/// [`TopicId`] from its own membership's fabric plus this name, so there is no
/// `topic create` and nothing to register (spec §1).
#[derive(Args, Clone, Debug, Default)]
pub(crate) struct TopicArgs {
    /// The topic name, derived under this node's fabric (e.g. `ops`).
    /// Defaults to the channel `wires init` / `wires join` recorded.
    #[arg(default_value = "", hide_default_value = true)]
    pub(crate) topic: String,
    /// A base64 topic ticket to bootstrap from. Repeatable; every peer in every
    /// ticket is tried, and the ones that answer are remembered.
    #[arg(long = "peer")]
    pub(crate) peer: Vec<String>,
    /// Hex 32-byte seed of this node's key. Falls back to `$WIRES_NODE_SEED`,
    /// then `--node-seed-file`, then the keystore (`node.seed`).
    #[arg(long)]
    pub(crate) node_seed: Option<String>,
    /// Read the node key seed (hex) from this file instead of the keystore.
    #[arg(long)]
    pub(crate) node_seed_file: Option<PathBuf>,
    /// Use a self-hosted relay at this URL instead of the n0 default.
    #[arg(long)]
    pub(crate) relay_url: Option<String>,
    /// The base64 membership token to use. Falls back to the keystore
    /// (`membership.json`); its `fabric` is the topic's fabric root.
    #[arg(long, conflicts_with = "membership_file")]
    pub(crate) membership: Option<String>,
    /// Read the membership token from this file instead of the keystore.
    #[arg(long)]
    pub(crate) membership_file: Option<PathBuf>,
    /// The base64 inclusion proof presented at admission. Falls back to the
    /// keystore (`inclusion-proof.json`).
    #[arg(long, conflicts_with = "inclusion_proof_file")]
    pub(crate) inclusion_proof: Option<String>,
    /// Read the inclusion proof from this file instead of the keystore.
    #[arg(long)]
    pub(crate) inclusion_proof_file: Option<PathBuf>,
}

/// Everything the topic commands resolve *before* touching the network
/// (spec §7.2).
///
/// The preflight exists so that a missing credential is a local error naming
/// the command that fixes it, rather than a QUIC dial that eventually fails
/// with something about a handshake. Five things must be on hand — a node key,
/// a membership, an inclusion proof, a roster head, and at least one fabric key
/// — and every one of them has a one-line remedy.
pub(crate) struct TopicContext {
    /// This node's signing identity (also the endpoint's key).
    pub(crate) node: NodeIdentity,
    /// The membership whose `fabric` is the trusted root here.
    pub(crate) membership: Membership,
    /// This node's inclusion proof, presented at every admission.
    pub(crate) proof: InclusionProof,
    /// Where the roster head is re-read from, per admission and per watchdog
    /// pass. Armed: preflight proved a head exists, so a later missing one
    /// fails closed.
    pub(crate) head_source: Arc<transport::HeadSource>,
    /// The keystore the keyring, the head, and adopted heads live in.
    pub(crate) keystore: Arc<keystore::Keystore>,
    /// The wires home — the parent of `topics/` and `run/`.
    pub(crate) home: PathBuf,
    /// The topic name as typed.
    pub(crate) name: String,
    /// The derived topic id.
    pub(crate) topic: TopicId,
    /// `membership.fabric`: the root every signature is checked against.
    pub(crate) fabric_root: NodeId,
    /// Peers named by `--peer` tickets.
    pub(crate) ticket_peers: Vec<TopicPeer>,
    /// A self-hosted relay, if one was configured.
    pub(crate) relay_url: Option<String>,
}

impl fmt::Debug for TopicContext {
    /// Names the topic and the fabric, never the identity: this struct holds
    /// the node's signing key, and a `Debug` that prints it would put a seed in
    /// a log line the first time something goes wrong.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TopicContext")
            .field("name", &self.name)
            .field("topic", &self.topic.hex())
            .field("fabric_root", &self.fabric_root.hex())
            .field("node", &self.node.node_id().hex())
            .field("home", &self.home)
            .field("ticket_peers", &self.ticket_peers.len())
            .field("relay_url", &self.relay_url)
            .finish_non_exhaustive()
    }
}

impl TopicContext {
    /// Resolve every credential the topic commands need against `ks`, or fail
    /// with a message naming the `wires` command that supplies what is missing.
    ///
    /// The testable form (the `_in` pattern): `wires watch` and `wires advanced publish`
    /// call it with the resolved keystore and home.
    pub(crate) fn resolve(
        ks: Arc<keystore::Keystore>,
        home: PathBuf,
        a: &TopicArgs,
    ) -> anyhow::Result<TopicContext> {
        let name = if a.topic.trim().is_empty() {
            ks.read_channel()?.ok_or_else(|| {
                anyhow::anyhow!(
                    "no topic named and no channel joined; pass one (e.g. `wires watch ops`) or \
                     run `wires join <token>` first"
                )
            })?
        } else {
            a.topic.clone()
        };
        let node = match (a.node_seed.as_deref(), a.node_seed_file.as_deref()) {
            (Some(hex), _) => NodeIdentity::from_seed_hex(hex).context("--node-seed")?,
            (None, Some(path)) => keystore::read_identity_file(path)?,
            (None, None) => keystore::node_identity_in(&ks)?,
        };
        let membership = match token_arg(
            a.membership.as_deref(),
            a.membership_file.as_deref(),
            "--membership",
        )? {
            Some(text) => Membership::decode(&text).context("--membership")?,
            None => ks.read_membership()?.ok_or_else(|| {
                anyhow::anyhow!(
                    "no membership: run `wires advanced import --membership <token>` with the token your \
                     operator minted (looked for {})",
                    ks.path("membership.json").display()
                )
            })?,
        };
        // The same two consistency checks `call` runs, for the same reason:
        // credentials issued to another node must not masquerade as a network
        // failure later.
        preflight(node.node_id(), &membership, None).map_err(anyhow::Error::msg)?;

        let proof = match token_arg(
            a.inclusion_proof.as_deref(),
            a.inclusion_proof_file.as_deref(),
            "--inclusion-proof",
        )? {
            Some(text) => InclusionProof::decode(&text).context("--inclusion-proof")?,
            None => ks.read_inclusion_proof()?.ok_or_else(|| {
                anyhow::anyhow!(
                    "no inclusion proof: topics admit peers by roster inclusion, so this node \
                     needs its own proof — run `wires advanced import --inclusion-proof-file \
                     <node-id>.proof` from `wires advanced roster commit --out DIR` (looked for {})",
                    ks.path("inclusion-proof.json").display()
                )
            })?,
        };
        let head = ks.read_roster_head()?.ok_or_else(|| {
            anyhow::anyhow!(
                "no roster head: admission checks every peer's proof against a signed head, so \
                 this node needs the current one — run `wires advanced import --roster-head <token>` \
                 (looked for {})",
                ks.path("roster-head.json").display()
            )
        })?;
        if ks.latest_fabric_key()?.is_none() {
            anyhow::bail!(
                "no fabric key in the keyring: topics are end-to-end encrypted, so a member with \
                 no key can neither publish nor read — run `wires advanced import --fabric-key-file \
                 <node-id>.key` from `wires advanced roster commit --out DIR` (looked in {})",
                ks.keyring_dir().display()
            );
        }

        let fabric_root = membership.fabric;
        let topic = TopicId::derive(fabric_root, &name);
        let mut ticket_peers = Vec::new();
        for text in &a.peer {
            let ticket = TopicTicket::decode(text.trim())
                .context("--peer (is the pasted base64 ticket complete?)")?;
            if ticket.fabric != fabric_root {
                anyhow::bail!(
                    "--peer: this ticket is for fabric {}, but this node's membership is in \
                     fabric {}; a ticket from another fabric can never be admitted",
                    ticket.fabric.hex(),
                    fabric_root.hex()
                );
            }
            if ticket.name != name {
                anyhow::bail!(
                    "--peer: this ticket is for topic {:?}, not {:?}; the peers on it are on a \
                     different mesh",
                    ticket.name,
                    name
                );
            }
            ticket_peers.extend(ticket.peers);
        }
        tracing::debug!(
            topic = %topic.hex(),
            head = head.version.0,
            peers = ticket_peers.len(),
            "preflight ok"
        );
        Ok(TopicContext {
            node,
            membership,
            proof,
            head_source: Arc::new(transport::HeadSource::Keystore {
                path: ks.path("roster-head.json"),
                // Seen: a head that disappears later must fail closed, not
                // silently drop back to admitting nobody's proof.
                armed: std::sync::atomic::AtomicBool::new(true),
            }),
            keystore: ks,
            home,
            name,
            topic,
            fabric_root,
            ticket_peers,
            relay_url: a.relay_url.clone(),
        })
    }

    /// The node config for this context's topic.
    pub(crate) fn node_config(&self, store: Arc<store::TopicStore>) -> topics::TopicNodeConfig {
        let mut cfg = topics::TopicNodeConfig::new(
            self.topic,
            self.fabric_root,
            Arc::clone(&self.head_source),
            self.proof.clone(),
            Arc::clone(&self.keystore),
            store,
        );
        cfg.relay_url = self.relay_url.clone();
        cfg
    }

    /// This topic's control socket path.
    pub(crate) fn socket_path(&self) -> PathBuf {
        ipc::socket_path(&self.home, self.topic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::provisioned;

    #[test]
    fn preflight_resolves_a_provisioned_member() {
        let member = provisioned([2u8; 32]);
        let ctx = member.resolve(&member.args()).unwrap();
        assert_eq!(ctx.fabric_root, member.root.node_id());
        assert_eq!(ctx.topic, TopicId::derive(member.root.node_id(), "ops"));
        assert_eq!(ctx.membership.member, member.node.node_id());
        assert_eq!(ctx.name, "ops");
        assert!(ctx.ticket_peers.is_empty());
        // The socket is the one this home's topic resolves to (under the home,
        // or — for a home as deep as the test sandbox's — the short fallback;
        // `ipc`'s suite asserts both shapes).
        assert_eq!(ctx.socket_path(), ipc::socket_path(&member.home, ctx.topic));
    }

    #[test]
    fn preflight_names_the_import_for_a_missing_membership() {
        let member = provisioned([2u8; 32]);
        std::fs::remove_file(member.ks.path("membership.json")).unwrap();
        let err = member.resolve(&member.args()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("wires advanced import --membership"), "{msg}");
    }

    #[test]
    fn preflight_names_the_import_for_a_missing_proof() {
        let member = provisioned([2u8; 32]);
        std::fs::remove_file(member.ks.path("inclusion-proof.json")).unwrap();
        let err = member.resolve(&member.args()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("wires advanced import --inclusion-proof"),
            "{msg}"
        );
        assert!(msg.contains("roster commit --out"), "{msg}");
    }

    #[test]
    fn preflight_names_the_import_for_a_missing_head() {
        let member = provisioned([2u8; 32]);
        std::fs::remove_file(member.ks.path("roster-head.json")).unwrap();
        let err = member.resolve(&member.args()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("wires advanced import --roster-head"), "{msg}");
    }

    #[test]
    fn preflight_names_the_import_for_an_empty_keyring() {
        let member = provisioned([2u8; 32]);
        std::fs::remove_dir_all(member.ks.keyring_dir()).unwrap();
        let err = member.resolve(&member.args()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("wires advanced import --fabric-key"), "{msg}");
        assert!(msg.contains("end-to-end encrypted"), "{msg}");
    }

    #[test]
    fn preflight_refuses_a_credential_issued_to_another_node() {
        // Bob's keystore, but Alice's node seed on the command line.
        let member = provisioned([2u8; 32]);
        let stranger = NodeIdentity::from_seed([7u8; 32]);
        let args = TopicArgs {
            node_seed: Some(stranger.seed_hex()),
            ..member.args()
        };
        let msg = format!("{:#}", member.resolve(&args).unwrap_err());
        assert!(msg.contains(&stranger.node_id().hex()), "{msg}");
        assert!(msg.contains("wires advanced import --membership"), "{msg}");
    }

    #[test]
    fn preflight_refuses_a_ticket_from_another_fabric_or_topic() {
        let member = provisioned([2u8; 32]);
        let stranger = NodeIdentity::from_seed([8u8; 32]).node_id();

        let foreign = TopicTicket::new(stranger, "ops", vec![TopicPeer::new(stranger)])
            .encode()
            .unwrap();
        let args = TopicArgs {
            peer: vec![foreign],
            ..member.args()
        };
        let msg = format!("{:#}", member.resolve(&args).unwrap_err());
        assert!(
            msg.contains("another fabric") || msg.contains("for fabric"),
            "{msg}"
        );

        let other_topic = TopicTicket::new(member.root.node_id(), "eng", Vec::new())
            .encode()
            .unwrap();
        let args = TopicArgs {
            peer: vec![other_topic],
            ..member.args()
        };
        let msg = format!("{:#}", member.resolve(&args).unwrap_err());
        assert!(msg.contains("\"eng\""), "{msg}");
    }

    #[test]
    fn no_topic_means_the_joined_channel() {
        let member = provisioned([2u8; 32]);
        let args = TopicArgs {
            topic: String::new(),
            ..member.args()
        };
        let msg = format!("{:#}", member.resolve(&args).unwrap_err());
        assert!(msg.contains("wires join"), "{msg}");

        member.ks.save_channel("ops").unwrap();
        let ctx = member.resolve(&args).unwrap();
        assert_eq!(ctx.name, "ops");
        assert_eq!(ctx.topic, TopicId::derive(member.root.node_id(), "ops"));
    }

    #[test]
    fn preflight_takes_the_peers_off_a_good_ticket() {
        let member = provisioned([2u8; 32]);
        let peer = TopicPeer::new(NodeIdentity::from_seed([9u8; 32]).node_id())
            .with_addrs(vec!["127.0.0.1:4242".parse().unwrap()]);
        let ticket = TopicTicket::new(member.root.node_id(), "ops", vec![peer.clone()])
            .encode()
            .unwrap();
        let args = TopicArgs {
            peer: vec![ticket],
            ..member.args()
        };
        let ctx = member.resolve(&args).unwrap();
        assert_eq!(ctx.ticket_peers, vec![peer]);
    }
}

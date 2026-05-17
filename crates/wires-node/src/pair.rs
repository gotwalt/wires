//! Pair-grant installation logic. Verifies a decrypted PairGrant and writes
//! every artifact Bob needs to become a fully-onboarded household member.

use std::path::Path;

use snafu::{ResultExt, ensure};
use wires_net::pair::PairGrant;

use crate::atomic_write::atomic_write;
use crate::config::{HostConfig, NodeConfig};
use crate::error::{
    AgentMismatchSnafu, ConfigWriteSnafu, NodeError, Result, UnknownTopicSnafu, UpsertCapSnafu,
    VerifyCapSnafu,
};
use crate::node::Node;
use crate::topic_names::upsert_entries as upsert_topic_names;

pub struct InstallOutcome {
    pub cap_id: [u8; 16],
}

pub fn install_grant(
    data_dir: &Path,
    node: &Node,
    self_agent_pubkey: &[u8; 32],
    grant: &PairGrant,
) -> Result<InstallOutcome> {
    ensure!(&grant.cap.agent == self_agent_pubkey, AgentMismatchSnafu);
    grant
        .cap
        .verify(&grant.root_pubkey)
        .context(VerifyCapSnafu)?;
    for tk in &grant.topic_keys {
        ensure!(
            grant.topic_names.iter().any(|n| n.topic_id == tk.topic_id),
            UnknownTopicSnafu {
                topic_id_hex: hex::encode(tk.topic_id)
            }
        );
    }

    let cfg_path = data_dir.join("config.toml");
    let mut cfg: NodeConfig = if cfg_path.exists() {
        let s = std::fs::read_to_string(&cfg_path).context(ConfigWriteSnafu)?;
        toml::from_str(&s).map_err(|e| NodeError::ConfigWrite {
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
            location: snafu::location!(),
        })?
    } else {
        NodeConfig {
            data_dir: data_dir.to_path_buf(),
            root_pubkey_hex: String::new(),
            host: None,
        }
    };
    cfg.root_pubkey_hex = hex::encode(grant.root_pubkey);
    if let Some(host) = &grant.host {
        cfg.host = Some(HostConfig {
            peer_hints: host.peer_hints.clone(),
            discovery_url: None,
        });
    }
    let toml_str = toml::to_string_pretty(&cfg).map_err(|e| NodeError::ConfigWrite {
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
        location: snafu::location!(),
    })?;
    atomic_write(&cfg_path, toml_str.as_bytes(), None).context(ConfigWriteSnafu)?;

    upsert_topic_names(
        data_dir,
        grant
            .topic_names
            .iter()
            .map(|e| (e.name.clone(), e.topic_id)),
    )?;

    for tk in &grant.topic_keys {
        node.install_epoch_key(tk.topic_id, tk.epoch, tk.key)?;
    }

    // Cap goes last so the invariant "keys present ⟹ cap present" never inverts.
    node.caps.upsert_grant(&grant.cap).context(UpsertCapSnafu)?;

    Ok(InstallOutcome {
        cap_id: grant.cap.cap_id.0,
    })
}

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::{Mutex, oneshot};
use wires_net::pair::{
    PairAck, PairFrame, PairGrantEnvelope, PairHandler, PairReject, PairRejectCode,
};
use wires_net::unix_now_ms;
use x25519_dalek::StaticSecret;

/// Outcome signaled to the outer pair-listen loop on a successful install.
#[derive(Debug)]
pub enum PairOutcome {
    Paired { cap_id: [u8; 16] },
}

/// Concrete PairHandler that verifies a PairGrantEnvelope against the
/// in-memory pending pair state, installs the grant, and signals the loop.
pub struct NodePairHandler {
    inner: Arc<Mutex<HandlerState>>,
}

struct HandlerState {
    data_dir: std::path::PathBuf,
    node: Arc<Node>,
    self_agent_pubkey: [u8; 32],
    expected_nonce: [u8; 32],
    ephemeral_secret: StaticSecret,
    request_expires_ms: i64,
    outcome_tx: Option<oneshot::Sender<PairOutcome>>,
    completed: bool,
}

impl NodePairHandler {
    pub fn new(
        data_dir: std::path::PathBuf,
        node: Arc<Node>,
        self_agent_pubkey: [u8; 32],
        expected_nonce: [u8; 32],
        ephemeral_secret: StaticSecret,
        request_expires_ms: i64,
        outcome_tx: oneshot::Sender<PairOutcome>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HandlerState {
                data_dir,
                node,
                self_agent_pubkey,
                expected_nonce,
                ephemeral_secret,
                request_expires_ms,
                outcome_tx: Some(outcome_tx),
                completed: false,
            })),
        }
    }
}

#[async_trait]
impl PairHandler for NodePairHandler {
    async fn handle_grant(&self, envelope: PairGrantEnvelope) -> PairFrame {
        let mut state = self.inner.lock().await;
        if state.completed {
            return reject(
                PairRejectCode::AlreadyPaired,
                "already paired in this window",
            );
        }

        let grant = match envelope.open_and_verify(&state.ephemeral_secret, &state.expected_nonce) {
            Ok(g) => g,
            Err(wires_net::NetError::PairSignature { .. }) => {
                return reject(PairRejectCode::SignatureInvalid, "signature invalid");
            }
            Err(wires_net::NetError::PairCrypto { .. }) => {
                return reject(
                    PairRejectCode::SealUndecryptable,
                    "sealed payload undecryptable",
                );
            }
            Err(e) => {
                return reject(PairRejectCode::InternalError, &format!("{e}"));
            }
        };

        if grant.root_pubkey != envelope.root_pubkey {
            return reject(PairRejectCode::RootMismatch, "inner/outer root mismatch");
        }
        if grant.nonce != state.expected_nonce {
            return reject(PairRejectCode::NonceMismatch, "nonce mismatch");
        }
        if grant.issued_at > state.request_expires_ms {
            return reject(
                PairRejectCode::NonceExpired,
                "grant issued after request expired",
            );
        }

        match install_grant(
            &state.data_dir.clone(),
            &state.node,
            &state.self_agent_pubkey,
            &grant,
        ) {
            Ok(out) => {
                if let Err(e) = crate::pair_pending::delete(&state.data_dir) {
                    return reject(
                        PairRejectCode::InternalError,
                        &format!("delete pair_pending: {e}"),
                    );
                }
                state.completed = true;
                if let Some(tx) = state.outcome_tx.take() {
                    let _ = tx.send(PairOutcome::Paired { cap_id: out.cap_id });
                }
                PairFrame::Ack(PairAck {
                    installed_cap_id: out.cap_id,
                    installed_at: unix_now_ms(),
                })
            }
            Err(NodeError::AgentMismatch { .. }) => {
                reject(PairRejectCode::CapInvalid, "cap targets a different agent")
            }
            Err(NodeError::VerifyCap { .. }) => {
                reject(PairRejectCode::CapInvalid, "cap failed root verification")
            }
            Err(NodeError::UnknownTopic { .. }) => reject(
                PairRejectCode::CapInvalid,
                "grant references unknown topic_id",
            ),
            Err(e) => reject(PairRejectCode::InternalError, &format!("{e}")),
        }
    }
}

fn reject(code: PairRejectCode, msg: &str) -> PairFrame {
    PairFrame::Reject(PairReject {
        code,
        message: msg.to_string(),
    })
}

use ed25519_dalek::SigningKey;
use wires_net::pair::{ALPN as PAIR_ALPN, PairDial, PairManifest, PairProtocol, PairRequest};
use x25519_dalek::PublicKey as XPub;

pub struct PairListenArgs {
    pub manifest: PairManifest,
    pub ttl: std::time::Duration,
}

pub struct PairListenStarted {
    pub request_token: String,
    pub outcome: oneshot::Receiver<PairOutcome>,
    pub router: iroh::protocol::Router,
}

/// Spin up a pair-listen window: register the protocol on the router,
/// persist pair_pending.json (or resume an existing one), return the encoded
/// PairRequest token and a oneshot receiver for the outcome.
/// Caller blocks on outcome with a TTL deadline.
pub async fn pair_listen(
    data_dir: std::path::PathBuf,
    node: Arc<Node>,
    agent_sk: SigningKey,
    agent_x25519: [u8; 32],
    endpoint: iroh::Endpoint,
    args: PairListenArgs,
) -> crate::error::Result<PairListenStarted> {
    use crate::error::NodeError;

    // If a prior window left pair_pending.json behind, resume with its state.
    let pending =
        crate::pair_pending::load(&data_dir).map_err(|source| NodeError::ConfigWrite {
            source,
            location: snafu::location!(),
        })?;

    let (nonce, ephemeral_sk, request_token, request_expires_ms) = if let Some(p) = pending {
        let nonce_arr = hex_to_arr32(&p.nonce_hex)?;
        let secret_arr = hex_to_arr32(&p.ephemeral_x25519_secret_hex)?;
        (
            nonce_arr,
            StaticSecret::from(secret_arr),
            p.request_token,
            p.expires_unix_ms,
        )
    } else {
        use rand_core::RngCore as _;
        let mut nonce = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let ephemeral_sk = StaticSecret::random_from_rng(rand_core::OsRng);
        let ephemeral_pk = XPub::from(&ephemeral_sk).to_bytes();
        let agent_pk = agent_sk.verifying_key().to_bytes();
        let now = unix_now_ms();
        let expires = now + args.ttl.as_millis() as i64;
        let dial = pair_dial_from(&endpoint);
        let mut req = PairRequest {
            version: 1,
            agent_pubkey: agent_pk,
            agent_x25519,
            ephemeral_x25519: ephemeral_pk,
            dial,
            manifest: args.manifest,
            nonce,
            issued_at: now,
            expires,
            signature: [0u8; 64],
        };
        req.sign(&agent_sk)
            .map_err(|source| NodeError::PairListenSign {
                source: Box::new(source),
                location: snafu::location!(),
            })?;
        let token = req.encode().map_err(|source| NodeError::PairListenSign {
            source: Box::new(source),
            location: snafu::location!(),
        })?;
        crate::pair_pending::save(
            &data_dir,
            &crate::pair_pending::PairPending {
                version: 1,
                nonce_hex: hex::encode(nonce),
                ephemeral_x25519_secret_hex: hex::encode(ephemeral_sk.to_bytes()),
                expires_unix_ms: expires,
                request_token: token.clone(),
            },
        )
        .map_err(|source| NodeError::ConfigWrite {
            source,
            location: snafu::location!(),
        })?;
        (nonce, ephemeral_sk, token, expires)
    };

    let (outcome_tx, outcome_rx) = oneshot::channel();
    let handler = Arc::new(NodePairHandler::new(
        data_dir,
        node,
        agent_sk.verifying_key().to_bytes(),
        nonce,
        ephemeral_sk,
        request_expires_ms,
        outcome_tx,
    ));
    let protocol = PairProtocol::new(handler);
    let router = iroh::protocol::Router::builder(endpoint)
        .accept(PAIR_ALPN, protocol)
        .spawn();
    Ok(PairListenStarted {
        request_token,
        outcome: outcome_rx,
        router,
    })
}

/// Build a `PairDial` from a running iroh `Endpoint`.
///
/// Uses `endpoint.id()` for the node_id and `endpoint.addr()` to extract
/// direct socket addresses and the optional relay URL. Mirrors the pattern
/// used in the wires-cli tests (`cli_publish_auto_dials.rs`).
fn pair_dial_from(endpoint: &iroh::Endpoint) -> PairDial {
    let node_id = hex::encode(endpoint.id().as_bytes());
    let endpoint_addr = endpoint.addr();
    let mut addrs: Vec<String> = Vec::new();
    let mut relay: Option<String> = None;
    for t in &endpoint_addr.addrs {
        match t {
            iroh::TransportAddr::Ip(sa) => addrs.push(sa.to_string()),
            iroh::TransportAddr::Relay(url) => relay = Some(url.to_string()),
            _ => {}
        }
    }
    PairDial {
        node_id,
        addrs,
        relay,
    }
}

fn hex_to_arr32(s: &str) -> crate::error::Result<[u8; 32]> {
    use crate::error::NodeError;
    let bytes = hex::decode(s).map_err(|_| NodeError::ConfigWrite {
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, "bad hex"),
        location: snafu::location!(),
    })?;
    bytes.try_into().map_err(|_| NodeError::ConfigWrite {
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, "wrong length"),
        location: snafu::location!(),
    })
}

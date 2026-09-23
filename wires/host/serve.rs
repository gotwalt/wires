//! `wires serve host.json`: the host's one command.
//!
//! Everything the host decides — what it exposes, the channel it records
//! every call on, the IdPs it trusts, and which roles may run which tool —
//! comes from one file (see [`config`](super::config)). The flags left are
//! where the host's own credentials live and `--relay-url`.
//!
//! `wires serve --check host.json` validates the file and prints what it
//! means, without touching the keystore or the network.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use clap::Args;
use library::NodeId;

use super::config::HostConfig;
use super::{announce, audit, identity, transport};
use crate::admin::keystore;
use crate::caller::jwks;
use crate::channel::context::{TopicArgs, TopicContext};
use crate::channel::watch::run_tail;
use crate::init_logging;

/// `serve` arguments: `host.json`, and where this host's own key and
/// credentials come from.
#[derive(Args)]
pub(crate) struct ServeArgs {
    /// The host's config: tools, channel, trusted IdPs, roles (see
    /// `wires serve --check`).
    #[arg(value_name = "HOST_JSON")]
    pub(crate) config: PathBuf,
    /// Validate HOST_JSON, print which roles may run which tools and which
    /// issuers are trusted, and exit.
    #[arg(long)]
    pub(crate) check: bool,
    /// Hex 32-byte seed of this host's node key. Falls back to
    /// `$WIRES_NODE_SEED`, then `--node-seed-file`, then the keystore (`node.seed`).
    #[arg(long)]
    pub(crate) node_seed: Option<String>,
    /// Read the node key seed (hex) from this file instead of the keystore.
    #[arg(long)]
    pub(crate) node_seed_file: Option<PathBuf>,
    /// CRL JSON literal of revoked subjects (overrides `--crl-file` / keystore).
    #[arg(long, conflicts_with = "crl_file")]
    pub(crate) crl_json: Option<String>,
    /// Read the CRL from this file (else the keystore's `crl.json`, else empty).
    #[arg(long)]
    pub(crate) crl_file: Option<PathBuf>,
    /// Use a self-hosted relay at this URL instead of the n0 default.
    #[arg(long)]
    pub(crate) relay_url: Option<String>,
    /// The host's own membership token: it names the fabric (the trust root)
    /// whose members may call, and is presented in the handshake ack. Falls
    /// back to `$WIRES_MEMBERSHIP`, then `--membership-file`, then the
    /// keystore (`membership.json`).
    #[arg(long)]
    pub(crate) membership: Option<String>,
    /// Read the host's membership token from this file.
    #[arg(long)]
    pub(crate) membership_file: Option<PathBuf>,
    /// The signed roster head this host enforces (inclusion proof required
    /// from callers). Falls back to `$WIRES_ROSTER_HEAD`, then
    /// `--roster-head-file`, then the keystore (`roster-head.json`, re-checked
    /// per connection — a head imported later enforces on the next dial, with
    /// no restart). With no head at all: membership + CRL + TTL only.
    #[arg(long)]
    pub(crate) roster_head: Option<String>,
    /// Read the roster head token from this file.
    #[arg(long)]
    pub(crate) roster_head_file: Option<PathBuf>,
    /// The host's own inclusion proof token (optional; presented in the ack).
    #[arg(long)]
    pub(crate) inclusion_proof: Option<String>,
    /// Read the host's inclusion proof from this file.
    #[arg(long)]
    pub(crate) inclusion_proof_file: Option<PathBuf>,
    /// A base64 topic ticket to bootstrap the channel from (repeatable).
    #[arg(long)]
    pub(crate) peer: Vec<String>,
}

/// `serve`: load `host.json`, bind, verify every caller's fabric membership
/// and roster inclusion, ask the host's policy, exec the invoked tool + bridge.
pub(crate) async fn serve_cmd(a: ServeArgs) -> anyhow::Result<()> {
    let host = HostConfig::load(&a.config)?;
    if a.check {
        print!("{}", host.summary());
        return Ok(());
    }
    init_logging();
    let node = keystore::node_identity(a.node_seed.as_deref(), a.node_seed_file.as_deref())?;
    let membership = keystore::membership(a.membership.as_deref(), a.membership_file.as_deref())?;
    // The fabric this host is a member of is the one whose members it serves.
    let trust_root = membership.fabric;
    // `channel`: resolve the channel credentials *before* serving, so a host
    // that is not a member of its channel fails closed here.
    let audit_ctx = match host.channel.as_deref() {
        Some(name) => Some(audit_context_in(
            Arc::new(keystore::Keystore::resolve()?),
            keystore::home()?,
            &a,
            name,
            node.node_id(),
            trust_root,
        )?),
        None => None,
    };
    let identities = match &audit_ctx {
        Some(ctx) => Some(serve_identities(&host, &ctx.home)?),
        None => None,
    };
    // Credential *sources*, not values: a file-backed CRL or head is re-read on
    // every connection, so `wires advanced revoke` / `wires advanced roster commit` take effect on
    // the next dial without bouncing this process.
    let crl = keystore::crl_source(a.crl_json.as_deref(), a.crl_file.clone())?;
    let head = keystore::roster_head_source(a.roster_head.as_deref(), a.roster_head_file.clone())?;
    let proof = keystore::inclusion_proof(
        a.inclusion_proof.as_deref(),
        a.inclusion_proof_file.as_deref(),
    )?;
    let (sink, records) = match audit_ctx {
        Some(_) => {
            let (sink, rx) = transport::AuditSink::channel(audit::AUDIT_QUEUE);
            (Some(sink), Some(rx))
        }
        None => (None, None),
    };
    let gate = match (&identities, &audit_ctx) {
        (Some(ids), Some(ctx)) => Some(Arc::new(identity::IdentityGate::new(
            Arc::clone(ids),
            ctx.name.clone(),
        ))),
        _ => None,
    };
    let policy: Arc<dyn super::policy::Policy> = Arc::new(host.policy());
    // The channel directory (card 15): the same policy and identities that
    // decide each call decide what each member sees announced.
    let announcer = match (&gate, &identities, &audit_ctx) {
        (Some(gate), Some(ids), Some(ctx)) => Some(
            announce::Announcer::new(
                node.node_id(),
                Arc::clone(&policy),
                Arc::clone(gate),
                Arc::clone(ids),
                host.descriptions(),
                announce::heartbeat(),
            )
            .watching_keys(Arc::clone(&ctx.keystore)),
        ),
        _ => None,
    };
    let config = transport::ServeConfig {
        tools: host.commands(),
        audit: sink,
        identity: gate,
        policy,
        trust_root,
        require_grant: false,
        crl,
        head,
        membership,
        proof,
    };
    match (audit_ctx, records) {
        (Some(ctx), Some(records)) => {
            tracing::info!(topic = %ctx.name, "serving the session ALPN on the channel's node");
            let hosted = audit::Hosted {
                session: transport::SessionProtocol(Arc::new(config)),
                records,
                identities: identities.expect("built with the audit context"),
                announcer,
            };
            run_tail(&ctx, 0, false, Some(hosted)).await
        }
        _ => transport::serve(node, config, a.relay_url.as_deref()).await,
    }
}

/// The host's identity index, verifying claims under `host.json`'s
/// `identity.issuers` (each issuer with its own audiences) — never the
/// environment: what the host trusts is in the file.
pub(crate) fn serve_identities(
    host: &HostConfig,
    home: &Path,
) -> anyhow::Result<Arc<identity::Identities>> {
    let fetcher = jwks::KeyFetcher::new(Some(home.join("jwks")))?;
    Ok(Arc::new(identity::Identities::new(fetcher, host.trust())))
}

/// Resolve `host.json`'s `channel` into the same [`TopicContext`] `wires
/// watch` would build, failing (with the `wires advanced import` remedy) when
/// this node is not a provisioned member of the channel, or when the channel's
/// fabric is not the one this host's membership names.
///
/// The testable form (the `_in` pattern): `serve` passes the resolved keystore
/// and home.
fn audit_context_in(
    ks: Arc<keystore::Keystore>,
    home: PathBuf,
    a: &ServeArgs,
    name: &str,
    node: NodeId,
    trust_root: NodeId,
) -> anyhow::Result<TopicContext> {
    let args = TopicArgs {
        topic: name.to_string(),
        peer: a.peer.clone(),
        node_seed: a.node_seed.clone(),
        node_seed_file: a.node_seed_file.clone(),
        relay_url: a.relay_url.clone(),
        membership: a.membership.clone(),
        membership_file: a.membership_file.clone(),
        inclusion_proof: a.inclusion_proof.clone(),
        inclusion_proof_file: a.inclusion_proof_file.clone(),
    };
    let ctx = TopicContext::resolve(ks, home, &args).with_context(|| {
        format!("host.json channel {name:?} needs this host to be a member of it")
    })?;
    if ctx.node.node_id() != node {
        anyhow::bail!("channel {name:?} resolved a different node key than the one serving");
    }
    if ctx.fabric_root != trust_root {
        anyhow::bail!(
            "channel {name:?} is in fabric {}, but this host's membership is in {}",
            ctx.fabric_root.hex(),
            trust_root.hex()
        );
    }
    Ok(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Member, provisioned};
    use crate::{Cli, Command};
    use clap::Parser;
    use library::{NodeIdentity, TopicId};

    #[test]
    fn serve_takes_host_json_and_nothing_else_decides() {
        let parse = |args: &[&str]| Cli::try_parse_from(["wires", "serve"].iter().chain(args));
        let Command::Serve(a) = parse(&["host.json", "--check"]).unwrap().command else {
            panic!("expected serve");
        };
        assert_eq!(a.config, PathBuf::from("host.json"));
        assert!(a.check);
        assert!(parse(&[]).is_err(), "host.json is required");
        assert!(parse(&["h.json", "--relay-url", "https://r.example"]).is_ok());
        assert!(parse(&["h.json", "--peer", "t1", "--peer", "t2"]).is_ok());
        // The flag-based form is gone: host.json is the only one.
        for gone in [
            &["h.json", "--expose", "a=cat"][..],
            &["h.json", "--expose-file", "t.json"],
            &["h.json", "--require-idp", "email=*@x.com"],
            &["h.json", "--oidc-audience", "x"],
            &["h.json", "--oidc-issuer", "https://x"],
            &["h.json", "--audit-topic", "ops"],
            &["h.json", "--allow-any-member"],
            &["h.json", "--trust-root", "00"],
            &["h.json", "--", "cat"],
        ] {
            assert!(parse(gone).is_err(), "{gone:?}");
        }
    }

    /// `serve --check` validates and summarizes without a keystore; a bad
    /// file fails with the reason.
    #[tokio::test]
    async fn check_validates_without_a_keystore() {
        let dir = crate::testutil::temp_dir();
        let good = dir.join("host.json");
        std::fs::write(
            &good,
            r#"{"version":1,"tools":{"gh":{"command":["gh"],"allow":["member"]}}}"#,
        )
        .unwrap();
        let args = |path: &Path| {
            let Command::Serve(a) =
                Cli::try_parse_from(["wires", "serve", "--check", path.to_str().unwrap()])
                    .unwrap()
                    .command
            else {
                panic!("expected serve");
            };
            a
        };
        serve_cmd(args(&good)).await.unwrap();
        let bad = dir.join("bad.json");
        std::fs::write(&bad, r#"{"version":1,"tools":{},"extra":1}"#).unwrap();
        let e = format!("{:#}", serve_cmd(args(&bad)).await.unwrap_err());
        assert!(e.contains("is not a valid host.json"), "{e}");
        assert!(e.contains("unknown field `extra`"), "{e}");
    }

    /// `wires serve host.json --peer t1` for `member`, parsed from the CLI.
    fn audit_serve_args(member: &Member) -> ServeArgs {
        let cli = Cli::try_parse_from([
            "wires",
            "serve",
            "host.json",
            "--node-seed",
            &member.node.seed_hex(),
            "--peer",
            "t1",
        ])
        .unwrap();
        match cli.command {
            Command::Serve(a) => a,
            _ => panic!("expected serve"),
        }
    }

    /// Run the serve-side audit preflight against `member`'s keystore.
    fn audit_preflight(member: &Member, a: &ServeArgs) -> anyhow::Result<TopicContext> {
        audit_context_in(
            Arc::clone(&member.ks),
            member.home.clone(),
            a,
            "ops",
            member.node.node_id(),
            member.root.node_id(),
        )
    }

    #[test]
    fn serve_parses_the_peer_flag() {
        let member = provisioned([2u8; 32]);
        let a = audit_serve_args(&member);
        assert_eq!(a.peer, vec!["t1".to_string()]);
    }

    #[test]
    fn audit_topic_preflight_accepts_a_provisioned_member() {
        let member = provisioned([2u8; 32]);
        let mut a = audit_serve_args(&member);
        a.peer.clear();
        let ctx = audit_preflight(&member, &a).unwrap();
        assert_eq!(ctx.topic, TopicId::derive(member.root.node_id(), "ops"));
    }

    #[test]
    fn audit_topic_refuses_to_start_without_a_fabric_key() {
        let member = provisioned([2u8; 32]);
        std::fs::remove_dir_all(member.ks.keyring_dir()).unwrap();
        let mut a = audit_serve_args(&member);
        a.peer.clear();
        let e = format!("{:#}", audit_preflight(&member, &a).unwrap_err());
        assert!(e.contains("channel \"ops\" needs this host"), "{e}");
        assert!(e.contains("wires advanced import --fabric-key-file"), "{e}");
    }

    #[test]
    fn audit_topic_refuses_to_start_without_an_inclusion_proof() {
        let member = provisioned([2u8; 32]);
        std::fs::remove_file(member.ks.path("inclusion-proof.json")).unwrap();
        let mut a = audit_serve_args(&member);
        a.peer.clear();
        let e = format!("{:#}", audit_preflight(&member, &a).unwrap_err());
        assert!(
            e.contains("wires advanced import --inclusion-proof-file"),
            "{e}"
        );
    }

    #[test]
    fn audit_topic_refuses_a_channel_in_another_fabric() {
        let member = provisioned([2u8; 32]);
        let mut a = audit_serve_args(&member);
        a.peer.clear();
        let e = audit_context_in(
            Arc::clone(&member.ks),
            member.home.clone(),
            &a,
            "ops",
            member.node.node_id(),
            NodeIdentity::from_seed([77u8; 32]).node_id(),
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("this host's membership"), "{e:#}");
    }
}

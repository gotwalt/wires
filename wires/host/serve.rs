//! `wires serve`: the host's one command.
//!
//! Resolves the host's credentials, the tools it exposes, and — with
//! `--audit-topic` — the channel it records every call on and the IdP policy
//! it enforces, then serves the session protocol ([`transport`]).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use clap::Args;
use library::NodeId;

use super::{audit, identity, idp_policy, transport};
use crate::admin::keystore;
use crate::caller::jwks;
use crate::channel::context::{TopicArgs, TopicContext};
use crate::channel::idp_view;
use crate::channel::watch::run_tail;
use crate::init_logging;

/// `serve` arguments: the responder key, what it trusts, and the tools it
/// exposes.
#[derive(Args)]
pub(crate) struct ServeArgs {
    /// Hex 32-byte seed of this responder's node key. Falls back to
    /// `$WIRES_NODE_SEED`, then `--node-seed-file`, then the keystore (`node.seed`).
    #[arg(long)]
    pub(crate) node_seed: Option<String>,
    /// Read the node key seed (hex) from this file instead of the keystore.
    #[arg(long)]
    pub(crate) node_seed_file: Option<PathBuf>,
    /// Hex node id of the trusted fabric root whose memberships and grants are
    /// honored.
    #[arg(long)]
    pub(crate) trust_root: String,
    /// Serve any fabric member, with no grant (inclusion-only). An explicit
    /// acknowledgement of the authorization downgrade: the tool execs for any
    /// member and must authorize from the injected identity (or `--require-idp`
    /// does).
    #[arg(long)]
    pub(crate) allow_any_member: bool,
    /// CRL JSON literal of revoked subjects (overrides `--crl-file` / keystore).
    #[arg(long, conflicts_with = "crl_file")]
    pub(crate) crl_json: Option<String>,
    /// Read the CRL from this file (else the keystore's `crl.json`, else empty).
    #[arg(long)]
    pub(crate) crl_file: Option<PathBuf>,
    /// Use a self-hosted relay at this URL instead of the n0 default.
    #[arg(long)]
    pub(crate) relay_url: Option<String>,
    /// The responder's own membership token, presented in the handshake ack so a
    /// ticket-less dialer can verify it. Falls back to `$WIRES_MEMBERSHIP`, then
    /// `--membership-file`, then the keystore (`membership.json`).
    #[arg(long)]
    pub(crate) membership: Option<String>,
    /// Read the responder's membership token from this file.
    #[arg(long)]
    pub(crate) membership_file: Option<PathBuf>,
    /// The signed roster head this responder enforces (inclusion proof required
    /// from callers). Falls back to `$WIRES_ROSTER_HEAD`, then
    /// `--roster-head-file`, then the keystore (`roster-head.json`, re-checked
    /// per connection — a head imported later enforces on the next dial, with
    /// no restart). With no head at all: membership + CRL + TTL only.
    #[arg(long)]
    pub(crate) roster_head: Option<String>,
    /// Read the roster head token from this file.
    #[arg(long)]
    pub(crate) roster_head_file: Option<PathBuf>,
    /// The responder's own inclusion proof token (optional; presented in the ack).
    #[arg(long)]
    pub(crate) inclusion_proof: Option<String>,
    /// Read the responder's inclusion proof from this file.
    #[arg(long)]
    pub(crate) inclusion_proof_file: Option<PathBuf>,
    /// Expose a CLI as a named tool: `NAME=COMMAND ARGS…` (repeatable). The
    /// command is split on ASCII whitespace — no quoting, no shell — and each
    /// call's arguments are appended to it. Callers need a grant scoped
    /// `tool:NAME` (or `tool:*`) unless `--allow-any-member`. For a SQL tool
    /// use sqlite3's `-safe` flag (3.37+), which disables dot-commands like
    /// `.shell`/`.system`: `--expose 'db_query=sqlite3 -safe -readonly orders.db'`.
    #[arg(
        long,
        value_name = "NAME=COMMAND",
        required_unless_present = "expose_file"
    )]
    pub(crate) expose: Vec<String>,
    /// Expose the tools in this JSON file, `{"NAME": ["program", "arg", …]}`,
    /// for argv that needs spaces. Combines with `--expose`.
    #[arg(long)]
    pub(crate) expose_file: Option<PathBuf>,
    /// Publish a record of every call (started, finished, denied) to this
    /// topic. The responder hosts the topic node itself — same endpoint, same
    /// key — so it must be a provisioned member of the channel (membership,
    /// inclusion proof, roster head and fabric key in the keystore).
    #[arg(long)]
    pub(crate) audit_topic: Option<String>,
    /// A base64 topic ticket to bootstrap the audit topic from (repeatable).
    #[arg(long = "audit-peer", requires = "audit_topic")]
    pub(crate) audit_peer: Vec<String>,
    /// Only run tools for callers whose node key is bound to a verified IdP
    /// identity matching this rule: `key=value,…` with keys `iss`, `email`
    /// (exact or `*@domain`), `org`, `group`; all must match. Repeatable: any
    /// rule may match. Identities come from `wires login --topic <audit
    /// topic>` claims, so this needs `--audit-topic`.
    #[arg(long, value_name = "RULE", requires = "audit_topic")]
    pub(crate) require_idp: Vec<String>,
    /// An accepted ID-token audience (OAuth client id); repeatable or
    /// comma-separated. Default: `$WIRES_OIDC_AUDIENCE`, else
    /// `$WIRES_OIDC_CLIENT_ID`.
    #[arg(long, value_name = "CLIENT_ID")]
    pub(crate) oidc_audience: Vec<String>,
    /// A trusted ID-token issuer; repeatable or comma-separated. Default:
    /// `$WIRES_OIDC_ISSUER`, else Google. Every `--require-idp iss=` is
    /// trusted too.
    #[arg(long, value_name = "URL")]
    pub(crate) oidc_issuer: Vec<String>,
}

/// `serve`: bind, verify membership (and, unless `--allow-any-member`, a tool
/// grant) against the trust root, exec the invoked tool + bridge.
pub(crate) async fn serve_cmd(a: ServeArgs) -> anyhow::Result<()> {
    init_logging();
    let node = keystore::node_identity(a.node_seed.as_deref(), a.node_seed_file.as_deref())?;
    let trust_root = NodeId::from_hex(&a.trust_root)?;
    // `--audit-topic`: resolve the channel credentials *before* serving, so a
    // responder that is not a member of its audit channel fails closed here.
    let audit_ctx = match a.audit_topic.as_deref() {
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
        Some(ctx) => Some(serve_identities(&a, &ctx.home)?),
        None => None,
    };
    let tools = transport::exposed_tools(&a.expose, a.expose_file.as_deref())?;
    if tools.is_empty() {
        anyhow::bail!(
            "refusing to serve: nothing is exposed; pass --expose NAME=COMMAND (or \
             --expose-file)"
        );
    }
    // Credential *sources*, not values: a file-backed CRL or head is re-read on
    // every connection, so `wires advanced revoke` / `wires advanced roster commit` take effect on
    // the next dial without bouncing this process.
    let crl = keystore::crl_source(a.crl_json.as_deref(), a.crl_file.clone())?;
    let membership = keystore::membership(a.membership.as_deref(), a.membership_file.as_deref())?;
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
        (Some((ids, policy)), Some(ctx)) => Some(Arc::new(identity::IdentityGate::new(
            Arc::clone(ids),
            policy.clone(),
            ctx.name.clone(),
        ))),
        _ => None,
    };
    let config = transport::ServeConfig {
        tools,
        audit: sink,
        identity: gate,
        trust_root,
        require_grant: !a.allow_any_member,
        crl,
        head,
        membership,
        proof,
    };
    match (audit_ctx, records) {
        (Some(ctx), Some(records)) => {
            tracing::info!(topic = %ctx.name, "serving the session ALPN on the audit topic's node");
            let hosted = audit::Hosted {
                session: transport::SessionProtocol(Arc::new(config)),
                records,
                identities: identities.expect("built with the audit context").0,
            };
            run_tail(&ctx, 0, false, Some(hosted)).await
        }
        _ => transport::serve(node, config, a.relay_url.as_deref()).await,
    }
}

/// The responder's identity index and `--require-idp` policy.
///
/// Trusted issuers are `--oidc-issuer` (else `$WIRES_OIDC_ISSUER`, else
/// Google) plus every rule's `iss`; audiences are `--oidc-audience` (else the
/// environment). A policy with no accepted audience could never admit anyone,
/// so it is refused here rather than at the first call.
pub(crate) fn serve_identities(
    a: &ServeArgs,
    home: &Path,
) -> anyhow::Result<(Arc<identity::Identities>, idp_policy::IdpPolicy)> {
    let policy = idp_policy::IdpPolicy::parse(&a.require_idp)?;
    let trust = idp_view::IdpTrust::from_flags_or_env(&a.oidc_issuer, &a.oidc_audience)
        .trusting(policy.issuers());
    if !policy.is_empty() && trust.audiences.is_empty() {
        anyhow::bail!(
            "--require-idp needs an accepted audience: pass --oidc-audience <client id> or set \
             WIRES_OIDC_AUDIENCE"
        );
    }
    let fetcher = jwks::KeyFetcher::new(Some(home.join("jwks")))?;
    Ok((Arc::new(identity::Identities::new(fetcher, trust)), policy))
}

/// Resolve `serve --audit-topic <name>` into the same [`TopicContext`] `wires
/// tail` would build, failing (with the `wires advanced import` remedy) when this node
/// is not a provisioned member of the channel, or when the channel's fabric is
/// not the one this responder trusts.
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
        peer: a.audit_peer.clone(),
        node_seed: a.node_seed.clone(),
        node_seed_file: a.node_seed_file.clone(),
        relay_url: a.relay_url.clone(),
        membership: a.membership.clone(),
        membership_file: a.membership_file.clone(),
        inclusion_proof: a.inclusion_proof.clone(),
        inclusion_proof_file: a.inclusion_proof_file.clone(),
    };
    let ctx = TopicContext::resolve(ks, home, &args)
        .context("--audit-topic needs this responder to be a member of the channel")?;
    if ctx.node.node_id() != node {
        anyhow::bail!("--audit-topic resolved a different node key than the one serving");
    }
    if ctx.fabric_root != trust_root {
        anyhow::bail!(
            "--audit-topic: this node's membership is in fabric {}, but --trust-root is {}",
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
    fn serve_requires_an_exposed_tool() {
        let base = ["wires", "serve", "--trust-root", "00"];
        let parse = |extra: &[&str]| Cli::try_parse_from(base.iter().chain(extra));
        let Command::Serve(a) = parse(&["--expose", "a=cat", "--expose", "b=rg -n"])
            .unwrap()
            .command
        else {
            panic!("expected serve");
        };
        assert_eq!(a.expose, ["a=cat", "b=rg -n"]);
        assert!(parse(&["--expose-file", "t.json"]).is_ok());
        assert!(parse(&[]).is_err(), "nothing exposed");
        // The single-command form and its `--scope` are gone.
        assert!(parse(&["--", "cat"]).is_err());
        assert!(parse(&["--expose", "a=cat", "--", "cat"]).is_err());
        assert!(parse(&["--expose", "a=cat", "--scope", "s"]).is_err());
    }

    /// `wires serve --audit-topic ops …` for `member`, parsed from the CLI.
    fn audit_serve_args(member: &Member) -> ServeArgs {
        let cli = Cli::try_parse_from([
            "wires",
            "serve",
            "--trust-root",
            &member.root.node_id().hex(),
            "--allow-any-member",
            "--node-seed",
            &member.node.seed_hex(),
            "--audit-topic",
            "ops",
            "--audit-peer",
            "t1",
            "--expose",
            "cat=cat",
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
    fn serve_parses_the_audit_flags() {
        let member = provisioned([2u8; 32]);
        let a = audit_serve_args(&member);
        assert_eq!(a.audit_topic.as_deref(), Some("ops"));
        assert_eq!(a.audit_peer, vec!["t1".to_string()]);
        // `--audit-peer` means nothing without a topic.
        assert!(
            Cli::try_parse_from([
                "wires",
                "serve",
                "--trust-root",
                "ab",
                "--audit-peer",
                "t",
                "--expose",
                "cat=cat"
            ])
            .is_err()
        );
    }

    #[test]
    fn audit_topic_preflight_accepts_a_provisioned_member() {
        let member = provisioned([2u8; 32]);
        let mut a = audit_serve_args(&member);
        a.audit_peer.clear();
        let ctx = audit_preflight(&member, &a).unwrap();
        assert_eq!(ctx.topic, TopicId::derive(member.root.node_id(), "ops"));
    }

    #[test]
    fn audit_topic_refuses_to_start_without_a_fabric_key() {
        let member = provisioned([2u8; 32]);
        std::fs::remove_dir_all(member.ks.keyring_dir()).unwrap();
        let mut a = audit_serve_args(&member);
        a.audit_peer.clear();
        let e = format!("{:#}", audit_preflight(&member, &a).unwrap_err());
        assert!(e.contains("--audit-topic"), "{e}");
        assert!(e.contains("wires advanced import --fabric-key-file"), "{e}");
    }

    #[test]
    fn audit_topic_refuses_to_start_without_an_inclusion_proof() {
        let member = provisioned([2u8; 32]);
        std::fs::remove_file(member.ks.path("inclusion-proof.json")).unwrap();
        let mut a = audit_serve_args(&member);
        a.audit_peer.clear();
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
        a.audit_peer.clear();
        let e = audit_context_in(
            Arc::clone(&member.ks),
            member.home.clone(),
            &a,
            "ops",
            member.node.node_id(),
            NodeIdentity::from_seed([77u8; 32]).node_id(),
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("--trust-root"), "{e:#}");
    }
}

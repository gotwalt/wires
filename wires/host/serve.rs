//! `wires serve host.json`: the host's one command.
//!
//! What the host implements — each service's command, working directory and
//! environment, the IdPs it trusts, stricter local rules, push, and where its
//! call log is exported — comes from `host.json` (version 2, see
//! [`config_v2`](super::config_v2)). Who may call is the admin-signed state's
//! to say. The flags left are where the host's own credentials live and
//! `--relay-url`.
//!
//! `wires serve --check host.json` validates the file and prints what it
//! means, without touching the keystore or the network.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use clap::Args;
use library::NodeId;

use super::config_v2::HostConfigV2;
use super::{call_log, capability, control, gate, identity, otlp, push, transport};
use crate::admin::keystore;
use crate::caller::jwks;
use crate::init_logging;

/// `serve` arguments: `host.json`, and where this host's own key and
/// credentials come from.
#[derive(Args)]
pub(crate) struct ServeArgs {
    /// The host's config: the services it implements, trusted IdPs, push
    /// (see `wires serve --check`).
    #[arg(value_name = "HOST_JSON")]
    pub(crate) config: PathBuf,
    /// Validate HOST_JSON, print the services it implements and which
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
    /// Use a self-hosted relay at this URL instead of the n0 default.
    #[arg(long)]
    pub(crate) relay_url: Option<String>,
    /// The host's own membership token: it names the fabric (the trust root)
    /// whose signed state decides every call, and is presented in the
    /// `HelloAck`. Falls back to `$WIRES_MEMBERSHIP`, then
    /// `--membership-file`, then the keystore (`membership.json`).
    #[arg(long)]
    pub(crate) membership: Option<String>,
    /// Read the host's membership token from this file.
    #[arg(long)]
    pub(crate) membership_file: Option<PathBuf>,
}

/// `serve`: refuse to start unless this node holds a fresh signed state that
/// assigns every service in `host.json` to it; then serve the session ALPN,
/// the state ALPN (members pull newer states from hosts), and — with `push` —
/// the inbox ALPN plus a local control socket for `wires push`, deciding
/// every call by the signed state as it stands at that connection.
pub(crate) async fn serve_cmd(a: ServeArgs) -> anyhow::Result<()> {
    let config = HostConfigV2::load(&a.config)?;
    if a.check {
        print!("{}", config.summary());
        return Ok(());
    }
    init_logging();
    let node = keystore::node_identity(a.node_seed.as_deref(), a.node_seed_file.as_deref())?;
    let membership = keystore::membership(a.membership.as_deref(), a.membership_file.as_deref())?;
    let home = keystore::home()?;
    let ks = Arc::new(keystore::Keystore::resolve()?);
    let mut host = services_host(node.node_id(), membership, Arc::clone(&ks), &home, config)?;
    // A host assigned a service while it was offline: pull, then try again.
    let state = match host.preflight(crate::now_unix()) {
        Ok(state) => state,
        Err(e) => match crate::state::sync::pull_now(&ks, &node, a.relay_url.as_deref()).await {
            Ok(Some(_)) => host.preflight(crate::now_unix())?,
            _ => return Err(e),
        },
    };
    tracing::info!(
        state_version = state.state.version.0,
        services = host.config.services.len(),
        "signed state assigns every host.json service to this host"
    );
    let exporter = match host.config.audit.as_ref().and_then(|a| a.otlp.as_deref()) {
        Some(url) => Some(otlp::Exporter::spawn(url)?.0),
        None => None,
    };
    let log = call_log::CallLog::open(
        &home.join(call_log::LOG_FILE),
        library::NodeIdentity::from_seed(node.seed_bytes()),
        library::Retention::default(),
    )?;
    let (sink, _, _tee) = call_log::start(log, exporter, false);
    host.audit = Some(sink);
    let host = Arc::new(host);
    let push = host.config.push.is_some().then(|| {
        Arc::new(
            push::PushHost::from_state(Arc::clone(&host))
                .persisted_queue(home.join(push::QUEUE_FILE)),
        )
    });
    let endpoint = transport::bind(&node, a.relay_url.as_deref()).await?;
    if let Err(e) = crate::caller::pick::write_own_hint(&ks, &endpoint) {
        tracing::warn!("could not write this host's hint line: {e:#}");
    }
    let _router = services_router(endpoint.clone(), Arc::clone(&host), push.clone());
    // A push missed while down is pulled on a timer.
    tokio::spawn(crate::state::sync::refresh_loop(endpoint, Arc::clone(&ks)));
    match push {
        Some(push) => {
            let (commands_tx, commands) = tokio::sync::mpsc::channel(16);
            let _sockets = push_sockets(&home, &host, commands_tx).await?;
            tokio::select! {
                () = push.run(commands) => Ok(()),
                r = tokio::signal::ctrl_c() => r.context("waiting for ctrl-c"),
            }
        }
        None => tokio::signal::ctrl_c().await.context("waiting for ctrl-c"),
    }
}

/// The file whose presence marks an admin keystore.
const ROOT_SEED: &str = "root.seed";

/// A host for `me` (before its call log is attached): its identity verifier
/// trusts exactly `config`'s issuers and keeps their keys **in memory only**
/// (a key set on disk could have been planted by anything running as this
/// user, a service child included). With `push` on, calls get a per-call
/// push capability on the child socket under `home`.
///
/// Refuses an admin keystore (one holding `root.seed`): a host runs service
/// children, and the fabric's root key must not sit beside them.
pub(crate) fn services_host(
    me: NodeId,
    membership: library::Membership,
    keystore: Arc<keystore::Keystore>,
    home: &Path,
    config: HostConfigV2,
) -> anyhow::Result<gate::ServicesHost> {
    if keystore.path(ROOT_SEED).exists() {
        anyhow::bail!(
            "{} holds the admin key ({ROOT_SEED}); a host runs services and must not share a \
             keystore with the fabric's root. Run `wires serve` from the host's own keystore \
             (WIRES_HOME=<another dir> wires id, invite that node, join it there)",
            keystore.path("").display()
        );
    }
    let fetcher = jwks::KeyFetcher::new(None)?;
    let identities = Arc::new(identity::Identities::new(fetcher, config.identity.trust()));
    let push_grants = config.push.is_some().then(|| capability::PushGrants {
        caps: Arc::default(),
        socket: capability::child_socket(home),
    });
    Ok(gate::ServicesHost {
        me,
        trust_root: membership.fabric,
        membership,
        keystore,
        config,
        identities,
        audit: None,
        push_grants,
        high_water: Default::default(),
    })
}

/// Bind the push control sockets and serve them into `commands`: the
/// operator's (`run/serve.sock`, any push) and, when `host` hands out push
/// capabilities, the child socket (a call's push to its own caller). Keep
/// the handles: aborting one unbinds its socket.
pub(crate) async fn push_sockets(
    home: &Path,
    host: &gate::ServicesHost,
    commands: tokio::sync::mpsc::Sender<push::PushCommand>,
) -> anyhow::Result<Vec<tokio::task::JoinHandle<()>>> {
    let operator = control::ControlSocket::bind(&push::host_socket(home)).await?;
    let mut handles = vec![operator.spawn(commands.clone(), control::Authority::Operator)];
    if let Some(grants) = &host.push_grants {
        let child = control::ControlSocket::bind(&grants.socket).await?;
        handles.push(child.spawn(
            commands,
            control::Authority::Calls(Arc::clone(&grants.caps)),
        ));
    }
    Ok(handles)
}

/// Serve a host on `endpoint`: the session ALPN, the state ALPN (so members
/// can pull newer signed states from it, and the admin's pushes land), the
/// record stream (`wires watch`, card 26b), plus the inbox ALPN when it
/// pushes (and push's direct deliveries dial from
/// this endpoint). Keep the router alive for as long as the host serves.
pub(crate) fn services_router(
    endpoint: iroh::Endpoint,
    host: Arc<gate::ServicesHost>,
    push: Option<Arc<push::PushHost>>,
) -> iroh::protocol::Router {
    let mut builder = iroh::protocol::Router::builder(endpoint.clone())
        .accept(
            library::STATE_ALPN,
            crate::state::sync::StateResponder(Arc::clone(&host.keystore)),
        )
        .accept(
            transport::ALPN,
            transport::ServicesProtocol::new(Arc::clone(&host)),
        )
        .accept(
            super::record_stream::ALPN,
            super::record_stream::RecordStream::new(host),
        );
    if let Some(push) = push {
        push.attach(endpoint);
        builder = builder.accept(library::INBOX_ALPN, push::PushFetch(push));
    }
    tracing::info!("serving services");
    builder.spawn()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Command};
    use clap::Parser;

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
        // The flag-based and channel-era forms are gone: host.json and the
        // signed state are the only ones.
        for gone in [
            &["h.json", "--expose", "a=cat"][..],
            &["h.json", "--audit-topic", "ops"],
            &["h.json", "--peer", "t1"],
            &["h.json", "--roster-head", "x"],
            &["h.json", "--inclusion-proof", "x"],
            &["h.json", "--", "cat"],
        ] {
            assert!(parse(gone).is_err(), "{gone:?}");
        }
    }

    /// A host's parts for the tests below: root 1, host 10, a keystore at
    /// `home`, and a host.json trusting `issuer` (none: no identity).
    fn host_at(
        home: &Path,
        issuer: Option<&library::Issuer>,
    ) -> anyhow::Result<gate::ServicesHost> {
        let root = library::NodeIdentity::from_seed([1u8; 32]);
        let me = library::NodeIdentity::from_seed([10u8; 32]).node_id();
        let identity = issuer.map_or(String::new(), |iss| {
            format!(
                r#""identity":{{"issuers":[{{"issuer":"{}","audiences":["{}"]}}]}},"#,
                iss.as_str(),
                crate::caller::mock_idp::MOCK_CLIENT_ID
            )
        });
        let config = HostConfigV2::parse(&format!(
            r#"{{"version":2,{identity}"services":{{"status":{{"command":["true"]}}}}}}"#
        ))
        .unwrap();
        services_host(
            me,
            library::Membership::mint(&root, me, 0, i64::MAX).unwrap(),
            Arc::new(keystore::Keystore::at(home)),
            home,
            config,
        )
    }

    fn signed(version: u64) -> library::SignedState {
        let root = library::NodeIdentity::from_seed([1u8; 32]);
        let mut s = library::State::new(root.node_id());
        s.version = library::StateVersion(version);
        s.not_after = i64::MAX;
        s.sign(&root).unwrap()
    }

    #[test]
    fn serve_refuses_an_admin_keystore() {
        let home = crate::testutil::temp_dir();
        host_at(&home, None).unwrap();
        keystore::Keystore::at(&home)
            .save_root(&library::NodeIdentity::from_seed([1u8; 32]), false)
            .unwrap();
        let e = format!("{:#}", host_at(&home, None).unwrap_err());
        assert!(e.contains("root.seed") && e.contains("own keystore"), "{e}");
    }

    #[test]
    fn a_host_refuses_to_decide_under_a_rolled_back_state() {
        let home = crate::testutil::temp_dir();
        let host = host_at(&home, None).unwrap();
        let ks = keystore::Keystore::at(&home);
        let root = library::NodeIdentity::from_seed([1u8; 32]).node_id();
        let now = crate::now_unix();
        crate::state::store::adopt_if_newer(&ks, &signed(1), root, now).unwrap();
        assert_eq!(host.state().unwrap().state.version.0, 1);
        crate::state::store::adopt_if_newer(&ks, &signed(2), root, now).unwrap();
        assert_eq!(host.state().unwrap().state.version.0, 2);
        // Someone with write access puts version 1 back: it still verifies.
        let old = signed(1).encode().unwrap();
        std::fs::write(ks.path(crate::state::store::STATE_FILE), format!("{old}\n")).unwrap();
        let e = format!("{:#}", host.state().unwrap_err());
        assert!(e.contains("version 1") && e.contains("version 2"), "{e}");
        // The push rule reads the same state, and refuses too.
        assert!(host.decide_push(host.me, now).is_err());
        // A state at least as new as the mark is decided under again.
        crate::state::store::adopt_if_newer(&ks, &signed(3), root, now).unwrap();
        assert_eq!(host.state().unwrap().state.version.0, 3);
    }

    /// A key set on disk in the host's home (a caller's cache, or one planted
    /// by anything running as this user) is never what the host verifies
    /// with: it fetches the issuer's keys itself.
    #[tokio::test]
    async fn a_host_trusts_only_the_keys_it_fetched_itself() {
        let idp = crate::caller::mock_idp::MockIdp::start("alice@example.com").await;
        let home = crate::testutil::temp_dir();
        let now = crate::now_unix();
        jwks::KeyFetcher::new(Some(home.join("jwks")))
            .unwrap()
            .keys(&idp.issuer, None, now)
            .await
            .unwrap();
        assert_eq!(idp.jwks_fetches(), 1);
        assert!(
            std::fs::read_dir(home.join("jwks"))
                .unwrap()
                .next()
                .is_some()
        );

        let host = host_at(&home, Some(&idp.issuer)).unwrap();
        let alice = library::NodeIdentity::from_seed([2u8; 32]).node_id();
        let token = idp.mint(&library::OidcNonce::for_node(&alice), now + 3600);
        let who = host
            .identities
            .verify_token(alice, &token, now)
            .await
            .unwrap();
        assert_eq!(who.email.as_deref(), Some("alice@example.com"));
        assert_eq!(
            idp.jwks_fetches(),
            2,
            "the host must fetch, not read the disk"
        );
    }

    /// `serve --check` validates and summarizes without a keystore; a bad
    /// file fails with the reason.
    #[tokio::test]
    async fn check_validates_without_a_keystore() {
        let dir = crate::testutil::temp_dir();
        let good = dir.join("host.json");
        std::fs::write(
            &good,
            r#"{"version":2,"services":{"gh":{"command":["gh"]}}}"#,
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
        std::fs::write(&bad, r#"{"version":2,"services":{},"extra":1}"#).unwrap();
        let e = format!("{:#}", serve_cmd(args(&bad)).await.unwrap_err());
        assert!(e.contains("is not a valid host.json"), "{e}");
        assert!(e.contains("unknown field `extra`"), "{e}");
        let v1 = dir.join("v1.json");
        std::fs::write(
            &v1,
            r#"{"version":1,"tools":{"gh":{"command":["gh"],"allow":["member"]}}}"#,
        )
        .unwrap();
        let e = format!("{:#}", serve_cmd(args(&v1)).await.unwrap_err());
        assert!(e.contains("version 1"), "{e}");
    }
}

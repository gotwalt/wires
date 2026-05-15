use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use iroh::SecretKey;
use snafu::ResultExt;
use wires_core::cap::Right;
use wires_net::load_or_create_secret;
use wires_net::pair::{PairManifest, RequestedScope};
use wires_node::{Node, NodeConfig, PairListenArgs, PairOutcome, pair_listen as run_listen};

use crate::error::{IoSnafu, NetSnafu, NodeSnafu, Result, TomlParseSnafu};
use crate::invalid;

pub async fn run(
    data_dir: &Path,
    role: String,
    description: String,
    requests: Vec<String>,
    ttl: Duration,
    qr: bool,
) -> Result<()> {
    let scopes = parse_requests(&requests)?;

    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let node = Arc::new(Node::open(cfg).context(NodeSnafu)?);

    let agent_sk = SigningKey::from_bytes(&load_identity_32(data_dir, "identity.ed25519")?);

    let agent_x25519_secret = load_identity_32(data_dir, "identity.x25519")?;
    let agent_x25519_pk =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(agent_x25519_secret))
            .to_bytes();

    let secret = load_or_create_secret(&data_dir.join("iroh.secret")).context(NetSnafu)?;
    let endpoint = wires_net::bind_lan(SecretKey::from_bytes(&secret), vec![])
        .await
        .context(NetSnafu)?;

    let started = run_listen(
        data_dir.to_path_buf(),
        node,
        agent_sk,
        agent_x25519_pk,
        endpoint,
        PairListenArgs {
            manifest: PairManifest {
                role,
                description,
                requested_scopes: scopes,
            },
            ttl,
        },
    )
    .await
    .context(NodeSnafu)?;

    println!("Pair-listen window open for {} seconds.", ttl.as_secs());
    println!("Share this token with the operator:");
    println!("{}", started.request_token);
    if qr {
        let req = wires_net::pair::PairRequest::decode(&started.request_token).context(NetSnafu)?;
        let art = req.render_qr_ansi().context(NetSnafu)?;
        println!();
        print!("{art}");
    }
    println!();
    println!("Waiting for pair-approve…");
    match tokio::time::timeout(ttl, started.outcome).await {
        Ok(Ok(PairOutcome::Paired { cap_id })) => {
            println!("Paired. Installed cap: {}", hex::encode(cap_id));
            started.router.shutdown().await.ok();
            Ok(())
        }
        Ok(Err(_)) => {
            started.router.shutdown().await.ok();
            Err(invalid!("pair-listen handler closed without outcome"))
        }
        Err(_) => {
            wires_node::pair_pending::delete(data_dir).ok();
            started.router.shutdown().await.ok();
            Err(invalid!("pair-listen window expired"))
        }
    }
}

fn load_identity_32(data_dir: &Path, file: &str) -> Result<[u8; 32]> {
    let bytes = std::fs::read(data_dir.join(file)).context(IoSnafu)?;
    bytes
        .try_into()
        .map_err(|_| invalid!("{file} must be 32 bytes"))
}

fn parse_requests(reqs: &[String]) -> Result<Vec<RequestedScope>> {
    let mut out = Vec::new();
    for r in reqs {
        let (name, rights) = r
            .split_once(':')
            .ok_or_else(|| invalid!("--request '{}' must be 'name:rights'", r))?;
        let mut rs = Vec::new();
        for token in rights.split('+') {
            match token {
                "read" => rs.push(Right::Read),
                "write" => rs.push(Right::Write),
                other => return Err(invalid!("unknown right '{}' in --request '{}'", other, r)),
            }
        }
        out.push(RequestedScope {
            topic_name: name.to_string(),
            rights: rs,
        });
    }
    if out.is_empty() {
        return Err(invalid!(
            "--request <name:rights> is required at least once"
        ));
    }
    Ok(out)
}

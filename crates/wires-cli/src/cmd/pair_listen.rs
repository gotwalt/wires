use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use iroh::{Endpoint, SecretKey, endpoint::presets};
use wires_core::cap::Right;
use wires_net::load_or_create_secret;
use wires_net::pair::{PairManifest, RequestedScope};
use wires_node::{Node, NodeConfig, PairListenArgs, PairOutcome, pair_listen as run_listen};

pub async fn run(
    data_dir: &Path,
    role: String,
    description: String,
    requests: Vec<String>,
    ttl: Duration,
    qr: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let scopes = parse_requests(&requests)?;

    let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
    let node = Arc::new(Node::open(cfg)?);

    let agent_sk_bytes = std::fs::read(data_dir.join("identity.ed25519"))?;
    if agent_sk_bytes.len() != 32 {
        return Err("identity.ed25519 must be 32 bytes".into());
    }
    let agent_sk = SigningKey::from_bytes(&agent_sk_bytes.try_into().unwrap());

    let agent_x25519_secret = std::fs::read(data_dir.join("identity.x25519"))?;
    if agent_x25519_secret.len() != 32 {
        return Err("identity.x25519 must be 32 bytes".into());
    }
    let agent_x25519_secret_arr: [u8; 32] = agent_x25519_secret.try_into().unwrap();
    let agent_x25519_pk =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(agent_x25519_secret_arr))
            .to_bytes();

    let secret = load_or_create_secret(&data_dir.join("iroh.secret"))?;
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::from_bytes(&secret))
        .bind()
        .await?;

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
    .await?;

    println!("Pair-listen window open for {} seconds.", ttl.as_secs());
    println!("Share this token with the operator:");
    println!("{}", started.request_token);
    if qr {
        println!(
            "(--qr requested; pipe the token to `qrencode -t ANSI256UTF8 -o-` for a terminal QR)"
        );
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
            Err("pair-listen handler closed without outcome".into())
        }
        Err(_) => {
            wires_node::pair_pending::delete(data_dir).ok();
            started.router.shutdown().await.ok();
            Err("pair-listen window expired".into())
        }
    }
}

fn parse_requests(reqs: &[String]) -> Result<Vec<RequestedScope>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for r in reqs {
        let (name, rights) = r
            .split_once(':')
            .ok_or_else(|| format!("--request '{r}' must be 'name:rights'"))?;
        let mut rs = Vec::new();
        for token in rights.split('+') {
            match token {
                "read" => rs.push(Right::Read),
                "write" => rs.push(Right::Write),
                other => return Err(format!("unknown right '{other}' in --request '{r}'").into()),
            }
        }
        out.push(RequestedScope {
            topic_name: name.to_string(),
            rights: rs,
        });
    }
    if out.is_empty() {
        return Err("--request <name:rights> is required at least once".into());
    }
    Ok(out)
}

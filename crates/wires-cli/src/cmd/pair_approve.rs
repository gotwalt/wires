use std::io::Write;
use std::path::Path;

use iroh::SecretKey;
use snafu::ResultExt;
use wires_core::Capability;
use wires_core::cap::Right;
use wires_net::pair::{
    HostInfo, PairClient, PairGrant, PairGrantEnvelope, PairRequest, RequestedScope, TopicEpochKey,
    TopicNameEntry,
};
use wires_net::{load_or_create_secret, unix_now_ms};
use wires_node::{Node, NodeConfig, load_root_signing_key, load_topic_names};

use crate::error::{CoreSnafu, IoSnafu, NetSnafu, NodeSnafu, Result, StoreSnafu, TomlParseSnafu};
use crate::invalid;

pub async fn run(
    data_dir: &Path,
    token: &str,
    narrow_scopes: Vec<String>,
    narrow_topics: Option<Vec<String>>,
    no_host: bool,
    assume_yes: bool,
) -> Result<()> {
    let request = PairRequest::decode(token).context(NetSnafu)?;
    request.verify().context(NetSnafu)?;
    let now = unix_now_ms();
    if now >= request.expires {
        return Err(invalid!("pair request has expired"));
    }

    print_manifest(&request, now);
    if !assume_yes && !prompt_yes_no("Approve and grant? [y/N] ")? {
        return Err(invalid!("rejected by operator"));
    }

    let raw = std::fs::read_to_string(data_dir.join("config.toml")).context(IoSnafu)?;
    let cfg: NodeConfig = toml::from_str(&raw).context(TomlParseSnafu)?;
    let host_info = if no_host {
        None
    } else {
        cfg.host.as_ref().map(|h| HostInfo {
            peer_hints: h.peer_hints.clone(),
        })
    };
    let node = Node::open(cfg).context(NodeSnafu)?;
    let root_sk = load_root_signing_key(data_dir).context(IoSnafu)?;
    let root_pk = root_sk.verifying_key().to_bytes();

    let name_map = load_topic_names(data_dir).context(IoSnafu)?;
    let scopes = filter_scopes(
        &request.manifest.requested_scopes,
        &narrow_scopes,
        narrow_topics.as_deref(),
    )?;

    let mut topic_keys = Vec::new();
    let mut topic_names = Vec::new();
    let mut cap_topics: Vec<String> = Vec::new();
    let mut cap_rights: Vec<Right> = Vec::new();
    let mut seen_rights = std::collections::HashSet::new();
    for scope in &scopes {
        let topic_id = name_map
            .get(&scope.topic_name)
            .ok_or_else(|| invalid!("unknown topic '{}'", scope.topic_name))?;
        let keys = node.epoch_keys_for(topic_id).context(NodeSnafu)?;
        let (epoch, key) = keys
            .latest()
            .context(StoreSnafu)?
            .ok_or_else(|| invalid!("no epoch key for topic '{}'", scope.topic_name))?;
        topic_keys.push(TopicEpochKey {
            topic_id: *topic_id,
            epoch,
            key,
        });
        topic_names.push(TopicNameEntry {
            topic_id: *topic_id,
            name: scope.topic_name.clone(),
        });
        cap_topics.push(scope.topic_name.clone());
        for r in &scope.rights {
            if seen_rights.insert(*r) {
                cap_rights.push(*r);
            }
        }
    }

    let mut cap = Capability::new_unsigned(request.agent_pubkey, cap_topics, cap_rights, now, None);
    cap.sign(&root_sk).context(CoreSnafu)?;
    let cap_id = cap.cap_id.0;
    let grant = PairGrant {
        version: 1,
        root_pubkey: root_pk,
        cap,
        topic_keys,
        topic_names,
        host: host_info,
        nonce: request.nonce,
        issued_at: now,
    };
    let envelope = PairGrantEnvelope::seal_and_sign(&grant, &request.ephemeral_x25519, &root_sk)
        .context(NetSnafu)?;

    let secret = load_or_create_secret(&data_dir.join("iroh.secret")).context(NetSnafu)?;
    let endpoint = wires_net::bind_lan(SecretKey::from_bytes(&secret), vec![])
        .await
        .context(NetSnafu)?;
    let client = PairClient::new(endpoint);
    let ack = client
        .deliver_grant(&request.dial, envelope)
        .await
        .context(NetSnafu)?;
    println!(
        "Paired: cap {} installed at {} on agent {}",
        hex::encode(cap_id),
        ack.installed_at,
        hex::encode(request.agent_pubkey),
    );
    Ok(())
}

fn print_manifest(req: &PairRequest, now_ms: i64) {
    println!("Pair request from agent {}", hex::encode(req.agent_pubkey));
    println!("  role        : {}", req.manifest.role);
    println!("  description : {}", req.manifest.description);
    println!("  requested   :");
    for s in &req.manifest.requested_scopes {
        let rs: Vec<&str> = s
            .rights
            .iter()
            .map(|r| match r {
                Right::Read => "read",
                Right::Write => "write",
            })
            .collect();
        println!("    {} : {}", s.topic_name, rs.join(", "));
    }
    println!("  issued_at   : {} (ms)", req.issued_at);
    let remaining_s = (req.expires - now_ms).max(0) / 1000;
    println!(
        "  expires_at  : {} ({}s remaining)",
        req.expires, remaining_s
    );
    println!("  nonce       : {}...", &hex::encode(req.nonce)[..16]);
}

fn prompt_yes_no(prompt: &str) -> Result<bool> {
    print!("{prompt}");
    std::io::stdout().flush().context(IoSnafu)?;
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf).context(IoSnafu)?;
    Ok(matches!(
        buf.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn filter_scopes(
    requested: &[RequestedScope],
    narrow_scopes: &[String],
    narrow_topics: Option<&[String]>,
) -> Result<Vec<RequestedScope>> {
    let mut base: Vec<RequestedScope> = match narrow_topics {
        Some(names) => requested
            .iter()
            .filter(|s| names.iter().any(|n| n == &s.topic_name))
            .cloned()
            .collect(),
        None => requested.to_vec(),
    };
    for spec in narrow_scopes {
        let (name, rights) = spec
            .split_once(':')
            .ok_or_else(|| invalid!("--scope '{}' must be 'name:rights'", spec))?;
        let mut rs = Vec::new();
        for t in rights.split('+') {
            match t {
                "read" => rs.push(Right::Read),
                "write" => rs.push(Right::Write),
                other => return Err(invalid!("unknown right '{}' in --scope '{}'", other, spec)),
            }
        }
        if let Some(s) = base.iter_mut().find(|s| s.topic_name == name) {
            s.rights.retain(|r| rs.contains(r));
        }
    }
    base.retain(|s| !s.rights.is_empty());
    if base.is_empty() {
        return Err(invalid!("after narrowing, no scopes remain to grant"));
    }
    Ok(base)
}

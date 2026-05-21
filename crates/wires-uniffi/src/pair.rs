//! Build, seal, sign, and deliver a `PairGrant` to a pending pair request.

use std::sync::Arc;
use std::time::SystemTime;

use iroh::Endpoint;
use wires_core::{Capability, RootSigner, cap::Right as CoreRight};
use wires_net::pair::grant::{HostInfo as PairHostInfo, PairGrant, TopicEpochKey, TopicNameEntry};
use wires_net::pair::{PairClient, PairGrantEnvelope, PairRequest};
use wires_net::peer_hint::PeerHint;

use crate::error::{
    InternalSnafu, PairDeliveryFailedSnafu, PairRejectedSnafu, PairRequestExpiredSnafu, WiresError,
};
use crate::signer::{SwiftRootSigner, SwiftRootSignerAdapter};
use crate::types::{GrantedScope, HostInfo, PairAckRecord, Right};

pub async fn approve_pair_request(
    endpoint: Endpoint,
    root_signer: Arc<dyn SwiftRootSigner>,
    request: &PairRequest,
    granted_scopes: Vec<GrantedScope>,
    host: HostInfo,
) -> Result<PairAckRecord, WiresError> {
    let now = now_ms()?;
    if now > request.expires {
        return Err(PairRequestExpiredSnafu.build());
    }

    let adapter = SwiftRootSignerAdapter {
        inner: root_signer.clone(),
    };
    let root_pubkey = <SwiftRootSignerAdapter as RootSigner>::pubkey(&adapter);

    // 1. Build the Capability covering every granted topic.
    let topic_names: Vec<String> = granted_scopes
        .iter()
        .map(|g| g.topic_name.clone())
        .collect();
    let rights: Vec<CoreRight> = combined_rights(&granted_scopes);
    let mut cap =
        Capability::new_unsigned(request.agent_pubkey, topic_names.clone(), rights, now, None);
    cap.sign(&adapter).map_err(|e| {
        InternalSnafu {
            message: format!("cap sign failed: {e}"),
        }
        .build()
    })?;

    // 2. Assemble the PairGrant.
    let topic_keys: Vec<TopicEpochKey> = granted_scopes
        .iter()
        .flat_map(|g| {
            let topic_id = decode_topic_id(&g.topic_id_hex);
            g.epochs.iter().map(move |e| {
                let mut key = [0u8; 32];
                let n = e.key.len().min(32);
                key[..n].copy_from_slice(&e.key[..n]);
                TopicEpochKey {
                    topic_id,
                    epoch: e.epoch,
                    key,
                }
            })
        })
        .collect();

    let topic_name_entries: Vec<TopicNameEntry> = granted_scopes
        .iter()
        .map(|g| TopicNameEntry {
            topic_id: decode_topic_id(&g.topic_id_hex),
            name: g.topic_name.clone(),
        })
        .collect();

    let grant = PairGrant {
        version: 1,
        root_pubkey,
        cap,
        topic_keys,
        topic_names: topic_name_entries,
        host: Some(PairHostInfo {
            peer_hints: vec![PeerHint {
                node_id: host.endpoint_id_hex,
                addrs: host.addrs,
                relay: host.relay,
            }],
        }),
        nonce: request.nonce,
        issued_at: now,
    };

    // 3. Seal and sign the envelope.
    let envelope = PairGrantEnvelope::seal_and_sign(&grant, &request.ephemeral_x25519, &adapter)
        .map_err(|e| {
            InternalSnafu {
                message: format!("envelope seal/sign failed: {e}"),
            }
            .build()
        })?;

    // 4. Deliver.
    let client = PairClient::new(endpoint);
    let ack = client
        .deliver_grant(&request.dial, envelope)
        .await
        .map_err(map_pair_err)?;

    Ok(PairAckRecord {
        installed_cap_id_hex: hex::encode(ack.installed_cap_id),
        installed_at_ms: ack.installed_at,
    })
}

fn combined_rights(scopes: &[GrantedScope]) -> Vec<CoreRight> {
    let mut read = false;
    let mut write = false;
    for s in scopes {
        for r in &s.rights {
            match r {
                Right::Read => read = true,
                Right::Write => write = true,
            }
        }
    }
    let mut out = Vec::with_capacity(2);
    if read {
        out.push(CoreRight::Read);
    }
    if write {
        out.push(CoreRight::Write);
    }
    out
}

fn decode_topic_id(hex_s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Ok(bytes) = hex::decode(hex_s) {
        let n = bytes.len().min(32);
        out[..n].copy_from_slice(&bytes[..n]);
    }
    out
}

fn map_pair_err(e: wires_net::error::NetError) -> WiresError {
    use wires_net::error::NetError;
    match e {
        NetError::PairRejected { code, message, .. } => PairRejectedSnafu { code, message }.build(),
        other => PairDeliveryFailedSnafu {
            message: format!("{other}"),
        }
        .build(),
    }
}

fn now_ms() -> Result<i64, WiresError> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| {
            InternalSnafu {
                message: e.to_string(),
            }
            .build()
        })?
        .as_millis() as i64)
}

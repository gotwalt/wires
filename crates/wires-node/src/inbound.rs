use snafu::ResultExt;
use wires_core::{
    check_kind_matches, verify_chain_link, verify_envelope, CanonicalContent, MessageHash,
    MessageKind, WireMessage,
};
use wires_crypto::{decrypt_standard, open_sealed, X25519Secret};
use wires_store::{CapTable, EpochKeyStore, TopicLog};

use crate::error::{CoreSnafu, Result, StoreSnafu};

/// Outcome of processing one inbound message.
#[derive(Debug)]
pub enum Inbound {
    /// Verified envelope, persisted, content decrypted.
    Accepted { msg: WireMessage, content: Option<CanonicalContent> },
    /// Verified envelope, persisted, but content not decryptable (no epoch key,
    /// or sealed to someone else, or content not well-formed).
    AcceptedOpaque { msg: WireMessage },
    /// Refused. Persisted nothing.
    Rejected { reason: String, message_hash: MessageHash },
}

pub struct InboundCtx<'a> {
    pub topic_log: &'a TopicLog,
    pub epoch_keys: &'a EpochKeyStore,
    pub cap_table: &'a CapTable,
    pub self_x25519_sk: &'a X25519Secret,
    pub self_x25519_pk: &'a [u8; 32],
}

pub fn process(ctx: &InboundCtx, msg: WireMessage) -> Result<Inbound> {
    // 1. Envelope signature
    if verify_envelope(&msg).is_err() {
        let hash = msg.message_hash().unwrap_or_default();
        return Ok(Inbound::Rejected { reason: "bad signature".into(), message_hash: hash });
    }

    // 2. Cap check (coarse): cap_id known and not revoked, AND issued to this sender pubkey.
    let entry = ctx.cap_table.get(&msg.cap_id).context(StoreSnafu)?;
    let cap_ok = matches!(&entry, Some(e) if !e.revoked && e.cap.agent == msg.sender);
    if !cap_ok {
        let hash = msg.message_hash().context(CoreSnafu)?;
        return Ok(Inbound::Rejected {
            reason: "cap missing/revoked".into(),
            message_hash: hash,
        });
    }

    // 3. Hash-chain link check (if we have prior messages from this sender)
    let prior = if msg.seq == 0 {
        None
    } else {
        let candidates = ctx
            .topic_log
            .read_after(&msg.sender, msg.seq.checked_sub(2), 2)
            .context(StoreSnafu)?;
        candidates.into_iter().find(|m| m.seq + 1 == msg.seq)
    };
    if verify_chain_link(&msg, prior.as_ref()).is_err() {
        let hash = msg.message_hash().context(CoreSnafu)?;
        return Ok(Inbound::Rejected {
            reason: "chain break".into(),
            message_hash: hash,
        });
    }

    // 4. Persist (idempotent)
    let _newly = ctx.topic_log.append(&msg).context(StoreSnafu)?;

    // 5. Compute AAD per the publish-time pattern (ciphertext + payload_len zeroed).
    let mut aad_view = msg.clone();
    aad_view.ciphertext = vec![];
    aad_view.payload_len = 0;
    aad_view.signature = [0u8; 64];
    let aad = aad_view.signing_bytes().context(CoreSnafu)?;

    // 6. Try to decrypt content based on kind
    let content = match &msg.kind {
        MessageKind::Standard => {
            match ctx.epoch_keys.get(msg.epoch).context(StoreSnafu)? {
                Some(key) => decrypt_standard(
                    &key, &msg.topic_id, &msg.sender, msg.seq, &msg.ciphertext, &aad,
                )
                .ok()
                .and_then(|bytes| CanonicalContent::from_canonical_bytes(&bytes).ok()),
                None => None,
            }
        }
        MessageKind::SealedTo(recipient) if recipient == ctx.self_x25519_pk => {
            open_sealed(
                ctx.self_x25519_sk,
                &msg.topic_id,
                &msg.sender,
                msg.seq,
                &msg.ciphertext,
                &aad,
            )
            .ok()
            .and_then(|bytes| CanonicalContent::from_canonical_bytes(&bytes).ok())
        }
        MessageKind::SealedTo(_) => None, // not for us
        MessageKind::Public => CanonicalContent::from_canonical_bytes(&msg.ciphertext).ok(),
    };

    // 7. Reserved-type/mode enforcement once content is known
    if let Some(c) = &content {
        if check_kind_matches(&c.type_, &msg.kind).is_err() {
            let hash = msg.message_hash().context(CoreSnafu)?;
            return Ok(Inbound::Rejected {
                reason: format!("reserved type {} used with wrong mode", c.type_),
                message_hash: hash,
            });
        }
    }

    Ok(match content {
        Some(c) => Inbound::Accepted { msg, content: Some(c) },
        None => Inbound::AcceptedOpaque { msg },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publish::{build_message, KeyingMaterial, PublishParams};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use std::sync::Arc;
    use tempfile::TempDir;
    use wires_core::cap::Right;
    use wires_core::{CanonicalContent, Capability, MessageKind};
    use wires_crypto::{X25519Public, X25519Secret};
    use wires_store::{open_caps, open_topic_keys, open_topic_log, CapTable, EpochKeyStore, TopicLog};

    fn open_stores(tmp: &TempDir) -> (TopicLog, EpochKeyStore, CapTable) {
        let log = TopicLog::new(Arc::new(open_topic_log(tmp.path(), "x").unwrap()));
        let keys = EpochKeyStore::new(Arc::new(open_topic_keys(tmp.path(), "x").unwrap())).unwrap();
        let caps = CapTable::new(Arc::new(open_caps(tmp.path()).unwrap()));
        (log, keys, caps)
    }

    fn make_xkeys() -> (X25519Secret, [u8; 32]) {
        let sk = X25519Secret::random_from_rng(OsRng);
        let pk = X25519Public::from(&sk).to_bytes();
        (sk, pk)
    }

    fn issue_cap(root: &SigningKey, agent_pk: [u8; 32]) -> Capability {
        let mut cap = Capability::new_unsigned(
            agent_pk,
            vec!["__caps".into(), "home.*".into()],
            vec![Right::Read, Right::Write],
            0,
            None,
        );
        cap.sign(root).unwrap();
        cap
    }

    #[test]
    fn rejects_unknown_cap() {
        let tmp = TempDir::new().unwrap();
        let (log, keys, caps) = open_stores(&tmp);
        let (xsk, xpk) = make_xkeys();
        let ctx = InboundCtx {
            topic_log: &log, epoch_keys: &keys, cap_table: &caps,
            self_x25519_sk: &xsk, self_x25519_pk: &xpk,
        };

        let sender_sk = SigningKey::generate(&mut OsRng);
        let params = PublishParams {
            topic_id: [1u8; 32], sender_sk: &sender_sk, cap_id: [9u8; 16],
            kind: MessageKind::Public, content: CanonicalContent::new("x", "y"),
            epoch: 0, seq: 0, prev_hash: [0u8; 32], timestamp: 0,
            keying: KeyingMaterial::Public,
        };
        let msg = build_message(&params).unwrap();
        let result = process(&ctx, msg).unwrap();
        match result {
            Inbound::Rejected { reason, .. } => assert!(reason.contains("cap")),
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn accepts_valid_public_message() {
        let tmp = TempDir::new().unwrap();
        let (log, keys, caps) = open_stores(&tmp);
        let (xsk, xpk) = make_xkeys();

        let root = SigningKey::generate(&mut OsRng);
        let sender_sk = SigningKey::generate(&mut OsRng);
        let sender_pk = sender_sk.verifying_key().to_bytes();
        let cap = issue_cap(&root, sender_pk);
        let cap_id = cap.cap_id.0;
        caps.upsert_grant(&cap).unwrap();

        let ctx = InboundCtx {
            topic_log: &log, epoch_keys: &keys, cap_table: &caps,
            self_x25519_sk: &xsk, self_x25519_pk: &xpk,
        };
        let params = PublishParams {
            topic_id: [1u8; 32], sender_sk: &sender_sk, cap_id,
            kind: MessageKind::Public,
            content: CanonicalContent::new("__cap.revoke", "revoking cap deadbeef"),
            epoch: 0, seq: 0, prev_hash: [0u8; 32], timestamp: 0,
            keying: KeyingMaterial::Public,
        };
        let msg = build_message(&params).unwrap();
        let result = process(&ctx, msg).unwrap();
        match result {
            Inbound::Accepted { content, .. } => assert_eq!(content.unwrap().type_, "__cap.revoke"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn accepts_standard_when_epoch_key_present() {
        let tmp = TempDir::new().unwrap();
        let (log, keys, caps) = open_stores(&tmp);
        let (xsk, xpk) = make_xkeys();

        let root = SigningKey::generate(&mut OsRng);
        let sender_sk = SigningKey::generate(&mut OsRng);
        let sender_pk = sender_sk.verifying_key().to_bytes();
        let cap = issue_cap(&root, sender_pk);
        caps.upsert_grant(&cap).unwrap();
        let epoch_key = [42u8; 32];
        keys.put(0, &epoch_key).unwrap();

        let ctx = InboundCtx {
            topic_log: &log, epoch_keys: &keys, cap_table: &caps,
            self_x25519_sk: &xsk, self_x25519_pk: &xpk,
        };
        let params = PublishParams {
            topic_id: [1u8; 32], sender_sk: &sender_sk, cap_id: cap.cap_id.0,
            kind: MessageKind::Standard,
            content: CanonicalContent::new("home.fridge.temp", "38F"),
            epoch: 0, seq: 0, prev_hash: [0u8; 32], timestamp: 0,
            keying: KeyingMaterial::StandardEpochKey(&epoch_key),
        };
        let msg = build_message(&params).unwrap();
        let result = process(&ctx, msg).unwrap();
        match result {
            Inbound::Accepted { content, .. } => assert_eq!(content.unwrap().type_, "home.fridge.temp"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn opaque_when_no_epoch_key() {
        let tmp = TempDir::new().unwrap();
        let (log, keys, caps) = open_stores(&tmp);
        let (xsk, xpk) = make_xkeys();

        let root = SigningKey::generate(&mut OsRng);
        let sender_sk = SigningKey::generate(&mut OsRng);
        let sender_pk = sender_sk.verifying_key().to_bytes();
        let cap = issue_cap(&root, sender_pk);
        caps.upsert_grant(&cap).unwrap();
        // NOTE: no epoch key installed

        let ctx = InboundCtx {
            topic_log: &log, epoch_keys: &keys, cap_table: &caps,
            self_x25519_sk: &xsk, self_x25519_pk: &xpk,
        };
        let epoch_key = [42u8; 32]; // sender used this; receiver doesn't have it
        let params = PublishParams {
            topic_id: [1u8; 32], sender_sk: &sender_sk, cap_id: cap.cap_id.0,
            kind: MessageKind::Standard,
            content: CanonicalContent::new("home.fridge.temp", "38F"),
            epoch: 0, seq: 0, prev_hash: [0u8; 32], timestamp: 0,
            keying: KeyingMaterial::StandardEpochKey(&epoch_key),
        };
        let msg = build_message(&params).unwrap();
        let result = process(&ctx, msg).unwrap();
        match result {
            Inbound::AcceptedOpaque { .. } => {}
            other => panic!("expected AcceptedOpaque, got {other:?}"),
        }
    }
}

use ed25519_dalek::SigningKey;
use snafu::{OptionExt, ResultExt};
use wires_core::{
    sign_envelope, CanonicalContent, CapId, MessageKind, Pubkey, TopicId, WireMessage,
};
use wires_crypto::{encrypt_standard, seal_to};
use wires_store::{EpochKey, EpochKeyStore, TopicLog};

use crate::error::{CoreSnafu, CryptoSnafu, MissingEpochKeySnafu, Result, StoreSnafu};

pub struct PublishParams<'a> {
    pub topic_id: TopicId,
    pub sender_sk: &'a SigningKey,
    pub cap_id: CapId,
    pub kind: MessageKind,
    pub content: CanonicalContent,
    pub epoch: u32,
    pub seq: u64,
    pub prev_hash: [u8; 32],
    pub timestamp: i64,
    pub keying: KeyingMaterial<'a>,
}

pub enum KeyingMaterial<'a> {
    StandardEpochKey(&'a EpochKey),
    SealedRecipient(&'a [u8; 32]),
    Public,
}

/// Build a `WireMessage` from publish params: encrypt content, fill envelope, sign.
/// Caller is responsible for resolving `seq`/`prev_hash` from the local topic log
/// (use `next_seq_and_prev_hash`) and `epoch`+`epoch_key` from the local key store
/// (use `current_epoch_key`).
pub fn build_message(params: &PublishParams) -> Result<WireMessage> {
    params.content.validate().context(CoreSnafu)?;
    let content_bytes = params.content.to_canonical_bytes().context(CoreSnafu)?;

    let sender = params.sender_sk.verifying_key().to_bytes();
    // Build the envelope with ciphertext temporarily empty so signing_bytes()
    // gives us the AAD before we know the ciphertext. The ciphertext field is
    // included in signing_bytes, so we need to know it first → so we compute
    // ciphertext using a stand-in AAD? No: the design is that AAD is the
    // envelope minus signature minus ciphertext. Re-read spec §4: "AAD: byte
    // serialization of the cleartext envelope fields (everything above
    // `ciphertext`)" — actually the spec says envelope INCLUDING ciphertext
    // is AAD. That's a chicken-and-egg: ciphertext depends on AAD which
    // depends on ciphertext.
    //
    // The correct read of the spec is: `signing_bytes` covers every envelope
    // field including ciphertext (the AEAD tag goes in `signature`? no, the
    // tag is appended to ciphertext by chacha20poly1305). So the path is:
    // 1. Build envelope with placeholder ciphertext (empty Vec).
    // 2. Compute AAD = signing_bytes() of that envelope.
    // 3. Encrypt content with that AAD → ciphertext.
    // 4. Set the envelope's ciphertext field to the result.
    // 5. Re-compute signing_bytes (now including the actual ciphertext) and
    //    use that as the input to ed25519 signing.
    //
    // The AAD used for AEAD is the pre-encryption signing_bytes (with empty
    // ciphertext); decryption must reproduce the same AAD. Receivers do this
    // by setting ciphertext = [] in their local copy before computing AAD.
    //
    // To make this symmetric with decryption, we will document this in code
    // and matching it in the inbound task.
    let mut envelope = WireMessage {
        topic_id: params.topic_id,
        epoch: params.epoch,
        kind: params.kind.clone(),
        sender,
        cap_id: params.cap_id,
        seq: params.seq,
        prev_hash: params.prev_hash,
        timestamp: params.timestamp,
        payload_len: 0,
        signature: [0u8; 64],
        ciphertext: vec![],
    };
    let aad = envelope.signing_bytes().context(CoreSnafu)?;

    let ciphertext = match (&params.kind, &params.keying) {
        (MessageKind::Standard, KeyingMaterial::StandardEpochKey(key)) => {
            encrypt_standard(key, &params.topic_id, &sender, params.seq, &content_bytes, &aad)
                .context(CryptoSnafu)?
        }
        (MessageKind::SealedTo(target), KeyingMaterial::SealedRecipient(recipient))
            if target == *recipient =>
        {
            seal_to(*recipient, &params.topic_id, &sender, params.seq, &content_bytes, &aad)
                .context(CryptoSnafu)?
        }
        (MessageKind::SealedTo(_), KeyingMaterial::SealedRecipient(recipient)) => {
            seal_to(*recipient, &params.topic_id, &sender, params.seq, &content_bytes, &aad)
                .context(CryptoSnafu)?
        }
        (MessageKind::Public, KeyingMaterial::Public) => content_bytes,
        _ => {
            return crate::error::ConfigSnafu {
                message: "keying material mismatch with kind".to_string(),
            }
            .fail();
        }
    };

    envelope.payload_len = ciphertext.len() as u32;
    envelope.ciphertext = ciphertext;
    sign_envelope(&mut envelope, params.sender_sk).context(CoreSnafu)?;
    Ok(envelope)
}

/// Look up the next `(seq, prev_hash)` for `sender` on a topic.
pub fn next_seq_and_prev_hash(log: &TopicLog, sender: &Pubkey) -> Result<(u64, [u8; 32])> {
    let hwm = log.hwm().context(StoreSnafu)?;
    Ok(match hwm.get(sender) {
        None => (0, [0u8; 32]),
        Some((seq, hash)) => (seq + 1, *hash),
    })
}

pub fn current_epoch_key(keys: &EpochKeyStore, topic_id: &TopicId) -> Result<(u32, EpochKey)> {
    keys.latest().context(StoreSnafu)?.context(MissingEpochKeySnafu {
        topic_id_hex: hex::encode(topic_id),
        epoch: 0u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use wires_core::verify_envelope;
    use wires_crypto::decrypt_standard;

    #[test]
    fn build_standard_message_is_signed_and_decryptable() {
        let sk = SigningKey::generate(&mut OsRng);
        let epoch_key: EpochKey = [42u8; 32];
        let params = PublishParams {
            topic_id: [1u8; 32],
            sender_sk: &sk,
            cap_id: [0u8; 16],
            kind: MessageKind::Standard,
            content: CanonicalContent::new("home.fridge.temp", "38F"),
            epoch: 0,
            seq: 0,
            prev_hash: [0u8; 32],
            timestamp: 1_000,
            keying: KeyingMaterial::StandardEpochKey(&epoch_key),
        };
        let msg = build_message(&params).unwrap();
        verify_envelope(&msg).unwrap();
        // Decrypt round-trip — receiver computes AAD with empty ciphertext.
        let mut for_aad = msg.clone();
        for_aad.ciphertext = vec![];
        for_aad.payload_len = 0;
        for_aad.signature = [0u8; 64];
        let aad = for_aad.signing_bytes().unwrap();
        let pt = decrypt_standard(&epoch_key, &msg.topic_id, &msg.sender, msg.seq, &msg.ciphertext, &aad).unwrap();
        let content = CanonicalContent::from_canonical_bytes(&pt).unwrap();
        assert_eq!(content.type_, "home.fridge.temp");
    }

    #[test]
    fn build_public_skips_encryption() {
        let sk = SigningKey::generate(&mut OsRng);
        let params = PublishParams {
            topic_id: [1u8; 32],
            sender_sk: &sk,
            cap_id: [0u8; 16],
            kind: MessageKind::Public,
            content: CanonicalContent::new("__cap.revoke", "revoking cap deadbeef"),
            epoch: 0,
            seq: 0,
            prev_hash: [0u8; 32],
            timestamp: 1_000,
            keying: KeyingMaterial::Public,
        };
        let msg = build_message(&params).unwrap();
        verify_envelope(&msg).unwrap();
        // Public: ciphertext is the canonical JSON content directly
        let parsed = CanonicalContent::from_canonical_bytes(&msg.ciphertext).unwrap();
        assert_eq!(parsed.type_, "__cap.revoke");
    }

    #[test]
    fn build_message_kind_keying_mismatch_errors() {
        let sk = SigningKey::generate(&mut OsRng);
        let epoch_key: EpochKey = [42u8; 32];
        // Public kind but providing a StandardEpochKey
        let params = PublishParams {
            topic_id: [1u8; 32],
            sender_sk: &sk,
            cap_id: [0u8; 16],
            kind: MessageKind::Public,
            content: CanonicalContent::new("x", "y"),
            epoch: 0,
            seq: 0,
            prev_hash: [0u8; 32],
            timestamp: 1_000,
            keying: KeyingMaterial::StandardEpochKey(&epoch_key),
        };
        assert!(build_message(&params).is_err());
    }
}

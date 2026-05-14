use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::OsRng;
use snafu::{ensure, OptionExt};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::error::{DecryptSnafu, EncryptSnafu, Result, SealedShortSnafu};

/// 12-byte sealed-box nonce. Includes the recipient pubkey so that the same
/// (topic, sender, seq) sealed to two different recipients yields distinct nonces.
pub fn sealed_nonce(
    topic_id: &[u8; 32],
    sender: &[u8; 32],
    seq: u64,
    recipient_pubkey: &[u8; 32],
) -> [u8; 12] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(topic_id);
    hasher.update(sender);
    hasher.update(&seq.to_le_bytes());
    hasher.update(recipient_pubkey);
    let out = hasher.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&out.as_bytes()[..12]);
    nonce
}

/// Seal `content` so only the holder of `recipient_pk`'s x25519 secret can open.
/// Output: ephemeral_pubkey (32 bytes) || aead_ciphertext_with_tag.
pub fn seal_to(
    recipient_pk: &[u8; 32],
    topic_id: &[u8; 32],
    sender: &[u8; 32],
    seq: u64,
    content: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let recipient = PublicKey::from(*recipient_pk);
    let ephemeral = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pub = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&recipient);
    let key = derive_aead_key(shared.as_bytes());

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce_bytes = sealed_nonce(topic_id, sender, seq, recipient_pk);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, Payload { msg: content, aad })
        .ok()
        .context(EncryptSnafu)?;

    let mut out = Vec::with_capacity(32 + ct.len());
    out.extend_from_slice(ephemeral_pub.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open_sealed(
    recipient_sk: &StaticSecret,
    topic_id: &[u8; 32],
    sender: &[u8; 32],
    seq: u64,
    sealed_bytes: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    ensure!(sealed_bytes.len() >= 32, SealedShortSnafu);
    let mut ephemeral = [0u8; 32];
    ephemeral.copy_from_slice(&sealed_bytes[..32]);
    let ephemeral_pub = PublicKey::from(ephemeral);
    let shared = recipient_sk.diffie_hellman(&ephemeral_pub);
    let key = derive_aead_key(shared.as_bytes());

    let recipient_pub_bytes = PublicKey::from(recipient_sk).to_bytes();
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce_bytes = sealed_nonce(topic_id, sender, seq, &recipient_pub_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, Payload { msg: &sealed_bytes[32..], aad })
        .ok()
        .context(DecryptSnafu)
}

fn derive_aead_key(shared: &[u8; 32]) -> [u8; 32] {
    // BLAKE3 keyed-derive KDF, domain-separated.
    let mut hasher = blake3::Hasher::new_derive_key("wires.sealed.v1.aead");
    hasher.update(shared);
    let out = hasher.finalize();
    *out.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (StaticSecret, [u8; 32]) {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = PublicKey::from(&sk).to_bytes();
        (sk, pk)
    }

    #[test]
    fn roundtrip_via_recipient_key() {
        let (sk, pk) = keypair();
        let sealed = seal_to(&pk, &[1u8; 32], &[2u8; 32], 5, b"secret", b"aad").unwrap();
        let pt = open_sealed(&sk, &[1u8; 32], &[2u8; 32], 5, &sealed, b"aad").unwrap();
        assert_eq!(pt, b"secret");
    }

    #[test]
    fn other_recipient_cannot_open() {
        let (sk_a, pk_a) = keypair();
        let (sk_b, _pk_b) = keypair();
        let sealed = seal_to(&pk_a, &[1u8; 32], &[2u8; 32], 5, b"secret", b"aad").unwrap();
        assert!(open_sealed(&sk_b, &[1u8; 32], &[2u8; 32], 5, &sealed, b"aad").is_err());
        // Original recipient still works:
        open_sealed(&sk_a, &[1u8; 32], &[2u8; 32], 5, &sealed, b"aad").unwrap();
    }

    #[test]
    fn aad_mismatch_fails() {
        let (sk, pk) = keypair();
        let sealed = seal_to(&pk, &[1u8; 32], &[2u8; 32], 5, b"x", b"a").unwrap();
        assert!(open_sealed(&sk, &[1u8; 32], &[2u8; 32], 5, &sealed, b"b").is_err());
    }

    #[test]
    fn short_sealed_rejected() {
        let (sk, _pk) = keypair();
        let r = open_sealed(&sk, &[0u8; 32], &[0u8; 32], 0, &[1, 2, 3], b"a");
        assert!(r.is_err());
    }

    #[test]
    fn seq_must_match_for_decrypt() {
        let (sk, pk) = keypair();
        let sealed = seal_to(&pk, &[1u8; 32], &[2u8; 32], 5, b"x", b"a").unwrap();
        assert!(open_sealed(&sk, &[1u8; 32], &[2u8; 32], 6, &sealed, b"a").is_err());
    }
}
